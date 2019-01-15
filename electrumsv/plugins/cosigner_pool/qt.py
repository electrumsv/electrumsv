#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import time
from xmlrpc.client import ServerProxy

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QPushButton

from electrumsv import util, keystore, ecc
from electrumsv import transaction
from electrumsv.bip32 import deserialize_xpub, deserialize_xprv
from electrumsv.crypto import sha256d
from electrumsv.i18n import _
from electrumsv.keystore import is_xpubkey, parse_xpubkey
from electrumsv.logs import logs
from electrumsv.plugin import BasePlugin, hook
from electrumsv.util import bh2u, bfh
from electrumsv.wallet import Multisig_Wallet

from electrumsv.gui.qt.util import WaitingDialog

logger = logs.get_logger("cosignerpool")

server = ServerProxy('https://cosigner.electrum.org/', allow_none=True)


class Listener(util.DaemonThread):

    def __init__(self, parent):
        util.DaemonThread.__init__(self)
        self.daemon = True
        self.parent = parent
        self.received = set()
        self.keyhashes = []

    def set_keyhashes(self, keyhashes):
        self.keyhashes = keyhashes

    def clear(self, keyhash):
        server.delete(keyhash)
        self.received.remove(keyhash)

    def run(self):
        while self.running:
            if not self.keyhashes:
                time.sleep(2)
                continue
            for keyhash in self.keyhashes:
                if keyhash in self.received:
                    continue
                try:
                    message = server.get(keyhash)
                except Exception as e:
                    logger.error("cannot contact cosigner pool")
                    time.sleep(30)
                    continue
                if message:
                    self.received.add(keyhash)
                    logger.debug("received message for %s", keyhash)
                    self.parent.obj.cosigner_receive_signal.emit(
                        keyhash, message)
            # poll every 30 seconds
            time.sleep(30)


class QReceiveSignalObject(QObject):
    cosigner_receive_signal = pyqtSignal(object, object)


class Plugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.listener = None
        self.obj = QReceiveSignalObject()
        self.obj.cosigner_receive_signal.connect(self.on_receive)
        self.keys = []
        self.cosigner_list = []

    @hook
    def init_qt(self, gui):
        for window in gui.windows:
            self.on_new_window(window)

    @hook
    def on_new_window(self, window):
        self.update(window)

    @hook
    def on_close_window(self, window):
        self.update(window)

    def is_available(self):
        return True

    def update(self, window):
        wallet = window.wallet
        if type(wallet) != Multisig_Wallet:
            return
        if self.listener is None:
            logger.debug("starting listener")
            self.listener = Listener(self)
            self.listener.start()
        elif self.listener:
            logger.debug("shutting down listener")
            self.listener.stop()
            self.listener = None
        self.keys = []
        self.cosigner_list = []
        for key, keystore_ in wallet.keystores.items():
            xpub = keystore_.get_master_public_key()
            K = deserialize_xpub(xpub)[-1]
            _hash = bh2u(sha256d(K))
            if not keystore_.is_watching_only():
                self.keys.append((key, _hash, window))
            else:
                self.cosigner_list.append((window, xpub, K, _hash))
        if self.listener:
            self.listener.set_keyhashes([t[1] for t in self.keys])

    @hook
    def transaction_dialog(self, d):
        d.cosigner_send_button = b = QPushButton(_("Send to cosigner"))
        b.clicked.connect(lambda: self.do_send(d.tx))
        d.buttons.insert(0, b)
        self.transaction_dialog_update(d)

    @hook
    def transaction_dialog_update(self, d):
        if d.tx.is_complete() or d.wallet.can_sign(d.tx):
            d.cosigner_send_button.hide()
            return
        for window, xpub, K, _hash in self.cosigner_list:
            if window.wallet == d.wallet and self.cosigner_can_sign(d.tx, xpub):
                d.cosigner_send_button.show()
                break
        else:
            d.cosigner_send_button.hide()

    def cosigner_can_sign(self, tx, cosigner_xpub):
        xpub_set = set([])
        for txin in tx.inputs():
            for x_pubkey in txin['x_pubkeys']:
                if is_xpubkey(x_pubkey):
                    xpub, s = parse_xpubkey(x_pubkey)
                    xpub_set.add(xpub)
        return cosigner_xpub in xpub_set

    def do_send(self, tx):
        def on_success(result):
            window.show_message(_("Your transaction was sent to the cosigning pool.") + '\n' +
                                _("Open your cosigner wallet to retrieve it."))

        def on_failure(exc_info):
            logger.exception("", exc_info=exc_info)
            window.show_error(_("Failed to send transaction to cosigning pool")
                              + ':\n' + str(exc_info[1]))

        for window, xpub, K, _hash in self.cosigner_list:
            if not self.cosigner_can_sign(tx, xpub):
                continue
            # construct message
            raw_tx_bytes = bfh(str(tx))
            public_key = ecc.ECPubkey(K)
            message = public_key.encrypt_message(raw_tx_bytes).decode('ascii')
            # send message
            def task():
                server.put(_hash, message)
            msg = _('Sending transaction to cosigning pool...')
            WaitingDialog(window, msg, task, on_success, on_failure)

    def on_receive(self, keyhash, message):
        logger.debug("signal arrived for '%s'", keyhash)
        window = None
        for key, _hash, window in self.keys:
            if _hash == keyhash:
                break
        else:
            logger.error("keyhash not found")
            return

        wallet = window.wallet
        if isinstance(wallet.keystore, keystore.Hardware_KeyStore):
            window.show_warning(
                _('An encrypted transaction was retrieved from cosigning pool.') + '\n' +
                _('However, hardware wallets do not support message decryption, '
                  'which makes them not compatible with the current design of cosigner pool.'))
            return
        if wallet.has_password():
            password = window.password_dialog(
                _('An encrypted transaction was retrieved from cosigning pool.') + '\n' +
                _('Please enter your password to decrypt it.'))
            if not password:
                return
        else:
            password = None
            if not window.question(
                    _("An encrypted transaction was retrieved from cosigning pool.") + '\n' +
                    _("Do you want to open it now?")):
                return

        xprv = wallet.keystore.get_master_private_key(password)
        if not xprv:
            return
        try:
            k = deserialize_xprv(xprv)[-1]
            EC = ecc.ECPrivkey(k)
            message = bh2u(EC.decrypt_message(message))
        except Exception as e:
            logger.exception("")
            window.show_error(_('Error decrypting message') + ':\n' + str(e))
            return

        self.listener.clear(keyhash)
        tx = transaction.Transaction(message)
        window.show_transaction(tx, prompt_if_unsaved=True)
