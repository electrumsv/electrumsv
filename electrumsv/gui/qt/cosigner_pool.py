# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
# Copyright (C) 2019 ElectrumSV developers
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

from collections import namedtuple
from functools import partial
import time
from xmlrpc.client import ServerProxy

from bitcoinx import PublicKey, bip32_key_from_string


from electrumsv import util, keystore
from electrumsv import transaction
from electrumsv.app_state import app_state
from electrumsv.crypto import sha256d
from electrumsv.extensions import cosigner_pool
from electrumsv.i18n import _
from electrumsv.keystore import is_xpubkey, parse_xpubkey
from electrumsv.logs import logs
from electrumsv.util import bh2u, bfh
from electrumsv.wallet import Multisig_Wallet

from electrumsv.gui.qt.util import WaitingDialog

logger = logs.get_logger("cosignerpool")

server = ServerProxy('https://cosigner.electrum.org/', allow_none=True)

CosignerItem = namedtuple("CosignerItem", "window xpub K hash watching_only")


class Listener(util.DaemonThread):

    def __init__(self, parent):
        super().__init__('cosigner')
        self.daemon = True
        self.parent = parent
        self.received = set()

    def clear(self, keyhash):
        server.delete(keyhash)
        self.received.remove(keyhash)

    def run(self):
        while self.running:
            keyhashes = [item.hash for item in self.parent.items
                         if not item.watching_only]
            if not keyhashes:
                time.sleep(2)
                continue
            for keyhash in keyhashes:
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
                    app_state.app.cosigner_received_signal.emit(keyhash, message)
            # poll every 30 seconds
            time.sleep(30)


class CosignerPool(object):

    def __init__(self):
        self.listener = None
        self.items = []
        app_state.app.cosigner_received_signal.connect(self.on_receive)
        app_state.app.window_opened_signal.connect(self.window_opened)
        app_state.app.window_closed_signal.connect(self.window_closed)
        self.on_enabled_changed()

    def on_enabled_changed(self):
        if cosigner_pool.is_enabled():
            if self.listener is None:
                logger.debug("starting listener")
                self.listener = Listener(self)
                self.listener.start()
            for window in app_state.app.windows:
                self.window_opened(window)
        elif self.listener:
            logger.debug("shutting down listener")
            self.listener.stop()
            self.listener = None
            self.items.clear()

    def window_closed(self, window):
        if cosigner_pool.is_enabled():
            self.items = [item for item in self.items if item.window != window]

    def window_opened(self, window):
        wallet = window.wallet
        if cosigner_pool.is_enabled() and type(wallet) == Multisig_Wallet:
            items = []
            for key, keystore in wallet.keystores.items():
                xpub = keystore.get_master_public_key()
                pubkey = bip32_key_from_string(xpub)
                K = pubkey.to_bytes()
                K_hash = bh2u(sha256d(K))
                items.append(CosignerItem(window, xpub, K, K_hash, keystore.is_watching_only()))
            # Presumably atomic
            self.items.extend(items)

    def cosigner_can_sign(self, tx, cosigner_xpub):
        xpub_set = set([])
        for txin in tx.inputs():
            for x_pubkey in txin['x_pubkeys']:
                if is_xpubkey(x_pubkey):
                    xpub, s = parse_xpubkey(x_pubkey)
                    xpub_set.add(xpub)
        return cosigner_xpub in xpub_set

    def is_theirs(self, wallet, item, tx):
        return (item.window.wallet is wallet and item.watching_only
                and self.cosigner_can_sign(tx, item.xpub))

    def show_button(self, wallet, tx):
        if tx.is_complete() or wallet.can_sign(tx):
            return False
        return any(self.is_theirs(wallet, item, tx) for item in self.items)

    def do_send(self, wallet, tx):
        def on_done(window, future):
            try:
                future.result()
            except Exception as exc:
                window.on_exception(exc)
            else:
                window.show_message('\n'.join((
                    _("Your transaction was sent to the cosigning pool."),
                    _("Open your cosigner wallet to retrieve it."),
                )))

        def send_message():
            server.put(item.hash, message)

        for item in self.items:
            if self.is_theirs(wallet, item, tx):
                raw_tx_bytes = bfh(str(tx))
                public_key = PublicKey.from_bytes(item.K)
                message = public_key.encrypt_message_to_base64(raw_tx_bytes)
                WaitingDialog(item.window, _('Sending transaction to cosigning pool...'),
                              send_message, on_done=partial(on_done, item.window))

    def on_receive(self, keyhash, message):
        logger.debug("signal arrived for '%s'", keyhash)
        for item in self.items:
            if item.hash == keyhash:
                window = item.window
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
            self.listener.clear(keyhash)
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

        self.listener.clear(keyhash)

        xprv = wallet.keystore.get_master_private_key(password)
        if not xprv:
            return
        privkey = bip32_key_from_string(xprv)
        try:
            message = bh2u(privkey.decrypt_message(message))
        except Exception as e:
            logger.exception("")
            window.show_error(_('Error decrypting message') + ':\n' + str(e))
            return

        tx = transaction.Transaction(message)
        window.show_transaction(tx, prompt_if_unsaved=True)
