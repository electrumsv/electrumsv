# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
# Copyright (C) 2019-2020 The ElectrumSV Developers
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


# NOTE(rt12) BACKLOG It should be possible for a multi-signature wallet to integrate multiple
# non-watching keys, and require each to sign. This may result in duplicate messages. It's
# probably best for those doing so to do it manually until the cosigner pool handles it.


from functools import partial
import json
import time
from typing import List, NamedTuple, Set
from xmlrpc.client import ServerProxy

from bitcoinx import PublicKey, bip32_key_from_string

from electrumsv import util
from electrumsv.app_state import app_state
from electrumsv.crypto import sha256d
from electrumsv.extensions import cosigner_pool
from electrumsv.i18n import _
from electrumsv.keystore import Hardware_KeyStore
from electrumsv.logs import logs
from electrumsv.transaction import Transaction
from electrumsv.wallet import MultisigAccount, AbstractAccount

from electrumsv.gui.qt.util import WaitingDialog


logger = logs.get_logger("cosignerpool")
server = ServerProxy('https://cosigner.electrum.org/', allow_none=True)


class CosignerItem(NamedTuple):
    window: 'ElectrumWindow'
    account_id: int
    xpub: str
    pubkey_bytes: bytes
    keyhash_hex: str
    watching_only: bool


class Listener(util.DaemonThread):
    """
    Polls the cosigner pool server for messages to the SHA256d hashes of the signing public keys of
    all local multi-signature accounts.
    """

    def __init__(self, parent: 'CosignerPool'):
        super().__init__('cosigner')
        self.daemon = True
        self.parent = parent
        self.received: Set[str] = set()

    def clear(self, keyhash_hex: str) -> None:
        server.delete(keyhash_hex)
        self.received.remove(keyhash_hex)

    def run(self) -> None:
        while self.running:
            relevant_items = [item for item in self.parent._items if not item.watching_only]
            if not relevant_items:
                time.sleep(2)
                continue
            for item in relevant_items:
                if item.keyhash_hex in self.received:
                    continue
                try:
                    message = server.get(item.keyhash_hex)
                except Exception as e:
                    logger.error("cannot contact cosigner pool")
                    time.sleep(30)
                    continue
                if message:
                    self.received.add(item.keyhash_hex)
                    logger.debug("received message for %s", item.keyhash_hex)
                    app_state.app.cosigner_received_signal.emit(item, message)
            # poll every 30 seconds
            time.sleep(30)


class CosignerPool:
    _listener: Listener = None

    def __init__(self):
        # This is accessed without locking by both the UI thread and the listener thread.
        self._items: List[CosignerItem] = []
        app_state.app.cosigner_received_signal.connect(self._on_receive)
        app_state.app.window_opened_signal.connect(self._window_opened)
        app_state.app.window_closed_signal.connect(self._window_closed)
        self.on_enabled_changed()

    # Externally invoked when the extension is enabled or disabled.
    def on_enabled_changed(self):
        if cosigner_pool.is_enabled():
            if self._listener is None:
                logger.debug("starting listener")
                self._listener = Listener(self)
                self._listener.start()
            for window in app_state.app.windows:
                self._window_opened(window)
        elif self._listener:
            logger.debug("shutting down listener")
            self._listener.stop()
            self._listener = None
            self._items.clear()

    def _window_closed(self, window: 'ElectrumWindow') -> None:
        if cosigner_pool.is_enabled():
            self._items = [item for item in self._items if item.window != window]

    def _window_opened(self, window: 'ElectrumWindow') -> None:
        if not cosigner_pool.is_enabled():
            return

        for account in window._wallet.get_accounts():
            if type(account) is not MultisigAccount:
                continue

            account_id = account.get_id()
            items = []
            for keystore in account.get_keystores():
                xpub = keystore.get_master_public_key()
                pubkey = bip32_key_from_string(xpub)
                pubkey_bytes = pubkey.to_bytes()
                keyhash_hex = sha256d(pubkey_bytes).hex()
                items.append(CosignerItem(window, account_id, xpub, pubkey_bytes,
                    keyhash_hex, keystore.is_watching_only()))
            self._items.extend(items)

    def _cosigner_can_sign(self, tx: Transaction, cosigner_xpub: str) -> bool:
        xpub_set = set([])
        for txin in tx.inputs:
            for x_pubkey in txin.x_pubkeys:
                if x_pubkey.is_bip32_key():
                    xpub_set.add(x_pubkey.bip32_extended_key())
        return cosigner_xpub in xpub_set

    def _is_theirs(self, window: 'ElectrumWindow', account_id: int, item: CosignerItem,
            tx: Transaction) -> bool:
        return (item.window is window and item.account_id == account_id and item.watching_only and
            self._cosigner_can_sign(tx, item.xpub))

    # Externally invoked to find out if the transaction can be sent to cosigners.
    def show_send_to_cosigner_button(self, window: 'ElectrumWindow', account: AbstractAccount,
            tx: Transaction) -> bool:
        if window.network is None:
            return False
        if tx.is_complete() or account.can_sign(tx):
            return False
        account_id = account.get_id()
        return any(self._is_theirs(window, account_id, item, tx) for item in self._items)

    # Externally invoked to send the transaction to cosigners.
    def do_send(self, window: 'ElectrumWindow', account: AbstractAccount, tx: Transaction) -> None:
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

        def send_message() -> None:
            server.put(item.keyhash_hex, message)

        account_id = account.get_id()
        for item in self._items:
            if self._is_theirs(window, account_id, item, tx):
                raw_tx_bytes = json.dumps(tx.to_dict()).encode()
                public_key = PublicKey.from_bytes(item.pubkey_bytes)
                message = public_key.encrypt_message_to_base64(raw_tx_bytes)
                WaitingDialog(item.window, _('Sending transaction to cosigning pool...'),
                              send_message, on_done=partial(on_done, item.window))

    def _on_receive(self, item: CosignerItem, message: str) -> None:
        logger.debug("signal arrived for '%s'", item.keyhash_hex)
        window = item.window
        account = window._wallet.get_account(item.account_id)

        for keystore in account.get_keystores():
            if keystore.get_master_public_key() == item.xpub:
                break
        else:
            window.show_error(_('Message for non-existent non-watching cosigner'))
            return

        if isinstance(keystore, Hardware_KeyStore):
            window.show_warning(
                _('An encrypted transaction was retrieved from cosigning pool.') + '\n' +
                _('However, hardware wallets do not support message decryption, '
                  'which makes them incompatible with the current design of cosigner pool.'))
            self._listener.clear(item.keyhash_hex)
            return

        password = window.password_dialog(
            _('An encrypted transaction was retrieved from cosigning pool.') + '\n' +
            _('Please enter your password to decrypt it.'))
        if not password:
            return

        self._listener.clear(item.keyhash_hex)

        xprv = keystore.get_master_private_key(password)
        if not xprv:
            return
        privkey = bip32_key_from_string(xprv)
        try:
            message = privkey.decrypt_message(message).decode()
        except Exception as e:
            logger.exception("")
            window.show_error(_('Error decrypting message') + ':\n' + str(e))
            return

        txdict = json.loads(message)
        tx = Transaction.from_dict(txdict)
        window.show_transaction(account, tx, prompt_if_unsaved=True)
