# ElectrumSV - lightweight Bitcoin client
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

import base64
from functools import partial
import json
import hashlib
import os
import requests
import threading
from typing import Any, Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QPushButton, QVBoxLayout

from electrumsv.app_state import app_state
from electrumsv.crypto import aes_decrypt_with_iv, aes_encrypt_with_iv
from electrumsv.exceptions import UserCancelled
from electrumsv.extensions import label_sync
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.wallet import AbstractAccount, Wallet

from .util import (Buttons, EnterButton, FormSectionWidget, FramedTextWidget, OkButton,
    WindowModalDialog)


logger = logs.get_logger("labels")


# Label sync only currently works for addresses and transactions. It needs several pieces of
# work before it can be re-enabled:
# - Labels are now only tracked for keys and transactions that exist. This means that if someone
#   does a sync, unlike before where there was a dictionary that was not required to map to
#   existing entries, any entries that are for unknown entries will be lost without special
#   handling.
# - Addresses cannot be mapped to keys, unless we enumerate all existing keys. Any labels for
#   addresses we cannot find through enumeration, will similarly be lost without special handling.
#   If we modify this to take labels from keys, the code should perhaps instead map the label
#   to the masterkey fingerprint combined with the derivation path. However, this still leaves
#   room for the presence of unsynced keys.
# - There is no per-account storage for "wallet_nonce" to be get/set from/to.
# TODO: Need to fix `set_transaction_label` before this can work again as well, work grows.
DISABLE_INTEGRATION = True

class LabelSync(object):
    def __init__(self):
        self.target_host = 'labels.electrum.org'
        self._accounts = {}
        app_state.app.window_opened_signal.connect(self.window_opened)
        app_state.app.window_closed_signal.connect(self.window_closed)

    def encode(self, account: AbstractAccount, msg):
        password, iv, account_id = self._accounts[account]
        encrypted = aes_encrypt_with_iv(password, iv, msg.encode('utf8'))
        return base64.b64encode(encrypted).decode()

    def decode(self, account: AbstractAccount, message):
        password, iv, wallet_id = self._accounts[account]
        decoded = base64.b64decode(message)
        decrypted = aes_decrypt_with_iv(password, iv, decoded)
        return decrypted.decode('utf8')

    def get_nonce(self, account : AbstractAccount) -> int:
        # nonce is the nonce to be used with the next change
        if DISABLE_INTEGRATION:
            return 1
        # TODO BACKLOG there is no working account get/set
        nonce = account.get('wallet_nonce', None)
        if nonce is None:
            nonce = 1
            self.set_nonce(account, nonce)
        return nonce

    def set_nonce(self, account: AbstractAccount, nonce: int) -> None:
        logger.debug("set {} nonce to {}".format(account.name(), nonce))
        # TODO BACKLOG there is no working account get/set
        account.put("wallet_nonce", nonce)

    def set_transaction_label(self, wallet: Wallet, tx_hash: bytes, text: Optional[str]) -> None:
        if DISABLE_INTEGRATION:
            return
        raise NotImplementedError("Transaction labels not supported")
        # label_key = tx_hash
        # assert label_key != tx_hash, "Label sync transaction support not implemented"
        # # label_key = "tx:"+ hash_to_hex_str(tx_hash)
        # self._set_label(account, label_key, text)

    def set_keyinstance_label(self, account: AbstractAccount, key_id: int, text: str) -> None:
        if DISABLE_INTEGRATION:
            return
        # TODO(rt12) BACKLOG if this is going to be made to work, it needs to fetch the
        # fingerprint and derivation data, or something equivalent.
        label_key = key_id # "key:"+ key_id
        assert label_key != key_id, "Label sync key instance support not implemented"
        self._set_label(account, label_key, text)

    def _set_label(self, account: AbstractAccount, item, label) -> None:
        if account not in self._accounts:
            return
        if not item:
            return
        nonce = self.get_nonce(account)
        wallet_id = self._accounts[account][2]
        bundle = {"walletId": wallet_id,
                "walletNonce": nonce,
                "externalId": self.encode(account, item),
                "encryptedLabel": self.encode(account, label)}
        t = threading.Thread(target=self.do_request_safe,
                            args=["POST", "/label", False, bundle])
        t.setDaemon(True)
        t.start()
        # Caller will write the wallet
        self.set_nonce(account, nonce + 1)

    def do_request(self, method, url = "/labels", is_batch=False, data=None):
        url = 'https://' + self.target_host + url
        kwargs = {'headers': {}}
        if method == 'GET' and data:
            kwargs['params'] = data
        elif method == 'POST' and data:
            kwargs['data'] = json.dumps(data)
            kwargs['headers']['Content-Type'] = 'application/json'
        response = requests.request(method, url, **kwargs)
        if response.status_code != 200:
            raise Exception(response.status_code, response.text)
        response = response.json()
        if "error" in response:
            raise Exception(response["error"])
        return response

    def do_request_safe(self, *args, **kwargs):
        try:
            self.do_request(*args, **kwargs)
        except Exception:
            logger.exception('requesting labels')

    def push_thread(self, account) -> None:
        assert not DISABLE_INTEGRATION

        account_data = self._accounts.get(account, None)
        if not account_data:
            raise Exception('Account {} not loaded'.format(account))
        wallet_id = account_data[2]
        bundle = {"labels": [],
                "walletId": wallet_id,
                "walletNonce": self.get_nonce(account)}
        # TODO(rt12) BACKLOG there is no account.labels any more. IT needs to iterate over
        # transaction and keyinstance labels.
        for key, value in account.labels.items():
            try:
                encoded_key = self.encode(account, key)
                encoded_value = self.encode(account, value)
            except Exception:
                logger.error('cannot encode %r %r', key, value)
                continue
            bundle["labels"].append({'encryptedLabel': encoded_value,
                                    'externalId': encoded_key})
        self.do_request("POST", "/labels", True, bundle)

    def pull_thread(self, account: AbstractAccount, force: bool) -> Optional[Any]:
        account_data = self._accounts.get(account, None)
        if not account_data:
            raise Exception('Account {} not loaded'.format(account))

        wallet_id = account_data[2]
        nonce = 1 if force else self.get_nonce(account) - 1
        logger.debug(f"asking for labels since nonce {nonce}")
        response = self.do_request("GET", ("/labels/since/%d/for/%s" % (nonce, wallet_id) ))
        if response["labels"] is None:
            logger.debug('no new labels')
            return
        result = {}
        for label in response["labels"]:
            try:
                key = self.decode(account, label["externalId"])
                value = self.decode(account, label["encryptedLabel"])
            except Exception:
                continue
            try:
                json.dumps(key)
                json.dumps(value)
            except Exception:
                logger.error(f'no json {key}')
                continue
            result[key] = value

        logger.info(f"received {len(result):,d} labels")

        updates = {}
        for key, value in result.items():
            # TODO(rt12) BACKLOG there is no account.labels any more.
            if force or not account.labels.get(key):
                updates[key] = value

        if DISABLE_INTEGRATION:
            return updates

        if len(updates):
            # TODO(rt12) BACKLOG there is no account.put or account storage at this time, or
            # even `account.labels`.
            account.labels.update(updates)
            # do not write to disk because we're in a daemon thread. The handed off writing to
            # the sqlite writer thread would achieve this.
            account.put('labels', account.labels)
        self.set_nonce(account, response["nonce"] + 1)
        self.on_pulled(account, updates)

    def pull_thread_safe(self, account: AbstractAccount, force: bool) -> None:
        try:
            self.pull_thread(account, force)
        except Exception as e:
            logger.exception('could not retrieve labels')

    def start_account(self, account: AbstractAccount) -> None:
        nonce = self.get_nonce(account)
        logger.debug("Account %s nonce is %s", account.name(), nonce)
        mpk = ''.join(sorted(account.get_master_public_keys()))
        if not mpk:
            return
        mpk = mpk.encode('ascii')
        password = hashlib.sha1(mpk).hexdigest()[:32].encode('ascii')
        iv = hashlib.sha256(password).digest()[:16]
        wallet_id = hashlib.sha256(mpk).hexdigest()
        self._accounts[account] = (password, iv, wallet_id)

        if DISABLE_INTEGRATION:
            return

        # If there is an auth token we can try to actually start syncing
        t = threading.Thread(target=self.pull_thread_safe, args=(account, False))
        t.setDaemon(True)
        t.start()

    def stop_account(self, account: AbstractAccount) -> None:
        self._accounts.pop(account, None)

    def on_enabled_changed(self) -> None:
        if label_sync.is_enabled():
            for window in app_state.app.windows:
                self.window_opened(window)
        else:
            for window in app_state.app.windows:
                self.window_closed(window)

    def window_opened(self, window):
        if label_sync.is_enabled():
            app_state.app.labels_changed_signal.connect(window.update_tabs)
            for account in window._wallet.get_accounts():
                self.start_account(account)

    def window_closed(self, window):
        for account in window._wallet.get_accounts():
            self.stop_account(account)

    def settings_widget(self, *args):
        return EnterButton(_('Export'), partial(self.settings_dialog, *args))

    def threaded_button(self, text, dialog, func, *args):
        def on_clicked(_checked):
            self.run_in_thread(dialog, button, func, *args)
        button = QPushButton(text)
        button.clicked.connect(on_clicked)
        return button

    def settings_dialog(self, prefs_window, account: AbstractAccount):
        d = WindowModalDialog(prefs_window, _("Label Settings"))
        form = FormSectionWidget()
        form.add_title(_("Label sync options"))

        if not DISABLE_INTEGRATION:
            upload = self.threaded_button("Force upload", d, self.push_thread, account)
            form.add_row(_("Upload labels"), upload)
        download = self.threaded_button("Force download", d, self.pull_thread, account, True)
        form.add_row(_("Export labels"), download)

        label = FramedTextWidget(_("The label sync services are no longer supported. However, "
            "ElectrumSV will still allow users to download and export their existing labels. These "
            "exported label files can then be imported, and any entries they have which can be "
            "matched to wallet contents may be added to the appropriate record."))

        vbox = QVBoxLayout(d)
        vbox.addWidget(label)
        vbox.addWidget(form)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(OkButton(d)))
        return bool(d.exec_())

    def on_pulled(self, account: AbstractAccount, updates: Any) -> None:
        app_state.app.labels_changed_signal.emit(account._wallet.get_storage_path(),
            account.get_id(), updates)

    def on_exception(self, dialog, exception):
        if not isinstance(exception, UserCancelled):
            logger.exception("")
            d = QMessageBox(QMessageBox.Warning, dialog, _('Error'), str(exception))
            d.setWindowModality(Qt.WindowModal)
            d.exec_()

    def run_in_thread(self, dialog, button, func, *args) -> Any:
        def on_done(future):
            button.setEnabled(True)
            try:
                data = future.result()
            except Exception as exc:
                self.on_exception(dialog, exc)
            else:
                if DISABLE_INTEGRATION:
                    if data is None:
                        dialog.show_message(_("No labels were present."))
                    else:
                        filename = 'electrumsv_labelsync_labels.json'
                        directory = os.path.expanduser('~')
                        path = os.path.join(directory, filename)
                        filename, __ = QFileDialog.getSaveFileName(dialog,
                            _('Enter a filename for the copy of your labels'), path, "*.json")
                        if not filename:
                            return
                        json_text = json.dumps(data)
                        with open(filename, "w") as f:
                            f.write(json_text)
                else:
                    dialog.show_message(_("Your labels have been synchronised."))

        button.setEnabled(False)
        app_state.app.run_in_thread(func, *args, on_done=on_done)
