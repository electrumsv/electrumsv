#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

from typing import List, Optional

from PyQt5.QtWidgets import QVBoxLayout, QLabel

from electrumsv.bitcoin import script_template_to_string
from electrumsv.i18n import _

from .main_window import ElectrumWindow
from .util import WindowModalDialog, ButtonsLineEdit, ColorScheme, Buttons, CloseButton
from .history_list import HistoryList
from .qrtextedit import ShowQRTextEdit


class KeyDialog(WindowModalDialog):
    def __init__(self, main_window: ElectrumWindow, account_id: int, key_id: int) -> None:
        WindowModalDialog.__init__(self, main_window, _("Key"))
        self._account_id = account_id
        self._key_id = key_id
        self._main_window = main_window
        self._account = main_window._wallet.get_account(account_id)
        self._config = main_window.config
        self._app = main_window.app
        self._saved = True

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Address:")))
        self._key_edit = ButtonsLineEdit()
        self._key_edit.addCopyButton(self._app)
        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self._key_edit.addButton(icon, self.show_qr, _("Show QR Code"))
        self._key_edit.setReadOnly(True)
        vbox.addWidget(self._key_edit)
        self.update_key()

        pubkeys = self._account.get_public_keys_for_id(key_id)
        if pubkeys:
            vbox.addWidget(QLabel(_("Public keys") + ':'))
            for pubkey in pubkeys:
                pubkey_e = ButtonsLineEdit(pubkey.to_hex())
                pubkey_e.addCopyButton(self._app)
                vbox.addWidget(pubkey_e)

        payment_template = self._account.get_script_template_for_id(key_id)
        vbox.addWidget(QLabel(_("Payment script") + ':'))
        redeem_e = ShowQRTextEdit(text=payment_template.to_script_bytes().hex())
        redeem_e.addCopyButton(self._app)
        vbox.addWidget(redeem_e)

        vbox.addWidget(QLabel(_("History")))
        self._history_list = HistoryList(self._main_window, self._main_window)
        self._history_list._on_account_change(self._account_id, self._account)
        self._history_list.get_domain = self.get_domain
        vbox.addWidget(self._history_list)

        vbox.addLayout(Buttons(CloseButton(self)))
        self._history_list.update()

        # connect slots so the embedded history list gets updated whenever the history changes
        main_window.history_updated_signal.connect(self._history_list.update)
        main_window.network_signal.connect(self._on_transaction_verified)

    def _on_transaction_verified(self, event: str, args) -> None:
        if event == 'verified':
            self._history_list.update_tx_item(*args)

    def update_key(self) -> None:
        script_template = self._account.get_script_template_for_id(self._key_id)
        if script_template is not None:
            text = script_template_to_string(script_template)
            self._key_edit.setText(text)

    def get_domain(self) -> Optional[List[int]]:
        return [self._key_id]

    def show_qr(self) -> None:
        script_template = self._account.get_script_template_for_id(self._key_id)
        if script_template is not None:
            text = script_template_to_string(script_template)
            try:
                self._main_window.show_qrcode(text, 'Key script', parent=self)
            except Exception as e:
                self.show_message(str(e))
