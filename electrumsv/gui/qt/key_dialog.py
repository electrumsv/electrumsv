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

from PyQt5.QtWidgets import QComboBox, QLabel, QVBoxLayout

from ...bitcoin import script_template_to_string
from ...constants import ACCOUNT_SCRIPT_TYPES, ScriptType
from ...i18n import _
from ...wallet_database.types import KeyDataTypes

from .main_window import ElectrumWindow
from .util import WindowModalDialog, ButtonsLineEdit, ColorScheme, Buttons, CloseButton
from .history_list import HistoryList
from .qrtextedit import ShowQRTextEdit


class KeyDialog(WindowModalDialog):
    def __init__(self, main_window: ElectrumWindow, account_id: int, key_data: KeyDataTypes,
            used_script_type: ScriptType) -> None:
        WindowModalDialog.__init__(self, main_window, _("Key"))

        self._account = main_window._wallet.get_account(account_id)
        assert self._account is not None

        # Detect and prevent the integer values from being given.
        assert isinstance(used_script_type, ScriptType)
        script_type = used_script_type
        if script_type == ScriptType.NONE:
            script_type = self._account.get_default_script_type()
            # This will most likely just be imported address wallets. There's a larger discussion
            # about what script types they hold, whether it is one or any. For now we assume any
            # but do not guarantee it is officially supported.
            if script_type == ScriptType.NONE:
                script_type = ScriptType.P2PKH

        self._account_id = account_id
        self._key_data = key_data
        self._script_type = script_type
        self._main_window = main_window
        self._config = main_window.config
        self._app = main_window.app
        self._saved = True

        self.setMinimumWidth(700)
        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Script type:")))
        self._script_type_combo = QComboBox()
        self._script_type_combo.clear()
        self._script_type_combo.addItems(
            [ v.name for v in ACCOUNT_SCRIPT_TYPES[self._account.type()] ])
        vbox.addWidget(self._script_type_combo)

        vbox.addWidget(QLabel(_("Address:")))
        self._key_edit = ButtonsLineEdit()
        self._key_edit.addCopyButton(self._app)
        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self._key_edit.addButton(icon, self.show_qr, _("Show QR Code"))
        self._key_edit.setReadOnly(True)
        vbox.addWidget(self._key_edit)

        pubkeys = self._account.get_public_keys_for_key_data(key_data)
        if pubkeys:
            vbox.addWidget(QLabel(_("Public keys") + ':'))
            for pubkey in pubkeys:
                pubkey_e = ButtonsLineEdit(pubkey.to_hex())
                pubkey_e.addCopyButton(self._app)
                vbox.addWidget(pubkey_e)

        vbox.addWidget(QLabel(_("Payment script") + ':'))
        self._script_edit = ShowQRTextEdit()
        self._script_edit.addCopyButton(self._app)
        vbox.addWidget(self._script_edit)

        self._update_script_type(script_type)
        self._script_type_combo.currentIndexChanged.connect(self._event_script_type_combo_changed)
        if used_script_type != ScriptType.NONE:
            self._script_type_combo.setEnabled(False)

        # NOTE(rt12) This history is for all the entries for the key, not just the
        vbox.addWidget(QLabel(_("History")))
        self._history_list = HistoryList(self._main_window, self._main_window)
        self._history_list._on_account_change(self._account_id, self._account)
        self._history_list.get_domain = self.get_domain
        vbox.addWidget(self._history_list)

        vbox.addLayout(Buttons(CloseButton(self)))
        self._history_list.update()

        # connect slots so the embedded history list gets updated whenever the history changes
        main_window.history_updated_signal.connect(self._history_list.update)
        main_window.transaction_verified_signal.connect(self._on_transaction_verified)

    def _update_script_type(self, script_type: ScriptType) -> None:
        self._script_type = script_type
        self._script_type_combo.setCurrentIndex(
            self._script_type_combo.findText(script_type.name))
        self._update_address()
        self._update_script()

    def _event_script_type_combo_changed(self) -> None:
        script_type_name = self._script_type_combo.currentText()
        script_type = getattr(ScriptType, script_type_name)
        self._update_script_type(script_type)

    def _on_transaction_verified(self, tx_hash: bytes, block_height: int, block_position: int,
            confirmations: int, timestamp: int) -> None:
        self._history_list.update_tx_item(tx_hash, block_height, block_position, confirmations,
            timestamp)

    def _update_address(self) -> None:
        script_template = self._account.get_script_template_for_key_data(self._key_data,
            self._script_type)
        text = ""
        if script_template is not None:
            text = script_template_to_string(script_template)
        self._key_edit.setText(text)

    def _update_script(self) -> None:
        payment_template = self._account.get_script_template_for_key_data(self._key_data,
            self._script_type)
        self._script_edit.setText(payment_template.to_script_bytes().hex())

    def get_domain(self) -> Optional[List[int]]:
        """
        This filters the history list for whatever key instances are returned below.
        """
        return [ self._key_data.keyinstance_id ]

    def show_qr(self) -> None:
        script_template = self._account.get_script_template_for_key_data(self._key_data,
            self._script_type)
        if script_template is not None:
            text = script_template_to_string(script_template)
            try:
                self._main_window.show_qrcode(text, 'Key script', parent=self)
            except Exception as e:
                self.show_message(str(e))
