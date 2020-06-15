# The Open BSV license.
#
# Copyright © 2020 Bitcoin Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
#   1. The above copyright notice and this permission notice shall be included
#      in all copies or substantial portions of the Software.
#   2. The Software, and any software that is derived from the Software or parts
#      thereof, can only be used on the Bitcoin SV blockchains. The Bitcoin SV
#      blockchains are defined, for purposes of this license, as the Bitcoin
#      blockchain containing block height #556767 with the hash
#      “000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b” and
#      the test blockchains that are supported by the unmodified Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from bitcoinx import bip32_key_from_string

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QLabel, QVBoxLayout, QWidget

from electrumsv.bitcoin import is_new_seed
from electrumsv.constants import DerivationType
from electrumsv.i18n import _
from electrumsv.keystore import bip39_is_checksum_valid, KeyStore

from .main_window import ElectrumWindow
from .qrtextedit import ShowQRTextEdit
from .util import Buttons, CloseButton, FormSectionWidget


class SecuredDataDialog(QDialog):
    def __init__(self, main_window: ElectrumWindow, parent: QWidget, keystore: KeyStore,
            password: str) -> None:
        super().__init__(parent, Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)

        self._main_window = main_window

        self.setWindowTitle(_("Secured Account Data"))
        self.setMinimumSize(500, 200)

        vbox = QVBoxLayout()
        self._form = form = FormSectionWidget(minimum_label_width=120)

        assert keystore.derivation_type in (DerivationType.BIP32, DerivationType.ELECTRUM_OLD)

        self._seed_edit = None
        if keystore.seed is not None:
            seed_text = keystore.get_seed(password)

            seed_type_text = _("Unknown")
            if keystore.derivation_type == DerivationType.BIP32:
                if is_new_seed(seed_text):
                    seed_type_text = _("Electrum")
                is_checksum_valid, is_wordlist_valid = bip39_is_checksum_valid(seed_text)
                if is_checksum_valid and is_wordlist_valid:
                    seed_type_text = _("BIP39")
            elif keystore.derivation_type == DerivationType.ELECTRUM_OLD:
                seed_type_text = _("Old-style Electrum")
            form.add_row(_("Seed type"), QLabel(seed_type_text))

            seed_edit = ShowQRTextEdit(self)
            seed_edit.setFixedHeight(80)
            seed_edit.addCopyButton(self._main_window.app)
            seed_edit.setText(seed_text)
            form.add_row(_("Seed phrase"), seed_edit, True)
            self._seed_edit = seed_edit

        # Ambiguous if empty string or None.
        passphrase_widget: QWidget
        if keystore.passphrase:
            passphrase_text = keystore.get_passphrase(password)

            passphrase_edit = ShowQRTextEdit(self)
            passphrase_edit.setFixedHeight(80)
            passphrase_edit.addCopyButton(self._main_window.app)
            passphrase_edit.setText(passphrase_text)
            passphrase_widget = passphrase_edit
        else:
            passphrase_widget = QLabel(_("None"))
        form.add_row(_("Passphrase"), passphrase_widget, True)

        if keystore.derivation_type == DerivationType.BIP32:
            if keystore.xprv is not None:
                xprv_text = keystore.get_master_private_key(password)
                private_key = bip32_key_from_string(xprv_text)

                xprv_edit = ShowQRTextEdit(self)
                xprv_edit.setFixedHeight(80)
                xprv_edit.addCopyButton(self._main_window.app)
                xprv_edit.setText(private_key.to_extended_key_string())
                form.add_row(_("Master private key"), xprv_edit, True)

        vbox.addWidget(form)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)
