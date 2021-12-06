# Open BSV License version 4
#
# Copyright (c) 2021 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Required in 3.9 to allow `ProxyType[ElectrumWindow]` generic form to execute and not just pass
# typing checks.
from __future__ import annotations
from typing import cast, Union
from weakref import ProxyType

from bitcoinx import bip32_key_from_string, BIP39Mnemonic, ElectrumMnemonic, Wordlists

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QLabel, QVBoxLayout, QWidget

from ...constants import DerivationType, SEED_PREFIX
from ...i18n import _
from ...keystore import BIP32_KeyStore, Deterministic_KeyStore, KeyStore

from .main_window import ElectrumWindow
from .qrtextedit import ShowQRTextEdit
from .util import Buttons, CloseButton, FormSectionWidget


class SecuredDataDialog(QDialog):
    def __init__(self, main_window: Union[ElectrumWindow, ProxyType[ElectrumWindow]],
            parent: QWidget, keystore: KeyStore, password: str) -> None:
        super().__init__(parent, Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint))

        self._main_window = main_window

        self.setWindowTitle(_("Secured Account Data"))
        self.setMinimumSize(500, 200)

        vbox = QVBoxLayout()
        self._form = form = FormSectionWidget()

        assert keystore.derivation_type in (DerivationType.BIP32, DerivationType.ELECTRUM_OLD)
        deterministic_keystore = cast(Deterministic_KeyStore, keystore)

        self._seed_edit = None
        if deterministic_keystore.seed is not None:
            seed_text = deterministic_keystore.get_seed(password)

            seed_type_text = _("Unknown")
            if keystore.derivation_type == DerivationType.BIP32:
                seed_type_text = _("BIP32")

                possible_seed_types = []
                if ElectrumMnemonic.is_valid_new(seed_text, SEED_PREFIX):
                    possible_seed_types.append(_("Electrum"))

                is_bip39_valid = False
                try:
                    is_bip39_valid = BIP39Mnemonic.is_valid(seed_text,
                        Wordlists.bip39_wordlist("english.txt"))
                except (ValueError, BIP39Mnemonic.BadWords):
                    import traceback
                    traceback.print_exc()
                    pass
                else:
                    if is_bip39_valid:
                        possible_seed_types.append(_("BIP39"))

                if len(possible_seed_types) == 1:
                    seed_type_text += f" ({possible_seed_types[0]})"
                else:
                    seed_type_text += f" (either {' or '.join(possible_seed_types)})"
            elif keystore.derivation_type == DerivationType.ELECTRUM_OLD:
                seed_type_text = _("BIP32 (Old-style Electrum)")
            form.add_row(_("Seed type"), QLabel(seed_type_text))

            seed_edit = ShowQRTextEdit()
            seed_edit.setFixedHeight(80)
            seed_edit.addCopyButton()
            seed_edit.setText(seed_text)
            form.add_row(_("Seed phrase"), seed_edit)
            self._seed_edit = seed_edit

        # Ambiguous if empty string or None.
        passphrase_widget: QWidget
        if deterministic_keystore.passphrase:
            passphrase_text = deterministic_keystore.get_passphrase(password)

            passphrase_edit = ShowQRTextEdit()
            passphrase_edit.setFixedHeight(80)
            passphrase_edit.addCopyButton()
            passphrase_edit.setText(passphrase_text)
            passphrase_widget = passphrase_edit
        else:
            passphrase_widget = QLabel(_("None"))
        form.add_row(_("Passphrase"), passphrase_widget)

        if keystore.derivation_type == DerivationType.BIP32:
            bip32_keystore = cast(BIP32_KeyStore, keystore)
            if bip32_keystore.xprv is not None:
                xprv_text = bip32_keystore.get_master_private_key(password)
                private_key = bip32_key_from_string(xprv_text)

                xprv_edit = ShowQRTextEdit()
                xprv_edit.setFixedHeight(80)
                xprv_edit.addCopyButton()
                xprv_edit.setText(private_key.to_extended_key_string())
                form.add_row(_("Master private key"), xprv_edit)

        vbox.addWidget(form)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)
