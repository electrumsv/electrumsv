# Required in 3.9 to allow `ProxyType[ElectrumWindow]` generic form to execute and not just pass
# typing checks.
from __future__ import annotations
from typing import cast, Union
from weakref import ProxyType

from bitcoinx import bip32_key_from_string, BIP39Mnemonic, ElectrumMnemonic, Wordlists

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QLabel, QVBoxLayout, QWidget

from ...constants import DerivationType, SEED_PREFIX_ACCOUNT, SEED_PREFIX_WALLET
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
                if ElectrumMnemonic.is_valid_new(seed_text, SEED_PREFIX_ACCOUNT):
                    possible_seed_types.append(_("Electrum (single account)"))
                if ElectrumMnemonic.is_valid_new(seed_text, SEED_PREFIX_WALLET):
                    possible_seed_types.append(_("Electrum (multi-account)"))

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
