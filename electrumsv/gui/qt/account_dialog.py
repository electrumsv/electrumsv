# Required in 3.9 to allow `ProxyType[ElectrumWindow]` generic form to execute and not just pass
# typing checks.
from __future__ import annotations
from typing import cast, Optional
from weakref import ProxyType

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QComboBox, QDialog, QLabel, QLineEdit, QSizePolicy, QSpacerItem, \
    QVBoxLayout, QWidget

from ...constants import ACCOUNT_SCRIPT_TYPES, DerivationType, KeystoreType, ScriptType
from ...i18n import _
from ...keystore import Hardware_KeyStore, Multisig_KeyStore, SinglesigKeyStoreTypes
from ...networks import Net
from ...wallet import Wallet

from .cosigners_view import CosignerState, CosignerList
from .main_window import ElectrumWindow
from .qrtextedit import ShowQRTextEdit
from .util import Buttons, CloseButton, FormSectionWidget


class AccountDialog(QDialog):
    _list: Optional[CosignerList] = None

    def __init__(self, main_window: ProxyType[ElectrumWindow], wallet: Wallet, account_id: int,
            parent: QWidget) -> None:
        super().__init__(parent, Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint))

        assert type(main_window) is ProxyType
        self._main_window = main_window
        self._wallet = wallet

        self._account = account = self._wallet.get_account(account_id)
        assert account is not None
        keystore = account.get_keystore()

        self.setWindowTitle(_("Account Information"))

        vbox = QVBoxLayout()
        # Ensure the size of the dialog is hard fixed to the space used by the widgets.
        vbox.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        # The fixed size constraint leaves no way to ensure a minimum width, so we use a spacer.
        vbox.addSpacerItem(QSpacerItem(600, 1))

        self._form = form = FormSectionWidget()

        name_widget = QLineEdit()
        name_widget.setText(account.display_name())
        name_widget.setReadOnly(True)
        form.add_row(_("Account name"), name_widget, True)

        form.add_row(_("Account type"), QLabel(account.type().value))
        if keystore is not None:
            form.add_row(_("Keystore type"), QLabel(keystore.type().value))

        #######

        if keystore is not None and keystore.type() == KeystoreType.HARDWARE:
            hkeystore = cast(Hardware_KeyStore, keystore)
            form.add_row(_("Derivation path"), QLabel(hkeystore.derivation))

        script_type_combo = QComboBox()

        def update_script_types() -> None:
            assert account is not None
            default_script_type = account.get_default_script_type()
            combo_items = [ v.name for v in ACCOUNT_SCRIPT_TYPES[account.type()] ]

            script_type_combo.clear()
            script_type_combo.addItems(combo_items)
            script_type_combo.setCurrentIndex(script_type_combo.findText(default_script_type.name))

        def on_script_type_change(_index: int) -> None:
            assert account is not None
            script_type_name = script_type_combo.currentText()
            new_script_type = getattr(ScriptType, script_type_name)
            current_script_type = account.get_default_script_type()
            if current_script_type != new_script_type:
                account.set_default_script_type(new_script_type)

                view = self._main_window.get_receive_view(account.get_id())
                view.update_script_type(new_script_type)

        update_script_types()
        script_type_combo.currentIndexChanged.connect(on_script_type_change)

        # NOTE(warning) We explicitly do not allow accumulator multi-signature because it is an
        # experimental option and requires some form of testing. This is the reason we do not
        # allow changing the script type at this time. If it is enabled for some reason,
        # accumulator multi-signature should be excluded UNLESS it has been tested sufficiently.
        script_type_combo.setEnabled(not Net.is_mainnet())
        form.add_row(_("Script type"), script_type_combo)

        vbox.addWidget(form)

        add_stretch = True
        if keystore is not None:
            if keystore.derivation_type == DerivationType.ELECTRUM_MULTISIG:
                mkeystore = cast(Multisig_KeyStore, keystore)
                multisig_form = FormSectionWidget()
                multisig_form.add_title("Multi-signature properties")
                multisig_form.add_row(_("Number of cosigners"), QLabel(str(mkeystore.n)))
                multisig_form.add_row(_("Number of signatures required"), QLabel(str(mkeystore.m)))
                vbox.addWidget(multisig_form)

                self._list = list = CosignerList(self._main_window, create=False)
                list.setMinimumHeight(350)
                for i, keystore in enumerate(account.get_keystores()):
                    state = CosignerState(i, cast(SinglesigKeyStoreTypes, keystore))
                    list.add_state(state)
                vbox.addWidget(list, 1)
                add_stretch = False
            elif account.is_deterministic():
                mpk_list = account.get_master_public_keys()
                mpk_text = ShowQRTextEdit()
                mpk_text.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Fixed)
                mpk_text.addCopyButton()
                mpk_text.setText(mpk_list[0])
                mpk_text.repaint()   # macOS hack for Electrum #4777
                form.add_row(_("Master public key"), mpk_text)
        if add_stretch:
            vbox.addStretch(1)

        buttons = Buttons(CloseButton(self))
        self._buttons = buttons

        vbox.addLayout(self._buttons)
        self.setLayout(vbox)

