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

import concurrent
import enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from bitcoinx import (Address, Base58Error, bip32_decompose_chain_string,
    bip32_key_from_string, PrivateKey, P2SH_Address)

from PyQt5.QtCore import QObject, QSize, Qt
from PyQt5.QtGui import QBrush, QColor, QPainter, QPalette, QPen, QPixmap, QTextOption
from PyQt5.QtWidgets import (
    QCheckBox, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QProgressBar, QRadioButton, QSizePolicy, QSlider, QTextEdit,
    QVBoxLayout, QWidget, QWizard, QWizardPage
)

from electrumsv.app_state import app_state
from electrumsv.bitcoin import compose_chain_string, is_new_seed, is_old_seed
from electrumsv.constants import (DEFAULT_COSIGNER_COUNT, DerivationType, IntFlag,
    KeystoreTextType, MAXIMUM_COSIGNER_COUNT, ScriptType)
from electrumsv.device import DeviceInfo
from electrumsv.exceptions import UserCancelled
from electrumsv.i18n import _
from electrumsv.keystore import (bip39_is_checksum_valid, bip44_derivation_cointype, from_seed,
    instantiate_keystore_from_text, KeyStore, Multisig_KeyStore)
from electrumsv.logs import logs
from electrumsv.networks import Net
from electrumsv.storage import WalletStorage
from electrumsv.wallet import Wallet, instantiate_keystore

from .cosigners_view import CosignerState, CosignerList
from .main_window import ElectrumWindow
from .util import (ChoicesLayout, icon_path, MessageBox, MessageBoxMixin, protected, query_choice,
    read_QIcon)
from .wizard_common import BaseWizard, DEFAULT_WIZARD_FLAGS, WizardFlags, WizardFormSection


logger = logs.get_logger('wizard-account')

DeviceList = List[Tuple[str, DeviceInfo]]

PASSWORD_EXISTING_TEXT = _("Your wallet has a password, and you will need to provide that "
    "password in order to secure this account.")

NO_DEVICES_FOUND_TEXT = _("A scan has been unable to locate any connected hardware wallets. "
    "Once you have connected your hardware wallet, and if necessary turned it on, please "
    "press the 'Rescan' button to try again.") +"\n\n"+ _("If any problems were encountered "
    "during the scan, they will be displayed below. If there are no indications why your "
    "hardware wallet is not being found, press the 'Help' button for further direction.")

DEVICE_SETUP_ERROR_TEXT = _("The selected hardware wallet failed to complete it's setup "
    "process. If your hardware wallet has an application that needs to be running, please "
    "run it and then return to the previous page to rescan.") +"\n\n"+ _("If any problems "
    "were encountered during the setup attempt, they will be displayed below. If there are no "
    "indications why your hardware wallet is not being found, press the 'Help' button for further "
    "direction.")

DEVICE_SETUP_SUCCESS_TEXT = _("Your {} hardware wallet was both successfully detected and "
    "configured.") +"\n\n"+ _("In order to link the account to how the hardware wallet has been "
    "previously used, or specify how it should be used going forward, you need to provide a "
    "derivation path.") +"\n\n"+ _("If you are not sure what your derivation path is, leave "
    "this field unchanged.") + _("The default value of {} is the default derivation for "
    "{} wallets. This matches BTC usage and that of most other BSV wallet software. To match "
    "BCH wallet addresses use m/44'/145'/0'")


KeystoreMatchType = Union[str, Set[str]]


class AccountPage(enum.IntEnum):
    NONE = 0

    ADD_ACCOUNT_MENU = 100

    CREATE_MULTISIG_ACCOUNT = 300
    CREATE_MULTISIG_ACCOUNT_CUSTOM = 301
    CREATE_MULTISIG_ACCOUNT_COSIGNERS = 302

    IMPORT_ACCOUNT_FILE = 400
    IMPORT_ACCOUNT_TEXT = 405
    IMPORT_ACCOUNT_TEXT_CUSTOM = 410

    FIND_HARDWARE_WALLET = 500
    SETUP_HARDWARE_WALLET = 505

class KeyFlags(enum.IntEnum):
    NONE = 0
    CAN_BE_MULTISIG_READ_ONLY = 1 << 0
    CAN_BE_MULTISIG_WRITABLE = (1 << 1) | CAN_BE_MULTISIG_READ_ONLY

TextKeystoreTypeFlags = {
    KeystoreTextType.ADDRESSES: KeyFlags.NONE,
    KeystoreTextType.PRIVATE_KEYS: KeyFlags.NONE,
    KeystoreTextType.EXTENDED_PUBLIC_KEY: KeyFlags.CAN_BE_MULTISIG_READ_ONLY,
    KeystoreTextType.EXTENDED_PRIVATE_KEY: KeyFlags.CAN_BE_MULTISIG_WRITABLE,
    KeystoreTextType.BIP39_SEED_WORDS: KeyFlags.CAN_BE_MULTISIG_WRITABLE,
    KeystoreTextType.ELECTRUM_SEED_WORDS: KeyFlags.CAN_BE_MULTISIG_WRITABLE,
    KeystoreTextType.ELECTRUM_OLD_SEED_WORDS: KeyFlags.CAN_BE_MULTISIG_WRITABLE,
}

class ResultType(IntFlag):
    UNKNOWN = 0

    NEW = 1
    MULTISIG = 2
    IMPORTED = 3
    HARDWARE = 4


def request_password(parent: Optional[QWidget], storage: WalletStorage) -> Optional[str]:
    from .password_dialog import PasswordDialog
    d = PasswordDialog(parent, PASSWORD_EXISTING_TEXT, password_check_fn=storage.is_password_valid)
    d.setMaximumWidth(200)
    return d.run()



class AccountWizard(BaseWizard, MessageBoxMixin):
    HELP_DIRNAME = "account-wizard"

    _last_page_id: Optional[AccountPage] = None
    _selected_device: Optional[Tuple[str, DeviceInfo]] = None
    _keystore: Optional[KeyStore] = None
    _keystore_type = ResultType.UNKNOWN

    def __init__(self, main_window: ElectrumWindow,
            flags: WizardFlags=DEFAULT_WIZARD_FLAGS, parent: Optional[QWidget]=None) -> None:
        if parent is None:
            parent = main_window
        super().__init__(parent)

        self.flags = flags

        self._main_window = main_window
        self._wallet: Wallet = main_window._wallet

        self._text_import_type: Optional[KeystoreTextType] = None
        self._text_import_matches: Optional[KeystoreMatchType] = None

        self.set_subtitle("")
        self.setModal(True)
        self.setMinimumSize(600, 600)
        self.setOption(QWizard.HaveCustomButton1, True)
        self.button(QWizard.CustomButton1).setVisible(False)

        self.setPage(AccountPage.ADD_ACCOUNT_MENU, AddAccountWizardPage(self))
        self.setPage(AccountPage.IMPORT_ACCOUNT_TEXT, ImportWalletTextPage(self))
        self.setPage(AccountPage.IMPORT_ACCOUNT_TEXT_CUSTOM, ImportWalletTextCustomPage(self))
        self.setPage(AccountPage.CREATE_MULTISIG_ACCOUNT, CreateMultisigAccountPage(self))
        self.setPage(AccountPage.CREATE_MULTISIG_ACCOUNT_CUSTOM,
            CreateMultisigAccountCustomPage(self))
        self.setPage(AccountPage.CREATE_MULTISIG_ACCOUNT_COSIGNERS,
            MultisigAccountCosignerListPage(self))
        self.setPage(AccountPage.FIND_HARDWARE_WALLET, FindHardwareWalletAccountPage(self))
        self.setPage(AccountPage.SETUP_HARDWARE_WALLET, SetupHardwareWalletAccountPage(self))

        self.setStartId(AccountPage.ADD_ACCOUNT_MENU)

    # Used by hardware wallets.
    def query_choice(self, msg: str, choices: Iterable[str]) -> Optional[int]:
        return query_choice(self, msg, choices)

    def set_subtitle(self, subtitle: str) -> None:
        suffix = f" - {subtitle}" if len(subtitle) else ""
        self.setWindowTitle(f'ElectrumSV{suffix}')

    def set_selected_device(self, device: Optional[Tuple[str, DeviceInfo]]) -> None:
        self._selected_device = device

    def get_selected_device(self) -> Optional[Tuple[str, DeviceInfo]]:
        return self._selected_device

    def get_main_window(self) -> ElectrumWindow:
        "For page access to the parent window."
        return self._main_window

    def get_wallet(self) -> Wallet:
        "For page access to any wallet."
        return self._wallet

    def set_text_import_matches(self, text_type: KeystoreTextType,
            text_matches: KeystoreMatchType) -> None:
        self._text_import_type = text_type
        self._text_import_matches = text_matches

    def get_text_import_type(self) -> Optional[KeystoreTextType]:
        return self._text_import_type

    def get_text_import_matches(self) -> Optional[KeystoreMatchType]:
        return self._text_import_matches

    def has_result(self) -> bool:
        return self._keystore_type != ResultType.UNKNOWN

    def get_keystore(self) -> KeyStore:
        return self._keystore

    def set_keystore_result(self, result_type: ResultType, keystore: Optional[KeyStore]) -> None:
        self._keystore_type = result_type
        self._keystore = keystore

        if keystore is None:
            return

        # For now, all other result types are expected to be collected by the invoking logic of
        # this account wizard instance.
        if self.flags & WizardFlags.ACCOUNT_RESULT:
            self._wallet.create_account_from_keystore(keystore)

    def set_text_entry_account_result(self, result_type: ResultType, text_type: KeystoreTextType,
            script_type: ScriptType, text_matches: KeystoreMatchType,
            password: Optional[str]) -> None:
        self._keystore_type = result_type

        if self.flags & WizardFlags.ACCOUNT_RESULT:
            assert password is not None
            self._wallet.create_account_from_text_entries(text_type, script_type, text_matches,
                password)
        else:
            raise NotImplementedError("Invalid attempt to generate keyless keystore data")



class AddAccountWizardPage(QWizardPage):
    def __init__(self, wizard: AccountWizard) -> None:
        super().__init__(wizard)

        self.setTitle(_("Account Types"))
        self.setFinalPage(False)

        page = self
        class ListWidget(QListWidget):
            def keyPressEvent(self, event):
                key = event.key()
                if key == Qt.Key_Return or key == Qt.Key_Enter:
                    page._event_key_press_selection()
                else:
                    super(ListWidget, self).keyPressEvent(event)

        option_list = self._option_list = ListWidget()
        option_list.setIconSize(QSize(30, 30))
        option_list.setStyleSheet("""
            QListWidget {
                background-color: white;
            }
            QListWidget::item:selected {
                background-color: white;
                color: black;
            }
        """)

        for entry in self._get_entries():
            if not entry.get("enabled", True):
                continue
            if wizard.flags & entry.get("mode_mask", WizardFlags.NONE) == WizardFlags.NONE:
                continue
            list_item = QListWidgetItem()
            list_item.setSizeHint(QSize(40, 40))
            list_item.setIcon(read_QIcon(entry['icon_filename']))
            list_item.setText(entry['description'])
            list_item.setData(Qt.UserRole, entry)
            option_list.addItem(list_item)

        option_list.setMaximumWidth(400)
        option_list.setWordWrap(True)

        option_detail = self._option_detail = QLabel()
        option_detail.setMinimumWidth(200)
        option_detail.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        option_detail.setTextFormat(Qt.RichText)
        option_detail.setWordWrap(True)
        option_detail.setOpenExternalLinks(True)
        option_detail.setText(self._get_entry_detail())

        layout = QHBoxLayout()
        # It looks tidier with more separation between the list and the detail pane.
        layout.setSpacing(15)
        layout.addWidget(option_list)
        layout.addWidget(option_detail)
        self.setLayout(layout)

        option_list.itemSelectionChanged.connect(self._event_selection_changed)
        option_list.itemDoubleClicked.connect(self._event_double_click_item)

    # Qt default QWizardPage event when page is entered.
    def on_enter(self) -> None:
        wizard: AccountWizard = self.wizard()
        # Clear the result. This shouldn't be needed except in the case of an unexpected error
        # where the wizard does not exit and the user returns back to this page.
        wizard.set_keystore_result(ResultType.UNKNOWN, None)
        # The click event arrives after the standard wizard next page handling. We use it to
        # perform actions that finish on the current page.
        next_button = wizard.button(QWizard.NextButton)
        next_button.clicked.connect(self._event_click_next_button)
        self._restore_button_text = wizard.buttonText(QWizard.NextButton)

    def on_leave(self) -> None:
        wizard: AccountWizard = self.wizard()
        next_button = wizard.button(QWizard.NextButton)
        next_button.clicked.disconnect(self._event_click_next_button)
        wizard.setButtonText(QWizard.NextButton, self._restore_button_text)

    # Qt method called to determine if 'Next' or 'Finish' should be enabled or disabled.
    # Overriding this requires us to emit the 'completeChanges' signal where applicable.
    def isComplete(self) -> bool:
        return len(self._option_list.selectedItems()) > 0

    # Qt method called when 'Next' or 'Finish' is clicked for last-minute validation.
    def validatePage(self) -> bool:
        if self.isComplete():
            next_page_id = self.nextId()
            if next_page_id != AccountPage.NONE:
                return True
            # In the case we manually accept for a no-page option, check we have the result.
            wizard: AccountWizard = self.wizard()
            if wizard.has_result():
                return True
        return False

    # Qt method called to get the Id of the next page.
    def nextId(self) -> int:
        items = self._option_list.selectedItems()
        if len(items) > 0:
            return items[0].data(Qt.UserRole).get("page", AccountPage.NONE)
        return AccountPage.NONE

    def _event_selection_changed(self) -> None:
        wizard: AccountWizard = self.wizard()
        items = self._option_list.selectedItems()
        if len(items) > 0:
            entry = items[0].data(Qt.UserRole)
            button_text = entry.get("button_text", self._restore_button_text)
            self._option_detail.setText(self._get_entry_detail(entry))
        else:
            button_text = self._restore_button_text
            self._option_detail.setText(self._get_entry_detail())
        wizard.setButtonText(QWizard.NextButton, button_text)
        self.completeChanged.emit()

    def _event_key_press_selection(self) -> None:
        items = self._option_list.selectedItems()
        if len(items):
            self._select_item(items[0])

    def _event_double_click_item(self, item: QListWidgetItem) -> None:
        self._option_list.setCurrentItem(item)
        self._select_item(item)

    def _event_click_next_button(self) -> None:
        items = self._option_list.selectedItems()
        if len(items):
            self._select_item(items[0], direct_only=True)

    def _select_item(self, item: QListWidgetItem, direct_only: bool=False) -> None:
        entry = item.data(Qt.UserRole)
        page = entry.get("page", AccountPage.NONE)
        if page == AccountPage.NONE:
            # This is something that either finishes on this page, or requires custom handling
            # before manually invoking a move to the next page.
            entry['handler']()
        elif not direct_only:
            self.completeChanged.emit()
            self.wizard().next()

    def _create_new_account(self) -> None:
        wizard: AccountWizard = self.wizard()
        wallet_storage = wizard.get_main_window()._wallet.get_storage()
        password = request_password(self, wallet_storage)
        if password is None:
            return

        from electrumsv import mnemonic
        seed_phrase = mnemonic.Mnemonic('en').make_seed('standard')
        keystore = from_seed(seed_phrase, '')
        keystore.update_password(password)
        wizard.set_keystore_result(ResultType.NEW, keystore)
        wizard.accept()

    def _get_entry_detail(self, entry=None):
        title_start_html = "<b>"
        title_end_html = "</b>"
        if entry is None:
            title_start_html = title_end_html = ""
            entry = {
                'icon_filename': 'icons8-decision-80.png',
                'description': _("Select the way in which you want to add a new account "+
                    "from the options to the left."),
            }
        html = f"""
        <center>
            <img src='{icon_path(entry['icon_filename'])}' width=80 height=80 />
        </center>
        <p>
            {title_start_html}
            {entry['description']}
            {title_end_html}
        </p>
        """
        html += entry.get('long_description', '')
        return html

    def _get_entries(self):
        seed_phrase_html = ("<p>"+
            _("A seed phrase is a way of storing an account's private key. "+
              "Using it ElectrumSV can access the wallet's previous "+
              "payments, and send and receive the coins in the wallet.") +
            "</p>")

        original_wallet_html = ("<p>"+
            _("If the original wallet application a seed phrase came from is still being used to "+
              "access the given account, then it is not safe to access it in ElectrumSV "+
              "while this is the case.") +
            " %(extra)s"+
            "</p>")

        original_wallet_unsafe_html = original_wallet_html % {
            "extra": _("%(wallet_name)s is one of these applications. If you are still using it, "+
                       "it may get confused if you do more than watch, like sending and "+
                       "receiving coins using ElectrumSV."),
        }

        original_wallet_safe_html = original_wallet_html % {
            "extra": _("%(wallet_name)s however, works in a compatible way "+
                       "where it should be possible to use both it and "+
                       "ElectrumSV at the same time."),
        }

        return [
            {
                'page': AccountPage.NONE,
                'description': _("Standard"),
                'icon_filename': 'icons8-create-80.png',
                'long_description': _("If you want to create a brand new standard account in "
                    "ElectrumSV this is the option you want.") +"<br/><br/>"+ _("A "
                    "standard account is one where you are in control of all payments."),
                'button_text': _("Create"),
                'enabled': True,
                'mode_mask': WizardFlags.ALL_MODES,
                'handler': self._create_new_account,
            },
            {
                'page': AccountPage.CREATE_MULTISIG_ACCOUNT,
                'description': _("Multi-signature"),
                'icon_filename': 'icons8-group-task-80-blueui-active.png',
                'long_description': _("If you want to create a brand new multi-signature account "
                    "in ElectrumSV this is the option you want.") +"<br/><br/>"+ _("A "
                    "multi-signature account is one where more than one person is required to "
                    "approve each payment. This requires that the participants, or cosigners, "
                    "coordinate the signing of each payment."),
                'enabled': True,
                'mode_mask': WizardFlags.STANDARD_MODE,
            },
            {
                'page': AccountPage.IMPORT_ACCOUNT_FILE,
                'description': _("Import from file"),
                'icon_filename': 'icons8-document.svg',
                'long_description': _("..."),
                'enabled': False,
            },
            {
                'page': AccountPage.IMPORT_ACCOUNT_TEXT,
                'description': _("Import from text (any seed phrase, public keys, "+
                                 "private keys or addresses)"),
                'icon_filename': 'icons8-brain-80.png',
                'long_description': _("If you have some text to paste, or type in, and want "
                    "ElectrumSV to examine it and offer you some choices on how it can be "
                    "imported, this is the option you probably want."),
                'enabled': True,
                'mode_mask': WizardFlags.ALL_MODES,
            },
            {
                'page': AccountPage.FIND_HARDWARE_WALLET,
                'description': _("Import hardware wallet"),
                'icon_filename': 'icons8-usb-2-80-blueui-active.png',
                'enabled': True,
                'mode_mask': WizardFlags.ALL_MODES,
            },
        ]


class ImportWalletTextPage(QWizardPage):
    def __init__(self, wizard: AccountWizard) -> None:
        super().__init__(wizard)

        self.setTitle(_("Import Account From Text"))
        self.setFinalPage(True)

        self._next_page_id = -1
        self._checked_match_type: Optional[KeystoreTextType] = None
        self._matches: Dict[KeystoreTextType, KeystoreMatchType] = {}

        self.text_area = QTextEdit()
        self.text_area.textChanged.connect(self._on_text_changed)
        self.text_area.setAcceptRichText(False)
        self.text_area.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        self.text_area.setTabChangesFocus(True)

        self._label = QLabel(_("Please enter some text and any valid matches will be "
            "made available below.."))

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(self._label)
        hbox.addStretch(1)

        self._addresses_button = QRadioButton(_("Addresses"))
        self._privkeys_button = QRadioButton(_("Private keys"))
        self._xpub_button = QRadioButton(_("Extended public key"))
        self._xprv_button = QRadioButton(_("Extended private key"))
        self._bip39seed_button = QRadioButton(_("BIP39 seed words"))
        self._esvseed_button = QRadioButton(_("Electrum seed words"))
        self._esvoldseed_button = QRadioButton(_("Electrum old-style seed words"))

        for match_type, button in self._get_buttons(wizard):
            def make_check_callback(match_type: KeystoreTextType) -> Callable[[bool], None]:
                def on_button_check(checked: bool=False):
                    self._on_match_type_selected(match_type)
                return on_button_check
            button.clicked.connect(make_check_callback(match_type))

        # Simple logic for two columns of options.
        textbuttons_box = QGridLayout()
        button_entries = self._get_buttons(wizard)
        row_length = len(button_entries) // 2
        if len(button_entries) % 2 != 0:
            row_length += 1
        for button_index in range(len(button_entries)):
            button = button_entries[button_index][1]
            row_index = button_index % row_length
            column_index = button_index // row_length
            textbuttons_box.addWidget(button, row_index, column_index)
        texttype_box = QGroupBox()
        texttype_box.setFlat(True)
        texttype_box.setLayout(textbuttons_box)

        hbox2 = QHBoxLayout()
        hbox2.addStretch(1)
        hbox2.addWidget(texttype_box)
        hbox2.addStretch(1)

        layout = QVBoxLayout()
        layout.addWidget(self.text_area)
        layout.addLayout(hbox)
        layout.addLayout(hbox2)

        self.setLayout(layout)

    def _get_buttons(self, wizard: AccountWizard) -> List[Tuple[KeystoreTextType, QRadioButton]]:
        button_entries = [
            (KeystoreTextType.ADDRESSES, self._addresses_button),
            (KeystoreTextType.PRIVATE_KEYS, self._privkeys_button),
            (KeystoreTextType.EXTENDED_PUBLIC_KEY, self._xpub_button),
            (KeystoreTextType.EXTENDED_PRIVATE_KEY, self._xprv_button),
            (KeystoreTextType.BIP39_SEED_WORDS, self._bip39seed_button),
            (KeystoreTextType.ELECTRUM_SEED_WORDS, self._esvseed_button),
            (KeystoreTextType.ELECTRUM_OLD_SEED_WORDS, self._esvoldseed_button),
        ]
        if wizard.flags & WizardFlags.MULTISIG_MODE == WizardFlags.MULTISIG_MODE:
            entries = []
            for text_type, button in button_entries:
                key_flags = TextKeystoreTypeFlags[text_type]
                if key_flags == KeyFlags.NONE:
                    continue
                entries.append((text_type, button))
            return entries
        return button_entries

    def _set_matches(self, matches: Dict[KeystoreTextType, KeystoreMatchType]) -> None:
        self._checked_match_type = None
        self._matches = matches

        # These two types are expected to be the sole kind of match, but will have one or more
        # matches of that type.
        if KeystoreTextType.ADDRESSES in matches or KeystoreTextType.PRIVATE_KEYS in matches:
            if len(matches) > 1:
                matches.clear()

        wizard: AccountWizard = self.wizard()
        for match_type, button in self._get_buttons(wizard):
            if len(matches) == 1 and match_type in matches:
                self._checked_match_type = match_type
                button.setChecked(True)
            else:
                button.setChecked(False)
            button.setEnabled(match_type in matches)

        self._on_match_type_selected(self._checked_match_type)

    def _on_match_type_selected(self, match_type: Optional[KeystoreTextType]) -> None:
        self._checked_match_type = match_type

        button = self.wizard().button(QWizard.CustomButton1)
        button.setEnabled(self._checked_match_type is not None and \
            self._checked_match_type not in { KeystoreTextType.ADDRESSES,
                KeystoreTextType.PRIVATE_KEYS, KeystoreTextType.ELECTRUM_OLD_SEED_WORDS })
        self.completeChanged.emit()

    def _on_text_changed(self) -> None:
        matches: Dict[KeystoreTextType, KeystoreMatchType] = {}
        text = self.text_area.toPlainText().strip()

        # First try the matches that match the entire text.
        if is_old_seed(text):
            matches[KeystoreTextType.ELECTRUM_OLD_SEED_WORDS] = text
        if is_new_seed(text):
            matches[KeystoreTextType.ELECTRUM_SEED_WORDS] = text
        is_checksum_valid, is_wordlist_valid = bip39_is_checksum_valid(text)
        if is_checksum_valid and is_wordlist_valid:
            matches[KeystoreTextType.BIP39_SEED_WORDS] = text

        try:
            key = bip32_key_from_string(text)
            if isinstance(key, PrivateKey):
                matches[KeystoreTextType.EXTENDED_PRIVATE_KEY] = text
            else:
                matches[KeystoreTextType.EXTENDED_PUBLIC_KEY] = text
        except (Base58Error, ValueError):
            pass

        # If no full matches, try and match each "word".
        if not len(matches):
            text = text.split()
            for word in text:
                match_found = False
                try:
                    PrivateKey.from_text(word)
                except (Base58Error, ValueError):
                    pass
                else:
                    match_found = True
                    if KeystoreTextType.PRIVATE_KEYS not in matches:
                        matches[KeystoreTextType.PRIVATE_KEYS] = set()
                    matches[KeystoreTextType.PRIVATE_KEYS].add(word)

                try:
                    address = Address.from_string(word, Net.COIN)
                    if isinstance(address, P2SH_Address):
                        raise ValueError("P2SH not supported")
                except (Base58Error, ValueError):
                    pass
                else:
                    match_found = True
                    if KeystoreTextType.ADDRESSES not in matches:
                        matches[KeystoreTextType.ADDRESSES] = set()
                    matches[KeystoreTextType.ADDRESSES].add(word)

                if not match_found:
                    if KeystoreTextType.UNRECOGNIZED not in matches:
                        matches[KeystoreTextType.UNRECOGNIZED] = set()
                    matches[KeystoreTextType.UNRECOGNIZED].add(word)

        self._set_matches(matches)

    def _on_customize_button_clicked(self, *checked) -> None:
        assert self.isComplete()
        self._next_page_id = AccountPage.IMPORT_ACCOUNT_TEXT_CUSTOM

        wizard: AccountWizard = self.wizard()
        wizard.next()

    # Qt method called to determine if 'Next' or 'Finish' should be enabled or disabled.
    # Overriding this requires us to emit the 'completeChanges' signal where applicable.
    def isComplete(self) -> bool:
        return self._checked_match_type is not None

    # Qt method called when 'Next' or 'Finish' is clicked for last-minute validation.
    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        assert self.isComplete()

        wizard: AccountWizard = self.wizard()
        if self._next_page_id == -1:
            # Create the account with no customisation
            if not self._create_account(main_window=wizard._main_window):
                return False
        else:
            wizard.set_text_import_matches(self._checked_match_type,
                self._matches[self._checked_match_type])
        return True

    # Qt method called to get the Id of the next page.
    def nextId(self) -> int:
        # Need to know if customize is clicked and go to the custom page.
        return self._next_page_id

    def on_enter(self) -> None:
        self._next_page_id = -1
        wizard: AccountWizard = self.wizard()

        button = wizard.button(QWizard.CustomButton1)
        button.setText(_("&Customize"))
        button.setContentsMargins(10, 0, 10, 0)
        button.clicked.connect(self._on_customize_button_clicked)
        button.setVisible(True)
        button.setEnabled(False)

        self._set_matches(self._matches)

    def on_leave(self) -> None:
        button = self.wizard().button(QWizard.CustomButton1)
        button.clicked.disconnect()
        button.setVisible(False)
        self._next_page_id = -1

    @protected
    def _create_account(self, main_window: Optional[ElectrumWindow]=None,
            password: Optional[str]=None) -> bool:
        wizard: AccountWizard = self.wizard()
        entries = self._matches[self._checked_match_type]
        if self._checked_match_type in (KeystoreTextType.ADDRESSES, KeystoreTextType.PRIVATE_KEYS):
            script_type = (ScriptType.P2PKH
                if self._checked_match_type == KeystoreTextType.PRIVATE_KEYS else ScriptType.NONE)
            wizard.set_text_entry_account_result(ResultType.IMPORTED, self._checked_match_type,
                script_type, entries, password)
        else:
            _keystore = instantiate_keystore_from_text(self._checked_match_type,
                self._matches[self._checked_match_type], password)
            wizard.set_keystore_result(ResultType.IMPORTED, _keystore)
        return True


class ImportWalletTextCustomPage(QWizardPage):
    def __init__(self, wizard: AccountWizard) -> None:
        super().__init__(wizard)

        self.setTitle(_("Import Account From Text With Customizations"))

        self._text_type: Optional[KeystoreTextType] = None
        self._text_matches: Optional[KeystoreMatchType] = None
        self._derivation_text = ""

        self._passphrase_label = QLabel(_("Passphrase"))
        self._passphrase_edit = QLineEdit()
        self._passphrase_edit.setFixedWidth(140)

        self._derivation_label = QLabel(_("Derivation path"))
        self._derivation_edit = QLineEdit(self._derivation_text)
        self._derivation_edit.setFixedWidth(140)
        self._derivation_edit.textEdited.connect(self._on_derivation_text_edited)

        self._options_label = QLabel(_("Options"))
        self._watchonly_button = QCheckBox(_("This is a watch-only account."))

        grid = QGridLayout()
        grid.addWidget(self._passphrase_label, 0, 0, Qt.AlignRight)
        grid.addWidget(self._passphrase_edit, 0, 1, Qt.AlignLeft)
        grid.addWidget(self._derivation_label, 1, 0, Qt.AlignRight)
        grid.addWidget(self._derivation_edit, 1, 1, Qt.AlignLeft)
        grid.addWidget(self._options_label, 2, 0, Qt.AlignRight)
        grid.addWidget(self._watchonly_button, 2, 1, Qt.AlignLeft)

        layout = QVBoxLayout()
        layout.addLayout(grid)
        self.setLayout(layout)

    def _on_derivation_text_edited(self, text: str) -> None:
        self._derivation_text = text.strip()
        self.completeChanged.emit()

    # Qt method called to determine if 'Next' or 'Finish' should be enabled or disabled.
    # Overriding this requires us to emit the 'completeChanges' signal where applicable.
    def isComplete(self) -> bool:
        if self._allow_derivation_path_usage():
            try:
                derivation = bip32_decompose_chain_string(self._derivation_text)
            except ValueError:
                return False
        return True

    # Qt method called when 'Next' or 'Finish' is clicked for last-minute validation.
    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        assert self.isComplete()

        wizard: AccountWizard = self.wizard()
        if not self._create_account(main_window=wizard._main_window):
            return False
        return True

    # Qt method called to get the Id of the next page.
    def nextId(self) -> int:
        return -1

    def on_enter(self) -> None:
        wizard: AccountWizard = self.wizard()

        self._text_type = wizard.get_text_import_type()
        self._text_matches = wizard.get_text_import_matches()
        if self._text_type == KeystoreTextType.BIP39_SEED_WORDS:
            self._derivation_text = bip44_derivation_cointype(0, 0)
        else:
            self._derivation_text = ""

        self._passphrase_edit.setText("")
        self._passphrase_edit.setEnabled(self._allow_passphrase_usage())
        self._derivation_edit.setText(self._derivation_text)
        self._derivation_edit.setEnabled(self._allow_derivation_path_usage())
        self._watchonly_button.setChecked(False)
        self._watchonly_button.setEnabled(self._allow_watch_only_usage())

    def on_leave(self) -> None:
        pass

    def _allow_passphrase_usage(self) -> bool:
        return self._text_type in (KeystoreTextType.ELECTRUM_SEED_WORDS,
            KeystoreTextType.BIP39_SEED_WORDS)

    def _allow_derivation_path_usage(self) -> bool:
        return self._text_type in (KeystoreTextType.BIP39_SEED_WORDS,)

    def _allow_watch_only_usage(self) -> bool:
        return self._text_type in (KeystoreTextType.BIP39_SEED_WORDS,
            KeystoreTextType.ELECTRUM_SEED_WORDS, KeystoreTextType.EXTENDED_PRIVATE_KEY)

    @protected
    def _create_account(self, main_window: Optional[ElectrumWindow]=None,
            password: Optional[str]=None) -> bool:
        passphrase = (self._passphrase_edit.text().strip()
            if self._allow_passphrase_usage() else None)
        derivation_text = self._derivation_text if self._allow_derivation_path_usage() else None
        watch_only = (self._watchonly_button.isChecked()
            if self._allow_watch_only_usage() else False)

        _keystore = instantiate_keystore_from_text(self._text_type, self._text_matches,
            password, derivation_text, passphrase, watch_only)
        wizard: AccountWizard = self.wizard()
        wizard.set_keystore_result(ResultType.IMPORTED, _keystore)
        return True


class FindHardwareWalletAccountPage(QWizardPage):
    _selected_device: Optional[Tuple[str, DeviceInfo]]
    _devices: List[Tuple[str, DeviceInfo]]
    _device_debug_message: Optional[str]
    _alive: bool = False

    def __init__(self, wizard: AccountWizard):
        super().__init__(wizard)

        self._devices = []
        self._selected_device = None
        self._device_debug_message = None

        self.setTitle(_("Import a Hardware Wallet as an Account"))
        self.setFinalPage(False)

    # Qt method called to get the Id of the next page.
    def nextId(self):
        return AccountPage.SETUP_HARDWARE_WALLET

    # Qt method called when 'Next' or 'Finish' is clicked for last-minute validation.
    def validatePage(self) -> bool:
        wizard: AccountWizard = self.wizard()
        wizard.set_selected_device(self._selected_device)
        return True

    # Qt method called to determine if 'Next' or 'Finish' should be enabled or disabled.
    # Overriding this requires us to emit the 'completeChanges' signal where applicable.
    def isComplete(self) -> bool:
        return self._selected_device is not None

    def on_enter(self) -> None:
        button = self.wizard().button(QWizard.CustomButton1)
        button.setText(_("&Rescan"))
        button.setContentsMargins(10, 0, 10, 0)
        button.clicked.connect(self._on_rescan_clicked)

        self._alive = True
        if len(self._devices):
            self._display_scan_success_results()
        else:
            self._initiate_scan()

    def on_leave(self) -> None:
        self._show_rescan_button(False)
        self._alive = False
        button = self.wizard().button(QWizard.CustomButton1)
        button.clicked.disconnect()

    def _on_rescan_clicked(self, *checked) -> None:
        self._initiate_scan()

    def _display_scan_in_progress(self) -> None:
        progress_bar = QProgressBar()
        progress_bar.setRange(0, 0)
        progress_bar.setOrientation(Qt.Horizontal)
        progress_bar.setMinimumWidth(250)
        # This explicitly needs to be done for the progress bar otherwise it has some RHS space.
        progress_bar.setAlignment(Qt.AlignCenter)

        progress_label = QLabel(_("Please wait for hardware wallets to be located."))

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(progress_bar, alignment=Qt.AlignCenter)
        vbox.addWidget(progress_label, alignment=Qt.AlignCenter)
        vbox.addStretch(1)

        if self.layout():
            QWidget().setLayout(self.layout())

        hlayout = QHBoxLayout()
        hlayout.addStretch(1)
        hlayout.addLayout(vbox)
        hlayout.addStretch(1)
        self.setLayout(hlayout)

    def _display_scan_success_results(self) -> None:
        choices = []
        for name, info in self._devices:
            state = _("initialized") if info.initialized else _("wiped")
            label = info.label or _("An unnamed {}").format(name)
            choices.append(((name, info), f"{label} [{name}, {state}]"))

        c_values = [x[0] for x in choices]
        c_titles = [x[1] for x in choices]
        def _on_choice_clicked(choices: ChoicesLayout) -> None:
            self._selected_device = c_values[choices.selected_index()]
            self.completeChanged.emit()
        self._selected_device = c_values[0]
        self.completeChanged.emit()

        message = _('Select a device')
        self._choices = ChoicesLayout(message, c_titles, on_clicked=_on_choice_clicked)

        vbox = QVBoxLayout()
        vbox.addLayout(self._choices.layout())
        vbox.addStretch(1)

        if self.layout():
            QWidget().setLayout(self.layout())
        self.setLayout(vbox)

    def _display_scan_failure_results(self) -> None:
        label = QLabel(NO_DEVICES_FOUND_TEXT + "\n")
        label.setWordWrap(True)

        logo_grid = QGridLayout()
        logo_grid.setSpacing(18)
        logo_grid.setColumnMinimumWidth(0, 70)
        logo_grid.setColumnStretch(1,1)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        lockfile = "icons8-usb-disconnected-80.png"
        logo.setPixmap(QPixmap(icon_path(lockfile)).scaledToWidth(80))

        logo_grid.addWidget(logo,  0, 0)
        logo_grid.addWidget(label, 0, 1, 1, 2)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)

        scan_text_label = QLabel(_("Debug messages") +":")
        scan_text_edit = QTextEdit()
        scan_text_edit.setText(self._device_debug_message)
        scan_text_edit.setReadOnly(True)
        grid.addWidget(scan_text_label, 0, 0, 2, 1, Qt.AlignRight)
        grid.addWidget(scan_text_edit, 1, 0, 2, 2, Qt.AlignLeft)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(10, 10, 20, 10)
        vbox.addLayout(logo_grid)
        vbox.addSpacing(10)
        vbox.addWidget(scan_text_label)
        vbox.addWidget(scan_text_edit)
        vbox.addLayout(grid)
        vbox.addStretch(1)

        if self.layout():
            QWidget().setLayout(self.layout())
        self.setLayout(vbox)

    def _show_rescan_button(self, is_shown: bool) -> None:
        if not self._alive:
            return
        button = self.wizard().button(QWizard.CustomButton1)
        button.setVisible(is_shown)

    def _initiate_scan(self) -> None:
        self._show_rescan_button(False)

        self._devices = []
        self._selected_device = None
        self._device_debug_message = None
        self.completeChanged.emit()

        self._display_scan_in_progress()

        app_state.app.run_in_thread(self._scan_attempt, on_done=self._on_scan_complete)

    def _on_scan_complete(self, future: concurrent.futures.Future) -> None:
        if len(self._devices):
            self._display_scan_success_results()
        else:
            self._display_scan_failure_results()
        self._show_rescan_button(True)

    def _scan_attempt(self) -> None:
        self._scan_devices()
        self.completeChanged.emit()

    def _scan_devices(self) -> None:
        devices: DeviceList = []
        devmgr = app_state.device_manager

        debug_msg = ''
        supported_devices = devmgr.supported_devices()
        try:
            scanned_devices = devmgr.scan_devices()
        except Exception:
            logger.exception(f'error scanning devices')
        else:
            for device_kind, plugin in supported_devices.items():
                # plugin init errored?
                if isinstance(plugin, Exception):
                    tail = '\n    '.join([_('You might have an incompatible library.'), '']
                                         + str(plugin).splitlines())
                    debug_msg += f'  {device_kind}: (error loading plugin)\n{tail}\n'
                    continue

                try:
                    # FIXME: side-effect: unpaired_device_info sets client.handler
                    u = devmgr.unpaired_device_infos(None, plugin, devices=scanned_devices)
                    devices += [(device_kind, x) for x in u]
                except Exception as e:
                    logger.exception(f'error getting device information for {device_kind}')
                    tail = '\n    '.join([''] + str(e).splitlines())
                    debug_msg += f'  {device_kind}: (error getting device information)\n{tail}\n'
        if not debug_msg:
            debug_msg = '  {}'.format(_('No exceptions encountered.'))

        if len(devices):
            self._devices = devices
        else:
            self._device_debug_message = debug_msg

        # Help text?
        #     msg = ''.join([
        #         _('No hardware device detected.') + '\n',
        #         _('To trigger a rescan, press \'Next\'.') + '\n\n',
        #         _('If your device is not detected on Windows, go to "Settings", "Devices", '
        #           '"Connected devices", and do "Remove device". '
        #           'Then, plug your device again.') + ' ',
        #         _('On Linux, you might have to add a new permission to your udev rules.')
        # + '\n\n',
        #         _('Debug message') + '\n',
        #         debug_msg
        #     ])
        #     self.confirm_dialog(title=title, message=msg,
        #                         run_next= lambda x: self.choose_hw_device())
        #     return


class SetupHardwareWalletAccountPage(QWizardPage):
    _plugin: Any
    _plugin_debug_message: Optional[str]
    _derivation_default: Sequence[int] = tuple(bip32_decompose_chain_string(
        bip44_derivation_cointype(0, 0)))
    _derivation_user: Optional[Sequence[int]] = None

    def __init__(self, wizard: AccountWizard):
        super().__init__(wizard)

        self._plugin = None
        self._plugin_debug_message = None

        self.setTitle(_("Import a Hardware Wallet as an Account"))
        self.setFinalPage(False)

    # Qt method called to get the Id of the next page.
    def nextId(self):
        return -1

    # Qt method called when 'Next' or 'Finish' is clicked for last-minute validation.
    def validatePage(self) -> bool:
        wizard: AccountWizard = self.wizard()
        if self._create_account(main_window=wizard._main_window):
            return True
        return False

    # Qt method called to determine if 'Next' or 'Finish' should be enabled or disabled.
    # Overriding this requires us to emit the 'completeChanges' signal where applicable.
    def isComplete(self) -> bool:
        return (self._plugin_debug_message is None and self._plugin is not None and
            self._derivation_user is not None)

    def on_enter(self) -> None:
        # if self.wallet_type=='multisig':
        #     # There is no general standard for HD multisig.
        #     # This is partially compatible with BIP45; assumes index=0
        #     default_derivation = "m/45'/0"

        self._initiate_setup()

    def on_leave(self) -> None:
        self._plugin = None
        self._plugin_debug_message = None

    def _initiate_setup(self) -> None:
        self._setup_device()

        # 2023-05-03 RT: There are issues with Qt and hardware wallets. This comment explains why
        #     we choose to live with them given they seem to just be a poor experience, but work,
        #     where the larger fix requires a lot of rewriting.

        # There's a thing where the trezor password "confirm on device" dialog is blank. This is
        # because the hardware wallet setup code is running in the GUI thread and the hardware
        # wallet blocks the GUI thread. But it works. The proper fix is to move the hardware wallet
        # setup code to the a worker thread, but this is not as easy as it seems because the
        # signals on the hardware wallet objects likely need to be created on the GUI thread and
        # that requires restructuring the code (otherwise they seem to bind to the thread they are
        # created on?).

    #     app_state.app.run_in_thread(self._setup_device, on_done=self._on_setup_complete)

    # def _on_setup_complete(self, future: concurrent.futures.Future) -> None:
        # Display according to result.
        if self._plugin_debug_message is None:
            self._display_setup_success_results()
        else:
            self._display_setup_failure_results()
        self.completeChanged.emit()

    def _display_setup_success_results(self) -> None:
        wizard: AccountWizard = self.wizard()
        name, device_info = wizard.get_selected_device()

        wallet_type = "standard"
        text = DEVICE_SETUP_SUCCESS_TEXT.format(name.capitalize(),
            compose_chain_string(self._derivation_default), wallet_type)

        label = QLabel(text + "\n")
        label.setWordWrap(True)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        logo_filename = "icons8-usb-connected-80.png"
        logo.setPixmap(QPixmap(icon_path(logo_filename)).scaledToWidth(80))

        logo_grid = QGridLayout()
        logo_grid.setSpacing(18)
        logo_grid.setColumnMinimumWidth(0, 70)
        logo_grid.setColumnStretch(1,1)
        logo_grid.addWidget(logo,  0, 0, Qt.AlignTop)
        logo_grid.addWidget(label, 0, 1, 1, 2)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setContentsMargins(50, 10, 50, 10)
        grid.setColumnStretch(1,1)

        path_text = compose_chain_string(self._derivation_default)
        self._path_edit = QLineEdit()
        self._path_edit.setText(path_text)
        self._path_edit.textEdited.connect(self._on_derivation_path_changed)
        self._path_edit.setFixedWidth(140)
        self._on_derivation_path_changed(path_text)

        grid.addWidget(QLabel(_("Derivation path")), 1, 0, 1, 1, Qt.AlignRight)
        grid.addWidget(self._path_edit, 1, 1, 1, 2, Qt.AlignLeft)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(10, 10, 20, 10)
        vbox.addLayout(logo_grid)
        vbox.addSpacing(10)
        vbox.addLayout(grid)
        vbox.addStretch(1)

        if self.layout():
            QWidget().setLayout(self.layout())
        self.setLayout(vbox)

    def _display_setup_failure_results(self) -> None:
        # This might happen for instance, if the "bitcoin cash" application is not open.
        label = QLabel(DEVICE_SETUP_ERROR_TEXT + "\n")
        label.setWordWrap(True)

        logo_grid = QGridLayout()
        logo_grid.setSpacing(18)
        logo_grid.setColumnMinimumWidth(0, 70)
        logo_grid.setColumnStretch(1,1)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        logo_filename = "icons8-usb-disconnected-80.png"
        logo.setPixmap(QPixmap(icon_path(logo_filename)).scaledToWidth(80))

        logo_grid.addWidget(logo,  0, 0)
        logo_grid.addWidget(label, 0, 1, 1, 2)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)

        scan_text_label = QLabel(_("Debug messages:"))
        scan_text_edit = QTextEdit()
        scan_text_edit.setText(self._plugin_debug_message)
        scan_text_edit.setReadOnly(True)
        grid.addWidget(scan_text_label, 0, 0, 2, 1, Qt.AlignRight)
        grid.addWidget(scan_text_edit, 1, 0, 2, 2, Qt.AlignLeft)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(10, 10, 20, 10)
        vbox.addLayout(logo_grid)
        vbox.addSpacing(10)
        vbox.addWidget(scan_text_label)
        vbox.addWidget(scan_text_edit)
        vbox.addLayout(grid)
        vbox.addStretch(1)

        if self.layout():
            QWidget().setLayout(self.layout())
        self.setLayout(vbox)

    def _setup_device(self) -> None:
        self._plugin = None
        self._plugin_debug_message = None

        wizard: AccountWizard = self.wizard()
        name, device_info = wizard.get_selected_device()
        self._plugin = app_state.device_manager.get_plugin(name)
        try:
            self._plugin.setup_device(device_info, wizard)
        except UserCancelled:
            return
        except OSError as e:
            self._plugin_debug_message = (_('We encountered an error while connecting to your '
                'device:') +'\n'+ str(e) +'\n'+
                _('To try to fix this, we will now re-pair with your device.') +'\n'+
                _('Please try again.'))
            app_state.device_manager.unpair_id(device_info.device.id_)
            return
        except Exception as e:
            self._plugin_debug_message = str(e)
            logger.exception("Problem encountered setting up hardware device")
            return

    def _on_derivation_path_changed(self, text: str) -> None:
        path_text = self._path_edit.text().strip()
        try:
            self._derivation_user = tuple(bip32_decompose_chain_string(path_text))
        except ValueError:
            self._derivation_user = None
        self.completeChanged.emit()

    @protected
    def _create_account(self, main_window: Optional[ElectrumWindow]=None,
            password: Optional[str]=None) -> bool:
        # The derivation path is valid, proceed to create the account.
        wizard: AccountWizard = self.wizard()
        name, device_info = wizard.get_selected_device()

        derivation_text = compose_chain_string(self._derivation_user)
        try:
            mpk = self._plugin.get_master_public_key(device_info.device.id_, derivation_text,
                wizard)
        except Exception as e:
            logger.exception("Failed getting master public key for hardware wallet (%s, %s)",
                self._derivation_user, derivation_text)
            MessageBox.show_error(str(e))
            return False

        label = device_info.label
        data = {
            'hw_type': name,
            'derivation': derivation_text,
            'xpub': mpk.to_extended_key_string(),
            'label': label.strip() if label and label.strip() else None,
        }
        keystore = instantiate_keystore(DerivationType.HARDWARE, data)
        wizard.set_keystore_result(ResultType.HARDWARE, keystore)

        return True


class CosignWidget(QWidget):
    size = 200

    def __init__(self, m: int, n: int) -> None:
        QWidget.__init__(self)
        self.setMinimumHeight(self.size)
        self.setMaximumHeight(self.size)
        self.m = m
        self.n = n

        self._green = QBrush(QColor.fromRgb(0x55, 0xDD, 0x55))

    def set_n(self, n: int) -> None:
        self.n = n
        self.update()

    def set_m(self, m: int) -> None:
        self.m = m
        self.update()

    def paintEvent(self, event) -> None:
        bgcolor = self.palette().color(QPalette.Background)
        pen = QPen(bgcolor, 7, Qt.SolidLine)
        qp = QPainter()
        qp.begin(self)
        qp.setPen(pen)
        qp.setRenderHint(QPainter.Antialiasing)
        qp.setBrush(Qt.gray)
        x = int((self.width() - self.size) / 2)
        for i in range(self.n):
            alpha = int(16 * 360 * i/self.n)
            alpha2 = int(16 * 360 * 1/self.n)
            qp.setBrush(self._green if i<self.m else Qt.gray)
            qp.drawPie(x, 0, self.size, self.size, alpha, alpha2)
        qp.end()


class CreateMultisigAccountPageContext(QObject):
    def __init__(self, page: QWizardPage, cosign_widget: CosignWidget,
            summary_label: QLabel) -> None:
        self.page = page
        self.cosign_widget = cosign_widget
        self.summary_label = summary_label

        self._watch_only = False

    def set_m(self, value: int) -> None:
        self.cosign_widget.set_m(value)
        self.update_summary_label()

    def set_n(self, value: int) -> None:
        self.cosign_widget.set_n(value)
        self.update_summary_label()

    def set_watch_only(self, value: bool) -> None:
        self._watch_only = value

    def update_summary_label(self) -> None:
        self.summary_label.setText(_("Every transaction must be signed by at least {} of the {} "
            "cosigners.").format(self.cosign_widget.m, self.cosign_widget.n))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "m": self.cosign_widget.m,
            "n": self.cosign_widget.n,
            "watch_only": False,
        }


class CreateMultisigAccountOptionsWidget(WizardFormSection):
    def __init__(self, form_context: Optional[CreateMultisigAccountPageContext],
            page: QWizardPage) -> None:
        super().__init__(page)

        self.setObjectName("CreateMultisigAccountOptions")
        self._form_context = form_context

        widget = QCheckBox(_("Watch only."))

        self.add_title(_("Additional options"))
        self.add_row(_("Account type")+":", widget)

        page.registerField("multisig-watch-only", widget, "checked")

    def set_form_context(self, form_context: CreateMultisigAccountPageContext) -> None:
        self._form_context = form_context


class CreateMultisigAccountSettingsWidget(WizardFormSection):
    def __init__(self, form_context: Optional[CreateMultisigAccountPageContext],
            page: QWizardPage) -> None:
        super().__init__(page)

        self.setObjectName("CreateMultisigAccountSettings")
        self._page = page
        self._form_context = form_context

        m_edit = QSlider(Qt.Horizontal, self)
        m_edit.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Maximum)
        n_edit = QSlider(Qt.Horizontal, self)
        n_edit.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Maximum)
        n_edit.setMinimum(2)
        n_edit.setMaximum(MAXIMUM_COSIGNER_COUNT)
        m_edit.setMinimum(1)
        m_edit.setMaximum(DEFAULT_COSIGNER_COUNT)
        n_edit.setValue(DEFAULT_COSIGNER_COUNT)
        m_edit.setValue(DEFAULT_COSIGNER_COUNT)
        n_label = QLabel()
        m_label = QLabel()

        def on_m(m: int) -> None:
            nonlocal m_label
            m_label.setText(_('Require %d signatures')%m +":")
            if self._form_context is not None:
                self._form_context.set_m(m)
        def on_n(n: int) -> None:
            nonlocal n_label, n_edit
            n_label.setText(_('From %d cosigners')%n +":")
            if self._form_context is not None:
                self._form_context.set_n(n)
            m_edit.setMaximum(n)
        n_edit.valueChanged.connect(on_n)
        m_edit.valueChanged.connect(on_m)
        # Prime the labels.
        on_n(DEFAULT_COSIGNER_COUNT)
        on_m(DEFAULT_COSIGNER_COUNT)

        self.add_row(n_label, n_edit, True)
        self.add_row(m_label, m_edit, True)

        page.registerField("multisig-m", m_edit, "value")
        page.registerField("multisig-n", n_edit, "value")

    def set_form_context(self, form_context: CreateMultisigAccountPageContext) -> None:
        self._form_context = form_context


class CreateMultisigAccountPage(QWizardPage):
    def __init__(self, wizard: AccountWizard):
        super().__init__(wizard)

        self.setTitle(_("Create a Multi-signature Account"))
        self.setFinalPage(False)

        self._next_page_id = AccountPage.CREATE_MULTISIG_ACCOUNT_COSIGNERS

        self._form_context: Optional[CreateMultisigAccountPageContext] = None
        self._cosign_widget = CosignWidget(DEFAULT_COSIGNER_COUNT, DEFAULT_COSIGNER_COUNT)
        self._summary_label = QLabel()
        self._settings_widget = CreateMultisigAccountSettingsWidget(self._form_context, self)

        layout = self._create_layout()
        self.setLayout(layout)

    def _create_form_context(self) -> None:
        self._form_context = CreateMultisigAccountPageContext(self, self._cosign_widget,
            self._summary_label)

    def _create_layout(self) -> QVBoxLayout:
        if self._form_context is not None:
            self._settings_widget.set_form_context(self._form_context)
            self._form_context.update_summary_label()

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(self._cosign_widget)
        vbox.addStretch(1)
        vbox.addWidget(self._summary_label, 0, Qt.AlignCenter)
        vbox.addStretch(1)
        vbox.addWidget(self._settings_widget)

        return vbox

    def on_enter(self) -> None:
        self._next_page_id = AccountPage.CREATE_MULTISIG_ACCOUNT_COSIGNERS

        button = self.wizard().button(QWizard.CustomButton1)
        button.setText(_("&Customize"))
        button.setContentsMargins(10, 0, 10, 0)
        button.clicked.connect(self._on_customize_button_clicked)
        button.setVisible(True)
        # The customize page is disabled for now. It's one option was obsoleted.
        button.setEnabled(False)

        self._create_form_context()
        discardable = QWidget()
        discardable.setLayout(self.layout())
        self.setLayout(self._create_layout())

    def on_leave(self) -> None:
        button = self.wizard().button(QWizard.CustomButton1)
        button.clicked.disconnect()
        button.setVisible(False)

        self._form_context = None

    # Qt method called to get the Id of the next page.
    def nextId(self):
        # Need to know if customize is clicked and go to the custom page.
        return self._next_page_id

    def _on_customize_button_clicked(self, *checked) -> None:
        assert self.isComplete()
        self._next_page_id = AccountPage.CREATE_MULTISIG_ACCOUNT_CUSTOM

        wizard: AccountWizard = self.wizard()
        wizard.next()


class CreateMultisigAccountCustomPage(QWizardPage):
    def __init__(self, wizard: AccountWizard):
        super().__init__(wizard)

        self.setTitle(_("Create a Multi-signature Account - Customize"))
        self.setFinalPage(False)

        self._next_page_id = AccountPage.CREATE_MULTISIG_ACCOUNT_COSIGNERS

        self._form_context: Optional[CreateMultisigAccountPageContext] = None
        self._cosign_widget = CosignWidget(2, 2)
        self._summary_label = QLabel()
        self._options_widget = CreateMultisigAccountOptionsWidget(self._form_context, self)

        layout = self._create_layout()
        self.setLayout(layout)

    def _create_form_context(self) -> None:
        self._form_context = CreateMultisigAccountPageContext(self, self._cosign_widget,
            self._summary_label)

    def _create_layout(self,
            form_context: Optional[CreateMultisigAccountPageContext]=None) -> QVBoxLayout:
        # Object creation has no context.
        if self._form_context is not None:
            self._options_widget.set_form_context(self._form_context)
            self._form_context.set_m(self.field("multisig-m"))
            self._form_context.set_n(self.field("multisig-n"))
            self._form_context.update_summary_label()

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(self._cosign_widget)
        vbox.addStretch(1)
        vbox.addWidget(self._summary_label, 0, Qt.AlignCenter)
        vbox.addStretch(1)
        vbox.addWidget(self._options_widget)

        return vbox

    def on_enter(self) -> None:
        self._next_page_id = AccountPage.CREATE_MULTISIG_ACCOUNT_COSIGNERS

        self._create_form_context()
        discardable = QWidget()
        discardable.setLayout(self.layout())
        self.setLayout(self._create_layout())

    def on_leave(self) -> None:
        self._form_context = None

    # Qt method called to get the Id of the next page.
    def nextId(self):
        # Need to know if customize is clicked and go to the custom page.
        return self._next_page_id


class MultisigAccountCosignerListPage(QWizardPage):
    _cosigner_states: List[CosignerState] = []

    _list: Optional[QListWidget] = None

    def __init__(self, wizard: AccountWizard) -> None:
        super().__init__(wizard)

        self.setTitle(_("Create a Multi-signature Account") +" - "+ _("Cosigners"))

        self._list = CosignerList(wizard.get_main_window())

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        vbox.addWidget(self._list)
        self.setLayout(vbox)

    def on_enter(self) -> None:
        self._list.clear()
        cosigner_count = self.field("multisig-n")
        self._cosigner_states = [ CosignerState(i) for i in range(cosigner_count) ]

        for cosigner_state in self._cosigner_states:
            card = self._list.add_state(cosigner_state)
            card.cosigner_updated.connect(self.event_cosigner_updated)

    def on_leave(self) -> None:
        pass

    # Qt method called when 'Next' or 'Finish' is clicked for last-minute validation.
    def validatePage(self) -> bool:
        assert len(self._cosigner_states) == self.field("multisig-n"), "Mismatched cosigner counts"

        keystore = Multisig_KeyStore({
            "m": self.field("multisig-m"),
            "n": self.field("multisig-n"),
            "cosigner-keys": [],
        })
        for state in self._cosigner_states:
            assert state.keystore is not None, f"Expected complete keystore {state.cosigner_index}"
            keystore.add_cosigner_keystore(state.keystore)

        wizard: AccountWizard = self.wizard()
        wizard.set_keystore_result(ResultType.MULTISIG, keystore)
        return True

    # Qt method called to get the Id of the next page.
    def nextId(self) -> int:
        return -1

    # Qt method called to determine if 'Next' or 'Finish' should be enabled or disabled.
    # Overriding this requires us to emit the 'completeChanges' signal where applicable.
    def isComplete(self) -> bool:
        return len(self._cosigner_states) and all(s.is_complete() for s in self._cosigner_states)

    def event_cosigner_updated(self, cosigner_index: int) -> None:
        self.completeChanged.emit()
