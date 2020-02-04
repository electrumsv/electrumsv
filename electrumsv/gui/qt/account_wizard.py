import concurrent
import enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from bitcoinx import (Address, Base58Error, bip32_decompose_chain_string,
    bip32_key_from_string, PrivateKey, P2SH_Address)
from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QPainter, QPalette, QPen, QPixmap, QTextOption
from PyQt5.QtWidgets import (
    QCheckBox, QVBoxLayout, QHBoxLayout, QLabel, QWizard, QWizardPage, QGridLayout, QGroupBox,
    QLineEdit, QListWidget, QListWidgetItem, QProgressBar, QRadioButton, QSlider, QTextEdit,
    QWidget
)

from electrumsv.app_state import app_state
from electrumsv.bitcoin import compose_chain_string, is_new_seed, is_old_seed
from electrumsv.constants import DerivationType, KeystoreTextType, ScriptType
from electrumsv.exceptions import InvalidPassword
from electrumsv.device import DeviceInfo
from electrumsv.i18n import _
from electrumsv import keystore
from electrumsv.logs import logs
from electrumsv.networks import Net
from electrumsv.wallet import Wallet, instantiate_keystore

from .main_window import ElectrumWindow
from .password_dialog import PasswordLineEdit
from .util import ChoicesLayout, icon_path, MessageBox, protected, read_QIcon, WWLabel


logger = logs.get_logger('wizard-account')

DeviceList = List[Tuple[str, DeviceInfo]]

PASSWORD_EXISTING_TEXT = _("Your wallet has a password, and you will need to provide that "
    "password in order to add this account.")

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

class AccountPages(enum.IntEnum):
    ADD_ACCOUNT_MENU = 12
    CREATE_NEW_STANDARD_ACCOUNT = 13
    CREATE_NEW_MULTISIG_ACCOUNT = 14
    IMPORT_ACCOUNT_FILE = 15
    IMPORT_ACCOUNT_TEXT = 16
    IMPORT_ACCOUNT_TEXT_CUSTOM = 17
    # Hardware wallets.
    FIND_HARDWARE_WALLET = 51
    SETUP_HARDWARE_WALLET = 52
    #
    IMPORT_ACCOUNT_IDENTIFY_USAGE = 100


class AccountWizard(QWizard):
    _last_page_id = None
    _selected_device: Optional[Tuple[str, DeviceInfo]] = None

    def __init__(self, main_window: ElectrumWindow) -> None:
        super().__init__(main_window)

        self._main_window = main_window
        self._wallet: Wallet = main_window._wallet
        self._text_import_type: Optional[KeystoreTextType] = None
        self._text_import_matches: Optional[KeystoreMatchType] = None

        self.setWindowTitle('ElectrumSV')
        self.setModal(True)
        self.setMinimumSize(600, 600)
        self.setOption(QWizard.IndependentPages, False)
        self.setOption(QWizard.NoDefaultButton, True)
        self.setOption(QWizard.HaveHelpButton, True)
        self.setOption(QWizard.HelpButtonOnRight, False)
        self.setOption(QWizard.HaveCustomButton1, True)

        self.setPage(AccountPages.ADD_ACCOUNT_MENU, AddAccountWizardPage(self))
        self.setPage(AccountPages.IMPORT_ACCOUNT_TEXT, ImportWalletTextPage(self))
        self.setPage(AccountPages.IMPORT_ACCOUNT_TEXT_CUSTOM, ImportWalletTextCustomPage(self))
        self.setPage(AccountPages.CREATE_NEW_STANDARD_ACCOUNT, CreateStandardAccountPage(self))
        self.setPage(AccountPages.CREATE_NEW_MULTISIG_ACCOUNT, CreateMultisigAccountPage(self))
        self.setPage(AccountPages.FIND_HARDWARE_WALLET, FindHardwareWalletAccountPage(self))
        self.setPage(AccountPages.SETUP_HARDWARE_WALLET, SetupHardwareWalletAccountPage(self))

        self.currentIdChanged.connect(self.on_current_id_changed)

        self.setStartId(AccountPages.ADD_ACCOUNT_MENU)

    def run(self):
        button = self.button(QWizard.HelpButton)
        button.clicked.connect(self._on_help_button_clicked)

        self.ensure_shown()
        result = self.exec()
        return result

    def ensure_shown(self):
        self.show()
        self.raise_()

    def on_current_id_changed(self, page_id):
        if self._last_page_id is not None:
            page = self.page(self._last_page_id)
            if hasattr(page, "on_leave"):
                page.on_leave()

        self._last_page_id = page_id
        page = self.page(page_id)
        if hasattr(page, "on_enter"):
            page.on_enter()
        else:
            button = self.button(QWizard.CustomButton1)
            button.setVisible(False)

    def _on_help_button_clicked(self, *checked) -> None:
        print("Help button clicked")

    def set_selected_device(self, device: Optional[Tuple[str, DeviceInfo]]) -> None:
        self._selected_device = device

    def get_selected_device(self) -> Optional[Tuple[str, DeviceInfo]]:
        return self._selected_device

    def get_main_window(self) -> ElectrumWindow:
        return self._main_window

    def get_wallet(self) -> Wallet:
        return self._wallet

    def set_text_import_matches(self, text_type: KeystoreTextType,
            text_matches: KeystoreMatchType) -> None:
        self._text_import_type = text_type
        self._text_import_matches = text_matches

    def get_text_import_type(self) -> Optional[KeystoreTextType]:
        return self._text_import_type

    def get_text_import_matches(self) -> Optional[KeystoreMatchType]:
        return self._text_import_matches


class AddAccountWizardPage(QWizardPage):
    def __init__(self, wizard: AccountWizard):
        super().__init__(wizard)

        self.setTitle(_("Add Account"))
        self.setFinalPage(False)

        option_list = self.option_list = QListWidget()
        option_list.setIconSize(QSize(30, 30))
        option_list.setStyleSheet("""
            QListView::item:selected {
                background-color: #F5F8FA;
                color: black;
            }
        """)

        for entry in self._get_entries():
            if not entry.get("enabled", True):
                continue
            list_item = QListWidgetItem()
            list_item.setSizeHint(QSize(40, 40))
            list_item.setIcon(read_QIcon(entry['icon_filename']))
            list_item.setText(entry['description'])
            list_item.setData(Qt.UserRole, entry)
            option_list.addItem(list_item)

        option_list.setMaximumWidth(400)
        option_list.setWordWrap(True)

        option_detail = self.optionDetail = QLabel()
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

        def _on_item_selection_changed():
            selected_items = self.option_list.selectedItems()
            if len(selected_items):
                entry = selected_items[0].data(Qt.UserRole)
                self.optionDetail.setText(self._get_entry_detail(entry))
            else:
                self.optionDetail.setText(self._get_entry_detail())
            self.completeChanged.emit()

        def _on_item_double_clicked(clicked_item: QListWidgetItem) -> None:
            self.option_list.setCurrentItem(clicked_item)
            self.completeChanged.emit()
            wizard.next()

        option_list.itemDoubleClicked.connect(_on_item_double_clicked)
        option_list.itemSelectionChanged.connect(_on_item_selection_changed)

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        selected_items = self.option_list.selectedItems()
        return len(selected_items)

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        if self.isComplete():
            return True
        return False

    def nextId(self) -> int:
        selected_items = self.option_list.selectedItems()
        result = AccountPages.CREATE_NEW_STANDARD_ACCOUNT
        if len(selected_items):
            result = selected_items[0].data(Qt.UserRole)['page']
        return result

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
                'page': AccountPages.CREATE_NEW_STANDARD_ACCOUNT,
                'description': _("Create new standard account"),
                'icon_filename': 'icons8-create-80.png',
                'long_description': _("If you want to create a brand new standard account in "
                    "ElectrumSV this is the option you want.") +"<br/><br/>"+ _("A "
                    "standard account is one where you are in control of all payments."),
                'enabled': True,
            },
            {
                'page': AccountPages.CREATE_NEW_MULTISIG_ACCOUNT,
                'description': _("Create new multi-signature account"),
                'icon_filename': 'icons8-create-80.png',
                'long_description': _("If you want to create a brand new multi-signature account "
                    "in ElectrumSV this is the option you want.") +"<br/><br/>"+ _("A "
                    "multi-signature account is one where more than one person is required to "
                    "approve each payment. This requires that the participants, or co-signers, "
                    "coordinate the signing of each payment."),
                'enabled': False,
            },
            {
                'page': AccountPages.IMPORT_ACCOUNT_FILE,
                'description': _("Import account file"),
                'icon_filename': 'icons8-document.svg',
                'long_description': _("..."),
                'enabled': False,
            },
            {
                'page': AccountPages.IMPORT_ACCOUNT_TEXT,
                'description': _("Import account using text (any seed phrase, public keys, "+
                                 "private keys or addresses)"),
                'icon_filename': 'icons8-brain-80.png',
                'long_description': _("If you have some text to paste, or type in, and want "
                    "ElectrumSV to examine it and offer you some choices on how it can be "
                    "imported, this is the option you probably want."),
                'enabled': True,
            },
            {
                'page': AccountPages.FIND_HARDWARE_WALLET,
                'description': _("Import hardware wallet"),
                'icon_filename': 'icons8-usb-2-80.png',
                'enabled': False,
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

        # Beats me.
        self.registerField("wallet-import-text*", self.text_area, "plainText",
            self.text_area.textChanged)

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

        for match_type, button in self._get_buttons():
            def make_check_callback(match_type: KeystoreTextType) -> Callable[[bool], None]:
                def on_button_check(checked: bool=False):
                    self._on_match_type_selected(match_type)
                return on_button_check
            button.clicked.connect(make_check_callback(match_type))

        textbuttons_box = QGridLayout()
        textbuttons_box.addWidget(self._addresses_button, 0, 0)
        textbuttons_box.addWidget(self._privkeys_button, 1, 0)
        textbuttons_box.addWidget(self._xpub_button, 2, 0)
        textbuttons_box.addWidget(self._xprv_button, 3, 0)
        textbuttons_box.addWidget(self._bip39seed_button, 0, 1)
        textbuttons_box.addWidget(self._esvseed_button, 1, 1)
        textbuttons_box.addWidget(self._esvoldseed_button, 2, 1)
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

    def _get_buttons(self) -> List[Tuple[KeystoreTextType, QRadioButton]]:
        return [
            (KeystoreTextType.ADDRESSES, self._addresses_button),
            (KeystoreTextType.PRIVATE_KEYS, self._privkeys_button),
            (KeystoreTextType.EXTENDED_PUBLIC_KEY, self._xpub_button),
            (KeystoreTextType.EXTENDED_PRIVATE_KEY, self._xprv_button),
            (KeystoreTextType.BIP39_SEED_WORDS, self._bip39seed_button),
            (KeystoreTextType.ELECTRUM_SEED_WORDS, self._esvseed_button),
            (KeystoreTextType.ELECTRUM_OLD_SEED_WORDS, self._esvoldseed_button),
        ]

    def _set_matches(self, matches: Dict[KeystoreTextType, KeystoreMatchType]) -> None:
        self._checked_match_type = None
        self._matches = matches

        # These two types are expected to be the sole kind of match, but will have one or more
        # matches of that type.
        if KeystoreTextType.ADDRESSES in matches or KeystoreTextType.PRIVATE_KEYS in matches:
            if len(matches) > 1:
                matches.clear()

        for match_type, button in self._get_buttons():
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
                KeystoreTextType.PRIVATE_KEYS })
        self.completeChanged.emit()

    def _on_text_changed(self) -> None:
        matches: Dict[KeystoreTextType, KeystoreMatchType] = {}
        text = self.text_area.toPlainText().strip()

        # First try the matches that match the entire text.
        if is_old_seed(text):
            matches[KeystoreTextType.ELECTRUM_OLD_SEED_WORDS] = text
        if is_new_seed(text):
            matches[KeystoreTextType.ELECTRUM_SEED_WORDS] = text
        is_checksum_valid, is_wordlist_valid = keystore.bip39_is_checksum_valid(text)
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
        self._next_page_id = AccountPages.IMPORT_ACCOUNT_TEXT_CUSTOM

        wizard: AccountWizard = self.wizard()
        wizard.next()

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        return self._checked_match_type is not None

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

    def nextId(self) -> int:
        # Need to know if customize is clicked and go to the custom page.
        return self._next_page_id

    def on_enter(self) -> None:
        self._next_page_id = -1

        button = self.wizard().button(QWizard.CustomButton1)
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
        wallet = wizard.get_wallet()
        entries = self._matches[self._checked_match_type]
        if self._checked_match_type in (KeystoreTextType.ADDRESSES, KeystoreTextType.PRIVATE_KEYS):
            script_type = (ScriptType.P2PKH
                if self._checked_match_type == KeystoreTextType.PRIVATE_KEYS else ScriptType.NONE)
            wallet.create_account_from_text_entries(self._checked_match_type, script_type,
                entries, password)
        else:
            _keystore = keystore.instantiate_keystore_from_text(self._checked_match_type,
                self._matches[self._checked_match_type], password)
            wallet.create_account_from_keystore(_keystore)
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

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        if self._allow_derivation_path_usage():
            try:
                derivation = bip32_decompose_chain_string(self._derivation_text)
            except ValueError:
                return False
        return True

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        assert self.isComplete()

        wizard: AccountWizard = self.wizard()
        if not self._create_account(main_window=wizard._main_window):
            return False
        return True

    def nextId(self) -> int:
        return -1

    def on_enter(self) -> None:
        wizard: AccountWizard = self.wizard()

        self._text_type = wizard.get_text_import_type()
        self._text_matches = wizard.get_text_import_matches()
        if self._text_type == KeystoreTextType.BIP39_SEED_WORDS:
            self._derivation_text = keystore.bip44_derivation_cointype(0, 0)
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
            KeystoreTextType.ELECTRUM_SEED_WORDS, KeystoreTextType.ELECTRUM_OLD_SEED_WORDS,
            KeystoreTextType.EXTENDED_PRIVATE_KEY)

    @protected
    def _create_account(self, main_window: Optional[ElectrumWindow]=None,
            password: Optional[str]=None) -> bool:
        wizard: AccountWizard = self.wizard()
        wallet = wizard.get_wallet()

        passphrase = (self._passphrase_edit.text().strip()
            if self._allow_passphrase_usage() else None)
        derivation_text = self._derivation_text if self._allow_derivation_path_usage() else None
        watch_only = (self._watchonly_button.isChecked()
            if self._allow_watch_only_usage() else False)

        _keystore = keystore.instantiate_keystore_from_text(self._text_type, self._text_matches,
            password, derivation_text, passphrase, watch_only)
        wallet.create_account_from_keystore(_keystore)
        return True


class CreateStandardAccountPage(QWizardPage):
    _is_complete = False
    _is_final_page = False

    def __init__(self, parent: AccountWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Create a Standard Account"))
        self.setFinalPage(True)

        vbox = QVBoxLayout()

        self._password_edit = PasswordLineEdit()
        # We use `textEdited` to get manual changes, but not programmatic ones.
        self._password_edit.textEdited.connect(self._on_password_changed)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)

        pwlabel = QLabel(_('Password:'))
        pwlabel.setAlignment(Qt.AlignTop)
        grid.addWidget(pwlabel, 0, 0)
        grid.addWidget(self._password_edit, 0, 1)

        label = QLabel(PASSWORD_EXISTING_TEXT + "\n")
        label.setWordWrap(True)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        lockfile = "lock.png"
        logo.setPixmap(QPixmap(icon_path(lockfile)).scaledToWidth(36))

        logo_grid = QGridLayout()
        logo_grid.setSpacing(8)
        logo_grid.setColumnMinimumWidth(0, 70)
        logo_grid.setColumnStretch(1,1)

        logo_grid.addWidget(logo,  0, 0)
        logo_grid.addWidget(label, 0, 1, 1, 2)

        vbox.addLayout(logo_grid)
        vbox.addLayout(grid)

        hlayout = QHBoxLayout()
        hlayout.addStretch(1)
        hlayout.addLayout(vbox)
        hlayout.addStretch(1)
        self.setLayout(hlayout)

    def isFinalPage(self) -> bool:
        return False

    def nextId(self) -> int:
        return -1

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        return self._is_complete

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        self._create_account(self._get_password())
        return True

    def on_enter(self) -> None:
        pass

    def on_leave(self) -> None:
        self._password_edit.setText("")

    def _on_password_changed(self, text: str) -> None:
        wizard: AccountWizard = self.wizard()
        password = self._get_password()

        was_complete = self._is_complete
        self._is_complete = False

        try:
            wizard._wallet.check_password(password)
            self._is_complete = True
        except InvalidPassword:
            pass

        if was_complete == self._is_complete:
            return

        self.completeChanged.emit()

    def _get_password(self) -> str:
        return self._password_edit.text().strip()

    def _create_account(self, password: str) -> bool:
        from electrumsv import mnemonic
        seed_phrase = mnemonic.Mnemonic('en').make_seed('standard')
        k = keystore.from_seed(seed_phrase, '')
        k.update_password(password)

        wizard: AccountWizard = self.wizard()
        wizard._wallet.create_account_from_keystore(k)
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

    def nextId(self):
        return AccountPages.SETUP_HARDWARE_WALLET

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        wizard: AccountWizard = self.wizard()
        wizard.set_selected_device(self._selected_device)
        return True

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
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

        scan_text_label = QLabel(_("Debug messages:"))
        scan_text_edit = QTextEdit()
        scan_text_edit.setText(self._device_debug_message)
        scan_text_edit.setReadOnly(True)
        grid.addWidget(scan_text_label, 0, 0, 2, 1)
        grid.addWidget(scan_text_edit, 1, 0, 2, 2)

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
                    debug_msg += f'  {device_kind}: (error loding plugin)\n{tail}\n'
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
        keystore.bip44_derivation_cointype(0, 0)))
    _derivation_user: Optional[Sequence[int]] = None

    def __init__(self, wizard: AccountWizard):
        super().__init__(wizard)

        self._plugin = None
        self._plugin_debug_message = None

        self.setTitle(_("Import a Hardware Wallet as an Account"))
        self.setFinalPage(False)

    def nextId(self):
        return -1

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        wizard: AccountWizard = self.wizard()
        if self._create_account(main_window=wizard._main_window):
            return True
        return False

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
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
        app_state.app.run_in_thread(self._setup_device, on_done=self._on_setup_complete)

    def _on_setup_complete(self, future: concurrent.futures.Future) -> None:
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
        self._on_derivation_path_changed(path_text)

        grid.addWidget(QLabel(_("Derivation path")), 1, 0, 1, 1)
        grid.addWidget(self._path_edit, 1, 1, 1, 2)

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
        grid.addWidget(scan_text_label, 0, 0, 2, 1)
        grid.addWidget(scan_text_edit, 1, 0, 2, 2)

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
        except OSError as e:
            self._plugin_debug_message = (_('We encountered an error while connecting to your '
                'device:') +'\n'+ str(e) +'\n'+
                _('To try to fix this, we will now re-pair with your device.') +'\n'+
                _('Please try again.'))
            app_state.device_manager.unpair_id(device_info.device.id_)
            return
        except Exception as e:
            self._plugin_debug_message = str(e)
            return

    def _on_derivation_path_changed(self, text: str) -> None:
        path_text = self._path_edit.text().strip()
        try:
            self._derivation_user = tuple(bip32_decompose_chain_string(path_text))
        except ValueError:
            pass
        self.completeChanged.emit()

    @protected
    def _create_account(self, main_window: Optional[ElectrumWindow]=None,
            password: Optional[str]=None) -> bool:
        # The derivation path is valid, proceed to create the account.
        wizard: AccountWizard = self.wizard()
        name, device_info = wizard.get_selected_device()
        wallet = wizard.get_wallet()

        derivation_text = compose_chain_string(self._derivation_user)
        try:
            mpk = self._plugin.get_master_public_key(device_info.device.id_, derivation_text,
                wizard.get_main_window())
        except Exception as e:
            MessageBox.show_error(str(e))
            return False

        data = {
            'hw_type': name,
            'derivation': self._derivation_user,
            'xpub': mpk.to_extended_key_string(),
            'label': device_info.label,
        }
        _keystore = instantiate_keystore(DerivationType.HARDWARE, data)
        wallet.create_account_from_keystore(_keystore)

        return True


class CosignWidget(QWidget):
    size = 200

    def __init__(self, m: int, n: int) -> None:
        QWidget.__init__(self)
        self.setMinimumHeight(self.size)
        self.setMaximumHeight(self.size)
        self.m = m
        self.n = n

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
            qp.setBrush(Qt.green if i<self.m else Qt.gray)
            qp.drawPie(x, 0, self.size, self.size, alpha, alpha2)
        qp.end()


class CreateMultisigAccountPage(QWizardPage):
    def __init__(self, wizard: AccountWizard):
        super().__init__(wizard)

        self.setTitle(_("Create a Multi-signature Account"))
        self.setFinalPage(False)

        cw = CosignWidget(2, 2)

        m_edit = QSlider(Qt.Horizontal, self)
        n_edit = QSlider(Qt.Horizontal, self)
        n_edit.setMinimum(2)
        n_edit.setMaximum(15)
        m_edit.setMinimum(1)
        m_edit.setMaximum(2)
        n_edit.setValue(2)
        m_edit.setValue(2)
        n_label = QLabel()
        m_label = QLabel()
        grid = QGridLayout()
        grid.setContentsMargins(50, 10, 50, 10)
        grid.addWidget(n_label, 0, 0)
        grid.addWidget(n_edit, 0, 1)
        grid.addWidget(m_label, 1, 0)
        grid.addWidget(m_edit, 1, 1)
        def on_m(m: int) -> None:
            m_label.setText(_('Require %d signatures')%m)
            cw.set_m(m)
        def on_n(n: int) -> None:
            n_label.setText(_('From %d cosigners')%n)
            cw.set_n(n)
            m_edit.setMaximum(n)
        n_edit.valueChanged.connect(on_n)
        m_edit.valueChanged.connect(on_m)
        on_n(2)
        on_m(2)
        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(cw)
        vbox.addStretch(1)
        vbox.addWidget(WWLabel(_("Choose the number of signatures needed to unlock "
                                 "funds in your account:")))
        vbox.addLayout(grid)
        vbox.addStretch(1)

        self.setLayout(vbox)

    def nextId(self):
        return -1

