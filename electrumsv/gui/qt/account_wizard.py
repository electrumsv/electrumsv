import enum
from typing import Any, List, Optional, Tuple

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QPainter, QPalette, QPen, QPixmap, QTextOption
from PyQt5.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QLabel, QWizard, QWizardPage, QGridLayout, QListWidget,
    QListWidgetItem, QSlider, QTextEdit, QWidget
)

from electrumsv.app_state import app_state
from electrumsv.exceptions import InvalidPassword
from electrumsv.device import DeviceInfo
from electrumsv.i18n import _
from electrumsv import keystore
from electrumsv.logs import logs
from electrumsv import wallet_support

from .main_window import ElectrumWindow
from .password_dialog import PasswordLineEdit
from .util import ChoicesLayout, icon_path, MessageBoxMixin, read_QIcon, WWLabel

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
    "setup.")


class AccountPages(enum.IntEnum):
    ADD_ACCOUNT_MENU = 12
    CREATE_NEW_STANDARD_ACCOUNT = 13
    CREATE_NEW_MULTISIG_ACCOUNT = 14
    IMPORT_ACCOUNT_FILE = 15
    IMPORT_ACCOUNT_TEXT = 16
    # Hardware wallets.
    FIND_HARDWARE_WALLET = 51
    SETUP_HARDWARE_WALLET = 52
    #
    IMPORT_ACCOUNT_IDENTIFY_USAGE = 100


class AccountWizard(MessageBoxMixin, QWizard):
    _last_page_id = None
    _selected_device: Optional[Tuple[str, DeviceInfo]] = None

    def __init__(self, main_window: ElectrumWindow) -> None:
        super().__init__(main_window)

        self._main_window = main_window
        self._wallet = main_window._wallet

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
            if entry.get("disabled", False):
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
                    "standard account is one where you are in control of all payments.")
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
                'disabled': True,
            },
            {
                'page': AccountPages.IMPORT_ACCOUNT_FILE,
                'description': _("Import account file"),
                'icon_filename': 'icons8-document.svg',
                'long_description': _("..."),
                'disabled': True,
            },
            {
                'page': AccountPages.IMPORT_ACCOUNT_TEXT,
                'description': _("Import account using text (any seed phrase, public keys, "+
                                 "private keys or addresses)"),
                'icon_filename': 'icons8-brain-80.png',
                'long_description': _("If you have some text to paste, or type in, and want "
                    "ElectrumSV to examine it and offer you some choices on how it can be "
                    "imported, this is the option you probably want."),
                'disabled': True,
            },
            {
                'page': AccountPages.FIND_HARDWARE_WALLET,
                'description': _("Import hardware wallet"),
                'icon_filename': 'icons8-usb-2-80.png',
                'disabled': True,
            },
        ]


class ImportWalletTextPage(QWizardPage):
    def __init__(self, wizard: AccountWizard):
        super().__init__(wizard)

        self.setTitle(_("Import Account From Text"))
        self.setFinalPage(False)

        self._text_matches = set([])
        self._text_value = None

        self.text_area = QTextEdit()
        self.text_area.textChanged.connect(self._on_text_changed)
        self.text_area.setAcceptRichText(False)
        self.text_area.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        self.text_area.setTabChangesFocus(True)

        # Beats me.
        self.registerField("wallet-import-text*", self.text_area, "plainText",
            self.text_area.textChanged)

        label_text = self._get_label_text()
        label_area = self._label = QLabel(label_text)
        label_area.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        label_area.setContentsMargins(10, 20, 10, 20)

        layout = QVBoxLayout()
        layout.addWidget(self.text_area)
        layout.addWidget(label_area)

        self.setLayout(layout)

    def get_text_value(self):
        return self._text_value

    def set_text_value(self, value):
        self._text_value = value

    text_value = property(get_text_value, set_text_value)

    def _get_label_text(self):
        text = self.text_area.toPlainText().strip()

        general_name = _('Private key')
        error_name = _('error identifying text')
        if len(self._text_matches) == 0:
            if len(text):
                return _("The text you have entered above is unrecognized.")
            return _("Please enter some wallet-related text above.")

        if len(self._text_matches) > 1:
            return f"{general_name} ({_('ambiguous matches')})"

        if wallet_support.TextImportTypes.PRIVATE_KEY_MINIKEY in self._text_matches:
            return f"{general_name} ({_('minikey')})"

        if wallet_support.TextImportTypes.PRIVATE_KEY_SEED in self._text_matches:
            matches = wallet_support.find_matching_seed_word_types(text)
            error_name = _("error identifying seed words")

            if len(matches) > 1:
                return f"{general_name} ({_('ambiguous seed words')})"
            elif wallet_support.SeedWordTypes.ELECTRUM_OLD in matches:
                return f"{general_name} ({_('Electrum old seed words')})"
            elif wallet_support.SeedWordTypes.ELECTRUM_NEW in matches:
                return f"{general_name} ({_('Electrum seed words')})"
            elif wallet_support.SeedWordTypes.BIP39 in matches:
                return f"{general_name} ({_('BIP39 seed words')})"

        return f"{_('Private key')} ({error_name})"

    def _on_text_changed(self):
        """ The contents of the text area have changed. """
        text = self.text_area.toPlainText().strip()
        new_text_matches = wallet_support.find_matching_text_import_types(text)
        if new_text_matches != self._text_matches:
            self._text_matches = new_text_matches
        self._label.setText(self._get_label_text())

    def isFinalPage(self):
        return False

    def isComplete(self):
        return len(self._text_matches)

    def validatePage(self):
        return self.isComplete()

    def nextId(self):
        return -1


class CreateStandardAccountPage(QWizardPage):
    _is_complete = False
    _is_final_page = False

    def __init__(self, parent: AccountWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Create a Standard Account"))
        self.setFinalPage(True)

        vbox = QVBoxLayout()

        label = QLabel(PASSWORD_EXISTING_TEXT + "\n")
        label.setWordWrap(True)

        logo_grid = QGridLayout()
        logo_grid.setSpacing(8)
        logo_grid.setColumnMinimumWidth(0, 70)
        logo_grid.setColumnStretch(1,1)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)

        logo_grid.addWidget(logo,  0, 0)
        logo_grid.addWidget(label, 0, 1, 1, 2)

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
        lockfile = "lock.png"
        logo.setPixmap(QPixmap(icon_path(lockfile)).scaledToWidth(36))

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

    def _create_account(self, password: str) -> None:
        from electrumsv import mnemonic
        seed_phrase = mnemonic.Mnemonic('en').make_seed('standard')
        k = keystore.from_seed(seed_phrase, '')
        k.update_password(password)

        wizard: AccountWizard = self.wizard()
        wizard._wallet.create_account_from_keystore(k)


class FindHardwareWalletAccountPage(QWizardPage):
    _selected_device: Optional[Tuple[str, DeviceInfo]]
    _devices: List[Tuple[str, DeviceInfo]]
    _device_debug_message: Optional[str]

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
        self._scan_attempt()

        button = self.wizard().button(QWizard.CustomButton1)
        button.setVisible(True)
        button.setText(_("&Rescan"))
        button.setContentsMargins(10, 0, 10, 0)
        button.clicked.connect(self._on_rescan_clicked)

    def on_leave(self) -> None:
        button = self.wizard().button(QWizard.CustomButton1)
        button.setVisible(False)
        button.clicked.disconnect()

    def _on_rescan_clicked(self, *checked) -> None:
        self._scan_attempt()

    def _scan_attempt(self) -> None:
        self._scan_devices()
        self.completeChanged.emit()

        if len(self._devices):
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
        else:
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

    def _scan_devices(self) -> None:
        self._selected_device = None
        self._devices = []
        self._device_debug_message = None

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
        return False

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        return self._plugin_debug_message is None and self._plugin is not None

    def on_enter(self) -> None:
        self._setup_attempt()

        # f = lambda x: self.run('on_hw_derivation', name, device_info, str(x))
        # if self.wallet_type=='multisig':
        #     # There is no general standard for HD multisig.
        #     # This is partially compatible with BIP45; assumes index=0
        #     default_derivation = "m/45'/0"
        # else:
        #     default_derivation = bip44_derivation_cointype(0, 0)
        # self.derivation_dialog(f, default_derivation)

    def _setup_attempt(self) -> None:
        self._setup_device()
        self.completeChanged.emit()

        wizard: AccountWizard = self.wizard()
        name, device_info = wizard.get_selected_device()

        if self._plugin_debug_message is None:
            text = DEVICE_SETUP_SUCCESS_TEXT.format(name.capitalize())

            label = QLabel(text + "\n")
            label.setWordWrap(True)

            logo_grid = QGridLayout()
            logo_grid.setSpacing(18)
            logo_grid.setColumnMinimumWidth(0, 70)
            logo_grid.setColumnStretch(1,1)

            logo = QLabel()
            logo.setAlignment(Qt.AlignCenter)
            logo_filename = "icons8-usb-connected-80.png"
            logo.setPixmap(QPixmap(icon_path(logo_filename)).scaledToWidth(80))

            logo_grid.addWidget(logo,  0, 0)
            logo_grid.addWidget(label, 0, 1, 1, 2)

            grid = QGridLayout()
            grid.setSpacing(8)
            grid.setColumnMinimumWidth(0, 150)
            grid.setColumnMinimumWidth(1, 100)
            grid.setColumnStretch(1,1)

            default_derivation =  keystore.bip44_derivation_cointype(0, 0)
            wallet_type = "standard"
            message = '\n'.join([
                _('Enter your wallet derivation here.  If you are not sure what this is, '
                'leave this field unchanged.\n'),
                _("The default value of {} is the default derivation for {} wallets.  "
                "This matches BTC wallet addresses and most other BSV wallet software.")
                .format(default_derivation, wallet_type),
                _("To match BCH wallet addresses use m/44'/145'/0'"),
            ])

            pwlabel = QLabel(_('Password:'))
            pwlabel.setAlignment(Qt.AlignTop)
            grid.addWidget(pwlabel, 0, 0)
            grid.addWidget(self._password_edit, 0, 1)
            lockfile = "lock.png"
            logo.setPixmap(QPixmap(icon_path(lockfile)).scaledToWidth(36))

            vbox = QVBoxLayout()
            vbox.setContentsMargins(10, 10, 20, 10)
            vbox.addLayout(logo_grid)
            vbox.addSpacing(10)
            pass
            vbox.addStretch(1)

            if self.layout():
                QWidget().setLayout(self.layout())
            self.setLayout(vbox)
        else:
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

