# TODO:
# - QTableWidget vs. QListView
#
#   Consolidate the use of QTableWidget and QListView between the wallet selection screen and
#   the add wallet screen. The decision holding the choice back, is the need to both sort and
#   filter the contents. I suspect that the choice may not matter though and we should go with
#   one or the other.
#
# - Interrupted migration
#
#   Should not only stop the migration process, but it should also delete any changes and
#   restore the backup? Better in the short term to prevent cancellation.
#

import enum
import os
from typing import Any, Dict, Optional

from bitcoinx import DecryptionError
from PyQt5.QtCore import Qt, QItemSelection, QModelIndex
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QVBoxLayout, QTableWidget, QAbstractItemView, QWidget, QHBoxLayout, QLabel, QWizard,
    QWizardPage, QHeaderView, QTextBrowser, QPushButton, QSizePolicy, QFileDialog, QGridLayout,
    QLineEdit, QProgressBar
)

from electrumsv.app_state import app_state
from electrumsv.constants import StorageKind
from electrumsv.crypto import pw_encode
from electrumsv.exceptions import IncompatibleWalletError, InvalidPassword
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.storage import WalletStorage, categorise_file
from electrumsv.util import get_wallet_name_from_path
from electrumsv.version import PACKAGE_VERSION
from electrumsv.wallet import Wallet

from .password_dialog import PasswordLayout, PasswordAction, PasswordLineEdit
from .util import icon_path, MessageBox


logger = logs.get_logger('wizard-wallet')

PASSWORD_MISSING_TEXT = _("This wallet is an older format that does not have a password. To "
    "be able to import it, you need to provide a password so that it's data can be "
    "secured.")
PASSWORD_NEW_TEXT = _("Your password only encrypts your private keys and other essential data, "
    "only your choice of location secures the privacy of the rest of your wallet data.")
PASSWORD_EXISTING_TEXT = _("Your wallet has a password, you will need to provide that password "
    "in order to access it. You will also be asked to provide it later, when your permission "
    "is needed for secure operations.")


class WalletAction(enum.IntEnum):
    NONE = 0
    OPEN = 1
    CREATE = 2

class WalletPage(enum.IntEnum):
    NONE = 0
    SPLASH_SCREEN = 1
    RELEASE_NOTES = 2
    CHOOSE_WALLET = 3
    PRECREATION_PASSWORD_ADDITION = 4
    PREMIGRATION_PASSWORD_ADDITION = 5
    PREMIGRATION_PASSWORD_REQUEST = 6
    MIGRATE_OLDER_WALLET = 7

class PasswordState(enum.IntEnum):
    UNKNOWN = 0
    NO_PASSWORD = 1
    EXISTING_PASSWORD = 2


class WalletWizard(QWizard):
    _handle_initial_wallet: bool = False
    _last_page_id = WalletPage.NONE
    _wallet_type = StorageKind.UNKNOWN
    _wallet_action = WalletAction.NONE
    _wallet_path: Optional[str] = None
    _wallet_password: Optional[str] = None
    _password_state = PasswordState.UNKNOWN
    _wallet: Optional[Wallet] = None

    def __init__(self, initial_path: str, is_startup=False):
        super().__init__(None)

        self._handle_initial_wallet = initial_path and not is_startup

        self._initial_path = initial_path
        self._recently_opened_entries = None

        self.setWindowTitle('ElectrumSV')
        self.setMinimumSize(600, 600)
        self.setOption(QWizard.IndependentPages, False)
        self.setOption(QWizard.NoDefaultButton, True)
        # TODO: implement consistent help
        self.setOption(QWizard.HaveHelpButton, False)
        self.setOption(QWizard.HaveCustomButton1, True)

        self.setPage(WalletPage.SPLASH_SCREEN, SplashScreenPage(self))
        self.setPage(WalletPage.RELEASE_NOTES, ReleaseNotesPage(self))
        self.setPage(WalletPage.CHOOSE_WALLET, ChooseWalletPage(self))
        self.setPage(WalletPage.PRECREATION_PASSWORD_ADDITION, CreateNewWalletPage(self))
        self.setPage(WalletPage.PREMIGRATION_PASSWORD_ADDITION,
            AddPasswordBeforeMigrationPage(self))
        self.setPage(WalletPage.PREMIGRATION_PASSWORD_REQUEST,
            RequestPasswordBeforeMigrationPage(self))
        self.setPage(WalletPage.MIGRATE_OLDER_WALLET, OlderWalletMigrationPage(self))

        self.currentIdChanged.connect(self.on_current_id_changed)

        if is_startup:
            self.setStartId(WalletPage.SPLASH_SCREEN)
        else:
            self.setStartId(WalletPage.CHOOSE_WALLET)

    def run(self):
        self.ensure_shown()
        try:
            result = self.exec()
        finally:
            self.set_wallet(None)
        return result

    def ensure_shown(self):
        self.show()
        self.raise_()

    def on_current_id_changed(self, page_id: WalletPage):
        if self._last_page_id != WalletPage.NONE:
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

    def get_initial_path(self) -> str:
        return self._initial_path

    def should_handle_initial_wallet(self) -> bool:
        return self._handle_initial_wallet

    def clear_handle_initial_wallet(self) -> None:
        self._handle_initial_wallet = False

    def set_wallet_action(self, action: WalletAction) -> None:
        self._wallet_action = action

    def get_wallet(self) -> Optional[Wallet]:
        return self._wallet

    def set_wallet(self, wallet: Optional[Wallet]) -> None:
        if self._wallet is not None:
            self._wallet.stop()
        self._wallet = wallet

    def set_wallet_path(self, wallet_path: Optional[str]) -> None:
        self._wallet_path = wallet_path

    def get_wallet_path(self) -> str:
        return self._wallet_path

    def set_wallet_type(self, wallet_type: StorageKind) -> None:
        self._wallet_type = wallet_type

    def get_wallet_type(self) -> StorageKind:
        return self._wallet_type

    def set_password_state(self, state: PasswordState) -> None:
        self._password_state = state

    def get_password_state(self) -> PasswordState:
        return self._password_state

    def set_wallet_password(self, password: Optional[str]) -> None:
        self._wallet_password = password

    def get_wallet_password(self) -> Optional[str]:
        return self._wallet_password


class SplashScreenPage(QWizardPage):
    _next_page_id = WalletPage.NONE

    def __init__(self, parent):
        super().__init__(parent)

        layout = QVBoxLayout()
        logo_layout = QHBoxLayout()
        logo_label = QLabel()
        logo_label.setPixmap(QPixmap(icon_path("title_logo.png"))
            .scaledToWidth(500, Qt.SmoothTransformation))
        logo_layout.addStretch(1)
        logo_layout.addWidget(logo_label)
        logo_layout.addStretch(1)
        layout.addLayout(logo_layout)
        version_label = QLabel(f"<b><big>v{PACKAGE_VERSION}</big></b>")
        version_label.setAlignment(Qt.AlignHCenter)
        version_label.setTextFormat(Qt.RichText)
        layout.addWidget(version_label)
        layout.addStretch(1)
        release_text = (
            "<big>"+
            "<p>"+
            _("ElectrumSV is a lightweight SPV wallet for Bitcoin SV.") +
            "</p>"+
            "<p>"+
            _("Bitcoin SV is the only Bitcoin that follows "+
            "the original whitepaper<br/> and values being stable and non-experimental.") +
            "</p>"+
            "</big>")
        release_label = QLabel(release_text)
        release_label.setAlignment(Qt.AlignHCenter)
        release_label.setWordWrap(True)
        layout.addWidget(release_label)
        layout.addStretch(1)

        self.setLayout(layout)

        self._on_reset_next_page()

    def _on_reset_next_page(self) -> None:
        self._next_page_id = WalletPage.CHOOSE_WALLET

    def _on_release_notes_clicked(self, *checked) -> None:
        # Change the page to the release notes page by intercepting nextId.
        self._next_page_id = WalletPage.RELEASE_NOTES
        self.wizard().next()

    def nextId(self) -> WalletPage:
        return self._next_page_id

    def on_enter(self) -> None:
        self._on_reset_next_page()

        button = self.wizard().button(QWizard.CustomButton1)
        button.setVisible(True)
        button.setText("    "+ _("Release notes") +"    ")
        button.setContentsMargins(10, 0, 10, 0)
        button.clicked.connect(self._on_release_notes_clicked)

    def on_leave(self) -> None:
        button = self.wizard().button(QWizard.CustomButton1)
        button.setVisible(False)
        button.clicked.disconnect()


class ReleaseNotesPage(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)

        self.setTitle(_("Release Notes"))

        # TODO: Relocate the release note text from dialogs.
        # TODO: Make it look better and more readable, currently squashed horizontally.

        widget = QTextBrowser()
        widget.setAcceptRichText(True)
        widget.setHtml("...")

        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)

    def nextId(self) -> WalletPage:
        return WalletPage.CHOOSE_WALLET


class ChooseWalletPage(QWizardPage):
    _force_completed = False

    def __init__(self, parent: WalletWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Select an existing wallet"))
        self.setButtonText(QWizard.NextButton, "  "+ _("Open &Selected Wallet") +"  ")

        vlayout = QVBoxLayout()

        page = self
        class TableWidget(QTableWidget):
            def keyPressEvent(self, event):
                key = event.key()
                if key == Qt.Key_Return or key == Qt.Key_Enter:
                    page._on_key_selection()
                else:
                    super(TableWidget, self).keyPressEvent(event)

        self._wallet_table = TableWidget()
        #self._wallet_table.setIconSize(QSize(24, 24))
        self._wallet_table.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self._wallet_table.doubleClicked.connect(self._on_entry_doubleclicked)

        if not parent.should_handle_initial_wallet():
            self._populate_list()

        vlayout.addWidget(self._wallet_table)

        tablebutton_layout = QHBoxLayout()
        self.file_button = QPushButton("  "+ _("Open &Other Wallet") +"  ")
        self.file_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        self.file_button.clicked.connect(self._on_open_file_click)
        tablebutton_layout.addStretch()
        tablebutton_layout.addWidget(self.file_button, Qt.AlignRight)
        vlayout.addLayout(tablebutton_layout)

        self.setLayout(vlayout)

        self._recent_wallet_entries: Dict[str, Any] = {}
        self._on_reset_next_page()

    def _on_reset_next_page(self) -> None:
        self._next_page_id = WalletPage.PREMIGRATION_PASSWORD_ADDITION

    def _populate_list(self) -> None:
        while self._wallet_table.rowCount():
            self._wallet_table.removeRow(self._wallet_table.rowCount()-1)

        unlocked_pixmap = QPixmap(icon_path("icons8-lock-80.png")).scaledToWidth(
            40, Qt.SmoothTransformation)

        self._wallet_table.setHorizontalHeaderLabels([ "Recently Opened Wallets" ])

        hh = self._wallet_table.horizontalHeader()
        hh.setStretchLastSection(True)

        vh = self._wallet_table.verticalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeToContents)
        vh.hide()

        self._wallet_table.setColumnCount(1)
        self._wallet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._wallet_table.setStyleSheet("""
            QTableView {
                selection-background-color: #F5F8FA;
            }
            QHeaderView::section {
                font-weight: bold;
            }
        """)
        # Tab by default in QTableWidget, moves between list items. The arrow keys also perform
        # the same function, and we want tab to allow toggling to the wizard button bar instead.
        self._wallet_table.setTabKeyNavigation(False)

        recent_wallet_entries = self._get_recently_opened_wallets()
        for d in recent_wallet_entries:
            row_index = self._wallet_table.rowCount()
            self._wallet_table.insertRow(row_index)

            row_widget = QWidget()
            row_layout = QHBoxLayout()
            row_layout.setSpacing(0)
            row_layout.setContentsMargins(0, 0, 0, 0)

            row_icon_label = QLabel()
            row_icon_label.setPixmap(unlocked_pixmap)
            row_icon_label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
            row_icon_label.setMaximumWidth(80)

            row_desc_label = QLabel(d['name'])

            row_layout.addWidget(row_icon_label)
            row_layout.addWidget(row_desc_label)

            row_widget.setLayout(row_layout)
            self._wallet_table.setCellWidget(row_index, 0, row_widget)

        self._recent_wallet_entries = recent_wallet_entries

    def nextId(self) -> WalletPage:
        return self._next_page_id

    def isFinalPage(self) -> bool:
        return False

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        if self._force_completed:
            return True
        return len(self._wallet_table.selectedIndexes())

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        return self.isComplete()

    def _get_recently_opened_wallets(self) -> Dict[str, Any]:
        results = []
        for file_path in app_state.config.get('recently_open', []):
            if os.path.exists(file_path) and categorise_file(file_path) != StorageKind.HYBRID:
                results.append({
                    'name': get_wallet_name_from_path(file_path),
                    'path': file_path,
                })

        return results

    def _attempt_open_wallet(self, wallet_path: str, change_page: bool=False) -> bool:
        try:
            storage = WalletStorage(wallet_path)
        except Exception:
            logger.exception("problem looking at selected wallet '%s'", wallet_path)
            MessageBox.show_error(_("Unrecognised or unsupported wallet file."))
            return False

        try:
            storage_info = categorise_file(wallet_path)
            if storage_info.kind == StorageKind.HYBRID:
                MessageBox.show_error(_("Unrecognised or unsupported wallet file."))
                return False

            wallet_type = StorageKind.FILE if storage.is_legacy_format() else StorageKind.DATABASE
            if wallet_type == StorageKind.FILE:
                text_store = storage.get_text_store()
                text_store.attempt_load_data()
                if storage.get("use_encryption") or text_store.is_encrypted():
                    # If there is a password and the wallet is not encrypted, then the private data
                    # is encrypted. If there is a password and the wallet is encrypted, then the
                    # private data is encrypted and the file is encrypted.
                    self._next_page_id = WalletPage.PREMIGRATION_PASSWORD_REQUEST
                else:
                    # Neither the private data is encrypted or the file itself.
                    self._next_page_id = WalletPage.PREMIGRATION_PASSWORD_ADDITION
            else:
                self._next_page_id = WalletPage.PREMIGRATION_PASSWORD_REQUEST
        finally:
            storage.close()

        self._force_completed = True

        wizard: WalletWizard = self.wizard()
        wizard.set_wallet_action(WalletAction.OPEN)
        wizard.set_wallet_type(wallet_type)
        wizard.set_wallet_path(wallet_path)

        if change_page:
            wizard.next()

        return True

    def _on_open_file_click(self) -> None:
        initial_path = self.wizard().get_initial_path()
        wallet_folder = os.path.dirname(initial_path)
        path, __ = QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder)
        if path:
            self._attempt_open_wallet(path, change_page=True)

    def _on_selection_changed(self, selected: QItemSelection, deselected: QItemSelection) -> None:
        # Selecting an entry should change the page elements to be ready to either move to another
        # page, or whatever else is applicable.
        selected_page = False
        if len(selected.indexes()):
            wallet_path = self._recent_wallet_entries[selected.indexes()[0].row()]['path']
            selected_page = self._attempt_open_wallet(wallet_path)

        # Therefore if there was nothing valid selected with this event, then disable those
        # elements.
        if not selected_page:
            self._reset()

        self.completeChanged.emit()

    def _on_key_selection(self) -> None:
        wizard: WalletWizard = self.wizard()
        if wizard._wallet_action == WalletAction.OPEN:
            wizard.next()

    def _on_entry_doubleclicked(self, index: QModelIndex) -> None:
        wallet_path = self._recent_wallet_entries[index.row()]['path']
        self._attempt_open_wallet(wallet_path, change_page=True)

    def _on_new_wallet_clicked(self) -> None:
        # Change the page to the wallet creation page by intercepting nextId.
        self._next_page_id = WalletPage.PRECREATION_PASSWORD_ADDITION
        self._force_completed = True

        wizard: WalletWizard = self.wizard()
        wizard.set_wallet_action(WalletAction.CREATE)
        wizard.next()

    def _reset(self) -> None:
        self._force_completed = False
        self._on_reset_next_page()

        wizard: WalletWizard = self.wizard()
        wizard.set_wallet(None)
        wizard.set_wallet_type(StorageKind.UNKNOWN)
        wizard.set_wallet_path(None)

    def on_enter(self) -> None:
        self._reset()

        wizard: WalletWizard = self.wizard()
        wizard.set_password_state(PasswordState.UNKNOWN)

        button = self.wizard().button(QWizard.CustomButton1)
        button.setVisible(True)
        button.setText("  "+ _("Create &New Wallet") +"  ")
        button.clicked.connect(self._on_new_wallet_clicked)

        if wizard.should_handle_initial_wallet():
            initial_path = wizard.get_initial_path()
            info = categorise_file(initial_path)
            if info.exists():
                wizard.clear_handle_initial_wallet()
                if self._attempt_open_wallet(wizard._initial_path, change_page=True):
                    # Avoid the slow list population.
                    return
            else:
                self._on_new_wallet_clicked()
                return

        self._populate_list()
        self._wallet_table.setFocus()

    def on_leave(self) -> None:
        button = self.wizard().button(QWizard.CustomButton1)
        button.setVisible(False)
        button.clicked.disconnect()


class AddPasswordBeforeMigrationPage(QWizardPage):
    _password_completed = False

    def __init__(self, parent: WalletWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Open wallet"))

        vbox = QVBoxLayout()

        def password_change_cb(state: bool) -> None:
            new_password = self._get_password()

            wizard: WalletWizard = self.wizard()
            wizard.set_wallet_password(new_password)
            wizard.set_password_state(PasswordState.NO_PASSWORD)

            self._password_completed = state and new_password is not None
            self.completeChanged.emit()

        self._add_password_object = PasswordLayout(None,
            PASSWORD_MISSING_TEXT +"\n\n"+ PASSWORD_NEW_TEXT, PasswordAction.NEW,
            password_change_cb)
        self._add_password_object.pw.setVisible(False)
        self._add_password_object.new_pw.text_submitted_signal.connect(self._on_password_submitted)

        vbox.addLayout(self._add_password_object.layout())

        hlayout = QHBoxLayout()
        hlayout.addStretch(1)
        hlayout.addLayout(vbox)
        hlayout.addStretch(1)
        self.setLayout(hlayout)

    def nextId(self) -> WalletPage:
        return WalletPage.MIGRATE_OLDER_WALLET

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        return self._password_completed

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        return self.isComplete()

    def _on_password_submitted(self) -> None:
        if self._password_completed:
            wizard: WalletWizard = self.wizard()
            wizard.next()

    def on_enter(self) -> None:
        self._password_completed = False
        self._add_password_object.pw.setText("")
        self._add_password_object.new_pw.setText("")
        self._add_password_object.conf_pw.setText("")

        self._load_wallet()

    def on_leave(self) -> None:
        pass

    def _load_wallet(self) -> None:
        wizard: WalletWizard = self.wizard()
        if wizard.get_wallet() is not None:
            return None
        wallet_path = wizard.get_wallet_path()
        wizard.set_wallet(Wallet(WalletStorage(wallet_path)))

    def _get_password(self) -> Optional[str]:
        new_password = self._add_password_object.new_pw.text().strip()
        return new_password if len(new_password) else None


class RequestPasswordBeforeMigrationPage(QWizardPage):
    _is_complete = False
    _is_final_page = False

    def __init__(self, parent: WalletWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Open wallet"))

        vbox = QVBoxLayout()

        self._password_edit = PasswordLineEdit()
        # We use `textEdited` to get manual changes, but not programmatic ones.
        self._password_edit.textEdited.connect(self._on_password_changed)
        self._password_edit.text_submitted_signal.connect(self._on_password_submitted)

        label = QLabel(PASSWORD_EXISTING_TEXT + "\n")
        label.setWordWrap(True)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)

        logo_grid = QGridLayout()
        logo_grid.setSpacing(8)
        logo_grid.setColumnMinimumWidth(0, 70)
        logo_grid.setColumnStretch(1,1)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)

        logo_grid.addWidget(logo,  0, 0)
        logo_grid.addWidget(label, 0, 1, 1, 2)

        pwlabel = QLabel(_('Password') +":")
        grid.addWidget(pwlabel, 0, 0, Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self._password_edit, 0, 1, Qt.AlignLeft)
        lockfile = "lock.png"
        logo.setPixmap(QPixmap(icon_path(lockfile)).scaledToWidth(36))

        vbox.addLayout(logo_grid)
        vbox.addLayout(grid)

        hlayout = QHBoxLayout()
        hlayout.addStretch(1)
        hlayout.addLayout(vbox)
        hlayout.addStretch(1)
        self.setLayout(hlayout)

    def _load_wallet(self) -> None:
        wizard: WalletWizard = self.wizard()
        wallet_path = wizard.get_wallet_path()
        wizard.set_wallet(Wallet(WalletStorage(wallet_path)))

    def nextId(self) -> WalletPage:
        if self._is_final_page:
            return -1
        return WalletPage.MIGRATE_OLDER_WALLET

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        return self._is_complete

    def validatePage(self) -> bool:
        return True

    def on_enter(self) -> None:
        self._load_wallet()

    def on_leave(self) -> None:
        self._password_edit.setText("")

    def _on_password_changed(self, text: str) -> None:
        wizard: WalletWizard = self.wizard()
        wallet = wizard.get_wallet()
        storage = wallet.get_storage()

        was_complete = self._is_complete
        self._is_complete = False

        if wizard.get_wallet_type() == StorageKind.FILE:
            text_store = storage.get_text_store()
            text_store.attempt_load_data()
            try:
                text_store.decrypt(text)
                self._is_complete = True
            except DecryptionError:
                pass
        else:
            try:
                wallet.check_password(text)
                self._is_complete = True
            except InvalidPassword:
                pass

        if was_complete == self._is_complete:
            return

        wizard: WalletWizard = self.wizard()
        wizard.set_wallet_password(text)
        wizard.set_password_state(PasswordState.EXISTING_PASSWORD)

        self._is_final_page = not (storage.requires_split() or storage.requires_upgrade())
        self.setFinalPage(self._is_final_page)
        self.completeChanged.emit()

    def _on_password_submitted(self) -> None:
        if self._is_complete:
            wizard: WalletWizard = self.wizard()
            if self._is_final_page:
                wizard.accept()
            else:
                wizard.next()

    def _get_password(self) -> str:
        return self._password_edit.text().strip()


class OlderWalletMigrationPage(QWizardPage):
    _migration_completed = False
    _migration_successful = False
    _migration_error_text: str = _("Unexpected migration failure.")

    def __init__(self, parent: WalletWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Migrating wallet.."))
        self.setFinalPage(True)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 0)
        self._progress_bar.setOrientation(Qt.Horizontal)
        self._progress_bar.setMinimumWidth(250)
        # This explicitly needs to be done for the progress bar otherwise it has some RHS space.
        self._progress_bar.setAlignment(Qt.AlignCenter)

        self._progress_label = QLabel(_("Please wait while your wallet is backed up and migrated "
            "to the new format."))

        vbox = QVBoxLayout()
        vbox.addStretch(1)
        vbox.addWidget(self._progress_bar, alignment=Qt.AlignCenter)
        vbox.addWidget(self._progress_label, alignment=Qt.AlignCenter)
        vbox.addStretch(1)

        hlayout = QHBoxLayout()
        hlayout.addStretch(1)
        hlayout.addLayout(vbox)
        hlayout.addStretch(1)
        self.setLayout(hlayout)

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        return self._migration_completed

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        return self.isComplete()

    def on_enter(self) -> None:
        self._migration_completed = False
        self._migration_successful = False
        self._migration_error_text = self.__class__._migration_error_text
        self._future = app_state.app.run_in_thread(self._migrate_wallet,
            on_done=self._on_migration_completed)

    def on_leave(self) -> None:
        self._future.cancel()
        self._future = None

    def _migrate_wallet(self) -> None:
        try:
            self._migrate_wallet2()
        except Exception:
            logger.exception("unexpected migration error")

    def _migrate_wallet2(self) -> None:
        logger.debug("wallet migration started")

        wizard: WalletWizard = self.wizard()
        wallet_path = wizard.get_wallet_path()
        password_state = wizard.get_password_state()
        wallet_password = wizard.get_wallet_password()

        wallet = wizard.get_wallet()
        storage = wallet.get_storage()
        text_store = storage.get_text_store()
        if password_state == PasswordState.EXISTING_PASSWORD:
            try:
                data = text_store.decrypt(wallet_password)
            except DecryptionError:
                # To get to this point the password had already been checked.
                self._migration_error_text = _("Unexpected wallet migration failure due to "
                    "invalid password.")
                return
            text_store.load_data(data)
            # The existing private data will already be encoded with this password.
        else:
            assert text_store.attempt_load_data()

        has_password = password_state == PasswordState.EXISTING_PASSWORD
        try:
            storage.upgrade(has_password, wallet_password)
        except IncompatibleWalletError as e:
            storage.close()
            logger.exception("wallet migration error '%s'", wallet_path)
            self._migration_error_text = e.args[0]
            return

        logger.debug("wallet migration successful")
        self._migration_successful = True

    def _on_migration_completed(self, _future: Any) -> None:
        if _future != self._future:
            logger.debug("wallet migration completion ignored (stale)")
            return

        logger.debug("wallet migration completed")
        self._migration_completed = True
        self._progress_bar.setRange(1, 5)
        self._progress_bar.setValue(5)

        if self._migration_successful:
            self._progress_label.setText(_("Your wallet has been backed up and migrated."))
        else:
            style_sheet = ("QProgressBar::chunk {background: QLinearGradient( x1: 0, y1: 0, "+
                "x2: 1, y2: 0,stop: 0 #FF0350,stop: 0.4999 #FF0020,stop: 0.5 #FF0019,"+
                "stop: 1 #FF0000 );border-bottom-right-radius: 5px;"+
                "border-bottom-left-radius: 5px;border: .px solid black;}")
            self._progress_bar.setStyleSheet(style_sheet)
            self._progress_label.setText(self._migration_error_text)

        self.completeChanged.emit()


class CreateNewWalletPage(QWizardPage):
    def __init__(self, parent: WalletWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Create a new wallet"))
        self.setFinalPage(True)

        filename_label = QLabel(_("File name") +":")
        self._filename_edit = QLineEdit()
        self._filename_edit.textChanged.connect(self._on_filename_changed)

        self._password_completed = False

        def password_change_cb(state: bool) -> None:
            self._password_completed = state
            self.completeChanged.emit()

        self._password_layout = PasswordLayout(None, PASSWORD_NEW_TEXT, PasswordAction.NEW,
            password_change_cb)

        select_button = QPushButton(_("Select"))
        select_button.clicked.connect(self._on_select_new_wallet_file)

        filename_layout = QHBoxLayout()
        filename_layout.addWidget(self._filename_edit)
        filename_layout.addWidget(select_button)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)
        grid.addWidget(filename_label, 0, 0, Qt.AlignRight | Qt.AlignVCenter)
        grid.addLayout(filename_layout, 0, 1, Qt.AlignLeft)

        self._error_label = QLabel()
        grid.addWidget(self._error_label, 1, 1)

        layout = QHBoxLayout()
        # It looks tidier with more separation between the two panes.
        layout.addStretch(1)
        vlayout = QVBoxLayout()
        vlayout.addLayout(grid)
        vlayout.addSpacing(30)
        vlayout.addLayout(self._password_layout.layout())
        layout.addLayout(vlayout)
        layout.addStretch(1)
        self.setLayout(layout)

    def nextId(self) -> int:
        return -1

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.

        # Condition 1: The wallet path has to be valid and not in use.
        # - If it is manually edited, warn if it already exists?
        # Condition 2: Passwords have been provided adequately.
        wallet_filepath = self._filename_edit.text().strip()
        if os.path.exists(wallet_filepath):
            return False
        dirpath, filename = os.path.split(wallet_filepath)
        if not dirpath or not os.path.isdir(dirpath) or not os.access(dirpath, os.R_OK | os.W_OK):
            return False
        return self._password_completed

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        result = self.isComplete()
        if result:
            new_password = self._password_layout.new_pw.text().strip()

            # If we are going to exit then create the empty wallet.
            wizard: WalletWizard = self.wizard()
            wallet_filepath = wizard.get_wallet_path()
            storage = WalletStorage(wallet_filepath)
            storage.put("password-token", pw_encode(os.urandom(32).hex(), new_password))
            storage.close()
        return result

    def _on_filename_changed(self, text: str) -> None:
        path = text.strip()
        if len(path):
            wizard: WalletWizard = self.wizard()
            wizard.set_wallet_path(text)
        self.completeChanged.emit()

    def _on_select_new_wallet_file(self) -> None:
        initial_path = self.wizard().get_initial_path()
        wallet_folder = os.path.dirname(initial_path)
        path, __ = QFileDialog.getSaveFileName(self, "Enter a new wallet file name", wallet_folder)

        self._filename_edit.setText(path.strip())

    def _set_filename_message(self, msg: str, is_error: bool=True, is_warning: bool=True) -> None:
        self._error_label.setText(msg)
        if is_error:
            self._error_label.setStyleSheet("color: red;")
        elif is_warning:
            self._error_label.setStyleSheet("color: yellow;")
        else:
            self._error_label.setStyleSheet("")

    def on_enter(self) -> None:
        # Automate populating the initial path.
        wizard: WalletWizard = self.wizard()
        if wizard.should_handle_initial_wallet():
            wizard.clear_handle_initial_wallet()
            self._filename_edit.setText(wizard.get_initial_path())
