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

import enum
import os
import shutil
import sys
import threading
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from bitcoinx import DecryptionError
from PyQt5.QtCore import pyqtSignal, Qt, QItemSelection, QModelIndex, QObject
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QAbstractItemView, QAction,
    QFileDialog, QHeaderView, QHBoxLayout, QLabel, QMenu,
    QProgressBar, QPushButton, QSizePolicy, QTableWidget, QTextBrowser,
    QVBoxLayout, QWidget, QWizard, QWizardPage
)

from electrumsv.app_state import app_state
from electrumsv.constants import DATABASE_EXT, IntFlag, MIGRATION_CURRENT, StorageKind
from electrumsv.exceptions import DatabaseMigrationError, IncompatibleWalletError
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.storage import WalletStorage, categorise_file
from electrumsv.util import get_wallet_name_from_path, read_resource_text
from electrumsv.version import PACKAGE_VERSION
from electrumsv.wallet import Wallet

from .util import (AspectRatioPixmapLabel, can_show_in_file_explorer, create_new_wallet, icon_path,
    MessageBox, show_in_file_explorer)
from .wizard_common import BaseWizard, HelpContext


logger = logs.get_logger('wizard-wallet')

PASSWORD_MISSING_TEXT = _("This wallet is an older format that does not have a password. To "
    "be able to import it, you need to provide a password so that key data can be "
    "secured.")
PASSWORD_NEW_TEXT = _("Your password only encrypts your private keys and other essential data, "
    "only your choice of location secures the privacy of the rest of your wallet data.")
PASSWORD_EXISTING_TEXT = _("Your wallet has a password, you will need to provide that password "
    "in order to access it. You will also be asked to provide it later, when your permission "
    "is needed for secure operations.")

PASSWORD_REQUEST_TEXT = _("Your wallet has a password, you will need to provide that password "
    "in order to access it.")

OPEN_DIRECTORY_IN_EXPLORER = _("Open directory in Explorer")
SHOW_IN_EXPLORER = _("Show in Explorer")
OPEN_FOLDER_IN_FINDER = _("Show folder in Finder")
SHOW_IN_FINDER = _("Show in Finder")


class WalletAction(enum.IntEnum):
    NONE = 0
    OPEN = 1
    CREATE = 2

class WalletPage(enum.IntEnum):
    NONE = 0
    SPLASH_SCREEN = 1
    RELEASE_NOTES = 2
    CHOOSE_WALLET = 3
    MIGRATE_OLDER_WALLET = 4

class PasswordState(IntFlag):
    UNKNOWN = 0
    NONE = 1
    PASSWORDED = 2
    ENCRYPTED = 4

class FileState(NamedTuple):
    name: Optional[str] = None
    path: Optional[str] = None
    action: WalletAction = WalletAction.NONE
    storage_kind: StorageKind = StorageKind.UNKNOWN
    password_state: PasswordState = PasswordState.UNKNOWN
    requires_upgrade: bool = False
    modification_time: int = 0
    is_too_modern: bool = False

class MigrationContext(NamedTuple):
    entry: FileState
    storage: WalletStorage
    password: str


def create_file_state(wallet_path: str) -> Optional[FileState]:
    if not os.path.exists(wallet_path):
        return None

    try:
        storage = WalletStorage(wallet_path)
    except Exception:
        logger.exception("problem looking at selected wallet '%s'", wallet_path)
        return None

    is_too_modern = False
    try:
        storage_info = categorise_file(wallet_path)
        if storage_info.kind == StorageKind.HYBRID:
            return None

        wallet_action = WalletAction.OPEN
        password_state = PasswordState.UNKNOWN

        if storage_info.kind == StorageKind.FILE:
            text_store = storage.get_text_store()
            try:
                text_store.attempt_load_data()
            except IOError:
                # IOError: storage.py:load_data() raises when selected file cannot be parsed.
                return None
            if storage.get("use_encryption"):
                # If there is a password and the wallet is not encrypted, then the private data
                # is encrypted.
                password_state = PasswordState.PASSWORDED
            elif text_store.is_encrypted():
                # If there is a password and the wallet is encrypted, then the private data is
                # encrypted and the file is encrypted.
                password_state = PasswordState.PASSWORDED | PasswordState.ENCRYPTED
            else:
                # Neither the private data is encrypted or the file itself.
                password_state = PasswordState.NONE
        else:
            assert storage_info.kind == StorageKind.DATABASE
            password_state = PasswordState.PASSWORDED
            database_store = storage.get_database_store()
            is_too_modern = database_store.get("migration") > MIGRATION_CURRENT

        requires_upgrade = storage.requires_split() or storage.requires_upgrade()
    finally:
        storage.close()

    name = get_wallet_name_from_path(wallet_path)
    modification_time = os.path.getmtime(wallet_path)
    return FileState(name, wallet_path, wallet_action, storage_info.kind, password_state,
        requires_upgrade, modification_time, is_too_modern)


def request_password(parent: Optional[QWidget], storage: WalletStorage, entry: FileState) \
        -> Optional[str]:
    name_edit = QLabel(entry.name)
    name_edit.setAlignment(Qt.AlignTop)
    fields = [
        (_("Wallet"), name_edit),
    ]

    if entry.password_state & PasswordState.PASSWORDED:
        from .password_dialog import PasswordDialog
        d = PasswordDialog(parent, PASSWORD_REQUEST_TEXT,
            fields=fields, password_check_fn=storage.is_password_valid)
        d.setMaximumWidth(200)
        return d.run()

    from .password_dialog import ChangePasswordDialog, PasswordAction
    d = ChangePasswordDialog(parent, PASSWORD_MISSING_TEXT,
            _("Add Password") +" - "+ _("Wallet Migration"), fields, kind=PasswordAction.NEW)
    success, _old_password, password = d.run()
    if success and len(password.strip()) > 0:
        return password
    return None


class WalletWizard(BaseWizard):
    """
    Wallet selection/creation related circumstances:
    - SHOWN: With no explicit path on application startup.
      - The wizard appears and it is up to the user to select or create a wallet.
    - MAYBE SHOWN: With an explicit path on application startup.
      - The user should get the password request then it should open or attempt a migration.
    - MAYBE SHOWN: Via the open wallet menu in an already open wallet window.
      - The user should get the password request then it should open or attempt a migration.
    - NOT SHOWN: Via the new wallet menu in an already open wallet window.
      - The user should get asked for a password for the creation after which it should open.
    """
    HELP_DIRNAME = "wallet-wizard"

    _last_page_id = WalletPage.NONE
    _wallet_type = StorageKind.UNKNOWN
    _wallet_path: Optional[str] = None
    _password_state = PasswordState.UNKNOWN
    _wallet: Optional[Wallet] = None

    def __init__(self, is_startup: bool=False,
            migration_data: Optional[MigrationContext]=None) -> None:
        super().__init__(None)

        self._recently_opened_entries = None

        self.setWindowTitle('ElectrumSV')
        self.setMinimumSize(600, 600)

        self.setPage(WalletPage.SPLASH_SCREEN, SplashScreenPage(self))
        self.setPage(WalletPage.RELEASE_NOTES, ReleaseNotesPage(self))
        self.setPage(WalletPage.CHOOSE_WALLET, ChooseWalletPage(self))
        self.setPage(WalletPage.MIGRATE_OLDER_WALLET,
            OlderWalletMigrationPage(self, migration_data))

        if migration_data is not None:
            self.setStartId(WalletPage.MIGRATE_OLDER_WALLET)
            return

        self.setOption(QWizard.HaveCustomButton1, True)

        if is_startup:
            self.setStartId(WalletPage.SPLASH_SCREEN)
        else:
            self.setStartId(WalletPage.CHOOSE_WALLET)

    @classmethod
    def attempt_open(klass, wallet_path: str) -> Tuple[bool, bool, Optional['WalletWizard']]:
        """
        Returns a tuple containing:
        `is_valid` - indicates the open action should proceed.
        `was_aborted` - indicates the user performed an action to abort the process.
        `wizard` - optionally present for valid cases where the wallet cannot be opened directly
            (migration is required).
        """
        entry = create_file_state(wallet_path)
        was_aborted = False
        if entry is not None and not entry.is_too_modern:
            storage = WalletStorage(wallet_path)
            try:
                password = request_password(None, storage, entry)
                if password is not None:
                    if entry.requires_upgrade:
                        migration_context = MigrationContext(entry, storage, password)
                        # We hand off the storage reference to the wallet wizard to close.
                        storage = None
                        return True, False, klass(migration_data=migration_context)
                    return True, False, None
                was_aborted = True
            finally:
                if storage is not None:
                    storage.close()
        return False, was_aborted, None

    def set_wallet_path(self, wallet_path: Optional[str]) -> None:
        self._wallet_path = wallet_path

    def get_wallet_path(self) -> str:
        return self._wallet_path


class SplashScreenPage(QWizardPage):
    _next_page_id = WalletPage.NONE

    def __init__(self, parent: WalletWizard) -> None:
        super().__init__(parent)

        layout = QVBoxLayout()
        logo_layout = QHBoxLayout()
        logo_label = AspectRatioPixmapLabel(self)
        logo_layout.addStretch(1)
        logo_layout.addWidget(logo_label)
        logo_layout.addStretch(1)
        layout.addLayout(logo_layout)

        logo_pixmap = QPixmap(icon_path("title_logo.png"))
        logo_label.setPixmap(logo_pixmap)

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
            "the original whitepaper and values being stable and non-experimental.") +
            "</p>"+
            "</big>")
        self._release_label = release_label = QLabel(release_text)
        release_label.setContentsMargins(50, 10, 50, 10)
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
    def __init__(self, parent: WalletWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Release Notes"))

        release_html = read_resource_text("wallet-wizard", "release-notes.html")

        widget = QTextBrowser()
        widget.document().setDocumentMargin(15)
        widget.setOpenExternalLinks(True)
        widget.setAcceptRichText(True)
        widget.setHtml(release_html)

        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)

    def nextId(self) -> WalletPage:
        return WalletPage.CHOOSE_WALLET


class ListPopulationContext(QObject):
    update_list_entry = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self.stale = False


class ChooseWalletPage(QWizardPage):
    HELP_CONTEXT = HelpContext("choose-wallet")

    _force_completed = False
    _list_thread_context: Optional[ListPopulationContext] = None
    _list_thread: Optional[threading.Thread] = None
    _commit_pressed = False

    def __init__(self, parent: WalletWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Select an existing wallet"))
        self.setButtonText(QWizard.CommitButton, "  "+ _("Open &Selected Wallet") +"  ")
        self.setCommitPage(True)

        self._recent_wallet_paths: List[str] = []
        self._recent_wallet_entries: Dict[str, FileState] = {}

        vlayout = QVBoxLayout()

        page = self
        class TableWidget(QTableWidget):
            def keyPressEvent(self, event):
                key = event.key()
                if key == Qt.Key_Return or key == Qt.Key_Enter:
                    page._event_key_selection()
                else:
                    super(TableWidget, self).keyPressEvent(event)

            def contextMenuEvent(self, event):
                if not can_show_in_file_explorer():
                    return

                selected_indexes = self.selectedIndexes()
                if not len(selected_indexes):
                    return
                wallet_path = page._recent_wallet_paths[selected_indexes[0].row()]
                entry = page._recent_wallet_entries[wallet_path]

                show_file_action: Optional[QAction] = None
                show_directory_action: Optional[QAction] = None

                menu = QMenu(self)
                if sys.platform == 'win32':
                    show_file_action = menu.addAction(SHOW_IN_EXPLORER)
                    show_directory_action = menu.addAction(OPEN_DIRECTORY_IN_EXPLORER)
                elif sys.platform == 'darwin':
                    show_file_action = menu.addAction(SHOW_IN_FINDER)
                    show_directory_action = menu.addAction(OPEN_FOLDER_IN_FINDER)

                action = menu.exec_(self.mapToGlobal(event.pos()))
                if action == show_file_action:
                    show_in_file_explorer(entry.path)
                elif action == show_directory_action:
                    path = os.path.dirname(entry.path)
                    show_in_file_explorer(path)

        self._wallet_table = TableWidget()
        self._wallet_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._wallet_table.selectionModel().selectionChanged.connect(
            self._event_selection_changed)
        self._wallet_table.doubleClicked.connect(self._event_entry_doubleclicked)

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
        self._wallet_table.setHorizontalHeaderLabels([ "Recently Opened Wallets" ])

        self._unlocked_pixmap = QPixmap(icon_path("icons8-lock-80.png")).scaledToWidth(
            40, Qt.SmoothTransformation)

        vlayout.addWidget(self._wallet_table)

        tablebutton_layout = QHBoxLayout()
        self.file_button = QPushButton("  "+ _("Open &Other Wallet") +"  ")
        self.file_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        self.file_button.clicked.connect(self._event_click_open_file)
        tablebutton_layout.addStretch()
        tablebutton_layout.addWidget(self.file_button, Qt.AlignRight)
        vlayout.addLayout(tablebutton_layout)

        self.setLayout(vlayout)

        self._on_reset_next_page()

    def _on_reset_next_page(self) -> None:
        self._next_page_id = WalletPage.MIGRATE_OLDER_WALLET

    def nextId(self) -> WalletPage:
        return self._next_page_id

    def isFinalPage(self) -> bool:
        return False

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        if self._commit_pressed:
            # The default "Commit" button page switching should be prevented by this flag.
            result = False
        elif self._force_completed:
            result = True
        else:
            result = len(self._wallet_table.selectedIndexes()) > 0
        # logger.debug("isComplete %s", result)
        return result

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        # logger.debug("validatePage %s", self.isComplete())
        return self.isComplete()

    def _attempt_open_wallet(self, wallet_path: str, change_page: bool=False) -> bool:
        if not os.path.exists(wallet_path):
            MessageBox.show_error(_("Unable to open a deleted wallet."))
            return False

        entry: Optional[FileState] = None
        for entry in self._recent_wallet_entries.values():
            if entry.path == wallet_path:
                break
        else:
            entry = create_file_state(wallet_path)
            if entry is None:
                MessageBox.show_error(_("Unrecognised or unsupported wallet file."))
                return False

        if entry.is_too_modern:
            MessageBox.show_error(_("The selected wallet cannot be opened as it is from a later "
                "version of ElectrumSV."))
            return False

        password: str = None
        wizard: WalletWizard = self.wizard()
        storage = WalletStorage(entry.path)
        try:
            password = request_password(self, storage, entry)
            if password is None:
                return False

            if change_page:
                self._force_completed = True

                if entry.requires_upgrade:
                    self._next_page_id = WalletPage.MIGRATE_OLDER_WALLET
                    migration_page = wizard.page(WalletPage.MIGRATE_OLDER_WALLET)
                    migration_page.set_migration_data(entry, storage, password)
                    # Give the storage object to the migration page, which we are going to.
                    storage = None
                    wizard.next()
                else:
                    assert entry.storage_kind == StorageKind.DATABASE, \
                        f"not a database {entry.storage_kind}"
                    wizard.set_wallet_path(entry.path)
                    wizard.accept()
        finally:
            # We may have handed off the storage and are no longer responsible for closing it.
            if storage is not None:
                storage.close()
        return True

    def _event_click_create_wallet(self) -> None:
        initial_path = app_state.config.get_preferred_wallet_dirpath()
        create_filepath = create_new_wallet(self, initial_path)
        if create_filepath is not None:
            # How the app knows which wallet was selected/created.
            wizard: WalletWizard = self.wizard()
            wizard.set_wallet_path(create_filepath)

            # Exit the wizard.
            self._force_completed = True
            self._next_page_id = -1
            wizard.accept()

    def _event_click_open_file(self) -> None:
        initial_dirpath = app_state.config.get_preferred_wallet_dirpath()
        wallet_filepath, __ = QFileDialog.getOpenFileName(self, "Select your wallet file",
            initial_dirpath)
        if wallet_filepath:
            # QFileDialog.getOpenFileName uses forward slashes for "easier pathing".. correct this.
            wallet_filepath = os.path.normpath(wallet_filepath)
            self._attempt_open_wallet(wallet_filepath, change_page=True)

    def _event_click_open_selected_file(self) -> None:
        # The default "Commit" button page switching should have been prevented by this flag.
        # This event should come after it, and clear the flag so it can manually switch the
        # page itself.
        self._commit_pressed = False
        # This should be someone clicking the next/commit button.
        selected_indexes = self._wallet_table.selectedIndexes()
        wallet_path = self._recent_wallet_paths[selected_indexes[0].row()]
        self._attempt_open_wallet(wallet_path, change_page=True)

    def _event_press_open_selected_file(self) -> None:
        # The default "Commit" button page switching should be prevented by this flag.
        # Ensure both `validatePage` and `isComplete` fail until the click event happens. The
        # click event happens last, after the press, the release, and the default "Commit" button
        # page switching.
        self._commit_pressed = True

    def _event_selection_changed(self, _selected: QItemSelection, _deselected: QItemSelection) \
            -> None:
        # Selecting an entry should change the page elements to be ready to either move to another
        # page, or whatever else is applicable.
        # NOTE: We request the selected indexes rather than using those from the events, as there
        # have been occasional error reports where the selection did not match the wallet paths.
        # https://github.com/electrumsv/electrumsv/issues/404
        selected_indexes = self._wallet_table.selectedIndexes()
        selected_row = selected_indexes[0].row() if len(selected_indexes) else -1
        if selected_row != -1:
            wallet_path = self._recent_wallet_paths[selected_row]
            entry = self._recent_wallet_entries[wallet_path]
            if entry.requires_upgrade:
                self._next_page_id = WalletPage.MIGRATE_OLDER_WALLET
            else:
                self._next_page_id = -1
        else:
            self._clear_selection()

        self.completeChanged.emit()

    def _event_key_selection(self) -> None:
        selected_indexes = self._wallet_table.selectedIndexes()
        if len(selected_indexes):
            self._select_row(selected_indexes[0].row())

    def _event_entry_doubleclicked(self, index: QModelIndex) -> None:
        self._select_row(index.row())

    def _select_row(self, row: int) -> None:
        wallet_path = self._recent_wallet_paths[row]
        self._attempt_open_wallet(wallet_path, change_page=True)

    def _clear_selection(self) -> None:
        self._force_completed = False
        self._on_reset_next_page()
        self._commit_pressed = False

        wizard: WalletWizard = self.wizard()
        wizard.set_wallet_path(None)

    # Qt default QWizardPage event when page is entered.
    def on_enter(self) -> None:
        self._clear_selection()

        wizard: WalletWizard = self.wizard()
        button = wizard.button(QWizard.CustomButton1)
        button.setVisible(True)
        button.setText("  "+ _("Create &New Wallet") +"  ")
        button.clicked.connect(self._event_click_create_wallet)
        button.show()

        cancel_button = wizard.button(QWizard.CancelButton)
        cancel_button.show()

        # The commit button will try and do a "next page" and fail because the next page
        # will be -1, and there is no next page. The click event will follow that and we will
        # do the correct next page or finish action depending on wallet type.
        commit_button = wizard.button(QWizard.CommitButton)
        commit_button.clicked.connect(self._event_click_open_selected_file)
        commit_button.pressed.connect(self._event_press_open_selected_file)

        self._gui_list_reset()
        self._recent_wallet_paths.extend(
            [ candidate_path for candidate_path in [ os.path.normpath(candidate_path)
            for candidate_path in app_state.config.get('recently_open', []) ]
            if os.path.exists(candidate_path) ])

        self._list_thread_context = ListPopulationContext()
        self._list_thread_context.update_list_entry.connect(self._gui_list_update)
        self._list_thread = threading.Thread(target=self._populate_list_in_thread,
            args=(self._list_thread_context,))
        self._list_thread.setDaemon(True)
        self._list_thread.start()

        self._wallet_table.setFocus()

    # Qt default QWizardPage event when page is exited.
    def on_leave(self) -> None:
        if self._list_thread is not None:
            assert self._list_thread_context is not None
            self._list_thread_context.update_list_entry.disconnect()
            self._list_thread_context.stale = True
            self._list_thread = None

        wizard: WalletWizard = self.wizard()
        button = wizard.button(QWizard.CustomButton1)
        button.setVisible(False)
        button.clicked.disconnect(self._event_click_create_wallet)

        commit_button = wizard.button(QWizard.CommitButton)
        commit_button.clicked.disconnect(self._event_click_open_selected_file)

    def _populate_list_in_thread(self, context: ListPopulationContext) -> None:
        for file_path in self._recent_wallet_paths:
            if context.stale:
                return
            # We can assume that the state does not exist because we doing initial population.
            entry = create_file_state(file_path)
            if context.stale:
                return
            # This should filter out invalid wallets. But if there's an Sqlite error it will
            # skip them. In theory the retrying in the Sqlite support code should prevent
            # this from happening.
            if entry is not None:
                context.update_list_entry.emit(entry)

    def _get_file_state(self, wallet_path: str) -> Optional[FileState]:
        if not os.path.exists(wallet_path):
            return None

        entry = self._recent_wallet_entries.get(wallet_path)
        if entry is not None:
            # Ensure the entry is still current or get a new one.
            modification_time = os.path.getmtime(entry.path)
            if entry.modification_time == modification_time:
                return entry

        return create_file_state(wallet_path)

    def _gui_list_reset(self) -> None:
        self._recent_wallet_paths: List[str] = []
        self._recent_wallet_entries: Dict[str, FileState] = {}

        while self._wallet_table.rowCount():
            self._wallet_table.removeRow(self._wallet_table.rowCount()-1)

    def _gui_list_update(self, entry: FileState) -> None:
        assert entry.path is not None

        row_index = self._wallet_table.rowCount()
        if entry.path in self._recent_wallet_entries:
            return
        self._wallet_table.insertRow(row_index)
        self._recent_wallet_entries[entry.path] = entry

        row_widget = QWidget()
        row_layout = QHBoxLayout()
        row_layout.setSpacing(0)
        row_layout.setContentsMargins(0, 0, 0, 0)

        row_icon_label = QLabel()
        row_icon_label.setPixmap(self._unlocked_pixmap)
        row_icon_label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        row_icon_label.setMaximumWidth(80)

        row_desc_label = QLabel(entry.name +
            "<br/><font color='grey'>"+ os.path.dirname(entry.path) +"</font>")
        row_desc_label.setTextFormat(Qt.RichText)

        row_layout.addWidget(row_icon_label)
        row_layout.addWidget(row_desc_label)
        row_layout.addStretch(1)

        row_widget.setLayout(row_layout)
        self._wallet_table.setCellWidget(row_index, 0, row_widget)


class OlderWalletMigrationPage(QWizardPage):
    HELP_CONTEXT = HelpContext("migrate-wallet")

    _migration_completed = False
    _migration_successful = False
    _migration_error_text: str = _("Unexpected migration failure.")

    _migration_entry: Optional[FileState] = None
    _migration_storage: Optional[WalletStorage] = None
    _migration_password: Optional[str] = None

    def __init__(self, parent: WalletWizard,
            migration_data: Optional[MigrationContext]=None) -> None:
        super().__init__(parent)

        if migration_data is not None:
            self.set_migration_data(*migration_data)

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
        self._progress_label.setAlignment(Qt.AlignCenter)

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

    def set_migration_data(self, entry: FileState, storage: WalletStorage, password: str) -> None:
        self._migration_entry = entry
        self._migration_storage = storage
        self._migration_password = password

    def isComplete(self) -> bool:
        # Called to determine if 'Next' or 'Finish' should be enabled or disabled.
        # Overriding this requires us to emit the 'completeChanges' signal where applicable.
        return self._migration_completed

    def validatePage(self) -> bool:
        # Called when 'Next' or 'Finish' is clicked for last-minute validation.
        return self.isComplete()

    def on_enter(self) -> None:
        wizard: WalletWizard = self.wizard()
        wizard.setOption(QWizard.HaveCustomButton1, False)
        wizard.setOption(QWizard.NoCancelButton, True)

        cancel_button = wizard.button(QWizard.CancelButton)
        cancel_button.hide()

        assert self._migration_entry is not None
        assert self._migration_storage is not None
        if self._migration_entry.storage_kind & PasswordState.PASSWORDED == \
                PasswordState.PASSWORDED:
            assert self._migration_password is not None

        self._migration_completed = False
        self._migration_successful = False
        self._migration_error_text = self.__class__._migration_error_text
        self._future = app_state.app.run_in_thread(self._migrate_wallet,
            on_done=self._on_migration_completed)

        wizard.button(QWizard.HelpButton).setFocus(Qt.OtherFocusReason)

    def on_leave(self) -> None:
        self._future.cancel()
        self._future = None

        self._migration_entry = None
        self._migration_storage.close()
        self._migration_storage = None
        self._migration_password = None

    def _migrate_wallet(self) -> None:
        try:
            self._attempt_migrate_wallet()
        except Exception:
            logger.exception("unhandled migration error")

    def _attempt_migrate_wallet(self) -> None:
        logger.debug("wallet migration started")

        wizard: WalletWizard = self.wizard()
        entry = self._migration_entry
        storage = self._migration_storage
        wallet_password = self._migration_password
        has_password = entry.password_state & PasswordState.PASSWORDED == PasswordState.PASSWORDED

        try:
            if storage.is_legacy_format():
                text_store = storage.get_text_store()
                if has_password:
                    if entry.password_state & PasswordState.ENCRYPTED == PasswordState.ENCRYPTED:
                        try:
                            data = text_store.decrypt(wallet_password)
                        except DecryptionError:
                            # To get to this point the password had already been checked.
                            self._migration_error_text = _("Unexpected wallet migration failure "
                                "due to invalid password.")
                            return
                    text_store.load_data(data)
                    # The existing private data will already be encoded with the password.
                else:
                    assert text_store.attempt_load_data()

            try:
                storage.upgrade(has_password, wallet_password)
            except (IncompatibleWalletError, DatabaseMigrationError) as e:
                logger.exception("wallet migration error '%s'", entry.path)
                self._migration_error_text += "\n"+ e.args[0]
            else:
                logger.debug("wallet migration successful")
                wizard.set_wallet_path(entry.path)
                self._migration_successful = True
        finally:
            storage.close()

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
            self._migration_failure_cleanup()

            style_sheet = ("QProgressBar::chunk {background: QLinearGradient( x1: 0, y1: 0, "+
                "x2: 1, y2: 0,stop: 0 #FF0350,stop: 0.4999 #FF0020,stop: 0.5 #FF0019,"+
                "stop: 1 #FF0000 );border-bottom-right-radius: 5px;"+
                "border-bottom-left-radius: 5px;border: .px solid black;}")
            self._progress_bar.setStyleSheet(style_sheet)
            self._progress_label.setText(self._migration_error_text)

            wizard: WalletWizard = self.wizard()
            wizard.button(QWizard.FinishButton).setText("E&xit")

        self.completeChanged.emit()

    def _migration_failure_cleanup(self) -> None:
        backup_filepaths = self._migration_storage.get_backup_filepaths()
        if backup_filepaths is not None:
            original_filepath, backup_filepath = backup_filepaths
            logger.debug("Restoring '%s' to '%s'", backup_filepath, original_filepath)
            shutil.move(backup_filepath, original_filepath)
            db_path = self._migration_storage.get_storage_path() + DATABASE_EXT
            # The move was possibly an overwrite, if they were both 1.3 wallets. In which case
            # this delete would be data loss of the original wallet.
            if db_path != original_filepath:
                logger.debug("Removing failed db '%s'", db_path)
                os.remove(db_path)

