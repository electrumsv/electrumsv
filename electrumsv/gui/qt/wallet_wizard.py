import enum
import os

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QTableWidget, QAbstractItemView, QWidget,
    QHBoxLayout, QLabel, QMessageBox, QWizard, QWizardPage, QListWidget,
    QListWidgetItem
)

from electrumsv.app_state import app_state
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.storage import WalletStorage

from .password_dialog import PasswordDialog
from .util import icon_path, read_QIcon

logger = logs.get_logger('wallet_wizard')


def open_wallet_wizard():
    wizard_window = WalletWizard2()
    result = wizard_window.run()

    if result != QDialog.Accepted:
        return

    wallet_data = wizard_window.wallet_data
    if not wallet_data:
        return
    wallet_window = app_state.app.get_wallet_window(wallet_data['path'])
    if not wallet_window:
        password = None
        if wallet_data['is_encrypted']:
            password_dialog = PasswordDialog()
            password = password_dialog.run()
            if not password:
                return

        try:
            wallet = app_state.daemon.load_wallet(wallet_data['path'], password)
        except Exception as e:
            logger.exception("")
            if '2fa' in str(e):
                d = QMessageBox(QMessageBox.Warning, _('Error'),
                                '2FA wallets are not unsupported.')
                d.exec_()
            else:
                d = QMessageBox(QMessageBox.Warning, _('Error'),
                                'Cannot load wallet:\n' + str(e))
                d.exec_()
            return
        wallet_window = app_state.app._create_window_for_wallet(wallet)
    wallet_window.bring_to_top()
    wallet_window.setWindowState(wallet_window.windowState() & ~Qt.WindowMinimized | Qt.WindowActive)

    # this will activate the window
    wallet_window.activateWindow()
    return wallet_window


class Pages(enum.IntEnum):
    SELECT_WALLET = 1
    ADD_WALLET = 2


class WalletWizard2(QWizard):
    def __init__(self):
        super().__init__(None)

        self.setWindowTitle('ElectrumSV')
        self.setMinimumSize(600, 600)
        self.setOption(QWizard.NoDefaultButton, True)

        self.wallet_data = None

        self.setOption(QWizard.HaveHelpButton, True)
        self.setPage(Pages.SELECT_WALLET, SelectWalletWizardPage(self))
        self.setPage(Pages.ADD_WALLET, AddWalletWizardPage(self))

        self.setStartId(Pages.SELECT_WALLET)

    def run(self):
        self.ensure_shown()

        result = self.exec()
        return result

    def ensure_shown(self):
        self.show()
        self.raise_()

    def accept(self):
        page = self.currentPage()
        self.wallet_data = None
        if isinstance(page, SelectWalletWizardPage):
            self.wallet_data = page.get_wallet_data()
        super().accept()


class SelectWalletWizardPage(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)

        self.setTitle(_("Select Wallet"))
        self.setButtonText(QWizard.NextButton, _("&Add Wallet"))
        self.setFinalPage(True)

        wallet_data = self._get_recently_opened_wallets()

        locked_pixmap = QPixmap(icon_path("icons8-lock-80.png")).scaledToWidth(
            50, Qt.SmoothTransformation)
        unlocked_pixmap = QPixmap(icon_path("icons8-unlock-80.png")).scaledToWidth(
            50, Qt.SmoothTransformation)

        layout = QVBoxLayout()

        wallet_table = self.wallet_table = QTableWidget()
        wallet_table.setColumnCount(1)
        wallet_table.setIconSize(QSize(64, 64))
        wallet_table.setHorizontalHeaderLabels([ "Recently Opened Wallets" ])
        wallet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        wallet_table.setStyleSheet("""
            QTableView {
                selection-background-color: #F5F8FA;
            }
            QHeaderView::section {
                font-weight: bold;
            }
        """)
        wallet_table.setTabKeyNavigation(False)

        hh = wallet_table.horizontalHeader()
        hh.setStretchLastSection(True)

        vh = wallet_table.verticalHeader()
        vh.setSectionResizeMode(vh.Fixed)
        vh.setDefaultSectionSize(80)
        vh.hide()

        for d in wallet_data:
            wallet_path = d['path']
            wallet_storage = WalletStorage(wallet_path, manual_upgrades=True)

            row_index = wallet_table.rowCount()
            wallet_table.insertRow(row_index)

            row_widget = QWidget()
            row_layout = QHBoxLayout()

            row_icon_label = QLabel()
            if wallet_storage.is_encrypted():
                row_icon_label.setPixmap(locked_pixmap)
            else:
                row_icon_label.setPixmap(unlocked_pixmap)
            row_icon_label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
            row_icon_label.setMaximumWidth(80)

            row_desc_label = QLabel(d['name'])

            row_layout.addWidget(row_icon_label)
            row_layout.addWidget(row_desc_label)

            row_widget.setLayout(row_layout)
            wallet_table.setCellWidget(row_index, 0, row_widget)

        self.wallet_data = wallet_data

        layout.addWidget(wallet_table)

        self.setLayout(layout)

        wallet_table.setFocus()
        wallet_table.selectRow(0)

    def nextId(self):
        return Pages.ADD_WALLET

    def get_wallet_data(self):
        selected_indexes = self.wallet_table.selectedIndexes()
        wallet_index = selected_indexes[0].row()
        return self.wallet_data[wallet_index]

    def validatePage(self):
        selected_indexes = self.wallet_table.selectedIndexes()
        return len(selected_indexes)

    def _get_recently_opened_wallets(self):
        return [
            {
                'name': os.path.basename(file_path),
                'path': file_path,
                'is_encrypted': WalletStorage(file_path, manual_upgrades=True).is_encrypted,
            }
            for file_path in app_state.config.get('recently_open', [])
            if os.path.exists(file_path)
        ]


class AddEntryType(enum.IntEnum):
    CREATE_NEW = 1
    EXTERNAL_SEED_IMPORT = 2


class AddWalletWizardPage(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)

        self.setTitle(_("Add Wallet"))

        option_list = self.option_list = QListWidget()
        option_list.setIconSize(QSize(50, 50))
        option_list.setStyleSheet("""
            QListView::item:selected {
                background-color: #F5F8FA;
                color: black;
            }
        """)

        entries = [
            {
                'type': AddEntryType.CREATE_NEW,
                'description': _("Create new wallet"),
                'icon_filename': 'icons8-reuse-80.png',
            },
            {
                'type': AddEntryType.EXTERNAL_SEED_IMPORT,
                'description': _("Import any seed phrase with guessing"),
                'icon_filename': 'icons8-brain-80.png',
            },
            {
                'type': AddEntryType.EXTERNAL_SEED_IMPORT,
                'description': _("Import using Centbee seed phrase"),
                'icon_filename': 'icons8-reuse-80.png',
            },
            {
                'type': AddEntryType.EXTERNAL_SEED_IMPORT,
                'description': _("Import using HandCash seed phrase"),
                'icon_filename': 'icons8-reuse-80.png',
            },
            {
                'type': AddEntryType.EXTERNAL_SEED_IMPORT,
                'description': _("Import using MoneyButton seed phrase"),
                'icon_filename': 'icons8-reuse-80.png',
            },
        ]

        for entry in entries:
            list_item = QListWidgetItem()
            list_item.setSizeHint(QSize(100, 80))
            list_item.setIcon(read_QIcon(entry['icon_filename']))
            list_item.setText(entry['description'])
            option_list.addItem(list_item)

        layout = QVBoxLayout()
        layout.addWidget(option_list)
        self.setLayout(layout)

