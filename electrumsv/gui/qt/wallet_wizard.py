# TODO:
# - QTableWidget vs. QListView
#
#   Consolidate the use of QTableWidget and QListView between the wallet selection screen and
#   the add wallet screen. The decision holding the choice back, is the need to both sort and
#   filter the contents. I suspect that the choice may not matter though and we should go with
#   one or the other.
#
# - ...

import enum
import os

from PyQt5.QtCore import QSize, Qt, QModelIndex
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QTableWidget, QAbstractItemView, QWidget,
    QHBoxLayout, QLabel, QMessageBox, QWizard, QWizardPage, QListWidget,
    QListWidgetItem, QHeaderView
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
    ADD_WALLET_MENU = 2
    CREATE_NEW_STANDARD_WALLET = 3
    CREATE_NEW_MULTISIG_WALLET = 4
    IMPORT_WALLET_FILE = 5
    IMPORT_WALLET_TEXT = 6
    IMPORT_WALLET_TEXT_SEED_PHRASE_CENTBEE = 41
    IMPORT_WALLET_TEXT_SEED_PHRASE_HANDCASH = 42
    IMPORT_WALLET_TEXT_SEED_PHRASE_MONEYBUTTON = 43
    IMPORT_HARDWARE_WALLET_FOR_DIGITALBITBOX = 51
    IMPORT_HARDWARE_WALLET_FOR_KEEPKEY = 52
    IMPORT_HARDWARE_WALLET_FOR_LEDGER = 53
    IMPORT_HARDWARE_WALLET_FOR_TREZOR = 54


class WalletWizard2(QWizard):
    def __init__(self):
        super().__init__(None)

        self.setWindowTitle('ElectrumSV')
        self.setMinimumSize(600, 600)
        self.setOption(QWizard.NoDefaultButton, True)

        self.wallet_data = None

        self.setOption(QWizard.HaveHelpButton, True)
        self.setPage(Pages.SELECT_WALLET, SelectWalletWizardPage(self))
        self.setPage(Pages.ADD_WALLET_MENU, AddWalletWizardPage(self))

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


wallet_table = None

class SelectWalletWizardPage(QWizardPage):
    def __init__(self, parent):
        global wallet_table

        super().__init__(parent)

        self.setTitle(_("Select Wallet"))
        self.setButtonText(QWizard.NextButton, _("&Add Wallet"))
        self.setFinalPage(True)

        wallet_data = self._get_recently_opened_wallets()

        locked_pixmap = QPixmap(icon_path("icons8-lock-80.png")).scaledToWidth(
            40, Qt.SmoothTransformation)
        unlocked_pixmap = QPixmap(icon_path("icons8-unlock-80.png")).scaledToWidth(
            40, Qt.SmoothTransformation)

        layout = QVBoxLayout()

        wallet_table = self.wallet_table = QTableWidget()
        wallet_table.setColumnCount(1)
        #wallet_table.setIconSize(QSize(24, 24))
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
        # Tab by default in QTableWidget, moves between list items. The arrow keys also perform
        # the same function, and we want tab to allow toggling to the wizard button bar instead.
        wallet_table.setTabKeyNavigation(False)

        hh = wallet_table.horizontalHeader()
        hh.setStretchLastSection(True)

        vh = wallet_table.verticalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeToContents)
        vh.hide()

        for d in wallet_data:
            wallet_path = d['path']
            wallet_storage = WalletStorage(wallet_path, manual_upgrades=True)

            row_index = wallet_table.rowCount()
            wallet_table.insertRow(row_index)

            row_widget = QWidget()
            row_layout = QHBoxLayout()
            row_layout.setSpacing(0)
            row_layout.setContentsMargins(0, 0, 0, 0)

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
        return Pages.ADD_WALLET_MENU

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


class AddWalletWizardPage(QWizardPage):
    def __init__(self, parent):
        super().__init__(parent)

        self.setTitle(_("Add Wallet"))
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

        def _on_current_row_changed(current_row):
            self.completeChanged.emit()

        def _on_item_selection_changed():
            self.completeChanged.emit()
            selected_items = self.option_list.selectedItems()
            if len(selected_items):
                entry = selected_items[0].data(Qt.UserRole)
                self.optionDetail.setText(self._get_entry_detail(entry))
            else:
                self.optionDetail.setText(self._get_entry_detail())

        option_list.currentRowChanged.connect(_on_current_row_changed)
        option_list.itemSelectionChanged.connect(_on_item_selection_changed)

    def isFinalPage(self):
        return False

    def isComplete(self):
        selected_items = self.option_list.selectedItems()
        return len(selected_items)

    def validatePage(self):
        selected_items = self.option_list.selectedItems()
        return len(selected_items)

    def nextId(self):
        selected_items = self.option_list.selectedItems()
        if len(selected_items):
            return selected_items[0].data(Qt.UserRole)['page']
        # If -1 is returned, it guesses final page and uses "Finish" instead
        # of "Next".
        return Pages.CREATE_NEW_STANDARD_WALLET

    def _get_entry_detail(self, entry=None):
        title_start_html = "<b>"
        title_end_html = "</b>"
        if entry is None:
            title_start_html = title_end_html = ""
            entry = {
                'icon_filename': 'icons8-decision-80.png',
                'description': _("Select the way in which you want to add a new wallet "+
                    "from the list on the left."),
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
            _("A seed phrase is a way of storing a wallet's private key. "+
              "Using it ElectrumSV can access the wallet's previous "+
              "payments, and send and receive the coins in the wallet.") +
            "</p>")

        original_wallet_html = ("<p>"+
            _("If the original wallet application a seed phrase came from is still being used to "+
              "access the given wallet, then it is not always safe to access it in ElectrumSV "+
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
                'page': Pages.CREATE_NEW_STANDARD_WALLET,
                'description': _("Create new standard wallet"),
                'icon_filename': 'icons8-create-80.png',
                'long_description': f"""
                If you want to create a brand new wallet in ElectrumSV this is the option you
                want.
                """,
            },
            {
                'page': Pages.CREATE_NEW_MULTISIG_WALLET,
                'description': _("Create new multi-signature wallet"),
                'icon_filename': 'icons8-create-80.png',
                'long_description': f"""
                If you want to create a brand new multi-signature wallet in ElectrumSV this is the
                option you want.
                """,
            },
            {
                'page': Pages.IMPORT_WALLET_FILE,
                'description': _("Import wallet file"),
                'icon_filename': 'icons8-document.svg',
                'long_description': f"""
                ...
                """,
            },
            {
                'page': Pages.IMPORT_WALLET_TEXT,
                'description': _("Import wallet using text (any seed phrase, public keys, "+
                                 "private keys or addresses)"),
                'icon_filename': 'icons8-brain-80.png',
                'long_description': f"""
                If you have some text to paste, or type in, and want ElectrumSV to examine it
                and offer you some choices on how it can be imported, this is the option you
                probably want.
                """,
            },
            {
                'page': Pages.IMPORT_WALLET_TEXT_SEED_PHRASE_CENTBEE,
                'description': _("Import wallet using seed phrase (Centbee)"),
                'icon_filename': 'icons8-reuse-80.png',
                'long_description': f"""
                <p>
                If you are already using the <a href='https://www.centbee.com/'>Centbee</a>
                mobile wallet and have your seed phrase, this option allows you to add and access
                that same wallet in ElectrumSV.
                </p>
                {seed_phrase_html}
                {original_wallet_safe_html % {"wallet_name": "Centbee"}}
                """,
            },
            {
                'page': Pages.IMPORT_WALLET_TEXT_SEED_PHRASE_HANDCASH,
                'description': _("Import wallet using seed phrase (HandCash)"),
                'icon_filename': 'icons8-reuse-80.png',
                'long_description': f"""
                <p>
                If you are already using the <a href='https://handcash.io/'>HandCash</a>
                mobile wallet and have your seed phrase, this option allows you to add and access
                that same wallet in ElectrumSV.
                </p>
                {seed_phrase_html}
                {original_wallet_unsafe_html % {"wallet_name": "HandCash"}}
                """,
            },
            {
                'page': Pages.IMPORT_WALLET_TEXT_SEED_PHRASE_MONEYBUTTON,
                'description': _("Import wallet using seed phrase (MoneyButton)"),
                'icon_filename': 'icons8-reuse-80.png',
                'long_description': f"""
                <p>
                If you are already using the
                <a href='https://www.moneybutton.com/'>Money Button</a>
                mobile wallet and have your seed phrase, this option allows you to add and access
                that same wallet in ElectrumSV.
                </p>
                {seed_phrase_html}
                {original_wallet_unsafe_html % {"wallet_name": "Money Button"}}
                """,
            },
            {
                'page': Pages.IMPORT_HARDWARE_WALLET_FOR_DIGITALBITBOX,
                'description': _("Import hardware wallet (Digital Bitbox)"),
                'icon_filename': 'icons8-usb-2-80.png',
            },
            {
                'page': Pages.IMPORT_HARDWARE_WALLET_FOR_KEEPKEY,
                'description': _("Import hardware wallet (Keepkey)"),
                'icon_filename': 'icons8-usb-2-80.png',
            },
            {
                'page': Pages.IMPORT_HARDWARE_WALLET_FOR_LEDGER,
                'description': _("Import hardware wallet (Ledger)"),
                'icon_filename': 'icons8-usb-2-80.png',
            },
            {
                'page': Pages.IMPORT_HARDWARE_WALLET_FOR_TREZOR,
                'description': _("Import hardware wallet (Trezor)"),
                'icon_filename': 'icons8-usb-2-80.png',
            },
        ]
