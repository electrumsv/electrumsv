# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
# Copyright (C) 2019 ElectrumSV developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
import base64
from collections import Counter
import csv
from decimal import Decimal
from functools import partial
import json
import os
import shutil
import threading
import time
from typing import Iterable, Tuple, Optional
import weakref
import webbrowser

from bitcoinx import PublicKey, Script, Address, P2PKH_Address, TxOutput
from bitcoinx import OP_RETURN, OP_FALSE # pylint: disable=no-name-in-module

from PyQt5.QtCore import (pyqtSignal, Qt, QSize, QStringListModel, QTimer, QUrl)
from PyQt5.QtGui import QKeySequence, QCursor, QDesktopServices
from PyQt5.QtWidgets import (
    QPushButton, QMainWindow, QTabWidget, QSizePolicy, QShortcut, QFileDialog, QMenuBar,
    QMessageBox, QGridLayout, QLineEdit, QLabel, QComboBox, QHBoxLayout,
    QVBoxLayout, QWidget, QCompleter, QMenu, QTreeWidgetItem, QTextEdit,
    QInputDialog, QToolBar, QAction, QPlainTextEdit, QTreeView
)

import electrumsv
from electrumsv import bitcoin, commands, keystore, paymentrequest, qrscanner, util
from electrumsv.app_state import app_state
from electrumsv.bitcoin import COIN, is_address_valid, address_from_string
from electrumsv.constants import DATABASE_EXT #, TxFlags
from electrumsv.exceptions import NotEnoughFunds, UserCancelled, ExcessiveFee
from electrumsv.i18n import _
from electrumsv.keystore import Hardware_KeyStore
from electrumsv.logs import logs
from electrumsv.network import broadcast_failure_reason
from electrumsv.networks import Net
from electrumsv.paymentrequest import PR_PAID
from electrumsv.transaction import (
    Transaction, tx_from_str, tx_output_to_display_text,
)
from electrumsv.util import (
    format_time, format_satoshis, format_satoshis_plain, bh2u, format_fee_satoshis,
    get_update_check_dates, get_identified_release_signers, profiler, get_wallet_name_from_path
)
from electrumsv.version import PACKAGE_VERSION
from electrumsv.wallet import sweep_preparations, Abstract_Wallet, ParentWallet
import electrumsv.web as web

from .amountedit import AmountEdit, BTCAmountEdit, MyLineEdit
from .contact_list import ContactList, edit_contact_dialog
from .coinsplitting_tab import CoinSplittingTab
from . import dialogs
from .preferences import PreferencesDialog
from .qrcodewidget import QRCodeWidget, QRDialog
from .qrtextedit import ShowQRTextEdit, ScanQRTextEdit
from .transaction_dialog import TxDialog
from .util import (
    MessageBoxMixin, ColorScheme, HelpLabel, expiration_values, ButtonsLineEdit,
    WindowModalDialog, Buttons, CopyCloseButton, MyTreeWidget, EnterButton,
    WaitingDialog, ChoicesLayout, OkButton, WWLabel, read_QIcon,
    CloseButton, CancelButton, text_dialog, filename_field, address_combo,
    update_fixed_tree_height, UntrustedMessageDialog, protected
)
from .wallet_api import WalletAPI


logger = logs.get_logger("mainwindow")


class ElectrumWindow(QMainWindow, MessageBoxMixin):

    payment_request_ok_signal = pyqtSignal()
    payment_request_error_signal = pyqtSignal()
    notify_transactions_signal = pyqtSignal()
    new_fx_quotes_signal = pyqtSignal()
    new_fx_history_signal = pyqtSignal()
    network_signal = pyqtSignal(str, object)
    history_updated_signal = pyqtSignal()
    network_status_signal = pyqtSignal()
    addresses_updated_signal = pyqtSignal(object)
    addresses_created_signal = pyqtSignal(object, object)

    def __init__(self, parent_wallet: ParentWallet):
        QMainWindow.__init__(self)

        self._api = WalletAPI(self)

        self.logger = logger
        self.config = app_state.config

        self.parent_wallet = parent_wallet
        wallet = parent_wallet.get_default_wallet()
        # TODO: ACCOUNTS: This paradigm of dealing with different wallets being used by different
        # tabs needs to be thought out and revisited with either the multi-account issue or the
        # multi-account polishing issue.
        self._send_wallet = wallet
        self._receive_wallet = wallet
        self._addresses_wallet = wallet

        self.network = app_state.daemon.network
        self.contacts = parent_wallet.contacts
        self.app = app_state.app
        self.cleaned_up = False
        self.is_max = False
        self.payment_request = None
        self.checking_accounts = False
        self.qr_window = None
        self.not_enough_funds = False
        self.require_fee_update = False
        self.tx_notifications = []
        self.tx_notify_timer = None
        self.tx_dialogs = []
        self.tl_windows = []
        self.tx_external_keypairs = {}

        self.create_status_bar()
        self.need_update = threading.Event()

        self.fee_unit = self.config.get('fee_unit', 0)

        self.completions = QStringListModel()

        self.tabs = tabs = QTabWidget(self)
        self.send_tab = self.create_send_tab()
        self.receive_tab = self.create_receive_tab()
        self.addresses_tab = self.create_addresses_tab()
        self.utxo_tab = self.create_utxo_tab()
        self.console_tab = self.create_console_tab()
        self.contacts_tab = self.create_contacts_tab()
        self.coinsplitting_tab = self.create_coinsplitting_tab()

        tabs.addTab(self.create_history_tab(), read_QIcon("tab_history.png"), _('History'))
        tabs.addTab(self.send_tab, read_QIcon("tab_send.png"), _('Send'))
        tabs.addTab(self.receive_tab, read_QIcon("tab_receive.png"), _('Receive'))

        def add_optional_tab(tabs, tab, icon, description, name, default=False):
            tab.tab_icon = icon
            tab.tab_description = description
            tab.tab_pos = len(tabs)
            tab.tab_name = name
            if self.config.get('show_{}_tab'.format(name), default):
                tabs.addTab(tab, icon, description.replace("&", ""))

        add_optional_tab(tabs, self.addresses_tab, read_QIcon("tab_addresses.png"),
                         _("&Addresses"), "addresses")
        add_optional_tab(tabs, self.utxo_tab, read_QIcon("tab_coins.png"),
                         _("Co&ins"), "utxo")
        add_optional_tab(tabs, self.contacts_tab, read_QIcon("tab_contacts.png"),
                         _("Con&tacts"), "contacts")
        add_optional_tab(tabs, self.console_tab, read_QIcon("tab_console.png"),
                         _("Con&sole"), "console")
        add_optional_tab(tabs, self.coinsplitting_tab, read_QIcon("tab_coins.png"),
                         _("Coin Splitting"), "coinsplitter", True)

        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(tabs)

        # Some tabs may want to be refreshed to show current state when selected.
        def on_tab_changed(to_tab_index):
            current_tab = self.tabs.currentWidget()
            if current_tab is self.coinsplitting_tab:
                self.coinsplitting_tab.update_layout()
        self.tabs.currentChanged.connect(on_tab_changed)

        if self.config.get("is_maximized"):
            self.showMaximized()

        self.init_menubar()
        self.init_toolbar()

        wrtabs = weakref.proxy(tabs)
        QShortcut(QKeySequence("Ctrl+W"), self, self.close)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Ctrl+R"), self, self.update_wallet)
        QShortcut(QKeySequence("Ctrl+PgUp"), self,
                  lambda: wrtabs.setCurrentIndex((wrtabs.currentIndex() - 1)%wrtabs.count()))
        QShortcut(QKeySequence("Ctrl+PgDown"), self,
                  lambda: wrtabs.setCurrentIndex((wrtabs.currentIndex() + 1)%wrtabs.count()))

        for i in range(wrtabs.count()):
            QShortcut(QKeySequence("Alt+" + str(i + 1)), self,
                      lambda i=i: wrtabs.setCurrentIndex(i))

        self.network_status_signal.connect(self._update_network_status)
        self.payment_request_ok_signal.connect(self.payment_request_ok)
        self.payment_request_error_signal.connect(self.payment_request_error)
        self.notify_transactions_signal.connect(self.notify_transactions)
        self.history_view.setFocus(True)

        # Link wallet synchronisation to throttled UI updates.
        self._wallet_sync_event = app_state.async_.event()
        self._monitor_wallet_network_status_tasks = []
        for wallet in self.parent_wallet.get_child_wallets():
            task = app_state.async_.spawn(self._monitor_wallet_network_status, wallet)
            self._monitor_wallet_network_status_tasks.append(task)
        self.network_status_task = app_state.async_.spawn(self._maintain_network_status)

        # network callbacks
        if self.network:
            self.network_signal.connect(self.on_network_qt)
            interests = ['updated', 'new_transaction', 'status',
                         'banner', 'verified', 'fee']
            # To avoid leaking references to "self" that prevent the
            # window from being GC-ed when closed, callbacks should be
            # methods of this class only, and specifically not be
            # partials, lambdas or methods of subobjects.  Hence...
            self.network.register_callback(self.on_network, interests)
            # set initial message
            self.console.showMessage(self.network.main_server.state.banner)
            self.network.register_callback(self.on_quotes, ['on_quotes'])
            self.network.register_callback(self._on_history, ['on_history'])
            self.network.register_callback(self._on_addresses_updated, ['on_addresses_updated'])
            self.network.register_callback(self._on_addresses_created, ['on_addresses_created'])
            self.new_fx_quotes_signal.connect(self.on_fx_quotes)
            self.new_fx_history_signal.connect(self.on_fx_history)

        self.load_wallet()
        self.app.timer.timeout.connect(self.timer_actions)

    def _on_addresses_created(self, event_name: str, addresses: Iterable[Address],
            is_change: bool=False) -> None:
        # logger.debug("_on_addresses_created %s %s", [a.to_string() for a in addresses], is_change)
        self.addresses_created_signal.emit(addresses, is_change)

    def _on_addresses_updated(self, event_name: str, addresses: Iterable[Address]) -> None:
        # logger.debug("_on_addresses_updated %s", [ a.to_string() for a in addresses ])
        self.addresses_updated_signal.emit(addresses)

    def _on_history(self, b):
        self.new_fx_history_signal.emit()

    def on_fx_history(self):
        self.history_view.update_tx_headers()
        self.history_view.update_tx_list()
        # inform things like address_dialog that there's a new history
        self.history_updated_signal.emit()

    def on_quotes(self, b):
        self.new_fx_quotes_signal.emit()

    def on_fx_quotes(self):
        self.update_status()
        # Refresh edits with the new rate
        edit = self.fiat_send_e if self.fiat_send_e.is_last_edited else self.amount_e
        edit.textEdited.emit(edit.text())
        edit = self.fiat_receive_e if self.fiat_receive_e.is_last_edited else self.receive_amount_e
        edit.textEdited.emit(edit.text())
        # History tab needs updating if it used spot
        if app_state.fx.history_used_spot:
            self.history_view.update_tx_list()
            self.history_updated_signal.emit()

    def toggle_tab(self, tab):
        show = self.tabs.indexOf(tab) == -1
        self.config.set_key('show_{}_tab'.format(tab.tab_name), show)
        item_text = (_("Hide") if show else _("Show")) + " " + tab.tab_description
        tab.menu_action.setText(item_text)
        if show:
            # Find out where to place the tab
            index = len(self.tabs)
            for i in range(len(self.tabs)):
                try:
                    if tab.tab_pos < self.tabs.widget(i).tab_pos:
                        index = i
                        break
                except AttributeError:
                    pass
            self.tabs.insertTab(index, tab, tab.tab_icon, tab.tab_description.replace("&", ""))
        else:
            i = self.tabs.indexOf(tab)
            self.tabs.removeTab(i)

    def push_top_level_window(self, window):
        '''Used for e.g. tx dialog box to ensure new dialogs are appropriately
        parented.  This used to be done by explicitly providing the parent
        window, but that isn't something hardware wallet prompts know.'''
        self.tl_windows.append(window)

    def pop_top_level_window(self, window):
        self.tl_windows.remove(window)

    def top_level_window(self):
        '''Do the right thing in the presence of tx dialog windows'''
        override = self.tl_windows[-1] if self.tl_windows else None
        return self.top_level_window_recurse(override)

    def is_hidden(self):
        return self.isMinimized() or self.isHidden()

    def show_or_hide(self):
        if self.is_hidden():
            self.bring_to_top()
        else:
            self.hide()

    def bring_to_top(self):
        self.show()
        self.raise_()

    def on_exception(self, exception):
        if not isinstance(exception, UserCancelled):
            self.logger.exception("")
            self.show_error(str(exception))

    def on_error(self, exc_info):
        self.on_exception(exc_info[1])

    def on_network(self, event, *args):
        if event == 'updated':
            self.need_update.set()

        elif event == 'new_transaction':
            tx, wallet = args
            if self.parent_wallet.contains_wallet(wallet):
                self.tx_notifications.append((tx, wallet))
                self.notify_transactions_signal.emit()
                self.need_update.set()
        elif event in ['status', 'banner', 'verified', 'fee']:
            # Handle in GUI thread
            self.network_signal.emit(event, args)
        else:
            self.logger.debug("unexpected network message event='%s' args='%s'", event, args)

    def on_network_qt(self, event, args=None):
        # Handle a network message in the GUI thread
        if event == 'status':
            self.update_status()
        elif event == 'banner':
            self.console.showMessage(self.network.main_server.state.banner)
        elif event == 'verified':
            self.history_view.update_tx_item(*args)
        elif event == 'fee':
            pass
        else:
            self.logger.debug("unexpected network_qt signal event='%s' args='%s'", event, args)

    def load_wallet(self):
        parent_wallet = self.parent_wallet
        self.logger = logs.get_logger(f"mainwindow[{parent_wallet.name()}]")
        self.update_recently_visited(parent_wallet.get_storage_path())
        # address used to create a dummy transaction and estimate transaction fee
        self.history_view.update_tx_list()
        self.utxo_list.update()
        self.need_update.set()
        # Once GUI has been initialized check if we want to announce something since the
        # callback has been called before the GUI was initialized
        self.notify_transactions()
        # update menus
        self.update_buttons_on_seed()
        self.update_console()
        self.clear_receive_tab()
        self.request_list.update()
        self.tabs.show()
        self.init_geometry()
        if self.config.get('hide_gui') and self.app.tray.isVisible():
            self.hide()
        else:
            self.show()
        self._update_window_title()
        self.history_updated_signal.emit()
        parent_wallet.create_gui_handlers(self)

    def init_geometry(self):
        winpos = self.parent_wallet.get_storage().get("winpos-qt")
        try:
            screen = self.app.desktop().screenGeometry()
            assert screen.contains(QRect(*winpos))
            self.setGeometry(*winpos)
        except:
            self.logger.debug("using default geometry")
            self.setGeometry(100, 100, 840, 400)

    def _update_window_title(self):
        title = f'ElectrumSV {PACKAGE_VERSION} ({Net.NAME})  -  {self.parent_wallet.name()}'
        self.setWindowTitle(title)

        # TODO: ACCOUNTS: This requires more nuance, in terms of showing which are watching only
        # when we get to the multi-account stage.
        for child_wallet in self.parent_wallet.get_child_wallets():
            if self.warn_if_watching_only(child_wallet):
                break

    def warn_if_watching_only(self, wallet: Abstract_Wallet) -> bool:
        if wallet.is_watching_only():
            msg = ' '.join([
                _("This wallet is watching-only."),
                _("This means you will not be able to spend Bitcoin SV with it."),
                _("Make sure you own the seed phrase or the private keys, "
                  "before you request Bitcoin SV to be sent to this wallet.")
            ])
            self.show_warning(msg, title=_('Information'))
            return True
        return False

    def open_wallet(self):
        try:
            wallet_folder = self.get_wallet_folder()
        except FileNotFoundError as e:
            self.show_error(str(e))
            return
        if not os.path.exists(wallet_folder):
            wallet_folder = None
        filename, __ = QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder)
        if not filename:
            return
        self.app.new_window(filename)

    def backup_wallet(self):
        path = self.parent_wallet.get_storage_path()
        wallet_folder = os.path.dirname(path)
        filename, __ = QFileDialog.getSaveFileName(
            self, _('Enter a filename for the copy of your wallet'), wallet_folder)
        if not filename:
            return

        new_path = os.path.join(wallet_folder, filename)
        if new_path != path:
            try:
                # Copy file contents
                shutil.copyfile(path, new_path)

                # Copy file attributes if possible
                # (not supported on targets like Flatpak documents)
                try:
                    shutil.copystat(path, new_path)
                except (IOError, os.error):
                    pass

                self.show_message(_("A copy of your wallet file was created in")
                                  +" '%s'" % str(new_path), title=_("Wallet backup created"))
            except (IOError, os.error) as reason:
                self.show_critical(_("ElectrumSV was unable to copy your wallet file "
                                     "to the specified location.") + "\n" + str(reason),
                                   title=_("Unable to create backup"))

    def update_recently_visited(self, filename):
        recent = self.config.get('recently_open', [])
        if filename in recent:
            recent.remove(filename)
        recent.insert(0, filename)
        recent = [path for path in recent if os.path.exists(path)][:10]
        self.config.set_key('recently_open', recent)
        self.recently_visited_menu.clear()

        wallet_names = [get_wallet_name_from_path(path) for path in recent]
        counts = Counter(wallet_names)
        pairs = sorted((wallet_name if counts[wallet_name] == 1 else path, path)
                       for wallet_name, path in zip(wallet_names, recent))
        for menu_text, path in pairs:
            self.recently_visited_menu.addAction(menu_text, partial(self.app.new_window, path))
        self.recently_visited_menu.setEnabled(bool(pairs))

    def get_wallet_folder(self):
        return os.path.dirname(os.path.abspath(self.config.get_wallet_path()))

    def new_wallet(self):
        try:
            wallet_folder = self.get_wallet_folder()
        except FileNotFoundError as e:
            self.show_error(str(e))
            return
        i = 1
        existing_filenames = [ filename.lower() for filename in os.listdir(wallet_folder) ]
        while True:
            filename = "wallet_%d" % i
            if filename + DATABASE_EXT not in existing_filenames:
                break
            i += 1
        full_path = os.path.join(wallet_folder, filename)
        self.app.start_new_window(full_path, None)

    def init_menubar(self):
        menubar = QMenuBar()

        file_menu = menubar.addMenu(_("&File"))
        self.recently_visited_menu = file_menu.addMenu(_("&Recently open"))
        file_menu.addAction(_("&Open"), self.open_wallet).setShortcut(QKeySequence.Open)
        file_menu.addAction(_("&New/Restore"), self.new_wallet).setShortcut(QKeySequence.New)
        file_menu.addAction(_("&Save Copy"), self.backup_wallet).setShortcut(QKeySequence.SaveAs)
        file_menu.addAction(_("Delete"), self.remove_wallet)
        file_menu.addSeparator()
        file_menu.addAction(_("&Quit"), self.close)

        wallet_menu = menubar.addMenu(_("&Wallet"))
        wallet_menu.addAction(_("&Information"), self.show_wallet_information)
        if Net.NAME in ("testnet", "scalingtestnet"):
            def temp_func():
                from importlib import reload
                from . import wallet_wizard
                reload(wallet_wizard)
                wallet_wizard.open_wallet_wizard()
            wallet_menu.addAction(_("&New Wizard"), temp_func)
        wallet_menu.addSeparator()

        self.password_menu = wallet_menu.addAction(_("&Password"), self.change_password_dialog)
        wallet_menu.addSeparator()

        contacts_menu = wallet_menu.addMenu(_("Contacts"))
        contacts_menu.addAction(_("&New"), partial(edit_contact_dialog, self._api))
        invoices_menu = wallet_menu.addMenu(_("Invoices"))
        invoices_menu.addAction(_("Import"), self.invoice_list.import_invoices)
        hist_menu = wallet_menu.addMenu(_("&History"))
        hist_menu.addAction("Export", self.export_history_dialog)

        wallet_menu.addSeparator()
        wallet_menu.addAction(_("Find"), self.toggle_search).setShortcut(QKeySequence("Ctrl+F"))

        def add_toggle_action(view_menu, tab):
            is_shown = self.tabs.indexOf(tab) > -1
            item_name = (_("Hide") if is_shown else _("Show")) + " " + tab.tab_description
            tab.menu_action = view_menu.addAction(item_name, lambda: self.toggle_tab(tab))

        view_menu = menubar.addMenu(_("&View"))
        add_toggle_action(view_menu, self.addresses_tab)
        add_toggle_action(view_menu, self.utxo_tab)
        add_toggle_action(view_menu, self.contacts_tab)
        add_toggle_action(view_menu, self.coinsplitting_tab)
        add_toggle_action(view_menu, self.console_tab)

        tools_menu = menubar.addMenu(_("&Tools"))

        tools_menu.addAction(_("Preferences"), self.preferences_dialog)
        tools_menu.addAction(_("&Network"), lambda: self.app.show_network_dialog(self))
        tools_menu.addSeparator()
        # TODO: ACCOUNTS: Currently assumes default wallet, should factor in the multi-account
        # paradigm.
        tools_menu.addAction(_("&Sign/verify message"), self.sign_verify_message)
        tools_menu.addAction(_("&Encrypt/decrypt message"), self.encrypt_message)
        tools_menu.addSeparator()

        paytomany_menu = tools_menu.addAction(_("&Pay to many"), self.paytomany)

        raw_transaction_menu = tools_menu.addMenu(_("&Load transaction"))
        raw_transaction_menu.addAction(_("&From file"), self.do_process_from_file)
        raw_transaction_menu.addAction(_("&From text"), self.do_process_from_text)
        raw_transaction_menu.addAction(_("&From the blockchain"), self.do_process_from_txid)
        raw_transaction_menu.addAction(_("&From QR code"), self.do_process_from_qrcode)
        self.raw_transaction_menu = raw_transaction_menu

        help_menu = menubar.addMenu(_("&Help"))
        help_menu.addAction(_("&About"), self.show_about)
        help_menu.addAction(_("&Check for updates"), self.show_update_check)
        help_menu.addAction(_("&Official website"), lambda: webbrowser.open("http://electrumsv.io"))
        help_menu.addSeparator()
        help_menu.addAction(_("Documentation"),
            lambda: webbrowser.open("http://electrumsv.readthedocs.io/")
        ).setShortcut(QKeySequence.HelpContents)
        help_menu.addAction(_("&Report Bug"), self.show_report_bug)
        help_menu.addSeparator()
        help_menu.addAction(_("&Donate to server"), self.donate_to_server)

        self.setMenuBar(menubar)

    def init_toolbar(self):
        self.toolbar = toolbar = QToolBar(self)
        icon_size = self.app.dpi / 5.8
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(icon_size, icon_size))
        toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)

        make_payment_action = QAction(read_QIcon("icons8-initiate-money-transfer-80.png"),
            _("Make Payment"), self)
        make_payment_action.triggered.connect(self.new_payment)
        toolbar.addAction(make_payment_action)

        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        spacer.setVisible(True)
        self.spacer_action = toolbar.addWidget(spacer)

        log_action = QAction(read_QIcon("icons8-moleskine-80.png"), _("Log Viewer"), self)
        log_action.triggered.connect(self.app.show_log_viewer)
        toolbar.addAction(log_action)

        network_action = QAction(read_QIcon("network.png"), _("Network"), self)
        network_action.triggered.connect(lambda: self.app.show_network_dialog(self))
        toolbar.addAction(network_action)

        preferences_action = QAction(read_QIcon("preferences.png"), _("Preferences"), self)
        preferences_action.triggered.connect(self.preferences_dialog)
        toolbar.addAction(preferences_action)

        self._update_check_state = "default"
        update_action = QAction(
            read_QIcon("icons8-available-updates-80-blue"), _("Update Check"), self)
        def _update_show_menu(checked: bool = False):
            self._update_menu.exec(QCursor.pos())
        update_action.triggered.connect(_update_show_menu)
        self._update_action = update_action
        toolbar.addAction(update_action)
        self._update_check_toolbar_update()

        toolbar.insertSeparator(update_action)

        self.addToolBar(toolbar)
        self.setUnifiedTitleAndToolBarOnMac(True)

    def add_toolbar_action(self, action: QAction) -> None:
        self.toolbar.insertAction(self.spacer_action, action)

    def _update_check_toolbar_update(self):
        update_check_state = "default"
        check_result = self.config.get('last_update_check')
        stable_version = "?"
        if check_result is not None:
            # The latest stable release date, the date of the build we are using.
            stable_result = check_result["stable"]
            stable_signers = get_identified_release_signers(stable_result)
            if stable_signers:
                release_date, current_date = get_update_check_dates(stable_result["date"])
                if release_date > current_date:
                    if time.time() - release_date.timestamp() < 24 * 60 * 60:
                        update_check_state = "update-present-immediate"
                    else:
                        update_check_state = "update-present-prolonged"
                stable_version = stable_result["version"]

        def _on_check_for_updates(checked: bool=False):
            self.show_update_check()

        def _on_view_pending_update(checked: bool=False):
            QDesktopServices.openUrl(QUrl("https://electrumsv.io/#downloads"))

        menu = QMenu()
        self._update_menu = menu
        self._update_check_action = menu.addAction(
            _("Check for Updates"), _on_check_for_updates)

        if update_check_state == "default":
            icon_path = "icons8-available-updates-80-blue"
            icon_text = _("Updates")
            tooltip = _("Check for Updates")
            menu.setDefaultAction(self._update_check_action)
        elif update_check_state == "update-present-immediate":
            icon_path = "icons8-available-updates-80-yellow"
            icon_text = f"{stable_version}"
            tooltip = _("A newer version of ElectrumSV is available, and "+
                "was released on {0:%c}").format(release_date)
            self._update_view_pending_action = menu.addAction(
                _("View Pending Update"), _on_view_pending_update)
            menu.setDefaultAction(self._update_view_pending_action)
        elif update_check_state == "update-present-prolonged":
            icon_path = "icons8-available-updates-80-red"
            icon_text = f"{stable_version}"
            tooltip = _("A newer version of ElectrumSV is available, and "+
                "was released on {0:%c}").format(release_date)
            self._update_view_pending_action = menu.addAction(
                _("View Pending Update"), _on_view_pending_update)
            menu.setDefaultAction(self._update_view_pending_action)
        # Apply the update state.
        self._update_action.setMenu(menu)
        self._update_action.setIcon(read_QIcon(icon_path))
        self._update_action.setText(icon_text)
        self._update_action.setToolTip(tooltip)
        self._update_check_state = update_check_state

    def on_update_check(self, success, result):
        if success:
            stable_result = result["stable"]
            stable_signers = get_identified_release_signers(stable_result)
            if stable_signers:
                # The latest stable release date, the date of the build we are using.
                stable_date_string = stable_result["date"]
                release_date, current_date = get_update_check_dates(stable_date_string)
                if release_date > current_date:
                    self.app.tray.showMessage(
                        "ElectrumSV",
                        _("A new version of ElectrumSV, version {}, is available for download")
                            .format(stable_result["version"]),
                        read_QIcon("electrum_dark_icon"), 20000)

        self._update_check_toolbar_update()

    def new_payment(self):
        from . import payment
        from importlib import reload
        reload(payment)
        self.w = payment.PaymentWindow(self._api, parent=self)
        self.w.show()

    def donate_to_server(self):
        server = self.network.main_server
        addr = server.state.donation_address
        if is_address_valid(addr):
            addr = address_from_string(addr)
            self.pay_to_URI(web.create_URI(addr, 0, _('Donation for {}').format(server.host)))
        else:
            self.show_error(_('The server {} has not provided a valid donation address')
                            .format(server))

    def show_about(self):
        QMessageBox.about(self, "ElectrumSV",
            _("Version")+" %s" % PACKAGE_VERSION + "\n\n" +
            _("ElectrumSV's focus is speed, with low resource usage and simplifying "
              "Bitcoin SV. You do not need to perform regular backups, because your "
              "wallet can be recovered from a secret phrase that you can memorize or "
              "write on paper. Startup times are instant because it operates in "
              "conjunction with high-performance servers that handle the most complicated "
              "parts of the Bitcoin SV system."  + "\n\n" +
              _("Uses icons from the Icons8 icon pack (icons8.com).")))

    def show_update_check(self):
        from . import update_check
        update_check.UpdateCheckDialog()

    def show_report_bug(self):
        msg = ' '.join([
            _("Please report any bugs as issues on github:<br/>"),
            "<a href=\"https://github.com/ElectrumSV/ElectrumSV/issues"
            "\">https://github.com/ElectrumSV/ElectrumSV/issues</a><br/><br/>",
            _("Before reporting a bug, upgrade to the most recent version of ElectrumSV "
              "(latest release or git HEAD), and include the version number in your report."),
            _("Try to explain not only what the bug is, but how it occurs.")
         ])
        self.show_message(msg, title="ElectrumSV - " + _("Reporting Bugs"))

    last_notify_tx_time = 0.0
    notify_tx_rate = 30.0

    def notify_tx_cb(self):
        n_ok = 0
        if self.network and self.network.is_connected():
            num_txns = len(self.tx_notifications)
            if num_txns:
                # Combine the transactions
                total_amount = 0
                for tx, wallet in self.tx_notifications:
                    if tx:
                        is_relevant, is_mine, v, fee = wallet.get_wallet_delta(tx)
                        if v > 0 and is_relevant:
                            total_amount += v
                            n_ok += 1
                if n_ok:
                    self.logger.debug("Notifying GUI %d tx", n_ok)
                    if n_ok > 1:
                        self.notify(_("{} new transactions received: Total amount received "
                                      "in the new transactions {}")
                                    .format(n_ok, self.format_amount_and_units(total_amount)))
                    else:
                        self.notify(_("New transaction received: {}").format(
                            self.format_amount_and_units(total_amount)))
        self.tx_notifications = list()
        self.last_notify_tx_time = time.time() if n_ok else self.last_notify_tx_time
        if self.tx_notify_timer:
            self.tx_notify_timer.stop()
            self.tx_notify_timer = None


    def notify_transactions(self):
        if self.tx_notify_timer or not len(self.tx_notifications) or self.cleaned_up:
            # common case: extant notify timer -- we already enqueued to notify. So bail
            # and wait for timer to handle it.
            return
        elapsed = time.time() - self.last_notify_tx_time
        if elapsed < self.notify_tx_rate:
            # spam control. force tx notify popup to not appear more often than every 30
            # seconds by enqueing the request for a timer to handle it sometime later
            self.tx_notify_timer = QTimer(self)
            self.tx_notify_timer.setSingleShot(True)
            self.tx_notify_timer.timeout.connect(self.notify_tx_cb)
            when = (self.notify_tx_rate - elapsed)
            self.logger.debug("Notify spam control: will notify GUI of %d new tx's in %f seconds",
                              len(self.tx_notifications), when)
            self.tx_notify_timer.start(when * 1e3) # time in ms
        else:
            # it's been a while since we got a tx notify -- so do it immediately (no timer
            # necessary)
            self.notify_tx_cb()


    def notify(self, message):
        self.app.tray.showMessage("ElectrumSV", message,
                                  read_QIcon("electrum_dark_icon"), 20000)

    # custom wrappers for getOpenFileName and getSaveFileName, that remember the path
    # selected by the user
    def getOpenFileName(self, title, filter = ""):
        directory = self.config.get('io_dir', os.path.expanduser('~'))
        fileName, __ = QFileDialog.getOpenFileName(self, title, directory, filter)
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def getOpenFileNames(self, title, filter = ""):
        directory = self.config.get('io_dir', os.path.expanduser('~'))
        fileNames, __ = QFileDialog.getOpenFileNames(self, title, directory, filter)
        if fileNames and directory != os.path.dirname(fileNames[0]):
            self.config.set_key('io_dir', os.path.dirname(fileNames[0]), True)
        return fileNames

    def getSaveFileName(self, title, filename, filter = ""):
        directory = self.config.get('io_dir', os.path.expanduser('~'))
        path = os.path.join( directory, filename )
        fileName, __ = QFileDialog.getSaveFileName(self, title, path, filter)
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def timer_actions(self):
        # Note this runs in the GUI thread
        if self.need_update.is_set():
            self.need_update.clear()
            self.update_wallet()

        # resolve aliases (used to be used for openalias)
        self.payto_e.resolve()

        # update fee
        if self.require_fee_update:
            self.do_update_fee()
            self.require_fee_update = False

    def format_amount(self, x, is_diff=False, whitespaces=False):
        return format_satoshis(x, app_state.num_zeros, app_state.decimal_point,
                               is_diff=is_diff, whitespaces=whitespaces)

    def format_amount_and_units(self, amount):
        text = self.format_amount(amount) + ' ' + app_state.base_unit()
        if app_state.fx and app_state.fx.is_enabled():
            x = app_state.fx.format_amount_and_units(amount)
            if text and x:
                text += ' (%s)'%x
        return text

    def get_amount_and_units(self, amount: int) -> Tuple[str, str]:
        bitcoin_text = self.format_amount(amount) + ' ' + app_state.base_unit()
        if app_state.fx and app_state.fx.is_enabled():
            fiat_text = app_state.fx.format_amount_and_units(amount)
        else:
            fiat_text = ''
        return bitcoin_text, fiat_text

    def format_fee_rate(self, fee_rate: int) -> str:
        return format_fee_satoshis(fee_rate/1000, app_state.num_zeros) + ' sat/B'

    def connect_fields(self, window, btc_e, fiat_e, fee_e):

        def edit_changed(edit):
            if edit.follows:
                return
            edit.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())
            fiat_e.is_last_edited = (edit == fiat_e)
            amount = edit.get_amount()
            rate = app_state.fx.exchange_rate() if app_state.fx else None
            if rate is None or amount is None:
                if edit is fiat_e:
                    btc_e.setText("")
                    if fee_e:
                        fee_e.setText("")
                else:
                    fiat_e.setText("")
            else:
                if edit is fiat_e:
                    btc_e.follows = True
                    btc_e.setAmount(int(amount / Decimal(rate) * COIN))
                    btc_e.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
                    btc_e.follows = False
                    if fee_e:
                        window.update_fee()
                else:
                    fiat_e.follows = True
                    fiat_e.setText(app_state.fx.ccy_amount_str(
                        amount * Decimal(rate) / COIN, False))
                    fiat_e.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
                    fiat_e.follows = False

        btc_e.follows = False
        fiat_e.follows = False
        fiat_e.textChanged.connect(partial(edit_changed, fiat_e))
        btc_e.textChanged.connect(partial(edit_changed, btc_e))
        fiat_e.is_last_edited = False

    async def _monitor_wallet_network_status(self, wallet: Abstract_Wallet) -> None:
        while True:
            await wallet.progress_event.wait()
            wallet.progress_event.clear()
            self._wallet_sync_event.set()

    async def _maintain_network_status(self) -> None:
        while True:
            await self._wallet_sync_event.wait()
            self.network_status_signal.emit()
            # Throttle updates
            await asyncio.sleep(1.0)

    def _update_network_status(self) -> None:
        text = _("Offline")
        if self.network:
            request_count = 0
            response_count = 0
            for wallet in self.parent_wallet.get_child_wallets():
                if wallet.request_count > wallet.response_count:
                    request_count += wallet.request_count
                    response_count += wallet.response_count
                else:
                    wallet.request_count = 0
                    wallet.response_count = 0
            if request_count > response_count:
                text = _("Synchronizing...")
                text += f' {response_count:,d}/{request_count:,d}'
            else:
                server_height = self.network.get_server_height()
                if server_height == 0:
                    text = _("Not connected")
                else:
                    server_lag = self.network.get_local_height() - server_height
                    if server_lag > 1:
                        text = _("Server {} blocks behind").format(server_lag)
                    else:
                        text = _("Connected")
        self._status_bar.set_network_status(text)

    def update_status(self):
        fiat_status = None
        # Display if offline. Display if online. Do not display if synchronizing.
        if self.network and self.network.is_connected():
            # append fiat balance and price
            if app_state.fx.is_enabled():
                balance = 0
                for wallet in self.parent_wallet.get_child_wallets():
                    c, u, x = wallet.get_balance()
                    balance += c
                fiat_status = app_state.fx.get_fiat_status(
                    balance, app_state.base_unit(), app_state.decimal_point)
        self.set_status_bar_balance(True)
        self._status_bar.set_fiat_status(fiat_status)

    @profiler
    def update_wallet(self):
        self.update_status()
        if (self.parent_wallet.is_synchronized() or not self.network or
                not self.network.is_connected()):
            self.update_tabs()

    def update_tabs(self, *args):
        self.history_view.update_tx_list()
        self.request_list.update()
        self.utxo_list.update()
        self.contact_list.update()
        self.invoice_list.update()
        self.history_updated_signal.emit()

    def create_history_tab(self):
        from .history_list import HistoryView
        self.history_view = HistoryView(self, self.parent_wallet)
        return self.history_view

    def show_address(self, wallet: Abstract_Wallet, addr: Address):
        from . import address_dialog
        d = address_dialog.AddressDialog(self, wallet, addr)
        d.exec_()

    def show_transaction(self, tx, tx_desc=None, prompt_if_unsaved=False):
        '''tx_desc is set only for txs created in the Send tab'''
        tx_dialog = TxDialog(tx, self, tx_desc, prompt_if_unsaved)
        tx_dialog.finished.connect(partial(self.on_tx_dialog_finished, tx_dialog))
        self.tx_dialogs.append(tx_dialog)
        tx_dialog.show()
        return tx_dialog

    def on_tx_dialog_finished(self, tx_dialog, status):
        tx_dialog.finished.disconnect()
        self.tx_dialogs.remove(tx_dialog)

    def create_receive_tab(self):
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self.receive_grid = grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        self.receive_address = None
        self.receive_address_e = ButtonsLineEdit()
        self.receive_address_e.addCopyButton(self.app)
        self.receive_address_e.setReadOnly(True)
        msg = _('Bitcoin SV address where the payment should be received. '
                'Note that each payment request uses a different Bitcoin SV address.')
        self.receive_address_label = HelpLabel(_('Receiving address'), msg)
        self.receive_address_e.textChanged.connect(self.update_receive_qr)
        self.receive_address_e.setFocusPolicy(Qt.NoFocus)
        grid.addWidget(self.receive_address_label, 0, 0)
        grid.addWidget(self.receive_address_e, 0, 1, 1, -1)

        self.receive_message_e = QLineEdit()
        grid.addWidget(QLabel(_('Description')), 1, 0)
        grid.addWidget(self.receive_message_e, 1, 1, 1, -1)
        self.receive_message_e.textChanged.connect(self.update_receive_qr)

        self.receive_amount_e = BTCAmountEdit()
        grid.addWidget(QLabel(_('Requested amount')), 2, 0)
        grid.addWidget(self.receive_amount_e, 2, 1)
        self.receive_amount_e.textChanged.connect(self.update_receive_qr)

        self.fiat_receive_e = AmountEdit(app_state.fx.get_currency if app_state.fx else '')
        if not app_state.fx or not app_state.fx.is_enabled():
            self.fiat_receive_e.setVisible(False)
        grid.addWidget(self.fiat_receive_e, 2, 2, Qt.AlignLeft)
        self.connect_fields(self, self.receive_amount_e, self.fiat_receive_e, None)

        self.expires_combo = QComboBox()
        self.expires_combo.addItems([i[0] for i in expiration_values])
        self.expires_combo.setCurrentIndex(3)
        self.expires_combo.setFixedWidth(self.receive_amount_e.width())
        msg = ' '.join([
            _('Expiration date of your request.'),
            _('This information is seen by the recipient if you send them '
              'a signed payment request.'),
            _('Expired requests have to be deleted manually from your list, '
              'in order to free the corresponding Bitcoin SV addresses.'),
            _('The Bitcoin SV address never expires and will always be part '
              'of this ElectrumSV wallet.'),
        ])
        grid.addWidget(HelpLabel(_('Request expires'), msg), 3, 0)
        grid.addWidget(self.expires_combo, 3, 1)
        self.expires_label = QLineEdit('')
        self.expires_label.setReadOnly(1)
        self.expires_label.setFocusPolicy(Qt.NoFocus)
        self.expires_label.hide()
        grid.addWidget(self.expires_label, 3, 1)

        self.save_request_button = QPushButton(_('Save'))
        self.save_request_button.clicked.connect(self.save_payment_request)

        self.new_request_button = QPushButton(_('New'))
        self.new_request_button.clicked.connect(self.new_payment_request)

        self.receive_qr = QRCodeWidget(fixedSize=200)
        self.receive_qr.mouseReleaseEvent = lambda x: self.toggle_qr_window()
        self.receive_qr.enterEvent = lambda x: self.app.setOverrideCursor(
            QCursor(Qt.PointingHandCursor))
        self.receive_qr.leaveEvent = lambda x: self.app.setOverrideCursor(QCursor(Qt.ArrowCursor))

        self.receive_buttons = buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.save_request_button)
        buttons.addWidget(self.new_request_button)
        grid.addLayout(buttons, 4, 1, 1, 2)

        self.receive_requests_label = QLabel(_('Requests'))

        from .request_list import RequestList
        self.request_list = RequestList(self)

        # layout
        vbox_g = QVBoxLayout()
        vbox_g.addLayout(grid)
        vbox_g.addStretch()

        hbox = QHBoxLayout()
        hbox.addLayout(vbox_g)
        hbox.addWidget(self.receive_qr)

        w = QWidget()
        w.searchable_list = self.request_list
        vbox = QVBoxLayout(w)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.receive_requests_label)
        vbox.addWidget(self.request_list)
        vbox.setStretchFactor(self.request_list, 1000)

        return w

    def delete_payment_request(self, address: Address) -> None:
        self._receive_wallet.remove_payment_request(address, self.config)
        self.request_list.update()
        self.clear_receive_tab()

    def get_request_URI(self, address: Address) -> str:
        req = self._receive_wallet.receive_requests[address]
        message = self._receive_wallet.labels.get(address.to_string(), '')
        amount = req['amount']
        URI = web.create_URI(address, amount, message)
        if req.get('time'):
            URI += "&time=%d"%req.get('time')
        if req.get('exp'):
            URI += "&exp=%d"%req.get('exp')
        return str(URI)

    def save_payment_request(self):
        if not self.receive_address:
            self.show_error(_('No receiving address'))
        amount = self.receive_amount_e.get_amount()
        message = self.receive_message_e.text()
        if not message and not amount:
            self.show_error(_('No message or amount'))
            return False
        i = self.expires_combo.currentIndex()
        expiration = [x[1] for x in expiration_values][i]
        req = self._receive_wallet.make_payment_request(self.receive_address, amount,
                                               message, expiration)
        self._receive_wallet.add_payment_request(req, self.config)
        self.request_list.update()
        # The existence of the address in the payment request index changes it's state (not unused).
        if self._addresses_wallet is self._receive_wallet and self.address_list is not None:
            self.address_list.update_addresses([ self.receive_address ])
        self.save_request_button.setEnabled(False)

    def view_and_paste(self, title, msg, data):
        dialog = WindowModalDialog(self, title)
        vbox = QVBoxLayout()
        label = QLabel(msg)
        label.setWordWrap(True)
        vbox.addWidget(label)
        pr_e = ShowQRTextEdit(text=data)
        vbox.addWidget(pr_e)
        vbox.addLayout(Buttons(CopyCloseButton(pr_e.text, self.app, dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()

    def export_payment_request(self, addr) -> None:
        r = self._receive_wallet.receive_requests[addr]
        pr_data = paymentrequest.PaymentRequest.from_wallet_entry(r).to_json()
        name = r['id'] + '.bip270.json'
        fileName = self.getSaveFileName(_("Select where to save your payment request"),
                                        name, "*.bip270.json")
        if fileName:
            with open(fileName, "w") as f:
                f.write(pr_data)
            self.show_message(_("Request saved successfully"))
            self.saved = True

    def new_payment_request(self) -> None:
        addr = self._receive_wallet.get_unused_address()
        if addr is None:
            if not self._receive_wallet.is_deterministic():
                msg = [
                    _('No more addresses in your wallet.'),
                    _('You are using a non-deterministic wallet, which '
                      'cannot create new addresses.'),
                    _('If you want to create new addresses, use a deterministic wallet instead.')
                   ]
                self.show_message(' '.join(msg))
                return
            if not self.question(_(
                    'Warning: The next address will not be recovered automatically if '
                    'you restore your wallet from seed; you may need to add it manually.\n\n'
                    'This occurs because you have too many unused addresses in your wallet. '
                    'To avoid this situation, use the existing addresses first.\n\n'
                    'Create anyway?'
            )):
                return
            addr = self._receive_wallet.create_new_address(False)
        self.set_receive_address(addr)
        self.expires_label.hide()
        self.expires_combo.show()
        self.new_request_button.setEnabled(False)
        self.receive_message_e.setFocus(1)

    def set_receive_address(self, addr: Address) -> None:
        self.receive_address = addr
        self.receive_message_e.setText('')
        self.receive_amount_e.setAmount(None)
        self.update_receive_address_widget()

    def update_receive_address_widget(self) -> None:
        text = ''
        if self.receive_address:
            text = self.receive_address.to_string()
        self.receive_address_e.setText(text)

    def clear_receive_tab(self) -> None:
        self.expires_label.hide()
        self.expires_combo.show()
        self.set_receive_address(self._receive_wallet.get_receiving_address())

    def toggle_qr_window(self):
        from . import qrwindow
        if not self.qr_window:
            self.qr_window = qrwindow.QR_Window(self)
            self.qr_window.setVisible(True)
            self.qr_window_geometry = self.qr_window.geometry()
        else:
            if not self.qr_window.isVisible():
                self.qr_window.setVisible(True)
                self.qr_window.setGeometry(self.qr_window_geometry)
            else:
                self.qr_window_geometry = self.qr_window.geometry()
                self.qr_window.setVisible(False)
        self.update_receive_qr()

    def show_send_tab(self):
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.send_tab))

    def show_receive_tab(self):
        self.tabs.setCurrentIndex(self.tabs.indexOf(self.receive_tab))

    def receive_at(self, addr):
        self.receive_address = addr
        self.show_receive_tab()
        self.new_request_button.setEnabled(True)
        self.update_receive_address_widget()

    def update_receive_qr(self):
        amount = self.receive_amount_e.get_amount()
        message = self.receive_message_e.text()
        self.save_request_button.setEnabled((amount is not None) or (message != ""))
        uri = web.create_URI(self.receive_address, amount, message)
        self.receive_qr.setData(uri)
        if self.qr_window and self.qr_window.isVisible():
            self.qr_window.set_content(self.receive_address_e.text(), amount,
                                       message, uri)

    def create_send_tab(self):
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self.send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        # This ensures all columns are stretched over the full width of the last tab.
        grid.setColumnStretch(4, 1)

        from .paytoedit import PayToEdit
        self.amount_e = BTCAmountEdit()
        self.payto_e = PayToEdit(self)

        # From fields row.
        # This is enabled by "spending" coins in the coins tab.

        self.from_label = QLabel(_('From'))
        self.from_label.setContentsMargins(0, 5, 0, 0)
        self.from_label.setAlignment(Qt.AlignTop)
        grid.addWidget(self.from_label, 1, 0)
        self.from_list = MyTreeWidget(self, self.from_list_menu, ['Address / Outpoint','Amount'])
        self.from_list.setMaximumHeight(80)
        grid.addWidget(self.from_list, 1, 1, 1, -1)
        self.set_pay_from([])

        msg = (_('Recipient of the funds.') + '\n\n' +
               _('You may enter a Bitcoin SV address, a label from your list of '
                 'contacts (a list of completions will be proposed), or an alias '
                 '(email-like address that forwards to a Bitcoin SV address)'))
        payto_label = HelpLabel(_('Pay to'), msg)
        payto_label.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
        grid.addWidget(payto_label, 2, 0)
        grid.addWidget(self.payto_e, 2, 1, 1, -1)

        msg = (_('Amount to be sent.') + '\n\n' +
               _('The amount will be displayed in red if you do not have '
                 'enough funds in your wallet.') + ' '
               + _('Note that if you have frozen some of your addresses, the available '
                   'funds will be lower than your total balance.') + '\n\n'
               + _('Keyboard shortcut: type "!" to send all your coins.'))
        amount_label = HelpLabel(_('Amount'), msg)
        grid.addWidget(amount_label, 3, 0)
        grid.addWidget(self.amount_e, 3, 1)

        self.fiat_send_e = AmountEdit(app_state.fx.get_currency if app_state.fx else '')
        if not app_state.fx or not app_state.fx.is_enabled():
            self.fiat_send_e.setVisible(False)
        grid.addWidget(self.fiat_send_e, 3, 2)
        self.amount_e.frozen.connect(
            lambda: self.fiat_send_e.setFrozen(self.amount_e.isReadOnly()))

        self.max_button = EnterButton(_("Max"), self.spend_max)
        self.max_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        grid.addWidget(self.max_button, 3, 3)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
        self.payto_e.set_completer(completer)
        completer.setModel(self.completions)

        msg = (_('Description of the transaction (not mandatory).') + '\n\n' +
               _('The description is not sent to the recipient of the funds. '
                 'It is stored in your wallet file, and displayed in the \'History\' tab.'))
        description_label = HelpLabel(_('Description'), msg)
        grid.addWidget(description_label, 4, 0)
        self.message_e = MyLineEdit()
        grid.addWidget(self.message_e, 4, 1, 1, -1)

        # OP_RETURN fields row

        msg_attached = (_('Attached files (optional).') + '\n\n' +
                        _('Posts PERMANENT data to the Bitcoin SV blockchain as part of '
                          'this transaction using OP_RETURN.') + '\n\n' +
                        _('If you attach files, the \'Pay to\' field can be left blank.'))
        attached_data_label = HelpLabel(_('Attached Files'), msg_attached)
        attached_data_label.setContentsMargins(0, 5, 0, 0)
        attached_data_label.setAlignment(Qt.AlignTop)
        grid.addWidget(attached_data_label,  5, 0)

        hbox = QHBoxLayout()
        hbox.setSpacing(0)
        def attach_menu(*args):
            pass
        self.send_data_list = MyTreeWidget(self, attach_menu,
            [ "", _("File size"), _("File name"), "" ], 2)
        self.send_data_list.setSelectionMode(MyTreeWidget.SingleSelection)
        self.send_data_list.setSelectionBehavior(MyTreeWidget.SelectRows)
        hbox.addWidget(self.send_data_list)
        vbox = QVBoxLayout()
        vbox.setSpacing(0)
        vbox.setContentsMargins(5, 0, 0, 0)
        attach_button = EnterButton("", self._do_add_send_attachments)
        attach_button.setToolTip(_("Add file(s)"))
        attach_button.setIcon(read_QIcon("icons8-attach-96.png"))
        attach_button.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)
        vbox.addWidget(attach_button)
        vbox.addStretch()
        hbox.addLayout(vbox)
        self._on_send_data_list_updated()
        grid.addLayout(hbox, 5, 1, 1, -1)

        self.connect_fields(self, self.amount_e, self.fiat_send_e, None)

        self.preview_button = EnterButton(_("Preview"), self.do_preview)
        self.preview_button.setToolTip(
            _('Display the details of your transactions before signing it.'))
        self.send_button = EnterButton(_("Send"), self.do_send)
        if self.network is None:
            self.send_button.setEnabled(False)
            self.send_button.setToolTip(_('You are using ElectrumSV in offline mode; restart '
                                          'ElectrumSV if you want to get connected'))

        self.clear_button = EnterButton(_("Clear"), self.do_clear)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.clear_button)
        buttons.addWidget(self.preview_button)
        buttons.addWidget(self.send_button)
        buttons.addStretch(1)
        grid.addLayout(buttons, 6, 0, 1, -1)

        self.amount_e.shortcut.connect(self.spend_max)
        self.payto_e.textChanged.connect(self.update_fee)
        self.amount_e.textEdited.connect(self.update_fee)

        def reset_max(t):
            self.is_max = False
            self.max_button.setEnabled(not bool(t))
        self.amount_e.textEdited.connect(reset_max)
        self.fiat_send_e.textEdited.connect(reset_max)

        def entry_changed():
            text = ""
            if self.not_enough_funds:
                amt_color = ColorScheme.RED
                text = _( "Not enough funds" )
                c, u, x = self._send_wallet.get_frozen_balance()
                if c+u+x:
                    text += (' (' + self.format_amount(c+u+x).strip() + ' ' +
                             app_state.base_unit() + ' ' + _("are frozen") + ')')

            if self.amount_e.isModified():
                amt_color = ColorScheme.DEFAULT
            else:
                amt_color = ColorScheme.BLUE

            self.statusBar().showMessage(text)
            self.amount_e.setStyleSheet(amt_color.as_stylesheet())

        self.amount_e.textChanged.connect(entry_changed)

        self.invoices_label = QLabel(_('Invoices'))
        from .invoice_list import InvoiceList
        self.invoice_list = InvoiceList(self)

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)
        w = QWidget()
        vbox = QVBoxLayout(w)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.invoices_label)
        vbox.addWidget(self.invoice_list)
        vbox.setStretchFactor(self.invoice_list, 1000)
        w.searchable_list = self.invoice_list
        return w

    def spend_max(self):
        self.is_max = True
        self.do_update_fee()

    def update_fee(self):
        self.require_fee_update = True

    def get_payto_or_dummy(self):
        r = self.payto_e.get_recipient()
        if r:
            return r
        return self._send_wallet.dummy_address()

    def get_custom_fee_text(self, fee_rate = None):
        if not self.config.has_custom_fee_rate():
            return ""
        else:
            if fee_rate is None: fee_rate = self.config.custom_fee_rate() / 1000.0
            return str(round(fee_rate*100)/100) + " sats/B"

    def get_opreturn_outputs(self, outputs):
        table = self.send_data_list

        file_paths = []
        for row_index in range(table.model().rowCount()):
            item = table.topLevelItem(row_index)
            file_paths.append(item.data(0, Qt.UserRole))
        if len(file_paths):
            data_chunks = []
            for file_path in file_paths:
                with open(file_path, "rb") as f:
                    data_chunks.append(f.read())
            script = (Script() << OP_FALSE << OP_RETURN).push_many(data_chunks)
            return [TxOutput(0, script)]
        return []

    def do_update_fee(self):
        '''Recalculate the fee.  If the fee was manually input, retain it, but
        still build the TX to see if there are enough funds.
        '''
        amount = all if self.is_max else self.amount_e.get_amount()
        if amount is None:
            self.not_enough_funds = False
            self.statusBar().showMessage('')
        else:
            fee = None
            outputs = self.payto_e.get_outputs(self.is_max)
            if not outputs:
                addr = self.get_payto_or_dummy()
                outputs = [TxOutput(amount, addr.to_script())]

            outputs.extend(self.get_opreturn_outputs(outputs))
            try:
                tx = self._send_wallet.make_unsigned_transaction(self.get_coins(self._send_wallet),
                    outputs, self.config, fee)
                self.not_enough_funds = False
            except NotEnoughFunds:
                self.not_enough_funds = True
                return
            except Exception:
                return

            if self.is_max:
                amount = tx.output_value()
                self.amount_e.setAmount(amount)

    def from_list_delete(self, item):
        i = self.from_list.indexOfTopLevelItem(item)
        self.pay_from.pop(i)
        self.redraw_from_list()
        self.update_fee()

    def from_list_menu(self, position):
        item = self.from_list.itemAt(position)
        menu = QMenu()
        menu.addAction(_("Remove"), lambda: self.from_list_delete(item))
        menu.exec_(self.from_list.viewport().mapToGlobal(position))

    def set_pay_from(self, coins):
        self.pay_from = list(coins)
        self.redraw_from_list()

    def redraw_from_list(self):
        self.from_list.clear()
        self.from_label.setHidden(len(self.pay_from) == 0)
        self.from_list.setHidden(len(self.pay_from) == 0)

        def format_utxo(utxo):
            h = utxo.tx_hash
            return '{}...{}:{:d}\t{}'.format(h[0:10], h[-10:],
                                             utxo.out_index, utxo.address)

        for utxo in self.pay_from:
            self.from_list.addTopLevelItem(QTreeWidgetItem(
                [format_utxo(utxo), self.format_amount(utxo.value)]))

        update_fixed_tree_height(self.from_list)

    def get_contact_payto(self, contact_id):
        contact = self.contacts.get_contact(contact_id)
        return contact.label

    def read_send_tab(self):
        isInvoice= False

        if self.payment_request and self.payment_request.has_expired():
            self.show_error(_('Payment request has expired'))
            return
        label = self.message_e.text()

        if self.payment_request:
            isInvoice = True
            outputs = self.payment_request.get_outputs()
        else:
            errors = self.payto_e.get_errors()
            if errors:
                self.show_warning(_("Invalid lines found:") + "\n\n" +
                                  '\n'.join([ _("Line #") + str(x[0]+1) + ": " + x[1]
                                              for x in errors]))
                return
            outputs = self.payto_e.get_outputs(self.is_max)

        outputs.extend(self.get_opreturn_outputs(outputs))

        if not outputs:
            self.show_error(_('No outputs'))
            return

        if any(output.value is None for output in outputs):
            self.show_error(_('Invalid Amount'))
            return
        fee = None
        coins = self.get_coins(self._send_wallet, isInvoice)
        return outputs, fee, label, coins

    def _on_send_data_list_updated(self):
        item_count = self.send_data_list.model().rowCount()

        is_enabled = item_count > 0
        self.send_data_list.setEnabled(is_enabled)
        self.send_data_list.setToolTip(_("Attach a file to include it in the transaction."))
        update_fixed_tree_height(self.send_data_list, maximum_height=80)

    def _do_add_send_attachments(self):
        dialogs.show_named('illegal-files-are-traceable')

        table = self.send_data_list
        file_paths = self.getOpenFileNames(_("Select file(s)"))
        last_item = None
        for file_path in file_paths:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            item = QTreeWidgetItem()
            item.setData(0, Qt.UserRole, file_path)
            item.setIcon(0, read_QIcon("icons8-file-512.png"))
            item.setText(1, str(file_size))
            item.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            item.setText(2, file_name)

            table.addChild(item)

            # Setting item column widgets only works when the item is added to the table.
            delete_button = QPushButton()
            delete_button.clicked.connect(partial(self._on_delete_attachment, file_path))
            delete_button.setFlat(True)
            delete_button.setCursor(QCursor(Qt.PointingHandCursor))
            delete_button.setIcon(read_QIcon("icons8-trash.svg"))
            table.setItemWidget(item, 3, delete_button)

            last_item = item

        if last_item is not None:
            self._on_send_data_list_updated()
            table.scrollToItem(last_item)

    def _on_delete_attachment(self, file_path, checked=False):
        table = self.send_data_list
        for row_index in range(table.model().rowCount()):
            item = table.topLevelItem(row_index)
            item_file_path = item.data(0, Qt.UserRole)
            if item_file_path == file_path:
                table.takeTopLevelItem(row_index)
                break

    def do_preview(self):
        self.do_send(preview = True)

    def do_send(self, preview = False):
        dialogs.show_named('think-before-sending')

        r = self.read_send_tab()
        if not r:
            return
        outputs, fee, tx_desc, coins = r
        try:
            tx = self._send_wallet.make_unsigned_transaction(coins, outputs, self.config, fee)
        except NotEnoughFunds:
            self.show_message(_("Insufficient funds"))
            return
        except ExcessiveFee:
            self.show_message(_("Your fee is too high.  Max is 50 sat/byte."))
            return
        except Exception as e:
            self.logger.exception("")
            self.show_message(str(e))
            return

        amount = tx.output_value() if self.is_max else sum(output.value for output in outputs)
        fee = tx.get_fee()

        if preview:
            self.show_transaction(tx, tx_desc)
            return

        # confirmation dialog
        msg = [
            _("Amount to be sent") + ": " + self.format_amount_and_units(amount),
            _("Mining fee") + ": " + self.format_amount_and_units(fee),
        ]

        confirm_rate = 2 * self.config.max_fee_rate()

        if fee < (tx.estimated_size()):
            msg.append(_('Warning') + ': ' +
                       _('The fee is less than 1000 sats/kb.  '
                         'It may take a very long time to confirm.'))

        if self.parent_wallet.has_password():
            msg.append("")
            msg.append(_("Enter your password to proceed"))
            password = self.password_dialog('\n'.join(msg))
            if not password:
                return
        else:
            msg.append(_('Proceed?'))
            password = None
            if not self.question('\n'.join(msg)):
                return

        def sign_done(success):
            if success:
                if not tx.is_complete():
                    self.show_transaction(tx)
                    self.do_clear()
                else:
                    self.broadcast_transaction(self._send_wallet, tx, tx_desc)
        self.sign_tx_with_password(tx, sign_done, password)

    @protected
    def sign_tx(self, tx, callback, password, window=None):
        self.sign_tx_with_password(tx, callback, password, window=window)

    def sign_tx_with_password(self, tx, callback, password, window=None):
        '''Sign the transaction in a separate thread.  When done, calls
        the callback with a success code of True or False.
        '''
        def on_done(future):
            try:
                future.result()
            except Exception as exc:
                self.on_exception(exc)
                callback(False)
            else:
                callback(True)

        def sign_tx():
            if self.tx_external_keypairs:
                tx.sign(self.tx_external_keypairs)
            else:
                self._send_wallet.sign_transaction(tx, password)

        window = window or self
        WaitingDialog(window, _('Signing transaction...'), sign_tx, on_done=on_done)

    def broadcast_transaction(self, wallet: Abstract_Wallet, tx: Transaction,
            tx_desc: Optional[str], success_text: Optional[str]=None, window=None) -> Optional[str]:
        if success_text is None:
            success_text = _('Payment sent.')
        window = window or self

        def broadcast_tx():
            # non-GUI thread
            status = False
            msg = "Failed"
            pr = self.payment_request
            if pr:
                if pr.has_expired():
                    self.payment_request = None
                    raise Exception(_("Payment request has expired"))
                # The invoices are contextual to the send tab at this time, and it's selected
                # child wallet, so use the receiving addresses from there.
                refund_address = self._send_wallet.get_receiving_addresses()[0]
                ack_status, ack_msg = pr.send_payment(str(tx), refund_address)
                msg = ack_msg
                if ack_status:
                    self._send_wallet.invoices.set_paid(pr, tx.txid())
                    self._send_wallet.invoices.save()
                    self.payment_request = None
                return
            else:
                # wallet.set_transaction_state(tx.txid(), TxFlags.StateDispatched)
                return self.network.broadcast_transaction_and_wait(tx)

        def on_done(future):
            # GUI thread
            try:
                tx_id = future.result()
            except Exception as exception:
                self.logger.info(f'raw server error (untrusted): {exception}')
                reason = broadcast_failure_reason(exception)
                d = UntrustedMessageDialog(
                    window, _("Transaction Broadcast Error"),
                    _("Your transaction was not sent: ") + reason + ".",
                    exception)
                d.exec()
            else:
                if tx_id:
                    if tx_desc is not None and tx.is_complete():
                        self._send_wallet.set_label(tx.txid(), tx_desc)
                    window.show_message(success_text + '\n' + tx_id)
                    self.invoice_list.update()
                    self.do_clear()

        WaitingDialog(window, _('Broadcasting transaction...'), broadcast_tx, on_done=on_done)

    def query_choice(self, msg, choices):
        # Needed by QtHandler for hardware wallets
        dialog = WindowModalDialog(self.top_level_window())
        clayout = ChoicesLayout(msg, choices)
        vbox = QVBoxLayout(dialog)
        vbox.addLayout(clayout.layout())
        vbox.addLayout(Buttons(OkButton(dialog)))
        if not dialog.exec_():
            return None
        return clayout.selected_index()

    def lock_amount(self, b):
        self.amount_e.setFrozen(b)
        self.max_button.setEnabled(not b)

    def prepare_for_payment_request(self):
        self.show_send_tab()
        self.payto_e.is_pr = True
        for e in [self.payto_e, self.amount_e, self.message_e]:
            e.setFrozen(True)
        self.max_button.setDisabled(True)
        self.payto_e.setText(_("please wait..."))
        return True

    def delete_invoice(self, key):
        self._send_wallet.invoices.remove(key)
        self.invoice_list.update()

    def payment_request_ok(self):
        pr = self.payment_request
        key = self._send_wallet.invoices.add(pr)
        status = self._send_wallet.invoices.get_status(key)
        self.invoice_list.update()
        if status == PR_PAID:
            self.show_message("invoice already paid")
            self.do_clear()
            self.payment_request = None
            return
        self.payto_e.is_pr = True
        if not pr.has_expired():
            self.payto_e.set_validated()
        else:
            self.payto_e.set_expired()
        self.payto_e.setText(pr.get_requestor())
        self.amount_e.setText(format_satoshis_plain(pr.get_amount(), app_state.decimal_point))
        self.message_e.setText(pr.get_memo())
        # signal to set fee
        self.amount_e.textEdited.emit("")

    def payment_request_error(self):
        self.show_message(self.payment_request.error)
        self.payment_request = None
        self.do_clear()

    def on_pr(self, request):
        self.payment_request = request
        if self.payment_request.verify(self.contacts):
            self.payment_request_ok_signal.emit()
        else:
            self.payment_request_error_signal.emit()

    def pay_to_URI(self, URI):
        if not URI:
            return
        try:
            out = web.parse_URI(URI, self.on_pr)
        except Exception as e:
            self.show_error(str(e))
            return
        self.show_send_tab()

        payment_url = out.get('r')
        if payment_url:
            self.prepare_for_payment_request()
            return

        address = out.get('address')
        amount = out.get('amount')
        label = out.get('label')
        message = out.get('message')
        # use label as description (not BIP21 compliant)
        if label and not message:
            message = label
        if address:
            self.payto_e.setText(address)
        if message:
            self.message_e.setText(message)
        if amount:
            self.amount_e.setAmount(amount)
            self.amount_e.textEdited.emit("")

    def do_clear(self):
        self.is_max = False
        self.not_enough_funds = False
        self.payment_request = None
        self.payto_e.is_pr = False

        edit_fields = []
        edit_fields.extend(self.send_tab.findChildren(QPlainTextEdit))
        edit_fields.extend(self.send_tab.findChildren(QLineEdit))
        for edit_field in edit_fields:
            edit_field.setText('')
            edit_field.setFrozen(False)

        for tree in self.send_tab.findChildren(QTreeView):
            tree.clear()
        self._on_send_data_list_updated()

        self.max_button.setDisabled(False)
        self.set_pay_from([])
        self.tx_external_keypairs = {}
        self.update_status()

    def set_frozen_state(self, child_wallet: Abstract_Wallet, addrs: Iterable[Address],
            freeze: bool) -> None:
        child_wallet.set_frozen_state(addrs, freeze)
        if self.address_list is not None:
            self.address_list.update_frozen_addresses(addrs, freeze)
        self.utxo_list.update()
        self.update_fee()

    def set_frozen_coin_state(self, child_wallet: Abstract_Wallet, utxos, freeze: bool) -> None:
        child_wallet.set_frozen_coin_state(utxos, freeze)
        self.utxo_list.update()
        self.update_fee()

    def create_coinsplitting_tab(self):
        return CoinSplittingTab(self)

    def create_list_tab(self, l, list_header=None):
        w = QWidget()
        w.searchable_list = l
        vbox = QVBoxLayout()
        w.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        if list_header:
            hbox = QHBoxLayout()
            for b in list_header:
                hbox.addWidget(b)
            hbox.addStretch()
            vbox.addLayout(hbox)
        vbox.addWidget(l)
        return w

    def create_addresses_tab(self):
        from .address_list import AddressList
        self.address_list = l = AddressList(self, self.parent_wallet.get_default_wallet())
        return self.create_list_tab(l)

    def create_utxo_tab(self) -> None:
        from .utxo_list import UTXOList
        self.utxo_list = l = UTXOList(self, self.parent_wallet.get_default_wallet())
        return self.create_list_tab(l)

    def create_contacts_tab(self) -> None:
        self.contact_list = l = ContactList(self._api, self)
        return self.create_list_tab(l)

    def remove_address(self, address: Address) -> None:
        if self.question(_("Do you want to remove {} from your wallet?"
                           .format(address.to_string()))):
            self._addresses_wallet.delete_address(address)
            if self.address_list is not None:
                self.address_list.remove_addresses([ address ])
            self.history_view.update_tx_list()
            self.history_updated_signal.emit()
            self.clear_receive_tab()

    def get_coins(self, child_wallet: Abstract_Wallet, isInvoice = False):
        if self.pay_from:
            return self.pay_from
        else:
            return child_wallet.get_spendable_coins(None, self.config, isInvoice)

    def spend_coins(self, coins):
        self.set_pay_from(coins)
        self.show_send_tab()
        self.update_fee()

    def paytomany(self) -> None:
        self.show_send_tab()
        self.payto_e.paytomany()
        msg = '\n'.join([
            _('Enter a list of outputs in the \'Pay to\' field.'),
            _('One output per line.'),
            _('Format: address, amount'),
            _('You may load a CSV file using the file icon.')
        ])
        self.show_message(msg, title=_('Pay to many'))

    def payto_contacts(self, contact_ids: Iterable[int]):
        paytos = [self.get_contact_payto(contact_id) for contact_id in contact_ids]
        self.show_send_tab()
        if len(paytos) == 1:
            self.payto_e.setText(paytos[0])
            self.amount_e.setFocus()
        else:
            text = "\n".join([payto + ", 0" for payto in paytos])
            self.payto_e.setText(text)
            self.payto_e.setFocus()

    def _on_contacts_changed(self) -> None:
        self.contact_list.update()
        self.history_view.update_tx_list()
        self.history_updated_signal.emit()

    def show_invoice(self, key):
        pr = self._send_wallet.invoices.get(key)
        pr.verify(self.contacts)
        self.show_pr_details(pr)

    def show_pr_details(self, pr):
        key = pr.get_id()
        d = WindowModalDialog(self, _("Invoice"))
        vbox = QVBoxLayout(d)
        grid = QGridLayout()
        grid.addWidget(QLabel(_("Requestor") + ':'), 0, 0)
        grid.addWidget(QLabel(pr.get_requestor()), 0, 1)
        grid.addWidget(QLabel(_("Amount") + ':'), 1, 0)
        outputs_str = '\n'.join(self.format_amount(tx_output.value) + app_state.base_unit() +
                                ' @ ' + tx_output_to_display_text(tx_output)[0]
                                for tx_output in pr.get_outputs())
        grid.addWidget(QLabel(outputs_str), 1, 1)
        expires = pr.get_expiration_date()
        grid.addWidget(QLabel(_("Memo") + ':'), 2, 0)
        grid.addWidget(QLabel(pr.get_memo()), 2, 1)
        grid.addWidget(QLabel(_("Signature") + ':'), 3, 0)
        grid.addWidget(QLabel(pr.get_verify_status()), 3, 1)
        if expires:
            grid.addWidget(QLabel(_("Expires") + ':'), 4, 0)
            grid.addWidget(QLabel(format_time(expires, _("Unknown"))), 4, 1)
        vbox.addLayout(grid)
        def do_export():
            fn = self.getSaveFileName(_("Save invoice to file"), "*.bip270.json")
            if not fn:
                return
            with open(fn, 'w') as f:
                data = f.write(pr.to_json())
            self.show_message(_('Invoice saved as' + ' ' + fn))
        exportButton = EnterButton(_('Save'), do_export)
        def do_delete():
            if self.question(_('Delete invoice?')):
                self._send_wallet.invoices.remove(key)
                self.history_view.update_tx_list()
                self.history_updated_signal.emit()
                self.invoice_list.update()
                d.close()
        deleteButton = EnterButton(_('Delete'), do_delete)
        vbox.addLayout(Buttons(exportButton, deleteButton, CloseButton(d)))
        d.exec_()

    def do_pay_invoice(self, key):
        pr = self._send_wallet.invoices.get(key)
        self.payment_request = pr
        self.prepare_for_payment_request()
        pr.error = None  # this forces verify() to re-run
        if pr.verify(self.contacts):
            self.payment_request_ok()
        else:
            self.payment_request_error()

    def create_console_tab(self):
        from .console import Console
        self.console = console = Console()
        return console

    def update_console(self):
        console = self.console
        console.history = self.config.get("console-history",[])
        console.history_index = len(console.history)

        console.updateNamespace({
            'app': self.app,
            'config': app_state.config,
            'daemon': app_state.daemon,
            'electrumsv': electrumsv,
            'network': self.network,
            'util': util,
            'parent_wallet': self.parent_wallet,
            'window': self,
        })

        c = commands.Commands(self.config, self.parent_wallet, self.network,
                              lambda: self.console.set_json(True))
        methods = {}
        def mkfunc(f, method):
            return lambda *args, **kwargs: f(method, *args, password_getter=self.password_dialog,
                                             **kwargs)
        for m in dir(c):
            if m[0] == '_' or m in ['network', 'parent_wallet', 'config']:
                continue
            methods[m] = mkfunc(c._run, m)

        console.updateNamespace(methods)

    def create_status_bar(self):
        from .status_bar import StatusBar
        self._status_bar = StatusBar(self)
        self.set_status_bar_balance(True)
        self._update_network_status()
        self.setStatusBar(self._status_bar)

    def set_status_bar_balance(self, shown: bool) -> None:
        if shown:
            balance = 0
            for wallet in self.parent_wallet.get_child_wallets():
                c, u, x = wallet.get_balance()
                balance += c
            bsv_status, fiat_status = self.get_amount_and_units(balance)
        else:
            bsv_status, fiat_status = _("Unknown"), None
        self._status_bar.set_balance_status(bsv_status, fiat_status)

    def update_buttons_on_seed(self):
        self.send_button.setVisible(not self._send_wallet.is_watching_only())

    def change_password_dialog(self):
        from .password_dialog import ChangePasswordDialog
        d = ChangePasswordDialog(self, self.parent_wallet)
        ok, password, new_password = d.run()
        if not ok:
            return
        try:
            self.parent_wallet.update_password(password, new_password)
        except Exception as e:
            self.show_error(str(e))
            return
        except:
            self.logger.exception("")
            self.show_error(_('Failed to update password'))
            return
        msg = (_('Password was updated successfully') if new_password
               else _('Password is disabled, this wallet is not protected'))
        self.show_message(msg, title=_("Success"))

    def toggle_search(self):
        self._status_bar.search_box.setHidden(not self._status_bar.search_box.isHidden())
        if not self._status_bar.search_box.isHidden():
            self._status_bar.search_box.setFocus(1)
        else:
            self.do_search('')

    def do_search(self, t):
        tab = self.tabs.currentWidget()
        if hasattr(tab, 'searchable_list'):
            tab.searchable_list.filter(t)

    def show_wallet_information(self):
        pass

    def remove_wallet(self):
        if self.question('\n'.join([
                _('Delete wallet file?'),
                "%s"%self.parent_wallet.get_storage_path(),
                _('If your wallet contains funds, make sure you have saved its seed.')])):
            self._delete_wallet() # pylint: disable=no-value-for-parameter

    @protected
    def _delete_wallet(self, password):
        wallet_path = self.parent_wallet.get_storage_path()
        basename = self.parent_wallet.name()
        app_state.daemon.stop_wallet_at_path(wallet_path)
        self.close()
        os.unlink(wallet_path)
        self.update_recently_visited(wallet_path) # this ensures it's deleted from the menu
        self.show_error("Wallet removed:" + basename)

    def show_qrcode(self, data, title = _("QR code"), parent=None):
        if not data:
            return
        d = QRDialog(data, parent or self, title)
        d.exec_()

    @protected
    def show_private_key(self, wallet: Abstract_Wallet, address, password):
        if not address:
            return
        try:
            pk = wallet.export_private_key(address, password)
        except Exception as e:
            self.logger.exception("")
            self.show_message(str(e))
            return
        d = WindowModalDialog(self, _("Private key"))
        d.setMinimumSize(600, 150)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel('{}: {}'.format(_("Address"), address)))
        vbox.addWidget(QLabel(_("Private key") + ':'))
        keys_e = ShowQRTextEdit(text=pk)
        keys_e.addCopyButton(self.app)
        vbox.addWidget(keys_e)
        vbox.addWidget(QLabel(_("Redeem Script") + ':'))
        rds_e = ShowQRTextEdit(text=address.to_script_bytes().hex())
        rds_e.addCopyButton(self.app)
        vbox.addWidget(rds_e)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)
        d.exec_()

    msg_sign = _("Signing with an address actually means signing with the corresponding "
                "private key, and verifying with the corresponding public key. The "
                "address you have entered does not have a unique public key, so these "
                "operations cannot be performed.") + '\n\n' + \
               _('The operation is undefined. Not just in ElectrumSV, but in general.')

    @protected
    def do_sign(self, wallet: Abstract_Wallet, address: Address, message, signature, password):
        address  = address.text().strip()
        message = message.toPlainText().strip()
        try:
            addr = address_from_string(address)
        except:
            self.show_message(_('Invalid Bitcoin SV address.'))
            return
        if not isinstance(addr, P2PKH_Address):
            self.show_message(_('Cannot sign messages with this type of address.') + '\n\n' +
                              self.msg_sign)
        if wallet.is_watching_only():
            self.show_message(_('This is a watching-only wallet.'))
            return
        if not wallet.is_mine(addr):
            self.show_message(_('Address not in wallet.'))
            return

        def show_signed_message(sig):
            signature.setText(base64.b64encode(sig).decode('ascii'))
        self.run_in_thread(wallet.sign_message, addr, message, password,
            on_success=show_signed_message)

    def run_in_thread(self, func, *args, on_success=None):
        def _on_done(future):
            try:
                result = future.result()
            except Exception as exc:
                self.on_exception(exc)
            else:
                if on_success:
                    on_success(result)
        return self.app.run_in_thread(func, *args, on_done=_on_done)

    def do_verify(self, address, message, signature):
        try:
            address = address_from_string(address.text().strip()).to_string()
        except:
            self.show_message(_('Invalid Bitcoin SV address.'))
            return
        message = message.toPlainText().strip()
        try:
            # This can throw on invalid base64
            sig = base64.b64decode(signature.toPlainText())
            verified = PublicKey.verify_message_and_address(sig, message, address)
        except:
            verified = False

        if verified:
            self.show_message(_("Signature verified"))
        else:
            self.show_error(_("Wrong signature"))

    def sign_verify_message(self, wallet: Optional[Abstract_Wallet]=None,
            address: Optional[Address]=None) -> None:
        if wallet is None:
            wallet = self.parent_wallet.get_default_wallet()

        d = WindowModalDialog(self, _('Sign/verify Message'))
        d.setMinimumSize(610, 290)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        message_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        address_e = QLineEdit()
        address_e.setText(address.to_string() if address else '')
        layout.addWidget(QLabel(_('Address')), 2, 0)
        layout.addWidget(address_e, 2, 1)

        signature_e = QTextEdit()
        signature_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Signature')), 3, 0)
        layout.addWidget(signature_e, 3, 1)
        layout.setRowStretch(3,1)

        hbox = QHBoxLayout()

        b = QPushButton(_("Sign"))
        def do_sign(checked=False):
            # pylint: disable=no-value-for-parameter
            self.do_sign(wallet, address_e, message_e, signature_e)
        b.clicked.connect(do_sign)
        hbox.addWidget(b)

        b = QPushButton(_("Verify"))
        b.clicked.connect(partial(self.do_verify, address_e, message_e, signature_e))
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 4, 1)
        d.exec_()

    @protected
    def do_decrypt(self, child_wallet: Abstract_Wallet, message_e, pubkey_e, encrypted_e,
            password) -> None:
        if child_wallet.is_watching_only():
            self.show_message(_('This is a watching-only wallet.'))
            return
        cyphertext = encrypted_e.toPlainText()

        def show_decrypted_message(msg):
            message_e.setText(msg.decode())
        self.run_in_thread(child_wallet.decrypt_message, pubkey_e.text(), cyphertext, password,
                           on_success=show_decrypted_message)

    def do_encrypt(self, child_wallet: Abstract_Wallet, message_e, pubkey_e, encrypted_e) -> None:
        message = message_e.toPlainText()
        message = message.encode('utf-8')
        try:
            public_key = PublicKey.from_hex(pubkey_e.text())
        except Exception as e:
            self.logger.exception("")
            self.show_warning(_('Invalid Public key'))
        else:
            encrypted = public_key.encrypt_message_to_base64(message)
            encrypted_e.setText(encrypted)

    def encrypt_message(self, child_wallet: Abstract_Wallet, public_key_str='') -> None:
        d = WindowModalDialog(self, _('Encrypt/decrypt Message'))
        d.setMinimumSize(630, 490)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        message_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        pubkey_e = QLineEdit()
        layout.addWidget(QLabel(_('Public key')), 2, 0)
        layout.addWidget(pubkey_e, 2, 1)
        pubkey_e.setText(public_key_str)

        encrypted_e = QTextEdit()
        encrypted_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Encrypted')), 3, 0)
        layout.addWidget(encrypted_e, 3, 1)
        layout.setRowStretch(3,1)

        hbox = QHBoxLayout()
        b = QPushButton(_("Encrypt"))
        b.clicked.connect(lambda: self.do_encrypt(child_wallet, message_e, pubkey_e, encrypted_e))
        hbox.addWidget(b)

        b = QPushButton(_("Decrypt"))
        def do_decrypt(checked=False):
            # pylint: disable=no-value-for-parameter
            self.do_decrypt(child_wallet, message_e, pubkey_e, encrypted_e)
        b.clicked.connect(do_decrypt)
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)

        layout.addLayout(hbox, 4, 1)
        d.exec_()

    def password_dialog(self, msg=None, parent=None):
        from .password_dialog import PasswordDialog
        parent = parent or self
        d = PasswordDialog(parent, msg)
        return d.run()

    def tx_from_text(self, txt):
        if not txt:
            return None
        hex_str = tx_from_str(txt)
        tx = Transaction.from_hex(hex_str)
        for wallet in self.parent_wallet.get_child_wallets():
            my_coins = wallet.get_spendable_coins(None, self.config)
            my_outpoints = [coin.key() for coin in my_coins]
            for txin in tx.inputs:
                outpoint = (txin.prev_hash, txin.prev_idx)
                if outpoint in my_outpoints:
                    my_index = my_outpoints.index(outpoint)
                    txin.value = my_coins[my_index].value
        return tx

    def read_tx_from_qrcode(self):
        data = qrscanner.scan_barcode(self.config.get_video_device())
        if not data:
            return
        # if the user scanned a bitcoin URI
        if web.is_URI(data):
            self.pay_to_URI(data)
            return
        # else if the user scanned an offline signed tx
        data = bh2u(bitcoin.base_decode(data, length=None, base=43))
        return self.tx_from_text(data)

    def read_tx_from_file(self):
        fileName = self.getOpenFileName(_("Select your transaction file"), "*.txn")
        if not fileName:
            return
        with open(fileName, "r") as f:
            file_content = f.read()
        tx_file_dict = json.loads(file_content.strip())
        return self.tx_from_text(file_content)

    def do_process_from_qrcode(self):
        try:
            tx = self.read_tx_from_qrcode()
            if tx:
                self.show_transaction(tx)
        except Exception as reason:
            self.logger.exception(reason)
            self.show_critical(_("ElectrumSV was unable to read the transaction:") +
                               "\n" + str(reason))

    def do_process_from_text(self):
        text = text_dialog(self, _('Input raw transaction'), _("Transaction:"),
                           _("Load transaction"))
        try:
            tx = self.tx_from_text(text)
            if tx:
                self.show_transaction(tx)
        except Exception as reason:
            self.logger.exception(reason)
            self.show_critical(_("ElectrumSV was unable to read the transaction:") +
                               "\n" + str(reason))

    def do_process_from_file(self):
        try:
            tx = self.read_tx_from_file()
            if tx:
                self.show_transaction(tx)
        except Exception as reason:
            self.logger.exception(reason)
            self.show_critical(_("ElectrumSV was unable to read the transaction:") +
                               "\n" + str(reason))

    def do_process_from_txid(self):
        from electrumsv import transaction
        prompt = _('Enter the transaction ID:') + '\u2001' * 30   # em quad
        txid, ok = QInputDialog.getText(self, _('Lookup transaction'), prompt)
        if ok and txid:
            txid = str(txid).strip()
            try:
                hex_str = self.network.request_and_wait('blockchain.transaction.get', [txid])
            except Exception as exc:
                d = UntrustedMessageDialog(
                    self, _("Transaction Lookup Error"),
                    _("The server was unable to locate the transaction you specified."),
                    exc)
                d.exec()
                return
            tx = transaction.Transaction.from_hex(hex_str)
            self.show_transaction(tx)

    def do_import_labels(self, wallet_id: int) -> None:
        wallet = self.parent_wallet.get_wallet_for_account(wallet_id)

        labelsFile = self.getOpenFileName(_("Open labels file"), "*.json")
        if not labelsFile: return

        try:
            with open(labelsFile, 'r') as f:
                data = f.read()
            updates = json.loads(data).items()
            for key, value in updates:
                wallet.set_label(key, value)
            self.show_message(_("Your labels were imported from") + " '%s'" % str(labelsFile))
        except (IOError, os.error) as reason:
            self.show_critical(_("ElectrumSV was unable to import your labels.") + "\n" +
                               str(reason))

        if self.address_list is not None:
            self.address_list.update_labels(wallet, list(updates))

        self.history_view.update_tx_list()
        self.history_updated_signal.emit()

    def do_export_labels(self, wallet_id: int) -> None:
        wallet = self.parent_wallet.get_wallet_for_account(wallet_id)

        try:
            file_name = self.getSaveFileName(_("Select file to save your labels"),
                                            'electrumsv_labels.json', "*.json")
            if file_name:
                with open(file_name, 'w+') as f:
                    json.dump(wallet.labels, f, indent=4, sort_keys=True)
                self.show_message(_("Your labels were exported to") + " '%s'" % str(file_name))
        except (IOError, os.error) as reason:
            self.show_critical(_("ElectrumSV was unable to export your labels.") + "\n" +
                               str(reason))

    def export_history_dialog(self) -> None:
        d = WindowModalDialog(self, _('Export History'))
        d.setMinimumSize(400, 200)
        vbox = QVBoxLayout(d)
        defaultname = os.path.expanduser('~/electrumsv-history.csv')
        select_msg = _('Select file to export your wallet transactions to')
        hbox, filename_e, csv_button = filename_field(self.config, defaultname, select_msg)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        hbox = Buttons(CancelButton(d), OkButton(d, _('Export')))
        vbox.addLayout(hbox)
        self.update()
        if not d.exec_():
            return
        filename = filename_e.text()
        if not filename:
            return
        # TODO: ACCOUNTS: This should be a per-account option, as well as a generic option
        # for what is viewed in the history list (when moving to multi-accounts).
        wallet = self.parent_wallet.get_default_wallet()
        try:
            self.do_export_history(wallet, filename, csv_button.isChecked())
        except (IOError, os.error) as reason:
            export_error_label = _("ElectrumSV was unable to produce a transaction export.")
            self.show_critical(export_error_label + "\n" + str(reason),
                               title=_("Unable to export history"))
            return
        self.show_message(_("Your wallet history has been successfully exported."))

    def do_export_history(self, wallet: Abstract_Wallet, fileName: str, is_csv: bool) -> None:
        history = wallet.export_history()
        lines = []
        for item in history:
            if is_csv:
                lines.append([item['txid'], item.get('label', ''),
                              item['confirmations'], item['value'], item['date']])
            else:
                lines.append(item)

        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f, lineterminator='\n')
                transaction.writerow(["transaction_hash", "label", "confirmations",
                                      "value", "timestamp"])
                for line in lines:
                    transaction.writerow(line)
            else:
                f.write(json.dumps(lines, indent=4))

    def sweep_key_dialog(self, wallet_id: int) -> None:
        wallet = self.parent_wallet.get_wallet_for_account(wallet_id)
        addresses = wallet.get_unused_addresses()
        if not addresses:
            try:
                addresses = wallet.get_receiving_addresses()
            except AttributeError:
                addresses = wallet.get_addresses()
        if not addresses:
            self.show_warning(_('Wallet has no address to sweep to'))
            return

        d = WindowModalDialog(self, title=_('Sweep private keys'))
        d.setMinimumSize(600, 300)

        vbox = QVBoxLayout(d)
        vbox.addWidget(QLabel(_("Enter private keys:")))

        keys_e = ScanQRTextEdit(allow_multi=True)
        keys_e.setTabChangesFocus(True)
        vbox.addWidget(keys_e)

        h, addr_combo = address_combo(addresses)
        vbox.addLayout(h)

        vbox.addStretch(1)
        sweep_button = OkButton(d, _('Sweep'))
        vbox.addLayout(Buttons(CancelButton(d), sweep_button))

        def get_address_text():
            return addr_combo.currentText()

        def get_priv_keys():
            return keystore.get_private_keys(keys_e.toPlainText())

        def enable_sweep():
            sweep_button.setEnabled(bool(get_address_text()
                                         and get_priv_keys()))

        keys_e.textChanged.connect(enable_sweep)
        enable_sweep()
        if not d.exec_():
            return

        try:
            self.do_clear()
            coins, keypairs = sweep_preparations(get_priv_keys(), self.network.get_utxos)
            self.tx_external_keypairs = keypairs
            self.payto_e.setText(get_address_text())
            self.spend_coins(coins)
            self.spend_max()
        except Exception as e:
            self.show_message(str(e))
            return
        self.payto_e.setFrozen(True)
        self.amount_e.setFrozen(True)
        self.warn_if_watching_only(wallet)

    def _do_import(self, title, msg, func):
        text = text_dialog(self, title, msg + ' :', _('Import'),
                           allow_multi=True)
        if not text:
            return
        bad = []
        good = []
        for key in str(text).split():
            try:
                addr = func(key)
                good.append(addr)
            except Exception as e:
                bad.append(key)
                continue
        if good:
            self.show_message(_("The following addresses were added") + ':\n' +
                '\n'.join(address.to_string() for address in good))
        if bad:
            self.show_critical(_("The following inputs could not be imported") +
                               ':\n'+ '\n'.join(bad))
        self.history_view.update_tx_list()
        self.history_updated_signal.emit()

    #
    # Preferences dialog and its signals.
    #
    def on_num_zeros_changed(self):
        self.history_view.update_tx_list()
        self.history_updated_signal.emit()

    def on_fiat_ccy_changed(self):
        '''Called when the user changes fiat currency in preferences.'''
        b = app_state.fx and app_state.fx.is_enabled()
        self.fiat_send_e.setVisible(b)
        self.fiat_receive_e.setVisible(b)
        self.history_view.update_tx_headers()
        self.history_view.update_tx_list()
        self.history_updated_signal.emit()
        self.update_status()

    def on_base_unit_changed(self):
        edits = self.amount_e, self.receive_amount_e
        amounts = [edit.get_amount() for edit in edits]
        self.history_view.update_tx_list()
        self.history_updated_signal.emit()
        self.request_list.update()
        for edit, amount in zip(edits, amounts):
            edit.setAmount(amount)
        self.update_status()
        for tx_dialog in self.tx_dialogs:
            tx_dialog.update()

    # App event broadcast to all wallet windows.
    def on_fiat_history_changed(self):
        self.history_view.update_tx_headers()

    # App event broadcast to all wallet windows.
    def on_fiat_balance_changed(self):
        pass

    def preferences_dialog(self):
        dialog = PreferencesDialog(self.parent_wallet)
        dialog.exec_()

    def ok_to_close(self):
        # Close our tx dialogs; return False if any cannot be closed
        for tx_dialog in list(self.tx_dialogs):
            if not tx_dialog.close():
                return False
        return True

    def closeEvent(self, event):
        if self.ok_to_close():
            # It seems in some rare cases this closeEvent() is called twice
            if not self.cleaned_up:
                self.clean_up()
                self.cleaned_up = True
            event.accept()
        else:
            event.ignore()

    def clean_up(self):
        if self.network:
            self.network.unregister_callback(self.on_network)

        if self.tx_notify_timer:
            self.tx_notify_timer.stop()
            self.tx_notify_timer = None

        self.network_status_task.cancel()

        for task in self._monitor_wallet_network_status_tasks:
            task.cancel()

        # We catch these errors with the understanding that there is no recovery at
        # this point, given user has likely performed an action we cannot recover
        # cleanly from.  So we attempt to exit as cleanly as possible.
        try:
            self.config.set_key("is_maximized", self.isMaximized())
            self.config.set_key("console-history", self.console.history[-50:], True)
        except (OSError, PermissionError):
            self.logger.exception("unable to write to config (directory removed?)")

        if not self.isMaximized():
            try:
                g = self.geometry()
                self.parent_wallet.get_storage().put(
                    "winpos-qt", [g.left(),g.top(),g.width(),g.height()])
            except (OSError, PermissionError):
                self.logger.exception("unable to write to wallet storage (directory removed?)")

        # Should be no side-effects in this function relating to file access past this point.
        if self.qr_window:
            self.qr_window.close()

        if self.address_list:
            self.address_list.clean_up()

        for wallet in self.parent_wallet.get_child_wallets():
            for keystore in wallet.get_keystores():
                if isinstance(keystore, Hardware_KeyStore):
                    app_state.device_manager.unpair_xpub(keystore.xpub)
            self.logger.debug(f'closing wallet {self.parent_wallet.get_storage_path()}')

        self.app.timer.timeout.disconnect(self.timer_actions)
        self.app.close_window(self)

    def cpfp(self, wallet: Abstract_Wallet, parent_tx: Transaction, new_tx: Transaction) -> None:
        total_size = parent_tx.estimated_size() + new_tx.estimated_size()
        d = WindowModalDialog(self, _('Child Pays for Parent'))
        vbox = QVBoxLayout(d)
        msg = (
            "A CPFP is a transaction that sends an unconfirmed output back to "
            "yourself, with a high fee. The goal is to have miners confirm "
            "the parent transaction in order to get the fee attached to the "
            "child transaction.")
        vbox.addWidget(WWLabel(_(msg)))
        msg2 = ("The proposed fee is computed using your "
            "fee/kB settings, applied to the total size of both child and "
            "parent transactions. After you broadcast a CPFP transaction, "
            "it is normal to see a new unconfirmed transaction in your history.")
        vbox.addWidget(WWLabel(_(msg2)))
        grid = QGridLayout()
        grid.addWidget(QLabel(_('Total size') + ':'), 0, 0)
        grid.addWidget(QLabel('%d bytes'% total_size), 0, 1)
        max_fee = new_tx.output_value()
        grid.addWidget(QLabel(_('Input amount') + ':'), 1, 0)
        grid.addWidget(QLabel(self.format_amount(max_fee) + ' ' + app_state.base_unit()), 1, 1)
        output_amount = QLabel('')
        grid.addWidget(QLabel(_('Output amount') + ':'), 2, 0)
        grid.addWidget(output_amount, 2, 1)
        fee_e = BTCAmountEdit()
        def f(x):
            a = max_fee - fee_e.get_amount()
            output_amount.setText((self.format_amount(a) + ' ' + app_state.base_unit())
                                  if a else '')
        fee_e.textChanged.connect(f)
        fee = self.config.fee_per_kb() * total_size / 1000
        fee_e.setAmount(fee)
        grid.addWidget(QLabel(_('Fee' + ':')), 3, 0)
        grid.addWidget(fee_e, 3, 1)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec_():
            return
        fee = fee_e.get_amount()
        if fee > max_fee:
            self.show_error(_('Max fee exceeded'))
            return
        new_tx = wallet.cpfp(parent_tx, fee)
        if new_tx is None:
            self.show_error(_('CPFP no longer valid'))
            return
        self.show_transaction(new_tx)
