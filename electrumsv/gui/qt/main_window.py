# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
# Copyright (C) 2019-2020 The ElectrumSV Developers
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
import concurrent.futures
import csv
from decimal import Decimal
from functools import partial
import gzip
import itertools
import json
import os
import shutil
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Set, Tuple, TypeVar, Optional, Union
import weakref
import webbrowser

import aiorpcx
from bitcoinx import PublicKey

from PyQt5.QtCore import pyqtSignal, Qt, QSize, QTimer, QUrl, QRect
from PyQt5.QtGui import QKeySequence, QCursor, QDesktopServices
from PyQt5.QtWidgets import (
    QAction, QDialog, QFileDialog, QGridLayout, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMenu, QMenuBar, QMessageBox, QPushButton, QSizePolicy, QShortcut,
    QStackedWidget, QTextEdit, QToolBar, QVBoxLayout, QWidget
)
from PyQt5 import sip

import electrumsv
from electrumsv import bitcoin, commands, paymentrequest, qrscanner, util
from electrumsv.app_state import app_state
from electrumsv.bitcoin import (COIN, is_address_valid, address_from_string,
    script_template_to_string)
from electrumsv.constants import DATABASE_EXT, NetworkEventNames, TxFlags, WalletEventFlag, \
    WalletEventType, WalletSettings
from electrumsv.exceptions import UserCancelled
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.network import broadcast_failure_reason
from electrumsv.networks import Net
from electrumsv.storage import WalletStorage
from electrumsv.transaction import Transaction, TransactionContext, txdict_from_str
from electrumsv.types import WaitingUpdateCallback
from electrumsv.util import (
    bh2u, format_fee_satoshis, get_update_check_dates, get_identified_release_signers, profiler,
    get_wallet_name_from_path
)
from electrumsv.version import PACKAGE_VERSION
from electrumsv.wallet import AbstractAccount, UTXO, Wallet
from electrumsv.wallet_database.tables import InvoiceRow, KeyInstanceRow, WalletEventRow
import electrumsv.web as web

from .amountedit import AmountEdit, BTCAmountEdit
from .constants import CSS_WALLET_WINDOW_STYLE, UIBroadcastSource
from .contact_list import ContactList, edit_contact_dialog
from .qrcodewidget import QRDialog
from .qrtextedit import ShowQRTextEdit
from .receive_view import ReceiveView
from .send_view import SendView
from .table_widgets import TableTopButtonLayout
from .util import (Buttons, CancelButton, CloseButton, ColorScheme,
    create_new_wallet, ButtonsLineEdit, FormSectionWidget, MessageBoxMixin, OkButton, query_choice,
    protected, read_QIcon, show_in_file_explorer, text_dialog, top_level_window_recurse,
    UntrustedMessageDialog, WaitingDialog, WindowModalDialog, WWLabel)
from .wallet_api import WalletAPI


logger = logs.get_logger("mainwindow")


SendViewTypes = Union[SendView, QWidget]
ReceiveViewTypes = Union[ReceiveView, QWidget]
T = TypeVar('T')


class ElectrumWindow(QMainWindow, MessageBoxMixin):
    notify_transactions_signal = pyqtSignal()
    new_fx_quotes_signal = pyqtSignal()
    new_fx_history_signal = pyqtSignal()
    network_signal = pyqtSignal(str, object)
    history_updated_signal = pyqtSignal()
    network_status_signal = pyqtSignal()
    account_created_signal = pyqtSignal(int, object)
    account_change_signal = pyqtSignal(int, object)
    keys_updated_signal = pyqtSignal(object, object)
    keys_created_signal = pyqtSignal(object, object)
    transaction_state_signal = pyqtSignal(object, object, object, object)
    transaction_added_signal = pyqtSignal(object, object, object)
    transaction_deleted_signal = pyqtSignal(object, object)
    show_secured_data_signal = pyqtSignal(object)
    wallet_setting_changed_signal = pyqtSignal(str, object)
    present_notifications_tab_signal = pyqtSignal()

    _last_update_notification = 0.0

    def __init__(self, wallet: Wallet):
        QMainWindow.__init__(self)

        self.setStyleSheet(CSS_WALLET_WINDOW_STYLE)

        self._api = WalletAPI(self)

        self._logger = logger
        self.config = app_state.config

        self._wallet = wallet
        self._account: Optional[AbstractAccount] = wallet.get_default_account()
        self._account_id: Optional[int] = (self._account.get_id() if self._account is not None
            else None)

        self.network = app_state.daemon.network
        self.contacts = wallet.contacts
        self.app = app_state.app
        self.cleaned_up = False
        self.tx_notifications: List[Transaction] = []
        self.tx_notify_timer = None
        self.tx_dialogs = []
        self.tl_windows = []

        self.create_status_bar()
        self.need_update = threading.Event()

        self.fee_unit = self.config.get('fee_unit', 0)

        self._accounts_view = self._create_accounts_view()
        self._send_views: Dict[int, SendViewTypes] = {}
        self._send_view: Optional[SendViewTypes] = None
        self._receive_views: Dict[int, ReceiveViewTypes] = {}
        self._receive_view: Optional[ReceiveViewTypes] = None

        self._tab_widget = tabs = self._accounts_view.get_tab_widget()

        self._create_tabs()

        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setCentralWidget(self._accounts_view)

        self._tab_widget.currentChanged.connect(self._on_tab_changed)

        if self.config.get("is_maximized"):
            self.showMaximized()

        self.init_menubar()
        self.init_toolbar()

        QShortcut(QKeySequence("Ctrl+W"), self, self.close)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Ctrl+R"), self, self.refresh_wallet_display)
        QShortcut(QKeySequence("Ctrl+PgUp"), self,
                  lambda: tabs.setCurrentIndex((tabs.currentIndex() - 1)%tabs.count()))
        QShortcut(QKeySequence("Ctrl+PgDown"), self,
                  lambda: tabs.setCurrentIndex((tabs.currentIndex() + 1)%tabs.count()))

        for i in range(tabs.count()):
            QShortcut(QKeySequence("Alt+" + str(i + 1)), self,
                      lambda i=i: tabs.setCurrentIndex(i))

        self.network_status_signal.connect(self._update_network_status)
        self.notify_transactions_signal.connect(self._notify_transactions)
        self.show_secured_data_signal.connect(self._on_show_secured_data)
        self.present_notifications_tab_signal.connect(self._present_notifications_tab)

        # Link wallet synchronisation to throttled UI updates.
        self._wallet_sync_event = app_state.async_.event()
        self._monitor_wallet_network_status_task = app_state.async_.spawn(
            self._monitor_wallet_network_status)
        self._network_status_task = app_state.async_.spawn(self._maintain_network_status)

        # network callbacks
        if self.network:
            self.network_signal.connect(self.on_network_qt)
            interests = ['updated', 'status', 'banner', 'verified']
            # To avoid leaking references to "self" that prevent the
            # window from being GC-ed when closed, callbacks should be
            # methods of this class only, and specifically not be
            # partials, lambdas or methods of subobjects.  Hence...
            self.network.register_callback(self.on_network, interests)
            # set initial message
            if self.network.main_server:
                self.console.showMessage(self.network.main_server.state.banner)
            self.network.register_callback(self._on_exchange_rate_quotes,
                [ NetworkEventNames.EXCHANGE_RATE_QUOTES ])
            self.network.register_callback(self._on_historical_exchange_rates,
                [ NetworkEventNames.HISTORICAL_EXCHANGE_RATES ])

            self.new_fx_quotes_signal.connect(self._on_ui_exchange_rate_quotes)
            self.new_fx_history_signal.connect(self._on_ui_historical_exchange_rates)

        self._wallet.register_callback(self._on_account_created, ['on_account_created'])
        self._wallet.register_callback(self._on_wallet_setting_changed, ['on_setting_changed'])
        self._wallet.register_callback(self._on_keys_updated, ['on_keys_updated'])
        self._wallet.register_callback(self._on_keys_created, ['on_keys_created'])
        self._wallet.register_callback(self._on_transaction_state_change,
            ['transaction_state_change'])
        self._wallet.register_callback(self._on_transaction_added, ['transaction_added'])
        self._wallet.register_callback(self._on_transaction_deleted, ['transaction_deleted'])

        self.load_wallet()
        self._on_ready()

        self.app.timer.timeout.connect(self.timer_actions)

    def reference(self) -> 'ElectrumWindow':
        return self

    def __del__(self) -> None:
        logger.debug(f"Wallet window garbage collected {self!r}")

    def _on_tab_changed(self, to_tab_index: int) -> None:
        # Some tabs may want to be refreshed to show current state when selected.
        current_tab = self._tab_widget.currentWidget()
        if current_tab is self.coinsplitting_tab:
            self.coinsplitting_tab.update_layout()

    def _on_ready(self) -> None:
        self._accounts_view.on_wallet_loaded()

        use_multiple_accounts = self._wallet.get_boolean_setting(WalletSettings.MULTIPLE_ACCOUNTS)
        self._update_add_account_button(use_multiple_accounts)
        self._present_notifications_tab()

        # This is what should normally happen when the window is ready, and multiple-accounts
        # are allowed.
        # self._add_account_action.setEnabled(True)

    def _create_tabs(self) -> None:
        tabs = self._tab_widget

        self.send_tab = self._create_send_tab()
        self.receive_tab = self._create_receive_tab()
        self.notifications_tab = self.create_notifications_tab()
        self.keys_tab = self.create_keys_tab()
        self.utxo_tab = self.create_utxo_tab()
        self.console_tab = self.create_console_tab()
        self.contacts_tab = self.create_contacts_tab()
        self.coinsplitting_tab = self.create_coinsplitting_tab()

        history_view = self.create_history_tab()

        tabs.addTab(history_view, read_QIcon("tab_history.png"), _('History'))

        transaction_tab = self.create_transaction_tab()
        self.transaction_view.changed_signal.connect(history_view.on_transaction_view_changed)

        tabs.addTab(transaction_tab, read_QIcon("icons8-transaction-list-96.png"),
            _('Transactions'))
        tabs.addTab(self.send_tab, read_QIcon("tab_send.png"), _('Send'))
        tabs.addTab(self.receive_tab, read_QIcon("tab_receive.png"), _('Receive'))

        tabs.setTabToolTip(0, _("Published transactions"))
        tabs.setTabToolTip(1, _("Unpublished transactions"))
        tabs.setTabToolTip(2, _("Create a transaction"))
        tabs.setTabToolTip(3, _("Receive a transaction"))

        self._add_optional_tab(tabs, self.notifications_tab,
            read_QIcon("icons8-event-64-cute-clipart.png"), _("Notifications"), "notifications",
            True)
        self._add_optional_tab(tabs, self.keys_tab, read_QIcon("tab_keys.png"),
            _("&Keys"), "keys")
        self._add_optional_tab(tabs, self.utxo_tab, read_QIcon("tab_coins.png"),
            _("Co&ins"), "utxo")
        # self._add_optional_tab(tabs, self.contacts_tab, read_QIcon("tab_contacts.png"),
        #     _("Con&tacts"), "contacts")
        self._add_optional_tab(tabs, self.console_tab, read_QIcon("tab_console.png"),
            _("Con&sole"), "console")
        self._add_optional_tab(tabs, self.coinsplitting_tab, read_QIcon("tab_coins.png"),
            _("Coin Splitting"), "coinsplitter", True)

    def _add_optional_tab(self, tabs, tab, icon, description: str, name: str,
            default: bool=False) -> None:
        tab.tab_icon = icon
        tab.tab_description = description
        tab.tab_pos = len(tabs)
        tab.tab_name = name
        if self.config.get('show_{}_tab'.format(name), default):
            tabs.addTab(tab, icon, description.replace("&", ""))

    def _on_wallet_setting_changed(self, event_name: str, setting_name: str, setting_value: Any) \
            -> None:
        if setting_name == WalletSettings.MULTIPLE_ACCOUNTS:
            self._update_add_account_button(setting_value)
        self.wallet_setting_changed_signal.emit(setting_name, setting_value)

    def _on_transaction_state_change(self, event_name: str, account_id: int, tx_hash: bytes,
            old_state: TxFlags, new_state: TxFlags) -> None:
        self.transaction_state_signal.emit(account_id, tx_hash, old_state, new_state)

    def _on_transaction_added(self, event_name: str, tx_hash: bytes, tx: Transaction,
            account_ids: Set[int], is_external: bool) -> None:
        # Account ids is the accounts that have changed the balance.
        self._logger.debug("_on_transaction_added %s %s %s", self._wallet.get_account_ids(),
            account_ids, is_external)
        if self._wallet.get_account_ids() & account_ids and is_external:
            # Always notify of incoming transactions regardless of the active account.
            self.tx_notifications.append(tx)
            self.notify_transactions_signal.emit()

        # Only update the display for the new transaction if it is in the current account?
        if self._account_id in account_ids:
            self.need_update.set()

        self.transaction_added_signal.emit(tx_hash, tx, account_ids)

    def _on_transaction_deleted(self, event_name: str, account_id: int, tx_hash: bytes) -> None:
        self.transaction_deleted_signal.emit(account_id, tx_hash)

    def _on_account_created(self, event_name: str, new_account_id: int) -> None:
        account = self._wallet.get_account(new_account_id)

        # NOTE(rt12) single-account At this time we disallow more than one account.
        setting_value = self._wallet.get_boolean_setting(WalletSettings.MULTIPLE_ACCOUNTS)
        self._update_add_account_button(setting_value)

        self._wallet.create_gui_handler(self, account)

        self.account_created_signal.emit(new_account_id, account)
        # This is an `emit` that happens in the UI thread.
        wallet_event_row = self._wallet.remove_add_account_notification()
        if wallet_event_row is not None:
            self._api.dismiss_notification(self._wallet.get_storage_path(), wallet_event_row)
        self.set_active_account(account)
        self.present_notifications_tab()

    def set_active_account(self, account: AbstractAccount) -> None:
        account_id = account.get_id()
        self._account_id = account_id
        self._account = account

        # Update the console tab.
        self.console.updateNamespace({ 'account': account })
        self._reset_menus(account_id)
        self._reset_send_tab()
        # Reset these tabs:
        # - The history tab.
        # - The local transactions tab.
        # - The UTXO tab.
        # - The coin-splitting tab.
        # - The keys tab.
        self.account_change_signal.emit(account_id, account)
        # - The receive tab.
        self._reset_receive_tab()
        self._receive_view.update_contents()

        # Update the status bar, and maybe the tab contents. If we are mid-synchronisation the
        # tab contents will be skipped, but that's okay as the synchronisation completion takes
        # care of triggering an update.
        self.need_update.set()

    def _update_add_account_button(self, setting_enabled: bool) -> None:
        is_disabled = len(self._wallet.get_accounts()) > 0 and not setting_enabled
        self._add_account_action.setDisabled(is_disabled)
        if is_disabled:
            self._add_account_action.setToolTip("Accounts are limited to one at this time.")
        else:
            self._add_account_action.setToolTip("Experimental multiple account creation enabled.")

    def _on_keys_created(self, event_name: str, account_id: int,
            keys: Iterable[KeyInstanceRow]) -> None:
        self.keys_created_signal.emit(account_id, keys)

    def _on_keys_updated(self, event_name: str, account_id: int,
            keys: Iterable[KeyInstanceRow]) -> None:
        # logger.debug("_on_keys_updated %r", keys)
        self.keys_updated_signal.emit(account_id, keys)

    def _on_show_secured_data(self, account_id: int) -> None:
        self._accounts_view._view_secured_data(main_window=self, account_id=account_id)

    def _on_historical_exchange_rates(self, _event_name: str) -> None:
        # Notify the UI thread.
        self.new_fx_history_signal.emit()

    def _on_ui_historical_exchange_rates(self) -> None:
        self.history_view.update_tx_headers()
        self.update_history_view()

    def _on_exchange_rate_quotes(self, _event_name: str) -> None:
        # Notify the UI thread.
        self.new_fx_quotes_signal.emit()

    def _on_ui_exchange_rate_quotes(self) -> None:
        self.update_status_bar()

        # Refresh edits with the new rate
        for send_view in self._send_views.values():
            if isinstance(send_view, SendView):
                send_view.update_for_fx_quotes()

        for receive_view in self._receive_views.values():
            if isinstance(receive_view, ReceiveView):
                receive_view.update_for_fx_quotes()

        # History tab needs updating if it used spot
        if app_state.fx.history_used_spot:
            self.update_history_view()

    def present_notifications_tab(self) -> None:
        self.present_notifications_tab_signal.emit()

    def _present_notifications_tab(self) -> None:
        self.toggle_tab(self.notifications_tab, True, to_front=True)

    def toggle_tab(self, tab: QWidget, desired_state: Optional[bool]=None,
            to_front: bool=False) -> None:
        show = self._tab_widget.indexOf(tab) == -1
        if desired_state is None or desired_state == show:
            self.config.set_key('show_{}_tab'.format(tab.tab_name), show)
            item_text = (_("Hide") if show else _("Show")) + " " + tab.tab_description
            tab.menu_action.setText(item_text)
            if show:
                # Find out where to place the tab
                index = len(self._tab_widget)
                for i in range(len(self._tab_widget)):
                    try:
                        if tab.tab_pos < self._tab_widget.widget(i).tab_pos:
                            index = i
                            break
                    except AttributeError:
                        pass
                self._tab_widget.insertTab(index, tab, tab.tab_icon,
                    tab.tab_description.replace("&", ""))
            else:
                i = self._tab_widget.indexOf(tab)
                self._tab_widget.removeTab(i)

        if self._tab_widget.indexOf(tab) != -1 and to_front:
            self._tab_widget.setCurrentWidget(tab)

    def push_top_level_window(self, window) -> None:
        '''Used for e.g. tx dialog box to ensure new dialogs are appropriately
        parented.  This used to be done by explicitly providing the parent
        window, but that isn't something hardware wallet prompts know.'''
        self.tl_windows.append(window)

    def pop_top_level_window(self, window) -> None:
        self.tl_windows.remove(window)

    def top_level_window(self):
        '''Do the right thing in the presence of tx dialog windows'''
        override = self.tl_windows[-1] if self.tl_windows else self
        return top_level_window_recurse(override)

    def is_hidden(self) -> bool:
        return self.isMinimized() or self.isHidden()

    def show_or_hide(self) -> None:
        if self.is_hidden():
            self.bring_to_top()
        else:
            self.hide()

    def bring_to_top(self) -> None:
        self.show()
        self.raise_()

    def on_exception(self, exception: Exception) -> None:
        if not isinstance(exception, UserCancelled):
            self._logger.exception("")
            self.show_error(str(exception))

    def on_error(self, exc_info) -> None:
        self.on_exception(exc_info[1])

    def on_network(self, event, *args) -> None:
        if event in ('updated', 'verified'):
            self.need_update.set()
            return

        if event in ['status', 'banner']:
            # Handle in GUI thread
            self.network_signal.emit(event, args)
        else:
            self._logger.debug("unexpected network message event='%s' args='%s'", event, args)

    def on_network_qt(self, event, args=None):
        # Handle a network message in the GUI thread
        if event == 'status':
            self.update_status_bar()
        elif event == 'banner':
            self.console.showMessage(self.network.main_server.state.banner)
        # NOTE(rt12): Disabled due to fact we can't update individual rows and their order due
        # to the balance column being dependent on order. Redirected to the `need_update` flow.
        # elif event == 'verified':
        #     self.history_view.update_tx_item(*args[1:])
        else:
            self._logger.debug("unexpected network_qt signal event='%s' args='%s'", event, args)

    def load_wallet(self) -> None:
        wallet = self._wallet
        self._logger = logs.get_logger(f"mainwindow[{wallet.name()}]")
        self.init_geometry()
        self.update_recently_visited(wallet.get_storage_path())
        self.update_console()
        self._tab_widget.show()
        if self.config.get('hide_gui') and self.app.tray.isVisible():
            self.hide()
        else:
            self.show()

        self._update_window_title()

        for account in wallet.get_accounts():
            self._wallet.create_gui_handler(self, account)

        # Once GUI has been initialized check if we want to announce something since the
        # callback has been called before the GUI was initialized
        self._notify_transactions()

    def init_geometry(self):
        winpos = self._wallet.get_storage().get("winpos-qt")
        if winpos is not None:
            try:
                screen = self.app.desktop().screenGeometry()
                assert screen.contains(QRect(*winpos))
                self.setGeometry(*winpos)
            except Exception:
                self._logger.exception("using default geometry")
                winpos = None
        if winpos is None:
            self.setGeometry(100, 100, 840, 400)

        splitter_sizes = self._wallet.get_storage().get("split-sizes-qt")
        self._accounts_view.init_geometry(splitter_sizes)

    def _update_window_title(self):
        title = f'ElectrumSV {PACKAGE_VERSION} ({Net.NAME}) - {self._wallet.name()}'
        self.setWindowTitle(title)

        # TODO: ACCOUNTS: This requires more nuance, in terms of showing which are watching only
        # when we get to the multi-account stage.
        for account in self._wallet.get_accounts():
            if self.warn_if_watching_only(account):
                break

    def warn_if_watching_only(self, account: AbstractAccount) -> bool:
        if account.is_watching_only():
            msg = ' '.join([
                _("This account is watching-only."),
                _("This means you will not be able to spend Bitcoin SV with it."),
                _("Make sure you own the seed phrase or the private keys, "
                  "before you request Bitcoin SV to be sent to this account.")
            ])
            self.show_warning(msg, title=_('Information'))
            return True
        return False

    def _backup_wallet(self):
        # TODO(rt12): https://stackoverflow.com/questions/23395888/
        # This does not work as is. The link might provide a way of doing it better.
        path = self._wallet.get_storage_path()
        wallet_folder = os.path.dirname(path)
        filename, __ = QFileDialog.getSaveFileName(
            self, _('Enter a filename for the copy of your wallet'), wallet_folder)
        if not filename:
            return

        # QFileDialog.getSaveFileName uses forward slashes for "easier pathing".. correct this.
        filename = os.path.normpath(filename)

        new_path = os.path.join(wallet_folder, filename)
        new_path = WalletStorage.canonical_path(new_path)
        if new_path.casefold() != path.casefold():
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
        filename = os.path.normpath(filename)
        if filename in recent:
            recent.remove(filename)
        recent.insert(0, filename)
        recent = [path for path in recent if os.path.exists(path)][:10]
        self.config.set_key('recently_open', recent)
        self.recently_visited_menu.clear()

        wallet_names = [get_wallet_name_from_path(path) for path in recent]
        counts = Counter(wallet_names)
        pairs = ((wallet_name if counts[wallet_name] == 1 else path, path)
            for wallet_name, path in zip(wallet_names, recent))
        for menu_text, path in pairs:
            self.recently_visited_menu.addAction(menu_text, partial(self.app.new_window, path))
        self.recently_visited_menu.setEnabled(bool(pairs))

    def _open_wallet(self) -> None:
        try:
            wallet_folder = self.config.get_preferred_wallet_dirpath()
        except FileNotFoundError as e:
            self.show_error(str(e))
            return

        if not os.path.exists(wallet_folder):
            wallet_folder = None
        filename, __ = QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder)
        if not filename:
            return
        # QFileDialog.getOpenFileName uses forward slashes for "easier pathing".. correct this.
        filename = os.path.normpath(filename)
        self.app.new_window(filename)

    def _new_wallet(self) -> None:
        try:
            wallet_folder = self.config.get_preferred_wallet_dirpath()
        except FileNotFoundError as e:
            self.show_error(str(e))
            return

        create_filepath = create_new_wallet(self, wallet_folder)
        if create_filepath is not None:
            self.app.start_new_window(create_filepath + DATABASE_EXT, None)

    def init_menubar(self) -> None:
        menubar = QMenuBar()
        file_menu = menubar.addMenu(_("&File"))
        self.recently_visited_menu = file_menu.addMenu(_("&Recently open"))
        file_menu.addAction(_("&Open"), self._open_wallet).setShortcut(QKeySequence.Open)
        file_menu.addAction(_("&New"), self._new_wallet).setShortcut(QKeySequence.New)
        # TODO(rt12): See the `_backup_wallet` function.
        save_copy_action = file_menu.addAction(_("&Save Copy"), self._backup_wallet)
        save_copy_action.setShortcut(QKeySequence.SaveAs)
        save_copy_action.setEnabled(False)
        file_menu.addSeparator()
        file_menu.addAction(_("&Quit"), self.close)

        wallet_menu = menubar.addMenu(_("&Wallet"))
        wallet_menu.addAction(_("&Information"), self._show_wallet_information)
        wallet_menu.addSeparator()

        self.password_menu = wallet_menu.addAction(_("&Password"), self.change_password_dialog)
        wallet_menu.addSeparator()

        # NOTE(rt12): Contacts menu is disabled as tab is disabled.
        if False:
            contacts_menu = wallet_menu.addMenu(_("Contacts"))
            contacts_menu.addAction(_("&New"), partial(edit_contact_dialog, self._api))

        wallet_menu.addSeparator()
        wallet_menu.addAction(_("Find"), self._toggle_search).setShortcut(QKeySequence("Ctrl+F"))

        weakself = weakref.proxy(self)
        self._account_menu = menubar.addMenu(_("&Account"))
        if self._account_id is not None:
            self._accounts_view.add_menu_items(self._account_menu, self._account, weakself)

        # Make sure the lambda reference does not prevent garbage collection.
        def add_toggle_action(view_menu, tab) -> None:
            is_shown = self._tab_widget.indexOf(tab) > -1
            item_name = (_("Hide") if is_shown else _("Show")) + " " + tab.tab_description
            tab.menu_action = view_menu.addAction(item_name, lambda: weakself.toggle_tab(tab))

        view_menu = menubar.addMenu(_("&View"))
        add_toggle_action(view_menu, self.keys_tab)
        add_toggle_action(view_menu, self.utxo_tab)
        # add_toggle_action(view_menu, self.contacts_tab)
        add_toggle_action(view_menu, self.coinsplitting_tab)
        add_toggle_action(view_menu, self.console_tab)
        add_toggle_action(view_menu, self.notifications_tab)

        tools_menu = menubar.addMenu(_("&Tools"))

        tools_menu.addAction(_("Preferences"), self.preferences_dialog)
        tools_menu.addAction(_("&Network"), self._show_network_dialog)
        tools_menu.addSeparator()
        tools_menu.addAction(_("&Sign/verify message"), self.sign_verify_message)
        tools_menu.addAction(_("&Encrypt/decrypt message"), self.encrypt_message)
        tools_menu.addSeparator()

        self._paytomany_menu = tools_menu.addAction(_("&Pay to many"), self.paytomany)

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
        help_menu.addAction(_("Documentation"), self._open_documentation).setShortcut(
            QKeySequence.HelpContents)
        help_menu.addAction(_("&Report Bug"), self.show_report_bug)
        help_menu.addSeparator()
        help_menu.addAction(_("&Donate to server"), self.donate_to_server)

        self.setMenuBar(menubar)

        # The menus that rely on accounts should default to behaving as if there is no account.
        # They will get enabled if a first account is created, or the account list is loaded and
        # it has a default account to enable for initial display.
        self._reset_menus()

    def _reset_menus(self, account_id: Optional[int]=None) -> None:
        self._paytomany_menu.setEnabled(account_id is not None)

        if account_id is not None:
            weakself = weakref.proxy(self)
            self._accounts_view.add_menu_items(self._account_menu, self._account, weakself)

    def _show_network_dialog(self) -> None:
        self.app.show_network_dialog(self)

    def _open_documentation(self) -> None:
        webbrowser.open("https://electrumsv.readthedocs.io/")

    def init_toolbar(self):
        self.toolbar = toolbar = QToolBar(self)
        icon_size = int(self.app.dpi / 5.8)
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(icon_size, icon_size))
        toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)

        self._add_account_action = QAction(read_QIcon("icons8-add-folder-80.png"),
            _("Add Account"), self)
        self._add_account_action.triggered.connect(self.add_account)
        toolbar.addAction(self._add_account_action)
        self._add_account_action.setEnabled(
            self._wallet.get_boolean_setting(WalletSettings.MULTIPLE_ACCOUNTS))

        # make_payment_action = QAction(read_QIcon("icons8-initiate-money-transfer-80.png"),
        #     _("Make Payment"), self)
        # make_payment_action.triggered.connect(self.new_payment)
        # toolbar.addAction(make_payment_action)

        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        spacer.setVisible(True)
        self.spacer_action = toolbar.addWidget(spacer)

        log_action = QAction(read_QIcon("icons8-moleskine-80.png"), _("Log Viewer"), self)
        log_action.triggered.connect(self.app.show_log_viewer)
        toolbar.addAction(log_action)

        network_action = QAction(read_QIcon("network.png"), _("Network"), self)
        network_action.triggered.connect(self._show_network_dialog)
        toolbar.addAction(network_action)

        preferences_action = QAction(read_QIcon("preferences.png"), _("Preferences"), self)
        preferences_action.triggered.connect(self.preferences_dialog)
        toolbar.addAction(preferences_action)

        self._update_check_state = "default"
        update_action = QAction(
            read_QIcon("icons8-available-updates-80-blue"), _("Update Check"), self)
        update_action.triggered.connect(self._update_show_menu)
        self._update_action = update_action
        toolbar.addAction(update_action)
        self._update_check_toolbar_update()

        toolbar.insertSeparator(update_action)

        self.addToolBar(toolbar)
        self.setUnifiedTitleAndToolBarOnMac(True)

    def add_toolbar_action(self, action: QAction) -> None:
        self.toolbar.insertAction(self.spacer_action, action)

    def _update_show_menu(self, checked: bool = False) -> None:
        self._update_menu.exec(QCursor.pos())

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

        def _on_view_pending_update(checked: bool=False):
            QDesktopServices.openUrl(QUrl("https://electrumsv.io/download.html"))

        menu = QMenu()
        self._update_menu = menu
        self._update_check_action = menu.addAction(
            _("Check for Updates"), self._on_check_for_updates)

        have_update = False
        if update_check_state == "default":
            icon_path = "icons8-available-updates-80-blue"
            icon_text = _("Updates")
            tooltip = _("Check for Updates")
            menu.setDefaultAction(self._update_check_action)
        elif update_check_state == "update-present-immediate":
            have_update = True
            icon_path = "icons8-available-updates-80-yellow"
            icon_text = f"{stable_version}"
            tooltip = _("A newer version of ElectrumSV is available, and "+
                "was released on {0:%c}").format(release_date)
            self._update_view_pending_action = menu.addAction(
                _("View Pending Update"), _on_view_pending_update)
            menu.setDefaultAction(self._update_view_pending_action)
        elif update_check_state == "update-present-prolonged":
            have_update = True
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

        if not have_update:
            return

        require_update_event = False
        if self._last_update_notification > time.time() - 60.0:
            # Paranoid to avoid event spamming.
            require_update_event = False
        else:
            for wallet_event in self._wallet.read_wallet_events():
                if wallet_event.event_type == WalletEventType.WALLET_UPDATE:
                    if wallet_event.event_flags & WalletEventFlag.UNREAD == WalletEventFlag.UNREAD:
                        break
            else:
                # There is either no update notification or it has been marked as read. Add a new
                # one, we strongly advise users to update as older versions are unsupported.
                require_update_event = True

        if require_update_event:
            self._last_update_notification = time.time()

            wallet_events = self._wallet.create_wallet_events([
                WalletEventRow(0, WalletEventType.WALLET_UPDATE, None,
                    WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, int(time.time()))
            ])
            self._api.post_notification(self._wallet.get_storage_path(), wallet_events[0])

    def _on_check_for_updates(self, checked: bool=False) -> None:
        self.show_update_check()

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

    def add_account(self) -> None:
        from . import account_wizard
        # from importlib import reload
        # reload(account_wizard)
        wizard_window = account_wizard.AccountWizard(self)
        result = wizard_window.run()
        if result != QDialog.Accepted:
            # Clean up?
            return

    def new_payment(self) -> None:
        from . import payment
        # from importlib import reload
        # reload(payment)
        self.w = payment.PaymentWindow(self._api, parent=self)
        self.w.show()

    def donate_to_server(self):
        server = self.network.main_server
        addr = server.state.donation_address
        if is_address_valid(addr):
            self.pay_to_URI(web.create_URI(addr, 0, _('Donation for {}').format(server.host)))
        else:
            self.show_error(_('The server {} has not provided a valid donation address')
                            .format(server))

    def show_about(self):
        QMessageBox.about(self, "ElectrumSV",
            _("Version")+" %s" % PACKAGE_VERSION + "\n\n" +
            _("ElectrumSV's focus is speed, with low resource usage and simplifying "
              "Bitcoin SV. Startup times are instant because it operates in "
              "conjunction with high-performance servers that handle the most complicated "
              "parts of the Bitcoin SV system."  + "\n\n" +
              _("Uses icons from the Icons8 icon pack (icons8.com).")))

    def show_update_check(self):
        if self.network is None:
            self.show_message(_("Unable to check for updates in offline mode."))
            return

        from . import update_check
        update_check.UpdateCheckDialog(self)

    def show_report_bug(self) -> None:
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

    def _notify_tx_cb(self) -> None:
        n_ok = 0
        if self.network and self.network.is_connected():
            num_txns = len(self.tx_notifications)
            if num_txns:
                # Combine the transactions
                total_amount = 0
                total_delta = 0
                for tx in self.tx_notifications:
                    if tx:
                        for result in self._wallet.get_transaction_deltas(tx.hash()):
                            total_amount += result.total
                            total_delta += abs(result.total)
                        n_ok += 1
                if n_ok and total_delta:
                    self._logger.debug("Notifying GUI %d tx", n_ok)
                    if n_ok > 1:
                        self.notify(_("{} new transactions received: Total amount received "
                                      "in the new transactions {}")
                                    .format(n_ok, app_state.format_amount_and_units(total_amount)))
                    else:
                        self.notify(_("New transaction received: {}").format(
                            app_state.format_amount_and_units(total_amount)))
        self.tx_notifications = []
        self.last_notify_tx_time = time.time() if n_ok else self.last_notify_tx_time
        if self.tx_notify_timer:
            self.tx_notify_timer.stop()
            self.tx_notify_timer = None

    def _notify_transactions(self) -> None:
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
            self.tx_notify_timer.timeout.connect(self._notify_tx_cb)
            when = self.notify_tx_rate - elapsed
            self._logger.debug("Notify spam control: will notify GUI of %d new tx's in %f seconds",
                              len(self.tx_notifications), when)
            self.tx_notify_timer.start(when * 1e3) # time in ms
        else:
            # it's been a while since we got a tx notify -- so do it immediately (no timer
            # necessary)
            self._notify_tx_cb()

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

    def getSaveFileName(self, title, filename, filter: str = "", parent: Optional[QWidget]=None):
        parent = self if parent is None else parent
        directory = self.config.get('io_dir', os.path.expanduser('~'))
        path = os.path.join( directory, filename )
        fileName, _selectedFilter = QFileDialog.getSaveFileName(parent, title, path, filter)
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def timer_actions(self):
        # Note this runs in the GUI thread
        if self.need_update.is_set():
            self.need_update.clear()
            self.refresh_wallet_display()

        if self.is_send_view_active():
            self._send_view.on_timer_action()

    def format_fee_rate(self, fee_rate: int) -> str:
        return format_fee_satoshis(fee_rate/1000, app_state.num_zeros) + ' sat/B'

    def connect_fields(self, btc_e: BTCAmountEdit, fiat_e: AmountEdit) -> None:
        def edit_changed(edit) -> None:
            if edit.in_event:
                return
            edit.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())
            fiat_e.is_last_edited = edit == fiat_e
            amount = edit.get_amount()
            rate = app_state.fx.exchange_rate() if app_state.fx else None
            if rate is None or amount is None:
                if edit is fiat_e:
                    btc_e.setText("")
                else:
                    fiat_e.setText("")
            else:
                if edit is fiat_e:
                    btc_e.in_event = True
                    btc_e.setAmount(int(amount / Decimal(rate) * COIN))
                    btc_e.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
                    btc_e.in_event = False
                else:
                    fiat_e.in_event = True
                    fiat_e.setText(
                        app_state.fx.ccy_amount_str(amount * Decimal(rate) / COIN, False))
                    fiat_e.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
                    fiat_e.in_event = False

        fiat_e.is_last_edited = False
        fiat_e.in_event = False
        fiat_e.textChanged.connect(partial(edit_changed, fiat_e))
        btc_e.in_event = False
        btc_e.textChanged.connect(partial(edit_changed, btc_e))

    async def _monitor_wallet_network_status(self) -> None:
        while True:
            await self._wallet.progress_event.wait()
            self._wallet.progress_event.clear()
            self._wallet_sync_event.set()

    async def _maintain_network_status(self) -> None:
        while True:
            await self._wallet_sync_event.wait()
            self.network_status_signal.emit()
            # Throttle updates
            await asyncio.sleep(1.0)

    @profiler
    def refresh_wallet_display(self) -> None:
        self.update_status_bar()
        if self._wallet.is_synchronized() or not self.network or not self.network.is_connected():
            self.update_tabs()

    def update_status_bar(self) -> None:
        "Update the entire status bar."
        fiat_status = None
        # Display if offline. Display if online. Do not display if synchronizing.
        if self.network and self.network.is_connected():
            # append fiat balance and price
            if app_state.fx.is_enabled():
                balance = 0
                for account in self._wallet.get_accounts():
                    c, u, x = account.get_balance()
                    balance += c
                fiat_status = app_state.fx.get_fiat_status(
                    balance, app_state.base_unit(), app_state.decimal_point)
        self.set_status_bar_balance(True)
        self._status_bar.set_fiat_status(fiat_status)
        self._update_network_status()

    def _update_network_status(self) -> None:
        "Update the network status portion of the status bar."
        text = _("Offline")
        if self.network:
            request_count, response_count = self._wallet.get_request_response_counts()
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

    def update_tabs(self, *args) -> None:
        if self.is_receive_view_active():
            self._receive_view.update_widgets()
        if self.is_send_view_active():
            self._send_view.update_widgets()
        self.utxo_list.update()
        self.contact_list.update()
        self.update_history_view()

    def _create_accounts_view(self):
        from .accounts_view import AccountsView
        return AccountsView(self, self._wallet)

    def create_history_tab(self):
        from .history_list import HistoryView
        self.history_view = HistoryView(self._accounts_view, self)
        return self.history_view

    def create_transaction_tab(self) -> QWidget:
        from .transaction_list import TransactionView
        self.transaction_view = TransactionView(self._accounts_view, self)
        return self.create_list_tab(self.transaction_view)

    def show_key(self, account: AbstractAccount, key_id: int) -> None:
        from . import address_dialog
        d = address_dialog.KeyDialog(self, account.get_id(), key_id)
        d.exec_()

    def show_transaction(self, account: AbstractAccount, tx: Transaction,
            prompt_if_unsaved: bool=False,
            pr: Optional[paymentrequest.PaymentRequest]=None) -> None:
        '''tx_desc is set only for txs created in the Send tab'''
        self._wallet.synchronize_incomplete_transaction(tx)
        from . import transaction_dialog
        # from importlib import reload
        # reload(transaction_dialog)
        tx_dialog = transaction_dialog.TxDialog(account, tx, self, prompt_if_unsaved, pr)
        tx_dialog.finished.connect(partial(self.on_tx_dialog_finished, tx_dialog))
        self.tx_dialogs.append(tx_dialog)
        tx_dialog.show()
        return tx_dialog

    def on_tx_dialog_finished(self, tx_dialog, status):
        tx_dialog.finished.disconnect()
        self.tx_dialogs.remove(tx_dialog)

    def is_send_view_active(self) -> None:
        return self._send_view is not None and self._account is not None and \
            self._account.can_spend()

    def is_receive_view_active(self) -> None:
        return self._receive_view is not None and self._account_id is not None

    def _reset_send_tab(self) -> None:
        self._send_view = self._reset_stacked_tab(self.send_tab, self.get_send_view)

    def _reset_receive_tab(self) -> None:
        self._receive_view = self._reset_stacked_tab(self.receive_tab, self.get_receive_view)

    def _reset_stacked_tab(self, stack_tab: QStackedWidget, create_func: Callable[[int], T]) -> T:
        current_widget = stack_tab.currentWidget()
        assert current_widget is not None, f"should be unavailable or a view of the correct type"

        if self._account_id is None:
            assert isinstance(current_widget, QWidget)
            return None

        view = create_func(self._account_id)
        widget_index = stack_tab.indexOf(view)
        if widget_index == -1:
            stack_tab.addWidget(view)
        stack_tab.setCurrentWidget(view)
        return view

    def _create_account_unavailable_layout(self, text: Optional[str]=None) -> QVBoxLayout:
        if text is None:
            text = _("No active account.")

        label_title = WWLabel(_("<p>"+ text +"</p>"))
        label_title.setAlignment(Qt.AlignCenter)

        vbox2 = QVBoxLayout()
        vbox2.addStretch(1)
        vbox2.addWidget(label_title)
        vbox2.addStretch(1)
        return vbox2

    def show_send_tab(self) -> None:
        self._tab_widget.setCurrentIndex(self._tab_widget.indexOf(self.send_tab))

    def show_receive_tab(self) -> None:
        self._tab_widget.setCurrentIndex(self._tab_widget.indexOf(self.receive_tab))

    def get_send_view(self, account_id: Optional[int]) -> SendViewTypes:
        view = self._send_views.get(account_id)
        if view is None:
            text: Optional[str] = None
            if account_id is not None:
                account = self._wallet.get_account(account_id)
                if account.can_spend():
                    view = SendView(self, self._account_id)
                else:
                    text = _("This functionality is not available for this type of account.")
            if view is None:
                view = QWidget()
                view.setLayout(self._create_account_unavailable_layout(text))
            if account_id is not None:
                self._send_views[account_id] = view
        return view

    def get_receive_view(self, account_id: Optional[int]) -> ReceiveViewTypes:
        view = self._receive_views.get(account_id)
        if view is None:
            if account_id is not None:
                view = ReceiveView(self, self._account_id)
            if view is None:
                view = QWidget()
                view.setLayout(self._create_account_unavailable_layout())
            if account_id is not None:
                self._receive_views[account_id] = view
        return view

    def _create_send_tab(self) -> QStackedWidget:
        tab_widget = QStackedWidget()
        view = self.get_send_view(self._account_id)
        tab_widget.addWidget(view)
        tab_widget.setCurrentWidget(view)
        self._send_view = view
        return tab_widget

    def _create_receive_tab(self) -> QStackedWidget:
        tab_widget = QStackedWidget()
        view = self.get_receive_view(self._account_id)
        tab_widget.addWidget(view)
        tab_widget.setCurrentWidget(view)
        self._receive_view = view
        return tab_widget

    def get_custom_fee_text(self, fee_rate = None) -> str:
        if not self.config.has_custom_fee_rate():
            return ""
        else:
            if fee_rate is None: fee_rate = self.config.custom_fee_rate() / 1000.0
            return str(round(fee_rate*100)/100) + " sats/B"

    def get_contact_payto(self, contact_id):
        contact = self.contacts.get_contact(contact_id)
        return contact.label

    def confirm_broadcast_transaction(self, tx_hash: bytes, source: UIBroadcastSource) -> bool:
        # This function is intended to centralise the checks related to whether it is okay to
        # broadcast a transaction prior to calling `broadcast_transaction` on this wallet window.
        # Pass in the context of the call and check against the relevant contexts.

        # Skip confirmation for transactions loaded for broadcast.
        entry = self._account.get_transaction_entry(tx_hash) \
            if self._account is not None else None
        if entry is None:
            return True

        if entry.flags & TxFlags.PaysInvoice and source == UIBroadcastSource.TRANSACTION_DIALOG:
            # At this time invoice payment is hooked into transaction broadcasting and it
            # defers to the send tab for an active invoice, and completes payment of that invoice.
            # TODO: Fix the requirement an invoice is active in the send tab, but make sure that
            # the user knows that they are paying an invoice and what the invoice is for by
            # changing the UI experience.

            body_text = (_("If you broadcast the transaction there is a large chance that whomever "
                "gave you the invoice will not accept payment of the invoice. It is "
                "strongly recommended that you delete this transaction and get a new "
                "invoice, rather than broadcasting it.") +
                "<br/><br/>" +
                _("Do you still wish to broadcast this transaction?"))

            invoice_row = self._account.invoices.get_invoice_for_tx_hash(tx_hash)
            if invoice_row is None:
                if not self.question(_("This transaction is associated with a deleted invoice.") +
                        "<br/><br/>" + body_text,
                        icon=QMessageBox.Warning):
                    return False
            elif paymentrequest.has_expired(invoice_row.date_expires):
                if not self.question(_("This transaction is associated with an expired invoice.") +
                        "<br/><br/>" + body_text,
                        icon=QMessageBox.Warning):
                    return False
            elif (self._send_view._payment_request is None or
                    self._send_view._payment_request.get_id() != invoice_row.invoice_id):
                self.show_error(_("This transaction is associated with an invoice, but cannot "
                    "be broadcast as it is not active on the send tab. Go to the send tab and "
                    "select it from the invoice list and choose the 'Pay now' option."))
                return False

        return True

    @protected
    def sign_tx(self, tx: Transaction, callback: Callable[[bool], None], password: str,
            window=None, tx_context: Optional[TransactionContext]=None) -> None:
        self.sign_tx_with_password(tx, callback, password, window=window, tx_context=tx_context)

    def sign_tx_with_password(self, tx: Transaction, callback: Callable[[bool], None],
            password: str, window=None, tx_context: Optional[TransactionContext]=None) -> None:
        '''Sign the transaction in a separate thread.  When done, calls
        the callback with a success code of True or False.'''
        def on_done(future: concurrent.futures.Future) -> None:
            try:
                future.result()
            except Exception as exc:
                self.on_exception(exc)
                callback(False)
            else:
                callback(True)

        def sign_tx(update_cb: WaitingUpdateCallback) -> None:
            nonlocal tx, password, tx_context
            self._account.sign_transaction(tx, password, tx_context=tx_context)
            update_cb(False, _("Done."))

        window = window or self
        WaitingDialog(window, _('Signing transaction...'), sign_tx, on_done=on_done,
            title=_("Transaction signing"))

    def broadcast_transaction(self, account: Optional[AbstractAccount], tx: Transaction,
            success_text: Optional[str]=None, window=None) -> Optional[str]:
        if success_text is None:
            success_text = _('Payment sent.')
        window = window or self

        def broadcast_tx(update_cb: WaitingUpdateCallback) -> None:
            nonlocal tx, account
            # non-GUI thread
            if account and not self._send_view.maybe_send_invoice_payment(tx):
                return None

            try:
                result = self.network.broadcast_transaction_and_wait(tx)
            except aiorpcx.jsonrpc.RPCError as e:
                # If we sent an invoice payment, or someone else beat us to broadcasting this
                # transaction we should treat it the same as success.
                if e.code == 1 and "Transaction already in the mempool" in e.message:
                    result = tx.txid()
                else:
                    raise e

            tx_hash = tx.hash()
            # Not all transactions that are broadcast are in the account. Arbitrary transaction
            # broadcast is supported.
            if result == tx.txid() and account and account.have_transaction(tx_hash):
                account.maybe_set_transaction_dispatched(tx_hash)
            update_cb(False, _("Done."))
            return result

        def on_done(future: concurrent.futures.Future) -> None:
            nonlocal window, success_text
            # GUI thread
            try:
                tx_id: Optional[str] = future.result()
            except concurrent.futures.CancelledError:
                window.show_error(_("Transaction broadcast failed.") +"<br/><br/>"+
                    _("The most likely reason for this is that there is no available connection "
                    "to a main server. The signed transaction can be found in the "
                    "Transactions tab and can be rebroadcast from there."), )
            except Exception as exception:
                self._logger.exception('unhandled exception broadcasting transaction')
                reason = broadcast_failure_reason(exception)
                d = UntrustedMessageDialog(
                    window, _("Transaction Broadcast Error"),
                    _("Your transaction was not sent: ") + reason +".",
                    exception)
                d.exec()
            else:
                if account and tx_id:
                    if tx.context.description is not None:
                        self._wallet.set_transaction_label(tx.hash(), tx.context.description)
                    window.show_message(success_text + '\n' + tx_id)

                    self._send_view.clear()

        WaitingDialog(window, _('Broadcasting the transaction..'), broadcast_tx,
            on_done=on_done, title=_("Transaction broadcast"))

    # Used by hardware wallets.
    def query_choice(self, msg: str, choices: Iterable[str]) -> Optional[int]:
        return query_choice(self, msg, choices)

    def pay_to_URI(self, URI: str) -> None:
        if not URI:
            return

        if self._send_view is None:
            self.show_error(_("No active account."))
            return

        send_view = self.get_send_view(self._account_id)
        try:
            out = web.parse_URI(URI, send_view.on_payment_request,
                send_view.payment_request_import_error)
        except Exception as e:
            self.show_error(str(e))
            return
        self.show_send_tab()

        payment_url = out.get('r')
        if payment_url:
            send_view.prepare_for_payment_request()
            return

        send_view.set_payment_request_data(out)

    def set_frozen_coin_state(self, account: AbstractAccount, utxos: List[UTXO],
            freeze: bool) -> None:
        account.set_frozen_coin_state(utxos, freeze)
        keys = [ account.get_keyinstance(u.keyinstance_id) for u in utxos ]
        if self.key_view:
            self.key_view.update_frozen_keys(keys, freeze)
        self.utxo_list.update()
        send_view = self.get_send_view(account.get_id())
        send_view.update_fee()

    def create_coinsplitting_tab(self) -> QWidget:
        from .coinsplitting_tab import CoinSplittingTab
        return CoinSplittingTab(self)

    def create_notifications_tab(self) -> QWidget:
        from .notifications_view import View
        return View(self._api, self)

    def create_list_tab(self, list_widget: QWidget) -> None:
        top_button_layout: Optional[TableTopButtonLayout] = None

        w = QWidget()
        if hasattr(list_widget, "filter"):
            top_button_layout = TableTopButtonLayout()
            if hasattr(list_widget, "reset_table"):
                top_button_layout.refresh_signal.connect(list_widget.reset_table)
            else:
                top_button_layout.refresh_signal.connect(self.refresh_wallet_display)
            top_button_layout.filter_signal.connect(list_widget.filter)
            w.on_search_toggled = partial(top_button_layout.on_toggle_filter)
        vbox = QVBoxLayout()
        w.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        if top_button_layout is not None:
            vbox.addLayout(top_button_layout)
        vbox.addWidget(list_widget)
        return w

    def create_keys_tab(self):
        from .keys_view import KeyView
        self.key_view = l = KeyView(self)
        return self.create_list_tab(l)

    def create_utxo_tab(self) -> None:
        from .utxo_list import UTXOList
        self.utxo_list = l = UTXOList(self._accounts_view, self)
        return self.create_list_tab(l)

    def create_contacts_tab(self) -> None:
        self.contact_list = l = ContactList(self._api, self)
        return self.create_list_tab(l)

    def remove_key(self, account_id: int, key_id: int) -> None:
        account = self._wallet.get_account(account_id)

        extra_text = ""
        coin_count = len(account.get_key_utxos({ key_id }))
        if coin_count > 0:
            extra_text += " "+ _("It has {} known coins associated with it.").format(coin_count)

        if self.question(_("Do you want to remove this key from your wallet?") + extra_text):
            keyinstance = self._account.get_keyinstance(key_id)
            # This if successful will unload the key from the account (not delete).
            if account.archive_keys({ key_id }):
                if self.key_view is not None:
                    self.key_view.remove_keys([ keyinstance ])
                self.update_history_view()
                self._receive_view.update_contents()

    def remove_transaction(self, tx_hash: str) -> None:
        raise NotImplementedError()

    def spend_coins(self, coins: List[UTXO]) -> None:
        self._send_view.set_pay_from(coins)
        self.show_send_tab()
        self._send_view.update_fee()

    def paytomany(self) -> None:
        self.show_send_tab()
        self._send_view.paytomany()

    def _on_contacts_changed(self) -> None:
        self.contact_list.update()
        self.update_history_view()

    def show_invoice(self, account: AbstractAccount, row: InvoiceRow) -> None:
        from .invoice_dialog import InvoiceDialog
        d = InvoiceDialog(self, row)
        d.exec_()

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
            'wallet': self._wallet,
            'account': (self._wallet.get_account(self._account_id) if self._account_id is not None
                else None),
            'window': self,
        })

        c = commands.Commands(self.config, self._wallet, self.network, self.console.set_json)
        methods = {}
        def mkfunc(f, method):
            return lambda *args, **kwargs: f(method, *args, password_getter=self.password_dialog,
                                             **kwargs)
        for m in dir(c):
            if m[0] == '_' or m in ['network', 'wallet', 'config']:
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
            for account in self._wallet.get_accounts():
                c, u, x = account.get_balance()
                balance += c
            bsv_status, fiat_status = app_state.get_amount_and_units(balance)
        else:
            bsv_status, fiat_status = _("Unknown"), None
        self._status_bar.set_balance_status(bsv_status, fiat_status)

    def change_password_dialog(self):
        from .password_dialog import ChangePasswordDialog
        storage = self._wallet.get_storage()
        d = ChangePasswordDialog(self, password_check_fn=storage.is_password_valid)
        ok, password, new_password = d.run()
        if not ok:
            return
        try:
            self._wallet.update_password(new_password, password)
        except Exception as e:
            self._logger.exception("")
            self.show_error(_('Failed to update password'))
            return
        msg = (_('Password was updated successfully') if new_password
               else _('Password is disabled, this wallet is not protected'))
        self.show_message(msg, title=_("Success"))

    def _toggle_search(self) -> None:
        tab_parent = self._tab_widget.currentWidget()
        tab = tab_parent.currentWidget() if isinstance(tab_parent, QStackedWidget) else tab_parent

        if not hasattr(tab, 'on_search_toggled'):
            self.show_warning(_("The current tab does not support searching."))
            return

        tab.on_search_toggled()

    def _show_wallet_information(self) -> None:
        def open_file_explorer(path: str, *_discard: Iterable[Any]) -> None:
            show_in_file_explorer(path)

        dialog = QDialog(self)
        dialog.setWindowTitle(_("Wallet Information"))
        dialog.setMinimumSize(450, 100)
        vbox = QVBoxLayout()
        wallet_filepath = self._wallet.get_storage_path()
        wallet_dirpath = os.path.dirname(wallet_filepath)
        wallet_name = os.path.basename(wallet_filepath)

        name_edit = ButtonsLineEdit(wallet_name)
        name_edit.setReadOnly(True)
        name_edit.addButton("icons8-opened-folder-windows.svg",
            partial(open_file_explorer, wallet_filepath), _("View file in filesystem"))
        name_edit.addCopyButton(self.app)

        path_edit = ButtonsLineEdit(wallet_dirpath)
        path_edit.setReadOnly(True)
        path_edit.addButton("icons8-opened-folder-windows.svg",
            partial(open_file_explorer, wallet_dirpath), _("View location in filesystem"))
        path_edit.addCopyButton(self.app)

        file_form = FormSectionWidget()
        file_form.add_row(_("File name"), name_edit, True)
        file_form.add_row(_("File path"), path_edit, True)
        vbox.addWidget(file_form)

        current_txcachesize_label = QLabel()
        maximum_txcachesize_label = QLabel()
        hits_label = QLabel()
        misses_label = QLabel()

        def update_txcachesizes():
            nonlocal current_txcachesize_label, maximum_txcachesize_label
            nonlocal hits_label, misses_label
            cache = self._wallet._transaction_cache._txdata_cache
            current_size, max_size = cache.get_sizes()
            current_txcachesize_label.setText(str(current_size))
            maximum_txcachesize_label.setText(str(max_size))
            hits_label.setText(str(cache.hits))
            misses_label.setText(str(cache.misses))
        update_txcachesizes()

        memory_usage_form = FormSectionWidget(minimum_label_width=100)
        memory_usage_form.add_title(_("Transaction data cache"))
        memory_usage_form.add_row(_("Current usage"), current_txcachesize_label)
        memory_usage_form.add_row(_("Maximum usage"), maximum_txcachesize_label)
        memory_usage_form.add_row(_("Cache hits"), hits_label)
        memory_usage_form.add_row(_("Cache misses"), misses_label)
        vbox.addWidget(memory_usage_form)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(dialog)))

        update_timer = QTimer(self)
        update_timer.setSingleShot(False)
        update_timer.setInterval(1000)
        update_timer.timeout.connect(update_txcachesizes)
        update_timer.start()
        try:
            dialog.setLayout(vbox)
            dialog.exec_()
        finally:
            update_timer.stop()

    # TODO(rt12): This should be moved into the wallet wizard as a context menu option. Doing it
    # on an open wallet makes no sense post-JSON "save on exit".
    # @protected
    # def _delete_wallet(self, password):
    #     wallet_path = self._wallet.get_storage_path()
    #     basename = self._wallet.name()
    #     app_state.daemon.stop_wallet_at_path(wallet_path)
    #     self.close()
    #     os.unlink(wallet_path)
    #     self.update_recently_visited(wallet_path) # this ensures it's deleted from the menu
    #     self.show_error("Wallet removed:" + basename)

    def show_qrcode(self, data, title = _("QR code"), parent=None) -> None:
        if not data:
            return
        d = QRDialog(data, parent or self, title)
        d.exec_()

    @protected
    def show_private_key(self, account: AbstractAccount, keyinstance_id: int,
            password: str) -> None:
        try:
            privkey_text = account.export_private_key(keyinstance_id, password)
        except Exception as e:
            self._logger.exception("")
            self.show_message(str(e))
            return

        script_template = account.get_script_template_for_id(keyinstance_id)

        d = WindowModalDialog(self, _("Private key"))
        d.setMinimumSize(600, 150)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_("Private key") + ':'))
        keys_e = ShowQRTextEdit(text=privkey_text)
        keys_e.addCopyButton(self.app)
        vbox.addWidget(keys_e)
        vbox.addWidget(QLabel(_("Payment script") + ':'))
        rds_e = ShowQRTextEdit(text=script_template_to_string(script_template))
        rds_e.addCopyButton(self.app)
        vbox.addWidget(rds_e)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)
        d.exec_()

    @protected
    def do_sign(self, account: AbstractAccount, key_id: int, message: str, signature,
            password: str) -> None:
        message = message.toPlainText().strip()
        if account.is_watching_only():
            self.show_message(_('This is a watching-only account.'))
            return

        def show_signed_message(sig: bytes) -> None:
            nonlocal signature
            # Empty signature indicates user exit.
            # Deleted signature object indicates that user pre-emptively closed widget.
            if not len(sig) or sip.isdeleted(signature):
                return
            signature.setText(base64.b64encode(sig).decode('ascii'))
        self.run_in_thread(account.sign_message, key_id, message, password,
            on_success=show_signed_message)

    def run_in_thread(self, func, *args, on_success=None):
        def _on_done(future: concurrent.futures.Future) -> None:
            try:
                result = future.result()
            except Exception as exc:
                self.on_exception(exc)
            else:
                if on_success:
                    on_success(result)
        return self.app.run_in_thread(func, *args, on_done=_on_done)

    def do_verify(self, account: AbstractAccount, key_id: Optional[int], address: QLineEdit,
            message, signature) -> None:
        if key_id is None:
            try:
                address = address_from_string(address.text().strip()).to_string()
            except Exception:
                self.show_message(_('Invalid Bitcoin SV address.'))
                return
        else:
            public_key = account.get_public_keys_for_id(key_id)[0]
            address = public_key.to_address(coin=Net.COIN)

        message = message.toPlainText().strip()
        try:
            # This can throw on invalid base64
            sig = base64.b64decode(signature.toPlainText())
            verified = PublicKey.verify_message_and_address(sig, message, address)
        except Exception:
            verified = False

        if verified:
            self.show_message(_("Signature verified"))
        else:
            self.show_error(_("Wrong signature"))

    def sign_verify_message(self, account: Optional[AbstractAccount]=None,
            key_id: Optional[int]=None) -> None:
        if account is None:
            account = self._wallet.get_default_account()

        d = WindowModalDialog(self, _('Sign/verify Message'))
        d.setMinimumSize(610, 290)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        message_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        address_e = QLineEdit()
        if key_id is not None:
            address_e.setText(f"Key {key_id}")
            address_e.setReadOnly(True)
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
            self.do_sign(account, key_id, message_e, signature_e)
        b.clicked.connect(do_sign)
        hbox.addWidget(b)

        b = QPushButton(_("Verify"))
        b.clicked.connect(partial(self.do_verify, account, key_id, address_e, message_e,
            signature_e))
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 4, 1)
        d.exec_()

    @protected
    def do_decrypt(self, account: AbstractAccount, key_id: int, message_e: QTextEdit,
            encrypted_e: QTextEdit, password: Optional[str]) -> None:
        if account.is_watching_only():
            self.show_message(_('This is a watching-only account, and cannot decrypt.'))
            return

        cyphertext = encrypted_e.toPlainText()

        def show_decrypted_message(msg):
            message_e.setText(msg.decode())

        self.run_in_thread(account.decrypt_message, key_id, cyphertext, password,
            on_success=show_decrypted_message)

    def do_encrypt(self, account: AbstractAccount, key_id: Optional[int], message_e: QTextEdit,
            pubkey_e: QLineEdit, encrypted_e: QTextEdit) -> None:
        message = message_e.toPlainText()
        message = message.encode('utf-8')
        if key_id is not None:
            public_key = account.get_public_keys_for_id(key_id)[0]
        else:
            try:
                public_key = PublicKey.from_hex(pubkey_e.text())
            except Exception as e:
                self._logger.exception("")
                self.show_warning(_('Invalid Public key'))
                return
        encrypted = public_key.encrypt_message_to_base64(message)
        encrypted_e.setText(encrypted)

    def encrypt_message(self, account: Optional[AbstractAccount]=None,
            key_id: Optional[int]=None) -> None:
        account = self._account if account is None else account

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

        if key_id is not None:
            pubkey_e.setText(f"Key {key_id}")
            pubkey_e.setReadOnly(True)

        encrypted_e = QTextEdit()
        encrypted_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Encrypted')), 3, 0)
        layout.addWidget(encrypted_e, 3, 1)
        layout.setRowStretch(3,1)

        hbox = QHBoxLayout()
        b = QPushButton(_("Encrypt"))
        b.clicked.connect(lambda: self.do_encrypt(account, key_id, message_e, pubkey_e,
            encrypted_e))
        hbox.addWidget(b)

        b = QPushButton(_("Decrypt"))
        def do_decrypt(checked=False):
            # pylint: disable=no-value-for-parameter
            self.do_decrypt(account, key_id, message_e, encrypted_e)
        b.clicked.connect(do_decrypt)
        hbox.addWidget(b)

        b.setEnabled(key_id is not None)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)

        layout.addLayout(hbox, 4, 1)
        d.exec_()

    def password_dialog(self, msg: Optional[str]=None, parent: Optional[QWidget]=None,
            fields: List[Tuple[Union[str, QLabel], QWidget]]=None) -> str:
        from .password_dialog import PasswordDialog
        parent = parent or self
        storage = self._wallet.get_storage()
        d = PasswordDialog(parent, msg, password_check_fn=storage.is_password_valid, fields=fields)
        return d.run()

    def tx_from_text(self, txt: str) -> Optional[Transaction]:
        if not txt:
            return None
        txdict = txdict_from_str(txt)
        tx = Transaction.from_dict(txdict)

        for account in self._wallet.get_accounts():
            my_coins = account.get_spendable_coins(None, self.config)
            my_outpoints = [coin.key() for coin in my_coins]
            for txin in tx.inputs:
                outpoint = (txin.prev_hash, txin.prev_idx)
                if outpoint in my_outpoints:
                    my_index = my_outpoints.index(outpoint)
                    txin.value = my_coins[my_index].value
        return tx

    def read_tx_from_qrcode(self) -> Optional[Transaction]:
        data = qrscanner.scan_barcode(self.config.get_video_device())
        if not data:
            return
        # if the user scanned a bitcoin URI
        if web.is_URI(data):
            self.pay_to_URI(data)
            return
        # else if the user scanned an offline signed tx
        data = bitcoin.base_decode(data, length=None, base=43)
        if data.startswith(b"\x1f\x8b"):
            text = gzip.decompress(data).decode()
        else:
            text = bh2u(data)
        return self.tx_from_text(text)

    def read_tx_from_file(self) -> Optional[Transaction]:
        fileName = self.getOpenFileName(_("Select your transaction file"),
            "*.json;;*.txn;;*.txt;;*.*")
        if not fileName:
            return
        with open(fileName, "r") as f:
            file_content = f.read()
        return self.tx_from_text(file_content.strip())

    def do_process_from_qrcode(self):
        try:
            tx = self.read_tx_from_qrcode()
            if tx:
                self.show_transaction(self._account, tx)
        except Exception as reason:
            self._logger.exception(reason)
            self.show_critical(_("ElectrumSV was unable to read the transaction:") +
                               "\n" + str(reason))

    def do_process_from_text(self):
        text = text_dialog(self, _('Input raw transaction'), _("Transaction:"),
                           _("Load transaction"))
        try:
            tx = self.tx_from_text(text)
            if tx:
                self.show_transaction(self._account, tx)
        except Exception as reason:
            self._logger.exception(reason)
            self.show_critical(_("ElectrumSV was unable to read the transaction:") +
                               "\n" + str(reason))

    def do_process_from_file(self):
        try:
            tx = self.read_tx_from_file()
            if tx:
                self.show_transaction(self._account, tx)
        except Exception as reason:
            self._logger.exception(reason)
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
            self.show_transaction(self._account, tx)

    def do_import_labels(self, account_id: int) -> None:
        from .import_export import LabelImporter
        widget = LabelImporter(self, self._wallet, account_id)
        widget.labels_updated.connect(self._on_labels_updated)
        widget.run()

    def _on_labels_updated(self, account_id: int, key_updates: Set[int],
            transaction_updates: Set[bytes]) -> None:
        if self.key_view is not None:
            self.key_view.update_labels(self._wallet.get_storage_path(), account_id, key_updates)

        if len(transaction_updates):
            self.update_history_view()

    def do_export_labels(self, account_id: int) -> None:
        account = self._wallet.get_account(account_id)
        label_data = account.get_label_data()
        try:
            file_name = self.getSaveFileName(_("Select file to save your labels"),
                'electrumsv_labels.json', "*.json")
            if file_name:
                with open(file_name, 'w+') as f:
                    json.dump(label_data, f, indent=4, sort_keys=True)
                self.show_message(_("Your labels were exported to") + " '%s'" % str(file_name))
        except (IOError, os.error) as reason:
            self.show_critical(_("ElectrumSV was unable to export your labels.") + "\n" +
                               str(reason))

    def export_history_dialog(self) -> None:
        filter_text = "CSV files (*.csv);;JSON files (*.json)"
        default_filename = os.path.expanduser(os.path.join("~", "electrumsv-history.csv"))
        export_filename = self.getSaveFileName(_("Export History"), default_filename, filter_text)
        if not export_filename:
            return

        root_path, filename_ext = os.path.splitext(export_filename)
        if filename_ext not in (".csv", ".json"):
            return

        try:
            self._do_export_history(self._account, export_filename, filename_ext == ".csv")
        except (IOError, os.error) as reason:
            export_error_label = _("ElectrumSV was unable to produce a transaction export.")
            self.show_critical(export_error_label + "\n" + str(reason),
                               title=_("Unable to export history"))
            return

        self.show_message(_("Your wallet history has been successfully exported."))

    def _do_export_history(self, account: AbstractAccount, fileName: str, is_csv: bool) -> None:
        history = account.export_history()
        lines = []
        for item in history:
            if is_csv:
                lines.append([item['txid'], item.get('label', ''), item['value'],
                    item['timestamp']])
            else:
                lines.append(item)

        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f, lineterminator='\n')
                transaction.writerow(["transaction_hash", "label", "value", "timestamp"])
                for line in lines:
                    transaction.writerow(line)
            else:
                f.write(json.dumps(lines, indent=4))

    def _do_import(self, title, msg, func):
        text = text_dialog(self, title, msg + ' :', _('Import'),
                           allow_multi=True)
        if not text:
            return
        bad = []
        good = []
        for key in str(text).split():
            try:
                func(key)
                good.append(key)
            except Exception as e:
                self._logger.exception("import")
                bad.append(key)
                continue
        if good:
            self.show_message(_("The following entries were added") + ':\n' +
                '\n'.join(text for text in good))
        if bad:
            self.show_critical(_("The following entries could not be imported") +
                               ':\n'+ '\n'.join(bad))
        self.update_history_view()

    def update_history_view(self) -> None:
        self.history_view.update_tx_list()
        self.history_updated_signal.emit()

    #
    # Preferences dialog and its signals.
    #
    def on_num_zeros_changed(self):
        self.update_history_view()

    def on_fiat_ccy_changed(self):
        '''Called when the user changes fiat currency in preferences.'''
        b = bool(app_state.fx and app_state.fx.is_enabled())
        if self._account_id is not None:
            for send_view in self._send_views.values():
                if isinstance(send_view, SendView):
                    send_view.set_fiat_ccy_enabled(b)
            for receive_view in self._receive_views.values():
                if isinstance(receive_view, ReceiveView):
                    receive_view.set_fiat_ccy_enabled(b)
        self.history_view.update_tx_headers()
        self.update_history_view()
        self.update_status_bar()

    def on_base_unit_changed(self):
        edits = list(itertools.chain.from_iterable(v.get_bsv_edits()
            for v in self._send_views.values() if isinstance(v, SendView)))
        edits.extend(
            itertools.chain.from_iterable(v.get_bsv_edits() for v in self._receive_views.values()
                if isinstance(v, ReceiveView)))
        amounts = [edit.get_amount() for edit in edits]
        self.update_history_view()
        if self.is_receive_view_active():
            self._receive_view.update_widgets()
        for edit, amount in zip(edits, amounts):
            edit.setAmount(amount)
        self.update_status_bar()
        for tx_dialog in self.tx_dialogs:
            tx_dialog.update()

    # App event broadcast to all wallet windows.
    def on_fiat_history_changed(self) -> None:
        self.history_view.update_tx_headers()

    # App event broadcast to all wallet windows.
    def on_fiat_balance_changed(self) -> None:
        pass

    def preferences_dialog(self) -> None:
        from . import preferences
        from importlib import reload
        reload(preferences)
        dialog = preferences.PreferencesDialog(self, self._wallet, self._account)
        dialog.exec_()

    def ok_to_close(self) -> bool:
        # Close our tx dialogs; return False if any cannot be closed
        for tx_dialog in list(self.tx_dialogs):
            if not tx_dialog.close():
                return False
        return True

    def closeEvent(self, event) -> None:
        if self.ok_to_close():
            # It seems in some rare cases this closeEvent() is called twice
            if not self.cleaned_up:
                self.clean_up()
                self.cleaned_up = True
            event.accept()
        else:
            event.ignore()

    def clean_up(self) -> None:
        self._wallet.unregister_callbacks_for_object(self)

        if self.network:
            self.network.unregister_callbacks_for_object(self)

        if self.tx_notify_timer:
            self.tx_notify_timer.stop()
            self.tx_notify_timer = None

        # Cancelled tasks have a reference to a cancelled exception, if we do not delete the
        # future that links to the task, the task methods on the window class will keep the window
        # from being garbage collected.
        self._network_status_task.cancel()
        self._network_status_task = None
        self._monitor_wallet_network_status_task.cancel()
        self._monitor_wallet_network_status_task = None

        # We catch these errors with the understanding that there is no recovery at
        # this point, given user has likely performed an action we cannot recover
        # cleanly from.  So we attempt to exit as cleanly as possible.
        try:
            self.config.set_key("is_maximized", self.isMaximized())
            self.config.set_key("console-history", self.console.history[-50:], True)
        except (OSError, PermissionError):
            self._logger.exception("unable to write to config (directory removed?)")

        if not self.isMaximized():
            try:
                self._wallet.get_storage().put("winpos-qt", self.geometry().getRect())
                self._wallet.get_storage().put("split-sizes-qt", self._accounts_view.sizes())
            except (OSError, PermissionError):
                self._logger.exception("unable to write to wallet storage (directory removed?)")

        self._api.clean_up()
        self.console.clean_up()

        # Should be no side-effects in this function relating to file access past this point.

        for receive_view in self._receive_views.values():
            if isinstance(receive_view, ReceiveView):
                receive_view.clean_up()
        self._receive_views.clear()

        for send_view in self._send_views.values():
            if isinstance(send_view, SendView):
                send_view.clean_up()
        self._send_views.clear()

        if self.key_view:
            self.key_view.clean_up()

        if self.transaction_view:
            self.transaction_view.clean_up()

        for account in self._wallet.get_accounts():
            for keystore in account.get_keystores():
                keystore.clean_up()

        self._logger.debug('closing wallet %s', self._wallet)

        self.app.timer.timeout.disconnect(self.timer_actions)
        self.app.close_window(self)

    def cpfp(self, account: AbstractAccount, parent_tx: Transaction, new_tx: Transaction) -> None:
        total_size = parent_tx.size() + new_tx.estimated_size()
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
        grid.addWidget(QLabel(app_state.format_amount(max_fee) + ' ' + app_state.base_unit()), 1, 1)
        output_amount = QLabel('')
        grid.addWidget(QLabel(_('Output amount') + ':'), 2, 0)
        grid.addWidget(output_amount, 2, 1)
        fee_e = BTCAmountEdit()
        def f(x):
            a = max_fee - fee_e.get_amount()
            output_amount.setText((app_state.format_amount(a) + ' ' + app_state.base_unit())
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
        new_tx = account.cpfp(parent_tx, fee)
        if new_tx is None:
            self.show_error(_('CPFP no longer valid'))
            return
        self.show_transaction(self._account, new_tx)
