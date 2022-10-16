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

from __future__ import annotations
import asyncio
import base64
import binascii
from collections import Counter
import concurrent.futures
import csv
from decimal import Decimal
from functools import partial
import gzip
import itertools
import json
import math
import os
import shutil
import threading
import time
from typing import Any, Callable, cast, Dict, Iterable, List, Optional, Set, Tuple, \
    TYPE_CHECKING, TypeVar, Union
import urllib.parse
import weakref
import webbrowser

from bitcoinx import hex_str_to_hash, Header, PublicKey
from mypy_extensions import Arg, DefaultNamedArg, KwArg, VarArg

from PyQt6.QtCore import pyqtSignal, QKeyCombination, Qt, QSize, QTimer, QRect
from PyQt6.QtGui import QAction, QCloseEvent, QKeySequence, QIcon, QShortcut
from PyQt6.QtWidgets import (
    QDialog, QFileDialog, QGridLayout, QHBoxLayout, QInputDialog, QLabel,
    QLineEdit, QMainWindow, QMenu, QMenuBar, QMessageBox, QPushButton, QSizePolicy,
    QStackedWidget, QTabWidget, QTextEdit, QToolBar, QVBoxLayout, QWidget
)
from PyQt6 import sip

# TODO this should be a relative import, is that legal?
import electrumsv
from ... import bitcoin, commands, dpp_messages, util
from ...app_state import app_state
from ...bitcoin import address_from_string, COIN, script_template_to_string
from ...constants import (AccountType, CredentialPolicyFlag, DATABASE_EXT, NetworkEventNames,
    NetworkServerFlag, ScriptType, ServerConnectionFlag, TransactionImportFlag,
    TransactionOutputFlag, TxFlags, WalletEvent)
from ...exceptions import UserCancelled
from ...i18n import _
from ...logs import logs
from ...networks import Net
from ...standards.tsc_merkle_proof import TSCMerkleProof
from ...storage import WalletStorage
from ...transaction import Transaction, TransactionContext
from ...types import ExceptionInfoType, Outpoint, WaitingUpdateCallback
from ...util import UpdateCheckResultType, format_fee_satoshis, get_identified_release_signers, \
    get_update_check_dates, get_wallet_name_from_path, profiler
from ...version import PACKAGE_VERSION
from ...wallet import AbstractAccount, AccountInstantiationFlags, Wallet
from ...wallet_database.types import (InvoiceRow, KeyDataProtocol, TransactionLinkState,
    TransactionOutputSpendableProtocol)
from ... import web

from .amountedit import AmountEdit, BTCAmountEdit
from .console import Console
from .constants import CSS_WALLET_WINDOW_STYLE, RestorationDialogRole, UIBroadcastSource
from .contact_list import ContactList, edit_contact_dialog
from .network_dialog import NetworkDialog
from .password_dialog import LayoutFields
from .qrcodewidget import QRDialog
from .qrreader import scan_qrcode
from .qrtextedit import ShowQRTextEdit
from .receive_view import ReceiveView
from .send_view import SendView
from .tab_widget import TabWidget
from .table_widgets import TableTopButtonLayout
from .util import (Buttons, CancelButton, CloseButton, ColorScheme,
    create_new_wallet, ButtonsLineEdit, FormSectionWidget, MessageBoxMixin, OkButton,
    protected, read_QIcon, show_in_file_explorer, text_dialog,
    top_level_window_recurse, UntrustedMessageDialog, WaitingDialog,
    WindowModalDialog, WWLabel)
from .wallet_api import WalletAPI

if TYPE_CHECKING:
    from .coinsplitting_tab import CoinSplittingTab
    from .history_list import HistoryView
    from .transaction_dialog import TxDialog
    from .wallet_navigation_view import WalletNavigationView


logger = logs.get_logger("mainwindow")


SendViewTypes = Union[SendView, QWidget]
ReceiveViewTypes = Union[ReceiveView, QWidget]
T = TypeVar('T')
T1 = TypeVar("T1")


class ElectrumWindow(QMainWindow, MessageBoxMixin):
    notify_transactions_signal = pyqtSignal()
    new_fx_quotes_signal = pyqtSignal()
    new_fx_history_signal = pyqtSignal()
    network_signal = pyqtSignal(object, object)
    history_updated_signal = pyqtSignal()
    network_status_signal = pyqtSignal()
    account_created_signal = pyqtSignal(int, object)
    account_change_signal = pyqtSignal(object, object, bool)
    account_restoration_signal = pyqtSignal(int)
    keys_updated_signal = pyqtSignal(object, object)
    keys_created_signal = pyqtSignal(object, object)
    notifications_created_signal = pyqtSignal(object)
    notifications_updated_signal = pyqtSignal(object)
    transaction_state_signal = pyqtSignal(object, object, object)
    transaction_added_signal = pyqtSignal(object, object, object)
    transaction_deleted_signal = pyqtSignal(object, object)
    transaction_verified_signal = pyqtSignal(object, object, object)
    transaction_labels_updated_signal = pyqtSignal(object)
    payment_requests_paid_signal = pyqtSignal(list)
    show_secured_data_signal = pyqtSignal(object)
    wallet_setting_changed_signal = pyqtSignal(str, object)
    password_request_signal = pyqtSignal(object, str)
    update_required_signal = pyqtSignal()
    # This signal should only be emitted to. It is just used to dispatch callback execution in
    # the UI thread, without having to do a signal per callback.
    ui_callback_signal = pyqtSignal(object, object)

    _scan_account_action: QAction
    _add_account_action: QAction

    def __init__(self, wallet: Wallet):
        QMainWindow.__init__(self)

        self.setStyleSheet(CSS_WALLET_WINDOW_STYLE)

        self._api = WalletAPI(self)

        self._logger = logger
        self.config = app_state.config

        self._wallet = wallet
        self._account: AbstractAccount | None = None
        self._account_id: int | None = None

        app_state.credentials.set_request_callback(wallet.get_storage_path(),
            self.password_request_signal.emit)

        self.network = app_state.daemon.network
        self.contacts = wallet.contacts
        self.app = app_state.app_qt
        self.cleaned_up = False
        self.tx_notifications: List[Transaction] = []
        self.tx_notify_timer: Optional[QTimer] = None
        self.tx_dialogs: List[TxDialog] = []
        self.tl_windows: List[QDialog] = []

        self.create_status_bar()
        self._update_account_specific_event = threading.Event()
        self._update_common_event = threading.Event()

        self.fee_unit = self.config.get('fee_unit', 0)

        self._navigation_view = self._create_navigation_view()
        self._send_views: Dict[int, SendViewTypes] = {}
        self._send_view: Optional[SendViewTypes] = None
        self._receive_views: Dict[int, ReceiveViewTypes] = {}
        self._receive_view: Optional[ReceiveViewTypes] = None
        self._network_dialog: Optional[NetworkDialog] = None

        self._tab_widget = tabs = self._navigation_view.get_tab_widget()

        self._create_tabs()

        tabs.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setCentralWidget(self._navigation_view)

        self._tab_widget.currentChanged.connect(self._on_tab_changed)

        if self.config.get("is_maximized"):
            self.showMaximized()

        self.init_menubar()
        self.init_toolbar()

        # NOTE(typing) `close` does not have the right signature.
        QShortcut(QKeySequence("Ctrl+W"), self, self.close) # type: ignore
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close) # type: ignore
        QShortcut(QKeySequence("Ctrl+R"), self, self.refresh_wallet_display)
        QShortcut(QKeySequence("Ctrl+PgUp"), self,
                  lambda: tabs.setCurrentIndex((tabs.currentIndex() - 1)%tabs.count()))
        QShortcut(QKeySequence("Ctrl+PgDown"), self,
                  lambda: tabs.setCurrentIndex((tabs.currentIndex() + 1)%tabs.count()))

        for i in range(tabs.count()):
            QShortcut(QKeySequence("Alt+" + str(i + 1)), self,
                      lambda i=i: tabs.setCurrentIndex(i))

        self.keys_updated_signal.connect(self._on_keys_updated)
        self.network_status_signal.connect(self._update_network_status)
        self.notify_transactions_signal.connect(self._notify_transactions)
        self.account_restoration_signal.connect(self._on_account_restoration_signal)
        self.show_secured_data_signal.connect(self._on_show_secured_data)
        self.transaction_labels_updated_signal.connect(self._on_transaction_labels_updated_signal)
        self.transaction_state_signal.connect(self._on_transaction_state_change)
        self.password_request_signal.connect(self._on_password_request)
        self.ui_callback_signal.connect(self._on_ui_callback_to_dispatch)

        self._last_network_status_change = 0.0
        self._network_status_loop_task = app_state.async_.spawn(
            self._update_network_status_loop())

        # network callbacks
        if self.network:
            self.network_signal.connect(self.on_network_qt)
            # To avoid leaking references to "self" that prevent the
            # window from being GC-ed when closed, callbacks should be
            # methods of this class only, and specifically not be
            # partials, lambdas or methods of subobjects.  Hence...
            self.network.register_callback(self.on_network, [ NetworkEventNames.GENERIC_UPDATE,
                NetworkEventNames.GENERIC_STATUS, NetworkEventNames.BANNER ])

            self.network.register_callback(self._on_exchange_rate_quotes,
                [ NetworkEventNames.EXCHANGE_RATE_QUOTES ])
            self.network.register_callback(self._on_historical_exchange_rates,
                [ NetworkEventNames.HISTORICAL_EXCHANGE_RATES ])

            self.new_fx_quotes_signal.connect(self._on_ui_exchange_rate_quotes)
            self.new_fx_history_signal.connect(self._on_ui_historical_exchange_rates)

        # NOTE(ui-thread) These callbacks should actually all be routed through signals, in order
        #   to ensure that they are happening in the UI thread.
        self._wallet.events.register_callback(self._on_account_created,
            [ WalletEvent.ACCOUNT_CREATE ])
        self._wallet.events.register_callback(self._on_wallet_setting_changed,
            [ WalletEvent.WALLET_SETTING_CHANGE ])
        self._wallet.events.register_callback(self._dispatch_in_ui_thread, [
            WalletEvent.KEYS_CREATE, WalletEvent.KEYS_UPDATE, WalletEvent.NOTIFICATIONS_CREATE,
            WalletEvent.NOTIFICATIONS_UPDATE,
            WalletEvent.TRANSACTION_HEIGHTS_UPDATED, WalletEvent.TRANSACTION_STATE_CHANGE,
            WalletEvent.TRANSACTION_LABELS_UPDATE
        ])
        self._wallet.events.register_callback(self._on_transaction_added,
            [ WalletEvent.TRANSACTION_ADD])
        self._wallet.events.register_callback(self._on_transaction_deleted,
            [ WalletEvent.TRANSACTION_DELETE ])
        self._wallet.events.register_callback(self._on_transaction_verified,
            [ WalletEvent.TRANSACTION_VERIFIED ])
        self._wallet.events.register_callback(self._on_payment_requests_paid,
            [ WalletEvent.PAYMENT_REQUEST_PAID ])

        self.load_wallet()

        self._navigation_view.on_wallet_loaded()
        if self._account is not None:
            self._update_active_account(startup=True)

        # If the user is opening a wallet with no accounts, we show them the add an account wizard
        # automatically. It may be that at a later time, we allow people to disable this optionally
        # but some users struggle to read the "add account" text or maybe just like to complain.
        if not len(wallet.get_accounts()):
            main_window_proxy: ElectrumWindow = weakref.proxy(self)
            from . import account_wizard
            wizard_window = account_wizard.AccountWizard(main_window_proxy)
            wizard_window.show()

        self.app.timer.timeout.connect(self.timer_actions)

    def reference(self) -> 'ElectrumWindow':
        return self

    def __del__(self) -> None:
        logger.debug(f"Wallet window garbage collected {self!r}")

    def _on_tab_changed(self, to_tab_index: int) -> None:
        # Some tabs may want to be refreshed to show current state when selected.
        current_tab = self._tab_widget.currentWidget()
        if current_tab is self.coinsplitting_tab:
            self.coinsplitting_tab.on_tab_activated()
        elif current_tab is self.send_tab and self.is_send_view_active():
            assert isinstance(self._send_view, SendView)
            self._send_view.on_tab_activated()

    def _create_tabs(self) -> None:
        tabs = self._tab_widget

        self.send_tab = self._create_send_tab()
        self.receive_tab = self._create_receive_tab()
        self.keys_tab = self.create_keys_tab()
        self.utxo_tab = self.create_utxo_tab()
        self.coinsplitting_tab = self.create_coinsplitting_tab()

        history_view = self.create_history_tab()

        tabs.addTab(history_view, read_QIcon("tab_history.png"), _('History'))
        tabs.addTab(self.send_tab, read_QIcon("tab_send.png"), _('Send'))
        tabs.addTab(self.receive_tab, read_QIcon("tab_receive.png"), _('Receive'))

        tabs.setTabToolTip(0, _("Published transactions"))
        tabs.setTabToolTip(1, _("Create a transaction"))
        tabs.setTabToolTip(2, _("Receive a transaction"))

        self._add_optional_tab(tabs, self.keys_tab, read_QIcon("tab_keys.png"),
            _("&Keys"), "keys")
        self._add_optional_tab(tabs, self.utxo_tab, read_QIcon("tab_coins.png"),
            _("Co&ins"), "utxo")
        self._add_optional_tab(tabs, self.coinsplitting_tab, read_QIcon("tab_coins.png"),
            _("Coin Splitting"), "coinsplitter", True)

    def _add_optional_tab(self, tabs: QTabWidget, tab: QWidget, icon: QIcon, description: str,
            name: str, default: bool=False) -> None:
        tab.tab_icon = icon # type: ignore[attr-defined]
        tab.tab_description = description # type: ignore[attr-defined]
        tab.tab_pos = len(tabs) # type: ignore[attr-defined]
        tab.tab_name = name # type: ignore[attr-defined]
        if self.config.get('show_{}_tab'.format(name), default):
            tabs.addTab(tab, icon, description.replace("&", ""))

    def _on_wallet_setting_changed(self, event_name: str, setting_name: str, setting_value: Any) \
            -> None:
        self.wallet_setting_changed_signal.emit(setting_name, setting_value)

    def _on_transaction_heights_updated(self, *args: Any) -> None:
        self.utxo_list.update()

    def _dispatch_in_ui_thread(self, event_name: WalletEvent, *args: Any) -> None:
        if event_name == WalletEvent.NOTIFICATIONS_CREATE:
            self.notifications_created_signal.emit(*args)
        elif event_name == WalletEvent.NOTIFICATIONS_UPDATE:
            self.notifications_updated_signal.emit(*args)
        elif event_name == WalletEvent.KEYS_CREATE:
            self.keys_created_signal.emit(*args)
        elif event_name == WalletEvent.KEYS_UPDATE:
            self.keys_updated_signal.emit(*args)
        elif event_name == WalletEvent.TRANSACTION_HEIGHTS_UPDATED:
            self.ui_callback_signal.emit(self._on_transaction_heights_updated, args)
        elif event_name == WalletEvent.TRANSACTION_LABELS_UPDATE:
            self.transaction_labels_updated_signal.emit(*args)
        elif event_name == WalletEvent.TRANSACTION_STATE_CHANGE:
            self.transaction_state_signal.emit(*args)
        else:
            raise NotImplementedError(f"Event '{event_name}' not recognised")

    # Map the wallet event to a Qt UI signal.
    def _on_transaction_added(self, event_name: str, tx_hash: bytes, tx: Transaction,
            link_result: TransactionLinkState, import_flags: TransactionImportFlag) -> None:
        # Account ids are the accounts that have changed the balance.
        assert link_result.account_ids is not None
        if self._wallet.get_account_ids() & link_result.account_ids and \
                import_flags & TransactionImportFlag.PROMPTED == 0:
            # Always notify of incoming transactions regardless of the active account.
            self.tx_notifications.append(tx)
            self.notify_transactions_signal.emit()

        self._update_account_specific_event.set()
        self._update_common_event.set()
        self.transaction_added_signal.emit(tx_hash, tx, link_result.account_ids)

    # Map the wallet event to a Qt UI signal.
    def _on_transaction_deleted(self, event_name: str, account_id: int, tx_hash: bytes) -> None:
        self._update_account_specific_event.set()
        self._update_common_event.set()
        self.transaction_deleted_signal.emit(account_id, tx_hash)

    # Map the wallet event to a Qt UI signal.
    def _on_transaction_verified(self, event_name: str, tx_hash: bytes, header: Header,
            tsc_proof: TSCMerkleProof) -> None:
        self._update_account_specific_event.set()
        self.transaction_verified_signal.emit(tx_hash, header, tsc_proof)
        # NOTE(rt12): Disabled due to fact we can't update individual rows and their order due
        # to the balance column being dependent on order. Redirected to the `need_update` flow.
        # self.history_view.update_tx_item(tx_hash, header, tsc_proof)

    def _on_payment_requests_paid(self, event_name: str, paymentrequest_ids: list[int]) -> None:
        self.payment_requests_paid_signal.emit(paymentrequest_ids)

    def _on_account_created(self, event_name: str, new_account_id: int,
            flags: AccountInstantiationFlags) -> None:
        account = self._wallet.get_account(new_account_id)
        assert account is not None

        self._wallet.create_gui_handler(self, account)

        self.account_created_signal.emit(new_account_id, account)
        self.set_active_account(account)

        if self.network is not None and flags & AccountInstantiationFlags.NEW == 0 and \
                (account.is_deterministic() or
                    flags & (AccountInstantiationFlags.IMPORTED_PRIVATE_KEYS|
                AccountInstantiationFlags.IMPORTED_ADDRESSES) != 0):
            # This delays the opening of the account restoration UI as otherwise the account
            # wizard window does not close.
            self.account_restoration_signal.emit(RestorationDialogRole.ACCOUNT_CREATION)

    def set_active_account(self, account: Optional[AbstractAccount]) -> None:
        if self._account is account:
            return

        account_id: Optional[int] = None
        if account is not None:
            account_id = account.get_id()
        self._account_id = account_id
        self._account = account
        self._update_active_account()

    # ShowHomeSectionOnStartup
    def _update_active_account(self, startup: bool=False) -> None:
        # Update the console tab.
        self.console.updateNamespace({ 'account': self._account })
        self._reset_menus(self._account_id)
        self._reset_send_tab()

        # Reset these tabs:
        # - The history tab.
        # - The local transactions tab.
        # - The UTXO tab.
        # - The coin-splitting tab.
        # - The keys tab.
        self.account_change_signal.emit(self._account_id, self._account, startup)
        # - The receive tab.
        self._reset_receive_tab()

        if self.is_receive_view_active():
            assert isinstance(self._receive_view, ReceiveView)
            self._receive_view.update_contents()

        # Update the status bar, and maybe the tab contents. If we are mid-synchronisation the
        # tab contents will be skipped, but that's okay as the synchronisation completion takes
        # care of triggering an update.
        self._update_account_specific_event.set()
        self._update_common_event.set()

    def _on_show_secured_data(self, account_id: int) -> None:
        main_window_proxy: ElectrumWindow = weakref.proxy(self)
        self._navigation_view._view_secured_data(main_window_proxy=main_window_proxy,
            account_id=account_id)

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

        # History tab needs updating if it used spot
        assert app_state.fx is not None
        if app_state.fx.history_used_spot:
            self.update_history_view()

    def toggle_tab(self, tab: TabWidget, desired_state: Optional[bool]=None,
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
                        if tab.tab_pos < cast(TabWidget, self._tab_widget.widget(i)).tab_pos:
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

    def push_top_level_window(self, window: QDialog) -> None:
        """
        Used for e.g. tx dialog box to ensure new dialogs are appropriately parented to them,
        and not their wallet window.  This used to be done by explicitly providing the parent
        window, but that isn't something hardware wallet prompts know.

        This is of course horrendously sloppy and the correct fix would be to fix hardware
        wallets.
        """
        # TODO(cleanup) See if it is possible to fix up the hardware wallet situation and remove
        #   this hack.
        self.tl_windows.append(window)

    def pop_top_level_window(self, window: "QDialog") -> None:
        self.tl_windows.remove(window)

    def top_level_window(self) -> QWidget:
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
        self.activateWindow()

    def on_exception(self, exception: BaseException) -> None:
        if not isinstance(exception, UserCancelled):
            self._logger.exception("")
            self.show_error(str(exception))

    def on_error(self, exc_info: ExceptionInfoType) -> None:
        self.on_exception(exc_info[1])

    def on_network(self, event: NetworkEventNames, *args: Any) -> None:
        if event == NetworkEventNames.GENERIC_UPDATE:
            self._update_account_specific_event.set()
            self._update_common_event.set()
            return

        if event in [ NetworkEventNames.GENERIC_STATUS, NetworkEventNames.BANNER ]:
            # Handle in GUI thread
            self.network_signal.emit(event, args)
        else:
            self._logger.debug("unexpected network message event='%s' args='%s'", event, args)

    def on_network_qt(self, event: NetworkEventNames, args: Any=None) -> None:
        # Handle a network message in the GUI thread
        if event == NetworkEventNames.GENERIC_STATUS:
            self.update_status_bar()
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

    def init_geometry(self) -> None:
        winpos = self._wallet.get_storage().get("winpos-qt")
        if winpos is not None:
            try:
                screen = self.app.primaryScreen().geometry()
                assert screen.contains(QRect(*winpos))
                self.setGeometry(*winpos)
            except Exception:
                self._logger.exception("using default geometry")
                winpos = None
        if winpos is None:
            self.setGeometry(100, 100, 840, 400)

        splitter_sizes = self._wallet.get_storage().get("split-sizes-qt")
        self._navigation_view.init_geometry(splitter_sizes)

    def _update_window_title(self) -> None:
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

    def _backup_wallet(self) -> None:
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

    def update_recently_visited(self, filename: str) -> None:
        default_recent: List[str] = []
        recent = self.config.get_explicit_type(list, 'recently_open', default_recent)
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
            wallet_folder = ""
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
        file_menu.addAction(_("&Open"), self._open_wallet).setShortcut(
            QKeySequence.StandardKey.Open)
        file_menu.addAction(_("&New"), self._new_wallet).setShortcut(QKeySequence.StandardKey.New)
        # TODO(rt12): See the `_backup_wallet` function.
        save_copy_action = file_menu.addAction(_("&Save Copy"), self._backup_wallet)
        save_copy_action.setShortcut(QKeySequence.StandardKey.SaveAs)
        save_copy_action.setEnabled(False)
        file_menu.addSeparator()
        import_submenu = file_menu.addMenu(_("&Import"))
        import_submenu.addAction(_("&Transaction"), self._show_transaction_from_file)
        file_menu.addSeparator()
        # NOTE(typing) `close` has an incorrect signature for `addAction`, not that it matters.
        file_menu.addAction(_("&Quit"), self.close) # type: ignore

        wallet_menu = menubar.addMenu(_("&Wallet"))
        wallet_menu.addAction(_("&Information"), self._show_wallet_information)
        wallet_menu.addSeparator()

        self.password_menu = wallet_menu.addAction(_("Change &password"),
            self._change_password_dialog)
        self._secured_data_menu = wallet_menu.addAction(_("&Secured data"),
            self._view_wallet_secured_data)
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
            assert self._account is not None
            self._navigation_view.add_menu_items(self._account_menu, self._account, weakself)

        # Make sure the lambda reference does not prevent garbage collection.
        def add_toggle_action(view_menu: QMenu, tab: TabWidget) -> None:
            is_shown = self._tab_widget.indexOf(tab) > -1
            item_name = (_("Hide") if is_shown else _("Show")) + " " + tab.tab_description
            tab.menu_action = view_menu.addAction(item_name,
                cast(Callable[..., None], lambda: weakself.toggle_tab(tab)))

        view_menu = menubar.addMenu(_("&View"))
        add_toggle_action(view_menu, self.keys_tab)
        add_toggle_action(view_menu, self.utxo_tab)
        add_toggle_action(view_menu, self.coinsplitting_tab)

        tools_menu = menubar.addMenu(_("&Tools"))

        tools_menu.addAction(_("Preferences"), self.preferences_dialog)
        tools_menu.addAction(_("&Network"), self._show_network_dialog)
        tools_menu.addAction(_("&Log viewer"), self.app.show_log_viewer)

        devtools_key_combo = QKeyCombination(Qt.Modifier.SHIFT | Qt.Modifier.CTRL, Qt.Key.Key_I)
        devtools_action = tools_menu.addAction(_("Developer tools"),
            self._navigation_view.show_developer_tools)
        devtools_action.setShortcut(devtools_key_combo.key())

        tools_menu.addSeparator()
        tools_menu.addAction(_("&Sign/verify message"), self.sign_verify_message)
        tools_menu.addAction(_("&Encrypt/decrypt message"), self.encrypt_message)
        tools_menu.addSeparator()

        self._paytomany_menu = tools_menu.addAction(_("&Pay to many"), self.paytomany)

        raw_transaction_menu = tools_menu.addMenu(_("&View transaction"))
        raw_transaction_menu.addAction(_("From &file"), self._show_transaction_from_file)
        raw_transaction_menu.addAction(_("From &text"), self._show_transaction_from_text)
        blockchain_action = raw_transaction_menu.addAction(_("From the &blockchain"),
            self._show_transaction_from_txid)
        blockchain_action.setEnabled(self.network is not None)
        raw_transaction_menu.addAction(_("From &QR code"), self._show_transaction_from_qrcode)
        self.raw_transaction_menu = raw_transaction_menu

        help_menu = menubar.addMenu(_("&Help"))
        help_menu.addAction(_("&About"), self.show_about)
        help_menu.addAction(_("&Check for updates"), self.show_update_check)
        # NOTE(typing) The `webbrowser.open` signature does not match `addAction`.
        help_menu.addAction(_("&Official website"),
            cast(Callable[..., None], lambda: webbrowser.open("http://electrumsv.io")))
        help_menu.addSeparator()
        help_menu.addAction(_("Documentation"), self._open_documentation).setShortcut(
            QKeySequence.StandardKey.HelpContents)
        help_menu.addAction(_("&Report Bug"), self.show_report_bug)
        help_menu.addSeparator()

        self.setMenuBar(menubar)

        # The menus that rely on accounts should default to behaving as if there is no account.
        # They will get enabled if a first account is created, or the account list is loaded and
        # it has a default account to enable for initial display.
        self._reset_menus()

    def _reset_menus(self, account_id: Optional[int]=None) -> None:
        enable_spending_menus = False
        if account_id is not None:
            account = self._wallet.get_account(account_id)
            assert account is not None
            enable_spending_menus = account.can_spend()

        self._paytomany_menu.setEnabled(enable_spending_menus)

        if account_id is not None:
            self._account_menu.setEnabled(True)
            assert self._account is not None
            weakself = weakref.proxy(self)
            self._navigation_view.add_menu_items(self._account_menu, self._account, weakself)
        else:
            self._account_menu.clear()
            self._account_menu.setEnabled(False)

    def _show_network_dialog(self) -> None:
        # TODO(1.4.0) Networking, issue#905. WRT offline mode. Make the dialog offline friendly.
        # if not app_state.daemon.network:
        #     parent.show_warning(_('You are using ElectrumSV in offline mode; restart '
        #                           'ElectrumSV if you want to get connected'), title=_('Offline'))
        #     return
        if self._network_dialog is not None:
            self._network_dialog._event_network_updated()
            self._network_dialog.show()
            self._network_dialog.raise_()
            return

        # from importlib import reload
        # reload(network_dialog)
        self._network_dialog = NetworkDialog(self, self._wallet)
        self._network_dialog.show()

    def _open_documentation(self) -> None:
        webbrowser.open("https://electrumsv.readthedocs.io/")

    def init_toolbar(self) -> None:
        self.toolbar = toolbar = QToolBar(self)
        icon_size = int(self.app.dpi / 5.8)
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(icon_size, icon_size))
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)

        self._add_account_action = QAction(read_QIcon("icons8-add-folder-80.png"),
            _("Add Account"), self)
        self._add_account_action.triggered.connect(self.show_account_creation_wizard)
        toolbar.addAction(self._add_account_action)
        self._add_account_action.setEnabled(True)

        # make_payment_action = QAction(read_QIcon("icons8-initiate-money-transfer-80.png"),
        #     _("Make Payment"), self)
        # make_payment_action.triggered.connect(self.new_payment)
        # toolbar.addAction(make_payment_action)

        spacer = QWidget(self)
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        spacer.setVisible(True)
        self.spacer_action = toolbar.addWidget(spacer)

        # TODO(1.4.0) User experience, issue#909. WRT updates. Make sure this is revisited and
        #     reused if possible.
        # self._update_check_state = "default"
        # update_action = QAction(
        #     read_QIcon("icons8-available-updates-80-blue"), _("Update Check"), self)
        # update_action.triggered.connect(self._update_show_menu)
        # self._update_action = update_action
        # toolbar.addAction(update_action)
        # self._update_check_toolbar_update()

        # toolbar.insertSeparator(update_action)

        self.addToolBar(toolbar)
        self.setUnifiedTitleAndToolBarOnMac(True)

    def add_toolbar_action(self, action: QAction) -> None:
        self.toolbar.insertAction(self.spacer_action, action)

    def _update_show_menu(self, checked: bool = False) -> None:
        pass
        # self._update_menu.exec(QCursor.pos())

    # TODO(1.4.0) User experience, issue#909. WRT updates. Make sure this is revisited and reused
    #     if possible.
    # def _update_check_toolbar_update(self) -> None:
    #     update_check_state = "default"
    #     check_result: Optional[ReleaseDocumentType] = self.config.get('last_update_check')
    #     stable_version = "?"
    #     release_date: Optional[datetime.datetime] = None
    #     if check_result is not None:
    #         # The latest stable release date, the date of the build we are using.
    #         stable_result = check_result["stable"]
    #         stable_signers = get_identified_release_signers(stable_result)
    #         if stable_signers:
    #             release_date, current_date = get_update_check_dates(stable_result["date"])
    #             if release_date > current_date:
    #                 if time.time() - release_date.timestamp() < 24 * 60 * 60:
    #                     update_check_state = "update-present-immediate"
    #                 else:
    #                     update_check_state = "update-present-prolonged"
    #             stable_version = stable_result["version"]

    #     def _on_view_pending_update(checked: bool=False) -> None:
    #         QDesktopServices.openUrl(QUrl("https://electrumsv.io/download.html"))

    def _on_check_for_updates(self, checked: bool=False) -> None:
        self.show_update_check()

    # Called via `SVApplication._start` setup.
    def on_update_check(self, success: bool, result: UpdateCheckResultType) -> None:
        if success:
            assert isinstance(result, dict)
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
                self.update_required_signal.emit()

    def show_account_creation_wizard(self) -> None:
        main_window_proxy: ElectrumWindow = weakref.proxy(self)
        from . import account_wizard
        from importlib import reload
        reload(account_wizard)
        wizard_window = account_wizard.AccountWizard(main_window_proxy)
        wizard_window.show()

    def _on_account_restoration_signal(self, scan_role: RestorationDialogRole) -> None:
        # We have to delay the opening of the account restoration UI in the case of the
        # account wizard as otherwise the account wizard does not close.
        QTimer.singleShot(500, partial(self.restore_active_account, scan_role))

    def restore_active_account_manual(self) -> None:
        self.restore_active_account(RestorationDialogRole.MANUAL_RESCAN)

    def restore_active_account(self, scan_role: RestorationDialogRole) -> None:
        """
        Display the blockchain scanning UI for the active account.

        This is displayed in two different circumstances:
        - The user creates a new account that uses deterministic key derivation.
        - The user clicks the button in the toolbar.
        """
        assert self._account_id is not None
        assert self._account is not None

        from . import account_restoration_dialog
        # from importlib import reload # TODO(dev-helper) Remove at some point.
        # reload(account_restoration_dialog)
        dialog = account_restoration_dialog.AccountRestorationDialog(weakref.proxy(self),
            self._wallet, self._account_id, scan_role)
        dialog.show()

    def new_payment(self) -> None:
        from . import payment
        from importlib import reload
        reload(payment)
        self.w = payment.PaymentWindow(self._api, parent=self)
        self.w.show()

    def has_connected_blockchain_server(self) -> bool:
        return self._wallet.is_connected_to_blockchain_server()

    def show_about(self) -> None:
        QMessageBox.about(self, "ElectrumSV",
            _("Version")+" %s" % PACKAGE_VERSION + "\n\n" +
            _("ElectrumSV's focus is speed, with low resource usage and simplifying "
              "Bitcoin SV. Startup times are instant because it operates in "
              "conjunction with high-performance servers that handle the most complicated "
              "parts of the Bitcoin SV system."  + "\n\n" +
              _("Uses icons from the Icons8 icon pack (icons8.com).")))

    def show_update_check(self) -> None:
        from . import update_check
        update_dialog = update_check.UpdateCheckDialog(self)
        update_dialog.setModal(True)
        update_dialog.raise_()
        update_dialog.show()

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
        if self._wallet.is_connected_to_blockchain_server():
            num_txns = len(self.tx_notifications)
            if num_txns:
                # Combine the transactions
                total_amount = 0
                total_delta = 0
                for tx in self.tx_notifications:
                    if tx:
                        for result in self._wallet.data.get_transaction_deltas(tx.hash()):
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
            when = int((self.notify_tx_rate - elapsed) * 1e3) # time in ms
            self._logger.debug("Notify spam control: will notify GUI of %d new tx's in %f seconds",
                              len(self.tx_notifications), when)
            self.tx_notify_timer.start(when)
        else:
            # it's been a while since we got a tx notify -- so do it immediately (no timer
            # necessary)
            self._notify_tx_cb()

    def notify(self, message: str) -> None:
        self.app.tray.showMessage("ElectrumSV", message,
                                  read_QIcon("electrum_dark_icon"), 20000)

    # custom wrappers for getOpenFileName and getSaveFileName, that remember the path
    # selected by the user
    def getOpenFileName(self, title: str, filter: str="") -> str:
        directory = self.config.get_explicit_type(str, 'io_dir', os.path.expanduser('~'))
        fileName, __ = QFileDialog.getOpenFileName(self, title, directory, filter)
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def getOpenFileNames(self, title: str, filter: str="") -> list[str]:
        directory = self.config.get_explicit_type(str, 'io_dir', os.path.expanduser('~'))
        fileNames, __ = QFileDialog.getOpenFileNames(self, title, directory, filter)
        if fileNames and directory != os.path.dirname(fileNames[0]):
            self.config.set_key('io_dir', os.path.dirname(fileNames[0]), True)
        return fileNames

    def getSaveFileName(self, title: str, filename: str, filter: str="",
            parent: Optional[QWidget]=None) -> str:
        parent = self if parent is None else parent
        directory = self.config.get_explicit_type(str, 'io_dir', os.path.expanduser('~'))
        path = os.path.join( directory, filename)
        fileName, _selectedFilter = QFileDialog.getSaveFileName(parent, title, path, filter)
        if fileName and directory != os.path.dirname(fileName):
            self.config.set_key('io_dir', os.path.dirname(fileName), True)
        return fileName

    def timer_actions(self) -> None:
        # Note this runs in the GUI thread
        if self._update_account_specific_event.is_set():
            self._update_account_specific_event.clear()
            self._refresh_account_specific_ui()

        if self._update_common_event.is_set():
            self._update_common_event.clear()
            self._refresh_common_ui()

        if self.is_send_view_active():
            assert isinstance(self._send_view, SendView)
            self._send_view.on_timer_action()

    def format_fee_rate(self, fee_rate: int) -> str:
        return format_fee_satoshis(fee_rate//1000, app_state.num_zeros) + ' sat/B'

    def connect_fields(self, btc_edit: BTCAmountEdit, fiat_edit: AmountEdit) -> None:
        def edit_changed(edit: AmountEdit) -> None:
            if edit.in_event:
                return

            edit.setStyleSheet(ColorScheme.DEFAULT.as_stylesheet())
            fiat_edit.is_last_edited = (edit == fiat_edit)
            amount = edit.get_amount()
            rate = app_state.fx.exchange_rate() if app_state.fx else None
            if rate is None or amount is None:
                if edit is fiat_edit:
                    btc_edit.setText("")
                else:
                    fiat_edit.setText("")
            else:
                assert app_state.fx is not None
                if edit is fiat_edit:
                    btc_edit.in_event = True
                    btc_edit.setAmount(int(amount / Decimal(rate) * COIN))
                    btc_edit.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
                    btc_edit.in_event = False
                else:
                    fiat_edit.in_event = True
                    fiat_edit.setText(
                        app_state.fx.ccy_amount_str(amount * Decimal(rate) / COIN, False))
                    fiat_edit.setStyleSheet(ColorScheme.BLUE.as_stylesheet())
                    fiat_edit.in_event = False

        fiat_edit.is_last_edited = False
        fiat_edit.in_event = False
        fiat_edit.textChanged.connect(partial(edit_changed, fiat_edit))
        btc_edit.in_event = False
        btc_edit.textChanged.connect(partial(edit_changed, btc_edit))

    async def _update_network_status_loop(self) -> None:
        while True:
            # Only update the network status once a second (arbitrary amount of time).
            seconds_passed = time.time() - self._last_network_status_change
            if seconds_passed < 1.0:
                await asyncio.sleep(1.0 - seconds_passed)

            self._last_network_status_change = time.time()
            self.network_status_signal.emit()

            # Wait for all the events that can change something that should result in a change
            # in network status.
            awaitables = [
                # The wallet is updating it's local chain.
                self._wallet.local_chain_update_event.wait(),
                # If there is a blockchain server and its connection state changes.
                self._wallet.progress_event.wait(),
            ]
            if self.network is not None:
                # A new server has connected (might be the blockchain one reconnecting).
                awaitables.append(self.network.new_server_ready_event.wait())
                # A server has lost connection (might be the blockchain one disconnecting).
                awaitables.append(self.network.lost_server_connection_event.wait())
            # We have a timeout so that we can indicate that we might be lagging if we have
            # not had any events, but no headers have been received recently.
            await asyncio.wait(awaitables, timeout=4*60, return_when=asyncio.FIRST_COMPLETED)

    def _on_keys_updated(self, account_id: int, keyinstance_ids: List[int]) -> None:
        self.update_status_bar()
        self._navigation_view.refresh_account_balances()

    @profiler
    def refresh_wallet_display(self) -> None:
        self._refresh_common_ui()
        self._refresh_account_specific_ui()

    def _refresh_common_ui(self) -> None:
        self.update_status_bar()
        self._navigation_view.refresh_account_balances()
        self._navigation_view.refresh_notifications()

    def _refresh_account_specific_ui(self) -> None:
        if not self.network or self._wallet.is_synchronized() or \
                not self._wallet.is_connected_to_blockchain_server():
            self.update_tabs()

    def update_status_bar(self) -> None:
        "Update the entire status bar."
        fiat_status: Optional[Tuple[Optional[str], Optional[str]]] = None
        # Display if offline. Display if online. Do not display if synchronizing.
        if self._wallet.is_connected_to_blockchain_server():
            # append fiat balance and price
            assert app_state.fx is not None
            if app_state.fx.is_enabled():
                balance = 0
                for account in self._wallet.get_accounts():
                    balance += account.get_balance().confirmed
                fiat_status = app_state.fx.get_fiat_status(
                    balance, app_state.base_unit(), app_state.decimal_point)
        self.status_bar.set_fiat_status(fiat_status)
        self._update_network_status()

    def _update_network_status(self) -> None:
        """
        Update the network status portion of the status bar.
        """
        if self.network is None:
            self.status_bar.set_network_status(_("Offline"),
                _("You have started ElectrumSV in offline mode."))
            return

        if self._wallet.is_blockchain_server_active():
            # This is the header connection state for our designated blockchain server.
            wallet_blockchain_server_state = self._wallet.get_blockchain_server_state()
            if wallet_blockchain_server_state is None:
                self.status_bar.set_network_status(_("Blockchain server not connected yet.."),
                    _("No connection has been established to the selected blockchain server yet."))
            else:
                # This is the reference server connection for our designated blockchain server.
                server_state = self._wallet.get_connection_state_for_usage(
                    NetworkServerFlag.USE_BLOCKCHAIN)
                if server_state is None:
                    self.status_bar.set_network_status(
                        _("Waiting to connect to blockchain server.."),
                        _("Attempting to connect to the selected server."))
                elif server_state.connection_flags & ServerConnectionFlag.WEB_SOCKET_READY:
                    # The wallet is following the chain of the fully connected blockchain server.
                    server_chain_tip = wallet_blockchain_server_state.tip_header
                    server_height = 0 if server_chain_tip is None else server_chain_tip.height
                    server_lag = self.network.get_local_height() - server_height
                    if server_height == 0:
                        self.status_bar.set_network_status(
                            _("Blockchain server not synchronised yet.."),
                            _("The blockchain server is still providing information."))
                    elif server_lag > 1:
                        self.status_bar.set_network_status(
                            _("Blockchain server {} blocks behind").format(server_lag),
                            _("The blockchain server is lagging and not on the longest chain."))
                    else:
                        self.status_bar.set_network_status(
                            _("Blockchain server connected"),
                            _("The blockchain server connection looks good and it is up to date."))
                elif server_state.connection_flags & ServerConnectionFlag.ESTABLISHING_WEB_SOCKET:
                    self.status_bar.set_network_status(_("Connecting to blockchain server.."),
                        _("Making a web socket connection to the selected server."))
                elif server_state.connection_flags & ServerConnectionFlag.VERIFYING:
                    self.status_bar.set_network_status(_("Evaluating blockchain server.."),
                        _("Verifying the remote server state against the wallet.."))
                elif server_state.connection_flags & ServerConnectionFlag.DISCONNECTED:
                    self.status_bar.set_network_status(_("Disconnected"),
                        _("The blockchain server is not current connectable."))
                elif server_state.connection_flags & ServerConnectionFlag.INITIALISED:
                    self.status_bar.set_network_status(_("Blockchain server connection pending.."),
                        _("The process of connecting has not quite started yet."))
                else:
                    assert False, f"Connection flags not handled {server_state.connection_flags}"
        else:
            # The wallet is in theory following the longest chain.
            lagging_server = False
            for server_key in self.network.get_known_header_servers():
                if self.network.is_header_server_ready(server_key):
                    server_metadata = self.network.get_header_server_metadata(server_key)
                    if server_metadata.last_good >= server_metadata.last_try:
                        if server_metadata.last_good + 10*60 > time.time():
                            self.status_bar.set_network_status(_("Monitoring headers"),
                                _("The header server connections look okay."))
                            break
                        else:
                            lagging_server = True
            else:
                if lagging_server:
                    self.status_bar.set_network_status(_("Monitoring headers (possibly lagging)"),
                        _("The header server connections have not provided a recent header."))
                else:
                    self.status_bar.set_network_status(_("No connected header sources yet.."),
                        _("There are no header server connections currently."))

    def update_tabs(self, *args: Any) -> None:
        if self.is_receive_view_active():
            assert isinstance(self._receive_view, ReceiveView)
            self._receive_view.update_widgets()
        if self.is_send_view_active():
            assert isinstance(self._send_view, SendView)
            self._send_view.update_widgets()
        self.utxo_list.update()
        self.contact_list.update()
        self.update_history_view()

    def _create_navigation_view(self) -> WalletNavigationView:
        from .wallet_navigation_view import WalletNavigationView
        return WalletNavigationView(self, self._wallet)

    def create_history_tab(self) -> HistoryView:
        from .history_list import HistoryView
        self.history_view = HistoryView(self._navigation_view, self)
        return self.history_view

    def show_key(self, account: AbstractAccount, key_data: KeyDataProtocol,
            script_type: ScriptType) -> None:
        from . import key_dialog
        # from importlib import reload
        # reload(key_dialog)
        d = key_dialog.KeyDialog(self, account.get_id(), key_data, script_type)
        d.exec()

    def show_transaction(self, account: Optional[AbstractAccount], tx: Transaction,
            context: Optional[TransactionContext]=None, prompt_if_unsaved: bool=False,
            pr: Optional[dpp_messages.PaymentTerms]=None) -> TxDialog:
        self._wallet.ensure_incomplete_transaction_keys_exist(tx)
        from . import transaction_dialog
        # from importlib import reload
        # reload(transaction_dialog)
        tx_dialog = transaction_dialog.TxDialog(account, tx, context, self, prompt_if_unsaved, pr)
        tx_dialog.finished.connect(partial(self.on_tx_dialog_finished, tx_dialog))
        self.tx_dialogs.append(tx_dialog)
        tx_dialog.show()
        return tx_dialog

    def on_tx_dialog_finished(self, tx_dialog: TxDialog, status: int) -> None:
        tx_dialog.finished.disconnect()
        self.tx_dialogs.remove(tx_dialog)

    def is_send_view_active(self) -> bool:
        return bool(self._send_view is not None and self._account is not None and \
            self._account.can_spend())

    def is_receive_view_active(self) -> bool:
        return bool(isinstance(self._receive_view, ReceiveView) and self._account_id is not None)

    def _reset_send_tab(self) -> None:
        self._send_view = self._reset_stacked_tab(self.send_tab, self.get_send_view)
        current_tab_index = self._tab_widget.currentIndex()
        self._on_tab_changed(current_tab_index)

    def _reset_receive_tab(self) -> None:
        self._receive_view = self._reset_stacked_tab(self.receive_tab, self.get_receive_view)

    def _reset_stacked_tab(self, stack_tab: QStackedWidget, create_func: Callable[[int], T]) \
            -> Optional[T]:
        current_widget = stack_tab.currentWidget()
        assert current_widget is not None, "Should be unavailable or a view of the correct type"

        if self._account_id is None:
            assert isinstance(current_widget, QWidget)
            return None

        view = create_func(self._account_id)
        view_widget = cast(QWidget, view)
        widget_index = stack_tab.indexOf(view_widget)
        if widget_index == -1:
            stack_tab.addWidget(view_widget)
        stack_tab.setCurrentWidget(view_widget)
        return view

    def _create_account_unavailable_layout(self, text: Optional[str]=None) -> QVBoxLayout:
        if text is None:
            text = _("No active account.")

        label_title = WWLabel(_("<p>"+ text +"</p>"))
        label_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

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
        view = None if account_id is None else self._send_views.get(account_id)
        if view is None:
            text: Optional[str] = None
            if account_id is not None:
                account = self._wallet.get_account(account_id)
                assert account is not None
                if account.can_spend():
                    view = SendView(self, account_id)
                else:
                    text = _("This functionality is not available for this type of account.")
            if view is None:
                view = QWidget()
                view.setLayout(self._create_account_unavailable_layout(text))
            if account_id is not None:
                self._send_views[account_id] = view
        return view

    def get_receive_view(self, account_id: Optional[int]) -> ReceiveViewTypes:
        view = None if account_id is None else self._receive_views.get(account_id)
        if view is None:
            text: Optional[str] = None
            if account_id is not None:
                account = self._wallet.get_account(account_id)
                assert account is not None
                if account.type() in \
                        { AccountType.IMPORTED_ADDRESS, AccountType.IMPORTED_PRIVATE_KEY }:
                    text = _("This functionality is not available for this type of account.")
                else:
                    view = ReceiveView(self, account_id)
            if view is None:
                view = QWidget()
                view.setLayout(self._create_account_unavailable_layout(text))
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

    def get_contact_payto(self, contact_id: int) -> str:
        contact = self.contacts.get_contact(contact_id)
        assert contact is not None
        return contact.label

    def confirm_broadcast_transaction(self, tx_hash: bytes, source: UIBroadcastSource) -> bool:
        # This function is intended to centralise the checks related to whether it is okay to
        # broadcast a transaction prior to calling `broadcast_transaction` on this wallet window.
        # Pass in the context of the call and check against the relevant contexts.

        # Skip confirmation for transactions loaded for broadcast.
        flags = self._wallet.data.get_transaction_flags(tx_hash)
        if flags is None:
            return True

        if flags & TxFlags.PAYS_INVOICE and source == UIBroadcastSource.TRANSACTION_DIALOG:
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

            assert self._account is not None
            assert isinstance(self._send_view, SendView)

            invoice_row = self._account._wallet.data.read_invoice(tx_hash=tx_hash)
            if invoice_row is None:
                if not self.question(_("This transaction is associated with a deleted invoice.") +
                        "<br/><br/>" + body_text,
                        icon=QMessageBox.Icon.Warning):
                    return False
            elif dpp_messages.has_expired(invoice_row.date_expires):
                if not self.question(_("This transaction is associated with an expired invoice.") +
                        "<br/><br/>" + body_text,
                        icon=QMessageBox.Icon.Warning):
                    return False
            elif (self._send_view._payment_request is None or
                    self._send_view._payment_request.get_id() != invoice_row.invoice_id):
                self.show_error(_("This transaction is associated with an invoice, but cannot "
                    "be broadcast as it is not active on the send tab. Go to the send tab and "
                    "select it from the invoice list and choose the 'Pay now' option."))
                return False

        return True

    @protected
    def sign_tx(self, tx: Transaction, callback: Callable[[bool], None],
            password: Optional[str]=None,
            window: Optional[QWidget]=None, context: Optional[TransactionContext]=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) -> None:
        # NOTE(typing) The decorator wrapper will inject a password argument to the decoratee the
        #   caller of the decorated function does not provide. So we do not require the password
        #   argument so that typing works, but reject the call if it is not there.
        assert password is not None
        self.sign_tx_with_password(tx, callback, password, window=window, context=context,
            import_flags=import_flags)

    def sign_tx_with_password(self, tx: Transaction, callback: Callable[[bool], None],
            password: str, window: Optional[QWidget]=None,
            context: Optional[TransactionContext]=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) -> None:
        '''Sign the transaction in a separate thread.  When done, calls
        the callback with a success code of True or False.'''
        usable_accounts = [ account for account in self._wallet.get_visible_accounts()
            if account.can_sign(tx) ]
        assert len(usable_accounts) > 0
        account = usable_accounts[0]

        def on_done(future: concurrent.futures.Future[None]) -> None:
            try:
                future.result()
            except Exception as exc:
                self.on_exception(exc)
                callback(False)
            else:
                callback(True)

        def sign_tx(update_cb: WaitingUpdateCallback) -> None:
            future = account.sign_transaction(tx, password, context=context,
                import_flags=import_flags)
            if future is not None:
                future.result()
            update_cb(False, _("Done."))

        window = window or self
        WaitingDialog(window, _('Signing transaction...'), sign_tx, on_done=on_done,
            title=_("Transaction signing"))

    def broadcast_transaction(self, account: AbstractAccount | None, tx: Transaction,
            context: Optional[TransactionContext]=None,
            success_text: Optional[str]=None, window: Optional[QWidget]=None) -> None:
        send_view = cast(SendView, self._send_view)
        final_success_text = _('Payment sent.') if success_text is None else success_text
        window = window or self

        def broadcast_tx(update_cb: WaitingUpdateCallback) -> bool:
            """This all gets run in a thread so blocking is acceptable"""
            # Ensure we are not in offline mode.
            assert self.network is not None

            # Non-GUI thread. Is the broadcast done through invoicing payment delivery instead?
            if send_view.is_invoice_payment():
                send_invoice_payment_success = send_view.send_invoice_payment(tx)
                if not send_invoice_payment_success:
                    # The invoice payment delivery either did not happen because the invoice was no
                    # longer valid, or for some other reason.
                    return False
                return True
            else:
                broadcast_response, peer_channel_info, peer_channel_server_state = \
                    app_state.async_.spawn_and_wait(
                        self._wallet.broadcast_transaction_async(tx, context))
                update_cb(False, _("Done."))
                return broadcast_response["returnResult"] == "success"

        def on_done(future: concurrent.futures.Future[bool]) -> None:
            assert window is not None
            # GUI thread
            try:
                was_broadcast = future.result()
            except concurrent.futures.CancelledError:
                cast(MessageBoxMixin, window).show_error(
                    _("Transaction broadcast failed.") +"<br/><br/>"+
                    _("The most likely reason for this is that there is no available connection "
                    "to a main server. The signed transaction can be found in the "
                    "Transactions tab and can be rebroadcast from there."), )
            except Exception as exception:
                self._logger.exception('unhandled exception broadcasting transaction')
                reason = str(exception)
                d = UntrustedMessageDialog(
                    window, _("Transaction Broadcast Error"),
                    _("Your transaction was not sent: ") + reason +".", exception)
                d.exec()
            else:
                if was_broadcast:
                    tx_id = tx.txid()
                    assert tx_id is not None
                    cast(MessageBoxMixin, window).show_message(final_success_text + '\n' + tx_id)
                    send_view.clear()

        WaitingDialog(window, _('Broadcasting the transaction..'), broadcast_tx,
            on_done=on_done, title=_("Transaction broadcast"))

    def pay_to_URI(self, URI: str) -> None:
        if not URI:
            return

        if self._send_view is None:
            self.show_error(_("No active account."))
            return

        send_view = cast(SendView, self.get_send_view(self._account_id))

        try:
            parsed_url = urllib.parse.urlparse(URI)
        except Exception as parse_error:
            logger.debug("Error processing payment URI", exc_info=parse_error)
            self.show_error(_("Unable to process the provided URL"))
            return

        if parsed_url.scheme == "pay":
            try:
                payment_url, receiver_address = web.parse_pay_url(URI)
            except ValueError as value_error:
                self.show_error(str(value_error))
                return

            def get_payment_terms_thread() -> None:
                from ... import dpp_messages
                from ...exceptions import Bip270Exception
                try:
                    request = dpp_messages.get_payment_terms(payment_url, receiver_address)
                except Bip270Exception as e:
                    send_view.payment_request_import_error(e.args[0])
                    return
                send_view.on_payment_request(request, receiver_address)
            t = threading.Thread(target=get_payment_terms_thread)
            t.setDaemon(True)
            t.start()

            send_view.prepare_for_payment_request()
        else:
            try:
                out = web.parse_URI(URI)
            except Exception as e:
                self.show_error(str(e))
                return
            send_view.set_processed_url_data(out)

        self.show_send_tab()

    def show_invoice(self, account: AbstractAccount, row: InvoiceRow) -> None:
        from .invoice_dialog import InvoiceDialog
        d = InvoiceDialog(self, row)
        d.exec()

    def delete_invoice(self, invoice_id: int) -> None:
        send_view = self.get_send_view(self._account_id)
        # TODO(1.4.0) Invoicing. `SendView` does not have `delete_invoice`.
        # assert isinstance(send_view, SendView)
        # send_view.delete_invoice(invoice_id)

    def pay_invoice(self, invoice_id: int) -> None:
        send_view = self.get_send_view(self._account_id)
        assert isinstance(send_view, SendView)
        send_view.invoice_list.pay_invoice(invoice_id)

    def set_frozen_coin_state(self, account: AbstractAccount, txo_keys: List[Outpoint],
            freeze: bool) -> concurrent.futures.Future[bool]:
        """
        Encapsulate the blocking action of freezing or unfreezing coins.
        """
        def callback(future: concurrent.futures.Future[bool]) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()

            # Apply the visual effects of coins being frozen or unfrozen.
            if self.key_view:
                self.key_view.update_frozen_transaction_outputs(txo_keys, freeze)

            # NOTE This callback will be happening in the database thread. No UI calls should
            #   be made within it, unless we explicitly emit a signal to do it.
            def ui_callback(args: Any) -> None:
                self.utxo_list.update()
                send_view = cast(SendView, self.get_send_view(account.get_id()))
                # This will refresh the send view for selected coins.
                send_view.update_fee()
            self.ui_callback_signal.emit(ui_callback, ())

        # Attempt to make the change.
        future = account.get_wallet().data.update_transaction_output_flags(
            txo_keys, TransactionOutputFlag.FROZEN)
        future.add_done_callback(callback)

        return future

    def create_coinsplitting_tab(self) -> "CoinSplittingTab":
        from .coinsplitting_tab import CoinSplittingTab
        return CoinSplittingTab(self)

    def create_list_tab(self, list_widget: QWidget) -> TabWidget:
        top_button_layout: Optional[TableTopButtonLayout] = None

        w = TabWidget()
        if hasattr(list_widget, "filter"):
            top_button_layout = TableTopButtonLayout()
            if hasattr(list_widget, "reset_table"):
                top_button_layout.refresh_signal.connect(
                    list_widget.reset_table) # type: ignore[attr-defined]
            else:
                top_button_layout.refresh_signal.connect(self.refresh_wallet_display)
            top_button_layout.filter_signal.connect(list_widget.filter) # type: ignore[attr-defined]
            w.on_search_toggled = partial( # type: ignore[attr-defined]
                top_button_layout.on_toggle_filter)

        vbox = QVBoxLayout()
        w.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.setSpacing(0)
        if top_button_layout is not None:
            vbox.addLayout(top_button_layout)
        vbox.addWidget(list_widget)

        if hasattr(list_widget, "update_top_button_layout"):
            list_widget.update_top_button_layout(top_button_layout) # type: ignore[attr-defined]

        return w

    def create_keys_tab(self) -> TabWidget:
        from .keys_view import KeyView
        self.key_view = l = KeyView(self)
        return self.create_list_tab(l)

    def create_utxo_tab(self) -> TabWidget:
        from .utxo_list import UTXOList
        self.utxo_list = l = UTXOList(self._navigation_view, self)
        return self.create_list_tab(l)

    def create_contacts_list(self) -> ContactList:
        """
        Called by the wallet navigation view to create and obtain this element.
        """
        self.contact_list = l = ContactList(self._api, self)
        return l

    def spend_coins(self, coins: Iterable[TransactionOutputSpendableProtocol]) -> None:
        assert isinstance(self._send_view, SendView)
        self._send_view.set_pay_from(coins)
        self.show_send_tab()
        self._send_view.update_fee()

    def paytomany(self) -> None:
        self.show_send_tab()
        if isinstance(self._send_view, SendView):
            self._send_view.paytomany()

    def _on_contacts_changed(self) -> None:
        self.contact_list.update()
        self.update_history_view()

    def create_console(self) -> Console:
        self.console = console = Console()
        return console

    def update_console(self) -> None:
        console = self.console
        console.history = cast(List[str], self.config.get("console-history", []))
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
        def mkfunc(f: Callable[[Arg(str, "method_name"), VarArg(Any),
                DefaultNamedArg(Optional[Callable[[], Optional[str]]], "password_getter"),
                KwArg(Any)], Any], method: str) -> Any:
            return lambda *args, **kwargs: f(method, *args, password_getter=self.password_dialog,
                                             **kwargs)
        for m in dir(c):
            if m[0] == '_' or m in ['network', 'wallet', 'config']:
                continue
            methods[m] = mkfunc(c._run, m)

        console.updateNamespace(methods)

    def create_status_bar(self) -> None:
        from .status_bar import StatusBar
        self.status_bar = StatusBar(self)
        self.update_status_bar()
        self.setStatusBar(self.status_bar)

    def _change_password_dialog(self) -> None:
        from .password_dialog import ChangePasswordDialog
        storage = self._wallet.get_storage()
        d = ChangePasswordDialog(self, password_check_fn=storage.is_password_valid)
        ok, password, new_password = d.run()
        if not ok:
            return
        assert password is not None
        assert new_password is not None
        try:
            self._wallet.update_password(password, new_password)
        except Exception:
            self._logger.exception("")
            self.show_error(_('Failed to update password'))
            return
        msg = (_('Password was updated successfully') if new_password
               else _('Password is disabled, this wallet is not protected'))
        self.show_message(msg, title=_("Success"))

    def _view_wallet_secured_data(self) -> None:
        # TODO(1.4.0) Wallet worst case scenario recovery data. issue#920
        self.show_error(_('Not yet implemented'))

    def _toggle_search(self) -> None:
        tab_parent = self._tab_widget.currentWidget()
        tab = tab_parent.currentWidget() if isinstance(tab_parent, QStackedWidget) else tab_parent

        if not hasattr(tab, 'on_search_toggled'):
            self.show_warning(_("The current tab does not support searching."))
            return

        tab.on_search_toggled() # type: ignore[attr-defined]

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
        name_edit.addCopyButton()

        path_edit = ButtonsLineEdit(wallet_dirpath)
        path_edit.setReadOnly(True)
        path_edit.addButton("icons8-opened-folder-windows.svg",
            partial(open_file_explorer, wallet_dirpath), _("View location in filesystem"))
        path_edit.addCopyButton()

        file_form = FormSectionWidget()
        file_form.add_row(_("File name"), name_edit)
        file_form.add_row(_("File path"), path_edit)
        vbox.addWidget(file_form)

        current_txcachesize_label = QLabel()
        maximum_txcachesize_label = QLabel()
        hits_label = QLabel()
        misses_label = QLabel()

        def update_txcachesizes() -> None:
            nonlocal current_txcachesize_label, maximum_txcachesize_label
            nonlocal hits_label, misses_label
            cache = self._wallet._transaction_cache2
            current_size, max_size = cache.get_sizes()
            current_txcachesize_label.setText(str(current_size))
            maximum_txcachesize_label.setText(str(max_size))
            hits_label.setText(str(cache.hits))
            misses_label.setText(str(cache.misses))
        update_txcachesizes()

        memory_usage_form = FormSectionWidget()
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
            dialog.exec()
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

    def show_qrcode(self, data: str, title: str=_("QR code"),
            parent: Optional[QWidget]=None) -> None:
        if not data:
            return
        d = QRDialog(data, parent or self, title)
        d.exec()

    @protected
    def show_private_key(self, account: AbstractAccount, keydata: KeyDataProtocol,
            script_type: ScriptType, password: str) -> None:
        try:
            privkey_text = account.export_private_key(keydata, password)
        except Exception as e:
            self._logger.exception("")
            self.show_message(str(e))
            return

        script_template = account.get_script_template_for_derivation(script_type,
            keydata.derivation_type, keydata.derivation_data2)

        d = WindowModalDialog(self, _("Private key"))
        d.setMinimumSize(600, 150)
        vbox = QVBoxLayout()
        vbox.addWidget(QLabel(_("Private key") + ':'))
        keys_e = ShowQRTextEdit(text=privkey_text)
        keys_e.addCopyButton()
        vbox.addWidget(keys_e)
        vbox.addWidget(QLabel(_("Payment script") + ':'))
        rds_e = ShowQRTextEdit(text=script_template_to_string(script_template))
        rds_e.addCopyButton()
        vbox.addWidget(rds_e)
        vbox.addLayout(Buttons(CloseButton(d)))
        d.setLayout(vbox)
        d.exec()

    @protected
    def do_sign(self, account: AbstractAccount, key_data: Optional[KeyDataProtocol],
            message: QTextEdit, signature: QTextEdit, password: str="") -> None:
        assert len(password), "password decorator failure"
        message_text = message.toPlainText().strip()
        if account.is_watching_only():
            self.show_message(_('This is a watching-only account.'))
            return

        if key_data is None:
            self.show_error(_("Signing messages with user-provided addresses is not supported at "
                "this time. Select the given key from the list in the Keys tab and use the "
                "context menu there to sign a message using it."))
            return

        def show_signed_message(sig: bytes) -> None:
            nonlocal signature
            # Empty signature indicates user exit.
            # Deleted signature object indicates that user pre-emptively closed widget.
            if not len(sig) or sip.isdeleted(signature):
                return
            signature.setText(base64.b64encode(sig).decode('ascii'))
        self.run_in_thread(account.sign_message, key_data, message_text, password,
            on_success=show_signed_message)

    def run_in_thread(self, func: Callable[..., T1], *args: Any,
            on_success: Optional[Callable[[T1], None]]=None) \
                -> concurrent.futures.Future[T1]:
        def _on_done(future: concurrent.futures.Future[T1]) -> None:
            try:
                result = future.result()
            except Exception as exc:
                self.on_exception(exc)
            else:
                if on_success:
                    on_success(result)
        return self.app.run_in_thread(func, *args, on_done=_on_done)

    def do_verify(self, account: AbstractAccount, key_data: Optional[KeyDataProtocol],
            address_widget: QLineEdit, message_widget: QTextEdit, signature: QTextEdit) -> None:
        if key_data is None:
            try:
                address = address_from_string(address_widget.text().strip())
            except Exception:
                self.show_message(_('Invalid Bitcoin SV address.'))
                return
        else:
            public_key = account.get_public_keys_for_derivation(
                key_data.derivation_type, key_data.derivation_data2)[0]
            address = public_key.to_address(network=Net.COIN)

        message_text = message_widget.toPlainText().strip()
        try:
            # This can throw on invalid base64
            sig = base64.b64decode(signature.toPlainText())
            verified = PublicKey.verify_message_and_address(sig, message_text, address)
        except Exception:
            verified = False

        if verified:
            self.show_message(_("Signature verified"))
        else:
            self.show_error(_("Wrong signature"))

    def sign_verify_message(self, account: Optional[AbstractAccount]=None,
            key_data: Optional[KeyDataProtocol]=None) -> None:
        # TODO(1.4.0) Accounts. We used to have a default account concept. There is no such thing
        #     any more.
        assert account is not None

        d = WindowModalDialog(self, _('Sign/verify Message'))
        d.setMinimumSize(610, 290)

        layout = QGridLayout(d)

        message_e = QTextEdit()
        message_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Message')), 1, 0)
        layout.addWidget(message_e, 1, 1)
        layout.setRowStretch(2,3)

        address_e = QLineEdit()
        if key_data is not None:
            address_e.setText(f"Key {key_data.keyinstance_id}")
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
        def do_sign(checked: bool=False) -> None:
            assert account is not None
            self.do_sign(account, key_data, message_e,signature_e) # pylint: disable=no-value-for-parameter
        b.clicked.connect(do_sign)
        hbox.addWidget(b)

        b = QPushButton(_("Verify"))
        b.clicked.connect(partial(self.do_verify, account, key_data, address_e, message_e,
            signature_e))
        hbox.addWidget(b)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)
        layout.addLayout(hbox, 4, 1)
        d.exec()

    @protected
    def do_decrypt(self, account: AbstractAccount, key_data: KeyDataProtocol, message_e: QTextEdit,
            encrypted_e: QTextEdit, password: Optional[str]) -> None:
        if account.is_watching_only():
            self.show_message(_('This is a watching-only account, and cannot decrypt.'))
            return

        cyphertext = encrypted_e.toPlainText()

        def show_decrypted_message(msg_bytes: bytes) -> None:
            message_e.setText(msg_bytes.decode())

        self.run_in_thread(account.decrypt_message, key_data, cyphertext, password,
            on_success=show_decrypted_message)

    def do_encrypt(self, account: AbstractAccount, key_data: Optional[KeyDataProtocol],
            message_e: QTextEdit, pubkey_e: QLineEdit, encrypted_e: QTextEdit) -> None:
        message = message_e.toPlainText()
        message_bytes = message.encode('utf-8')
        if key_data is not None:
            public_key = account.get_public_keys_for_derivation(key_data.derivation_type,
                key_data.derivation_data2)[0]
        else:
            try:
                public_key = PublicKey.from_hex(pubkey_e.text())
            except Exception as e:
                self._logger.exception("")
                self.show_warning(_('Invalid Public key'))
                return
        encrypted = public_key.encrypt_message_to_base64(message_bytes)
        encrypted_e.setText(encrypted)

    def encrypt_message(self, account: Optional[AbstractAccount]=None,
            key_data: Optional[KeyDataProtocol]=None) -> None:
        account = self._account if account is None else account
        assert account is not None

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

        if key_data is not None:
            pubkey_e.setText(f"Key {key_data.keyinstance_id}")
            pubkey_e.setReadOnly(True)

        encrypted_e = QTextEdit()
        encrypted_e.setAcceptRichText(False)
        layout.addWidget(QLabel(_('Encrypted')), 3, 0)
        layout.addWidget(encrypted_e, 3, 1)
        layout.setRowStretch(3,1)

        hbox = QHBoxLayout()
        b = QPushButton(_("Encrypt"))
        # NOTE(typing) Pylance seems incapable of detecting `account` is not None.
        b.clicked.connect(lambda: self.do_encrypt(account, key_data, message_e, # type: ignore
            pubkey_e, encrypted_e))
        hbox.addWidget(b)

        b = QPushButton(_("Decrypt"))
        def do_decrypt(checked: bool=False) -> None:
            # pylint: disable=no-value-for-parameter
            # NOTE(typing) The password decorator is not visible to Pylance.
            self.do_decrypt(account, key_data, message_e, encrypted_e) # type: ignore
        b.clicked.connect(do_decrypt)
        hbox.addWidget(b)

        b.setEnabled(key_data is not None)

        b = QPushButton(_("Close"))
        b.clicked.connect(d.accept)
        hbox.addWidget(b)

        layout.addLayout(hbox, 4, 1)
        d.exec()

    def password_dialog(self, msg: Optional[str]=None, parent: Optional[QWidget]=None,
            fields: Optional[LayoutFields]=None) -> Optional[str]:
        storage = self._wallet.get_storage()
        password = app_state.credentials.get_wallet_password(storage.get_path())
        if password is not None:
            return password

        from .password_dialog import PasswordDialog
        parent = parent or self
        d = PasswordDialog(parent, msg, storage.is_password_valid, fields=fields)
        password = d.run()
        if password is not None:
            app_state.credentials.set_wallet_password(storage.get_path(), password,
                CredentialPolicyFlag.FLUSH_ALMOST_IMMEDIATELY)
        return password

    def _show_transaction_from_qrcode(self) -> None:
        def callback(raw: bytes | None) -> None:
            assert raw is not None
            tx, tx_context = self._wallet.load_transaction_from_bytes(raw)
            if tx is not None:
                self.show_transaction(self._account, tx, tx_context)
        self.read_qrcode_and_call_callback(callback, expect_transaction=True)

    def read_qrcode_and_call_callback(self, result_callback: Callable[[bytes | None], None],
            expect_transaction: bool=False) -> None:
        def scan_callback(success: bool, error_text: str, text: str | None) -> None:
            if not success:
                if error_text:
                    self.show_error(error_text)
                return

            if expect_transaction:
                if not text:
                    return

                # First try base 43.
                try:
                    qrcode_bytes = bitcoin.base_decode(text, base=43)
                except ValueError:
                    # The text was not a valid base 43 encoded value.
                    pass
                else:
                    if qrcode_bytes.startswith(b"\x1f\x8b"):
                        raw = gzip.decompress(qrcode_bytes)
                    else:
                        raw = qrcode_bytes
                    result_callback(raw)
                    return

                # Next try base 64
                try:
                    qrcode_bytes = base64.b64decode(text, validate=True)
                except binascii.Error:
                    # The text was not a valid base 64 value.
                    pass
                else:
                    if qrcode_bytes.startswith(b"\x1f\x8b"):
                        raw = gzip.decompress(qrcode_bytes)
                    else:
                        raw = qrcode_bytes
                    result_callback(raw)
                    return

            self.show_error("Unable to decode QR code")

            # # if the user scanned a bitcoin URI
            # if web.is_URI(data):
            #     self.pay_to_URI(data)
            #     return

            # # else if the user scanned an offline signed tx
            # data_bytes = bitcoin.base_decode(data, base=43)
            # if data_bytes.startswith(b"\x1f\x8b"):
            #     text = gzip.decompress(data_bytes).decode()
            # else:
            #     text = data_bytes.hex()
            # return self._wallet.load_transaction_from_text(text)
        scan_qrcode(parent=self.top_level_window(), config=self.config, callback=scan_callback)

    def _show_transaction_from_text(self) -> None:
        tx, tx_context = self.prompt_obtain_transaction_from_text()
        if tx is not None:
            self.show_transaction(self._account, tx, tx_context)

    def prompt_obtain_transaction_from_text(self, *, ok_text: str | None=None) \
            -> tuple[Transaction | None, TransactionContext | None]:
        if ok_text is None:
            ok_text = _("View")
        text = text_dialog(self, _('Enter the raw transaction below..'), _("Transaction (hex):"),
            ok_text)
        if text is not None and len(text) != 0:
            try:
                raw = bytes.fromhex(text)
            except ValueError:
                self.show_critical(_("Unable to recognize the hex encoding."))
                return None, None

            try:
                return self._wallet.load_transaction_from_bytes(raw)
            except Exception as reason:
                self._logger.exception(reason)
                self.show_critical(_("ElectrumSV was unable to read the transaction:") +
                                "\n" + str(reason))
        return None, None

    def _show_transaction_from_file(self) -> None:
        matches = self.prompt_obtain_transactions_from_files(multiple=False)
        if len(matches) == 1:
            transaction, transaction_context = matches[0]
            self.show_transaction(self._account, transaction, transaction_context)

    def prompt_obtain_transactions_from_files(self, multiple: bool=False) \
            -> list[tuple[Transaction, TransactionContext | None]]:
        if multiple:
            file_names = self.getOpenFileNames(_("Select your transaction files"),
                "Transactions (*.json *.psbt *.raw *.txn *.txt);;*.*")
            if len(file_names) == 0:
                return []
        else:
            file_name = self.getOpenFileName(_("Select your transaction file"),
                "Transactions (*.json *.psbt *.raw *.txn *.txt);;*.*")
            if not file_name:
                return []
            file_names = [ file_name ]

        results: list[tuple[Transaction, TransactionContext | None]] = []
        for file_name in file_names:
            if file_name.endswith(".psbt"):
                # Binary-encoded files.
                with open(file_name, "rb") as f:
                    data = f.read()
            else:
                # Text-encoded files.
                with open(file_name, "r") as f:
                    file_content = f.read()
                text = file_content.strip()
                if text == "":
                    return []
                data = text.encode()
            try:
                transaction, transaction_context = self._wallet.load_transaction_from_bytes(data)
            except ValueError as exception_value:
                self.show_critical(
                    _("Unable to import the transaction file '{}':").format(file_name) +" "+
                    str(exception_value))
                return []
            results.append((transaction, transaction_context))
        return results

    def _show_transaction_from_txid(self) -> None:
        tx, tx_context = self.prompt_obtain_transaction_from_txid()
        if tx is not None:
            self.show_transaction(self._account, tx, tx_context)

    def prompt_obtain_transaction_from_txid(self) \
            -> tuple[Optional[Transaction], Optional[TransactionContext]]:
        # We should have disabled this
        assert self.network is not None
        assert self._account is not None
        prompt = _('Enter the transaction ID:') + '\u2001' * 30   # em quad
        txid, ok = QInputDialog.getText(self, _('Lookup transaction'), prompt)
        if ok and txid:
            txid = str(txid).strip()
            try:
                rawtx = app_state.async_.spawn_and_wait(self._wallet.fetch_raw_transaction_async(
                    hex_str_to_hash(txid), self._account), timeout=10)
            except Exception as exc:
                d = UntrustedMessageDialog(
                    self, _("Transaction Lookup Error"),
                    _("The server was unable to locate the transaction you specified."),
                    exc)
                d.exec()
                return None, None
            tx = Transaction.from_bytes(rawtx)
            return tx, None
        return None, None

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
        assert account is not None
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

        assert self._account is not None
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
        csv_lines: List[Tuple[str, str, str, str]] = []
        for item in history:
            if is_csv:
                csv_lines.append((item['txid'], item.get('label', ''), item['value'],
                    item['timestamp']))

        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f, lineterminator='\n')
                transaction.writerow(["transaction_hash", "label", "value", "timestamp"])
                for line in csv_lines:
                    transaction.writerow(line)
            else:
                f.write(json.dumps(history, indent=4))

    def _do_import(self, title: str, msg: str, func: Callable[[str], None]) -> None:
        text = text_dialog(self, title, msg + ' :', _('Import'), allow_multi=True)
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

    def _on_password_request(self, completion_callback: Callable[[], None], reason_text: str) \
            -> None:
        """
        Some process needs to prompt the wallet window to request the wallet password, as it
        is likely not in the credential cache. This is called in the context of a Qt signal
        so will not block the caller.
        """
        self.password_dialog(reason_text)
        completion_callback()

    def _on_ui_callback_to_dispatch(self, callback: Callable[[Tuple[Any, ...]], None],
            args: Tuple[Any, ...]) -> None:
        callback(args)

    def _on_transaction_labels_updated_signal(self,
            update_entries: List[Tuple[Optional[str], int, bytes]]) -> None:
        self.history_view.update_descriptions(update_entries)
        self.utxo_list.update_tx_labels(update_entries)

    def _on_transaction_state_change(self, account_id: int, tx_hash: bytes,
            new_state: TxFlags) -> None:
        self.update_history_view()

    def update_history_view(self) -> None:
        self.history_view.update_tx_list()
        self.history_updated_signal.emit()

    #
    # Preferences dialog and its signals.
    #
    def on_num_zeros_changed(self) -> None:
        self.update_history_view()

    def on_fiat_ccy_changed(self) -> None:
        '''Called when the user changes fiat currency in preferences.'''
        self.history_view.update_tx_headers()
        self.update_history_view()
        self.update_status_bar()

    def on_base_unit_changed(self) -> None:
        edits = list(itertools.chain.from_iterable(
            v.get_bsv_edits()
            for v in self._send_views.values()
            if isinstance(v, SendView)))
        edits.extend(
            itertools.chain.from_iterable(
                v.get_bsv_edits()
                for v in self._receive_views.values()
                if isinstance(v, ReceiveView)))
        amounts = [edit.get_amount() for edit in edits]
        self.update_history_view()
        if self.is_receive_view_active():
            assert isinstance(self._receive_view, ReceiveView)
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
        dialog.exec()

    def ok_to_close(self) -> bool:
        # Close our tx dialogs; return False if any cannot be closed
        for tx_dialog in list(self.tx_dialogs):
            if not tx_dialog.close():
                return False
        return True

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.ok_to_close():
            # It seems in some rare cases this closeEvent() is called twice
            if not self.cleaned_up:
                self.clean_up()
                self.cleaned_up = True
            event.accept()
        else:
            event.ignore()

    def clean_up(self) -> None:
        app_state.credentials.set_request_callback(self._wallet.get_storage_path(), None)
        self._wallet.events.unregister_callbacks_for_object(self)

        if self.network:
            self.network.unregister_callbacks_for_object(self)

        if self.tx_notify_timer is not None:
            self.tx_notify_timer.stop()
            self.tx_notify_timer = None

        if self._network_dialog is not None:
            self._network_dialog.clean_up()
            self._network_dialog.close()
            self._network_dialog = None

        # Cancelled tasks have a reference to a cancelled exception, if we do not delete the
        # future that links to the task, the task methods on the window class will keep the window
        # from being garbage collected.
        self._network_status_loop_task.cancel()
        del self._network_status_loop_task

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
                self._wallet.get_storage().put("split-sizes-qt", self._navigation_view.sizes())
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

        if self.coinsplitting_tab:
            self.coinsplitting_tab.clean_up()

        if self.key_view:
            self.key_view.clean_up()

        for account in self._wallet.get_accounts():
            for keystore in account.get_keystores():
                keystore.clean_up()

        self._logger.debug('closing wallet %s', self._wallet)

        # NOTE(qt-signals) 2022-06-22/rt12 This may have been cleaned up by Qt depending on how the
        #     wallet exits. At the time of writing this is reproduced by killing ElectrumSV from
        #     the DOS command line using Control+C.
        try:
            self.app.timer.timeout.disconnect(self.timer_actions)
        except TypeError:
            pass
        self.app.close_window(self)

    def cpfp(self, account: AbstractAccount, parent_tx: Transaction, new_tx: Transaction) -> None:
        total_size = parent_tx.size() + sum(new_tx.estimated_size())
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
        grid.addWidget(QLabel(app_state.format_amount(max_fee) +' '+ app_state.base_unit()), 1, 1)
        output_amount = QLabel('')
        grid.addWidget(QLabel(_('Output amount') + ':'), 2, 0)
        grid.addWidget(output_amount, 2, 1)
        fee_e = BTCAmountEdit()
        def event_fee_changed(new_text: str) -> None:
            fee_value = fee_e.get_amount()
            if fee_value is None:
                fee_value = 0
            a = max_fee - fee_value
            output_amount.setText((app_state.format_amount(a) + ' ' + app_state.base_unit())
                                  if a else '')
        fee_e.textChanged.connect(event_fee_changed)
        fee1 = math.ceil(self.config.fee_per_kb() * total_size / 1000)
        fee_e.setAmount(fee1)
        grid.addWidget(QLabel(_('Fee' + ':')), 3, 0)
        grid.addWidget(fee_e, 3, 1)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec():
            return

        fee2 = fee_e.get_amount()
        assert fee2 is not None
        if fee2 > max_fee:
            self.show_error(_('Max fee exceeded'))
            return

        cpfp_tx = account.cpfp(parent_tx, fee2)
        if cpfp_tx is None:
            self.show_error(_('CPFP no longer valid'))
            return

        self.show_transaction(account, cpfp_tx)

