from __future__ import annotations
import csv
from enum import IntEnum
from functools import partial
import json
import os
import threading
import time
from typing import Any, cast, Dict, List, Optional, Sequence
from weakref import proxy

from bitcoinx import hash_to_hex_str

from PyQt6.QtCore import QEvent, QItemSelectionModel, QModelIndex, QPoint, pyqtSignal, QSize, Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (QHeaderView, QLabel, QTreeWidget, QTreeWidgetItem, QMenu, QSplitter,
    QStackedWidget, QTabWidget, QTextEdit, QVBoxLayout, QWidget)

from ...app_state import app_state
from ...bitcoin import address_from_string, script_template_to_string
from ...constants import AccountType, DerivationType, KeystoreType
from ...i18n import _
from ...logs import logs
from ...platform import platform
from ...wallet import (AbstractAccount, ImportedAddressAccount, ImportedPrivkeyAccount,
    MultisigAccount, Wallet)

from .account_dialog import AccountDialog
from .constants import RestorationDialogRole
from .debugger_view import DebuggerView
from .home_view import HomeView
from .main_window import ElectrumWindow
from . import notifications_view
from .util import (Buttons, CancelButton, filename_field, line_dialog, MessageBox, OkButton,
    protected, read_QIcon, WindowModalDialog)



class TreeColumns(IntEnum):
    MAIN = 0
    BSV_VALUE = 1
    FIAT_VALUE = 2


BASE_TREE_HEADERS = [ '' ]


class WalletNavigationView(QSplitter):
    computing_privkeys_signal = pyqtSignal()
    show_privkeys_signal = pyqtSignal()

    _home_item: QTreeWidgetItem
    _accounts_item: QTreeWidgetItem

    def __init__(self, main_window: ElectrumWindow, wallet: Wallet) -> None:
        super().__init__(main_window)

        self._logger = logs.get_logger("navigation-view")
        # NOTE(proxytype-is-shitty) weakref.proxy does not return something that mirrors
        #     attributes. This means that everything accessed is an `Any` and we leak those
        #     and it introduces silent typing problems everywhere it touches.
        self._main_window_proxy: ElectrumWindow = proxy(main_window)
        self._wallet = wallet

        self._main_window_proxy.account_created_signal.connect(self._on_account_created)
        self._main_window_proxy.account_change_signal.connect(self._on_account_changed)
        self._main_window_proxy.new_fx_quotes_signal.connect(self.refresh_account_balances)
        self._main_window_proxy.notifications_updated_signal.connect(self.refresh_notifications)

        app_state.app_qt.base_unit_changed.connect(self.refresh_account_balances)
        app_state.app_qt.fiat_ccy_changed.connect(self.refresh_account_balances)

        # We subclass QListWidget so accounts cannot be deselected.
        class CustomTreeWidget(QTreeWidget):
            def selectionCommand(self, index: QModelIndex, event: Optional[QEvent]=None) \
                    -> QItemSelectionModel.SelectionFlag:
                flags = super().selectionCommand(index, event)
                if flags == QItemSelectionModel.SelectionFlag.Deselect:
                    return QItemSelectionModel.SelectionFlag.NoUpdate
                return flags

        self._account_tree_items: Dict[int, QTreeWidgetItem] = {}

        self._home_widget = HomeView(self._main_window_proxy.reference(), self._wallet)
        self._accounts_widget = QWidget()
        self._contacts_widget = self._main_window_proxy.create_contacts_list()
        self._notifications_widget = notifications_view.View(self._main_window_proxy._api,
            self._main_window_proxy.reference())
        self._advanced_widget = QWidget()
        self._console_widget = self._main_window_proxy.create_console()
        self._debugger_widget = DebuggerView()
        self._tab_widget = QTabWidget()

        self._pane_view = QStackedWidget()
        self._pane_view.addWidget(self._tab_widget)
        self._pane_view.addWidget(self._accounts_widget)
        self._pane_view.addWidget(self._notifications_widget)
        self._pane_view.addWidget(self._contacts_widget)
        self._pane_view.addWidget(self._advanced_widget)
        self._pane_view.addWidget(self._console_widget)
        self._pane_view.addWidget(self._debugger_widget)
        # ShowHomeSectionOnStartup
        # 1. Sigh. We can set the current widget all we want after this point in this call stack,
        #    but Qt5 ignores the call and just shows the last added widget. It does not appear
        #    possible to initialise the stacked widget then tell it immediately which to display.
        # 2. When there is an account change event we ignore it if it is on startup so that we do
        #    not switch away from the Home pane unwittingly.
        # We want to show the home widget as a dashboard, the first thing the user sees on opening
        # a wallet.
        self._pane_view.addWidget(self._home_widget)
        self._initialize_home()

        self._selection_tree = CustomTreeWidget()
        self._selection_tree.setMinimumWidth(150)
        self._selection_tree.setIconSize(QSize(20, 20))
        self._selection_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._selection_tree.customContextMenuRequested.connect(self._show_account_menu)
        self._selection_tree.currentItemChanged.connect(self._on_current_item_changed)
        self._monospace_font = QFont(platform.monospace_font)

        self._current_account_id: Optional[int] = None

        self.addWidget(self._selection_tree)
        self.addWidget(self._pane_view)

        self.setChildrenCollapsible(False)

    def on_wallet_loaded(self) -> None:
        self._initialize_tree()

    def _initialize_home(self) -> None:
        self._home_widget.update_health_report()

    def update_history_headers(self) -> None:
        self._home_widget.update_history_headers()

    def update_history_list(self) -> None:
        self._home_widget.update_history_list()

    def init_geometry(self, sizes: Optional[Sequence[int]]=None) -> None:
        self._logger.debug("init_geometry.1 %r", sizes)
        if sizes is None:
            default_left_width = 315
            sizes = [ default_left_width,
                self._main_window_proxy.size().width() - default_left_width ]
            self._logger.debug("init_geometry.2 %r", sizes)
        self.setSizes(sizes)

    def _on_account_created(self, new_account_id: int, new_account: AbstractAccount) -> None:
        # It should be made the active wallet account and followed up with the change event.
        self._add_account_to_tree(new_account)

    # ShowHomeSectionOnStartup
    def _on_account_changed(self, new_account_id: int | None, new_account: AbstractAccount | None,
            startup: bool) -> None:
        # The list is being told what to focus on.
        if new_account_id is not None and self._update_active_account(new_account_id) and \
                not startup:
            account_item = self._account_tree_items[new_account_id]
            self._selection_tree.setCurrentItem(account_item)

        # TODO(invoice-import) What format are these imported files? No idea.
        # if self._import_invoices_action is not None:
        #     self._import_invoices_action.setEnabled(self._main_window_proxy.is_send_view_active())

    def refresh_account_balances(self) -> None:
        """
        Update the headers and account balances.

        This is called when:
        - The user enables or disables fiat display.
        - The quotes we have for the given currency change.
        - The user changes the base unit for BSV value display.

        Note that we may not have a quote when the user first enables fiat display, but we
        should update the empty balances when the first quote arrives.
        """
        self._update_tree_headers()

    def _on_current_item_changed(self, item: QTreeWidgetItem, last_item: QTreeWidgetItem) -> None:
        if item is self._home_item:
            self._pane_view.setCurrentWidget(self._home_widget)
        elif item is self._contacts_item:
            self._pane_view.setCurrentWidget(self._contacts_widget)
        elif item is self._notifications_item:
            self._pane_view.setCurrentWidget(self._notifications_widget)
        elif item is self._advanced_item:
            self._pane_view.setCurrentWidget(self._advanced_widget)
        elif item is self._console_item:
            self._pane_view.setCurrentWidget(self._console_widget)
        elif item is self._debugger_item:
            self._pane_view.setCurrentWidget(self._debugger_widget)
        elif item is self._accounts_item:
            self._pane_view.setCurrentWidget(self._accounts_widget)
        else:
            account_id = item.data(TreeColumns.MAIN, Qt.ItemDataRole.UserRole)
            # This should update the internal tracking, and also the active wallet account.
            self._select_account(account_id)
            return

        self._update_selected_account(None)

    def _update_active_account(self, account_id: Optional[int]) -> bool:
        if account_id == self._current_account_id:
            return False
        self._current_account_id = account_id
        return True

    def get_tab_widget(self) -> QTabWidget:
        return self._tab_widget

    def _initialize_tree(self) -> None:
        self._selection_tree.clear()
        self._account_tree_items.clear()

        self._home_item = QTreeWidgetItem()
        self._home_item.setIcon(TreeColumns.MAIN, read_QIcon("icons8-general-ledger-80-blueui.png"))
        self._home_item.setText(TreeColumns.MAIN, _("Home"))
        self._home_item.setToolTip(TreeColumns.MAIN,
            _("The home page or dashboard for your wallet"))
        # self._home_item.setData(TreeColumns.MAIN, Qt.FontRole, QFont("", 16));
        self._selection_tree.addTopLevelItem(self._home_item)

        self._contacts_item = QTreeWidgetItem()
        self._contacts_item.setIcon(TreeColumns.MAIN,
            read_QIcon("icons8-contacts-80-blueui.png"))
        self._contacts_item.setText(TreeColumns.MAIN, _("Contacts"))
        self._contacts_item.setToolTip(TreeColumns.MAIN, _("The contacts in this wallet"))
        self._selection_tree.addTopLevelItem(self._contacts_item)

        self._notifications_item = QTreeWidgetItem()
        self.update_notifications_icon(
            len(self._main_window_proxy._api.get_notification_rows()))
        self._notifications_item.setText(TreeColumns.MAIN, _("Notifications"))
        self._notifications_item.setToolTip(TreeColumns.MAIN, _("The notifications in this wallet"))
        self._selection_tree.addTopLevelItem(self._notifications_item)

        # Accounts sub-tree.
        self._accounts_item = QTreeWidgetItem()
        self._accounts_item.setIcon(TreeColumns.MAIN,
            read_QIcon("icons8-merchant-account-80-blueui.png"))
        self._accounts_item.setText(TreeColumns.MAIN, _("Accounts"))
        self._accounts_item.setToolTip(TreeColumns.MAIN,
            _("The accounts in this wallet"))
        self._selection_tree.addTopLevelItem(self._accounts_item)

        # We order the accounts in order of creation, except for petty cash which should always
        # come last.
        # NOTE(petty-cash) We do not show the petty cash account for now. We do not have
        #     micro-payment support in the servers or the wallet itself yet.
        accounts = sorted(self._wallet.get_visible_accounts(),
            key=lambda a: (a.is_petty_cash(), a.get_id()))
        for account in accounts:
            self._add_account_to_tree(account)

        self._accounts_item.setExpanded(True)

        # Advanced sub-tree.
        self._advanced_item = QTreeWidgetItem()
        self._advanced_item.setIcon(TreeColumns.MAIN,
            read_QIcon("icons8-administrative-tools-80-blueui.png"))
        self._advanced_item.setText(TreeColumns.MAIN, _("Developer tools"))
        self._advanced_item.setToolTip(TreeColumns.MAIN, _("Developer tools"))
        self._selection_tree.addTopLevelItem(self._advanced_item)

        self._console_item = QTreeWidgetItem()
        self._console_item.setIcon(TreeColumns.MAIN,
            read_QIcon("icons8-console-80-blueui.png"))
        self._console_item.setText(TreeColumns.MAIN, _("Console"))
        self._console_item.setToolTip(TreeColumns.MAIN, _("An embedded Python console"))
        self._advanced_item.addChild(self._console_item)

        self._debugger_item = QTreeWidgetItem()
        self._debugger_item.setIcon(TreeColumns.MAIN,
            read_QIcon("icons8-bug-80-blueui.png"))
        self._debugger_item.setText(TreeColumns.MAIN, _("Debugger"))
        self._debugger_item.setToolTip(TreeColumns.MAIN, _("An Bitcoin script debugger"))
        self._advanced_item.addChild(self._debugger_item)

        # Final updates.
        self._selection_tree.setCurrentItem(self._home_item)
        self.refresh_account_balances()

    def _update_tree_headers(self) -> None:
        headers = BASE_TREE_HEADERS[:]

        self._selection_tree.setColumnCount(len(headers))
        self._selection_tree.setHeaderLabels(headers)
        self._selection_tree.header().setDefaultAlignment(Qt.AlignmentFlag.AlignCenter)

        self._selection_tree.header().setSectionResizeMode(TreeColumns.MAIN,
            QHeaderView.ResizeMode.Stretch)

    def _add_account_to_tree(self, account: AbstractAccount) -> None:
        account_id = account.get_id()

        other_conflicting_accounts = self._get_conflicting_accounts(account.display_name())

        item = QTreeWidgetItem()
        keystore = account.get_keystore()
        derivation_type = keystore.derivation_type if keystore is not None \
            else DerivationType.NONE
        is_watching_only = keystore.is_watching_only() if keystore is not None else True
        icon_state = "inactive" if is_watching_only else "active"
        if derivation_type == DerivationType.ELECTRUM_MULTISIG:
            tooltip_text = _("Multi-signature account")
            icon_filename = "icons8-group-task-80-blueui-{}.png"
        elif derivation_type == DerivationType.HARDWARE:
            tooltip_text = _("Hardware wallet account")
            icon_filename = "icons8-usb-2-80-blueui-{}.png"
        elif derivation_type == DerivationType.IMPORTED:
            # This should not be watch only as imported public keys have no keystore.
            tooltip_text = _("Imported private key account")
            icon_filename = "icons8-key-80-plus-blueui-{}.png"
        elif derivation_type == DerivationType.ELECTRUM_OLD:
            tooltip_text = _("Old-style Electrum account")
            icon_filename = "icons8-password-1-80-blueui-{}.png"
        elif derivation_type == DerivationType.BIP32:
            tooltip_text = _("BIP32 account")
            icon_filename ="icons8-grand-master-key-80-blueui-{}.png"
        else:
            # This should always be watch only as imported public keys have no keystore.
            tooltip_text = _("Imported public key account")
            icon_filename = "icons8-key-80-plus-blueui-{}.png"
        if is_watching_only:
            tooltip_text += f" ({_('watch only')})"
        item.setIcon(TreeColumns.MAIN, read_QIcon(icon_filename.format(icon_state)))
        item.setData(TreeColumns.MAIN, Qt.ItemDataRole.UserRole, account_id)
        item.setText(TreeColumns.MAIN, account.display_name())
        item.setToolTip(TreeColumns.MAIN, tooltip_text)

        # Accounts are by default ordered in the order of creation, with the exception of petty
        # cash which comes last.
        if account.is_petty_cash():
            self._accounts_item.addChild(item)
        else:
            for child_index in range(self._accounts_item.childCount()):
                child_item = self._accounts_item.child(child_index)
                child_account_id = cast(int,
                    child_item.data(TreeColumns.MAIN, Qt.ItemDataRole.UserRole))
                child_account = self._wallet.get_account(child_account_id)
                assert child_account is not None
                if account_id > child_account_id or child_account.is_petty_cash():
                    self._accounts_item.insertChild(child_index, item)
                    break
            else:
                self._accounts_item.addChild(item)

        self._account_tree_items[account_id] = item

        if len(other_conflicting_accounts) > 1:
            self._rename_conflicting_accounts(other_conflicting_accounts)

    def _show_account_menu(self, position: QPoint) -> None:
        item = self._selection_tree.currentItem()
        if not item:
            return

        if item.parent() is not self._accounts_item:
            return

        account_id = item.data(TreeColumns.MAIN, Qt.ItemDataRole.UserRole)
        account = self._wallet.get_account(account_id)
        assert account is not None

        menu = QMenu()
        # NOTE(proxytype-is-shitty) weakref.proxy does not return something that mirrors
        #     attributes. This means that everything accessed is an `Any` and we leak those
        #     and it introduces silent typing problems everywhere it touches.
        self.add_menu_items(menu, account, self._main_window_proxy)
        menu.exec(self._selection_tree.viewport().mapToGlobal(position))

    def add_menu_items(self, menu: QMenu, account: AbstractAccount,
            main_window_proxy: ElectrumWindow) -> None:
        menu.clear()

        # This expects a reference to the main window, not the weakref. ??
        account_id = account.get_id()
        account_row = account.get_row()

        menu.addAction(_("&Information"), partial(self._show_account_information, account_id))
        seed_menu = menu.addAction(_("View &secured data"),
            partial(self._view_secured_data, main_window_proxy=main_window_proxy,
                account_id=account_id))
        seed_menu.setEnabled(self._can_view_secured_data(account))
        menu.addAction(_("&Rename"), partial(self._rename_account, account_id))
        menu.addSeparator()

        menu.addAction(_("&Restore account"),
            main_window_proxy.restore_active_account_manual)

        owned_bitcache = account_row.bitcache_channel_id is not None
        no_bitcache = account_row.bitcache_channel_id is None and \
            account_row.external_bitcache_channel_id is None

        bitcache_menu = menu.addMenu(_("&Bitcache"))
        bitcache_menu.addAction(_("&Setup new"),
            partial(main_window_proxy.setup_new_bitcache, account_id)).setEnabled(no_bitcache)
        bitcache_menu.addAction(_("&Connect to existing"),
            partial(main_window_proxy.connect_to_existing_bitcache, account_id)).setEnabled(
                no_bitcache)
        bitcache_menu.addAction(_("&Grant access"),
            partial(main_window_proxy.show_bitcache_access_dialog, account_id)).setEnabled(
                owned_bitcache)
        menu.addSeparator()

        private_keys_menu = menu.addMenu(_("&Private keys"))
        import_menu = private_keys_menu.addAction(_("&Import"), partial(self._import_privkey,
            main_window_proxy=main_window_proxy, account_id=account_id))
        import_menu.setEnabled(account.can_import_privkey())
        export_menu = private_keys_menu.addAction(_("&Export"), partial(self._export_privkeys,
            main_window_proxy=main_window_proxy, account_id=account_id))
        export_menu.setEnabled(account.can_export())
        if account.can_import_address():
            menu.addAction(_("Import addresses"), partial(self._import_addresses, account_id))

        menu.addSeparator()

        # TODO(1.4.0) Payments. Export history.
        # hist_menu = menu.addMenu(_("&History"))
        # hist_menu.addAction("Export", main_window_proxy.export_history_dialog)

        invoices_menu = menu.addMenu(_("Invoices"))
        self._import_invoices_action = invoices_menu.addAction(_("Import"),
            partial(self._on_menu_import_invoices, account_id))
        self._import_invoices_action.setEnabled(False)
        # self._import_invoices_action.setEnabled(main_window.is_send_view_active())

        payments_menu = menu.addMenu(_("Payments"))
        ed_action = payments_menu.addAction(_("Export destinations"),
            partial(self._on_menu_generate_destinations, account_id))
        keystore = account.get_keystore()
        ed_action.setEnabled(keystore is not None and
            keystore.type() != KeystoreType.IMPORTED_PRIVATE_KEY)

        menu.addSeparator()

        debug_menu = menu.addMenu(_("Debug"))
        debug_menu.addAction(_("Export txkey data"),
            partial(self._on_menu_export_txkey_data, account_id))

    def _on_menu_import_invoices(self, account_id: int) -> None:
        pass
    # TODO(invoice-import) What format are these imported files? No idea.
    #     send_view = self._main_window_proxy.get_send_view(account_id)
    #     send_view.import_invoices()

    def _rename_account(self, account_id: int) -> None:
        assert self._current_account_id is not None
        account = self._main_window_proxy._wallet.get_account(self._current_account_id)
        assert account is not None

        conflicting_accounts_before = self._get_conflicting_accounts(account.display_name())
        if len(conflicting_accounts_before) > 1:
            pass

        new_account_name = line_dialog(self, _("Rename account"), _("Account name"), _("OK"),
            account.get_name())
        if new_account_name is None:
            return
        account.set_name(new_account_name)

        # Ensure the new name is qualified if there are now duplicate entries.
        conflicting_accounts_after = self._get_conflicting_accounts(account.display_name())
        if len(conflicting_accounts_after) > 1:
            self._rename_conflicting_accounts(conflicting_accounts_after)
        else:
            account_item = self._account_tree_items[account_id]
            account_item.setText(TreeColumns.MAIN, new_account_name)

        # Work out if we need to unqualify any now non-duplicated entries.
        conflicting_accounts_before.remove(account)
        if len(conflicting_accounts_before) == 1:
            self._unrename_conflicting_accounts(conflicting_accounts_before)

    def _show_account_information(self, account_id: int) -> None:
        dialog = AccountDialog(self._main_window_proxy, self._wallet, account_id, self)
        dialog.exec()

    def _on_menu_generate_destinations(self, account_id: int) -> None:
        from . import payment_destinations_dialog
        from importlib import reload
        reload(payment_destinations_dialog)
        dialog = payment_destinations_dialog.PaymentDestinationsDialog(self._main_window_proxy,
            self._wallet, account_id, self)
        dialog.exec()

    def _on_menu_restore_account(self, account_id: int) -> None:
        if not self._main_window_proxy.has_connected_blockchain_server():
            MessageBox.show_message(_("The wallet is not currently connected to a blockchain "
                "server. As such, the account scanner cannot be used at this time."),
                self._main_window_proxy.reference())
            return

        from . import account_restoration_dialog
        # from importlib import reload # TODO(dev-helper) Remove at some point.
        # reload(account_restoration_dialog)
        dialog = account_restoration_dialog.AccountRestorationDialog(self._main_window_proxy,
            self._wallet, account_id, RestorationDialogRole.MANUAL_RESCAN)
        dialog.exec()

    def _can_view_secured_data(self, account: AbstractAccount) -> bool:
        return bool(not account.is_watching_only() and not isinstance(account, MultisigAccount)
            and not account.involves_hardware_wallet()
            and account.type() != AccountType.IMPORTED_PRIVATE_KEY)

    @protected
    def _view_secured_data(self,
            main_window_proxy: ElectrumWindow,      # input to @protected
            account_id: int=-1,
            password: Optional[str]=None) -> None:  # output from @protected
        # account_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        account = self._wallet.get_account(account_id)
        assert account is not None
        if self._can_view_secured_data(account):
            keystore = account.get_keystore()
            assert keystore is not None
            from .secured_data_dialog import SecuredDataDialog
            assert password is not None
            d = SecuredDataDialog(self._main_window_proxy, self, keystore, password)
            d.exec()
        else:
            MessageBox.show_message(_("This type of account has no secured data. You are advised "
                "to manually back up this wallet."), self._main_window_proxy.reference())

    @protected
    def _import_privkey(self, main_window_proxy: ElectrumWindow, account_id: int=-1,
            password: Optional[str]=None) -> None:
        # account_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        account = cast(ImportedPrivkeyAccount, self._wallet.get_account(account_id))

        title, msg = _('Import private keys'), _("Enter private keys")
        # NOTE(typing) `password` is non-None here, but we cannot do an assertion that is the case
        #   and have the type checker (pylance) observe it in the lambda.
        self._main_window_proxy._do_import(title, msg,
            lambda x: account.import_private_key(x, password)) # type:ignore

    def _import_addresses(self, account_id: int) -> None:
        account = cast(ImportedAddressAccount, self._wallet.get_account(account_id))

        title, msg = _('Import addresses'), _("Enter addresses")
        def import_addr(addr: str) -> None:
            address = address_from_string(addr)
            account.import_address(address)
        self._main_window_proxy._do_import(title, msg, import_addr)

    @protected
    def _export_privkeys(self,
            main_window_proxy: ElectrumWindow,      # input to @protected
            account_id: int=-1,
            password: Optional[str]=None) -> None:  # output from @protected
        account = self._wallet.get_account(account_id)
        assert account is not None

        if isinstance(self._wallet, MultisigAccount):
            MessageBox.show_message(
                _('WARNING: This is a multi-signature wallet.') + '\n' +
                _('It can not be "backed up" by simply exporting these private keys.')
            )

        d = WindowModalDialog(self, _('Private keys'))
        d.setMinimumSize(850, 300)
        vbox = QVBoxLayout(d)

        msg = "\n".join([
            _("WARNING: ALL your private keys are secret."),
            _("Exposing a single private key can compromise your entire wallet!"),
            _("In particular, DO NOT use 'redeem private key' services proposed by third parties.")
        ])
        vbox.addWidget(QLabel(msg))

        e = QTextEdit()
        e.setReadOnly(True)
        vbox.addWidget(e)

        defaultname = 'electrumsv-private-keys.csv'
        select_msg = _('Select file to export your private keys to')
        hbox, filename_e, csv_button = filename_field(main_window_proxy.config, defaultname,
            select_msg)
        vbox.addLayout(hbox)

        b = OkButton(d, _('Export'))
        b.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(d), b))

        private_keys = {}
        keyinstances = account.get_keyinstances()
        # TODO(ScriptTypeAssumption) really what we would have is the used script type for
        # each key, rather than just using the redeem script based on the accounts default
        # script type. However, who really exports their private keys? It seems like a weird
        # thing to do and has no definitive use case.
        script_type = account.get_default_script_type()
        done = False
        cancelled = False
        def privkeys_thread() -> None:
            nonlocal done, cancelled, keyinstances, password, private_keys, script_type
            assert account is not None
            assert password is not None
            for keyinstance in keyinstances:
                time.sleep(0.1)
                if done or cancelled:
                    break
                privkey = account.export_private_key(keyinstance, password)
                assert privkey is not None
                script_template = account.get_script_template_for_derivation(script_type,
                    keyinstance.derivation_type, keyinstance.derivation_data2)
                script_text = script_template_to_string(script_template)
                private_keys[script_text] = privkey
                self.computing_privkeys_signal.emit()
            if not cancelled:
                self.computing_privkeys_signal.disconnect()
                self.show_privkeys_signal.emit()

        def show_privkeys() -> None:
            nonlocal b, done, e
            s = "\n".join('{}\t{}'.format(script_text, privkey)
                          for script_text, privkey in private_keys.items())
            e.setText(s)
            b.setEnabled(True)
            self.show_privkeys_signal.disconnect()
            done = True

        def on_dialog_closed(*args: Any)-> None:
            nonlocal cancelled, done
            if not done:
                cancelled = True
                self.computing_privkeys_signal.disconnect()
                self.show_privkeys_signal.disconnect()

        self.computing_privkeys_signal.connect(lambda: e.setText(
            "Please wait... %d/%d" % (len(private_keys), len(keyinstances))))
        self.show_privkeys_signal.connect(show_privkeys)
        d.finished.connect(on_dialog_closed)
        threading.Thread(target=privkeys_thread).start()

        if not d.exec():
            done = True
            return

        filename = filename_e.text()
        if not filename:
            return

        try:
            self._do_export_privkeys(filename, private_keys, csv_button.isChecked())
        except (IOError, os.error) as reason:
            txt = "\n".join([
                _("ElectrumSV was unable to produce a private key-export."),
                str(reason)
            ])
            MessageBox.show_error(txt, title=_("Unable to create csv"))
        except Exception as exc:
            MessageBox.show_message(str(exc), main_window_proxy.reference())
            return

        MessageBox.show_message(_('Private keys exported'), main_window_proxy.reference())

    def _do_export_privkeys(self, fileName: str, pklist: Dict[str, str], is_csv: bool) -> None:
        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f)
                transaction.writerow(["reference", "private_key"])
                for key_text, pk in pklist.items():
                    transaction.writerow([key_text, pk])
            else:
                f.write(json.dumps(pklist, indent = 4))

    def show_developer_tools(self) -> None:
        self._selection_tree.setCurrentItem(self._advanced_item)

    def show_debugger(self) -> None:
        self._selection_tree.setCurrentItem(self._debugger_item)

    def _update_selected_account(self, account_id: Optional[int]) -> bool:
        if self._update_active_account(account_id):
            account = self._main_window_proxy._wallet.get_account(account_id) \
                if account_id is not None else None
            self._main_window_proxy.set_active_account(account)
            return True
        return False

    def _select_account(self, account_id: int) -> bool:
        self._pane_view.setCurrentWidget(self._tab_widget)
        return self._update_selected_account(account_id)

    def _get_conflicting_accounts(self, display_name: str) -> List[AbstractAccount]:
        display_name = display_name.lower()
        accounts: List[AbstractAccount] = []
        for other_account in self._wallet.get_accounts():
            if other_account.display_name().lower() == display_name:
                accounts.append(other_account)
        return accounts

    def _rename_conflicting_accounts(self, accounts: List[AbstractAccount]) -> None:
        account_ids = { account.get_id() for account in accounts }
        for child_index in range(self._accounts_item.childCount()):
            child_item = self._accounts_item.child(child_index)
            child_account_id = cast(int,
                child_item.data(TreeColumns.MAIN, Qt.ItemDataRole.UserRole))
            if child_account_id in account_ids:
                child_account = self._wallet.get_account(child_account_id)
                assert child_account is not None
                display_name = f"{child_account.display_name()} #{child_account_id}"
                child_item.setText(TreeColumns.MAIN, display_name)

    def _unrename_conflicting_accounts(self, accounts: List[AbstractAccount]) -> None:
        account_ids = { account.get_id() for account in accounts }
        for child_index in range(self._accounts_item.childCount()):
            child_item = self._accounts_item.child(child_index)
            child_account_id = cast(int,
                child_item.data(TreeColumns.MAIN, Qt.ItemDataRole.UserRole))
            if child_account_id in account_ids:
                child_account = self._wallet.get_account(child_account_id)
                assert child_account is not None
                child_item.setText(TreeColumns.MAIN, child_account.display_name())

    def update_notifications_icon(self, entry_count: int) -> None:
        if entry_count > 0:
            self._notifications_item.setIcon(TreeColumns.MAIN,
                read_QIcon("icons8-notification-80-blueui-urgent-edit.png"))
        else:
            self._notifications_item.setIcon(TreeColumns.MAIN,
                read_QIcon("icons8-notification-80-blueui.png"))

    def refresh_notifications(self) -> None:
        # Update the navigation view entry.
        notification_count = len(self._main_window_proxy._api.get_notification_rows())
        self.update_notifications_icon(notification_count)
        # Update the contents of the notifications view.
        self._notifications_widget.reset_contents()

    def _on_menu_export_txkey_data(self, account_id: int) -> None:
        export_path = self._main_window_proxy.getExistingDirectory("Export folder")
        # List all transactions in the wallet by creation date ascending.
        # Have key data for each transaction.
        # Export as named files, tx and key metadata.
        from ...wallet_support.dump import convert_txrow_to_jsondata
        account = self._wallet.get_account(account_id)
        assert account is not None
        key_fingerprint = account.get_fingerprint()
        for i, row in enumerate(self._wallet.data.read_debug_bitcache_transactions(account_id)):
            tx_id = hash_to_hex_str(row.tx_hash)
            tx_prefix = f"A{account_id:06d}_T{i:06d}_{tx_id[:8]}"
            with open(os.path.join(export_path, tx_prefix+".txn"), "wb") as f:
                f.write(row.tx_data)

            with open(os.path.join(export_path, tx_prefix+".json"), "w") as f:
                json.dump(convert_txrow_to_jsondata(row, key_fingerprint), f)
