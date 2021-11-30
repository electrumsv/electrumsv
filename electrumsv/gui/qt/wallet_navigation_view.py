# Open BSV License version 4
#
# Copyright (c) 2021 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import annotations
import csv
from enum import IntEnum
from functools import partial
import json
import os
import threading
import time
from typing import Any, cast, Dict, Optional, Sequence
import weakref

from PyQt5.QtCore import QEvent, QItemSelectionModel, QModelIndex, QPoint, pyqtSignal, QSize, Qt
from PyQt5.QtWidgets import (QGroupBox, QHBoxLayout, QLabel, QTreeWidget, QTreeWidgetItem, QMenu,
    QSplitter, QStackedWidget, QTabWidget, QTextEdit, QVBoxLayout, QWidget)

from ...bitcoin import address_from_string, script_template_to_string
from ...constants import AccountType, DerivationType, KeystoreType
from ...i18n import _
from ...logs import logs
from ...wallet import (AbstractAccount, ImportedAddressAccount, ImportedPrivkeyAccount,
    MultisigAccount, Wallet)

from .account_dialog import AccountDialog
from .constants import ScanDialogRole
from .main_window import ElectrumWindow
from .util import (Buttons, CancelButton, filename_field, line_dialog, MessageBox, OkButton,
    protected, read_QIcon, WindowModalDialog)



class TreeColumns(IntEnum):
    MAIN = 0


class WalletNavigationView(QSplitter):
    computing_privkeys_signal = pyqtSignal()
    show_privkeys_signal = pyqtSignal()

    _home_item: QTreeWidgetItem
    _accounts_item: QTreeWidgetItem

    def __init__(self, main_window: ElectrumWindow, wallet: Wallet) -> None:
        super().__init__(main_window)

        self._logger = logs.get_logger("navigation-view")
        self._main_window = weakref.proxy(main_window)
        self._wallet = wallet

        self._main_window.account_created_signal.connect(self._on_account_created)
        self._main_window.account_change_signal.connect(self._on_account_changed)

        # We subclass QListWidget so accounts cannot be deselected.
        class CustomTreeWidget(QTreeWidget):
            def selectionCommand(self, index: QModelIndex, event: Optional[QEvent]=None) \
                    -> QItemSelectionModel.SelectionFlags:
                flags = super().selectionCommand(index, event)
                if flags == \
                        QItemSelectionModel.SelectionFlags(
                            QItemSelectionModel.SelectionFlag.Deselect):
                    return QItemSelectionModel.SelectionFlags(
                        QItemSelectionModel.SelectionFlag.NoUpdate)
                return flags

        self._account_tree_items: Dict[int, QTreeWidgetItem] = {}

        self._home_widget = QWidget()
        self._accounts_widget = QWidget()
        self._tab_widget = QTabWidget()

        self._pane_view = QStackedWidget()
        self._pane_view.addWidget(self._tab_widget)
        self._pane_view.addWidget(self._accounts_widget)
        # Sigh. We can set the current widget all we want after this point in this call stack,
        # but Qt5 ignores the call and just shows the last added widget. It does not appear
        # possible to initialise the stacked widget then tell it immediately which to display.
        self._pane_view.addWidget(self._home_widget)

        self._initialize_home()

        self._selection_tree = CustomTreeWidget()
        self._selection_tree.setHeaderHidden(True)
        self._selection_tree.setMinimumWidth(150)
        self._selection_tree.setIconSize(QSize(20, 20))
        self._selection_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._selection_tree.customContextMenuRequested.connect(self._show_account_menu)
        self._selection_tree.currentItemChanged.connect(self._on_current_item_changed)

        self._current_account_id: Optional[int] = None

        self.addWidget(self._selection_tree)
        self.addWidget(self._pane_view)

        self.setChildrenCollapsible(False)

    def on_wallet_loaded(self) -> None:
        self._initialize_account_list()

    def init_geometry(self, sizes: Optional[Sequence[int]]=None) -> None:
        self._logger.debug("init_geometry.1 %r", sizes)
        if sizes is None:
            sizes = [ 200, self._main_window.size().width() - 200 ]
            self._logger.debug("init_geometry.2 %r", sizes)
        self.setSizes(sizes)

    def _on_account_created(self, new_account_id: int, new_account: AbstractAccount) -> None:
        # It should be made the active wallet account and followed up with the change event.
        self._add_account_to_list(new_account)

    def _on_account_changed(self, new_account_id: int, new_account: AbstractAccount) -> None:
        # The list is being told what to focus on.
        if self._update_active_account(new_account_id):
            account_item = self._account_tree_items[new_account_id]
            self._selection_tree.setCurrentItem(account_item)

        # TODO(invoice-import) What format are these imported files? No idea.
        # if self._import_invoices_action is not None:
        #     self._import_invoices_action.setEnabled(self._main_window.is_send_view_active())

    def _on_current_item_changed(self, item: QTreeWidgetItem, last_item: QTreeWidgetItem) -> None:
        if item is self._home_item:
            self._select_home()
        elif item is self._accounts_item:
            self._select_accounts_parent()
        else:
            account_id = item.data(TreeColumns.MAIN, Qt.ItemDataRole.UserRole)
            # This should update the internal tracking, and also the active wallet account.
            self._select_account(account_id)

    def _update_active_account(self, account_id: int) -> bool:
        if account_id == self._current_account_id:
            return False
        self._current_account_id = account_id
        return True

    def _update_window_account(self, account: AbstractAccount) -> None:
        self._main_window.set_active_account(account)

    def get_tab_widget(self) -> QTabWidget:
        return self._tab_widget

    def _initialize_home(self) -> None:
        summary_layout = QHBoxLayout()
        summary_box = QGroupBox()
        summary_box.setTitle(_('Account summary'))
        summary_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        summary_box.setLayout(summary_layout)

        summary_label = QLabel(_("SUMMARY"))
        summary_layout.addWidget(summary_label)

        backup_layout = QHBoxLayout()
        backup_box = QGroupBox()
        backup_box.setTitle(_('Backup status'))
        backup_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        backup_box.setLayout(backup_layout)

        backup_label = QLabel(_("BACKUP"))
        backup_layout.addWidget(backup_label)

        notification_layout = QHBoxLayout()
        notification_box = QGroupBox()
        notification_box.setTitle(_('Notifications'))
        notification_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        notification_box.setLayout(notification_layout)

        notification_label = QLabel(_("NOTIFICATIONS"))
        notification_layout.addWidget(notification_label)

        row_layout = QVBoxLayout()
        row_layout.setContentsMargins(0, 3, 5, 0)
        row_layout.setSpacing(2)
        column_layout = QHBoxLayout()
        column_layout.setContentsMargins(0, 0, 0, 0)
        column1_layout = QVBoxLayout()
        column1_layout.setContentsMargins(0, 0, 0, 0)
        column2_layout = QVBoxLayout()
        column2_layout.setContentsMargins(0, 0, 0, 0)
        column_layout.addLayout(column1_layout)
        column_layout.addLayout(column2_layout)
        row_layout.addLayout(column_layout)
        row_layout.addWidget(notification_box)

        self._home_widget.setLayout(row_layout)

        column1_layout.addWidget(summary_box)
        column2_layout.addWidget(backup_box)

    def _initialize_account_list(self) -> None:
        self._selection_tree.clear()
        self._account_tree_items.clear()

        self._home_item = QTreeWidgetItem()
        self._home_item.setIcon(TreeColumns.MAIN, read_QIcon("icons8-general-ledger-80-blueui.png"))
        self._home_item.setText(TreeColumns.MAIN, _("Home"))
        self._home_item.setToolTip(TreeColumns.MAIN,
            _("The home page or dashboard for your wallet"))
        # self._home_item.setData(TreeColumns.MAIN, Qt.FontRole, QFont("", 16));
        self._selection_tree.addTopLevelItem(self._home_item)

        self._accounts_item = QTreeWidgetItem()
        self._accounts_item.setIcon(TreeColumns.MAIN,
            read_QIcon("icons8-merchant-account-80-blueui.png"))
        self._accounts_item.setText(TreeColumns.MAIN, _("Accounts"))
        self._accounts_item.setToolTip(TreeColumns.MAIN,
            _("Your wallet accounts"))
        self._selection_tree.addTopLevelItem(self._accounts_item)

        for account in self._wallet.get_accounts():
            self._add_account_to_list(account)

        self._accounts_item.setExpanded(True)
        self._selection_tree.setCurrentItem(self._home_item)

    def _add_account_to_list(self, account: AbstractAccount) -> None:
        account_id = account.get_id()
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
        self._accounts_item.addChild(item)
        self._account_tree_items[account_id] = item

    def _show_account_menu(self, position: QPoint) -> None:
        item = self._selection_tree.currentItem()
        if not item:
            return

        account_id = item.data(TreeColumns.MAIN, Qt.ItemDataRole.UserRole)
        account = self._wallet.get_account(account_id)
        assert account is not None

        menu = QMenu()
        self.add_menu_items(menu, account, self._main_window)
        menu.exec_(self._selection_tree.viewport().mapToGlobal(position))

    def add_menu_items(self, menu: QMenu, account: AbstractAccount, main_window: ElectrumWindow) \
            -> None:
        menu.clear()

        # This expects a reference to the main window, not the weakref.
        account_id = account.get_id()

        menu.addAction(_("&Information"),
            partial(self._show_account_information, account_id))
        seed_menu = menu.addAction(_("View &Secured Data"),
            partial(self._view_secured_data, main_window=main_window, account_id=account_id))
        seed_menu.setEnabled(self._can_view_secured_data(account))
        menu.addAction(_("&Rename"),
            partial(self._rename_account, account_id))
        menu.addSeparator()

        private_keys_menu = menu.addMenu(_("&Private keys"))
        import_menu = private_keys_menu.addAction(_("&Import"), partial(self._import_privkey,
                main_window=main_window, account_id=account_id))
        import_menu.setEnabled(account.can_import_privkey())
        export_menu = private_keys_menu.addAction(_("&Export"), partial(self._export_privkeys,
            main_window=main_window, account_id=account_id))
        export_menu.setEnabled(account.can_export())
        if account.can_import_address():
            menu.addAction(_("Import addresses"), partial(self._import_addresses, account_id))

        menu.addSeparator()

        hist_menu = menu.addMenu(_("&History"))
        hist_menu.addAction("Export", main_window.export_history_dialog)

        labels_menu = menu.addMenu(_("&Labels"))
        action = labels_menu.addAction(_("&Import"),
            partial(self._on_menu_import_labels, account_id))
        labels_menu.addAction(_("&Export"), partial(self._on_menu_export_labels, account_id))

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

    def _on_menu_import_labels(self, account_id: int) -> None:
        self._main_window.do_import_labels(account_id)

    def _on_menu_export_labels(self, account_id: int) -> None:
        self._main_window.do_export_labels(account_id)

    def _on_menu_import_invoices(self, account_id: int) -> None:
        pass
    # TODO(invoice-import) What format are these imported files? No idea.
    #     send_view = self._main_window.get_send_view(account_id)
    #     send_view.import_invoices()

    def _rename_account(self, account_id: int) -> None:
        assert self._current_account_id is not None
        account = self._main_window._wallet.get_account(self._current_account_id)
        assert account is not None
        new_account_name = line_dialog(self, _("Rename account"), _("Account name"), _("OK"),
            account.get_name())
        if new_account_name is None:
            return
        account.set_name(new_account_name)
        account_item = self._account_tree_items[account_id]
        account_item.setText(TreeColumns.MAIN, new_account_name)

    def _show_account_information(self, account_id: int) -> None:
        dialog = AccountDialog(self._main_window, self._wallet, account_id, self)
        dialog.exec_()

    def _on_menu_generate_destinations(self, account_id: int) -> None:
        from . import payment_destinations_dialog
        from importlib import reload
        reload(payment_destinations_dialog)
        dialog = payment_destinations_dialog.PaymentDestinationsDialog(self._main_window,
            self._wallet, account_id, self)
        dialog.exec_()

    def _on_menu_blockchain_scan(self, account_id: int) -> None:
        if not self._main_window.has_connected_main_server():
            MessageBox.show_message(_("The wallet is not currently connected to an indexing "
                "server. As such, the blockchain scanner cannot be used at this time."),
                self._main_window.reference())
            return

        from . import blockchain_scan_dialog
        # from importlib import reload # TODO(dev-helper) Remove at some point.
        # reload(blockchain_scan_dialog)
        dialog = blockchain_scan_dialog.BlockchainScanDialog(self._main_window,
            self._wallet, account_id, ScanDialogRole.MANUAL_RESCAN)
        dialog.exec_()

    def _can_view_secured_data(self, account: AbstractAccount) -> bool:
        return bool(not account.is_watching_only() and not isinstance(account, MultisigAccount)
            and not account.involves_hardware_wallet()
            and account.type() != AccountType.IMPORTED_PRIVATE_KEY)

    @protected
    def _view_secured_data(self, main_window: ElectrumWindow, account_id: int=-1,
            password: Optional[str]=None) -> None:
        # account_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        account = self._wallet.get_account(account_id)
        assert account is not None
        if self._can_view_secured_data(account):
            keystore = account.get_keystore()
            assert keystore is not None
            from .secured_data_dialog import SecuredDataDialog
            assert password is not None
            d = SecuredDataDialog(self._main_window, self, keystore, password)
            d.exec_()
        else:
            MessageBox.show_message(_("This type of account has no secured data. You are advised "
                "to manually back up this wallet."), self._main_window.reference())

    @protected
    def _import_privkey(self, main_window: ElectrumWindow, account_id: int=-1,
            password: Optional[str]=None) -> None:
        # account_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        account = cast(ImportedPrivkeyAccount, self._wallet.get_account(account_id))

        title, msg = _('Import private keys'), _("Enter private keys")
        # NOTE(typing) `password` is non-None here, but we cannot do an assertion that is the case
        #   and have the type checker (pylance) observe it in the lambda.
        self._main_window._do_import(title, msg,
            lambda x: account.import_private_key(x, password)) # type:ignore

    def _import_addresses(self, account_id: int) -> None:
        account = cast(ImportedAddressAccount, self._wallet.get_account(account_id))

        title, msg = _('Import addresses'), _("Enter addresses")
        def import_addr(addr: str) -> None:
            address = address_from_string(addr)
            account.import_address(address)
        self._main_window._do_import(title, msg, import_addr)

    @protected
    def _export_privkeys(self, main_window: ElectrumWindow, account_id: int=-1,
            password: Optional[str]=None) -> None:
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
        hbox, filename_e, csv_button = filename_field(main_window.config, defaultname,
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

        if not d.exec_():
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
            MessageBox.show_message(str(exc), main_window.reference())
            return

        MessageBox.show_message(_('Private keys exported'), main_window.reference())

    def _do_export_privkeys(self, fileName: str, pklist: Dict[str, str], is_csv: bool) -> None:
        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f)
                transaction.writerow(["reference", "private_key"])
                for key_text, pk in pklist.items():
                    transaction.writerow([key_text, pk])
            else:
                f.write(json.dumps(pklist, indent = 4))

    def _select_home(self) -> None:
        # Display the dashboard / home widget in the pane view.
        self._pane_view.setCurrentWidget(self._home_widget)

    def _select_accounts_parent(self) -> None:
        # Display the accounts widget in the pane view.
        # TODO(no-checkin) Not sure what this does yet. In theory it could be show all account
        #   content, but that might be messy for balances.
        self._pane_view.setCurrentWidget(self._accounts_widget)

    def _select_account(self, account_id: int) -> bool:
        self._pane_view.setCurrentWidget(self._tab_widget)

        if self._update_active_account(account_id):
            account = self._main_window._wallet.get_account(account_id)
            assert account is not None
            self._update_window_account(account)
            return True
        return False
