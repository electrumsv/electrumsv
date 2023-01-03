import csv
from functools import partial
import json
import os
import threading
import time
from typing import List, Optional, Sequence
import weakref

from PyQt5.QtCore import QEvent, QItemSelectionModel, QModelIndex, pyqtSignal, QSize, Qt
from PyQt5.QtGui import QPainter, QPaintEvent
from PyQt5.QtWidgets import (QLabel, QListWidget, QListWidgetItem, QMenu, QSplitter, QTabWidget,
    QTextEdit, QVBoxLayout)

from electrumsv.bitcoin import address_from_string, script_template_to_string
from electrumsv.constants import AccountType, DerivationType, KeystoreType
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.wallet import AbstractAccount, MultisigAccount, Wallet

from .account_dialog import AccountDialog
from .main_window import ElectrumWindow
from .util import (Buttons, CancelButton, filename_field, line_dialog, MessageBox, OkButton,
    protected, read_QIcon, WindowModalDialog)


class AccountsView(QSplitter):
    computing_privkeys_signal = pyqtSignal()
    show_privkeys_signal = pyqtSignal()

    def __init__(self, main_window: ElectrumWindow, wallet: Wallet) -> None:
        super().__init__(main_window)

        self._logger = logs.get_logger("accounts-view")
        self._main_window = weakref.proxy(main_window)
        self._wallet = wallet

        self._main_window.account_created_signal.connect(self._on_account_created)
        self._main_window.account_change_signal.connect(self._on_account_changed)

        # We subclass QListWidget so accounts cannot be deselected.
        class CustomListWidget(QListWidget):
            def selectionCommand(self, index: QModelIndex, event: Optional[QEvent]) \
                    -> QItemSelectionModel.SelectionFlags:
                flags = super().selectionCommand(index, event)
                if flags == QItemSelectionModel.Deselect:
                    return QItemSelectionModel.NoUpdate
                return flags

            def paintEvent(self, event: QPaintEvent) -> None:
                super().paintEvent(event)

                if self.count() > 0:
                    return

                painter = QPainter(self.viewport())
                painter.drawText(self.rect(), Qt.AlignCenter, _("Add an account.."))

        self._account_ids: List[int] = []
        self._tab_widget = QTabWidget()

        self._selection_list = CustomListWidget()
        self._selection_list.setMinimumWidth(150)
        self._selection_list.setIconSize(QSize(32, 32))
        self._selection_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._selection_list.customContextMenuRequested.connect(self._show_account_menu)
        self._selection_list.currentItemChanged.connect(self._on_current_item_changed)

        self._current_account_id: Optional[int] = None

        self.addWidget(self._selection_list)
        self.addWidget(self._tab_widget)

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
            row = self._account_ids.index(new_account_id)
            self._selection_list.setCurrentRow(row)

        # Invoice import is not supported.
        # if self._import_invoices_action is not None:
        #     self._import_invoices_action.setEnabled(self._main_window.is_send_view_active())

    def _on_current_item_changed(self, item: QListWidgetItem, last_item: QListWidgetItem) -> None:
        account_id = item.data(Qt.UserRole)
        # This should update the internal tracking, and also the active wallet account.
        if self._update_active_account(account_id):
            account = self._main_window._wallet.get_account(account_id)
            self._update_window_account(account)

    def _update_active_account(self, account_id: int) -> bool:
        if account_id == self._current_account_id:
            return False
        self._current_account_id = account_id
        return True

    def _update_window_account(self, account: AbstractAccount) -> None:
        self._main_window.set_active_account(account)

    def get_tab_widget(self) -> QTabWidget:
        return self._tab_widget

    def _initialize_account_list(self) -> None:
        self._selection_list.clear()
        self._account_ids.clear()

        # TODO(rt12): These should respect user ordering, and perhaps also later hierarchy.
        for account in self._wallet.get_accounts():
            self._add_account_to_list(account)

        if len(self._account_ids):
            self._selection_list.setCurrentRow(0)
            currentItem = self._selection_list.currentItem()
            account_id = currentItem.data(Qt.UserRole)
            if self._update_active_account(account_id):
                account = self._main_window._wallet.get_account(account_id)
                self._update_window_account(account)

    def _add_account_to_list(self, account: AbstractAccount) -> None:
        account_id = account.get_id()
        item = QListWidgetItem()
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
        item.setIcon(read_QIcon(icon_filename.format(icon_state)))
        item.setData(Qt.UserRole, account_id)
        item.setText(account.display_name())
        item.setToolTip(tooltip_text)
        self._selection_list.addItem(item)
        self._account_ids.append(account_id)

    def _show_account_menu(self, position) -> None:
        item = self._selection_list.currentItem()
        if not item:
            return

        account_id = item.data(Qt.UserRole)
        account = self._wallet.get_account(account_id)

        menu = QMenu()
        self.add_menu_items(menu, account, self._main_window)
        menu.exec_(self._selection_list.viewport().mapToGlobal(position))

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
        # Invoice import is not supported.
        self._import_invoices_action.setEnabled(False)
        # self._import_invoices_action.setEnabled(main_window.is_send_view_active())

        payments_menu = menu.addMenu(_("Payments"))
        ed_action = payments_menu.addAction(_("Export destinations"),
            partial(self._generate_destinations, account_id))
        keystore = account.get_keystore()
        ed_action.setEnabled(keystore is not None and
            keystore.type() != KeystoreType.IMPORTED_PRIVATE_KEY)

    def _on_menu_import_labels(self, account_id: int) -> None:
        self._main_window.do_import_labels(account_id)

    def _on_menu_export_labels(self, account_id: int) -> None:
        self._main_window.do_export_labels(account_id)

    def _on_menu_import_invoices(self, account_id: int) -> None:
        send_view = self._main_window.get_send_view(account_id)
        send_view.import_invoices()

    def _rename_account(self, account_id: int) -> None:
        account = self._main_window._wallet.get_account(self._current_account_id)
        new_account_name = line_dialog(self, _("Rename account"), _("Account name"), _("OK"),
            account.get_name())
        if new_account_name is None:
            return
        account.set_name(new_account_name)
        account_row = self._account_ids.index(account_id)
        item: QListWidgetItem = self._selection_list.item(account_row)
        item.setText(new_account_name)

    def _show_account_information(self, account_id: int) -> None:
        dialog = AccountDialog(self._main_window, self._wallet, account_id, self)
        dialog.exec_()

    def _generate_destinations(self, account_id) -> None:
        from . import payment_destinations_dialog
        from importlib import reload
        reload(payment_destinations_dialog)
        dialog = payment_destinations_dialog.PaymentDestinationsDialog(self._main_window,
            self._wallet, account_id, self)
        dialog.exec_()

    def _can_view_secured_data(self, account: AbstractAccount) -> None:
        return not account.is_watching_only() and not isinstance(account, MultisigAccount) \
            and not account.involves_hardware_wallet() \
            and account.type() != AccountType.IMPORTED_PRIVATE_KEY

    @protected
    def _view_secured_data(self, main_window: ElectrumWindow, account_id: int=-1,
            password: Optional[str]=None) -> None:
        # account_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        account = self._wallet.get_account(account_id)
        if self._can_view_secured_data(account):
            keystore = account.get_keystore()
            from .secured_data_dialog import SecuredDataDialog
            d = SecuredDataDialog(self._main_window, self, keystore, password)
            d.exec_()
        elif isinstance(account, MultisigAccount):
            self._show_account_information(account_id)
        else:
            MessageBox.show_message(_("This type of account has no secured data. You are advised "
                "to manually back up this wallet."), self._main_window.reference())

    @protected
    def _import_privkey(self, main_window: ElectrumWindow, account_id: int=-1,
            password: Optional[str]=None) -> None:
        # account_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        account = self._wallet.get_account(account_id)

        title, msg = _('Import private keys'), _("Enter private keys")
        self._main_window._do_import(title, msg,
            lambda x: account.import_private_key(x, password))

    def _import_addresses(self, account_id: int) -> None:
        account = self._wallet.get_account(account_id)

        title, msg = _('Import addresses'), _("Enter addresses")
        def import_addr(addr):
            address = address_from_string(addr)
            if account.import_address(address):
                return addr
            # Show duplicate addition same as good addition.
            return addr
        self._main_window._do_import(title, msg, import_addr)

    @protected
    def _export_privkeys(self, main_window: ElectrumWindow, account_id: int=-1,
            password: Optional[str]=None) -> None:
        account = self._wallet.get_account(account_id)

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
        keyinstance_ids = account.get_keyinstance_ids()
        done = False
        cancelled = False
        def privkeys_thread():
            for keyinstance_id in keyinstance_ids:
                time.sleep(0.1)
                if done or cancelled:
                    break
                privkey = account.export_private_key(keyinstance_id, password)
                script_template = account.get_script_template_for_id(keyinstance_id)
                script_text = script_template_to_string(script_template)
                private_keys[script_text] = privkey
                self.computing_privkeys_signal.emit()
            if not cancelled:
                self.computing_privkeys_signal.disconnect()
                self.show_privkeys_signal.emit()

        def show_privkeys():
            s = "\n".join('{}\t{}'.format(script_text, privkey)
                          for script_text, privkey in private_keys.items())
            e.setText(s)
            b.setEnabled(True)
            self.show_privkeys_signal.disconnect()
            nonlocal done
            done = True

        def on_dialog_closed(*args):
            nonlocal done
            nonlocal cancelled
            if not done:
                cancelled = True
                self.computing_privkeys_signal.disconnect()
                self.show_privkeys_signal.disconnect()

        self.computing_privkeys_signal.connect(lambda: e.setText(
            "Please wait... %d/%d" % (len(private_keys),len(keyinstance_ids))))
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
        except Exception as e:
            MessageBox.show_message(str(e), main_window.reference())
            return

        MessageBox.show_message(_('Private keys exported'), main_window.reference())

    def _do_export_privkeys(self, fileName: str, pklist, is_csv):
        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f)
                transaction.writerow(["reference", "private_key"])
                for key_text, pk in pklist.items():
                    transaction.writerow([key_text, pk])
            else:
                f.write(json.dumps(pklist, indent = 4))

