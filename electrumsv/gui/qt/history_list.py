#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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

import csv
import enum
from functools import partial
import json
import os
import threading
import time
from typing import Union, Optional
import webbrowser

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QBrush, QFont, QIcon, QColor
from PyQt5.QtWidgets import (QDialog, QListWidget, QListWidgetItem, QMenu, QSplitter, QWidget,
    QVBoxLayout, QGridLayout, QLabel, QTextEdit)

from electrumsv.app_state import app_state
from electrumsv.bitcoin import COINBASE_MATURITY, address_from_string
from electrumsv.i18n import _
from electrumsv.platform import platform
from electrumsv.util import timestamp_to_datetime, profiler, format_time

from electrumsv.wallet import Abstract_Wallet, ParentWallet, Multisig_Wallet
import electrumsv.web as web

from .main_window import ElectrumWindow
from .qrtextedit import ShowQRTextEdit
from .util import (MyTreeWidget, SortableTreeWidgetItem, read_QIcon, MessageBox, protected,
    Buttons, CloseButton, ChoicesLayout, WindowModalDialog, filename_field, OkButton,
    CancelButton)


class TxStatus(enum.IntEnum):
    MISSING = 0
    UNCONFIRMED = 1
    UNVERIFIED = 2
    UNMATURED = 3
    FINAL = 4

TX_ICONS = [
    "icons8-question-mark-96.png",      # Missing.
    "icons8-checkmark-grey-52.png",     # Unconfirmed.
    "icons8-checkmark-grey-52.png",     # Unverified.
    "icons8-lock-96.png",               # Unmatured.
    "icons8-checkmark-green-52.png",    # Confirmed / verified.
]

TX_STATUS = {
    TxStatus.FINAL: _('Confirmed'),
    TxStatus.MISSING: _('Missing'),
    TxStatus.UNCONFIRMED: _('Unconfirmed'),
    TxStatus.UNMATURED: _('Unmatured'),
    TxStatus.UNVERIFIED: _('Unverified'),
}


class HistoryList(MyTreeWidget):
    filter_columns = [2, 3, 4]  # Date, Description, Amount

    def __init__(self, parent: QWidget, wallet: Abstract_Wallet) -> None:
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 3)
        self.wallet = wallet

        self.refresh_headers()
        self.setColumnHidden(1, True)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.AscendingOrder)

        self.monospace_font = QFont(platform.monospace_font)
        self.withdrawalBrush = QBrush(QColor("#BC1E1E"))
        self.invoiceIcon = read_QIcon("seal")

    def refresh_headers(self):
        headers = ['', '', _('Date'), _('Description') , _('Amount'), _('Balance')]
        fx = app_state.fx
        if fx and fx.show_history():
            headers.extend(['%s '%fx.ccy + _('Amount'), '%s '%fx.ccy + _('Balance')])
        self.update_headers(headers)

    def get_domain(self):
        '''Replaced in address_dialog.py'''
        return self.wallet.get_addresses()

    def on_update(self):
        self._on_update_history_list()

    @profiler
    def _on_update_history_list(self):
        wallet_id = self.wallet.get_id()
        h = self.wallet.get_history(self.get_domain())
        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole)[1] if item else None
        self.clear()
        fx = app_state.fx
        if fx:
            fx.history_used_spot = False
        for h_item in h:
            tx_hash, height, conf, timestamp, value, balance = h_item
            status = get_tx_status(self.wallet, tx_hash, height, conf, timestamp)
            status_str = get_tx_desc(status, timestamp)
            has_invoice = self.wallet.invoices.paid.get(tx_hash)
            icon = get_tx_icon(status)
            v_str = self.parent.format_amount(value, True, whitespaces=True)
            balance_str = self.parent.format_amount(balance, whitespaces=True)
            label = self.wallet.get_label(tx_hash)
            entry = ['', tx_hash, status_str, label, v_str, balance_str]
            if fx and fx.show_history():
                date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                for amount in [value, balance]:
                    text = fx.historical_value_str(amount, date)
                    entry.append(text)

            item = SortableTreeWidgetItem(entry)
            item.setIcon(0, icon)
            item.setToolTip(0, get_tx_tooltip(status, conf))
            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            if has_invoice:
                item.setIcon(3, self.invoiceIcon)
            for i in range(len(entry)):
                if i>3:
                    item.setTextAlignment(i, Qt.AlignRight)
                if i!=2:
                    item.setFont(i, self.monospace_font)
            if value and value < 0:
                item.setForeground(3, self.withdrawalBrush)
                item.setForeground(4, self.withdrawalBrush)
            item.setData(0, Qt.UserRole, (wallet_id, tx_hash))
            self.insertTopLevelItem(0, item)
            if current_tx == tx_hash:
                self.setCurrentItem(item)

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            super(HistoryList, self).on_doubleclick(item, column)
        else:
            wallet_id, tx_hash = item.data(0, Qt.UserRole)
            wallet = self.parent.parent_wallet.get_wallet_for_account(wallet_id)
            tx = wallet.get_transaction(tx_hash)
            if tx is not None:
                self.parent.show_transaction(tx)
            else:
                MessageBox.show_error(_("The full transaction is not yet present in your wallet."+
                    " Please try again when it has been obtained from the network."))

    def update_labels(self) -> None:
        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            wallet_id, txid = item.data(0, Qt.UserRole)
            wallet = self.parent.parent_wallet.get_wallet_for_account(wallet_id)
            label = wallet.get_label(txid)
            item.setText(3, label)

    def update_item(self, tx_hash, height, conf, timestamp) -> None:
        status = get_tx_status(self.wallet, tx_hash, height, conf, timestamp)
        icon = get_tx_icon(status)
        items = self.findItems(tx_hash, Qt.UserRole|Qt.MatchContains|Qt.MatchRecursive, column=1)
        if items:
            item = items[0]
            item.setIcon(0, icon)
            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            item.setText(2, get_tx_desc(status, timestamp))
            item.setToolTip(0, get_tx_tooltip(status, conf))

    def create_menu(self, position):
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return
        column = self.currentColumn()
        edit_data = item.data(0, Qt.UserRole)
        if not edit_data:
            return
        wallet_id, tx_hash = edit_data
        if column == 0:
            column_title = "ID"
            column_data = tx_hash
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column).strip()

        wallet = self.parent.parent_wallet.get_wallet_for_account(wallet_id)

        tx_URL = web.BE_URL(self.config, 'tx', tx_hash)
        height, _conf, _timestamp = wallet.get_tx_height(tx_hash)
        tx = wallet.get_transaction(tx_hash)
        if not tx: return # this happens sometimes on wallet synch when first starting up.
        # is_relevant, is_mine, v, fee = self.wallet.get_wallet_delta(tx)
        is_unconfirmed = height <= 0
        pr_key = wallet.invoices.paid.get(tx_hash)

        menu = QMenu()
        menu.addAction(_("Copy {}").format(column_title),
            lambda: self.parent.app.clipboard().setText(column_data))
        if column in self.editable_columns:
            # We grab a fresh reference to the current item, as it has been deleted in a
            # reported issue.
            menu.addAction(_("Edit {}").format(column_title),
                lambda: self.currentItem() and self.editItem(self.currentItem(), column))
        label = wallet.get_label(tx_hash) or None
        menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx, label))
        if is_unconfirmed and tx:
            child_tx = wallet.cpfp(tx, 0)
            if child_tx:
                menu.addAction(_("Child pays for parent"),
                    lambda: self.parent.cpfp(wallet, tx, child_tx))
        if pr_key:
            menu.addAction(read_QIcon("seal"), _("View invoice"),
                           lambda: self.parent.show_invoice(pr_key))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))


def get_tx_status(wallet: Abstract_Wallet, tx_hash: str, height: int, conf: int,
        timestamp: Union[bool, int]) -> TxStatus:
    if not wallet.have_transaction_data(tx_hash):
        return TxStatus.MISSING

    if wallet.is_coinbase_transaction(tx_hash):
        if height + COINBASE_MATURITY > wallet.get_local_height():
            return TxStatus.UNMATURED
    elif conf == 0:
        if height > 0:
            return TxStatus.UNVERIFIED
        return TxStatus.UNCONFIRMED

    return TxStatus.FINAL

def get_tx_desc(status: TxStatus, timestamp: Union[bool, int]) -> str:
    if status in [ TxStatus.UNCONFIRMED, TxStatus.MISSING ]:
        return TX_STATUS[status]
    return format_time(timestamp, _("unknown")) if timestamp else _("unknown")

def get_tx_tooltip(status: TxStatus, conf: int) -> str:
    text = str(conf) + " confirmation" + ("s" if conf != 1 else "")
    if status == TxStatus.UNMATURED:
        text = text + "\n" + _("Unmatured")
    elif status in TX_STATUS:
        text = text + "\n"+ TX_STATUS[status]
    return text

def get_tx_icon(status: TxStatus) -> QIcon:
    return read_QIcon(TX_ICONS[status])


class HistoryView(QSplitter):
    computing_privkeys_signal = pyqtSignal()
    show_privkeys_signal = pyqtSignal()

    def __init__(self, parent: ElectrumWindow, parent_wallet: ParentWallet) -> None:
        super().__init__(parent)

        self._main_window = parent
        self._parent_wallet = parent_wallet

        # Left-hand side a list of wallets.
        # Right-hand side a history view showing the current wallet.
        self._selection_list = QListWidget()
        self._history_list = HistoryList(parent, parent_wallet.get_default_wallet())

        self.addWidget(self._selection_list)
        self.addWidget(self._history_list)

        self.setStretchFactor(1, 2)

        self._selection_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._selection_list.customContextMenuRequested.connect(self._create_wallet_menu)

        self._update_wallet_list()

    def _update_wallet_list(self) -> None:
        for child_wallet in self._parent_wallet.get_child_wallets():
            item = QListWidgetItem()
            item.setData(Qt.UserRole, child_wallet.get_id())
            item.setText(child_wallet.display_name())
            self._selection_list.addItem(item)

    def _create_wallet_menu(self, position) -> None:
        item = self._selection_list.currentItem()
        if not item:
            return

        wallet_id = item.data(Qt.UserRole)
        wallet = self._parent_wallet.get_wallet_for_account(wallet_id)

        menu = QMenu()
        menu.addAction(_("&Information"),
            partial(self._show_master_public_keys, wallet_id))
        seed_menu = menu.addAction(_("&Seed"),
            partial(self._show_seed_dialog, wallet_id=wallet_id))
        seed_menu.setEnabled(wallet.has_seed())
        menu.addSeparator()

        private_keys_menu = menu.addMenu(_("&Private keys"))
        private_keys_menu.addAction(_("&Sweep"),
            partial(self._main_window.sweep_key_dialog, wallet_id))
        import_privkey_menu = private_keys_menu.addAction(_("&Import"),
            partial(self._import_privkey, wallet_id=wallet_id))
        import_privkey_menu.setVisible(wallet.can_import_privkey())
        export_menu = private_keys_menu.addAction(_("&Export"),
            partial(self.export_privkeys_dialog, wallet_id=wallet_id))
        export_menu.setEnabled(wallet.can_export())

        import_address_menu = menu.addAction(_("Import addresses"),
            partial(self._import_addresses, wallet_id))
        import_address_menu.setVisible(wallet.can_import_address())

        menu.addSeparator()

        labels_menu = menu.addMenu(_("&Labels"))
        labels_menu.addAction(_("&Import"), partial(self._main_window.do_import_labels, wallet_id))
        labels_menu.addAction(_("&Export"), partial(self._main_window.do_export_labels, wallet_id))

        menu.exec_(self._selection_list.viewport().mapToGlobal(position))

    @property
    def searchable_list(self) -> HistoryList:
        return self._history_list

    def update_tx_list(self) -> None:
        self._history_list.update()

    def update_tx_headers(self) -> None:
        self._history_list.refresh_headers()

    def update_tx_labels(self) -> None:
        self._history_list.update_labels()

    def update_tx_item(self, tx_hash: str, height, conf, timestamp) -> None:
        self._history_list.update_item(tx_hash, height, conf, timestamp)

    def _show_master_public_keys(self, wallet_id):
        wallet = self._parent_wallet.get_wallet_for_account(wallet_id)

        dialog = QDialog(self)
        dialog.setWindowTitle(_("Wallet Information"))
        dialog.setMinimumSize(500, 100)
        mpk_list = wallet.get_master_public_keys()
        vbox = QVBoxLayout()
        wallet_type = wallet.wallet_type
        grid = QGridLayout()
        grid.addWidget(QLabel(_("Wallet name")+ ':'), 0, 0)
        grid.addWidget(QLabel(wallet.display_name()), 0, 1)
        grid.addWidget(QLabel(_("Wallet type")+ ':'), 1, 0)
        grid.addWidget(QLabel(wallet_type), 1, 1)
        grid.addWidget(QLabel(_("Script type")+ ':'), 2, 0)
        grid.addWidget(QLabel(wallet.txin_type), 2, 1)
        vbox.addLayout(grid)
        if wallet.is_deterministic():
            mpk_text = ShowQRTextEdit()
            mpk_text.setMaximumHeight(150)
            mpk_text.addCopyButton(self._main_window.app)
            def show_mpk(index):
                mpk_text.setText(mpk_list[index])
                mpk_text.repaint()   # macOS hack for Electrum #4777
            # only show the combobox in case multiple accounts are available
            if len(mpk_list) > 1:
                def label(key):
                    if isinstance(wallet, Multisig_Wallet):
                        return _("cosigner") + ' ' + str(key+1)
                    return ''
                labels = [label(i) for i in range(len(mpk_list))]
                on_click = lambda clayout: show_mpk(clayout.selected_index())
                labels_clayout = ChoicesLayout(_("Master Public Keys"), labels, on_click)
                vbox.addLayout(labels_clayout.layout())
            else:
                vbox.addWidget(QLabel(_("Master Public Key")))
            show_mpk(0)
            vbox.addWidget(mpk_text)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()

    @protected
    def _show_seed_dialog(self, wallet_id: int=-1, password: Optional[str]=None) -> None:
        # wallet_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        wallet = self._parent_wallet.get_wallet_for_account(wallet_id)
        if not wallet.has_seed():
            MessageBox.show_message(self._main_window, _('This wallet has no seed'))
            return

        keystore = wallet.get_keystore()
        try:
            seed = keystore.get_seed(password)
            passphrase = keystore.get_passphrase(password)
        except Exception as e:
            MessageBox.show_error(self._main_window, str(e))
            return

        from .seed_dialog import SeedDialog
        d = SeedDialog(self._main_window, seed, passphrase)
        d.exec_()

    @protected
    def _import_privkey(self, wallet_id: int=-1, password: Optional[str]=None) -> None:
        # wallet_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        wallet = self._parent_wallet.get_wallet_for_account(wallet_id)

        title, msg = _('Import private keys'), _("Enter private keys")
        self._main_window._do_import(title, msg,
            lambda x: wallet.import_private_key(x, password))

    @protected
    def export_privkeys_dialog(self, wallet_id: int=-1, password: Optional[str]=None):
        # wallet_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        wallet = self._parent_wallet.get_wallet_for_account(wallet_id)

        if wallet.is_watching_only():
            MessageBox.show_message(self, _("This is a watching-only wallet"))
            return

        if isinstance(wallet, Multisig_Wallet):
            MessageBox.show_message(self,
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
        hbox, filename_e, csv_button = filename_field(self._main_window.config,
            defaultname, select_msg)
        vbox.addLayout(hbox)

        b = OkButton(d, _('Export'))
        b.setEnabled(False)
        vbox.addLayout(Buttons(CancelButton(d), b))

        private_keys = {}
        addresses = wallet.get_addresses()
        done = False
        cancelled = False
        def privkeys_thread():
            for addr in addresses:
                time.sleep(0.1)
                if done or cancelled:
                    break
                privkey = wallet.export_private_key(addr, password)
                private_keys[addr.to_string()] = privkey
                self.computing_privkeys_signal.emit()
            if not cancelled:
                self.computing_privkeys_signal.disconnect()
                self.show_privkeys_signal.emit()

        def show_privkeys():
            s = "\n".join('{}\t{}'.format(addr, privkey)
                          for addr, privkey in private_keys.items())
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
            "Please wait... %d/%d" % (len(private_keys),len(addresses))))
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
            MessageBox.show_critical(self, txt, title=_("Unable to create csv"))

        except Exception as e:
            MessageBox.show_message(self, str(e))
            return

        MessageBox.show_message(self, _("Private keys exported."))

    def _do_export_privkeys(self, fileName, pklist, is_csv):
        with open(fileName, "w+") as f:
            if is_csv:
                transaction = csv.writer(f)
                transaction.writerow(["address", "private_key"])
                for addr, pk in pklist.items():
                    transaction.writerow(["%34s"%addr,pk])
            else:
                f.write(json.dumps(pklist, indent = 4))

    def _import_addresses(self, wallet_id):
        wallet = self._parent_wallet.get_wallet_for_account(wallet_id)

        title, msg = _('Import addresses'), _("Enter addresses")
        def import_addr(addr):
            address = address_from_string(addr)
            if wallet.import_address(address):
                return address
            return None
        self._main_window._do_import(title, msg, import_addr)
