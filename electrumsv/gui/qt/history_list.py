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

import enum
from functools import partial
import time
from typing import List, Optional, Union, TYPE_CHECKING
import weakref
import webbrowser

from bitcoinx import hash_to_hex_str, MissingHeader

from PyQt5.QtCore import Qt, QPoint
from PyQt5.QtGui import QBrush, QFont, QIcon, QColor
from PyQt5.QtWidgets import QLabel, QMenu, QTreeWidgetItem, QVBoxLayout, QWidget

from electrumsv.app_state import app_state
from electrumsv.bitcoin import COINBASE_MATURITY
from electrumsv.constants import TxFlags
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.platform import platform
from electrumsv.util import timestamp_to_datetime, profiler, format_time
from electrumsv.wallet import AbstractAccount
from electrumsv.wallet_database.tables import InvoiceRow
import electrumsv.web as web

from .util import MyTreeWidget, SortableTreeWidgetItem, read_QIcon, MessageBox

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


logger = logs.get_logger("history-list")


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

    def __init__(self, parent: QWidget, main_window: 'ElectrumWindow') -> None:
        MyTreeWidget.__init__(self, parent, main_window, self.create_menu, [], 3)

        self._main_window = weakref.proxy(main_window)
        self._account_id: Optional[int] = None
        self._account: AbstractAccount = None
        self._wallet = main_window._wallet

        self._main_window.account_change_signal.connect(self._on_account_change)

        self.update_tx_headers()
        self.setColumnHidden(1, True)
        self.setSortingEnabled(True)
        self.sortByColumn(0, Qt.DescendingOrder)

        self.monospace_font = QFont(platform.monospace_font)
        self.withdrawalBrush = QBrush(QColor("#BC1E1E"))
        self.invoiceIcon = read_QIcon("seal")

    def _on_account_change(self, new_account_id: int, new_account: AbstractAccount) -> None:
        self.clear()
        old_account_id = self._account_id
        self._account_id = new_account_id
        self._account = new_account

    def update_tx_headers(self) -> None:
        headers = ['', '', _('Date'), _('Description') , _('Amount'), _('Balance')]
        fx = app_state.fx
        if fx and fx.show_history():
            headers.extend(['%s '%fx.ccy + _('Amount'), '%s '%fx.ccy + _('Balance')])
        self.update_headers(headers)

    @property
    def searchable_list(self) -> 'HistoryList':
        return self

    def get_domain(self) -> Optional[List[int]]:
        '''Replaced in address_dialog.py'''
        return None

    def on_update(self) -> None:
        self._on_update_history_list()

    @profiler
    def _on_update_history_list(self) -> None:
        item = self.currentItem()
        current_tx = item.data(0, Qt.UserRole)[1] if item else None
        self.clear()
        if self._account is None:
            return
        fx = app_state.fx
        if fx:
            fx.history_used_spot = False
        local_height = self._wallet.get_local_height()
        server_height = self._main_window.network.get_server_height() if self._main_window.network \
            else 0
        header_at_height = app_state.headers.header_at_height
        chain = app_state.headers.longest_chain()
        missing_header_heights = []
        for line, balance in self._account.get_history(self.get_domain()):
            tx_id = hash_to_hex_str(line.tx_hash)
            conf = 0 if line.height <= 0 else max(local_height - line.height + 1, 0)
            timestamp = False
            if line.height > 0:
                try:
                    timestamp = header_at_height(chain, line.height).timestamp
                except MissingHeader:
                    if line.height <= server_height:
                        missing_header_heights.append(line.height)
                    else:
                        logger.debug("Unable to backfill header at %d (> %d)",
                            line.height, server_height)
            status = get_tx_status(self._account, line.tx_hash, line.height, conf, timestamp)
            status_str = get_tx_desc(status, timestamp)
            icon = get_tx_icon(status)
            v_str = app_state.format_amount(line.value_delta, True, whitespaces=True)
            balance_str = app_state.format_amount(balance, whitespaces=True)
            label = self._wallet.get_transaction_label(line.tx_hash)
            entry = ['', tx_id, status_str, label, v_str, balance_str]
            if fx and fx.show_history():
                date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                for amount in [line.value_delta, balance]:
                    text = fx.historical_value_str(amount, date)
                    entry.append(text)

            item = SortableTreeWidgetItem(entry)
            item.setIcon(0, icon)
            item.setToolTip(0, get_tx_tooltip(status, conf))
            item.setData(0, SortableTreeWidgetItem.DataRole, line.sort_key)
            if line.tx_flags & TxFlags.PaysInvoice:
                item.setIcon(3, self.invoiceIcon)
            for i in range(len(entry)):
                if i>3:
                    item.setTextAlignment(i, Qt.AlignRight)
                if i!=2:
                    item.setFont(i, self.monospace_font)
            if line.value_delta and line.value_delta < 0:
                item.setForeground(3, self.withdrawalBrush)
                item.setForeground(4, self.withdrawalBrush)
            item.setData(0, Qt.UserRole, (self._account_id, line.tx_hash))
            self.insertTopLevelItem(0, item)
            if current_tx == line.tx_hash:
                self.setCurrentItem(item)
        if len(missing_header_heights) and self._main_window.network:
            self._main_window.network.backfill_headers_at_heights(missing_header_heights)

    def on_doubleclick(self, item: QTreeWidgetItem, column: int) -> None:
        if self.permit_edit(item, column):
            super(HistoryList, self).on_doubleclick(item, column)
        else:
            account_id, tx_hash = item.data(0, Qt.UserRole)
            account = self._wallet.get_account(account_id)
            tx = account.get_transaction(tx_hash)
            if tx is not None:
                self._main_window.show_transaction(account, tx)
            else:
                MessageBox.show_error(_("The full transaction is not yet present in your wallet."+
                    " Please try again when it has been obtained from the network."))

    def update_tx_labels(self) -> None:
        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            account_id, tx_hash = item.data(0, Qt.UserRole)
            label = self._wallet.get_transaction_label(tx_hash)
            item.setText(3, label)

    # From the wallet 'verified' event.
    def update_tx_item(self, tx_hash: bytes, height: int, conf: int, timestamp: int) -> None:
        # External event may be called before the UI element has an account.
        if self._account is None:
            return
        status = get_tx_status(self._account, tx_hash, height, conf, timestamp)
        icon = get_tx_icon(status)
        tx_id = hash_to_hex_str(tx_hash)
        items = self.findItems(tx_id, Qt.UserRole|Qt.MatchContains|Qt.MatchRecursive, column=1)
        if items:
            item = items[0]
            item.setIcon(0, icon)
            item.setData(0, SortableTreeWidgetItem.DataRole, (status, conf))
            item.setText(2, get_tx_desc(status, timestamp))
            item.setToolTip(0, get_tx_tooltip(status, conf))

    def create_menu(self, position: QPoint) -> None:
        self.selectedIndexes()
        item = self.currentItem()
        if not item:
            return
        column = self.currentColumn()
        edit_data = item.data(0, Qt.UserRole)
        if not edit_data:
            return
        account_id, tx_hash = edit_data
        if column == 0:
            column_title = "ID"
            column_data = hash_to_hex_str(tx_hash)
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column).strip()

        account = self._wallet.get_account(account_id)

        tx_id = hash_to_hex_str(tx_hash)
        tx_URL = web.BE_URL(self.config, 'tx', tx_id)
        height, _conf, _timestamp = self._wallet.get_tx_height(tx_hash)
        tx = account.get_transaction(tx_hash)
        if not tx: return # this happens sometimes on account synch when first starting up.
        is_unconfirmed = height <= 0
        invoice_row = self._account.invoices.get_invoice_for_tx_hash(tx_hash)

        menu = QMenu()
        menu.addAction(_("Copy {}").format(column_title),
            lambda: self._main_window.app.clipboard().setText(column_data))
        if column in self.editable_columns:
            # We grab a fresh reference to the current item, as it has been deleted in a
            # reported issue.
            menu.addAction(_("Edit {}").format(column_title),
                lambda: self.currentItem() and self.editItem(self.currentItem(), column))
        label = self._wallet.get_transaction_label(tx_hash) or None
        menu.addAction(_("Details"), lambda: self._main_window.show_transaction(account,
            tx, label))
        if is_unconfirmed and tx:
            child_tx = account.cpfp(tx, 0)
            if child_tx:
                menu.addAction(_("Child pays for parent"),
                    lambda: self._main_window.cpfp(account, tx, child_tx))
        if invoice_row is not None:
            menu.addAction(read_QIcon("seal"), _("View invoice"),
                partial(self._show_invoice_window, invoice_row))
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def _show_invoice_window(self, row: InvoiceRow) -> None:
        self._main_window.show_invoice(self._account, row)


def get_tx_status(account: AbstractAccount, tx_hash: bytes, height: int, conf: int,
        timestamp: Union[bool, int]) -> TxStatus:
    if not account.have_transaction_data(tx_hash):
        return TxStatus.MISSING

    metadata = account.get_transaction_metadata(tx_hash)
    if metadata.position == 0:
        if height + COINBASE_MATURITY > account._wallet.get_local_height():
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


class HistoryView(QWidget):
    def __init__(self, parent: QWidget, main_window: 'ElectrumWindow') -> None:
        super().__init__(parent)

        self._account_id: Optional[int] = None
        self._account: AbstractAccount = None

        # The history view is created before the transactions view, so this will be updated by
        # an event from the transactions view. If this ordering changes you may see that it is
        # not updated.
        self._local_count = 0
        self._local_value = 0
        label = self._local_summary_label = QLabel()
        label.setAlignment(Qt.AlignCenter)
        label.setToolTip(_("The account balance shown in the status bar does "
            "not include any coins allocated and used by transactions in the Transactions tab."
            "<br/><br/>"
            "This summary indicates the current balance of the Transactions tab."))
        label.setContentsMargins(5, 5, 5, 5)
        label.setVisible(False)

        self.list = HistoryList(parent, main_window)

        vbox = QVBoxLayout()
        vbox.setSpacing(0)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(label)
        vbox.addWidget(self.list)
        self.setLayout(vbox)

        self._update_transactions_tab_summary()

        main_window.account_change_signal.connect(self._on_account_changed)

    def _on_account_changed(self, new_account_id: int, new_account: AbstractAccount) -> None:
        self._account_id = new_account_id
        self._account = new_account

        self._update_transactions_tab_summary()

    def on_transaction_view_changed(self, account_id: int) -> None:
        if self._account_id == account_id:
            self._update_transactions_tab_summary()

    def _update_transactions_tab_summary(self) -> None:
        local_count = 0
        local_value = 0

        if self._account_id is not None:
            wallet = self._account.get_wallet()
            with wallet.get_transaction_delta_table() as table:
                local_value, local_count = table.read_balance(self._account_id,
                    mask=TxFlags.STATE_UNCLEARED_MASK)

        if local_count == 0:
            self._local_summary_label.setVisible(False)
            return

        value_text = app_state.format_amount(local_value) +" "+ app_state.base_unit()
        if local_count == 1:
            text = _("The Transactions tab has <b>1</b> transaction containing <b>{balance}</b> "
                "in allocated coins.").format(balance=value_text)
        else:
            text = _("The Transactions tab has <b>{count}</b> transactions containing "
                "<b>{balance}</b> in allocated coins.").format(count=local_count,
                balance=value_text)
        self._local_summary_label.setText(text)
        self._local_summary_label.setVisible(True)

    def update_tx_headers(self) -> None:
        self.list.update_tx_headers()

    # From the wallet 'verified' event.
    def update_tx_item(self, tx_hash: bytes, height: int, conf: int, timestamp: int) -> None:
        self.list.update_tx_item(tx_hash, height, conf, timestamp)

    def update_tx_list(self) -> None:
        self.list.update()

    @property
    def searchable_list(self) -> 'HistoryList':
        return self.list
