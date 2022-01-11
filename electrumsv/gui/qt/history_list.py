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
from typing import Callable, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING
import weakref
import webbrowser

from bitcoinx import hash_to_hex_str, Header, Headers, MissingHeader

from PyQt5.QtCore import Qt, QPoint
from PyQt5.QtGui import QBrush, QIcon, QColor, QFont
from PyQt5.QtWidgets import QMenu, QMessageBox, QTreeWidgetItem, QVBoxLayout, QWidget

from ...app_state import app_state
from ...bitcoin import COINBASE_MATURITY, TSCMerkleProof
from ...constants import BlockHeight, PaymentFlag, TxFlags
from ...i18n import _
from ...logs import logs
from ...paymentrequest import has_expired
from ...platform import platform
from ...util import format_posix_timestamp, get_posix_timestamp, posix_timestamp_to_datetime, \
    profiler
from ...wallet import AbstractAccount
from ...wallet_database.exceptions import TransactionRemovalError
from ... import web

from .constants import ICON_NAME_INVOICE_PAYMENT
from .table_widgets import TableTopButtonLayout
from .util import MyTreeWidget, read_QIcon, MessageBox, SortableTreeWidgetItem

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


logger = logs.get_logger("history-list")


class TxStatus(enum.IntEnum):
    MISSING = 0
    SIGNED = 1
    DISPATCHED = 2
    RECEIVED = 3
    UNCONFIRMED = 4
    UNVERIFIED = 5
    UNMATURED = 6
    FINAL = 7


TX_ICONS = {
    TxStatus.MISSING: "icons8-question-mark-96.png",
    TxStatus.FINAL: "icons8-checkmark-green-52.png",
    TxStatus.UNCONFIRMED: "icons8-checkmark-grey-52.png",
    TxStatus.UNMATURED: "icons8-lock-96.png",
    TxStatus.UNVERIFIED: "icons8-checkmark-grey-52.png",
}


TX_STATUS = {
    TxStatus.SIGNED: _('Signed'),
    TxStatus.DISPATCHED: _('Dispatched'),
    TxStatus.RECEIVED: _('Received'),
    TxStatus.FINAL: _('Confirmed'),
    TxStatus.MISSING: _('Missing'),
    TxStatus.UNCONFIRMED: _('Unconfirmed'),
    TxStatus.UNMATURED: _('Unmatured'),
    TxStatus.UNVERIFIED: _('Unverified'),
}

# This was intended to see if increasing the cell height would cause the monospace fonts to be
# aligned in the center.
# class ItemDelegate(QItemDelegate):
#     def __init__(self, parent: Optional[QWidget], height: int=-1) -> None:
#         super().__init__(parent)
#         self._height = height

#     def set_height(self, height: int) -> None:
#         self._height = height

#     def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
#         size = super().sizeHint(option, index)
#         if self._height != -1:
#             size.setHeight(self._height)
#         return size


class Columns(enum.IntEnum):
    STATUS = 0
    TX_ID = 1
    DATE = 2
    DESCRIPTION = 3
    AMOUNT = 4
    BALANCE = 5
    FIAT_AMOUNT = 6
    FIAT_BALANCE = 7


class HistoryList(MyTreeWidget):
    filter_columns = [ Columns.DATE, Columns.DESCRIPTION, Columns.AMOUNT ]
    ACCOUNT_ROLE = Qt.ItemDataRole.UserRole
    TX_ROLE = Qt.ItemDataRole.UserRole + 2

    def __init__(self, parent: QWidget, main_window: 'ElectrumWindow') -> None:
        MyTreeWidget.__init__(self, parent, main_window, self.create_menu, [], Columns.DESCRIPTION)

        self._main_window = cast("ElectrumWindow", weakref.proxy(main_window))
        self._account_id: Optional[int] = None
        self._account: Optional[AbstractAccount] = None
        self._wallet = main_window._wallet

        self._main_window.account_change_signal.connect(self._on_account_change)

        self.update_tx_headers()

        self.setUniformRowHeights(True)
        self.setColumnHidden(Columns.TX_ID, True)
        self.setSortingEnabled(True)
        self.sortByColumn(Columns.STATUS, Qt.SortOrder.DescendingOrder)

        self.monospace_font = QFont(platform.monospace_font)
        self.withdrawalBrush = QBrush(QColor("#BC1E1E"))
        self.invoiceIcon = read_QIcon(ICON_NAME_INVOICE_PAYMENT)

        # self._delegate = ItemDelegate(None, 50)
        # self.setItemDelegate(self._delegate)

    def _on_account_change(self, new_account_id: int, new_account: AbstractAccount) -> None:
        self.clear()
        self._account_id = new_account_id
        self._account = new_account

    def on_edited(self, item: QTreeWidgetItem, column: int, prior_text: str) -> None:
        '''Called only when the text actually changes'''
        text: Optional[str] = item.text(column).strip()
        if text == "":
            text = None
        account_id = item.data(Columns.STATUS, self.ACCOUNT_ROLE)
        tx_hash = item.data(Columns.STATUS, self.TX_ROLE)
        account = cast(AbstractAccount, self._wallet.get_account(account_id))
        account.set_transaction_label(tx_hash, text)

    def update_tx_headers(self) -> None:
        headers = ['', '', _('Date'), _('Description') , _('Amount'), _('Balance')]
        fx = app_state.fx
        if fx and fx.show_history():
            headers.extend(['%s '%fx.ccy + _('Amount'), '%s '%fx.ccy + _('Balance')])
        self.update_headers(headers)

    def get_domain(self) -> Optional[Sequence[int]]:
        '''Overridden in key_dialog.py'''
        return None

    def on_update(self) -> None:
        self._on_update_history_list()

    @profiler
    def _on_update_history_list(self) -> None:
        item = self.currentItem()
        current_tx_hash = item.data(Columns.STATUS, self.TX_ROLE) if item else None
        self.clear()
        if self._account is None:
            return
        fx = app_state.fx
        if fx:
            fx.history_used_spot = False

        local_height = self._wallet.get_local_height()
        headers_obj = cast(Headers, app_state.headers)
        lookup_header = headers_obj.lookup

        items = []
        for entry in self._account.get_history(self.get_domain()):
            row = entry.row
            tx_id = hash_to_hex_str(row.tx_hash)

            header = None
            conf = 0
            block_height = 0
            timestamp = False
            if row.block_hash is not None:
                try:
                    header, _chain = lookup_header(row.block_hash)
                    block_height = header.height
                    timestamp = header.timestamp
                    conf = 0 if block_height <= 0 else max(local_height - block_height + 1, 0)
                except MissingHeader:
                    # Most likely a transaction with a merkle proof that is waiting on the header
                    pass
            status = get_tx_status(self._account, row.tx_flags & TxFlags.MASK_STATE,
                block_height, row.block_position, conf)
            status_str = get_tx_desc(status, timestamp)
            v_str = app_state.format_amount(row.value_delta, True, whitespaces=True)
            balance_str = app_state.format_amount(entry.balance, whitespaces=True)
            line: List[str] = ["", tx_id, status_str,
                row.description if row.description is not None else "", v_str, balance_str]
            if fx and fx.show_history():
                date = posix_timestamp_to_datetime(
                    get_posix_timestamp() if conf <= 0 else timestamp)
                for amount in [row.value_delta, entry.balance]:
                    text = fx.historical_value_str(amount, date)
                    line.append(text)

            item = SortableTreeWidgetItem(line)
            icon = get_tx_icon(status)
            if icon is not None:
                item.setIcon(Columns.STATUS, icon)
            item.setToolTip(Columns.STATUS, get_tx_tooltip(status, conf))
            if row.tx_flags & TxFlags.PAYS_INVOICE:
                item.setIcon(Columns.DESCRIPTION, self.invoiceIcon)
            for i in range(len(line)):
                if i > Columns.DESCRIPTION:
                    item.setTextAlignment(i, Qt.AlignmentFlag.AlignRight |
                        Qt.AlignmentFlag.AlignVCenter)
                else:
                    item.setTextAlignment(i, Qt.AlignmentFlag.AlignLeft |
                        Qt.AlignmentFlag.AlignVCenter)
                if i != Columns.DATE:
                    item.setFont(i, self.monospace_font)
            if row.value_delta and row.value_delta < 0:
                item.setForeground(Columns.DESCRIPTION, self.withdrawalBrush)
                item.setForeground(Columns.AMOUNT, self.withdrawalBrush)
            item.setData(Columns.STATUS, SortableTreeWidgetItem.DataRole, entry.sort_key)
            item.setData(Columns.DATE, SortableTreeWidgetItem.DataRole, entry.sort_key)
            item.setData(Columns.STATUS, self.ACCOUNT_ROLE, self._account_id)
            item.setData(Columns.STATUS, self.TX_ROLE, row.tx_hash)

            # self.insertTopLevelItem(0, item)
            if current_tx_hash == row.tx_hash:
                self.setCurrentItem(item)

            items.append(item)

        self.addTopLevelItems(items)

    def on_doubleclick(self, item: QTreeWidgetItem, column: int) -> None:
        if self.permit_edit(item, column):
            super(HistoryList, self).on_doubleclick(item, column)
        else:
            account_id = item.data(Columns.STATUS, self.ACCOUNT_ROLE)
            tx_hash = item.data(Columns.STATUS, self.TX_ROLE)

            account = self._wallet.get_account(account_id)
            tx = self._wallet.get_transaction(tx_hash)
            if tx is not None:
                self._main_window.show_transaction(account, tx)
            else:
                MessageBox.show_error(_("The full transaction is not yet present in your wallet."+
                    " Please try again when it has been obtained from the network."))

    def update_descriptions(self, entries: List[Tuple[Optional[str], int, bytes]]) -> None:
        tx_hash_descriptions: Dict[bytes, Optional[str]] = {}
        for description, account_id, tx_hash in entries:
            if account_id == self._account_id:
                tx_hash_descriptions[tx_hash] = description

        if not len(tx_hash_descriptions):
            return

        root = self.invisibleRootItem()
        child_count = root.childCount()
        for i in range(child_count):
            item = root.child(i)
            tx_hash = item.data(Columns.STATUS, self.TX_ROLE)
            if tx_hash in tx_hash_descriptions:
                description = tx_hash_descriptions[tx_hash]
                item.setText(Columns.DESCRIPTION, description or "")

    # From the wallet 'verified' event.
    def update_tx_item(self, tx_hash: bytes, header: Header, tsc_proof: TSCMerkleProof) -> None:
        # External event may be called before the UI element has an account.
        if self._account is None:
            return

        local_height = self._wallet.get_local_height()
        confirmations = 0 if header.height <= 0 else max(local_height - header.height + 1, 0)
        status = get_tx_status(self._account, TxFlags.STATE_SETTLED, header.height,
            tsc_proof.transaction_index,
            confirmations)
        tx_id = hash_to_hex_str(tx_hash)
        items = self.findItems(tx_id,
            Qt.MatchFlag(Qt.MatchFlag.MatchContains | Qt.MatchFlag.MatchRecursive),
            column=Columns.TX_ID)
        if items:
            item = items[0]
            icon = get_tx_icon(status)
            if icon is not None:
                item.setIcon(Columns.STATUS, icon)
            item.setText(Columns.DATE, get_tx_desc(status, header.timestamp))
            item.setToolTip(Columns.STATUS, get_tx_tooltip(status, confirmations))

            # NOTE: This is a damned if you do and damned if you don't situation.
            # - If we update the now verified row then it is not guaranteed to be in final order.
            #   It will have been in order of date added to wallet before the update, and after
            #   the naive display update above will still be in that order. But on the next list
            #   update it will be in block order (height, position). CURRENT PROBLEM
            # - If we update the sorting information without correcting all the balances, then
            #   the balances will be out of order. WORSE PROBLEM.

            # NOTE: Update the balances and then update the sorting keys and it is correct?
            #       Manually updating the balances could be painful as we need to preserve the
            #       value_delta and regenerate the balance, the fiat value (if applicable) and
            #       the fiat balance (if applicable). And we need to do it in the order of sorting.
            #       At this point, the painfulness of this, seems to suggest we would be better off
            #       rewriting this whole thing to be paging based.

            # # Consistent sorting.
            # metadata = self._wallet._transaction_cache.get_metadata(tx_hash)
            # sort_key = block_height, metadata.position
            # item.setData(Columns.STATUS, SortableTreeWidgetItem.DataRole, sort_key)
            # item.setData(Columns.DATE, SortableTreeWidgetItem.DataRole, sort_key)

    def create_menu(self, position: QPoint) -> None:
        item = self.currentItem()
        if not item:
            return

        column = self.currentColumn()
        account_id = item.data(Columns.STATUS, self.ACCOUNT_ROLE)
        tx_hash = item.data(Columns.STATUS, self.TX_ROLE)
        if account_id is None or tx_hash is None:
            return

        if column == Columns.STATUS:
            column_title = "ID"
            column_data = hash_to_hex_str(tx_hash)
        else:
            column_title = self.headerItem().text(column)
            column_data = item.text(column).strip()

        account = self._wallet.get_account(account_id)
        assert account is not None
        assert self._account is not None

        tx_id = hash_to_hex_str(tx_hash)
        tx_URL = web.BE_URL(self.config, 'tx', tx_id)
        tx_with_context = account.get_transaction(tx_hash)
        assert tx_with_context is not None
        tx, tx_context = tx_with_context

        menu = QMenu()
        menu.addAction(_("Copy {}").format(column_title),
            lambda: self._main_window.app.clipboard().setText(column_data))
        if column in self.editable_columns:
            # We grab a fresh reference to the current item, as it has been deleted in a
            # reported issue.
            menu.addAction(_("Edit {}").format(column_title),
                lambda: self.editItem(self.currentItem(), column) if self.currentItem() else None)
        menu.addAction(_("Details"),
            cast(Callable[[], None], lambda: self._main_window.show_transaction(account, tx,
                tx_context)))

        flags = self._wallet.get_transaction_flags(tx_hash)
        if flags is not None and flags & TxFlags.PAYS_INVOICE:
            invoice_row = self._account._wallet.read_invoice(tx_hash=tx_hash)
            invoice_id = invoice_row.invoice_id if invoice_row is not None else None
            action = menu.addAction(read_QIcon(ICON_NAME_INVOICE_PAYMENT), _("View invoice"),
                    partial(self._show_invoice_window, invoice_id))
            action.setEnabled(invoice_id is not None)

        if tx_URL:
            menu.addAction(_("View on block explorer"),
                cast(Callable[[], None], lambda: webbrowser.open(tx_URL)))

        menu.addSeparator()

        if flags is not None and flags & TxFlags.STATE_CLEARED:
            child_tx = account.cpfp(tx, 0)
            if child_tx:
                menu.addAction(_("Child pays for parent"),
                    partial(self._main_window.cpfp, account, tx, child_tx))

        if flags is not None and flags & TxFlags.MASK_STATE_UNCLEARED != 0:
            if flags & TxFlags.PAYS_INVOICE:
                broadcast_action = menu.addAction(self.invoiceIcon, _("Pay invoice"))
                row = self._account._wallet.read_invoice(tx_hash=tx_hash)
                if row is None:
                    # The associated invoice has been deleted.
                    broadcast_action.setEnabled(False)
                elif row.flags & PaymentFlag.UNPAID == 0:
                    # The associated invoice has already been paid.
                    broadcast_action.setEnabled(False)
                elif has_expired(row.date_expires):
                    # The associated invoice has expired.
                    broadcast_action.setEnabled(False)
                else:
                    broadcast_action.triggered.connect(
                        partial(self._main_window.pay_invoice, row.invoice_id))
            else:
                menu.addAction(_("Broadcast"),
                    lambda: self._broadcast_transaction(tx_hash))

            menu.addAction(_("Remove from account"), partial(self._delete_transaction, tx_hash))

        menu.exec_(self.viewport().mapToGlobal(position))

    def _broadcast_transaction(self, tx_hash: bytes) -> None:
        tx = self._wallet.get_transaction(tx_hash)
        assert tx is not None
        self._main_window.broadcast_transaction(self._account, tx)

    def _show_invoice_window(self, invoice_id: int) -> None:
        row = self._wallet.read_invoice(invoice_id=invoice_id)
        if row is None:
            self._main_window.show_error(_("The invoice for the transaction has been deleted."))
            return
        assert self._account is not None
        self._main_window.show_invoice(self._account, row)

    def _delete_transaction(self, tx_hash: bytes) -> None:
        if self._main_window.question(_("Are you sure you want to remove this transaction?") +
                "<br/><br/>" +
                _("This removes the transaction from all associated accounts and frees up any "
                "coins that are allocated for it."), title=_("Remove transaction"),
                icon=QMessageBox.Warning):
            try:
                self._wallet.remove_transaction(tx_hash)
            except TransactionRemovalError as e:
                self._main_window.show_error(e.args[0])


def get_tx_status(account: AbstractAccount, state_flag: TxFlags, height: int,
        position: Optional[int], conf: int) -> TxStatus:
    # TODO `STATE_DISPATCHED`/`STATE_RECEIVED` should be handled differently at some point.
    if state_flag == TxFlags.STATE_SIGNED:
        return TxStatus.SIGNED
    elif state_flag == TxFlags.STATE_RECEIVED:
        return TxStatus.RECEIVED
    elif state_flag == TxFlags.STATE_DISPATCHED:
        return TxStatus.DISPATCHED

    if position == 0:
        if height + COINBASE_MATURITY > account._wallet.get_local_height():
            return TxStatus.UNMATURED
    elif state_flag == TxFlags.STATE_CLEARED:
        if height > BlockHeight.MEMPOOL:
            return TxStatus.UNVERIFIED
        return TxStatus.UNCONFIRMED

    return TxStatus.FINAL


def get_tx_desc(status: TxStatus, timestamp: Optional[int]) -> str:
    if status in { TxStatus.UNCONFIRMED, TxStatus.MISSING, TxStatus.SIGNED, TxStatus.DISPATCHED,
            TxStatus.RECEIVED }:
        return TX_STATUS[status]
    return format_posix_timestamp(timestamp, _("unknown")) if timestamp else _("unknown")


def get_tx_tooltip(status: TxStatus, conf: int) -> str:
    if status in { TxStatus.SIGNED, TxStatus.DISPATCHED, TxStatus.RECEIVED }:
        return _("This is a local signed transaction.")
    text = str(conf) + " confirmation" + ("s" if conf != 1 else "")
    if status == TxStatus.UNMATURED:
        text = text + "\n" + _("This is a mined block reward that is not spendable yet.")
    elif status in TX_STATUS:
        text = text + "\n"+ TX_STATUS[status]
    return text


def get_tx_icon(status: TxStatus) -> Optional[QIcon]:
    icon_filename = TX_ICONS.get(status)
    if icon_filename is None:
        return None
    return read_QIcon(icon_filename)


class HistoryView(QWidget):
    def __init__(self, parent: QWidget, main_window: 'ElectrumWindow') -> None:
        super().__init__(parent)

        self._main_window = weakref.proxy(main_window)

        self._account_id: Optional[int] = None
        self._account: Optional[AbstractAccount] = None

        self.list = HistoryList(parent, main_window)
        self._top_button_layout = TableTopButtonLayout()
        self._top_button_layout.refresh_signal.connect(self._main_window.refresh_wallet_display)
        self._top_button_layout.filter_signal.connect(self.filter_tx_list)
        self._top_button_layout.add_button("icons8-export-32-windows.png",
            self._main_window.export_history_dialog, _("Export history as.."))

        vbox = QVBoxLayout()
        vbox.setSpacing(0)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addLayout(self._top_button_layout)
        vbox.addWidget(self.list, 1)
        self.setLayout(vbox)

        main_window.account_change_signal.connect(self._on_account_changed)

    def _on_account_changed(self, new_account_id: int, new_account: AbstractAccount) -> None:
        self._account_id = new_account_id
        self._account = new_account

    def update_descriptions(self, entries: List[Tuple[Optional[str], int, bytes]]) -> None:
        self.list.update_descriptions(entries)

    def update_tx_headers(self) -> None:
        self.list.update_tx_headers()

    # From the wallet 'verified' event (not actually called see the list method).
    def update_tx_item(self, tx_hash: bytes, header: Header, tsc_proof: TSCMerkleProof) -> None:
        self.list.update_tx_item(tx_hash, header, tsc_proof)

    def update_tx_list(self) -> None:
        self.list.update()

    # Called externally via the Find menu option.
    def on_search_toggled(self) -> None:
        self._top_button_layout.on_toggle_filter()

    def filter_tx_list(self, text: str) -> None:
        self.list.filter(text)
