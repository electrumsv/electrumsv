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

# TODO(rt12): Update pausing. We do not apply updates when the wallet is synchronising.
#   - The problem is that it seems to reach a point with larger wallets where it stops
#     synchronising and starts again, resulting in a partial update. Also, when a wallet is
#     first synchronised the list sits empty for ages.
#     - We should be able to batch additions/updates even further, and insert/update the data
#       before issuing the begin/end module events.
# TODO(rt12): Out of date indications.
#   - It is not obvious that the reason the list is not updated is because it is synchronising.
#     If we would otherwise pause updates, we might want to let the user choose to resume them.
# TODO(rt12): Type column icons are not horizontally centered.
#   - This is because the non-existent text (DisplayRole) is still the main focus. To fix this
#     requires perhaps using an item delegate and overriding the paint method to shift the icon
#     into the center.
# TODO(rt12): The beyond limit state is not currently updated or shown.
#   - I suspect the way forward for this is to have the wallet know the watermark and simply
#     respond and reflect changes in that.
# TODO(rt12): The index column for non-deterministic wallets is perhaps meaningless as is.
#   - It is possible to add some addresses, delete an earlier one, add a new one, and have
#     duplicate index numbers for different rows.

from collections import namedtuple
import enum
from functools import partial
import threading
import time
from typing import List, Any, Optional, Dict, Tuple, Iterable, Set
import webbrowser

from PyQt5.QtCore import (QAbstractItemModel, QModelIndex, QVariant, Qt, QSortFilterProxyModel,
    QTimer)
from PyQt5.QtGui import QFont, QBrush, QColor, QKeySequence
from PyQt5.QtWidgets import QTableView, QAbstractItemView, QHeaderView, QMenu, QWidget
from bitcoinx import Address

from electrumsv.i18n import _
from electrumsv.app_state import app_state
from electrumsv.bitcoin import address_from_string
from electrumsv.keystore import Hardware_KeyStore
from electrumsv.logs import logs
from electrumsv.networks import Net
from electrumsv.platform import platform
from electrumsv.util import profiler
from electrumsv.wallet import Multisig_Wallet, Abstract_Wallet
import electrumsv.web as web

from .util import read_QIcon, get_source_index


QT_SORT_ROLE = Qt.UserRole+1

COLUMN_NAMES = [ _("Type"), _("State"), _('Address'), _('Index'), _('Label'), _('Usages'),
    _('Balance'), _('') ]

TYPE_COLUMN = 0
STATE_COLUMN = 1
ADDRESS_COLUMN = 2
INDEX_COLUMN = 3
LABEL_COLUMN = 4
USAGES_COLUMN = 5
BALANCE_COLUMN = 6
FIAT_BALANCE_COLUMN = 7


class EventFlags(enum.IntFlag):
    UNSET = 0 << 0
    ADDRESS_ADDED = 1 << 0
    ADDRESS_UPDATED = 1 << 1
    ADDRESS_REMOVED = 1 << 2

    ADDRESS_RECEIVING = 1 << 8
    ADDRESS_CHANGE = 1 << 9
    TYPE_MASK = ADDRESS_RECEIVING | ADDRESS_CHANGE

    LABEL_UPDATE = 1 << 13
    FREEZE_UPDATE = 1 << 14


class ListActions(enum.IntEnum):
    RESET = 1
    RESET_BALANCES = 2
    RESET_FIAT_BALANCES = 3


class AddressFlags(enum.IntFlag):
    # Type related.
    RECEIVING = 1 << 0
    CHANGE = 1 << 1
    TYPE_MASK = RECEIVING | CHANGE

    # State related.
    FROZEN = 1 << 16
    RETIRED = 1 << 17
    BEYOND_LIMIT = 1 << 18


LI_FLAGS = 0
LI_ADDRESS = 1
LI_INDEX = 2
LI_BALANCE = 3


class AddressLine(namedtuple("AddressLine", "flags, address, index, balance")):
    pass

def get_sort_key(line: AddressLine) -> Any:
    # This is the sorting used for insertion of new lines, or updating lines where the line
    # needs to be removed from it's current row and inserted into the new row position.
    return (line.flags & AddressFlags.TYPE_MASK, line.index)


class _ItemModel(QAbstractItemModel):
    def __init__(self, parent: Any, column_names: List[str]) -> None:
        super().__init__(parent)

        self._view = parent
        self._logger = self._view._logger

        self._column_names = column_names
        self._balances = None

        self._monospace_font = QFont(platform.monospace_font)

        self._receive_icon = read_QIcon("icons8-down-arrow-96")
        self._change_icon = read_QIcon("icons8-rotate-96")

        self._frozen_brush = QBrush(QColor('lightblue'))
        self._beyond_limit_brush = QBrush(QColor('red'))
        self._archived_brush = QBrush(QColor('lightgrey'))

    def set_column_names(self, column_names: List[str]) -> None:
        self._column_names = column_names[:]

    def set_column_name(self, column_index: int, column_name: str) -> None:
        self._column_names[column_index] = column_name

    def set_data(self, data: List[AddressLine]) -> None:
        self.beginResetModel()
        self._data = data
        self.endResetModel()

    def _get_row(self, address: Address) -> Optional[int]:
        # Get the offset of the line with the given transaction hash.
        for i, line in enumerate(self._data):
            if line.address == address:
                return i
        return None

    def _get_match_row(self, line: AddressLine) -> int:
        # Get the existing line that precedes where the given line would go.
        new_key = get_sort_key(line)
        for i in range(len(self._data)-1, -1, -1):
            key = get_sort_key(self._data[i])
            if new_key >= key:
                return i
        return -1

    def _add_line(self, line: AddressLine) -> int:
        match_row = self._get_match_row(line)
        insert_row = match_row + 1

        # Signal the insertion of the new row.
        self.beginInsertRows(QModelIndex(), insert_row, insert_row)
        row_count = self.rowCount(QModelIndex())
        if insert_row == row_count:
            self._data.append(line)
        else:
            # Insert the data entries.
            self._data.insert(insert_row, line)
        self.endInsertRows()

        return insert_row

    def remove_row(self, row: int) -> AddressLine:
        line = self._data[row]

        self.beginRemoveRows(QModelIndex(), row, row)
        del self._data[row]
        self.endRemoveRows()

        return line

    def add_line(self, line: AddressLine) -> None:
        # The `_add_line` will signal it's line insertion.
        insert_row = self._add_line(line)

        # If there are any other rows that need to be updated relating to the data in that
        # line, here is the place to do it.  Then signal what has changed.

    def update_line(self, address: Address, values: Dict[int, Any]) -> bool:
        row = self._get_row(address)
        if row is None:
            self._logger.debug("update_line called for non-existent entry %s", address.to_string())
            return False

        return self.update_row(row, values)

    def update_row(self, row: int, values: Dict[int, Any]) -> bool:
        old_line = self._data[row]
        self._logger.debug("update_line tx=%s idx=%d", old_line.address.to_string(), row)

        if len(values):
            l = list(old_line)
            for value_index, value in values.items():
                l[value_index] = value
            new_line = self._data[row] = AddressLine(*l)

            old_key = get_sort_key(old_line)
            new_key = get_sort_key(new_line)

            if old_key != new_key:
                # We need to move the line, so it is more than a simple row update.
                self.remove_row(row)
                insert_row = self._add_line(new_line)
                return True

        start_index = self.createIndex(row, 0)
        column_count = self.columnCount(start_index)
        end_index = self.createIndex(row, column_count-1)
        self.dataChanged.emit(start_index, end_index)

        return True

    def invalidate_cell_by_key(self, address: Address, column: int) -> None:
        row = self._get_row(address)
        if row is None:
            self._logger.debug("invalidate_cell_by_key called for non-existent key %s",
                address.to_string())
            return

        self.invalidate_cell(row, column)

    def invalidate_cell(self, row: int, column: int) -> None:
        cell_index = self.createIndex(row, column)
        self.dataChanged.emit(cell_index, cell_index)

    def invalidate_column(self, column: int) -> None:
        start_index = self.createIndex(0, column)
        row_count = self.rowCount(start_index)
        end_index = self.createIndex(row_count-1, column)
        self.dataChanged.emit(start_index, end_index)

    def invalidate_row(self, row: int) -> None:
        start_index = self.createIndex(row, 0)
        column_count = self.columnCount(start_index)
        end_index = self.createIndex(row, column_count-1)
        self.dataChanged.emit(start_index, end_index)

    # Overridden methods:

    def columnCount(self, model_index: QModelIndex) -> int:
        return len(self._column_names)

    def data(self, model_index: QModelIndex, role: int) -> QVariant:
        row = model_index.row()
        column = model_index.column()
        if row >= len(self._data):
            return None
        if column >= len(self._column_names):
            return None

        if model_index.isValid():
            line = self._data[row]

            # First check the custom sort role.
            if role == QT_SORT_ROLE:
                if column == TYPE_COLUMN:
                    if line.flags & AddressFlags.RECEIVING:
                        return 1
                    elif line.flags & AddressFlags.CHANGE:
                        return 2
                    return 100
                elif column == STATE_COLUMN:
                    if line.flags & AddressFlags.FROZEN:
                        return 1
                    elif line.flags & AddressFlags.RETIRED:
                        return 2
                    elif line.flags & AddressFlags.BEYOND_LIMIT:
                        return 3
                    return 0
                elif column == ADDRESS_COLUMN:
                    return line.address.hash160()
                elif column == INDEX_COLUMN:
                    return line.index
                elif column == LABEL_COLUMN:
                    return self._view._wallet.labels.get(line.address.to_string(), '')
                elif column == USAGES_COLUMN:
                    return len(self._view._wallet.get_address_history(line.address))
                elif column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN):
                    if column == BALANCE_COLUMN:
                        return self._view._parent.format_amount(line.balance, whitespaces=True)
                    elif column == FIAT_BALANCE_COLUMN:
                        fx = app_state.fx
                        rate = fx.exchange_rate()
                        return fx.value_str(line.balance, rate)

            elif role == Qt.DecorationRole:
                if column == TYPE_COLUMN:
                    if line.flags & AddressFlags.RECEIVING:
                        return self._receive_icon
                    elif line.flags & AddressFlags.CHANGE:
                        return self._change_icon

            elif role == Qt.DisplayRole:
                if column == TYPE_COLUMN:
                    pass
                elif column == STATE_COLUMN:
                    if line.flags & AddressFlags.BEYOND_LIMIT:
                        return "B"
                elif column == ADDRESS_COLUMN:
                    return line.address.to_string()
                elif column == INDEX_COLUMN:
                    return line.index
                elif column == LABEL_COLUMN:
                    return self._view._wallet.get_address_label(line.address.to_string())
                elif column == USAGES_COLUMN:
                    return len(self._view._wallet.get_address_history(line.address))
                elif column == BALANCE_COLUMN:
                    return self._view._parent.format_amount(line.balance, whitespaces=True)
                elif column == FIAT_BALANCE_COLUMN:
                    fx = app_state.fx
                    rate = fx.exchange_rate()
                    return fx.value_str(line.balance, rate)
            elif role == Qt.FontRole:
                if column in (ADDRESS_COLUMN, BALANCE_COLUMN, FIAT_BALANCE_COLUMN):
                    return self._monospace_font

            elif role == Qt.BackgroundRole:
                if column == STATE_COLUMN:
                    if line.flags & AddressFlags.FROZEN:
                        return self._frozen_brush
                    elif line.flags & AddressFlags.RETIRED:
                        return self._archived_brush
                    elif line.flags & AddressFlags.BEYOND_LIMIT:
                        return self._beyond_limit_brush
            elif role == Qt.TextAlignmentRole:
                if column in (TYPE_COLUMN, STATE_COLUMN):
                    return Qt.AlignCenter
                elif column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN, USAGES_COLUMN, INDEX_COLUMN):
                    return Qt.AlignRight | Qt.AlignVCenter
                return Qt.AlignVCenter

            elif role == Qt.ToolTipRole:
                if column == TYPE_COLUMN:
                    if line.flags & AddressFlags.RECEIVING:
                        return _("Receiving address")
                    elif line.flags & AddressFlags.CHANGE:
                        return _("Change address")
                elif column == STATE_COLUMN:
                    if line.flags & AddressFlags.FROZEN:
                        return _("This is a frozen address")
                    elif line.flags & AddressFlags.RETIRED:
                        return _("This an address that was once in use, "+
                            "but is now empty and has been retired")
                    elif line.flags & AddressFlags.BEYOND_LIMIT:
                        return _("This address is generated from beyond the current gap limit")

            elif role == Qt.EditRole:
                if column == LABEL_COLUMN:
                    return self._view._wallet.get_address_label(line.address.to_string())

    def flags(self, model_index: QModelIndex) -> int:
        if model_index.isValid():
            column = model_index.column()
            flags = super().flags(model_index)
            if column == LABEL_COLUMN:
                flags |= Qt.ItemIsEditable
            return flags
        return Qt.ItemIsEnabled

    def headerData(self, section: int, orientation: int, role: int) -> QVariant:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if section < len(self._column_names):
                return self._column_names[section]

    def index(self, row: int, column: int, parent: Any) -> QModelIndex:
        if self.hasIndex(row, column, parent):
            return self.createIndex(row, column)
        return QModelIndex()

    def parent(self, model_index: QModelIndex) -> QModelIndex:
        return QModelIndex()

    def rowCount(self, model_index: QModelIndex) -> int:
        return len(self._data)

    def setData(self, model_index: QModelIndex, value: QVariant, role: int) -> bool:
        if model_index.isValid() and role == Qt.EditRole:
            row = model_index.row()
            line = self._data[row]
            if model_index.column() == LABEL_COLUMN:
                self._view._wallet.set_label(line.address.to_string(), value)
            self.dataChanged.emit(model_index, model_index)
            return True
        return False


class _SortFilterProxyModel(QSortFilterProxyModel):
    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex) -> bool:
        value_left = self.sourceModel().data(source_left, QT_SORT_ROLE)
        value_right = self.sourceModel().data(source_right, QT_SORT_ROLE)
        return value_left < value_right


class AddressList(QTableView):
    def __init__(self, parent: QWidget, wallet: Abstract_Wallet) -> None:
        super().__init__(parent)

        self._parent = parent
        self._wallet = wallet
        self._logger = logs.get_logger(f"address-list[{wallet.name()}]")
        self._update_lock = threading.Lock()
        self._is_synchronizing = False

        self._headers = COLUMN_NAMES

        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)

        self._pending_state: Dict[Address, EventFlags] = {}
        self._pending_actions = set([ ListActions.RESET ])
        self._parent.addresses_created_signal.connect(self._on_addresses_created)
        self._parent.addresses_updated_signal.connect(self._on_addresses_updated)

        model = _ItemModel(self, self._headers)
        model.set_data([])
        self._base_model = model

        # If the underlying model changes, observe it in the sort.
        proxy_model = _SortFilterProxyModel()
        proxy_model.setDynamicSortFilter(True)
        proxy_model.setSortRole(QT_SORT_ROLE)
        proxy_model.setSourceModel(model)
        self.setModel(proxy_model)

        fx = app_state.fx
        self._set_fiat_columns_enabled(fx and fx.get_fiat_address_config())

        # Sort by type then by index, by making sure the initial sort is our type column.
        self.sortByColumn(TYPE_COLUMN, Qt.AscendingOrder)
        self.setSortingEnabled(True)

        self.horizontalHeader().setSectionResizeMode(LABEL_COLUMN, QHeaderView.Stretch)
        for i in range(FIAT_BALANCE_COLUMN):
            if i != LABEL_COLUMN:
                self.horizontalHeader().setSectionResizeMode(i, QHeaderView.ResizeToContents)
        self.horizontalHeader().setMinimumSectionSize(20)
        self.verticalHeader().setMinimumSectionSize(20)
        # The initial spacing of rows is generous. This will draw in the spacing based on the
        # initial data we have put in the model, and give a more professional compact layout.
        # If there is no initial data, then this should be ineffectual, so we also call this on
        # explicit post-creation addition of rows as well to cover that case.
        self.resizeRowsToContents()

        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        # New selections clear existing selections, unless the user holds down control.
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._event_create_menu)

        app_state.app.base_unit_changed.connect(self._on_balance_display_change)
        app_state.app.fiat_balance_changed.connect(self._on_fiat_balance_display_change)
        app_state.app.fiat_ccy_changed.connect(self._on_fiat_balance_display_change)
        app_state.app.labels_changed_signal.connect(self.update_labels)
        app_state.app.num_zeros_changed.connect(self._on_balance_display_change)

        self.setEditTriggers(QAbstractItemView.DoubleClicked)
        self.doubleClicked.connect(self._event_double_clicked)

        self._last_not_synced = 0
        self._timer = QTimer(self)
        self._timer.setSingleShot(False)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._on_update_check)
        self._timer.start()

    def clean_up(self) -> None:
        self._timer.stop()

    def keyPressEvent(self, event):
        if event.matches(QKeySequence.Copy):
            selected_indexes = self.selectedIndexes()
            if len(selected_indexes):
                # This is an index on the sort/filter model, translate it to the base model.
                selected = {}
                for selected_index in selected_indexes:
                    base_index = get_source_index(selected_index, _ItemModel)
                    row = base_index.row()
                    # We get an index for each selected cell, not just one per row.
                    if row not in selected:
                        selected[row] = self._data[row]

                # The imported address wallet splits on any type of whitespace and strips excess.
                text = "\n".join(line.address.to_string() for line in selected.values())
                self._parent.app.clipboard().setText(text)
        else:
            super().keyPressEvent(event)

    def _on_update_check(self) -> None:
        # No point in proceeding if no updates, or the wallet is synchronising still.
        if not self._have_pending_updates() or (time.time() - self._last_not_synced) < 5.0:
            return
        # We do not update if there has been a recent sync.
        if not self._parent.parent_wallet.is_synchronized():
            self._last_not_synced = time.time()
            return
        self._last_not_synced = 0

        with self._update_lock:
            pending_actions = self._pending_actions
            pending_state = self._pending_state
            self._pending_actions = set()
            self._pending_state = {}

        self._dispatch_updates(pending_actions, pending_state)

    def _have_pending_updates(self) -> bool:
        return len(self._pending_actions) or len(self._pending_state)

    @profiler
    def _dispatch_updates(self, pending_actions: Set[ListActions],
            pending_state: Dict[Address, EventFlags]) -> None:
        if ListActions.RESET in pending_actions:
            self._logger.debug("_on_update_check reset")

            receiving_addresses = self._wallet.get_receiving_addresses()[:]
            change_addresses = self._wallet.get_change_addresses()[:]
            self._data = self._create_data_snapshot(receiving_addresses, change_addresses)
            self._base_model.set_data(self._data)
            return

        additions = []
        updates = []
        removals = []
        for address, flags in pending_state.items():
            if flags & EventFlags.ADDRESS_ADDED:
                additions.append(address)
            elif flags & EventFlags.ADDRESS_UPDATED:
                updates.append(address)
            elif flags & EventFlags.ADDRESS_REMOVED:
                removals.append(address)

        # self._logger.debug("_on_update_check actions=%s adds=%d updates=%d removals=%d",
        #     pending_actions, len(additions), len(updates), len(removals))

        self._remove_addresses(removals)
        self._add_addresses(additions, pending_state)
        self._update_addresses(updates, pending_state)

        for action in pending_actions:
            if ListActions.RESET_BALANCES:
                self._base_model.invalidate_column(BALANCE_COLUMN)
            elif ListActions.RESET_FIAT_BALANCES:
                fx = app_state.fx
                flag = fx and fx.get_fiat_address_config()
                # This will show or hide the relevant columns as applicable.
                self._set_fiat_columns_enabled(flag)
                # This will notify the model that the relevant cells are changed.
                self._base_model.invalidate_column(FIAT_BALANCE_COLUMN)
            else:
                self._logger.error("_on_update_check action %s not applied", action)

        self.resizeRowsToContents()

    def _on_addresses_created(self, addresses: Iterable[Address], is_change: bool=False) -> None:
        flags = EventFlags.ADDRESS_ADDED
        if is_change:
            flags |= EventFlags.ADDRESS_CHANGE
        else:
            flags |= EventFlags.ADDRESS_RECEIVING
        for address in addresses:
            self._pending_state[address] = flags

    # Change in address history state.
    # - Archived.
    # - Usages.
    # - Balance.
    def _on_addresses_updated(self, addresses: Iterable[Address]) -> None:
        new_flags = EventFlags.ADDRESS_UPDATED
        for address in addresses:
            flags = self._pending_state.get(address, EventFlags.UNSET)
            self._pending_state[address] = flags | new_flags

    def _add_addresses(self, addresses: List[Address], state: Dict[Address, EventFlags]) -> None:
        self._logger.debug("_add_addresses %d", len(addresses))
        # self._logger.debug("_add_addresses %s",
        #     [ a.to_string(coin=Net.COIN) for a in addresses ])

        # TODO: Use state to identify if we know the receiving or change status of an address.
        receiving_addresses = self._wallet.get_receiving_addresses()[:]
        change_addresses = self._wallet.get_change_addresses()[:]

        for address in addresses:
            # See if we already know if it is change or receiving.
            event_flags = state[address] & EventFlags.TYPE_MASK
            if event_flags & EventFlags.ADDRESS_RECEIVING:
                is_change = False
                n = receiving_addresses.index(address)
            elif event_flags & EventFlags.ADDRESS_CHANGE:
                is_change = True
                n = change_addresses.index(address)
            else:
                is_change = True
                try:
                    n = change_addresses.index(address)
                except ValueError:
                    is_change = False
                    n = receiving_addresses.index(address)
            self._base_model.add_line(self._create_address_entry(address, is_change, n=n))

    def _update_addresses(self, addresses: List[Address], state: Dict[Address, EventFlags]) -> None:
        self._logger.debug("_update_addresses %d", len(addresses))
        # self._logger.debug("_update_addresses %s",
        #     [ a.to_string(coin=Net.COIN) for a in addresses ])

        # TODO(rt12): It should be possible to look at the state and see if partial updates
        # are enough.

        # Old frozen updating code.
        # for i, line in self._match_addresses(addresses):
        #     flags = line.flags
        #     if freeze:
        #         flags |= AddressFlags.FROZEN
        #     else:
        #         flags &= ~AddressFlags.FROZEN
        #     self._base_model.update_row(i, { LI_FLAGS: flags })

        # Old label updating code.
        # for row, line in self._match_addresses(addresses):
        #     self._base_model.invalidate_cell(row, LABEL_COLUMN)

        matches = self._match_addresses(addresses)
        if len(matches) != len(addresses):
            self._logger.debug("_update_addresses missing entries %s",
                [ a.to_string(coin=Net.COIN) for a in matches if a not in addresses ])
        for row, line in matches:
            new_line = self._create_address_entry(line.address,
                (line.flags & AddressFlags.CHANGE) == AddressFlags.CHANGE,
                (line.flags & AddressFlags.BEYOND_LIMIT) == AddressFlags.BEYOND_LIMIT,
                line.index)
            # TODO(rt12): It is possible that the beyond limit state has changed at this point
            # and that it is incorrect. We need to correct for that.
            self._data[row] = new_line
            self._base_model.invalidate_row(row)

    def _remove_addresses(self, addresses: List[Address]) -> None:
        self._logger.debug("_remove_addresses %d", len(addresses))
        # self._logger.debug("_remove_addresses %s",
        #     [ a.to_string(coin=Net.COIN) for a in addresses ])
        matches = self._match_addresses(addresses)
        if len(matches) != len(addresses):
            self._logger.debug("_remove_addresses missing entries %s",
                [ a.to_string(coin=Net.COIN) for a in matches if a not in addresses ])
        # Make sure that we will be removing rows from the last to the first, to preserve offsets.
        for row, line in sorted(matches, reverse=True, key=lambda v: v[0]):
            self._base_model.remove_row(row)

    # Called by the wallet window.
    def update_addresses(self, addresses: List[Address]) -> List[Address]:
        with self._update_lock:
            for address in addresses:
                flags = self._pending_state.get(address, EventFlags.UNSET)
                self._pending_state[address] = flags | EventFlags.ADDRESS_UPDATED

    # Called by the wallet window.
    def remove_addresses(self, addresses: List[Address]) -> None:
        with self._update_lock:
            for address in addresses:
                flags = self._pending_state.get(address, EventFlags.UNSET)
                self._pending_state[address] = flags | EventFlags.ADDRESS_REMOVED

   # Called by the wallet window.
    def update_frozen_addresses(self, addresses: List[Address], freeze: bool) -> None:
        with self._update_lock:
            new_flags = EventFlags.ADDRESS_UPDATED | EventFlags.FREEZE_UPDATE
            for address in addresses:
                flags = self._pending_state.get(address, EventFlags.UNSET)
                self._pending_state[address] = flags | new_flags

    # The user has toggled the preferences setting.
    def _on_balance_display_change(self) -> None:
        with self._update_lock:
            self._pending_actions.add(ListActions.RESET_BALANCES)

    # The user has toggled the preferences setting.
    def _on_fiat_balance_display_change(self) -> None:
        with self._update_lock:
            self._pending_actions.add(ListActions.RESET_FIAT_BALANCES)

    # The user has edited a label either here, or in some other wallet location.
    def update_labels(self, wallet: Abstract_Wallet, updates: Dict[str, str]) -> None:
        with self._update_lock:
            new_flags = EventFlags.ADDRESS_UPDATED | EventFlags.LABEL_UPDATE

            addresses = []
            for label_key in updates.keys():
                # Labels can be for both addresses and transactions.
                try:
                    address = address_from_string(label_key)
                except ValueError:
                    continue

                flags = self._pending_state.get(address, EventFlags.UNSET)
                self._pending_state[address] = flags | new_flags

    def _match_addresses(self, addresses: List[Address]) -> List[Tuple[int, AddressLine]]:
        matches = []
        _addresses = set(addresses)
        for row, line in enumerate(self._data):
            if line.address in _addresses:
                matches.append((row, line))
                if len(matches) == len(addresses):
                    break
        return matches

    # @profiler
    # def _create_data_snapshot(self) -> None:
    #     import cProfile, pstats, io
    #     from pstats import SortKey
    #     pr = cProfile.Profile()
    #     pr.enable()
    #     ret = self._create_data_snapshot2()
    #     pr.disable()
    #     s = io.StringIO()
    #     sortby = SortKey.CUMULATIVE
    #     ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    #     ps.print_stats()
    #     print(s.getvalue())
    #     return ret

    def _create_data_snapshot(self, receiving_addresses: Iterable[Address],
            change_addresses: Iterable[Address]) -> None:
        lines = []
        type_flags = [ AddressFlags.RECEIVING, AddressFlags.CHANGE ]
        sequences = [ 0, 1 ] if change_addresses else [ 0 ]
        def is_beyond_limit(address) -> bool:
            return False

        for is_change in sequences:
            addr_list = change_addresses if is_change else receiving_addresses
            # if self._wallet.is_deterministic():
            #     address_hashes = dict((a.hash160(), idx) for idx, a in enumerate(addr_list))
            #     gap_limit = (self._wallet.gap_limit_for_change if is_change
            #         else self._wallet.gap_limit)

            #     limit_idx = None
            #     for i in range(len(addr_list)-1, -1, -1):
            #         if self._wallet.get_address_history(addr_list[i]):
            #             limit_idx = i + 1 + gap_limit
            #             break

            #     def is_beyond_limit(address) -> bool: # pylint: disable=function-redefined
            #         idx = address_hashes[address.hash160()]
            #         ref_idx = idx - gap_limit
            #         if ref_idx < 0 or limit_idx is None:
            #             return False
            #         return idx >= limit_idx

            for n, address in enumerate(addr_list):
                lines.append(self._create_address_entry(address, is_change,
                    is_beyond_limit(address), n))

        return sorted(lines, key=get_sort_key)

    def _set_fiat_columns_enabled(self, flag: bool) -> None:
        self._fiat_history_enabled = flag

        if flag:
            fx = app_state.fx
            self._base_model.set_column_name(FIAT_BALANCE_COLUMN, f"{fx.ccy} {_('Balance')}")

        self.setColumnHidden(FIAT_BALANCE_COLUMN, not flag)

    def _create_address_entry(self, address: Address, is_change: bool=False,
            is_beyond_limit: bool=False, n: int=-1) -> None:
        balance = sum(self._wallet.get_addr_balance(address))
        is_archived = self._wallet.is_archived_address(address)

        if is_change:
            flags = AddressFlags.CHANGE
        else:
            flags = AddressFlags.RECEIVING

        if self._wallet.is_frozen_address(address):
            flags |= AddressFlags.FROZEN
        if is_beyond_limit:
            flags |= AddressFlags.BEYOND_LIMIT
        if is_archived:
            flags |= AddressFlags.RETIRED

        return AddressLine(flags, address, n, balance)

    def _event_double_clicked(self, model_index: QModelIndex) -> None:
        base_index = get_source_index(model_index, _ItemModel)
        column = base_index.column()
        if column == LABEL_COLUMN:
            self.edit(model_index)
        else:
            line = self._data[base_index.row()]
            self._parent.show_address(self._wallet, line.address)

    def _event_create_menu(self, position):
        menu = QMenu()

        # What the user clicked on.
        menu_index = self.indexAt(position)
        menu_source_index = get_source_index(menu_index, _ItemModel)

        if menu_source_index.row() != -1:
            menu_line = self._data[menu_source_index.row()]
            menu_column = menu_source_index.column()
            column_title = self._headers[menu_column]
            if menu_column == 0:
                copy_text = menu_line.address.to_string()
            else:
                copy_text = str(
                    menu_source_index.model().data(menu_source_index, Qt.DisplayRole)).strip()
            menu.addAction(_("Copy {}").format(column_title),
                lambda: self._parent.app.clipboard().setText(copy_text))

        # The row selection.
        selected_indexes = self.selectedIndexes()
        if len(selected_indexes):
            # This is an index on the sort/filter model, translate it to the base model.
            selected = []
            for selected_index in selected_indexes:
                base_index = get_source_index(selected_index, _ItemModel)

                row = base_index.row()
                column = base_index.column()
                line = self._data[row]
                selected.append((row, column, line, selected_index, base_index))

            is_multisig = isinstance(self._wallet, Multisig_Wallet)
            can_delete = self._wallet.can_delete_address()

            rows = set(v[0] for v in selected)
            multi_select = len(rows) > 1

            if not multi_select:
                row, column, line, selected_index, base_index = selected[0]
                addr = line.address
                menu.addAction(_('Details'), lambda: self._parent.show_address(self._wallet, addr))
                if column == LABEL_COLUMN:
                    menu.addAction(_("Edit {}").format(column_title),
                        lambda: self.edit(selected_index))
                menu.addAction(_("Request payment"), lambda: self._parent.receive_at(addr))
                if self._wallet.can_export():
                    menu.addAction(_("Private key"),
                        lambda: self._parent.show_private_key(self._wallet, addr))
                if not is_multisig and not self._wallet.is_watching_only():
                    menu.addAction(_("Sign/verify message"),
                                lambda: self._parent.sign_verify_message(self._wallet, addr))
                    menu.addAction(_("Encrypt/decrypt message"),
                                lambda: self.encrypt_message(addr))
                if can_delete:
                    menu.addAction(_("Remove from wallet"),
                        lambda: self._parent.remove_address(addr))
                addr_URL = web.BE_URL(self._parent.config, 'addr', addr)
                if addr_URL:
                    menu.addAction(_("View on block explorer"), lambda: webbrowser.open(addr_URL))

                keystore = self._wallet.get_keystore()
                if self._wallet.wallet_type == 'standard':
                    if isinstance(keystore, Hardware_KeyStore):
                        def show_address():
                            self._parent.run_in_thread(
                                keystore.plugin.show_address, self._wallet, addr)
                        menu.addAction(_("Show on {}").format(keystore.plugin.device), show_address)

            freeze = self._parent.set_frozen_state
            addrs = [ line.address for (row, column, line, selected_index, base_index) in selected ]
            if any(self._wallet.is_frozen_address(addr) for addr in addrs):
                menu.addAction(_("Unfreeze"), partial(freeze, self._wallet, addrs, False))
            if not all(self._wallet.is_frozen_address(addr) for addr in addrs):
                menu.addAction(_("Freeze"), partial(freeze, self._wallet, addrs, True))

            coins = self._wallet.get_spendable_coins(domain = addrs, config = self._parent.config)
            if coins:
                menu.addAction(_("Spend from"), partial(self._parent.spend_coins, coins))

        menu.exec_(self.viewport().mapToGlobal(position))

    def encrypt_message(self, address: Address) -> None:
        public_key_str = self._wallet.get_public_key(address) or ''
        self._parent.encrypt_message(self._wallet, public_key_str)
