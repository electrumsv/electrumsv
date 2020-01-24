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

from collections import defaultdict
import enum
from functools import partial
import threading
import time
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Set, Tuple

from PyQt5.QtCore import (QAbstractItemModel, QModelIndex, QVariant, Qt, QSortFilterProxyModel,
    QTimer)
from PyQt5.QtGui import QFont, QBrush, QColor, QKeySequence
from PyQt5.QtWidgets import QTableView, QAbstractItemView, QHeaderView, QMenu

from electrumsv.i18n import _
from electrumsv.app_state import app_state
from electrumsv.constants import ScriptType
from electrumsv.keystore import Hardware_KeyStore
from electrumsv.logs import logs
from electrumsv.platform import platform
from electrumsv.util import profiler
from electrumsv.wallet import MultisigAccount, AbstractAccount, StandardAccount
from electrumsv.wallet_database.tables import KeyInstanceRow, KeyInstanceFlag

from .main_window import ElectrumWindow
from .util import read_QIcon, get_source_index


QT_SORT_ROLE = Qt.UserRole+1

COLUMN_NAMES = [ _("Type"), _("State"), _('Key'), _('Script'), _('Label'), _('Usages'),
    _('Balance'), _('') ]

TYPE_COLUMN = 0
STATE_COLUMN = 1
KEY_COLUMN = 2
SCRIPT_COLUMN = 3
LABEL_COLUMN = 4
USAGES_COLUMN = 5
BALANCE_COLUMN = 6
FIAT_BALANCE_COLUMN = 7


class EventFlags(enum.IntFlag):
    UNSET = 0 << 0
    KEY_ADDED = 1 << 0
    KEY_UPDATED = 1 << 1
    KEY_REMOVED = 1 << 2

    LABEL_UPDATE = 1 << 13
    FREEZE_UPDATE = 1 << 14


class ListActions(enum.IntEnum):
    RESET = 1
    RESET_BALANCES = 2
    RESET_FIAT_BALANCES = 3


class KeyFlags(enum.IntFlag):
    UNSET = 0
    # State related.
    FROZEN = 1 << 16
    INACTIVE = 1 << 17


class KeyLine(NamedTuple):
    row: KeyInstanceRow
    key_text: str
    flags: KeyFlags
    usages: int
    balance: int


def get_sort_key(line: KeyLine) -> Any:
    # This is the sorting used for insertion of new lines, or updating lines where the line
    # needs to be removed from it's current row and inserted into the new row position.
    return -line.balance


class _ItemModel(QAbstractItemModel):
    def __init__(self, parent: Any, column_names: List[str]) -> None:
        super().__init__(parent)

        self._view = parent
        self._logger = self._view._logger

        self._column_names = column_names
        self._balances = None

        self._monospace_font = QFont(platform.monospace_font)

        self._receive_icon = read_QIcon("icons8-down-arrow-96")

        self._frozen_brush = QBrush(QColor('lightblue'))
        self._beyond_limit_brush = QBrush(QColor('red'))
        self._inactive_brush = QBrush(QColor('lightgrey'))

    def set_column_names(self, column_names: List[str]) -> None:
        self._column_names = column_names[:]

    def set_column_name(self, column_index: int, column_name: str) -> None:
        self._column_names[column_index] = column_name

    def set_data(self, data: List[KeyLine]) -> None:
        self.beginResetModel()
        self._data = data
        self.endResetModel()

    def _get_row(self, key: KeyInstanceRow) -> Optional[int]:
        # Get the offset of the line with the given transaction hash.
        key_id = key.keyinstance_id
        for i, line in enumerate(self._data):
            if line.row.keyinstance_id == key_id:
                return i
        return None

    def _get_match_row(self, line: KeyLine) -> int:
        # Get the existing line that precedes where the given line would go.
        new_key = get_sort_key(line)
        for i in range(len(self._data)-1, -1, -1):
            key = get_sort_key(self._data[i])
            if new_key >= key:
                return i
        return -1

    def _add_line(self, line: KeyLine) -> int:
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

    def remove_row(self, row: int) -> KeyLine:
        line = self._data[row]

        self.beginRemoveRows(QModelIndex(), row, row)
        del self._data[row]
        self.endRemoveRows()

        return line

    def add_line(self, line: KeyLine) -> None:
        # The `_add_line` will signal it's line insertion.
        insert_row = self._add_line(line)

        # If there are any other rows that need to be updated relating to the data in that
        # line, here is the place to do it.  Then signal what has changed.

    def update_line(self, key: KeyInstanceRow, values: Dict[int, Any]) -> bool:
        row = self._get_row(key)
        if row is None:
            self._logger.debug("update_line called for non-existent entry %r", key)
            return False

        return self.update_row(row, values)

    def update_row(self, row: int, values: Dict[int, Any]) -> bool:
        old_line = self._data[row]
        self._logger.debug("update_line key=%s idx=%d", old_line.key_text, row)

        if len(values):
            l = list(old_line)
            for value_index, value in values.items():
                l[value_index] = value
            new_line = self._data[row] = KeyLine(*l)

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

    def invalidate_cell_by_key(self, key: KeyInstanceRow, column: int) -> None:
        row = self._get_row(key)
        if row is None:
            self._logger.debug("invalidate_cell_by_key called for non-existent key %r", key)
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
                    return line.row.script_type
                elif column == STATE_COLUMN:
                    return line.row.flags
                elif column == KEY_COLUMN:
                    return line.key_text
                elif column == SCRIPT_COLUMN:
                    return ScriptType(line.row.script_type).name
                elif column == LABEL_COLUMN:
                    return self._view._account.get_keyinstance_label(line.row.keyinstance_id)
                elif column == USAGES_COLUMN:
                    return line.usages
                elif column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN):
                    if column == BALANCE_COLUMN:
                        return self._view._main_window.format_amount(line.balance, whitespaces=True)
                    elif column == FIAT_BALANCE_COLUMN:
                        fx = app_state.fx
                        rate = fx.exchange_rate()
                        return fx.value_str(line.balance, rate)

            elif role == Qt.DecorationRole:
                if column == TYPE_COLUMN:
                    # TODO(rt12) BACKLOG Need to add variation in icons.
                    # if line.row.script_type == ScriptType.MULTISIG_P2SH:
                    return self._receive_icon

            elif role == Qt.DisplayRole:
                if column == TYPE_COLUMN:
                    pass
                elif column == STATE_COLUMN:
                    if line.row.flags & KeyInstanceFlag.ALLOCATED_MASK:
                        return "A"
                elif column == KEY_COLUMN:
                    return line.key_text
                elif column == SCRIPT_COLUMN:
                    return ScriptType(line.row.script_type).name
                elif column == LABEL_COLUMN:
                    return self._view._account.get_keyinstance_label(line.row.keyinstance_id)
                elif column == USAGES_COLUMN:
                    return line.usages
                elif column == BALANCE_COLUMN:
                    return self._view._main_window.format_amount(line.balance, whitespaces=True)
                elif column == FIAT_BALANCE_COLUMN:
                    fx = app_state.fx
                    rate = fx.exchange_rate()
                    return fx.value_str(line.balance, rate)
            elif role == Qt.FontRole:
                if column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN):
                    return self._monospace_font

            elif role == Qt.BackgroundRole:
                if column == STATE_COLUMN:
                    if line.row.flags & KeyInstanceFlag.ALLOCATED_MASK:
                        return self._frozen_brush
                    elif not line.row.flags & KeyInstanceFlag.IS_ACTIVE:
                        return self._inactive_brush
            elif role == Qt.TextAlignmentRole:
                if column in (TYPE_COLUMN, STATE_COLUMN):
                    return Qt.AlignCenter
                elif column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN, USAGES_COLUMN):
                    return Qt.AlignRight | Qt.AlignVCenter
                return Qt.AlignVCenter

            elif role == Qt.ToolTipRole:
                if column == TYPE_COLUMN:
                    return _("Key")
                elif column == STATE_COLUMN:
                    if line.row.flags & KeyInstanceFlag.ALLOCATED_MASK:
                        return _("This is an allocated address")
                    elif not line.row.flags & KeyInstanceFlag.IS_ACTIVE:
                        return _("This is an inactive address")

            elif role == Qt.EditRole:
                if column == LABEL_COLUMN:
                    return self._view._account.get_keyinstance_label(line.row.keyinstance_id)

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
                self._view._account.set_keyinstance_label(line.row.keyinstance_id, value)
            self.dataChanged.emit(model_index, model_index)
            return True
        return False


class _SortFilterProxyModel(QSortFilterProxyModel):
    _filter_match: Optional[str] = None

    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex) -> bool:
        value_left = self.sourceModel().data(source_left, QT_SORT_ROLE)
        value_right = self.sourceModel().data(source_right, QT_SORT_ROLE)
        return value_left < value_right

    def set_filter_match(self, text: Optional[str]) -> None:
        self._filter_match = text.lower() if text is not None else None
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        text = self._filter_match
        if text is None:
            return True
        source_model = self.sourceModel()
        for column in (KEY_COLUMN, LABEL_COLUMN, SCRIPT_COLUMN):
            column_index = source_model.index(source_row, column, source_parent)
            if text in source_model.data(column_index, Qt.DisplayRole).lower():
                return True
        return False


class KeyView(QTableView):
    def __init__(self, main_window: ElectrumWindow) -> None:
        super().__init__(main_window)
        self._logger = logs.get_logger("key-view")

        self._main_window = main_window
        self._account: AbstractAccount = None
        self._account_id: Optional[int] = None

        self._update_lock = threading.Lock()

        self._headers = COLUMN_NAMES

        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)

        self._pending_state: Dict[int, Tuple[KeyInstanceRow, EventFlags]] = {}
        self._pending_actions = set([ ListActions.RESET ])
        self._main_window.keys_created_signal.connect(self._on_keys_created)
        self._main_window.keys_updated_signal.connect(self._on_keys_updated)
        self._main_window.account_change_signal.connect(self._on_account_change)

        model = _ItemModel(self, self._headers)
        model.set_data([])
        self._base_model = model

        # If the underlying model changes, observe it in the sort.
        self._proxy_model = proxy_model = _SortFilterProxyModel()
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

    def clean_up(self) -> None:
        self._timer.stop()

    def filter(self, text: Optional[str]) -> None:
        self._proxy_model.set_filter_match(text)

    def _on_account_change(self, new_account_id: int) -> None:
        with self._update_lock:
            self._pending_state.clear()
            self._pending_actions = set([ ListActions.RESET ])

            old_account_id = self._account_id
            self._account_id = new_account_id
            self._account = self._main_window._wallet.get_account(self._account_id)
            if old_account_id is None:
                self._timer.start()

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
                text = "\n".join(line.key_text for line in selected.values())
                self._main_window.app.clipboard().setText(text)
        else:
            super().keyPressEvent(event)

    def _on_update_check(self) -> None:
        # No point in proceeding if no updates, or the wallet is synchronising still.
        if not self._have_pending_updates() or (time.time() - self._last_not_synced) < 5.0:
            return
        # We do not update if there has been a recent sync.
        if not self._main_window._wallet.is_synchronized():
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
            pending_state: Dict[int, Tuple[KeyInstanceRow, EventFlags]]) -> None:
        if ListActions.RESET in pending_actions:
            self._logger.debug("_on_update_check reset")

            self._data = self._create_data_snapshot()
            self._base_model.set_data(self._data)
            self.resizeRowsToContents()
            return

        additions = []
        updates = []
        removals = []
        for key, flags in pending_state.values():
            if flags & EventFlags.KEY_ADDED:
                additions.append(key)
            elif flags & EventFlags.KEY_UPDATED:
                updates.append(key)
            elif flags & EventFlags.KEY_REMOVED:
                removals.append(key)

        # self._logger.debug("_on_update_check actions=%s adds=%d updates=%d removals=%d",
        #     pending_actions, len(additions), len(updates), len(removals))

        self._remove_keys(removals)
        self._add_keys(additions, pending_state)
        self._update_keys(updates, pending_state)

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

    def _validate_event(self, wallet_path: str, account_id: int) -> bool:
        if account_id != self._account_id:
            return False
        if wallet_path != self._main_window._wallet.get_storage_path():
            return False
        return True

    def _on_keys_created(self, wallet_path: str, account_id: int,
            keys: Iterable[KeyInstanceRow]) -> None:
        if not self._validate_event(wallet_path, account_id):
            return

        flags = EventFlags.KEY_ADDED
        for key in keys:
            self._pending_state[key.keyinstance_id] = (key, flags)

    def _on_keys_updated(self, wallet_path: str, account_id: int,
            keys: Iterable[KeyInstanceRow]) -> None:
        if not self._validate_event(wallet_path, account_id):
            return

        new_flags = EventFlags.KEY_UPDATED
        for key in keys:
            key_, flags = self._pending_state.get(key.keyinstance_id, (key, EventFlags.UNSET))
            self._pending_state[key.keyinstance_id] = key, flags | new_flags

    def _add_keys(self, keys: List[KeyInstanceRow],
            state: Dict[int, Tuple[KeyInstanceRow, EventFlags]]) -> None:
        self._logger.debug("_add_keys %d", len(keys))

        for line in self._create_entries(keys, state):
            self._base_model.add_line(line)

    def _update_keys(self, keys: List[KeyInstanceRow],
            state: Dict[int, Tuple[KeyInstanceRow, EventFlags]]) -> None:
        self._logger.debug("_update_keys %d", len(keys))

        matches = self._match_keys(keys)
        if len(matches) != len(keys):
            matched_key_ids = [ line.row.keyinstance_id for (row, line) in matches ]
            self._logger.debug("_update_keys missing entries %s",
                [ k.keyinstance_id for k in keys if k.keyinstance_id not in matched_key_ids ])

        new_lines = { l.row.keyinstance_id: l for l in self._create_entries(keys, state) }
        for row, line in matches:
            self._data[row] = new_lines[line.row.keyinstance_id]
            self._base_model.invalidate_row(row)

    def _remove_keys(self, keys: List[KeyInstanceRow]) -> None:
        self._logger.debug("_remove_keys %d", len(keys))
        matches = self._match_keys(keys)
        if len(matches) != len(keys):
            matched_key_ids = [ line.row.keyinstance_id for (row, line) in matches ]
            self._logger.debug("_remove_keys missing entries %s", [ k.row.keyinstance_id
                for k in keys if k.row.keyinstance_id not in matched_key_ids ])
        # Make sure that we will be removing rows from the last to the first, to preserve offsets.
        for row, line in sorted(matches, reverse=True, key=lambda v: v[0]):
            self._base_model.remove_row(row)

    # Called by the wallet window.
    def update_keys(self, keys: List[KeyInstanceRow]) -> None:
        with self._update_lock:
            for key in keys:
                _key, flags = self._pending_state.get(key.keyinstance_id, (key, EventFlags.UNSET))
                self._pending_state[key.keyinstance_id] = (key, flags | EventFlags.KEY_UPDATED)

    # Called by the wallet window.
    def remove_keys(self, keys: List[KeyInstanceRow]) -> None:
        with self._update_lock:
            for key in keys:
                _key, flags = self._pending_state.get(key.keyinstance_id, (key, EventFlags.UNSET))
                self._pending_state[key.keyinstance_id] = (key, flags | EventFlags.KEY_REMOVED)

   # Called by the wallet window.
    def update_frozen_keys(self, keys: List[KeyInstanceRow], freeze: bool) -> None:
        with self._update_lock:
            new_flags = EventFlags.KEY_UPDATED | EventFlags.FREEZE_UPDATE
            for key in keys:
                _key, flags = self._pending_state.get(key.keyinstance_id, (key, EventFlags.UNSET))
                self._pending_state[key.keyinstance_id] = (key, flags | new_flags)

    # The user has toggled the preferences setting.
    def _on_balance_display_change(self) -> None:
        with self._update_lock:
            self._pending_actions.add(ListActions.RESET_BALANCES)

    # The user has toggled the preferences setting.
    def _on_fiat_balance_display_change(self) -> None:
        with self._update_lock:
            self._pending_actions.add(ListActions.RESET_FIAT_BALANCES)

    # The user has edited a label either here, or in some other wallet location.
    def update_labels(self, wallet_path: str, account_id: int, updates: Dict[str, str]) -> None:
        if not self._validate_event(wallet_path, account_id):
            return

        with self._update_lock:
            new_flags = EventFlags.KEY_UPDATED | EventFlags.LABEL_UPDATE

            for line in self._data:
                if line.key_text in updates:
                    key, flags = self._pending_state.get(line.row.keyinstance_id,
                        (key, EventFlags.UNSET))
                    self._pending_state[line.row.keyinstance_id] = (key, flags | new_flags)

    def _match_keys(self, keys: List[KeyInstanceRow]) -> List[Tuple[int, KeyLine]]:
        matches = []
        key_ids = set(key.keyinstance_id for key in keys)
        for row, line in enumerate(self._data):
            if line.row.keyinstance_id in key_ids:
                matches.append((row, line))
                if len(matches) == len(key_ids):
                    break
        return matches

    def _create_data_snapshot(self) -> None:
        keys = list(self._account._keyinstances.values())
        lines = self._create_entries(keys, {})
        return sorted(lines, key=get_sort_key)

    def _set_fiat_columns_enabled(self, flag: bool) -> None:
        self._fiat_history_enabled = flag

        if flag:
            fx = app_state.fx
            self._base_model.set_column_name(FIAT_BALANCE_COLUMN, f"{fx.ccy} {_('Balance')}")

        self.setColumnHidden(FIAT_BALANCE_COLUMN, not flag)

    def _create_entries(self, keys: List[KeyInstanceRow],
            state: Dict[int, Tuple[KeyInstanceRow, EventFlags]]) -> List[KeyLine]:

        utxos = defaultdict(list)
        for utxo in self._account._utxos.values():
            utxos[utxo.keyinstance_id].append(utxo)

        lines = []
        for key in keys:
            coins = utxos.get(key.keyinstance_id, [])
            # NOTE(rt12) BACKLOG This is the current usage not the all time usage.
            usages = len(coins)
            key_text = self._account.get_key_text(key.keyinstance_id)
            line = KeyLine(key, key_text, KeyFlags.UNSET, usages,
                sum(c.value for c in coins))
            lines.append(line)
        return lines

    def _event_double_clicked(self, model_index: QModelIndex) -> None:
        base_index = get_source_index(model_index, _ItemModel)
        column = base_index.column()
        if column == LABEL_COLUMN:
            self.edit(model_index)
        else:
            line = self._data[base_index.row()]
            self._main_window.show_key(self._account, line.row.keyinstance_id)

    def _event_create_menu(self, position):
        account_id = self._account_id

        menu = QMenu()

        # What the user clicked on.
        menu_index = self.indexAt(position)
        menu_source_index = get_source_index(menu_index, _ItemModel)

        if menu_source_index.row() != -1:
            menu_line = self._data[menu_source_index.row()]
            menu_column = menu_source_index.column()
            column_title = self._headers[menu_column]
            if menu_column == 0:
                copy_text = menu_line.key_text
            else:
                copy_text = str(
                    menu_source_index.model().data(menu_source_index, Qt.DisplayRole)).strip()
            menu.addAction(_("Copy {}").format(column_title),
                lambda: self._main_window.app.clipboard().setText(copy_text))

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

            is_multisig = isinstance(self._account, MultisigAccount)

            rows = set(v[0] for v in selected)
            multi_select = len(rows) > 1

            if not multi_select:
                row, column, line, selected_index, base_index = selected[0]
                key_id = line.row.keyinstance_id
                menu.addAction(_('Details'),
                    lambda: self._main_window.show_key(self._account, key_id))
                if column == LABEL_COLUMN:
                    menu.addAction(_("Edit {}").format(column_title),
                        lambda: self.edit(selected_index))
                menu.addAction(_("Request payment"),
                    lambda: self._main_window.receive_at_id(key_id))
                if self._account.can_export():
                    menu.addAction(_("Private key"),
                        lambda: self._main_window.show_private_key(self._account, key_id))
                if not is_multisig and not self._account.is_watching_only():
                    menu.addAction(_("Sign/verify message"),
                        lambda: self._main_window.sign_verify_message(self._account, key_id))
                    menu.addAction(_("Encrypt/decrypt message"),
                                lambda: self._main_window.encrypt_message(self._account, key_id))
                # addr_URL = web.BE_URL(self._main_window.config, 'addr', addr)
                # if addr_URL:
                #     menu.addAction(_("View on block explorer"), lambda: webbrowser.open(addr_URL))

                if isinstance(self._account, StandardAccount):
                    keystore = self._account.get_keystore()
                    if isinstance(keystore, Hardware_KeyStore):
                        def show_key():
                            self._main_window.run_in_thread(
                                keystore.plugin.show_key, self._account, key_id)
                        menu.addAction(_("Show on {}").format(keystore.plugin.device), show_key)

            # freeze = self._main_window.set_frozen_state
            key_ids = [ line.row.keyinstance_id
                for (row, column, line, selected_index, base_index) in selected ]
            # if any(self._account.is_frozen_address(addr) for addr in addrs):
            #     menu.addAction(_("Unfreeze"), partial(freeze, self._account, addrs, False))
            # if not all(self._account.is_frozen_address(addr) for addr in addrs):
            #     menu.addAction(_("Freeze"), partial(freeze, self._account, addrs, True))

            coins = self._account.get_spendable_coins(domain=key_ids,
                config=self._main_window.config)
            if coins:
                menu.addAction(_("Spend from"), partial(self._main_window.spend_coins, coins))

        menu.exec_(self.viewport().mapToGlobal(position))
