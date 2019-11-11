#!/usr/bin/env python

from collections import namedtuple
import enum
import threading
import time
from typing import List, Any, Optional, Dict, Tuple, Set
import webbrowser

from bitcoinx import hash_to_hex_str
from PyQt5.QtCore import (QAbstractItemModel, QModelIndex, QVariant, Qt, QSortFilterProxyModel,
    QTimer)
from PyQt5.QtGui import QFont, QBrush, QColor, QKeySequence
from PyQt5.QtWidgets import QTableView, QAbstractItemView, QHeaderView, QMenu, QWidget

from electrumsv.i18n import _
from electrumsv.app_state import app_state
from electrumsv.constants import TxFlags
from electrumsv.logs import logs
from electrumsv.platform import platform
from electrumsv.util import profiler, format_time
from electrumsv.wallet import AbstractAccount
from electrumsv.wallet_database import TxData
import electrumsv.web as web

from .main_window import ElectrumWindow
from .util import read_QIcon, get_source_index


QT_SORT_ROLE = Qt.UserRole+1

COLUMN_NAMES = [ _("Date Added"), _("Date Updated"), _("State"), _('Label'), _('Value'), _('') ]

DATE_ADDED_COLUMN = 0
DATE_UPDATED_COLUMN = 1
STATE_COLUMN = 2
LABEL_COLUMN = 3
VALUE_COLUMN = 4
FIAT_VALUE_COLUMN = 5


class EventFlags(enum.IntFlag):
    UNSET = 0 << 0
    TX_ADDED = 1 << 0
    TX_UPDATED = 1 << 1
    TX_REMOVED = 1 << 2

    LABEL_UPDATE = 1 << 13


class ListActions(enum.IntEnum):
    RESET = 1
    RESET_VALUES = 2
    RESET_FIAT_VALUES = 3


class TxEntryFlags(enum.IntFlag):
    # State related.
    NO_IDEA = 1 << 16


LI_HASH = 0
LI_DATE_ADDED = 1
LI_DATE_UPDATED = 2
LI_FLAGS = 3
LI_VALUE = 4


class TxLine(namedtuple("TxLine", "hash, date_added, date_updated, flags, value")):
    pass

def get_sort_key(line: TxLine) -> Any:
    # This is the sorting used for insertion of new lines, or updating lines where the line
    # needs to be removed from it's current row and inserted into the new row position.
    return line.date_added


class _ItemModel(QAbstractItemModel):
    def __init__(self, parent: Any, column_names: List[str]) -> None:
        super().__init__(parent)

        self._view = parent
        self._logger = self._view._logger

        self._column_names = column_names

        self._monospace_font = QFont(platform.monospace_font)

        self._EXAMPLE_icon = read_QIcon("icons8-rotate-96")
        self._EXAMPLE_brush = QBrush(QColor('lightgrey'))

    def set_column_names(self, column_names: List[str]) -> None:
        self._column_names = column_names[:]

    def set_column_name(self, column_index: int, column_name: str) -> None:
        self._column_names[column_index] = column_name

    def set_data(self, data: List[TxLine]) -> None:
        self.beginResetModel()
        self._data = data
        self.endResetModel()

    def _get_row(self, tx_hash: bytes) -> Optional[int]:
        # Get the offset of the line with the given transaction hash.
        for i, line in enumerate(self._data):
            if line.hash == tx_hash:
                return i
        return None

    def _get_match_row(self, line: TxLine) -> int:
        # Get the existing line that precedes where the given line would go.
        new_key = get_sort_key(line)
        for i in range(len(self._data)-1, -1, -1):
            key = get_sort_key(self._data[i])
            if new_key >= key:
                return i
        return -1

    def _add_line(self, line: TxLine) -> int:
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

    def remove_row(self, row: int) -> TxLine:
        line = self._data[row]

        self.beginRemoveRows(QModelIndex(), row, row)
        del self._data[row]
        self.endRemoveRows()

        return line

    def add_line(self, line: TxLine) -> None:
        # The `_add_line` will signal it's line insertion.
        insert_row = self._add_line(line)

        # If there are any other rows that need to be updated relating to the data in that
        # line, here is the place to do it.  Then signal what has changed.

    def update_line(self, tx_hash: bytes, values: Dict[int, Any]) -> bool:
        row = self._get_row(tx_hash)
        if row is None:
            self._logger.debug("update_line called for non-existent entry %s", tx_hash)
            return False

        return self.update_row(row, values)

    def update_row(self, row: int, values: Dict[int, Any]) -> bool:
        old_line = self._data[row]
        tx_id = hash_to_hex_str(old_line.hash)
        self._logger.debug("update_line tx=%s idx=%d", tx_id, row)

        if len(values):
            l = list(old_line)
            for value_index, value in values.items():
                l[value_index] = value
            new_line = self._data[row] = TxLine(*l)

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

    def invalidate_cell_by_key(self, tx_hash: bytes, column: int) -> None:
        row = self._get_row(tx_hash)
        if row is None:
            self._logger.debug("invalidate_cell_by_key called for non-existent key %s", tx_hash)
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
                if column == DATE_ADDED_COLUMN:
                    return line.date_added
                elif column == DATE_UPDATED_COLUMN:
                    return line.date_updated
                elif column == STATE_COLUMN:
                    if line.flags == TxFlags.StateDispatched:
                        return 0
                    elif line.flags == TxFlags.StateReceived:
                        return 2
                    elif line.flags == TxFlags.StateSigned:
                        return 1
                    else:
                        return 3
                elif column == LABEL_COLUMN:
                    return self._view._account.get_transaction_label(line.hash)
                elif column in (VALUE_COLUMN, FIAT_VALUE_COLUMN):
                    return line.value

            elif role == Qt.DisplayRole:
                if column == DATE_ADDED_COLUMN:
                    return (format_time(line.date_added, _("unknown"))
                        if line.date_added else _("unknown"))
                elif column == DATE_UPDATED_COLUMN:
                    return (format_time(line.date_updated, _("unknown"))
                        if line.date_updated else _("unknown"))

                elif column == STATE_COLUMN:
                    if line.flags == TxFlags.StateDispatched:
                        return _("Dispatched")
                    elif line.flags == TxFlags.StateReceived:
                        return _("Received")
                    elif line.flags == TxFlags.StateSigned:
                        return _("Signed")
                    return _("Unknown")
                elif column == LABEL_COLUMN:
                    return self._view._account.get_transaction_label(line.hash)
                elif column == VALUE_COLUMN:
                    return self._view._main_window.format_amount(line.value, whitespaces=True)
                elif column == FIAT_VALUE_COLUMN:
                    fx = app_state.fx
                    rate = fx.exchange_rate()
                    return fx.value_str(line.value, rate)

            elif role == Qt.FontRole:
                if column in (VALUE_COLUMN, FIAT_VALUE_COLUMN):
                    return self._monospace_font

            elif role == Qt.TextAlignmentRole:
                if column in (VALUE_COLUMN, FIAT_VALUE_COLUMN):
                    return Qt.AlignRight | Qt.AlignVCenter
                return Qt.AlignVCenter

            elif role == Qt.ToolTipRole:
                if column == STATE_COLUMN:
                    if line.flags == TxFlags.StateDispatched:
                        return _("This transaction has been sent to the network, but has not "
                            "cleared yet.")
                    elif line.flags == TxFlags.StateReceived:
                        return _("This transaction has been received from another party, but "
                            "has not been broadcast yet.")
                    elif line.flags == TxFlags.StateSigned:
                        return _("This transaction has been signed, but has not been broadcast "
                            "yet.")

            elif role == Qt.EditRole:
                if column == LABEL_COLUMN:
                    return self._view._account.get_transaction_label(line.hash)

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
                if value.strip() == "":
                    value = None
                self._view._account.set_transaction_label(line.hash, value)
            self.dataChanged.emit(model_index, model_index)
            return True
        return False


class _SortFilterProxyModel(QSortFilterProxyModel):
    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex) -> bool:
        value_left = self.sourceModel().data(source_left, QT_SORT_ROLE)
        value_right = self.sourceModel().data(source_right, QT_SORT_ROLE)
        return value_left < value_right


class TransactionView(QTableView):
    def __init__(self, parent: QWidget, main_window: ElectrumWindow) -> None:
        super().__init__(parent)

        self._main_window = main_window
        self._logger = logs.get_logger("transaction-list")
        self._account_id: Optional[int] = None
        self._account: Optional[AbstractAccount] = None
        self._update_lock = threading.Lock()

        self._headers = COLUMN_NAMES

        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)

        self._pending_state: Dict[bytes, EventFlags] = {}
        self._pending_actions = set([ ListActions.RESET ])

        self._main_window.transaction_state_signal.connect(self._on_transaction_state_change)
        self._main_window.transaction_added_signal.connect(self._on_transaction_added)
        self._main_window.transaction_deleted_signal.connect(self._on_transaction_deleted)
        self._main_window.account_change_signal.connect(self._on_account_change)

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
        self.sortByColumn(DATE_ADDED_COLUMN, Qt.AscendingOrder)
        self.setSortingEnabled(True)

        self.horizontalHeader().setSectionResizeMode(LABEL_COLUMN, QHeaderView.Stretch)
        for i in range(FIAT_VALUE_COLUMN):
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

    def _on_account_change(self, new_account_id: int) -> None:
        with self._update_lock:
            self._pending_state.clear()
            self._pending_actions = set([ ListActions.RESET ])

            old_account_id = self._account_id
            self._account_id = new_account_id
            self._account = self._main_window._wallet.get_account(self._account_id)
            if old_account_id is None:
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

                # The imported address account splits on any type of whitespace and strips excess.
                text = "\n".join(hash_to_hex_str(line.hash) for line in selected.values())
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
            pending_state: Dict[bytes, EventFlags]) -> None:
        if ListActions.RESET in pending_actions:
            self._logger.debug("_on_update_check reset")

            self._data = self._create_data_snapshot()
            self._base_model.set_data(self._data)

            self.resizeRowsToContents()
            return

        additions = []
        updates = []
        removals = []
        for tx_hash, flags in pending_state.items():
            if flags & EventFlags.TX_ADDED:
                additions.append(tx_hash)
            elif flags & EventFlags.TX_UPDATED:
                updates.append(tx_hash)
            elif flags & EventFlags.TX_REMOVED:
                removals.append(tx_hash)

        # self._logger.debug("_on_update_check actions=%s adds=%d updates=%d removals=%d",
        #     pending_actions, len(additions), len(updates), len(removals))

        self._remove_transactions(removals)
        self._add_transactions(additions, pending_state)
        self._update_transactions(updates, pending_state)

        for action in pending_actions:
            if ListActions.RESET_VALUES:
                self._base_model.invalidate_column(VALUE_COLUMN)
            elif ListActions.RESET_FIAT_VALUES:
                fx = app_state.fx
                flag = fx and fx.get_fiat_address_config()
                # This will show or hide the relevant columns as applicable.
                self._set_fiat_columns_enabled(flag)
                # This will notify the model that the relevant cells are changed.
                self._base_model.invalidate_column(FIAT_VALUE_COLUMN)
            else:
                self._logger.error("_on_update_check action %s not applied", action)

        self.resizeRowsToContents()

    def _validate_event(self, wallet_path: str, account_id: int) -> bool:
        if account_id != self._account_id:
            return False
        if wallet_path != self._main_window._wallet.get_storage_path():
            return False
        return True

    def _on_transaction_state_change(self, wallet_path: str, account_id: int, tx_hash: bytes,
            old_state: TxFlags, new_state: TxFlags) -> None:
        if not self._validate_event(wallet_path, account_id):
            return

        self._logger.debug("_on_transaction_state_change %s %s %s", tx_hash,
            TxFlags.to_repr(old_state), TxFlags.to_repr(new_state))

        if new_state & TxFlags.STATE_BROADCAST_MASK:
            self.remove_transactions([ tx_hash ])
        else:
            self.update_transactions([ tx_hash ])

    def _on_transaction_added(self, wallet_path: str, account_id: int, tx_hash: bytes) -> None:
        if not self._validate_event(wallet_path, account_id):
            return

        with self._update_lock:
            self._pending_state[tx_hash] = EventFlags.TX_ADDED

    def _on_transaction_deleted(self, wallet_path: str, account_id: int, tx_hash: bytes) -> None:
        if not self._validate_event(wallet_path, account_id):
            return

        self._logger.debug("_on_transaction_deleted %s", hash_to_hex_str(tx_hash))
        self.remove_transactions([ tx_hash ])

    def _add_transactions(self, tx_hashes: List[bytes], state: Dict[bytes, EventFlags]) -> None:
        self._logger.debug("_add_transactions %d", len(tx_hashes))

        # The default for getting the transaction metadata in this way is requiring all exist.
        for tx_hash, tx_data in self._account.get_transaction_metadatas(tx_hashes=tx_hashes,
                mask=TxFlags.STATE_UNCLEARED_MASK):
            assert tx_hash in tx_hashes, f"got bad result {hash_to_hex_str(tx_hash)}"
            self._base_model.add_line(self._create_transaction_entry(tx_hash, tx_data))

    def _update_transactions(self, tx_hashes: List[bytes], state: Dict[bytes, EventFlags]) -> None:
        self._logger.debug("_update_transactions %d", len(tx_hashes))

        matches = self._match_transactions(tx_hashes)
        if len(matches) != len(tx_hashes):
            matched_tx_hashes = [ line.hash for (row, line) in matches ]
            self._logger.debug("_update_transactions missing entries %s",
                [ hash_to_hex_str(a) for a in tx_hashes if a not in matched_tx_hashes ])
        matches_by_hash = dict((t[1].hash, t) for t in matches)
        matched_tx_hashes = matches_by_hash.keys()
        for tx_hash, tx_data in self._account.get_transaction_metadatas(
                tx_hashes=matched_tx_hashes):
            row, line = matches_by_hash[tx_hash]
            new_line = self._create_transaction_entry(tx_hash, tx_data)
            self._data[row] = new_line
            self._base_model.invalidate_row(row)

    def _remove_transactions(self, tx_hashes: List[bytes]) -> None:
        self._logger.debug("_remove_transactions %d", len(tx_hashes))
        matches = self._match_transactions(tx_hashes)
        if len(tx_hashes) != len(tx_hashes):
            matched_tx_hashes = [ line.hash for (row, line) in matches ]
            self._logger.debug("_remove_transactions missing entries %s",
                [ hash_to_hex_str(a) for a in tx_hashes if a not in matched_tx_hashes ])
        # Make sure that we will be removing rows from the last to the first, to preserve offsets.
        for row, line in sorted(matches, reverse=True, key=lambda v: v[0]):
            self._base_model.remove_row(row)

    def update_transactions(self, tx_hashes: List[bytes]) -> List[bytes]:
        with self._update_lock:
            for tx_hash in tx_hashes:
                flags = self._pending_state.get(tx_hash, EventFlags.UNSET)
                self._pending_state[tx_hash] = flags | EventFlags.TX_UPDATED

    def remove_transactions(self, tx_hashes: List[bytes]) -> None:
        with self._update_lock:
            for tx_hash in tx_hashes:
                flags = self._pending_state.get(tx_hash, EventFlags.UNSET)
                self._pending_state[tx_hash] = flags | EventFlags.TX_REMOVED

    # The user has toggled the preferences setting.
    def _on_balance_display_change(self) -> None:
        with self._update_lock:
            self._pending_actions.add(ListActions.RESET_VALUES)

    # The user has toggled the preferences setting.
    def _on_fiat_balance_display_change(self) -> None:
        with self._update_lock:
            self._pending_actions.add(ListActions.RESET_FIAT_VALUES)

    def _validate_event(self, wallet_path: str, account_id: int) -> bool:
        if account_id != self._account_id:
            return False
        if wallet_path != self._main_window._wallet.get_storage_path():
            return False
        return True

    # The user has edited a label either here, or in some other wallet location.
    def update_labels(self, wallet_path: str, account_id: int, updates: Dict[bytes, str]) -> None:
        if not self._validate_event(wallet_path, account_id):
            return

        with self._update_lock:
            new_flags = EventFlags.TX_UPDATED | EventFlags.LABEL_UPDATE

            tx_hashes = []
            for label_key in updates.keys():
                metadata = self._account.get_transaction_metadata(label_key)
                if metadata is None:
                    continue

                flags = self._pending_state.get(label_key, EventFlags.UNSET)
                self._pending_state[label_key] = flags | new_flags

    def _match_transactions(self, tx_hashes: List[bytes]) -> List[Tuple[int, TxLine]]:
        matches = []
        _tx_hashes = set(tx_hashes)
        for row, line in enumerate(self._data):
            if line.hash in _tx_hashes:
                matches.append((row, line))
                if len(matches) == len(tx_hashes):
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

    def _create_data_snapshot(self) -> None:
        lines = []
        for tx_hash, tx_data in self._account.get_transaction_metadatas(
                mask=TxFlags.STATE_UNCLEARED_MASK):
            lines.append(self._create_transaction_entry(tx_hash, tx_data))
        return sorted(lines, key=get_sort_key)

    def _set_fiat_columns_enabled(self, flag: bool) -> None:
        self._fiat_history_enabled = flag

        if flag:
            fx = app_state.fx
            self._base_model.set_column_name(FIAT_VALUE_COLUMN, f"{fx.ccy} {_('Balance')}")

        self.setColumnHidden(FIAT_VALUE_COLUMN, not flag)

    def _create_transaction_entry(self, tx_hash: bytes, tx_data: TxData) -> None:
        assert tx_data.date_added is not None, \
            f"{hash_to_hex_str(tx_hash)} has no valid date_added"
        tx_entry = self._account.get_transaction_entry(tx_hash)
        flags = tx_entry.flags & TxFlags.STATE_MASK
        delta_value = self._account.get_transaction_delta(tx_hash)
        return TxLine(tx_hash, tx_data.date_added, tx_data.date_updated, flags, delta_value)

    def _event_double_clicked(self, model_index: QModelIndex) -> None:
        base_index = get_source_index(model_index, _ItemModel)
        column = base_index.column()
        if column == LABEL_COLUMN:
            self.edit(model_index)
        else:
            line = self._data[base_index.row()]
            tx = self._account.get_transaction(line.hash)
            self._main_window.show_transaction(self._account, tx)

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
                copy_text = hash_to_hex_str(menu_line.hash)
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

            rows = set(v[0] for v in selected)
            multi_select = len(rows) > 1

            if not multi_select:
                row, column, line, selected_index, base_index = selected[0]
                menu.addAction(_('Details'), lambda: self._main_window.show_transaction(
                    self._account, self._account.get_transaction(line.hash)))
                line_URL = web.BE_URL(self._main_window.config, 'tx', hash_to_hex_str(line.hash))
                if line_URL:
                    menu.addAction(_("View on block explorer"), lambda: webbrowser.open(line_URL))
                menu.addSeparator()
                if column == LABEL_COLUMN:
                    menu.addAction(_("Edit {}").format(column_title),
                        lambda: self.edit(selected_index))
                entry = self._account.get_transaction_entry(line.hash)
                if entry.flags & TxFlags.STATE_UNCLEARED_MASK != 0:
                    menu.addAction(_("Broadcast"),
                        lambda: self._broadcast_transaction(line.hash))
                    menu.addSeparator()
                    menu.addAction(_("Remove from account"),
                        lambda: self._account.delete_transaction(line.hash))

        menu.exec_(self.viewport().mapToGlobal(position))

    def _broadcast_transaction(self, tx_hash: bytes) -> None:
        desc = None
        tx = self._account.get_transaction(tx_hash)
        self._main_window.broadcast_transaction(self._account, tx, desc, window=self._main_window)
