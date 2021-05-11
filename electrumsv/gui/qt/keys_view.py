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

# TODO(rt12): Type column icons are not horizontally centered.
#   - This is because the non-existent text (DisplayRole) is still the main focus. To fix this
#     requires perhaps using an item delegate and overriding the paint method to shift the icon
#     into the center.

import enum
from functools import partial
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union
import weakref
import webbrowser

from bitcoinx import Address, bip32_build_chain_string, hash_to_hex_str

from PyQt5.QtCore import (QAbstractItemModel, QModelIndex, QVariant, Qt, QSortFilterProxyModel,
    QTimer)
from PyQt5.QtGui import QFont, QFontMetrics, QKeySequence
from PyQt5.QtWidgets import QTableView, QAbstractItemView, QHeaderView, QMenu

from electrumsv.i18n import _
from electrumsv.app_state import app_state
from electrumsv.bitcoin import scripthash_bytes, sha256
from electrumsv.constants import (ACCOUNT_SCRIPT_TYPES, DerivationType, IntFlag, KeyInstanceFlag,
    ScriptType, TransactionOutputFlag, unpack_derivation_path)
from electrumsv.keystore import Hardware_KeyStore
from electrumsv.logs import logs
from electrumsv.networks import Net
from electrumsv.platform import platform
from electrumsv.types import TxoKeyType
from electrumsv.util import profiler
from electrumsv.wallet import MultisigAccount, AbstractAccount, StandardAccount
from electrumsv.wallet_database.types import KeyInstanceRow, KeyListRow
from electrumsv import web

from .main_window import ElectrumWindow
from .util import read_QIcon, get_source_index


QT_SORT_ROLE = Qt.UserRole+1
QT_FILTER_ROLE = Qt.UserRole+2

COLUMN_NAMES = [ _("Type"), _("State"), _('Key'), _('Script'), _('Label'), _('Balance'), '' ]

TYPE_COLUMN = 0
STATE_COLUMN = 1
KEY_COLUMN = 2
SCRIPT_COLUMN = 3
LABEL_COLUMN = 4
BALANCE_COLUMN = 5
FIAT_BALANCE_COLUMN = 6


class EventFlags(IntFlag):
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


class KeyFlags(IntFlag):
    UNSET = 0
    # State related.
    FROZEN = 1 << 16
    INACTIVE = 1 << 17

# TODO(no-merge) This should allow multi-select
# TODO(no-merge) This should combine key uses instead of having one row per key/txout.
# TODO(no-merge) Add back in the Uses column.
KeyLine = KeyListRow


def get_key_text(line: KeyLine) -> str:
    text = f"{line.keyinstance_id}:{line.masterkey_id}"
    derivation_text = ""
    if line.derivation_type == DerivationType.BIP32_SUBPATH:
        derivation_path = unpack_derivation_path(line.derivation_data2)
        derivation_text = bip32_build_chain_string(derivation_path)
    return text +":"+ derivation_text


def data_row_key(row: KeyListRow) -> Tuple[int, bytes, int]:
    return row.keyinstance_id, row.tx_hash, row.txo_index


class _ItemModel(QAbstractItemModel):
    def __init__(self, parent: Any, column_names: List[str]) -> None:
        super().__init__(parent)

        self._view = parent
        self._logger = self._view._logger

        self._column_names = column_names
        self._account_id: Optional[int] = None

        self._receive_icon = read_QIcon("icons8-down-arrow-96")

    def set_column_names(self, column_names: List[str]) -> None:
        self._column_names = column_names[:]

    def set_column_name(self, column_index: int, column_name: str) -> None:
        self._column_names[column_index] = column_name

    def set_data(self, account_id: Optional[int], data: List[KeyLine]) -> None:
        self.beginResetModel()
        self._account_id = account_id
        self._data = data
        self.endResetModel()

    def _get_data_line(self, key_id: int) -> Optional[int]:
        # Get the offset of the line with the given transaction hash.
        for data_index, line in enumerate(self._data):
            if line.keyinstance_id == key_id:
                return data_index
        return None

    def _add_line(self, line: KeyLine) -> int:
        insert_row = len(self._data)

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

    def remove_row(self, row_index: int) -> KeyLine:
        line = self._data[row_index]

        self.beginRemoveRows(QModelIndex(), row_index, row_index)
        del self._data[row_index]
        self.endRemoveRows()

        return line

    def add_line(self, line: KeyLine) -> None:
        # The `_add_line` will signal it's line insertion.
        insert_row = self._add_line(line)

        # If there are any other rows that need to be updated relating to the data in that
        # line, here is the place to do it.  Then signal what has changed.

    def invalidate_column(self, column_index: int) -> None:
        start_index = self.createIndex(0, column_index)
        row_count = self.rowCount(start_index)
        end_index = self.createIndex(row_count-1, column_index)
        self.dataChanged.emit(start_index, end_index)

    def invalidate_row(self, row_index: int) -> None:
        start_index = self.createIndex(row_index, 0)
        column_count = self.columnCount(start_index)
        end_index = self.createIndex(row_index, column_count-1)
        self.dataChanged.emit(start_index, end_index)

    # Overridden methods:

    def columnCount(self, model_index: QModelIndex) -> int:
        return len(self._column_names)

    def data(self, model_index: QModelIndex, role: int) -> Any:
        if self._view._account_id != self._account_id:
            return None

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
                    return line.txo_script_type
                elif column == STATE_COLUMN:
                    return line.flags
                elif column == KEY_COLUMN:
                    return get_key_text(line)
                elif column == SCRIPT_COLUMN:
                    if line.txo_script_type is None:
                        return ""
                    return ScriptType(line.txo_script_type).name
                elif column == LABEL_COLUMN:
                    return line.description
                elif column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN):
                    if line.txo_value is not None:
                        value = line.txo_value if line.txo_flags and \
                            (line.txo_flags & TransactionOutputFlag.IS_SPENT) == 0 else 0
                        if column == BALANCE_COLUMN:
                            return value
                        elif column == FIAT_BALANCE_COLUMN:
                            fx = app_state.fx
                            rate = fx.exchange_rate()
                            return fx.value_str(value, rate)

            elif role == QT_FILTER_ROLE:
                if column == KEY_COLUMN:
                    return line

            elif role == Qt.DecorationRole:
                if column == TYPE_COLUMN:
                    # TODO(rt12) BACKLOG Need to add variation in icons.
                    return self._receive_icon

            elif role == Qt.DisplayRole:
                if column == TYPE_COLUMN:
                    return None
                elif column == STATE_COLUMN:
                    state_text = ""
                    if line.flags & KeyInstanceFlag.IS_ACTIVE:
                        state_text += "A"
                    if line.flags & KeyInstanceFlag.IS_INVOICE:
                        state_text += "I"
                    if line.flags & KeyInstanceFlag.IS_PAYMENT_REQUEST:
                        state_text += "P"
                    if line.flags & KeyInstanceFlag.USER_SET_ACTIVE:
                        state_text += "F"
                    if line.flags & KeyInstanceFlag.IS_ASSIGNED:
                        state_text += "X"
                    if not len(state_text) and line.flags:
                        state_text = str(line.flags)
                    if state_text:
                        return state_text
                elif column == KEY_COLUMN:
                    return get_key_text(line)
                elif column == SCRIPT_COLUMN:
                    if line.txo_script_type is None:
                        return ""
                    return ScriptType(line.txo_script_type).name
                elif column == LABEL_COLUMN:
                    return line.description
                elif column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN):
                    if line.txo_flags is not None:
                        value = 0 if line.txo_flags & TransactionOutputFlag.IS_SPENT \
                            else line.txo_value
                        if column == BALANCE_COLUMN:
                            return app_state.format_amount(value, whitespaces=True)
                        elif column == FIAT_BALANCE_COLUMN:
                            fx = app_state.fx
                            rate = fx.exchange_rate()
                            return fx.value_str(value, rate)
            elif role == Qt.FontRole:
                if column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN):
                    return self._view._monospace_font

            elif role == Qt.BackgroundRole:
                # This does not work because the CSS overrides it.
                pass
            elif role == Qt.TextAlignmentRole:
                if column in (TYPE_COLUMN, STATE_COLUMN):
                    return Qt.AlignCenter
                elif column in (BALANCE_COLUMN, FIAT_BALANCE_COLUMN):
                    return Qt.AlignRight | Qt.AlignVCenter
                return Qt.AlignVCenter

            elif role == Qt.ToolTipRole:
                if column == TYPE_COLUMN:
                    return _("Key")
                elif column == STATE_COLUMN:
                    lines = []
                    if line.flags & KeyInstanceFlag.IS_ACTIVE:
                        lines.append(_("A: Activated by wallet"))
                    if line.flags & KeyInstanceFlag.IS_INVOICE:
                        lines.append(_("I: Invoice related"))
                    if line.flags & KeyInstanceFlag.IS_PAYMENT_REQUEST:
                        lines.append(_("P: Payment request related"))
                    if line.flags & KeyInstanceFlag.USER_SET_ACTIVE:
                        lines.append(_("F: Forced active"))
                    if line.flags & KeyInstanceFlag.IS_ASSIGNED:
                        lines.append(_("X: Assigned"))
                    if len(lines):
                        return "\n".join(lines)
                elif column == KEY_COLUMN:
                    derivation_path_text: str = ""
                    if line.derivation_type == DerivationType.BIP32_SUBPATH:
                        derivation_path = unpack_derivation_path(line.derivation_data2)
                        derivation_path_text = bip32_build_chain_string(derivation_path)
                    return "\n".join([
                        f"Key instance id: {line.keyinstance_id}",
                        f"Master key id: {line.masterkey_id}",
                        f"Derivation path {derivation_path_text}",
                    ])

            elif role == Qt.EditRole:
                if column == LABEL_COLUMN:
                    return line.description

    def flags(self, model_index: QModelIndex) -> int:
        if model_index.isValid():
            column = model_index.column()
            flags = super().flags(model_index)
            if column == LABEL_COLUMN:
                flags |= Qt.ItemIsEditable
            return flags
        return Qt.ItemIsEnabled

    def headerData(self, section: int, orientation: int, role: int) -> Any:
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            if section < len(self._column_names):
                return self._column_names[section]

    def index(self, row_index: int, column_index: int, parent: Any) -> QModelIndex:
        if self.hasIndex(row_index, column_index, parent):
            return self.createIndex(row_index, column_index)
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
                self._view._account.set_keyinstance_label(line.keyinstance_id, value)
            self.dataChanged.emit(model_index, model_index)
            return True
        return False


class MatchType(enum.IntEnum):
    UNKNOWN = -1
    TEXT = 0
    ADDRESS = 1


class _SortFilterProxyModel(QSortFilterProxyModel):
    _filter_type: MatchType = MatchType.UNKNOWN
    _filter_match: Optional[Union[str, Address]] = None
    _account: Optional[AbstractAccount] = None

    def set_account(self, account: AbstractAccount) -> None:
        self._account = account

    def set_filter_match(self, text: Optional[str]) -> None:
        self._filter_type = MatchType.UNKNOWN

        if text is not None:
            try:
                address = Address.from_string(text, Net.COIN)
            except ValueError:
                pass
            else:
                self._filter_type = MatchType.ADDRESS
                self._filter_match = address

            if self._filter_type == MatchType.UNKNOWN:
                self._filter_type = MatchType.TEXT
                self._filter_match = text.lower()
        else:
            self._filter_match = None
        self.invalidateFilter()

    def lessThan(self, source_left: QModelIndex, source_right: QModelIndex) -> bool:
        # There is the chance that the data can be None which will not compare in problematic
        # situations, however the filter should check for it and prevent those rows from being
        # compared.
        value_left = self.sourceModel().data(source_left, QT_SORT_ROLE)
        value_right = self.sourceModel().data(source_right, QT_SORT_ROLE)
        return value_left < value_right

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        match = self._filter_match
        if match is None:
            return True

        source_model = self.sourceModel()
        if self._filter_type == MatchType.TEXT:
            for column in (KEY_COLUMN, LABEL_COLUMN, SCRIPT_COLUMN):
                column_index = source_model.index(source_row, column, source_parent)
                cell_data = source_model.data(column_index, Qt.DisplayRole)
                # In rare occasions the filter may get a None result for cell data.
                if cell_data and match in cell_data.lower():
                    return True
        elif self._filter_type == MatchType.ADDRESS and self._account is not None:
            column_index = source_model.index(source_row, KEY_COLUMN, source_parent)
            line: KeyLine = source_model.data(column_index, QT_FILTER_ROLE)
            account = self._account
            for script_type in ACCOUNT_SCRIPT_TYPES[account.type()]:
                template = account.get_script_template_for_key_data(line, script_type)
                if match == template:
                    return True
        return False


class KeyView(QTableView):
    def __init__(self, main_window: ElectrumWindow) -> None:
        super().__init__(main_window)
        self._logger = logs.get_logger("key-view")

        self._main_window = weakref.proxy(main_window)
        self._account: Optional[AbstractAccount] = None
        self._account_id: Optional[int] = None

        self._update_lock = threading.Lock()

        self._headers = COLUMN_NAMES

        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)

        self._pending_state: Dict[int, EventFlags] = {}
        self._pending_actions = { ListActions.RESET }
        self._main_window.keys_created_signal.connect(self._on_keys_created)
        self._main_window.keys_updated_signal.connect(self._on_keys_updated)
        self._main_window.account_change_signal.connect(self._on_account_change)

        model = _ItemModel(self, self._headers)
        model.set_data(self._account_id, [])
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
        self.sortByColumn(BALANCE_COLUMN, Qt.DescendingOrder)
        self.setSortingEnabled(True)

        defaultFontMetrics = QFontMetrics(app_state.app.font())
        def fw(s: str) -> int:
            return defaultFontMetrics.boundingRect(s).width() + 10

        self._monospace_font = QFont(platform.monospace_font)
        monospaceFontMetrics = QFontMetrics(self._monospace_font)
        def mw(s: str) -> int:
            return monospaceFontMetrics.boundingRect(s).width() + 10

        # We set the columm widths so that rendering is instant rather than taking a second or two
        # because ResizeToContents does not scale for thousands of rows.
        horizontalHeader = self.horizontalHeader()
        horizontalHeader.setMinimumSectionSize(20)
        horizontalHeader.resizeSection(TYPE_COLUMN, fw(COLUMN_NAMES[TYPE_COLUMN]))
        horizontalHeader.resizeSection(STATE_COLUMN, fw(COLUMN_NAMES[STATE_COLUMN]))
        horizontalHeader.resizeSection(KEY_COLUMN, fw("1442:01:m/000/1392"))
        horizontalHeader.resizeSection(SCRIPT_COLUMN, fw("MULTISIG_ACCUMULATOR"))
        horizontalHeader.setSectionResizeMode(LABEL_COLUMN, QHeaderView.Stretch)
        balance_width = mw(app_state.format_amount(1.2, whitespaces=True))
        horizontalHeader.resizeSection(BALANCE_COLUMN, balance_width)

        verticalHeader = self.verticalHeader()
        verticalHeader.setSectionResizeMode(QHeaderView.Fixed)
        # This value will get pushed out if the contents are larger, so it does not have to be
        # correct, it just has to be minimal.
        lineHeight = defaultFontMetrics.height()
        verticalHeader.setDefaultSectionSize(lineHeight)

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

    def reset_table(self) -> None:
        with self._update_lock:
            self._pending_state.clear()
            self._pending_actions = { ListActions.RESET }

    def _on_account_change(self, new_account_id: int, new_account: AbstractAccount) -> None:
        with self._update_lock:
            self._pending_state.clear()
            self._pending_actions = { ListActions.RESET }

            old_account_id = self._account_id
            self._account_id = new_account_id
            self._account = new_account

            self._logger = logs.get_logger(
                f"key-view[{new_account.get_wallet().name()}/{new_account_id}]")

            if old_account_id is None:
                self._timer.start()
            self._proxy_model.set_account(self._account)

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
                text = "\n".join(get_key_text(line) for line in selected.values())
                self._main_window.app.clipboard().setText(text)
        else:
            super().keyPressEvent(event)

    def _on_update_check(self) -> None:
        # No point in proceeding if no updates, or the wallet is synchronising still.
        if not self._have_pending_updates() or (time.time() - self._last_not_synced) < 5.0:
            return
        # We do not update if there has been a recent sync.
        if self._main_window.network and not self._main_window._wallet.is_synchronized():
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
        return bool(len(self._pending_actions) or len(self._pending_state))

    # def _dispatch_updates(self, pending_actions: Set[ListActions],
    #         pending_state: Dict[int, Tuple[KeyInstanceRow, EventFlags]]) -> None:
    #     import cProfile, pstats, io
    #     from pstats import SortKey
    #     pr = cProfile.Profile()
    #     pr.enable()
    #     self._dispatch_updates2(pending_actions, pending_state)
    #     pr.disable()
    #     s = io.StringIO()
    #     sortby = SortKey.CUMULATIVE
    #     ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    #     ps.print_stats()
    #     print(s.getvalue())

    @profiler
    def _dispatch_updates(self, pending_actions: Set[ListActions],
            pending_state: Dict[int, EventFlags]) -> None:
        account_id = self._account_id
        account = self._main_window._wallet.get_account(account_id)

        if ListActions.RESET in pending_actions:
            self._logger.debug("_on_update_check reset")

            self._data = account.get_key_list()
            self._base_model.set_data(account_id, self._data)
            return

        additions = []
        updates = []
        removals = []
        for key_id, flags in pending_state.items():
            if flags & EventFlags.KEY_ADDED:
                additions.append(key_id)
            elif flags & EventFlags.KEY_UPDATED:
                updates.append(key_id)
            elif flags & EventFlags.KEY_REMOVED:
                removals.append(key_id)

        # self._logger.debug("_on_update_check actions=%s adds=%d updates=%d removals=%d",
        #     pending_actions, len(additions), len(updates), len(removals))

        # We should process removals and additions before updates, as updates can happen to key
        # usages that are updated.
        self._remove_keys(removals)
        self._add_keys(account, additions, pending_state)
        self._update_keys(account, updates, pending_state)

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

    def _validate_account_event(self, account_id: int) -> bool:
        return account_id == self._account_id

    def _validate_application_event(self, wallet_path: str, account_id: int) -> bool:
        if wallet_path == self._main_window._wallet.get_storage_path():
            return self._validate_account_event(account_id)
        return False

    def _on_keys_created(self, account_id: int, keyinstance_ids: Iterable[int]) -> None:
        if not self._validate_account_event(account_id):
            return

        flags = EventFlags.KEY_ADDED
        for keyinstance_id in keyinstance_ids:
            self._pending_state[keyinstance_id] = flags

    def _on_keys_updated(self, account_id: int, keyinstance_ids: Iterable[int]) -> None:
        if not self._validate_account_event(account_id):
            return

        new_flags = EventFlags.KEY_UPDATED
        for keyinstance_id in keyinstance_ids:
            flags = self._pending_state.get(keyinstance_id, EventFlags.UNSET)
            self._pending_state[keyinstance_id] = flags | new_flags

    def _add_keys(self, account: AbstractAccount, key_ids: List[int],
            state: Dict[int, EventFlags]) -> None:
        self._logger.debug("_add_keys %r", key_ids)
        if not len(key_ids):
            return

        for line in account.get_key_list(key_ids):
            self._base_model.add_line(line)

    def _update_keys(self, account: AbstractAccount, update_key_ids: List[int],
            _state: Dict[int, EventFlags]) -> None:
        self._logger.debug("_update_keys %r", update_key_ids)

        matched_key_ids = set()
        new_line_map = {
            data_row_key(line): line for line in account.get_key_list(update_key_ids)
        }

        for row_index, line in enumerate(self._data):
            line_key = data_row_key(line)
            if line.keyinstance_id not in update_key_ids:
                continue
            matched_key_ids.add(line.keyinstance_id)
            new_line = new_line_map.get(line_key)
            if new_line is None:
                # This version of the key no longer exists.
                self._base_model.remove_row(row_index)
                self._logger.debug("_update_keys found stale entry for %r", line_key)
                continue
            self._data[row_index] = new_line
            self._base_model.invalidate_row(row_index)

        unmatched_key_ids = set(update_key_ids) - matched_key_ids
        if unmatched_key_ids:
            self._logger.debug("_update_keys missing entries %r", unmatched_key_ids)

    def _remove_keys(self, remove_key_ids: List[int]) -> None:
        self._logger.debug("_remove_keys %r", remove_key_ids)

        matched_key_ids = set()
        # Make sure that we will be removing rows from the last to the first, to preserve offsets.
        for data_index in range(len(self._data)-1, -1, -1):
            line = self._data[data_index]
            if line.keyinstance_id not in remove_key_ids:
                continue
            matched_key_ids.add(line.keyinstance_id)
            self._base_model.remove_row(data_index)

        unmatched_key_ids = set(remove_key_ids) - matched_key_ids
        if unmatched_key_ids:
            self._logger.debug("_remove_keys missing entries %r", unmatched_key_ids)

    # Called by the wallet window.
    def update_keys(self, keys: List[KeyInstanceRow]) -> None:
        with self._update_lock:
            for key in keys:
                flags = self._pending_state.get(key.keyinstance_id, EventFlags.UNSET)
                self._pending_state[key.keyinstance_id] = flags | EventFlags.KEY_UPDATED

    # Called by the wallet window.
    def remove_keys(self, keys: List[KeyInstanceRow]) -> None:
        with self._update_lock:
            for key in keys:
                flags = self._pending_state.get(key.keyinstance_id, EventFlags.UNSET)
                self._pending_state[key.keyinstance_id] = flags | EventFlags.KEY_REMOVED

   # Called by the wallet window.
    def update_frozen_transaction_outputs(self, txo_keys: List[TxoKeyType], freeze: bool) -> None:
        # NOTE We get the full row, but only use one column.
        keyinstance_ids = [
            txo.keyinstance_id
            for txo in self._main_window._wallet.get_transaction_outputs_short(txo_keys)
        ]
        with self._update_lock:
            new_flags = EventFlags.KEY_UPDATED | EventFlags.FREEZE_UPDATE
            for keyinstance_id in keyinstance_ids:
                flags = self._pending_state.get(keyinstance_id, EventFlags.UNSET)
                self._pending_state[keyinstance_id] = new_flags

    # The user has toggled the preferences setting.
    def _on_balance_display_change(self) -> None:
        with self._update_lock:
            self._pending_actions.add(ListActions.RESET_BALANCES)

    # The user has toggled the preferences setting.
    def _on_fiat_balance_display_change(self) -> None:
        with self._update_lock:
            self._pending_actions.add(ListActions.RESET_FIAT_BALANCES)

    # The user has edited a label either here, or in some other wallet location.
    def update_labels(self, wallet_path: str, account_id: int, key_updates: Set[int]) -> None:
        if not self._validate_application_event(wallet_path, account_id):
            return

        with self._update_lock:
            new_flags = EventFlags.KEY_UPDATED | EventFlags.LABEL_UPDATE

            for line in self._data:
                if line.keyinstance_id in key_updates:
                    flags = self._pending_state.get(line.keyinstance_id, EventFlags.UNSET)
                    self._pending_state[line.keyinstance_id] = flags | new_flags

    def _match_key_ids(self, key_ids: List[int]) -> List[Tuple[int, KeyLine]]:
        matches = []
        for row_index, line in enumerate(self._data):
            if line.keyinstance_id in key_ids:
                matches.append((row_index, line))
                if len(matches) == len(key_ids):
                    break
        return matches

    def _set_fiat_columns_enabled(self, flag: bool) -> None:
        self._fiat_history_enabled = flag

        if flag:
            fx = app_state.fx
            self._base_model.set_column_name(FIAT_BALANCE_COLUMN, f"{fx.ccy} {_('Balance')}")

        self.setColumnHidden(FIAT_BALANCE_COLUMN, not flag)

    def _set_user_active(self, keyinstance_ids: Set[int], enable: bool) -> None:
        self._logger.debug("_set_user_active %s %s", keyinstance_ids, enable)
        flags = KeyInstanceFlag.USER_SET_ACTIVE if enable else KeyInstanceFlag.NONE
        mask = KeyInstanceFlag(~KeyInstanceFlag.USER_SET_ACTIVE)
        self._account.set_keyinstance_flags(list(keyinstance_ids), flags, mask)

    def _event_double_clicked(self, model_index: QModelIndex) -> None:
        base_index = get_source_index(model_index, _ItemModel)
        column = base_index.column()
        if column == LABEL_COLUMN:
            self.edit(model_index)
        else:
            line: KeyListRow = self._data[base_index.row()]
            script_type = ScriptType(line.txo_script_type) if line.txo_script_type is not None \
                else ScriptType.NONE
            self._main_window.show_key(self._account, line, script_type)

    def _event_create_menu(self, position):
        menu = QMenu()

        # What the user clicked on.
        menu_index = self.indexAt(position)
        menu_source_index = get_source_index(menu_index, _ItemModel)
        menu_column = menu_source_index.column()

        column_title: Optional[str] = None
        if menu_source_index.row() != -1:
            menu_line = self._data[menu_source_index.row()]
            column_title = self._headers[menu_column]
            if menu_column == 0:
                copy_text = get_key_text(menu_line)
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
                script_type = ScriptType(line.txo_script_type) if line.txo_script_type is not None \
                    else ScriptType.NONE
                menu.addAction(_('Details'),
                    partial(self._main_window.show_key, self._account, line, script_type))
                if column == LABEL_COLUMN:
                    column_title = self._headers[menu_column]
                    menu.addAction(_("Edit {}").format(column_title),
                        lambda: self.edit(selected_index))
                menu.addAction(_("Request payment"),
                    lambda: self._main_window._receive_view.receive_at_key(line))
                if self._account.can_export():
                    menu.addAction(_("Private key"),
                        lambda: self._main_window.show_private_key(self._account, line,
                            line.txo_script_type))
                if not is_multisig and not self._account.is_watching_only():
                    menu.addAction(_("Sign/verify message"),
                        lambda: self._main_window.sign_verify_message(self._account, line))
                    menu.addAction(_("Encrypt/decrypt message"),
                                lambda: self._main_window.encrypt_message(self._account, line))

                explore_menu = menu.addMenu(_("View on block explorer"))

                addr_URL = script_URL = None
                if line.txo_script_type != ScriptType.NONE:
                    script_template = self._account.get_script_template_for_key_data(line,
                        line.txo_script_type)
                    if isinstance(script_template, Address):
                        addr_URL = web.BE_URL(self._main_window.config, 'addr', script_template)

                    scripthash = sha256(script_template.to_script_bytes())
                    scripthash_hex = hash_to_hex_str(scripthash)
                    script_URL = web.BE_URL(self._main_window.config, 'script', scripthash_hex)

                # NOTE(typing) `addAction` does not like a return value for the callback.
                addr_action = explore_menu.addAction(_("By address"),
                    partial(webbrowser.open, addr_URL)) # type: ignore
                if not addr_URL:
                    addr_action.setEnabled(False)
                # NOTE(typing) `addAction` does not like a return value for the callback.
                script_action = explore_menu.addAction(_("By script"),
                    partial(webbrowser.open, script_URL)) # type: ignore
                if not script_URL:
                    script_action.setEnabled(False)

                for script_type, script in self._account.get_possible_scripts_for_key_data(line):
                    scripthash_hex = hash_to_hex_str(scripthash_bytes(script))
                    script_URL = web.BE_URL(self._main_window.config, 'script', scripthash_hex)
                    if script_URL:
                        # NOTE(typing) `addAction` does not like a return value for the callback.
                        explore_menu.addAction(
                            _("As {scripttype}").format(scripttype=script_type.name),
                            partial(webbrowser.open, script_URL)) # type: ignore

                if isinstance(self._account, StandardAccount):
                    keystore = self._account.get_keystore()
                    if isinstance(keystore, Hardware_KeyStore):
                        # NOTE(typing) The whole keystore.plugin thing is not well defined.
                        def show_key():
                            self._main_window.run_in_thread(
                                keystore.plugin.show_key, self._account, # type: ignore
                                    line.keyinstance_id)
                        menu.addAction(_("Show on {}").format(
                            keystore.plugin.device), show_key) # type: ignore

            user_active_keyinstance_ids: Set[int] = set()
            non_user_active_keyinstance_ids: Set[int] = set()
            for _row, _column, line, _selected_index, _base_index in selected:
                if (line.flags & KeyInstanceFlag.USER_SET_ACTIVE) == 0:
                    non_user_active_keyinstance_ids.add(line.keyinstance_id)
                else:
                    user_active_keyinstance_ids.add(line.keyinstance_id)

            if len(non_user_active_keyinstance_ids):
                menu.addAction(_("Force activeness"),
                    partial(self._set_user_active, non_user_active_keyinstance_ids, True))
            if len(user_active_keyinstance_ids):
                menu.addAction(_("Remove forced activeness"),
                    partial(self._set_user_active, user_active_keyinstance_ids, False))

            # TODO(no-merge) Add option to set/unset frozen flag.

            user_active_keyinstance_ids: Set[int] = set()
            non_user_active_keyinstance_ids: Set[int] = set()
            for _row, _column, line, _selected_index, _base_index in selected:
                if (line.flags & KeyInstanceFlag.USER_SET_ACTIVE) == 0:
                    non_user_active_keyinstance_ids.add(line.keyinstance_id)
                else:
                    user_active_keyinstance_ids.add(line.keyinstance_id)

            if len(non_user_active_keyinstance_ids):
                menu.addAction(_("Force activeness"),
                    partial(self._set_user_active, non_user_active_keyinstance_ids, True))
            if len(user_active_keyinstance_ids):
                menu.addAction(_("Remove forced activeness"),
                    partial(self._set_user_active, user_active_keyinstance_ids, False))

            # TODO(nocheckin) Add option to set/unset frozen flag.

            # freeze = self._main_window.set_frozen_state
            # if any(self._account.is_frozen_address(addr) for addr in addrs):
            #     menu.addAction(_("Unfreeze"), partial(freeze, self._account, addrs, False))
            # if not all(self._account.is_frozen_address(addr) for addr in addrs):
            #     menu.addAction(_("Freeze"), partial(freeze, self._account, addrs, True))

            # These are KeyData-based rows, that may contain some limited output data.
            # We need spendable transaction output rows to give to the send tab.
            keyinstance_ids = [ line.keyinstance_id
                for (_row, _column, line, _selected_index, _base_index) in selected ]

            coins = self._account.get_spendable_transaction_outputs(
                keyinstance_ids=keyinstance_ids)
            if coins:
                menu.addAction(_("Spend from"), partial(self._main_window.spend_coins, coins))

        menu.exec_(self.viewport().mapToGlobal(position))
