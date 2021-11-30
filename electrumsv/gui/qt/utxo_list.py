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

from enum import IntEnum
from typing import cast, Dict, List, Optional, Set, Tuple, TYPE_CHECKING
import weakref

from PyQt5.QtCore import QItemSelectionModel, QPoint, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QAbstractItemView, QMenu, QTreeWidgetItem, QWidget

from bitcoinx import hash_to_hex_str

from ...app_state import app_state
from ...constants import TransactionOutputFlag
from ...i18n import _
from ...logs import logs
from ...platform import platform
from ...types import Outpoint
from ...util import profiler
from ...wallet import AbstractAccount
from ...wallet_database.types import AccountTransactionOutputSpendableRowExtended

from .util import SortableTreeWidgetItem, MyTreeWidget, ColorScheme


if TYPE_CHECKING:
    from .main_window import ElectrumWindow


logger = logs.get_logger("utxo-list")


class Column(IntEnum):
    OUTPOINT = 0
    DESCRIPTION = 1
    AMOUNT = 2
    HEIGHT = 3


class Role(IntEnum):
    DataUTXO = Qt.ItemDataRole.UserRole+2


class UTXOList(MyTreeWidget):
    filter_columns = [0, 2]  # Address, Label

    def __init__(self, parent: QWidget, main_window: "ElectrumWindow") -> None:
        MyTreeWidget.__init__(self, parent, main_window, self.create_menu, [
            _('Output point'), _('Transaction label'), _('Amount'), _('Height')],
            Column.DESCRIPTION)

        self._main_window = cast("ElectrumWindow", weakref.proxy(main_window))
        self._wallet = main_window._wallet
        self._account_id: Optional[int] = None
        self._account: Optional[AbstractAccount] = None

        self._main_window.account_change_signal.connect(self._on_account_change)

        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)

        self._monospace_font = QFont(platform.monospace_font)

    def on_account_change(self, new_account_id: int) -> None:
        self._account_id = new_account_id
        self._account = self._main_window._wallet.get_account(new_account_id)

    def _on_account_change(self, new_account_id: Optional[int],
            new_account: Optional[AbstractAccount]) -> None:
        self.clear()
        self._account_id = new_account_id
        self._account = new_account

    def on_doubleclick(self, item: QTreeWidgetItem, column: int) -> None:
        if self.permit_edit(item, column):
            super().on_doubleclick(item, column)
        else:
            utxo = cast(AccountTransactionOutputSpendableRowExtended, item.data(0, Role.DataUTXO))
            assert utxo.account_id is not None
            account = self._wallet.get_account(utxo.account_id)
            tx = self._wallet.get_transaction(utxo.tx_hash)
            assert tx is not None
            self._main_window.show_transaction(account, tx)

    # NOTE(typing) Ignore the stupid override stuff from mypy. This matches one signature.
    def update(self) -> None: # type: ignore[override]
        self._on_update_utxo_list()

    @profiler
    def _on_update_utxo_list(self) -> None:
        if self._account is None:
            return

        prev_selection = self.get_selected() # cache previous selection, if any
        self.clear()

        utxo_rows = self._account.get_transaction_outputs_with_key_and_tx_data(
            confirmed_only=False, mature=False, exclude_frozen=False)
        tx_hashes = set(utxo_row.tx_hash for utxo_row in utxo_rows)
        tx_labels: Dict[bytes, str] = {}
        if len(tx_hashes):
            for tx_label_row in self._account.get_transaction_labels(list(tx_hashes)):
                if tx_label_row.description:
                    tx_labels[tx_label_row.tx_hash] = tx_label_row.description

        for utxo in utxo_rows:
            prevout_str = f"{hash_to_hex_str(utxo.tx_hash)}:{utxo.txo_index}"
            prevout_str = prevout_str[0:10] + '...' + prevout_str[-2:]
            label = tx_labels.get(utxo.tx_hash, "")
            amount = app_state.format_amount(utxo.value, whitespaces=True)
            utxo_item = SortableTreeWidgetItem(
                [ prevout_str, label, amount, str(utxo.block_height) ])
            # set this here to avoid sorting based on Qt.UserRole+1
            utxo_item.DataRole = Qt.ItemDataRole.UserRole+100
            for col in (Column.OUTPOINT, Column.AMOUNT):
                utxo_item.setFont(col, self._monospace_font)
            utxo_item.setData(0, Role.DataUTXO, utxo)
            if utxo.flags & TransactionOutputFlag.FROZEN:
                utxo_item.setBackground(Column.OUTPOINT, ColorScheme.BLUE.as_color(True))
            self.addChild(utxo_item)
            if utxo in prev_selection:
                # NB: This needs to be here after the item is added to the widget. See #979.
                utxo_item.setSelected(True) # restore previous selection

    def update_tx_labels(self, update_entries: List[Tuple[Optional[str], int, bytes]]) -> None:
        tx_descriptions: Dict[bytes, str] = {}
        for text, account_id, tx_hash in update_entries:
            if account_id == self._account_id:
                tx_descriptions[tx_hash] = text or ""

        for row_idx in range(self.topLevelItemCount()):
            item = self.topLevelItem(row_idx)
            utxo = cast(AccountTransactionOutputSpendableRowExtended, item.data(0, Role.DataUTXO))
            if utxo.tx_hash not in tx_descriptions:
                continue
            new_description = tx_descriptions[utxo.tx_hash]
            if new_description != item.text(Column.DESCRIPTION):
                item.setText(Column.DESCRIPTION, new_description)

    def get_selected(self) -> Set[AccountTransactionOutputSpendableRowExtended]:
        return { item.data(0, Role.DataUTXO) for item in self.selectedItems() }

    def create_menu(self, position: QPoint) -> None:
        coins = self.get_selected()
        if not coins:
            return
        txo_keys = [ Outpoint(coin.tx_hash, coin.txo_index) for coin in coins ]

        menu = QMenu()
        menu.addAction(_("Spend"), lambda: self._main_window.spend_coins(coins))

        def freeze_coins() -> None:
            self._freeze_coins(txo_keys, True)
        def unfreeze_coins() -> None:
            self._freeze_coins(txo_keys, False)

        any_c_frozen = any(coin.flags & TransactionOutputFlag.FROZEN for coin in coins)
        all_c_frozen = all(coin.flags & TransactionOutputFlag.FROZEN for coin in coins)

        if len(coins) == 1:
            # single selection, offer them the "Details" option and also coin
            # "freeze" status, if any
            coin = list(coins)[0]
            def menu_show_transaction() -> None:
                tx = self._wallet.get_transaction(coin.tx_hash)
                assert tx is not None
                self._main_window.show_transaction(self._account, tx)
            menu.addAction(_("Details"), menu_show_transaction)

            if any_c_frozen:
                menu.addSeparator()
                menu.addAction(_("Coin is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Coin"), unfreeze_coins)
                menu.addSeparator()
            else:
                menu.addAction(_("Freeze Coin"), freeze_coins)
        else:
            # multi-selection
            menu.addSeparator()
            if not all_c_frozen:
                menu.addAction(_("Freeze Coins"), freeze_coins)
            if any_c_frozen:
                menu.addAction(_("Unfreeze Coins"), unfreeze_coins)

        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item: QTreeWidgetItem, column: int) -> bool:
        # disable editing fields in this tab (labels)
        return False

    def _freeze_coins(self, txo_keys: List[Outpoint], freeze: bool) -> None:
        assert self._account is not None
        self._main_window.set_frozen_coin_state(self._account, txo_keys, freeze)

    def select_coins(self, txo_keys: Set[Outpoint]) -> int:
        self.clearSelection()
        found = 0
        selection_model = self.selectionModel()
        items: List[QTreeWidgetItem] = []
        for row_idx in range(self.topLevelItemCount()):
            item = self.topLevelItem(row_idx)
            utxo = cast(AccountTransactionOutputSpendableRowExtended, item.data(0, Role.DataUTXO))
            txo_key = Outpoint(utxo.tx_hash, utxo.txo_index)
            if txo_key not in txo_keys:
                continue
            items.append(item)
            row_index = self.indexFromItem(item)
            selection_model.select(row_index, QItemSelectionModel.SelectionFlag(
                QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows))
            found += 1

        if len(items):
            self.scrollToItem(items[0])

        return found
