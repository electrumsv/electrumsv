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

from typing import List, Optional
import weakref

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QAbstractItemView, QMenu, QWidget

from electrumsv.app_state import app_state
from electrumsv.i18n import _
from electrumsv.platform import platform
from electrumsv.util import profiler
from electrumsv.wallet import AbstractAccount, UTXO

from .main_window import ElectrumWindow
from .util import SortableTreeWidgetItem, MyTreeWidget, ColorScheme


class UTXOList(MyTreeWidget):
    filter_columns = [0, 2]  # Address, Label

    def __init__(self, parent: QWidget, main_window: ElectrumWindow) -> None:
        MyTreeWidget.__init__(self, parent, main_window, self.create_menu, [
            _('Output point'), _('Label'), _('Amount'), _('Height')], 1)

        self._main_window = weakref.proxy(main_window)
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

    def _on_account_change(self, new_account_id: int, new_account: AbstractAccount) -> None:
        self.clear()
        old_account_id = self._account_id
        self._account_id = new_account_id
        self._account = new_account

    def update(self) -> None:
        self._on_update_utxo_list()

    @profiler
    def _on_update_utxo_list(self):
        if self._account_id is None:
            return

        prev_selection = self.get_selected() # cache previous selection, if any
        self.clear()

        for utxo in self._account.get_utxos():
            metadata = self._account.get_transaction_metadata(utxo.tx_hash)
            prevout_str = utxo.key_str()
            prevout_str = prevout_str[0:10] + '...' + prevout_str[-2:]
            label = self._wallet.get_transaction_label(utxo.tx_hash)
            amount = app_state.format_amount(utxo.value, whitespaces=True)
            utxo_item = SortableTreeWidgetItem(
                [ prevout_str, label, amount, str(metadata.height) ])
            # set this here to avoid sorting based on Qt.UserRole+1
            utxo_item.DataRole = Qt.UserRole+100
            for col in (0, 2):
                utxo_item.setFont(col, self._monospace_font)
            utxo_item.setData(0, Qt.UserRole+2, utxo)
            if self._account.is_frozen_utxo(utxo):
                utxo_item.setBackground(0, ColorScheme.BLUE.as_color(True))
            self.addChild(utxo_item)
            if utxo in prev_selection:
                # NB: This needs to be here after the item is added to the widget. See #979.
                utxo_item.setSelected(True) # restore previous selection

    def get_selected(self):
        return {item.data(0, Qt.UserRole+2) for item in self.selectedItems()}

    def create_menu(self, position) -> None:
        coins = self.get_selected()
        if not coins:
            return
        menu = QMenu()
        menu.addAction(_("Spend"), lambda: self._main_window.spend_coins(coins))

        def freeze_coins() -> None:
            self.freeze_coins(coins, True)
        def unfreeze_coins() -> None:
            self.freeze_coins(coins, False)

        any_c_frozen = any(self._account.is_frozen_utxo(coin) for coin in coins)
        all_c_frozen = all(self._account.is_frozen_utxo(coin) for coin in coins)

        if len(coins) == 1:
            # single selection, offer them the "Details" option and also coin
            # "freeze" status, if any
            coin = list(coins)[0]
            tx = self._account.get_transaction(coin.tx_hash)
            menu.addAction(_("Details"), lambda: self._main_window.show_transaction(
                self._account, tx))
            needsep = True
            if any_c_frozen:
                menu.addSeparator()
                menu.addAction(_("Coin is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Coin"), unfreeze_coins)
                menu.addSeparator()
                needsep = False
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

    def on_permit_edit(self, item, column) -> bool:
        # disable editing fields in this tab (labels)
        return False

    def freeze_coins(self, coins: List[UTXO], freeze: bool) -> None:
        self._main_window.set_frozen_coin_state(self._account, coins, freeze)
