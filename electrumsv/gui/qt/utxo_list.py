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

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import QAbstractItemView, QMenu

from .util import SortableTreeWidgetItem, MyTreeWidget, ColorScheme
from electrumsv.i18n import _
from electrumsv.platform import platform
from electrumsv.util import profiler
from electrumsv.wallet import Abstract_Wallet


class UTXOList(MyTreeWidget):
    filter_columns = [0, 2]  # Address, Label

    def __init__(self, parent: 'ElectrumWindow', initial_wallet: Abstract_Wallet) -> None:
        MyTreeWidget.__init__(self, parent, self.create_menu, [
            _('Address'), _('Label'), _('Amount'), _('Height'), _('Output point')], 1)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        # force attributes to always be defined, even if None, at construction.
        # TODO: ACCOUNTS: In the multi-account paradigm, we need to consider how to view all
        # utxos. And how to view per-wallet utxos.
        self.wallet = initial_wallet
        self.monospace_font = QFont(platform.monospace_font)

    def on_update(self):
        self._on_update_utxo_list()

    @profiler
    def _on_update_utxo_list(self):
        prev_selection = self.get_selected() # cache previous selection, if any
        wallet_id = self.wallet.get_id()
        self.clear()
        for utxo in self.wallet.get_utxos():
            address_text = utxo.address.to_string()
            prevout_str = utxo.key_str()
            prevout_str = prevout_str[0:10] + '...' + prevout_str[-2:]
            label = self.wallet.get_label(utxo.tx_hash)
            amount = self.parent.format_amount(utxo.value, whitespaces=True)
            utxo_item = SortableTreeWidgetItem([address_text, label, amount,
                                                str(utxo.height), prevout_str])
            # set this here to avoid sorting based on Qt.UserRole+1
            utxo_item.DataRole = Qt.UserRole+100
            for col in (0, 2, 4):
                utxo_item.setFont(col, self.monospace_font)
            utxo_item.setData(0, Qt.UserRole, (wallet_id, address_text))
            utxo_item.setData(0, Qt.UserRole+2, utxo)
            a_frozen = self.wallet.is_frozen_address(utxo.address)
            c_frozen = self.wallet.is_frozen_utxo(utxo)
            if a_frozen and not c_frozen:
                # address is frozen, coin is not frozen
                # emulate the "Look" off the address_list .py's frozen entry
                utxo_item.setBackground(0, QColor('lightblue'))
            elif c_frozen and not a_frozen:
                # coin is frozen, address is not frozen
                utxo_item.setBackground(0, ColorScheme.BLUE.as_color(True))
            elif c_frozen and a_frozen:
                # both coin and address are frozen so color-code it to indicate that.
                utxo_item.setBackground(0, QColor('lightblue'))
                utxo_item.setForeground(0, QColor('#3399ff'))
            self.addChild(utxo_item)
            if utxo in prev_selection:
                # NB: This needs to be here after the item is added to the widget. See #979.
                utxo_item.setSelected(True) # restore previous selection

    def get_selected(self):
        return {item.data(0, Qt.UserRole+2) for item in self.selectedItems()}

    def create_menu(self, position):
        coins = self.get_selected()
        if not coins:
            return
        menu = QMenu()
        menu.addAction(_("Spend"), lambda: self.parent.spend_coins(coins))

        def freeze_addresses():
            self.freeze_addresses(coins, True)
        def unfreeze_addresses():
            self.freeze_addresses(coins, False)
        def freeze_coins():
            self.freeze_coins(coins, True)
        def unfreeze_coins():
            self.freeze_coins(coins, False)

        any_a_frozen = any(self.wallet.is_frozen_address(coin.address) for coin in coins)
        all_a_frozen = all(self.wallet.is_frozen_address(coin.address) for coin in coins)
        any_c_frozen = any(self.wallet.is_frozen_utxo(coin) for coin in coins)
        all_c_frozen = all(self.wallet.is_frozen_utxo(coin) for coin in coins)

        if len(coins) == 1:
            # single selection, offer them the "Details" option and also coin/address
            # "freeze" status, if any
            coin = list(coins)[0]
            tx = self.wallet.get_transaction(coin.tx_hash)
            menu.addAction(_("Details"), lambda: self.parent.show_transaction(tx))
            needsep = True
            if any_c_frozen:
                menu.addSeparator()
                menu.addAction(_("Coin is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Coin"), unfreeze_coins)
                menu.addSeparator()
                needsep = False
            else:
                menu.addAction(_("Freeze Coin"), freeze_coins)
            if any_a_frozen:
                if needsep: menu.addSeparator()
                menu.addAction(_("Address is frozen"), lambda: None).setEnabled(False)
                menu.addAction(_("Unfreeze Address"), unfreeze_addresses)
            else:
                menu.addAction(_("Freeze Address"), freeze_addresses)
        else:
            # multi-selection
            menu.addSeparator()
            if not all_c_frozen:
                menu.addAction(_("Freeze Coins"), freeze_coins)
            if any_c_frozen:
                menu.addAction(_("Unfreeze Coins"), unfreeze_coins)
            if not all_a_frozen:
                menu.addAction(_("Freeze Addresses"), freeze_addresses)
            if any_a_frozen:
                menu.addAction(_("Unfreeze Addresses"), unfreeze_addresses)

        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # disable editing fields in this tab (labels)
        return False

    def freeze_addresses(self, coins, freeze: bool) -> None:
        addrs = {coin.address for coin in coins}
        self.parent.set_frozen_state(self.wallet, list(addrs), freeze)

    def freeze_coins(self, coins, freeze: bool) -> None:
        self.parent.set_frozen_coin_state(self.wallet, coins, freeze)
