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

from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QTreeWidgetItem, QMenu

from electrumsv.bitcoin import script_template_to_string
from electrumsv.constants import RECEIVING_SUBPATH, PaymentState
from electrumsv.i18n import _
from electrumsv.util import format_time, age
from electrumsv.wallet import AbstractAccount

from .main_window import ElectrumWindow
from .util import MyTreeWidget, pr_tooltips, pr_icons, read_QIcon


class RequestList(MyTreeWidget):
    filter_columns = [0, 1, 2, 3, 4]  # Date, Account, Destination, Description, Amount

    def __init__(self, parent: ElectrumWindow) -> None:
        self._main_window = parent
        self._account: AbstractAccount = None
        self._account_id: Optional[int] = None

        MyTreeWidget.__init__(self, parent, parent, self.create_menu, [
            _('Date'), _('Destination'), '', _('Description'), _('Amount'), _('Status')], 3,
            [])
        self.currentItemChanged.connect(self.item_changed)
        self.itemClicked.connect(self.item_changed)
        self.setSortingEnabled(True)
        self.setColumnWidth(0, 180)
        self.hideColumn(1)

        self._main_window.account_change_signal.connect(self._on_account_change)

    def _on_account_change(self, new_account_id: int) -> None:
        old_account_id = self._account_id
        self._account_id = new_account_id
        self._account = self._main_window._wallet.get_account(self._account_id)

        self.update()

    def item_changed(self, item):
        if item is None:
            return
        if not item.isSelected():
            return
        pr_id = item.data(0, Qt.UserRole)
        pr = self._account.get_payment_request(pr_id)
        expires = age(pr.date_created + pr.expiration) if pr.expiration else _('Never')

        self._main_window._receive_key_id = pr.keyinstance_id
        script_template = self._account.get_script_template_for_id(pr.keyinstance_id)
        address_text = script_template_to_string(script_template)
        self._main_window.receive_destination_e.setText(address_text)
        self._main_window.receive_message_e.setText(pr.description or "")
        self._main_window.receive_amount_e.setAmount(pr.value)
        self._main_window.expires_combo.hide()
        self._main_window.expires_label.show()
        self._main_window.expires_label.setText(expires)
        self._main_window.new_request_button.setEnabled(True)

    def on_update(self) -> None:
        if self._account_id is None:
            return

        # hide receive tab if no receive requests available
        b = len(self._account._payment_requests) > 0
        self.setVisible(b)
        self._main_window.receive_requests_label.setVisible(b)
        if not b:
            self._main_window.expires_label.hide()
            self._main_window.expires_combo.show()

        # update the receive address if necessary
        current_key_id = self._main_window.get_receive_key_id()
        if current_key_id is None:
            return

        keyinstance = None
        if self._account.is_deterministic():
            keyinstance = self._account.get_fresh_keys(RECEIVING_SUBPATH, 1)[0]
        if keyinstance is not None:
            self._main_window.set_receive_key(keyinstance)
        self._main_window.new_request_button.setEnabled(
            current_key_id != keyinstance.keyinstance_id)

        account_id = self._account.get_id()

        # clear the list and fill it again
        self.clear()
        for req in self._account.get_sorted_requests():
            date = format_time(req.date_created, _("Unknown"))
            amount_str = self._main_window.format_amount(req.value) if req.value else ""

            script_template = self._account.get_script_template_for_id(req.keyinstance_id)
            address_text = script_template_to_string(script_template)

            item = QTreeWidgetItem([date, address_text, '', req.description or "",
                amount_str, pr_tooltips.get(req.state,'')])
            item.setData(0, Qt.UserRole, req.paymentrequest_id)
            if req.state != PaymentState.UNKNOWN:
                item.setIcon(6, read_QIcon(pr_icons.get(req.state)))
            self.addTopLevelItem(item)

    def create_menu(self, position):
        item = self.itemAt(position)
        if not item:
            return
        pr_id = item.data(0, Qt.UserRole)
        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()
        menu = QMenu(self)
        menu.addAction(_("Copy {}").format(column_title),
                       lambda: self._main_window.app.clipboard().setText(column_data))
        menu.addAction(_("Copy URI"),
                       lambda: self._main_window.view_and_paste(
                           'URI', '', self._main_window.get_request_URI(pr_id)))
        menu.addAction(_("Save as BIP270 file"),
            lambda: self._main_window.export_payment_request(pr_id))
        menu.addAction(_("Delete"),
            lambda: self._main_window.delete_payment_request(pr_id))
        menu.exec_(self.viewport().mapToGlobal(position))
