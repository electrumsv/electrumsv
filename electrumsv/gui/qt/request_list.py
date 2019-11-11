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
from PyQt5.QtWidgets import QTreeWidgetItem, QMenu

from electrumsv.bitcoin import address_from_string, script_template_to_string
from electrumsv.i18n import _
from electrumsv.util import format_time, age
from electrumsv.paymentrequest import PR_UNKNOWN

from .util import MyTreeWidget, pr_tooltips, pr_icons, read_QIcon


class RequestList(MyTreeWidget):
    filter_columns = [0, 1, 2, 3, 4]  # Date, Account, Address, Description, Amount

    def __init__(self, parent):
        self._account = parent._wallet.get_default_account()
        MyTreeWidget.__init__(self, parent, parent, self.create_menu, [
            _('Date'), _('Payment destination'), '', _('Description'), _('Amount'), _('Status')], 3)
        self.currentItemChanged.connect(self.item_changed)
        self.itemClicked.connect(self.item_changed)
        self.setSortingEnabled(True)
        self.setColumnWidth(0, 180)
        self.hideColumn(1)

    def item_changed(self, item):
        if item is None:
            return
        if not item.isSelected():
            return
        key_id = item.data(0, Qt.UserRole)
        req = self._account.receive_requests[key_id]
        expires = age(req['time'] + req['exp']) if req.get('exp') else _('Never')
        amount = req['amount']

        script_template = self._account.get_script_template_for_id(key_id)
        address_text = script_template_to_string(script_template)
        self.parent.receive_destination_e.setText(address_text)

        message = self._account.get_keyinstance_label(key_id)
        self.parent.receive_message_e.setText(message)

        self.parent.receive_amount_e.setAmount(amount)
        self.parent.expires_combo.hide()
        self.parent.expires_label.show()
        self.parent.expires_label.setText(expires)
        self.parent.new_request_button.setEnabled(True)

    def on_update(self):
        # hide receive tab if no receive requests available
        b = len(self._account.receive_requests) > 0
        self.setVisible(b)
        self.parent.receive_requests_label.setVisible(b)
        if not b:
            self.parent.expires_label.hide()
            self.parent.expires_combo.show()

        # update the receive address if necessary
        current_address_string = self.parent.receive_destination_e.text().strip()
        current_address = (address_from_string(current_address_string)
                           if len(current_address_string) else None)

        # TODO(rt12) BACKLOG replace with either create or allocate key.
        addr = self._account.get_unused_address_REPLACE()
        if addr:
            self.parent.set_receive_address(addr)
        self.parent.new_request_button.setEnabled(addr != current_address)

        account_id = self._account.get_id()

        # clear the list and fill it again
        self.clear()
        for req in self._account.get_sorted_requests():
            key_id = req["key_id"]
            timestamp = req.get('time', 0)
            amount = req.get('amount')
            expiration = req.get('exp', None)
            message = req.get('memo', '')
            date = format_time(timestamp, _("Unknown"))
            status = req.get('status')
            amount_str = self.parent.format_amount(amount) if amount else ""

            script_template = self._account.get_script_template_for_id(key_id)
            address_text = script_template_to_string(script_template)

            item = QTreeWidgetItem([date, address_text, '', message,
                                    amount_str, pr_tooltips.get(status,'')])
            item.setData(0, Qt.UserRole, key_id)
            if status is not PR_UNKNOWN:
                item.setIcon(6, read_QIcon(pr_icons.get(status)))
            self.addTopLevelItem(item)

    def create_menu(self, position):
        item = self.itemAt(position)
        if not item:
            return
        key_id = item.data(0, Qt.UserRole)
        req = self._account.receive_requests[key_id]
        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()
        menu = QMenu(self)
        menu.addAction(_("Copy {}").format(column_title),
                       lambda: self.parent.app.clipboard().setText(column_data))
        menu.addAction(_("Copy URI"),
                       lambda: self.parent.view_and_paste(
                           'URI', '', self.parent.get_request_URI(key_id)))
        menu.addAction(_("Save as BIP270 file"),
            lambda: self.parent.export_payment_request(key_id))
        menu.addAction(_("Delete"),
            lambda: self.parent.delete_payment_request(key_id))
        menu.exec_(self.viewport().mapToGlobal(position))
