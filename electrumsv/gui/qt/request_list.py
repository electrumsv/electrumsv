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

from functools import partial
from typing import Optional, TYPE_CHECKING
import weakref

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QLabel, QTreeWidgetItem, QMenu, QVBoxLayout

from electrumsv.app_state import app_state
from electrumsv.bitcoin import script_template_to_string
from electrumsv.constants import RECEIVING_SUBPATH, PaymentFlag
from electrumsv.i18n import _
from electrumsv import paymentrequest
from electrumsv.platform import platform
from electrumsv.util import format_time, age
from electrumsv.wallet import AbstractAccount
from electrumsv import web

from .constants import pr_icons, pr_tooltips
from .qrtextedit import ShowQRTextEdit
from .util import Buttons, CopyCloseButton, MyTreeWidget, read_QIcon, WindowModalDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .receive_view import ReceiveView


class RequestList(MyTreeWidget):
    filter_columns = [0, 1, 2, 3, 4]  # Date, Account, Destination, Description, Amount

    update_signal = pyqtSignal()

    def __init__(self, receive_view: 'ReceiveView', main_window: 'ElectrumWindow') -> None:
        self._receive_view = receive_view
        self._main_window = weakref.proxy(main_window)
        self._account: Optional[AbstractAccount] = main_window._account
        self._account_id: Optional[int] = main_window._account_id

        self._monospace_font = QFont(platform.monospace_font)

        MyTreeWidget.__init__(self, receive_view, main_window, self.create_menu, [
            _('Date'), _('Destination'), '', _('Description'), _('Amount'), _('Status')], 3, [])

        self.currentItemChanged.connect(self._on_item_changed)
        self.itemClicked.connect(self._on_item_changed)
        self.setSortingEnabled(True)
        self.setColumnWidth(0, 180)
        self.hideColumn(1)

        self.update_signal.connect(self.update)

    def _on_item_changed(self, item) -> None:
        if item is None:
            return
        if not item.isSelected():
            return
        pr_id = item.data(0, Qt.UserRole)
        with self._account._wallet.get_payment_request_table() as table:
            pr = table.read_one(pr_id)
        expires = age(pr.date_created + pr.expiration) if pr.expiration else _('Never')

        self._receive_view.set_receive_key_id(pr.keyinstance_id)
        script_template = self._account.get_script_template_for_id(pr.keyinstance_id)
        address_text = script_template_to_string(script_template)
        self._receive_view.set_form_contents(address_text, pr.value, pr.description, expires)

    def on_update(self) -> None:
        if self._account_id is None:
            return

        wallet = self._account._wallet
        with wallet.get_payment_request_table() as table:
            rows = table.read(self._account_id, flags=PaymentFlag.NONE,
                mask=PaymentFlag.ARCHIVED)

        # update the receive address if necessary
        current_key_id = self._receive_view.get_receive_key_id()
        if current_key_id is None:
            return

        keyinstance = None
        if self._account.is_deterministic():
            keyinstance = self._account.get_fresh_keys(RECEIVING_SUBPATH, 1)[0]
        if keyinstance is not None:
            self._receive_view.set_receive_key(keyinstance)
            self._receive_view.set_new_button_enabled(current_key_id != keyinstance.keyinstance_id)

        # clear the list and fill it again
        self.clear()
        for row in rows:
            date = format_time(row.date_created, _("Unknown"))
            amount_str = app_state.format_amount(row.value, whitespaces=True) if row.value else ""

            script_template = self._account.get_script_template_for_id(row.keyinstance_id)
            address_text = script_template_to_string(script_template)

            state = row.state & sum(pr_icons.keys())
            item = QTreeWidgetItem([date, address_text, '', row.description or "",
                amount_str, pr_tooltips.get(state,'')])
            item.setData(0, Qt.UserRole, row.paymentrequest_id)
            if state != PaymentFlag.UNKNOWN:
                icon_name = pr_icons.get(state)
                if icon_name is not None:
                    item.setIcon(6, read_QIcon(icon_name))
            item.setFont(4, self._monospace_font)
            self.addTopLevelItem(item)

    def create_menu(self, position):
        item = self.itemAt(position)
        if not item:
            return
        request_id = item.data(0, Qt.UserRole)
        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()
        menu = QMenu(self)
        menu.addAction(_("Copy {}").format(column_title),
            lambda: app_state.app.clipboard().setText(column_data))
        menu.addAction(_("Copy URI"),
            lambda: self._view_and_paste('URI', '', self._get_request_URI(request_id)))
        action = menu.addAction(_("Save as BIP270 file"),
            lambda: self._export_payment_request(request_id))
        # There cannot be a payment URI at this time.
        # TODO: Revisit when there is a identity and hosted service.
        action.setEnabled(False)
        menu.addAction(_("Delete"), partial(self._delete_payment_request, request_id))
        menu.exec_(self.viewport().mapToGlobal(position))

    def _get_request_URI(self, pr_id: int) -> str:
        with self._account.get_wallet().get_payment_request_table() as table:
            req = table.read_one(pr_id)
        message = self._account.get_keyinstance_label(req.keyinstance_id)
        script_template = self._account.get_script_template_for_id(req.keyinstance_id)
        address_text = script_template_to_string(script_template)

        URI = web.create_URI(address_text, req.value, message)
        URI += f"&time={req.date_created}"
        if req.expiration:
            URI += f"&exp={req.expiration}"
        return str(URI)

    def _export_payment_request(self, pr_id: int) -> None:
        with self._account.get_wallet().get_payment_request_table() as table:
            pr = table.read_one(pr_id)
        pr_data = paymentrequest.PaymentRequest.from_wallet_entry(self._account, pr).to_json()
        name = f'{pr.paymentrequest_id}.bip270.json'
        fileName = self._main_window.getSaveFileName(
            _("Select where to save your payment request"), name, "*.bip270.json")
        if fileName:
            with open(fileName, "w") as f:
                f.write(pr_data)
            self.show_message(_("Request saved successfully"))

    def _delete_payment_request(self, request_id: int) -> None:
        def callback(exc_value: Optional[Exception]=None) -> None:
            if exc_value is not None:
                raise exc_value # pylint: disable=raising-bad-type
            self.update_signal.emit()

        self._account.requests.delete_request(request_id, callback)

        # The key may have been freed up and should be used first.
        self._receive_view.update_contents()

    def _view_and_paste(self, title: str, msg: str, data: str) -> None:
        dialog = WindowModalDialog(self, title)
        vbox = QVBoxLayout()
        label = QLabel(msg)
        label.setWordWrap(True)
        vbox.addWidget(label)
        pr_e = ShowQRTextEdit(text=data)
        vbox.addWidget(pr_e)
        vbox.addLayout(Buttons(CopyCloseButton(pr_e.text, app_state.app, dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()
