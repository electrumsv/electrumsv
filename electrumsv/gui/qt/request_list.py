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

from ...app_state import app_state
from ...bitcoin import script_template_to_string
from ...constants import PaymentFlag
from ...i18n import _
from ...logs import logs
from ...paymentrequest import PaymentRequest
from ...platform import platform
from ...util import format_time
from ...wallet import AbstractAccount
from ...web import create_URI

from .constants import pr_icons, pr_tooltips
from .qrtextedit import ShowQRTextEdit
from .util import Buttons, CopyCloseButton, MyTreeWidget, read_QIcon, WindowModalDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .receive_view import ReceiveView


# TODO(ScriptTypeAssumption) It is assumed that all active payment requests from the receive tab
# are given out for the wallet's default script type. This isn't necessarily true but is close
# enough for now. To fix it we'd have to extend the database table, and also display the
# script type in the list or similarly allow the user to see it.

class RequestList(MyTreeWidget):
    filter_columns = [0, 1, 2, 3, 4]  # Date, Account, Destination, Description, Amount

    update_signal = pyqtSignal()

    def __init__(self, receive_view: 'ReceiveView', main_window: 'ElectrumWindow') -> None:
        self._receive_view = receive_view
        self._main_window = weakref.proxy(main_window)
        self._account: Optional[AbstractAccount] = main_window._account
        self._account_id: Optional[int] = main_window._account_id

        self._monospace_font = QFont(platform.monospace_font)
        self._logger = logs.get_logger("request-list")

        MyTreeWidget.__init__(self, receive_view, main_window, self.create_menu, [
            _('Date'), _('Destination'), '', _('Description'), _('Amount'), _('Status')], 3, [])

        self.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.setSortingEnabled(True)
        self.setColumnWidth(0, 180)
        self.hideColumn(1)

        self.update_signal.connect(self.update)

    def _on_item_double_clicked(self, item) -> None:
        self._logger.debug("request_list._on_item_double_clicked")
        if item is None:
            return
        if not item.isSelected():
            return
        request_id = item.data(0, Qt.UserRole)

        dialog = self._receive_view.get_dialog(request_id)
        if dialog is None:
            dialog = self._receive_view.create_edit_dialog(request_id)
        dialog.show()

    def on_update(self) -> None:
        if self._account_id is None:
            return

        # TODO(nocheckin) Check the account and only update if applicable?

        wallet = self._account._wallet
        rows = wallet.read_payment_requests(self._account_id, flags=PaymentFlag.NONE,
            mask=PaymentFlag.ARCHIVED)


        # clear the list and fill it again
        self.clear()
        for row in rows:
            date = format_time(row.date_created, _("Unknown"))
            amount_str = app_state.format_amount(row.value, whitespaces=True) if row.value else ""

            # TODO(ScriptTypeAssumption) see above for context
            # TODO: This is a per-row database lookup.
            pr_keyinstance = wallet.read_keyinstance(keyinstance_id=row.keyinstance_id)
            script_template = self._account.get_script_template_for_key_data(pr_keyinstance,
                self._account.get_default_script_type())
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
        wallet = self._account.get_wallet()
        req = self._account._wallet.read_payment_request(request_id=pr_id)
        message = self._account.get_keyinstance_label(req.keyinstance_id)
        # TODO(ScriptTypeAssumption) see above for context
        keyinstance = wallet.read_keyinstance(keyinstance_id=req.keyinstance_id)
        script_template = self._account.get_script_template_for_key_data(keyinstance,
            self._account.get_default_script_type())
        address_text = script_template_to_string(script_template)

        URI = create_URI(address_text, req.value, message)
        URI += f"&time={req.date_created}"
        if req.expiration:
            URI += f"&exp={req.expiration}"
        return str(URI)

    def _export_payment_request(self, pr_id: int) -> None:
        pr = self._account._wallet.read_payment_request(request_id=pr_id)
        pr_data = PaymentRequest.from_wallet_entry(self._account, pr).to_json()
        name = f'{pr.paymentrequest_id}.bip270.json'
        fileName = self._main_window.getSaveFileName(
            _("Select where to save your payment request"), name, "*.bip270.json")
        if fileName:
            with open(fileName, "w") as f:
                f.write(pr_data)
            self.show_message(_("Request saved successfully"))

    def _delete_payment_request(self, request_id: int) -> None:
        # Blocking deletion call.
        wallet = self._account.get_wallet()
        row = wallet.read_payment_request(request_id=request_id)
        if row is None:
            return

        future = wallet.delete_payment_request(request_id, row.keyinstance_id)
        future.result()

        self.update_signal.emit()
        # The key may have been freed up and should be used first.
        # NOTE(rt12) WTF does this even mean?
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
