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
import math
import time
from typing import TYPE_CHECKING, Optional
import weakref

from PyQt5.QtCore import Qt, QPoint, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QHeaderView, QTreeWidgetItem, QFileDialog, QMenu

from electrumsv.app_state import app_state
from electrumsv.constants import PaymentFlag
from electrumsv.exceptions import FileImportFailed
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.paymentrequest import PaymentRequest
from electrumsv.platform import platform
from electrumsv.util import format_time
from electrumsv.wallet import AbstractAccount
from electrumsv.wallet_database.tables import InvoiceRow

from .constants import pr_icons, pr_tooltips
from .util import MyTreeWidget, read_QIcon

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .send_view import SendView


logger = logs.get_logger("invoice-list")


class InvoiceList(MyTreeWidget):
    filter_columns = [0, 1, 2, 3]  # Date, Requestor, Description, Amount

    def __init__(self, parent: 'SendView', main_window: 'ElectrumWindow') -> None:
        MyTreeWidget.__init__(self, parent, main_window, self.create_menu, [
            _('Expires'), _('Requestor'), _('Description'), _('Amount'), _('Status')], 2)

        self._send_view = parent
        self._main_window = weakref.proxy(main_window)

        self.monospace_font = QFont(platform.monospace_font)
        self.setSortingEnabled(True)
        self.header().setSectionResizeMode(1, QHeaderView.Interactive)
        self.setColumnWidth(1, 200)

        # This is used if there is a pending expiry.
        self._timer: Optional[QTimer] = None

    def _start_timer(self, event_time: int) -> None:
        seconds = math.ceil(event_time - time.time())
        assert seconds > 0, f"got invalid timer duration {seconds}"
        logger.debug("start_timer for %d seconds", seconds)
        interval = seconds * 1000

        assert self._timer is None, "timer already active"
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_timer_event)
        self._timer.start(interval)

    def _stop_timer(self) -> None:
        if self._timer is None:
            return
        self._timer.stop()
        self._timer = None

    def _on_timer_event(self) -> None:
        logger.debug("_on_timer_event")
        self._stop_timer()
        self.update()

    def on_update(self) -> None:
        if self._send_view._account_id is None:
            return

        self._stop_timer()
        self.clear()

        current_time = time.time()
        expiry_time = float("inf")

        for row in self._send_view._account.invoices.get_invoices():
            flags = row.flags & PaymentFlag.STATE_MASK
            if flags & PaymentFlag.UNPAID and row.date_expires:
                if row.date_expires <= current_time + 4:
                    flags = (row.flags & ~PaymentFlag.UNPAID) | PaymentFlag.EXPIRED
                else:
                    expiry_time = min(expiry_time, row.date_expires)

            date_str = format_time(row.date_expires, _("Unknown")
                if row.date_expires else _('Never'))
            item = QTreeWidgetItem([date_str, row.payment_uri, row.description,
                app_state.format_amount(row.value, whitespaces=True),
                pr_tooltips.get(flags, '')])
            icon_entry = pr_icons.get(flags)
            if icon_entry:
                item.setIcon(4, read_QIcon(icon_entry))
            item.setData(0, Qt.UserRole, row.invoice_id)
            item.setFont(1, self.monospace_font)
            item.setFont(3, self.monospace_font)
            self.addTopLevelItem(item)
        self.setCurrentItem(self.topLevelItem(0))

        if expiry_time != float("inf"):
            self._start_timer(expiry_time)

    def on_edited(self, item, column, prior) -> None:
        '''Called only when the text actually changes'''
        text = item.text(column).strip()
        if text == "":
            text = None
        invoice_id = item.data(0, Qt.UserRole)
        self._send_view._account.invoices.set_invoice_description(invoice_id, text)

    def import_invoices(self, account: AbstractAccount) -> None:
        try:
            wallet_folder = self.config.get_preferred_wallet_dirpath()
        except FileNotFoundError as e:
            self._main_window.show_error(str(e))
            return

        filename, __ = QFileDialog.getOpenFileName(self._main_window, _("Select your wallet file"),
            wallet_folder)
        if not filename:
            return

        try:
            account.invoices.import_file(filename)
        except FileImportFailed as e:
            self._main_window.show_message(str(e))
        self.on_update()

    def create_menu(self, position: QPoint) -> None:
        menu = QMenu()
        item = self.itemAt(position)
        if not item:
            return
        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()

        invoice_id: int = item.data(0, Qt.UserRole)
        row = self._send_view._account.invoices.get_invoice_for_id(invoice_id)
        assert row is not None, f"invoice {invoice_id} not found"

        flags = row.flags & PaymentFlag.STATE_MASK
        if flags & PaymentFlag.UNPAID and row.date_expires:
            if row.date_expires <= time.time() + 4:
                flags = (row.flags & ~PaymentFlag.UNPAID) | PaymentFlag.EXPIRED

        if column_data:
            menu.addAction(_("Copy {}").format(column_title),
                lambda: self._main_window.app.clipboard().setText(column_data))
        menu.addAction(_("Details"), partial(self._show_invoice_window, row))
        if flags & PaymentFlag.UNPAID:
            menu.addAction(_("Pay Now"), partial(self._pay_invoice, row))
        menu.addAction(_("Delete"), lambda: self._delete_invoice(invoice_id))
        menu.exec_(self.viewport().mapToGlobal(position))

    def _show_invoice_window(self, row: InvoiceRow) -> None:
        self._main_window.show_invoice(self._send_view._account, row)

    def _pay_invoice(self, row: InvoiceRow) -> None:
        pr = PaymentRequest.from_json(row.invoice_data)
        pr.set_id(row.invoice_id)

        self._send_view.pay_for_payment_request(pr)

    def _delete_invoice(self, invoice_id: int) -> None:
        if not self._main_window.question(_('Delete invoice?')):
            return

        def callback(exc_value: Optional[Exception]=None) -> None:
            nonlocal invoice_id
            if exc_value is not None:
                raise exc_value # pylint: disable=raising-bad-type
            self._send_view.payment_request_deleted_signal.emit(invoice_id)

        self._send_view._account.invoices.delete_invoice(invoice_id, callback)
