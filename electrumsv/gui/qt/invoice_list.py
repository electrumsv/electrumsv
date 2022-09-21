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

import concurrent.futures
from functools import partial
import math
import time
from typing import cast, TYPE_CHECKING, Optional
import urllib.parse
import weakref

from PyQt6.QtCore import Qt, QPoint, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QHeaderView, QTreeWidgetItem, QMenu

from electrumsv.app_state import app_state
from electrumsv.constants import PaymentFlag
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.dpp_messages import PaymentTerms
from electrumsv.platform import platform
from electrumsv.util import format_posix_timestamp, get_posix_timestamp
from electrumsv.wallet_database.types import InvoiceRow

from .constants import pr_icons, pr_tooltips
from .util import MyTreeWidget, read_QIcon

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .send_view import SendView


logger = logs.get_logger("invoice-list")


COL_RECEIVED = 0
COL_EXPIRES = 1
COL_REQUESTOR = 2
COL_DESCRIPTION = 3
COL_AMOUNT = 4
COL_STATUS = 5


class InvoiceList(MyTreeWidget):
    filter_columns = [COL_RECEIVED, COL_EXPIRES, COL_REQUESTOR, COL_DESCRIPTION, COL_AMOUNT]

    def __init__(self, parent: 'SendView', main_window: 'ElectrumWindow') -> None:
        MyTreeWidget.__init__(self, parent, main_window, self.create_menu, [
            _('Received'), _('Expires'), _('Requestor'), _('Description'), _('Amount'),
            _('Status')], COL_DESCRIPTION)

        self._send_view = parent
        self._main_window = weakref.proxy(main_window)

        self._monospace_font = QFont(platform.monospace_font)
        self.setSortingEnabled(True)
        self.header().setSectionResizeMode(COL_REQUESTOR, QHeaderView.ResizeMode.Interactive)
        self.setColumnWidth(COL_REQUESTOR, 200)

        # This is used if there is a pending expiry.
        self._timer: Optional[QTimer] = None

    def _start_timer(self, event_time: float) -> None:
        seconds = math.ceil(event_time - time.time())
        assert seconds > 0, f"got invalid timer duration {seconds}"
        # logger.debug("start_timer for %d seconds", seconds)
        interval = seconds * 1000

        assert self._timer is None, "timer already active"
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._on_timer_event)
        self._timer.start(interval)

    def _stop_timer(self) -> None:
        if self._timer is None:
            return
        # logger.debug("_stop_timer")
        self._timer.stop()
        self._timer = None

    def _on_timer_event(self) -> None:
        self._stop_timer()
        self.update()

    def on_update(self) -> None:
        if self._send_view._account_id is None:
            return

        self._stop_timer()

        current_id = None
        current_item: Optional[QTreeWidgetItem] = None
        if self._send_view._payment_request is not None:
            current_id = self._send_view._payment_request.get_id()
        if current_id is None:
            current_item = self.currentItem()
            current_id = current_item.data(COL_RECEIVED, Qt.ItemDataRole.UserRole) \
                if current_item else None

        self.clear()

        current_item = None
        current_time = get_posix_timestamp()
        nearest_expiry_time = float("inf")

        # TODO Ability to change the invoice list to specify what invoices are shown.
        #   This would for instance allow viewing of archived invoices.
        assert self._send_view._account is not None
        wallet = self._send_view._account.get_wallet()
        invoice_rows = wallet.data.read_invoices_for_account(self._send_view._account.get_id(),
            PaymentFlag.NONE, PaymentFlag.ARCHIVED)

        for row in invoice_rows:
            flags = row.flags & PaymentFlag.MASK_STATE
            if flags & PaymentFlag.UNPAID and row.date_expires:
                if row.date_expires <= current_time + 5:
                    flags = (row.flags & ~PaymentFlag.UNPAID) | PaymentFlag.EXPIRED
                else:
                    nearest_expiry_time = min(nearest_expiry_time, row.date_expires)

            requestor_uri = urllib.parse.urlparse(row.payment_uri)
            requestor_text = requestor_uri.netloc
            received_text = format_posix_timestamp(row.date_created, _("Unknown"))
            expires_text = format_posix_timestamp(row.date_expires, _("Unknown")) \
                if row.date_expires else _('Never')
            description = row.description if row.description is not None else ""
            item = QTreeWidgetItem([received_text, expires_text, requestor_text, description,
                app_state.format_amount(row.value, whitespaces=True),
                # The tooltip text should be None to ensure the icon does not have extra RHS space.
                pr_tooltips.get(flags, "")])
            icon_entry = pr_icons.get(flags)
            if icon_entry:
                item.setIcon(COL_STATUS, read_QIcon(icon_entry))
            if row.invoice_id == current_id:
                current_item = item
            item.setData(COL_RECEIVED, Qt.ItemDataRole.UserRole, row.invoice_id)
            item.setFont(COL_DESCRIPTION, self._monospace_font)
            item.setFont(COL_AMOUNT, self._monospace_font)
            self.addTopLevelItem(item)

        if current_item is not None:
            self.setCurrentItem(current_item)

        if nearest_expiry_time != float("inf"):
            self._start_timer(nearest_expiry_time)

    def on_edited(self, item: QTreeWidgetItem, column: int, prior: str) -> None:
        '''Called only when the text actually changes'''
        assert self._send_view._account is not None

        text: Optional[str] = item.text(column).strip()
        if text == "":
            text = None
        invoice_id = cast(int, item.data(COL_RECEIVED, Qt.ItemDataRole.UserRole))
        future = self._send_view._account._wallet.data.update_invoice_descriptions(
            [ (text, invoice_id) ])
        future.result()

    # TODO(invoice-import) What format are these imported files? No idea.
    #   This imported some json files directly into an invoice store.
    #   https://github.com/electrumsv/electrumsv/blob/sv-1.2.5/electrumsv/paymentrequest.py#L523
    # def import_invoices(self, account: AbstractAccount) -> None:
    #     try:
    #         wallet_folder = self.config.get_preferred_wallet_dirpath()
    #     except FileNotFoundError as e:
    #         self._main_window.show_error(str(e))
    #         return

    #     filename, __ = QFileDialog.getOpenFileName(self._main_window.reference(),
    #         _("Select your wallet file"), wallet_folder)
    #     if not filename:
    #         return

    #     try:
    #         account.invoices.import_file(filename)
    #     except FileImportFailed as e:
    #         self._main_window.show_message(str(e))
    #     self.on_update()

    def create_menu(self, position: QPoint) -> None:
        assert self._send_view._account is not None

        menu = QMenu()
        item = self.itemAt(position)
        if not item:
            return
        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()

        invoice_id: int = item.data(COL_RECEIVED, Qt.ItemDataRole.UserRole)
        row = self._send_view._account._wallet.data.read_invoice(invoice_id=invoice_id)
        assert row is not None, f"invoice {invoice_id} not found"

        flags = row.flags & PaymentFlag.MASK_STATE
        if flags & PaymentFlag.UNPAID and row.date_expires:
            if row.date_expires <= get_posix_timestamp() + 4:
                flags = (row.flags & ~PaymentFlag.UNPAID) | PaymentFlag.EXPIRED

        if column_data:
            menu.addAction(_("Copy {}").format(column_title),
                lambda: self._main_window.app.clipboard().setText(column_data))
        menu.addAction(_("Details"), partial(self._show_invoice_window, row))
        if flags & PaymentFlag.UNPAID:
            menu.addAction(_("Pay Now"), partial(self.pay_invoice, row.invoice_id))
        menu.addAction(_("Delete"), lambda: self._delete_invoice(invoice_id))
        menu.exec(self.viewport().mapToGlobal(position))

    def _show_invoice_window(self, row: InvoiceRow) -> None:
        assert self._send_view._account is not None
        self._main_window.show_invoice(self._send_view._account, row)

    def pay_invoice(self, invoice_id: int) -> None:
        assert self._send_view._account is not None
        row = self._send_view._account._wallet.data.read_invoice(invoice_id=invoice_id)
        if row is None:
            return

        pr = PaymentTerms.from_json(row.invoice_data)
        if pr.has_expired():
            self._main_window.show_error(_("This invoice cannot be paid as it has expired."))
            return

        self._main_window.show_send_tab()
        pr.set_id(row.invoice_id)
        self._send_view.pay_for_payment_request(pr)

    def _delete_invoice(self, invoice_id: int) -> None:
        assert self._send_view._account is not None

        if not self._main_window.question(_('Delete invoice?')):
            return

        def callback(future: concurrent.futures.Future[None]) -> None:
            nonlocal invoice_id
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()

            # NOTE This callback will be happening in the database thread. No UI calls should
            #   be made, unless we emit a signal to do it.
            self._send_view.payment_request_deleted_signal.emit(invoice_id)

        future = self._send_view._account._wallet.data.delete_invoices([ invoice_id ])
        future.add_done_callback(callback)
