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
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QHeaderView, QTreeWidgetItem, QFileDialog, QMenu, QWidget

from electrumsv.constants import PaymentState
from electrumsv.i18n import _
from electrumsv.platform import platform
from electrumsv.exceptions import FileImportFailed
from electrumsv.util import format_time
from electrumsv.wallet import AbstractAccount

from .main_window import ElectrumWindow
from .util import MyTreeWidget, pr_icons, pr_tooltips, read_QIcon


class InvoiceList(MyTreeWidget):
    filter_columns = [0, 1, 2, 3]  # Date, Requestor, Description, Amount

    def __init__(self, parent: QWidget, main_window: ElectrumWindow) -> None:
        MyTreeWidget.__init__(self, parent, main_window, self.create_menu, [
            _('Expires'), _('Requestor'), _('Description'), _('Amount'), _('Status')], 2)

        self._main_window = main_window
        self._account_id: Optional[int] = None
        self._account: AbstractAccount = None

        self._main_window.account_change_signal.connect(self._on_account_change)

        self.monospace_font = QFont(platform.monospace_font)
        self.setSortingEnabled(True)
        self.header().setSectionResizeMode(1, QHeaderView.Interactive)
        self.setColumnWidth(1, 200)

    def _on_account_change(self, new_account_id: int) -> None:
        self.clear()
        old_account_id = self._account_id
        self._account_id = new_account_id
        self._account = self._main_window._wallet.get_account(self._account_id)

    def on_update(self) -> None:
        if self._account_id is None:
            return

        invoices = self._account.invoices
        inv_list = invoices.unpaid_invoices()
        self.clear()
        for pr in inv_list:
            key = pr.get_id()
            status = invoices.get_status(key)
            requestor = pr.get_requestor()
            exp = pr.get_expiration_date()
            date_str = format_time(exp, _("Unknown")) if exp else _('Never')
            item = QTreeWidgetItem([date_str, requestor, pr.memo,
                self._main_window.format_amount(pr.get_amount(), whitespaces=True),
                pr_tooltips.get(status,'')])
            item.setIcon(4, read_QIcon(pr_icons.get(status)))
            item.setData(0, Qt.UserRole, (self._account_id, key))
            item.setFont(1, self.monospace_font)
            item.setFont(3, self.monospace_font)
            self.addTopLevelItem(item)
        self.setCurrentItem(self.topLevelItem(0))
        self.setVisible(len(inv_list))
        self._main_window.invoices_label.setVisible(len(inv_list))

    def import_invoices(self):
        wallet_folder = self._main_window.get_wallet_folder()
        filename, __ = QFileDialog.getOpenFileName(self._main_window, "Select your wallet file",
            wallet_folder)
        if not filename:
            return
        try:
            self._main_window._account.invoices.import_file(filename)
        except FileImportFailed as e:
            self._main_window.show_message(str(e))
        self.on_update()

    def create_menu(self, position):
        menu = QMenu()
        item = self.itemAt(position)
        if not item:
            return
        wallet_id, key = item.data(0, Qt.UserRole)
        # TODO: ACCOUNTS: Consider if send wallet is correct, or if we should look to the
        # wallet for the wallet id.
        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()
        pr = self._main_window._account.invoices.get(key)
        status = self._main_window._account.invoices.get_status(key)
        if column_data:
            menu.addAction(_("Copy {}").format(column_title),
                           lambda: self._main_window.app.clipboard().setText(column_data))
        menu.addAction(_("Details"), lambda: self._main_window.show_invoice(key))
        if status == PaymentState.UNPAID:
            menu.addAction(_("Pay Now"), lambda: self._main_window.do_pay_invoice(key))
        menu.addAction(_("Delete"), lambda: self._main_window.delete_invoice(key))
        menu.exec_(self.viewport().mapToGlobal(position))
