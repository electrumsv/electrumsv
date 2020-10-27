from typing import TYPE_CHECKING
import weakref

from bitcoinx import classify_output_script

from PyQt5.QtCore import Qt, QAbstractItemModel
from PyQt5.QtWidgets import QAbstractItemView, QHeaderView, QLabel, QMenu, QVBoxLayout

from electrumsv.app_state import app_state
from electrumsv.constants import PaymentFlag
from electrumsv.i18n import _
from electrumsv.networks import Net
from electrumsv.paymentrequest import has_expired, PaymentRequest
from electrumsv.transaction import script_to_display_text
from electrumsv.util import format_time
from electrumsv.wallet_database.tables import InvoiceRow

from .constants import pr_tooltips
from .util import (Buttons, ButtonsTableWidget, CloseButton, EnterButton, FormSectionWidget,
    get_source_index, QMessageBox, WindowModalDialog)

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class InvoiceDialog(WindowModalDialog):
    _table_column_names = [ _("Amount"), _("Memo"), _("Destination") ]

    def __init__(self, main_window: 'ElectrumWindow', row: InvoiceRow) -> None:
        super().__init__(main_window, _("Invoice"))

        self.setMinimumWidth(400)

        self._main_window = weakref.proxy(main_window)

        self._pr = pr = PaymentRequest.from_json(row.invoice_data)

        state = row.flags & PaymentFlag.STATE_MASK
        if state & PaymentFlag.UNPAID and has_expired(row.date_expires):
            state = PaymentFlag.EXPIRED

        total_amount = 0
        for output in pr.outputs:
            total_amount += output.amount

        vbox = QVBoxLayout(self)
        form = FormSectionWidget(minimum_label_width=120)
        form.add_row(_('Type'), QLabel(_("BIP270")))
        form.add_row(_("State"), QLabel(pr_tooltips.get(state, _("Unknown"))))
        form.add_row(_('Amount'),
            QLabel(app_state.format_amount(output.amount) +" "+ app_state.base_unit()))
        form.add_row(_('Memo'), QLabel(row.description))
        form.add_row(_('Date Created'),
            QLabel(format_time(pr.creation_timestamp, _("Unknown"))))
        form.add_row(_('Date Received'),
            QLabel(format_time(row.date_created, _("Unknown"))))
        if row.date_expires:
            form.add_row(_('Date Expires'),
                QLabel(format_time(row.date_expires, _("Unknown"))))
        vbox.addWidget(form)

        self._table = table = ButtonsTableWidget()
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)

        vh = table.verticalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeToContents)
        vh.hide()

        table.setColumnCount(3)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self._on_table_menu)
        table.setHorizontalHeaderLabels(self._table_column_names)
        table.setRowCount(len(pr.outputs))
        # table.addButton("icons8-copy-to-clipboard-32.png", f,
        #     _("Copy all listed destinations to the clipboard"))
        # table.addButton("icons8-save-as-32-windows.png", f,
        #     _("Save the listed destinations to a file"))
        hh = table.horizontalHeader()
        hh.setStretchLastSection(True)

        for row, output in enumerate(pr.outputs):
            label = QLabel(app_state.format_amount(output.amount) +" "+ app_state.base_unit())
            table.setCellWidget(row, 0, label)

            table.setCellWidget(row, 1, QLabel(output.description))

            kind = classify_output_script(output.script, Net.COIN)
            text = script_to_display_text(output.script, kind)
            table.setCellWidget(row, 2, QLabel(text))

            vbox.addWidget(table, 1)

        def do_export():
            fn = self._main_window.getSaveFileName(_("Export invoice to file"), "*.bip270.json")
            if not fn:
                return
            with open(fn, 'w') as f:
                data = f.write(row.invoice_data)
            self._main_window.show_message(_('Invoice saved as' + ' ' + fn))
        exportButton = EnterButton(_('Export'), do_export)

        def do_delete():
            if self.question(_('Are you sure you want to delete this invoice?'),
                    title=_("Delete invoice"), icon=QMessageBox.Warning):
                self._main_window._send_view._invoice_list._delete_invoice(row.invoice_id)
                self.close()

        deleteButton = EnterButton(_('Delete'), do_delete)

        vbox.addLayout(Buttons(exportButton, deleteButton, CloseButton(self)))

    def _on_table_menu(self, position) -> None:
        menu = QMenu()

        # What the user clicked on.
        menu_index = self._table.indexAt(position)
        menu_source_index = get_source_index(menu_index, QAbstractItemModel)

        if menu_source_index.row() != -1:
            menu_column = menu_source_index.column()
            item = self._table.cellWidget(menu_source_index.row(), menu_column)
            column_title = self._table_column_names[menu_column]
            copy_text = item.text().strip()
            menu.addAction(_("Copy {}").format(column_title),
                lambda: self._main_window.app.clipboard().setText(copy_text))

        menu.exec_(self._table.viewport().mapToGlobal(position))
