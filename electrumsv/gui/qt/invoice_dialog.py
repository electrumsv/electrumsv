from typing import Callable, cast, TYPE_CHECKING
import weakref

from bitcoinx import classify_output_script, Script

from PyQt6.QtCore import Qt, QAbstractItemModel, QPoint
from PyQt6.QtWidgets import QAbstractItemView, QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, \
    QVBoxLayout

from electrumsv.app_state import app_state
from electrumsv.constants import PaymentFlag
from electrumsv.i18n import _
from electrumsv.networks import Net
from electrumsv.dpp_messages import has_expired, PaymentTerms
from electrumsv.transaction import script_to_display_text
from electrumsv.util import format_posix_timestamp
from electrumsv.wallet_database.types import InvoiceRow

from .constants import pr_tooltips
from .util import (Buttons, ButtonsTableWidget, CloseButton, EnterButton, FormSectionWidget,
    get_source_index, WindowModalDialog)

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class InvoiceDialog(WindowModalDialog):
    _table_column_names = [ _("Amount"), _("Memo"), _("Destination") ]

    def __init__(self, main_window: 'ElectrumWindow', row: InvoiceRow) -> None:
        super().__init__(main_window, _("Invoice"))

        self.setMinimumWidth(400)

        self._main_window = weakref.proxy(main_window)

        self._pr = pr = PaymentTerms.from_json(row.invoice_data)

        state = row.flags & PaymentFlag.MASK_STATE
        # `EXPIRED` is never stored and solely used for extra visual state.
        if state == PaymentFlag.STATE_UNPAID and has_expired(row.date_expires):
            state = PaymentFlag.STATE_EXPIRED

        total_amount = 0
        for output in pr.outputs:
            assert output.amount is not None and output.amount >= 0
            total_amount += output.amount

        vbox = QVBoxLayout(self)
        form = FormSectionWidget()
        form.add_row(_('Type'), QLabel(_("BIP270")))
        form.add_row(_("State"), QLabel(pr_tooltips.get(state, _("Unknown"))))
        form.add_row(_('Amount'),
            QLabel(app_state.format_amount(total_amount) +" "+ app_state.base_unit()))
        form.add_row(_('Memo'), QLabel(row.description))
        form.add_row(_('Date Created'),
            QLabel(format_posix_timestamp(pr.creation_timestamp, _("Unknown"))))
        form.add_row(_('Date Received'),
            QLabel(format_posix_timestamp(row.date_created, _("Unknown"))))
        if row.date_expires:
            form.add_row(_('Date Expires'),
                QLabel(format_posix_timestamp(row.date_expires, _("Unknown"))))
        vbox.addWidget(form)

        self._table = table = ButtonsTableWidget()
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        vh = table.verticalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        vh.hide()

        table.setColumnCount(3)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self._on_table_menu)
        table.setHorizontalHeaderLabels(self._table_column_names)
        table.setRowCount(len(pr.outputs))
        # table.addButton("icons8-copy-to-clipboard-32.png", f,
        #     _("Copy all listed destinations to the clipboard"))
        # table.addButton("icons8-save-as-32-windows.png", f,
        #     _("Save the listed destinations to a file"))
        hh = table.horizontalHeader()
        hh.setStretchLastSection(True)

        for output_idx, output in enumerate(pr.outputs):
            label = QLabel(app_state.format_amount(output.amount) +" "+ app_state.base_unit())
            table.setCellWidget(output_idx, 0, label)

            table.setCellWidget(output_idx, 1, QLabel(output.description))

            script = Script(output.script_bytes)
            kind = classify_output_script(script, Net.COIN)
            text = script_to_display_text(script, kind)
            table.setCellWidget(output_idx, 2, QLabel(text))

            vbox.addWidget(table, 1)

        def do_export() -> None:
            fn = self._main_window.getSaveFileName(_("Export invoice to file"), "*.bip270.json")
            if not fn:
                return
            with open(fn, 'wb') as f:
                data = f.write(row.invoice_data)
            self._main_window.show_message(_('Invoice saved as' + ' ' + fn))
        exportButton = EnterButton(_('Export'), do_export)

        def do_delete() -> None:
            if self.question(_('Are you sure you want to delete this invoice?'),
                    title=_("Delete invoice"), icon=QMessageBox.Icon.Warning):
                self._main_window.delete_invoice(row.invoice_id)
                self.close()

        deleteButton = EnterButton(_('Delete'), do_delete)

        vbox.addLayout(Buttons(exportButton, deleteButton, CloseButton(self)))

    def _on_table_menu(self, position: QPoint) -> None:
        menu = QMenu()

        # What the user clicked on.
        menu_index = self._table.indexAt(position)
        menu_source_index = get_source_index(menu_index, QAbstractItemModel)

        if menu_source_index.row() != -1:
            menu_column = menu_source_index.column()
            item = cast(QLineEdit, self._table.cellWidget(menu_source_index.row(), menu_column))
            column_title = self._table_column_names[menu_column]
            copy_text = item.text().strip()
            menu.addAction(_("Copy {}").format(column_title),
                cast(Callable[[], None],
                    lambda: self._main_window.app.clipboard().setText(copy_text)))

        menu.exec(self._table.viewport().mapToGlobal(position))
