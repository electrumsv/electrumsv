import os
from typing import List

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QLabel, QSpinBox, QVBoxLayout, QWidget

from electrumsv.constants import RECEIVING_SUBPATH
from electrumsv.i18n import _
from electrumsv.wallet import Wallet

from .main_window import ElectrumWindow
from .util import (Buttons, ButtonsTableWidget, CloseButton, FormSectionWidget, HelpDialogButton,
    MessageBox)


class PaymentDestinationsDialog(QDialog):
    def __init__(self, main_window: ElectrumWindow, wallet: Wallet, account_id: int,
            parent: QWidget) -> None:
        super().__init__(parent, Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)

        self._main_window = main_window
        self._wallet = wallet

        self._account = account = self._wallet.get_account(account_id)
        keystore = account.get_keystore()

        self.setWindowTitle(_("Payment Destinations"))
        self.setMinimumSize(400, 400)

        quantity_widget = QSpinBox()
        quantity_widget.setMinimum(1)
        quantity_widget.setMaximum(1000)
        quantity_widget.setValue(10)
        quantity_widget.valueChanged.connect(self._on_value_changed)

        vbox = QVBoxLayout()

        self._form = form = FormSectionWidget(minimum_label_width=80)
        form.add_title(_("Options"))
        form.add_row(_("How many"), quantity_widget)
        vbox.addWidget(form)

        self._table = table = ButtonsTableWidget()
        table.addButton("icons8-copy-to-clipboard-32.png", self._on_copy_button_click,
            _("Copy all listed destinations to the clipboard"))
        table.addButton("icons8-save-as-32-windows.png", self._on_save_as_button_click,
            _("Save the listed destinations to a file"))
        hh = table.horizontalHeader()
        hh.setStretchLastSection(True)
        vbox.addWidget(self._table, 1)

        buttons = Buttons(CloseButton(self))
        buttons.add_left_button(HelpDialogButton(self, "misc", "payment-destinations-dialog"))
        self._buttons = buttons

        vbox.addLayout(self._buttons)
        self.setLayout(vbox)

        self._entries: List[str] = []
        self._on_value_changed(quantity_widget.value())

    def _get_text(self) -> str:
        return os.linesep.join(self._entries)

    def _show_warning(self, prefix: str) -> None:
        MessageBox.show_warning(prefix +" "+ _("Note that "
            "this does not reserve the destinations, and that until the wallet includes "
            "transactions that use them, they might be used for other purposes."))

    def _on_copy_button_click(self) -> None:
        self._main_window.app.clipboard().setText(self._get_text())
        self._show_warning(_("The destinations have been copied to the clipboard."))

    def _on_save_as_button_click(self) -> None:
        name = "payment-destinations.txt"
        filepath = self._main_window.getSaveFileName(
            _("Select where to save your destination list"), name, "*.txt")
        if filepath:
            with open(filepath, "w") as f:
                f.write(self._get_text())
        self._show_warning(_("The destinations have been written to the file."))

    def _on_value_changed(self, new_value: int) -> None:
        keyinstances = self._account.get_fresh_keys(RECEIVING_SUBPATH, new_value)
        self._table.clear()
        self._table.setColumnCount(1)
        self._table.setHorizontalHeaderLabels([ _("Destination") ])
        self._table.setRowCount(new_value)
        self._entries = [ "" ] * new_value
        for row, keyinstance in enumerate(keyinstances):
            text = self._account.get_script_template_for_id(keyinstance.keyinstance_id).to_string()
            self._entries[row] = text
            label = QLabel(text)
            self._table.setCellWidget(row, 0, label)
