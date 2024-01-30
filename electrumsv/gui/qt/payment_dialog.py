# TODO This needs to do the multi-tx payment dialog.
# - The code should support it at a basic level.
# - The GUI should display as if it were formally supported.
# - We can assert that it should not work yet.

from __future__ import annotations
import dataclasses
from typing import cast, TYPE_CHECKING
import weakref

from bitcoinx import hash_to_hex_str

from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtWidgets import QDialog, QGridLayout, QLabel, QMenu, QPlainTextEdit, QPushButton, \
    QTabWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from ...app_state import app_state
from ...constants import CHANGE_SUBPATH, RECEIVING_SUBPATH, TxFlag
from ...i18n import _
from ...transaction import Transaction, TxContext
from ...wallet_database.types import AccountHistoryOutputRow, InvoiceRow, PaymentRow, \
    PaymentRequestOutputRow, PaymentRequestRow, TransactionRow

from .constants import ViewPaymentMode
from .util import Buttons, CloseButton, MessageBoxMixin, MyTreeWidget, read_QIcon

if TYPE_CHECKING:
    from ...wallet import WalletDataAccess
    from .main_window import ElectrumWindow


@dataclasses.dataclass
class SharedState:
    main_window: ElectrumWindow
    dax: WalletDataAccess

    mode: ViewPaymentMode
    account_ids: list[int]
    payment_id: int|None
    txs: list[Transaction]|None
    tx_ctxs: list[TxContext]|None

    history_outputs: list[AccountHistoryOutputRow] = dataclasses.field(default_factory=list)
    invoice_row: InvoiceRow|None = dataclasses.field(default=None)
    payment_row: PaymentRow|None = dataclasses.field(default=None)
    request_row: PaymentRequestRow|None = dataclasses.field(default=None)
    request_output_rows: list[PaymentRequestOutputRow] = dataclasses.field(default_factory=list)
    tx_rows: list[TransactionRow] = dataclasses.field(default_factory=list)
    account_names: dict[int, str] = dataclasses.field(default_factory=dict)
    tx_summaries: list[TxSummary] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class TxSummary:
    tx_hash: bytes
    external_funding: bool = dataclasses.field(default=False)
    internal_funding: bool = dataclasses.field(default=False)
    external_payment: bool = dataclasses.field(default=False)
    internal_payment: bool = dataclasses.field(default=False)
    missing_external_parents: bool = dataclasses.field(default=False)
    spent_value: int = dataclasses.field(default=0)
    externally_spent_value: int = dataclasses.field(default=0)
    received_value: int = dataclasses.field(default=0)
    externally_received_value: int = dataclasses.field(default=0)
    fee_value: int|None = dataclasses.field(default=None)


def get_txs_summary(state: SharedState) -> list[TxSummary]:
    summaries: list[TxSummary] = []
    if state.txs is None: return summaries
    for tx in state.txs:
        tx_hash = tx.hash()
        summary = TxSummary(tx_hash)
        for txi in tx.inputs:
            if txi.x_pubkeys:
                summary.internal_funding = True
                assert txi.value is not None
                summary.spent_value += txi.value
            else:
                summary.external_funding = True
                if txi.value is None:   summary.missing_external_parents = True
                else:                   summary.externally_spent_value += txi.value
        for txo in tx.outputs:
            if len(txo.x_pubkeys) == 0:
                summary.external_payment = True
                summary.externally_received_value += txo.value
            elif len(txo.x_pubkeys) == 1:
                k = next(iter(txo.x_pubkeys))
                if txo.x_pubkeys[k].derivation_path[:1] == CHANGE_SUBPATH:
                    assert summary.spent_value > 0
                    summary.spent_value -= txo.value
                elif txo.x_pubkeys[k].derivation_path[:1] == RECEIVING_SUBPATH:
                    summary.internal_payment = True
                    summary.received_value += txo.value
                else: raise NotImplementedError
            else: raise NotImplementedError
        if not summary.missing_external_parents:
            summary.fee_value = (summary.spent_value + summary.externally_spent_value) - \
                (summary.externally_received_value + summary.received_value)
        summaries.append(summary)
    return summaries


def refresh_state(state: SharedState) -> None:
    if state.payment_id:
        state.payment_row = state.dax.read_payment(state.payment_id)
        state.invoice_row = state.dax.read_invoice(payment_id=state.payment_id)
        state.request_row, state.request_output_rows = state.dax.read_payment_request(
            payment_id=state.payment_id)

        # These will be (should be) empty for other than FROM_HISTORY (given draftness).
        state.account_ids = state.dax.read_payment_account_ids(state.payment_id)
        state.tx_rows = state.dax.read_transactions(payment_id=state.payment_id)
        if state.account_ids:
            # TODO(technical-debt) Payments. Longer term goal is handling multi-account.
            assert len(state.account_ids) == 1, state.account_ids
            state.history_outputs = state.dax.read_history_for_outputs(state.account_ids[0],
                payment_id=state.payment_id)

        if state.mode == ViewPaymentMode.FROM_HISTORY:
            assert state.txs is None and state.tx_ctxs is None
        else:
            assert state.txs and state.tx_ctxs and len(state.txs) == len(state.tx_ctxs)
    else:
        assert state.txs and state.tx_ctxs and len(state.txs) == len(state.tx_ctxs)

    state.tx_summaries = get_txs_summary(state)
    state.account_names = { acc_row.account_id:acc_row.account_name
        for acc_row in state.dax.read_accounts() if acc_row.account_id in state.account_ids }


class PaymentDialog(QDialog, MessageBoxMixin):
    _invoice_row: InvoiceRow|None = None
    _pr_row: PaymentRequestRow|None = None
    _pr_output_rows: list[PaymentRequestOutputRow]|None = None

    def __init__(self, mode: ViewPaymentMode, payment_id: int|None, txs: list[Transaction]|None,
            tx_ctxs: list[TxContext]|None, account_id: int|None, main_window: ElectrumWindow) \
                -> None:
        # We want to be a top-level window
        QDialog.__init__(self, parent=None, flags=Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint))

        # These are the ones we accept indicating intent from the caller.
        assert mode in { ViewPaymentMode.UNSIGNED, ViewPaymentMode.PARTIALLY_SIGNED,
            ViewPaymentMode.FROM_HISTORY }

        self._mode = mode
        self._wallet = main_window._wallet

        dax = self._wallet.data
        self._state = SharedState(cast("ElectrumWindow", weakref.proxy(main_window)), dax, mode,
            [account_id] if account_id else [], payment_id, txs, tx_ctxs)
        refresh_state(self._state)

        self._overview_widget = OverviewWidget(self._state)
        self._txs_widget = TransactionsWidget(self._state)

        self._tab_widget = QTabWidget()
        self._tab_widget.addTab(self._overview_widget, read_QIcon("tab_history.png"), _("Overview"))
        self._tab_widget.addTab(self._txs_widget, read_QIcon("tab_history.png"), _("Transactions"))

        self._delete_button = QPushButton(_("Delete"))
        self._send_button = QPushButton(_("Send"))
        self._sign_button = QPushButton(_("Sign"))

        right_buttons = [ self._sign_button, self._send_button, CloseButton(self) ]

        layout = QVBoxLayout()
        layout.addWidget(self._tab_widget)
        buttons = Buttons(*right_buttons)
        buttons.add_left_button(self._delete_button)
        self._buttons = buttons
        layout.addLayout(self._buttons)
        self.setLayout(layout)

        self.update_dialog()

    def update_dialog(self) -> None:
        # Update the display of the dialog to reflect the current state.
        refresh_state(self._state)

        if self._state.payment_id:
            if self._state.invoice_row:
                self.setWindowTitle(_("Outgoing invoiced payment"))
            elif self._state.request_row:
                self.setWindowTitle(_("Incoming requested payment"))
            else:
                # TODO(1.4.0) Payments. Add flag for restored payments and know source of payment.
                self.setWindowTitle(_("Restored payment"))
        else:
            self.setWindowTitle(_("Draft payment"))

        tx_are_complete = not self._state.txs or all(tx.is_complete() for tx in self._state.txs)
        some_are_local = self._state.tx_rows is not None and \
            all(tx_row.flags & TxFlag.MASK_STATE_LOCAL for tx_row in self._state.tx_rows)
        # TODO(1.4.0) Payments. This should only be enabled for local transactions and make the
        #     user confirm that they have not shared the payment or given any of the transactions
        #     to anyone else. At least that's the most useful case to support.
        delete_enabled = False
        send_enabled = not tx_are_complete or some_are_local
        sign_enabled = not tx_are_complete

        if delete_enabled:
            delete_tooltip = \
                _("Delete this payment and all related records and transactions from the wallet.\n"
                "This will reiterate the consequences to you and require you confirm the deletion\n"
                "before proceeding.")
        else:
            delete_tooltip = \
                _("This payment is not one that can be deleted from the wallet at this time.")

        if send_enabled:
            send_tooltip = \
                _("This payment has not been delivered to the recipient. Clicking on this button\n"
                "will attempt to delivery it. If this is for an invoice, the entire payment\n"
                "message will be sent directly. If this is a legacy payment, the transactions\n"
                "will be broadcast to the blockchain.")
        else:
            send_tooltip = \
                _("This payment has either already been delivered or is not fully signed. If\n"
                "additional signatures are required and can be provided by this wallet the\n"
                "'Send' button should be enabled.")

        if sign_enabled:
            sign_tooltip = \
                _("One or more of the transactions in this payment are unsigned and can be\n"
                "signed by one of the accounts in this wallet. If you click this button you\n"
                "will be asked for your password and it will be used to sign them.")
        else:
            sign_tooltip = _("This payment is already fully signed.")

        self._delete_button.setEnabled(delete_enabled)
        self._delete_button.setToolTip(delete_tooltip)
        self._send_button.setEnabled(send_enabled)
        self._send_button.setToolTip(send_tooltip)
        self._sign_button.setEnabled(sign_enabled)
        self._sign_button.setToolTip(sign_tooltip)

        self._overview_widget.refresh_contents()
        self._txs_widget.refresh_contents()


class OverviewWidget(QWidget):
    def __init__(self, state: SharedState) -> None:
        super().__init__()

        self._state = state

        layout = QGridLayout()
        # Left top column.
        account_label = QLabel(_("Account:"))
        account_widget = QLabel(state.account_names[state.account_ids[0]])
        from_label = QLabel(_("From:"))
        from_widget = QLabel("-")
        to_label = QLabel(_("To:"))
        to_widget = QLabel("-")
        layout.addWidget(account_label, 0, 0, 1, 1)
        layout.addWidget(account_widget, 0, 1, 1, 1)
        layout.addWidget(from_label, 1, 0, 1, 1)
        layout.addWidget(from_widget, 1, 1, 1, 1)
        layout.addWidget(to_label, 2, 0, 1, 1)
        layout.addWidget(to_widget, 2, 1, 1, 1)
        # Right top column.
        id_key_label = QLabel(_("ID:"))
        id_value_label = QLabel(str(state.payment_id))
        amount_label = QLabel(_("Amount:"))
        self._amount_widget = QLabel()
        fee_label = QLabel(_("Fee:"))
        self._fee_widget = QLabel()
        layout.addWidget(id_key_label, 0, 2, 1, 1)
        layout.addWidget(id_value_label, 0, 3, 1, 1)
        layout.addWidget(amount_label, 1, 2, 1, 1)
        layout.addWidget(self._amount_widget, 1, 3, 1, 1)
        layout.addWidget(fee_label, 2, 2, 1, 1)
        layout.addWidget(self._fee_widget, 2, 3, 1, 1)
        # Row for details from other party.
        their_note_label = QLabel("Their note:")
        self._their_note_widget = QPlainTextEdit()
        layout.addWidget(their_note_label, 4, 0, 1, 4)
        layout.addWidget(self._their_note_widget, 5, 0, 1, 4) # Alignment breaks widget stretch.
        layout.setRowStretch(5, True)
        # Row for details from wallet owner.
        our_note_label = QLabel("Your note:")
        self._our_note_widget = QPlainTextEdit()
        layout.addWidget(our_note_label, 6, 0, 1, 4)
        layout.addWidget(self._our_note_widget, 7, 0, 1, 4) # Alignment breaks widget stretch.
        layout.setRowStretch(7, True)
        # TODO Detail: Date sent?
        # TODO Detail: Date created?
        self.setLayout(layout)

    def refresh_contents(self) -> None:
        if all(summary.fee_value is not None for summary in self._state.tx_summaries):
            fee_value = sum(cast(int, summary.fee_value) for summary in self._state.tx_summaries)
            self._fee_widget.setText(app_state.format_amount(fee_value, True, whitespaces=True))
        else:
            self._fee_widget.setText("?")

        their_text = ""
        if self._state.request_row:
            placeholder_text = _("You did not describe for the other party what this payment "
                "is for.")
            if self._state.request_row.merchant_reference:
                their_text = self._state.request_row.merchant_reference
        elif self._state.invoice_row: # TODO Correct?
            placeholder_text = _("The other party did not describe what this payment is for.")
            if self._state.invoice_row.description:
                their_text = self._state.invoice_row.description
        elif self._state.payment_id:
            placeholder_text = _("This payment was restored and this means we cannot work out "
                "what if anything might have been here.")
        else:
            placeholder_text = _("This payment is a legacy payment. It will be delivered to the "
                "payee indirectly through the blockchain and does not have any way to attach "
                "a note for them.")
        self._their_note_widget.setReadOnly(True)
        self._their_note_widget.setPlaceholderText(placeholder_text)
        if their_text:
            self._their_note_widget.setPlainText(their_text)

        self._our_note_widget.setPlaceholderText(
            _("Write the description you want to see for this payment here.."))
        our_text = ""
        if self._state.request_row and self._state.request_row.description:
            our_text = self._state.request_row.description
        self._our_note_widget.setPlainText(our_text)


class TransactionsWidget(QWidget):
    def __init__(self, state: SharedState) -> None:
        super().__init__()

        self._state = state

        layout = QVBoxLayout()

        self._tx_list_label = QLabel()
        self._tx_list = MyTreeWidget(self, state.main_window.reference(), self._on_tx_menu_event,
            [ _("Short TxID"), _("Size/KiB"), _("From"), _("To"), _("Parents"), _("Fee"),
                _("Spent"), _("Recvd"), _("Spent (ext)"), _("Recvd (ext)") ])
        self._tx_list.setUniformRowHeights(True)
        layout.addWidget(self._tx_list_label,
            alignment=Qt.AlignmentFlag.AlignTop|Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._tx_list, stretch=1)

        self._dc_label = QLabel()
        self._dc_list = MyTreeWidget(self, state.main_window.reference(), self._on_dc_menu_event,
            [ _('Short TxID'), _("Vout"), _("Amount") ])
        self._dc_list.setUniformRowHeights(True)
        layout.addWidget(self._dc_label,
            alignment=Qt.AlignmentFlag.AlignTop|Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._dc_list, stretch=1)

        self.setLayout(layout)

    def refresh_contents(self) -> None:
        self._redraw_tx_list()
        self._redraw_dc_list()

    def _redraw_tx_list(self) -> None:
        self._tx_list.clear()

        if self._state.mode == ViewPaymentMode.FROM_HISTORY:
            self._tx_list_label.setText(_("Payment transactions (database):"))

            for tx_row in self._state.tx_rows:
                item = QTreeWidgetItem([ hash_to_hex_str(tx_row.tx_hash)[:8],
                    str(len(cast(bytes, tx_row.tx_bytes)) / 1000.) ])
                item.setTextAlignment(0, Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                self._tx_list.addTopLevelItem(item)
        else:
            self._tx_list_label.setText(_("Payment transactions (draft):"))
            assert self._state.txs is not None

            source_texts = {(False,False):_("None"), (True,False):_("Internal"),
                (False,True):_("External"), (True,True):_("Co-funded")}
            target_texts = {(False,False):_("None"), (True,False):_("Internal"),
                (False,True):_("External"), (True,True):_("Co-paid")}
            for i, summary in enumerate(self._state.tx_summaries):
                tx = self._state.txs[i]
                tx_id = f"Draft[{i}]" if not tx.is_complete() else \
                    hash_to_hex_str(summary.tx_hash)[:8]
                tx_bytes = tx.to_bytes()
                item = QTreeWidgetItem([
                    tx_id,
                    str(len(tx_bytes) / 1000.),
                    source_texts[(summary.internal_funding, summary.external_funding)],
                    target_texts[(summary.internal_payment, summary.external_payment)],
                    _("Missing") if summary.missing_external_parents else _("Present"),
                    app_state.format_amount(summary.fee_value, False, whitespaces=True)
                        if summary.fee_value is not None else "?",
                    app_state.format_amount(summary.spent_value, False, whitespaces=True),
                    app_state.format_amount(summary.received_value, False, whitespaces=True),
                    app_state.format_amount(summary.externally_spent_value,False,whitespaces=True),
                    app_state.format_amount(summary.externally_received_value,False,
                        whitespaces=True),
                ])
                item.setTextAlignment(0, Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(2, Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(3, Qt.AlignmentFlag.AlignVCenter)
                # item.setTextAlignment(4,Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(5, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(6, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(7, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(8, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(9, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                self._tx_list.addTopLevelItem(item)

    def _redraw_dc_list(self) -> None:
        self._dc_list.clear()

        if self._state.mode == ViewPaymentMode.FROM_HISTORY:
            self._dc_label.setText(_("Spent and received (database):"))

            # for row in self._state.history_outputs:
            #     value_str = app_state.format_amount(row.value, True, whitespaces=True)
            #     item = QTreeWidgetItem([ hash_to_hex_str(row.tx_hash)[:8], str(row.txo_index),
            #         value_str ])
            #     item.setTextAlignment(0, Qt.AlignmentFlag.AlignVCenter)
            #     item.setTextAlignment(1,
            #       Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
            #     item.setTextAlignment(2, Qt.AlignmentFlag.AlignVCenter)
            #     self._dc_list.addTopLevelItem(item)
        else:
            self._dc_label.setText(_("Spent and received (draft):"))

            def add_item(tx_id: str, txo_index: int, value: int) -> None:
                value_str = app_state.format_amount(value, True, whitespaces=True)
                item = QTreeWidgetItem([ tx_id, str(txo_index), value_str ])
                item.setTextAlignment(0, Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(1, Qt.AlignmentFlag.AlignRight|Qt.AlignmentFlag.AlignVCenter)
                item.setTextAlignment(2, Qt.AlignmentFlag.AlignVCenter)
                self._dc_list.addTopLevelItem(item)


    def _on_tx_menu_event(self, position: QPoint) -> None:
        item = self._tx_list.itemAt(position)
        menu = QMenu()
        menu.addAction(_("NOP"), lambda: self._on_menu_nop(item))
        menu.exec(self._tx_list.viewport().mapToGlobal(position))

    def _on_dc_menu_event(self, position: QPoint) -> None:
        item = self._tx_list.itemAt(position)
        menu = QMenu()
        menu.addAction(_("NOP"), lambda: self._on_menu_nop(item))
        menu.exec(self._tx_list.viewport().mapToGlobal(position))

    def _on_menu_nop(self, item: QTreeWidgetItem) -> None:
        print("MENU nop", item)
