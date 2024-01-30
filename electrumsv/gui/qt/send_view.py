from __future__ import annotations
import concurrent.futures
import random
import textwrap
import time
from typing import Any, cast, Iterable, Sequence, TYPE_CHECKING
import weakref

from bitcoinx import Address, classify_output_script, hash_to_hex_str, P2PKH_Address

from PyQt6.QtCore import pyqtSignal, QPoint, QStringListModel, Qt
from PyQt6.QtWidgets import (QCompleter, QGridLayout, QGroupBox, QHBoxLayout, QMenu,
    QLabel, QSizePolicy, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ...app_state import app_state
from ...bitcoin import ScriptTemplate
from ...constants import DEFAULT_FEE, MAX_VALUE, PaymentRequestFlag
from ...exceptions import ExcessiveFee, NotEnoughFunds
from ...i18n import _
from ...logs import logs
from ...dpp_messages import is_inv_expired, PaymentTermsMessage
from ...networks import Net
from ...transaction import Transaction, TxContext
from ...types import BroadcastResult, MAPIFeeContext, PaymentCtx
from ...util import format_satoshis_plain
from ...wallet import AbstractAccount
from ...wallet_database.types import InvoiceRow, UTXOProtocol

from .amountedit import AmountEdit, BTCAmountEdit, MyLineEdit
from .constants import ViewPaymentMode
from . import dialogs
from .invoice_list import InvoiceList
from .paytoedit import PayToEdit
from .table_widgets import TableTopButtonLayout
from .types import FrozenEditProtocol
from .util import (ColorScheme, EnterButton, HelpDialogButton, HelpLabel, MyTreeWidget,
    update_fixed_tree_height)


if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class SendView(QWidget):
    """
    We only show this for account types that can construct transactions. This is actually all
    account types except imported address accounts. Watch only wallets can construct transactions
    and in fact this is a valid workflow for multi-signature signing - where there is an online
    watch only wallet and offline signing wallets and the former hands off the constructed
    transaction to the latter and receives it back for dispatching to the recipient.
    """

    display_invoice_signal = pyqtSignal(object)
    import_and_display_invoice_signal = pyqtSignal()
    invoice_import_error_signal = pyqtSignal(object)
    invoice_deleted_signal = pyqtSignal(int)

    _payto_e: PayToEdit
    amount_e: BTCAmountEdit
    _fiat_send_e: AmountEdit
    _account: AbstractAccount
    _fee_quote_future: concurrent.futures.Future[list[MAPIFeeContext]] | None = None

    def __init__(self, main_window: ElectrumWindow, account_id: int) -> None:
        super().__init__(main_window)

        self._main_window = cast("ElectrumWindow", weakref.proxy(main_window))
        self._account_id = account_id
        self._account = cast(AbstractAccount, main_window._wallet.get_account(account_id))
        self._logger = logs.get_logger(f"send_view[{self._account_id}]")

        self._is_max = False
        self._not_enough_funds = False
        self._require_fee_update: float|None = None
        self._payment_id: int|None = None
        self._invoice: PaymentTermsMessage|None = None
        # If this is an invoice this will be the security address from the "pay:" URL.
        self._invoice_address: Address|None = None
        self._completions = QStringListModel()

        self.setLayout(self.create_send_layout())

        self.display_invoice_signal.connect(self._display_invoice)
        self.import_and_display_invoice_signal.connect(self._import_and_display_invoice)
        self.invoice_import_error_signal.connect(self._invoice_import_error)
        self.invoice_deleted_signal.connect(self._invoice_deleted)

        app_state.app_qt.fiat_ccy_changed.connect(self._on_fiat_ccy_changed)
        self._main_window.new_fx_quotes_signal.connect(self._on_ui_exchange_rate_quotes)
        self._main_window.keys_updated_signal.connect(self._on_keys_updated)
        self._main_window.payment_success_signal.connect(self._on_ui_payment_success)

    def clean_up(self) -> None:
        if self._fee_quote_future is not None:
            self._fee_quote_future.cancel()

        # Disconnect external signals.
        self._main_window.keys_updated_signal.disconnect(self._on_keys_updated)
        self._main_window.new_fx_quotes_signal.disconnect(self._on_ui_exchange_rate_quotes)
        app_state.app_qt.fiat_ccy_changed.disconnect(self._on_fiat_ccy_changed)

    def _on_fiat_ccy_changed(self) -> None:
        flag = bool(app_state.fx and app_state.fx.is_enabled())
        self._fiat_send_e.setVisible(flag)

    def _on_ui_exchange_rate_quotes(self) -> None:
        edit = self._fiat_send_e if self._fiat_send_e.is_last_edited else self.amount_e
        edit.textEdited.emit(edit.text())

    def _on_keys_updated(self, account_id: int, keyinstance_ids: list[int]) -> None:
        # Mostly this will re-select outputs, and for instance not select newly frozen
        # keys. However, if the user has spent from specific keys we assume they want to
        # spend those coins, and we do not reselect them.
        if account_id != self._account_id:
            return
        self.update_fee()

    def create_send_layout(self) -> QVBoxLayout:
        """ Re-render the layout and it's child widgets of this view. """
        assert self._account is not None
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self._send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        # This ensures all columns are stretched over the full width of the last tab.
        grid.setColumnStretch(4, 1)

        self._payto_e = PayToEdit(self)
        self.amount_e = BTCAmountEdit(self)

        # From fields row.
        # This is enabled by "spending" coins in the coins tab.

        self._from_label = QLabel(_('From'), self)
        self._from_label.setContentsMargins(0, 5, 0, 0)
        self._from_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        grid.addWidget(self._from_label, 1, 0)

        self._from_list = MyTreeWidget(self, self._main_window.reference(), self.from_list_menu,
            [ _('Outpoint / Key ID'), _('Amount') ])
        self._from_list.setMaximumHeight(80)
        grid.addWidget(self._from_list, 1, 1, 1, -1)
        self.set_pay_from([])

        msg = (_('Recipient of the funds.') + '\n\n' +
               _('You may enter a Bitcoin SV address, a label from your list of '
                 'contacts (a list of completions will be proposed), or an alias '
                 '(email-like address that forwards to a Bitcoin SV address)'))
        payto_label = HelpLabel(_('Pay to'), msg, self)
        payto_label.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        grid.addWidget(payto_label, 2, 0)
        grid.addWidget(self._payto_e, 2, 1, 1, -1)

        msg = (_('Amount to be sent.') + '\n\n' +
               _('The amount will be displayed in red if you do not have '
                 'enough funds in your wallet.') + ' '
               + _('Note that if you have frozen some of your coins, the available '
                   'funds will be lower than your total balance.') + '\n\n'
               + _('Keyboard shortcut: type "!" to send all your coins.'))
        amount_label = HelpLabel(_('Amount'), msg, self)
        grid.addWidget(amount_label, 3, 0)
        grid.addWidget(self.amount_e, 3, 1)

        self._fiat_send_e = AmountEdit(app_state.fx.get_currency if app_state.fx else lambda: "",
            self)
        self._on_fiat_ccy_changed()

        grid.addWidget(self._fiat_send_e, 3, 2)
        self.amount_e.frozen.connect(
            lambda: self._fiat_send_e.setFrozen(self.amount_e.isReadOnly()))

        self._max_button = EnterButton(_("Max"), self._spend_max, self)
        self._max_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Preferred)
        grid.addWidget(self._max_button, 3, 3)

        completer = QCompleter()
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseSensitive)
        self._payto_e.set_completer(completer)
        completer.setModel(self._completions)

        msg = (_('Description of the transaction (not mandatory).') + '\n\n' +
               _('The description is not sent to the recipient of the funds. '
                 'It is stored in your wallet file, and displayed in the \'History\' tab.'))
        description_label = HelpLabel(_('Description'), msg, self)
        grid.addWidget(description_label, 4, 0)
        self._message_e = MyLineEdit(self)
        grid.addWidget(self._message_e, 4, 1, 1, -1)

        self._main_window.connect_fields(self.amount_e, self._fiat_send_e)

        self._help_button = HelpDialogButton(self, "misc", "send-tab", _("Help"))
        self._preview_button = EnterButton(_("Preview"), self.preview_payment, self)
        self._preview_button.setToolTip(
            _('Display the details of your transactions before signing it.'))
        self._send_button = EnterButton(_("Send"), self.send_payment, self)
        if self._main_window.network is None:
            self._send_button.setEnabled(False)
            self._send_button.setToolTip(_('You are using ElectrumSV in offline mode; restart '
                                          'ElectrumSV if you want to get connected'))
        self._send_button.setVisible(not self._account.is_watching_only())
        self._clear_button = EnterButton(_("Clear"), self.clear, self)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self._help_button)
        buttons.addWidget(self._clear_button)
        buttons.addWidget(self._preview_button)
        buttons.addWidget(self._send_button)
        buttons.addStretch(1)
        grid.addLayout(buttons, 7, 0, 1, -1)

        self.amount_e.shortcut.connect(self._spend_max)
        self._payto_e.textChanged.connect(self.update_fee)
        self.amount_e.textEdited.connect(self.update_fee)

        def reset_max(t: str) -> None:
            # Invoices set the amounts, which invokes this despite them being frozen.
            if self._invoice is not None:
                return
            self._is_max = False
            self._max_button.setEnabled(not bool(t))
        self.amount_e.textEdited.connect(reset_max)
        self.amount_e.textChanged.connect(self._on_entry_changed)
        self._fiat_send_e.textEdited.connect(reset_max)

        self._invoice_list_toolbar_layout = TableTopButtonLayout()
        self._invoice_list_toolbar_layout.refresh_signal.connect(
            self._main_window.refresh_wallet_display)
        self._invoice_list_toolbar_layout.filter_signal.connect(self._filter_invoice_list)

        self.invoice_list = InvoiceList(self, self._main_window.reference())

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)

        invoice_layout = QVBoxLayout()
        invoice_layout.setSpacing(0)
        invoice_layout.setContentsMargins(6, 0, 6, 6)
        invoice_layout.addLayout(self._invoice_list_toolbar_layout)
        invoice_layout.addWidget(self.invoice_list)

        invoice_box = QGroupBox()
        invoice_box.setTitle(_('Invoices'))
        invoice_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        invoice_box.setContentsMargins(0, 0, 0, 0)
        invoice_box.setLayout(invoice_layout)

        vbox = QVBoxLayout(self)
        vbox.addLayout(hbox)
        vbox.addSpacing(20)
        vbox.addWidget(invoice_box)
        vbox.setStretchFactor(self.invoice_list, 1000)

        return vbox

    def on_tab_activated(self) -> None:
        self._mapi_fee_contexts: list[MAPIFeeContext] = []
        self._fee_quote_future = None

        # We cannot obtain fee quotes if we are offline.
        if self._main_window.network is None or self._account is None:
            return

        if self._invoice is not None:
            self._logger.debug("Send view not requesting MAPI fee quotes due to use for invoice %s",
                self._invoice.get_id())
            return

        self._send_button.setEnabled(False)
        self._preview_button.setEnabled(False)
        self._main_window.status_bar.showMessage(_("Requesting fee quotes from MAPI servers.."))

        account_id = self._account.get_id()
        self._fee_quote_future = app_state.app_qt.run_coro(
            self._account._wallet.update_mapi_fee_quotes_async(account_id),
            on_done=self._on_future_fee_quotes_done)

    def _on_future_fee_quotes_done(self,
            future: concurrent.futures.Future[list[MAPIFeeContext]]) -> None:
        if future.cancelled():
            return

        self._mapi_fee_contexts = future.result()
        if len(self._mapi_fee_contexts) > 0:
            message_text = _("Fee quotes obtained from {server_count} MAPI servers.").format(
                    server_count=len(self._mapi_fee_contexts))
            # # NOTE(rt12) For now we just pick one at random.
            # fee_context = random.choice(self._fee_quotes)
            # self._transaction_creation_context.set_fee_quote(fee_context.fee_quote)
            # self._transaction_creation_context.set_mapi_broadcast_hint(
            #     fee_context.server_and_credential)
            self._send_button.setEnabled(True)
        else:
            message_text = _("Unable to obtain fee quotes from any MAPI servers.")
            self._send_button.setToolTip(_("Unable to broadcast transactions as there no "
                "available MAPI servers"))
        self._main_window.status_bar.showMessage(message_text, 5000)

        self._preview_button.setEnabled(True)

    # Called externally via the Find menu option.
    def on_search_toggled(self) -> None:
        self._invoice_list_toolbar_layout.on_toggle_filter()

    def _filter_invoice_list(self, text: str) -> None:
        self.invoice_list.filter(text)

    def _on_entry_changed(self) -> None:
        assert self._account is not None
        text = ""
        if self._not_enough_funds:
            amt_color = ColorScheme.RED
            text = _( "Not enough funds" )
            c, u, x, a = self._account.get_frozen_balance()
            if c+u+x+a:
                text += (' (' + app_state.format_amount(c+u+x).strip() + ' ' +
                            app_state.base_unit() + ' ' + _("are frozen") + ')')

        if self.amount_e.isModified():
            amt_color = ColorScheme.DEFAULT
        else:
            amt_color = ColorScheme.BLUE

        self._main_window.statusBar().showMessage(text)
        self.amount_e.setStyleSheet(amt_color.as_stylesheet())

    def lock_amount(self, flag: bool) -> None:
        self.amount_e.setFrozen(flag)
        self._max_button.setEnabled(not flag)

    def set_spend_maximum(self, is_max: bool) -> None:
        self._is_max = is_max

    def is_spending_maximum(self) -> bool:
        return self._is_max

    def _spend_max(self) -> None:
        self._is_max = True
        self.do_update_fee()

    def clear(self) -> None:
        # NOTE: This clears trees in the view. That includes the invoice list.
        # So anything that calls this should follow it with a call to `update_widgets`.
        self._is_max = False
        self._not_enough_funds = False
        self._payment_id = None
        self._invoice = None
        self._payto_e.is_invoice = False

        edit_fields: tuple[FrozenEditProtocol, ...] = \
            (self._payto_e, self.amount_e, self._fiat_send_e, self._message_e)
        for edit_field in edit_fields:
            # TODO: Does this work with refresh given the ' ' refresh note in some edit.
            edit_field.setText('')
            edit_field.setFrozen(False)

        for tree in self.findChildren(QTreeWidget):
            tree.clear()

        self._max_button.setDisabled(False)
        self.set_pay_from([])

        # TODO: Revisit what this does.
        self._main_window.update_status_bar()
        self.update_widgets()

    def update_fee(self) -> None:
        self._require_fee_update = time.monotonic()

    def set_pay_from(self, coins: Iterable[UTXOProtocol]) -> None:
        self.pay_from = list(coins)
        self.redraw_from_list()

    def _on_from_list_menu_remove(self, item: QTreeWidgetItem) -> None:
        i = self._from_list.indexOfTopLevelItem(item)
        self.pay_from.pop(i)
        self.redraw_from_list()
        self.update_fee()

    def from_list_menu(self, position: QPoint) -> None:
        item = self._from_list.itemAt(position)
        menu = QMenu()
        menu.addAction(_("Remove"), lambda: self._on_from_list_menu_remove(item))
        menu.exec(self._from_list.viewport().mapToGlobal(position))

    def redraw_from_list(self) -> None:
        self._from_list.clear()
        self._from_label.setHidden(len(self.pay_from) == 0)
        self._from_list.setHidden(len(self.pay_from) == 0)

        def format_utxo(utxo: UTXOProtocol) -> str:
            h = hash_to_hex_str(utxo.tx_hash)
            return '{}...{}:{:d}\t{}'.format(h[0:10], h[-10:], utxo.txo_index, utxo.keyinstance_id)

        for utxo in self.pay_from:
            self._from_list.addTopLevelItem(QTreeWidgetItem(
                [format_utxo(utxo), app_state.format_amount(utxo.value)]))

        update_fixed_tree_height(self._from_list)

    def on_timer_action(self) -> None:
        if self._require_fee_update is None:
            return

        # We only want to update the displayed amount data when the user stops typing. At the
        # time of writing this, coin selection from large numbers of coins is slow and causes lag.
        if time.monotonic() - self._require_fee_update > 0.5:
            self.do_update_fee()
            self._require_fee_update = None

    def _make_base_transactions(self) -> tuple[list[Transaction], list[TxContext]]:
        """
        Raises `ValueError` for any unforeseen problems. The contents will be intended for display
            to the user and therefore are internationalised.
        """
        if self._invoice is not None:
            assert self._payment_id is not None
            if self._invoice.has_expired():
                raise ValueError(_("This invoice has expired"))

            txs: list[Transaction] = []
            tx_ctxs: list[TxContext] = []
            for tx_idx, tx in enumerate(self._invoice.transactions):
                txs.append(Transaction.from_io(tx.inputs, tx.outputs, tx.locktime))
                policy_dict = self._invoice.transaction_policies[tx_idx]
                fee_quote = policy_dict["fees"] if policy_dict is not None else None
                # We do not persist because we want to fund and sign them all successfully before
                # doing so. This simplifies things as we then only deal in funded complete payments.
                tx_ctxs.append(TxContext(fee_quote=fee_quote))
            return txs, tx_ctxs

        errors = self._payto_e.get_errors()
        if errors:
            raise ValueError(_("Invalid lines found:") + "\n\n" +
                '\n'.join([
                    "\n".join(textwrap.wrap(_("Line #") + str(x[0]+1) +": "+ x[1]))
                    for x in errors]))

        # NOTE(rt12) "pay to many" does not currently have a way for the user to denote a
        # manual split so these are implicitly lumped into one transaction for now.
        outputs = self._payto_e.get_outputs(self._is_max)

        # Handle the case where the user copies an address from the keys tab. If we do not do this
        # the wallet will lose track of the coins.
        script_templates: dict[ScriptTemplate, int] = {}
        for i, xtxo in enumerate(outputs):
            script_template = cast(ScriptTemplate,
                classify_output_script(xtxo.script_pubkey, Net.COIN))
            if isinstance(script_template, P2PKH_Address):
                script_templates[script_template] = i

        if script_templates:
            wallet = self._main_window._wallet
            match_count = 0
            for key_row in wallet.data.read_keyinstances():
                account = wallet.get_account(key_row.account_id)
                assert account is not None
                script_type = account.get_default_script_type()
                script_template = account.get_script_template_for_derivation(script_type,
                    key_row.derivation_type, key_row.derivation_data2)
                output_idx = script_templates.get(script_template)
                if output_idx is not None:
                    outputs[output_idx].x_pubkeys = account.get_xpubkeys_for_key_data(key_row)
                    match_count += 1
                if match_count == len(script_templates):
                    break

        if any(output.value is None for output in outputs):
            raise ValueError(_('Invalid Amount'))

        # TODO(1.4.0) Payments. Don't we need to persist the server and fee quote with a
        #     persisted payment? Or is there a simpler way?
        if len(self._mapi_fee_contexts) == 0:
            default_fee_rate =  app_state.config.get_explicit_type(int, "customfee", DEFAULT_FEE)
            tx_ctx = TxContext(fee_quote={
                "standard": {"satoshis": default_fee_rate, "bytes": 1000},
                "data": {"satoshis": default_fee_rate, "bytes": 1000},
            })
        else:
            fee_context = random.choice(self._mapi_fee_contexts)
            tx_ctx = TxContext(mapi_server_hint=fee_context.server_and_credential,
                fee_quote=fee_context.fee_quote)
        return [ Transaction.from_io([], outputs) ], [ tx_ctx ]

    def do_update_fee(self) -> None:
        """Recalculate the fee.  If the fee was manually input, retain it, but
        still build the TX to see if there are enough funds."""
        assert self._account is not None
        amount = MAX_VALUE if self._is_max else self.amount_e.get_amount()
        if amount is None:
            # The amount the user entered is junk text that cannot be reconciled to a value.
            self._not_enough_funds = False
            self._on_entry_changed()
            return

        try:
            txs, tx_ctxs = self._make_base_transactions()
        except ValueError as exc:
            self._logger.debug("Failed calculating fee: %s", str(exc))
            return

        if len(txs) == 0:
            # TODO(1.4.0) Payments. Judge if fees in this case
            # fees ...
            # assert self._invoice_terms is not None
            # outputs = self._payto_e.get_outputs(self._is_max)
            # if not outputs:
            #     output_script = self._payto_e.get_payee_script()
            #     if output_script is None:
            #         output_script = self._account.get_dummy_script_template().to_script()
            #     # NOTE(typing) workaround for mypy not recognising the base class init arguments.
            #     outputs = [XTxOutput(amount, output_script)] # type: ignore
            # fee_context: MAPIFeeContext|None = random.choice(self._mapi_fee_contexts) \
            #     if len(self._mapi_fee_contexts) > 0 else None
            return

        utxos = self._get_utxos()
        for i, tx in enumerate(txs):
            try:
                txs[i], utxos = self._account.make_unsigned_tx(tx, tx_ctxs[i], utxos)
                self._not_enough_funds = False
            except NotEnoughFunds:
                self._logger.debug("Not enough funds")
                self._not_enough_funds = True
                self._on_entry_changed()
                return
            except Exception:
                self._logger.exception("transaction failure")
                return

        if self._is_max:
            amount = tx.output_value()
            self.amount_e.setAmount(amount)

    def preview_payment(self) -> None:
        self.send_payment(preview=True)

    def send_payment(self, preview: bool=False) -> None:
        assert self._account is not None
        dialogs.show_named('think-before-sending')

        try:
            txs, tx_ctxs = self._make_base_transactions()
        except ValueError as exc:
            self._main_window.show_error(str(exc))
            return

        if len(txs) == 0:
            assert self._invoice is None # This cannot happen with invoices.
            self._main_window.show_error(_('Please specify a destination for this payment.'))
            return

        tx_label = self._message_e.text()
        utxos = self._get_utxos()
        for i, tx in enumerate(txs):
            tx_ctx = tx_ctxs[i]
            try:
                txs[i], utxos = self._account.make_unsigned_tx(tx, tx_ctx, utxos)
            except (ExcessiveFee, NotEnoughFunds) as exc:
                self._main_window.show_error(str(exc))
                return
            except Exception as e:
                self._logger.exception("")
                self._main_window.show_message(str(e))
                return

        payment_ctx = PaymentCtx(self._payment_id, description=tx_label)

        if preview:
            self._main_window.show_payment(ViewPaymentMode.UNSIGNED, payment_ctx.payment_id, txs,
                tx_ctxs, self._account.get_id())
            return

        # TODO(1.4.0) Payments. If the other party funds the transaction, we need to have the value
        #     of their spend outputs to work out the fee. This would come as part of the SPV.
        assert len(txs) == 1
        tx = txs[0]
        fee = tx.get_fee()
        # ????? not sure about all this any of it.
        input_value = sum([ cast(int, txi.value) for tx in txs for txi in tx.inputs
            if txi.x_pubkeys ])
        output_value = sum([ txo.value for tx in txs for txo in tx.outputs if txo.x_pubkeys ])
        amount = output_value - input_value

        msg = []
        if fee < round(sum(tx.estimated_size()) * 0.1):
            msg.append(_("Warning") +": "+ _("The fee is less than {} sats/kb. It may take a "
                "very long time to confirm.").format(100))
        msg.extend([ "", _("Enter your password to proceed") ])

        password = self._main_window.password_dialog('\n'.join(msg), fields=[
            (_("Amount to send"), QLabel(app_state.format_amount_and_units(amount))),
            (_("Mining fee"), QLabel(app_state.format_amount_and_units(fee))),
        ])
        if not password:
            return

        def sign_done(success: bool) -> None:
            nonlocal payment_ctx, txs, tx_ctxs
            if not success:
                return
            assert payment_ctx.payment_id is not None

            if all(tx.is_complete() for tx in txs):
                if self._invoice:
                    if self._main_window.send_invoice_payment(payment_ctx.payment_id, self._invoice,
                            txs):
                        self.clear()
                    return

                def broadcast_done(results: list[BroadcastResult]) -> None: pass
                self._main_window.broadcast_transactions(payment_ctx.payment_id, txs, tx_ctxs,
                    broadcast_done, self._main_window.reference())
                return

            # Successful partial signing. At time of writing this will be multisig.
            assert self._account is not None
            self._main_window.show_payment(ViewPaymentMode.PARTIALLY_SIGNED,
                payment_ctx.payment_id, txs, tx_ctxs, self._account.get_id())
            self.clear()

        self._main_window.sign_transactions(self._account, payment_ctx, txs, tx_ctxs, sign_done,
            password)

    def _get_utxos(self) -> Sequence[UTXOProtocol]:
        if self.pay_from:
            return self.pay_from
        assert self._account is not None
        return cast(Sequence[UTXOProtocol], self._account.get_transaction_outputs_with_key_data())

    # Legacy payment.

    def set_processed_url_data(self, data: dict[str, Any]) -> None:
        address = data.get('address')
        bip276_text = data.get('bip276')
        amount = data.get('amount')
        label = data.get('label')
        message = data.get('message')
        # use label as description (not BIP21 compliant)
        if label and not message:
            message = label
        if address:
            self._payto_e.setText(address)
        if bip276_text:
            # NOTE(typing) This is our `PayToEdit.setPlainText` override.
            self._payto_e.setText(bip276_text, True) # type: ignore
        if message:
            self._message_e.setText(message)
        if amount:
            self.amount_e.setAmount(amount)
            self.amount_e.textEdited.emit("")

    def display_invoice(self, terms: PaymentTermsMessage) -> None:
        assert self._account is not None
        self._invoice = terms
        invoice_id = terms.get_id()
        assert invoice_id is not None
        row = self._account._wallet.data.read_invoice(invoice_id=invoice_id)
        self.display_invoice_signal.emit(row)

    def show_invoice_loading_state(self) -> None:
        """Calling context: Guaranteed to be the UI thread."""
        self._payto_e.is_invoice = True
        edit_widgets: list[FrozenEditProtocol] = [self._payto_e, self.amount_e, self._message_e]
        for widget in edit_widgets:
            widget.setFrozen(True)
        self._max_button.setDisabled(True)
        self._payto_e.setText(_("please wait..."))

    def import_and_display_invoice(self, terms: PaymentTermsMessage,
            receiver_address: Address) -> None:
        """Calling context: Not guaranteed to be the UI thread."""
        self._invoice_address = receiver_address
        self._invoice = terms
        # Proceed to process the invoice on the GUI thread.
        self.import_and_display_invoice_signal.emit()

    def payable_invoice_import_error(self, text: str) -> None:
        """Calling context: Not guaranteed to be the UI thread."""
        self.invoice_import_error_signal.emit(text)

    def _invoice_import_error(self, text: str) -> None:
        self._main_window.show_error(_("The invoice is invalid.") +"<br/><br/>" + text)
        self.clear()

    def _import_and_display_invoice(self) -> None:
        assert self._account is not None and self._invoice is not None
        if self._invoice.get_id() is not None:
            row = self._account._wallet.data.read_invoice(invoice_id=self._invoice.get_id())
            assert row is not None
            if row.flags & PaymentRequestFlag.STATE_PAID:
                self._main_window.show_message(_("This invoice is both already imported and paid."))
                self.clear()
            self.display_invoice_signal.emit(row)
            return

        def future_callback(future: concurrent.futures.Future[InvoiceRow]) -> None:
            if future.cancelled() or self._invoice is None:
                return
            row = future.result()
            self._payment_id = row.payment_id
            self._invoice.set_id(row.invoice_id)
            self.display_invoice_signal.emit(row)

        contact_id: int|None = None
        future = app_state.async_.spawn(
            self._account.import_invoice_async(self._invoice, contact_id))
        future.add_done_callback(future_callback)

    # TODO(1.4.0) Payments. Called by the invoice list to populate the send view with the invoice
    #     payment details. This should be called by the history list instead.
    def _display_invoice(self, row: InvoiceRow) -> None:
        assert self._invoice is not None
        assert self._invoice.get_id() == row.invoice_id

        assert row.description is not None
        self.invoice_list.update()
        self._payto_e.is_invoice = True
        if not is_inv_expired(row.date_expires):
            self._payto_e.set_validated()
        else:
            self._payto_e.set_expired()
        self._payto_e.setText(row.payment_uri)
        self.amount_e.setText(format_satoshis_plain(row.value, app_state.decimal_point))
        self._message_e.setText(row.description)
        # signal to set fee
        self.amount_e.textEdited.emit("")

    # TODO(1.4.0) Payments. Called by the invoice list to clear the current invoice if it was
    #     deleted there. Similarly to `display_invoice` above.
    def _invoice_deleted(self, invoice_id: int) -> None:
        if self._invoice is not None and self._invoice.get_id() == invoice_id:
            self.clear()
        # Remove the seal from the history lines.
        self._main_window.update_history_view()
        # Update the invoice list.
        self.update_widgets()

    def _on_ui_payment_success(self, payment_id: int) -> None:
        if self._invoice is not None:
            if payment_id == self._invoice.get_id():
                self.clear()
        else:
            self.clear()

    def get_bsv_edits(self) -> list[BTCAmountEdit]:
        """External entrypoint where the user has changed the base unit and we are updating the
        edit widgets that embed that base unit."""
        return [ self.amount_e ]

    def paytomany(self) -> None:
        """External entrypoint where the send view has been put to the front and it is modified to
        show a modified UI where the user can enter multiple payment destinations. These will
        explicitly be legacy payment destinations."""
        self._payto_e.paytomany()
        msg = '\n'.join([
            _('Enter a list of outputs in the \'Pay to\' field.'),
            _('One output per line.'),
            _('Format: address, amount'),
            _('You may load a CSV file using the file icon.')
        ])
        self._main_window.show_message(msg, title=_('Pay to many'))

    # TODO(invoice-import) What format are these imported files? No idea.
    # def import_invoices(self) -> None:
    #     assert self._account is not None
    #     self.invoice_list.import_invoices(self._account)

    def update_widgets(self) -> None:
        """External entrypoint where the main window has blindly been asked to update and this is
        how it tells us to update this tab. This is non-ideal."""
        self.invoice_list.update()
