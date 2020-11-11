# The Open BSV license.
#
# Copyright © 2019-2020 Bitcoin Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
#   1. The above copyright notice and this permission notice shall be included
#      in all copies or substantial portions of the Software.
#   2. The Software, and any software that is derived from the Software or parts
#      thereof, can only be used on the Bitcoin SV blockchains. The Bitcoin SV
#      blockchains are defined, for purposes of this license, as the Bitcoin
#      blockchain containing block height #556767 with the hash
#      “000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b” and
#      the test blockchains that are supported by the unmodified Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import textwrap
import time
from typing import Any, Dict, List, Tuple, Optional, TYPE_CHECKING
import weakref

from bitcoinx import hash_to_hex_str

from PyQt5.QtCore import pyqtSignal, Qt, QStringListModel
from PyQt5.QtWidgets import (QCheckBox, QCompleter, QGridLayout, QGroupBox, QHBoxLayout, QMenu,
    QLabel, QSizePolicy, QTreeView, QTreeWidgetItem, QVBoxLayout, QWidget)

from electrumsv.app_state import app_state
from electrumsv.constants import PaymentFlag, WalletSettings
from electrumsv.exceptions import ExcessiveFee, NotEnoughFunds
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.paymentrequest import has_expired, PaymentRequest
from electrumsv.transaction import Transaction, XTxOutput
from electrumsv.util import format_satoshis_plain
from electrumsv.wallet import AbstractAccount, UTXO
from electrumsv.wallet_database.tables import InvoiceRow

from .amountedit import AmountEdit, BTCAmountEdit, MyLineEdit
from . import dialogs
from .invoice_list import InvoiceList
from .paytoedit import PayToEdit
from .table_widgets import TableTopButtonLayout
from .util import (ColorScheme, EnterButton, HelpDialogButton, HelpLabel, MyTreeWidget,
    UntrustedMessageDialog, update_fixed_tree_height)


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

    payment_request_ok_signal = pyqtSignal()
    payment_request_error_signal = pyqtSignal(int, bytes)
    payment_request_import_error_signal = pyqtSignal(object)
    payment_request_imported_signal = pyqtSignal(object)
    payment_request_deleted_signal = pyqtSignal(int)

    _account_id: Optional[int] = None
    _account: Optional[AbstractAccount] = None

    def __init__(self, main_window: 'ElectrumWindow', account_id: int) -> None:
        super().__init__(main_window)

        self._main_window = weakref.proxy(main_window)
        self._account_id = account_id
        self._account = main_window._wallet.get_account(account_id)
        self._logger = logs.get_logger(f"send_view[{self._account_id}]")

        self._is_max = False
        self._not_enough_funds = False
        self._require_fee_update: Optional[int] = None
        self._payment_request: Optional[PaymentRequest] = None
        self._completions = QStringListModel()

        self.setLayout(self.create_send_layout())

        self.payment_request_ok_signal.connect(self.payment_request_ok)
        self.payment_request_error_signal.connect(self.payment_request_error)
        self.payment_request_import_error_signal.connect(self._payment_request_import_error)
        self.payment_request_imported_signal.connect(self._payment_request_imported)
        self.payment_request_deleted_signal.connect(self._payment_request_deleted)

        self._main_window.wallet_setting_changed_signal.connect(self._on_wallet_setting_changed)

    def create_send_layout(self) -> QVBoxLayout:
        """ Re-render the layout and it's child widgets of this view. """
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self._send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        # This ensures all columns are stretched over the full width of the last tab.
        grid.setColumnStretch(4, 1)

        self.amount_e = BTCAmountEdit(self)
        self._payto_e = PayToEdit(self)

        # From fields row.
        # This is enabled by "spending" coins in the coins tab.

        self._from_label = QLabel(_('From'), self)
        self._from_label.setContentsMargins(0, 5, 0, 0)
        self._from_label.setAlignment(Qt.AlignTop)
        grid.addWidget(self._from_label, 1, 0)

        self._from_list = MyTreeWidget(self, self._main_window.reference(), self.from_list_menu,
            ['Address / Outpoint','Amount'])
        self._from_list.setMaximumHeight(80)
        grid.addWidget(self._from_list, 1, 1, 1, -1)
        self.set_pay_from([])

        msg = (_('Recipient of the funds.') + '\n\n' +
               _('You may enter a Bitcoin SV address, a label from your list of '
                 'contacts (a list of completions will be proposed), or an alias '
                 '(email-like address that forwards to a Bitcoin SV address)'))
        payto_label = HelpLabel(_('Pay to'), msg, self)
        payto_label.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
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

        self._fiat_send_e = AmountEdit(app_state.fx.get_currency if app_state.fx else '', self)
        self.set_fiat_ccy_enabled(bool(app_state.fx and app_state.fx.is_enabled()))

        grid.addWidget(self._fiat_send_e, 3, 2)
        self.amount_e.frozen.connect(
            lambda: self._fiat_send_e.setFrozen(self.amount_e.isReadOnly()))

        self._max_button = EnterButton(_("Max"), self._spend_max, self)
        self._max_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        grid.addWidget(self._max_button, 3, 3)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
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

        self._coinsplitting_checkbox = QCheckBox(_('Add extra data to ensure the coins used '
            'by the transaction are only used on the Bitcoin SV blockchain (coin-splitting).'),
            self)
        self._coinsplitting_checkbox.setChecked(not self._account.involves_hardware_wallet())
        self._coinsplitting_checkbox.setVisible(self._show_splitting_option())
        # Hardware wallets can only sign a small set of fixed types of scripts (not this kind).
        self._coinsplitting_checkbox.setEnabled(not self._account.involves_hardware_wallet())
        def coinsplitting_checkbox_cb(state: int) -> None:
            if state != Qt.Checked:
                dialogs.show_named('sv-only-disabled')
        self._coinsplitting_checkbox.stateChanged.connect(coinsplitting_checkbox_cb)
        grid.addWidget(self._coinsplitting_checkbox, 5, 1, 1, -1)

        self._help_button = HelpDialogButton(self, "misc", "send-tab", _("Help"))
        self._preview_button = EnterButton(_("Preview"), self._do_preview, self)
        self._preview_button.setToolTip(
            _('Display the details of your transactions before signing it.'))
        self._send_button = EnterButton(_("Send"), self._do_send, self)
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

        def reset_max(t) -> None:
            # Invoices set the amounts, which invokes this despite them being frozen.
            if self._payment_request is not None:
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

        self._invoice_list = InvoiceList(self, self._main_window.reference())

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)

        invoice_layout = QVBoxLayout()
        invoice_layout.setSpacing(0)
        invoice_layout.setContentsMargins(6, 0, 6, 6)
        invoice_layout.addLayout(self._invoice_list_toolbar_layout)
        invoice_layout.addWidget(self._invoice_list)

        invoice_box = QGroupBox()
        invoice_box.setTitle(_('Invoices'))
        invoice_box.setAlignment(Qt.AlignCenter)
        invoice_box.setContentsMargins(0, 0, 0, 0)
        invoice_box.setLayout(invoice_layout)

        vbox = QVBoxLayout(self)
        vbox.addLayout(hbox)
        vbox.addSpacing(20)
        vbox.addWidget(invoice_box)
        vbox.setStretchFactor(self._invoice_list, 1000)

        return vbox

    def clean_up(self) -> None:
        pass

    def _on_wallet_setting_changed(self, setting_name: str, setting_value: Any) -> None:
        if setting_name == WalletSettings.ADD_SV_OUTPUT:
            self._coinsplitting_checkbox.setVisible(setting_value)

    def _show_splitting_option(self) -> bool:
        return self._account._wallet.get_boolean_setting(WalletSettings.ADD_SV_OUTPUT)

    # Called externally via the Find menu option.
    def on_search_toggled(self) -> None:
        self._invoice_list_toolbar_layout.on_toggle_filter()

    def _filter_invoice_list(self, text: str) -> None:
        self._invoice_list.filter(text)

    def _on_entry_changed(self) -> None:
        text = ""
        if self._not_enough_funds:
            amt_color = ColorScheme.RED
            text = _( "Not enough funds" )
            c, u, x = self._account.get_frozen_balance()
            if c+u+x:
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

    def set_is_spending_maximum(self, is_max: bool) -> None:
        self._is_max = is_max

    def get_is_spending_maximum(self) -> bool:
        return self._is_max

    def _spend_max(self) -> None:
        self._is_max = True
        self.do_update_fee()

    def clear(self) -> None:
        # NOTE: This clears trees in the view. That includes the invoice list.
        # So anything that calls this should follow it with a call to `update_widgets`.
        self._is_max = False
        self._not_enough_funds = False
        self._payment_request = None
        self._payto_e.is_pr = False

        edit_fields = (self._payto_e, self.amount_e, self._fiat_send_e, self._message_e)
        for edit_field in edit_fields:
            # TODO: Does this work with refresh given the ' ' refresh note in some edit.
            edit_field.setText('')
            edit_field.setFrozen(False)

        for tree in self.findChildren(QTreeView):
            tree.clear()

        self._max_button.setDisabled(False)
        self.set_pay_from([])
        self._coinsplitting_checkbox.setChecked(True)

        # TODO: Revisit what this does.
        self._main_window.update_status_bar()
        self.update_widgets()

    def update_fee(self) -> None:
        self._require_fee_update = time.monotonic()

    def set_pay_from(self, coins: List[UTXO]) -> None:
        self.pay_from = list(coins)
        self.redraw_from_list()

    def _on_from_list_menu_remove(self, item: QTreeWidgetItem) -> None:
        i = self._from_list.indexOfTopLevelItem(item)
        self.pay_from.pop(i)
        self.redraw_from_list()
        self.update_fee()

    def from_list_menu(self, position) -> None:
        item = self._from_list.itemAt(position)
        menu = QMenu()
        menu.addAction(_("Remove"), lambda: self._on_from_list_menu_remove(item))
        menu.exec_(self._from_list.viewport().mapToGlobal(position))

    def redraw_from_list(self) -> None:
        self._from_list.clear()
        self._from_label.setHidden(len(self.pay_from) == 0)
        self._from_list.setHidden(len(self.pay_from) == 0)

        def format_utxo(utxo: UTXO) -> str:
            h = hash_to_hex_str(utxo.tx_hash)
            return '{}...{}:{:d}\t{}'.format(h[0:10], h[-10:], utxo.out_index, utxo.address)

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

    def do_update_fee(self) -> None:
        '''Recalculate the fee.  If the fee was manually input, retain it, but
        still build the TX to see if there are enough funds.
        '''
        amount = all if self._is_max else self.amount_e.get_amount()
        if amount is None:
            self._not_enough_funds = False
            self._on_entry_changed()
        else:
            fee = None
            outputs = self._payto_e.get_outputs(self._is_max)
            if not outputs:
                output_script = self._payto_e.get_payee_script()
                if output_script is None:
                    output_script = self._account.get_dummy_script_template().to_script()
                outputs = [XTxOutput(amount, output_script)]

            coins = self._get_coins()
            outputs.extend(self._account.create_extra_outputs(coins, outputs))
            try:
                tx = self._account.make_unsigned_transaction(self._get_coins(), outputs,
                    self._main_window.config, fee)
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

    def _do_preview(self) -> None:
        self._do_send(preview=True)

    def _do_send(self, preview: bool=False) -> None:
        dialogs.show_named('think-before-sending')

        if self._payment_request is not None:
            tx = self.get_transaction_for_invoice()
            if tx is not None:
                if preview or not tx.is_complete():
                    self._main_window.show_transaction(self._account, tx, pr=self._payment_request)
                    self.clear()
                    return

                self._main_window.broadcast_transaction(self._account, tx)
                return

        r = self._read()
        if not r:
            return

        outputs, fee, tx_desc, coins = r
        outputs.extend(self._account.create_extra_outputs(coins, outputs))
        try:
            tx = self._account.make_unsigned_transaction(coins, outputs, self._main_window.config,
                fee)
        except NotEnoughFunds:
            self._main_window.show_message(_("Insufficient funds"))
            return
        except ExcessiveFee:
            self._main_window.show_message(_("Your fee is too high.  Max is 50 sat/byte."))
            return
        except Exception as e:
            self.logger.exception("")
            self._main_window.show_message(str(e))
            return

        tx.context.description = tx_desc
        if preview:
            self._main_window.show_transaction(self._account, tx, pr=self._payment_request)
        else:
            amount = tx.output_value() if self._is_max else sum(output.value for output in outputs)
            self._sign_tx_and_broadcast_if_complete(amount, tx)

    def _read(self) -> Tuple[List[XTxOutput], Optional[int], str, List[UTXO]]:
        if self._payment_request and self._payment_request.has_expired():
            self._main_window.show_error(_('Payment request has expired'))
            return
        label = self._message_e.text()

        outputs: List[XTxOutput]
        if self._payment_request:
            outputs = self._payment_request.get_outputs()
        else:
            errors = self._payto_e.get_errors()
            if errors:
                self._main_window.show_warning(_("Invalid lines found:") + "\n\n" +
                    '\n'.join([
                        "\n".join(textwrap.wrap(_("Line #") + str(x[0]+1) +": "+ x[1]))
                        for x in errors]))
                return
            outputs = self._payto_e.get_outputs(self._is_max)

        if not outputs:
            self._main_window.show_error(_('No payment destinations provided'))
            return

        if any(output.value is None for output in outputs):
            self._main_window.show_error(_('Invalid Amount'))
            return

        fee = None
        coins = self._get_coins()
        return outputs, fee, label, coins

    def _get_coins(self) -> List[UTXO]:
        if self.pay_from:
            return self.pay_from
        return self._account.get_spendable_coins(None, self._main_window.config)

    def _sign_tx_and_broadcast_if_complete(self, amount: int, tx: Transaction) -> None:
        # confirmation dialog
        fee = tx.get_fee()

        msg = []
        if fee < round(tx.estimated_size() * 0.5):
            msg.append(_('Warning') + ': ' +
                _('The fee is less than 500 sats/kb. It may take a very long time to confirm.'))
        msg.append("")
        msg.append(_("Enter your password to proceed"))

        password = self._main_window.password_dialog('\n'.join(msg), fields=[
            (_("Amount to send"), QLabel(app_state.format_amount_and_units(amount))),
            (_("Mining fee"), QLabel(app_state.format_amount_and_units(fee))),
        ])
        if not password:
            return

        if self._payment_request is not None:
            tx.context.invoice_id = self._payment_request.get_id()

        def sign_done(success: bool) -> None:
            if success:
                if not tx.is_complete():
                    self._main_window.show_transaction(self._account, tx, pr=self._payment_request)
                    self.clear()
                    return

                self._main_window.broadcast_transaction(self._account, tx)

        self._main_window.sign_tx_with_password(tx, sign_done, password, tx_context=tx.context)

    def get_transaction_for_invoice(self) -> Optional[Transaction]:
        invoice_row = self._account.invoices.get_invoice_for_id(self._payment_request.get_id())
        if invoice_row.tx_hash is not None:
            return self._account.get_transaction(invoice_row.tx_hash)
        return None

    def maybe_send_invoice_payment(self, tx: Transaction) -> bool:
        pr = self._payment_request
        if pr:
            tx_hash = tx.hash()
            invoice_id = pr.get_id()

            # TODO: Remove the dependence of broadcasting a transaction to pay an invoice on that
            # invoice being active in the send tab. Until then we assume that broadcasting a
            # transaction that is not related to the active invoice and it's repercussions, has
            # been confirmed by the appropriate calling logic. Like `confirm_broadcast_transaction`
            # in the main window logic.
            invoice_row = self._account.invoices.get_invoice_for_id(invoice_id)
            if tx_hash != invoice_row.tx_hash:
                # Calling logic should have detected this and warned/confirmed with the user.
                return True

            if pr.has_expired():
                pr.error = _("The invoice has expired")
                self.payment_request_error_signal.emit(invoice_id, tx_hash)
                return False

            if not pr.send_payment(self._account, str(tx)):
                self.payment_request_error_signal.emit(invoice_id, tx_hash)
                return False

            self._account.invoices.set_invoice_paid(invoice_id)

            self._payment_request = None
            # On success we broadcast as well, but it is assumed that the merchant also
            # broadcasts.
        return True

    def pay_for_payment_request(self, pr: PaymentRequest) -> None:
        # The invoice id will already be set on the payment request.
        self._payment_request = pr
        self.prepare_for_payment_request()
        self.payment_request_ok()

    def prepare_for_payment_request(self) -> None:
        self._payto_e.is_pr = True
        for widget in [self._payto_e, self.amount_e, self._message_e]:
            widget.setFrozen(True)
        self._max_button.setDisabled(True)
        self._payto_e.setText(_("please wait..."))

    def on_payment_request(self, request: PaymentRequest) -> None:
        self._payment_request = request
        # Proceed to process the payment request on the GUI thread.
        self.payment_request_ok_signal.emit()

    def payment_request_import_error(self, text: str) -> None:
        self.payment_request_import_error_signal.emit(text)

    def _payment_request_import_error(self, text: str) -> None:
        self.clear()

        extended_text = _("The payment request is invalid.") +"<br/><br/>"
        extended_text += text
        self._main_window.show_error(extended_text)

    def set_payment_request_data(self, data: Dict[str, Any]) -> None:
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
            self._payto_e.setText(bip276_text, True)
        if message:
            self._message_e.setText(message)
        if amount:
            self.amount_e.setAmount(amount)
            self.amount_e.textEdited.emit("")

    def payment_request_ok(self) -> None:
        pr = self._payment_request

        service = self._account.invoices
        if pr.get_id() is None:
            def callback(exc_value: Optional[Exception]=None) -> None:
                nonlocal service
                if exc_value is not None:
                    raise exc_value # pylint: disable=raising-bad-type
                row = service.get_invoice_for_payment_uri(pr.get_payment_uri())
                pr.set_id(row.invoice_id)
                self.payment_request_imported_signal.emit(row)

            row = service.import_payment_request(pr, callback)
            if row.invoice_id is None:
                # We're waiting for the callback.
                return
        else:
            row = service.get_invoice_for_id(pr.get_id())

        # The invoice is already present. Populate it unless it's paid.
        if row.flags & PaymentFlag.PAID:
            self._main_window.show_message("invoice already paid")
            self._payment_request = None
            self.clear()
            return
        self._payment_request_imported(row)

    def _payment_request_imported(self, row: InvoiceRow) -> None:
        self._invoice_list.update()

        self._payto_e.is_pr = True
        if not has_expired(row.date_expires):
            self._payto_e.set_validated()
        else:
            self._payto_e.set_expired()
        self._payto_e.setText(row.payment_uri)
        self.amount_e.setText(format_satoshis_plain(row.value, app_state.decimal_point))
        self._message_e.setText(row.description)
        # signal to set fee
        self.amount_e.textEdited.emit("")

    def _payment_request_deleted(self, invoice_id: int) -> None:
        if self._payment_request is not None:
            if self._payment_request.get_id() == invoice_id:
                self._payment_request = None
                self.clear()

        # Remove the seal from the history lines.
        self._main_window.update_history_view()
        # Update the invoice list.
        self.update_widgets()

    def payment_request_error(self, invoice_id: int, tx_hash: bytes) -> None:
        # The transaction is still signed and associated with the invoice. This should be
        # indicated to the user in the UI, and they can deal with it.

        d = UntrustedMessageDialog(
            self._main_window.reference(), _("Invoice Payment Error"),
            _("Your payment was rejected for some reason."),
            untrusted_text=str(self._payment_request.error))
        d.exec()

        self._payment_request = None
        self.clear()

    def get_bsv_edits(self) -> List[BTCAmountEdit]:
        # Used to apply changes like base unit changes to all applicable edit fields.
        return [ self.amount_e ]

    def update_for_fx_quotes(self) -> None:
        edit = self._fiat_send_e if self._fiat_send_e.is_last_edited else self.amount_e
        edit.textEdited.emit(edit.text())

    def paytomany(self) -> None:
        self._payto_e.paytomany()
        msg = '\n'.join([
            _('Enter a list of outputs in the \'Pay to\' field.'),
            _('One output per line.'),
            _('Format: address, amount'),
            _('You may load a CSV file using the file icon.')
        ])
        self._main_window.show_message(msg, title=_('Pay to many'))

    def import_invoices(self) -> None:
        self._invoice_list.import_invoices(self._account)

    def update_widgets(self) -> None:
        self._invoice_list.update()

    def set_fiat_ccy_enabled(self, flag: bool) -> None:
        self._fiat_send_e.setVisible(flag)
