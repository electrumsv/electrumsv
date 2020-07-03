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

from typing import Any, Dict, List, Tuple, Optional, TYPE_CHECKING

from bitcoinx import hash_to_hex_str

from PyQt5.QtCore import pyqtSignal, Qt, QStringListModel
from PyQt5.QtWidgets import (QCompleter, QGridLayout, QHBoxLayout, QLineEdit, QMenu, QLabel,
    QPlainTextEdit, QSizePolicy, QTreeView, QTreeWidgetItem, QVBoxLayout, QWidget)

from electrumsv.app_state import app_state
from electrumsv.constants import PaymentState
from electrumsv.exceptions import ExcessiveFee, NotEnoughFunds
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.paymentrequest import PaymentRequest
from electrumsv.transaction import Transaction, XTxOutput
from electrumsv.util import format_satoshis_plain
from electrumsv.wallet import AbstractAccount, UTXO

from .amountedit import AmountEdit, BTCAmountEdit, MyLineEdit
from . import dialogs
from .invoice_list import InvoiceList
from .paytoedit import PayToEdit
from .util import ColorScheme, EnterButton, HelpLabel, MyTreeWidget, update_fixed_tree_height


if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class SendView(QWidget):
    payment_request_ok_signal = pyqtSignal()
    payment_request_error_signal = pyqtSignal()

    _account_id: Optional[int] = None
    _account: Optional[AbstractAccount] = None

    searchable_list: Optional[QWidget] = None

    def __init__(self, main_window: 'ElectrumWindow', account_id: int) -> None:
        super().__init__(main_window)

        self._main_window = main_window
        self._account_id = account_id
        self._account = main_window._wallet.get_account(account_id)
        self._logger = logs.get_logger(f"send_view[{self._account_id}]")

        self.is_max = False
        self.not_enough_funds = False
        self.require_fee_update = False
        self.payment_request = None
        self.completions = QStringListModel()

        self.setLayout(self.create_send_layout())

        self.payment_request_ok_signal.connect(self.payment_request_ok)
        self.payment_request_error_signal.connect(self.payment_request_error)

    def create_send_layout(self) -> QVBoxLayout:
        """ Re-render the layout and it's child widgets of this view. """
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        self._send_grid = grid = QGridLayout()
        grid.setSpacing(8)
        # This ensures all columns are stretched over the full width of the last tab.
        grid.setColumnStretch(4, 1)

        self.amount_e = BTCAmountEdit(self)
        self.payto_e = PayToEdit(self)

        # From fields row.
        # This is enabled by "spending" coins in the coins tab.

        self.from_label = QLabel(_('From'), self)
        self.from_label.setContentsMargins(0, 5, 0, 0)
        self.from_label.setAlignment(Qt.AlignTop)
        grid.addWidget(self.from_label, 1, 0)

        self.from_list = MyTreeWidget(self, self._main_window, self.from_list_menu,
            ['Address / Outpoint','Amount'])
        self.from_list.setMaximumHeight(80)
        grid.addWidget(self.from_list, 1, 1, 1, -1)
        self.set_pay_from([])

        msg = (_('Recipient of the funds.') + '\n\n' +
               _('You may enter a Bitcoin SV address, a label from your list of '
                 'contacts (a list of completions will be proposed), or an alias '
                 '(email-like address that forwards to a Bitcoin SV address)'))
        payto_label = HelpLabel(_('Pay to'), msg, self)
        payto_label.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Preferred)
        grid.addWidget(payto_label, 2, 0)
        grid.addWidget(self.payto_e, 2, 1, 1, -1)

        msg = (_('Amount to be sent.') + '\n\n' +
               _('The amount will be displayed in red if you do not have '
                 'enough funds in your wallet.') + ' '
               + _('Note that if you have frozen some of your coins, the available '
                   'funds will be lower than your total balance.') + '\n\n'
               + _('Keyboard shortcut: type "!" to send all your coins.'))
        amount_label = HelpLabel(_('Amount'), msg, self)
        grid.addWidget(amount_label, 3, 0)
        grid.addWidget(self.amount_e, 3, 1)

        self.fiat_send_e = AmountEdit(app_state.fx.get_currency if app_state.fx else '', self)
        self.set_fiat_ccy_enabled(app_state.fx and app_state.fx.is_enabled())

        grid.addWidget(self.fiat_send_e, 3, 2)
        self.amount_e.frozen.connect(
            lambda: self.fiat_send_e.setFrozen(self.amount_e.isReadOnly()))

        self.max_button = EnterButton(_("Max"), self.spend_max, self)
        self.max_button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        grid.addWidget(self.max_button, 3, 3)

        completer = QCompleter()
        completer.setCaseSensitivity(False)
        self.payto_e.set_completer(completer)
        completer.setModel(self.completions)

        msg = (_('Description of the transaction (not mandatory).') + '\n\n' +
               _('The description is not sent to the recipient of the funds. '
                 'It is stored in your wallet file, and displayed in the \'History\' tab.'))
        description_label = HelpLabel(_('Description'), msg, self)
        grid.addWidget(description_label, 4, 0)
        self.message_e = MyLineEdit(self)
        grid.addWidget(self.message_e, 4, 1, 1, -1)

        self._main_window.connect_fields(self.amount_e, self.fiat_send_e)

        self.preview_button = EnterButton(_("Preview"), self.do_preview, self)
        self.preview_button.setToolTip(
            _('Display the details of your transactions before signing it.'))
        self.send_button = EnterButton(_("Send"), self.do_send, self)
        if self._main_window.network is None:
            self.send_button.setEnabled(False)
            self.send_button.setToolTip(_('You are using ElectrumSV in offline mode; restart '
                                          'ElectrumSV if you want to get connected'))
        self.send_button.setVisible(not self._account.is_watching_only())
        self.clear_button = EnterButton(_("Clear"), self.clear, self)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self.clear_button)
        buttons.addWidget(self.preview_button)
        buttons.addWidget(self.send_button)
        buttons.addStretch(1)
        grid.addLayout(buttons, 6, 0, 1, -1)

        self.amount_e.shortcut.connect(self.spend_max)
        self.payto_e.textChanged.connect(self.update_fee)
        self.amount_e.textEdited.connect(self.update_fee)

        def reset_max(t) -> None:
            self.is_max = False
            self.max_button.setEnabled(not bool(t))
        self.amount_e.textEdited.connect(reset_max)
        self.fiat_send_e.textEdited.connect(reset_max)

        def entry_changed() -> None:
            text = ""
            if self.not_enough_funds:
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

        self.amount_e.textChanged.connect(entry_changed)

        self.invoices_label = QLabel(_('Invoices'), self)
        self.invoice_list = InvoiceList(self, self._main_window)

        vbox0 = QVBoxLayout()
        vbox0.addLayout(grid)
        hbox = QHBoxLayout()
        hbox.addLayout(vbox0)

        vbox = QVBoxLayout(self)
        vbox.addLayout(hbox)
        vbox.addStretch(1)
        vbox.addWidget(self.invoices_label)
        vbox.addWidget(self.invoice_list)
        vbox.setStretchFactor(self.invoice_list, 1000)

        self.searchable_list = self.invoice_list

        return vbox

    def lock_amount(self, flag: bool) -> None:
        self.amount_e.setFrozen(flag)
        self.max_button.setEnabled(not flag)

    def spend_max(self) -> None:
        self.is_max = True
        self.do_update_fee()

    def clear(self) -> None:
        self.is_max = False
        self.not_enough_funds = False
        self.payment_request = None
        self.payto_e.is_pr = False

        # TODO: Clean up this with direct clears on widgets so it's not incomprehensible magic.
        edit_fields = []
        edit_fields.extend(self.findChildren(QPlainTextEdit))
        edit_fields.extend(self.findChildren(QLineEdit))
        for edit_field in edit_fields:
            # TODO: Does this work with refresh given the ' ' refresh note in some edit.
            edit_field.setText('')
            edit_field.setFrozen(False)

        for tree in self.findChildren(QTreeView):
            tree.clear()

        self.max_button.setDisabled(False)
        self.set_pay_from([])

        # TODO: Revisit what this does.
        self._main_window.update_status_bar()

    def update_fee(self) -> None:
        self.require_fee_update = True

    def set_pay_from(self, coins: List[UTXO]) -> None:
        self.pay_from = list(coins)
        self.redraw_from_list()

    def _on_from_list_menu_remove(self, item: QTreeWidgetItem) -> None:
        i = self.from_list.indexOfTopLevelItem(item)
        self.pay_from.pop(i)
        self.redraw_from_list()
        self.update_fee()

    def from_list_menu(self, position) -> None:
        item = self.from_list.itemAt(position)
        menu = QMenu()
        menu.addAction(_("Remove"), lambda: self._on_from_list_menu_remove(item))
        menu.exec_(self.from_list.viewport().mapToGlobal(position))

    def redraw_from_list(self) -> None:
        self.from_list.clear()
        self.from_label.setHidden(len(self.pay_from) == 0)
        self.from_list.setHidden(len(self.pay_from) == 0)

        def format_utxo(utxo: UTXO) -> str:
            h = hash_to_hex_str(utxo.tx_hash)
            return '{}...{}:{:d}\t{}'.format(h[0:10], h[-10:], utxo.out_index, utxo.address)

        for utxo in self.pay_from:
            self.from_list.addTopLevelItem(QTreeWidgetItem(
                [format_utxo(utxo), app_state.format_amount(utxo.value)]))

        update_fixed_tree_height(self.from_list)

    def on_timer_action(self) -> None:
        if self.require_fee_update:
            self.do_update_fee()
            self.require_fee_update = False

    def do_update_fee(self) -> None:
        '''Recalculate the fee.  If the fee was manually input, retain it, but
        still build the TX to see if there are enough funds.
        '''
        amount = all if self.is_max else self.amount_e.get_amount()
        if amount is None:
            self.not_enough_funds = False
            self._main_window.statusBar().showMessage('')
        else:
            fee = None
            outputs = self.payto_e.get_outputs(self.is_max)
            if not outputs:
                output_script = self.payto_e.get_payee_script()
                if output_script is None:
                    output_script = self._account.get_dummy_script_template().to_script()
                outputs = [XTxOutput(amount, output_script)]
            try:
                tx = self._account.make_unsigned_transaction(
                    self.get_coins(self._account), outputs, self._main_window.config, fee)
                self.not_enough_funds = False
            except NotEnoughFunds:
                self.not_enough_funds = True
                return
            except Exception:
                self._logger.exception("transaction failure")
                return

            if self.is_max:
                amount = tx.output_value()
                self.amount_e.setAmount(amount)

    def do_preview(self) -> None:
        self.do_send(preview=True)

    def do_send(self, preview: bool=False) -> None:
        dialogs.show_named('think-before-sending')

        r = self._read()
        if not r:
            return

        outputs, fee, tx_desc, coins = r
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

        amount = tx.output_value() if self.is_max else sum(output.value for output in outputs)
        fee = tx.get_fee()

        if preview:
            self._main_window.show_transaction(self._account, tx, tx_desc)
            return

        # confirmation dialog
        msg = [
            _("Amount to be sent") + ": " + app_state.format_amount_and_units(amount),
            _("Mining fee") + ": " + app_state.format_amount_and_units(fee),
        ]

        if fee < round(tx.estimated_size() * 0.5):
            msg.append(_('Warning') + ': ' +
                       _('The fee is less than 500 sats/kb.  '
                         'It may take a very long time to confirm.'))

        msg.append("")
        msg.append(_("Enter your password to proceed"))
        password = self._main_window.password_dialog('\n'.join(msg))
        if not password:
            return

        def sign_done(success: bool) -> None:
            if success:
                if not tx.is_complete():
                    self._main_window.show_transaction(self._account, tx)
                    self.clear()
                else:
                    self._main_window.broadcast_transaction(self._account, tx, tx_desc)
        self._main_window.sign_tx_with_password(tx, sign_done, password)

    def _read(self) -> Tuple[List[XTxOutput], Optional[int], str, List[UTXO]]:
        isInvoice = False

        if self.payment_request and self.payment_request.has_expired():
            self._main_window.show_error(_('Payment request has expired'))
            return
        label = self.message_e.text()

        outputs: List[XTxOutput]
        if self.payment_request:
            isInvoice = True
            outputs = self.payment_request.get_outputs()
        else:
            errors = self.payto_e.get_errors()
            if errors:
                self._main_window.show_warning(_("Invalid lines found:") + "\n\n" +
                    '\n'.join([ _("Line #") + str(x[0]+1) +": "+ x[1] for x in errors]))
                return
            outputs = self.payto_e.get_outputs(self.is_max)

        if not outputs:
            self._main_window.show_error(_('No outputs'))
            return

        if any(output.value is None for output in outputs):
            self._main_window.show_error(_('Invalid Amount'))
            return

        fee = None
        coins = self.get_coins(isInvoice)
        return outputs, fee, label, coins

    def get_coins(self, isInvoice=False) -> List[UTXO]:
        if self.pay_from:
            return self.pay_from
        return self._account.get_spendable_coins(None, self._main_window.config, isInvoice)

    def maybe_send_payment_request(self, tx: Transaction) -> bool:
        pr = self.payment_request
        if pr:
            if pr.has_expired():
                pr.error = _("The payment request has expired")
                self.payment_request_error_signal.emit()
                return False

            if not pr.send_payment(self._account, str(tx)):
                self.payment_request_error_signal.emit()
                return False

            self._account.invoices.set_paid(pr, tx.txid())
            self._account.invoices.save()
            self.payment_request = None
            # On success we broadcast as well, but it is assumed that the merchant also
            # broadcasts.
        return True

    def prepare_for_payment_request(self) -> None:
        self.payto_e.is_pr = True
        for e in [self.payto_e, self.amount_e, self.message_e]:
            e.setFrozen(True)
        self.max_button.setDisabled(True)
        self.payto_e.setText(_("please wait..."))

    def on_payment_request(self, request: PaymentRequest) -> None:
        self.payment_request = request
        self.payment_request_ok_signal.emit()

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
            self.payto_e.setText(address)
        if bip276_text:
            self.payto_e.setText(bip276_text, True)
        if message:
            self.message_e.setText(message)
        if amount:
            self.amount_e.setAmount(amount)
            self.amount_e.textEdited.emit("")

    def payment_request_ok(self) -> None:
        pr = self.payment_request
        key = self._account.invoices.add(pr)
        status = self._account.invoices.get_status(key)
        self.invoice_list.update()
        if status == PaymentState.PAID:
            self._main_window.show_message("invoice already paid")
            self.clear()
            self.payment_request = None
            return
        self.payto_e.is_pr = True
        if not pr.has_expired():
            self.payto_e.set_validated()
        else:
            self.payto_e.set_expired()
        self.payto_e.setText(pr.get_requestor())
        self.amount_e.setText(format_satoshis_plain(pr.get_amount(), app_state.decimal_point))
        self.message_e.setText(pr.get_memo())
        # signal to set fee
        self.amount_e.textEdited.emit("")

    def payment_request_error(self) -> None:
        self._main_window.show_message(self.payment_request.error)
        self.payment_request = None
        self.clear()

    def get_bsv_edits(self) -> List[BTCAmountEdit]:
        # Used to apply changes like base unit changes to all applicable edit fields.
        return [ self.amount_e ]

    def update_for_fx_quotes(self) -> None:
        edit = self.fiat_send_e if self.fiat_send_e.is_last_edited else self.amount_e
        edit.textEdited.emit(edit.text())

    def paytomany(self) -> None:
        self.payto_e.paytomany()
        msg = '\n'.join([
            _('Enter a list of outputs in the \'Pay to\' field.'),
            _('One output per line.'),
            _('Format: address, amount'),
            _('You may load a CSV file using the file icon.')
        ])
        self._main_window.show_message(msg, title=_('Pay to many'))

    def import_invoices(self) -> None:
        self.invoice_list.import_invoices(self._account)

    def update_widgets(self) -> None:
        self.invoice_list.update()

    def set_fiat_ccy_enabled(self, flag: bool) -> None:
        self.fiat_send_e.setVisible(flag)
