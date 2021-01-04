#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

import concurrent
import copy
import datetime
import enum
from functools import partial
import gzip
import json
import math
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Set, Tuple
import weakref
import webbrowser

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QBrush, QCursor, QFont
from PyQt5.QtWidgets import (QDialog, QLabel, QMenu, QPushButton, QHBoxLayout,
    QToolTip, QTreeWidgetItem, QVBoxLayout, QWidget)

from bitcoinx import hash_to_hex_str, MissingHeader, Unknown_Output

from electrumsv.app_state import app_state
from electrumsv.bitcoin import base_encode, script_bytes_to_asm
from electrumsv.constants import CHANGE_SUBPATH, RECEIVING_SUBPATH, ScriptType, TxFlags, \
    TransactionOutputFlag
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.paymentrequest import PaymentRequest
from electrumsv.platform import platform
from electrumsv.services.coins import CoinService
from electrumsv.transaction import (Transaction, TxFileExtensions, TxSerialisationFormat,
    tx_output_to_display_text, XTxOutput)
from electrumsv.types import TxoKeyType, WaitingUpdateCallback
from electrumsv.wallet import AbstractAccount
from electrumsv.wallet_database.tables import MissingRowError
import electrumsv.web as web

from .constants import UIBroadcastSource
from .util import (Buttons, ButtonsLineEdit, ColorScheme, FormSectionWidget, MessageBox,
    MessageBoxMixin, MyTreeWidget, read_QIcon, WaitingDialog)


logger = logs.get_logger("tx-dialog")


class TxInfo(NamedTuple):
    hash: bytes
    state: TxFlags
    status: str
    label: str
    can_broadcast: bool
    amount: Optional[int]
    fee: Optional[int]
    height: Optional[int]
    conf: Optional[int]
    date_mined: Optional[int]
    date_created: Optional[int]


class InputColumns(enum.IntEnum):
    INDEX = 0
    ACCOUNT = 1
    SOURCE = 2
    AMOUNT = 3


class OutputColumns(enum.IntEnum):
    INDEX = 0
    ACCOUNT = 1
    DESTINATION = 2
    AMOUNT = 3


class Roles(enum.IntEnum):
    ACCOUNT_ID = Qt.UserRole
    TX_HASH = Qt.UserRole + 1
    IS_MINE = Qt.UserRole + 2
    KEY_ID = Qt.UserRole + 3


class InvalidAction(Exception):
    pass


class TxDialog(QDialog, MessageBoxMixin):
    copy_data_ready_signal = pyqtSignal(object, object)
    save_data_ready_signal = pyqtSignal(object, object)
    dummy_signal = pyqtSignal(object, object)

    def __init__(self, account: Optional[AbstractAccount], tx: Transaction,
            main_window: 'ElectrumWindow', prompt_if_unsaved: bool,
            payment_request: Optional[PaymentRequest]=None) -> None:
        '''Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        '''
        # We want to be a top-level window
        QDialog.__init__(self, parent=None, flags=Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)

        self.copy_data_ready_signal.connect(self._copy_transaction_ready)
        self.save_data_ready_signal.connect(self._save_transaction_ready)

        # Take a copy; it might get updated in the main window by the FX thread.  If this
        # happens during or after a long sign operation the signatures are lost.
        self.tx = copy.deepcopy(tx)
        self.tx.context = copy.deepcopy(tx.context)
        self._tx_hash = tx.hash()

        self._main_window = main_window
        self._wallet = main_window._wallet
        self._account = account
        self._account_id = account.get_id() if account is not None else None
        self._payment_request = payment_request
        self._coin_service = CoinService(self._wallet)
        self._prompt_if_unsaved = prompt_if_unsaved
        self._saved = False

        self.setMinimumWidth(1000)
        self.setWindowTitle(_("Transaction"))
        self._monospace_font = QFont(platform.monospace_font)

        self._change_brush = QBrush(ColorScheme.YELLOW.as_color(background=True))
        self._receiving_brush = QBrush(ColorScheme.GREEN.as_color(background=True))
        self._broken_brush = QBrush(ColorScheme.RED.as_color(background=True))

        form = FormSectionWidget()

        vbox = QVBoxLayout()
        vbox.addWidget(form)
        self.setLayout(vbox)

        self.tx_hash_e  = ButtonsLineEdit()
        self.tx_hash_e.addButton("qrcode.png",
            self._on_click_show_tx_hash_qr, _("Show as QR code"))
        self.tx_hash_e.addButton("copy.png",
            self._on_click_copy_tx_id, _("Copy to clipboard"))
        self.tx_hash_e.setReadOnly(True)
        form.add_row(_("Transaction ID"), self.tx_hash_e, True)

        self.tx_desc = QLabel()
        form.add_row(_("Description"), self.tx_desc)

        self.status_label = QLabel()
        form.add_row(_('Status'), self.status_label)

        self.date_label = QLabel()
        form.add_row(_("Date"), self.date_label)

        self.amount_label = QLabel()
        form.add_row(_("Amount"), self.amount_label)

        self.size_label = QLabel()
        form.add_row(_("Size"), self.size_label)

        self.fee_label = QLabel()
        form.add_row(_("Fee"), self.fee_label)

        if self.tx.locktime > 0:
            form.add_row(_("Lock time"), QLabel(str(self.tx.locktime)))

        self._add_io(vbox)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.qr_button = b = QPushButton()
        b.setIcon(read_QIcon("qrcode.png"))
        b.clicked.connect(self._show_qr)

        self._copy_menu = QMenu()
        self._copy_button = QPushButton(_("Copy"))
        self._copy_button.setMenu(self._copy_menu)

        self._save_menu = QMenu()
        self.save_button = QPushButton(_("Save"))
        self.save_button.setMenu(self._save_menu)

        self.cosigner_button = b = QPushButton(_("Send to cosigner"))
        b.clicked.connect(self.cosigner_send)

        # Action buttons
        self.buttons = [self.cosigner_button, self.sign_button, self.broadcast_button,
                        self.cancel_button]
        # Transaction sharing buttons
        self.sharing_buttons = [self._copy_button, self.qr_button, self.save_button]

        hbox = QHBoxLayout()
        hbox.addLayout(Buttons(*self.sharing_buttons))
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        vbox.addLayout(hbox)
        self.update()

        # connect slots so we update in realtime as blocks come in, etc
        main_window.history_updated_signal.connect(self.update_tx_if_in_wallet)
        main_window.network_signal.connect(self._on_transaction_verified)
        main_window.transaction_added_signal.connect(self._on_transaction_added)

    def _validate_account_event(self, account_ids: Set[int]) -> bool:
        return self._account_id in account_ids

    def _validate_application_event(self, wallet_path: str, account_id: int) -> bool:
        if wallet_path == self._main_window._wallet.get_storage_path():
            return self._validate_account_event({ account_id })
        return False

    def _on_transaction_added(self, tx_hash: bytes, tx: Transaction, account_ids: Set[int]) \
            -> None:
        if not self._validate_account_event(account_ids):
            return

        # This will happen when the partially signed transaction is fully signed.
        if tx_hash == self._tx_hash:
            self.update()

    def cosigner_send(self) -> None:
        app_state.app.cosigner_pool.do_send(self._main_window, self._account, self.tx)

    def _on_click_show_tx_hash_qr(self) -> None:
        self._main_window.show_qrcode(str(self.tx_hash_e.text()), 'Transaction ID', parent=self)

    def _on_click_copy_tx_id(self) -> None:
        app_state.app.clipboard().setText(hash_to_hex_str(self._tx_hash))
        QToolTip.showText(QCursor.pos(), _("Transaction ID copied to clipboard"), self)

    def _on_transaction_verified(self, event, args):
        if event == 'verified' and args[0] == self._tx_hash:
            self.update()

    def update_tx_if_in_wallet(self) -> None:
        if self._tx_hash and self._account.has_received_transaction(self._tx_hash):
            self.update()

    def do_broadcast(self) -> None:
        if not self._main_window.confirm_broadcast_transaction(self._tx_hash,
                UIBroadcastSource.TRANSACTION_DIALOG):
            return

        self._main_window.broadcast_transaction(self._account, self.tx, window=self)
        self._saved = True
        self.update()

    def ok_to_close(self) -> bool:
        if self._prompt_if_unsaved and not self._saved:
            return self.question(_('This transaction is not saved. Close anyway?'),
                title=_("Warning"))
        return True

    def __del__(self) -> None:
        logger.debug('TX dialog destroyed')

    def reject(self) -> None:
        # Invoked on user escape key
        if self.ok_to_close():
            super().reject()

    def closeEvent(self, event) -> None:
        # Invoked by user closing in window manager
        if self.ok_to_close():
            event.accept()
            self.accept()
        else:
            event.ignore()

    def _show_qr(self) -> None:
        if self.tx.is_complete():
            text = base_encode(self.tx.to_bytes(), base=43)
        else:
            data = self._tx_to_text().encode()
            data = gzip.compress(data)
            text = base_encode(data, base=43)

        try:
            self._main_window.show_qrcode(text, 'Transaction', parent=self)
        except Exception as e:
            self.show_message(str(e))

    def sign(self) -> None:
        def sign_done(success: bool) -> None:
            if success:
                # If the signing was successful the hash will have changed.
                self._tx_hash = self.tx.hash()
                self._prompt_if_unsaved = True
                # If the signature(s) from this wallet complete the transaction, then it is
                # effectively saved in the local transactions list.
                self._saved = self.tx.is_complete()

            self.update()
            self._main_window.pop_top_level_window(self)

        if self._payment_request is not None:
            self.tx.context.invoice_id = self._payment_request.get_id()

        self.sign_button.setDisabled(True)
        self._main_window.push_top_level_window(self)
        self._main_window.sign_tx(self.tx, sign_done, window=self, tx_context=self.tx.context)
        if not self.tx.is_complete():
            self.sign_button.setDisabled(False)

    def _tx_to_text(self, prefer_readable: bool=False) -> str:
        assert not self.tx.is_complete(), "complete transactions are directly encoded from raw"

        tx_dict = self.tx.to_dict()
        if prefer_readable:
            return json.dumps(tx_dict, indent=4) + '\n'
        return json.dumps(tx_dict)

    def update(self) -> None:
        base_unit = app_state.base_unit()
        format_amount = app_state.format_amount
        tx_info = self._get_tx_info(self.tx)
        tx_info_fee = tx_info.fee

        self.broadcast_button.setEnabled(tx_info.can_broadcast)
        if self._main_window.network is None:
            self.broadcast_button.setEnabled(False)
            self.broadcast_button.setToolTip(_('You are using ElectrumSV in offline mode; restart '
                                               'ElectrumSV if you want to get connected'))

        can_sign = not self.tx.is_complete() and self._account.can_sign(self.tx)
        self.sign_button.setEnabled(can_sign)

        self._tx_hash = tx_info.hash
        tx_id = hash_to_hex_str(tx_info.hash)
        self.tx_hash_e.setText(tx_id)

        if tx_info_fee is None:
            try:
                # Try and compute fee. We don't always have 'value' in all the inputs though. :/
                tx_info_fee = self.tx.get_fee()
            except TypeError: # At least one of the XTxInputs does not have an attached value.
                pass
            else:
                if tx_info_fee < 0:
                    tx_info_fee = None

        if self.tx.context.description is None:
            self.tx_desc.hide()
        else:
            self.tx_desc.setText(self.tx.context.description)
            self.tx_desc.show()
        self.status_label.setText(tx_info.status)

        time_str = ""
        if tx_info.date_mined:
            time_str = datetime.datetime.fromtimestamp(tx_info.date_mined).isoformat(' ')[:-3]
            time_str += "\n"
        if tx_info.date_created:
            time_str += (datetime.datetime.fromtimestamp(tx_info.date_created).isoformat(' ')[:-3] +
                " ("+ _("added to account") +")")

        self.date_label.setText(time_str)
        self.date_label.show()

        if tx_info.amount is None:
            amount_str = _("Unknown")
        elif math.isclose(tx_info.amount, 0, abs_tol=1e-9):
            amount_str = "No external payment"
        elif tx_info.amount > 0:
            amount_str = _("Received") +" "+ format_amount(tx_info.amount) +" " + base_unit
        else:
            amount_str = _("Sent") +" "+ format_amount(-tx_info.amount) +" "+ base_unit
        self.amount_label.setText(amount_str)

        size = self.tx.size()
        self.size_label.setText('%d bytes' % size)

        if tx_info_fee is not None:
            fee_amount = '{} {}'.format(format_amount(tx_info_fee), base_unit)
        else:
            fee_amount = _('Unknown')
        fee_str = '{}'.format(fee_amount)
        if tx_info_fee is not None:
            fee_str += ' ({}) '.format(self._main_window.format_fee_rate(tx_info_fee/size * 1000))
        self.fee_label.setText(fee_str)

        # Cosigner button
        visible = app_state.app.cosigner_pool.show_send_to_cosigner_button(self._main_window,
            self._account, self.tx)
        self.cosigner_button.setVisible(visible)

        # Copy options.
        self._copy_menu.clear()
        if self.tx.is_complete():
            self._copy_hex_menu = self._copy_menu.addAction(
                _("Transaction (hex)"),
                partial(self._copy_transaction, TxSerialisationFormat.HEX))
            if self._account:
                self._copy_extended_full_menu = self._copy_menu.addAction(
                    _("Transaction with proofs (JSON)"),
                    partial(self._copy_transaction, TxSerialisationFormat.JSON_WITH_PROOFS))
        else:
            self._copy_extended_basic_menu = self._copy_menu.addAction(
                _("Incomplete transaction (JSON)"),
                partial(self._copy_transaction, TxSerialisationFormat.JSON))
            if self._account:
                self._copy_extended_full_menu = self._copy_menu.addAction(
                    _("Incomplete transaction with proofs (JSON)"),
                    partial(self._copy_transaction, TxSerialisationFormat.JSON_WITH_PROOFS))

        # Save options.
        self._save_menu.clear()
        if self.tx.is_complete():
            self._save_raw_menu = self._save_menu.addAction(
                _("Transaction (raw)"),
                partial(self._save_transaction, TxSerialisationFormat.RAW))
            self._save_hex_menu = self._save_menu.addAction(
                _("Transaction (hex)"),
                partial(self._save_transaction, TxSerialisationFormat.HEX))
            if self._account:
                self._save_extended_full_menu = self._save_menu.addAction(
                    _("Transaction with proofs (JSON)"),
                    partial(self._save_transaction, TxSerialisationFormat.JSON_WITH_PROOFS))
        else:
            self._save_extended_basic_menu = self._save_menu.addAction(
                _("Incomplete transaction (JSON)"),
                partial(self._save_transaction, TxSerialisationFormat.JSON))
            if self._account:
                self._save_extended_full_menu = self._save_menu.addAction(
                    _("Incomplete transaction with proofs (JSON)"),
                    partial(self._save_transaction, TxSerialisationFormat.JSON_WITH_PROOFS))

    def _obtain_transaction_data(self, format: TxSerialisationFormat,
            completion_signal: Optional[pyqtSignal], done_signal: pyqtSignal,
            completion_text: str) -> None:
        tx_data = self.tx.to_format(format)
        if not isinstance(tx_data, dict):
            # This is not ideal, but it covers both bases.
            if completion_signal is not None:
                completion_signal.emit(format, tx_data)
            done_signal.emit(format, tx_data)
            return

        steps = self._account.estimate_extend_serialised_transaction_steps(format, self.tx,
            tx_data)

        # The done callbacks should happen in the context of the GUI thread.
        def on_done(weakwindow: 'ElectrumWindow', future: concurrent.futures.Future) -> None:
            nonlocal format, done_signal
            try:
                data = future.result()
            except concurrent.futures.CancelledError:
                done_signal.emit(format, None)
            except Exception as exc:
                weakwindow.on_exception(exc)
            else:
                done_signal.emit(format, data)

        title = _("Obtaining transaction data")
        func = partial(self._obtain_transaction_data_worker, format, tx_data, completion_signal,
            completion_text)
        weakwindow = weakref.proxy(self._main_window)
        WaitingDialog(self, title, func, on_done=partial(on_done, weakwindow),
            progress_steps=steps, allow_cancel=True, close_delay=5)

    def _obtain_transaction_data_worker(self, format: TxSerialisationFormat,
            tx_data: Dict[str, Any], completion_signal: Optional[pyqtSignal], completion_text: str,
            update_cb: Optional[WaitingUpdateCallback]=None) -> Optional[Dict[str, Any]]:
        """ This wraps the worker code that runs in the threaded task by the waiting dialog. """
        data = self._account.extend_serialised_transaction(format, self.tx, tx_data, update_cb)
        if data is not None:
            if completion_signal is not None:
                completion_signal.emit(format, data)
            update_cb(False, completion_text)
        return data

    def _copy_transaction(self, format: TxSerialisationFormat) -> None:
        # Completion: The dialog is still open and they should be able to use the copied data.
        # Done: The dialog is closed, we do not need to do anything else.
        self._obtain_transaction_data(format, self.copy_data_ready_signal, self.dummy_signal,
            _("Data copied to clipboard"))

    def _copy_transaction_ready(self, format: TxSerialisationFormat,
            tx_data: Optional[Dict[str, Any]]=None) -> None:
        if tx_data is None:
            logger.debug("_copy_transaction_ready aborted")
            return

        # NOTE(rt12) Will not be RAW, as we do not support non-textual clipboard data at this time
        # and we do not offer it as a menu option anyway for copying because of this.
        tx_text: str = tx_data if type(tx_data) is str else json.dumps(tx_data)
        self._main_window.app.clipboard().setText(tx_text)

    def _save_transaction(self, format: TxSerialisationFormat) -> None:
        # Completion: The dialog is still open and it is not the right time to save.
        # Done: The dialog is closed, give them the option to save then.
        self._obtain_transaction_data(format, None, self.save_data_ready_signal,
            _("Data ready to save"))

    def _save_transaction_ready(self, format: TxSerialisationFormat,
            tx_data: Optional[Dict[str, Any]]=None) -> None:
        if tx_data is None:
            logger.debug("_copy_transaction_ready aborted")
            return

        suffix_text = TxFileExtensions[format]
        if self.tx.is_complete():
            tx_short_id = self.tx.txid()[0:8]
            name = f'signed_{tx_short_id}.{suffix_text}'
        else:
            tx_short_id = datetime.datetime.now().strftime("%Y%m%d_%H%M")
            name = f'incomplete_{tx_short_id}.{suffix_text}'
        fileName = self._main_window.getSaveFileName(_("Select where to save your transaction"),
            name, filter=f"*.{suffix_text}", parent=self)
        if fileName:
            mode = "wb" if format == TxSerialisationFormat.RAW else "w"
            write_data = json.dumps(tx_data) if type(tx_data) is dict else tx_data
            with open(fileName, mode) as f:
                f.write(write_data)
            self.show_message(_("Transaction saved successfully"))
            self._saved = True

    def _add_io(self, vbox: QVBoxLayout) -> None:
        self._i_table = InputTreeWidget(self, self._main_window)
        self._o_table = OutputTreeWidget(self, self._main_window)

        self._spent_value_label = QLabel()
        input_header_layout = QHBoxLayout()
        input_header_layout.addWidget(QLabel(_("Inputs") + ' (%d)' % len(self.tx.inputs)))
        input_header_layout.addStretch(1)
        input_header_layout.addWidget(self._spent_value_label)

        self._received_value_label = QLabel()
        output_header_layout = QHBoxLayout()
        output_header_layout.addWidget(QLabel(_("Outputs") + ' (%d)' % len(self.tx.outputs)))
        output_header_layout.addStretch(1)
        output_header_layout.addWidget(self._received_value_label)

        vbox.addLayout(input_header_layout)
        vbox.addWidget(self._i_table)
        vbox.addLayout(output_header_layout)
        vbox.addWidget(self._o_table)

        self._update_io(self._i_table, self._o_table)

    def _update_io(self, i_table: MyTreeWidget, o_table: MyTreeWidget) -> None:
        def get_xtxoutput_account(output: XTxOutput) -> Tuple[Optional[AbstractAccount], int]:
            if output.x_pubkeys:
                for x_pubkey in output.x_pubkeys:
                    result = self._main_window._wallet.resolve_xpubkey(x_pubkey)
                    if result is not None:
                        account, keyinstance_id = result
                        if account.get_script_for_id(keyinstance_id) == output.script_pubkey:
                            return account, keyinstance_id
                        # TODO: Document when this happens
                        break
            return None, -1

        def get_keyinstance_id(account: AbstractAccount, txo_key: TxoKeyType) -> Optional[int]:
            utxo = account._utxos.get(txo_key)
            if utxo is not None:
                return utxo.keyinstance_id
            stxo_keyinstance_id = account._stxos.get(txo_key)
            if stxo_keyinstance_id is not None:
                return stxo_keyinstance_id
            return None

        def compare_key_path(account: AbstractAccount, keyinstance_id: int,
                leading_path: Sequence[int]) -> bool:
            key_path = account.get_derivation_path(keyinstance_id)
            return key_path is not None and key_path[:len(leading_path)] == leading_path

        def name_for_account(account: AbstractAccount) -> str:
            name = account.display_name()
            return f"{account.get_id()}: {name}"

        is_tx_complete = self.tx.is_complete()
        is_tx_known = self._account and self._account.have_transaction_data(self._tx_hash)

        prev_txos = self._coin_service.get_outputs(
            [ TxoKeyType(txin.prev_hash, txin.prev_idx) for txin in self.tx.inputs ])
        prev_txo_dict = { TxoKeyType(r.tx_hash, r.tx_index): r for r in prev_txos }
        self._spent_value_label.setText(_("Spent input value") +": "+
            app_state.format_amount(sum(r.value for r in prev_txos)))

        for tx_index, txin in enumerate(self.tx.inputs):
            account_name = ""
            source_text = ""
            amount_text = ""
            is_receiving = is_change = is_broken = False
            txo_key = TxoKeyType(txin.prev_hash, txin.prev_idx)

            if txin.is_coinbase():
                source_text = "<coinbase>"
            else:
                prev_hash_hex = hash_to_hex_str(txin.prev_hash)
                source_text = f"{prev_hash_hex}:{txin.prev_idx}"
                # There are only certain kinds of transactions that have values on the inputs,
                # likely deserialised incomplete transactions from cosigners. Others?
                value = txin.value
                if self._account is not None:
                    keyinstance_id = get_keyinstance_id(self._account, txo_key)
                    is_receiving = compare_key_path(self._account, keyinstance_id,
                        RECEIVING_SUBPATH)
                    is_change = compare_key_path(self._account, keyinstance_id, CHANGE_SUBPATH)
                    account_name = name_for_account(self._account)
                    prev_txo = prev_txo_dict.get(txo_key, None)
                    if prev_txo is not None and is_tx_complete:
                        value = prev_txo.value
                        if is_tx_known:
                            # The transaction has been added to the account.
                            is_broken = (prev_txo.flags & TransactionOutputFlag.IS_SPENT) == 0
                        else:
                            # The transaction was most likely loaded from external source and is
                            # being viewed but has not been added to the account.
                            is_broken = (prev_txo.flags & TransactionOutputFlag.IS_SPENT) != 0
                amount_text = app_state.format_amount(value, whitespaces=True)

            item = QTreeWidgetItem([ str(tx_index), account_name, source_text, amount_text ])
            item.setData(InputColumns.INDEX, Roles.TX_HASH, txin.prev_hash)
            item.setData(InputColumns.INDEX, Roles.IS_MINE, is_change or is_receiving)
            if is_receiving:
                item.setBackground(InputColumns.SOURCE, self._receiving_brush)
            if is_change:
                item.setBackground(InputColumns.SOURCE, self._change_brush)
            if is_broken:
                item.setBackground(InputColumns.SOURCE, self._broken_brush)
            item.setTextAlignment(InputColumns.AMOUNT, Qt.AlignRight | Qt.AlignVCenter)
            item.setFont(InputColumns.AMOUNT, self._monospace_font)
            i_table.addTopLevelItem(item)

        # TODO: Rewrite this to be lot simpler when we have better TXO management. At this time
        # we do not track UTXOs except when a transaction is known to the network as we rely on
        # the server state to map key usage to transactions or something. We need to completely
        # rewrite that and then rewrite this. Anyway, that is why signed tx outputs do not get
        # identified and colourised.

        received_value = 0
        for tx_index, tx_output in enumerate(self.tx.outputs):
            text, _kind = tx_output_to_display_text(tx_output)
            if isinstance(_kind, Unknown_Output):
                text = script_bytes_to_asm(tx_output.script_pubkey)

            # In the longer run we will have some form of abstraction for incomplete transactions
            # that maps where the keys come from, but for now we manually map them to the limited
            # key hierarchy that currently exists.
            xtxo_account, xtxo_keyinstance_id = get_xtxoutput_account(tx_output)
            accounts: List[AbstractAccount] = []
            if xtxo_account is not None:
                accounts.append(xtxo_account)
            if self._account is not None and xtxo_account is not self._account:
                accounts.append(self._account)

            account_id: Optional[int] = None
            account_name = ""
            keyinstance_id: Optional[int] = None
            is_receiving = is_change = False
            txo_key = TxoKeyType(self._tx_hash, tx_index)
            for account in accounts:
                if is_tx_complete:
                    keyinstance_id = get_keyinstance_id(account, txo_key)
                elif account is xtxo_account and xtxo_keyinstance_id != -1:
                    keyinstance_id = xtxo_keyinstance_id

                if keyinstance_id is not None:
                    account_id = account.get_id()
                    is_receiving = compare_key_path(account, keyinstance_id, RECEIVING_SUBPATH)
                    is_change = compare_key_path(account, keyinstance_id, CHANGE_SUBPATH)
                    account_name = name_for_account(account)
                    received_value += tx_output.value
                    break

            amount_text = app_state.format_amount(tx_output.value, whitespaces=True)

            item = QTreeWidgetItem([ str(tx_index), account_name, text, amount_text ])
            item.setData(OutputColumns.INDEX, Roles.IS_MINE, is_change or is_receiving)
            item.setData(OutputColumns.INDEX, Roles.ACCOUNT_ID, account_id)
            item.setData(OutputColumns.INDEX, Roles.KEY_ID, keyinstance_id)
            if is_receiving:
                item.setBackground(OutputColumns.DESTINATION, self._receiving_brush)
            if is_change:
                item.setBackground(OutputColumns.DESTINATION, self._change_brush)
            item.setTextAlignment(OutputColumns.AMOUNT, Qt.AlignRight | Qt.AlignVCenter)
            item.setFont(OutputColumns.AMOUNT, self._monospace_font)
            o_table.addTopLevelItem(item)

        self._received_value_label.setText(_("Received output value") +": "+
            app_state.format_amount(received_value))

    # Only called from the history ui dialog.
    def _get_tx_info(self, tx: Transaction) -> TxInfo:
        value_delta = 0
        can_broadcast = False
        label = ''
        fee = height = conf = date_created = date_mined = None
        state = TxFlags.Unset

        wallet = self._wallet
        if tx.is_complete():
            metadata = wallet._transaction_cache.get_metadata(self._tx_hash)
            if metadata is None:
                # The transaction is not known to the wallet.
                status = _("External signed transaction")
                state = TxFlags.StateReceived | TxFlags.StateSigned
                can_broadcast = wallet._network is not None
            else:
                date_created = metadata.date_added

                # It is possible the wallet has the transaction but it is not associated with
                # any accounts. We still need to factor that in.
                fee = metadata.fee

                if metadata.height is not None and metadata.height > 0:
                    chain = app_state.headers.longest_chain()
                    try:
                        header = app_state.headers.header_at_height(chain, metadata.height)
                        date_mined = header.timestamp
                    except MissingHeader:
                        pass

                label = wallet.get_transaction_label(self._tx_hash)

                state = wallet._transaction_cache.get_flags(self._tx_hash) & TxFlags.STATE_MASK
                if state & TxFlags.StateSettled:
                    height = metadata.height
                    conf = max(wallet.get_local_height() - height + 1, 0)
                    status = _("{:,d} confirmations (in block {:,d})").format(conf, height)
                elif state & TxFlags.StateCleared:
                    if metadata.height > 0:
                        status = _('Not verified')
                    else:
                        status = _('Unconfirmed')
                elif state & TxFlags.StateReceived:
                    status = _("Received")
                    can_broadcast = wallet._network is not None
                elif state & TxFlags.StateDispatched:
                    status = _("Dispatched")
                elif state & TxFlags.StateSigned:
                    status = _("Signed")
                    can_broadcast = wallet._network is not None
                else:
                    status = _('Unknown')

            account_deltas = wallet.get_transaction_deltas(self._tx_hash)
            value_delta = sum(row.total for row in account_deltas)
            # # It is possible that the wallet does not have the transaction.
            # if delta_result.match_count == 0:
            #     pass
            # else:
            #     value_delta += delta_result.total
        else:
            state = TxFlags.StateReceived

            # For now all inputs must come from the same account.
            for input in tx.inputs:
                value_delta -= input.value
            for output in tx.outputs:
                # If we know what type of script it is, we sign it's spend (or co-sign it).
                # We are sending to ourselves or we are receiving change.
                if output.script_type != ScriptType.NONE:
                    value_delta += output.value

            s, r = tx.signature_count()
            status = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        if value_delta < 0:
            if fee is not None:
                # We remove the fee as the user can work out the fee is part of the sum themselves.
                amount = value_delta + fee
            else:
                amount = value_delta
        elif value_delta > 0:
            amount = value_delta
        else:
            amount = None

        return TxInfo(self._tx_hash, state, status, label, can_broadcast, amount, fee, height,
            conf, date_mined, date_created)


class InputTreeWidget(MyTreeWidget):
    def __init__(self, parent: QWidget, main_window: 'ElectrumWindow') -> None:
        MyTreeWidget.__init__(self, parent, main_window, self._create_menu,
            [ _("Index"), _("Account"), _("Source"), _("Amount") ], InputColumns.SOURCE, [])

    def on_doubleclick(self, item: QTreeWidgetItem, column: int) -> None:
        if self.permit_edit(item, column):
            super(InputTreeWidget, self).on_doubleclick(item, column)
        else:
            tx_hash = item.data(InputColumns.INDEX, Roles.TX_HASH)
            self._show_other_transaction(tx_hash)

    def _create_menu(self, position) -> None:
        item = self.currentItem()
        if not item:
            return

        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()

        tx_hash = item.data(InputColumns.INDEX, Roles.TX_HASH)
        have_tx = self.parent()._account.have_transaction_data(tx_hash)

        tx_id = hash_to_hex_str(tx_hash)
        tx_URL = web.BE_URL(self._main_window.config, 'tx', tx_id)

        menu = QMenu()
        menu.addAction(_("Copy {}").format(column_title),
            lambda: self._main_window.app.clipboard().setText(column_data))
        details_menu = menu.addAction(_("Transaction details"),
            partial(self._show_other_transaction, tx_hash))
        details_menu.setEnabled(have_tx)
        if tx_URL:
            menu.addAction(_("View on block explorer"), lambda: webbrowser.open(tx_URL))
        menu.exec_(self.viewport().mapToGlobal(position))

    def _show_other_transaction(self, tx_hash: bytes) -> None:
        dialog = self.parent()
        account = dialog._account
        try:
            tx = account.get_transaction(tx_hash)
        except MissingRowError:
            MessageBox.show_error(_("This transaction is unrelated to your wallet."
                " For now use a blockchain explorer."))
        else:
            if tx is not None:
                self._main_window.show_transaction(account, tx)
            else:
                MessageBox.show_error(_("The data for this  transaction is not yet present in "
                    "your wallet. Please try again when it has been obtained from the network."))


class OutputTreeWidget(MyTreeWidget):
    def __init__(self, parent: QWidget, main_window: 'ElectrumWindow') -> None:
        MyTreeWidget.__init__(self, parent, main_window, self._create_menu,
            [ _("Index"), _("Account"), _("Destination"), _("Amount") ],
            OutputColumns.DESTINATION, [])

    def on_doubleclick(self, item: QTreeWidgetItem, column: int) -> None:
        if self.permit_edit(item, column):
            super(OutputTreeWidget, self).on_doubleclick(item, column)
        else:
            pass

    def _create_menu(self, position) -> None:
        item = self.currentItem()
        if not item:
            return

        column = self.currentColumn()
        column_title = self.headerItem().text(column)
        column_data = item.text(column).strip()

        is_mine = item.data(OutputColumns.INDEX, Roles.IS_MINE)

        menu = QMenu()
        menu.addAction(_("Copy {}").format(column_title),
            lambda: self._main_window.app.clipboard().setText(column_data))
        menu.exec_(self.viewport().mapToGlobal(position))

    def _show_other_transaction(self, tx_hash: bytes) -> None:
        dialog = self.parent()
        account = dialog._account
        tx = account.get_transaction(tx_hash)
        if tx is not None:
            self._main_window.show_transaction(account, tx)
        else:
            MessageBox.show_error(_("The full transaction is not yet present in your wallet."+
                " Please try again when it has been obtained from the network."))
