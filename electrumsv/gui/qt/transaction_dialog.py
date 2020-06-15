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

from collections import namedtuple
import copy
import datetime
import json
from typing import Optional, Set, Tuple

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QBrush, QCursor, QFont, QTextCharFormat
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QTextEdit, QToolTip
)

from bitcoinx import hash_to_hex_str, MissingHeader

from electrumsv.app_state import app_state
from electrumsv.bitcoin import base_encode
from electrumsv.constants import ScriptType, TxFlags
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.platform import platform
from electrumsv.transaction import tx_output_to_display_text, Transaction, XTxOutput
from electrumsv.wallet import AbstractAccount
from .util import (Buttons, ButtonsLineEdit, ColorScheme, FormSectionWidget, MessageBoxMixin,
    read_QIcon)


logger = logs.get_logger("tx-dialog")

TxInfo = namedtuple('TxInfo', 'hash status label can_broadcast amount '
                    'fee height conf timestamp')

class TxDialog(QDialog, MessageBoxMixin):
    def __init__(self, account: AbstractAccount, tx, main_window: 'ElectrumWindow',
            desc: Optional[str], prompt_if_unsaved: bool) -> None:
        '''Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        '''
        # We want to be a top-level window
        QDialog.__init__(self, parent=None, flags=Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)
        # Take a copy; it might get updated in the main window by the FX thread.  If this
        # happens during or after a long sign operation the signatures are lost.
        self.tx = copy.deepcopy(tx)
        if desc is not None:
            self.tx.description = desc
        self._tx_hash = tx.hash()

        self._main_window = main_window
        self._wallet = main_window._wallet
        self._account = account
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.monospace_font = QFont(platform.monospace_font)

        self.setMinimumWidth(1000)
        self.setWindowTitle(_("Transaction"))

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

        self.add_io(vbox)

        self.sign_button = b = QPushButton(_("Sign"))
        b.clicked.connect(self.sign)

        self.broadcast_button = b = QPushButton(_("Broadcast"))
        b.clicked.connect(self.do_broadcast)

        self.save_button = b = QPushButton(_("Save"))
        b.clicked.connect(self.save)

        self.cancel_button = b = QPushButton(_("Close"))
        b.clicked.connect(self.close)
        b.setDefault(True)

        self.qr_button = b = QPushButton()
        b.setIcon(read_QIcon("qrcode.png"))
        b.clicked.connect(self.show_qr)

        self.copy_button = QPushButton(_("Copy"))
        self.copy_button.clicked.connect(self.copy_tx_to_clipboard)

        self.cosigner_button = b = QPushButton(_("Send to cosigner"))
        b.clicked.connect(self.cosigner_send)

        # Action buttons
        self.buttons = [self.cosigner_button, self.sign_button, self.broadcast_button,
                        self.cancel_button]
        # Transaction sharing buttons
        self.sharing_buttons = [self.copy_button, self.qr_button, self.save_button]

        hbox = QHBoxLayout()
        hbox.addLayout(Buttons(*self.sharing_buttons))
        hbox.addStretch(1)
        hbox.addLayout(Buttons(*self.buttons))
        vbox.addLayout(hbox)
        self.update()

        # connect slots so we update in realtime as blocks come in, etc
        main_window.history_updated_signal.connect(self.update_tx_if_in_wallet)
        main_window.network_signal.connect(self.got_verified_tx)
        main_window.transaction_added_signal.connect(self._on_transaction_added)

    def _validate_event(self, wallet_path: str, account_id: int) -> bool:
        if account_id != self._account.get_id():
            return False
        if wallet_path != self._wallet.get_storage_path():
            return False
        return True

    def _on_transaction_added(self, wallet_path: str, account_id: int, tx_hash: bytes) -> None:
        if not self._validate_event(wallet_path, account_id):
            return

        # This will happen when the partially signed transaction is fully signed.
        if tx_hash == self._tx_hash:
            self.update()

    def cosigner_send(self) -> None:
        app_state.app.cosigner_pool.do_send(self._main_window, self._account, self.tx)

    def copy_tx_to_clipboard(self) -> None:
        self._main_window.app.clipboard().setText(str(self.tx))

    def _on_click_show_tx_hash_qr(self) -> None:
        self._main_window.show_qrcode(str(self.tx_hash_e.text()), 'Transaction ID', parent=self)

    def _on_click_copy_tx_id(self) -> None:
        app_state.app.clipboard().setText(hash_to_hex_str(self._tx_hash))
        QToolTip.showText(QCursor.pos(), _("Transaction ID copied to clipboard"), self)

    def got_verified_tx(self, event, args):
        if (event == 'verified' and args[0] == self._wallet.get_storage_path()
                and args[1] == self.tx.hash()):
            self.update()

    def update_tx_if_in_wallet(self) -> None:
        tx_hash = self.tx.hash()
        if tx_hash and self._account.has_received_transaction(tx_hash):
            self.update()

    def do_broadcast(self) -> None:
        self._main_window.broadcast_transaction(self._account, self.tx, self.tx.description,
            window=self)
        self.saved = True
        self.update()

    def ok_to_close(self) -> bool:
        if self.prompt_if_unsaved and not self.saved:
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

    def show_qr(self) -> None:
        text = base_encode(self.tx.to_bytes(), base=43)
        try:
            self._main_window.show_qrcode(text, 'Transaction', parent=self)
        except Exception as e:
            self.show_message(str(e))

    def sign(self) -> None:
        def sign_done(success: bool) -> None:
            if success:
                # If the signing was successful the hash will have changed.
                self._tx_hash = self.tx.hash()
                self.prompt_if_unsaved = True
                # If the signature(s) from this wallet complete the transaction, then it is
                # effectively saved in the local transactions list.
                self.saved = self.tx.is_complete()
            self.update()
            self._main_window.pop_top_level_window(self)

        self.sign_button.setDisabled(True)
        self._main_window.push_top_level_window(self)
        self._main_window.sign_tx(self.tx, sign_done, window=self)
        if not self.tx.is_complete():
            self.sign_button.setDisabled(False)

    def save(self) -> None:
        if self.tx.is_complete():
            name = 'signed_%s.txn' % (self.tx.txid()[0:8])
        else:
            name = 'unsigned.txn'
        fileName = self._main_window.getSaveFileName(
            _("Select where to save your signed transaction"), name, "*.txn")
        if fileName:
            tx_dict = self.tx.to_dict()
            with open(fileName, "w+") as f:
                f.write(json.dumps(tx_dict, indent=4) + '\n')
            self.show_message(_("Transaction saved successfully"))
            self.saved = True

    def update(self) -> None:
        base_unit = app_state.base_unit()
        format_amount = self._main_window.format_amount
        tx_info = self.get_tx_info(self.tx)
        tx_info_fee = tx_info.fee

        size = self.tx.size()
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
                # Try and compute fee. We don't always have 'value' in
                # all the inputs though. :/
                tx_info_fee = self.tx.get_fee()
            except KeyError: # Value key missing from an input
                pass
            if tx_info_fee < 0:
                tx_info_fee = None
        if self.tx.description is None:
            self.tx_desc.hide()
        else:
            self.tx_desc.setText(self.tx.description)
            self.tx_desc.show()
        self.status_label.setText(tx_info.status)

        if tx_info.timestamp:
            time_str = datetime.datetime.fromtimestamp(
                tx_info.timestamp).isoformat(' ')[:-3]
            self.date_label.setText(time_str)
            self.date_label.show()
        else:
            self.date_label.hide()
        if tx_info.amount is None:
            amount_str = _("Transaction unrelated to your wallet")
        elif tx_info.amount > 0:
            amount_str = '{} {} {}'.format(_("Received") +" ",
                                           format_amount(tx_info.amount),
                                           base_unit)
        else:
            amount_str = '{} {} {}'.format(_("Sent") +" ",
                                           format_amount(-tx_info.amount),
                                           base_unit)
        size_str = '%d bytes'% size
        if tx_info_fee is not None:
            fee_amount = '{} {}'.format(format_amount(tx_info_fee), base_unit)
        else:
            fee_amount = _('unknown')
        fee_str = '{}'.format(fee_amount)
        if tx_info_fee is not None:
            fee_str += ' ({}) '.format(self._main_window.format_fee_rate(
                tx_info_fee / size * 1000))
        self.amount_label.setText(amount_str)
        self.fee_label.setText(fee_str)
        self.size_label.setText(size_str)

        # Cosigner button
        visible = app_state.app.cosigner_pool.show_send_to_cosigner_button(self._main_window,
            self._account, self.tx)
        self.cosigner_button.setVisible(visible)

    def add_io(self, vbox: QVBoxLayout) -> None:
        vbox.addWidget(QLabel(_("Inputs") + ' (%d)'%len(self.tx.inputs)))

        i_text = QTextEdit()
        i_text.setFont(self.monospace_font)
        i_text.setReadOnly(True)

        vbox.addWidget(i_text)
        vbox.addWidget(QLabel(_("Outputs") + ' (%d)'%len(self.tx.outputs)))
        o_text = QTextEdit()
        o_text.setFont(self.monospace_font)
        o_text.setReadOnly(True)
        vbox.addWidget(o_text)
        self.update_io(i_text, o_text)

    def update_io(self, i_text: QTextEdit, o_text: QTextEdit):
        ext = QTextCharFormat()
        rec = QTextCharFormat()
        rec.setBackground(QBrush(ColorScheme.GREEN.as_color(background=True)))
        rec.setToolTip(_("Wallet receive key"))
        # chg = QTextCharFormat()
        # chg.setBackground(QBrush(QColor("yellow")))
        # chg.setToolTip(_("Wallet change key"))

        def verify_own_output(output: XTxOutput) -> bool:
            if not output.x_pubkeys:
                return False
            for x_pubkey in output.x_pubkeys:
                result = self._main_window._wallet.resolve_xpubkey(x_pubkey)
                if result is not None:
                    account, keyinstance_id = result
                    return account.get_script_for_id(keyinstance_id) == output.script_pubkey
            return False

        known_txos: Set[Tuple[bytes, int]]
        if self._account is None:
            known_txos = set()
        else:
            known_txos = set(self._account._utxos) | set(self._account._stxos)

        def text_format(utxo_key: Tuple[bytes, int]) -> QTextCharFormat:
            nonlocal known_txos
            return rec if utxo_key in known_txos else ext

        def format_amount(amt: int) -> str:
            return self._main_window.format_amount(amt, whitespaces = True)

        i_text.clear()
        cursor = i_text.textCursor()
        for txin in self.tx.inputs:
            if txin.is_coinbase():
                cursor.insertText('coinbase')
            else:
                prev_hash_hex = hash_to_hex_str(txin.prev_hash)
                cursor.insertText(f'{prev_hash_hex}:{txin.prev_idx:<6d}', ext)
                txo_key = (txin.prev_hash, txin.prev_idx)
                if txo_key in known_txos:
                    txo_text = _("Mine")
                else:
                    txo_text = _("Unknown")
                cursor.insertText(txo_text, text_format(txo_key))
                if txin.value is not None:
                    cursor.insertText(format_amount(txin.value), ext)
            cursor.insertBlock()

        o_text.clear()
        cursor = o_text.textCursor()
        tx_hash: bytes = self.tx.hash()
        for tx_index, tx_output in enumerate(self.tx.outputs):
            text, kind = tx_output_to_display_text(tx_output)

            out_format = ext
            if verify_own_output(tx_output):
                out_format = rec
            elif (self._tx_hash, tx_index) in known_txos:
                out_format = rec
            cursor.insertText(text, out_format)

            if len(text) > 42: # for long outputs, make a linebreak.
                cursor.insertBlock()
                text = '\u21b3'
                cursor.insertText(text, ext)
            # insert enough spaces until column 43, to line up amounts
            cursor.insertText(' '*(43 - len(text)), ext)
            cursor.insertText(format_amount(tx_output.value), ext)
            cursor.insertBlock()

    # Only called from the history ui dialog.
    def get_tx_info(self, tx: Transaction) -> TxInfo:
        value_delta = 0
        can_broadcast = False
        label = ''
        fee = height = conf = timestamp = None
        tx_hash = tx.hash()
        if tx.is_complete():
            metadata = self._wallet._transaction_cache.get_metadata(tx_hash)
            if metadata is not None:
                fee = metadata.fee
            if self._account is not None:
                label = self._account.get_transaction_label(tx_hash)
                value_delta = self._account.get_transaction_delta(tx_hash)
            if value_delta is None:
                # When the transaction is fully signed and updated before the delta changes
                # are committed to the database (pending write).
                value_delta = 0
            if self._account and self._account.has_received_transaction(tx_hash):
                entry_flags = self._wallet._transaction_cache.get_flags(tx_hash)
                if (entry_flags & TxFlags.StateSettled
                        or entry_flags & TxFlags.StateCleared and metadata.height > 0):
                    chain = app_state.headers.longest_chain()
                    try:
                        header = app_state.headers.header_at_height(chain, metadata.height)
                        timestamp = header.timestamp
                    except MissingHeader:
                        pass

                    if entry_flags & TxFlags.StateSettled:
                        height = metadata.height
                        conf = max(self._wallet.get_local_height() - height + 1, 0)
                        status = _("{:,d} confirmations (in block {:,d})"
                            ).format(conf, height)
                    else:
                        status = _('Not verified')
                else:
                    status = _('Unconfirmed')
            else:
                status = _("Signed")
                can_broadcast = self._wallet._network is not None
        else:
            for input in tx.inputs:
                value_delta -= input.value
            for output in tx.outputs:
                # If we know what type of script it is, we sign it's spend (or co-sign it).
                if output.script_type != ScriptType.NONE:
                    value_delta += output.value

            s, r = tx.signature_count()
            status = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        if value_delta < 0:
            if fee is not None:
                amount = value_delta + fee
            else:
                amount = value_delta
        elif value_delta > 0:
            amount = value_delta
        else:
            amount = None

        return TxInfo(tx_hash, status, label, can_broadcast, amount, fee,
                      height, conf, timestamp)
