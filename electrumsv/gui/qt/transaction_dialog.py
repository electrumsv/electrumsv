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

import copy
import datetime
import json

from PyQt5.QtGui import QFont, QBrush, QTextCharFormat, QColor
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QTextEdit
)

from electrumsv.address import Address, PublicKey
from electrumsv.app_state import app_state
from electrumsv.bitcoin import base_encode
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.platform import platform
from electrumsv.util import bfh
from .util import MessageBoxMixin, ButtonsLineEdit, Buttons, ColorScheme, read_QIcon


logger = logs.get_logger("tx_dialog")


class TxDialog(QDialog, MessageBoxMixin):

    def __init__(self, tx, parent, desc, prompt_if_unsaved):
        '''Transactions in the wallet will show their description.
        Pass desc to give a description for txs not yet in the wallet.
        '''
        # We want to be a top-level window
        QDialog.__init__(self, parent=None)
        # Take a copy; it might get updated in the main window by the FX thread.  If this
        # happens during or after a long sign operation the signatures are lost.
        self.tx = copy.deepcopy(tx)
        self.tx.deserialize()
        self.main_window = parent
        self.wallet = parent.wallet
        self.prompt_if_unsaved = prompt_if_unsaved
        self.saved = False
        self.desc = desc
        self.monospace_font = QFont(platform.monospace_font)

        self.setMinimumWidth(750)
        self.setWindowTitle(_("Transaction"))

        vbox = QVBoxLayout()
        self.setLayout(vbox)

        vbox.addWidget(QLabel(_("Transaction ID:")))
        self.tx_hash_e  = ButtonsLineEdit()
        self.tx_hash_e.addButton("qrcode.png", self.show_tx_hash_qr, _("Show as QR code"))

        self.tx_hash_e.setReadOnly(True)
        vbox.addWidget(self.tx_hash_e)
        self.tx_desc = QLabel()
        vbox.addWidget(self.tx_desc)
        self.status_label = QLabel()
        vbox.addWidget(self.status_label)
        self.date_label = QLabel()
        vbox.addWidget(self.date_label)
        self.amount_label = QLabel()
        vbox.addWidget(self.amount_label)
        self.size_label = QLabel()
        vbox.addWidget(self.size_label)
        self.fee_label = QLabel()
        vbox.addWidget(self.fee_label)

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
        parent.history_updated_signal.connect(self.update_tx_if_in_wallet)
        parent.network_signal.connect(self.got_verified_tx)

    def cosigner_send(self):
        app_state.app.cosigner_pool.do_send(self.wallet, self.tx)

    def copy_tx_to_clipboard(self):
        self.main_window.app.clipboard().setText(str(self.tx))

    def show_tx_hash_qr(self):
        self.main_window.show_qrcode(str(self.tx_hash_e.text()), 'Transaction ID', parent=self)

    def got_verified_tx(self, event, args):
        if event == 'verified' and args[0] == self.tx.txid():
            self.update()

    def update_tx_if_in_wallet(self):
        if self.wallet.has_received_transaction(self.tx.txid()):
            self.update()

    def do_broadcast(self):
        self.main_window.broadcast_transaction(self.tx, self.desc, window=self)
        self.saved = True
        self.update()

    def ok_to_close(self):
        if self.prompt_if_unsaved and not self.saved:
            return self.question(_('This transaction is not saved.  Close anyway?'),
                                 title=_("Warning"))
        return True

    def __del__(self):
        logger.debug('TX dialog destroyed')

    def reject(self):
        # Invoked on user escape key
        if self.ok_to_close():
            super().reject()

    def closeEvent(self, event):
        # Invoked by user closing in window manager
        if self.ok_to_close():
            event.accept()
            self.accept()
        else:
            event.ignore()

    def show_qr(self):
        text = bfh(str(self.tx))
        text = base_encode(text, base=43)
        try:
            self.main_window.show_qrcode(text, 'Transaction', parent=self)
        except Exception as e:
            self.show_message(str(e))

    def sign(self):
        def sign_done(success):
            if success:
                self.prompt_if_unsaved = True
                self.saved = False
            self.update()
            self.main_window.pop_top_level_window(self)

        self.sign_button.setDisabled(True)
        self.main_window.push_top_level_window(self)
        self.main_window.sign_tx(self.tx, sign_done, window=self)

    def save(self):
        if self.tx.is_complete():
            name = 'signed_%s.txn' % (self.tx.txid()[0:8])
        else:
            name = 'unsigned.txn'
        fileName = self.main_window.getSaveFileName(
            _("Select where to save your signed transaction"), name, "*.txn")
        if fileName:
            tx_dict = self.tx.as_dict()
            with open(fileName, "w+") as f:
                f.write(json.dumps(tx_dict, indent=4) + '\n')
            self.show_message(_("Transaction saved successfully"))
            self.saved = True

    def update(self):
        desc = self.desc
        base_unit = app_state.base_unit()
        format_amount = self.main_window.format_amount
        tx_info = self.wallet.get_tx_info(self.tx)
        tx_info_fee = tx_info.fee

        size = self.tx.estimated_size()
        self.broadcast_button.setEnabled(tx_info.can_broadcast)
        if self.main_window.network is None:
            self.broadcast_button.setEnabled(False)
            self.broadcast_button.setToolTip(_('You are using ElectrumSV in offline mode; restart '
                                               'ElectrumSV if you want to get connected'))
        can_sign = not self.tx.is_complete() and \
            (self.wallet.can_sign(self.tx) or bool(self.main_window.tx_external_keypairs))
        self.sign_button.setEnabled(can_sign)
        self.tx_hash_e.setText(tx_info.hash or _('Unknown'))
        if tx_info_fee is None:
            try:
                # Try and compute fee. We don't always have 'value' in
                # all the inputs though. :/
                tx_info_fee = self.tx.get_fee()
            except KeyError: # Value key missing from an input
                pass
        if desc is None:
            self.tx_desc.hide()
        else:
            self.tx_desc.setText(_("Description") + ': ' + desc)
            self.tx_desc.show()
        self.status_label.setText(_('Status:') + ' ' + tx_info.status)

        if tx_info.timestamp:
            time_str = datetime.datetime.fromtimestamp(
                tx_info.timestamp).isoformat(' ')[:-3]
            self.date_label.setText(_("Date: {}").format(time_str))
            self.date_label.show()
        else:
            self.date_label.hide()
        if tx_info.amount is None:
            amount_str = _("Transaction unrelated to your wallet")
        elif tx_info.amount > 0:
            amount_str = '{} {} {}'.format(_("Amount received:"),
                                           format_amount(tx_info.amount),
                                           base_unit)
        else:
            amount_str = '{} {} {}'.format(_("Amount sent:"),
                                           format_amount(-tx_info.amount),
                                           base_unit)
        size_str = _("Size:") + ' %d bytes'% size
        if tx_info_fee is not None:
            fee_amount = '{} {}'.format(format_amount(tx_info_fee), base_unit)
        else:
            fee_amount = _('unknown')
        fee_str = '{}: {}'.format(_("Fee"), fee_amount)
        dusty_fee = self.tx.ephemeral.get('dust_to_fee', 0)
        if tx_info_fee is not None:
            fee_str += '  ( {} ) '.format(self.main_window.format_fee_rate(
                tx_info_fee / size * 1000))
            if dusty_fee:
                fee_str += (' <font color=#999999>' +
                            (_("( %s in dust was added to fee )") % format_amount(dusty_fee)) +
                            '</font>')
        self.amount_label.setText(amount_str)
        self.fee_label.setText(fee_str)
        self.size_label.setText(size_str)

        # Cosigner button
        visible = app_state.app.cosigner_pool.show_button(self.wallet, self.tx)
        self.cosigner_button.setVisible(visible)

    def add_io(self, vbox):
        if self.tx.locktime > 0:
            vbox.addWidget(QLabel("LockTime: %d\n" % self.tx.locktime))

        vbox.addWidget(QLabel(_("Inputs") + ' (%d)'%len(self.tx.inputs())))

        i_text = QTextEdit()
        i_text.setFont(self.monospace_font)
        i_text.setReadOnly(True)

        vbox.addWidget(i_text)
        vbox.addWidget(QLabel(_("Outputs") + ' (%d)'%len(self.tx.outputs())))
        o_text = QTextEdit()
        o_text.setFont(self.monospace_font)
        o_text.setReadOnly(True)
        vbox.addWidget(o_text)
        self.update_io(i_text, o_text)

    def update_io(self, i_text, o_text):
        ext = QTextCharFormat()
        rec = QTextCharFormat()
        rec.setBackground(QBrush(ColorScheme.GREEN.as_color(background=True)))
        rec.setToolTip(_("Wallet receive address"))
        chg = QTextCharFormat()
        chg.setBackground(QBrush(QColor("yellow")))
        chg.setToolTip(_("Wallet change address"))

        def text_format(addr):
            if isinstance(addr, Address) and self.wallet.is_mine(addr):
                return chg if self.wallet.is_change(addr) else rec
            return ext

        def format_amount(amt):
            return self.main_window.format_amount(amt, whitespaces = True)

        i_text.clear()
        cursor = i_text.textCursor()
        for x in self.tx.inputs():
            if x['type'] == 'coinbase':
                cursor.insertText('coinbase')
            else:
                prevout_hash = x.get('prevout_hash')
                prevout_n = x.get('prevout_n')
                cursor.insertText(prevout_hash[0:8] + '...', ext)
                cursor.insertText(prevout_hash[-8:] + ":%-4d " % prevout_n, ext)
                addr = x['address']
                if isinstance(addr, PublicKey):
                    addr = addr.toAddress()
                if addr is None:
                    addr_text = _('unknown')
                else:
                    addr_text = addr.to_string()
                cursor.insertText(addr_text, text_format(addr))
                if x.get('value'):
                    cursor.insertText(format_amount(x['value']), ext)
            cursor.insertBlock()

        o_text.clear()
        cursor = o_text.textCursor()
        for addr, v in self.tx.get_outputs():
            addrstr = addr.to_string()
            cursor.insertText(addrstr, text_format(addr))
            if v is not None:
                if len(addrstr) > 42: # for long outputs, make a linebreak.
                    cursor.insertBlock()
                    addrstr = '\u21b3'
                    cursor.insertText(addrstr, ext)
                # insert enough spaces until column 43, to line up amounts
                cursor.insertText(' '*(43 - len(addrstr)), ext)
                cursor.insertText(format_amount(v), ext)
            cursor.insertBlock()
