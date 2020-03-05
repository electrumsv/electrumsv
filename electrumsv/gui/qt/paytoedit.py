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

import time
from decimal import Decimal
from typing import List, Optional

from bitcoinx import Address, cashaddr, Script

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFontMetrics, QTextCursor
from PyQt5.QtWidgets import QCompleter, QPlainTextEdit

from electrumsv.bitcoin import string_to_bip276_script
from electrumsv.i18n import _
from electrumsv.network import Net
from electrumsv.transaction import XTxOutput
from electrumsv.web import is_URI

from .main_window import ElectrumWindow
from .qrtextedit import ScanQRTextEdit
from . import util


RE_ALIAS = '^(.*?)\s*\<([0-9A-Za-z:]{26,})\>$'

frozen_style = "QWidget { background-color:none; border:none;}"
normal_style = "QPlainTextEdit { }"

class PayToEdit(ScanQRTextEdit):
    ''' timestamp indicating when the user was last warned about using cash addresses. '''
    last_cashaddr_warning = None

    def __init__(self, main_window: ElectrumWindow) -> None:
        ScanQRTextEdit.__init__(self)
        self._main_window = main_window
        self.amount_edit = main_window.amount_e
        self.document().contentsChanged.connect(self.update_size)
        self.heightMin = 0
        self.heightMax = 150
        self.c = None
        self.textChanged.connect(self._on_text_changed)
        self.outputs: List[XTxOutput] = []
        self.errors = []
        self.is_pr = False
        self.is_alias = False
        self._ignore_uris = False
        self.scan_f = main_window.pay_to_URI
        self.update_size()
        self.payto_script: Optional[Script] = None

        self.previous_payto = ''

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setStyleSheet(frozen_style if b else normal_style)
        for button in self.buttons:
            button.setHidden(b)

    def set_validated(self):
        self.setStyleSheet(util.ColorScheme.GREEN.as_stylesheet(True))

    def set_expired(self):
        self.setStyleSheet(util.ColorScheme.RED.as_stylesheet(True))

    def _show_cashaddr_warning(self, address_text):
        '''
        cash addresses are not in the future for BSV. Anyone who uses one should be warned that
        they are being phased out, in order to encourage them to pre-emptively move on.
        '''
        # We only care if it is decoded, as this will be a cash address.
        try:
            cashaddr.decode(address_text)
        except Exception:
            return

        last_check_time = PayToEdit.last_cashaddr_warning
        ignore_watermark_time = time.time() - 24 * 60 * 60
        if last_check_time is None or last_check_time < ignore_watermark_time:
            PayToEdit.last_cashaddr_warning = time.time()

            message = ("<p>"+
                _("One or more of the addresses you have provided has been recognized "+
                "as a 'cash address'. For now, this is acceptable but is recommended that you get "+
                "in the habit of requesting that anyone who provides you with payment addresses "+
                "do so in the form of normal Bitcoin SV addresses.")+
                "</p>"+
                "<p>"+
                _("Within the very near future, various services and applications in the Bitcoin "+
                "SV ecosystem will stop accepting 'cash addresses'. It is in your best interest "+
                "to make sure you transition over to normal Bitcoin SV addresses as soon as "+
                "possible, in order to ensure that you can both be paid, and also get paid.")+
                "</p>"
                )
            util.MessageBox.show_warning(message, title=_("Cash address warning"))

    def _parse_tx_output(self, line: str) -> XTxOutput:
        x, y = line.split(',')
        script = self._parse_output(x)
        amount = self._parse_amount(y)
        return XTxOutput(amount, script)

    def _parse_output(self, text: str) -> Script:
        try:
            address =  Address.from_string(text, Net.COIN)
            self._show_cashaddr_warning(text)
            return address.to_script()
        except ValueError:
            pass

        try:
            return string_to_bip276_script(text)
        except ValueError:
            pass

        return Script.from_asm(text)

    def _parse_amount(self, x):
        if x.strip() == '!':
            return all
        p = pow(10, self.amount_edit.decimal_point())
        return int(p * Decimal(x.strip()))

    def setPlainText(self, text: str, ignore_uris: bool=False) -> None:
        # We override this so that there's no infinite loop where pay_to_URI calls this then
        # the BIP276 URI is detected as a URI and we feed it back to pay_to_URI via scan_f.
        self._ignore_uris = ignore_uris
        try:
            super().setPlainText(text)
        finally:
            self._ignore_uris = False

    def _on_text_changed(self):
        self.errors = []
        if self.is_pr:
            return
        # filter out empty lines
        lines = [i for i in self._lines() if i]
        outputs = []
        total = 0
        self.payto_script = None
        if len(lines) == 1:
            data = lines[0]
            if not self._ignore_uris and is_URI(data):
                self.scan_f(data)
                return
            try:
                self.payto_script = self._parse_output(data)
            except Exception:
                pass
            if self.payto_script is not None:
                self._main_window.lock_amount(False)
                return

        is_max = False
        for i, line in enumerate(lines):
            try:
                tx_output = self._parse_tx_output(line)
            except Exception:
                self.errors.append((i, line.strip()))
                continue

            outputs.append(tx_output)
            if tx_output.value is all:
                is_max = True
            else:
                total += tx_output.value

        self._main_window.is_max = is_max
        self.outputs = outputs
        self.payto_script = None

        if self._main_window.is_max:
            self._main_window.do_update_fee()
        else:
            self.amount_edit.setAmount(total if outputs else None)
            self._main_window.lock_amount(total or len(lines)>1)

    def get_errors(self):
        return self.errors

    def get_payee_script(self) -> Optional[Script]:
        return self.payto_script

    def get_outputs(self, is_max):
        if self.payto_script is not None:
            if is_max:
                amount = all
            else:
                amount = self.amount_edit.get_amount()
            self.outputs = [XTxOutput(amount, self.payto_script)]
        return self.outputs[:]

    def _lines(self):
        return self.toPlainText().split('\n')

    def _is_multiline(self):
        return len(self._lines()) > 1

    def paytomany(self):
        self.setText("\n\n\n")
        self.update_size()

    def update_size(self):
        lineHeight = QFontMetrics(self.document().defaultFont()).height()
        docHeight = self.document().size().height()
        h = docHeight * lineHeight + 11
        if self.heightMin <= h <= self.heightMax:
            self.setMinimumHeight(h)
            self.setMaximumHeight(h)
        self.verticalScrollBar().hide()

    def set_completer(self, completer):
        self.c = completer
        self.c.setWidget(self)
        self.c.setCompletionMode(QCompleter.PopupCompletion)
        self.c.activated.connect(self._insert_completion)

    def _insert_completion(self, completion):
        if self.c.widget() != self:
            return
        tc = self.textCursor()
        extra = len(completion) - len(self.c.completionPrefix())
        tc.movePosition(QTextCursor.Left)
        tc.movePosition(QTextCursor.EndOfWord)
        tc.insertText(completion[-extra:])
        self.setTextCursor(tc)

    def _get_text_under_cursor(self):
        tc = self.textCursor()
        tc.select(QTextCursor.WordUnderCursor)
        return tc.selectedText()

    def keyPressEvent(self, e):
        if self.isReadOnly():
            return

        if self.c.popup().isVisible():
            if e.key() in [Qt.Key_Enter, Qt.Key_Return]:
                e.ignore()
                return

        if e.key() in [Qt.Key_Tab]:
            e.ignore()
            return

        if e.key() in [Qt.Key_Down, Qt.Key_Up] and not self._is_multiline():
            e.ignore()
            return

        QPlainTextEdit.keyPressEvent(self, e)

        ctrlOrShift = e.modifiers() and (Qt.ControlModifier or Qt.ShiftModifier)
        if self.c is None or (ctrlOrShift and not e.text()):
            return

        eow = "~!@#$%^&*()_+{}|:\"<>?,./;'[]\\-="
        hasModifier = (e.modifiers() != Qt.NoModifier) and not ctrlOrShift
        completionPrefix = self._get_text_under_cursor()

        if hasModifier or not e.text() or len(completionPrefix) < 1 or eow.find(e.text()[-1]) >= 0:
            self.c.popup().hide()
            return

        if completionPrefix != self.c.completionPrefix():
            self.c.setCompletionPrefix(completionPrefix)
            self.c.popup().setCurrentIndex(self.c.completionModel().index(0, 0))

        cr = self.cursorRect()
        cr.setWidth(self.c.popup().sizeHintForColumn(0)
                    + self.c.popup().verticalScrollBar().sizeHint().width())
        self.c.complete(cr)

    def qr_input(self):
        data = super(PayToEdit,self).qr_input()
        if data and data.startswith("bitcoincash:"):
            self.scan_f(data)
            # TODO: update fee

    def resolve(self):
        self.is_alias = False
        if self.hasFocus():
            return
        if self._is_multiline():  # only supports single line entries atm
            return
        if self.is_pr:
            return
        key = str(self.toPlainText())
        if key == self.previous_payto:
            return
        self.previous_payto = key
