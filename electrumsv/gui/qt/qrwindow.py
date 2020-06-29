#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QLabel, QLineEdit, QGridLayout, QWidget,
    QPlainTextEdit)

from electrumsv.app_state import app_state
from electrumsv.i18n import _

from .qrcodewidget import QRCodeWidget


class QR_Window(QWidget):

    def __init__(self, win):
        QWidget.__init__(self)
        self.win = win
        self.setWindowTitle('ElectrumSV - ' + _('Payment Request'))
        self.label = ''
        self.amount = 0
        self.setFocusPolicy(Qt.NoFocus)

        layout = QGridLayout()

        self.qrw = QRCodeWidget()
        layout.addWidget(self.qrw, 0, 0, 1, 4, Qt.AlignHCenter)

        self._address_label = QLabel(_("Destination") +":")
        layout.addWidget(self._address_label, 1, 1, 1, 1, Qt.AlignRight)
        self._address_edit = QPlainTextEdit()
        self._address_edit.setReadOnly(True)
        self._address_edit.setMinimumWidth(300)
        layout.addWidget(self._address_edit, 1, 2, 1, 1, Qt.AlignLeft)

        self._message_label = QLabel(_("Message") +":")
        layout.addWidget(self._message_label, 2, 1, 1, 1, Qt.AlignRight)
        self._message_edit = QPlainTextEdit()
        self._message_edit.setReadOnly(True)
        self._message_edit.setMinimumWidth(300)
        layout.addWidget(self._message_edit, 2, 2, 1, 1, Qt.AlignLeft)

        self._amount_label = QLabel(_("Amount") +":")
        layout.addWidget(self._amount_label, 3, 1, 1, 1, Qt.AlignRight)
        self._amount_edit = QLineEdit()
        self._message_edit.setReadOnly(True)
        layout.addWidget(self._amount_edit, 3, 2, 1, 1, Qt.AlignLeft)

        self.setLayout(layout)

    def set_content(self, address_text, amount, message, url):
        self._address_edit.setPlainText(address_text)
        if amount:
            amount_text = '{} {}'.format(app_state.format_amount(amount), app_state.base_unit())
        else:
            amount_text = ''
        self._amount_edit.setText(amount_text)
        self._message_edit.setPlainText(message)
        self.qrw.setData(url)
