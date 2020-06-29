# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
# Copyright (C) 2019-2020 The ElectrumSV Developers
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

from decimal import Decimal
from typing import Optional

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QPalette, QPainter
from PyQt5.QtWidgets import (QLineEdit, QStyle, QStyleOptionFrame)

from electrumsv.app_state import app_state
from electrumsv.util import format_satoshis_plain


class MyLineEdit(QLineEdit):
    frozen = pyqtSignal()

    def setFrozen(self, b):
        self.setReadOnly(b)
        self.setFrame(not b)
        self.frozen.emit()


class AmountEdit(MyLineEdit):
    shortcut = pyqtSignal()

    def __init__(self, base_unit_func, parent=None):
        super().__init__(parent)
        # This seems sufficient for hundred-BTC amounts with 8 decimals
        self.setFixedWidth(140)
        self.base_unit_func = base_unit_func
        self.textChanged.connect(self.numbify)
        self.is_shortcut = False
        self.help_palette = QPalette()

    def decimal_point(self):
        return 8

    def numbify(self):
        text = self.text().strip()
        if text == '!':
            self.shortcut.emit()
            return
        pos = self.cursorPosition()
        chars = '0123456789.'
        s = ''.join([i for i in text if i in chars])
        if '.' in s:
            p = s.find('.')
            s = s.replace('.','')
            s = s[:p] + '.' + s[p: p + self.decimal_point()]
        self.setText(s)
        # setText sets Modified to False.  Instead we want to remember
        # if updates were because of user modification.
        self.setModified(self.hasFocus())
        self.setCursorPosition(pos)

    def paintEvent(self, event):
        QLineEdit.paintEvent(self, event)
        if self.base_unit_func:
            panel = QStyleOptionFrame()
            self.initStyleOption(panel)
            textRect = self.style().subElementRect(QStyle.SE_LineEditContents, panel, self)
            textRect.adjust(2, 0, -10, 0)
            painter = QPainter(self)
            painter.setPen(self.help_palette.brush(QPalette.Disabled, QPalette.Text).color())
            painter.drawText(textRect, Qt.AlignRight | Qt.AlignVCenter, self.base_unit_func())

    def get_amount(self):
        try:
            return Decimal(str(self.text()))
        except Exception:
            return None


class BTCAmountEdit(AmountEdit):
    def __init__(self, parent=None) -> None:
        super().__init__(app_state.base_unit, parent)

    def decimal_point(self):
        return app_state.decimal_point

    def get_amount(self) -> Optional[int]:
        try:
            x = Decimal(str(self.text()))
        except Exception:
            return None

        p = pow(10, self.decimal_point())
        return int( p * x )

    def setAmount(self, amount: int) -> None:
        if amount is None:
            self.setText(" ") # Space forces repaint in case units changed
        else:
            self.setText(format_satoshis_plain(amount, self.decimal_point()))


class BTCSatsByteEdit(AmountEdit):

    def __init__(self, parent=None):
        super().__init__(self.base_unit, parent=parent)

    def decimal_point(self):
        return 2

    def base_unit(self):
        return 'sats/B'

    def get_amount(self):
        try:
            x = float(Decimal(str(self.text())))
        except Exception:
            return None
        return x if x > 0.0 else None

    def setAmount(self, amount):
        if amount is None:
            self.setText(" ") # Space forces repaint in case units changed
        else:
            self.setText(str(round(amount*100.0)/100.0))
