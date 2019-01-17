from .qt_generic import QtPlugin
from .keepkey import KeepKeyPlugin


class Plugin(KeepKeyPlugin, QtPlugin):
    icon_paired = "keepkey.png"
    icon_unpaired = "keepkey_unpaired.png"

    @classmethod
    def pin_matrix_widget_class(self):
        #from keepkeylib.qt.pinmatrix import PinMatrixWidget
        return PinMatrixWidget


import math

from PyQt5.QtWidgets import (QPushButton, QLineEdit, QSizePolicy, QLabel,
                             QWidget, QGridLayout, QVBoxLayout, QHBoxLayout)
from PyQt5.QtGui import QRegExpValidator
from PyQt5.QtCore import QRegExp, Qt


class PinButton(QPushButton):
    def __init__(self, password, encoded_value):
        super(PinButton, self).__init__('?')
        self.password = password
        self.encoded_value = encoded_value
        self.clicked.connect(self._pressed)

    def _pressed(self):
        self.password.setText(self.password.text() + str(self.encoded_value))
        self.password.setFocus()


class PinMatrixWidget(QWidget):
    '''
        Displays widget with nine blank buttons and password box.
        Encodes button clicks into sequence of numbers for passing
        into PinAck messages of KeepKey.
        show_strength=True may be useful for entering new PIN
    '''
    def __init__(self, show_strength=True, parent=None):
        super(PinMatrixWidget, self).__init__(parent)

        self.password = QLineEdit()
        self.password.setValidator(QRegExpValidator(QRegExp('[1-9]+'), None))
        self.password.setEchoMode(QLineEdit.Password)

        self.password.textChanged.connect(self._password_changed)
        self.strength = QLabel()
        self.strength.setMinimumWidth(75)
        self.strength.setAlignment(Qt.AlignCenter)
        self._set_strength(0)

        grid = QGridLayout()
        grid.setSpacing(0)
        for y in range(3)[::-1]:
            for x in range(3):
                button = PinButton(self.password, x + y * 3 + 1)
                button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
                button.setFocusPolicy(Qt.NoFocus)
                grid.addWidget(button, 3 - y, x)

        hbox = QHBoxLayout()
        hbox.addWidget(self.password)
        if show_strength:
            hbox.addWidget(self.strength)

        vbox = QVBoxLayout()
        vbox.addLayout(grid)
        vbox.addLayout(hbox)
        self.setLayout(vbox)

    def _set_strength(self, strength):
        if strength < 3000:
            self.strength.setText('weak')
            self.strength.setStyleSheet("QLabel { color : #d00; }")
        elif strength < 60000:
            self.strength.setText('fine')
            self.strength.setStyleSheet("QLabel { color : #db0; }")
        elif strength < 360000:
            self.strength.setText('strong')
            self.strength.setStyleSheet("QLabel { color : #0a0; }")
        else:
            self.strength.setText('ULTIMATE')
            self.strength.setStyleSheet("QLabel { color : #000; font-weight: bold;}")

    def _password_changed(self, password):
        self._set_strength(self.get_strength())

    def get_strength(self):
        digits = len(set(str(self.password.text())))
        strength = math.factorial(9) / math.factorial(9 - digits)
        return strength

    def get_value(self):
        return self.password.text()
