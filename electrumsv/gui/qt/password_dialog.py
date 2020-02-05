#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2013 ecdsa@github
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

import enum
import math
import re

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QVBoxLayout, QGridLayout, QLabel, QLineEdit, QWidget
)

from electrumsv.i18n import _
from electrumsv.wallet import Wallet

from .virtual_keyboard import VirtualKeyboard
from .util import (
    WindowModalDialog, OkButton, Buttons, CancelButton, icon_path, read_QIcon, ButtonsLineEdit,
)


def check_password_strength(password: str) -> str:
    '''
    Check the strength of the password entered by the user and return back the same
    :param password: password entered by user in New Password
    :return: password strength Weak or Medium or Strong
    '''

    password = password
    n = math.log(len(set(password)))
    num = re.search("[0-9]", password) is not None and re.match("^[0-9]*$", password) is None
    caps = password != password.upper() and password != password.lower()
    extra = re.match("^[a-zA-Z0-9]*$", password) is None
    score = len(password)*( n + caps + num + extra)/20
    password_strength = {0:"Weak",1:"Medium",2:"Strong",3:"Very Strong"}
    return password_strength[min(3, int(score))]


class PasswordAction(enum.IntEnum):
    NEW = 0
    CHANGE = 1
    PASSPHRASE = 2


class PasswordLineEdit(QWidget):
    """
    Display a password QLineEdit with a button to open a virtual keyboard.
    """

    reveal_png = "icons8-eye-32.png"
    hide_png = "icons8-hide-32.png"

    def __init__(self, text=''):
        super().__init__()
        self.pw = ButtonsLineEdit(text)
        self.pw.setMinimumWidth(220)
        self.reveal_button = self.pw.addButton(self.reveal_png, self.toggle_visible,
                                               _("Toggle visibility"))
        self.reveal_button.setFocusPolicy(Qt.NoFocus)
        keyboard_button = self.pw.addButton("keyboard.png", self.toggle_keyboard,
            _("Virtual keyboard"))
        keyboard_button.setFocusPolicy(Qt.NoFocus)
        self.pw.setEchoMode(QLineEdit.Password)
        # self.pw.setMinimumWidth(200)
        self.keyboard = VirtualKeyboard(self.pw)
        self.keyboard.setVisible(False)
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.setSizeConstraint(QVBoxLayout.SetFixedSize)
        layout.addWidget(self.pw)
        layout.addWidget(self.keyboard)
        self.setLayout(layout)

        # Pass-throughs
        self.text_submitted_signal = self.pw.text_submitted_signal
        self.returnPressed = self.pw.returnPressed
        self.setFocus = self.pw.setFocus
        self.setMaxLength = self.pw.setMaxLength
        self.setPlaceholderText = self.pw.setPlaceholderText
        self.setText = self.pw.setText
        self.setValidator = self.pw.setValidator
        self.text = self.pw.text
        self.textChanged = self.pw.textChanged
        self.editingFinished = self.pw.editingFinished
        self.textEdited = self.pw.textEdited

    def toggle_keyboard(self):
        self.keyboard.setVisible(not self.keyboard.isVisible())

    def toggle_visible(self):
        if self.pw.echoMode() == QLineEdit.Password:
            self.pw.setEchoMode(QLineEdit.Normal)
            self.reveal_button.setIcon(read_QIcon(self.hide_png))
        else:
            self.pw.setEchoMode(QLineEdit.Password)
            self.reveal_button.setIcon(read_QIcon(self.reveal_png))


class PasswordLayout(object):

    titles = [_("Enter Password"), _("Change Password"), _("Enter Passphrase")]

    def __init__(self, wallet, msg, kind, state_change_cb) -> None:
        self.pw = PasswordLineEdit()
        self.new_pw = PasswordLineEdit()
        self.conf_pw = PasswordLineEdit()
        self.kind = kind
        self._state_change_cb = state_change_cb

        vbox = QVBoxLayout()
        label = QLabel(msg + "\n")
        label.setWordWrap(True)

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnMinimumWidth(0, 150)
        grid.setColumnMinimumWidth(1, 100)
        grid.setColumnStretch(1,1)

        if kind == PasswordAction.PASSPHRASE:
            vbox.addWidget(label)
            msgs = [_('Passphrase:'), _('Confirm Passphrase:')]
        else:
            logo_grid = QGridLayout()
            logo_grid.setSpacing(8)
            logo_grid.setColumnMinimumWidth(0, 70)
            logo_grid.setColumnStretch(1,1)

            logo = QLabel()
            logo.setAlignment(Qt.AlignCenter)

            logo_grid.addWidget(logo,  0, 0)
            logo_grid.addWidget(label, 0, 1, 1, 2)
            vbox.addLayout(logo_grid)

            if kind != PasswordAction.NEW:
                pwlabel = QLabel(_('Current Password') +":")
                pwlabel.setAlignment(Qt.AlignTop)
                grid.addWidget(pwlabel, 0, 0, Qt.AlignRight | Qt.AlignVCenter)
                grid.addWidget(self.pw, 0, 1, Qt.AlignLeft)

            m1 = _('New Password') +":" if kind == PasswordAction.CHANGE else _('Password') +":"
            msgs = [m1, _('Confirm Password') +":"]

            lockfile = "lock.png"
            logo.setPixmap(QPixmap(icon_path(lockfile)).scaledToWidth(36))

        label0 = QLabel(msgs[0])
        label0.setAlignment(Qt.AlignTop)
        grid.addWidget(label0, 1, 0, Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self.new_pw, 1, 1, Qt.AlignLeft)

        label1 = QLabel(msgs[1])
        label1.setAlignment(Qt.AlignTop)
        grid.addWidget(label1, 2, 0, Qt.AlignRight | Qt.AlignVCenter)
        grid.addWidget(self.conf_pw, 2, 1, Qt.AlignLeft)
        vbox.addLayout(grid)

        # Password Strength Label
        if kind != PasswordAction.PASSPHRASE:
            self._pw_strength_label = QLabel()
            self._pw_strength = QLabel()
            grid.addWidget(self._pw_strength_label, 3, 0, 1, 1, Qt.AlignRight | Qt.AlignVCenter)
            grid.addWidget(self._pw_strength, 3, 1, 1, 1, Qt.AlignLeft)
            self.new_pw.textChanged.connect(self.pw_changed)

        def enable_OK():
            ok = self.new_pw.text() == self.conf_pw.text()
            self._state_change_cb(ok)
        self.new_pw.textChanged.connect(enable_OK)
        self.conf_pw.textChanged.connect(enable_OK)

        self.vbox = vbox

    def title(self):
        return self.titles[self.kind]

    def layout(self):
        return self.vbox

    def pw_changed(self):
        password = self.new_pw.text()
        label = ""
        strength_text = ""
        if password:
            colors = {"Weak":"Red", "Medium":"Blue", "Strong":"Green",
                      "Very Strong":"Green"}
            strength = check_password_strength(password)
            strength_text = "<font color="+ colors[strength] + ">" + strength + "</font>"
            label = _("Password Strength") +":"
        self._pw_strength_label.setText(label)
        self._pw_strength.setText(strength_text)

    def old_password(self):
        if self.kind == PasswordAction.CHANGE:
            return self.pw.text() or None
        return None

    def new_password(self):
        pw = self.new_pw.text()
        # Empty passphrases are fine and returned empty.
        if pw == "" and self.kind != PasswordAction.PASSPHRASE:
            pw = None
        return pw


class ChangePasswordDialog(WindowModalDialog):
    def __init__(self, parent: QWidget, wallet: Wallet) -> None:
        WindowModalDialog.__init__(self, parent)
        OK_button = OkButton(self)
        def state_change_cb(state: bool) -> None:
            OK_button.setEnabled(state)
        msg = _('Your wallet is password protected.')
        msg += ' ' + _('Use this dialog to change your password.')
        self.playout = PasswordLayout(wallet, msg, PasswordAction.CHANGE, state_change_cb)
        self.setWindowTitle(self.playout.title())
        vbox = QVBoxLayout(self)
        vbox.setSizeConstraint(QVBoxLayout.SetFixedSize)
        vbox.addLayout(self.playout.layout())
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self), OK_button))

    def run(self):
        try:
            if not self.exec_():
                return False, None, None
            return (True, self.playout.old_password(), self.playout.new_password())
        finally:
            self.playout.pw.setText('')
            self.playout.conf_pw.setText('')
            self.playout.new_pw.setText('')


class PasswordDialog(WindowModalDialog):
    def __init__(self, parent=None, msg=None, force_keyboard=False):
        super().__init__(parent, _("Enter Password"))

        self.pw = pw = PasswordLineEdit()

        about_label = QLabel(msg or _('Enter your password:'))

        vbox = QVBoxLayout()
        vbox.addWidget(about_label)
        vbox.addWidget(pw)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self), OkButton(self)), Qt.AlignBottom)
        vbox.setSizeConstraint(QVBoxLayout.SetFixedSize)
        self.setLayout(vbox)

    def run(self):
        try:
            if not self.exec_():
                return None
            return self.pw.text()
        finally:
            self.pw.setText("")
