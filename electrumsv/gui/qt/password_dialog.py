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
from typing import Any, Callable, List, Optional, Tuple, Union

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QGridLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget
)

from electrumsv.exceptions import IncompatibleWalletError
from electrumsv.i18n import _

from .virtual_keyboard import VirtualKeyboard
from .util import (
    Buttons, ButtonsLineEdit, CancelButton, FormSectionWidget, icon_path, MessageBox, OkButton,
    read_QIcon, WindowModalDialog, WWLabel
)


MessageType = Union[str, List[Tuple[QWidget, QWidget]]]


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

    def __init__(self, text: str='') -> None:
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
        self.key_event_signal = self.pw.key_event_signal
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


LayoutFields = List[Tuple[Union[str, QLabel], QWidget]]
PasswordCheckCallbackType = Optional[Callable[[str], bool]]

class PasswordLayout(object):
    titles = [_("Enter Password"), _("Change Password"), _("Enter Passphrase")]

    def __init__(self, msg: str, fields: Optional[LayoutFields], kind: PasswordAction,
            state_change_fn: Callable[[bool], None],
            password_valid_fn: PasswordCheckCallbackType) -> None:
        self.pw = PasswordLineEdit()
        self.new_pw = PasswordLineEdit()
        self.conf_pw = PasswordLineEdit()
        self.kind = kind
        self._state_change_fn = state_change_fn

        vbox = QVBoxLayout()
        label = QLabel(msg + "\n")
        label.setWordWrap(True)

        form = FormSectionWidget(minimum_label_width=120)

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

            if kind == PasswordAction.CHANGE:
                form.add_row(_('Current Password'), self.pw)

            m1 = _('New Password') +":" if kind == PasswordAction.CHANGE else _('Password') +":"
            msgs = [m1, _('Confirm Password') +":"]

            lockfile = "lock.png"
            logo.setPixmap(QPixmap(icon_path(lockfile)).scaledToWidth(36))

        if fields is not None:
            for field_label, field_widget in fields:
                form.add_row(field_label, field_widget)

        form.add_row(msgs[0], self.new_pw)
        form.add_row(msgs[1], self.conf_pw)

        vbox.addWidget(form)

        # Password Strength Label
        if kind != PasswordAction.PASSPHRASE:
            self._pw_strength = QLabel()
            form.add_row(_("Password Strength"), self._pw_strength)
            self.new_pw.textChanged.connect(self.pw_changed)
            self.pw_changed()

        def enable_OK() -> None:
            new_password = self.new_pw.text().strip()
            confirm_password = self.conf_pw.text().strip()
            ok = len(new_password) and new_password == confirm_password
            if password_valid_fn is not None:
                existing_password = self.pw.text().strip()
                ok = ok and password_valid_fn(existing_password)
            self._state_change_fn(ok)

        self.new_pw.textChanged.connect(enable_OK)
        self.conf_pw.textChanged.connect(enable_OK)
        if password_valid_fn is not None:
            self.pw.textChanged.connect(enable_OK)

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
    def __init__(self, parent: QWidget,
            msg: Optional[str]=None,
            title: Optional[str]=None,
            fields: Optional[LayoutFields]=None,
            kind: PasswordAction=PasswordAction.CHANGE,
            password_check_fn: Optional[PasswordCheckCallbackType]=None,
            custom_button: Optional[QPushButton]=None,
            custom_button_result: Optional[Any]=None) -> None:
        WindowModalDialog.__init__(self, parent)

        ok_button = OkButton(self)
        # NOTE(rt12): I think the passphrase cases need to be updated to enable the button.
        ok_button.setEnabled(kind == PasswordAction.PASSPHRASE)
        self._ok_button = ok_button

        def state_change_fn(state: bool) -> None:
            nonlocal ok_button
            ok_button.setEnabled(state)

        if msg is None:
            if kind == PasswordAction.NEW:
                msg = _('Your wallet needs a password.')
                msg += ' ' + _('Use this dialog to set your password.')
            else:
                msg = _('Your wallet is password protected.')
                msg += ' ' + _('Use this dialog to change your password.')
        self.playout = PasswordLayout(msg, fields, kind, state_change_fn, password_check_fn)
        self.setWindowTitle(self.playout.title() if title is None else title)

        vbox = QVBoxLayout(self)
        vbox.setSizeConstraint(QVBoxLayout.SetFixedSize)
        vbox.addLayout(self.playout.layout())
        vbox.addStretch(1)
        buttons = Buttons(CancelButton(self), ok_button)
        if custom_button is not None and custom_button_result is not None:
            custom_button.clicked.connect(self._on_custom_button_clicked)
            buttons.add_left_button(custom_button)
        vbox.addLayout(buttons)

        self.playout.new_pw.key_event_signal.connect(self._on_key_event)
        self.playout.conf_pw.key_event_signal.connect(self._on_key_event)

        self._on_custom_button_used = False
        self._custom_button_result = custom_button_result

    def run(self) -> Tuple[bool, Optional[str], Optional[str]]:
        try:
            if not self.exec_():
                return False, None, None
            if self._on_custom_button_used:
                return (True, self._custom_button_result, self._custom_button_result)
            return (True, self.playout.old_password(), self.playout.new_password())
        finally:
            self.playout.pw.setText('')
            self.playout.conf_pw.setText('')
            self.playout.new_pw.setText('')

    def _on_key_event(self, keycode: int) -> None:
        if keycode not in {Qt.Key_Return, Qt.Key_Enter}:
            return
        if self._ok_button.isEnabled():
            self.accept()

    def _on_custom_button_clicked(self) -> None:
        self._on_custom_button_used = True
        self.accept()


PASSWORD_REQUEST_TEXT = _("Your wallet has a password, you will need to provide that password "
    "in order to access it.")

class PasswordDialog(WindowModalDialog):
    def __init__(self, parent=None, msg: Optional[str]=None, force_keyboard: bool=False,
            password_check_fn: PasswordCheckCallbackType=None,
            fields: Optional[LayoutFields]=None,
            title: Optional[str]=None) -> None:
        super().__init__(parent, title or _("Enter Password"))

        self.pw = pw = PasswordLineEdit()
        self._ok_button = OkButton(self)

        about_label = QLabel((msg or PASSWORD_REQUEST_TEXT) +"\n")
        about_label.setWordWrap(True)

        logo_grid = QGridLayout()
        logo_grid.setSpacing(8)
        logo_grid.setColumnMinimumWidth(0, 70)
        logo_grid.setColumnStretch(1,1)

        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        lockfile = "lock.png"
        logo.setPixmap(QPixmap(icon_path(lockfile)).scaledToWidth(36))

        logo_grid.addWidget(logo,  0, 0)
        logo_grid.addWidget(about_label, 0, 1, 1, 2)

        form = FormSectionWidget()

        if fields is not None:
            for field_label, field_widget in fields:
                form.add_row(field_label, field_widget)

        form.add_row(_('Password'), pw)

        vbox = QVBoxLayout()
        vbox.addLayout(logo_grid)
        vbox.addWidget(form)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CancelButton(self), self._ok_button), Qt.AlignBottom)
        vbox.setSizeConstraint(QVBoxLayout.SetFixedSize)
        self.setLayout(vbox)

        self.pw.key_event_signal.connect(self._on_key_event)

        # Real-time password validation and OK button disabling/enabling.
        self._password_check_fn = password_check_fn
        if password_check_fn is not None:
            self._ok_button.setEnabled(False)
            self.pw.textChanged.connect(self._on_text_changed)

    def _on_text_changed(self, text: str) -> None:
        is_password_valid = False
        try:
            is_password_valid = self._password_check_fn(text)
        except IncompatibleWalletError:
            MessageBox.show_error(_("Please check that this is a valid wallet."))

        if is_password_valid:
            self._ok_button.setEnabled(True)
        else:
            self._ok_button.setEnabled(False)

    def _on_key_event(self, keycode: int) -> None:
        if keycode not in {Qt.Key_Return, Qt.Key_Enter}:
            return
        if self._ok_button.isEnabled():
            self.accept()

    def run(self):
        try:
            if not self.exec_():
                return None
            return self.pw.text()
        finally:
            self.pw.setText("")


class PassphraseDialog(WindowModalDialog):
    '''Prompt for passphrase for hardware wallets.'''

    def __init__(self, parent: QWidget, on_device_result: Optional[Any]=None) -> None:
        super().__init__(parent, _("Enter Passphrase"))
        self._on_device_result = on_device_result
        self._on_device_selected = False

    def _on_key_event(self, keycode: int) -> None:
        if keycode in {Qt.Key_Return, Qt.Key_Enter}:
            self.accept()

    def _on_device_clicked(self) -> None:
        self._on_device_selected = True
        self.accept()

    @classmethod
    def run(cls, parent: QWidget, msg: str, on_device_result: Optional[Any]=None) -> Optional[Any]:
        d = cls(parent, on_device_result)
        pw = PasswordLineEdit()
        pw.setMinimumWidth(200)
        pw.key_event_signal.connect(d._on_key_event)
        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(msg))
        vbox.addWidget(pw)
        buttons = Buttons(CancelButton(d), OkButton(d))
        if d._on_device_result is not None:
            on_device_button = QPushButton(_("On Device"))
            on_device_button.setToolTip(
                _("Use the hardware device to enter the passphrase instead."))
            on_device_button.clicked.connect(d._on_device_clicked)
            buttons.add_left_button(on_device_button)
        vbox.addLayout(buttons)
        d.setLayout(vbox)
        if d.exec():
            # We want to be sure we clear the passphrase regardless.
            passphrase = pw.text()
            pw.setText('')
            if d._on_device_selected:
                return d._on_device_result
            return passphrase
        else:
            pw.setText('')
            return None
