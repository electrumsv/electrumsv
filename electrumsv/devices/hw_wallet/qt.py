#!/usr/bin/env python3
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
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

from functools import partial
from queue import Queue
import threading
from typing import Any, Iterable, Optional
import weakref

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QAction, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout
from PyQt5 import sip

from electrumsv.app_state import app_state
from electrumsv.exceptions import UserCancelled
from electrumsv.keystore import Hardware_KeyStore
from electrumsv.i18n import _

from electrumsv.gui.qt.main_window import ElectrumWindow
from electrumsv.gui.qt.password_dialog import (ChangePasswordDialog, PasswordAction,
                                               PassphraseDialog)
from electrumsv.gui.qt.util import WindowModalDialog, Buttons, CancelButton, read_QIcon


HandlerWindow = ElectrumWindow


# The trickiest thing about this handler was getting windows properly
# parented on MacOSX.
class QtHandlerBase(QObject):
    '''An interface between the GUI (here, QT) and the device handling
    logic for handling I/O.'''

    passphrase_signal = pyqtSignal(object, object)
    message_signal = pyqtSignal(object, object)
    error_signal = pyqtSignal(object, object)
    warning_signal = pyqtSignal(object)
    word_signal = pyqtSignal(object)
    clear_signal = pyqtSignal()
    query_signal = pyqtSignal(object, object)
    yes_no_signal = pyqtSignal(object)
    status_signal = pyqtSignal(object)

    _cleaned_up: bool = False
    _choice: Optional[int] = None
    _ok: int = 0

    word: Optional[str]

    # Copied over from QtPlugin below when `replace_gui_handler` is called.
    icon_paired: str
    icon_unpaired: str
    action: QAction

    def __init__(self, win: HandlerWindow, device):
        super(QtHandlerBase, self).__init__()
        self.clear_signal.connect(self.clear_dialog)
        self.error_signal.connect(self.error_dialog)
        self.warning_signal.connect(self.warning_dialog)
        self.message_signal.connect(self.message_dialog)
        self.passphrase_signal.connect(self.passphrase_dialog)
        self.word_signal.connect(self.word_dialog)
        self.query_signal.connect(self.win_query_choice)
        self.yes_no_signal.connect(self.win_yes_no_question)
        self.status_signal.connect(self._update_status)
        self.win = win
        self.device = device
        self.dialog: Optional[WindowModalDialog] = None
        self.done = threading.Event()
        self.passphrase_queue: Queue = Queue()
        self._on_device_passphrase_result: Optional[Any] = None

    def clean_up(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        del self.win

    def top_level_window(self):
        return self.win.top_level_window()

    def set_on_device_passphrase_result(self, value: Optional[Any]) -> None:
        self._on_device_passphrase_result = value

    def update_status(self, paired):
        self.status_signal.emit(paired)

    def _update_status(self, paired):
        icon = self.icon_paired if paired else self.icon_unpaired
        self.action.setIcon(read_QIcon(icon))

    def query_choice(self, msg: str, labels: Iterable[str]) -> Optional[int]:
        self.done.clear()
        self.query_signal.emit(msg, labels)
        self.done.wait()
        if self._choice is None:
            raise UserCancelled()
        return self._choice

    def yes_no_question(self, msg) -> int:
        self.done.clear()
        self.yes_no_signal.emit(msg)
        self.done.wait()
        if self._ok == -1:
            raise UserCancelled()
        return self._ok

    def show_message(self, msg, on_cancel=None):
        self.message_signal.emit(msg, on_cancel)

    def show_error(self, msg: str, blocking: bool=False) -> None:
        self.done.clear()
        self.error_signal.emit(msg, blocking)
        if blocking:
            self.done.wait()

    def show_warning(self, msg: str) -> None:
        self.done.clear()
        self.warning_signal.emit(msg)
        self.done.wait()

    def finished(self) -> None:
        self.clear_signal.emit()

    def get_word(self, msg: str) -> Optional[str]:
        self.done.clear()
        self.word_signal.emit(msg)
        self.done.wait()
        return self.word

    def get_passphrase(self, msg: str, confirm: bool) -> Optional[Any]:
        """
        Returns:
          str -> passphrase entered in ESV.
          None -> user cancelled.
          other -> custom result to indicate special per-device handling.
        """
        self.passphrase_signal.emit(msg, confirm)
        return self.passphrase_queue.get()

    def passphrase_dialog(self, msg: str, confirm: bool) -> None:
        # If confirm is true, require the user to enter the passphrase twice
        parent = self.top_level_window()
        if confirm:
            custom_button: Optional[QPushButton] = None
            if self._on_device_passphrase_result is not None:
                custom_button = QPushButton(_("On Device"))
            d = ChangePasswordDialog(parent, msg=msg, kind=PasswordAction.PASSPHRASE,
                custom_button=custom_button, custom_button_result=self._on_device_passphrase_result)
            _confirmed, _p, passphrase = d.run()
        else:
            passphrase = PassphraseDialog.run(parent, msg, self._on_device_passphrase_result)
        self.passphrase_queue.put(passphrase)

    def word_dialog(self, msg: str) -> None:
        dialog = WindowModalDialog(self.top_level_window(), "")
        hbox = QHBoxLayout(dialog)
        hbox.addWidget(QLabel(msg))
        text = QLineEdit()
        text.setMaximumWidth(100)
        text.returnPressed.connect(dialog.accept)
        hbox.addWidget(text)
        hbox.addStretch(1)
        dialog.exec_()  # Firmware cannot handle cancellation
        self.word = text.text()
        self.done.set()

    def message_dialog(self, msg, on_cancel):
        # Called more than once during signing, to confirm output and fee
        self.clear_dialog()
        title = _('Please check your {} device').format(self.device)
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), title)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(QLabel(msg))
        if on_cancel:
            dialog.rejected.connect(on_cancel)
            vbox.addLayout(Buttons(CancelButton(dialog)))
        dialog.show()

    def error_dialog(self, msg):
        self.win.show_error(msg, parent=self.top_level_window())
        self.done.set()

    def warning_dialog(self, msg):
        self.win.show_warning(msg, parent=self.top_level_window())
        self.done.set()

    def clear_dialog(self):
        if self.dialog is not None:
            if not sip.isdeleted(self.dialog):
                self.dialog.accept()
            self.dialog = None

    def win_query_choice(self, msg, labels) -> None:
        self._choice = None
        if not self._cleaned_up:
            self._choice = self.win.query_choice(msg, labels)
        self.done.set()

    def win_yes_no_question(self, msg: str) -> None:
        self._ok = -1
        if not self._cleaned_up:
            self._ok = self.win.question(msg)
        self.done.set()


class QtPluginBase(object):
    icon_paired: str
    icon_unpaired: str
    libraries_available_message: str
    name: str

    def create_handler(self, window: HandlerWindow) -> QtHandlerBase:
        raise NotImplementedError

    def replace_gui_handler(self, window: ElectrumWindow, keystore: Hardware_KeyStore):
        handler = self.create_handler(window)
        keystore.handler = handler # type: ignore
        keystore.plugin = self # type: ignore

        action_label = _('Unnamed')
        if keystore.label and keystore.label.strip():
            action_label = keystore.label.strip()
        action = QAction(read_QIcon(self.icon_unpaired), action_label, window)
        action.triggered.connect(partial(self.show_settings_wrapped, weakref.proxy(window),
            keystore))
        action.setToolTip(_("Hardware Wallet"))
        window.add_toolbar_action(action)

        handler.action = action
        handler.icon_unpaired = self.icon_unpaired
        handler.icon_paired = self.icon_paired

    def missing_message(self) -> str:
        if hasattr(self, 'libraries_available_message'):
            message = self.libraries_available_message + '\n'
        else:
            message = _("Cannot find python library for") + " '{}'.\n".format(self.name)
        message += _("Make sure you install it with python3")
        return message

    def choose_device(self, window, keystore):
        '''This dialog box should be usable even if the user has
        forgotten their PIN or it is in bootloader mode.'''
        device_id = app_state.device_manager.xpub_id(keystore.xpub)
        if not device_id:
            try:
                info = app_state.device_manager.select_device(self, keystore.handler, keystore)
            except UserCancelled:
                return
            device_id = info.device.id_
        return device_id

    def show_settings_dialog(self, window: ElectrumWindow, keystore: Hardware_KeyStore) -> None:
        raise NotImplementedError

    def show_settings_wrapped(self, window: ElectrumWindow, keystore: Hardware_KeyStore) -> None:
        if isinstance(window, weakref.ProxyType):
            window = window.reference()
        try:
            self.show_settings_dialog(window, keystore)
        except Exception as e:
            assert keystore.handler is not None
            keystore.handler.show_error(str(e))
