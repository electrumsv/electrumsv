# Electrum SV - lightweight Bitcoin SV client
# Copyright (C) 2019 The Electrum SV Developers
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
from PyQt5.QtWidgets import QMessageBox, QCheckBox

from electrumsv.app_state import app_state
from electrumsv.i18n import _


class BoxBase(object):

    def __init__(self, name, main_text, info_text):
        self.name = name
        self.main_text = main_text
        self.info_text = info_text

    def result(self, parent, wallet, **kwargs):
        '''Return the result of the suppressible box.  If this is saved in the configuration
        then the saved value is returned, otherwise the user is asked.'''
        key = f'suppress_{self.name}'
        if wallet:
            value = wallet.storage.get(key, None)
        else:
            value = app_state.config.get(key, None)

        if value is None:
            set_it, value = self.show_dialog(parent, **kwargs)
            if set_it and value is not None:
                if wallet:
                    wallet.storage.put(key, value)
                else:
                    app_state.config.set_key(key, value, True)

        return value

    def message_box(self, buttons, parent, cb, **kwargs):
        # Title bar text is blank for consistency across O/Ses (it is never shown on a Mac)
        main_text = kwargs.get('main_text', self.main_text)
        info_text = kwargs.get('info_text', self.info_text)
        icon = kwargs.get('icon', self.icon)
        dialog = QMessageBox(icon, '', main_text, buttons=buttons, parent=parent)
        dialog.setInformativeText(info_text)
        if parent:
            dialog.setWindowModality(Qt.WindowModal)
        dialog.setCheckBox(cb)
        return dialog


class InfoBox(BoxBase):
    icon = QMessageBox.Information

    def show_dialog(self, parent, **kwargs):
        cb = QCheckBox(_('Do not show me again'))
        dialog = self.message_box(QMessageBox.Ok, parent, cb, **kwargs)
        dialog.exec_()
        return cb.isChecked(), True


class WarningBox(InfoBox):
    icon = QMessageBox.Warning


class YesNoBox(BoxBase):
    icon = QMessageBox.Question

    def __init__(self, name, main_text, info_text, default):
        super().__init__(name, main_text, info_text)
        self.default = default

    def show_dialog(self, parent, **kwargs):
        cb = QCheckBox(_('Do not ask me again'))
        dialog = self.message_box(QMessageBox.Yes|QMessageBox.No, parent, cb, **kwargs)
        dialog.setDefaultButton(QMessageBox.Yes if self.default else QMessageBox.No)
        result = dialog.exec_()
        return cb.isChecked(), result == QMessageBox.Yes


def show_suppressible(name, *, parent=None, wallet=None, **kwargs):
    box = all_boxes_by_name.get(name)
    if not box:
        raise ValueError(f'no box with name {name} found')
    return box.result(parent, wallet, **kwargs)


all_boxes = [
    InfoBox('welcome-ESV-1.1',
            _('Welcome to Electrum SV 1.1'),
            '\n'.join((
                _('This release includes bug fixes, performance improvements and some '
                  'new features, including:-'),
                _('item A'),
                _('item B'),
                _('item C'),
            )),
    ),
    YesNoBox('delete-obsolete-headers', '', '', False),
]

all_boxes_by_name = {box.name: box for box in all_boxes}


def error_dialog(main_text, *, info_text='', parent=None):
    dialog = QMessageBox(QMessageBox.Critical, '', main_text,
                         buttons=QMessageBox.Ok, parent=parent)
    dialog.setInformativeText(info_text)
    if parent:
        dialog.setWindowModality(Qt.WindowModal)
    dialog.exec_()
