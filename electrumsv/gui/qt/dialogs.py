# ElectrumSV - lightweight Bitcoin SV client
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

import enum
import time

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox, QCheckBox

from electrumsv.app_state import app_state
from electrumsv.i18n import _

class DisplayFrequency(enum.Enum):
    Always = 1
    OncePerRun = 2


class BoxBase(object):
    display_frequency = DisplayFrequency.Always
    last_shown = {}

    def __init__(self, name, main_text, info_text, frequency=None):
        self.name = name
        self.main_text = main_text
        self.info_text = info_text
        self.display_frequency = frequency or self.display_frequency

    def result(self, parent, wallet, **kwargs):
        '''Return the result of the suppressible box.  If this is saved in the configuration
        then the saved value is returned, otherwise the user is asked.'''
        if self.name in self.last_shown:
            when, value = self.last_shown[self.name]
            if self.display_frequency == DisplayFrequency.OncePerRun:
                return value

        key = f'suppress_{self.name}'
        if wallet:
            value = wallet.get_storage().get(key, None)
        else:
            value = app_state.config.get(key, None)

        if value is None:
            set_it, value = self.show_dialog(parent, **kwargs)
            if set_it and value is not None:
                if wallet:
                    wallet.get_storage().put(key, value)
                else:
                    app_state.config.set_key(key, value, True)

            self.__class__.last_shown[self.name] = time.time(), value

        return value

    def message_box(self, buttons, parent, cb, **kwargs):
        # Title bar text is blank for consistency across O/Ses (it is never shown on a Mac)
        main_text = kwargs.get('main_text', self.main_text)
        info_text = kwargs.get('info_text', self.info_text)
        icon = kwargs.get('icon', self.icon)
        dialog = QMessageBox(icon, '', main_text, buttons=buttons, parent=parent)
        dialog.setInformativeText(info_text)
        # The text on the RHS on windows looks awful up against the edge of the window.
        margins = dialog.contentsMargins()
        margins.setRight(20)
        dialog.setContentsMargins(margins)
        _set_window_title_and_icon(dialog)
        if parent:
            dialog.setWindowModality(Qt.WindowModal)
        dialog.setCheckBox(cb)
        return dialog


class InfoBox(BoxBase):
    icon = QMessageBox.Information

    def show_dialog(self, parent, **kwargs):
        cb = QCheckBox(_('Do not show me again'))
        dialog = self.message_box(QMessageBox.Ok, parent, cb, **kwargs)
        _set_window_title_and_icon(dialog)
        dialog.exec_()
        return cb.isChecked(), True


class WarningBox(InfoBox):
    icon = QMessageBox.Warning


class YesNoBox(BoxBase):
    icon = QMessageBox.Question

    def __init__(self, name, main_text, info_text, yes_text, no_text, default, frequency=None):
        '''yes_text and no_text do not have defaults to encourage you to choose something more
        informative and direct than Yes or No.
        '''
        super().__init__(name, main_text, info_text, frequency=frequency)
        self.yes_text = yes_text
        self.no_text = no_text
        self.default = default

    def show_dialog(self, parent, **kwargs):
        cb = QCheckBox(_('Do not ask me again'))
        dialog = self.message_box(QMessageBox.NoButton, parent, cb, **kwargs)
        yes_button = dialog.addButton(kwargs.get('yes_text', self.yes_text), QMessageBox.YesRole)
        no_button = dialog.addButton(kwargs.get('no_text', self.no_text), QMessageBox.NoRole)
        dialog.setDefaultButton(yes_button if self.default else no_button)
        _set_window_title_and_icon(dialog)
        result = dialog.exec_()
        return cb.isChecked(), dialog.clickedButton() is yes_button


def show_named(name, *, parent=None, wallet=None, **kwargs):
    box = all_boxes_by_name.get(name)
    if not box:
        raise ValueError(f'no box with name {name} found')
    return box.result(parent, wallet, **kwargs)

article_uri = "https://electrumsv.io/articles/2023/electrumsv-1_3_16.html"

take_care_notice = """
<span>ElectrumSV is just a Bitcoin SV wallet, it cannot stop you from making bad decisions. Read
<a href="https://medium.com/@roger.taylor/avoiding-coin-loss-b8bd66855369">this article</a> for
an overview of the various risks, and the mistakes others have made resulting in the
<font color=red><b>loss of coins</b></font>.
Your coins are your responsibility, take care with them.</span>
"""

all_boxes = [
    InfoBox('welcome-ESV-1.3.17b1',
            _('Welcome to ElectrumSV 1.3.17 (beta 1)'),
            '<p>'+ take_care_notice +'</p>'+
            '<p>You can read about the changes included in this release, in the '+
            f'<a href="{article_uri}">release guide</a> we have written.</p>'
    ),
    YesNoBox('delete-obsolete-headers', '', '', _("Delete"), _("Cancel"), False),
    WarningBox("think-before-sending",
            _("Avoid Coin Loss"),
            take_care_notice,
            frequency=DisplayFrequency.OncePerRun),
    InfoBox("sv-only-disabled",
        _("Hiding This Option"),
        "\n".join((
            _("You can remove this option from the 'Send' tab by unchecking the relevant option "
            "in the 'Wallet' section in the Preferences. Use the 'Help' button to find out more "
            "about this option."),
        ))),
]

all_boxes_by_name = {box.name: box for box in all_boxes}


def _set_window_title_and_icon(dialog):
    # These have no effect on a Mac, but improve the look on Windows
    dialog.setWindowTitle('ElectrumSV')


def error_dialog(main_text, *, info_text='', parent=None):
    dialog = QMessageBox(QMessageBox.Critical, '', main_text,
                         buttons=QMessageBox.Ok, parent=parent)
    dialog.setInformativeText(info_text)
    _set_window_title_and_icon(dialog)
    if parent:
        dialog.setWindowModality(Qt.WindowModal)
    dialog.exec_()
