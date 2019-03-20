# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019 The ElectrumSV Developers
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

raw_release_notes = """
  * UI: Correctly set the application icon so that it is displayed for all windows. This is possibly
    irrelevant on some operating systems, but on Windows it ensures that the application icon
    featured in the top left-hand corner of the window is not blandly undefined but rather the
    glorious new icon that we have.
  * Wallet creation/restoration: Switch to cointype 0 (Bitcoin) for BIP44-derivations by default.
    145 (BCH) and 236 (BSV) might need to be tried when restoring a wallet.
  * Update checker: The release announcements are now expected to be signed and will only be
    shown to the user if they are, and the signature is that of kyuupichan or rt121212121.
  * Hardware wallets: A warning dialog has been added for hardware device usage highlighting
    the support/quality issues with these devices.
  * Hardware wallets: Trezor and Keepkey have had various UI-related bugs fixed.
  * Hardware wallets: KeepKey users should update their device firmware.
  * Hardware wallets: Digital Bitbox transaction signing now works again and has probably been
    broken since our first release.
  * Hardware wallets: Ledger Nano X has been added as a recognised device. It has not been tested
    as we do not have one, but at least it will now be found.
  * Exchange rates: BSV fiat values can now be obtained via Coinbase.
  * Code quality: Rewrite of the networking code to use asynchronous logic. This allows the code to
    be written in a clearer and more straightforward fashion, and both helps us ensure that it
    works correctly and reduces the chance of bugs.
  * Code quality: Rewrite of the SPV support functionality to work with the new asynchronous
    networking. This includes both the synchronisation of address usage in blockchain transactions
    and verification that located transactions are real and were included in blocks using merkle
    proofs.
  * Code quality: Several cleanups and improvements to internals that increase robustness and
    stability.
"""
raw_release_notes = raw_release_notes.replace("  * ", "<li>", 1)
raw_release_notes = raw_release_notes.replace("  * ", "</li><li>")
raw_release_notes += "</li>"

hardware_wallet_notes = """
<p>
Hardware wallet vendors have been slow to properly support Bitcoin SV with their products.
In addition they do not maintain the code in ElectrumSV that enables you to continue
to use their product.
</p>
<p>
Maintaining and improving ElectrumSV takes time and resources that we have to prioritize.
Owing to vendor apathy and the poor quality of the hardware wallet code and documentation,
we limit our efforts to the minimum necessary to enable you to continue to use the
hardware for normal operations.  However the vendors frequently change their software
libraries and wallet firmware, so we cannot guarantee we will be able to support the
hardware wallets and features indefinitely.
</p>
<p>
Hopefully in the future there will be less political, more professional and higher
quality hardware wallets, or equivalent solutions, available for our users' needs.
</p>
<p>
Below is the current support status for each vendor:
</p>
<ul>
<li>
<b>KeepKey</b> Bitcoin SV is fully supported with the most recent firmware and client
library releases from KeepKey.  The the hardware gives warnings about "wrong address path
for the selected coin" for wallets with Bitcoin Cash 145' derivations, which you can safely
ignore.
</li>
<li>
<b>Trezor</b> Trezor show no intent to support Bitcoin SV.  The hardware currently works
if we pretend to be Bitcoin Cash.  This means addresses show as Bitcoin Cash addresses, not
Bitcoin addresses, making verification difficult for you.
</li>
<li>
<b>Ledger</b> Ledger state that Bitcoin SV support is "not planned at this time".  The
hardware currently works if we pretend to be Bitcoin Cash.
</li>
<li>
<b>Digital Bitbox</b> DBB show no intent to support Bitcoin SV.  The hardware currently
works if we pretend to be Bitcoin Cash.
</li>
</ul>
"""

all_boxes = [
    InfoBox('welcome-ESV-1.2.0',
            _('Welcome to ElectrumSV 1.2.0'),
            _('This release includes the following changes:') +
            '<ul>'+ raw_release_notes +'</ul>'
    ),
    YesNoBox('delete-obsolete-headers', '', '', _("Delete"), _("Cancel"), False),
    WarningBox('illegal-files-are-traceable',
            _('Illegal Files Are Traceable'),
            '\n'.join((
                _('Bitcoin transactions are traceable. If you choose to upload illegal '
                  'material, you can be identified, and will risk the consequences.'),
            ))),
    WarningBox('hardware-wallet-quality',
            _('Hardware Wallet Quality'),
            hardware_wallet_notes,
            frequency=DisplayFrequency.OncePerRun),
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
