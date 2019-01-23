# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2019 ElectrumSV developers
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

'''ElectrumSV application.'''

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QApplication

from electrumsv.app_state import app_state
from electrumsv.i18n import _
from electrumsv.logs import logs

from .log_window import SVLogWindow, SVLogHandler
from .network_dialog import NetworkDialog


logger = logs.get_logger('app')


class SVApplication(QApplication):

    # Signals need to be on a QObject
    create_new_window_signal = pyqtSignal(str, object)
    alias_resolved = pyqtSignal()
    cosigner_received_signal = pyqtSignal(object, object)
    labels_changed_signal = pyqtSignal(object)
    window_opened_signal = pyqtSignal(object)
    window_closed_signal = pyqtSignal(object)
    # Logging
    new_category = pyqtSignal(str)
    new_log = pyqtSignal(object)
    # Preferences updates
    fiat_ccy_changed = pyqtSignal()
    custom_fee_changed = pyqtSignal()
    fees_editable_changed = pyqtSignal()
    op_return_enabled_changed = pyqtSignal()
    num_zeros_changed = pyqtSignal()
    base_unit_changed = pyqtSignal()
    fiat_history_changed = pyqtSignal()
    fiat_balance_changed = pyqtSignal()
    update_check_signal = pyqtSignal(bool, object)

    def __init__(self, argv):
        super().__init__(argv)
        self.log_window = None
        self.net_dialog = None
        self.log_handler = SVLogHandler()
        logs.add_handler(self.log_handler)

    def show_network_dialog(self, parent):
        if not app_state.daemon.network:
            parent.show_warning(_('You are using ElectrumSV in offline mode; restart '
                                  'ElectrumSV if you want to get connected'), title=_('Offline'))
            return
        if self.net_dialog:
            self.net_dialog.on_update()
            self.net_dialog.show()
            self.net_dialog.raise_()
            return
        self.net_dialog = NetworkDialog(app_state.daemon.network, app_state.config)
        self.net_dialog.show()

    def show_log_viewer(self):
        if self.log_window is None:
            self.log_window = SVLogWindow(None, self.log_handler)
        self.log_window.show()

    def last_window_closed(self):
        for dialog in (self.net_dialog, self.log_window):
            if dialog:
                dialog.accept()
