# ElectrumSV - lightweight Bitcoin client
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

'''ElectrumSV log window.'''

from collections import deque
import logging

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QPlainTextEdit, QHBoxLayout, QVBoxLayout, QLabel, QComboBox,
)

from electrumsv.app_state import app_state
from electrumsv.logs import logs
from electrumsv.i18n import _


class SVLogHandler(logging.Handler):

    def __init__(self, max_records=5_000, level=logging.NOTSET):
        super().__init__(level)
        self.max_records = max_records
        self.deque = deque()
        self.createLock()
        self.categories = set()

    def __enter__(self):
        self.acquire()

    def __exit__(self, *args):
        self.release()

    def emit(self, record):
        deque = self.deque
        with self:
            if record.name not in self.categories:
                self.categories.add(record.name)
                app_state.app.new_category.emit(record.name)
            deque.append(record)
            if len(deque) > self.max_records:
                deque.popleft()
        app_state.app.new_log.emit(record)

    def emit_all(self):
        with self:
            records = self.deque.copy()
        for record in records:
            app_state.app.new_log.emit(record)


class SVLogWindow(QDialog):

    def __init__(self, parent, log_handler):
        super().__init__(parent, Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)
        self.setModal(False)
        self.setWindowTitle('ElectrumSV Log Viewer')
        self.log_handler = log_handler
        self.category = 'all'
        self.levels = {
            logging.DEBUG: 'debug',
            logging.INFO: 'info',
            logging.WARNING: 'warning',
            logging.ERROR: 'error'
        }
        self.layout()
        app_state.app.new_log.connect(self.new_log)
        app_state.app.new_category.connect(self.new_category)
        self.log_handler.emit_all()

    def reject(self):
        self.hide()

    def new_category(self, name):
        self.category_cb.addItem(name)

    def new_log(self, record):
        if record.name == self.category or self.category == 'all':
            msg = self.log_handler.format(record)
            self.log_view.appendPlainText(msg)

    def layout(self):
        self.category_cb = QComboBox()
        self.category_cb.addItem('all')
        for category in sorted(self.log_handler.categories):
            self.category_cb.addItem(category)
        def on_category(_index):
            self.log_view.setPlainText('')
            self.category = self.category_cb.currentText()
            self.log_handler.emit_all()
        self.category_cb.currentIndexChanged.connect(on_category)

        level_cb = QComboBox()
        for level in self.levels.values():
            level_cb.addItem(level)
        def on_level(_index):
            logs.set_level(level_cb.currentText())
        level_cb.setCurrentIndex(level_cb.findText(self.levels[logs.level()]))
        level_cb.currentIndexChanged.connect(on_level)

        hlayout = QHBoxLayout()
        hlayout.addWidget(QLabel(_('Log Category:')))
        hlayout.addWidget(self.category_cb)
        hlayout.addWidget(QLabel(_('Level:')))
        hlayout.addWidget(level_cb)
        hlayout.addStretch(1)

        vlayout = QVBoxLayout()
        vlayout.addLayout(hlayout)
        self.log_view = QPlainTextEdit(self)
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(self.log_handler.max_records)
        vlayout.addWidget(self.log_view)

        self.setLayout(vlayout)
        self.setMinimumWidth(1000)
        self.setMinimumHeight(400)
