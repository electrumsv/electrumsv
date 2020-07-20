#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
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


import html
import json
import locale
import platform
import sys
import threading
import traceback

import requests
from PyQt5.QtCore import QObject, pyqtSignal, Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QMessageBox,
)

from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.version import PACKAGE_VERSION
from .main_window import ElectrumWindow
from .util import read_QIcon


logger = logs.get_logger("exc-handler")


issue_template = """<h2>Traceback</h2>
<pre>
{traceback}
</pre>

<h2>Additional information</h2>
<ul>
  <li>ElectrumSV version: {app_version}</li>
  <li>Python version: {python_version}</li>
  <li>Operating system: {os}</li>
  <li>Wallet type: {wallet_type}</li>
  <li>Locale: {locale}</li>
</ul>
"""
report_server = "https://crashhub.electrumsv.io/crash"


class Exception_Window(QDialog):
    _active_window = None

    def __init__(self, app, exc_triple):
        super().__init__()
        self.exc_triple = exc_triple
        self.app = app
        self.setWindowTitle('ElectrumSV - ' + _('An Error Occurred'))
        self.setMinimumSize(600, 300)

        main_box = QVBoxLayout()

        heading = QLabel('<h2>' + _('Sorry!') + '</h2>')
        main_box.addWidget(heading)
        main_box.addWidget(QLabel(_(
            'Something went wrong running ElectrumSV.')))

        main_box.addWidget(QLabel(
            _('To help us diagnose and fix the problem, you can send us a '
              'bug report that contains useful debug information:')))

        collapse_info = QPushButton(_("Show report contents"))
        collapse_info.clicked.connect(self.show_contents)
        main_box.addWidget(collapse_info)

        label = QLabel(''.join([
            _("Please briefly describe what led to the error (optional):"),
            "<br/>",
            "<i>",
            _("Add your email address if you are willing to provide further "
              "detail, but note that it will appear in the relevant github "
              "issue."),
            "</i>",
        ]))
        label.setTextFormat(Qt.RichText)
        main_box.addWidget(label)

        self.description_textfield = QTextEdit()
        self.description_textfield.setFixedHeight(50)
        main_box.addWidget(self.description_textfield)

        main_box.addWidget(QLabel(_("Do you want to send this report?")))

        buttons = QHBoxLayout()

        report_button = QPushButton(_('Send Bug Report'))
        report_button.clicked.connect(self.send_report)
        report_button.setIcon(read_QIcon("tab_send.png"))
        buttons.addWidget(report_button)

        never_button = QPushButton(_('Never'))
        never_button.clicked.connect(self.show_never)
        buttons.addWidget(never_button)

        close_button = QPushButton(_('Not Now'))
        close_button.clicked.connect(self.close)
        buttons.addWidget(close_button)

        main_box.addLayout(buttons)

        self.setLayout(main_box)

    def send_report(self):
        report = self.get_traceback_info()
        report.update(self.get_additional_info())
        report = json.dumps(report)
        response = requests.post(report_server, data=report)
        QMessageBox.about(self, "Crash report", response.text)
        self.close()

    def on_close(self):
        Exception_Window._active_window = None
        sys.__excepthook__(*self.exc_triple)
        self.close()

    def show_never(self):
        self.app.config.set_key("show_crash_reporter", False)
        self.close()

    def closeEvent(self, event):
        self.on_close()
        event.accept()

    def get_traceback_info(self):
        exc_string = str(self.exc_triple[1])
        stack = traceback.extract_tb(self.exc_triple[2])
        readable_trace = "".join(traceback.format_list(stack))
        traceback_id = {
            "file": stack[-1].filename,
            "name": stack[-1].name,
            "type": self.exc_triple[0].__name__
        }
        return {
            "exc_string": exc_string,
            "stack": readable_trace,
            "id": traceback_id
        }

    def get_additional_info(self):
        account_type_names = []
        for window in self.app.windows:
            if isinstance(window, ElectrumWindow):
                account_type_names.extend(a.debug_name() for a in window._wallet.get_accounts())
        wallet_types = ', '.join(account_type_names) if len(account_type_names) else "Unknown"
        return {
            "app_version": PACKAGE_VERSION,
            "python_version": sys.version,
            "os": platform.platform(),
            "locale": locale.getdefaultlocale()[0],
            "description": self.description_textfield.toPlainText(),
            "wallet_type": wallet_types,
        }

    def show_contents(self):
        info = self.get_additional_info()
        lines = traceback.format_exception(*self.exc_triple)
        info["traceback"] = html.escape(''.join(lines), quote=False)
        msg = issue_template.format(**info)
        QMessageBox.about(self, "Report contents", msg)


class Exception_Hook(QObject):
    uncaught_signal = pyqtSignal(object)

    def __init__(self, app):
        super().__init__()
        self.app = app
        sys.excepthook = self.handler
        self.uncaught_signal.connect(self.show)

    def handler(self, exctype, value, tb):
        if exctype is KeyboardInterrupt or exctype is SystemExit:
            sys.__excepthook__(exctype, value, tb)
        else:
            # Ensure that the exception is logged at the point of occurrence.
            logger.exception("logged exception, thread=%s", threading.get_ident(),
                exc_info=(exctype, value, tb))
            self.uncaught_signal.emit((exctype, value, tb))

    def show(self, exc_triple):
        cls = Exception_Window
        if not cls._active_window:
            cls._active_window = cls(self.app, exc_triple)
            cls._active_window.exec_()
