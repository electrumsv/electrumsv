# ElectrumSV - lightweight BitcoinSV client
# Copyright (C) 2012 thomasv@gitorious
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

# source: http://stackoverflow.com/questions/2758159

import os
import re
import sys
import traceback

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtGui import QFont, QResizeEvent, QTextCursor, QTextOption

from electrumsv import util
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.platform import platform


logger = logs.get_logger("console")


class OverlayLabel(QtWidgets.QLabel):
    STYLESHEET = '''
    QLabel, QLabel link {
        color: rgb(0, 0, 0);
        background-color: rgb(248, 240, 200);
        border: 1px solid;
        border-color: rgb(255, 114, 47);
        padding: 2px;
    }
    '''

    def __init__(self, text, parent):
        super().__init__(text, parent)
        self.setMinimumHeight(150)
        self.setGeometry(0, 0, self.width(), self.height())
        self.setStyleSheet(self.STYLESHEET)
        self.setMargin(0)
        parent.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.setWordWrap(True)

    def mousePressEvent(self, e):
        self.hide()

    def on_resize(self, w):
        padding = 2  # px, from the stylesheet above
        self.setFixedWidth(w - padding)


class Console(QtWidgets.QPlainTextEdit):
    def __init__(self, prompt='>> ', startup_message='', parent=None):
        QtWidgets.QPlainTextEdit.__init__(self, parent)

        self.prompt = prompt
        self.history = []
        self.namespace = {}
        self.construct = []

        self.setGeometry(50, 75, 600, 400)
        self.setWordWrapMode(QTextOption.WrapAnywhere)
        self.setUndoRedoEnabled(False)
        self.document().setDefaultFont(QFont(platform.monospace_font, 10, QFont.Normal))
        self.showMessage(startup_message)

        self.updateNamespace({'run': self.run_script})
        self.set_json(False)

        warning_text = "<h1><center>{}</center></h1><br>{}<br><br>{}<br><br>{}".format(
            _("Warning!"),
            _("Do not run code here that you don't understand.  Running bad or malicious code "
              "could lead to your coins being irreversibly lost."),
            _("Text shown here is sent by the server and may be malicious; ignore anything it "
              "might be asking you to do."),
            _("Click here to hide this message.")
        )
        self.messageOverlay = OverlayLabel(warning_text, self)

    def clean_up(self) -> None:
        self.namespace.clear()

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)

        scrollbar_width = self.verticalScrollBar().width() * self.verticalScrollBar().isVisible()
        self.messageOverlay.on_resize(self.width() - scrollbar_width)

    def set_json(self, b: bool=True) -> None:
        self.is_json = b

    def run_script(self, filename):
        with open(filename) as f:
            script = f.read()

        # eval is generally considered bad practice. use it wisely!
        # pylint: disable=eval-used
        eval(script, self.namespace, self.namespace)

    def updateNamespace(self, namespace):
        self.namespace.update(namespace)

    def showMessage(self, message):
        self.appendPlainText(message)
        self.newPrompt()

    def clear(self):
        self.setPlainText('')
        self.newPrompt()

    def newPrompt(self):
        if self.construct:
            prompt = '.' * len(self.prompt)
        else:
            prompt = self.prompt

        self.completions_pos = self.textCursor().position()
        self.completions_visible = False

        self.appendPlainText(prompt)
        self.moveCursor(QTextCursor.End)

    def getCommand(self):
        doc = self.document()
        curr_line = doc.findBlockByLineNumber(doc.lineCount() - 1).text()
        curr_line = curr_line.rstrip()
        curr_line = curr_line[len(self.prompt):]
        return curr_line

    def setCommand(self, command):
        if self.getCommand() == command:
            return

        doc = self.document()
        curr_line = doc.findBlockByLineNumber(doc.lineCount() - 1).text()
        self.moveCursor(QTextCursor.End)
        for i in range(len(curr_line) - len(self.prompt)):
            self.moveCursor(QTextCursor.Left, QTextCursor.KeepAnchor)

        self.textCursor().removeSelectedText()
        self.textCursor().insertText(command)
        self.moveCursor(QTextCursor.End)

    def show_completions(self, completions):
        if self.completions_visible:
            self.hide_completions()

        c = self.textCursor()
        c.setPosition(self.completions_pos)

        completions = [x.split('.')[-1] for x in completions]
        t = '\n' + ' '.join(completions)
        if len(t) > 500:
            t = t[:500] + '...'
        c.insertText(t)
        self.completions_end = c.position()

        self.moveCursor(QTextCursor.End)
        self.completions_visible = True

    def hide_completions(self):
        if not self.completions_visible:
            return
        c = self.textCursor()
        c.setPosition(self.completions_pos)
        for x in range(self.completions_end - self.completions_pos):
            c.deleteChar()

        self.moveCursor(QTextCursor.End)
        self.completions_visible = False

    def getConstruct(self, command):
        if self.construct:
            prev_command = self.construct[-1]
            self.construct.append(command)
            if not prev_command and not command:
                ret_val = '\n'.join(self.construct)
                self.construct = []
                return ret_val
            else:
                return ''
        else:
            if command and command[-1] == (':'):
                self.construct.append(command)
                return ''
            else:
                return command

    def getHistory(self):
        return self.history

    def setHisory(self, history):
        self.history = history

    def addToHistory(self, command):
        if command[0:1] == ' ':
            return

        if command and (not self.history or self.history[-1] != command):
            self.history.append(command)
        self.history_index = len(self.history)

    def getPrevHistoryEntry(self):
        if self.history:
            self.history_index = max(0, self.history_index - 1)
            return self.history[self.history_index]
        return ''

    def getNextHistoryEntry(self):
        if self.history:
            hist_len = len(self.history)
            self.history_index = min(hist_len, self.history_index + 1)
            if self.history_index < hist_len:
                return self.history[self.history_index]
        return ''

    def getCursorPosition(self):
        c = self.textCursor()
        return c.position() - c.block().position() - len(self.prompt)

    def setCursorPosition(self, position):
        self.moveCursor(QTextCursor.StartOfLine)
        for i in range(len(self.prompt) + position):
            self.moveCursor(QTextCursor.Right)

    def register_command(self, c, func):
        methods = {c: func}
        self.updateNamespace(methods)

    def runCommand(self):
        command = self.getCommand()
        self.addToHistory(command)

        command = self.getConstruct(command)

        if command:
            tmp_stdout = sys.stdout

            class stdoutProxy():
                def __init__(self, write_func):
                    self.write_func = write_func
                    self.skip = False

                def flush(self):
                    pass

                def write(self, text):
                    if not self.skip:
                        stripped_text = text.rstrip('\n')
                        self.write_func(stripped_text)
                        QtCore.QCoreApplication.processEvents()
                    self.skip = not self.skip

            sys.stdout = stdoutProxy(self.appendPlainText)
            try:
                try:
                    # eval is generally considered bad practice. use it wisely!
                    # pylint: disable=eval-used
                    result = eval(command, self.namespace, self.namespace)
                    if result is not None:
                        if self.is_json:
                            print(util.json_encode(result))
                        else:
                            self.appendPlainText(repr(result))
                except SyntaxError:
                    # exec is generally considered bad practice. use it wisely!
                    # pylint: disable=exec-used
                    exec(command, self.namespace, self.namespace)
            except SystemExit:
                self.close()
            except Exception:
                # Catch errors in the network layer as well, as long as it uses Exception.
                traceback_lines = traceback.format_exc().split('\n')
                # Remove traceback mentioning this file, and a linebreak
                for i in (3, 2, 1, -1):
                    traceback_lines.pop(i)
                self.appendPlainText('\n'.join(traceback_lines))
            sys.stdout = tmp_stdout
        self.newPrompt()
        self.set_json(False)

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Tab:
            self.completions()
            return

        self.hide_completions()

        if event.key() in (QtCore.Qt.Key_Enter, QtCore.Qt.Key_Return):
            self.runCommand()
            return
        if event.key() == QtCore.Qt.Key_Home:
            self.setCursorPosition(0)
            return
        if event.key() == QtCore.Qt.Key_PageUp:
            return
        elif event.key() in (QtCore.Qt.Key_Left, QtCore.Qt.Key_Backspace):
            if self.getCursorPosition() == 0:
                return
        elif event.key() == QtCore.Qt.Key_Up:
            self.setCommand(self.getPrevHistoryEntry())
            return
        elif event.key() == QtCore.Qt.Key_Down:
            self.setCommand(self.getNextHistoryEntry())
            return
        elif event.key() == QtCore.Qt.Key_L and event.modifiers() == QtCore.Qt.ControlModifier:
            self.clear()

        super(Console, self).keyPressEvent(event)

    def completions(self):
        cmd = self.getCommand()
        lastword = re.split(r' |\(|\)', cmd)[-1]
        beginning = cmd[0: -len(lastword)]

        path = lastword.split('.')
        prefix = '.'.join(path[:-1])
        prefix = (prefix + '.') if prefix else prefix
        ns = self.namespace.keys()

        if len(path) > 1:
            obj = self.namespace.get(path[0])
            try:
                for attr in path[1:-1]:
                    obj = getattr(obj, attr)
            except AttributeError:
                ns = []
            else:
                ns = dir(obj)

        completions = []
        for name in ns:
            if name[0] == '_':
                continue
            if name.startswith(path[-1]):
                completions.append(prefix + name)
        completions.sort()

        if not completions:
            self.hide_completions()
        elif len(completions) == 1:
            self.hide_completions()
            self.setCommand(beginning + completions[0])
        else:
            # find common prefix
            p = os.path.commonprefix(completions)
            if len(p) > len(lastword):
                self.hide_completions()
                self.setCommand(beginning + p)
            else:
                self.show_completions(completions)


welcome_message = '''
   ---------------------------------------------------------------
     Welcome to a primitive Python interpreter.
   ---------------------------------------------------------------
'''

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    console = Console(startup_message=welcome_message)
    console.updateNamespace({'myVar1': app, 'myVar2': 1234})
    console.show()
    sys.exit(app.exec_())
