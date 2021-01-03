import concurrent
from enum import IntEnum
from functools import partial, lru_cache
import os.path
import sys
import time
import traceback
from typing import Any, Iterable, List, Callable, Optional, Set, TYPE_CHECKING, Union
import weakref

from aiorpcx import RPCError

from PyQt5.QtCore import (pyqtSignal, Qt, QCoreApplication, QDir, QLocale, QProcess,
    QModelIndex, QSize, QTimer)
from PyQt5.QtGui import QFont, QCursor, QIcon, QKeyEvent, QColor, QPalette, QPixmap, QResizeEvent
from PyQt5.QtWidgets import (
    QAbstractButton, QButtonGroup, QDialog, QGridLayout, QGroupBox, QMessageBox, QHBoxLayout,
    QHeaderView, QLabel, QLayout, QLineEdit, QFileDialog, QFrame, QPlainTextEdit, QProgressBar,
    QPushButton, QRadioButton, QSizePolicy, QStyle, QStyledItemDelegate, QTableWidget,
    QToolButton, QToolTip, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget, QWizard
)
from PyQt5.uic import loadUi

from electrumsv.app_state import app_state
from electrumsv.constants import DATABASE_EXT
from electrumsv.exceptions import WaitingTaskCancelled
from electrumsv.i18n import _, languages
from electrumsv.logs import logs
from electrumsv.types import WaitingUpdateCallback
from electrumsv.util import resource_path

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


logger = logs.get_logger("qt-util")

dialogs = []


class EnterButton(QPushButton):
    def __init__(self, text, func, parent: Optional[QWidget]=None):
        super().__init__(text, parent)
        self.func = func
        self.clicked.connect(func)

    def keyPressEvent(self, e: QKeyEvent):
        if e.key() in (Qt.Key_Return, Qt.Key_Enter):
            self.func()


class KeyEventLineEdit(QLineEdit):
    key_event_signal = pyqtSignal(int)

    def __init__(self, parent: Optional[QWidget]=None, text: str='',
            override_events: Set[int]=frozenset()) -> None:
        QLineEdit.__init__(self, text, parent)

        self._override_events = override_events

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in self._override_events:
            self.key_event_signal.emit(event.key())
        else:
            super().keyPressEvent(event)



class WWLabel(QLabel):
    def __init__ (self, text="", parent=None):
        QLabel.__init__(self, text, parent)
        self.setWordWrap(True)


class HelpLabel(QLabel):
    def __init__(self, text, help_text, parent: Optional[QWidget]=None):
        super().__init__(text, parent)
        self.app = QCoreApplication.instance()
        self.font = QFont()
        self.set_help_text(help_text)

    def set_help_text(self, help_text):
        self.help_text = help_text

    def mouseReleaseEvent(self, x):
        QMessageBox.information(self, 'Help', self.help_text)

    def enterEvent(self, event):
        self.font.setUnderline(True)
        self.setFont(self.font)
        self.app.setOverrideCursor(QCursor(Qt.PointingHandCursor))
        return QLabel.enterEvent(self, event)

    def leaveEvent(self, event):
        self.font.setUnderline(False)
        self.setFont(self.font)
        self.app.setOverrideCursor(QCursor(Qt.ArrowCursor))
        return QLabel.leaveEvent(self, event)


class HelpButton(QPushButton):
    def __init__(self, text, textFormat=Qt.AutoText, title="Help", button_text="?"):
        self.textFormat = textFormat
        self.title = title
        QPushButton.__init__(self, button_text)
        self.help_text = text
        self.setFocusPolicy(Qt.NoFocus)
        self.setFixedWidth(20)
        self.clicked.connect(self._on_clicked)

    def _on_clicked(self) -> None:
        b = QMessageBox()
        b.setIcon(QMessageBox.Information)
        b.setTextFormat(self.textFormat)
        b.setText(self.help_text)
        b.setWindowTitle(self.title)
        b.exec()


class Buttons(QHBoxLayout):
    _insert_index: int = 0

    # Need to be careful this only covers Buttons layouts, and not things like the buttons in
    # buttons edit widgets.
    STYLESHEET = """
        QAbstractButton {
            padding-top: 4px;
            padding-bottom: 4px;
            padding-left: 20px;
            padding-right: 20px;
        }
    """

    def __init__(self, *buttons: Iterable[QAbstractButton]) -> None:
        QHBoxLayout.__init__(self)
        self.addStretch(1)
        for b in buttons:
            self.addWidget(b)

    def add_left_button(self, button: QAbstractButton) -> None:
        self.insertWidget(self._insert_index, button)
        self._insert_index += 1


class CloseButton(QPushButton):
    def __init__(self, dialog):
        QPushButton.__init__(self, _("Close"))
        self.clicked.connect(dialog.accept)
        self.setDefault(True)

class CopyButton(QPushButton):
    def __init__(self, text_getter, app):
        QPushButton.__init__(self, _("Copy"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))

class CopyCloseButton(QPushButton):
    def __init__(self, text_getter, app, dialog):
        QPushButton.__init__(self, _("Copy and Close"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))
        self.clicked.connect(dialog.close)
        self.setDefault(True)

class OkButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("OK"))
        self.clicked.connect(dialog.accept)
        self.setDefault(True)

class CancelButton(QPushButton):
    def __init__(self, dialog, label=None):
        QPushButton.__init__(self, label or _("Cancel"))
        self.clicked.connect(dialog.reject)

class HelpDialogButton(QPushButton):
    def __init__(self, parent: QWidget, dirname: str, filename: str,
            label: Optional[str]=None) -> None:
        super().__init__(label or _("Help"))

        self._parent = parent
        self._dirname = dirname
        self._filename = filename

        self.clicked.connect(self._event_button_clicked)

    def _event_button_clicked(self) -> None:
        from .help_dialog import HelpDialog
        h = HelpDialog(self._parent, self._dirname, self._filename)
        h.run()


def query_choice(win, msg: str, choices: Iterable[str]) -> Optional[int]:
    # Needed by QtHandler for hardware wallets
    dialog = WindowModalDialog(win.top_level_window())
    clayout = ChoicesLayout(msg, choices)
    vbox = QVBoxLayout(dialog)
    vbox.addLayout(clayout.layout())
    vbox.addLayout(Buttons(OkButton(dialog)))
    if not dialog.exec_():
        return None
    return clayout.selected_index()


def top_level_window_recurse(window) -> QWidget:
    classes = (WindowModalDialog, QMessageBox, QWizard)
    for n, child in enumerate(window.children()):
        # Test for visibility as old closed dialogs may not be GC-ed
        if isinstance(child, classes) and child.isVisible():
            return top_level_window_recurse(child)
    return window


class MessageBoxMixin(object):
    def top_level_window(self):
        return top_level_window_recurse(self)

    def question(self, msg: str, parent=None, title=None, icon=None) -> int:
        Yes, No = QMessageBox.Yes, QMessageBox.No
        return self.msg_box(icon or QMessageBox.Question,
                            parent, title or '',
                            msg, buttons=Yes|No, defaultButton=No) == Yes

    def show_warning(self, msg: str, parent=None, title=None) -> int:
        return self.msg_box(QMessageBox.Warning, parent,
                            title or _('Warning'), msg)

    def show_error(self, msg: str, parent=None) -> int:
        return self.msg_box(QMessageBox.Warning, parent,
                            _('Error'), msg)

    def show_critical(self, msg: str, parent=None, title=None) -> int:
        return self.msg_box(QMessageBox.Critical, parent,
                            title or _('Critical Error'), msg)

    def show_message(self, msg: str, parent=None, title=None) -> int:
        return self.msg_box(QMessageBox.Information, parent,
                            title or _('Information'), msg)

    def msg_box(self, icon, parent, title, text, buttons=QMessageBox.Ok,
                defaultButton=QMessageBox.NoButton) -> int:
        parent = parent or self.top_level_window()
        d = QMessageBox(icon, title, str(text), buttons, parent)
        if not app_state.config.get('ui_disable_modal_dialogs', False):
            d.setWindowModality(Qt.WindowModal)
        d.setWindowFlags(d.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        d.setDefaultButton(defaultButton)
        return d.exec_()


class MessageBox:
    @classmethod
    def show_message(cls, msg, parent=None, title=None):
        return cls.msg_box(QMessageBox.Information, parent, title or _('Information'), msg)

    @classmethod
    def question(cls, msg, parent=None, title=None, icon=None):
        Yes, No = QMessageBox.Yes, QMessageBox.No
        return cls.msg_box(icon or QMessageBox.Question, parent, title or '',
                           msg, buttons=Yes|No, defaultButton=No) == Yes

    @classmethod
    def show_warning(cls, msg, parent=None, title=None):
        return cls.msg_box(QMessageBox.Warning, parent, title or _('Warning'), msg)

    @classmethod
    def show_error(cls, msg, parent=None, title=None):
        return cls.msg_box(QMessageBox.Warning, parent, title or _('Error'), msg)

    @classmethod
    def msg_box(cls, icon, parent, title, text, buttons=QMessageBox.Ok,
                defaultButton=QMessageBox.NoButton):
        d = QMessageBox(icon, title, str(text), buttons, parent)
        d.setWindowFlags(d.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        d.setDefaultButton(defaultButton)
        return d.exec_()


class UntrustedMessageDialog(QDialog):
    def __init__(self, parent, title, description, exception: Optional[Exception]=None,
            untrusted_text: str="") -> None:
        QDialog.__init__(self, parent, Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)
        self.setWindowTitle(title)
        self.setMinimumSize(500, 280)
        self.setMaximumSize(1000, 400)
        vbox = QVBoxLayout(self)
        text_label = QLabel(description)
        text_label.setWordWrap(True)
        vbox.addWidget(text_label)
        text_label = QLabel(_(
            "The server returned the following message, which may or may not help describe "
            "the problem.  A malicious server may return misleading messages, so act on it "
            "at your own risk.  In particular, do not download software from any links "
            "provided; the official ElectrumSV website is only https://electrumsv.io/."
        ))
        text_label.setWordWrap(True)
        vbox.addWidget(text_label)
        if isinstance(exception, RPCError):
            untrusted_text += str(exception)
        elif isinstance(exception, Exception):
            untrusted_text += "".join(traceback.TracebackException.from_exception(
                exception).format())
        text_edit = QPlainTextEdit(untrusted_text)
        text_edit.setReadOnly(True)
        vbox.addWidget(text_edit)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(self)))
        self.setLayout(vbox)

class WindowModalDialog(QDialog, MessageBoxMixin):
    '''Handy wrapper; window modal dialogs are better for our multi-window
    daemon model as other wallet windows can still be accessed.'''
    def __init__(self, parent, title: Optional[str]=None, hide_close_button: bool=False):
        flags = Qt.WindowSystemMenuHint | Qt.WindowTitleHint
        # This is the window close button, not any one we add ourselves.
        if not hide_close_button:
            flags |= Qt.WindowCloseButtonHint
        QDialog.__init__(self, parent, flags)
        if not app_state.config.get('ui_disable_modal_dialogs', False):
            self.setWindowModality(Qt.WindowModal)
        if title:
            self.setWindowTitle(title)


WaitingCompletionCallback = Optional[Callable[[concurrent.futures.Future], None]]

class WaitingDialog(WindowModalDialog):
    """
    Shows a please wait dialog whilst runnning a task.  It is not necessary to maintain a reference
    to this dialog.

    Possible user experiences:
    - Task completes and dismissal count ends.
      - Use the `on_done` argument to notify the creator with the completed future.
      - `accept`
    - Task completes and user dismisses before the count ends.
      - Use the `on_done` argument to notify the creator with a `None` value.
      - `reject`
    - User closes the dialog before the task completes cancelling the task.
      - Use the `on_done` argument to notify the creator with a `None` value.
      - `reject`

    If a task does work, and is interrupted while doing this work, it should not be expected that
    the work done to that point is rolled back or never happened. An example of this is
    broadcasting a transaction, where the start of the work is the posting of a transaction
    to a remote node. The broadcasting process may wait for a response and incur rate limiting
    on the remote service delaying things, and interruption just prevents learning of the response.
    """
    advance_progress_signal = pyqtSignal(object, object)

    _title: Optional[str] = None

    _future: Optional[concurrent.futures.Future] = None
    _on_done_callback: WaitingCompletionCallback = None
    _was_accepted: bool = False
    _was_rejected: bool = False

    def __init__(self, parent: QWidget, message: str, func, *args,
            on_done: WaitingCompletionCallback=None, title: Optional[str]=None,
            watch_events: bool=False, progress_steps: int=0, close_delay: int=0,
            allow_cancel: bool=False) -> None:
        assert parent
        if title is None:
            title = _("Please wait")
        # Disable the window close button, not any one we add ourselves.
        super().__init__(parent, title)

        # If we do not do this, waiting dialogs get leaked. This can be observed by commenting
        # out this line and looking for the `__del__` call which should happen after this
        # dialog is closed.
        self.setAttribute(Qt.WA_DeleteOnClose)

        self._title = title
        self._base_message = message
        self._close_delay = close_delay

        self._main_label = QLabel()
        self._main_label.setAlignment(Qt.AlignCenter)
        self._main_label.setWordWrap(True)

        self._secondary_label = QLabel()
        self._secondary_label.setAlignment(Qt.AlignCenter)
        self._secondary_label.setWordWrap(True)

        self._progress_bar: Optional[QProgressBar] = None
        if progress_steps:
            progress_bar = self._progress_bar = QProgressBar()
            progress_bar.setRange(0, progress_steps)
            progress_bar.setValue(0)
            progress_bar.setOrientation(Qt.Horizontal)
            progress_bar.setMinimumWidth(250)
            # This explicitly needs to be done for the progress bar else it has some RHS space.
            progress_bar.setAlignment(Qt.AlignCenter)

        self.advance_progress_signal.connect(self._advance_progress)

        self._dismiss_button = QPushButton(_("Dismiss"))
        self._dismiss_button.clicked.connect(self.accept)
        self._dismiss_button.setEnabled(False)

        vbox = QVBoxLayout(self)
        vbox.addWidget(self._main_label)
        vbox.addWidget(self._secondary_label)
        if self._progress_bar is not None:
            vbox.addWidget(self._progress_bar)
        button_box_1 = QHBoxLayout()
        lm, tm, rm, bm = button_box_1.getContentsMargins()
        button_box_1.setContentsMargins(lm, tm + 10, rm, bm)
        button_box_1.addWidget(self._dismiss_button, False, Qt.AlignHCenter)
        vbox.addLayout(button_box_1)

        args = (*args, self._step_progress)
        # NOTE: The `on_done` callback runs in the GUI thread.
        self._on_done_callback = on_done
        self._future = app_state.app.run_in_thread(func, *args, on_done=self._on_run_done)

        self.accepted.connect(self._on_accepted)
        self.rejected.connect(self._on_rejected)

        self.update_message(_("Please wait."))
        self.setMinimumSize(250, 100)
        self.show()

    def __del__(self) -> None:
        logger.debug("%s[%s]: deleted", self.__class__.__name__, self._title)

    def _on_accepted(self) -> None:
        if self._was_accepted or self._was_rejected or self._future is None:
            return
        self._was_accepted = True
        self._future.cancel()

    def _on_rejected(self) -> None:
        if self._was_accepted or self._was_rejected or self._future is None:
            return
        self._was_rejected = True
        self._future.cancel()

    def _step_progress(self, advance: bool, message: Optional[str]=None) -> None:
        # This is likely called from the threaded task. It effectively passes over the arguments
        # to the GUI thread to deal with.
        try:
            self.advance_progress_signal.emit(advance, message)
        except RuntimeError:
            # This happens because of the DeleteOnClose setting.
            # "RuntimeError: wrapped C/C++ object of type WaitingDialog has been deleted"
            raise WaitingTaskCancelled()

    def _on_run_done(self, future: concurrent.futures.Future) -> None:
        self._advance_dismissal_process(self._close_delay)

    def _advance_dismissal_process(self, remaining_steps: int) -> None:
        if not (self._was_accepted or self._was_rejected) and remaining_steps > 0:
            self._dismiss_button.setEnabled(True)
            self._dismiss_button.setText(_("Dismiss ({})").format(remaining_steps))
            QTimer.singleShot(1000, partial(self._advance_dismissal_process, remaining_steps-1))
        else:
            self._dispatch_result()

    def _dispatch_result(self) -> None:
        if self._future is None:
            return
        future = self._future
        self._future = None
        on_done_callback = self._on_done_callback
        self._on_done_callback = None

        # To get here the future has to have completed successfully (or unsuccessfully).
        assert future.done()
        if not future.cancelled() and not self._was_accepted:
            self.accept()
        QTimer.singleShot(0, partial(on_done_callback, future))

    def _relay_watch_event(self) -> None:
        self.watch_signal.emit(self)

    def update_message(self, extra_message: Optional[str]=None) -> None:
        self._main_label.setText(self._base_message)
        self._secondary_label.setText(extra_message or ' ')

    def _advance_progress(self, advance: bool, message: Optional[str]=None) -> None:
        if advance and self._progress_bar is not None:
            self._progress_bar.setValue(self._progress_bar.value()+1)
        if message is not None:
            self.update_message(message)

    @classmethod
    def test(cls, window: 'ElectrumWindow', delay: int=5) -> None:
        title = "title"
        message = "message"
        steps = 5

        def func(update_cb: WaitingUpdateCallback) -> Optional[bool]:
            nonlocal delay, steps
            interval = delay / steps
            for i in range(steps):
                update_message = "Working on it (even).." if i % 2 else "Working on it (odd).."
                update_cb(False, update_message)
                time.sleep(interval)
                try:
                    update_cb(True)
                except WaitingTaskCancelled:
                    return None
            update_cb(False, "Done")
            return True

        def completed(future: concurrent.futures.Future) -> None:
            try:
                data = future.result()
            except concurrent.futures.CancelledError:
                logger.debug(f"{cls.__name__} cancelled")
            except Exception as exc:
                logger.exception(f"{cls.__name__} errored with: {exc}")
            else:
                logger.debug(f"{cls.__name__} completed with: {data}")

        return cls(window, message, func, title=title, progress_steps=steps, on_done=completed,
            allow_cancel=True, close_delay=5)


def line_dialog(parent: QWidget, title: str, label: str, ok_label: str,
        default: Optional[str]=None) -> Optional[str]:
    dialog = WindowModalDialog(parent, title)
    dialog.setMinimumWidth(500)
    l = QVBoxLayout()
    dialog.setLayout(l)
    l.addWidget(QLabel(label))
    ok_button = OkButton(dialog, ok_label)
    txt = QLineEdit()
    def enable_OK() -> None:
        nonlocal txt, ok_button
        new_text = txt.text().strip()
        ok_button.setEnabled(len(new_text))
    txt.textChanged.connect(enable_OK)
    if default:
        default = default.strip()
        txt.setText(default)
    l.addWidget(txt)
    enable_OK()
    txt.setFocus(True)
    txt.selectAll()
    l.addLayout(Buttons(CancelButton(dialog), ok_button))
    if dialog.exec_():
        return txt.text().strip()

def text_dialog(parent, title, label, ok_label, default=None, allow_multi=False):
    from .qrtextedit import ScanQRTextEdit
    dialog = WindowModalDialog(parent, title)
    dialog.setMinimumWidth(500)
    l = QVBoxLayout()
    dialog.setLayout(l)
    l.addWidget(QLabel(label))
    txt = ScanQRTextEdit(allow_multi=allow_multi)
    if default:
        txt.setText(default)
    l.addWidget(txt)
    l.addLayout(Buttons(CancelButton(dialog), OkButton(dialog, ok_label)))
    if dialog.exec_():
        return txt.toPlainText()

class ChoicesLayout(object):
    def __init__(self, msg: str, choices, on_clicked=None, checked_index=0):
        vbox = QVBoxLayout()
        if len(msg) > 50:
            vbox.addWidget(WWLabel(msg))
            msg = ""
        gb2 = QGroupBox(msg)
        vbox.addWidget(gb2)

        vbox2 = QVBoxLayout()
        gb2.setLayout(vbox2)

        self.group = group = QButtonGroup()
        for i,c in enumerate(choices):
            button = QRadioButton(gb2)
            button.setText(c)
            vbox2.addWidget(button)
            group.addButton(button)
            group.setId(button, i)
            if i==checked_index:
                button.setChecked(True)

        if on_clicked:
            group.buttonClicked.connect(partial(on_clicked, self))

        self.vbox = vbox

    def layout(self):
        return self.vbox

    def selected_index(self) -> int:
        return self.group.checkedId()


def filename_field(config, defaultname, select_msg):
    vbox = QVBoxLayout()
    gb = QGroupBox(_("Format"))
    gbox = QHBoxLayout()
    b1 = QRadioButton(gb)
    b1.setText(_("CSV"))
    b1.setChecked(True)
    b2 = QRadioButton(gb)
    b2.setText(_("JSON"))
    gbox.addWidget(b1)
    gbox.addWidget(b2)
    gb.setLayout(gbox)
    vbox.addWidget(gb)

    hbox = QHBoxLayout()

    directory = config.get('io_dir', os.path.expanduser('~'))
    path = os.path.join( directory, defaultname )
    filename_e = QLineEdit()
    filename_e.setText(path)

    def func():
        text = filename_e.text()
        _filter = ("*.csv" if text.endswith(".csv") else
                   "*.json" if text.endswith(".json") else
                   None)
        p, __ = QFileDialog.getSaveFileName(None, select_msg, text, _filter)
        if p:
            filename_e.setText(p)

    button = QPushButton(_('File'))
    button.clicked.connect(func)
    hbox.addWidget(button)
    hbox.addWidget(filename_e)
    vbox.addLayout(hbox)

    def set_csv(v):
        text = filename_e.text()
        text = text.replace(".json",".csv") if v else text.replace(".csv",".json")
        filename_e.setText(text)

    b1.clicked.connect(lambda: set_csv(True))
    b2.clicked.connect(lambda: set_csv(False))

    return vbox, filename_e, b1

class ElectrumItemDelegate(QStyledItemDelegate):
    def createEditor(self, parent, option, index):
        return self.parent().createEditor(parent, option, index)

class MyTreeWidget(QTreeWidget):

    def __init__(self, parent: QWidget, main_window: 'ElectrumWindow', create_menu, headers,
            stretch_column=None, editable_columns=None):
        QTreeWidget.__init__(self, parent)

        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)

        self._main_window = weakref.proxy(main_window)
        self.config = self._main_window.config
        self.stretch_column = stretch_column
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(create_menu)
        # extend the syntax for consistency
        self.addChild = self.addTopLevelItem
        self.insertChild = self.insertTopLevelItem

        # Control which columns are editable
        self.editor = None
        self.pending_update = False
        if editable_columns is None:
            editable_columns = [stretch_column]
        self.editable_columns = editable_columns
        self.setItemDelegate(ElectrumItemDelegate(self))
        self.itemDoubleClicked.connect(self.on_doubleclick)
        self.update_headers(headers)
        self.current_filter = ""

    def update_headers(self, headers):
        self.setColumnCount(len(headers))
        self.setHeaderLabels(headers)
        self.header().setStretchLastSection(False)
        for col in range(len(headers)):
            sm = (QHeaderView.Stretch if col == self.stretch_column
                  else QHeaderView.ResizeToContents)
            self.header().setSectionResizeMode(col, sm)

    def editItem(self, item, column):
        if column in self.editable_columns:
            self.editing_itemcol = (item, column, item.text(column))
            # Calling setFlags causes on_changed events for some reason
            item.setFlags(item.flags() | Qt.ItemIsEditable)
            QTreeWidget.editItem(self, item, column)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)

    def keyPressEvent(self, event: QKeyEvent):
        if event.key() in [ Qt.Key_F2, Qt.Key_Return ] and self.editor is None:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def permit_edit(self, item, column):
        return (column in self.editable_columns
                and self.on_permit_edit(item, column))

    def on_permit_edit(self, item, column):
        return True

    def on_doubleclick(self, item, column):
        if self.permit_edit(item, column):
            self.editItem(item, column)

    def on_activated(self, item, column):
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def createEditor(self, parent, option, index):
        self.editor = QStyledItemDelegate.createEditor(self.itemDelegate(),
                                                       parent, option, index)
        self.editor.editingFinished.connect(self.editing_finished)
        return self.editor

    def editing_finished(self) -> None:
        # Long-time QT bug - pressing Enter to finish editing signals
        # editingFinished twice.  If the item changed the sequence is
        # Enter key:  editingFinished, on_change, editingFinished
        # Mouse: on_change, editingFinished
        # This mess is the cleanest way to ensure we make the
        # on_edited callback with the updated item
        if self.editor:
            (item, column, prior_text) = self.editing_itemcol
            if self.editor.text() == prior_text:
                self.editor = None  # Unchanged - ignore any 2nd call
            elif item.text(column) == prior_text:
                pass # Buggy first call on Enter key, item not yet updated
            else:
                # What we want - the updated item
                self.on_edited(*self.editing_itemcol)
                self.editor = None

            # Now do any pending updates
            if self.editor is None and self.pending_update:
                self.pending_update = False
                self.on_update()

    def on_edited(self, item, column, prior) -> None:
        '''Called only when the text actually changes'''
        text = item.text(column).strip()
        if text == "":
            text = None
        account_id, tx_hash = item.data(0, Qt.UserRole)
        self._main_window._wallet.set_transaction_label(tx_hash, text)
        self._main_window.history_view.update_tx_labels()

    def update(self) -> None:
        # Defer updates if editing
        if self.editor:
            self.pending_update = True
        else:
            self.on_update()
        if self.current_filter:
            self.filter(self.current_filter)

    def on_update(self):
        pass

    def get_leaves(self, root):
        child_count = root.childCount()
        if child_count == 0:
            yield root
        for i in range(child_count):
            item = root.child(i)
            for x in self.get_leaves(item):
                yield x

    def filter(self, p):
        columns = self.__class__.filter_columns
        p = p.lower()
        self.current_filter = p
        for item in self.get_leaves(self.invisibleRootItem()):
            item.setHidden(all([item.text(column).lower().find(p) == -1
                                for column in columns]))


class ButtonsMode(IntEnum):
    INTERNAL = 0
    TOOLBAR_RIGHT = 1
    TOOLBAR_BOTTOM = 2



class ButtonsWidget(QWidget):
    buttons_mode = ButtonsMode.INTERNAL
    qt_css_extra = ""

    def __init__(self):
        super().__init__()
        self.buttons: Iterable[QAbstractButton] = []

    def resizeButtons(self):
        frame_width = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        if self.buttons_mode == ButtonsMode.INTERNAL:
            x = self.rect().right() - frame_width
            y = self.rect().top() + frame_width
            for button in self.buttons:
                sz = button.sizeHint()
                x -= sz.width()
                button.move(x, y)
        elif self.buttons_mode == ButtonsMode.TOOLBAR_RIGHT:
            x = self.rect().right() - frame_width
            y = self.rect().top() - frame_width
            for i, button in enumerate(self.buttons):
                sz = button.sizeHint()
                if i > 0:
                    y += sz.height()
                button.move(x - sz.width(), y)
        elif self.buttons_mode == ButtonsMode.TOOLBAR_BOTTOM:
            x = self.rect().left() - frame_width
            y = self.rect().bottom() + frame_width
            for i, button in enumerate(self.buttons):
                sz = button.sizeHint()
                if i > 0:
                    x += sz.width()
                button.move(x, y - sz.height())

    def addButton(self, icon_name: str, on_click: Callable[[], None], tooltip: str,
            insert: bool=False) -> None:
        button = QToolButton(self)
        button.setIcon(read_QIcon(icon_name))
        # Horizontal buttons are inside the edit widget and do not have borders.
        if self.buttons_mode == ButtonsMode.INTERNAL:
            button.setStyleSheet("QToolButton { border: none; hover {border: 1px} "
                                "pressed {border: 1px} padding: 0px; }")
        button.setVisible(True)
        button.setToolTip(tooltip)
        button.setCursor(QCursor(Qt.PointingHandCursor))
        button.clicked.connect(on_click)
        if insert:
            self.buttons.insert(0, button)
        else:
            self.buttons.append(button)

        # Vertical buttons are integrated into the widget, within a margin that moves the edge
        # of the edit widget over to make space.
        frame_width = self.style().pixelMetric(QStyle.PM_DefaultFrameWidth)
        if self.buttons_mode == ButtonsMode.TOOLBAR_RIGHT:
            self.button_padding = max(button.sizeHint().width() for button in self.buttons) + 4
            self.setStyleSheet(self.qt_css_class +
                " { margin-right: "+ str(self.button_padding) +"px; }"+
                self.qt_css_extra)
        elif self.buttons_mode == ButtonsMode.TOOLBAR_BOTTOM:
            self.button_padding = max(button.sizeHint().height() for button in self.buttons) + \
                frame_width
            self.setStyleSheet(
                self.qt_css_class +" { margin-bottom: "+ str(self.button_padding) +"px; }"+
                self.qt_css_extra)
        return button

    def addCopyButton(self, app, tooltipText: Optional[str]=None) -> QAbstractButton:
        if tooltipText is None:
            tooltipText = _("Copy to clipboard")
        self.app = app
        return self.addButton("icons8-copy-to-clipboard-32.png", self._on_copy,
            tooltipText)

    def _on_copy(self) -> None:
        self.app.clipboard().setText(self.text())
        QToolTip.showText(QCursor.pos(), _("Text copied to clipboard"), self)


class ButtonsLineEdit(KeyEventLineEdit, ButtonsWidget):
    qt_css_class = "QLineEdit"

    def __init__(self, text=''):
        KeyEventLineEdit.__init__(self, None, text, {Qt.Key_Return, Qt.Key_Enter})
        self.buttons: Iterable[QAbstractButton] = []

    def resizeEvent(self, event: QResizeEvent) -> None:
        QLineEdit.resizeEvent(self, event)
        self.resizeButtons()
        buttons_width = 0
        for button in self.buttons:
            buttons_width += button.size().width()
        self.setTextMargins(0, 0, buttons_width, 0)


class ButtonsTextEdit(QPlainTextEdit, ButtonsWidget):
    qt_css_class = "QPlainTextEdit"

    def __init__(self, text: Optional[str]=None) -> None:
        QPlainTextEdit.__init__(self, text)
        self.setText = self.setPlainText
        self.text = self.toPlainText
        self.buttons: Iterable[QAbstractButton] = []

    def resizeEvent(self, event: QResizeEvent) -> None:
        QPlainTextEdit.resizeEvent(self, event)
        self.resizeButtons()


class ButtonsTableWidget(QTableWidget, ButtonsWidget):
    buttons_mode = ButtonsMode.TOOLBAR_BOTTOM
    qt_css_class = "QTableWidget"

    def __init__(self, parent: Optional[QWidget]=None,
            buttons_mode: ButtonsMode=ButtonsMode.TOOLBAR_RIGHT) -> None:
        self.buttons_mode = buttons_mode
        QTableWidget.__init__(self, parent)
        self.buttons: Iterable[QAbstractButton] = []

    def resizeEvent(self, event: QResizeEvent) -> None:
        QTableWidget.resizeEvent(self, event)
        self.resizeButtons()


class ColorSchemeItem:
    def __init__(self, fg_color, bg_color):
        self.colors = (fg_color, bg_color)

    def _get_color(self, background):
        return self.colors[(int(background) + int(ColorScheme.dark_scheme)) % 2]

    def as_stylesheet(self, background: bool=False, class_name: str="QWidget", id_name: str="") \
            -> str:
        css_prefix = "background-" if background else ""
        color = self._get_color(background)
        key_name = class_name
        if id_name:
            key_name += "#"+ id_name
        return "{} {{ {}color:{}; }}".format(key_name, css_prefix, color)

    def as_color(self, background=False):
        color = self._get_color(background)
        return QColor(color)


class ColorScheme:
    dark_scheme = False

    DEFAULT = ColorSchemeItem("black", "white")
    BLUE = ColorSchemeItem("#123b7c", "#8cb3f2")
    GREEN = ColorSchemeItem("#117c11", "#8af296")
    RED = ColorSchemeItem("#7c1111", "#f18c8c")
    YELLOW = ColorSchemeItem("yellow", "yellow")

    @staticmethod
    def has_dark_background(widget):
        brightness = sum(widget.palette().color(QPalette.Background).getRgb()[0:3])
        return brightness < (255*3/2)

    @staticmethod
    def update_from_widget(widget):
        if ColorScheme.has_dark_background(widget):
            ColorScheme.dark_scheme = True


class SortableTreeWidgetItem(QTreeWidgetItem):
    DataRole = Qt.UserRole + 1

    def __lt__(self, other):
        column = self.treeWidget().sortColumn()
        self_data = self.data(column, self.DataRole)
        other_data = other.data(column, self.DataRole)
        if None not in (self_data, other_data):
            # We have set custom data to sort by
            return self_data < other_data
        try:
            # Is the value something numeric?
            self_text = self.text(column).replace(',', '')
            other_text = other.text(column).replace(',', '')
            return float(self_text) < float(other_text)
        except ValueError:
            # If not, we will just do string comparison
            return self.text(column) < other.text(column)


def update_fixed_tree_height(tree: QTreeWidget, maximum_height=None):
    # We can't always rely on the manually set maximum height sticking.
    # It's possible the setting of the fixed height explicitly replaces it.
    if maximum_height is None:
        maximum_height = tree.maximumHeight()

    tree_model = tree.model()
    cell_index = tree_model.index(0, 1)
    row_height = tree.rowHeight(cell_index)
    if row_height == 0:
        row_height = tree.header().height()
    row_count = tree_model.rowCount()
    table_height = row_height * row_count
    if maximum_height > 5:
        table_height = min(table_height, maximum_height)
    if tree.header().isVisible:
        table_height += tree.header().height() + 2
    tree.setFixedHeight(table_height)


def protected(func):
    '''Password request wrapper.  The password is passed to the function
    as the 'password' named argument.  "None" indicates either an
    unencrypted wallet, or the user cancelled the password request.
    An empty input is passed as the empty string.'''
    def request_password(self, *args, **kwargs):
        main_window = self
        if 'main_window' in kwargs:
            main_window = kwargs['main_window']
        elif 'wallet_id' in kwargs:
            main_window = app_state.app.get_wallet_window_by_id(kwargs['wallet_id'])

        parent = main_window.top_level_window()
        password: Optional[str] = None
        while True:
            password = main_window.password_dialog(parent=parent)
            if password is None:
                # User cancelled password input
                return
            try:
                main_window._wallet.check_password(password)
                break
            except Exception as e:
                main_window.show_error(str(e), parent=parent)
                continue

        kwargs['password'] = password
        return func(self, *args, **kwargs)
    return request_password


def icon_path(icon_basename):
    return resource_path('icons', icon_basename)

def read_qt_ui(ui_name):
    return loadUi(resource_path("ui", ui_name))

@lru_cache()
def read_QIcon(icon_basename):
    return QIcon(icon_path(icon_basename))

def get_source_index(model_index: QModelIndex, klass: Any):
    model = model_index.model()
    while model is not None and not isinstance(model, klass):
        model_index = model.mapToSource(model_index)
        model = model_index.model()
    return model_index

def get_default_language():
    name = QLocale.system().name()
    return name if name in languages else 'en_UK'

def can_show_in_file_explorer() -> bool:
    return sys.platform in ('win32', 'darwin')

def show_in_file_explorer(path: str) -> bool:
    # https://stackoverflow.com/a/46019091/11881963
    if sys.platform == 'win32':
        args = []
        if not os.path.isdir(path):
            args.append('/select,')
        args.append(QDir.toNativeSeparators(path))
        QProcess.startDetached('explorer', args)
    elif sys.platform == 'darwin':
        args = [
            '-e', 'tell application "Finder"',
            '-e', 'activate',
            '-e', 'select POSIX file "%s"' % path,
            '-e', 'end tell',
            '-e', 'return',
        ]
        QProcess.execute('/usr/bin/osascript', args)


def create_new_wallet(parent: QWidget, initial_dirpath: str) -> Optional[str]:
    create_filepath, __ = QFileDialog.getSaveFileName(parent, _("Enter a new wallet file name"),
        initial_dirpath)
    if not create_filepath:
        return None

    # QFileDialog.getSaveFileName uses forward slashes for "easier pathing".. correct this.
    create_filepath = os.path.normpath(create_filepath)

    if os.path.exists(create_filepath):
        MessageBox.show_error(_("Overwriting existing files not supported at this time."))
        return None

    dirpath, filename = os.path.split(create_filepath)

    if not create_filepath.endswith(DATABASE_EXT):
        if os.path.exists(create_filepath + DATABASE_EXT):
            MessageBox.show_error(_("The file name '{}' is already in use.").format(filename))
            return None

    if not dirpath or not os.path.isdir(dirpath) or not os.access(dirpath, os.R_OK | os.W_OK):
        MessageBox.show_error(_("The selected directory is not accessible."))
        return None

    name_edit = QLabel(filename)
    fields = [
        (QLabel(_("Wallet") +":"), name_edit),
    ]
    from .password_dialog import ChangePasswordDialog, PasswordAction
    from .wallet_wizard import PASSWORD_NEW_TEXT
    d = ChangePasswordDialog(parent, PASSWORD_NEW_TEXT, _("Create New Wallet"), fields,
        kind=PasswordAction.NEW)
    success, _old_password, new_password = d.run()
    if not success or not new_password.strip():
        return None

    from electrumsv.storage import WalletStorage
    storage = WalletStorage.create(create_filepath, new_password)
    storage.close()
    return create_filepath


class FormSeparatorLine(QFrame):
    def __init__(self) -> None:
        super().__init__()

        self.setObjectName("FormSeparatorLine")
        self.setFrameShape(QFrame.HLine)
        self.setFixedHeight(1)


FieldType = Union[QWidget, QLayout]

class FormSectionWidget(QWidget):
    show_help_label: bool = True
    minimum_label_width: int = 80

    def __init__(self, parent: Optional[QWidget]=None,
            minimum_label_width: Optional[int]=None) -> None:
        super().__init__(parent)

        if minimum_label_width is not None:
            self.minimum_label_width = minimum_label_width

        self.frame_layout = QVBoxLayout()
        self._resizable_rows: List[QVBoxLayout] = []

        frame = QFrame()
        frame.setObjectName("FormFrame")
        frame.setLayout(self.frame_layout)

        self.setStyleSheet("""
        #FormSeparatorLine {
            border: 1px solid #E3E2E2;
        }

        #FormSectionLabel {
            color: #444444;
        }

        #FormFrame {
            background-color: #F2F2F2;
            border: 1px solid #E3E2E2;
        }
        """)

        vlayout = QVBoxLayout()
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.addWidget(frame)
        self.setLayout(vlayout)

    def create_title(self, title_text: str) -> QLabel:
        label = QLabel(title_text)
        label.setObjectName("FormSectionTitle")
        label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        return label

    def add_title(self, title_text: str) -> None:
        label = self.create_title(title_text)
        self.frame_layout.addWidget(label, Qt.AlignTop)

    def add_title_row(self, title_object: FieldType) -> None:
        if isinstance(title_object, QLayout):
            self.frame_layout.addLayout(title_object)
        else:
            self.frame_layout.addWidget(title_object, Qt.AlignTop)

    def add_row(self, label_text: Union[str, QLabel], field_object: FieldType,
            stretch_field: bool=False) -> Optional[QLabel]:
        result: Optional[QLabel] = None

        if self.frame_layout.count() > 0:
            self.frame_layout.addWidget(FormSeparatorLine())

        if isinstance(label_text, QLabel):
            label = label_text
            label_text = label.text()
        else:
            if not label_text.endswith(":"):
                label_text += ":"
            label = QLabel(label_text)
            result = label
        label.setObjectName("FormSectionLabel")
        label.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)

        label_width = label.fontMetrics().boundingRect(label_text).width() + 10
        old_minimum_width = self.minimum_label_width
        if label_width > self.minimum_label_width:
            self.minimum_label_width = label_width

        grid_layout = QGridLayout()
        grid_layout.setContentsMargins(0, 0, 0, 0)
        grid_layout.addWidget(label, 0, 0, Qt.AlignRight | Qt.AlignTop)
        if stretch_field:
            if isinstance(field_object, QLayout):
                grid_layout.addLayout(field_object, 0, 1, Qt.AlignTop)
            else:
                grid_layout.addWidget(field_object, 0, 1, Qt.AlignTop)
        else:
            field_layout = QHBoxLayout()
            field_layout.setContentsMargins(0, 0, 0, 0)
            if isinstance(field_object, QLayout):
                field_layout.addLayout(field_object)
            else:
                field_layout.addWidget(field_object)
            field_layout.addStretch(1)
            grid_layout.addLayout(field_layout, 0, 1, Qt.AlignTop)
        grid_layout.setColumnMinimumWidth(0, self.minimum_label_width)
        grid_layout.setColumnStretch(0, 0)
        grid_layout.setColumnStretch(1, 1)
        grid_layout.setHorizontalSpacing(10)
        grid_layout.setSizeConstraint(QLayout.SetMinimumSize)

        if self.minimum_label_width != old_minimum_width:
            for layout in self._resizable_rows:
                layout.setColumnMinimumWidth(0, self.minimum_label_width)

        self.frame_layout.addLayout(grid_layout)
        self._resizable_rows.append(grid_layout)
        return result


class FramedTextWidget(QLabel):
    def __init__(self, parent: Optional[QWidget]=None) -> None:
        super().__init__(parent)

        self.setWordWrap(True)
        self.setFrameStyle(QFrame.Panel | QFrame.Raised)
        self.setMargin(10)


class ClickableLabel(QLabel):
    clicked = pyqtSignal()

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        self.setCursor(Qt.PointingHandCursor)

    def mousePressEvent(self, ev):
        self.clicked.emit()


# Derived from: https://stackoverflow.com/a/22618496/11881963
class AspectRatioPixmapLabel(QLabel):
    _pixmap: Optional[QPixmap] = None

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setMinimumSize(1,1)
        self.setScaledContents(True)

    def setPixmap(self, pixmap: QPixmap) -> None:
        self._pixmap = pixmap
        super().setPixmap(self._scaled_pixmap())

    def heightForWidth(self, width: int) -> int:
        return self.height() if self._pixmap is None else \
            (self._pixmap.height() * width) / self._pixmap.width()

    def sizeHint(self) -> QSize:
        width = self.parent().width()
        return QSize(width, self.heightForWidth(width))

    def _scaled_pixmap(self) -> QPixmap:
        return self._pixmap.scaled(self.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)

    def resizeEvent(self, event: QResizeEvent) -> None:
        if self._pixmap is not None:
            super().setPixmap(self._scaled_pixmap())
        super().resizeEvent(event)

