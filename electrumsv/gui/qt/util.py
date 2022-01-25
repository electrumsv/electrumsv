import concurrent.futures
from enum import IntEnum
from functools import partial, lru_cache
import os
import sys
import traceback
from typing import Any, Callable, cast, Iterable, Generator, List, Optional, Protocol, Set, \
    Tuple, TYPE_CHECKING, TypeVar, Union
import weakref

from aiorpcx import RPCError

from PyQt5.QtCore import (pyqtSignal, Qt, QCoreApplication, QDir, QEvent, QLocale, QPoint,
    QProcess, QModelIndex, QSize, QTimer)
from PyQt5.QtGui import QColor, QCursor, QFont, QIcon, QKeyEvent, QMouseEvent, QPalette, QPixmap, \
    QResizeEvent
from PyQt5.QtWidgets import (
    QAbstractButton, QButtonGroup, QDialog, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
    QHeaderView, QLabel, QLayout, QLineEdit, QMessageBox, QFrame, QPlainTextEdit, QProgressBar,
    QPushButton, QRadioButton, QSizePolicy, QStyle, QStyledItemDelegate, QStyleOptionViewItem,
    QTableWidget, QToolButton, QToolTip, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
    QWizard
)
from PyQt5.uic import loadUi

from electrumsv.app_state import app_state, get_app_state_qt
from electrumsv.simple_config import SimpleConfig
from electrumsv.constants import CredentialPolicyFlag, DATABASE_EXT
from electrumsv.exceptions import WaitingTaskCancelled
from electrumsv.i18n import _, languages
from electrumsv.logs import logs
from electrumsv.util import resource_path

if TYPE_CHECKING:
    from .app import SVApplication
    from .main_window import ElectrumWindow


WT = TypeVar('WT')
D1 = TypeVar('D1', bound=Callable[..., Any])


logger = logs.get_logger("qt-util")

# dialogs = []


class EnterButton(QPushButton):
    def __init__(self, text: str, func: Callable[..., None], parent: Optional[QWidget]=None):
        super().__init__(text, parent)
        self.func = func
        self.clicked.connect(func)

    def keyPressEvent(self, e: QKeyEvent) -> None:
        if e.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.func()


class KeyEventLineEdit(QLineEdit):
    key_event_signal = pyqtSignal(int)

    def __init__(self, parent: Optional[QWidget]=None, text: str='',
            override_events: Optional[Set[int]]=None) -> None:
        QLineEdit.__init__(self, text, parent)

        if override_events is None:
            override_events = set()
        self._override_events = override_events

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in self._override_events:
            self.key_event_signal.emit(event.key())
        else:
            super().keyPressEvent(event)



class WWLabel(QLabel):
    def __init__ (self, text: str="", parent: Optional[QWidget]=None) -> None:
        QLabel.__init__(self, text, parent)
        self.setWordWrap(True)


class HelpLabel(QLabel):
    def __init__(self, text: str, help_text: str, parent: Optional[QWidget]=None) -> None:
        super().__init__(text, parent)
        app = QCoreApplication.instance()
        assert app is not None
        self.app = app
        self._font = QFont()
        self.set_help_text(help_text)

    def set_help_text(self, help_text: str) -> None:
        self.help_text = help_text

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        QMessageBox.information(self, 'Help', self.help_text)

    def enterEvent(self, event: QEvent) -> None:
        self._font.setUnderline(True)
        self.setFont(self._font)
        self.app.setOverrideCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        QLabel.enterEvent(self, event)

    def leaveEvent(self, event: QEvent) -> None:
        self._font.setUnderline(False)
        self.setFont(self._font)
        self.app.setOverrideCursor(QCursor(Qt.CursorShape.ArrowCursor))
        QLabel.leaveEvent(self, event)


class HelpButton(QPushButton):
    def __init__(self, text: str, textFormat: Qt.TextFormat=Qt.TextFormat.AutoText,
            title: str="Help", button_text: str="?") -> None:
        self.textFormat = textFormat
        self.title = title
        QPushButton.__init__(self, button_text)
        self.help_text = text
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
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
        QToolButton {
            padding-top: 4px;
            padding-bottom: 4px;
            padding-left: 20px;
            padding-right: 20px;
        }
    """

    def __init__(self, *buttons: QAbstractButton) -> None:
        QHBoxLayout.__init__(self)
        self.addStretch(1)
        for b in buttons:
            self.addWidget(b)

    def add_left_button(self, button: QAbstractButton) -> None:
        self.insertWidget(self._insert_index, button)
        self._insert_index += 1


class CloseButton(QPushButton):
    def __init__(self, dialog: QDialog) -> None:
        QPushButton.__init__(self, _("Close"))
        self.clicked.connect(dialog.accept)
        self.setDefault(True)


class CopyButton(QPushButton):
    def __init__(self, text_getter: Callable[[], str], app: QCoreApplication) -> None:
        QPushButton.__init__(self, _("Copy"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))

class CopyCloseButton(QPushButton):
    def __init__(self, text_getter: Callable[[], str], app: QCoreApplication,
            dialog: QDialog) -> None:
        QPushButton.__init__(self, _("Copy and Close"))
        self.clicked.connect(lambda: app.clipboard().setText(text_getter()))
        self.clicked.connect(dialog.close)
        self.setDefault(True)

class OkButton(QPushButton):
    def __init__(self, dialog: QDialog, label: Optional[str]=None) -> None:
        QPushButton.__init__(self, label or _("OK"))
        self.clicked.connect(dialog.accept)
        self.setDefault(True)

class CancelButton(QPushButton):
    def __init__(self, dialog: QDialog, label: Optional[str]=None) -> None:
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


class WindowProtocol(Protocol):
    def top_level_window(self) -> QWidget:
        raise NotImplementedError

    def question(self, msg: str, parent: Optional[QWidget]=None, title: Optional[str]=None,
            icon: Optional[QMessageBox.Icon]=None) -> bool:
        raise NotImplementedError

    def query_choice(self, msg: str, choices: Iterable[str], parent: Optional[QWidget]=None) \
            -> Optional[int]:
        raise NotImplementedError

    def show_error(self, msg: str, parent: Optional[QWidget]=None) -> int:
        raise NotImplementedError

    def show_warning(self, msg: str, parent: Optional[QWidget]=None,
            title: Optional[str]=None) -> int:
        raise NotImplementedError


def window_query_choice(window: QWidget, msg: str, choices: Iterable[str]) -> Optional[int]:
    dialog = WindowModalDialog(window)
    clayout = ChoicesLayout(msg, choices)
    vbox = QVBoxLayout(dialog)
    vbox.addLayout(clayout.layout())
    vbox.addLayout(Buttons(OkButton(dialog)))
    if not dialog.exec_():
        return None
    return clayout.selected_index()


def top_level_window_recurse(window: QWidget) -> QWidget:
    classes = (WindowModalDialog, QMessageBox, QWizard)
    for n, child in enumerate(window.children()):
        # Test for visibility as old closed dialogs may not be GC-ed
        if isinstance(child, classes) and child.isVisible():
            return top_level_window_recurse(child)
    return window


class MessageBoxMixin(object):
    def top_level_window(self) -> QWidget:
        return top_level_window_recurse(cast(QWidget, self))

    def question(self, msg: str, parent: Optional[QWidget]=None, title: Optional[str]=None,
            icon: Optional[QMessageBox.Icon]=None) -> bool:
        Yes, No = QMessageBox.Yes, QMessageBox.No
        return self.msg_box(icon or QMessageBox.Question,
                            parent, title or '',
                            msg, buttons=Yes|No, defaultButton=No) == Yes

    def query_choice(self, msg: str, choices: Iterable[str], parent: Optional[QWidget]=None) \
            -> Optional[int]:
        parent = parent or self.top_level_window()
        return window_query_choice(parent, msg, choices)

    def show_error(self, msg: str, parent: Optional[QWidget]=None) -> int:
        return self.msg_box(QMessageBox.Warning, parent,
                            _('Error'), msg)

    def show_warning(self, msg: str, parent: Optional[QWidget]=None,
            title: Optional[str]=None) -> int:
        return self.msg_box(QMessageBox.Warning, parent,
                            title or _('Warning'), msg)

    def show_critical(self, msg: str, parent: Optional[QWidget]=None,
            title: Optional[str]=None) -> int:
        return self.msg_box(QMessageBox.Critical, parent,
                            title or _('Critical Error'), msg)

    def show_message(self, msg: str, parent: Optional[QWidget]=None,
            title: Optional[str]=None) -> int:
        return self.msg_box(QMessageBox.Information, parent,
                            title or _('Information'), msg)

    def msg_box(self, icon: QMessageBox.Icon, parent: Optional[QWidget], title: str,
            text: str,
            buttons: QMessageBox.StandardButtons=QMessageBox.StandardButtons(QMessageBox.Ok),
            defaultButton: QMessageBox.StandardButton=QMessageBox.NoButton) -> int:
        parent = parent or self.top_level_window()
        d = QMessageBox(icon, title, str(text), buttons, parent)
        if not app_state.config.get('ui_disable_modal_dialogs', False):
            d.setWindowModality(Qt.WindowModality.WindowModal)
        window_flags = int(d.windowFlags()) & ~Qt.WindowType.WindowContextHelpButtonHint
        d.setWindowFlags(Qt.WindowType(window_flags))
        d.setDefaultButton(defaultButton)
        return d.exec_()



class MessageBox:
    @classmethod
    def show_message(cls, msg: str, parent: Optional[QWidget]=None,
            title: Optional[str]=None) -> int:
        return cls.msg_box(QMessageBox.Information, parent, title or _('Information'), msg)

    @classmethod
    def question(cls, msg: str, parent: Optional[QWidget]=None, title: Optional[str]=None,
            icon: Optional[QMessageBox.Icon]=None) -> int:
        Yes, No = QMessageBox.Yes, QMessageBox.No
        return cls.msg_box(icon or QMessageBox.Question, parent, title or '',
                           msg, buttons=Yes|No, defaultButton=No) == Yes

    @classmethod
    def show_warning(cls, msg: str, parent: Optional[QWidget]=None,
            title: Optional[str]=None) -> int:
        return cls.msg_box(QMessageBox.Warning, parent, title or _('Warning'), msg)

    @classmethod
    def show_error(cls, msg: str, parent: Optional[QWidget]=None, title: Optional[str]=None) -> int:
        return cls.msg_box(QMessageBox.Warning, parent, title or _('Error'), msg)

    @classmethod
    def msg_box(cls, icon: QMessageBox.Icon, parent: Optional[QWidget], title: str, text: str,
            buttons: QMessageBox.StandardButtons=QMessageBox.StandardButtons(QMessageBox.Ok),
            defaultButton: QMessageBox.StandardButton=QMessageBox.NoButton) -> int:
        d = QMessageBox(icon, title, str(text), buttons, parent)
        window_flags = int(d.windowFlags()) & ~Qt.WindowType.WindowContextHelpButtonHint
        d.setWindowFlags(Qt.WindowType(window_flags))
        d.setDefaultButton(defaultButton)
        return d.exec_()


class UntrustedMessageDialog(QDialog):
    def __init__(self, parent: QWidget, title: str, description: str,
            exception: Optional[Exception]=None, untrusted_text: str="") -> None:
        QDialog.__init__(self, parent, Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint))
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
    def __init__(self, parent: Optional[QWidget], title: Optional[str]=None,
            hide_close_button: bool=False) -> None:
        flags = Qt.WindowType.WindowSystemMenuHint | Qt.WindowType.WindowTitleHint
        # This is the window close button, not any one we add ourselves.
        if not hide_close_button:
            flags |= Qt.WindowType.WindowCloseButtonHint
        QDialog.__init__(self, parent, Qt.WindowType(flags))
        if not app_state.config.get('ui_disable_modal_dialogs', False):
            self.setWindowModality(Qt.WindowModality.WindowModal)
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

    _on_done_callback: WaitingCompletionCallback = None
    _was_accepted: bool = False
    _was_rejected: bool = False

    def __init__(self, parent: QWidget, message: str, func: Callable[..., WT],
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
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        self._title = title
        self._base_message = message
        self._close_delay = close_delay

        self._main_label = QLabel()
        self._main_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._main_label.setWordWrap(True)

        self._secondary_label = QLabel()
        self._secondary_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._secondary_label.setWordWrap(True)

        self._progress_bar: Optional[QProgressBar] = None
        if progress_steps:
            progress_bar = self._progress_bar = QProgressBar()
            progress_bar.setRange(0, progress_steps)
            progress_bar.setValue(0)
            progress_bar.setOrientation(Qt.Orientation.Horizontal)
            progress_bar.setMinimumWidth(250)
            # This explicitly needs to be done for the progress bar else it has some RHS space.
            progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)

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
        button_box_1.addWidget(self._dismiss_button, False, Qt.AlignmentFlag.AlignHCenter)
        vbox.addLayout(button_box_1)

        args = (self._step_progress,)
        # NOTE: `run_in_thread` ensures the `on_done` callback runs in the GUI thread.
        self._on_done_callback = on_done
        self._future: Optional[concurrent.futures.Future[WT]] = \
            cast("SVApplication", app_state.app).run_in_thread(func, *args,
            on_done=self._on_run_done)

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

    def _on_run_done(self, future: concurrent.futures.Future[Any]) -> None:
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
        assert on_done_callback is not None
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
        ok_button.setEnabled(len(new_text) > 0)
    txt.textChanged.connect(enable_OK)
    if default:
        default = default.strip()
        txt.setText(default)
    l.addWidget(txt)
    enable_OK()
    txt.setFocus()
    txt.selectAll()
    l.addLayout(Buttons(CancelButton(dialog), ok_button))
    if dialog.exec_():
        return txt.text().strip()
    return None


def text_dialog(parent: QWidget, title: str, label: str, ok_label: str, default: Optional[str]=None,
        allow_multi: bool=False) -> Optional[str]:
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
    return None


class ChoicesLayout(object):
    def __init__(self, msg: str, choices: Iterable[str],
            on_clicked: Optional[Callable[..., None]]=None, checked_index: int=0) -> None:
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

    def layout(self) -> QVBoxLayout:
        return self.vbox

    def selected_index(self) -> int:
        return self.group.checkedId()


def filename_field(config: SimpleConfig, defaultname: str, select_msg: str) \
        -> Tuple[QVBoxLayout, QLineEdit, QRadioButton]:
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

    directory = config.get_explicit_type(str, 'io_dir', os.path.expanduser('~'))
    path = os.path.join( directory, defaultname )
    filename_e = QLineEdit()
    filename_e.setText(path)

    def func() -> None:
        text = filename_e.text()
        _filter = ("*.csv" if text.endswith(".csv") else
                   "*.json" if text.endswith(".json") else
                   None)
        # NOTE(typing) None filter seems to be no filter, but unsupported by the type signature.
        p, __ = QFileDialog.getSaveFileName(None, select_msg, text, _filter) # type: ignore
        if p:
            filename_e.setText(p)

    button = QPushButton(_('File'))
    button.clicked.connect(func)
    hbox.addWidget(button)
    hbox.addWidget(filename_e)
    vbox.addLayout(hbox)

    def set_csv(v: bool) -> None:
        text = filename_e.text()
        text = text.replace(".json",".csv") if v else text.replace(".csv",".json")
        filename_e.setText(text)

    b1.clicked.connect(lambda: set_csv(True))
    b2.clicked.connect(lambda: set_csv(False))

    return vbox, filename_e, b1


class ElectrumItemDelegate(QStyledItemDelegate):
    def createEditor(self, parent: QWidget, style_option: QStyleOptionViewItem,
            index: QModelIndex) -> QWidget:
        return cast("MyTreeWidget", self.parent()).createEditor(parent, style_option, index)


class MyTreeWidget(QTreeWidget):
    filter_columns: List[int]
    editable_columns: List[int]

    def __init__(self, parent: QWidget, main_window: 'ElectrumWindow',
            create_menu: Callable[[QPoint], None], headers: List[str],
            stretch_column: Optional[int]=None, editable_columns: Optional[List[int]]=None) -> None:
        QTreeWidget.__init__(self, parent)

        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)

        self._main_window = cast("ElectrumWindow", weakref.proxy(main_window))
        self.config = self._main_window.config
        self.stretch_column = stretch_column
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(create_menu)
        # extend the syntax for consistency
        self.addChild = self.addTopLevelItem
        self.insertChild = self.insertTopLevelItem

        # Control which columns are editable
        self.editor: Optional[QWidget] = None
        self.pending_update = False
        if stretch_column is None:
            self.editable_columns = []
        else:
            self.editable_columns = \
                [stretch_column] if editable_columns is None else editable_columns
        self.setItemDelegate(ElectrumItemDelegate(self))
        self.itemDoubleClicked.connect(self.on_doubleclick)
        self.update_headers(headers)
        self.current_filter = ""

    def update_headers(self, headers: List[str]) -> None:
        self.setColumnCount(len(headers))
        self.setHeaderLabels(headers)
        self.header().setStretchLastSection(False)
        for col in range(len(headers)):
            sm = (QHeaderView.Stretch if col == self.stretch_column
                  else QHeaderView.ResizeToContents)
            self.header().setSectionResizeMode(col, sm)

    def editItem(self, item: QTreeWidgetItem, column: int=0) -> None:
        if column in self.editable_columns:
            self.editing_itemcol = (item, column, item.text(column))
            # Calling setFlags causes on_changed events for some reason
            item.setFlags(Qt.ItemFlag(int(item.flags()) | Qt.ItemFlag.ItemIsEditable))
            QTreeWidget.editItem(self, item, column)
            item.setFlags(Qt.ItemFlag(int(item.flags()) & ~Qt.ItemFlag.ItemIsEditable))

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in [ Qt.Key.Key_F2, Qt.Key.Key_Return ] and self.editor is None:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def permit_edit(self, item: QTreeWidgetItem, column: int) -> bool:
        return (column in self.editable_columns
                and self.on_permit_edit(item, column))

    def on_permit_edit(self, item: QTreeWidgetItem, column: int) -> bool:
        return True

    def on_doubleclick(self, item: QTreeWidgetItem, column: int) -> None:
        if self.permit_edit(item, column):
            self.editItem(item, column)

    def on_activated(self, item: QTreeWidgetItem, column: int) -> None:
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def createEditor(self, parent: QWidget, option: QStyleOptionViewItem,
            index: QModelIndex) -> QWidget:
        self.editor = QStyledItemDelegate.createEditor(
            cast(QStyledItemDelegate, self.itemDelegate()),
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

    def on_edited(self, item: QTreeWidgetItem, column: int, prior_text: str) -> None:
        '''Called only when the text actually changes'''
        text: Optional[str]
        text = item.text(column).strip()
        if text == "":
            text = None
        account_id, tx_hash = item.data(0, Qt.ItemDataRole.UserRole)
        account = self._main_window._wallet.get_account(account_id)
        assert account is not None
        account.set_transaction_label(tx_hash, text)

    # NOTE(typing) This is complained about even though it is a method signature in QWidget.
    def update(self) -> None: # type: ignore
        # Defer updates if editing
        if self.editor:
            self.pending_update = True
        else:
            self.on_update()
        if self.current_filter:
            self.filter(self.current_filter)

    def on_update(self) -> None:
        pass

    def get_leaves(self, root: QTreeWidgetItem) -> Generator[QTreeWidgetItem, None, None]:
        child_count = root.childCount()
        if child_count == 0:
            yield root
        for i in range(child_count):
            item = root.child(i)
            for x in self.get_leaves(item):
                yield x

    def filter(self, p: str) -> None:
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
    qt_css_class = "ButtonsWidget"
    qt_css_extra = ""

    def __init__(self) -> None:
        super().__init__()
        self.buttons: List[QAbstractButton] = []

    def resizeButtons(self) -> None:
        frame_width = self.style().pixelMetric(QStyle.PixelMetric.PM_DefaultFrameWidth)
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

    def addButton(self, icon_name: str, on_click: Callable[..., Any], tooltip: str,
            insert: bool=False) -> QToolButton:
        button = QToolButton(self)
        button.setIcon(read_QIcon(icon_name))
        # Horizontal buttons are inside the edit widget and do not have borders.
        if self.buttons_mode == ButtonsMode.INTERNAL:
            button.setStyleSheet("QToolButton { border: none; hover {border: 1px} "
                                "pressed {border: 1px} padding: 0px; }")
        button.setVisible(True)
        button.setToolTip(tooltip)
        button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        button.clicked.connect(on_click)
        if insert:
            self.buttons.insert(0, button)
        else:
            self.buttons.append(button)

        # Vertical buttons are integrated into the widget, within a margin that moves the edge
        # of the edit widget over to make space.
        frame_width = self.style().pixelMetric(QStyle.PixelMetric.PM_DefaultFrameWidth)
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

    def addCopyButton(self, tooltipText: Optional[str]=None) -> QAbstractButton:
        if tooltipText is None:
            tooltipText = _("Copy to clipboard")
        return self.addButton("icons8-copy-to-clipboard-32.png", self._on_copy,
            tooltipText)

    def _on_copy(self) -> None:
        get_app_state_qt().app_qt.clipboard().setText(self.text())
        QToolTip.showText(QCursor.pos(), _("Text copied to clipboard"), self)


class ButtonsLineEdit(KeyEventLineEdit, ButtonsWidget):
    qt_css_class = "QLineEdit"

    def __init__(self, text: str='') -> None:
        KeyEventLineEdit.__init__(self, None, text, {Qt.Key.Key_Return, Qt.Key.Key_Enter})
        self.buttons: List[QAbstractButton] = []

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
        self.buttons: List[QAbstractButton] = []

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
        self.buttons: List[QAbstractButton] = []

    def resizeEvent(self, event: QResizeEvent) -> None:
        QTableWidget.resizeEvent(self, event)
        self.resizeButtons()


class ColorSchemeItem:
    def __init__(self, fg_color: str, bg_color: str) -> None:
        self.colors = (fg_color, bg_color)

    def _get_color(self, background: bool) -> str:
        return self.colors[(int(background) + int(ColorScheme.dark_scheme)) % 2]

    def as_stylesheet(self, background: bool=False, class_name: str="QWidget", id_name: str="") \
            -> str:
        css_prefix = "background-" if background else ""
        color = self._get_color(background)
        key_name = class_name
        if id_name:
            key_name += "#"+ id_name
        return "{} {{ {}color:{}; }}".format(key_name, css_prefix, color)

    def as_color(self, background: bool=False) -> QColor:
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
    def has_dark_background(widget: QWidget) -> bool:
        brightness = sum(widget.palette().color(QPalette.Background).getRgb()[0:3])
        return brightness < (255*3/2)

    @staticmethod
    def update_from_widget(widget: QWidget) -> None:
        if ColorScheme.has_dark_background(widget):
            ColorScheme.dark_scheme = True


class SortableTreeWidgetItem(QTreeWidgetItem):
    DataRole = Qt.ItemDataRole.UserRole + 1

    def __lt__(self, other: object) -> bool:
        assert isinstance(other, QTreeWidgetItem)
        column = self.treeWidget().sortColumn()
        self_data = self.data(column, self.DataRole)
        other_data = other.data(column, self.DataRole)
        if None not in (self_data, other_data):
            # We have set custom data to sort by
            return cast(bool, self_data < other_data)

        try:
            # Is the value something numeric?
            self_text = self.text(column).replace(',', '')
            other_text = other.text(column).replace(',', '')
            return float(self_text) < float(other_text)
        except ValueError:
            # If not, we will just do string comparison
            return self.text(column) < other.text(column)


def update_fixed_tree_height(tree: QTreeWidget, maximum_height: Optional[int]=None) -> None:
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


def protected(func: D1) -> D1:
    '''Password request wrapper.  The password is passed to the function
    as the 'password' named argument.  "None" indicates either an
    unencrypted wallet, or the user cancelled the password request.
    An empty input is passed as the empty string.'''
    def request_password(self: "ElectrumWindow", *args: Any, **kwargs: Any) -> Any:
        main_window = self
        if 'main_window' in kwargs:
            main_window = kwargs['main_window']
        elif 'main_window_proxy' in kwargs:
            main_window = kwargs['main_window_proxy']
        elif 'wallet_id' in kwargs:
            main_window2 = app_state.app_qt.get_wallet_window_by_id(kwargs['wallet_id'])
            assert main_window2 is not None
            main_window = main_window2

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
    return cast(D1, request_password)


def icon_path(icon_basename: str) -> str:
    return resource_path('icons', icon_basename)

def read_qt_ui(ui_name: str) -> QWidget:
    # NOTE(typing) This is not typed by PyQt5-stubs.
    return cast(QWidget, loadUi(resource_path("ui", ui_name))) # type: ignore

@lru_cache()
def read_QIcon(icon_basename: str) -> QIcon:
    return QIcon(icon_path(icon_basename))

def get_source_index(model_index: QModelIndex, klass: Any) -> QModelIndex:
    model = model_index.model()
    while model is not None and not isinstance(model, klass):
        model_index = model.mapToSource(model_index)
        model = model_index.model()
    return model_index

def get_default_language() -> str:
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
        return True
    elif sys.platform == 'darwin':
        args = [
            '-e', 'tell application "Finder"',
            '-e', 'activate',
            '-e', 'select POSIX file "%s"' % path,
            '-e', 'end tell',
            '-e', 'return',
        ]
        QProcess.execute('/usr/bin/osascript', args)
        return True
    return False


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
    # NOTE(typing) The signature matches for `fields` but the type checker gives a false positive.
    d = ChangePasswordDialog(parent, PASSWORD_NEW_TEXT, _("Create New Wallet"),
        fields, # type: ignore
        kind=PasswordAction.NEW)
    success, _old_password, new_password = d.run()
    if not success or not cast(str, new_password).strip():
        return None

    assert new_password is not None

    from electrumsv.storage import WalletStorage
    wallet_path = WalletStorage.canonical_path(create_filepath)
    # Store the credential in case we most likely are going to open it immediately and do not
    # want to prompt for the password immediately after the user just specififed it.
    password_token = app_state.credentials.set_wallet_password(wallet_path, new_password,
        CredentialPolicyFlag.FLUSH_AFTER_WALLET_LOAD | CredentialPolicyFlag.IS_BEING_ADDED)
    assert password_token is not None
    storage = WalletStorage.create(create_filepath, password_token)
    # This path is guaranteed to be the full file path with file extension.
    assert storage.get_path() == wallet_path
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
    """
    A standardised look for forms whether informational or user editable.

    In the longer term it might be worth looking at whether the standard Qt FormLayout
    can be used to do something that looks the same with less custom code to achieve it.
    """
    show_help_label: bool = True
    # minimum_label_width: int = 80

    _frame_layout: QFormLayout

    def __init__(self, parent: Optional[QWidget]=None,
            minimum_label_width: Optional[int]=None) -> None:
        super().__init__(parent)

        frame = self._frame = QFrame()
        frame.setObjectName("FormFrame")

        self.clear(have_layout=False)

        frame.setLayout(self._frame_layout)

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

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(frame)
        self.setLayout(vbox)

    def create_title(self, title_text: str) -> QLabel:
        label = QLabel(title_text)
        label.setObjectName("FormSectionTitle")
        label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        return label

    def add_title(self, title_text: str) -> None:
        label = self.create_title(title_text)
        self._frame_layout.addRow(label)

    def add_title_row(self, title_object: FieldType) -> None:
        if isinstance(title_object, QLayout):
            self._frame_layout.addRow(title_object)
        else:
            self._frame_layout.addRow(title_object)

    def add_row(self, label_text: Union[str, QLabel], field_object: FieldType,
            use_separator: bool=True) -> None:
        """
        Add a row to the form section.

        Returns the container widget for the generated row layout. It is envisioned that the
        caller can use that and helper functions to dynamically alter the form section display
        as needed (hide, show, ..).
        """
        if use_separator and self._frame_layout.count() > 0:
            self._frame_layout.addRow(FormSeparatorLine())

        if isinstance(label_text, QLabel):
            label = label_text
            label_text = label.text()
        else:
            if not label_text.endswith(":"):
                label_text += ":"
            label = QLabel(label_text)
        label.setObjectName("FormSectionLabel")
        label.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)

        self._frame_layout.addRow(label, field_object)

    def clear(self, have_layout: bool=True) -> None:
        if have_layout and self._frame_layout is not None:
            # NOTE This is a Qt thing. You have to transplant the layout from an object before you
            #   can set a new one. So that is what we are doing here, transplanting to nowhere.
            discardable_widget = QWidget()
            discardable_widget.setLayout(self._frame_layout)

        self._frame_layout = QFormLayout()
        self._frame.setLayout(self._frame_layout)


class FramedTextWidget(QLabel):
    def __init__(self, parent: Optional[QWidget]=None) -> None:
        super().__init__(parent)

        self.setWordWrap(True)
        self.setFrameStyle(QFrame.Panel | QFrame.Raised)
        self.setMargin(10)


class ClickableLabel(QLabel):
    clicked = pyqtSignal()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def mousePressEvent(self, event: QMouseEvent) -> None:
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
            (self._pixmap.height() * width) // self._pixmap.width()

    def sizeHint(self) -> QSize:
        width = self.parent().width()
        return QSize(width, self.heightForWidth(width))

    def _scaled_pixmap(self) -> QPixmap:
        assert self._pixmap is not None
        return self._pixmap.scaled(self.size(), Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)

    def resizeEvent(self, event: QResizeEvent) -> None:
        if self._pixmap is not None:
            super().setPixmap(self._scaled_pixmap())
        super().resizeEvent(event)


class ExpandableSection(QWidget):
    def __init__(self, title: str, child: QWidget) -> None:
        super().__init__()

        self._child = child

        expand_details_button = QPushButton("+")

        def on_clicked_button_expand_details() -> None:
            nonlocal expand_details_button, self
            is_expanded = expand_details_button.text() == "-"
            if is_expanded:
                expand_details_button.setText("+")
                self._child.setVisible(False)
            else:
                expand_details_button.setText("-")
                self._child.setVisible(True)

        expand_details_button.setStyleSheet("padding: 2px;")
        expand_details_button.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        expand_details_button.clicked.connect(on_clicked_button_expand_details)
        expand_details_button.setMinimumWidth(15)

        # NOTE(copy-paste) Generic separation line code used elsewhere as well.
        details_header_line = QFrame()
        details_header_line.setStyleSheet("QFrame { border: 1px solid #C3C2C2; }")
        details_header_line.setFrameShape(QFrame.HLine)
        details_header_line.setFixedHeight(1)

        details_header = QHBoxLayout()
        details_header.addWidget(expand_details_button)
        details_header.addWidget(QLabel(title))
        details_header.addWidget(details_header_line, 1)

        expandable_section_layout = self._details_layout = QVBoxLayout()
        expandable_section_layout.addLayout(details_header)
        expandable_section_layout.addWidget(child)
        expandable_section_layout.setContentsMargins(0, 0, 0, 0)

        self.setLayout(expandable_section_layout)

    def expand(self) -> None:
        self._child.setVisible(True)

    def contract(self) -> None:
        self._child.setVisible(False)
