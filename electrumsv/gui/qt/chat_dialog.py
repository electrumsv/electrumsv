from __future__ import annotations
from dataclasses import dataclass
import datetime
from functools import partial
from typing import TYPE_CHECKING
from weakref import proxy

from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QKeyEvent, QResizeEvent
from PyQt6.QtWidgets import QAbstractItemView, QDialog, QHBoxLayout, QListWidget, \
    QListWidgetItem, QTextEdit, QWidget, QVBoxLayout

from ...app_state import app_state
from ...network_support.direct_connection_protocol import send_direct_message_to_contact_async
from ...i18n import _

if TYPE_CHECKING:
    from ...wallet import WalletDataAccess
    from .main_window import ElectrumWindow


@dataclass
class DialogContext:
    wallet_id: int
    contact_id: int
    wallet_data: WalletDataAccess
    main_window_proxy: ElectrumWindow
    dialog: QDialog | None = None
    list_widget: QListWidget | None = None
    edit_widget: QTextEdit | None = None

class GlobalChatContext(object):
    chat_dialogs: dict[tuple[int, int], DialogContext] = {}


chat_stylesheet = """
#ContactCard {
    background-color: white;
    border-bottom: 1px solid #E3E2E2;
}

#ContactAvatar {
    padding: 4px;
    border: 1px solid #E2E2E2;
}
"""

class OutgoingMessageTextEdit(QTextEdit):
    def __init__(self, context: DialogContext) -> None:
        super().__init__()
        self._context = context

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            editor = self._context.edit_widget
            assert editor is not None
            message_text = editor.toPlainText()
            if len(message_text) > 0:
                add_chat_message(self._context.main_window_proxy, self._context.wallet_id,
                    self._context.contact_id, message_text, from_wallet_owner=True)
                app_state.app.run_coro(send_direct_message_to_contact_async(
                    self._context.wallet_data, self._context.contact_id, message_text))
                editor.setPlainText("")
        else:
            super().keyPressEvent(event)


def show_chat_dialog(main_window: ElectrumWindow, wallet_id: int, contact_id: int) -> DialogContext:
    if (wallet_id, contact_id) in GlobalChatContext.chat_dialogs:
        context = GlobalChatContext.chat_dialogs[(wallet_id, contact_id)]
        assert context.dialog is not None
        context.dialog.show()
        context.dialog.raise_()
        context.dialog.activateWindow()
        assert context.edit_widget is not None
        context.edit_widget.setFocus()
        return context

    wallet_data = main_window._wallet.data
    context = GlobalChatContext.chat_dialogs[(wallet_id, contact_id)] = \
        DialogContext(wallet_id, contact_id, wallet_data, proxy(main_window))
    dialog = context.dialog = QDialog(main_window,
        Qt.WindowType(Qt.WindowType.WindowSystemMenuHint | Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint))
    dialog.setWindowTitle(_("Chat"))
    # This is the magic width at which the text edit is not clipped and when there are more list
    # entries than can be displayed horizontally, the scroll bar appearing does not clip it either.
    dialog.setMinimumWidth(310)

    list = context.list_widget = QListWidget()
    list.setStyleSheet(chat_stylesheet)
    list.setSortingEnabled(False)
    list.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)

    editor = context.edit_widget = OutgoingMessageTextEdit(context)
    editor.setPlaceholderText(_("Write your message here.."))
    editor.setAcceptRichText(False)
    editor.setMaximumHeight(60)

    vbox = QVBoxLayout()
    vbox.addWidget(list)
    vbox.addWidget(editor)
    context.dialog.setLayout(vbox)

    update_dialog(dialog)

    def dialog_finished(result: int) -> None:
        nonlocal contact_id, context, wallet_id
        context.dialog = None
        del GlobalChatContext.chat_dialogs[(wallet_id, contact_id)]
    dialog.finished.connect(dialog_finished)
    dialog.show()

    editor.setFocus()
    return context


class MessageEntry(QWidget):
    resize_signal = pyqtSignal()

    def __init__(self, message_text: str) -> None:
        super().__init__(None)

        message_widget = self.message_widget = QTextEdit(message_text)
        message_widget.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        message_widget.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        def adjust_message_widget_size() -> None:
            nonlocal message_widget
            docheight = message_widget.document().size().height()
            margin = message_widget.document().documentMargin()
            message_widget.setMinimumHeight(int(docheight + 2*margin))
            message_widget.setMaximumHeight(int(docheight + 2*margin))
        message_widget.textChanged.connect(adjust_message_widget_size)
        message_widget.document().documentLayout().documentSizeChanged.connect(
            adjust_message_widget_size)

        self._layout = QHBoxLayout()
        self._layout.setSpacing(0)
        self._layout.setContentsMargins(3, 0, 3, 3)
        self._layout.addWidget(self.message_widget, stretch=1)
        self.setLayout(self._layout)

    def resizeEvent(self, resize_event: QResizeEvent) -> None:
        super().resizeEvent(resize_event)
        self.resize_signal.emit()


def add_chat_message(main_window: ElectrumWindow, wallet_id: int, contact_id: int,
        message_text: str, from_wallet_owner: bool=False) -> None:
    context = show_chat_dialog(main_window, wallet_id, contact_id)
    assert context is not None

    contact_name = "YOU"
    if not from_wallet_owner:
        wallet_data = main_window._wallet.data
        contact_rows = wallet_data.read_contacts([ contact_id ])
        assert len(contact_rows) == 1, "Contact does not exist"
        contact_name = contact_rows[0].contact_name

    d = datetime.datetime.now()
    hour = d.hour % 12 if d.hour > 0 else 12
    ampm_text = "PM" if d.hour > 12 else "AM"
    time_text = f"{hour}:{d.minute}{ampm_text}"
    message_text = f"<b>{contact_name}</b> {time_text}<br/>"+ message_text
    message_entry = MessageEntry(message_text)

    list = context.list_widget
    assert list is not None
    list_item = QListWidgetItem()
    list.addItem(list_item)
    list.setItemWidget(list_item, message_entry)

    # Widgets set on a QListItemWidget need to propagate their sizeHint.
    def update_item_size_hint(list_item: QListWidgetItem, widget: QWidget) -> None:
        list_item.setSizeHint(widget.sizeHint())
    message_entry.resize_signal.connect(partial(update_item_size_hint, list_item, message_entry))

    list.scrollToItem(list_item, QAbstractItemView.ScrollHint.PositionAtBottom)


def update_dialog(dialog: QDialog) -> None:
    pass
