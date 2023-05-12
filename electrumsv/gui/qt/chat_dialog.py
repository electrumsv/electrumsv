from __future__ import annotations
from dataclasses import dataclass
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QKeyEvent, QPainter, QPaintEvent
from PyQt6.QtWidgets import QAbstractItemView, QDialog, QHBoxLayout, QListWidget, \
    QListWidgetItem, QStyle, QStyleOption, QTextEdit, QWidget, QVBoxLayout

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

class TextEdit(QTextEdit):
    def __init__(self, context: DialogContext) -> None:
        super().__init__()
        self._context = context

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            editor = self._context.edit_widget
            assert editor is not None
            message_text = editor.toPlainText()
            if len(message_text) > 0:
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
        DialogContext(wallet_id, contact_id, wallet_data)
    dialog = context.dialog = QDialog(main_window,
        Qt.WindowType(Qt.WindowType.WindowSystemMenuHint | Qt.WindowType.WindowTitleHint |
            Qt.WindowType.WindowCloseButtonHint))
    dialog.setWindowTitle(_("Chat"))

    list = context.list_widget = QListWidget()
    list.setStyleSheet(chat_stylesheet)
    list.setSortingEnabled(False)

    editor = context.edit_widget = TextEdit(context)
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
    def __init__(self, message_text: str) -> None:
        super().__init__(None)

        self.setObjectName("MessageEntry")

        # avatar_label = QLabel("")
        # avatar_label.setPixmap(QPixmap(icon_path("icons8-decision-80.png")))
        # avatar_label.setObjectName("ContactAvatar")
        # avatar_label.setToolTip(_("What your contact avatar looks like."))

        # label = QLabel("...")
        # label.setSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Preferred)
        # label.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        # name_layout = QVBoxLayout()
        # name_layout.setContentsMargins(0, 0, 0, 0)
        # name_layout.addWidget(avatar_label)
        # name_layout.addWidget(label)

        self.message_widget = QTextEdit()
        self.message_widget.setReadOnly(True)
        self.message_widget.setText(message_text)
        self.message_widget.setMinimumHeight(50)

        self._layout = QHBoxLayout()
        self._layout.setSpacing(8)
        self._layout.setContentsMargins(20, 10, 20, 10)
        # self._layout.addLayout(name_layout)
        self._layout.addWidget(self.message_widget, stretch=1)
        self.setLayout(self._layout)

    # QWidget styles do not render. Found this somewhere on the qt5 doc site.
    def paintEvent(self, event: QPaintEvent) -> None:
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PrimitiveElement.PE_Widget, opt, p, self)


def add_chat_message(main_window: ElectrumWindow, wallet_id: int, contact_id: int,
        message_text: str, from_wallet_owner: bool=False) -> None:
    context = show_chat_dialog(main_window, wallet_id, contact_id)
    assert context is not None

    list_item = QListWidgetItem()
    # The item won't display unless it gets a size hint. It seems to resize horizontally
    # but unless the height is a minimal amount it won't do anything proactive..
    list_item.setSizeHint(QSize(256, 130))

    contact_name = "YOU"
    if not from_wallet_owner:
        wallet_data = main_window._wallet.data
        contact_rows = wallet_data.read_contacts([ contact_id ])
        assert len(contact_rows) == 1, "Contact does not exist"
        contact_name = contact_rows[0].contact_name

    message_text = f"<b>{contact_name}</b> 12:00PM<br/>"+ message_text

    message_entry = MessageEntry(message_text)

    list = context.list_widget
    assert list is not None
    list.addItem(list_item)
    list.setItemWidget(list_item, message_entry)
    list.scrollToItem(list_item, QAbstractItemView.ScrollHint.PositionAtBottom)

def update_dialog(dialog: QDialog) -> None:
    pass
