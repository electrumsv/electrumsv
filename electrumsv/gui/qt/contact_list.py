#!/usr/bin/env python
#
# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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

from __future__ import annotations
import concurrent.futures
import time
from typing import Any, Callable, cast, TYPE_CHECKING
import weakref

from PyQt6.QtCore import Qt, QObject, QSize
from PyQt6.QtGui import QAction, QPainter, QPaintEvent, QPixmap
from PyQt6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit, QPushButton, QSizePolicy,
    QStyle, QStyleOption, QToolBar, QVBoxLayout, QWidget)

from ...app_state import app_state, get_app_state_qt
from ...constants import NetworkServerFlag, TokenPermissions
from ...contacts import IdentityCheckResult
from ...exceptions import ServerConnectionError
from ...i18n import _
from ...logs import logs
from ...network_support.direct_connection_protocol import create_peer_channel_for_contact_async, \
    encode_invitation
from ...network_support.exceptions import GeneralAPIError
from ...wallet_database.types import ContactAddRow, ContactRow, PeerChannelAccessTokenRow, \
    ServerPeerChannelRow

if TYPE_CHECKING:
    from .main_window import ElectrumWindow

from . import server_required_dialog
from .util import Buttons, CancelButton, icon_path, OkButton, read_QIcon, WindowModalDialog

logger = logs.get_logger("ui-contact-list")


contactcard_stylesheet = """
#ContactCard {
    background-color: white;
    border-bottom: 1px solid #E3E2E2;
}

#ContactAvatar {
    padding: 4px;
    border: 1px solid #E2E2E2;
}
"""

class ListContext(QObject):
    def __init__(self, wallet_window: ElectrumWindow, contact_list: ContactList) -> None:
        super().__init__(contact_list)

        self.contact_list = contact_list
        self.wallet_data = wallet_window._wallet.data
        self.wallet_window = cast("ElectrumWindow", weakref.proxy(wallet_window))

        # Avoid race conditions with the user returning to the contact list before the invite data
        # is written to the database and re-clicking the "Connect" button.
        self.invites_in_progress: set[int] = set()


class ContactList(QWidget):
    def __init__(self, wallet_window: ElectrumWindow) -> None:
        super().__init__(wallet_window)

        self._context = ListContext(wallet_window, self)

        cards = ContactCards(self._context, self)
        self.setStyleSheet(contactcard_stylesheet)

        add_contact_action = QAction(self)
        add_contact_action.setIcon(read_QIcon("icons8-plus-blueui.svg"))
        add_contact_action.setToolTip(_("Add new contact"))
        add_contact_action.triggered.connect(self._on_add_contact_action)

        sort_action = QAction(self)
        sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-2-80-blueui.png"))
        sort_action.setToolTip(_("Sort"))
        sort_action.triggered.connect(self._on_sort_action)

        toolbar = QToolBar(self)
        toolbar.setMovable(False)
        toolbar.setOrientation(Qt.Orientation.Vertical)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        toolbar.addAction(add_contact_action)
        toolbar.addAction(sort_action)

        self._layout = QHBoxLayout()
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.addWidget(cards)
        self._layout.addWidget(toolbar)
        self.setLayout(self._layout)

        self._cards = cards
        self._sort_action = sort_action
        self._sort_type = 1

    def _on_add_contact_action(self) -> None:
        edit_contact_dialog(self._context)

    def _on_sort_action(self) -> None:
        assert self._cards._list is not None
        if self._sort_type == 1:
            self._sort_type = -1
            self._sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-80-blueui.png"))
            self._cards._list.sortItems(Qt.SortOrder.DescendingOrder)
        else:
            self._sort_type = 1
            self._sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-2-80-blueui.png"))
            self._cards._list.sortItems(Qt.SortOrder.AscendingOrder)


class ContactCards(QWidget):
    def __init__(self, context: ListContext, parent: Any=None) -> None:
        super().__init__(parent)

        self._context = context

        self._layout = QVBoxLayout()
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self._empty_label: QLabel | None = None
        self._list: QListWidget | None = None

        contact_rows = self._context.wallet_data.read_contacts()
        if len(contact_rows) > 0:
            for contact_row in sorted(contact_rows,
                    key=lambda contact_row: contact_row.contact_name):
                self._add_card_for_contact(contact_row)
        else:
            self._add_empty_label()

        self.setLayout(self._layout)

        self._context.wallet_window.contacts_created_signal.connect(self._on_contacts_created)
        self._context.wallet_window.contacts_updated_signal.connect(self._on_contacts_updated)
        self._context.wallet_window.contacts_deleted_signal.connect(self._on_contacts_deleted)

    def _add_card_for_contact(self, contact_row: ContactRow) -> None:
        self._remove_empty_label()
        if self._list is None:
            self._list = QListWidget(self)
            self._list.setSortingEnabled(True)
            self._layout.addWidget(self._list)

        test_card = ContactCard(self._context, contact_row)
        test_card.setSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Minimum)

        list_item = QListWidgetItem()
        list_item.setText(contact_row.contact_name)
        # The item won't display unless it gets a size hint. It seems to resize horizontally
        # but unless the height is a minimal amount it won't do anything proactive..
        list_item.setSizeHint(QSize(256, 130))
        self._list.addItem(list_item)
        self._list.setItemWidget(list_item, test_card)

    def _update_card_for_contact(self, contact_row: ContactRow) -> None:
        assert self._list is not None
        for i in range(self._list.count()-1, -1, -1):
            item = self._list.item(i)
            widget = cast(ContactCard, self._list.itemWidget(item))
            if widget._contact_row.contact_id == contact_row.contact_id:
                widget.update_contact_row(contact_row)
                break

    def _remove_card_for_contact(self, contact_row: ContactRow) -> None:
        assert self._list is not None
        for i in range(self._list.count()-1, -1, -1):
            item = self._list.item(i)
            widget = cast(ContactCard, self._list.itemWidget(item))
            if widget._contact_row.contact_id == contact_row.contact_id:
                self._list.takeItem(i)
                break

        if self._list.count() == 0:
            # Remove the list.
            # NOTE(typing) We need to do this to deparent the label, but no type stub from Qt5.
            self._list.setParent(None) # type: ignore[call-overload]
            self._list = None

            # Replace it with the placeholder label.
            self._add_empty_label()

    def _on_contacts_created(self, contact_rows: list[ContactRow]) -> None:
        for contact_row in contact_rows:
            self._add_card_for_contact(contact_row)

    def _on_contacts_updated(self, contact_rows: list[ContactRow]) -> None:
        for contact_row in contact_rows:
            self._update_card_for_contact(contact_row)

    def _on_contacts_deleted(self, contact_rows: list[ContactRow]) -> None:
        for contact_row in contact_rows:
            self._remove_card_for_contact(contact_row)

    def _add_empty_label(self) -> None:
        label = QLabel(_("You do not currently have any contacts."))
        label.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter)
        self._layout.addWidget(label)
        self._empty_label = label

    def _remove_empty_label(self) -> None:
        if self._empty_label is not None:
            # NOTE(typing) We need to do this to deparent the label, but no type stub from Qt5.
            self._empty_label.setParent(None) # type: ignore[call-overload]
            self._empty_label = None


class ContactCard(QWidget):
    def __init__(self, context: ListContext, contact_row: ContactRow) -> None:
        super().__init__(None)

        self._context = context
        self._contact_row = contact_row

        self.setObjectName("ContactCard")

        avatar_label = QLabel("")
        avatar_label.setPixmap(QPixmap(icon_path("icons8-decision-80.png")))
        avatar_label.setObjectName("ContactAvatar")
        avatar_label.setToolTip(_("What your contact avatar looks like."))

        label = QLabel("...")
        label.setSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Preferred)
        label.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        name_layout = QVBoxLayout()
        name_layout.setContentsMargins(0, 0, 0, 0)
        name_layout.addWidget(avatar_label)
        name_layout.addWidget(label)

        def event_peer_channel_creation_done(future: concurrent.futures.Future[
                tuple[ServerPeerChannelRow, PeerChannelAccessTokenRow]]) -> None:
            """
            `run_coro` ensures this completion callback happens on the GUI thread. The result will
            implicitly be ready and no blocking should occur waiting for it.
            """
            contact_id = self._contact_row.contact_id
            assert contact_id is not None

            try:
                peer_channel_row, write_access_token_row = future.result()
            except GeneralAPIError:
                logger.exception("TODO handle this")
                raise
            except ServerConnectionError:
                logger.exception("TODO handle this")
                raise
            else:
                self._contact_row = self._contact_row._replace(
                    local_peer_channel_id=peer_channel_row.peer_channel_id)
            finally:
                self._context.invites_in_progress.remove(contact_id)

            self._update()
            show_share_connection_details_dialog()

        def create_peer_channel_for_connection() -> None:
            assert self._contact_row.contact_id is not None
            wallet = self._context.wallet_window._wallet

            if self._contact_row.contact_id in self._context.invites_in_progress:
                self._context.wallet_window.show_warning(
                    _("Connection attempt already in progress."))
                return
            self._context.invites_in_progress.add(self._contact_row.contact_id)

            app_state.app.run_coro(create_peer_channel_for_contact_async(wallet,
                self._contact_row.contact_id), on_done=event_peer_channel_creation_done)

        def start_connection_preparation() -> None:
            wallet = self._context.wallet_window._wallet

            # The whole point of direct connection is that you connect over peer channels.
            # The message box services are peer channels.
            required_flags = NetworkServerFlag.USE_MESSAGE_BOX
            if wallet.have_wallet_servers(required_flags):
                create_peer_channel_for_connection()
                return

            dialog_text = _("Requesting a direct connection from a contact requires signing up "
                "with both message box services, where the connection process will create a "
                "channel they can connect to you through on your message box service."
                "<br/><br/>"
                "This wallet has not been set up to use the required service. If you run your "
                "own servers or wish to use third party servers, choose the 'Manage servers' "
                "option.")

            dialog = server_required_dialog.ServerRequiredDialog(self, wallet,
                NetworkServerFlag.USE_MESSAGE_BOX, dialog_text)
            # There are two paths to the user accepting this dialog:
            # - They checked "select servers on my behalf" then the OK buton and then servers were
            #   selected and connected to.
            # - They chose "Manage servers" which selected and connected to servers and then on exit
            #   from that wizard this dialog auto-accepted.
            dialog.accepted.connect(create_peer_channel_for_connection)
            dialog.show()

        def show_share_connection_details_dialog() -> None:
            title = _("Share connection details")
            share_dialog = WindowModalDialog(self._context.wallet_window.reference(), title)

            vbox = QVBoxLayout()
            description_label = QLabel(_("The details shown here should be copied and shared "
                "with this contact. You might send it to them by email. Click the clipboard icon "
                "or select it all and copy it all, and paste it to your contact."))
            description_label.setMinimumWidth(400)
            description_label.setWordWrap(True)
            vbox.addWidget(description_label)

            assert self._contact_row.local_peer_channel_id is not None
            peer_channel_rows = self._context.wallet_data.read_server_peer_channels(
                channel_id=self._contact_row.local_peer_channel_id)
            assert len(peer_channel_rows) == 1
            peer_channel_row = peer_channel_rows[0]

            access_token_rows = [
                access_token_row for access_token_row
                in self._context.wallet_data.read_server_peer_channel_access_tokens(
                    self._contact_row.local_peer_channel_id)
                if access_token_row.permission_flags == TokenPermissions.WRITE_ACCESS ]
            assert len(access_token_rows) == 1
            access_token_row = access_token_rows[0]

            identity_text = self._context.wallet_window._wallet._identity_public_key.to_hex(
                compressed=True)

            assert peer_channel_row.remote_url is not None
            assert access_token_row.access_token is not None
            payload_text = encode_invitation("Unknown", identity_text,
                peer_channel_row.remote_url, access_token_row.access_token)
            # RT:  Ideally we want an encoding that when the user double clicks to select it to
            #      copy and paste, will select all of it. For now we use hex, which is verbose.
            shareable_text = "Import this into ElectrumSV as a connection invitation!\n\n" + \
                payload_text

            name_edit = QPlainTextEdit(shareable_text)
            name_edit.setReadOnly(True)

            def on_copy_and_close_button_clicked() -> None:
                get_app_state_qt().app_qt.clipboard().setText(name_edit.toPlainText())

                nonlocal share_dialog
                share_dialog.accept()

            copy_and_close_button = QPushButton("  "+ _("Copy and close") +"  ")
            copy_and_close_button.clicked.connect(on_copy_and_close_button_clicked)

            vbox.addWidget(name_edit)
            vbox.addLayout(Buttons(CancelButton(share_dialog, _("Close")), copy_and_close_button))

            share_dialog.setLayout(vbox)
            share_dialog.show()

        def show_current_connection_dialog() -> None:
            assert self._contact_row.contact_id not in self._context.invites_in_progress
            print("show_current_connection_dialog")

        def _on_connect_button_clicked() -> None:
            if self._contact_row.remote_peer_channel_url is not None:
                assert self._contact_row.local_peer_channel_id is not None
                show_current_connection_dialog()
            elif self._contact_row.local_peer_channel_id is not None:
                show_share_connection_details_dialog()
            else:
                start_connection_preparation()

        def _on_pay_button_clicked() -> None:
            from . import payment
            # from importlib import reload
            # reload(payment)
            self.w = payment.PaymentWindow(self._context.wallet_window.reference(),
                self._contact_row, parent=self)
            self.w.show()

        def _on_message_button_clicked() -> None:
            assert self._contact_row.contact_id is not None
            wallet = self._context.wallet_window._wallet

            from .chat_dialog import show_chat_dialog
            show_chat_dialog(self._context.wallet_window.reference(),
                wallet.get_id(), self._contact_row.contact_id)

        def _on_delete_button_clicked() -> None:
            if not self._context.wallet_window.question(_("Are you sure?")):
                return
            # We do not wait for this as we do not want to block the UI. Any exceptions will be
            # logged as we do not pass an `on_done` handler to handle them ourselves.
            assert self._contact_row.contact_id is not None
            app_state.app.run_coro(self._context.wallet_data.delete_contacts_async([
                self._contact_row.contact_id ]))

        def _on_contact_edit_done(future: concurrent.futures.Future[list[ContactRow]]) -> None:
            future.result()
            self._update()

        def _on_edit_button_clicked() -> None:
            edit_contact_dialog(self._context, self._contact_row, _on_contact_edit_done)

        self._connection_button = QPushButton(_("Connect"))
        self._connection_button.clicked.connect(_on_connect_button_clicked)

        pay_button = QPushButton(_("Pay"))
        pay_button.setEnabled(False)
        pay_button.clicked.connect(_on_pay_button_clicked)

        self._message_button = QPushButton(_("Message"))
        self._message_button.clicked.connect(_on_message_button_clicked)

        edit_button = QPushButton(_("Edit"))
        edit_button.clicked.connect(_on_edit_button_clicked)

        delete_button = QPushButton(_("Delete"))
        delete_button.clicked.connect(_on_delete_button_clicked)

        action_layout = QVBoxLayout()
        action_layout.setSpacing(0)
        action_layout.addStretch(1)
        action_layout.addWidget(self._connection_button)
        action_layout.addWidget(pay_button)
        action_layout.addWidget(self._message_button)
        action_layout.addWidget(edit_button)
        action_layout.addWidget(delete_button)

        self._layout = QHBoxLayout()
        self._layout.setSpacing(8)
        self._layout.setContentsMargins(20, 10, 20, 10)
        self._layout.addLayout(name_layout)
        self._layout.addStretch(1)
        self._layout.addLayout(action_layout)
        self.setLayout(self._layout)

        self._avatar_label = avatar_label
        self._name_label = label

        self._update()

    # QWidget styles do not render. Found this somewhere on the qt5 doc site.
    def paintEvent(self, event: QPaintEvent) -> None:
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PrimitiveElement.PE_Widget, opt, p, self)

    def update_contact_row(self, contact_row: ContactRow) -> None:
        self._contact_row = contact_row
        self._update()

    def _update(self) -> None:
        self._name_label.setText(self._contact_row.contact_name)
        self._message_button.setEnabled(False)

        if self._contact_row.remote_peer_channel_url is not None:
            if self._contact_row.local_peer_channel_id is None:
                self._connection_button.setText(_("Connecting.."))
            else:
                self._connection_button.setText(_("Connected!"))
                self._message_button.setEnabled(True)
        elif self._contact_row.local_peer_channel_id is not None:
            self._connection_button.setText(_("Connect"))
        else:
            self._connection_button.setText(_("Connect"))

        if app_state.daemon.network is None:
            self._connection_button.setEnabled(False)
            self._connection_button.setToolTip(_("Not available while running in offline mode"))


def edit_contact_dialog(list_context: ListContext, contact_row: ContactRow | None=None,
        on_done: Callable[[ concurrent.futures.Future[list[ContactRow]] ], None] | None=None) \
            -> None:
    editing = contact_row is not None
    if editing:
        title = _("Edit Contact")
    else:
        title = _("New Contact")

    d = WindowModalDialog(list_context.wallet_window.reference(), title)
    vbox = QVBoxLayout(d)
    vbox.addWidget(QLabel(title + ':'))

    name_line = QLineEdit()

    ok_button = OkButton(d)
    ok_button.setEnabled(False)

    def _contact_text_changed(edit_text: str) -> None:
        nonlocal name_line

        name_line.setToolTip("")
        name_line.setStyleSheet("")

        edited_contact_name = edit_text.strip().lower()

        if len(edited_contact_name) == 0:
            name_result = IdentityCheckResult.Invalid
        else:
            # RT: If the user wants to add 10 Bobs do we really mind?
            # for read_row in list_context.wallet_data.read_contacts():
            #     if read_row is None or read_row.contact_id != contact_row.contact_id:
            #         if edited_contact_name == read_row.contact_name.lower():
            #             IdentityCheckResult.InUse
            #             break
            # else:
            name_result = IdentityCheckResult.Ok

        if name_result == IdentityCheckResult.Ok:
            ok_button.setEnabled(True)
        else:
            name_line.setStyleSheet("border: 1px solid red")
            if name_result == IdentityCheckResult.Invalid:
                name_line.setToolTip(_("Name too short"))
            ok_button.setEnabled(False)

    name_line.textChanged.connect(_contact_text_changed)

    grid = QGridLayout()
    name_line.setFixedWidth(280)
    grid.addWidget(QLabel(_("Name")), 2, 0)
    grid.addWidget(name_line, 2, 1)

    vbox.addLayout(grid)
    vbox.addLayout(Buttons(CancelButton(d), ok_button))

    if contact_row is not None:
        name_line.setText(contact_row.contact_name)
        name_line.setFocus()

    if d.exec():
        new_contact_name = name_line.text().strip()
        if contact_row is not None:
            new_contact_row = contact_row._replace(contact_name=new_contact_name,
                date_updated=int(time.time()))
            app_state.app.run_coro(list_context.wallet_data.update_contacts_async(
                [ new_contact_row ]), on_done=on_done)

        contact_add_row = ContactAddRow(new_contact_name)
        app_state.app.run_coro(list_context.wallet_data.create_contacts_async(
            [ contact_add_row ]), on_done=on_done)
