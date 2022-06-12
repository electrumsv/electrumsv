# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from functools import partial
from typing import Any, cast, List, Optional

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtGui import QAction, QPainter, QPaintEvent, QPixmap
from PyQt6.QtWidgets import (QHBoxLayout, QLabel, QListWidget,
    QListWidgetItem, QStyle, QStyleOption, QToolBar, QVBoxLayout, QWidget)

from electrumsv.constants import WalletEventFlag, WalletEventType
from electrumsv.i18n import _
from electrumsv.util import format_posix_timestamp
from electrumsv.wallet_database.types import WalletEventRow

from .util import ClickableLabel, icon_path, read_QIcon
from .wallet_api import WalletAPI



class ListContext(QObject):
    entry_added = pyqtSignal(object)
    entry_removed = pyqtSignal(object)

    sortable_list = False

    def __init__(self, wallet_api: WalletAPI, list: "View") -> None:
        super().__init__(list)

        self.list = list
        self.wallet_api = wallet_api

        self.wallet_api.new_notification.connect(self.entry_added.emit)

    def get_empty_text(self) -> str:
        return _("No new notifications.")

    def get_entry_text(self, row: WalletEventRow) -> str:
        if row.event_type == WalletEventType.SEED_BACKUP_REMINDER:
            return _("Add text about how users should backup their seeds.")
        # Intentionally not localised.
        return "Not yet implemented"

    def get_entry_image_text(self, row: WalletEventRow) -> str:
        image_text = _("Warning")
        return image_text

    def get_entry_image_filename(self, row: WalletEventRow) -> str:
        image_filename = "icons8-warning-shield-80-blueui.png"
        return image_filename

    def get_rows(self) -> List[WalletEventRow]:
        return self.wallet_api.get_notification_rows()

    def compare_rows(self, row1: WalletEventRow, row2: WalletEventRow) -> bool:
        return row1.event_id == row2.event_id

    def on_list_updated(self, row_count: int) -> None:
        pass

    def card_factory(self, row: WalletEventRow) -> 'NotificationCard':
        return NotificationCard(self, row)


class View(QWidget):
    def __init__(self, wallet_api: WalletAPI, parent: QWidget) -> None:
        super().__init__(parent)

        self._context = ListContext(wallet_api, self)

        cards = Cards(self._context, self)

        sort_action = QAction(self)
        sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-2-80-blueui.png"))
        sort_action.setToolTip(_("Sort"))
        sort_action.triggered.connect(self._on_sort_action)
        sort_action.setEnabled(self._context.sortable_list)

        toolbar = QToolBar(self)
        toolbar.setMovable(False)
        toolbar.setOrientation(Qt.Orientation.Vertical)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
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

    def _on_sort_action(self) -> None:
        list = cast(QListWidget, self._cards._list)
        if self._sort_type == 1:
            self._sort_type = -1
            self._sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-80-blueui.png"))
            list.sortItems(Qt.SortOrder.DescendingOrder)
        else:
            self._sort_type = 1
            self._sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-2-80-blueui.png"))
            list.sortItems(Qt.SortOrder.AscendingOrder)

    def is_empty(self) -> bool:
        return self._cards.is_empty()

    def reset_contents(self) -> None:
        self._cards.reset_contents()


class Cards(QWidget):
    _empty_label: Optional[QLabel] = None
    _list: Optional[QListWidget] = None

    def __init__(self, context: ListContext, parent: QWidget) -> None:
        super().__init__(parent)

        self._context = context

        self._layout = QVBoxLayout()
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self.reset_contents()
        self.setLayout(self._layout)

        self._context.entry_added.connect(partial(self._on_entry_added_or_removed, True))
        self._context.entry_removed.connect(partial(self._on_entry_added_or_removed, False))

    def reset_contents(self) -> None:
        rows = self._context.get_rows()
        if len(rows) > 0:
            if self._list is not None:
                self._list.clear()

            for row in rows:
                self._add_entry(row)
        else:
            self._display_empty_label()

        row_count = self._list.count() if self._list is not None else 0
        self._context.on_list_updated(row_count)

    def is_empty(self) -> bool:
        return self._empty_label is not None

    def _add_entry(self, row: Any) -> None:
        self._remove_empty_label()
        if self._list is None:
            self._list = QListWidget(self)
            self._list.setSortingEnabled(self._context.sortable_list)
            self._layout.addWidget(self._list)

        card = self._context.card_factory(row)
        list_item = QListWidgetItem()
        # The item won't display unless it gets a size hint. It seems to resize horizontally
        # but unless the height is a minimal amount it won't do anything proactive..
        list_item.setSizeHint(card.sizeHint())
        self._list.addItem(list_item)
        self._list.setItemWidget(list_item, card)

    def _remove_entry(self, row: Any) -> None:
        list = cast(QListWidget, self._list)
        for i in range(list.count()-1, -1, -1):
            item = list.item(i)
            widget = cast(NotificationCard, list.itemWidget(item))
            if self._context.compare_rows(widget._row, row):
                list.takeItem(i)

        if list.count() == 0:
            self._display_empty_label()

    def _on_entry_added_or_removed(self, added: bool, row: Any) -> None:
        if added:
            self._add_entry(row)
        else:
            self._remove_entry(row)

        row_count = self._list.count() if self._list is not None else 0
        self._context.on_list_updated(row_count)

    def _display_empty_label(self) -> None:
        if self._list is not None:
            # Remove the list.
            # NOTE(typing) This is a unrecognized Pylance signature.
            self._list.setParent(None) # type: ignore
            self._list = None

        if self._empty_label is None:
            self._empty_label = QLabel(self._context.get_empty_text())
            self._empty_label.setAlignment(Qt.AlignmentFlag(Qt.AlignmentFlag.AlignHCenter |
                Qt.AlignmentFlag.AlignVCenter))
            self._layout.addWidget(self._empty_label)

    def _remove_empty_label(self) -> None:
        if self._empty_label is not None:
            self._empty_label.setParent(None) # type: ignore[call-overload]
            self._empty_label = None


class Card(QWidget):
    def __init__(self, context: ListContext, row: WalletEventRow, parent: Optional[QWidget]=None):
        super().__init__(parent)

        self._context = context
        self._row = row

        image_filename = self._context.get_entry_image_filename(row)
        image_text = self._context.get_entry_image_text(row)

        self.setObjectName("NotificationCard")

        image_container_label = QLabel("")
        image_container_label.setPixmap(QPixmap(icon_path(image_filename)))
        image_container_label.setObjectName("NotificationCardImage")

        image_label = QLabel(image_text)
        image_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        name_layout = QVBoxLayout()
        name_layout.setContentsMargins(0, 0, 0, 0)
        name_layout.addStretch(1)
        name_layout.addWidget(image_container_label)
        name_layout.addWidget(image_label)
        name_layout.addStretch(1)

        action_layout = QVBoxLayout()
        action_layout.setSpacing(0)

        self.add_actions(action_layout)

        self._layout = QHBoxLayout()
        self._layout.setSpacing(8)
        self._layout.setContentsMargins(10, 10, 10, 10)
        self._layout.addLayout(name_layout)
        self.add_main_content(self._layout)
        self._layout.addLayout(action_layout)
        self.setLayout(self._layout)

    # QWidget styles do not render. Found this somewhere on the qt5 doc site.
    def paintEvent(self, event: QPaintEvent) -> None:
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PrimitiveElement.PE_Widget, opt, p, self)

    def add_main_content(self, layout: QHBoxLayout) -> None:
        raise NotImplementedError

    def add_actions(self, layout: QVBoxLayout) -> None:
        raise NotImplementedError


class NotificationCard(Card):
    def add_main_content(self, parent_layout: QHBoxLayout) -> None:
        layout = QVBoxLayout()
        parent_layout.addLayout(layout)

        layout.addStretch(1)
        if self._row.event_type == WalletEventType.SEED_BACKUP_REMINDER:
            title_label = QLabel(_("Backup your wallet"))
            title_label.setObjectName("NotificationCardTitle")

            description_label = QLabel(_("You should make sure you back up your wallet. If you "
                "lose access to it, you may not have any way to access or recover your funds and "
                "any other information it may contain. In the worst case, you may be able to "
                "write down and use your "
                "<a href=\"action:view-secured-data\">account's secured data</a>. More information "
                "is <a href=\"help:view-secured-data\">available here</a>."))
            description_label.setObjectName("NotificationCardDescription")
            description_label.setWordWrap(True)
            description_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
            description_label.linkActivated.connect(self.on_link_activated)

            date_context_label = QLabel(
                format_posix_timestamp(self._row.date_created, _("Unknown")))
            date_context_label.setAlignment(Qt.AlignmentFlag.AlignRight)
            date_context_label.setObjectName("NotificationCardContext")

            assert self._row.account_id is not None
            account_name = self._context.wallet_api.get_account_name(self._row.account_id)
            account_context_label = QLabel(_("Account: {}").format(account_name))
            account_context_label.setObjectName("NotificationCardContext")

            bottom_layout = QHBoxLayout()
            bottom_layout.addWidget(account_context_label, 1, Qt.AlignmentFlag.AlignLeft)
            bottom_layout.addWidget(date_context_label, 1, Qt.AlignmentFlag.AlignRight)

            layout.addWidget(title_label)
            layout.addWidget(description_label)
            layout.addLayout(bottom_layout)
        else:
            layout.addWidget(QLabel("Not yet implemented"))
        layout.addStretch(1)

    def add_actions(self, layout: QVBoxLayout) -> None:
        dismiss_label = ClickableLabel()
        dismiss_label.setPixmap(QPixmap(icon_path("icons8-delete.svg"))
            .scaledToWidth(15, Qt.TransformationMode.SmoothTransformation))
        dismiss_label.setToolTip(_("Dismiss this notification"))
        dismiss_label.clicked.connect(self._on_dismiss_button_clicked)

        layout.addWidget(dismiss_label)
        layout.addStretch(1)

    def _on_dismiss_button_clicked(self) -> None:
        new_flags = self._row.event_flags & ~WalletEventFlag.UNREAD
        self._context.wallet_api.update_notification_flags([ (new_flags, self._row.event_id) ])
        self._context.entry_removed.emit(self._row)

    def on_link_activated(self, url: str) -> None:
        url_type, url_path = url.split(":", 1)
        if url_type == "action":
            if url_path == "view-secured-data":
                assert self._row.account_id is not None
                self._context.wallet_api.prompt_to_show_secured_data(self._row.account_id)
                return
        elif url_type == "help":
            if url_path == "view-secured-data":
                self._context.wallet_api.show_help("misc", "secured-data")
                return
        raise NotImplementedError
