# The Open BSV license.
#
# Copyright © 2020 Bitcoin Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
#   1. The above copyright notice and this permission notice shall be included
#      in all copies or substantial portions of the Software.
#   2. The Software, and any software that is derived from the Software or parts
#      thereof, can only be used on the Bitcoin SV blockchains. The Bitcoin SV
#      blockchains are defined, for purposes of this license, as the Bitcoin
#      blockchain containing block height #556767 with the hash
#      “000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b” and
#      the test blockchains that are supported by the unmodified Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from functools import partial
from typing import Any, List

from PyQt5.QtCore import QObject, Qt, QUrl, pyqtSignal
from PyQt5.QtGui import QDesktopServices, QPainter, QPixmap
from PyQt5.QtWidgets import (QVBoxLayout, QLabel, QLayout, QWidget,
    QHBoxLayout, QStyle, QStyleOption, QToolBar, QAction, QListWidget,
    QListWidgetItem)

from electrumsv.constants import WalletEventFlag, WalletEventType
from electrumsv.i18n import _
from electrumsv.util import format_time
from electrumsv.wallet_database.tables import WalletEventRow

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
        self.wallet_api.dismissed_notification.connect(self.entry_removed.emit)

    def get_empty_text(self) -> str:
        return _("No new notifications.")

    def get_entry_text(self, row: WalletEventRow) -> str:
        if row.event_type == WalletEventType.SEED_BACKUP_REMINDER:
            return _("Add text about how users should backup their seeds.")
        # Intentionally not localised.
        return "Not yet implemented"

    def get_entry_image_text(self, row: WalletEventRow) -> str:
        if row.event_type == WalletEventType.SEED_BACKUP_REMINDER:
            image_text = _("Warning")
        elif row.event_type == WalletEventType.WALLET_UPDATE:
            image_text = _("Warning")
        else:
            image_text = _("Getting started")
        return image_text

    def get_entry_image_filename(self, row: WalletEventRow) -> str:
        if row.event_type == WalletEventType.SEED_BACKUP_REMINDER:
            image_filename = "icons8-warning-shield-80-blueui.png"
        elif row.event_type == WalletEventType.WALLET_UPDATE:
            image_filename = "icons8-warning-shield-80-blueui.png"
        elif row.event_type == WalletEventType.ACCOUNT_CREATION_HINT:
            image_filename = "icons8-add-folder-80.png"
        else:
            image_filename = "icons8-decision-80.png"
        return image_filename

    def get_rows(self) -> List[WalletEventRow]:
        return self.wallet_api.get_notification_rows()

    def compare_rows(self, row1: WalletEventRow, row2: WalletEventRow) -> bool:
        return row1.event_id == row2.event_id

    def on_list_updated(self, entry_count: int) -> None:
        self.wallet_api.update_displayed_notification_count(entry_count)

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
        toolbar.setOrientation(Qt.Vertical)
        toolbar.setToolButtonStyle(Qt.ToolButtonIconOnly)
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
        if self._sort_type == 1:
            self._sort_type = -1
            self._sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-80-blueui.png"))
            self._cards._list.sortItems(Qt.DescendingOrder)
        else:
            self._sort_type = 1
            self._sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-2-80-blueui.png"))
            self._cards._list.sortItems(Qt.AscendingOrder)


class Cards(QWidget):
    def __init__(self, context: ListContext, parent: QWidget) -> None:
        super().__init__(parent)

        self._context = context

        self._layout = QVBoxLayout()
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self._empty_label = None
        self._list = None

        rows = self._context.get_rows()
        if len(rows) > 0:
            for row in rows:
                self._add_entry(row)
        else:
            self._add_empty_label()

        self.setLayout(self._layout)

        self._context.entry_added.connect(partial(self._on_entry_added_or_removed, True))
        self._context.entry_removed.connect(partial(self._on_entry_added_or_removed, False))
        self._context.on_list_updated(len(rows))

    def _add_entry(self, row: Any) -> None:
        self._remove_empty_label()
        if self._list is None:
            self._list = QListWidget(self)
            self._list.setSortingEnabled(self._context.sortable_list)
            self._layout.addWidget(self._list)

        card = self._context.card_factory(row)
        for list_index in range(self._list.count()):
            list_item = self._list.item(list_index)
            if list_item.data(Qt.UserRole) == row.event_id:
                self._list.setItemWidget(list_item, card)
                return

        list_item = QListWidgetItem()
        # The item won't display unless it gets a size hint. It seems to resize horizontally
        # but unless the height is a minimal amount it won't do anything proactive..
        list_item.setSizeHint(card.sizeHint())
        list_item.setData(Qt.UserRole, row.event_id)
        self._list.addItem(list_item)
        self._list.setItemWidget(list_item, card)

    def _remove_entry(self, row: Any) -> None:
        # NOTE(rt12) Hack to silence bug in creating a second wallet while the first is open.
        #     No idea but seems to work anyway.
        if self._list is None:
            return
        for i in range(self._list.count()-1, -1, -1):
            item = self._list.item(i)
            widget = self._list.itemWidget(item)
            if self._context.compare_rows(widget._row, row):
                self._list.takeItem(i)

        if self._list.count() == 0:
            # Remove the list.
            self._list.setParent(None)
            self._list = None

            # Replace it with the placeholder label.
            self._add_empty_label()

    def _on_entry_added_or_removed(self, added: bool, row: Any) -> None:
        if added:
            self._add_entry(row)
        else:
            self._remove_entry(row)

        entry_count = 0 if self._list is None else self._list.count()
        self._context.on_list_updated(entry_count)

    def _add_empty_label(self) -> None:
        self._empty_label = QLabel(self._context.get_empty_text())
        self._empty_label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self._layout.addWidget(self._empty_label)

    def _remove_empty_label(self) -> None:
        if self._empty_label is not None:
            self._empty_label.setParent(None)
            self._empty_label = None


class Card(QWidget):
    def __init__(self, context: ListContext, row: Any, parent: Any=None):
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
        image_label.setAlignment(Qt.AlignHCenter)

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
    def paintEvent(self, event):
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PE_Widget, opt, p, self)

    def add_main_content(self, layout: QLayout) -> None:
        raise NotImplementedError

    def add_actions(self, layout: QLayout) -> None:
        raise NotImplementedError


class NotificationCard(Card):
    def add_main_content(self, parent_layout: QHBoxLayout) -> None:
        layout = QVBoxLayout()
        parent_layout.addLayout(layout)

        layout.addStretch(1)
        if self._row.event_type == WalletEventType.WALLET_UPDATE:
            title_label = QLabel(_("Update ElectrumSV"))
            title_label.setObjectName("NotificationCardTitle")

            description_label = QLabel(_("It is strongly advised that you update ElectrumSV as"
                "there is a new version available. The ElectrumSV developers do not support "
                "older versions of the wallet, so it is in your best interest to upgrade "
                "immediately when a new version is available. Click "
                "<a href=\"action:update\">here</a> to get the latest version."))
            description_label.setObjectName("NotificationCardDescription")
            description_label.setWordWrap(True)
            description_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
            description_label.linkActivated.connect(self.on_link_activated)

            date_context_label = QLabel(format_time(self._row.date_created, _("Unknown")))
            date_context_label.setAlignment(Qt.AlignRight)
            date_context_label.setObjectName("NotificationCardContext")

            bottom_layout = QHBoxLayout()
            bottom_layout.addWidget(date_context_label, 1, Qt.AlignRight)

            layout.addWidget(title_label)
            layout.addWidget(description_label)
            layout.addLayout(bottom_layout)
        elif self._row.event_type == WalletEventType.ACCOUNT_CREATION_HINT:
            title_label = QLabel(_("Create an account"))
            title_label.setObjectName("NotificationCardTitle")

            description_label = QLabel(_("Before you can access coins in your wallet you need to "
                "create an account. You can do this by clicking on the Add Account button in "
                "the toolbar area with the buttons above."))
            description_label.setObjectName("NotificationCardDescription")
            description_label.setWordWrap(True)
            description_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
            description_label.linkActivated.connect(self.on_link_activated)

            date_context_label = QLabel(format_time(self._row.date_created, _("Unknown")))
            date_context_label.setAlignment(Qt.AlignRight)
            date_context_label.setObjectName("NotificationCardContext")

            bottom_layout = QHBoxLayout()
            bottom_layout.addWidget(date_context_label, 1, Qt.AlignRight)

            layout.addWidget(title_label)
            layout.addWidget(description_label)
            layout.addLayout(bottom_layout)
        elif self._row.event_type == WalletEventType.SEED_BACKUP_REMINDER:
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
            description_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
            description_label.linkActivated.connect(self.on_link_activated)

            date_context_label = QLabel(format_time(self._row.date_created, _("Unknown")))
            date_context_label.setAlignment(Qt.AlignRight)
            date_context_label.setObjectName("NotificationCardContext")

            account_name = self._context.wallet_api.get_account_name(self._row.account_id)
            account_context_label = QLabel(_("Account: {}").format(account_name))
            account_context_label.setObjectName("NotificationCardContext")

            bottom_layout = QHBoxLayout()
            bottom_layout.addWidget(account_context_label, 1, Qt.AlignLeft)
            bottom_layout.addWidget(date_context_label, 1, Qt.AlignRight)

            layout.addWidget(title_label)
            layout.addWidget(description_label)
            layout.addLayout(bottom_layout)
        else:
            layout.addWidget(QLabel("Not yet implemented"))
        layout.addStretch(1)

    def add_actions(self, layout: QVBoxLayout) -> None:
        dismiss_label = ClickableLabel()
        dismiss_label.setPixmap(QPixmap(icon_path("icons8-delete.svg"))
            .scaledToWidth(15, Qt.SmoothTransformation))
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
                self._context.wallet_api.prompt_to_show_secured_data(self._row.account_id)
                return
            elif url_path == "update":
                QDesktopServices.openUrl(QUrl("https://electrumsv.io/download.html"))
                return
        elif url_type == "help":
            if url_path == "view-secured-data":
                self._context.wallet_api.show_help("misc", "secured-data")
                return
        raise NotImplementedError
