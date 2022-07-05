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

from __future__ import annotations
from datetime import datetime
import enum
import time
from typing import cast, TYPE_CHECKING
import weakref

from PyQt6.QtCore import pyqtSignal, QSize, Qt
from PyQt6.QtGui import QContextMenuEvent, QFontMetrics, QKeyEvent, QPaintEvent, QPixmap
from PyQt6.QtWidgets import QAbstractItemView, QGridLayout, QHBoxLayout, QHeaderView, QLabel, \
    QListWidget, QListWidgetItem, QSizePolicy, QTableWidget, QVBoxLayout, QWidget, QWizard, \
    QWizardPage

from ...constants import NetworkServerFlag, NetworkServerType
from ...i18n import _
from ...logs import logs
from ...platform import platform
from ...types import ServerAccountKey

from .util import icon_path, read_QIcon

if TYPE_CHECKING:
    from ...wallet import Wallet


logger = logs.get_logger('wizard-server')


class ListRole(enum.IntEnum):
    SERVER_KEY = Qt.ItemDataRole.UserRole + 1


# Qt6AutoPageSkip
# If the completion conditions for a wizard page are met (we might have a default option that is
# selected by default or no requirement to choose one of the options) Qt6 skips over the page and
# will even exit the wizard if the last page was like this. For this reason we tie pages that
# could otherwise be skipped over as not completed until they have been displayed at least once.

# Qt6AutoPageSkip
class PageState(enum.IntEnum):
    CLEANED_UP                      = 1
    INITIALIZED                     = 2
    UPDATED                         = 3


class Page(enum.IntEnum):
    FINISHED                        = -1
    NONE                            = 0
    START                           = 1
    SELECT_BLOCKCHAIN_SERVER        = 2
    SELECT_PEER_CHANNEL_SERVER      = 3
    SUMMARY                         = 4


class ListWidget(QListWidget):
    refresh_signal = pyqtSignal()
    key_signal = pyqtSignal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        if key == Qt.Key.Key_R and event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.refresh_signal.emit()
        elif key == Qt.Key.Key_Return or key == Qt.Key.Key_Enter:
            self.key_signal.emit()
        super(ListWidget, self).keyPressEvent(event)


class TableWidget(QTableWidget):
    key_activation_signal = pyqtSignal()
    refresh_signal = pyqtSignal()

    def __init__(self, header_titles: list[str], /, stretch_column: int,
            selection_mode: QAbstractItemView.SelectionMode=
                QAbstractItemView.SelectionMode.SingleSelection) -> None:
        super().__init__()

        self.setSelectionMode(selection_mode)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        self.setColumnCount(len(header_titles))
        horizontalHeader = self.horizontalHeader()
        horizontalHeader.setMinimumSectionSize(150)
        default_stretch_mode = QHeaderView.ResizeMode.ResizeToContents
        for column_index in range(len(header_titles)):
            if column_index != stretch_column:
                horizontalHeader.setSectionResizeMode(stretch_column, default_stretch_mode)
        horizontalHeader.setSectionResizeMode(stretch_column, QHeaderView.ResizeMode.Stretch)

        verticalHeader = self.verticalHeader()
        verticalHeader.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        verticalHeader.hide()

        self.setStyleSheet("""
            QTableView {
                selection-background-color: #F5F8FA;
            }
            QHeaderView::section {
                font-weight: bold;
            }
        """)
        self.setHorizontalHeaderLabels(header_titles)

        # Tab by default in QTableWidget, moves between list items. The arrow keys also perform
        # the same function, and we want tab to allow exiting the table instead.
        self.setTabKeyNavigation(False)

        # self.selectionModel().selectionChanged.connect(self._on_item_selection_changed)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        if key == Qt.Key.Key_R and event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            self.refresh_signal.emit()
        elif key == Qt.Key.Key_Return or key == Qt.Key.Key_Enter:
            self.key_activation_signal.emit()
        else:
            super().keyPressEvent(event)

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        pass

    def resize_vertically(self) -> None:
        # Account for row borders.
        total_height = 20

        vertical_header = self.verticalHeader()
        for row_index in range(vertical_header.count()):
            if not vertical_header.isSectionHidden(row_index):
                total_height += vertical_header.sectionSize(row_index)

        if self.horizontalScrollBar().isVisible():
            total_height += self.horizontalScrollBar().height()

        total_height += self.horizontalHeader().height()

        self.setMinimumHeight(total_height)
        self.setMaximumHeight(total_height)


class ServerSelectionWizard(QWizard):
    """
    Circumstances where this is displayed:
    - SHOWN: When a wallet is opened where it has not been displayed before.
      - The wizard appears and it is up to the user to select servers or dismiss it.
    - MAYBE SHOWN: Via a dashboard option that is displayed when a wallet is opened.
      - The wizard will open with context based on any current settings.
    """
    HELP_DIRNAME = "server-selection"

    existing_blockchain_server_key: ServerAccountKey | None = None
    existing_messagebox_server_key: ServerAccountKey | None = None
    selected_blockchain_server_key: ServerAccountKey | None = None
    selected_messagebox_server_key: ServerAccountKey | None = None

    def __init__(self, parent: QWidget, wallet: Wallet) -> None:
        super().__init__(parent)

        self.wallet: Wallet = weakref.proxy(wallet)

        self._load_existing_state()

        self.setWindowTitle('Server Selection')
        self.setMinimumSize(600, 600)

        # The default Windows platform is "Aero" designed for Windows Vista. The primary reason to
        # change it, is to get back buttons that are not hard to find.
        if platform.name != "MacOSX":
            self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setOption(QWizard.WizardOption.IndependentPages, True)

        self.setPage(Page.START, OverviewPage(self))
        self.setPage(Page.SELECT_BLOCKCHAIN_SERVER, SelectBlockchainServerPage(self))
        self.setPage(Page.SELECT_PEER_CHANNEL_SERVER, SelectPeerChannelServerPage(self))
        self.setPage(Page.SUMMARY, SummaryPage(self))

        self.setStartId(Page.START)

    def _load_existing_state(self) -> None:
        account_row = self.wallet._petty_cash_account.get_row()
        for server in self.wallet._servers.values():
            if server.server_id == account_row.peer_channel_server_id:
                self.existing_messagebox_server_key = server.key
            if server.server_id == account_row.blockchain_server_id:
                self.existing_blockchain_server_key = server.key


class OverviewPage(QWizardPage):
    # Qt6AutoPageSkip
    _page_state = PageState.CLEANED_UP

    _next_row_index = 0

    def __init__(self, wizard: ServerSelectionWizard) -> None:
        super().__init__(wizard)

        self.setTitle("Manage your wallet server usage")

        self._table_row_indexes: dict[TableWidget, int] = {}

        pass_base_pixmap = QPixmap(icon_path("icons8-pass-32-windows.png"))
        self._pass_pixmap = QPixmap(pass_base_pixmap.size())
        self._pass_pixmap.fill(Qt.GlobalColor.darkGreen)
        self._pass_pixmap.setMask(pass_base_pixmap.createMaskFromColor(Qt.GlobalColor.transparent))
        fail_base_pixmap = QPixmap(icon_path("icons8-fail-32-windows.png"))
        self._fail_pixmap = QPixmap(fail_base_pixmap.size())
        self._fail_pixmap.fill(Qt.GlobalColor.lightGray)
        self._fail_pixmap.setMask(fail_base_pixmap.createMaskFromColor(Qt.GlobalColor.transparent))

        self._signal_pixmap = QPixmap(icon_path("icons8-signal-80-blueui.png"))
        self._no_server_pixmap = QPixmap(icon_path("icons8-bad-decision-80-blueui.png"))

        self._server_table = TableWidget([ "Current servers", "Type" ], stretch_column=0)
        sizePolicy = QSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Maximum)
        self._server_table.setSizePolicy(sizePolicy)
        self._server_table.setMinimumHeight(100)
        self._server_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        # self._table.doubleClicked.connect(self._on_health_key_activation)
        # self._table.key_activation_signal.connect(self._on_health_key_activation)

        font_metrics = QFontMetrics(self.font())
        line_height = font_metrics.height() + 2
        support_entry_height = int(line_height * 2.2)

        self._blockchain_table = TableWidget(
            [ "The meaning of the current blockchain server setting" ], stretch_column=0)
        # The keyboard focus will not see this table. Nor will there be the dotted
        # "selection rectangle" that looks awful.
        self._blockchain_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        verticalHeader = self._blockchain_table.verticalHeader()
        verticalHeader.setMaximumSectionSize(support_entry_height)
        verticalHeader.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)

        self._messagebox_table = TableWidget(
            [ "The meaning of the current message box server setting" ], stretch_column=0)
        self._messagebox_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        verticalHeader = self._messagebox_table.verticalHeader()
        verticalHeader.setMaximumSectionSize(support_entry_height)
        verticalHeader.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)

        hint_label = QLabel(_("You can choose which servers to use on the next page."))
        hint_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint_label.setWordWrap(True)
        contents_margins = hint_label.contentsMargins()
        contents_margins.setTop(10)
        contents_margins.setBottom(10)
        hint_label.setContentsMargins(contents_margins)

        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 0)
        layout.addWidget(self._server_table)
        layout.addWidget(hint_label)
        layout.addWidget(self._blockchain_table)
        layout.addWidget(self._messagebox_table)
        layout.addStretch(1)

        self._update_layout(wizard)

        self.setLayout(layout)

    def _update_layout(self, wizard: ServerSelectionWizard) -> None:
        for table in [ self._server_table, self._blockchain_table, self._messagebox_table ]:
            while table.rowCount() > 0:
                table.removeRow(table.rowCount()-1)
            self._table_row_indexes[table] = 0

        if wizard.existing_blockchain_server_key:
            self._add_server_entry(self._signal_pixmap, wizard.existing_blockchain_server_key.url,
                _("You have previously set up this server"), _("Blockchain server"))
        else:
            self._add_server_entry(self._no_server_pixmap, _("No selected server"),
                _("You have not set up a server"), _("Blockchain server"))

        if wizard.existing_messagebox_server_key:
            self._add_server_entry(self._signal_pixmap, wizard.existing_messagebox_server_key.url,
                _("You have previously set up this server"), _("Message box server"))
        else:
            self._add_server_entry(self._no_server_pixmap, _("No selected server"),
                _("You have not set up a server"), _("Message box server"))

        self._server_table.resize_vertically()

        if wizard.existing_blockchain_server_key:
            self._add_support_entry(self._blockchain_table, self._pass_pixmap,
                _("The wallet can restore an account using seed words (given you understand "
                "the limitations of seed-based restoration)."))
            self._add_support_entry(self._blockchain_table, self._pass_pixmap,
                _("The wallet can obtain any known transactions that it needs."))
            self._add_support_entry(self._blockchain_table, self._pass_pixmap,
                _("The wallet can obtain proof that any transaction it has, has been mined, when "
                "it needs to."))
            if wizard.existing_messagebox_server_key:
                self._add_support_entry(self._blockchain_table, self._pass_pixmap,
                    _("The wallet can detect if someone sends you a payment to any addresses you "
                    "will give out."))
            else:
                self._add_support_entry(self._blockchain_table, self._fail_pixmap,
                    _("The wallet cannot detect if someone sends you a payment "
                    "to any addresses you will give out (as you do not have a message box server "
                    "that will receive them)."))
        else:
            self._add_support_entry(self._blockchain_table, self._fail_pixmap,
                _("The wallet cannot restore an account using seed words."))
            self._add_support_entry(self._blockchain_table, self._fail_pixmap,
                _("The wallet cannot obtain any known transactions that it needs."))
            self._add_support_entry(self._blockchain_table, self._fail_pixmap,
                _("The wallet cannot obtain proof that any transaction it "
                "has, has been mined, when it needs to."))
            self._add_support_entry(self._blockchain_table, self._fail_pixmap,
                _("The wallet cannot detect if someone sends you a payment to "
                "any address you will give out."))

        if wizard.existing_messagebox_server_key:
            self._add_support_entry(self._messagebox_table, self._pass_pixmap,
                _("The wallet can receive proof that transactions it has "
                "broadcast using MAPI servers have been mined."))
            self._add_support_entry(self._messagebox_table, self._pass_pixmap,
                _("The wallet can receive notifications that transactions "
                "it has received from others and broadcast using MAPI servers have been double "
                "spent."))
            if wizard.existing_blockchain_server_key:
                self._add_support_entry(self._messagebox_table, self._pass_pixmap,
                    _("The wallet can receive notifications if someone sends "
                    "you a payment to any addresses you will give out."))
            else:
                self._add_support_entry(self._messagebox_table, self._fail_pixmap,
                    _("The wallet cannot receive notifications if someone sends "
                    "you a payment to any addresses you will give out (as you do not have a "
                    "blockchain server that will send them)."))
        else:
            self._add_support_entry(self._messagebox_table, self._fail_pixmap,
                _("The wallet cannot receive proof that transactions it has "
                "broadcast using MAPI servers have been mined."))
            self._add_support_entry(self._messagebox_table, self._fail_pixmap,
                _("The wallet cannot receive notifications that transactions "
                "it has received from others and broadcast using MAPI servers have been double "
                "spent."))
            self._add_support_entry(self._messagebox_table, self._fail_pixmap,
                _("The wallet cannot receive notifications if someone sends "
                "you a payment to any addresses you will give out."))

    def initializePage(self) -> None:
        # Qt6AutoPageSkip
        self._page_state = PageState.INITIALIZED

        wizard = cast(ServerSelectionWizard, self.wizard())
        self._update_layout(wizard)

    def cleanupPage(self) -> None:
        # Qt6AutoPageSkip
        self._page_state = PageState.CLEANED_UP

    def validatePage(self) -> bool:
        # Qt6AutoPageSkip
        return self._page_state == PageState.UPDATED

    def paintEvent(self, event: QPaintEvent) -> None:
        # Qt6AutoPageSkip
        if self._page_state == PageState.INITIALIZED:
            self._page_state = PageState.UPDATED
        super().paintEvent(event)

    def _add_support_entry(self, table: TableWidget, pixmap: QPixmap, title_text: str) -> int:
        current_row = self._table_row_indexes[table]
        self._table_row_indexes[table] += 1

        table.insertRow(current_row)

        update_widget = QWidget()

        update_row_layout = QHBoxLayout()
        update_row_layout.setSpacing(0)
        contents_margins = update_row_layout.contentsMargins()
        contents_margins.setLeft(8)
        contents_margins.setRight(10)
        contents_margins.setTop(0)
        contents_margins.setBottom(0)
        update_row_layout.setContentsMargins(contents_margins)

        update_icon_label = QLabel()
        update_icon_label.setPixmap(pixmap.scaledToWidth(30,
            Qt.TransformationMode.SmoothTransformation))
        update_icon_label.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignVCenter)
        contents_margins = update_icon_label.contentsMargins()
        contents_margins.setRight(10)
        update_icon_label.setContentsMargins(contents_margins)

        update_text_label = QLabel(title_text)
        update_text_label.setWordWrap(True)
        update_text_label.setTextFormat(Qt.TextFormat.RichText)
        sizePolicy = QSizePolicy(QSizePolicy.Policy.MinimumExpanding, QSizePolicy.Policy.Maximum)
        update_text_label.setSizePolicy(sizePolicy)

        update_row_layout.addWidget(update_icon_label)
        update_row_layout.addWidget(update_text_label)

        update_widget.setLayout(update_row_layout)
        table.setCellWidget(current_row, 0, update_widget)
        table.resizeRowToContents(current_row)

        return current_row

    def _add_server_entry(self, pixmap: QPixmap, title_text: str, subtitle_text: str,
            server_type_text: str) -> int:
        current_row = self._table_row_indexes[self._server_table]
        self._table_row_indexes[self._server_table] += 1

        self._server_table.insertRow(current_row)

        update_widget = QWidget()
        update_row_layout = QHBoxLayout()
        update_row_layout.setSpacing(0)

        update_icon_label = QLabel()
        update_icon_label.setPixmap(pixmap.scaledToWidth(30,
            Qt.TransformationMode.SmoothTransformation))
        update_icon_label.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignVCenter)
        contents_margins = update_icon_label.contentsMargins()
        contents_margins.setLeft(0)
        contents_margins.setRight(10)
        contents_margins.setTop(0)
        contents_margins.setBottom(0)
        update_icon_label.setContentsMargins(contents_margins)

        update_text_label = QLabel(title_text +
            "<br/><font color='grey'>"+ subtitle_text +"</font>")
        update_text_label.setTextFormat(Qt.TextFormat.RichText)

        update_row_layout.addWidget(update_icon_label)
        update_row_layout.addWidget(update_text_label)
        update_row_layout.addStretch(1)

        update_widget.setLayout(update_row_layout)
        self._server_table.setCellWidget(current_row, 0, update_widget)

        extra_widget = QLabel(server_type_text)
        contentsMargins = extra_widget.contentsMargins()
        contentsMargins.setLeft(10)
        extra_widget.setContentsMargins(contentsMargins)
        self._server_table.setCellWidget(current_row, 1, extra_widget)

        return current_row

    def _on_list_item_selection_changed(self) -> None:
        pass

    def _on_list_item_key(self) -> None:
        pass


# ------------------------------------------------------------------------------------------------

class SelectBlockchainServerPage(QWizardPage):
    def __init__(self, parent: ServerSelectionWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Select a blockchain server"))

        self._list = ListWidget()
        self._list.setIconSize(QSize(40, 40))
        self._list.setMaximumWidth(400)
        self._list.setWordWrap(True)
        self._list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self._list.itemSelectionChanged.connect(self._on_list_item_selection_changed)
        self._list.key_signal.connect(self._on_list_item_key)

        self._option_detail = QLabel()
        self._option_detail.setMinimumWidth(200)
        self._option_detail.setAlignment(Qt.AlignmentFlag(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft))
        self._option_detail.setTextFormat(Qt.TextFormat.RichText)
        self._option_detail.setWordWrap(True)
        self._option_detail.setOpenExternalLinks(True)
        self._option_detail.setContentsMargins(10, 10, 10, 10)
        self._option_detail.setText(self._get_item_detail_qhtml())

        layout = QHBoxLayout()
        # It looks tidier with more separation between the list and the detail pane.
        layout.setSpacing(15)
        layout.addWidget(self._list)
        layout.addWidget(self._option_detail)
        self.setLayout(layout)

    def initializePage(self) -> None:
        wizard = cast(ServerSelectionWizard, self.wizard())

        signal_icon = read_QIcon("icons8-signal-80-blueui.png")
        no_server_icon = read_QIcon("icons8-bad-decision-80-blueui.png")

        selection_item: QListWidgetItem | None = None
        self._list.clear()

        text = "<b>"+ _("No blockchain server.") +"</b>"
        label = QLabel(text)
        margins = label.contentsMargins()
        label.setContentsMargins(margins.left() + 10, margins.top(), margins.right(),
            margins.bottom())

        list_item = QListWidgetItem()
        list_item.setSizeHint(QSize(50, 50))
        list_item.setIcon(no_server_icon)
        list_item.setData(ListRole.SERVER_KEY, None)
        self._list.addItem(list_item)
        self._list.setItemWidget(list_item, label)

        for server in wizard.wallet.get_servers():
            if server.key.server_type != NetworkServerType.GENERAL:
                continue
            server_row = server.database_rows[None]
            if server_row.server_flags & NetworkServerFlag.CAPABILITY_TIP_FILTER == 0:
                continue

            server_state = server.api_key_state.get(None, None)

            icon = no_server_icon
            last_good_date_text = "never"
            if server_state is not None:
                if server_state.last_good > 0:
                    last_good_date = datetime.fromtimestamp(server_state.last_good)
                    last_good_date_text = last_good_date.isoformat(sep=" ", timespec="seconds")

                    if server_state.last_good > time.time() - 10 * 60:
                        icon = signal_icon

            text = "<b>"+ server.url +"</b><br/>" \
                f"Last contacted: {last_good_date_text}"
            label = QLabel(text)
            margins = label.contentsMargins()
            label.setContentsMargins(margins.left() + 10, margins.top(), margins.right(),
                margins.bottom())

            list_item = QListWidgetItem()
            list_item.setSizeHint(QSize(50, 50))
            list_item.setIcon(icon)
            list_item.setData(Qt.ItemDataRole.UserRole, 1)
            list_item.setData(ListRole.SERVER_KEY, server.key)
            self._list.addItem(list_item)
            self._list.setItemWidget(list_item, label)

            if server.key == wizard.existing_blockchain_server_key:
                selection_item = list_item

        if selection_item is not None:
            self._list.setCurrentItem(selection_item)

    def _update_selected_item(self) -> QListWidgetItem | None:
        wizard = cast(ServerSelectionWizard, self.wizard())
        items = self._list.selectedItems()
        if len(items) > 0:
            wizard.existing_blockchain_server_key = items[0].data(ListRole.SERVER_KEY)
            return items[0]
        wizard.existing_blockchain_server_key = None
        return None

    # Qt method called to determine if 'Next' or 'Finish' should be enabled or disabled.
    # Overriding this requires us to emit the 'completeChanges' signal where applicable.
    def isComplete(self) -> bool:
        return len(self._list.selectedItems()) > 0

    # Qt method called when 'Next' or 'Finish' is clicked for last-minute validation.
    def validatePage(self) -> bool:
        self._update_selected_item()
        # print("SSW.BCS.validatePage", wizard.existing_blockchain_server_key)
        return True

    # Qt method called to get the Id of the next page.
    def nextId(self) -> Page:
        return Page.SELECT_PEER_CHANNEL_SERVER

    def _on_list_item_activated(self, item: QListWidgetItem) -> None:
        # This is a standard Qt event. It is supposed to be triggered for double clicks, pressing
        # the "return" key on Windows, or the standard selection combination on MacOS. However,
        # modern keyboards on Windows do not have a "return" key and likely have an "enter" key
        # and that does not do anything.
        if self._update_selected_item() is not None:
            self.wizard().next()

    def _on_list_item_key(self) -> None:
        # This is a custom event to detect pressing the "enter" or "return" key. The reason we do
        # this is because the standard "activated" event does not seem to work for "return".
        if self._update_selected_item() is not None:
            self.wizard().next()

    def _on_list_item_selection_changed(self) -> None:
        selected_item = self._update_selected_item()
        self.completeChanged.emit()
        self._option_detail.setText(self._get_item_detail_qhtml(selected_item))

    def _get_item_detail_qhtml(self, selected_item: QListWidgetItem | None=None) -> str:
        """
        """
        if selected_item is None or selected_item.data(ListRole.SERVER_KEY) is None:
            icon_name = icon_path("icons8-decision-80.png")
            return f"""
            <center>
                <img src='{icon_name}' width=80 height=80 />
            </center>
            <p>
                <b>You do not have a blockchain server selected for your wallet to use.</b>
            </p>
            <p>
                A blockchain server allows your wallet to:
            </p>
            <p>
                <b>&#9900;</b> Restore an account using seed words.
            </p>
            <p>
                <b>&#9900;</b> Obtain any known transactions that it needs.
            </p>
            <p>
                <b>&#9900;</b> Obtain proof that any transaction it has, has been mined,
                when it needs to.
            </p>
            <p>
                <b>&#9900;</b> Detect if someone sends you a payment to an address.
            </p>
            """
        icon_name = icon_path("icons8-decision-80.png")
        return f"""
        <center>
            <img src='{icon_name}' width=80 height=80 />
        </center>
        <p>
            <b>You have selected a blockchain server for your wallet to use.</b>
        </p>
        <p>
            It will allow your wallet to:
        </p>
        <p>
            <b>&#9900;</b> Restore an account using seed words.
        </p>
        <p>
            <b>&#9900;</b> Obtain any known transactions that it needs.
        </p>
        <p>
            <b>&#9900;</b> Obtain proof that any transaction it has, has been mined,
            when it needs to.
        </p>
        <p>
            <b>&#9900;</b> Detect if someone sends you a payment to an address.
        </p>
        """


class SelectPeerChannelServerPage(QWizardPage):
    def __init__(self, parent: ServerSelectionWizard) -> None:
        super().__init__(parent)

        self.setTitle(_("Select a message box server"))

        self._list = ListWidget()
        self._list.setIconSize(QSize(40, 40))
        self._list.setMaximumWidth(400)
        self._list.setWordWrap(True)
        self._list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        self._list.itemSelectionChanged.connect(self._on_list_item_selection_changed)
        self._list.key_signal.connect(self._on_list_item_key)

        self._option_detail = QLabel()
        self._option_detail.setMinimumWidth(200)
        self._option_detail.setAlignment(Qt.AlignmentFlag(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft))
        self._option_detail.setTextFormat(Qt.TextFormat.RichText)
        self._option_detail.setWordWrap(True)
        self._option_detail.setOpenExternalLinks(True)
        self._option_detail.setText(self._get_item_detail_qhtml())

        layout = QHBoxLayout()
        # It looks tidier with more separation between the list and the detail pane.
        layout.setSpacing(15)
        layout.addWidget(self._list)
        layout.addWidget(self._option_detail)
        self.setLayout(layout)

    def initializePage(self) -> None:
        wizard = cast(ServerSelectionWizard, self.wizard())

        signal_icon = read_QIcon("icons8-signal-80-blueui.png")
        no_server_icon = read_QIcon("icons8-no-connection-80-blueui.png")

        selection_item: QListWidgetItem | None = None
        self._list.clear()

        text = "<b>"+ _("No peer channel server.") +"</b>"
        label = QLabel(text)
        margins = label.contentsMargins()
        label.setContentsMargins(margins.left() + 10, margins.top(), margins.right(),
            margins.bottom())

        list_item = QListWidgetItem()
        list_item.setSizeHint(QSize(50, 50))
        list_item.setIcon(no_server_icon)
        list_item.setData(ListRole.SERVER_KEY, None)
        self._list.addItem(list_item)
        self._list.setItemWidget(list_item, label)

        for server in wizard.wallet.get_servers():
            if server.key.server_type != NetworkServerType.GENERAL:
                continue
            server_row = server.database_rows[None]
            if server_row.server_flags & NetworkServerFlag.CAPABILITY_PEER_CHANNELS == 0:
                continue

            server_state = server.api_key_state.get(None, None)

            icon = no_server_icon
            last_good_date_text = "never"
            if server_state is not None:
                if server_state.last_good > 0:
                    last_good_date = datetime.fromtimestamp(server_state.last_good)
                    last_good_date_text = last_good_date.isoformat(sep=" ", timespec="seconds")

                    if server_state.last_good > time.time() - 10 * 60:
                        icon = signal_icon

            text = "<b>"+ server.url +"</b><br/>" \
                f"Last contacted: {last_good_date_text}"
            label = QLabel(text)
            margins = label.contentsMargins()
            label.setContentsMargins(margins.left() + 10, margins.top(), margins.right(),
                margins.bottom())

            list_item = QListWidgetItem()
            list_item.setSizeHint(QSize(50, 50))
            list_item.setIcon(icon)
            list_item.setData(ListRole.SERVER_KEY, server.key)
            self._list.addItem(list_item)
            self._list.setItemWidget(list_item, label)

            if server.key == wizard.existing_messagebox_server_key:
                selection_item = list_item

        if selection_item is not None:
            self._list.setCurrentItem(selection_item)

    # Qt method called to determine if 'Next' or 'Finish' should be enabled or disabled.
    # Overriding this requires us to emit the 'completeChanges' signal where applicable.
    def isComplete(self) -> bool:
        return len(self._list.selectedItems()) > 0

    # Qt method called when 'Next' or 'Finish' is clicked for last-minute validation.
    def validatePage(self) -> bool:
        if self.isComplete():
            wizard = cast(ServerSelectionWizard, self.wizard())
            items = self._list.selectedItems()
            wizard.existing_messagebox_server_key = items[0].data(ListRole.SERVER_KEY)
            return True
        return False

    # Qt method called to get the Id of the next page.
    def nextId(self) -> Page:
        return Page.SUMMARY

    def _on_list_item_activated(self, item: QListWidgetItem) -> None:
        # This is a standard Qt event. It is supposed to be triggered for double clicks, pressing
        # the "return" key on Windows, or the standard selection combination on MacOS. However,
        # modern keyboards on Windows do not have a "return" key and likely have an "enter" key
        # and that does not do anything.
        self.wizard().next()

    def _on_list_item_key(self) -> None:
        # This is a custom event to detect pressing the "enter" or "return" key. The reason we do
        # this is because the standard "activated" event does not seem to work for "return".
        items = self._list.selectedItems()
        if len(items) > 0:
            self.wizard().next()

    def _on_list_item_selection_changed(self) -> None:
        self.completeChanged.emit()
        items = self._list.selectedItems()
        selected_item = items[0] if len(items) > 0 else None
        self._option_detail.setText(self._get_item_detail_qhtml(selected_item))

    def _get_item_detail_qhtml(self, selected_item: QListWidgetItem | None=None) -> str:
        """
        """
        if selected_item is None or selected_item.data(ListRole.SERVER_KEY) is None:
            icon_name = icon_path("icons8-decision-80.png")
            return f"""
            <center>
                <img src='{icon_name}' width=80 height=80 />
            </center>
            <p>
                <b>You do not have a message box server selected for your wallet to use.</b>
            </p>
            <p>
                A message box server allows your wallet to:
            </p>
            <p>
                <b>&#9900;</b> Receive proof that transactions it has broadcast using MAPI
                servers have been mined.
            </p>
            <p>
                <b>&#9900;</b> Receive notifications that transactions it has received from
                others and broadcast using MAPI servers have been double spent.
            </p>
            <p>
                <b>&#9900;</b> Receive notifications if someone sends you a payment to any
                addresses you will give out.
            </p>
            """
        icon_name = icon_path("icons8-decision-80.png")
        return f"""
        <center>
            <img src='{icon_name}' width=80 height=80 />
        </center>
        <p>
            <b>You have selected a message box server for your wallet to use.</b>
        </p>
        <p>
            It will allow your wallet to:
        </p>
        <p>
            <b>&#9900;</b> Receive proof that transactions it has broadcast using MAPI
            servers have been mined.
        </p>
        <p>
            <b>&#9900;</b> Receive notifications that transactions it has received from
            others and broadcast using MAPI servers have been double spent.
        </p>
        <p>
            <b>&#9900;</b> Receive notifications if someone sends you a payment to any
            addresses you will give out.
        </p>
        """


class SummaryPage(QWizardPage):
    # Qt6AutoPageSkip
    _page_state = PageState.CLEANED_UP

    def __init__(self, wizard: ServerSelectionWizard) -> None:
        super().__init__(wizard)

        self.setTitle("Summary")
        self.setFinalPage(True)

        self._pass_pixmap = QPixmap(icon_path("icons8-pass-32-windows.png"))
        fail_base_pixmap = QPixmap(icon_path("icons8-fail-32-windows.png"))
        self._fail_pixmap = QPixmap(fail_base_pixmap.size())
        self._fail_pixmap.fill(Qt.GlobalColor.lightGray)
        self._fail_pixmap.setMask(fail_base_pixmap.createMaskFromColor(Qt.GlobalColor.transparent))

        self._introduction_label = QLabel()
        self._introduction_label.setWordWrap(True)

        self._selected_blockchain_key_label = QLabel(_("Blockchain server:"))
        self._selected_messagebox_key_label = QLabel(_("Message box server:"))
        self._selected_blockchain_value_label = QLabel()
        self._selected_messagebox_value_label = QLabel()

        choice_layout = QGridLayout()
        choice_layout.setColumnStretch(0, False)
        choice_layout.setColumnStretch(1, True)
        choice_layout.addWidget(self._selected_blockchain_key_label, 0, 0, 1, 1)
        choice_layout.addWidget(self._selected_blockchain_value_label, 0, 1, 1, 1)
        choice_layout.addWidget(self._selected_messagebox_key_label, 1, 0, 1, 1)
        choice_layout.addWidget(self._selected_messagebox_value_label, 1, 1, 1, 1)

        self._blockchain_introduction_label = QLabel()
        self._blockchain_introduction_label.setWordWrap(True)

        self._b1_icon_label = QLabel()
        self._b1_label = QLabel()
        self._b1_label.setWordWrap(True)
        self._b2_icon_label = QLabel()
        self._b2_label = QLabel()
        self._b2_label.setWordWrap(True)
        self._b3_icon_label = QLabel()
        self._b3_label = QLabel()
        self._b3_label.setWordWrap(True)
        self._b4_icon_label = QLabel()
        self._b4_label = QLabel()
        self._b4_label.setWordWrap(True)

        self._messagebox_introduction_label = QLabel()
        self._messagebox_introduction_label.setWordWrap(True)

        self._m1_icon_label = QLabel()
        self._m1_label = QLabel()
        self._m1_label.setWordWrap(True)
        self._m2_icon_label = QLabel()
        self._m2_label = QLabel()
        self._m2_label.setWordWrap(True)
        self._m3_icon_label = QLabel()
        self._m3_label = QLabel()
        self._m3_label.setWordWrap(True)

        grid_layout = QGridLayout()
        grid_layout.setColumnStretch(0, False)
        grid_layout.setColumnStretch(1, True)

        iy = 0
        grid_layout.addWidget(self._introduction_label, 0, 0, 1, 2)
        grid_layout.addLayout(choice_layout, 1, 0, 1, 2)

        by = iy + 2
        grid_layout.addWidget(self._blockchain_introduction_label, by+0, 0, 1, 2)
        grid_layout.addWidget(self._b1_icon_label, by+2, 0, 1, 1)
        grid_layout.addWidget(self._b1_label, by+2, 1, 1, 1)
        grid_layout.addWidget(self._b2_icon_label, by+3, 0, 1, 1)
        grid_layout.addWidget(self._b2_label, by+3, 1, 1, 1)
        grid_layout.addWidget(self._b3_icon_label, by+4, 0, 1, 1)
        grid_layout.addWidget(self._b3_label, by+4, 1, 1, 1)
        grid_layout.addWidget(self._b4_icon_label, by+5, 0, 1, 1)
        grid_layout.addWidget(self._b4_label, by+5, 1, 1, 1)

        my = by + 5 + 5
        grid_layout.addWidget(self._messagebox_introduction_label, my+0, 0, 1, 2)
        grid_layout.addWidget(self._m1_icon_label, my+2, 0, 1, 1)
        grid_layout.addWidget(self._m1_label, my+2, 1, 1, 1)
        grid_layout.addWidget(self._m2_icon_label, my+3, 0, 1, 1)
        grid_layout.addWidget(self._m2_label, my+3, 1, 1, 1)
        grid_layout.addWidget(self._m3_icon_label, my+4, 0, 1, 1)
        grid_layout.addWidget(self._m3_label, my+4, 1, 1, 1)

        layout = QVBoxLayout()
        layout.setContentsMargins(80, 0, 80, 0)
        layout.addStretch(1)
        layout.addWidget(self._introduction_label)
        layout.addStretch(1)
        layout.addLayout(grid_layout)
        layout.addStretch(1)

        self._update_layout(wizard)

        self.setLayout(layout)

    def _update_layout(self, wizard: ServerSelectionWizard) -> None:
        self._introduction_label.setText(_("You have selected the following server options for "
            "your wallet."))

        if wizard.existing_blockchain_server_key:
            self._selected_blockchain_value_label.setText(wizard.existing_blockchain_server_key.url)
        else:
            self._selected_blockchain_value_label.setText(_("None."))

        if wizard.existing_messagebox_server_key:
            self._selected_messagebox_value_label.setText(wizard.existing_messagebox_server_key.url)
        else:
            self._selected_messagebox_value_label.setText(_("None."))

        self._blockchain_introduction_label.setText(_("The blockchain server choice means:"))
        if wizard.existing_blockchain_server_key:
            self._b1_label.setText(_("The wallet can restore an account using seed words (given "
                "you understand the limitations of seed-based restoration)."))
            self._b1_icon_label.setPixmap(self._pass_pixmap)
            self._b2_label.setText(_("The wallet can obtain any known transactions that it needs."))
            self._b2_icon_label.setPixmap(self._pass_pixmap)
            self._b3_label.setText(_("The wallet can obtain proof that any transaction it has, "
                "has been mined, when it needs to."))
            self._b3_icon_label.setPixmap(self._pass_pixmap)
            if wizard.existing_messagebox_server_key:
                self._b4_label.setText(_("The wallet can detect if someone sends you a payment "
                    "to any addresses you will give out."))
                self._b4_icon_label.setPixmap(self._pass_pixmap)
            else:
                self._b4_label.setText(_("The wallet cannot detect if someone sends you a payment "
                    "to any addresses you will give out (as you do not have a message box server "
                    "that will receive them)."))
                self._b4_icon_label.setPixmap(self._fail_pixmap)
        else:
            self._b1_label.setText(_("The wallet cannot restore an account using seed words."))
            self._b1_icon_label.setPixmap(self._fail_pixmap)
            self._b2_label.setText(_("The wallet cannot obtain any known transactions that it "
                "needs."))
            self._b2_icon_label.setPixmap(self._fail_pixmap)
            self._b3_label.setText(_("The wallet cannot obtain proof that any transaction it "
                "has, has been mined, when it needs to."))
            self._b3_icon_label.setPixmap(self._fail_pixmap)
            self._b4_label.setText(_("The wallet cannot detect if someone sends you a payment to "
                "any address you will give out."))
            self._b4_icon_label.setPixmap(self._fail_pixmap)

        self._messagebox_introduction_label.setText(_("The message box server choice means:"))
        if wizard.existing_messagebox_server_key:
            self._m1_label.setText(_("The wallet can receive proof that transactions it has "
                "broadcast using MAPI servers have been mined."))
            self._m1_icon_label.setPixmap(self._pass_pixmap)
            self._m2_label.setText(_("The wallet can receive notifications that transactions "
                "it has received from others and broadcast using MAPI servers have been double "
                "spent."))
            self._m2_icon_label.setPixmap(self._pass_pixmap)
            if wizard.existing_blockchain_server_key:
                self._m3_label.setText(_("The wallet can receive notifications if someone sends "
                    "you a payment to any addresses you will give out."))
                self._m3_icon_label.setPixmap(self._pass_pixmap)
            else:
                self._m3_label.setText(_("The wallet cannot receive notifications if someone sends "
                    "you a payment to any addresses you will give out (as you do not have a "
                    "blockchain server that will send them)."))
                self._m3_icon_label.setPixmap(self._fail_pixmap)
        else:
            self._m1_label.setText(_("The wallet cannot receive proof that transactions it has "
                "broadcast using MAPI servers have been mined."))
            self._m1_icon_label.setPixmap(self._fail_pixmap)
            self._m2_label.setText(_("The wallet cannot receive notifications that transactions "
                "it has received from others and broadcast using MAPI servers have been double "
                "spent."))
            self._m2_icon_label.setPixmap(self._fail_pixmap)
            self._m3_label.setText(_("The wallet cannot receive notifications if someone sends "
                "you a payment to any addresses you will give out."))
            self._m3_icon_label.setPixmap(self._fail_pixmap)

    def initializePage(self) -> None:
        # Qt6AutoPageSkip
        self._page_state = PageState.INITIALIZED

        wizard = cast(ServerSelectionWizard, self.wizard())
        self._update_layout(wizard)

    def cleanupPage(self) -> None:
        # Qt6AutoPageSkip
        self._page_state = PageState.CLEANED_UP

    def validatePage(self) -> bool:
        # Qt6AutoPageSkip
        return self._page_state == PageState.UPDATED

    def paintEvent(self, event: QPaintEvent) -> None:
        # Qt6AutoPageSkip
        if self._page_state == PageState.INITIALIZED:
            self._page_state = PageState.UPDATED
        super().paintEvent(event)

