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
from typing import TYPE_CHECKING
import weakref

from PyQt6.QtCore import pyqtSignal, QItemSelection, Qt
from PyQt6.QtGui import QContextMenuEvent, QKeyEvent, QPixmap
from PyQt6.QtWidgets import QAbstractItemView, QGroupBox, QHeaderView, QHBoxLayout, \
    QLabel, QSizePolicy, QTableWidget, QVBoxLayout, QWidget

from ...app_state import app_state
from ...i18n import _
from ...logs import logs
from ...types import ServerAccountKey
from ...wallet import Wallet
from ...util import ReleaseDocumentType

from . import server_selection_wizard
from .util import icon_path

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


logger = logs.get_logger("home-view")


class HealthTable(QTableWidget):
    key_activation_signal = pyqtSignal()
    refresh_signal = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()

        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        self.horizontalHeader().setStretchLastSection(True)
        self.setColumnCount(1)

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
        self.setHorizontalHeaderLabels([ "Health report" ])

        # Tab by default in QTableWidget, moves between list items. The arrow keys also perform
        # the same function, and we want tab to allow exiting the table instead.
        self.setTabKeyNavigation(False)

        self.selectionModel().selectionChanged.connect(self._on_item_selection_changed)

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

    def _on_item_selection_changed(self,  selected: QItemSelection, deselected: QItemSelection) \
            -> None:
        pass


class HomeView(QWidget):
    _offline_row: int | None = None
    _offline_icon_label: QLabel | None = None
    _offline_text_label: QLabel | None = None

    def __init__(self, main_window: ElectrumWindow, wallet: Wallet) -> None:
        super().__init__()

        self._main_window_proxy: ElectrumWindow = weakref.proxy(main_window)
        self._wallet_proxy = weakref.proxy(wallet)

        health_icon_path_1 = icon_path("icons8-high-priority-96-windows.png")
        self._health_pixmap_base = QPixmap(health_icon_path_1)

        self._health_pixmap_gray = QPixmap(self._health_pixmap_base.size())
        self._health_pixmap_gray.fill(Qt.GlobalColor.lightGray)
        self._health_pixmap_gray.setMask(
            self._health_pixmap_base.createMaskFromColor(Qt.GlobalColor.transparent))

        self._health_pixmap_red = QPixmap(self._health_pixmap_base.size())
        self._health_pixmap_red.fill(Qt.GlobalColor.red)
        self._health_pixmap_red.setMask(
            self._health_pixmap_base.createMaskFromColor(Qt.GlobalColor.transparent))

        self._health_pixmap_green = QPixmap(self._health_pixmap_base.size())
        self._health_pixmap_green.fill(Qt.GlobalColor.darkGreen)
        self._health_pixmap_green.setMask(
            self._health_pixmap_base.createMaskFromColor(Qt.GlobalColor.transparent))

        summary_layout = QHBoxLayout()
        summary_box = QGroupBox()
        summary_box.setTitle(_('Account summary'))
        summary_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        summary_box.setLayout(summary_layout)

        summary_label = QLabel(_("This might give an overview of all your account balances "
            "and the committed and available funds within them."))
        summary_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        summary_label.setWordWrap(True)
        summary_layout.addWidget(summary_label)

        self.health_table = HealthTable()
        size_policy = QSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.MinimumExpanding)
        self.health_table.setSizePolicy(size_policy)
        self.health_table.setContentsMargins(0, 0, 0, 0)
        self.health_table.doubleClicked.connect(self._on_health_key_activation)
        self.health_table.key_activation_signal.connect(self._on_health_key_activation)

        notification_layout = QHBoxLayout()
        notification_box = QGroupBox()
        notification_box.setTitle(_('Notifications'))
        notification_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        notification_box.setLayout(notification_layout)

        notification_label = QLabel(_("This will contain all the outstanding notifications "
            "received for any account in the wallet."))
        notification_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        notification_label.setWordWrap(True)
        notification_layout.addWidget(notification_label)

        row_layout = QVBoxLayout()
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(2)
        column_layout = QHBoxLayout()
        column_layout.setContentsMargins(0, 0, 0, 0)
        column1_layout = QVBoxLayout()
        column1_layout.setContentsMargins(0, 0, 0, 0)
        column2_layout = QVBoxLayout()
        column2_layout.setContentsMargins(0, 0, 0, 0)
        column_layout.addLayout(column1_layout)
        column_layout.addLayout(column2_layout)
        row_layout.addLayout(column_layout)

        column1_layout.addWidget(summary_box)
        column1_layout.addWidget(notification_box)
        column2_layout.addWidget(self.health_table)

        self.setLayout(row_layout)

        self._main_window_proxy.update_required_signal.connect(self._on_update_required)

    def update_health_report(self) -> None:
        self.health_table.clearContents()
        self._next_row_index = 0

        if self._wallet_proxy._network is None:
            pixmap, subtitle_text = self._get_state_for_offline_entry()
            self._offline_row, self._offline_icon_label, self._offline_text_label = \
                self._add_health_report_entry(pixmap, _("Offline mode"), subtitle_text)

        pixmap, subtitle_text = self._get_state_for_backup_entry()
        self._backup_row, self._backup_icon_label, self._backup_text_label = \
            self._add_health_report_entry(pixmap, _("Wallet backup"), subtitle_text)

        pixmap, subtitle_text = self._get_state_for_server_entry()
        self._server_row, self._server_icon_label, self._server_text_label = \
            self._add_health_report_entry(pixmap, _("Manage your server usage"), subtitle_text)

        pixmap, subtitle_text = self._get_state_for_update_entry()
        self._update_row, self._update_icon_label, self._update_text_label = \
            self._add_health_report_entry(pixmap, _("Update ElectrumSV"), subtitle_text)

    def _add_health_report_entry(self, pixmap: QPixmap, title_text: str, subtitle_text: str) \
            -> tuple[int, QLabel, QLabel]:
        current_row = self._next_row_index
        self._next_row_index += 1

        self.health_table.insertRow(current_row)

        update_widget = QWidget()
        update_row_layout = QHBoxLayout()
        update_row_layout.setSpacing(0)

        update_icon_label = QLabel()
        update_icon_label.setPixmap(pixmap.scaledToWidth(30,
            Qt.TransformationMode.SmoothTransformation))
        update_icon_label.setAlignment(Qt.AlignmentFlag.AlignHCenter|Qt.AlignmentFlag.AlignVCenter)
        contentsMargins = update_icon_label.contentsMargins()
        contentsMargins.setRight(10)
        update_icon_label.setContentsMargins(contentsMargins)

        update_text_label = QLabel(self._format_report_entry_text(title_text, subtitle_text))
        update_text_label.setTextFormat(Qt.TextFormat.RichText)

        update_row_layout.addWidget(update_icon_label)
        update_row_layout.addWidget(update_text_label)
        update_row_layout.addStretch(1)

        update_widget.setLayout(update_row_layout)
        self.health_table.setCellWidget(current_row, 0, update_widget)
        return current_row, update_icon_label, update_text_label

    def _format_report_entry_text(self, title_text: str, subtitle_text: str) -> str:
        return title_text +"<br/><font color='grey'>"+ subtitle_text +"</font>"

    def _on_health_key_activation(self) -> None:
        selected_indexes = self.health_table.selectedIndexes()
        if len(selected_indexes):
            selected_row = selected_indexes[0].row()
            if selected_row == self._backup_row:
                self._main_window_proxy.show_warning("Not yet implemented")
            elif selected_row == self._server_row:
                from importlib import reload
                reload(server_selection_wizard)
                wizard = server_selection_wizard.ServerSelectionWizard(self,
                    self._wallet_proxy.reference())
                wizard.setModal(True)
                wizard.raise_()
                wizard.show()
            elif selected_row == self._update_row:
                self._main_window_proxy.show_update_check()
            else:
                logger.error("_on_health_key_activation, unknown row %d", selected_row)

    def _on_update_required(self) -> None:
        pixmap, subtitle_text = self._get_state_for_update_entry()
        self._set_update_entry_state(pixmap, subtitle_text)

    def _set_update_entry_state(self, pixmap: QPixmap, subtitle_text: str) -> None:
        self._update_icon_label.setPixmap(pixmap.scaledToWidth(30,
            Qt.TransformationMode.SmoothTransformation))
        self._update_text_label.setText(self._format_report_entry_text(_("Update ElectrumSV"),
            subtitle_text))

    def _get_state_for_offline_entry(self) -> tuple[QPixmap, str]:
        return self._health_pixmap_green, _("ElectrumSV is in offline mode")

    def _get_state_for_backup_entry(self) -> tuple[QPixmap, str]:
        return self._health_pixmap_red, _("Your wallet contents have changed")

    def _get_state_for_server_entry(self) -> tuple[QPixmap, str]:
        account_row = self._wallet_proxy._petty_cash_account.get_row()
        existing_blockchain_server_key: ServerAccountKey | None = None
        existing_messagebox_server_key: ServerAccountKey | None = None
        for server in self._wallet_proxy._servers.values():
            if server.server_id == account_row.peer_channel_server_id:
                existing_messagebox_server_key = server.key
            if server.server_id == account_row.blockchain_server_id:
                existing_blockchain_server_key = server.key
        if existing_blockchain_server_key is None or existing_messagebox_server_key is None:
            return self._health_pixmap_red, _("Wallet functionality restricted")
        return self._health_pixmap_gray, _("Everything looks okay")

    def _get_state_for_update_entry(self) -> tuple[QPixmap, str]:
        last_update_check_time: float | None = None
        last_update_check_time_text = app_state.config.get('last_update_check_time')
        if last_update_check_time_text is not None:
            last_update_check_time = datetime.fromisoformat(last_update_check_time_text).timestamp()
        if last_update_check_time and app_state.app_qt.startup_time < last_update_check_time:
            check_result: ReleaseDocumentType | None = app_state.config.get('last_update_check')
            assert check_result is not None and "stable" in check_result
            version_text = check_result["stable"]["version"]

            pixmap = self._health_pixmap_red
            subtitle_text = _("Please update to version {version}").format(version=version_text)
        else:
            pixmap = self._health_pixmap_gray
            subtitle_text = _("No new update was detected")
        return pixmap, subtitle_text
