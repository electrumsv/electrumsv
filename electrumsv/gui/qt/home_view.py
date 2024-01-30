from __future__ import annotations
import dataclasses
from datetime import datetime
from typing import TYPE_CHECKING
import weakref

from PyQt6.QtCore import pyqtSignal, QItemSelection, QSize, Qt
from PyQt6.QtGui import QAction, QContextMenuEvent, QIcon, QKeyEvent, QPixmap
from PyQt6.QtWidgets import QAbstractItemView, QHeaderView, QHBoxLayout, QTableWidget, QToolBar, \
    QVBoxLayout, QWidget

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

        hh = self.horizontalHeader()
        hh.setStretchLastSection(True)
        hh.setDefaultSectionSize(hh.minimumSectionSize())
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
        self.setHorizontalHeaderLabels([ "Status" ])

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

    def sizeHint(self) -> QSize:
        # RT: StackOverflow gold. Why does QTableWidget default to 256 wide and how to fix it.
        # https://stackoverflow.com/a/8563372
        size = super().sizeHint()
        mw = 0
        for y in range(self.rowCount()):
            widget = self.cellWidget(y, 0)
            width = widget.sizeHint().width() + self.frameWidth() + 2
            mw = width if width > mw else mw
        size.setWidth(mw)
        return size


@dataclasses.dataclass
class IconStates:
    gray_pixmap: QPixmap
    red_pixmap: QPixmap
    green_pixmap: QPixmap


class HomeView(QWidget):
    def __init__(self, main_window: ElectrumWindow, wallet: Wallet) -> None:
        super().__init__()

        self._main_window_proxy: ElectrumWindow = weakref.proxy(main_window)
        self._wallet_proxy = weakref.proxy(wallet)

        icon_filenames = {
            "backup":  "icons8-backup-96-windows.png",
            "update":  "icons8-update-96-windows.png",
            "servers": "icons8-reception-96-windows.png",
            "offline": "icons8-offline-96-windows.png",
        }

        self._pixmaps: dict[str, IconStates] = {}
        for key, icon_filename in icon_filenames.items():
            base_pixmap = QPixmap(icon_path(icon_filename))

            gray_pixmap = QPixmap(base_pixmap.size())
            gray_pixmap.fill(Qt.GlobalColor.lightGray)
            gray_pixmap.setMask(base_pixmap.createMaskFromColor(Qt.GlobalColor.transparent))

            red_pixmap = QPixmap(base_pixmap.size())
            red_pixmap.fill(Qt.GlobalColor.red)
            red_pixmap.setMask(base_pixmap.createMaskFromColor(Qt.GlobalColor.transparent))

            green_pixmap = QPixmap(base_pixmap.size())
            green_pixmap.fill(Qt.GlobalColor.darkGreen)
            green_pixmap.setMask(base_pixmap.createMaskFromColor(Qt.GlobalColor.transparent))

            self._pixmaps[key] = IconStates(gray_pixmap, red_pixmap, green_pixmap)

        toolbar = self._health_toolbar = QToolBar()
        icon_size = int(app_state.app_qt.dpi / 5.8)
        toolbar.setOrientation(Qt.Orientation.Vertical)
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)
        toolbar.setIconSize(QSize(icon_size, icon_size))

        from .history_list import HistoryView
        self._history_view = HistoryView(self, self._main_window_proxy.reference(),
            for_account=False)
        # The "per account" history view is primed when an account was selected. We need to prime
        # this "all payments in wallet" history view when it is created
        self._history_view.update_tx_list(refresh=False)

        row_layout = QVBoxLayout()
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(2)
        column_layout = QHBoxLayout()
        column_layout.setContentsMargins(0, 0, 0, 0)
        column_layout.addWidget(self._history_view, 1)
        column_layout.addWidget(self._health_toolbar) # self._health_table)
        row_layout.addLayout(column_layout)
        self.setLayout(row_layout)

        self._main_window_proxy.update_required_signal.connect(self._on_update_required)

    def update_health_report(self) -> None:
        toolbar = self._health_toolbar
        toolbar.clear()

        if self._wallet_proxy._network is None:
            action = QAction(QIcon(self._pixmaps["offline"].green_pixmap), _("Offline mode"), self)
            toolbar.addAction(action)

        icon = QIcon(self._pixmaps["backup"].red_pixmap)
        action = QAction(icon, _("Backup"), self)
        toolbar.addAction(action)
        def callback() -> None:
            self._main_window_proxy.show_warning("Not yet implemented")
        action.triggered.connect(callback)

        account_row = self._wallet_proxy._petty_cash_account.get_row()
        existing_blockchain_server_key: ServerAccountKey | None = None
        existing_messagebox_server_key: ServerAccountKey | None = None
        for server in self._wallet_proxy._servers.values():
            if server.server_id == account_row.peer_channel_server_id:
                existing_messagebox_server_key = server.key
            if server.server_id == account_row.blockchain_server_id:
                existing_blockchain_server_key = server.key
        if existing_blockchain_server_key is None or existing_messagebox_server_key is None:
            icon = QIcon(self._pixmaps["servers"].red_pixmap)
        else:
            icon = QIcon(self._pixmaps["servers"].gray_pixmap)
        action = QAction(icon, _("Servers"), self)
        toolbar.addAction(action)
        def callback1() -> None:
            wizard = server_selection_wizard.ServerSelectionWizard(self,
                self._wallet_proxy.reference())
            wizard.setModal(True)
            wizard.raise_()
            wizard.show()
        action.triggered.connect(callback1)

        icon = QIcon(self._get_state_for_update_entry())
        action = self._servers_action = QAction(icon, _("Update"), self)
        toolbar.addAction(action)
        def callback2() -> None:
            self._main_window_proxy.show_update_check()
        action.triggered.connect(callback2)

    def update_history_list(self) -> None:
        self._history_view.update_tx_list()

    def update_history_headers(self) -> None:
        self._history_view.update_tx_headers()

    def _format_report_entry_text(self, title_text: str, subtitle_text: str) -> str:
        return title_text +"<br/><font color='grey'>"+ subtitle_text +"</font>"

    def _on_update_required(self) -> None:
        icon = QIcon(self._get_state_for_update_entry())
        self._servers_action.setIcon(icon)

    def _get_state_for_update_entry(self) -> QPixmap:
        last_update_check_time: float | None = None
        last_update_check_time_text = app_state.config.get('last_update_check_time')
        if last_update_check_time_text is not None:
            last_update_check_time = datetime.fromisoformat(last_update_check_time_text).timestamp()
        if last_update_check_time and app_state.app_qt.startup_time < last_update_check_time:
            check_result: ReleaseDocumentType | None = app_state.config.get('last_update_check')
            assert check_result is not None and "stable" in check_result
            version_text = check_result["stable"]["version"]

            pixmap = self._pixmaps["update"].red_pixmap
            # subtitle_text = _("Please update to version {version}").format(version=version_text)
        else:
            pixmap = self._pixmaps["update"].gray_pixmap
            # subtitle_text = _("No new update was detected")
        return pixmap
