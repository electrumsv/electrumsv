#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@gitorious
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

import concurrent.futures
import dataclasses
import datetime
import enum
from functools import partial
from typing import Any, Callable, cast, Dict, List, NamedTuple, Optional, \
    TYPE_CHECKING, Tuple

from PyQt5.QtCore import pyqtSignal, QAbstractItemModel, QModelIndex, QObject, Qt, \
    QTimer
from PyQt5.QtGui import QBrush, QCloseEvent, QColor, QContextMenuEvent, QIcon, QKeyEvent, \
    QPixmap, QValidator
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, \
    QFrame, QGridLayout, QHBoxLayout, QHeaderView, QItemDelegate, QLabel, QLineEdit, QMenu, \
    QMessageBox, QPushButton, QStyleOptionViewItem, \
    QSizePolicy, QTableWidget, QTableWidgetItem, QTabWidget, QTreeWidget, QTreeWidgetItem, \
    QVBoxLayout, QWidget

from ...app_state import app_state
from ...constants import API_SERVER_TYPES, NetworkServerFlag, NetworkServerType, TOKEN_PASSWORD
from ...crypto import pw_decode, pw_encode
from ...i18n import _
from ...logs import logs
from ...wallet import Wallet
from ...network import Network
from ...network_support.api_server import APIServerDefinition, CapabilitySupport, NewServer, \
    SERVER_CAPABILITIES
from ...types import ServerAccountKey
from ...util.network import DEFAULT_SCHEMES, UrlValidationError, validate_url
from ...wallet_database.types import NetworkServerRow, NetworkServerAccountRow

from .table_widgets import TableTopButtonLayout
from .util import Buttons, CloseButton, ExpandableSection, FormSectionWidget,  \
    HelpDialogButton, icon_path, MessageBox, read_QIcon, WindowModalDialog


if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class Roles:
    ITEM_DATA = Qt.ItemDataRole.UserRole
    TIMESTAMP_SORTKEY = Qt.ItemDataRole.UserRole + 1
    CONNECTEDNESS_SORTKEY = Qt.ItemDataRole.UserRole + 2

logger = logs.get_logger("network-ui")

# These are display ordered for the combo box.
SERVER_TYPE_ENTRIES = [
    NetworkServerType.GENERAL,
    NetworkServerType.MERCHANT_API,
]

SERVER_TYPE_LABELS = {
    NetworkServerType.GENERAL: _("General"),
    NetworkServerType.MERCHANT_API: _("MAPI"),
}


class ServerStatus(enum.IntEnum):
    CONNECTED = 0
    DISCONNECTED = 1


SERVER_STATUS = {
    ServerStatus.CONNECTED: _('Connected'),
    ServerStatus.DISCONNECTED: _('Disconnected'),
}


class ServerListEntry(NamedTuple):
    server_type: NetworkServerType
    url: str
    last_try: float = 0.0
    last_good: float = 0.0
    enabled_for_all_wallets: bool = True
    can_configure_wallet_access: bool = False
    api_key_supported: bool = False
    api_key_required: bool = False
    data_api: Optional[NewServer] = None


# The location of the help document.
HELP_FOLDER_NAME = "misc"
HELP_SERVER_EDIT_FILE_NAME = "network-server-dialog"

API_KEY_SET_TEXT = "<"+ _("API key hidden") +">"
API_KEY_UNSUPPORTED_TEXT = "<"+ _("not used for this server type") +">"
API_KEY_NOT_SET_TEXT = "<"+ _("doubleclick here to set") +">"

PASSWORD_REQUEST_TEXT = _("You have associated a new API key with the wallet '{}'. In order to "
    "encrypt the API key for storage in this wallet, you will need to provide it's password.")


# TODO(1.4.0) - modify to indicate current chain tips (a representation of the HeaderSV chain tips)
#  and which chain this wallet is on which at least in the near term will be
#  coupled to the indexer which always gives a materialized view of the longest chain.
# class NodesListColumn(enum.IntEnum):
#     SERVER = 0
#     HEIGHT = 1
#
#
# class NodesListWidget(QTreeWidget):
#
#     def __init__(self, parent: 'BlockchainTab', network: Network) -> None:
#         super().__init__()
#         self._network = network
#         self._parent_tab = parent
#         self.setHeaderLabels([ _('Connected server'), _('Height') ])
#         self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
#         self.customContextMenuRequested.connect(self.create_menu)
#
#         self._connected_pixmap = QPixmap(icon_path("icons8-data-transfer-80-blue.png")
#             ).scaledToWidth(16, Qt.TransformationMode.SmoothTransformation)
#         self._warning_pixmap = QPixmap(icon_path("icons8-error-48-ui.png")
#             ).scaledToWidth(16, Qt.TransformationMode.SmoothTransformation)
#         self._connected_icon = QIcon(self._connected_pixmap)
#         self._lock_pixmap = QPixmap(icon_path("icons8-lock-windows.svg")
#             ).scaledToWidth(16, Qt.TransformationMode.SmoothTransformation)
#
#     def create_menu(self, position: QPoint) -> None:
#         item = self.currentItem()
#         if not item:
#             return
#         server = item.data(NodesListColumn.SERVER, Qt.ItemDataRole.UserRole)
#         if not server:
#             return
#
#         def use_as_server(auto_connect: bool) -> None:
#             try:
#                 self._parent_tab._parent.follow_server(server, auto_connect)
#             except Exception as e:
#                 MessageBox.show_error(str(e))
#
#         menu = QMenu()
#         action = menu.addAction(_("Use as main server"), partial(use_as_server, True))
#         action.setEnabled(server != self._network.main_server)
#         if self._network.auto_connect() or server != self._network.main_server:
#             action = menu.addAction(_("Lock as main server"), partial(use_as_server, False))
#             action.setEnabled(app_state.config.is_modifiable('auto_connect'))
#         else:
#             action = menu.addAction(_("Unlock as main server"), partial(use_as_server, True))
#             action.setEnabled(app_state.config.is_modifiable('auto_connect') and \
#                 server == self._network.main_server)
#         menu.exec_(self.viewport().mapToGlobal(position))
#
#     def keyPressEvent(self, event: QKeyEvent) -> None:
#         if event.key() in [ Qt.Key.Key_F2, Qt.Key.Key_Return ]:
#             self.on_activated(self.currentItem(), self.currentColumn())
#         else:
#             QTreeWidget.keyPressEvent(self, event)
#
#     def on_activated(self, item: QTreeWidgetItem, _column: int) -> None:
#         # on 'enter' we show the menu
#         pt = self.visualItemRect(item).bottomLeft()
#         pt.setX(50)
#         self.customContextMenuRequested.emit(pt)
#
#     def chain_name(self, chain: Chain, our_chain: Chain) -> str:
#         if chain is our_chain:
#             return 'our_chain'
#
#         _chain, common_height = our_chain.common_chain_and_height(chain)
#         fork_height = common_height + 1
#         assert app_state.headers is not None
#         header = app_state.headers.header_at_height(chain, fork_height)
#         prefix = hash_to_hex_str(header.hash).lstrip('00')[0:10]
#         return f'{prefix}@{fork_height}'
#
#     def update(self) -> None: # type: ignore[override]
#         assert self._network.main_server is not None
#
#         self.clear()
#
#         chains = self._network.sessions_by_chain()
#         chain_items = list(chains.items())
#         host_counts: Dict[str, int] = {}
#         for chain, sessions in chain_items:
#             # If someone is connected to two nodes on the same server, indicate the difference.
#             for i, session in enumerate(sessions):
#                 host_counts[session.server.host] = host_counts.get(session.server.host, 0) + 1
#
#         tree_item: Union[NodesListWidget, QTreeWidgetItem]
#         our_chain = self._network.chain()
#         for chain, sessions in chain_items:
#             if len(chains) > 1:
#                 assert our_chain is not None
#                 name = self.chain_name(chain, our_chain)
#                 tree_item = QTreeWidgetItem([name, '%d' % chain.height])
#                 tree_item.setData(NodesListColumn.SERVER, Qt.ItemDataRole.UserRole, None)
#             else:
#                 tree_item = self
#             for session in sessions:
#                 assert session.tip is not None
#                 extra_name = ""
#                 if host_counts[session.server.host] > 1:
#                     extra_name = f" (port: {session.server.port})"
#                 extra_name += ' (main server)' if session.server is self._network.main_server \
#                     else ''
#                 item = QTreeWidgetItem([session.server.host + extra_name,
#                     str(session.tip.height)])
#                 item.setIcon(NodesListColumn.SERVER, self._connected_icon)
#                 if session.server.protocol == "t":
#                     item.setToolTip(NodesListColumn.SERVER, _("Unencrypted"))
#                 else:
#                     item.setToolTip(NodesListColumn.SERVER, _("Encrypted / SSL"))
#                 item.setData(NodesListColumn.SERVER, Qt.ItemDataRole.UserRole, session.server)
#                 if isinstance(tree_item, NodesListWidget):
#                     tree_item.addTopLevelItem(item)
#                 else:
#                     tree_item.addChild(item)
#             if len(chains) > 1:
#                 assert isinstance(tree_item, QTreeWidgetItem)
#                 self.addTopLevelItem(tree_item)
#                 tree_item.setExpanded(True)
#
#             height_str = "%d "%(self._network.get_local_height()) + _('blocks')
#             self._parent_tab.height_label.setText(height_str)
#             n = len(self._network.sessions)
#             if n == 0:
#                 status = _("Not connected")
#             elif n == 1:
#                 status = _("Connected to {:d} server.").format(n)
#             else:
#                 status = _("Connected to {:d} servers.").format(n)
#             self._parent_tab.status_label.setText(status)
#
#             chains2 = self._network.sessions_by_chain().keys()
#             if len(chains2) > 1:
#                 our_chain = self._network.chain()
#                 assert our_chain is not None
#                 heights = set()
#                 for chain in chains2:
#                     if chain != our_chain:
#                         _chain, common_height = our_chain.common_chain_and_height(chain)
#                         heights.add(common_height + 1)
#                 msg = _('Chain split detected at height(s) {}\n').format(
#                     ','.join(f'{height:,d}' for height in sorted(heights)))
#             else:
#                 msg = ''
#             self._parent_tab.split_label.setText(msg)
#             self._parent_tab.server_label.setText(self._network.main_server.host)
#
#             # Ordered pixmaps, show only as many as applicable. Probably a better way to do this.
#             pixmaps: List[Tuple[Optional[QPixmap], str]] = []
#             if not self._network.auto_connect():
#                 pixmaps.append((self._lock_pixmap,
#                     _("This server is locked into place as the permanent main server.")))
#             if self._network.main_server.state.last_good <
#                   self._network.main_server.state.last_try:
#                 pixmaps.append((self._warning_pixmap,
#                     _("This server is not known to be up to date.")))
#
#             while len(pixmaps) < 2:
#                 pixmaps.append((None, ''))
#
#             if pixmaps[0][0] is None:
#                 self._parent_tab.server_label_icon1.clear()
#             else:
#                 self._parent_tab.server_label_icon1.setPixmap(pixmaps[0][0])
#                 self._parent_tab.server_label_icon1.setToolTip(pixmaps[0][1])
#             if pixmaps[1][0] is None:
#                 self._parent_tab.server_label_icon2.clear()
#             else:
#                 self._parent_tab.server_label_icon2.setPixmap(pixmaps[1][0])
#                 self._parent_tab.server_label_icon2.setToolTip(pixmaps[1][1])
#
#         h = self.header()
#         h.setStretchLastSection(False)
#         h.setSectionResizeMode(NodesListColumn.SERVER, QHeaderView.ResizeMode.Stretch)
#         h.setSectionResizeMode(NodesListColumn.HEIGHT, QHeaderView.ResizeMode.ResizeToContents)
#

# TODO(1.4.0) - modify to indicate current chain tips (a representation of the HeaderSV chain tips)
#  and which chain this wallet is on which at least in the near term will be
#  coupled to the indexer which always gives a materialized view of the longest chain.
# class BlockchainTab(QWidget):
#
#     def __init__(self, parent: "NetworkTabsLayout", network: Network) -> None:
#         super().__init__()
#         self._parent = parent
#         self._network = network
#
#         blockchain_layout = QVBoxLayout(self)
#
#         form = FormSectionWidget()
#         self.status_label = QLabel(_("No connections yet."))
#         form.add_row(_('Status'), self.status_label)
#         self.server_label = QLabel()
#         self.server_label_icon1 = QLabel()
#         self.server_label_icon2 = QLabel()
#         server_label_layout = QHBoxLayout()
#         server_label_layout.addWidget(self.server_label)
#         server_label_layout.addSpacing(4)
#         server_label_layout.addWidget(self.server_label_icon1)
#         server_label_layout.addSpacing(4)
#         server_label_layout.addWidget(self.server_label_icon2)
#         server_label_layout.addStretch(1)
#         form.add_row(_('Main server'), server_label_layout)
#         self.height_label = QLabel('')
#         form.add_row(_('Blockchain'), self.height_label)
#
#         blockchain_layout.addWidget(form)
#
#         self.split_label = QLabel('')
#         form.add_row(QLabel(""), self.split_label)
#
#         self.nodes_list_widget = NodesListWidget(self, self._network)
#         blockchain_layout.addWidget(self.nodes_list_widget)
#         blockchain_layout.addStretch(1)
#         self.nodes_list_widget.update()


@dataclasses.dataclass
class InitialServerState:
    enabled: bool = False
    encrypted_api_key: Optional[str] = None
    decrypted_api_key: Optional[str] = None

    @classmethod
    def create_from(cls, other: "InitialServerState") -> "InitialServerState":
        return cls(other.enabled, other.encrypted_api_key, other.decrypted_api_key)


@dataclasses.dataclass
class EditServerState(InitialServerState):
    initial_state: Optional["InitialServerState"] = None


@dataclasses.dataclass
class WalletSaveState:
    wallet: Wallet
    added_servers: List[NetworkServerRow] = dataclasses.field(default_factory=list)
    added_server_accounts: List[NetworkServerAccountRow] = dataclasses.field(default_factory=list)
    updated_servers: List[NetworkServerRow] = dataclasses.field(default_factory=list)
    updated_server_accounts: List[NetworkServerAccountRow] = dataclasses.field(default_factory=list)
    deleted_server_keys: List[ServerAccountKey] = dataclasses.field(default_factory=list)
    deleted_server_account_keys: List[ServerAccountKey] = dataclasses.field(default_factory=list)
    updated_api_keys: Dict[ServerAccountKey, Tuple[Optional[str], Optional[Tuple[str, str]]]] = \
        dataclasses.field(default_factory=dict)

    def is_saveable(self) -> bool:
        return (len(self.added_servers) or len(self.added_server_accounts) or \
            len(self.updated_servers) or len(self.updated_server_accounts) or \
            len(self.deleted_server_keys) or len(self.deleted_server_account_keys)) > 0


class EditServerDialog(WindowModalDialog):
    """Two modes: edit_mode=True and edit_mode=False"""
    validation_change = pyqtSignal(bool)

    def __init__(self, parent: QWidget, network: Network, title: str, edit_mode: bool=False,
            entry: Optional[ServerListEntry]=None) -> None:
        super().__init__(parent, title=title)

        self.setWindowTitle(title)
        self.setMinimumWidth(500)

        self._network = network
        self._is_edit_mode = edit_mode

        self._server_url: Optional[str] = None
        if self._is_edit_mode:
            assert entry is not None
            self._server_url = entry.url
        else:
            entry = ServerListEntry(NetworkServerType.MERCHANT_API, "",
                can_configure_wallet_access=True, api_key_supported=True)

        self._entry = entry

        # Covers the "any account in any loaded wallet" row.
        # We enable this by default for all new added servers. The edit will overwrite this.
        self._edit_state = EditServerState(True)
        if entry is not None:
            self._edit_state.enabled = entry.enabled_for_all_wallets
            if entry.data_api is not None and entry.data_api.config is not None and \
                    entry.data_api.config.get("api_key"):
                encrypted_api_key = entry.data_api.config["api_key"]
                self._edit_state.encrypted_api_key = encrypted_api_key
                self._edit_state.decrypted_api_key = pw_decode(encrypted_api_key, TOKEN_PASSWORD)
        # This is used to track the initial application state, which comes from the config.
        self._edit_state.initial_state = InitialServerState.create_from(self._edit_state)

        # Covers the "any account" row with `account_id` of `-1`.
        # Covers all the accounts in the wallet under their `account_id`.
        self._wallet_state: Dict[str, Dict[int, EditServerState]] = {}
        # These are used to track initial wallet state, but it is unknown until a wallet is loaded.
        self._server_row_by_wallet_path: Dict[str, NetworkServerRow] = {}
        self._account_rows_by_wallet_path: Dict[str, List[NetworkServerAccountRow]] = {}

        self._vbox = QVBoxLayout(self)

        # NOTE(server-edit-limitations) We do not allow changing either server type or url for
        #   editing, because there is no support for updating these in the database.

        self._server_type_combobox = QComboBox()
        for server_type in SERVER_TYPE_ENTRIES:
            self._server_type_combobox.addItem(SERVER_TYPE_LABELS[server_type])
        self._server_type_combobox.setCurrentIndex(SERVER_TYPE_ENTRIES.index(entry.server_type))
        self._server_type_combobox.currentIndexChanged.connect(
            self._event_changed_combobox_server_type)
        if self._is_edit_mode:
            # NOTE(server-edit-limitations)
            self._server_type_combobox.setDisabled(True)
            self._server_type_combobox.setToolTip(
                _("Changing the server type is not currently supported."))

        def apply_line_edit_validation_style(edit: QLineEdit, default_brush: QBrush,
                validation_callback: Callable[[bool], None], _new_text: str) -> None:
            # NOTE(fragile-Qt-palette-changes) The initial validation failed colour change will
            #   just not apply. It keeps the original white background, not the yellow we set.
            #   Use the old delayed call trick to apply the colour change, there's only so much
            #   time we can spend on this.
            QTimer.singleShot(0, partial(_apply_line_edit_validation_style, edit, default_brush,
                validation_callback, _new_text))

        def _apply_line_edit_validation_style(edit: QLineEdit, default_brush: QBrush,
                validation_callback: Callable[[bool], None], _new_text: str) -> None:
            error_message = self._check_server_url_invalid()

            # Change the background to indicate whether the edit field contents are valid or not.
            palette = edit.palette()
            if error_message is None:
                palette.setBrush(palette.Base, default_brush)
            else:
                palette.setBrush(palette.Base, QColor(Qt.GlobalColor.yellow).lighter(167))
            edit.setPalette(palette)

            if error_message is not None:
                edit.setToolTip(error_message)

            validation_callback(error_message is None)

        self._server_url_edit = QLineEdit()
        self._server_url_edit.setMinimumWidth(300)
        self._server_url_edit.setText(entry.url)
        default_edit_palette = self._server_url_edit.palette()
        default_base_brush = default_edit_palette.brush(default_edit_palette.Base)
        server_type_schemes: Optional[set[str]] = None
        self._url_validator = URLValidator(schemes=server_type_schemes)
        self._server_url_edit.setValidator(self._url_validator)
        self._server_url_edit.textChanged.connect(
            partial(apply_line_edit_validation_style, self._server_url_edit, default_base_brush,
                self.validation_change.emit))
        if self._is_edit_mode:
            # NOTE(server-edit-limitations)
            self._server_url_edit.setDisabled(True)
            self._server_url_edit.setToolTip(
                _("Changing the server URL is not currently supported."))

        editable_form = FormSectionWidget()
        editable_form.add_row(_("Type"), self._server_type_combobox)
        editable_form.add_row(_("URL"), self._server_url_edit)

        self._vbox.addWidget(editable_form)

        ## The wallet and account access expandable section.
        class AccessTreeItemDelegate(QItemDelegate):
            def __init__(self, dialog: "EditServerDialog", editable_columns: List[int]) -> None:
                super().__init__(None)
                self._dialog = dialog
                self._editable_columns = editable_columns

            def createEditor(self, parent: QWidget, # type: ignore[override]
                    style_option: QStyleOptionViewItem, index: QModelIndex) -> Optional[QWidget]:
                """
                Overriden method that creates the widget used for editing.

                We only want certain columns to be editable. Note that to get here, the row's
                item had to have the `ItemIsEditable` flag already set. This creates the base
                editor widget, which should not have any data yet.
                """
                if index.column() in self._editable_columns:
                    # This just creates the editor widget, it does not have the data yet.
                    return super().createEditor(parent, style_option, index)
                return None

            def setEditorData(self, editor: QWidget, index: QModelIndex) -> None:
                """
                Overriden method that ensures our hidden actual editor widget text replaces the
                placeholder we show for non-edit display.
                """
                edit_state = self._dialog._get_edit_state_for_index(index)[-1]
                text = edit_state.decrypted_api_key \
                    if edit_state.decrypted_api_key is not None else ""
                line_edit = cast(QLineEdit, editor)
                line_edit.setText(text)

            def setModelData(self, editor: QWidget, model: QAbstractItemModel,
                    index: QModelIndex) -> None:
                """
                Overriden method that takes the editor widget text from the user is stored
                in the edit state, and replaced for non-edit display with the appropriate
                placeholder.
                """
                edit_state = self._dialog._get_edit_state_for_index(index)[-1]
                # We clear this because acquiring it requires the user enter their password and
                # we only do that at point of committing an update.
                edit_state.encrypted_api_key = None

                text = cast(QLineEdit, editor.text()).strip()
                if text:
                    if not edit_state.enabled:
                        edit_state.enabled = True

                        item = self._dialog._get_item_for_index(index)
                        item.setCheckState(0, Qt.CheckState.Checked)

                    edit_state.decrypted_api_key = text
                    model.setData(index, API_KEY_SET_TEXT, Qt.ItemDataRole.DisplayRole)
                else:
                    edit_state.decrypted_api_key = None
                    model.setData(index, API_KEY_NOT_SET_TEXT, Qt.ItemDataRole.DisplayRole)

        self._access_tree = QTreeWidget()
        self._access_tree.setItemDelegate(AccessTreeItemDelegate(self, [ 1 ]))
        self._access_tree.setHeaderLabels([ _('Scope'), _("API key") ])
        self._access_tree.itemChanged.connect(self._event_item_changed_access_tree)

        access_section = ExpandableSection(_("Wallet and account access"), self._access_tree)
        access_section.contract()
        self._vbox.addWidget(access_section)

        ### The server services expandable section.
        self._services_form = FormSectionWidget()

        services_section = ExpandableSection(_("Services"), self._services_form)
        services_section.contract()
        self._vbox.addWidget(services_section)

        ### The usage details expandable section.
        if edit_mode:
            self._usage_form = FormSectionWidget()

            if entry.last_try:
                attempt_label = QLabel(
                    datetime.datetime.fromtimestamp(int(entry.last_try)).isoformat(' '))
            else:
                attempt_label = QLabel("-")

            if entry.last_good:
                connected_label = QLabel(
                    datetime.datetime.fromtimestamp(int(entry.last_good)).isoformat(' '))
            else:
                connected_label = QLabel("-")

            self._usage_form.add_row(_("Last attempted"), attempt_label)
            self._usage_form.add_row(_("Last connected"), connected_label)

            usage_section = ExpandableSection(_("Usage data"), self._usage_form)
            usage_section.contract()
            self._vbox.addWidget(usage_section)

        # NOTE(copy-paste) Generic separation line code used elsewhere as well.
        button_box_line = QFrame()
        button_box_line.setStyleSheet("QFrame { border: 1px solid #E3E2E2; }")
        button_box_line.setFrameShape(QFrame.HLine)
        button_box_line.setFixedHeight(1)

        help_button = QPushButton(_("Help"))
        self._save_button = QPushButton(_("Update") if edit_mode else _("Add"))
        cancel_button = QPushButton(_("Cancel"))

        self._dialog_button_layout = QHBoxLayout()
        self._dialog_button_layout.addWidget(help_button)
        self._dialog_button_layout.addStretch(1)
        self._dialog_button_layout.addWidget(self._save_button)
        self._dialog_button_layout.addWidget(cancel_button)

        help_button.clicked.connect(self._event_clicked_button_help)
        self._save_button.clicked.connect(self._event_clicked_button_save)
        cancel_button.clicked.connect(self.reject)

        self._vbox.addWidget(button_box_line)
        self._vbox.addLayout(self._dialog_button_layout)
        self._vbox.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        self.setLayout(self._vbox)

        self.validation_change.connect(self._event_validation_change)

        self._update_state()

        # We subscribe to these events to keep the access list updated.
        app_state.app_qt.window_opened_signal.connect(self._on_wallet_opened)
        app_state.app_qt.window_closed_signal.connect(self._on_wallet_closed)

    def closeEvent(self, event: QCloseEvent) -> None:
        """
        Dialog close event. Do any necessary clean up/unregistration here.
        """
        app_state.app_qt.window_opened_signal.disconnect(self._on_wallet_opened)
        app_state.app_qt.window_closed_signal.disconnect(self._on_wallet_closed)

        event.accept()

    def get_access_tree(self) -> QTreeWidget:
        return self._access_tree

    def get_server_entry(self) -> Optional[ServerListEntry]:
        return self._entry

    def get_application_state(self) -> EditServerState:
        return self._edit_state

    def get_wallet_state(self, wallet_path: str) -> Dict[int, EditServerState]:
        return self._wallet_state[wallet_path]

    def _get_item_for_index(self, index: QModelIndex) -> QTreeWidgetItem:
        parent_row = index.parent().row()
        if parent_row == -1:
            item = self._access_tree.topLevelItem(index.row())
        else:
            parent_item = self._access_tree.topLevelItem(parent_row)
            item = parent_item.child(index.row())
        return item

    def _get_edit_state_for_index(self, index: QModelIndex) -> Tuple[str, int, EditServerState]:
        item = self._get_item_for_index(index)
        return self._get_edit_state_for_item(item)

    def _get_edit_state_for_item(self, item: QTreeWidgetItem) -> Tuple[str, int, EditServerState]:
        item_index = self._access_tree.indexOfTopLevelItem(item)
        if item_index == 0:
            return ("", -1, self.get_application_state())

        if item_index > -1:
            wallet_path = cast(str, item.data(0, Qt.ItemDataRole.UserRole))
            wallet_state = self.get_wallet_state(wallet_path)[-1]
            return (wallet_path, -1, wallet_state)

        wallet_item = item.parent()
        wallet_path = cast(str, wallet_item.data(0, Qt.ItemDataRole.UserRole))
        wallet_states = self.get_wallet_state(wallet_path)
        if wallet_item.indexOfChild(item) == 0:
            # Any account in this wallet.
            return (wallet_path, -1, wallet_states[-1])

        account_id = cast(int, item.data(0, Qt.ItemDataRole.UserRole))
        return (wallet_path, account_id, wallet_states[account_id])

    def _on_wallet_opened(self, window: 'ElectrumWindow') -> None:
        """
        Observe wallet open events to keep the access tree widget current.

        This will add the newly opened wallet to this network window's tree as a top-level
        item with all it's accounts underneath it.
        """
        self._add_wallet_to_access_tree(window._wallet)

    def _on_wallet_closed(self, window: 'ElectrumWindow') -> None:
        """
        Observe wallet close events to keep the access tree widget current.

        This will remove the closed wallet from the tree as a top-level item and all the child
        account items along with it.
        """
        self._remove_wallet_from_tree(window._wallet)

    def _add_wallet_to_access_tree(self, wallet: Wallet) -> None:
        """
        This needs to do two things:
        1. Build the tree of wallets and their accounts.
        2. Store the initial tree state.
        """
        wallet_path = wallet.get_storage_path()
        wallet_state = self._wallet_state[wallet_path] = {}

        if self._is_edit_mode:
            # Store the initial state used to populate the tree.
            assert self._server_url is not None
            assert self._entry is not None
            server_type_url = (self._entry.server_type, self._server_url)
            server_rows, server_account_rows = wallet.read_network_servers(server_type_url)
            # These are not related to the existence of the server, unless the server is not
            # registered and tracked by the application config.
            if len(server_rows):
                server_row = server_rows[0]
                self._server_row_by_wallet_path[wallet_path] = server_row
                self._account_rows_by_wallet_path[wallet_path] = server_account_rows

                all_account_state = wallet_state[-1] = EditServerState()
                if server_row is not None and server_row.flags & NetworkServerFlag.ANY_ACCOUNT:
                    all_account_state.enabled = True
                    if server_row.encrypted_api_key is not None:
                        server_key = ServerAccountKey.for_server_row(server_row)
                        credential_id = wallet.get_credential_id_for_server_key(server_key)
                        assert credential_id is not None
                        all_account_state.encrypted_api_key = server_row.encrypted_api_key
                        all_account_state.decrypted_api_key = \
                            app_state.credentials.get_indefinite_credential(
                                credential_id)
                all_account_state.initial_state = InitialServerState.create_from(all_account_state)

                for account_row in server_account_rows:
                    account_state = wallet_state[account_row.account_id] = EditServerState()
                    account_state.enabled = True
                    if account_row.encrypted_api_key is not None:
                        server_key = ServerAccountKey.for_account_row(account_row)
                        credential_id = wallet.get_credential_id_for_server_key(server_key)
                        assert credential_id is not None
                        account_state.encrypted_api_key = account_row.encrypted_api_key
                        account_state.decrypted_api_key = \
                            app_state.credentials.get_indefinite_credential(
                                credential_id)
                    account_state.initial_state = InitialServerState.create_from(account_state)

        wallet_item = QTreeWidgetItem([ f"Wallet: {wallet.name()}" ])
        wallet_item.setData(0, Qt.ItemDataRole.UserRole, wallet_path)

        account_state = wallet_state.setdefault(-1, EditServerState())
        check_state = Qt.CheckState.Unchecked
        if self._entry.api_key_supported:
            api_key_placeholder_text = API_KEY_NOT_SET_TEXT
            if account_state.enabled:
                check_state = Qt.CheckState.Checked
                api_key_placeholder_text = API_KEY_SET_TEXT \
                    if account_state.decrypted_api_key is not None else API_KEY_NOT_SET_TEXT
        else:
            api_key_placeholder_text = API_KEY_UNSUPPORTED_TEXT

        all_accounts_item = QTreeWidgetItem([ _("All accounts in this wallet"),
            api_key_placeholder_text ])
        if self._entry.api_key_supported:
            all_accounts_item.setFlags(
                Qt.ItemFlag(int(all_accounts_item.flags()) | Qt.ItemFlag.ItemIsEditable))
        all_accounts_item.setCheckState(0, check_state)
        all_accounts_item.setDisabled(not self._entry.can_configure_wallet_access)
        wallet_item.addChild(all_accounts_item)

        for account in wallet.get_accounts():
            account_id = account.get_id()
            account_state = wallet_state.setdefault(account_id, EditServerState())

            check_state = Qt.CheckState.Unchecked
            if self._entry.api_key_supported:
                api_key_placeholder_text = API_KEY_NOT_SET_TEXT
                if account_state.enabled:
                    check_state = Qt.CheckState.Checked
                    api_key_placeholder_text = API_KEY_SET_TEXT \
                        if account_state.decrypted_api_key is not None else API_KEY_NOT_SET_TEXT
            else:
                api_key_placeholder_text = API_KEY_UNSUPPORTED_TEXT

            account_item = QTreeWidgetItem([
                f"Account {account.get_id()}: {account.display_name()}",
                api_key_placeholder_text ])
            account_item.setData(0, Qt.ItemDataRole.UserRole, account.get_id())
            if self._entry.api_key_supported:
                account_item.setFlags(
                    Qt.ItemFlag(int(account_item.flags()) | Qt.ItemFlag.ItemIsEditable))
            account_item.setCheckState(0, check_state)
            account_item.setDisabled(not self._entry.can_configure_wallet_access)
            wallet_item.addChild(account_item)

        self._access_tree.addTopLevelItem(wallet_item)
        self._access_tree.resizeColumnToContents(0)

    def _remove_wallet_from_tree(self, wallet: Wallet) -> None:
        wallet_path = wallet.get_storage_path()
        for item_index in range(self._access_tree.topLevelItemCount()):
            wallet_item = self._access_tree.topLevelItem(item_index)
            wallet_item_path = wallet_item.data(0, Qt.ItemDataRole.UserRole)
            if wallet_path == wallet_item_path:
                # Discard this item and all it's children.
                self._access_tree.takeTopLevelItem(item_index)
                # Clear out any state we are holding for the wallet and it's accounts.
                del self._wallet_state[wallet_path]
                if self._is_edit_mode:
                    if wallet_path in self._server_row_by_wallet_path:
                        del self._server_row_by_wallet_path[wallet_path]
                    if wallet_path in self._account_rows_by_wallet_path:
                        del self._account_rows_by_wallet_path[wallet_path]
                break
        else:
            logger.error("Network dialog tried to remove an unrecognised wallet '%s'",
                wallet_path)

    def _is_form_valid(self) -> bool:
        """
        Check all the validated form fields to ensure that the form is filled out well enough
        to allow the user to create or update a given server.
        """
        # Check all "valid for add/update" conditions are met.
        if self._check_server_url_invalid():
            return False

        return True

    def _check_server_url_invalid(self) -> Optional[str]:
        """
        Determine if the current url is invalid.

        Returns an error message to display if the server is invalid, or `None` if it is valid.
        """
        url = self._server_url_edit.text().strip()

        # At this point the URL widget has been validated, and we can take any error message it has.
        server_edit_validator = cast(URLValidator, self._server_url_edit.validator())
        if server_edit_validator.get_last_message() != "":
            return server_edit_validator.get_last_message()

        # We do not allow servers to be saved if there is already a server present with the given
        # URL. We do case-insensitive checks, so we do not allow more than one server with the
        # given URL regardless of the case used. However, if we are editing the server that was
        # already using the given URL we allow it to be saved and consider it valid.
        server_type = self._get_server_type()
        if server_type in API_SERVER_TYPES:
            existing_urls = set(server_key.url.lower() \
                for server_key in self._network.get_api_servers())
            if url.lower() in existing_urls:
                # If we are editing this server, allow it to save/update with the same URL.
                assert self._entry.data_api is not None
                if self._is_edit_mode and self._entry.data_api.url.lower() == url.lower():
                    pass
                else:
                    return _("This URL is already in use.")
        else:
            raise NotImplementedError(f"Unsupported server type {server_type}")

        # No error message to return.
        return None

    def _event_validation_change(self, is_valid: bool) -> None:
        """
        Observe form validity.

        If the form is not valid for either creation or update depending on the context, then
        we want to disable the ability of the user to submit the form.
        """
        # Any invalid field makes the form invalid, but one valid field does not make the form
        # valid. So one valid field requires checking the whole form for validity.
        if is_valid:
            is_valid = self._is_form_valid()

        # The current sole effect of the form not being valid is the "add/update" button is
        # disabled.
        self._save_button.setEnabled(is_valid)

    def _event_clicked_button_help(self) -> None:
        from .help_dialog import HelpDialog
        h = HelpDialog(self, HELP_FOLDER_NAME, HELP_SERVER_EDIT_FILE_NAME)
        h.run()

    def _event_item_changed_access_tree(self, item: QTreeWidgetItem, column: int) -> None:
        if column == 0:
            edit_state = self._get_edit_state_for_item(item)[-1]
            edit_state.enabled = item.checkState(column) == Qt.CheckState.Checked

    def _event_clicked_button_save(self) -> None:
        """
        Process the user submitting the form.

        Once the create or update action is performed, the dialog will be accepted and will close.
        If the form is not valid, then the add/update button will be disabled and we should never
        reach here.
        """
        assert self._is_form_valid(), "should only get here if the form is valid and it is not"

        server_type = self._get_server_type()
        server_url = self._server_url_edit.text().strip()

        if server_type in API_SERVER_TYPES:
            self._save_api_server(server_type, server_url)
        else:
            raise NotImplementedError(f"Unsupported server type {server_type}")

    def _save_api_server(self, server_type: NetworkServerType, server_url: str) -> None:
        wallet: Optional[Wallet]

        def encrypt_api_key(wallet_window: "ElectrumWindow", api_key_text: str) -> Optional[str]:
            nonlocal wallet
            assert wallet is not None
            msg = PASSWORD_REQUEST_TEXT.format(wallet.name())
            password = wallet_window.password_dialog(parent=self, msg=msg)
            if password is None:
                MessageBox.show_message(_("Update aborted. Without the wallet password it is not "
                    "possible to save the API key into that wallet."))
                return None
            return pw_encode(api_key_text, password)

        date_now_utc = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        wallets_by_path = { w.get_storage_path(): w for w in app_state.app_qt.get_wallets() }
        saveable_states: List[WalletSaveState] = []
        saveable_application_state: APIServerDefinition = cast(APIServerDefinition, {})
        for item_index in range(self._access_tree.topLevelItemCount()):
            wallet_item = self._access_tree.topLevelItem(item_index)
            wallet_item_path = wallet_item.data(0, Qt.ItemDataRole.UserRole)
            if wallet_item_path is None:
                # Process the "All wallets" first top level item.
                assert item_index == 0
                state = self._edit_state
                assert state.initial_state is not None
                if state.decrypted_api_key == state.initial_state.decrypted_api_key:
                    if state.enabled == state.initial_state.enabled:
                        continue

                # We do not apply the updates here, we instead prepare them for application with
                # the rest of the changes later.
                saveable_application_state["enabled_for_all_wallets"] = state.enabled
                saveable_application_state["api_key"] = ""
                if state.enabled and state.decrypted_api_key:
                    saveable_application_state["api_key"] = pw_encode(state.decrypted_api_key,
                        TOKEN_PASSWORD)
                continue

            # Process the per-wallet top level items and their account children.
            assert item_index > 0
            wallet = wallets_by_path.get(wallet_item_path)
            if wallet is None:
                continue

            # Remember that each wallet has a separate database.
            window = cast("ElectrumWindow", app_state.app_qt.get_wallet_window(wallet_item_path))
            assert window is not None

            outgoing_state = WalletSaveState(wallet)
            edit_state = self._wallet_state.get(wallet_item_path, {})
            keeping_account_rows = False
            check_wallet_row_index = len(edit_state)-1

            encrypted_api_key: Optional[str] = None
            update_api_key_pair: Optional[Tuple[str, str]] = None

            # The wallet-level "any account for this wallet" entry must be last as it needs
            # to take into account the state of the accounts in the wallet.
            for account_index, account_id in enumerate(sorted(edit_state, reverse=True)):
                state = edit_state[account_id]
                if account_id is None:
                    continue

                if state.enabled:
                    if state.initial_state is not None:
                        keeping_account_rows = True
                        if state.decrypted_api_key == state.initial_state.decrypted_api_key and \
                                state.enabled == state.initial_state.enabled:
                            continue

                        # Update.
                        update_api_key_pair = None
                        encrypted_api_key = None
                        if state.decrypted_api_key is not None:
                            encrypted_api_key = encrypt_api_key(window, state.decrypted_api_key)
                            if encrypted_api_key is None:
                                return # Aborting the save operation completely.
                            update_api_key_pair = (state.decrypted_api_key, encrypted_api_key)

                        if state.initial_state.encrypted_api_key != encrypted_api_key:
                            outgoing_state.updated_api_keys[
                                ServerAccountKey(server_url, server_type,
                                        account_id)] \
                                    = (state.initial_state.encrypted_api_key, update_api_key_pair)

                        # The `date_created` field is set in the wallet when it applies the update.
                        if account_id == -1:
                            assert account_index == check_wallet_row_index
                            outgoing_state.updated_servers.append(
                                NetworkServerRow(server_url, server_type,
                                    encrypted_api_key, NetworkServerFlag.ANY_ACCOUNT,
                                    date_updated=date_now_utc))
                        else:
                            outgoing_state.updated_server_accounts.append(
                                NetworkServerAccountRow(server_url, server_type,
                                    account_id, encrypted_api_key,
                                    date_updated=date_now_utc))
                    else:
                        # Addition.
                        update_api_key_pair = None
                        encrypted_api_key = None
                        if state.decrypted_api_key is not None:
                            encrypted_api_key = encrypt_api_key(window, state.decrypted_api_key)
                            if encrypted_api_key is None:
                                return # Aborting the save operation completely.
                            update_api_key_pair = (state.decrypted_api_key, encrypted_api_key)

                        if encrypted_api_key is not None:
                            outgoing_state.updated_api_keys[ServerAccountKey(server_url, \
                                server_type, account_id)] = \
                                    (None, update_api_key_pair)

                        if account_id == -1:
                            assert account_index == check_wallet_row_index
                            outgoing_state.added_servers.append(NetworkServerRow(server_url,
                                server_type, encrypted_api_key,
                                NetworkServerFlag.ANY_ACCOUNT,
                                date_created=date_now_utc, date_updated=date_now_utc))
                        else:
                            keeping_account_rows = True
                            outgoing_state.added_server_accounts.append(
                                NetworkServerAccountRow(server_url, server_type,
                                    account_id, encrypted_api_key, date_created=date_now_utc,
                                    date_updated=date_now_utc))
                elif account_id == -1:
                    assert account_index == check_wallet_row_index
                    if keeping_account_rows:
                        if state.initial_state is None:
                            outgoing_state.added_servers.append(NetworkServerRow(server_url,
                                server_type, None, NetworkServerFlag.NONE,
                                date_created=date_now_utc, date_updated=date_now_utc))
                        elif state.initial_state.enabled or \
                                state.initial_state.decrypted_api_key is not None:
                            # Update if something changed.
                            outgoing_state.updated_servers.append(NetworkServerRow(server_url,
                                server_type, None,
                                NetworkServerFlag.NONE, date_created=date_now_utc,
                                date_updated=date_now_utc))
                    elif state.initial_state is not None:
                        # Deletion.
                        if state.initial_state.encrypted_api_key is not None:
                            outgoing_state.updated_api_keys[ServerAccountKey(server_url, \
                                server_type, -1)] = \
                                    (state.initial_state.encrypted_api_key, None)
                        outgoing_state.deleted_server_keys.append(
                            ServerAccountKey(server_url, server_type))
                else:
                    if state.initial_state is not None:
                        # Deletion
                        if state.initial_state.encrypted_api_key is not None:
                            outgoing_state.updated_api_keys[ServerAccountKey(server_url, \
                                server_type, account_id)] = \
                                    (state.initial_state.encrypted_api_key, None)
                        outgoing_state.deleted_server_account_keys.append(
                            ServerAccountKey(server_url, server_type,
                                account_id))

            if outgoing_state.is_saveable():
                saveable_states.append(outgoing_state)

        if saveable_application_state:
            if self._is_edit_mode:
                self._network.update_config_api_server(server_url, server_type,
                    saveable_application_state)
            else:
                saveable_application_state["url"] = server_url
                self._network.create_config_api_server(server_type, saveable_application_state)

        if saveable_states:
            futures: List[concurrent.futures.Future[None]] = []
            for outgoing_state in saveable_states:
                future = outgoing_state.wallet.update_network_servers(
                    outgoing_state.added_servers, outgoing_state.added_server_accounts,
                    outgoing_state.updated_servers, outgoing_state.updated_server_accounts,
                    outgoing_state.deleted_server_keys, outgoing_state.deleted_server_account_keys,
                    outgoing_state.updated_api_keys)
                futures.append(future)
            # We can just wait for the last future to complete and the rest should have completed
            # first due to the SQLite queued writes.
            futures[-1].result()

        self.accept()

    def _event_changed_combobox_server_type(self) -> None:
        """
        Update the form contents for changes in the server type.

        The different server types have different form fields that can or cannot be provided.
        It will also affect the validation of the server URL, so constraints relevant to that
        will need to be updated.
        """
        server_type = self._get_server_type()

        validator = cast(URLValidator, self._server_url_edit.validator())
        if server_type in API_SERVER_TYPES:
            validator.set_schemes(DEFAULT_SCHEMES)
            self._entry = self._entry._replace(
                server_type=server_type,
                can_configure_wallet_access=True,
                api_key_supported=True)
        else:
            raise NotImplementedError(f"Unsupported server type {server_type}")

        self._update_state()

        # Revalidate the server URL value and apply validation related UI changes.
        self._server_url_edit.textChanged.emit(self._server_url_edit.text())

    def _update_state(self) -> None:
        """
        Update the form contents for the current server type value.
        """
        server_type = self._get_server_type()
        server_capabilities: List[CapabilitySupport] = SERVER_CAPABILITIES[server_type]
        assert len(server_capabilities)
        if server_type in API_SERVER_TYPES:
            self._url_validator.set_criteria(allow_path=True)
        else:
            raise NotImplementedError(f"Unsupported server type {server_type}")

        api_key_placeholder_text = ""
        if not self._entry.api_key_supported:
            api_key_placeholder_text = API_KEY_UNSUPPORTED_TEXT
        if self._edit_state.enabled:
            check_state = Qt.CheckState.Checked
            if self._entry.api_key_supported:
                api_key_placeholder_text =  API_KEY_SET_TEXT \
                    if self._edit_state.decrypted_api_key is not None else API_KEY_NOT_SET_TEXT
        else:
            check_state = Qt.CheckState.Unchecked
            if self._entry.api_key_supported:
                api_key_placeholder_text = API_KEY_NOT_SET_TEXT

        # Rebuild the tree for wallet and account access.
        self._access_tree.clear()
        all_wallets_item = QTreeWidgetItem([ _("Any loaded wallet or account"),
            api_key_placeholder_text ])
        if self._entry.api_key_supported:
            all_wallets_item.setFlags(
                Qt.ItemFlag(int(all_wallets_item.flags()) | Qt.ItemFlag.ItemIsEditable))
        all_wallets_item.setCheckState(0, check_state)
        all_wallets_item.setDisabled(not self._entry.can_configure_wallet_access)
        self._access_tree.addTopLevelItem(all_wallets_item)
        for wallet in app_state.app_qt.get_wallets():
            self._add_wallet_to_access_tree(wallet)

        # Rebuild the services for this server/server type.
        self._services_form.clear()
        for capability in server_capabilities:
            # TODO(rt12) I also feel like there's some complexity to this we are not handling.
            #   Should one account be able to broadcast, but no others. This is currently a global
            #   setting for the application. Let's forget it for now.
            capability_checkbox = QCheckBox(_("Enabled."))
            if capability.is_unsupported:
                capability_checkbox.setChecked(False)
                capability_checkbox.setDisabled(True)
                capability_checkbox.setToolTip(
                    _("Enabling this service is not yet supported."))
            elif capability.can_disable:
                # TODO(API) This should be populated with the user's current setting.
                capability_checkbox.setChecked(True)
                # TODO(API) We do not currently implement the support for disabling this service
                #   so prevent the user from changing it. They can disable the server anyway
                #   by not enabling for any specific wallets and their accounts, and disabling
                #   the all wallets and their accounts application config setting.
                capability_checkbox.setDisabled(True)
            else:
                capability_checkbox.setChecked(True)
                capability_checkbox.setDisabled(True)
                capability_checkbox.setToolTip(
                    _("Disabling this service is not yet supported."))
            self._services_form.add_row(capability.name, capability_checkbox)

        # Revalidate the server URL value and apply validation related UI changes.
        self._server_url_edit.textChanged.emit("")

    def _get_server_type(self) -> NetworkServerType:
        return SERVER_TYPE_ENTRIES[self._server_type_combobox.currentIndex()]


class SortableServerQTableWidgetItem(QTableWidgetItem):

    def _has_poorer_connection(self, self_is_connected: bool, other_is_connected: bool) -> bool:
        """tcp:// SVServers that are not active as sessions have a lesser 'last_good' despite
        being capable of connecting - these should outrank disconnected SVServers"""
        if self_is_connected == other_is_connected:
            return True
        elif not self_is_connected and other_is_connected:
            return True
        elif self_is_connected and not other_is_connected:
            return False
        return False

    def __lt__(self, other: object) -> bool:
        assert isinstance(other, SortableServerQTableWidgetItem)
        column = self.column()
        if column == 0:
            self_last_good: int = int(self.data(Roles.TIMESTAMP_SORTKEY))
            other_last_good: int = int(other.data(Roles.TIMESTAMP_SORTKEY))
            self_is_connected: bool = self.data(Roles.CONNECTEDNESS_SORTKEY)
            other_is_connected: bool = other.data(Roles.CONNECTEDNESS_SORTKEY)

            if self._has_poorer_connection(self_is_connected, other_is_connected):
                return True
            return self_last_good < other_last_good
        else:
            return self.text() < other.text()


class ServersListWidget(QTableWidget):
    COLUMN_NAMES = ('', _('Service'), '', _('Type'))
    server_disconnected_signal = pyqtSignal()

    def __init__(self, parent: 'ServersTab', network: Network) -> None:
        super().__init__()
        self._parent_tab = parent
        self._network = network

        self.setStyleSheet("""
            QHeaderView::section {
                font-weight: bold;
            }
        """)

        self._connected_pixmap = QPixmap(icon_path("icons8-data-transfer-80-blue.png")
            ).scaledToWidth(16, Qt.TransformationMode.SmoothTransformation)
        self._connected_icon = QIcon(self._connected_pixmap)
        self._unavailable_brush = QBrush(QColor("grey"))
        self._lock_icon = read_QIcon("icons8-lock-windows.svg")

        self.doubleClicked.connect(self._event_double_clicked)
        self.server_disconnected_signal.connect(self._event_server_deleted)

        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        # Tab should move to the next UI element, not to the next link in the table. The user
        # should be able to use cursor keys to move selected lines.
        self.setTabKeyNavigation(False)

    def update_list(self, items: List[ServerListEntry]) -> None:
        # Clear the existing table contents.
        self.setRowCount(0)

        self.setColumnCount(len(self.COLUMN_NAMES))
        self.setHorizontalHeaderLabels(self.COLUMN_NAMES)

        vh = self.verticalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeToContents)
        vh.hide()

        hh = self.horizontalHeader()
        # This is done to ensure that the image column is not expanded to the normal default column
        # width of 39 pixels. 24 pixels is the resized pixmap width of 18 with some padding.
        # As the image is in a label, the label width is tied to the column width and this will
        # center the image in the column given the centered label alignment.
        hh.setMinimumSectionSize(24)
        hh.setDefaultSectionSize(24)

        # The sorting has to be disabled to maintain a stable order as we change the contents.
        self.setSortingEnabled(False)
        self.setRowCount(len(items))

        for row_index, list_entry in enumerate(items):
            # TODO This still needs to identify if the server does not have an API key and also to
            #   decide what that means. Does it mean for the application? For the wallet?
            #   For any account for any wallet?
            # if list_entry.item.api_key_supported and list_entry.item.api_key_required and \
            #         False:
            #     tooltip_text = _("This server requires an API key and does not have one.")
            #     considered_good = False

            is_connected = False
            considered_good = False
            # TODO (1.4.0) Maybe this is relevant to non ElectrumX server types?
            # if list_entry.data_electrumx is not None:
            #     is_connected = self._is_server_healthy(list_entry.data_electrumx,
            #         self._network.sessions)

            if self._network.is_server_disabled(list_entry.url, list_entry.server_type):
                tooltip_text = _("This server has been configured to be disabled by the user.")
                considered_good = False
            elif is_connected:
                tooltip_text = _("There is an active connection to this server.")
                considered_good = True
                is_connected = True
            elif not list_entry.last_try:
                tooltip_text = _("There has never been a connection to this server.")
                considered_good = False
            elif not list_entry.last_good:
                tooltip_text = _("There has never been a successful connection to this server.")
            elif list_entry.last_good < list_entry.last_try:
                tooltip_text = _("The last connection attempt to this server was unsuccessful.")
            else:
                tooltip_text = _("There is no current connection to this server.")
                considered_good = True

            item_0 = SortableServerQTableWidgetItem()
            item_0.setToolTip(tooltip_text)
            if is_connected:
                item_0.setIcon(self._connected_icon)
            item_0.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_0.setData(Roles.ITEM_DATA, list_entry)
            item_0.setData(Roles.TIMESTAMP_SORTKEY, list_entry.last_good if not None else 0)
            item_0.setData(Roles.CONNECTEDNESS_SORTKEY, is_connected)
            self.setItem(row_index, 0, item_0)

            item_1 = SortableServerQTableWidgetItem()
            if considered_good:
                item_1.setText(list_entry.url)
            else:
                item_1.setText(list_entry.url)
                item_1.setForeground(self._unavailable_brush)
            item_1.setToolTip(tooltip_text)
            # Unless we remove this flag, it seems for some reason this field is editable and when
            # it is double clicked it turns into a line edit as well as opening the edit dialog.
            # It's probably a default flag set when `setText` is called.
            item_1.setFlags(Qt.ItemFlag(int(item_1.flags()) & ~Qt.ItemFlag.ItemIsEditable))
            self.setItem(row_index, 1, item_1)

            item_2 = SortableServerQTableWidgetItem()
            self.setItem(row_index, 2, item_2)

            item_3 = SortableServerQTableWidgetItem()
            item_3.setText(SERVER_TYPE_LABELS[list_entry.server_type])
            self.setItem(row_index, 3, item_3)

        self.sortItems(0, Qt.SortOrder.DescendingOrder)
        self.setSortingEnabled(True)

        # If this happens before the row insertion loop it is not guaranteed that the last column
        # (at this time being the API type) will get resized to contents. Instead it will be
        # pushed right and clipped with only partial text displayed.
        hh = self.horizontalHeader()
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)

    def _get_selected_entry(self) -> ServerListEntry:
        items = self.selectedItems()
        assert len(items) == 1
        return cast(ServerListEntry, items[0].data(Roles.ITEM_DATA))

    def _view_entry(self, entry: ServerListEntry) -> None:
        dialog = EditServerDialog(self._parent_tab, self._network, title="Edit Server",
            edit_mode=True, entry=entry)
        if dialog.exec() == QDialog.Accepted:
            self._parent_tab.update_servers()

    # Qt signal handler.
    def _event_double_clicked(self, _index: QModelIndex) -> None:
        """
        The user double clicks on a row in the list.
        """
        items = self.selectedItems()
        if not len(items):
            return
        self._view_entry(items[0].data(Roles.ITEM_DATA))

    # Qt function override.
    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        if key == Qt.Key.Key_Return or key == Qt.Key.Key_Enter:
            entry = self._get_selected_entry()
            self._view_entry(entry)
            return
        super().keyPressEvent(event)

    # Qt function override.
    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        items = self.selectedItems()
        if not len(items):
            return
        entry = cast(ServerListEntry, items[0].data(Roles.ITEM_DATA))

        # def use_as_server(auto_connect: bool) -> None:
        #     nonlocal entry
        #     assert entry.data_electrumx is not None
        #     try:
        #         self._parent_tab._parent.follow_server(entry.data_electrumx, auto_connect)
        #     except Exception as e:
        #         MessageBox.show_error(str(e))

        menu = QMenu(self)
        details_action = menu.addAction("Details")

        menu.addAction(_("Delete server"), partial(self._on_menu_delete_server, entry))

        action = menu.exec_(self.mapToGlobal(event.pos()))
        if action == details_action:
            self._view_entry(entry)

    def _on_menu_delete_server(self, entry: ServerListEntry) -> None:
        if not MessageBox.question(_("Are you sure you want to delete this server "
                "from all loaded wallets and ElectrumSV's cached server list?\n\n"
                "If this server is present in the built-in initial server list, it will be "
                "recreated from the built-in record the next time ElectrumSV starts up."),
                self):
            return

        if entry.data_api is not None:
            # Delete this server from any loaded wallets. We do not know if it is actually used
            # by any of these servers but we can do the delete and it should flush out any
            # actual uses.
            deleted_keys = [ ServerAccountKey(entry.url, entry.server_type) ]
            for wallet in cast(List[Wallet], app_state.app_qt.get_wallets()):
                future = wallet.update_network_servers([], [], [], [], deleted_keys, [], {})
                future.result()
            self._network.delete_config_api_server(entry.url, entry.server_type)
            self._parent_tab.update_servers()
        else:
            raise NotImplementedError(f"Unsupported server type {entry.server_type}")

    def _event_server_deleted(self) -> None:
        self._parent_tab.update_servers()


class ServersTab(QWidget):

    def __init__(self, parent: 'NetworkTabsLayout', network: Network) -> None:
        super().__init__()
        self._parent = parent
        self._network = network

        grid = QGridLayout(self)
        grid.setSpacing(8)

        self._server_list = ServersListWidget(self, network)
        self._top_button_layout = TableTopButtonLayout(enable_filter=False)
        self._top_button_layout.add_create_button()
        self._top_button_layout.add_signal.connect(self._event_button_clicked_add_server)
        self._top_button_layout.refresh_signal.connect(self._event_button_clicked_refresh_list)
        grid.addLayout(self._top_button_layout, 0, 0)
        grid.addWidget(self._server_list, 2, 0, 1, 5)
        self.update_servers()

    def _show_help(self) -> None:
        b = QMessageBox()
        b.setIcon(QMessageBox.Information)
        b.setTextFormat(Qt.TextFormat.AutoText)
        b.setText(self.help_text)
        b.setWindowTitle("Help")
        b.exec()

    def _event_button_clicked_refresh_list(self) -> None:
        self.update_servers()

    def _event_button_clicked_add_server(self) -> None:
        dialog = EditServerDialog(self, self._network, title="Add Server")
        dialog.exec()

    def update_servers(self) -> None:
        items: List[ServerListEntry] = []

        # Add API server items.
        for server_key, api_server in self._network.get_api_servers().items():
            # TODO(API) If the server is not an application default and even if it is, there
            # can be multiple last_good/last_try options for all the different api key usages.
            # The application may allow usage without an api key usage for all wallets.
            # An account may have an api key that it uses instead, and it may have it's own
            # last good/last try record.
            if api_server.config is not None:
                print(api_server)
                last_try = api_server.config['last_try']
                last_good = api_server.config['last_good']
                enabled_for_all_wallets = api_server.config['enabled_for_all_wallets']
                api_key_supported = api_server.config['api_key_supported']
                api_key_required = api_server.config.get('api_key_required', False)
            else:
                last_try = 0
                last_good = 0
                enabled_for_all_wallets = False
                api_key_supported = True
                api_key_required = False
            assert api_server.config is not None
            items.append(ServerListEntry(
                api_server.server_type,
                server_key.url,
                last_try=last_try,
                last_good=last_good,
                enabled_for_all_wallets=enabled_for_all_wallets,
                can_configure_wallet_access=True,
                api_key_supported=api_key_supported,
                api_key_required=api_key_required,
                data_api=api_server))

        self._server_list.update_list(items)
        # TODO(1.4.0) - replace with HeaderSV chain tips and local chain state this wallet follows
        # self._parent._blockchain_tab.nodes_list_widget.update()
        self._enable_set_broadcast_service()

    def _enable_set_broadcast_service(self) -> None:
        if app_state.config.is_modifiable('broadcast_service'):
            self._server_list.setEnabled(True)
        else:
            self._server_list.setEnabled(False)


class NetworkTabsLayout(QVBoxLayout):
    def __init__(self, network: Network) -> None:
        super().__init__()
        self._filling_in = False
        self._network = network

        # TODO(1.4.0) - replace with HeaderSV chain tips and local chain state this wallet follows
        # self._blockchain_tab = BlockchainTab(self, network)
        self._servers_tab = ServersTab(self, network)

        self._tabs = QTabWidget()
        self._tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # TODO(1.4.0) - replace with HeaderSV chain tips and local chain state this wallet follows
        # self._tabs.addTab(self._blockchain_tab, _('Blockchain Status'))
        self._tabs.addTab(self._servers_tab, _('Servers'))

        self.addWidget(self._tabs)
        self.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        self.last_values = None

    # def follow_server(self, server: SVServer, auto_connect: bool) -> None:
    #     self._network.set_server(server, auto_connect)
    #     # This updates the blockchain tab too.
    #     self._servers_tab.update_servers()


class NetworkDialog(QDialog):
    network_updated_signal = pyqtSignal()

    def __init__(self, network: Network) -> None:
        super().__init__(flags=Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint))
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 350)
        self.resize(560, 400)

        self._network = network

        self._tabs_layout = NetworkTabsLayout(network)
        self._buttons_layout = Buttons(CloseButton(self))
        self._buttons_layout.add_left_button(HelpDialogButton(self, "misc", "network-dialog"))

        vbox = QVBoxLayout(self)
        # vbox.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        vbox.addLayout(self._tabs_layout)
        vbox.addLayout(self._buttons_layout)

        # The following event registrations cover what should be the full scope of keeping the
        # list up to date, both main server status and the existence of which servers the
        # application is connected to.
        self.network_updated_signal.connect(self._event_network_updated)

        # 'update': possible main server change.
        # 'sessions': a session is either opened or closed.
        network.register_callback(self._event_network_callbacks, ['updated', 'sessions'])

    def _event_network_callbacks(self, event: List[str], *args: Any) -> None:
        # This may run in network thread??
        self.network_updated_signal.emit()

    def _event_network_updated(self) -> None:
        # This always runs in main GUI thread.
        self._tabs_layout._servers_tab.update_servers()


class URLValidator(QValidator):
    """
    This backs up the visual indication of whether the entered server uri is valid.
    """

    _last_message: str = ""

    def __init__(self, parent: Optional[QObject]=None, schemes: Optional[set[str]]=None) -> None:
        super().__init__(parent)

        self._schemes = schemes
        self._allow_path = False

    def set_criteria(self, allow_path: bool=False) -> None:
        self._allow_path = allow_path

    def set_schemes(self, schemes: Optional[set[str]]=None) -> None:
        """
        Custom method to update the schemes to validate against.
        """
        self._schemes = schemes

    def get_last_message(self) -> str:
        return self._last_message

    def validate(self, text: str, position: int) -> tuple[QValidator.State, str, int]:
        """
        Overridden method to differentiate betwen intermediate and acceptable values.

        We intentionally do not return an `Invalid` result as that prevents the user from entering
        what they have entered, and unless we are differentiating between numbers and text or some
        equally distinct set of values this is not so easy.
        """
        try:
            text = validate_url(text, schemes=self._schemes, allow_path=self._allow_path)
        except UrlValidationError as e:
            if e.code == UrlValidationError.INVALID_SCHEME:
                schemes = self._schemes if self._schemes else DEFAULT_SCHEMES
                self._last_message = _("Invalid scheme (expected: {})").format(", ".join(schemes))
            else:
                self._last_message = e.args[0]
            return QValidator.State.Intermediate, text, position

        self._last_message = ""
        return QValidator.State.Acceptable, text, position

    def fixup(self, text: str) -> str:
        """
        Overridden method to fix the content.

        It is unclear from the documentation when this gets called, whether it is just for
        `Invalid` validation results, or any that are not `Acceptable`. We do not attempt to
        fix anything.
        """
        return text

