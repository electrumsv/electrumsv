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
import random
import socket
from typing import Callable, cast, Dict, List, NamedTuple, Optional, Sequence, TYPE_CHECKING, Tuple
import urllib.parse

from aiorpcx import NetAddress
from bitcoinx import hash_to_hex_str
from PyQt5.QtCore import pyqtSignal, QAbstractItemModel, QModelIndex, QObject, QPoint, Qt, \
    QThread, QTimer
from PyQt5.QtGui import QBrush, QCloseEvent, QColor, QContextMenuEvent, QIcon, QKeyEvent, \
    QPixmap, QValidator
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, \
    QFrame, QGridLayout, QHBoxLayout, QHeaderView, QItemDelegate, QLabel, QLineEdit, QMenu, \
    QMessageBox, QPushButton, QStyleOptionViewItem, \
    QSizePolicy, QTableWidget, QTableWidgetItem, QTabWidget, QTreeWidget, QTreeWidgetItem, \
    QVBoxLayout, QWidget

from ...app_state import app_state
from ...constants import NetworkServerFlag, NetworkServerType
from ...i18n import _
from ...logs import logs
from ...wallet import Wallet
from ...network import Network, SVServerKey, SVUserAuth, SVProxy, SVSession, SVServer
from ...util.network import DEFAULT_SCHEMES, UrlValidationError, validate_url
from ...wallet_database.types import NetworkServerRow, NetworkServerAccountRow

from .password_dialog import PasswordLineEdit
from .table_widgets import TableTopButtonLayout
from .util import Buttons, CloseButton, ExpandableSection, FormSectionWidget,  \
    HelpButton, HelpDialogButton, icon_path, MessageBox, read_QIcon, WindowModalDialog


if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class Roles:
    ITEM_DATA = Qt.ItemDataRole.UserRole
    TIMESTAMP_SORTKEY = Qt.ItemDataRole.UserRole + 1
    CONNECTEDNESS_SORTKEY = Qt.ItemDataRole.UserRole + 2

logger = logs.get_logger("network-ui")


# These are display ordered for the combo box.
SERVER_TYPE_ENTRIES = [
    NetworkServerType.ELECTRUMX,
    NetworkServerType.MERCHANT_API,
]

SERVER_TYPE_LABELS = {
    NetworkServerType.ELECTRUMX: _("ElectrumX"),
    NetworkServerType.MERCHANT_API: _("MAPI"),
}


class ServerStatus(enum.IntEnum):
    CONNECTED = 0
    DISCONNECTED = 1


SERVER_STATUS = {
    ServerStatus.CONNECTED: _('Connected'),
    ServerStatus.DISCONNECTED: _('Disconnected'),
}


class ServerCapabilities(enum.IntEnum):
    TRANSACTION_BROADCAST = 1
    FEE_QUOTE = 2
    SCRIPTHASH_HISTORY = 3
    MERKLE_PROOF = 4


class ServerItem(NamedTuple):
    server_id: int
    server_name: str
    server_type: NetworkServerType
    api_key_text: Optional[str] = None
    api_key_supported: bool = False
    api_key_required: bool = False
    enabled_for_all_wallets: bool = True


class ServerListEntry(NamedTuple):
    item: ServerItem
    server: Optional[SVServer]
    url: str
    last_try: float
    last_good: float
    is_connected: bool
    # TODO This can be determined using the `network` reference.
    is_main_server: bool


# The location of the help document.
HELP_FOLDER_NAME = "misc"
HELP_SERVER_EDIT_FILE_NAME = "network-server-dialog"

@dataclasses.dataclass
class CapabilitySupport:
    name: str
    is_unsupported: bool=False
    can_disable: bool=False


# TODO Upgrade how this is displayed and what is displayed. It would be valuable for users to
#      be able to get a per-capability tooltip when they have their mouse over a given entry.
#      This suggests a list view might be a good choice for an upgrade, but a table also might
#      be even better as it can show costing and quotas and so on. And the last time a capability
#      was used and how often it has been used. Given the limited space, this might mean a
#      tree view is even better.
MAPI_CAPABILITIES = [
    CapabilitySupport("Transaction broadcast", can_disable=True),
    CapabilitySupport("Transaction fee quotes"),
    CapabilitySupport("Transaction proofs", is_unsupported=True),
]

ELECTRUMX_CAPABILITIES = [
    CapabilitySupport("Blockchain scanning"),
    CapabilitySupport("Transaction broadcast"),
    CapabilitySupport("Transaction proofs"),
]

API_KEY_SET_TEXT = _("<API key hidden>")
API_KEY_UNSUPPORTED_TEXT = _("<unsupported>")
API_KEY_NOT_SET_TEXT = ""



def url_to_server_key(url: str) -> SVServerKey:
    """
    Convert a URL to a server key.

    This does not do validation in any way, shape or form. It is assumed before we got to this
    point there was some kind of validation that passed.
    """
    result = urllib.parse.urlparse(url)
    host, port_str = result.netloc.split(":")
    port = int(port_str)
    protocol = "s" if result.scheme.startswith("ssl") else "t"
    return SVServerKey(host, port, protocol)


class NodesListWidget(QTreeWidget):

    def __init__(self, parent: 'BlockchainTab', network: Network) -> None:
        super().__init__()
        self._network = network
        self._parent_tab = parent
        self.setHeaderLabels([ _('Connected server'), _('Height') ])
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)

        self._connected_pixmap = QPixmap(icon_path("icons8-data-transfer-80-blue.png")
            ).scaledToWidth(16, Qt.TransformationMode.SmoothTransformation)
        self._warning_pixmap = QPixmap(icon_path("icons8-error-48-ui.png")
            ).scaledToWidth(16, Qt.TransformationMode.SmoothTransformation)
        self._connected_icon = QIcon(self._connected_pixmap)
        self._lock_pixmap = QPixmap(icon_path("icons8-lock-windows.svg")
            ).scaledToWidth(16, Qt.TransformationMode.SmoothTransformation)

    def create_menu(self, position: QPoint) -> None:
        item = self.currentItem()
        if not item:
            return
        server = item.data(0, Qt.ItemDataRole.UserRole)
        if not server:
            return

        def use_as_server(auto_connect: bool) -> None:
            try:
                self._parent_tab._parent.follow_server(server, auto_connect)
            except Exception as e:
                MessageBox.show_error(str(e))

        menu = QMenu()
        action = menu.addAction(_("Use as main server"), partial(use_as_server, True))
        action.setEnabled(server != self._network.main_server)
        if self._network.auto_connect() or server != self._network.main_server:
            action = menu.addAction(_("Lock as main server"), partial(use_as_server, False))
            action.setEnabled(app_state.config.is_modifiable('auto_connect'))
        else:
            action = menu.addAction(_("Unlock as main server"), partial(use_as_server, True))
            action.setEnabled(app_state.config.is_modifiable('auto_connect') and \
                server == self._network.main_server)
        menu.exec_(self.viewport().mapToGlobal(position))

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in [ Qt.Key.Key_F2, Qt.Key.Key_Return ]:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def on_activated(self, item: QTreeWidgetItem, _column: int) -> None:
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def chain_name(self, chain, our_chain) -> str:
        if chain is our_chain:
            return 'our_chain'

        _chain, common_height = our_chain.common_chain_and_height(chain)
        fork_height = common_height + 1
        headers_obj = app_state.headers
        header = headers_obj.header_at_height(chain, fork_height)
        prefix = hash_to_hex_str(header.hash).lstrip('00')[0:10]
        return f'{prefix}@{fork_height}'

    def update(self) -> None:
        self.clear()

        chains = self._network.sessions_by_chain()
        our_chain = self._network.chain()
        for chain, sessions in chains.items():
            if len(chains) > 1:
                name = self.chain_name(chain, our_chain)
                tree_item = QTreeWidgetItem([name, '%d' % chain.height])
                tree_item.setData(0, Qt.ItemDataRole.UserRole, None)  # server
            else:
                tree_item = self
            # If someone is connected to two nodes on the same server, indicate the difference.
            host_counts = {}
            for session in sessions:
                host_counts[session.server.host] = host_counts.get(session.server.host, 0) + 1
            for session in sessions:
                extra_name = ""
                if host_counts[session.server.host] > 1:
                    extra_name = f" (port: {session.server.port})"
                extra_name += ' (main server)' if session.server is self._network.main_server \
                    else ''
                item = QTreeWidgetItem([session.server.host + extra_name,
                    str(session.tip.height)])
                item.setIcon(0, self._connected_icon)
                item.setData(0, Qt.ItemDataRole.UserRole, session.server)
                if isinstance(tree_item, NodesListWidget):
                    tree_item.addTopLevelItem(item)
                else:
                    tree_item.addChild(item)
            if len(chains) > 1:
                self.addTopLevelItem(tree_item)
                # NOTE(typing) remove ambiguity so it knows it is a tree item, not the tree itself.
                cast(QTreeWidgetItem, tree_item).setExpanded(True)

            height_str = "%d "%(self._network.get_local_height()) + _('blocks')
            self._parent_tab.height_label.setText(height_str)
            n = len(self._network.sessions)
            if n == 0:
                status = _("Not connected")
            elif n == 1:
                status = _("Connected to {:d} server.").format(n)
            else:
                status = _("Connected to {:d} servers.").format(n)
            self._parent_tab.status_label.setText(status)
            chains = self._network.sessions_by_chain().keys()
            if len(chains) > 1:
                our_chain = self._network.chain()
                heights = set()
                for chain in chains:
                    if chain != our_chain:
                        _chain, common_height = our_chain.common_chain_and_height(chain)
                        heights.add(common_height + 1)
                msg = _('Chain split detected at height(s) {}\n').format(
                    ','.join(f'{height:,d}' for height in sorted(heights)))
            else:
                msg = ''
            self._parent_tab.split_label.setText(msg)
            self._parent_tab.server_label.setText(self._network.main_server.host)

            # Ordered pixmaps, show only as many as applicable. Probably a better way to do this.
            pixmaps: List[Tuple[Optional[QPixmap], str]] = []
            if not self._network.auto_connect():
                pixmaps.append((self._lock_pixmap,
                    _("This server is locked into place as the permanent main server.")))
            if self._network.main_server.state.last_good < self._network.main_server.state.last_try:
                pixmaps.append((self._warning_pixmap, _("This server is not currently connected.")))

            while len(pixmaps) < 2:
                pixmaps.append((None, ''))

            if pixmaps[0][0] is None:
                self._parent_tab.server_label_icon1.clear()
            else:
                self._parent_tab.server_label_icon1.setPixmap(pixmaps[0][0])
                self._parent_tab.server_label_icon1.setToolTip(pixmaps[0][1])
            if pixmaps[1][0] is None:
                self._parent_tab.server_label_icon2.clear()
            else:
                self._parent_tab.server_label_icon2.setPixmap(pixmaps[1][0])
                self._parent_tab.server_label_icon2.setToolTip(pixmaps[1][1])

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)


class BlockchainTab(QWidget):

    def __init__(self, parent: "NetworkTabsLayout", network: Network) -> None:
        super().__init__()
        self._parent = parent
        self._network = network

        blockchain_layout = QVBoxLayout(self)

        form = FormSectionWidget()
        self.status_label = QLabel(_("No connections yet."))
        form.add_row(_('Status'), self.status_label, True)
        self.server_label = QLabel()
        self.server_label_icon1 = QLabel()
        self.server_label_icon2 = QLabel()
        server_label_layout = QHBoxLayout()
        server_label_layout.addWidget(self.server_label)
        server_label_layout.addSpacing(4)
        server_label_layout.addWidget(self.server_label_icon1)
        server_label_layout.addSpacing(4)
        server_label_layout.addWidget(self.server_label_icon2)
        server_label_layout.addStretch(1)
        form.add_row(_('Main server'), server_label_layout, True)
        self.height_label = QLabel('')
        form.add_row(_('Blockchain'), self.height_label, True)

        blockchain_layout.addWidget(form)

        self.split_label = QLabel('')
        form.add_row(QLabel(""), self.split_label)

        self.nodes_list_widget = NodesListWidget(self, self._network)
        blockchain_layout.addWidget(self.nodes_list_widget)
        blockchain_layout.addStretch(1)
        self.nodes_list_widget.update()


@dataclasses.dataclass
class EditServerState:
    enabled: bool = False
    # This is the decrypted API key.
    api_key_text: Optional[str] = None


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
        self._entry = entry

        # TODO The server id is kind of wonky. There's the built-in one, but it is possible for
        #   a user to edit a server and inherit it's static data server id, which makes it hard
        #   to update the server.

        # Generate an id for a new server. This will be overriden by any edited servers id.
        self._server_id: int = random.randrange(500000, 4294967295)
        if entry is not None:
            self._server_id = entry.item.server_id

        # Covers the "any account in any loaded wallet" row.
        # We enable this by default for all new added servers. The edit will overwrite this.
        self._application_state = EditServerState(True)
        if entry is not None:
            self._application_state.enabled = entry.item.enabled_for_all_wallets
            self._application_state.api_key_text = entry.item.api_key_text
        # This is used to track the initial application state, which comes from the config.
        self._initial_application_state = dataclasses.replace(self._application_state)

        # Covers the "any account" row with `account_id` of `None`.
        # Covers all the accounts in the wallet under their `account_id`.
        self._wallet_state: Dict[str, Dict[Optional[int], EditServerState]] = {}
        # These are used to track initial wallet state, but it is unknown until a wallet is loaded.
        self._server_row_by_wallet_path: Dict[str, NetworkServerRow] = {}
        self._account_rows_by_wallet_path: Dict[str, List[NetworkServerAccountRow]] = {}

        initial_server_url = ""
        initial_server_type = NetworkServerType.ELECTRUMX
        server_type_schemes: Optional[set[str]] = None
        if self._is_edit_mode:
            assert entry is not None
            initial_server_url = entry.url
            initial_server_type = entry.item.server_type
        if initial_server_type == NetworkServerType.ELECTRUMX:
            server_type_schemes = {"ssl", "tcp"}

        self._vbox = QVBoxLayout(self)

        self._server_type_combobox = QComboBox()
        for server_type in SERVER_TYPE_ENTRIES:
            self._server_type_combobox.addItem(SERVER_TYPE_LABELS[server_type])
        self._server_type_combobox.setCurrentIndex(SERVER_TYPE_ENTRIES.index(initial_server_type))
        self._server_type_combobox.currentIndexChanged.connect(
            self._event_changed_combobox_server_type)

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
            # Change the background to indicate whether the edit field contents are valid or not.
            palette = edit.palette()
            if edit.hasAcceptableInput():
                palette.setBrush(palette.Base, default_brush)
            else:
                palette.setBrush(palette.Base, QColor(Qt.GlobalColor.yellow).lighter(167))
            edit.setPalette(palette)

            # If the field contents are invalid, the tooltip will indicate why.
            validator = cast(URLValidator, edit.validator())
            last_message = validator.get_last_message()
            edit.setToolTip(last_message)

            validation_callback(last_message == "")

        self._server_url_edit = QLineEdit()
        self._server_url_edit.setMinimumWidth(300)
        self._server_url_edit.setText(initial_server_url)
        default_edit_palette = self._server_url_edit.palette()
        default_base_brush = default_edit_palette.brush(default_edit_palette.Base)
        self._url_validator = URLValidator(schemes=server_type_schemes)
        self._server_url_edit.setValidator(self._url_validator)
        self._server_url_edit.textChanged.connect(
            partial(apply_line_edit_validation_style, self._server_url_edit, default_base_brush,
                self.validation_change.emit))

        editable_form = FormSectionWidget()
        editable_form.add_row(_("Type"), self._server_type_combobox, True)
        editable_form.add_row(_("URL"), self._server_url_edit, True)

        self._vbox.addWidget(editable_form)

        server_dialog = self

        ## The wallet and account access expandable section.
        class AccessTreeItemDelegate(QItemDelegate):
            def __init__(self, editable_columns: List[int]) -> None:
                super().__init__(None)
                self._editable_columns = editable_columns

            def createEditor(self, parent: QWidget, style_option: QStyleOptionViewItem,
                    index: QModelIndex) -> Optional[QWidget]:
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
                edit_state = self._get_edit_state_for_index(index)
                assert edit_state.enabled
                text = edit_state.api_key_text if edit_state.api_key_text is not None else ""
                line_edit = cast(QLineEdit, editor)
                line_edit.setText(text)

            def setModelData(self, editor: QWidget, model: QAbstractItemModel,
                    index: QModelIndex) -> None:
                """
                Overriden method that takes the editor widget text from the user is stored
                in the edit state, and replaced for non-edit display with the appropriate
                placeholder.
                """
                edit_state = self._get_edit_state_for_index(index)

                text = cast(QLineEdit, editor.text()).strip()
                if text:
                    edit_state.api_key_text = text
                    model.setData(index, API_KEY_SET_TEXT, Qt.ItemDataRole.DisplayRole)
                else:
                    edit_state.api_key_text = None
                    model.setData(index, API_KEY_NOT_SET_TEXT, Qt.ItemDataRole.DisplayRole)

            def _get_edit_state_for_index(self, index: QModelIndex) -> EditServerState:
                """
                Helper method.
                """
                # TODO Using this reference from the outer scope is not ideal, there should be
                #   some better way to do this. It might be that we have to set a reference
                #   to the edit dialog on this delegate.
                nonlocal server_dialog
                parent_index = index.parent()
                wallet_row = parent_index.row() if parent_index.row() > -1 else index.row()
                wallet_item = server_dialog.get_access_tree().topLevelItem(wallet_row)
                if parent_index.row() == -1:
                    if index.row() == 0:
                        # All wallets in this application.
                        return server_dialog.get_application_state()
                    wallet_path = cast(str, wallet_item.data(0, Qt.ItemDataRole.UserRole))
                    wallet_state = server_dialog.get_wallet_state(wallet_path)
                    return wallet_state[None]
                else:
                    wallet_path = cast(str, wallet_item.data(0, Qt.ItemDataRole.UserRole))
                    wallet_state = server_dialog.get_wallet_state(wallet_path)
                    if index.row() == 0:
                        # Any account in this wallet.
                        return wallet_state[None]
                    account_item = wallet_item.child(index.row())
                    account_id = cast(int, account_item.data(0, Qt.ItemDataRole.UserRole))
                    return wallet_state[account_id]

        api_key_placeholder_text = ""
        if not self._entry.item.api_key_supported:
            api_key_placeholder_text = API_KEY_UNSUPPORTED_TEXT
        if self._application_state.enabled:
            check_state = Qt.CheckState.Checked
            if self._entry.item.api_key_supported:
                api_key_placeholder_text =  API_KEY_SET_TEXT \
                    if self._application_state.api_key_text is not None else API_KEY_NOT_SET_TEXT
        else:
            check_state = Qt.CheckState.Unchecked
            if self._entry.item.api_key_supported:
                api_key_placeholder_text = API_KEY_NOT_SET_TEXT

        self._access_tree = QTreeWidget()
        self._access_tree.setItemDelegate(AccessTreeItemDelegate([ 1 ]))
        self._access_tree.setHeaderLabels([ _('Scope'), _("API key") ])
        all_wallets_item = QTreeWidgetItem([ _("Any loaded wallet or account"),
            api_key_placeholder_text ])
        if self._entry.item.api_key_supported:
            all_wallets_item.setFlags(all_wallets_item.flags() | Qt.ItemFlag.ItemIsEditable)
        all_wallets_item.setCheckState(0, check_state)
        self._access_tree.addTopLevelItem(all_wallets_item)
        for wallet in app_state.app.get_wallets():
            self._add_wallet_to_access_tree(wallet)

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

            self._usage_form.add_row(_("Last attempted"), attempt_label, True)
            self._usage_form.add_row(_("Last connected"), connected_label, True)

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
        app_state.app.window_opened_signal.connect(self._on_wallet_opened)
        app_state.app.window_closed_signal.connect(self._on_wallet_closed)

    def closeEvent(self, event: QCloseEvent):
        """
        Dialog close event. Do any necessary clean up/unregistration here.
        """
        app_state.app.window_opened_signal.disconnect(self._on_wallet_opened)
        app_state.app.window_closed_signal.disconnect(self._on_wallet_closed)

        event.accept()

    def get_access_tree(self) -> QTreeWidget:
        return self._access_tree

    def get_server_entry(self) -> Optional[ServerListEntry]:
        return self._entry

    def get_application_state(self) -> EditServerState:
        return self._application_state

    def get_wallet_state(self, wallet_path: str) -> Dict[Optional[int], EditServerState]:
        return self._wallet_state[wallet_path]

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

        server_row: Optional[NetworkServerRow] = None
        if self._is_edit_mode:
            # Store the initial state used to populate the tree.
            assert self._server_id is not None
            server_rows, account_rows = wallet.read_network_servers(self._server_id)
            if len(server_rows):
                server_row = server_rows[0]
                self._server_row_by_wallet_path[wallet_path] = server_row
                self._account_rows_by_wallet_path[wallet_path] = account_rows

                all_account_state = wallet_state[None] = EditServerState()
                if server_row is not None and server_row.flags & NetworkServerFlag.ANY_ACCOUNT:
                    server_key = (server_row.server_id, None)
                    all_account_state.enabled = True
                    if server_key in wallet.server_api_keys:
                        all_account_state.api_key_text = wallet.server_api_keys[server_key]

                for account_row in account_rows:
                    account_key = (account_row.server_id, account_row.account_id)
                    account_state = wallet_state[account_row.account_id] = EditServerState()
                    account_state.enabled = True
                    if account_key in wallet.server_api_keys:
                        account_state.api_key_text = wallet.server_api_keys[account_key]
            else:
                assert wallet_path not in self._server_row_by_wallet_path
                assert wallet_path not in self._account_rows_by_wallet_path

        wallet_item = QTreeWidgetItem([ f"Wallet: {wallet.name()}" ])
        wallet_item.setData(0, Qt.ItemDataRole.UserRole, wallet_path)

        if None in wallet_state:
            account_state = wallet_state[None]
        else:
            account_state = wallet_state[None] = EditServerState()
        check_state = Qt.CheckState.Unchecked
        if self._entry.item.api_key_supported:
            api_key_placeholder_text = API_KEY_NOT_SET_TEXT
            if account_state.enabled:
                check_state = Qt.CheckState.Checked
                api_key_placeholder_text = API_KEY_SET_TEXT \
                    if account_state.api_key_text is not None else API_KEY_NOT_SET_TEXT
        else:
            api_key_placeholder_text = API_KEY_UNSUPPORTED_TEXT

        all_accounts_item = QTreeWidgetItem([ _("All accounts in this wallet"),
            api_key_placeholder_text ])
        if self._entry.item.api_key_supported:
            all_accounts_item.setFlags(all_accounts_item.flags() | Qt.ItemFlag.ItemIsEditable)
        all_accounts_item.setCheckState(0, check_state)
        wallet_item.addChild(all_accounts_item)

        for account in wallet.get_accounts():
            account_id = account.get_id()
            if account_id in wallet_state:
                account_state = wallet_state[account_id]
            else:
                account_state = wallet_state[account_id] = EditServerState()
            check_state = Qt.CheckState.Unchecked
            if self._entry.item.api_key_supported:
                if account_state.enabled:
                    check_state = Qt.CheckState.Checked
                    api_key_placeholder_text = API_KEY_SET_TEXT \
                        if account_state.api_key_text is not None else API_KEY_NOT_SET_TEXT
            else:
                api_key_placeholder_text = API_KEY_UNSUPPORTED_TEXT

            account_item = QTreeWidgetItem([
                f"Account {account.get_id()}: {account.display_name()}",
                api_key_placeholder_text ])
            account_item.setData(0, Qt.ItemDataRole.UserRole, account.get_id())
            account_item.setCheckState(0, check_state)
            if not self._entry.item.api_key_supported:
                account_item.setFlags(account_item.flags() | Qt.ItemFlag.ItemIsEditable)
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
        server_edit_validator = cast(URLValidator, self._server_url_edit.validator())
        if server_edit_validator.get_last_message() != "":
            return False
        return True

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

    def _event_clicked_button_save(self) -> None:
        """
        Process the user submitting the form.

        Once the create or update action is performed, the dialog will be accepted and will close.
        If the form is not valid, then the add/update button will be disabled and we should never
        reach here.
        """
        assert self._is_form_valid(), "should only get here if the form is valid and it is not"

        server_uri = self._server_url_edit.text().strip()
        server_type = self._get_server_type()

        date_now_utc = int(datetime.datetime.utcnow().timestamp())
        server_api_keys: Dict[Tuple[int, Optional[int]], str] = {}

        futures: List[concurrent.futures.Future] = []
        wallets_by_path = { w.get_storage_path(): w for w in app_state.app.get_wallets() }
        for item_index in range(self._access_tree.topLevelItemCount()):
            wallet_item = self._access_tree.topLevelItem(item_index)
            wallet_item_path = wallet_item.data(0, Qt.ItemDataRole.UserRole)
            if wallet_item_path:
                wallet = wallets_by_path.get(wallet_item_path)
                if wallet is None:
                    continue

                wallet_api_key = None
                all_accounts_item = wallet_item.child(0)
                # TODO Need to move the row creation outside of this loop. Build the new api key
                #   index. Build a checked index. Compare outside of this to the wallet.

                server_flags = NetworkServerFlag.NONE
                account_rows: List[NetworkServerAccountRow] = []
                for child_row in range(wallet_item.childCount()):
                    account_item = wallet_item.child(child_row)
                    if child_row == 0:
                        if account_item.checkState(0) == Qt.CheckState.Checked:
                            server_flags |= NetworkServerFlag.ANY_ACCOUNT
                            # TODO If api key is set, do the thing.
                    else:
                        pass

                server_rows = [ NetworkServerRow(self._server_id, server_type, server_uri,
                    wallet_api_key, server_flags, date_now_utc, date_now_utc) ]
                future = wallet.replace_network_server_entries(self._server_id, server_rows,
                    account_rows)
                futures.append(future)
                # TODO: Work out if anything has changed and what to update.
                #   TODO: Need to keep the loaded state for a wallet from the update.
                pass
            else:
                # TODO This should be the "All wallets entry"
                pass

        # TODO We want to delete everything from all displayed wallets.
        # TODO We want to create the per-wallet server where applicable.
        # TODO We want to create the per-wallet server accounts where applicable.
        server_id: int = -1
        server_entries: Dict[str, NetworkServerRow] = {}
        account_entries: Dict[str, List[NetworkServerAccountRow]] = {}
        if server_type == NetworkServerType.ELECTRUMX:
            if self._is_edit_mode:
                updated_server_key = url_to_server_key(server_uri)
                assert self._entry is not None
                # TODO(rt12) Need to change the update method on the network singleton to take
                # the old server key in addition to the new server key. It'd also be good to
                # make server keys named tuples.
                existing_server_key = url_to_server_key(self._entry.url)
                self._network.update_electrumx_server(existing_server_key, updated_server_key)
            else:
                raise Exception("...")
        elif server_type == NetworkServerType.MERCHANT_API:
            pass
        else:
            raise ValueError(f"unsupported server type '{server_type}'")

        # if self._is_edit_mode:
        #     # Update the server in the network code. This will need to disable/disconnect the
        #     # server (if it is connected), update it and then re-enable it.
        #     pass
        # else:
        #     # Add the server in the network code.
        #     pass

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
        if server_type == NetworkServerType.ELECTRUMX:
            validator.set_schemes({"ssl", "tcp"})
        else:
            validator.set_schemes(DEFAULT_SCHEMES)

        self._update_state()

        # Revalidate the server URL value and apply validation related UI changes.
        self._server_url_edit.textChanged.emit(self._server_url_edit.text())

    def _update_state(self) -> None:
        """
        Update the form contents for the current server type value.
        """
        server_capabilities: List[CapabilitySupport] = []

        server_type = self._get_server_type()
        if server_type == NetworkServerType.MERCHANT_API:
            server_capabilities = MAPI_CAPABILITIES
            self._url_validator.set_criteria(allow_path=True)
        elif server_type == NetworkServerType.ELECTRUMX:
            server_capabilities = ELECTRUMX_CAPABILITIES
            self._url_validator.set_criteria(allow_path=False)

        self._services_form.clear()
        for capability in server_capabilities:
            # TODO(rt12) At some point it should be possible to disable selected services for
            #   a given server type.
            # TODO I also feel like there's some complexity to this we are not handling. Should one
            #   account be able to broadcast, but no others. This is currently a global setting
            #   for the application. Let's forget it for now.
            if capability.can_disable:
                capability_checkbox = QCheckBox(_("Enabled"))
                capability_checkbox.setChecked(True)
                self._services_form.add_row(capability.name, capability_checkbox, True)
            elif capability.is_unsupported:
                label = QLabel(_("This service is unsupported."))
                self._services_form.add_row(capability.name, label, True)
            else:
                label = QLabel(_("This service cannot be disabled."))
                self._services_form.add_row(capability.name, label, True)

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

    def __lt__(self, other: 'SortableServerQTableWidgetItem') -> bool:
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

        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        # Tab should move to the next UI element, not to the next link in the table. The user
        # should be able to use cursor keys to move selected lines.
        self.setTabKeyNavigation(False)

    def update_list(self, items: List[ServerListEntry]) -> None:
        # Clear the existing table contents.
        self.setRowCount(0)

        network = cast(Network, app_state.daemon.network)

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
            considered_good = False
            # TODO This still needs to identify if the server does not an API key and also to
            #   decide what that means. Does it mean for the application? For the wallet?
            #   For any account for any wallet?
            # if list_entry.item.api_key_supported and list_entry.item.api_key_required and \
            #         False:
            #     tooltip_text = _("This server requires an API key and does not have one.")
            #     considered_good = False
            if list_entry.is_connected:
                tooltip_text = _("There is an active connection to this server.")
                considered_good = True
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
            if list_entry.is_connected:
                item_0.setIcon(self._connected_icon)
            item_0.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_0.setData(Roles.ITEM_DATA, list_entry)
            item_0.setData(Roles.TIMESTAMP_SORTKEY, list_entry.last_good if not None else 0)
            item_0.setData(Roles.CONNECTEDNESS_SORTKEY, list_entry.is_connected)
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
            item_1.setFlags(item_1.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.setItem(row_index, 1, item_1)

            item_2 = SortableServerQTableWidgetItem()
            if list_entry.is_main_server and not network.auto_connect():
                item_2.setIcon(self._lock_icon)
                item_2.setToolTip(
                    _("This server is locked into place as the permanent main server."))
            self.setItem(row_index, 2, item_2)

            item_3 = SortableServerQTableWidgetItem()
            item_3.setText(SERVER_TYPE_LABELS[list_entry.item.server_type])
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
        return items[0].data(Roles.ITEM_DATA)

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

        network = cast(Network, app_state.daemon.network)

        def use_as_server(auto_connect: bool) -> None:
            nonlocal entry
            assert entry.server is not None
            try:
                self._parent_tab._parent.follow_server(entry.server, auto_connect)
            except Exception as e:
                MessageBox.show_error(str(e))

        def delete_server() -> None:
            if not MessageBox.question(_("Are you sure you want to delete this server "
                    "from all loaded wallets and ElectrumSV's cached server list?\n\n"
                    "If this server is present in the built-in initial server list, it will be "
                    "recreated from the built-in record the next time ElectrumSV starts up."),
                    self):
                return

            # TODO(rt12) delete this all wallet databases.
            # entry.item.server_id
            # TODO(rt12) delete it from the network store and remove active servers.
            # TODO(rt12) refresh the list
            pass

        menu = QMenu(self)
        details_action = menu.addAction("Details")

        if entry.server is not None:
            action = menu.addAction(_("Use as main server"), partial(use_as_server, True))
            action.setEnabled(not entry.is_main_server)
            if network.auto_connect() or not entry.is_main_server:
                action = menu.addAction(_("Lock as main server"), partial(use_as_server, False))
                action.setEnabled(app_state.config.is_modifiable('auto_connect'))
            else:
                action = menu.addAction(_("Unlock as main server"), partial(use_as_server, True))
                action.setEnabled(app_state.config.is_modifiable('auto_connect') and \
                    entry.is_main_server)
            menu.addAction(_("Delete server"), delete_server)

        action = menu.exec_(self.mapToGlobal(event.pos()))
        if action == details_action:
            self._view_entry(entry)



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

    @staticmethod
    def _is_server_healthy(server: SVServer, sessions: Sequence[SVSession]) -> bool:
        """Sessions only include currently active SVSessions, hence the for loop and
        matching pattern - this only applies to ElectrumX type servers"""
        if not sessions:
            return False

        max_tip_height = max([session.tip.height for session in sessions])
        for session in sessions:
            if session.server == server:
                break
        else:
            return False  # The server is unable to connect - there is no SVSession for it

        is_more_than_two_blocks_behind = max_tip_height > session.tip.height + 2
        if server.state.last_good >= server.state.last_try and not is_more_than_two_blocks_behind:
            return True

        return False

    def update_servers(self) -> None:
        network = cast(Network, app_state.daemon.network)
        items: List[ServerListEntry] = []

        # Add ElectrumX servers
        sessions = network.sessions        # SVSession
        for server in network.get_servers():
            is_connected = self._is_server_healthy(server, sessions)
            is_main_server = server == network.main_server
            server_name = server.host
            server_item = ServerItem(000, server_name, NetworkServerType.ELECTRUMX)
            proto_prefix = f"tcp://" if server.protocol == "t" else "ssl://"
            url = proto_prefix + f"{server.host}:{server.port}"
            items.append(ServerListEntry(server_item, server, url, server.state.last_try,
                server.state.last_good, is_connected, is_main_server))

        # Add mAPI items
        is_main_server = False
        is_connected = False
        for mapi_server in network.get_mapi_servers():
            server_name = mapi_server['uri']
            server_item = ServerItem(mapi_server["id"], server_name,
                NetworkServerType.MERCHANT_API,
                mapi_server["api_key"],
                mapi_server["api_key_supported"],
                # This is not present if api keys are not supported.
                mapi_server.get("api_key_required", False),
                mapi_server["enabled_for_all_wallets"])
            items.append(ServerListEntry(server_item, None, mapi_server['uri'],
                mapi_server['last_try'], mapi_server['last_good'], False, is_main_server))

        self._server_list.update_list(items)
        self._parent._blockchain_tab.nodes_list_widget.update()
        self._enable_set_broadcast_service()

    def _enable_set_broadcast_service(self) -> None:
        if app_state.config.is_modifiable('broadcast_service'):
            self._server_list.setEnabled(True)
        else:
            self._server_list.setEnabled(False)


class ProxyTab(QWidget):

    def __init__(self):
        super().__init__()

        grid = QGridLayout(self)
        grid.setSpacing(8)

        # proxy setting
        self._proxy_checkbox = QCheckBox(_('Use proxy'))
        self._proxy_checkbox.clicked.connect(self._check_disable_proxy)
        self._proxy_checkbox.clicked.connect(self._set_proxy)

        self._proxy_mode_combo = QComboBox()
        self._proxy_mode_combo.addItems(list(SVProxy.kinds))
        self._proxy_host_edit = QLineEdit()
        self._proxy_host_edit.setFixedWidth(200)
        self._proxy_port_edit = QLineEdit()
        self._proxy_port_edit.setFixedWidth(100)
        self._proxy_username_edit = QLineEdit()
        self._proxy_username_edit.setPlaceholderText(_("Proxy user"))
        self._proxy_username_edit.setFixedWidth(self._proxy_host_edit.width())
        self._proxy_password_edit = PasswordLineEdit()
        self._proxy_password_edit.setPlaceholderText(_("Password"))

        self._proxy_mode_combo.currentIndexChanged.connect(self._set_proxy)
        self._proxy_host_edit.editingFinished.connect(self._set_proxy)
        self._proxy_port_edit.editingFinished.connect(self._set_proxy)
        self._proxy_username_edit.editingFinished.connect(self._set_proxy)
        self._proxy_password_edit.editingFinished.connect(self._set_proxy)

        self._proxy_mode_combo.currentIndexChanged.connect(self._proxy_settings_changed)
        self._proxy_host_edit.textEdited.connect(self._proxy_settings_changed)
        self._proxy_port_edit.textEdited.connect(self._proxy_settings_changed)
        self._proxy_username_edit.textEdited.connect(self._proxy_settings_changed)
        self._proxy_password_edit.textEdited.connect(self._proxy_settings_changed)

        self._tor_checkbox = QCheckBox(_("Use Tor Proxy"))
        self._tor_checkbox.setIcon(read_QIcon("tor_logo.png"))
        self._tor_checkbox.hide()
        self._tor_checkbox.clicked.connect(self._use_tor_proxy)

        grid.addWidget(self._tor_checkbox, 1, 0, 1, 3)
        grid.addWidget(self._proxy_checkbox, 2, 0, 1, 3)
        grid.addWidget(HelpButton(_('Proxy settings apply to all connections: both '
                                    'ElectrumSV servers and third-party services.')), 2, 4)
        grid.addWidget(self._proxy_mode_combo, 4, 1)
        grid.addWidget(self._proxy_host_edit, 4, 2)
        grid.addWidget(self._proxy_port_edit, 4, 3)
        grid.addWidget(self._proxy_username_edit, 5, 2, Qt.AlignmentFlag.AlignTop)
        grid.addWidget(self._proxy_password_edit, 5, 3, Qt.AlignmentFlag.AlignTop)
        grid.setRowStretch(7, 1)

        self._fill_in_proxy_settings()

    def _check_disable_proxy(self, b: bool) -> None:
        if not app_state.config.is_modifiable('proxy'):
            b = False
        for w in [ self._proxy_mode_combo, self._proxy_host_edit, self._proxy_port_edit,
                self._proxy_username_edit, self._proxy_password_edit ]:
            w.setEnabled(b)

    def _fill_in_proxy_settings(self) -> None:
        network = cast(Network, app_state.daemon.network)
        self._filling_in = True
        self._check_disable_proxy(network.proxy is not None)
        self._proxy_checkbox.setChecked(network.proxy is not None)
        proxy = network.proxy or SVProxy('localhost:9050', 'SOCKS5', None)
        self._proxy_mode_combo.setCurrentText(proxy.kind())
        self._proxy_host_edit.setText(str(proxy.host()))
        self._proxy_port_edit.setText(str(proxy.port()))
        self._proxy_username_edit.setText(proxy.username())
        self._proxy_password_edit.setText(proxy.password())
        self._filling_in = False

    def set_tor_detector(self) -> None:
        self.td = td = TorDetector()
        td.found_proxy.connect(self._suggest_proxy)
        td.start()

    def _set_proxy(self) -> None:
        if self._filling_in:
            return
        proxy = None
        if self._proxy_checkbox.isChecked():
            try:
                address = NetAddress(self._proxy_host_edit.text(), self._proxy_port_edit.text())
                if self._proxy_username_edit.text():
                    auth = SVUserAuth(self._proxy_username_edit.text(),
                        self._proxy_password_edit.text())
                else:
                    auth = None
                proxy = SVProxy(address, self._proxy_mode_combo.currentText(), auth)
            except Exception:
                logger.exception('error setting proxy')
        if not proxy:
            self._tor_checkbox.setChecked(False)

        # Apply the changes.
        network = cast(Network, app_state.daemon.network)
        network.set_proxy(proxy)

    def _suggest_proxy(self, found_proxy: tuple[str, int]) -> None:
        self._tor_proxy = found_proxy
        self._tor_checkbox.setText("Use Tor proxy at port " + str(found_proxy[1]))
        if (self._proxy_checkbox.isChecked() and
                self._proxy_mode_combo.currentText() == 'SOCKS5' and
                self._proxy_host_edit.text() == found_proxy[0] and
                self._proxy_port_edit.text() == str(found_proxy[1])):
            self._tor_checkbox.setChecked(True)
        self._tor_checkbox.show()

    def _use_tor_proxy(self, use_it: bool) -> None:
        if use_it:
            self._proxy_mode_combo.setCurrentText('SOCKS5')
            self._proxy_host_edit.setText(self._tor_proxy[0])
            self._proxy_port_edit.setText(str(self._tor_proxy[1]))
            self._proxy_username_edit.setText("")
            self._proxy_password_edit.setText("")
            self._proxy_checkbox.setChecked(True)
        else:
            self._proxy_checkbox.setChecked(False)
        self._check_disable_proxy(use_it)
        self._set_proxy()

    def _proxy_settings_changed(self) -> None:
        self._tor_checkbox.setChecked(False)


class TorDetector(QThread):
    found_proxy = pyqtSignal(object)

    def __init__(self) -> None:
        QThread.__init__(self)

    def run(self) -> None:
        # Probable ports for Tor to listen at
        ports = [9050, 9150]
        for p in ports:
            pair = ('localhost', p)
            if TorDetector.is_tor_port(pair):
                self.found_proxy.emit(pair)
                return

    @staticmethod
    def is_tor_port(pair) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect(pair)
            # Tor responds uniquely to HTTP-like requests
            s.send(b"GET\n")
            if b"Tor is not an HTTP Proxy" in s.recv(1024):
                return True
        except socket.error:
            pass
        return False


class NetworkTabsLayout(QVBoxLayout):
    def __init__(self, network: Network) -> None:
        super().__init__()
        self._tor_proxy = None
        self._filling_in = False
        self._network = network

        self._blockchain_tab = BlockchainTab(self, network)
        self._servers_tab = ServersTab(self, network)
        self._proxy_tab = ProxyTab()

        self._tabs = QTabWidget()
        self._tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._tabs.addTab(self._blockchain_tab, _('Blockchain Status'))
        self._tabs.addTab(self._servers_tab, _('Servers'))
        self._tabs.addTab(self._proxy_tab, _('Proxy'))

        self.addWidget(self._tabs)
        self.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        self._proxy_tab.set_tor_detector()
        self.last_values = None

    def follow_server(self, server: SVServer, auto_connect: bool) -> None:
        self._network.set_server(server, auto_connect)
        # This updates the blockchain tab too.
        self._servers_tab.update_servers()


class NetworkDialog(QDialog):
    network_updated_signal = pyqtSignal()

    def __init__(self, network: Network) -> None:
        super().__init__(flags=Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint))
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 200)
        self.resize(560, 400)

        self._network = network

        self._tabs_layout = NetworkTabsLayout(network)
        self._buttons_layout = Buttons(CloseButton(self))
        self._buttons_layout.add_left_button(HelpDialogButton(self, "misc", "network-dialog"))

        vbox = QVBoxLayout(self)
        vbox.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        vbox.addLayout(self._tabs_layout)
        vbox.addLayout(self._buttons_layout)

        # The following event registrations cover what should be the full scope of keeping the
        # list up to date, both main server status and the existence of which servers the
        # application is connected to.
        self.network_updated_signal.connect(self._event_network_updated)

        # 'update': possible main server change.
        # 'sessions': a session is either opened or closed.
        network.register_callback(self._event_network_callbacks, ['updated', 'sessions'])

    def _event_network_callbacks(self, event, *args):
        # This may run in network thread??
        self.network_updated_signal.emit()

    def _event_network_updated(self):
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


class APIKeyValidator(QValidator):
    """
    This backs up the visual indication of whether the entered API key value is valid.
    """

    _last_message: str = ""

    def __init__(self, parent: Optional[QObject]=None) -> None:
        super().__init__(parent)

        self._require_value = False

    def set_criteria(self, require_value: bool=False) -> None:
        """
        Not all APIs require an API key.
        """
        self._require_value = require_value

    def get_last_message(self) -> str:
        return self._last_message

    def validate(self, text: str, position: int) -> tuple[QValidator.State, str, int]:
        """
        Overridden method to differentiate betwen intermediate and acceptable values.

        We intentionally do not return an `Invalid` result as that prevents the user from entering
        what they have entered, and unless we are differentiating between numbers and text or some
        equally distinct set of values this is not so easy.
        """
        # For now we just consider a valid value (if one is required) as anything other than
        # no text at all. If we ever have..
        if not self._require_value or len(text.strip()) > 5:
            self._last_message = ""
            return QValidator.State.Acceptable, text, position

        self._last_message = _("Invalid API key")
        return QValidator.State.Intermediate, text, position


    def fixup(self, text: str) -> str:
        """
        Overridden method to fix the content.

        It is unclear from the documentation when this gets called, whether it is just for
        `Invalid` validation results, or any that are not `Acceptable`. We do not attempt to
        fix anything.
        """
        return text

