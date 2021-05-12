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

import datetime
import enum
from functools import partial
import socket
from typing import Callable, cast, List, NamedTuple, Optional, Sequence, Tuple
import urllib.parse

from aiorpcx import NetAddress
from bitcoinx import hash_to_hex_str
from PyQt5.QtCore import pyqtSignal, QModelIndex, QObject, QPoint, Qt, QThread
from PyQt5.QtGui import QBrush, QColor, QContextMenuEvent, QIcon, QKeyEvent, QPixmap, QValidator
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, \
    QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, \
    QSizePolicy, QTableWidget, QTableWidgetItem, QTabWidget, QTreeWidget, QTreeWidgetItem, \
    QVBoxLayout, QWidget

from ...app_state import app_state
from ...constants import BroadcastServicesUI, BroadcastServices
from ...i18n import _
from ...logs import logs
from ...network import Network, SVServerKey, SVUserAuth, SVProxy, SVSession, SVServer
from ...util.network import DEFAULT_SCHEMES, UrlValidationError, validate_url

from .password_dialog import PasswordLineEdit
from .table_widgets import TableTopButtonLayout
from .util import Buttons, CloseButton, FormSectionWidget, HelpButton, HelpDialogButton, \
    icon_path, MessageBox, read_QIcon, WindowModalDialog


class Roles:
    ITEM_DATA = Qt.ItemDataRole.UserRole
    TIMESTAMP_SORTKEY = Qt.ItemDataRole.UserRole + 1
    CONNECTEDNESS_SORTKEY = Qt.ItemDataRole.UserRole + 2

logger = logs.get_logger("network-ui")


SERVER_TYPE_ENTRIES = [
    BroadcastServices.ELECTRUMX,
    BroadcastServices.MERCHANT_API,
]

SERVER_TYPE_LABELS = {
    BroadcastServices.ELECTRUMX: _("ElectrumX"),
    BroadcastServices.MERCHANT_API: _("MAPI"),
}

COMBOBOX_INDEX_MAP = {
    BroadcastServices.ELECTRUMX: 0,
    BroadcastServices.MERCHANT_API: 1
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
    server_name: str
    server_type: str


class ServerListEntry(NamedTuple):
    item: ServerItem
    server: Optional[SVServer]
    url: str
    last_try: float
    last_good: float
    is_connected: bool
    is_main_server: bool


# TODO Upgrade how this is displayed and what is displayed. It would be valuable for users to
#      be able to get a per-capability tooltip when they have their mouse over a given entry.
#      This suggests a list view might be a good choice for an upgrade, but a table also might
#      be even better as it can show costing and quotas and so on. And the last time a capability
#      was used and how often it has been used. Given the limited space, this might mean a
#      tree view is even better.
MAPI_CAPABILITY_HTML = "Transaction broadcast.<br>"+ \
    "Transaction fee quotes."

ELECTRUMX_CAPABILITY_HTML = "Blockchain scanning.<br>"+ \
    "Transaction broadcast.<br>"+ \
    "Transaction proofs."


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

    def __init__(self, parent: 'BlockchainTab') -> None:
        QTreeWidget.__init__(self)
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

        # NOTE(typing) The dynamic app_state object does not propagate typing information.
        network = cast(Network, app_state.daemon.network)

        menu = QMenu()
        action = menu.addAction(_("Use as main server"), partial(use_as_server, True))
        action.setEnabled(server != network.main_server)
        if network.auto_connect() or server != network.main_server:
            action = menu.addAction(_("Lock as main server"), partial(use_as_server, False))
            action.setEnabled(app_state.config.is_modifiable('auto_connect'))
        else:
            action = menu.addAction(_("Unlock as main server"), partial(use_as_server, True))
            action.setEnabled(app_state.config.is_modifiable('auto_connect') and \
                server == network.main_server)
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

        # NOTE(typing) The dynamic app_state object does not propagate typing information.
        network = cast(Network, app_state.daemon.network)
        chains = network.sessions_by_chain()
        our_chain = network.chain()
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
                extra_name += ' (main server)' if session.server is network.main_server else ''
                item = QTreeWidgetItem([session.server.host + extra_name,
                    str(session.tip.height)])
                item.setIcon(0, self._connected_icon)
                item.setData(0, Qt.ItemDataRole.UserRole, session.server)
                tree_item.addTopLevelItem(item)
            if len(chains) > 1:
                self.addTopLevelItem(tree_item)
                # NOTE(typing) remove ambiguity so it knows it is a tree item, not the tree itself.
                cast(QTreeWidgetItem, tree_item).setExpanded(True)

            height_str = "%d "%(network.get_local_height()) + _('blocks')
            self._parent_tab.height_label.setText(height_str)
            n = len(network.sessions)
            if n == 0:
                status = _("Not connected")
            elif n == 1:
                status = _("Connected to {:d} server.").format(n)
            else:
                status = _("Connected to {:d} servers.").format(n)
            self._parent_tab.status_label.setText(status)
            chains = network.sessions_by_chain().keys()
            if len(chains) > 1:
                our_chain = network.chain()
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
            pixmaps: List[Tuple[Optional[QPixmap], str]] = []
            if not network.auto_connect():
                pixmaps.append((self._lock_pixmap,
                    _("This server is locked into place as the permanent main server.")))
            if network.main_server.state.last_good < network.main_server.state.last_try:
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
            self._parent_tab.server_label.setText(network.main_server.host)

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)


class BlockchainTab(QWidget):

    def __init__(self, parent: "NetworkTabsLayout") -> None:
        super().__init__()
        self._parent = parent

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

        self.nodes_list_widget = NodesListWidget(self)
        blockchain_layout.addWidget(self.nodes_list_widget)
        blockchain_layout.addStretch(1)
        self.nodes_list_widget.update()


class EditServerDialog(WindowModalDialog):
    """Two modes: edit_mode=True and edit_mode=False"""
    validation_change = pyqtSignal(bool)

    def __init__(self, parent: QWidget, title: str, edit_mode: bool=False,
            entry: Optional[ServerListEntry]=None) -> None:
        super().__init__(parent, title=title)

        # External accessible state.
        self._is_edit_mode = edit_mode
        self._entry = entry

        initial_server_url = ""
        initial_server_type = BroadcastServices.ELECTRUMX
        server_type_schemes: Optional[set[str]] = None
        if self._is_edit_mode:
            assert entry is not None
            initial_server_url = entry.url
            initial_server_type = entry.item.server_type
        if initial_server_type == BroadcastServices.ELECTRUMX:
            server_type_schemes = {"ssl", "tcp"}

        self.setWindowTitle(title)
        self.setMinimumWidth(380)

        self._vbox = QVBoxLayout(self)

        self._server_type_combobox = QComboBox()
        self._server_type_combobox.addItem(BroadcastServicesUI.ELECTRUMX)
        self._server_type_combobox.addItem(BroadcastServicesUI.MERCHANT_API)
        self._server_type_combobox.setCurrentIndex(SERVER_TYPE_ENTRIES.index(initial_server_type))
        self._server_type_combobox.currentIndexChanged.connect(
            self._event_combobox_server_type_changed)

        def apply_line_edit_validation_style(edit: QLineEdit, default_brush: QColor,
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

            # NOTE(bonus-feature) It is quite useful to visually indicate the reason the field
            #   contents are invalid, but using a tooltip to do so is awkward and gets in the
            #   way. It would be better to have a validation area in the form that appears
            #   below the field pushing the latter form rows further down.
            #
            # # This seems to map to the center of the widget, no effort to adjust it.
            # tooltip_position = edit.mapToGlobal(edit.pos())
            # QToolTip.showText(tooltip_position, last_message, edit)

        self._server_url_edit = QLineEdit()
        default_edit_palette = self._server_url_edit.palette()
        default_base_brush = default_edit_palette.brush(default_edit_palette.Base)
        self._server_url_edit.setValidator(URLValidator(schemes=server_type_schemes))
        self._server_url_edit.textChanged.connect(
            partial(apply_line_edit_validation_style, self._server_url_edit, default_base_brush,
                # NOTE(typing) signals are not handled properly by Pyright
                self.validation_change.emit)) # type: ignore
        # Ensure that the `textChanged` signal is emitted for initial validation and it's styling.
        if self._is_edit_mode and initial_server_url is not None:
            self._server_url_edit.setText(initial_server_url)
        else:
            # Manually trigger the signal and the validation as `setText("")` does not.
            self._server_url_edit.textChanged.emit("")

        self._api_key_edit = QLineEdit()

        editable_form = FormSectionWidget()
        editable_form.add_row(_("Type"), self._server_type_combobox, True)
        editable_form.add_row(_("URL"), self._server_url_edit, True)
        editable_form.add_row(_("API Key"), self._api_key_edit, True)
        self._vbox.addWidget(editable_form)

        self._offered_services_label = QLabel("...")

        # NOTE(rt12) This looks better than separate sections as it makes the label column width
        #   consistent.
        details_form = editable_form # FormSectionWidget()
        details_form.add_title(_("Details"))
        details_form.add_row(_("Offered services"), self._offered_services_label, True)

        if edit_mode:
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

            details_form.add_row(_("Last attempted"), attempt_label, True)
            details_form.add_row(_("Last connected"), connected_label, True)

        self._vbox.addWidget(details_form)

        self._dialog_button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton(QDialogButtonBox.Ok | QDialogButtonBox.Cancel))
        ok_button = self._dialog_button_box.button(
            QDialogButtonBox.StandardButton(QDialogButtonBox.Ok))
        if edit_mode:
            ok_button.setText(_("Update"))
        else:
            ok_button.setText(_("Add"))

        self._dialog_button_box.accepted.connect(self._event_dialog_button_box_accepted)
        self._dialog_button_box.rejected.connect(self.reject)

        self._vbox.addWidget(self._dialog_button_box)

        self._update_state()

        # NOTE(typing) signals are not handled properly by Pyright
        self.validation_change.connect(self._event_validation_change) # type: ignore
        # Do an initial validation change event, with asserted validity which will cause a check.
        self._event_validation_change(True)

    def _is_form_valid(self) -> bool:
        validator = cast(URLValidator, self._server_url_edit.validator())
        # Check all "valid for add/update" conditions are met. Only one for this form.
        return validator.get_last_message() == ""

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
        ok_button = self._dialog_button_box.button(
            QDialogButtonBox.StandardButton(QDialogButtonBox.Ok))
        ok_button.setEnabled(is_valid)

    def _event_dialog_button_box_accepted(self) -> None:
        """
        Process the user submitting the form.

        Once the create or update action is performed, the dialog will be accepted and will close.
        If the form is not valid, then the add/update button will be disabled and we should never
        reach here.
        """
        assert self._is_form_valid(), "should only get here if the form is valid and it is not"

        network = cast(Network, app_state.daemon.network)

        server_url = self._server_url_edit.text().strip()
        server_type = self._get_server_type()
        api_key = self._api_key_edit.text().strip()

        if server_type == BroadcastServices.ELECTRUMX:
            assert api_key == "", "the api key field is currently disabled for ElectrumX servers"
            if self._is_edit_mode:
                updated_server_key = url_to_server_key(server_url)
                assert self._entry is not None
                # TODO(rt12) Need to change the update method on the network singleton to take
                # the old server key in addition to the new server key. It'd also be good to
                # make server keys named tuples.
                existing_server_key = url_to_server_key(self._entry.url)
                network.update_electrumx_server(existing_server_key, updated_server_key)
            else:
                raise Exception("...")
        elif server_type == BroadcastServices.MERCHANT_API:
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

    def _event_combobox_server_type_changed(self) -> None:
        """
        Update the form contents for changes in the server type.

        The different server types have different form fields that can or cannot be provided.
        It will also affect the validation of the server URL, so constraints relevant to that
        will need to be updated.
        """
        server_type = self._get_server_type()

        validator = cast(URLValidator, self._server_url_edit.validator())
        if server_type == BroadcastServices.ELECTRUMX:
            validator.set_schemes({"ssl", "tcp"})
        else:
            validator.set_schemes(DEFAULT_SCHEMES)

        self._update_state()

        # Revalidate the server URL value and apply validation related UI changes.
        self._server_url_edit.textChanged.emit(self._server_url_edit.text())

    def _update_state(self) -> None:
        """
        Update the form contents for existing current server type value.
        """
        server_type = self._get_server_type()
        if server_type == BroadcastServices.MERCHANT_API:
            self._offered_services_label.setText(MAPI_CAPABILITY_HTML)
            self._api_key_edit.setEnabled(True)
        elif server_type == BroadcastServices.ELECTRUMX:
            self._offered_services_label.setText(ELECTRUMX_CAPABILITY_HTML)
            self._api_key_edit.setText("")
            self._api_key_edit.setEnabled(False)
        else:
            self._offered_services_label.setText(_("Unknown"))
            self._api_key_edit.setEnabled(False)

    def _get_server_type(self) -> str:
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
        # TODO This only sorts for the first column which is a good enough first step.
        #      We need sorting to work for all columns, like alphanumerically for the url column.
        self_last_good: int = int(self.data(Roles.TIMESTAMP_SORTKEY))
        other_last_good: int = int(other.data(Roles.TIMESTAMP_SORTKEY))
        self_is_connected: bool = self.data(Roles.CONNECTEDNESS_SORTKEY)
        other_is_connected: bool = other.data(Roles.CONNECTEDNESS_SORTKEY)

        if self._has_poorer_connection(self_is_connected, other_is_connected):
            return True
        return self_last_good < other_last_good


class ServersListWidget(QTableWidget):
    COLUMN_NAMES = ('', _('Service'), '', _('Type'))

    def __init__(self, parent: 'ServersTab') -> None:
        super().__init__()
        self._parent_tab = parent

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
            considered_active = False
            if list_entry.is_connected:
                tooltip_text = _("There is an active connection to this server.")
                considered_active = True
            elif not list_entry.last_try:
                tooltip_text = _("There has never been a connection to this server.")
                considered_active = True
            elif not list_entry.last_good:
                tooltip_text = _("There has never been a successful connection to this server.")
            elif list_entry.last_good < list_entry.last_try:
                tooltip_text = _("The last connection attempt to this server was unsuccessful.")
            else:
                tooltip_text = _("There is no current connection to this server.")
                considered_active = True

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
            if considered_active:
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

            row_type_label = QLabel(SERVER_TYPE_LABELS[list_entry.item.server_type])
            row_type_label.setStyleSheet("padding-left: 3px; padding-right: 3px;")
            self.setCellWidget(row_index, 3, row_type_label)

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
        dialog = EditServerDialog(self._parent_tab, title="Edit Server", edit_mode=True,
            entry=entry)
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
        entry = items[0].data(Roles.ITEM_DATA)

        network = cast(Network, app_state.daemon.network)

        def use_as_server(auto_connect: bool) -> None:
            nonlocal entry
            assert entry.server is not None
            try:
                self._parent_tab._parent.follow_server(entry.server, auto_connect)
            except Exception as e:
                MessageBox.show_error(str(e))

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

        action = menu.exec_(self.mapToGlobal(event.pos()))
        if action == details_action:
            self._view_entry(entry)



class ServersTab(QWidget):

    def __init__(self, parent: 'NetworkTabsLayout') -> None:
        super().__init__()
        self._parent = parent

        grid = QGridLayout(self)
        grid.setSpacing(8)

        self._server_list = ServersListWidget(self)
        self._top_button_layout = TableTopButtonLayout(enable_filter=False)
        self._top_button_layout.add_create_button()
        # NOTE(typing) signals are not handled properly by Pyright
        self._top_button_layout.add_signal.connect( # type: ignore
            self._event_button_clicked_add_server)
        self._top_button_layout.refresh_signal.connect( # type: ignore
            self._event_button_clicked_refresh_list)
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
        dialog = EditServerDialog(self, title="Add Server")
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

        # Add ElectrumX items
        sessions = network.sessions        # SVSession
        for server in network.get_servers():
            is_connected = self._is_server_healthy(server, sessions)
            is_main_server = server == network.main_server
            server_name = server.host
            server_item = ServerItem(server_name, BroadcastServices.ELECTRUMX)
            proto_prefix = f"tcp://" if server.protocol == "t" else "ssl://"
            url = proto_prefix + f"{server.host}:{server.port}"
            items.append(ServerListEntry(server_item, server, url, server.state.last_try,
                server.state.last_good, is_connected, is_main_server))

        # Add mAPI items
        is_main_server = False
        for mapi_server in network.get_mapi_servers():
            is_connected = mapi_server['last_good'] == mapi_server['last_try']
            server_name = mapi_server['uri']
            server_item = ServerItem(server_name, BroadcastServices.MERCHANT_API)
            items.append(ServerListEntry(server_item, None, mapi_server['uri'],
                mapi_server['last_try'], mapi_server['last_good'], is_connected, is_main_server))

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
        # NOTE(typing) signals are not handled properly by Pyright
        td.found_proxy.connect(self._suggest_proxy) # type: ignore
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
                # NOTE(typing) signals are not handled properly by Pyright
                self.found_proxy.emit(pair) # type: ignore
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
    def __init__(self, wizard=False) -> None:
        super().__init__()
        self._tor_proxy = None
        self._filling_in = False

        self._blockchain_tab = BlockchainTab(self)
        self._servers_tab = ServersTab(self)
        self._proxy_tab = ProxyTab()

        self._tabs = QTabWidget()
        self._tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self._tabs.addTab(self._blockchain_tab, _('Blockchain Status'))
        self._tabs.addTab(self._servers_tab, _('Servers'))
        self._tabs.addTab(self._proxy_tab, _('Proxy'))

        if wizard:
            self._tabs.setCurrentIndex(1)

        self.addWidget(self._tabs)
        self.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        self._proxy_tab.set_tor_detector()
        self.last_values = None

    def follow_server(self, server: SVServer, auto_connect: bool) -> None:
        network = cast(Network, app_state.daemon.network)
        network.set_server(server, auto_connect)
        # This updates the blockchain tab too.
        self._servers_tab.update_servers()


class NetworkDialog(QDialog):
    network_updated_signal = pyqtSignal()

    def __init__(self) -> None:
        super().__init__(flags=Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint))
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 200)
        self.resize(560, 400)

        self._tabs_layout = NetworkTabsLayout()
        self._buttons_layout = Buttons(CloseButton(self))
        self._buttons_layout.add_left_button(HelpDialogButton(self, "misc", "network-dialog"))

        vbox = QVBoxLayout(self)
        vbox.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        vbox.addLayout(self._tabs_layout)
        vbox.addLayout(self._buttons_layout)

        # The following event registrations cover what should be the full scope of keeping the
        # list up to date, both main server status and the existence of which servers the
        # application is connected to.
        # NOTE(typing) signals are not handled properly by Pyright
        self.network_updated_signal.connect(self._event_network_updated) # type: ignore

        # 'update': possible main server change.
        # 'sessions': a session is either opened or closed.
        network = cast(Network, app_state.daemon.network)
        network.register_callback(self._event_network_callbacks, ['updated', 'sessions'])

    def _event_network_callbacks(self, event, *args):
        # This may run in network thread??
        # NOTE(typing) signals are not handled properly by Pyright
        self.network_updated_signal.emit() # type: ignore

    def _event_network_updated(self):
        # This always runs in main GUI thread.
        self._tabs_layout._servers_tab.update_servers()


class URLValidator(QValidator):
    _last_message: str = ""

    def __init__(self, parent: Optional[QObject]=None, schemes: Optional[set[str]]=None) -> None:
        super().__init__(parent)

        self._schemes = schemes

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
            text = validate_url(text, schemes=self._schemes, host_only=True)
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

