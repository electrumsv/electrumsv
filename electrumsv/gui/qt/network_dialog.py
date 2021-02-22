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
import enum
import socket
from collections import namedtuple
from typing import List, Optional, Tuple

from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTabWidget, QSizePolicy, QWidget, QTreeWidget, \
    QTreeWidgetItem, QHeaderView, QLabel, QCheckBox, QComboBox, QLineEdit, QGridLayout, QMessageBox, \
    QMenu, QDialogButtonBox, QFormLayout
from PyQt5.QtCore import pyqtSignal, Qt, QThread
from aiorpcx import NetAddress
from bitcoinx import hash_to_hex_str

from electrumsv.app_state import app_state
from electrumsv.constants import BroadcastServicesUI, BroadcastServices
from electrumsv.gui.qt.password_dialog import PasswordLineEdit
from electrumsv.gui.qt.table_widgets import AddOrEditButtonsLayout
from electrumsv.logs import logs
from electrumsv.network import Network, SVUserAuth, SVProxy, SVSession
from electrumsv.gui.qt.util import Buttons, CloseButton, HelpDialogButton, FormSectionWidget, \
    HelpButton, read_QIcon, IconButton, MessageBox
from electrumsv.i18n import _

ITEM_DATA_ROLE = Qt.UserRole
URL_DATA_ROLE = Qt.UserRole + 1

logger = logs.get_logger("network-ui")

COMBOBOX_INDEX_MAP = {
    BroadcastServices.ELECTRUMX: 0,
    BroadcastServices.MERCHANT_API: 1
}

SERVER_STATUS_ICONS = [
    "icons8-checkmark-green-52.png",  # Connected.
    "red-cross.png",    # Disconnected.
]


class ServerStatus(enum.IntEnum):
    CONNECTED = 0
    DISCONNECTED = 1


SERVER_STATUS = {
    ServerStatus.CONNECTED: _('Connected'),
    ServerStatus.DISCONNECTED: _('Disconnected'),
}


ServerItem = namedtuple('ServerItem',
    ['status_icon', 'server_name', 'api_type', 'child_items'])
MERCHANT_API_CAPABILITIES = ('BROADCAST', 'FEE_QUOTE')
ELECTRUMX_CAPABILITIES = ('SCRIPTHASH_HISTORY', 'BROADCAST', 'REQUEST_MERKLE_PROOF')


class NodesListWidget(QTreeWidget):

    def __init__(self, parent: 'NetworkTabsLayout'):
        QTreeWidget.__init__(self)
        self.parent = parent
        self.setHeaderLabels([_('Connected node'), _('Height')])
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.create_menu)

    def create_menu(self, position):
        item = self.currentItem()
        if not item:
            return
        server = item.data(0, Qt.UserRole)
        if not server:
            return

        def use_as_server():
            try:
                self.parent.follow_server(server)
            except Exception as e:
                MessageBox.show_error(str(e))
        menu = QMenu()
        menu.addAction(_("Use as server"), use_as_server)
        menu.exec_(self.viewport().mapToGlobal(position))

    def keyPressEvent(self, event):
        if event.key() in [ Qt.Key_F2, Qt.Key_Return ]:
            self.on_activated(self.currentItem(), self.currentColumn())
        else:
            QTreeWidget.keyPressEvent(self, event)

    def on_activated(self, item, column):
        # on 'enter' we show the menu
        pt = self.visualItemRect(item).bottomLeft()
        pt.setX(50)
        self.customContextMenuRequested.emit(pt)

    def chain_name(self, chain, our_chain):
        if chain is our_chain:
            return f'our_chain'

        _chain, common_height = our_chain.common_chain_and_height(chain)
        fork_height = common_height + 1
        headers_obj = app_state.headers
        header = headers_obj.header_at_height(chain, fork_height)
        prefix = hash_to_hex_str(header.hash).lstrip('00')[0:10]
        return f'{prefix}@{fork_height}'

    def update(self, network):
        self.clear()
        chains = network.sessions_by_chain()
        our_chain = network.chain()
        for chain, sessions in chains.items():
            if len(chains) > 1:
                name = self.chain_name(chain, our_chain)
                x = QTreeWidgetItem([name, '%d' % chain.height])
                x.setData(0, Qt.UserRole, None)  # server
            else:
                x = self
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
                item.setData(0, Qt.UserRole, session.server)
                x.addTopLevelItem(item)
            if len(chains) > 1:
                self.addTopLevelItem(x)
                x.setExpanded(True)

            height_str = "%d "%(network.get_local_height()) + _('blocks')
            self.parent.height_label.setText(height_str)
            n = len(network.sessions)
            status = _("Connected to {:d} servers.").format(n) if n else _("Not connected")
            self.parent.status_label.setText(status)
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
            self.parent.split_label.setText(msg)
            self.parent.server_label.setText(network.main_server.host)

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Stretch)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)


class BlockchainTab(QWidget):

    def __init__(self, parent: 'NetworkTabsLayout'):
        super().__init__()
        self.parent = parent
        blockchain_layout = QVBoxLayout(self)

        form = FormSectionWidget()
        self.status_label = QLabel('')
        form.add_row(_('Status'), self.status_label, True)
        self.server_label = QLabel('')
        form.add_row(_('Server'), self.server_label, True)
        self.height_label = QLabel('')
        form.add_row(_('Blockchain'), self.height_label, True)

        blockchain_layout.addWidget(form)

        self.split_label = QLabel('')
        form.add_row(QLabel(""), self.split_label)

        self.nodes_list_widget = NodesListWidget(self)
        blockchain_layout.addWidget(self.nodes_list_widget)
        blockchain_layout.addStretch(1)
        self.nodes_list_widget.update(self.parent.network)


class EditServerDialog(QDialog):
    """Two modes: edit_mode=True and edit_mode=False"""

    def __init__(self, parent: 'ServersTab', title: str, edit_mode: bool=False):
        super().__init__()
        self.parent = parent
        self.servers_list = self.parent.servers_list
        self._is_edit_mode = edit_mode

        # Internal State -> see self.update_state()
        current_item: Optional[QTreeWidgetItem] = self.servers_list.get_current_item()
        self._selected_server: Optional['ServerItem'] = None
        self._server_url: Optional[str] = None
        self._server_type = None

        if current_item and self._is_edit_mode:
            self._selected_server: 'ServerItem' = current_item.data(0, ITEM_DATA_ROLE)
            self._server_url: str = current_item.data(0, URL_DATA_ROLE)
            server_type = BroadcastServices.from_ui_display_format(self._selected_server.api_type)
            self._server_type = server_type

        self.setWindowTitle(title)
        self.resize(380, 170)

        self._vbox = QVBoxLayout(self)
        self._form_layout = QFormLayout()

        self.row1 = QLabel(_("API Type:"))
        self.serverTypeCombobox = QComboBox()
        self.serverTypeCombobox.addItem(BroadcastServicesUI.ELECTRUMX)
        self.serverTypeCombobox.addItem(BroadcastServicesUI.MERCHANT_API)
        if self._server_type:
            self.serverTypeCombobox.setCurrentIndex(COMBOBOX_INDEX_MAP[self._server_type])
        self.serverTypeCombobox.currentIndexChanged.connect(self.on_server_type_changed)

        self.row2 = QLabel(_("URL:"))
        field2 = QLineEdit()
        if self._is_edit_mode:
            field2.setText(self._server_url)

        okay_cancel_button = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        self._form_layout.addRow(self.row1, self.serverTypeCombobox)
        self._form_layout.addRow(self.row2, field2)

        self.row3 = None
        if self._server_type == BroadcastServices.MERCHANT_API:
            self.row3 = QLabel("API Key:")
            self._mapi_api_key = QLineEdit()
            self._form_layout.addRow(self.row3, self._mapi_api_key)

        self._vbox.addLayout(self._form_layout)
        self._vbox.addWidget(okay_cancel_button)

        self.update_state()

    def update_state(self):
        """redraw to include / exclude the API Key field for Merchant API type server"""
        if self._server_type == BroadcastServices.MERCHANT_API and not self.row3:
            self.row3 = QLabel("API Key:")
            self._mapi_api_key = QLineEdit()
            self._form_layout.addRow(self.row3, self._mapi_api_key)
            self._vbox.update()

        elif not self._server_type == BroadcastServices.MERCHANT_API and self.row3:
            self.row3 = None
            self._form_layout.removeRow(2)

        self.update()

    def on_server_type_changed(self):
        self._server_type = BroadcastServices.from_ui_display_format(
            self.serverTypeCombobox.currentText())
        self.update_state()


class ServersListWidget(QTreeWidget):

    def __init__(self, parent: 'NetworkTabsLayout'):
        QTreeWidget.__init__(self)
        self.parent = parent
        self.headers = ['', _('Service Name'), _('API Type')]
        self.update_headers()

    def update_headers(self):
        self.setColumnCount(len(self.headers))
        self.setHeaderLabels(self.headers)
        self.header().setStretchLastSection(False)
        for col in range(len(self.headers)):
            sm = QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col, sm)

    def update(self, items):
        self.clear()
        for service, url in items:
            parent = QTreeWidgetItem(["", service[1], service[2]])
            parent.setIcon(0, service[0])
            parent.setData(0, ITEM_DATA_ROLE, service)
            parent.setData(0, URL_DATA_ROLE, url)

            lvl1_indent = " " * 4
            lvl2_indent = " " * 8
            child_lvl1 = QTreeWidgetItem(["", lvl1_indent+"capabilities"])
            parent.addChild(child_lvl1)
            capabilities: List[str] = service[len(service) - 1]
            if capabilities:
                for capability in capabilities:
                    child_lvl2 = QTreeWidgetItem(["", lvl2_indent+capability])
                    child_lvl1.addChild(child_lvl2)

            self.addTopLevelItem(parent)

        h = self.header()
        h.setStretchLastSection(False)
        h.setSectionResizeMode(0, QHeaderView.Fixed)
        h.setSectionResizeMode(1, QHeaderView.ResizeToContents)

    def get_current_item(self):
        return self.currentItem()

    def set_current_item(self, item: QTreeWidgetItem):
        return self.setCurrentItem(item)

    def add_item(self):
        pass


class ServersTab(QWidget):

    def __init__(self, parent: 'NetworkTabsLayout'):
        super().__init__()
        self.parent = parent
        self.config = self.parent.config
        self.network = self.parent.network
        grid = QGridLayout(self)
        grid.setSpacing(8)

        self.help_text = ' '.join([
            _("This is a high-level overview of the servers that ElectrumSV depends upon. "
              "You can add, remove or edit the entries via the buttons to the left.")
        ])
        help_icon_button = IconButton("icons8-info-80-blueui.png", self._show_help, tooltip="help")
        grid.addWidget(help_icon_button, 0, 4)

        self._top_button_layout = AddOrEditButtonsLayout()
        self._top_button_layout.add_signal.connect(self._on_add_server_button_clicked)
        self._top_button_layout.edit_signal.connect(self._on_edit_server_button_clicked)
        grid.addLayout(self._top_button_layout, 0, 0)
        self.servers_list = ServersListWidget(self)
        grid.addWidget(self.servers_list, 2, 0, 1, 5)
        self.update_servers()

    def _show_help(self) -> None:
        b = QMessageBox()
        b.setIcon(QMessageBox.Information)
        b.setTextFormat(Qt.AutoText)
        b.setText(self.help_text)
        b.setWindowTitle("Help")
        b.exec()

    def _get_server_status_icon(self, status: ServerStatus):
        return read_QIcon(SERVER_STATUS_ICONS[status])

    def _on_add_server_button_clicked(self):
        dialogue = EditServerDialog(self, title="Add Server")
        dialogue.exec()

    def _on_edit_server_button_clicked(self):
        dialogue = EditServerDialog(self, title="Edit Server", edit_mode=True)
        dialogue.exec()

    def update_servers(self):
        items: List[Tuple[ServerItem, str]] = []  # second type is full url

        # Add ElectrumX items
        api_type = BroadcastServices.to_ui_display_format(BroadcastServices.ELECTRUMX)
        sessions = self.network.sessions
        if sessions:
            max_tip_height = max([session.tip.height for session in sessions])

            for session in sessions:
                session: SVSession
                server = session.server
                is_more_than_two_blocks_behind = max_tip_height > session.tip.height + 2
                if server.state.last_good >= server.state.last_try and not \
                        is_more_than_two_blocks_behind:
                    status_icon = self._get_server_status_icon(ServerStatus.CONNECTED)
                else:
                    status_icon = self._get_server_status_icon(ServerStatus.DISCONNECTED)
                server_name = server.host
                child_items = ELECTRUMX_CAPABILITIES
                server_item = ServerItem(status_icon, server_name, api_type, child_items)
                url = f"tcp://" if server.protocol == "t" else "ssl://" + \
                      f"{server.host}:{server.port}"
                items.append((server_item, url))

        # Add mAPI items
        api_type = BroadcastServices.to_ui_display_format(BroadcastServices.MERCHANT_API)
        for mapi_server in self.network.get_mapi_servers():
            if mapi_server['last_good'] == mapi_server['last_try']:
                status_icon = self._get_server_status_icon(ServerStatus.CONNECTED)
            else:
                status_icon = self._get_server_status_icon(ServerStatus.DISCONNECTED)
            server_name = mapi_server['uri']

            child_items = MERCHANT_API_CAPABILITIES
            server_item = ServerItem(status_icon, server_name, api_type, child_items)
            items.append((server_item, mapi_server['uri']))

        self.servers_list.update(items)
        self.parent.blockchain_tab.nodes_list_widget.update(self.network)
        self.enable_set_broadcast_service()

    def enable_set_broadcast_service(self):
        if self.config.is_modifiable('broadcast_service'):
            self.servers_list.setEnabled(True)
        else:
            self.servers_list.setEnabled(False)


class ProxyTab(QWidget):

    def __init__(self, parent: 'NetworkTabsLayout'):
        super().__init__()
        self.parent = parent
        self.config = self.parent.config
        self.network = self.parent.network

        grid = QGridLayout(self)
        grid.setSpacing(8)

        # proxy setting
        self.proxy_cb = QCheckBox(_('Use proxy'))
        self.proxy_cb.clicked.connect(self.check_disable_proxy)
        self.proxy_cb.clicked.connect(self.set_proxy)

        self.proxy_mode = QComboBox()
        self.proxy_mode.addItems(list(SVProxy.kinds))
        self.proxy_host = QLineEdit()
        self.proxy_host.setFixedWidth(200)
        self.proxy_port = QLineEdit()
        self.proxy_port.setFixedWidth(100)
        self.proxy_username = QLineEdit()
        self.proxy_username.setPlaceholderText(_("Proxy user"))
        self.proxy_username.setFixedWidth(self.proxy_host.width())
        self.proxy_password = PasswordLineEdit()
        self.proxy_password.setPlaceholderText(_("Password"))

        self.proxy_mode.currentIndexChanged.connect(self.set_proxy)
        self.proxy_host.editingFinished.connect(self.set_proxy)
        self.proxy_port.editingFinished.connect(self.set_proxy)
        self.proxy_username.editingFinished.connect(self.set_proxy)
        self.proxy_password.editingFinished.connect(self.set_proxy)

        self.proxy_mode.currentIndexChanged.connect(self.proxy_settings_changed)
        self.proxy_host.textEdited.connect(self.proxy_settings_changed)
        self.proxy_port.textEdited.connect(self.proxy_settings_changed)
        self.proxy_username.textEdited.connect(self.proxy_settings_changed)
        self.proxy_password.textEdited.connect(self.proxy_settings_changed)

        self.tor_cb = QCheckBox(_("Use Tor Proxy"))
        self.tor_cb.setIcon(read_QIcon("tor_logo.png"))
        self.tor_cb.hide()
        self.tor_cb.clicked.connect(self.use_tor_proxy)

        grid.addWidget(self.tor_cb, 1, 0, 1, 3)
        grid.addWidget(self.proxy_cb, 2, 0, 1, 3)
        grid.addWidget(HelpButton(_('Proxy settings apply to all connections: both '
                                    'ElectrumSV servers and third-party services.')), 2, 4)
        grid.addWidget(self.proxy_mode, 4, 1)
        grid.addWidget(self.proxy_host, 4, 2)
        grid.addWidget(self.proxy_port, 4, 3)
        grid.addWidget(self.proxy_username, 5, 2, Qt.AlignTop)
        grid.addWidget(self.proxy_password, 5, 3, Qt.AlignTop)
        grid.setRowStretch(7, 1)

        self.fill_in_proxy_settings()

    def check_disable_proxy(self, b):
        if not self.config.is_modifiable('proxy'):
            b = False
        for w in [self.proxy_mode, self.proxy_host, self.proxy_port,
                  self.proxy_username, self.proxy_password]:
            w.setEnabled(b)

    def fill_in_proxy_settings(self):
        self.filling_in = True
        self.check_disable_proxy(self.network.proxy is not None)
        self.proxy_cb.setChecked(self.network.proxy is not None)
        proxy = self.network.proxy or SVProxy('localhost:9050', 'SOCKS5', None)
        self.proxy_mode.setCurrentText(proxy.kind())
        self.proxy_host.setText(proxy.host())
        self.proxy_port.setText(str(proxy.port()))
        self.proxy_username.setText(proxy.username())
        self.proxy_password.setText(proxy.password())
        self.filling_in = False

    def set_tor_detector(self):
        # tor detector
        self.td = td = TorDetector()
        td.found_proxy.connect(self.suggest_proxy)
        td.start()

    def set_protocol(self, protocol):
        if protocol != self.protocol:
            self.protocol = protocol

    def follow_server(self, server):
        self.network.set_server(server, self.network.auto_connect())
        self.blockchain_tab.nodes_list_widget.update(self.network)

    def set_proxy(self):
        if self.filling_in:
            return
        proxy = None
        if self.proxy_cb.isChecked():
            try:
                address = NetAddress(self.proxy_host.text(), self.proxy_port.text())
                if self.proxy_username.text():
                    auth = SVUserAuth(self.proxy_username.text(), self.proxy_password.text())
                else:
                    auth = None
                proxy = SVProxy(address, self.proxy_mode.currentText(), auth)
            except Exception:
                logger.exception('error setting proxy')
        if not proxy:
            self.tor_cb.setChecked(False)
        self.network.set_proxy(proxy)

    def suggest_proxy(self, found_proxy):
        self.tor_proxy = found_proxy
        self.tor_cb.setText("Use Tor proxy at port " + str(found_proxy[1]))
        if (self.proxy_cb.isChecked() and
                self.proxy_mode.currentText() == 'SOCKS5' and
                self.proxy_host.text() == found_proxy[0] and
                self.proxy_port.text() == str(found_proxy[1])):
            self.tor_cb.setChecked(True)
        self.tor_cb.show()

    def use_tor_proxy(self, use_it):
        if use_it:
            self.proxy_mode.setCurrentText('SOCKS5')
            self.proxy_host.setText(self.tor_proxy[0])
            self.proxy_port.setText(str(self.tor_proxy[1]))
            self.proxy_username.setText("")
            self.proxy_password.setText("")
            self.proxy_cb.setChecked(True)
        else:
            self.proxy_cb.setChecked(False)
        self.check_disable_proxy(use_it)
        self.set_proxy()

    def proxy_settings_changed(self):
        self.tor_cb.setChecked(False)


class TorDetector(QThread):
    found_proxy = pyqtSignal(object)

    def __init__(self):
        QThread.__init__(self)

    def run(self):
        # Probable ports for Tor to listen at
        ports = [9050, 9150]
        for p in ports:
            pair = ('localhost', p)
            if TorDetector.is_tor_port(pair):
                self.found_proxy.emit(pair)
                return

    @staticmethod
    def is_tor_port(pair):
        try:
            s = (socket._socketobject if hasattr(socket, "_socketobject")
                 else socket.socket)(socket.AF_INET, socket.SOCK_STREAM)
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

    def __init__(self, network, config, wizard=False):
        super().__init__()
        self.network = network
        self.config = config
        self.protocol = None
        self.tor_proxy = None
        self.filling_in = False

        self.blockchain_tab = BlockchainTab(self)
        self.servers_tab = ServersTab(self)
        self.proxy_tab = ProxyTab(self)

        self.tabs = QTabWidget()
        self.tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.tabs.addTab(self.blockchain_tab, _('Blockchain Status'))
        self.tabs.addTab(self.servers_tab, _('Servers'))
        self.tabs.addTab(self.proxy_tab, _('Proxy'))

        if wizard:
            self.tabs.setCurrentIndex(1)

        self.addWidget(self.tabs)
        self.setSizeConstraint(QVBoxLayout.SetFixedSize)
        self.proxy_tab.set_tor_detector()
        self.last_values = None

    def follow_server(self, server):
        self.network.set_server(server, self.network.auto_connect())
        self.blockchain_tab.nodes_list_widget.update(self.network)


class NetworkDialog(QDialog):
    network_updated_signal = pyqtSignal()

    def __init__(self, network: Network, config) -> None:
        super().__init__(flags=Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)
        self.setWindowTitle(_('Network'))
        self.setMinimumSize(500, 200)
        self.resize(560, 400)

        self._tabs_layout = NetworkTabsLayout(network, config)
        self._buttons_layout = Buttons(CloseButton(self))
        self._buttons_layout.add_left_button(HelpDialogButton(self, "misc", "network-dialog"))

        self.vbox = QVBoxLayout(self)
        self.vbox.setSizeConstraint(QVBoxLayout.SetFixedSize)
        self.vbox.addLayout(self._tabs_layout)
        self.vbox.addLayout(self._buttons_layout)

        self.network_updated_signal.connect(self.on_update)
        network.register_callback(self.on_network, ['updated', 'sessions'])

    def on_network(self, event, *args):
        ''' This may run in network thread '''
        self.network_updated_signal.emit()

    def on_update(self):
        ''' This always runs in main GUI thread '''
        self._tabs_layout.servers_tab.update_servers()

