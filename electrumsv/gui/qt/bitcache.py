from __future__ import annotations
import concurrent.futures, enum, urllib.parse, weakref
from functools import partial
from typing import Callable, cast, TYPE_CHECKING

from PyQt6.QtCore import pyqtSignal, QObject, QPoint, Qt
from PyQt6.QtWidgets import QCheckBox, QLabel, QLineEdit, QMenu, QPlainTextEdit, QPushButton, \
    QTreeWidgetItem, QVBoxLayout, QWidget

from ...app_state import app_state
from ...constants import NetworkServerFlag, ChannelAccessTokenFlag, TokenPermissions
from ...exceptions import ServerConnectionError
from ...i18n import _
from ...logs import logs
from ...network_support.bitcache_protocol import add_external_bitcache_connection_async, \
    create_peer_channel_for_bitcache_async
from ...network_support.peer_channel import create_peer_channel_api_token_async, \
    delete_peer_channel_api_token_async
from ...network_support.exceptions import GeneralAPIError
from ...wallet import AbstractAccount
from ...wallet_database.types import ChannelAccessTokenRow, ServerPeerChannelRow

from . import server_required_dialog
from .main_window import ElectrumWindow
from .util import Buttons, CancelButton, FormSectionWidget, MyTreeWidget, OkButton, \
    WindowModalDialog

if TYPE_CHECKING:
    from ...network_support.types import ServerConnectionState
    from ...wallet import Wallet, WalletDataAccess

logger = logs.get_logger("ui.bitcache")


class BitcacheThinger(QObject):
    success_signal = pyqtSignal(int, object)

    # Shared state accessed by all instances on the GUI thread.
    currently_creating: set[int] = set()

    def __init__(self, main_window: ElectrumWindow) -> None:
        self._main_window_proxy = cast(ElectrumWindow, weakref.proxy(main_window))
        super().__init__()

    def create_bitcache_peer_channel(self, wallet: Wallet, account_id: int) -> None:
        """
        Via `create_peer_channel_for_bitcache_async`:
            Raises `GeneralAPIError` if connection established but request unsuccessful.
            Raises `ServerConnectionError` if remote computer does not accept connection.
        """
        if account_id in self.currently_creating:
            self._main_window_proxy.show_warning(_("Already creating a new bitcache for this "
                "account."), parent=self._main_window_proxy.reference(),
                title=_("Already in progress"))
            return

        def event_peer_channel_creation_done(
                future: concurrent.futures.Future[ServerPeerChannelRow]) -> None:
            """
            `run_coro` ensures this callback happens on GUI thread. Result will implicitly be
            ready and no blocking should occur waiting for it.
            """
            try:
                peer_channel_row = future.result()
            except GeneralAPIError:
                logger.exception("TODO handle this")
                raise
            except ServerConnectionError:
                logger.exception("TODO handle this")
                raise
            else:
                self.success_signal.emit(account_id, peer_channel_row)
            finally:
                self.currently_creating.remove(account_id)

        self.currently_creating.add(account_id)
        app_state.app.run_coro(create_peer_channel_for_bitcache_async(wallet, account_id),
            on_done=event_peer_channel_creation_done)


def show_server_registration_dialog(main_window: ElectrumWindow, wallet: Wallet,
        callback: Callable[[], None]) -> bool:
    # The whole point of direct connection is that you connect over peer channels.
    # The message box services are peer channels.
    required_flags = NetworkServerFlag.USE_MESSAGE_BOX
    if wallet.have_wallet_servers(required_flags):
        callback()
        return False

    dialog_text = _("Making a new bitcache for this account requires signing up "
        "with a message box service, which will be used for the creation of any new bitcaches "
        "including this one."
        "<br/><br/>"
        "This wallet has not yet been set up to use the required service. If you run your "
        "own servers or wish to use third party servers, choose the 'Manage servers' "
        "option.")

    server_dialog = server_required_dialog.ServerRequiredDialog(main_window, wallet,
        NetworkServerFlag.USE_MESSAGE_BOX, dialog_text)
    # There are two paths to the user accepting this dialog:
    # - They checked "select servers on my behalf" then the OK buton and then servers were
    #   selected and connected to.
    # - They chose "Manage servers" which selected and connected to servers and then on exit
    #   from that wizard this dialog auto-accepted.
    server_dialog.accepted.connect(callback)
    server_dialog.show()
    return True

def show_connection_dialog(main_window: ElectrumWindow, wallet: Wallet, account_id: int) -> None:
    # TODO: Assert account does not have one.
    title = _("Connect account to bitcache")
    dialog = WindowModalDialog(main_window, title)

    vbox = QVBoxLayout()
    description_label = QLabel(_("You are here to connect this account to an existing external "
        "bitcache. In order to do this, you should have the URL and an access token."))
    description_label.setMinimumWidth(400)
    description_label.setWordWrap(True)
    vbox.addWidget(description_label)

    cancel_button = CancelButton(dialog)
    ok_button = QPushButton(_("Connect"), dialog)
    ok_button.setEnabled(False)

    def validate(url_text: str, token_text: str) -> None:
        nonlocal ok_button
        url_valid = False
        try:
            parsed_url = urllib.parse.urlparse(url_text)
        except ValueError:
            url_valid = True
        else:
            url_valid = parsed_url.scheme in ("http", "https")
            url_valid = url_valid and bool(parsed_url.netloc) # domain name
            url_valid = url_valid and bool(parsed_url.path)   # channel path
        token_valid = bool(token_text)
        ok_button.setEnabled(url_valid and token_valid)

    form = FormSectionWidget()
    url_edit = QLineEdit()
    token_edit = QLineEdit()
    def url_edit_changed(url_text: str) -> None:
        nonlocal token_edit; validate(url_text, token_edit.text())
    url_edit.textChanged.connect(url_edit_changed)
    form.add_row(_("URL"), url_edit)
    def token_edit_changed(token_text: str) -> None:
        nonlocal url_edit; validate(url_edit.text(), token_text)
    token_edit.textChanged.connect(token_edit_changed)
    form.add_row(_("API key"), token_edit)
    vbox.addWidget(form)

    def gui_callback_connect(future: concurrent.futures.Future[None]) -> None:
        nonlocal dialog, main_window, ok_button
        try:
            future.result()
        except GeneralAPIError:
            main_window.show_error(_("This server is incompatible."))
            ok_button.setEnabled(True)
        except ServerConnectionError:
            main_window.show_error(_("Unable to connect to server."))
            ok_button.setEnabled(True)
        else:
            dialog.accept()

    def on_ok_clicked() -> None:
        nonlocal dialog
        ok_button.setEnabled(False)
        app_state.app.run_coro(add_external_bitcache_connection_async(wallet, account_id,
            url_edit.text(), token_edit.text()), on_done=gui_callback_connect)

    ok_button.clicked.connect(on_ok_clicked)
    vbox.addLayout(Buttons(cancel_button, ok_button))

    dialog.setLayout(vbox)
    dialog.show()


class AccessColumn(enum.IntEnum):
    DETAILS     = 0
    RIGHTS      = 1


class AccessTokenList(MyTreeWidget):
    filter_columns = [ AccessColumn.DETAILS ]

    def __init__(self, parent: QWidget, main_window: ElectrumWindow, account_id: int) -> None:
        self._main_window = weakref.proxy(main_window)
        self._parent_widget = parent
        self._account_id: int = account_id
        account = main_window._wallet.get_account(account_id)
        assert account is not None
        self._account = account

        self._logger = logs.get_logger("request-list")

        MyTreeWidget.__init__(self, parent, main_window, self.create_menu, [ _('Note'),
            _('Access') ], stretch_column=AccessColumn.DETAILS,
            editable_columns=[AccessColumn.DETAILS])

        self.itemDoubleClicked.connect(self._on_item_double_clicked)
        self.setSortingEnabled(True)
        self.update()

    def _on_item_double_clicked(self, item: QTreeWidgetItem) -> None:
        if item is None: return
        if not item.isSelected(): return
        token_row = cast(ChannelAccessTokenRow, item.data(0, Qt.ItemDataRole.UserRole))
        show_view_token_dialog(self._parent_widget, self, token_row)

    def on_edited(self, item: QTreeWidgetItem, column: int, prior_text: str) -> None:
        '''Called only when the text actually changes'''
        text = item.text(column).strip()
        print("edited text", text)

    def on_update(self) -> None:
        # This is currently triggered by events like `WalletEvent.TRANSACTION_ADD` from the main
        # window.
        if self._account_id is None: return
        assert self._account is not None
        wallet = self._account._wallet
        channel_id = self._account.get_row().bitcache_peer_channel_id
        assert channel_id is not None
        self.clear()
        items: list[QTreeWidgetItem] = []
        for row in wallet.data.read_server_peer_channel_access_tokens(channel_id,
                ChannelAccessTokenFlag.FOR_THIRD_PARTY_USAGE):
            perms: list[str] = []
            if row.permission_flags & TokenPermissions.READ_ACCESS: perms.append(_("read"))
            if row.permission_flags & TokenPermissions.WRITE_ACCESS: perms.append(_("write"))
            item = QTreeWidgetItem([ row.description, "/".join(perms) ])
            item.setData(0, Qt.ItemDataRole.UserRole, row)
            items.append(item)
        self.addTopLevelItems(items)

    def create_menu(self, position: QPoint) -> None:
        item = self.itemAt(position)
        if not item: return
        token_row = cast(ChannelAccessTokenRow, item.data(0, Qt.ItemDataRole.UserRole))

        menu = QMenu()
        menu.addAction(_("View token"), cast(Callable[[], None],
            partial(show_view_token_dialog, self._parent_widget, self, token_row)))
        menu.exec(self.viewport().mapToGlobal(position))


def show_view_token_dialog(parent_dialog: WindowModalDialog, list_widget: AccessTokenList,
        token_row: ChannelAccessTokenRow) -> None:
    wallet = list_widget._account._wallet
    wallet_data = wallet.data
    channel_rows = wallet.data.read_server_peer_channels(channel_id=token_row.peer_channel_id)
    assert len(channel_rows) == 1
    channel_row = channel_rows[0]
    assert channel_row.remote_url is not None
    server_state = wallet.get_connection_state_for_usage(NetworkServerFlag.USE_MESSAGE_BOX)
    assert server_state is not None

    title = _("View token")
    dialog = WindowModalDialog(parent_dialog, title)
    vbox = QVBoxLayout()
    form = FormSectionWidget()
    form.add_row(_("Note"), QLabel(token_row.description))
    dialog.setLayout(vbox)
    access_vbox = QVBoxLayout()
    read_checkbox = QCheckBox(_("Read"))
    read_checkbox.setCheckState(
        Qt.CheckState.Checked if token_row.permission_flags & TokenPermissions.READ_ACCESS
        else Qt.CheckState.Unchecked)
    read_checkbox.setEnabled(False)
    access_vbox.addWidget(read_checkbox)
    write_checkbox = QCheckBox(_("Write"))
    write_checkbox.setCheckState(
        Qt.CheckState.Checked if token_row.permission_flags & TokenPermissions.WRITE_ACCESS
        else Qt.CheckState.Unchecked)
    write_checkbox.setEnabled(False)
    access_vbox.addWidget(write_checkbox)
    form.add_row(_("Access"), access_vbox)
    vbox.addWidget(form)
    url_edit = QPlainTextEdit(channel_row.remote_url)
    url_edit.setReadOnly(True)
    url_edit.setMaximumHeight(90)
    url_edit.setMaximumWidth(400)
    form.add_row(_("Channel URL"), url_edit)
    token_edit = QPlainTextEdit(token_row.access_token)
    token_edit.setReadOnly(True)
    token_edit.setMaximumHeight(90)
    token_edit.setMaximumWidth(400)
    form.add_row(_("Access token"), token_edit)
    revoke_button = QPushButton(_("Revoke"))
    cancel_button = CancelButton(dialog, _("Close"))
    buttons = Buttons(revoke_button, cancel_button)
    vbox.addLayout(buttons)
    dialog.setLayout(vbox)
    async def revoke_token_async() -> None:
        nonlocal channel_row, server_state, token_row, wallet_data
        assert channel_row.peer_channel_id is not None
        await delete_peer_channel_api_token_async(server_state,
            cast(str, channel_row.remote_channel_id), token_row.remote_id)
        await wallet_data.delete_server_channel_access_tokens_async([
            (channel_row.peer_channel_id, token_row.remote_id)])
    def event_revoke_done(future: concurrent.futures.Future[None]) -> None:
        """ Callback on GUI thread via `run_coro(on_done=)`. """
        nonlocal dialog
        try:
            future.result()
        except GeneralAPIError as exc1:
            dialog.show_error(_("Problem on server: {}").format(str(exc1)))
        except ServerConnectionError as exc2:
            dialog.show_error(_("Server connection problem: {}").format(str(exc2)))
        else:
            dialog.accept()
    def on_revoke_clicked() -> None:
        app_state.app.run_coro(revoke_token_async(), on_done=event_revoke_done)
    revoke_button.clicked.connect(on_revoke_clicked)
    dialog.accepted.connect(list_widget.update)
    dialog.show()

def show_add_token_dialog(parent_dialog: WindowModalDialog, wallet_data: WalletDataAccess,
        messagebox_server: ServerConnectionState, channel_id: int) -> WindowModalDialog:
    title = _("Add new token")
    dialog = WindowModalDialog(parent_dialog, title)
    vbox = QVBoxLayout()
    form = FormSectionWidget()
    edit_widget = QLineEdit()
    form.add_row(_("Note"), edit_widget)
    access_vbox = QVBoxLayout()
    read_checkbox = QCheckBox(_("Read"))
    read_checkbox.setCheckState(Qt.CheckState.Checked)
    access_vbox.addWidget(read_checkbox)
    write_checkbox = QCheckBox(_("Write"))
    write_checkbox.setCheckState(Qt.CheckState.Unchecked)
    access_vbox.addWidget(write_checkbox)
    form.add_row(_("Access to grant"), access_vbox)
    vbox.addWidget(form)
    add_button = QPushButton(_("Add"))
    cancel_button = CancelButton(dialog, _("Close"))
    buttons = Buttons(add_button, cancel_button)
    vbox.addLayout(buttons)
    dialog.setLayout(vbox)
    async def create_new_token_async(can_read: bool, can_write: bool, description: str) -> None:
        nonlocal channel_id, messagebox_server, wallet_data
        channel_rows = wallet_data.read_server_peer_channels(channel_id=channel_id)
        assert len(channel_rows) == 1
        assert channel_rows[0].remote_channel_id is not None
        new_token_dict = await create_peer_channel_api_token_async(messagebox_server,
            channel_rows[0].remote_channel_id, can_read, can_write, description)
        permissions = TokenPermissions.READ_ACCESS if can_read else TokenPermissions.NONE
        permissions |= TokenPermissions.WRITE_ACCESS if can_write else TokenPermissions.NONE
        remote_id = new_token_dict["id"]
        assert type(remote_id) is int
        new_tokens = [ ChannelAccessTokenRow(remote_id, channel_id,
            ChannelAccessTokenFlag.FOR_THIRD_PARTY_USAGE, permissions, new_token_dict["token"],
            description) ]
        await wallet_data.create_server_channel_access_tokens_async(new_tokens)
    def event_token_creation_done(future: concurrent.futures.Future[None]) -> None:
        """ Callback on GUI thread via `run_coro(on_done=)`. """
        nonlocal dialog
        try:
            future.result()
        except GeneralAPIError as exc1:
            dialog.show_error(_("Problem on server: {}").format(str(exc1)))
        except ServerConnectionError as exc2:
            dialog.show_error(_("Server connection problem: {}").format(str(exc2)))
        else:
            dialog.accept()
    def on_add_clicked() -> None:
        nonlocal dialog, edit_widget, read_checkbox, wallet_data, write_checkbox
        description = edit_widget.text().strip()
        if description == "":
            dialog.show_error(_("Description required"))
            return
        can_read = read_checkbox.checkState() == Qt.CheckState.Checked
        if not can_read:
            dialog.show_error(_("Tokens must have at least read access."))
            return
        can_write = write_checkbox.checkState() == Qt.CheckState.Checked
        app_state.app.run_coro(create_new_token_async(can_read, can_write, description),
            on_done=event_token_creation_done)
    add_button.clicked.connect(on_add_clicked)
    dialog.show()
    return dialog

def show_access_dialog(main_window: ElectrumWindow, wallet: Wallet, account_id: int) -> None:
    account = cast(AbstractAccount, wallet.get_account(account_id))
    channel_id = cast(int, account.get_row().bitcache_peer_channel_id)
    wallet_data = wallet.data
    server_state = wallet.get_connection_state_for_usage(NetworkServerFlag.USE_MESSAGE_BOX)
    assert server_state is not None

    title = _("Manage bitcache access")
    dialog = WindowModalDialog(main_window, title)
    vbox = QVBoxLayout()
    form = FormSectionWidget()
    form.add_row(_("Account"), QLabel(account.display_name()))
    vbox.addWidget(form)
    vbox.addWidget(QLabel(_("Active access tokens")), Qt.AlignmentFlag.AlignHCenter)
    token_list = AccessTokenList(dialog, main_window, account_id)
    vbox.addWidget(token_list)
    add_button = QPushButton(_("Add new"))
    def on_add_clicked() -> None:
        nonlocal channel_id, dialog, main_window, token_list, wallet_data
        token_dialog = show_add_token_dialog(dialog, wallet_data, server_state, channel_id)
        token_dialog.accepted.connect(token_list.update)
    add_button.clicked.connect(on_add_clicked)
    close_button = OkButton(dialog, _("Close"))
    buttons = Buttons(close_button)
    buttons.add_left_button(add_button)
    vbox.addLayout(buttons)
    dialog.setLayout(vbox)
    dialog.show()
