from __future__ import annotations
from typing import Callable, cast, TYPE_CHECKING
import concurrent.futures, urllib.parse, weakref

from PyQt6.QtCore import pyqtSignal, QObject
from PyQt6.QtWidgets import QLabel, QLineEdit, QPushButton, QVBoxLayout

from ...app_state import app_state
from ...constants import NetworkServerFlag
from ...exceptions import ServerConnectionError
from ...i18n import _
from ...logs import logs
from ...network_support.bitcache_protocol import add_external_bitcache_connection_async, \
    create_peer_channel_for_bitcache_async
from ...network_support.exceptions import GeneralAPIError
from ...wallet_database.types import PeerChannelAccessTokenRow, ServerPeerChannelRow

from . import server_required_dialog
from .main_window import ElectrumWindow
from .util import Buttons, CancelButton, FormSectionWidget, WindowModalDialog

if TYPE_CHECKING:
    from ...wallet import Wallet

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

        def event_peer_channel_creation_done(future: concurrent.futures.Future[
                tuple[ServerPeerChannelRow, PeerChannelAccessTokenRow]]) -> None:
            """
            `run_coro` ensures this callback happens on GUI thread. Result will implicitly be
            ready and no blocking should occur waiting for it.
            """
            try:
                peer_channel_row, write_access_token_row = future.result()
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
