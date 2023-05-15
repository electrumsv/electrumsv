from __future__ import annotations
import concurrent.futures
import re
from weakref import proxy

from bitcoinx import base58_decode_check, Base58Error

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QLabel, QLineEdit, QPushButton, QSpacerItem, \
    QVBoxLayout, QWidget

from ...app_state import app_state
from ...i18n import _
from ...constants import NetworkServerFlag
from ...contacts import IdentityCheckResult
from ...logs import logs
from ...network_support.direct_connection_protocol import ConnectionInvitationDict, \
    decode_invitation, import_contact_invitation_async
from ...wallet import Wallet

from .main_window import ElectrumWindow
from . import server_required_dialog
from .util import Buttons, CloseButton, FormSectionWidget, WindowModalDialog


logger = logs.get_logger("ui-connect")



def show_connect_dialog(main_window: ElectrumWindow, wallet: Wallet, parent: QWidget) -> None:
    def actually_show_connect_dialog() -> None:
        nonlocal main_window, parent, wallet
        connect_dialog = ConnectDialog(main_window, wallet, parent)
        connect_dialog.show()

    # The whole point of direct connection is that you connect over peer channels.
    # The message box services are peer channels.
    required_flags = NetworkServerFlag.USE_MESSAGE_BOX
    if wallet.have_wallet_servers(required_flags):
        actually_show_connect_dialog()
        return

    dialog_text = _("Responding to an invitation to connect with a contact requires signing up "
        "with a message box service, where the connection process will create a "
        "channel they can connect to you through on your message box service."
        "<br/><br/>"
        "This wallet has not been set up to use the required service. If you run your "
        "own servers or wish to use third party servers, choose the 'Manage servers' "
        "option.")

    server_dialog = server_required_dialog.ServerRequiredDialog(main_window, wallet,
        NetworkServerFlag.USE_MESSAGE_BOX, dialog_text)
    # There are two paths to the user accepting this dialog:
    # - They checked "select servers on my behalf" then the OK buton and then servers were
    #   selected and connected to.
    # - They chose "Manage servers" which selected and connected to servers and then on exit
    #   from that wizard this dialog auto-accepted.
    server_dialog.accepted.connect(actually_show_connect_dialog)
    server_dialog.show()


class ConnectDialog(QDialog):
    _invite_data = None
    _invite_was_valid = False

    def __init__(self, main_window: ElectrumWindow, wallet: Wallet, parent: QWidget) -> None:
        super().__init__(parent, Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint))

        # NOTE(proxytype-is-shitty) weakref.proxy does not return something that mirrors
        #     attributes. This means that everything accessed is an `Any` and we leak those
        #     and it introduces silent typing problems everywhere it touches.
        self._main_window_proxy: ElectrumWindow = proxy(main_window)
        self._wallet = wallet

        self.setWindowTitle(_("Connect to someone"))

        vbox = QVBoxLayout()
        # Ensure the size of the dialog is hard fixed to the space used by the widgets.
        vbox.setSizeConstraint(QVBoxLayout.SizeConstraint.SetFixedSize)
        # The fixed size constraint leaves no way to ensure a minimum width, so we use a spacer.
        vbox.addSpacerItem(QSpacerItem(400, 1))

        self._invite_label = QLabel(_("If you have received an invitation to connect with another "
            "ElectrumSV user, paste the large piece of text they sent you here."))
        self._invite_label.setWordWrap(True)

        self._invite_edit = QLineEdit()
        self._invite_edit.setPlaceholderText(_("Paste invitation details you have received here."))
        self._invite_edit.textChanged.connect(self._validate_form)

        self._name_edit = QLineEdit()
        self._name_edit.setPlaceholderText(_("The name you wish to use for the contact."))
        self._name_edit.textChanged.connect(self._validate_form)

        form2 = FormSectionWidget()
        form2.add_row(_("Their name"), self._name_edit)

        vbox.addWidget(self._invite_label)
        vbox.addWidget(self._invite_edit)
        vbox.addWidget(form2)

        self._connect_button = QPushButton(_("Connect"))
        self._connect_button.clicked.connect(self._event_connect_button_clicked)
        self._connect_button.setEnabled(False)

        buttons = Buttons(self._connect_button, CloseButton(self))
        self._buttons = buttons

        vbox.addLayout(self._buttons)
        self.setLayout(vbox)

        self._validate_form()

    def _set_validation_state(self, element: QWidget, is_valid: bool) -> None:
        if not is_valid:
            element.setStyleSheet("border: 1px solid red")
        else:
            element.setStyleSheet("")

    def _validate_form(self) -> None:
        invite_was_valid = self._invite_was_valid
        enable_connect_button = False

        # Locate the first base58 chunk and assume it's a possible invitation.
        invite_text = ""
        for word in re.split(r"[ \n\r\t]", self._invite_edit.text()):
            if len(word) > 50:
                try:
                    base58_decode_check(word)
                    invite_text = word
                    break
                except Base58Error:
                    continue

        invite_data = decode_invitation(invite_text)
        invite_is_valid = invite_data is not None
        self._invite_was_valid = invite_is_valid

        self._set_validation_state(self._invite_edit, invite_is_valid)

        name_is_valid = False
        if invite_is_valid:
            assert invite_data is not None
            self._invite_data = invite_data
            self._name_edit.setReadOnly(False)
            if not invite_was_valid:
                self._name_edit.setFocus()
                self._name_edit.setText(invite_data["name"])

            name_text = self._name_edit.text().strip()
            if len(name_text) == 0:
                name_result = IdentityCheckResult.Invalid
            else:
                # RT: If the user wants to add 10 Bobs do we really mind?
                # for read_row in list_context.wallet_data.read_contacts():
                #     if read_row is None or read_row.contact_id != contact_row.contact_id:
                #         if edited_contact_name == read_row.contact_name.lower():
                #             IdentityCheckResult.InUse
                #             break
                # else:
                name_result = IdentityCheckResult.Ok

            name_is_valid = name_result == IdentityCheckResult.Ok
            self._set_validation_state(self._name_edit, not invite_is_valid or name_is_valid)
            if name_is_valid:
                self._name_edit.setToolTip("")
            elif name_result == IdentityCheckResult.Invalid:
                self._name_edit.setToolTip(_("Name too short"))
            elif name_result == IdentityCheckResult.InUse:
                self._name_edit.setToolTip(_("Name already in use"))
        else:
            self._invite_data = None
            self._name_edit.setText(_(""))
            self._name_edit.setReadOnly(True)

        enable_connect_button = invite_is_valid and name_is_valid
        self._connect_button.setEnabled(enable_connect_button)
        if enable_connect_button:
            self._connect_button.setDefault(True)

    def _event_connect_button_clicked(self) -> None:
        # We are going to do a modal thing.
        assert self._invite_data is not None
        preferred_name = self._name_edit.text().strip()
        show_connect_progress_dialog(self._main_window_proxy.reference(), self, preferred_name,
            self._invite_data)


def show_connect_progress_dialog(wallet_window: ElectrumWindow, parent: QWidget,
        preferred_name: str, invite_data: ConnectionInvitationDict) -> None:
    wallet = wallet_window._wallet

    # We hide the close button because we do not allow dismissing this window until the process
    # either succeeds or fails. This should be a quick matter of seconds or we are doing something
    # wrong.
    title = _("Connection progress")
    progress_dialog = WindowModalDialog(parent, title, hide_close_button=True)

    vbox = QVBoxLayout()
    description_label = QLabel(_("Connecting to {}..").format(preferred_name))
    description_label.setMinimumWidth(400)
    description_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    description_label.setWordWrap(True)
    vbox.addWidget(description_label)

    close_button = CloseButton(progress_dialog)
    buttons = Buttons(close_button)
    vbox.addLayout(buttons)

    progress_dialog.setLayout(vbox)
    progress_dialog.show()

    def done_callback(future: concurrent.futures.Future[tuple[bool, str | None]]) -> None:
        nonlocal close_button, description_label
        success, error_text = future.result()

        if success:
            progress_dialog.close()
            parent.close()
        else:
            assert error_text is not None
            description_label.setText(error_text)
            close_button.setEnabled(True)

    app_state.app.run_coro(import_contact_invitation_async(wallet, preferred_name, invite_data),
        on_done=done_callback)

