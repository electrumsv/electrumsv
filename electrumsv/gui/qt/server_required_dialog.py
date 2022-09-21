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
import concurrent.futures
from enum import Enum, IntEnum
import random
from typing import TYPE_CHECKING
import weakref

from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import QCheckBox, QDialog, QGridLayout, QGroupBox, QLabel, QProgressBar, \
    QPushButton, QSpacerItem, QVBoxLayout, QWidget

from ...app_state import app_state
from ...constants import NetworkServerFlag, NetworkServerType, SERVER_USES, ServerConnectionFlag
from ...exceptions import InvalidPassword, ServerConnectionError
from ...i18n import _
from ...network_support.exceptions import AuthenticationError, GeneralAPIError
if TYPE_CHECKING:
    from ...network_support.api_server import NewServer
    from ...network_support.types import ServerConnectionState
    from ...wallet import Wallet


from . import server_selection_wizard
from .util import Buttons, WindowModalDialog


class PerServerStep(IntEnum):
    REGISTER            = 1
    CONNECT             = 2


class DisplayStage(Enum):
    INTRODUCTION                = 1
    REGISTRATION                = 2
    REGISTRATION_FAILURE        = 3


class ServerRequiredDialog(WindowModalDialog):
    """
    When an action requires use of servers but the user has not approved automatic server
    usage or supplied their own preferred servers, we pop up this dialog to gate keep the
    use of servers for the given action.
    """

    manage_servers_complete_signal = pyqtSignal(int)

    _display_stage: DisplayStage = DisplayStage.INTRODUCTION
    _introduction_widget: IntroductionWidget
    _registration_widget: RegistrationWidget
    _registration_failure_widget: RegistrationFailureWidget

    def __init__(self, parent: QWidget, wallet: Wallet, required_usage_flags: NetworkServerFlag,
            body_text: str, title_text: str | None=None) -> None:
        super().__init__(parent)
        self._wallet_proxy = weakref.proxy(wallet)

        if title_text is None:
            title_text = _("Server access required")

        self._required_usage_flags = required_usage_flags

        self.setWindowTitle(title_text)
        self.setMinimumSize(300, 200)
        self.setMaximumSize(550, 700)

        self._ok_button = QPushButton(_("OK"))
        self._ok_button.clicked.connect(self._on_button_clicked_ok)
        self._cancel_button = QPushButton(_("Cancel"))
        self._cancel_button.clicked.connect(self._on_button_clicked_cancel)
        self._manage_servers_button = QPushButton(_("Manage servers"))
        self._buttons = Buttons(self._ok_button, self._cancel_button)
        self._buttons.add_left_button(self._manage_servers_button)

        self._introduction_widget = IntroductionWidget(body_text)

        self._introduction_widget.automatic_checkbox.stateChanged.connect(
            self._on_checkbox_state_changed)
        # Ensure the display rules associated with checkbox selection are enforced to start with.
        # NOTE(typing) PyQt nonsense: `CheckState` is an `Enum` not and `IntEnum`.
        self._on_checkbox_state_changed(2 # Qt.CheckState.Checked
            if self._introduction_widget.automatic_checkbox.isChecked()
            else 0) # Qt.CheckState.Unchecked

        self._registration_widget = RegistrationWidget(self._wallet_proxy.reference(),
            required_usage_flags)
        self._registration_widget.cancel_signal.connect(self._on_cancel_signal_from_registration)
        self._registration_widget.success_signal.connect(self.accept)
        self._registration_widget.failure_signal.connect(self._on_failure_signal_from_registration)

        self._registration_failure_widget = RegistrationFailureWidget()
        self._registration_failure_widget.automatic_checkbox.stateChanged.connect(
            self._on_checkbox_state_changed)

        self.finished.connect(self._on_finished)
        self.manage_servers_complete_signal.connect(self._on_manage_servers_completed)

        self._vbox = QVBoxLayout()
        self._vbox.addWidget(self._introduction_widget)
        self._vbox.addLayout(self._buttons)
        self.setLayout(self._vbox)

        self._reset_tab_order(self._introduction_widget.automatic_checkbox)

        # NOTE(PyQt6) @ModalDialogLeakage
        # If we do not set this, this dialog does not get garbage collected and `main_window`
        # appears in `gc.get_referrers(self)` as a direct reference. So a `QDialog` merely having a
        # parent stored at the Qt level can create a circular reference, apparently. With this set,
        # the dialog will be gc'd on the next `collect` call.
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

    def closeEvent(self, event: QCloseEvent) -> None:
        # This is called if the user clicks on the OS "close window" button but not if the
        # dialog is accepted or rejected.
        self.clean_up()
        event.accept()

    def _on_finished(self) -> None:
        # This is called if the dialog is accepted or rejected but not if the OS "close window"
        # button is clicked.
        self.clean_up()

    def clean_up(self) -> None:
        self._registration_widget.clean_up()

    def _reset_tab_order(self, widget: QWidget) -> None:
        # Default tab order is in order of creation, but we create the checkboxes last and want
        # them to have default focus before the other widgets.
        self.setTabOrder(widget, self._ok_button)
        self.setTabOrder(self._ok_button, self._cancel_button)
        self.setTabOrder(self._cancel_button, self._manage_servers_button)

    def _on_button_clicked_ok(self) -> None:
        assert self._introduction_widget is not None

        # TODO Collect and select the servers.
        self._ok_button.setEnabled(False)
        self._cancel_button.setEnabled(False)

        previous_display_state = self._display_stage
        self._display_stage = DisplayStage.REGISTRATION
        if previous_display_state == DisplayStage.INTRODUCTION:
            self._vbox.replaceWidget(self._introduction_widget, self._registration_widget)
            self._introduction_widget.hide()
        elif previous_display_state == DisplayStage.REGISTRATION_FAILURE:
            self._vbox.replaceWidget(self._registration_failure_widget, self._registration_widget)
            self._registration_failure_widget.hide()

        if self._registration_widget.reset_widget():
            self._registration_widget.show()

            # We delay this so that the user can see the process starting.
            QTimer.singleShot(50, self._registration_widget.register_server)

    def _on_button_clicked_cancel(self) -> None:
        if self._display_stage in { DisplayStage.INTRODUCTION, DisplayStage.REGISTRATION_FAILURE }:
            # The introduction phase. Close the dialog and give up.
            self.reject()
        else:
            # The registration phase cannot be interrupted at this time.
            raise NotImplementedError()

    def _on_button_clicked_manage_servers(self) -> None:
        from importlib import reload
        reload(server_selection_wizard)
        wizard = server_selection_wizard.ServerSelectionWizard(self,
            self._wallet_proxy.reference())
        wizard.setModal(True)
        wizard.finished.connect(self.manage_servers_complete_signal)
        wizard.raise_()
        wizard.show()
        # TODO: React to this being closed by ...

    def _on_checkbox_state_changed(self, state: int) -> None:
        # NOTE(typing) PyQt nonsense: `CheckState` is an `Enum` not and `IntEnum` so direct
        #     comparison is not possible.
        check_state = Qt.CheckState(state)
        if check_state == Qt.CheckState.Checked:
            enable_manage_servers = False
            self._ok_button.setEnabled(True)
        else:
            enable_manage_servers = True
            self._ok_button.setEnabled(False)
        if self._display_stage == DisplayStage.INTRODUCTION:
            self._manage_servers_button.setEnabled(enable_manage_servers)
        else:
            self._manage_servers_button.setEnabled(False)
        self._cancel_button.setEnabled(True)

    def _on_cancel_signal_from_registration(self) -> None:
        self._display_stage = DisplayStage.INTRODUCTION
        self._vbox.replaceWidget(self._registration_widget, self._introduction_widget)
        self._registration_widget.hide()
        self._introduction_widget.reset_widget()
        self._introduction_widget.show()
        self._reset_tab_order(self._introduction_widget)

    def _on_failure_signal_from_registration(self, server: NewServer | None,
            server_flags: NetworkServerFlag, message_text: str) -> None:
        self._display_stage = DisplayStage.REGISTRATION_FAILURE
        self._vbox.replaceWidget(self._registration_widget, self._registration_failure_widget)
        self._registration_widget.hide()
        self._registration_failure_widget.set_state(server, server_flags, message_text)
        self._on_checkbox_state_changed(0) # Qt.CheckState.Unchecked
        self._registration_failure_widget.show()
        self._reset_tab_order(self._registration_failure_widget)

    def _on_manage_servers_completed(self, code: int) -> None:
        if code == QDialog.DialogCode.Accepted:
            # We want the user to have chosen servers for all required forms of usage and
            # for connections to have been established. If they have done this, then we
            # proceed with the acceptance of the dialog.
            state1 = self._wallet_proxy.get_connection_state_for_usage(
                NetworkServerFlag.USE_BLOCKCHAIN)
            state2 = self._wallet_proxy._wallet.get_connection_state_for_usage(
                NetworkServerFlag.USE_MESSAGE_BOX)
            if state1 is not None and state2 is not None:
                self.accept()
            else:
                # TODO Update the display to indicate required servers.
                pass
        elif code == QDialog.DialogCode.Rejected:
            pass


class IntroductionWidget(QWidget):
    def __init__(self, body_text: str) -> None:
        super().__init__()

        body_label = QLabel(body_text)
        body_label.setWordWrap(True)

        self.automatic_checkbox = QCheckBox(_("Select servers to use on my behalf."))

        vbox = QVBoxLayout(self)
        vbox.addWidget(body_label)
        vbox.addSpacerItem(QSpacerItem(1, 20))
        vbox.addWidget(self.automatic_checkbox, alignment=Qt.AlignmentFlag.AlignHCenter)

        self.setLayout(vbox)

        self.setFocusProxy(self.automatic_checkbox)
        self.reset_widget()

    def reset_widget(self) -> None:
        self.automatic_checkbox.setCheckState(Qt.CheckState.Checked)


class RegistrationWidget(QWidget):
    _step_count = 0
    _next_server_index = 0
    _current_server_index = -1
    _current_server: tuple[NewServer, NetworkServerFlag] | None = None

    _monitor_connection_future: concurrent.futures.Future[None] | None = None

    cancel_signal = pyqtSignal()
    success_signal = pyqtSignal()
    failure_signal = pyqtSignal(object, int, str)
    retry_signal = pyqtSignal(int, object, int, str)
    progress_update_signal = pyqtSignal(int, str)
    move_to_next_server_signal = pyqtSignal()

    def __init__(self, wallet: Wallet, required_usage_flags: NetworkServerFlag,
            title_text: str | None=None) -> None:
        super().__init__()
        self._wallet_proxy: Wallet = weakref.proxy(wallet)

        if title_text is None:
            title_text = _("Obtaining server access")

        self._required_usage_flags = required_usage_flags
        # This survives a reset as we do not want to retry bad servers.
        self._failed_servers: dict[NetworkServerFlag, set[NewServer]] = {}

        self._group_box = QGroupBox(_("Registering with required servers"))

        self._subtitle_label = QLabel("<b>"+ _("Registering with this server..") +"</b>")
        self._subtitle_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        server_name_key_label = QLabel(_("Server"))
        self._server_name_value_label = QLabel()
        server_type_key_label = QLabel(_("Server type"))
        self._server_type_value_label = QLabel()

        detail_layout = QGridLayout()
        detail_layout.addWidget(server_name_key_label, 0, 0, 1, 1)
        detail_layout.addWidget(self._server_name_value_label, 0, 1, 1, 1)
        detail_layout.addWidget(server_type_key_label, 1, 0, 1, 1)
        detail_layout.addWidget(self._server_type_value_label, 1, 1, 1, 1)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, self._step_count)
        self._progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._progress_bar.setFormat("%p%")

        self._progress_label = QLabel(_("Preparing.."))
        self._progress_label.setStyleSheet("QLabel { color: gray; }")
        self._progress_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self.reset_widget()

        self._group_box_layout = QVBoxLayout()
        self._group_box_layout.addLayout(detail_layout)
        self._group_box_layout.addWidget(self._progress_bar)
        self._group_box_layout.addWidget(self._progress_label)
        self._group_box.setLayout(self._group_box_layout)

        main_layout = QVBoxLayout()
        main_layout.addStretch(1)
        main_layout.addWidget(self._group_box)
        main_layout.addStretch(1)
        self.setLayout(main_layout)

        self.retry_signal.connect(self._retry_with_different_server_ui)
        self.progress_update_signal.connect(self._update_progress_bar_ui)
        self.move_to_next_server_signal.connect(self._on_signal_move_to_next_server)

    def reset_widget(self) -> bool:
        self._usage_flags = self._required_usage_flags
        for _server, server_flags in self._wallet_proxy.get_wallet_servers():
            for usage_flag in SERVER_USES:
                if server_flags & usage_flag != 0:
                    self._usage_flags &= ~usage_flag

        self._servers = self._get_viable_servers(self._usage_flags)
        # Two steps per server (register and connect).
        self._step_count = len(self._servers) * 2
        self._next_server_index = 0
        self._current_server_index = -1

        bad_server_flags = self._usage_flags
        # Remove the usages that we found servers for.
        for _server, server_flags in self._servers:
            bad_server_flags &= ~server_flags

        if bad_server_flags != NetworkServerFlag.NONE:
            self.failure_signal.emit(None, bad_server_flags,
                _("None of the known servers of this type are currently accessible."))
            return False

        assert self._prepare_to_register_next_server()
        return True

    def clean_up(self) -> None:
        if self._monitor_connection_future is not None:
            self._monitor_connection_future.cancel()

    def register_server(self) -> None:
        assert self._current_server is not None
        server, server_flags = self._current_server
        _future = app_state.app.run_coro(self._wallet_proxy.create_server_account_async(server,
            server_flags), on_done=self._on_future_done_create_server_account)

        self.progress_update_signal.emit((self._current_server_index * 2) + PerServerStep.REGISTER,
            _("Registering server account."))

    def _prepare_to_register_next_server(self) -> bool:
        if self._next_server_index == len(self._servers):
            return False

        self._current_server_index = self._next_server_index
        self._next_server_index += 1

        self._current_server = self._servers[self._current_server_index]
        assert self._current_server is not None
        server, server_flags = self._current_server
        assert server.key.server_type == NetworkServerType.GENERAL

        server_type_text = ""
        if server_flags == NetworkServerFlag.USE_MESSAGE_BOX | NetworkServerFlag.USE_BLOCKCHAIN:
            server_type_text = _("Blockchain and Message box")
        elif server_flags == NetworkServerFlag.USE_BLOCKCHAIN:
            server_type_text = _("Blockchain")
        elif server_flags == NetworkServerFlag.USE_MESSAGE_BOX:
            server_type_text += _("Message box")

        self._server_name_value_label.setText(server.key.url)
        self._server_type_value_label.setText(server_type_text)

        return True

    def _on_signal_move_to_next_server(self) -> None:
        if self._prepare_to_register_next_server():
            self.register_server()
        else:
            # All the servers have been registered.
            self.success_signal.emit()

    def _get_viable_servers(self, usage_flags: NetworkServerFlag) \
            -> list[tuple[NewServer, NetworkServerFlag]]:
        servers_by_usage_flag = self._wallet_proxy.get_unused_reference_servers(usage_flags,
            self._failed_servers)

        # For every used service type we need to have viable servers matched.
        usage_flag_by_server: dict[NewServer, NetworkServerFlag] = {}
        for usage_flag in { NetworkServerFlag.USE_BLOCKCHAIN, NetworkServerFlag.USE_MESSAGE_BOX }:
            if usage_flags & usage_flag == 0 or usage_flag not in servers_by_usage_flag:
                continue
            selected_server = random.choice(list(servers_by_usage_flag[usage_flag]))
            if selected_server in usage_flag_by_server:
                usage_flag_by_server[selected_server] |= usage_flag
            else:
                usage_flag_by_server[selected_server] = usage_flag
        return list(usage_flag_by_server.items())

    def _update_progress_bar_ui(self, step: int, step_text: str) -> None:
        self._progress_label.setText(step_text)
        self._progress_bar.setValue(step)

    def _retry_with_different_server_ui(self, step: int, server: NewServer,
            server_flags: NetworkServerFlag, message_text: str) -> None:
        self.progress_update_signal.emit(1 + (self._current_server_index * 2) + step,
            _("Failed: ") + message_text)

        for usage_flag in { NetworkServerFlag.USE_BLOCKCHAIN, NetworkServerFlag.USE_MESSAGE_BOX }:
            if server_flags & usage_flag != 0:
                if usage_flag in self._failed_servers:
                    self._failed_servers[usage_flag].add(server)
                else:
                    self._failed_servers[usage_flag] = { server }

        # TODO This should ideally have a retry mechanism that reselects servers and then retries
        #      but for now the flow supports failing and letting the user retry. They can close
        #      the dialog and get a new one to have the failure memory cleared.
        self.failure_signal.emit(server, server_flags, message_text)

    def _on_future_done_create_server_account(self, future: concurrent.futures.Future[None]) \
            -> None:
        """
        WARNING: This likely occurs in the async thread, not the UI thread. UI updates should
            be done in the UI thread.
        """
        if future.cancelled():
            return

        assert self._current_server is not None
        server, server_flags = self._current_server

        try:
            future.result()
        except InvalidPassword:
            # The user entered an invalid password (treat as cancel by user).
            self.cancel_signal.emit()
        except ServerConnectionError:
            # The server was not connectable (treat as temporarily inaccessible).
            self.retry_signal.emit(PerServerStep.REGISTER, server, server_flags,
                _("Unable to connect."))
        except GeneralAPIError:
            # The server returned invalid results (treat as temporarily unreliable).
            self.retry_signal.emit(PerServerStep.REGISTER, server, server_flags,
                _("Received an invalid response."))
        except AuthenticationError:
            # The server returned invalid results (treat as broken).
            self.retry_signal.emit(PerServerStep.REGISTER, server, server_flags,
                _("Received a broken response."))
        else:
            self.progress_update_signal.emit(
                (self._current_server_index * 2) + PerServerStep.CONNECT,
                _("Establishing server connection."))

            # The remote server account has been created so now establish a persistent connection.
            self._monitor_connection_future = app_state.app.run_coro(
                self._monitor_server_connection_progress_async(server, server_flags),
                on_done=self._on_future_done_monitor_server_connection_progress)

    async def _monitor_server_connection_progress_async(self, server: NewServer,
            server_flags: NetworkServerFlag) -> None:
        # Starting the connection continues in an async task and does not block this call
        # (at least not for the actual connecting part).
        server_state = await self._wallet_proxy.start_reference_server_connection_async(server,
            server_flags)
        while server_state.connection_flags & ServerConnectionFlag.MASK_EXIT == 0:
            if server_state.connection_flags & ServerConnectionFlag.WEB_SOCKET_READY != 0:
                # The connection was established successfully as far as we are concerned.
                self.move_to_next_server_signal.emit()
                return

            await server_state.stage_change_event.wait()

        # TODO Exited unexpectedly.

    def _on_future_done_monitor_server_connection_progress(self,
            future: concurrent.futures.Future[None]) -> None:
        if future.cancelled():
            return

        assert self._current_server is not None
        server, server_flags = self._current_server

        # TODO If there is nothing that needs to be done and only unexpected exceptions that will
        #      be raised, then we can just get rid of the done callback and let the default handler
        #      log it.
        future.result()


class RegistrationFailureWidget(QWidget):
    def __init__(self) -> None:
        super().__init__()

        self._body_label = QLabel("A problem was encountered registering with the selected server.")
        self._body_label.setWordWrap(True)

        self.automatic_checkbox = QCheckBox(_("Retry with the next potential server."))

        self._group_box = QGroupBox(_("Registration failure"))

        server_name_key_label = QLabel(_("Server"))
        server_name_key_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._server_name_value_label = QLabel()
        server_type_key_label = QLabel(_("Server type"))
        server_type_key_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._server_type_value_label = QLabel()
        server_problem_key_label = QLabel(_("Problem"))
        server_problem_key_label.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._message_label = QLabel()
        self._message_label.setWordWrap(True)

        detail_layout = QGridLayout()
        detail_layout.addWidget(server_name_key_label, 0, 0, 1, 1)
        detail_layout.addWidget(self._server_name_value_label, 0, 1, 1, 1)
        detail_layout.addWidget(server_type_key_label, 1, 0, 1, 1)
        detail_layout.addWidget(self._server_type_value_label, 1, 1, 1, 1)
        detail_layout.addWidget(server_problem_key_label, 2, 0, 1, 1)
        detail_layout.addWidget(self._message_label, 2, 1, 1, 1)

        self._group_box_layout = QVBoxLayout()
        self._group_box_layout.addLayout(detail_layout)
        self._group_box.setLayout(self._group_box_layout)

        vbox = QVBoxLayout(self)
        vbox.addSpacerItem(QSpacerItem(1, 10))
        vbox.addWidget(self._body_label)
        vbox.addStretch(1)
        vbox.addWidget(self._group_box)
        vbox.addStretch(1)
        vbox.addWidget(self.automatic_checkbox, alignment=Qt.AlignmentFlag.AlignHCenter)

        self.setLayout(vbox)

        self.setFocusProxy(self.automatic_checkbox)
        self.reset_widget()

    def set_state(self, server: NewServer | None, server_flags: NetworkServerFlag,
            message_text: str) -> None:
        self.reset_widget()

        if server is not None:
            self._group_box.setTitle(_("Registration failure"))
        else:
            self._group_box.setTitle(_("Server availability failure"))
        self.automatic_checkbox.setEnabled(server is not None)

        server_type_text = ""
        if server_flags == NetworkServerFlag.USE_MESSAGE_BOX | NetworkServerFlag.USE_BLOCKCHAIN:
            server_type_text = _("Blockchain and Message box")
        elif server_flags == NetworkServerFlag.USE_BLOCKCHAIN:
            server_type_text = _("Blockchain")
        elif server_flags == NetworkServerFlag.USE_MESSAGE_BOX:
            server_type_text = _("Message box")

        self._server_name_value_label.setText(server.url if server is not None else "-")
        self._server_type_value_label.setText(server_type_text)
        self._message_label.setText(message_text)

    def reset_widget(self) -> None:
        self.automatic_checkbox.setCheckState(Qt.CheckState.Unchecked)
