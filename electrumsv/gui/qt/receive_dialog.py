from __future__ import annotations
import concurrent.futures
from typing import Any, cast, Optional, TYPE_CHECKING
import weakref

from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QCloseEvent, QCursor, QFontMetrics, QKeyEvent
from PyQt6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QLayout, QLineEdit, \
    QMenu, QToolTip, QVBoxLayout

from ...app_state import app_state, get_app_state_qt
from ...bitcoin import script_template_to_string
from ...constants import PaymentFlag, PushDataHashRegistrationFlag, ScriptType, \
    ServerConnectionFlag, ServerCapability, TxFlags
from ...i18n import _
from ...logs import logs
from ...network_support.types import ServerConnectionState, TipFilterRegistrationJob, \
    TipFilterRegistrationJobEntry
from ...networks import Net, TEST_NETWORK_NAMES
from ...transaction import Transaction, TransactionContext
from ...util import age, get_posix_timestamp
from ... import web
from ...wallet_database.types import PaymentRequestRow, PaymentRequestUpdateRow

from .amountedit import AmountEdit, BTCAmountEdit
from .qrcodewidget import QRCodeWidget
from .qrwindow import QR_Window
from .util import Buttons, ButtonsLineEdit, EnterButton, FormSectionWidget, FormSeparatorLine, \
    HelpDialogButton, MessageBox

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .receive_view import ReceiveView
    from ...wallet import AbstractAccount
    from ...wallet_database.types import KeyInstanceRow, PaymentRequestReadRow


EXPIRATION_VALUES: list[tuple[str, Optional[int]]] = [
    (_('1 hour'), 60*60),
    (_('1 day'), 24*60*60),
    (_('1 week'), 7*24*60*60),
]

if Net.NAME in TEST_NETWORK_NAMES:
    EXPIRATION_VALUES = [
        # This is the minimum the regtest "simple indexer" project supports.
        (_('5 minutes'), 5*60),

        *EXPIRATION_VALUES,
    ]

NOT_CREATED_YET_STATUS_TEXT = "<b>"+ _("Not ready") +"</b><br/>"+ \
    _("Waiting for you to create this..")
IMPORTING_IN_PROGRESS_STATUS_TEXT = "<b>"+ _("Ready to receive payment") +"</b><br/>"+ \
    _("Waiting for you to import the transaction..")
IMPORTING_EXPIRED_TEXT = "<b>"+ _("Expired") +"</b><br/>"+ \
    _("This is no longer active.")
MONITORING_NOT_STARTED_STATUS_TEXT = "<b>"+ _("Not ready to receive payment") +"</b><br/>"+ \
    _("Wait until this is monitored before sharing it..")
MONITORING_NOT_AVAILABLE_STATUS_TEXT = "<b>"+ _("Not ready to receive payment") +"</b><br/>"+ \
    _("The server appears to be unavailable..")
MONITORING_REGISTERING_STATUS_TEXT = "<b>"+ _("Getting ready to receive payment") +"</b><br/>"+ \
    _("Asking the server to monitor for payments to this..")
MONITORING_IN_PROGRESS_STATUS_TEXT = "<b>"+ _("Ready to receive payment") +"</b><br/>"+ \
    _("The server is monitoring for this payment.")
MONITORING_REGISTRATION_FAILED_STATUS_TEXT = "<b>"+ _("Not ready") +"</b><br/>"+ \
    _("Previous attempt failed, you can retry..")
MONITORING_EXPIRED_STATUS_TEXT = "<b>"+ _("Expired") +"</b><br/>"+ \
    _("This is no longer being monitored.")


async def monitor_tip_filter_job(indexing_server_state: ServerConnectionState,
        job: TipFilterRegistrationJob) -> None:
    """
    This method is intentionally decoupled from the `ReceiveDialog` instance.
    """
    assert job.logger is not None
    assert job.paymentrequest_id is not None
    assert job.completion_callback is not None
    assert job.refresh_callback is not None

    job.logger.debug("Queuing tip filter registration job %d", job.paymentrequest_id)
    await indexing_server_state.tip_filter_new_registration_queue.put(job)
    job.logger.debug("Waiting for tip filter registration completion %d", job.paymentrequest_id)
    await job.start_event.wait()
    job.refresh_callback()
    await job.completed_event.wait()
    job.logger.debug("Tip filter registration completion detected %d", job.paymentrequest_id)

    job.completion_callback()


class ReceiveDialog(QDialog):
    """
    Display a popup window with a form containing the details of an existing expected payment.
    """
    show_error_signal = pyqtSignal(str)
    refresh_form_signal = pyqtSignal()
    tip_filter_registration_completed_signal = pyqtSignal()

    _qr_window: Optional[QR_Window] = None
    _fiat_receive_e: AmountEdit
    _receive_amount_e: BTCAmountEdit
    _timer: Optional[QTimer] = None
    _tip_filter_registration_job: Optional[TipFilterRegistrationJob] = None

    def __init__(self, main_window: ElectrumWindow, view: ReceiveView, account_id: int,
            request_id: Optional[int], request_type: PaymentFlag) -> None:
        super().__init__(main_window)
        self.setWindowTitle(_("Expected payment"))

        # If we do not set this, this dialog does not get garbage collected and `main_window`
        # appears in `gc.get_referrers(self)` as a direct reference. So a `QDialog` merely having a
        # parent stored at the Qt level can create a circular reference, apparently. With this set,
        # the dialog will be gc'd on the next `collect` call.
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        self._logger = logs.get_logger(f"receive-dialog[{account_id},{request_id}]")

        self._view: Optional[ReceiveView] = view
        self._main_window_proxy: ElectrumWindow = weakref.proxy(main_window)
        self._account_id = account_id
        self._account = cast("AbstractAccount", main_window._wallet.get_account(account_id))

        self._request_id = request_id
        self._request_type = request_type

        wallet = self._account.get_wallet()
        self._request_row: Optional[PaymentRequestReadRow] = None
        self._key_data: Optional[KeyInstanceRow] = None

        if request_id is not None:
            self._read_request_data_from_database()

        self._layout_pending = True
        self.setLayout(self._create_form_layout())
        self._connect_widgets()
        self._layout_pending = False

        self._on_fiat_ccy_changed()
        self._update_destination()
        if self._request_row is not None:
            self._receive_amount_e.setAmount(self._request_row.requested_value)

        self.refresh_form_signal.connect(self._update_form)
        self.tip_filter_registration_completed_signal.connect(
            self._tip_filter_registration_completed)

        app_state.app_qt.fiat_ccy_changed.connect(self._on_fiat_ccy_changed)
        self._main_window_proxy.new_fx_quotes_signal.connect(self._on_ui_exchange_rate_quotes)
        self._main_window_proxy.payment_requests_paid_signal.connect(self._on_payment_requests_paid)

    def closeEvent(self, event: QCloseEvent) -> None:
        self._view = None
        if self._qr_window is not None:
            self._qr_window.close()
            self._qr_window = None
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        self._main_window_proxy.payment_requests_paid_signal.disconnect(
            self._on_payment_requests_paid)
        self._main_window_proxy.new_fx_quotes_signal.disconnect(self._on_ui_exchange_rate_quotes)
        app_state.app_qt.fiat_ccy_changed.disconnect(self._on_fiat_ccy_changed)
        super().closeEvent(event)

    def clean_up(self) -> None:
        pass

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """
        The primary way that the refresh is performed is through the menu with it's key shortcut.
        As this is a separate window, pressing Control+R does not reach the menu, and besides we
        do not want to refresh the whole wallet.
        """
        key = event.key()
        if key == Qt.Key.Key_R and bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier):
            self._update_destination()
            self._update_receive_qr()
            self._update_form()
        else:
            super().keyPressEvent(event)

    def _read_request_data_from_database(self) -> None:
        assert self._request_id is not None
        wallet = self._main_window_proxy._wallet
        self._request_row = wallet.data.read_payment_request(request_id=self._request_id)
        assert self._request_row is not None
        self._key_data = wallet.data.read_keyinstance(
            keyinstance_id=self._request_row.keyinstance_id)
        self._request_type = self._request_row.state & PaymentFlag.MASK_TYPE

    def get_paymentrequest_id(self) -> Optional[int]:
        return self._request_id

    def _on_payment_requests_paid(self, paymentrequest_ids: list[int]) -> None:
        if self._request_id not in paymentrequest_ids:
            return

        self._read_request_data_from_database()
        self._update_form()

    def _tip_filter_registration_completed(self) -> None:
        self._logger.debug("_tip_filter_registration_completed")
        self._update_form()
        self._tip_filter_registration_job = None

    def _start_expiry_timer(self, expiry_timestamp: Optional[int]) -> None:
        """
        When the payment expires the dialog should update to reflect it in order to provide a
        polished user experience.
        """
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        if expiry_timestamp is not None:
            interval_ms = (int(get_posix_timestamp()) - expiry_timestamp) * 1000
            if interval_ms > 0:
                self._timer = QTimer(self)
                self._timer.setSingleShot(True)
                self._timer.timeout.connect(self._on_request_expired)
                self._timer.start(interval_ms)

    def _on_button_clicked_close(self) -> None:
        self.close()

    def _on_fiat_ccy_changed(self) -> None:
        flag = bool(app_state.fx and app_state.fx.is_enabled())
        self._fiat_receive_e.setVisible(flag)

    def _on_ui_exchange_rate_quotes(self) -> None:
        edit = (self._fiat_receive_e if self._fiat_receive_e.is_last_edited
            else self._receive_amount_e)
        edit.textEdited.emit(edit.text())

    def _create_form_layout(self) -> QVBoxLayout:
        self._form = form = FormSectionWidget()

        request_type = self._request_type
        if self._request_row is not None:
            request_type = self._request_row.state & PaymentFlag.MASK_TYPE
        if request_type == PaymentFlag.MONITORED:
            type_text = _("Monitor the blockchain")
        elif request_type == PaymentFlag.IMPORTED:
            type_text = _("Import the transaction yourself")
        elif request_type == PaymentFlag.INVOICE:
            type_text = _("Invoice hosted online")
        else:
            raise NotImplementedError(f"Invalid request type {request_type}")

        self._status_label = QLabel()

        form.add_row(_("Type"), QLabel(type_text))
        form.add_row(_("Status"), self._status_label)

        form.add_row(_("Account"), QLabel(self._account.get_name()))

        # Really we want to display a whole standard address.
        token_address = "mqrJ2AAzrR6U3L4Nzt9zDNxuLXGEsnWP47"
        defaultFontMetrics = QFontMetrics(self.font())
        def fw(s: str) -> int:
            return defaultFontMetrics.boundingRect(s).width() + 40

        self._receive_destination_edit = ButtonsLineEdit()
        self._receive_destination_edit.setMinimumWidth(fw(token_address))
        self._receive_destination_edit.addCopyButton()
        self._receive_destination_edit.setReadOnly(True)
        self._receive_destination_edit.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        form.add_row(_('Payment destination'), self._receive_destination_edit)

        self._receive_message_e = QLineEdit()
        form.add_row(_('Description'), self._receive_message_e)
        self._receive_message_e.setText(
            "" if self._request_row is None or self._request_row.description is None
            else self._request_row.description)

        self._receive_amount_e = BTCAmountEdit()
        self._fiat_receive_e = AmountEdit(app_state.fx.get_currency if app_state.fx else lambda: '')
        self._main_window_proxy.connect_fields(self._receive_amount_e, self._fiat_receive_e)

        amount_widget_layout = QHBoxLayout()
        amount_widget_layout.addWidget(self._receive_amount_e)
        amount_widget_layout.addSpacing(10)
        amount_widget_layout.addWidget(self._fiat_receive_e)
        form.add_row(_('Requested amount'), amount_widget_layout)

        self._expires_combo = QComboBox()
        self._expires_combo.addItems([i[0] for i in EXPIRATION_VALUES])
        # Default the current index to one hour or the last entry if that cannot be found for some
        # reason.
        current_index = 0
        for current_index, expiration_entry in enumerate(EXPIRATION_VALUES):
            if expiration_entry[1] == 60*60:
                break
        self._expires_combo.setCurrentIndex(current_index)
        self._expires_combo.setFixedWidth(self._receive_amount_e.width())

        # There are different variations on this.
        self._expires_label = QLabel("")
        expires_widget_layout = QHBoxLayout()
        expires_widget_layout.addWidget(self._expires_combo)
        expires_widget_layout.addWidget(self._expires_label)
        form.add_row(_('Request expires'), expires_widget_layout)

        self._copy_link_button = EnterButton(_('Copy payment link'), self._copy_qr_data)
        self._help_button = HelpDialogButton(self, "misc", "receive-dialog", _("&Help"))
        import_menu = QMenu()
        import_file_action = import_menu.addAction(_("From &file"), self._on_menu_import_from_file)
        import_file_action.setToolTip(_("Select a file containing the transaction data."))
        import_text_action = import_menu.addAction(_("From &text"), self._on_menu_import_from_text)
        import_text_action.setToolTip(_("Paste in text containing the transaction data in hex "
            "form."))
        import_blockchain_action = import_menu.addAction(_("From the &blockchain"),
            self._on_menu_import_from_blockchain)
        import_blockchain_action.setToolTip(_("Paste in the transaction id and the wallet will "
            "try and obtain the transaction from external services."))
        import_blockchain_action.setEnabled(self._main_window_proxy.network is not None)
        import_menu.addAction(_("From &QR code"), self._on_menu_import_from_qrcode)
        self._import_button = EnterButton(_("&Import"), self._on_button_clicked_import)
        self._import_button.setMenu(import_menu)
        self._import_button.setEnabled(False)
        if request_type != PaymentFlag.IMPORTED:
            self._import_button.hide()
        self._register_button = EnterButton(_("Register"), self._on_button_clicked_register)
        self._register_button.setEnabled(False)
        if request_type not in (PaymentFlag.INVOICE, PaymentFlag.MONITORED):
            self._register_button.hide()
        self._save_button = EnterButton(_('Update'), self._on_button_clicked_save)
        self._close_button = EnterButton(_('Cancel'), self._on_button_clicked_close)

        buttons = Buttons(self._import_button, self._register_button, self._save_button,
            self._close_button)
        buttons.add_left_button(self._help_button)

        self._receive_qr = QRCodeWidget(fixedSize=200)
        self._receive_qr_layout = QVBoxLayout()
        self._receive_qr_layout.addWidget(self._receive_qr)
        self._receive_qr_layout.addWidget(self._copy_link_button)
        self._receive_qr_layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)

        form_vbox = QVBoxLayout()
        form_vbox.addWidget(form)
        form_vbox.addStretch(1)

        hbox = QHBoxLayout()
        hbox.addLayout(form_vbox)
        hbox.addLayout(self._receive_qr_layout)

        buttons_line = FormSeparatorLine()

        vbox = QVBoxLayout()
        vbox.addLayout(hbox)
        vbox.addWidget(buttons_line)
        vbox.addLayout(buttons)

        self._update_form()

        return vbox

    def _connect_widgets(self) -> None:
        self._receive_destination_edit.textChanged.connect(self._update_receive_qr)
        self._receive_message_e.textChanged.connect(self._update_receive_qr)
        self._receive_amount_e.textChanged.connect(self._update_receive_qr)
        self._receive_qr.mouse_release_signal.connect(self._toggle_qr_window)

    def _copy_qr_data(self) -> None:
        text = self._receive_qr.data
        if text:
            get_app_state_qt().app_qt.clipboard().setText(text)
            tooltip_text = _("Text copied to clipboard")
        else:
            tooltip_text = _("Nothing to copy")
        QToolTip.showText(QCursor.pos(), tooltip_text, self._copy_link_button)

    def update_widgets(self) -> None:
        # This is currently unused, but is called in the generic `update_tabs` call in the
        # wallet window code.
        pass

    def _update_destination(self) -> None:
        if self._request_row is None:
            script_type = self._account.get_default_script_type()
        else:
            script_type = self._request_row.script_type
        self.update_script_type(script_type)

    def update_script_type(self, script_type: ScriptType) -> None:
        """
        Update the payment destination field.

        This is called both locally, and from the account information dialog when the script type
        is changed.
        """
        if self._key_data is None:
            return

        text = ""
        script_template = self._account.get_script_template_for_derivation(
            script_type,
            self._key_data.derivation_type, self._key_data.derivation_data2)
        if script_template is not None:
            text = script_template_to_string(script_template)
        self._receive_destination_edit.setText(text)

    # Bound to text fields in `_create_receive_form_layout`.
    def _update_receive_qr(self) -> None:
        if self._layout_pending or self._request_id is None:
            return

        assert self._key_data is not None

        amount = self._receive_amount_e.get_amount()
        message = self._receive_message_e.text()
        self._save_button.setEnabled((amount is not None) or (message != ""))

        script_template = self._account.get_script_template_for_derivation(
            self._account.get_default_script_type(),
            self._key_data.derivation_type, self._key_data.derivation_data2)
        address_text = script_template_to_string(script_template)

        uri = web.create_URI(address_text, amount, message)
        self._receive_qr.setData(uri)
        if self._qr_window and self._qr_window.isVisible():
            self._qr_window.set_content(self._receive_destination_edit.text(), amount,
                                       message, uri)

    def _toggle_qr_window(self) -> None:
        if not self._qr_window:
            self._qr_window = QR_Window(self)
            self._qr_window.setVisible(True)
            self._qr_window_geometry = self._qr_window.geometry()
        else:
            if not self._qr_window.isVisible():
                self._qr_window.setVisible(True)
                self._qr_window.setGeometry(self._qr_window_geometry)
            else:
                self._qr_window_geometry = self._qr_window.geometry()
                self._qr_window.setVisible(False)

        self._update_receive_qr()

    def get_bsv_edits(self) -> list[BTCAmountEdit]:
        """
        Called by the receive view when the user changes the displayed base unit.
        """
        return [ self._receive_amount_e ]

    def _update_form(self) -> None:
        status_text = ""
        expiry_timestamp: Optional[int] = None
        enable_register_button = False
        enable_import_button = False

        if self._request_id is not None:
            assert self._request_row is not None
            if self._request_type == PaymentFlag.MONITORED:
                wallet = self._main_window_proxy._wallet
                indexing_server_state = wallet.get_server_state_for_capability(
                    ServerCapability.TIP_FILTER)

                monitored_row = wallet.data.read_registered_tip_filter_pushdata_for_request(
                    self._request_id)
                if monitored_row is None:
                    if self._tip_filter_registration_job is None:
                        if indexing_server_state is None or \
                                indexing_server_state.connection_flags & \
                                    ServerConnectionFlag.TIP_FILTER_READY == 0:
                            status_text = MONITORING_NOT_AVAILABLE_STATUS_TEXT
                        else:
                            status_text = MONITORING_NOT_STARTED_STATUS_TEXT
                            enable_register_button = True
                    elif self._tip_filter_registration_job.failure_reason is not None:
                        status_text = "<b>"+ _("Not ready") +"</b><br/>"+ \
                            self._tip_filter_registration_job.failure_reason
                        enable_register_button = True
                    else:
                        status_text = MONITORING_REGISTERING_STATUS_TEXT
                elif self._tip_filter_registration_job is not None and \
                        self._tip_filter_registration_job.failure_reason is not None:
                    assert monitored_row.pushdata_flags & PushDataHashRegistrationFlag.REGISTERING \
                        == 0
                    status_text = "<b>"+ _("Not ready") +"</b><br/>"+ \
                        self._tip_filter_registration_job.failure_reason
                    enable_register_button = True
                elif monitored_row.pushdata_flags & PushDataHashRegistrationFlag.REGISTERING:
                    status_text = MONITORING_REGISTERING_STATUS_TEXT
                elif monitored_row.pushdata_flags & \
                        PushDataHashRegistrationFlag.REGISTRATION_FAILED:
                    status_text = MONITORING_REGISTRATION_FAILED_STATUS_TEXT
                else:
                    current_timestamp = int(get_posix_timestamp())
                    expiry_timestamp = monitored_row.date_created + \
                        monitored_row.duration_seconds
                    if expiry_timestamp > current_timestamp:
                        status_text = MONITORING_IN_PROGRESS_STATUS_TEXT
                    else:
                        status_text = MONITORING_EXPIRED_STATUS_TEXT
            elif self._request_type == PaymentFlag.IMPORTED:
                status_text = IMPORTING_IN_PROGRESS_STATUS_TEXT
                enable_import_button = True
                if self._request_row.expiration:
                    current_timestamp = int(get_posix_timestamp())
                    expiry_timestamp = self._request_row.date_created + self._request_row.expiration
                    if expiry_timestamp <= current_timestamp:
                        status_text = IMPORTING_EXPIRED_TEXT
                        enable_import_button = False
            elif self._request_type == PaymentFlag.INVOICE:
                status_text = "<b>"+ _("Not ready") +"</b><br/>"+ \
                    _("This is not working yet..")
                # if self._request_row.expiration:
                #     expiry_timestamp = self._request_row.date_created + \
                #         self._request_row.expiration
            else:
                raise NotImplementedError(f"Unknown request type {self._request_type}")

            self._save_button.setText(_("Update"))
            self._copy_link_button.setEnabled(True)
            self._receive_destination_edit.setEnabled(True)
            self._expires_label.setVisible(True)
            self._expires_combo.setVisible(False)
        else:
            status_text = NOT_CREATED_YET_STATUS_TEXT

            self._save_button.setText(_("Create"))
            self._copy_link_button.setEnabled(False)
            self._import_button.setEnabled(False)
            self._register_button.setEnabled(False)
            self._receive_destination_edit.setEnabled(False)
            self._expires_label.setVisible(False)
            self._expires_combo.setVisible(True)

        self._status_label.setText(status_text)
        self._import_button.setEnabled(enable_import_button)
        self._register_button.setEnabled(enable_register_button)
        self._expires_label.setText(age(expiry_timestamp).capitalize() \
            if expiry_timestamp is not None else _('Never') +".")

        self._start_expiry_timer(expiry_timestamp)

    def _on_button_clicked_register(self) -> None:
        # TODO(1.4.0) Payment requests, issue#911. Need to register the tip filter with the given
        #     server.
        pass

    def _on_button_clicked_import(self) -> None:
        # This does nothing. We use a drop down menu on the QPushButton and this is never called.
        pass

    def _on_button_clicked_save(self) -> None:
        """
        The user clicked the "Create"/"Update" button.
        """
        # These are the same constraints imposed in the receive view.
        message = self._receive_message_e.text()
        if not message:
            self._main_window_proxy.show_error(_('A description is required.'))
            return

        amount = self._receive_amount_e.get_amount()
        if not amount:
            amount = None

        if self._request_row is None:
            self._on_create_button_clicked(message, amount)
        else:
            self._on_update_button_clicked(message, amount)

    def _on_create_button_clicked(self, message: str, amount: Optional[int]) -> None:
        expires_index = self._expires_combo.currentIndex()
        duration_seconds = EXPIRATION_VALUES[expires_index][1]

        def callback(future: concurrent.futures.Future[list[PaymentRequestRow]]) -> None:
            """
            This callback happens in the database thread. No UI calls can be made in it and any
            UI calls should happen through emitting a signal.

            WARNING: Nothing should be done here that does not happen effectively instantly.
                Database callbacks should hand off work to be done elsewhere, whether in the
                async or UI thread.
            """
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            final_rows = future.result()
            assert len(final_rows) == 1
            self._request_id = final_rows[0].paymentrequest_id
            # While we get the 'PaymentRequestRow' type (used for creation) back, we currently
            # use the `PaymentRequestReadRow` type (used for reads) row type for local storage
            # (which includes related data like value received).
            self._read_request_data_from_database()

            # Attempt to start the process of registering with any server.
            wallet = self._main_window_proxy._wallet
            indexing_server_state = wallet.get_server_state_for_capability(
                ServerCapability.TIP_FILTER)
            if indexing_server_state is not None and \
                    indexing_server_state.connection_flags & \
                        ServerConnectionFlag.TIP_FILTER_READY != 0:
                assert self._request_row is not None
                assert self._request_row.expiration is not None
                assert self._tip_filter_registration_job is None
                job = self._tip_filter_registration_job = TipFilterRegistrationJob([
                    TipFilterRegistrationJobEntry(self._request_row.pushdata_hash,
                    self._request_row.expiration, self._request_row.keyinstance_id) ],
                    logger=self._logger, paymentrequest_id=self._request_id,
                    refresh_callback=self.refresh_form_signal.emit,
                    completion_callback=self.tip_filter_registration_completed_signal.emit)
                self._logger.debug("Creating TipFilterRegistrationJob task %r", job)
                app_state.app.run_coro(monitor_tip_filter_job(indexing_server_state, job))

            assert self._view is not None
            # Notify the view that the dialog now refers to an actual payment request.
            self._view.upgrade_draft_payment_request(self._request_id)
            # Notify the request list that it's contents have changed and it should update.
            self._view._request_list.update_signal.emit()
            # Refresh the contents of this window to reflect it is now an actual payment request.
            def ui_callback(args: tuple[Any, ...]) -> None:
                self._update_destination()
                self._update_receive_qr()
                self._update_form()
            self._main_window_proxy.ui_callback_signal.emit(ui_callback, ())

        future, _key_data = self._account.create_payment_request(message, amount, duration_seconds,
            self._request_type)
        future.add_done_callback(callback)

        # Prevent double-clicking.
        self._save_button.setEnabled(False)

    def _on_update_button_clicked(self, message: str, amount: Optional[int]) -> None:
        assert self._request_row is not None

        def callback(future: concurrent.futures.Future[None]) -> None:
            """
            This callback happens in the database thread. No UI calls can be made in it and any
            UI calls should happen through emitting a signal.
            """
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()

            assert self._view is not None
            self._view._request_list.update_signal.emit()
            def ui_callback(args: tuple[Any, ...]) -> None:
                self.close()
            self._main_window_proxy.ui_callback_signal.emit(ui_callback, ())

        wallet = self._account.get_wallet()
        # NOTE We do not allow updating the expiration date at this time. For tip filtering
        #     server registrations if we do support this in the future, we will need to do a
        #     different form of update where it contacts the server and modifies it.
        entries = [ PaymentRequestUpdateRow(self._request_row.state, amount,
            self._request_row.expiration, message, self._request_row.paymentrequest_id) ]
        future = wallet.data.update_payment_requests(entries)
        future.add_done_callback(callback)

    def _on_request_expired(self) -> None:
        self._update_form()

    def _attempt_import_transaction(self, tx: Transaction,
            tx_context: Optional[TransactionContext]) -> None:
        assert self._request_row is not None
        if not tx.is_complete():
            MessageBox.show_error(_("This transaction has not been finalised"), self)
            return

        wallet = self._main_window_proxy._wallet
        if tx_context is None:
            tx_context = TransactionContext()
        wallet.populate_transaction_context_key_data_from_database_keys(tx, tx_context)

        for key_data in tx_context.key_datas_by_txo_index.values():
            if key_data.keyinstance_id == self._request_row.keyinstance_id:
                break
        else:
            MessageBox.show_error(_("The given transaction does not make a payment for this "
                "payment request."), self)
            return

        # NOTE(output-spends) This will trigger registration for output spend events to monitor
        #     if this transaction gets broadcast externally.
        tx_state = TxFlags.STATE_RECEIVED
        wallet.import_transaction_with_error_callback(tx, tx_state, self.show_error_signal.emit)
        # Importing a transaction implicitly closes any payment requests that are reliant
        # on the payment in that transaction to be satisfied. We also support multiple
        # payments satisfying a payment request (address reuse..) so there's also that.

        # TODO(1.4.0) User experience, issue#909. WRT transaction import. We want to show this
        #     transaction has been imported visually. Just popping up the transaction dialog does
        #     not make much sense. Having a list on the payment request window and adding it there
        #     is a better idea. We should have a user visible notification that a payment request
        #     has been fully paid, but that would be triggered generally in the wallet code not the
        #     UI code.

    def _on_menu_import_from_file(self) -> None:
        tx, tx_context = self._main_window_proxy.prompt_obtain_transaction_from_file()
        if tx is not None:
            self._attempt_import_transaction(tx, tx_context)

    def _on_menu_import_from_blockchain(self) -> None:
        tx, tx_context = self._main_window_proxy.prompt_obtain_transaction_from_txid()
        if tx is not None:
            self._attempt_import_transaction(tx, tx_context)

    def _on_menu_import_from_text(self) -> None:
        tx, tx_context = self._main_window_proxy.prompt_obtain_transaction_from_text()
        if tx is not None:
            self._attempt_import_transaction(tx, tx_context)

    def _on_menu_import_from_qrcode(self) -> None:
        def callback(text: Optional[str]) -> None:
            assert text is not None
            tx, tx_context = self._main_window_proxy._wallet.load_transaction_from_text(text)
            if tx is not None:
                self._attempt_import_transaction(tx, tx_context)
        self._main_window_proxy.read_qrcode_and_call_callback(callback, expect_transaction=True)
