from __future__ import annotations
import asyncio
from concurrent.futures import Future
import time
from typing import Any, cast, TYPE_CHECKING
import weakref

from bitcoinx import Script

from PyQt6.QtCore import pyqtSignal, Qt, QTimer
from PyQt6.QtGui import QCloseEvent, QCursor, QKeyEvent
from PyQt6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QLayout, QLineEdit, \
    QMenu, QToolTip, QVBoxLayout

from ... import web
from ...app_state import app_state, get_app_state_qt
from ...bitcoin import script_template_to_string
from ...constants import PaymentFlag, PushDataHashRegistrationFlag
from ...exceptions import NoViableServersError, ServerConnectionError, ServiceUnavailableError, \
    UserCancelled
from ...i18n import _
from ...logs import logs
from ...networks import Net, TEST_NETWORK_NAMES
from ...standards.script_templates import classify_transaction_output_script
from ...transaction import Transaction, TransactionContext
from ...util import age
from ...wallet_database.types import PaymentRequestUpdateRow

from .amountedit import AmountEdit, BTCAmountEdit
from .qrcodewidget import QRCodeWidget
from .qrwindow import QR_Window
from .util import Buttons, EnterButton, FormSectionWidget, FormSeparatorLine, HelpDialogButton, \
    MessageBox

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
    from .receive_view import ReceiveView
    from ...wallet import AbstractAccount, HostedInvoiceCreationResult
    from ...wallet_database.types import PaymentRequestRow, PaymentRequestOutputRow


EXPIRATION_VALUES: list[tuple[str, int | None]] = [
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


CREATE_REQUEST_TYPES = { PaymentFlag.TYPE_IMPORTED, PaymentFlag.TYPE_MONITORED,
    PaymentFlag.TYPE_INVOICE }

class ReceiveDialog(QDialog):
    """
    Display a popup window with a form containing the details of an existing expected payment.
    """
    show_error_signal = pyqtSignal(str)
    refresh_form_signal = pyqtSignal()
    refresh_after_create_signal = pyqtSignal()

    _qr_window: QR_Window | None = None
    _fiat_receive_e: AmountEdit
    _receive_amount_e: BTCAmountEdit
    _timer: QTimer | None = None

    def __init__(self, main_window: ElectrumWindow, view: ReceiveView, account_id: int,
            request_id: int | None, request_type: PaymentFlag,
            request_state: PaymentFlag=PaymentFlag.STATE_PREPARING) -> None:
        super().__init__(main_window)

        # NOTE(PyQt6) @ModalDialogLeakage
        # If we do not set this, this dialog does not get garbage collected and `main_window`
        # appears in `gc.get_referrers(self)` as a direct reference. So a `QDialog` merely having a
        # parent stored at the Qt level can create a circular reference, apparently. With this set,
        # the dialog will be gc'd on the next `collect` call.
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)

        self._logger = logs.get_logger(f"receive-dialog[{account_id},{request_id}]")

        self._view: ReceiveView | None = view
        self._main_window_proxy: ElectrumWindow = weakref.proxy(main_window)
        self._account_id = account_id
        self._account = cast("AbstractAccount", main_window._wallet.get_account(account_id))

        self._request_id = request_id
        self._request_type = request_type
        self._request_state = request_state

        self._request_row: PaymentRequestRow | None = None
        self._request_output_rows: list[PaymentRequestOutputRow] = []

        if request_id is not None:
            # We are going to read the database entry for this payment request anyway, so the
            # convention is that the request type must be `NONE` if a request id is provided.
            assert request_type == PaymentFlag.NONE
            self._read_request_data_from_database()
            assert self._request_row is not None
            request_type = self._request_row.request_flags & PaymentFlag.MASK_TYPE
            self._request_type = request_type
        else:
            assert request_type in CREATE_REQUEST_TYPES

        title_text = _("Expected payment")
        if request_type == PaymentFlag.TYPE_MONITORED:
            title_text += " - "+ _("Legacy Bitcoin payment")
        elif request_type == PaymentFlag.TYPE_IMPORTED:
            title_text += " - "+ _("Transaction import")
        elif request_type == PaymentFlag.TYPE_INVOICE:
            title_text += " - "+ _("Payment request (DPP)")
        elif request_type == PaymentFlag.TYPE_LEGACY:
            title_text += " - "+ _("Legacy payment request")
        self.setWindowTitle(title_text)

        self._layout_pending = True
        self.setLayout(self._create_form_layout())
        self._connect_widgets()
        self._layout_pending = False

        self._on_fiat_ccy_changed()
        self._update_destination()
        if self._request_row is not None:
            self._receive_amount_e.setAmount(self._request_row.requested_value)

        self.show_error_signal.connect(self._show_error)
        self.refresh_form_signal.connect(self._update_form)
        self.refresh_after_create_signal.connect(self._refresh_after_create)

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
            self._update_form()
        else:
            super().keyPressEvent(event)

    def _show_error(self, text: str) -> None:
        """
        Helper method to be called through the signal so that messages are displayed on the GUI
        thread.
        """
        MessageBox.show_error(text, self)

    def _read_request_data_from_database(self) -> None:
        assert self._request_id is not None
        wallet = self._main_window_proxy._wallet
        request_row, request_output_rows = wallet.data.read_payment_request(
            request_id=self._request_id)
        assert request_row is not None
        self._set_request_rows(request_row, request_output_rows)

    def _set_request_rows(self, request_row: PaymentRequestRow|None,
            request_output_rows: list[PaymentRequestOutputRow]) -> None:
        self._request_row = request_row
        self._request_output_rows = request_output_rows
        if request_row is None:
            self._request_id = None
            self._request_state = PaymentFlag.NONE
        else:
            assert request_row.paymentrequest_id is not None
            self._request_id = request_row.paymentrequest_id
            self._request_state = request_row.request_flags & PaymentFlag.MASK_STATE

    def get_paymentrequest_id(self) -> int | None:
        return self._request_id

    def _on_payment_requests_paid(self, paymentrequest_ids: list[int]) -> None:
        if self._request_id not in paymentrequest_ids:
            return

        self._read_request_data_from_database()
        self._update_form()

    def _start_expiry_timer(self, expiry_timestamp: int | None) -> None:
        """
        When the payment expires the dialog should update to reflect it in order to provide a
        polished user experience.
        """
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        if expiry_timestamp is not None:
            interval_ms = (expiry_timestamp - int(time.time())) * 1000
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
            request_type = self._request_row.request_flags & PaymentFlag.MASK_TYPE
        assert request_type in { PaymentFlag.TYPE_MONITORED, PaymentFlag.TYPE_IMPORTED,
            PaymentFlag.TYPE_INVOICE }

        self._status_label = QLabel()
        self._status_label.setWordWrap(True)

        form.add_row(_("Status"), self._status_label)
        form.set_row_visible_for_object(self._status_label, False)

        form.add_row(_("Account"), QLabel(self._account.get_name()))

        self._payment_url = ""

        self._receive_amount_e = BTCAmountEdit()
        self._fiat_receive_e = AmountEdit(app_state.fx.get_currency if app_state.fx else lambda: '')
        self._main_window_proxy.connect_fields(self._receive_amount_e, self._fiat_receive_e)

        amount_widget_layout = QHBoxLayout()
        amount_widget_layout.addWidget(self._receive_amount_e)
        amount_widget_layout.addSpacing(10)
        amount_widget_layout.addWidget(self._fiat_receive_e)
        form.add_row(_('Requested amount'), amount_widget_layout)

        self._their_description_edit = QLineEdit()
        self._their_description_edit.setPlaceholderText(_("Reason for payment"))
        self._their_description_edit.setToolTip(_("Your counterparty will see this, telling them "
            "what they are paying for"))
        form.add_row(_("Purpose"), self._their_description_edit)
        self._their_description_edit.setText(
            "" if self._request_row is None or self._request_row.merchant_reference is None
            else self._request_row.merchant_reference)

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

        self._your_description_edit = QLineEdit()
        self._your_description_edit.setPlaceholderText(_("Counterparty and note"))
        self._your_description_edit.setToolTip(_("Name of counterparty and a note for your "
            "records. They will not see this note."))
        form.add_row(_('Personal reference'), self._your_description_edit)
        self._your_description_edit.setText(
            "" if self._request_row is None or self._request_row.description is None
            else self._request_row.description)

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
        if request_type not in { PaymentFlag.TYPE_IMPORTED, PaymentFlag.TYPE_MONITORED }:
            self._import_button.hide()

        self._save_button = EnterButton(_('Update'), self._on_button_clicked_save)
        self._close_button = EnterButton(_('Cancel'), self._on_button_clicked_close)

        buttons = Buttons(self._import_button, self._save_button,
            self._close_button)
        buttons.add_left_button(self._help_button)

        self._receive_qr = QRCodeWidget(fixedSize=200)
        self._copy_link_button = EnterButton(_('Copy payment link'), self._copy_qr_data)
        self._receive_qr_layout = QVBoxLayout()
        self._receive_qr_layout.addWidget(self._receive_qr)
        self._receive_qr_layout.addWidget(self._copy_link_button)
        self._receive_qr_layout.setSizeConstraint(QLayout.SizeConstraint.SetMinimumSize)

        form_vbox = QVBoxLayout()
        form_vbox.addWidget(form)
        form_vbox.addStretch(1)

        hbox = QHBoxLayout()
        hbox.addLayout(form_vbox)
        self._hbox = hbox

        buttons_line = FormSeparatorLine()

        vbox = QVBoxLayout()
        vbox.addLayout(hbox)
        vbox.addWidget(buttons_line)
        vbox.addLayout(buttons)

        self._update_form()

        return vbox

    def _connect_widgets(self) -> None:
        # These are part of the payment URL encoded by the QR code.
        self._their_description_edit.textChanged.connect(self._update_receive_qr)
        self._receive_amount_e.textChanged.connect(self._update_receive_qr)
        # Clicking on the QR code opens the QR window.
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
        """
        Visual update of the destination-related fields.
        """
        self._payment_url = ""
        if self._request_type == PaymentFlag.TYPE_INVOICE:
            if self._request_row is not None:
                assert self._request_row is not None
                assert self._request_row.server_id is not None
                assert self._request_row.dpp_invoice_id is not None

                wallet = self._account.get_wallet()
                server_url = wallet.get_dpp_server_url(self._request_row.server_id)
                self._payment_url = f"pay:?r={server_url}api/v1/payment/" \
                    f"{self._request_row.dpp_invoice_id}"
        elif self._request_type in { PaymentFlag.TYPE_MONITORED, PaymentFlag.TYPE_IMPORTED }:
            if self._request_row is not None:
                assert len(self._request_output_rows) == 1
                output_script = Script(self._request_output_rows[0].output_script_bytes)
                script_type, threshold, script_template = classify_transaction_output_script(
                    output_script)
                self._payment_url = script_template_to_string(script_template)
        else:
            raise NotImplementedError(f"Unexpected request type {self._request_type}")

        self._update_receive_qr()

    def _update_receive_qr(self) -> None:
        if self._layout_pending or self._request_id is None:
            return

        amount = self._receive_amount_e.get_amount()
        message = self._their_description_edit.text()
        self._save_button.setEnabled((amount is not None) or (message != ""))

        if self._request_row is None:
            return

        if self._request_type == PaymentFlag.TYPE_INVOICE:
            assert self._request_row.server_id is not None
            assert self._request_row.dpp_invoice_id is not None
            wallet = self._account.get_wallet()
            server_url = wallet.get_dpp_server_url(self._request_row.server_id)
            payment_url = f"pay:?r={server_url}api/v1/payment/" \
                f"{self._request_row.dpp_invoice_id}"
            self._receive_qr.setData(payment_url)
            if self._qr_window and self._qr_window.isVisible():
                self._qr_window.set_content(self._payment_url, amount, message, payment_url)
        elif self._request_type in { PaymentFlag.TYPE_MONITORED, PaymentFlag.TYPE_IMPORTED }:
            assert len(self._request_output_rows) == 1
            output_script = Script(self._request_output_rows[0].output_script_bytes)
            script_type, threshold, script_template = classify_transaction_output_script(
                output_script)
            address_text = script_template_to_string(script_template)
            uri = web.create_URI(address_text, amount, message)
            self._receive_qr.setData(uri)
            if self._qr_window and self._qr_window.isVisible():
                self._qr_window.set_content(self._payment_url, amount, message, uri)
        else:
            raise NotImplementedError(f"Unexpected request type {self._request_type}")

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
        """
        There are three states we display:
        1. The pre-creation form for the user to specify the details of the payment they
           wish to receive.
        2. The mid-creation locked down version of the pre-creation form.
        3. The post-creation/edit form.
        """
        if self._request_id is None or self._request_state == PaymentFlag.STATE_PREPARING:
            # Create mode.
            self._save_button.setText(_("Create"))
            self._copy_link_button.setEnabled(False)
            self._import_button.setEnabled(False)
            self._expires_label.setVisible(False)
            self._expires_combo.setVisible(True)
            self._start_expiry_timer(None)
            return

        # Edit mode.
        status_text = ""
        enable_import = False

        assert self._request_row is not None
        expiry_timestamp: int | None = None
        if self._request_type == PaymentFlag.TYPE_MONITORED:
            wallet = self._main_window_proxy._wallet
            monitored_row = wallet.data.read_registered_tip_filter_pushdata_for_request(
                self._request_id)
            if monitored_row is not None:
                assert monitored_row.pushdata_flags & PushDataHashRegistrationFlag.DELETED == 0
                if monitored_row.pushdata_flags == PushDataHashRegistrationFlag.NONE:
                    expiry_timestamp = monitored_row.date_created+monitored_row.duration_seconds
                # We allow imports for successfully registered unpaid invoices.
                enable_import = (self._request_row.request_flags & PaymentFlag.MASK_STATE) \
                    != PaymentFlag.STATE_PAID
        elif self._request_type == PaymentFlag.TYPE_IMPORTED:
            # We allow imports at any time as long as it has not already been paid. The user
            # is in control of this type of invoice, who knows how they are getting this
            # transaction or why they delayed in importing it.
            enable_import = (self._request_row.request_flags & PaymentFlag.MASK_STATE) \
                != PaymentFlag.STATE_PAID
            if self._request_row.date_expires:
                expiry_timestamp = self._request_row.date_expires
        elif self._request_type in { PaymentFlag.TYPE_INVOICE, PaymentFlag.TYPE_LEGACY }:
            pass
        else:
            raise NotImplementedError(f"Unknown request type {self._request_type}")

        # When transitioning from "create" mode to "edit" mode display the right-hand side.
        if self._hbox.count() < 2:
            self._hbox.addLayout(self._receive_qr_layout)

        self._save_button.setText(_("Update"))
        self._copy_link_button.setEnabled(True)
        self._import_button.setEnabled(enable_import)
        self._expires_label.setText(age(expiry_timestamp).capitalize() \
            if expiry_timestamp is not None else _('Never') +".")
        self._expires_label.setVisible(True)
        self._expires_combo.setVisible(False)

        self._status_label.setText(status_text)
        self._form.set_row_visible_for_object(self._status_label, False)

        self._start_expiry_timer(expiry_timestamp)

    def _on_button_clicked_import(self) -> None:
        # This does nothing. We use a drop down menu on the QPushButton and this is never called.
        pass

    def _on_button_clicked_save(self) -> None:
        """
        The user clicked the "Create"/"Update" button.
        """
        # These are the same constraints imposed in the receive view.
        your_text = self._your_description_edit.text().strip()
        if len(your_text) == 0:
            self._main_window_proxy.show_error(_('Your description is required.'))
            return

        their_text: str | None = None
        raw_their_text = self._their_description_edit.text().strip()
        if len(raw_their_text) > 0:
            their_text = raw_their_text

        amount = self._receive_amount_e.get_amount()
        if amount is None or amount <= 0:
            self._main_window_proxy.show_error(_('An amount is required.'))
            return

        if self._request_row is None:
            self._on_create_button_clicked(amount, your_text, their_text)
        else:
            self._on_update_button_clicked(amount, your_text, their_text)

    def _on_create_button_clicked(self, amount: int, your_text: str, their_text: str | None) \
            -> None:
        expires_index = self._expires_combo.currentIndex()
        duration_seconds = EXPIRATION_VALUES[expires_index][1]

        date_expires: int | None = None
        if duration_seconds is not None:
            date_expires = int(time.time()) + duration_seconds

        if self._request_type == PaymentFlag.TYPE_INVOICE:
            def ui_callback(future: Future[HostedInvoiceCreationResult]) -> None:
                """ `run_coro` ensures that our `on_done` callback happens in the UI thread. """
                if future.cancelled():
                    return

                try:
                    result = future.result()
                except UserCancelled:
                    # AbstractAccount.
                    pass
                except ServerConnectionError:
                    # TODO(1.4.0) DPP. The connection time out is something like 5 seconds. If we
                    #     cannot connect then there is a lag when the UI sits there before the
                    #     error appears. We need a progress dialog.
                    MessageBox.show_error(_("There was a problem hosting this invoice with "
                        "the selected invoice server."), self)
                except NoViableServersError:
                    MessageBox.show_error(_("None of the known invoice servers are "
                        "currently accessible."), self)
                else:
                    self._set_request_rows(result.request_row, result.request_output_rows)

                    self._refresh_after_create()

            assert date_expires is not None
            app_state.app.run_coro(self._account.create_hosted_invoice_async(amount,
                date_expires, your_text, their_text), on_done=ui_callback)
        elif self._request_type == PaymentFlag.TYPE_MONITORED:
            async def legacy_request_creation_process_async() -> None:
                """
                WARNING: This is running in the async thread. Qt calls should be done in the GUI
                    thread and otherwise signals used to trigger those calls from other threads.
                """
                future = app_state.async_.spawn(
                    self._account.create_monitored_blockchain_payment_async(amount, your_text,
                        merchant_reference=their_text, date_expires=date_expires))
                self._logger.debug("Waiting for tip filter registration completion")
                try:
                    request_row, request_output_rows, job_output = await asyncio.wrap_future(future)
                except NoViableServersError:
                    self.show_error_signal.emit(_("You do not appear to be registered with a "
                        "blockchain server. This is unexpected. Consider reporting this "
                        "to the ElectrumSV developers."))
                    return
                except ServiceUnavailableError:
                    self.show_error_signal.emit(_("You are not currently connected to your "
                        "blockchain server to the point where it can monitor your legacy "
                        "payments. Please wait and try again."))
                    return

                # NOTE(rt12) We would do something here to indicate progress?
                if job_output.date_registered is None:
                    self._logger.debug("Tip filter registration failure detected")
                else:
                    self._set_request_rows(request_row, request_output_rows)
                    self._logger.debug("Tip filter registration success detected %d",
                        self._request_id)
                self.refresh_after_create_signal.emit()

            app_state.app.run_coro(legacy_request_creation_process_async())
        elif self._request_type == PaymentFlag.TYPE_IMPORTED:
            async def imported_request_creation_process_async() -> None:
                request_row, request_output_rows = \
                    await self._account.create_payment_request_async(amount, your_text,
                        merchant_reference=their_text, date_expires=date_expires,
                        flags=PaymentFlag.TYPE_IMPORTED)
                self._set_request_rows(request_row, request_output_rows)
                self.refresh_after_create_signal.emit()

            app_state.app.run_coro(imported_request_creation_process_async())

        self._save_button.setEnabled(False)

    def _refresh_after_create(self) -> None:
        """
        Raises nothing.
        """
        assert self._request_row is not None
        assert self._request_id is not None

        assert self._view is not None
        # Notify the view that the dialog now refers to an actual payment request.
        self._view.upgrade_draft_payment_request(self._request_id)
        # Notify the request list that it's contents have changed and it should update.
        self._view._request_list.update_signal.emit()
        # Refresh the contents of this window to reflect it is now an actual payment
        # request. This is safe to do here because we are in the UI thread.
        self._refresh()

    def _refresh(self) -> None:
        self._update_destination()
        self._update_form()

    def _on_update_button_clicked(self, amount: int, your_text: str,
            their_text: str | None) -> None:
        assert self._request_row is not None
        assert self._request_row.paymentrequest_id is not None

        def callback(future: Future[None]) -> None:
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
        entries = [ PaymentRequestUpdateRow(self._request_row.request_flags, amount,
            self._request_row.date_expires, your_text, their_text,
            None, self._request_row.paymentrequest_id) ]
        future = wallet.data.update_payment_requests(entries)
        future.add_done_callback(callback)

    def _on_request_expired(self) -> None:
        self._update_form()

    def _attempt_import_transactions(self, candidates: list[tuple[Transaction,
            TransactionContext | None]]) -> None:
        """
        This is the manual import path. In theory it is the same as any direct P2P path.
        """
        assert self._request_id is not None

        wallet = self._main_window_proxy._wallet
        try:
            app_state.async_.spawn_and_wait(wallet.close_payment_request_async(self._request_id,
                candidates, self.show_error_signal.emit))
        except ValueError as exception_value:
            MessageBox.show_error(exception_value.args[0], self)
            return

        # TODO(1.4.0) User experience, issue#909. WRT transaction import. We want to show this
        #     transaction has been imported visually. Just popping up the transaction dialog does
        #     not make much sense. Having a list on the payment request window and adding it there
        #     is a better idea. We should have a user visible notification that a payment request
        #     has been fully paid, but that would be triggered generally in the wallet code not the
        #     UI code.

    def _on_menu_import_from_file(self) -> None:
        matches = self._main_window_proxy.prompt_obtain_transactions_from_files(
            multiple=True)
        if len(matches) > 0:
            self._attempt_import_transactions(matches)

    def _on_menu_import_from_blockchain(self) -> None:
        tx, tx_context = self._main_window_proxy.prompt_obtain_transaction_from_txid()
        if tx is not None:
            self._attempt_import_transactions([ (tx, tx_context) ])

    def _on_menu_import_from_text(self) -> None:
        tx, tx_context = self._main_window_proxy.prompt_obtain_transaction_from_text(
            ok_text=_("Import"))
        if tx is not None:
            self._attempt_import_transactions([ (tx, tx_context) ])

    def _on_menu_import_from_qrcode(self) -> None:
        def callback(raw: bytes | None) -> None:
            assert raw is not None
            tx, tx_context = self._main_window_proxy._wallet.load_transaction_from_bytes(raw)
            if tx is not None:
                self._attempt_import_transactions([ (tx, tx_context) ])
        self._main_window_proxy.read_qrcode_and_call_callback(callback, expect_transaction=True)
