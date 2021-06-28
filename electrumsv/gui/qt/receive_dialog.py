import concurrent.futures
from typing import List, Optional, TYPE_CHECKING
import weakref

from PyQt5.QtCore import QEvent, Qt
from PyQt5.QtGui import QCloseEvent
from PyQt5.QtWidgets import (QComboBox, QDialog, QGridLayout, QHBoxLayout, QLabel,
    QLineEdit, QVBoxLayout)

from ...app_state import app_state
from ...bitcoin import script_template_to_string
from ...i18n import _
from ...logs import logs
from ...util import age
from ... import web
from ...wallet_database.types import KeyDataTypes, PaymentRequestUpdateRow

from .amountedit import AmountEdit, BTCAmountEdit
from .constants import EXPIRATION_VALUES
if TYPE_CHECKING:
    from .main_window import ElectrumWindow
from .qrcodewidget import QRCodeWidget
from .qrwindow import QR_Window
from .util import ButtonsLineEdit, EnterButton, HelpLabel


# TODO(no-merge) Test that the update works correctly.
# TODO(no-merge) Consider allowing modification of the expiry date.
# TODO(no-merge) Add copy URL button.
# TODO(no-merge) Polish the layout, move the fiat value down under the BSV value, maybe
#     just disable it if fiat is not enabled but keep it visible. If this is done, then it might
#     be worth considering doing the same for the send tab/view.

class ReceiveDialog(QDialog):
    """
    Display a popup window with a form containing the details of an existing expected payment.
    """
    _qr_window: Optional[QR_Window] = None

    def __init__(self, main_window: 'ElectrumWindow', account_id: int, request_id: int) -> None:
        super().__init__(main_window)
        self.setWindowTitle(_("Expected payment"))

        self._main_window = weakref.proxy(main_window)
        self._account_id = account_id
        self._account = main_window._wallet.get_account(account_id)
        self._request_id = request_id
        self._read_only = False

        self._logger = logs.get_logger(f"receive-dialog[{self._account_id},{self._request_id}]")

        wallet = self._account.get_wallet()
        self._request_row = wallet.read_payment_request(request_id=self._request_id)
        self._key_data = wallet.read_keyinstance(keyinstance_id=self._request_row.keyinstance_id)
        self._receive_key_data: Optional[KeyDataTypes] = None

        self._layout_pending = True
        self.setLayout(self._create_form_layout())
        self._layout_pending = False

        self.update_destination()
        self._receive_amount_e.setAmount(self._request_row.value)

        # TODO(no-merge) Verify that these get disconnected on exit.
        app_state.app.fiat_ccy_changed.connect(self._on_fiat_ccy_changed)
        self._main_window.new_fx_quotes_signal.connect(self._on_ui_exchange_rate_quotes)

    def closeEvent(self, event: QCloseEvent) -> None:
        # If there are no accounts there won't be a receive QR code object created yet.
        if self._receive_qr is not None:
            self._receive_qr.clean_up()
        if self._qr_window is not None:
            self._qr_window.close()
        self._main_window.new_fx_quotes_signal.disconnect(self._on_ui_exchange_rate_quotes)
        app_state.app.fiat_ccy_changed.disconnect(self._on_fiat_ccy_changed)
        super().closeEvent(event)

    def _on_fiat_ccy_changed(self) -> None:
        flag = bool(app_state.fx and app_state.fx.is_enabled())
        self._fiat_receive_e.setVisible(flag)

    def _on_ui_exchange_rate_quotes(self) -> None:
        edit = (self._fiat_receive_e if self._fiat_receive_e.is_last_edited
            else self._receive_amount_e)
        edit.textEdited.emit(edit.text())

    def _create_form_layout(self) -> QHBoxLayout:
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        row = 0
        account_label = QLabel(_("Account"))
        account_name_widget = QLabel(self._account.get_name())
        grid.addWidget(account_label, row, 0)
        grid.addWidget(account_name_widget, row, 1)

        row += 1
        self._receive_destination_e = ButtonsLineEdit()
        self._receive_destination_e.addCopyButton(app_state.app)
        self._receive_destination_e.setReadOnly(True)
        msg = _('Bitcoin SV payment destination where the payment should be received. '
                'Note that each payment request uses a different Bitcoin SV payment destination.')
        receive_address_label = HelpLabel(_('Payment destination'), msg)
        self._receive_destination_e.textChanged.connect(self._update_receive_qr)
        self._receive_destination_e.setFocusPolicy(Qt.NoFocus)
        grid.addWidget(receive_address_label, row, 0)
        grid.addWidget(self._receive_destination_e, row, 1, 1, -1)

        row += 1
        self._receive_message_e = QLineEdit()
        grid.addWidget(QLabel(_('Description')), row, 0)
        grid.addWidget(self._receive_message_e, row, 1, 1, -1)
        self._receive_message_e.textChanged.connect(self._update_receive_qr)
        self._receive_message_e.setText("" if self._request_row.description is None
            else self._request_row.description)

        row += 1
        self._receive_amount_e = BTCAmountEdit()
        grid.addWidget(QLabel(_('Requested amount')), row, 0)
        grid.addWidget(self._receive_amount_e, row, 1)
        self._receive_amount_e.textChanged.connect(self._update_receive_qr)

        self._fiat_receive_e = AmountEdit(app_state.fx.get_currency if app_state.fx else '')
        self._on_fiat_ccy_changed()
        grid.addWidget(self._fiat_receive_e, row, 2, Qt.AlignLeft)
        self._main_window.connect_fields(self._receive_amount_e, self._fiat_receive_e)

        row += 1
        self._expires_combo = QComboBox()
        self._expires_combo.addItems([i[0] for i in EXPIRATION_VALUES])
        self._expires_combo.setCurrentIndex(3)
        self._expires_combo.setFixedWidth(self._receive_amount_e.width())
        msg = ' '.join([
            _('Expiration date of your request.'),
            _('This information is seen by the recipient if you send them '
              'a signed payment request.'),
            _('Expired requests have to be deleted manually from your list, '
              'in order to free the corresponding Bitcoin SV addresses.'),
            _('The Bitcoin SV address never expires and will always be part '
              'of this ElectrumSV wallet.'),
        ])
        grid.addWidget(HelpLabel(_('Request expires'), msg), row, 0)
        self._expires_combo.hide()
        grid.addWidget(self._expires_combo, row, 1)
        expires_text = age(self._request_row.date_created +
            self._request_row.expiration).capitalize() \
                if self._request_row.expiration else _('Never')
        self._expires_label = QLabel(expires_text)
        grid.addWidget(self._expires_label, row, 1)

        row += 1
        self._close_button = EnterButton(_('Close'), self.close)
        self._update_button = EnterButton(_('Update'), self._on_update_button_clicked)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self._close_button)
        buttons.addWidget(self._update_button)
        buttons.addStretch(1)
        grid.addLayout(buttons, row, 0, 1, -1)

        vbox_g = QVBoxLayout()
        vbox_g.addLayout(grid)
        vbox_g.addStretch()

        self._receive_qr = QRCodeWidget(fixedSize=200)
        self._receive_qr.link_to_window(self._toggle_qr_window)

        hbox = QHBoxLayout()
        hbox.addLayout(vbox_g)
        hbox.addWidget(self._receive_qr)

        return hbox

    def update_widgets(self) -> None:
        # This is currently unused, but is called in the generic `update_tabs` call in the
        # wallet window code.
        pass

    def update_destination(self) -> None:
        """
        Update the payment destination field.

        This is called both locally, and from the account information dialog when the script type
        is changed.
        """
        assert self._key_data is not None
        text = ""
        script_template = self._account.get_script_template_for_key_data(self._key_data,
            self._account.get_default_script_type())
        if script_template is not None:
            text = script_template_to_string(script_template)
        self._receive_destination_e.setText(text)

    # Bound to text fields in `_create_receive_form_layout`.
    def _update_receive_qr(self) -> None:
        if self._layout_pending:
            return

        assert self._key_data is not None

        amount = self._receive_amount_e.get_amount()
        message = self._receive_message_e.text()
        self._update_button.setEnabled((amount is not None) or (message != ""))

        script_template = self._account.get_script_template_for_key_data(self._key_data,
            self._account.get_default_script_type())
        address_text = script_template_to_string(script_template)

        uri = web.create_URI(address_text, amount, message)
        self._receive_qr.setData(uri)
        if self._qr_window and self._qr_window.isVisible():
            self._qr_window.set_content(self._receive_destination_e.text(), amount,
                                       message, uri)

    def _toggle_qr_window(self, event: QEvent) -> None:
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

    def get_request_id(self) -> int:
        return self._request_id

    def get_bsv_edits(self) -> List[BTCAmountEdit]:
        return [ self._receive_amount_e ]

    def _on_update_button_clicked(self) -> None:
        """
        The user clicked the "Update" button.
        """
        # These are the same constraints imposed in the receive view.
        message = self._receive_message_e.text()
        if not message:
            self._main_window.show_error(_('A description is required'))
            return

        amount = self._receive_amount_e.get_amount()
        if not amount:
            self._main_window.show_error(_('An amount is required'))
            return

        def callback(future: concurrent.futures.Future) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()

            # NOTE This callback will be happening in the database thread. No UI calls should
            #   be made, unless we emit a signal to do it.
            def ui_callback() -> None:
                self.close()
            self._main_window.ui_callback_signal.emit(ui_callback, ())

        wallet = self._account.get_wallet()
        i = self._expires_combo.currentIndex()
        expiration = [x[1] for x in EXPIRATION_VALUES][i]

        # Expiration is just a label, so we don't use the value.
        entries = [ PaymentRequestUpdateRow(self._request_row.state, amount,
            self._request_row.expiration, message, self._request_row.paymentrequest_id) ]
        future = wallet.update_payment_requests(entries)
        future.add_done_callback(callback)

        self._update_button.setEnabled(False)
