from typing import List, Optional, TYPE_CHECKING
import weakref

from PyQt5.QtCore import QEvent, Qt
from PyQt5.QtWidgets import (QComboBox, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QVBoxLayout, QWidget)

from electrumsv.app_state import app_state
from electrumsv.bitcoin import script_template_to_string
from electrumsv.constants import PaymentFlag, RECEIVING_SUBPATH
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.wallet_database.tables import KeyInstanceRow
from electrumsv import web

from .amountedit import AmountEdit, BTCAmountEdit
from .constants import expiration_values
if TYPE_CHECKING:
    from .main_window import ElectrumWindow
from .qrcodewidget import QRCodeWidget
from .qrwindow import QR_Window
from .request_list import RequestList
from .table_widgets import TableTopButtonLayout
from .util import ButtonsLineEdit, EnterButton, HelpLabel


class ReceiveView(QWidget):
    _qr_window: Optional[QR_Window] = None

    def __init__(self, main_window: 'ElectrumWindow', account_id: int) -> None:
        super().__init__(main_window)

        self._main_window = weakref.proxy(main_window)
        self._account_id = account_id
        self._account = main_window._wallet.get_account(account_id)
        self._logger = logs.get_logger(f"receive-view[{self._account_id}]")

        self._receive_key_id: Optional[int] = None

        self._request_list_toolbar_layout = TableTopButtonLayout()
        self._request_list_toolbar_layout.refresh_signal.connect(
            self._main_window.refresh_wallet_display)
        self._request_list_toolbar_layout.filter_signal.connect(self._filter_request_list)

        form_layout = self.create_form_layout()
        self._request_list = RequestList(self, main_window)
        request_container = self.create_request_list_container()

        vbox = QVBoxLayout(self)
        vbox.addLayout(form_layout)
        vbox.addSpacing(20)
        vbox.addWidget(request_container, 1)
        self.setLayout(vbox)

    def clean_up(self) -> None:
        # If there are no accounts there won't be a receive QR code object created yet.
        if self._receive_qr is not None:
            self._receive_qr.clean_up()
        if self._qr_window is not None:
            self._qr_window.close()

    def create_form_layout(self) -> QHBoxLayout:
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        self._receive_destination_e = ButtonsLineEdit()
        self._receive_destination_e.addCopyButton(app_state.app)
        self._receive_destination_e.setReadOnly(True)
        msg = _('Bitcoin SV payment destination where the payment should be received. '
                'Note that each payment request uses a different Bitcoin SV payment destination.')
        receive_address_label = HelpLabel(_('Receiving destination'), msg)
        self._receive_destination_e.textChanged.connect(self._update_receive_qr)
        self._receive_destination_e.setFocusPolicy(Qt.NoFocus)
        grid.addWidget(receive_address_label, 0, 0)
        grid.addWidget(self._receive_destination_e, 0, 1, 1, -1)

        self._receive_message_e = QLineEdit()
        grid.addWidget(QLabel(_('Description')), 1, 0)
        grid.addWidget(self._receive_message_e, 1, 1, 1, -1)
        self._receive_message_e.textChanged.connect(self._update_receive_qr)

        self._receive_amount_e = BTCAmountEdit()
        grid.addWidget(QLabel(_('Requested amount')), 2, 0)
        grid.addWidget(self._receive_amount_e, 2, 1)
        self._receive_amount_e.textChanged.connect(self._update_receive_qr)

        self._fiat_receive_e = AmountEdit(app_state.fx.get_currency if app_state.fx else '')
        if not app_state.fx or not app_state.fx.is_enabled():
            self._fiat_receive_e.setVisible(False)
        grid.addWidget(self._fiat_receive_e, 2, 2, Qt.AlignLeft)
        self._main_window.connect_fields(self._receive_amount_e, self._fiat_receive_e)

        self._expires_combo = QComboBox()
        self._expires_combo.addItems([i[0] for i in expiration_values])
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
        grid.addWidget(HelpLabel(_('Request expires'), msg), 3, 0)
        grid.addWidget(self._expires_combo, 3, 1)
        self._expires_label = QLineEdit('')
        self._expires_label.setReadOnly(1)
        self._expires_label.setFocusPolicy(Qt.NoFocus)
        self._expires_label.hide()
        grid.addWidget(self._expires_label, 3, 1)

        self._save_request_button = EnterButton(_('Save request'), self._save_form_as_request)
        self._new_request_button = EnterButton(_('New'), self._new_payment_request)

        self._receive_qr = QRCodeWidget(fixedSize=200)
        self._receive_qr.link_to_window(self._toggle_qr_window)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        buttons.addWidget(self._save_request_button)
        buttons.addWidget(self._new_request_button)
        grid.addLayout(buttons, 4, 1, 1, 2)

        vbox_g = QVBoxLayout()
        vbox_g.addLayout(grid)
        vbox_g.addStretch()

        hbox = QHBoxLayout()
        hbox.addLayout(vbox_g)
        hbox.addWidget(self._receive_qr)

        return hbox

    def create_request_list_container(self) -> QGroupBox:
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(6, 0, 6, 6)
        layout.addLayout(self._request_list_toolbar_layout)
        layout.addWidget(self._request_list)

        request_box = QGroupBox()
        request_box.setTitle(_('Requests'))
        request_box.setAlignment(Qt.AlignCenter)
        request_box.setContentsMargins(0, 0, 0, 0)
        request_box.setLayout(layout)
        return request_box

    def update_widgets(self) -> None:
        self._request_list.update()

    def update_destination(self) -> None:
        text = ""
        if self._receive_key_id is not None:
            script_template = self._account.get_script_template_for_id(self._receive_key_id)
            if script_template is not None:
                text = script_template_to_string(script_template)
        self._receive_destination_e.setText(text)

    def update_contents(self) -> None:
        self._expires_label.hide()
        self._expires_combo.show()
        if self._account.is_deterministic():
            fresh_key = self._account.get_fresh_keys(RECEIVING_SUBPATH, 1)[0]
            self.set_receive_key(fresh_key)

    def update_for_fx_quotes(self) -> None:
        if self._account_id is not None:
            edit = (self._fiat_receive_e
                if self._fiat_receive_e.is_last_edited else self._receive_amount_e)
            edit.textEdited.emit(edit.text())

    # Bound to text fields in `_create_receive_form_layout`.
    def _update_receive_qr(self) -> None:
        if self._receive_key_id is None:
            return

        amount = self._receive_amount_e.get_amount()
        message = self._receive_message_e.text()
        self._save_request_button.setEnabled((amount is not None) or (message != ""))

        script_template = self._account.get_script_template_for_id(self._receive_key_id)
        address_text = script_template_to_string(script_template)

        uri = web.create_URI(address_text, amount, message)
        self._receive_qr.setData(uri)
        if self._qr_window and self._qr_window.isVisible():
            self._qr_window.set_content(self._receive_destination_e.text(), amount,
                                       message, uri)

    def _toggle_qr_window(self, event: QEvent) -> None:
        if self._receive_key_id is None:
            self._main_window.show_message(_("No available receiving destination."))
            return

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

    def set_fiat_ccy_enabled(self, flag: bool) -> None:
        self._fiat_receive_e.setVisible(flag)

    def get_bsv_edits(self) -> List[BTCAmountEdit]:
        return [ self._receive_amount_e ]

    def _save_form_as_request(self) -> None:
        if not self._receive_key_id:
            self._main_window.show_error(_('No receiving payment destination'))
            return

        amount = self._receive_amount_e.get_amount()
        message = self._receive_message_e.text()
        if not message and not amount:
            self._main_window.show_error(_('No message or amount'))
            return

        def callback(exc_value: Optional[Exception]=None) -> None:
            if exc_value is not None:
                raise exc_value # pylint: disable=raising-bad-type
            self._request_list.update_signal.emit()

        i = self._expires_combo.currentIndex()
        expiration = [x[1] for x in expiration_values][i]
        row = self._account.requests.get_request_for_key_id(self._receive_key_id)
        if row is None:
            row = self._account.requests.create_request(self._receive_key_id,
                PaymentFlag.UNPAID, amount, expiration, message, callback)
        else:
            # Expiration is just a label, so we don't use the value.
            self._account.requests.update_request(row.paymentrequest_id, row.state, amount,
                row.expiration, message, callback)
        self._save_request_button.setEnabled(False)

    def _new_payment_request(self) -> None:
        keyinstances: List[KeyInstanceRow] = []
        if self._account.is_deterministic():
            keyinstances = self._account.get_fresh_keys(RECEIVING_SUBPATH, 1)
        if not len(keyinstances):
            if not self._account.is_deterministic():
                msg = [
                    _('No more payment destinations in your wallet.'),
                    _('You are using a non-deterministic account, which '
                      'cannot create new payment destinations.'),
                    _('If you want to create new payment destinations, '
                        'use a deterministic account instead.')
                   ]
                self._main_window.show_message(' '.join(msg))
                return
            self._main_window.show_message(
                _('Your wallet is broken and could not allocate a new payment destination.'))

        self.update_contents()

        self._new_request_button.setEnabled(False)
        self._receive_message_e.setFocus(1)

    def get_receive_key_id(self) -> Optional[int]:
        return self._receive_key_id

    # Only called from key list menu.
    def receive_at_id(self, key_id: int) -> None:
        self._receive_key_id = key_id
        self._new_request_button.setEnabled(True)
        self.update_destination()

        self._main_window.show_receive_tab()

    def set_receive_key_id(self, key_id: int) -> None:
        self._receive_key_id = key_id

    def set_receive_key(self, keyinstance: KeyInstanceRow) -> None:
        self._receive_key_id = keyinstance.keyinstance_id
        self._receive_message_e.setText("")
        self._receive_amount_e.setAmount(None)
        self.update_destination()

    def set_form_contents(self, address_text: str, value: int, description: Optional[str]=None,
            expires_description: str="") -> None:
        self._receive_destination_e.setText(address_text)
        self._receive_message_e.setText(description or "")
        self._receive_amount_e.setAmount(value)
        self._expires_combo.hide()
        self._expires_label.show()
        self._expires_label.setText(expires_description)
        self._new_request_button.setEnabled(True)

    def set_new_button_enabled(self, flag: bool) -> None:
        self._new_request_button.setEnabled(flag)

    def _filter_request_list(self, text: str) -> None:
        self._request_list.filter(text)
