import concurrent.futures
from typing import List, Optional, TYPE_CHECKING
import weakref

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QComboBox, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QVBoxLayout, QWidget)

from ...app_state import app_state
from ...constants import KeyInstanceFlag, PaymentFlag, RECEIVING_SUBPATH
from ...i18n import _
from ...logs import logs
from ...wallet_database.types import KeyDataTypes, PaymentRequestRow
from ...util import get_posix_timestamp

from .amountedit import AmountEdit, BTCAmountEdit
from .constants import EXPIRATION_VALUES
if TYPE_CHECKING:
    from .main_window import ElectrumWindow
from .receive_dialog import ReceiveDialog
from .request_list import RequestList
from .table_widgets import TableTopButtonLayout
from .util import EnterButton, HelpDialogButton, HelpLabel


class ReceiveView(QWidget):
    """
    Display a form for reservation of addresses for new expected payments, as well as a list of
    the existing expected payments.
    """
    def __init__(self, main_window: "ElectrumWindow", account_id: int) -> None:
        super().__init__(main_window)

        self._main_window = weakref.proxy(main_window)
        self._account_id = account_id
        self._account = main_window._wallet.get_account(account_id)
        self._logger = logs.get_logger(f"receive-view[{self._account_id}]")

        self._dialogs: weakref.WeakValueDictionary[int, ReceiveDialog] = \
            weakref.WeakValueDictionary()

        self._request_list_toolbar_layout = TableTopButtonLayout()
        self._request_list_toolbar_layout.refresh_signal.connect(
            self._main_window.refresh_wallet_display)
        self._request_list_toolbar_layout.filter_signal.connect(
            self._filter_request_list)

        form_layout = self._create_form_layout()
        self._request_list = RequestList(self, main_window)
        request_container = self.create_request_list_container()

        vbox = QVBoxLayout(self)
        vbox.addLayout(form_layout)
        vbox.addSpacing(20)
        vbox.addWidget(request_container, 1)
        self.setLayout(vbox)

        app_state.app.fiat_ccy_changed.connect(self._on_fiat_ccy_changed)
        self._main_window.new_fx_quotes_signal.connect(self._on_ui_exchange_rate_quotes)
        self._main_window.payment_requests_paid_signal.connect(self._on_payment_requests_paid)

    def clean_up(self) -> None:
        """
        Called by the main window when it is closed.
        """
        self._main_window.payment_requests_paid_signal.disconnect(self._on_payment_requests_paid)
        self._main_window.new_fx_quotes_signal.disconnect(self._on_ui_exchange_rate_quotes)
        app_state.app.fiat_ccy_changed.disconnect(self._on_fiat_ccy_changed)

    def _on_fiat_ccy_changed(self) -> None:
        """
        Application level event when the user changes a fiat related setting.
        """
        flag = bool(app_state.fx and app_state.fx.is_enabled())
        self._fiat_receive_e.setVisible(flag)

    def _on_ui_exchange_rate_quotes(self) -> None:
        """
        Window level event when there is a new known exchange rate for the current currency.
        """
        edit = (self._fiat_receive_e
            if self._fiat_receive_e.is_last_edited else self._receive_amount_e)
        edit.textEdited.emit(edit.text())

    def _on_payment_requests_paid(self) -> None:
        self.update_widgets()

    def _create_form_layout(self) -> QVBoxLayout:
        # A 4-column grid layout.  All the stretch is in the last column.
        # The exchange rate plugin adds a fiat widget in column 2
        grid = QGridLayout()
        grid.setSpacing(8)
        grid.setColumnStretch(3, 1)

        self._receive_message_e = QLineEdit()
        grid.addWidget(QLabel(_('Description')), 1, 0)
        grid.addWidget(self._receive_message_e, 1, 1, 1, -1)

        self._receive_amount_e = BTCAmountEdit()
        grid.addWidget(QLabel(_('Requested amount')), 2, 0)
        grid.addWidget(self._receive_amount_e, 2, 1)

        self._fiat_receive_e = AmountEdit(app_state.fx.get_currency if app_state.fx else '')
        if not app_state.fx or not app_state.fx.is_enabled():
            self._fiat_receive_e.setVisible(False)
        grid.addWidget(self._fiat_receive_e, 2, 2, Qt.AlignmentFlag.AlignLeft)
        self._main_window.connect_fields(self._receive_amount_e, self._fiat_receive_e)

        self._expires_combo = QComboBox()
        self._expires_combo.addItems([i[0] for i in EXPIRATION_VALUES])
        self._expires_combo.setCurrentIndex(2)
        self._expires_combo.setFixedWidth(self._receive_amount_e.width())
        msg = ' '.join([
            _('Expiration date of your request.'),
            _('This information is seen by the recipient if you send them '
              'a signed payment request.'),
        ])
        grid.addWidget(HelpLabel(_('Request expires'), msg), 3, 0)
        # These two expiry date value related widgets overlap and only one shows at once.
        grid.addWidget(self._expires_combo, 3, 1)
        self._expires_label = QLineEdit('')
        self._expires_label.setReadOnly(True)
        self._expires_label.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._expires_label.hide()
        grid.addWidget(self._expires_label, 3, 1)

        self._help_button = HelpDialogButton(self, "misc", "receive-tab", _("Help"))
        self._create_button = EnterButton(_('Create'), self._on_create_button_clicked)
        bhbox = QHBoxLayout()
        bhbox.addStretch(1)
        bhbox.addWidget(self._help_button)
        bhbox.addWidget(self._create_button)
        bhbox.addStretch(1)
        grid.addLayout(bhbox, 4, 0, 1, -1, Qt.AlignmentFlag.AlignHCenter)

        vbox = QVBoxLayout()
        vbox.addLayout(grid)
        vbox.addStretch()

        return vbox

    def create_request_list_container(self) -> QGroupBox:
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(6, 0, 6, 6)
        layout.addLayout(self._request_list_toolbar_layout)
        layout.addWidget(self._request_list)

        request_box = QGroupBox()
        request_box.setTitle(_('Incoming payments'))
        request_box.setAlignment(Qt.AlignmentFlag.AlignCenter)
        request_box.setContentsMargins(0, 0, 0, 0)
        request_box.setLayout(layout)
        return request_box

    def update_widgets(self) -> None:
        self._request_list.update()

    # TODO Test switching tabs with different content in each.
    def update_contents(self) -> None:
        """
        The main window is notifying us the active account has changed.
        """
        pass

    def get_bsv_edits(self) -> List[BTCAmountEdit]:
        return [ self._receive_amount_e ]

    def _on_create_button_clicked(self) -> None:
        # These are the same constraints imposed in the receive view.
        message = self._receive_message_e.text()
        if not message:
            self._main_window.show_error(_('A description is required'))
            return

        amount = self._receive_amount_e.get_amount()

        i = self._expires_combo.currentIndex()
        expiration = [ x[1] for x in EXPIRATION_VALUES ][i]

        # Note that we are allowed to set `ACTIVE` here because we clear it when we delete
        # the payment request, and we need to know about payments made to the given script or
        # address on the blockchain.
        keyinstance_id = self._account.reserve_unassigned_key(RECEIVING_SUBPATH,
            KeyInstanceFlag.IS_PAYMENT_REQUEST | KeyInstanceFlag.ACTIVE)

        def callback(future: concurrent.futures.Future) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()

            # NOTE This callback will be happening in the database thread. No UI calls should
            #   be made, unless we emit a signal to do it.
            self._request_list.update_signal.emit()

        # Update the payment request next.
        row = PaymentRequestRow(-1, keyinstance_id, PaymentFlag.UNPAID, amount, expiration, message,
            get_posix_timestamp())
        wallet = self._account.get_wallet()
        future = wallet.create_payment_requests(self._account.get_id(), [ row ])
        future.add_done_callback(callback)

        self._clear_form()

    def _clear_form(self) -> None:
        self._receive_message_e.setText("")
        self._receive_amount_e.setAmount(None)
        self._expires_combo.setCurrentIndex(2)

    # Only called from key list menu.
    # TODO(no-merge) We should support receiving in designated keys and we need to flesh this out
    # later and make sure it works right.
    def receive_at_key(self, key_data: KeyDataTypes) -> None:
        # TODO(no-merge) Ensure we are not already receiving at the given key? Popup the dialog
        # if we are?
        self._main_window.show_receive_tab()

    def get_dialog(self, request_id: int) -> Optional[ReceiveDialog]:
        return self._dialogs.get(request_id)

    def create_edit_dialog(self, request_id) -> ReceiveDialog:
        dialog = ReceiveDialog(self._main_window.reference(), self._account_id, request_id)
        self._dialogs[request_id] = dialog
        return dialog

    def _filter_request_list(self, text: str) -> None:
        self._request_list.filter(text)
