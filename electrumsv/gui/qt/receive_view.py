import concurrent.futures
from typing import Dict, List, Optional, TYPE_CHECKING
import weakref

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtWidgets import (QComboBox, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
    QVBoxLayout, QWidget)

from ...app_state import app_state
from ...constants import ScriptType
from ...i18n import _
from ...logs import logs
from ...wallet_database.types import PaymentRequestRow

from .amountedit import AmountEdit, BTCAmountEdit
from .receive_dialog import EXPIRATION_VALUES, ReceiveDialog
from .request_list import RequestList
from .table_widgets import TableTopButtonLayout
from .util import EnterButton, HelpDialogButton, HelpLabel

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class ReceiveView(QWidget):
    """
    Display a form for reservation of addresses for new expected payments, as well as a list of
    the existing expected payments.
    """

    open_dialog_signal = pyqtSignal(int)

    def __init__(self, main_window: "ElectrumWindow", account_id: int) -> None:
        super().__init__(main_window)

        self._main_window = weakref.proxy(main_window)
        self._account_id = account_id
        self._account = main_window._wallet.get_account(account_id)
        self._logger = logs.get_logger(f"receive-view[{self._account_id}]")

        self._dialogs: Dict[int, ReceiveDialog] = {}

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

        self.open_dialog_signal.connect(self.show_dialog)

        app_state.app_qt.fiat_ccy_changed.connect(self._on_fiat_ccy_changed)
        self._main_window.new_fx_quotes_signal.connect(self._on_ui_exchange_rate_quotes)
        self._main_window.payment_requests_paid_signal.connect(self._on_payment_requests_paid)

    def clean_up(self) -> None:
        """
        Called by the main window when the main window is closed.
        """
        self._main_window.payment_requests_paid_signal.disconnect(self._on_payment_requests_paid)
        self._main_window.new_fx_quotes_signal.disconnect(self._on_ui_exchange_rate_quotes)
        app_state.app_qt.fiat_ccy_changed.disconnect(self._on_fiat_ccy_changed)

        for dialog in self._dialogs.values():
            dialog.clean_up()
        self._dialogs.clear()

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
        assert self._account is not None

        # These are the same constraints imposed in the receive view.
        message = self._receive_message_e.text()
        if not message:
            self._main_window.show_error(_('A description is required'))
            return

        amount = self._receive_amount_e.get_amount()

        i = self._expires_combo.currentIndex()
        expiration = [ x[1] for x in EXPIRATION_VALUES ][i]

        def callback(future: concurrent.futures.Future[List[PaymentRequestRow]]) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            final_rows = future.result()

            # NOTE This callback will be happening in the database thread. No UI calls should
            #   be made, unless we emit a signal to do it.
            self._request_list.update_signal.emit()
            self.open_dialog_signal.emit(final_rows[0].paymentrequest_id)

        future, key_data = self._account.create_payment_request(message, amount, expiration)
        future.add_done_callback(callback)

        self._clear_form()

    def _clear_form(self) -> None:
        self._receive_message_e.setText("")
        self._receive_amount_e.setAmount(None)
        self._expires_combo.setCurrentIndex(2)

    def show_dialog(self, request_id: int) -> None:
        """
        Show the dialog for the given `request_id`.

        We cache the instance until it is closed, so that we can bring it to front if it is already
        open in the background and avoid having multiple copies open.
        """
        dialog = self.get_dialog(request_id)
        if dialog is None:
            dialog = self.create_edit_dialog(request_id)
        dialog.show()

    def get_dialog(self, request_id: int) -> Optional[ReceiveDialog]:
        """
        Get any existing open dialog for the given `request_id`.
        """
        return self._dialogs.get(request_id)

    def create_edit_dialog(self, request_id) -> ReceiveDialog:
        dialog = ReceiveDialog(self._main_window.reference(), self, self._account_id, request_id)
        self._dialogs[request_id] = dialog
        def dialog_finished(result: int) -> None:
            self._on_dialog_closed(request_id)
        dialog.finished.connect(dialog_finished)
        return dialog

    def update_script_type(self, script_type: ScriptType) -> None:
        for dialog in self._dialogs.values():
            dialog.update_script_type(script_type)

    def _on_dialog_closed(self, request_id: int) -> None:
        if request_id in self._dialogs:
            # print("DIALOG REMOVED")
            del self._dialogs[request_id]

    def update_request_list(self) -> None:
        self._request_list.update()

    def _filter_request_list(self, text: str) -> None:
        self._request_list.filter(text)
