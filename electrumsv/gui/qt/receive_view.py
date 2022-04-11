from typing import Dict, List, Optional, TYPE_CHECKING
import weakref

from PyQt5.QtCore import QSize, Qt
from PyQt5.QtWidgets import QAction, QHBoxLayout, QLabel, QMessageBox, QToolBar, QVBoxLayout, \
    QWidget

from ...app_state import app_state
from ...constants import PaymentFlag, ScriptType
from ...i18n import _
from ...logs import logs

from .amountedit import BTCAmountEdit
from .receive_dialog import EXPIRATION_VALUES, ReceiveDialog
from .request_list import RequestList
from .table_widgets import TableTopButtonLayout
from .util import read_QIcon

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class ReceiveView(QWidget):
    """
    Display a form for reservation of addresses for new expected payments, as well as a list of
    the existing expected payments.
    """

    _request_list: RequestList

    def __init__(self, main_window: "ElectrumWindow", account_id: int) -> None:
        super().__init__(main_window)

        self._main_window_proxy: ElectrumWindow = weakref.proxy(main_window)
        self._account_id = account_id
        self._account = main_window._wallet.get_account(account_id)
        self._logger = logs.get_logger(f"receive-view[{self._account_id}]")

        self._dialogs: Dict[Optional[int], ReceiveDialog] = {}

        toolbar_label = QLabel(_("Receive a new payment through:"))
        toolbar_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        toolbar = QToolBar(self)
        toolbar.setMovable(False)
        toolbar.setIconSize(QSize(80, 80))
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)

        is_offline = main_window.network is None
        invoice_action = QAction(read_QIcon("icons8-bill-80-blueui.png"),
            _("Online invoice"), self)
        if is_offline:
            invoice_action.setToolTip(_("Online invoice") +" ("+ _("disabled in offline mode") +")")
        invoice_action.setEnabled(not is_offline)
        invoice_action.triggered.connect(self._event_action_triggered_invoice)
        toolbar.addAction(invoice_action)

        handoff_action = QAction(read_QIcon("icons8-communication-80-blueui.png"),
            _("Transaction import"), self)
        handoff_action.triggered.connect(self._event_action_triggered_import)
        toolbar.addAction(handoff_action)

        blockchain_action = QAction(read_QIcon("icons8-signal-80-blueui.png"),
            _("Watch blockchain"), self)
        if is_offline:
            blockchain_action.setToolTip(_("Watch blockchain") +" ("+
                _("disabled in offline mode") +")")
        blockchain_action.setEnabled(not is_offline)
        blockchain_action.triggered.connect(self._event_action_triggered_blockchain)
        toolbar.addAction(blockchain_action)

        toolbar_hbox = QHBoxLayout()
        toolbar_hbox.addStretch(1)
        toolbar_hbox.addWidget(toolbar)
        toolbar_hbox.addStretch(1)

        self._request_list_toolbar_layout = TableTopButtonLayout()
        self._request_list_toolbar_layout.refresh_signal.connect(
            self._main_window_proxy.refresh_wallet_display)
        self._request_list_toolbar_layout.filter_signal.connect(
            self._filter_request_list)

        self._request_list = RequestList(self, main_window)

        list_layout = QVBoxLayout()
        list_layout.setSpacing(0)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.addLayout(self._request_list_toolbar_layout)
        list_layout.addWidget(self._request_list)

        vbox = QVBoxLayout(self)
        vbox.addWidget(toolbar_label)
        vbox.addLayout(toolbar_hbox)
        vbox.addSpacing(10)
        vbox.addLayout(list_layout)
        self.setLayout(vbox)

        self.update_widgets()

        self._main_window_proxy.payment_requests_paid_signal.connect(self._on_payment_requests_paid)

    def clean_up(self) -> None:
        """
        Called by the main window when the main window is closed.
        """
        self._main_window_proxy.payment_requests_paid_signal.disconnect(
            self._on_payment_requests_paid)

        for dialog in self._dialogs.values():
            dialog.clean_up()
        self._dialogs.clear()

    def _on_payment_requests_paid(self, paymentrequest_ids: list[int]) -> None:
        self.update_widgets()

    def _event_action_triggered_invoice(self) -> None:
        if None in self._dialogs:
            self._main_window_proxy.show_message(_("You are already creating a new expected "
                "payment. Please complete that one first."))
            return

        self.show_dialog(None, PaymentFlag.INVOICE)

    def _event_action_triggered_import(self) -> None:
        if None in self._dialogs:
            self._main_window_proxy.show_message(_("You are already creating a new expected "
                "payment. Please complete that one first."))
            return

        self.show_dialog(None, PaymentFlag.IMPORTED)

    def _event_action_triggered_blockchain(self) -> None:
        if None in self._dialogs:
            self._main_window_proxy.show_message(_("You are already creating a new expected "
                "payment. Please complete that one first."))
            return

        self.show_dialog(None, PaymentFlag.MONITORED)

    def update_widgets(self) -> None:
        """
        Called locally and by the wallet window.
        """
        self._request_list.update()

    # TODO Test switching tabs with different content in each.
    def update_contents(self) -> None:
        """
        The main window is notifying us the active account has changed.
        """
        pass

    def get_bsv_edits(self) -> List[BTCAmountEdit]:
        """
        Called by the main window to get the edit widgets to update when the user changes what
        base unit they wish to use.
        """
        edits = list[BTCAmountEdit]()
        for dialog in self._dialogs.values():
            edits.extend(dialog.get_bsv_edits())
        return edits

    def _on_create_handoff_button_clicked(self) -> None:
        if not self._main_window_proxy.question(_("If you choose to receive a payment this way, "
                "you are responsible for getting the transaction yourself and importing it into "
                "ElectrumSV. Any payments to the payment destination will not be detected "
                "on the blockchain automatically.\n\nAre you sure you wish to do this?"),
                title=_("Create hand-off payment"),
                parent=self._main_window_proxy.reference(), icon=QMessageBox.Warning):
            return

        self._common_create_button_clicked_handling(PaymentFlag.NONE)

    def _on_create_monitored_button_clicked(self) -> None:
        self._common_create_button_clicked_handling(PaymentFlag.MONITORED)

    def _clear_form(self) -> None:
        self._receive_message_e.setText("")
        self._receive_amount_e.setAmount(None)
        # Default the current index to one hour or the last entry if that cannot be found for some
        # reason.
        current_index = 0
        for current_index, expiration_entry in enumerate(EXPIRATION_VALUES):
            if expiration_entry[1] == 60*60:
                break
        self._expires_combo.setCurrentIndex(current_index)

    def show_dialog(self, request_id: Optional[int], request_type: PaymentFlag) -> None:
        """
        Show the dialog for the given `request_id`.

        We cache the instance until it is closed, so that we can bring it to front if it is already
        open in the background and avoid having multiple copies open.
        """
        # If the request is an existing one the type should be effectively unspecified.
        assert request_id is None or request_type & PaymentFlag.MASK_TYPE == PaymentFlag.NONE
        # If the request is not an existing one the flag should be a forward looking type.
        assert request_id is not None or request_type & PaymentFlag.MASK_TYPE != PaymentFlag.LEGACY

        dialog = self._dialogs.get(request_id)
        if dialog is None:
            dialog = ReceiveDialog(self._main_window_proxy.reference(), self, self._account_id,
                request_id, request_type)
            self._dialogs[request_id] = dialog
            def dialog_finished(result: int) -> None:
                assert dialog is not None
                self._on_dialog_closed(dialog._request_id)
            dialog.finished.connect(dialog_finished)
        dialog.show()

    def upgrade_draft_payment_request(self, request_id: int) -> None:
        """
        Ensure the previously draft request dialog is stored under it's new request id.
        Should always be expected to be called by the draft dialog, so no exception should happen.
        Raises a `KeyError` if there is no draft payment request or the current draft payment
            request has a different id.
        Raises an `AssertionError` if the current draft payment request has a different id.
        """
        assert self._dialogs[None].get_paymentrequest_id() == request_id
        self._dialogs[request_id] = self._dialogs.pop(None)

    def update_script_type(self, script_type: ScriptType) -> None:
        for dialog in self._dialogs.values():
            dialog.update_script_type(script_type)

    def _on_dialog_closed(self, request_id: Optional[int]) -> None:
        if request_id in self._dialogs:
            del self._dialogs[request_id]

    def update_request_list(self) -> None:
        self._request_list.update()

    def _filter_request_list(self, text: str) -> None:
        self._request_list.filter(text)
