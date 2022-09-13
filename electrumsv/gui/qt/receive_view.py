from functools import partial
from typing import Dict, List, Optional, TYPE_CHECKING
import weakref

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QToolBar, QVBoxLayout, QWidget

from ...constants import NetworkServerFlag, PaymentFlag
from ...i18n import _
from ...logs import logs

from .amountedit import BTCAmountEdit
from .receive_dialog import ReceiveDialog
from .request_list import RequestList
from . import server_required_dialog
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

        # The message box service is required to get mAPI merkle proof callbacks.
        required_flags = NetworkServerFlag.USE_MESSAGE_BOX
        if self._main_window_proxy._wallet.have_wallet_servers(required_flags):
            self.show_dialog(None, PaymentFlag.INVOICE)
            return

        dialog_text = _("Receiving invoice payments requires signing up "
            "with a message box service for receipt of merkle proofs and sharing them with the "
            "payer (i.e. the other peer SPV wallet)"
            "<br/><br/>"
            "This wallet has not been set up to use all the required services. If you run your "
            "own servers or wish to use third party servers, choose the 'Manage servers' option.")

        from importlib import reload
        reload(server_required_dialog)

        dialog = server_required_dialog.ServerRequiredDialog(self, self._main_window_proxy._wallet,
            NetworkServerFlag.USE_MESSAGE_BOX, dialog_text)
        # There are two paths to the user accepting this dialog:
        # - They checked "select servers on my behalf" then the OK buton and then servers were
        #   selected and connected to.
        # - They chose "Manage servers" which selected and connected to servers and then on exit
        #   from that wizard this dialog auto-accepted.
        dialog.accepted.connect(partial(self.show_dialog, None, PaymentFlag.INVOICE))
        dialog.show()


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

        # The blockchain services are required to have tip filters detect blockchain payments.
        # The message box services are required to get the notifications of detected payments.
        # We do not require that we are currently connected. If the services have problems then
        # this should be something that existing servers can unexpectedly experience.
        required_flags = NetworkServerFlag.USE_BLOCKCHAIN | NetworkServerFlag.USE_MESSAGE_BOX
        if self._main_window_proxy._wallet.have_wallet_servers(required_flags):
            self._show_blockchain_payment_dialog()
            return

        dialog_text = _("Receiving legacy payments requires signing up with both blockchain "
            "and message box services, where the blockchain service will detect your incoming "
            "payment and send you a notification through your message box service."
            "<br/><br/>"
            "This wallet has not been set up to use all the required services. If you run your "
            "own servers or wish to use third party servers, choose the 'Manage servers' option.")

        from importlib import reload
        reload(server_required_dialog)

        dialog = server_required_dialog.ServerRequiredDialog(self, self._main_window_proxy._wallet,
            NetworkServerFlag.USE_BLOCKCHAIN | NetworkServerFlag.USE_MESSAGE_BOX,
            dialog_text)
        # There are two paths to the user accepting this dialog:
        # - They checked "select servers on my behalf" then the OK buton and then servers were
        #   selected and connected to.
        # - They chose "Manage servers" which selected and connected to servers and then on exit
        #   from that wizard this dialog auto-accepted.
        dialog.accepted.connect(self._show_blockchain_payment_dialog)
        dialog.show()

    def _show_blockchain_payment_dialog(self) -> None:
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

    def _on_dialog_closed(self, request_id: Optional[int]) -> None:
        if request_id in self._dialogs:
            del self._dialogs[request_id]

    def update_request_list(self) -> None:
        self._request_list.update()

    def _filter_request_list(self, text: str) -> None:
        self._request_list.filter(text)
