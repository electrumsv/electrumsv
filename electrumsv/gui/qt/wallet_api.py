
from decimal import Decimal
from typing import cast, List, Tuple, TYPE_CHECKING
import weakref

from PyQt6.QtCore import pyqtSignal, QObject

from electrumsv.constants import WalletEventFlag
from electrumsv.wallet_database.types import WalletEventRow


if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class WalletAPI(QObject):
    # TODO: ...
    fiat_rate_changed = pyqtSignal(Decimal)
    # TODO: ...
    fiat_currency_changed = pyqtSignal(str)

    new_notification = pyqtSignal(object)

    def __init__(self, wallet_window: 'ElectrumWindow') -> None:
        super().__init__(wallet_window)

        self.wallet_window = cast("ElectrumWindow", weakref.proxy(wallet_window))
        self.wallet_window.notifications_created_signal.connect(self._on_new_notifications)

    def clean_up(self) -> None:
        self.wallet_window.notifications_created_signal.disconnect(self._on_new_notifications)

    # def __del__(self) -> None:
    #     print(f"Wallet API {self!r} was garbage collected")

    # Contact related:

    def get_account_name(self, account_id: int) -> str:
        account = self.wallet_window._wallet.get_account(account_id)
        assert account is not None
        return account.display_name()

    # Notification related.

    def get_notification_rows(self) -> List[WalletEventRow]:
        return self.wallet_window._wallet.data.read_wallet_events(
            mask=WalletEventFlag.UNREAD|WalletEventFlag.FEATURED)

    def update_notification_flags(self, updates: List[Tuple[WalletEventFlag, int]]) -> None:
        self.wallet_window._wallet.data.update_wallet_event_flags(updates)

    def _on_new_notifications(self, rows: List[WalletEventRow]) -> None:
        for row in rows:
            self.new_notification.emit(row)

    def prompt_to_show_secured_data(self, account_id: int) -> None:
        self.wallet_window.show_secured_data_signal.emit(account_id)

    def show_help(self, dirname: str, filename: str) -> None:
        from .help_dialog import HelpDialog
        h = HelpDialog(self.wallet_window.reference(), dirname, filename)
        h.run()
