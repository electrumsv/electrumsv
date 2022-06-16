
from decimal import Decimal
from typing import Any, Optional, Iterable, List, Tuple
import weakref

from PyQt5.QtCore import pyqtSignal, QObject

from electrumsv.app_state import app_state
from electrumsv.constants import WalletEventFlag
from electrumsv.contacts import ContactEntry, ContactIdentity, IdentitySystem, IdentityCheckResult
from electrumsv.wallet_database.tables import WalletEventRow


class WalletAPI(QObject):
    # TODO: ...
    fiat_rate_changed = pyqtSignal(Decimal)
    # TODO: ...
    fiat_currency_changed = pyqtSignal(str)

    contact_changed = pyqtSignal(bool, object, object)
    new_notification = pyqtSignal(object)
    dismissed_notification = pyqtSignal(object)

    def __init__(self, wallet_window: 'ElectrumWindow') -> None:
        super().__init__(wallet_window)

        self.wallet_window = weakref.proxy(wallet_window)

        app_state.app.identity_added_signal.connect(self._on_contact_added)
        app_state.app.identity_removed_signal.connect(self._on_contact_removed)
        app_state.app.contact_added_signal.connect(self._on_contact_added)
        app_state.app.contact_removed_signal.connect(self._on_contact_removed)
        app_state.app.new_notification.connect(self.post_notification)

    def clean_up(self) -> None:
        app_state.app.identity_added_signal.disconnect(self._on_contact_added)
        app_state.app.identity_removed_signal.disconnect(self._on_contact_removed)
        app_state.app.contact_added_signal.disconnect(self._on_contact_added)
        app_state.app.contact_removed_signal.disconnect(self._on_contact_removed)
        app_state.app.new_notification.disconnect(self.post_notification)

    # def __del__(self) -> None:
    #     print(f"Wallet API {self!r} was garbage collected")

    # Contact related:

    def add_identity(self, contact_id: int, system_id: IdentitySystem, system_data: str) -> None:
        self.wallet_window.contacts.add_identity(contact_id, system_id, system_data)

    def add_contact(self, system_id: IdentitySystem, label: str,
            identity_data: Any) -> ContactEntry:
        return self.wallet_window.contacts.add_contact(system_id, label, identity_data)

    def remove_contacts(self, contact_ids: Iterable[int]) -> None:
        self.wallet_window.contacts.remove_contacts(contact_ids)

    def remove_identity(self, contact_id: int, identity_id: int) -> None:
        self.wallet_window.contacts.remove_identity(contact_id, identity_id)

    def set_label(self, contact_id: int, label: str) -> None:
        self.wallet_window.contacts.set_label(contact_id, label)

    def get_contact(self, contact_id: int) -> Optional[ContactEntry]:
        return self.wallet_window.contacts.get_contact(contact_id)

    def get_identities(self):
        return self.wallet_window.contacts.get_contact_identities()

    def check_label(self, label: str) -> IdentityCheckResult:
        return self.wallet_window.contacts.check_label(label)

    def check_identity_valid(self, system_id: IdentitySystem, system_data: Any,
            skip_exists: Optional[bool]=False) -> IdentityCheckResult:
        return self.wallet_window.contacts.check_identity_valid(system_id, system_data, skip_exists)

    def get_account_name(self, account_id: int) -> str:
        account = self.wallet_window._wallet.get_account(account_id)
        return account.display_name()

    # Balance related.

    def get_balance(self, account_id=None) -> int:
        balance = 0
        for account in self.wallet_window._wallet.get_accounts():
            if account_id is None or account_id == account.get_id():
                c, u, x = account.get_balance()
                balance += c + u
        return balance

    def get_fiat_unit(self) -> Optional[str]:
        fx = app_state.fx
        if fx and fx.is_enabled():
            return fx.get_currency()

    def get_amount_and_units(self, amount: int) -> Tuple[str, str]:
        return app_state.get_amount_and_units(amount)

    # Fiat related.

    def get_fiat_amount(self, sv_value: int) -> Optional[str]:
        fx = app_state.fx
        if fx and fx.is_enabled():
            return fx.format_amount(sv_value)

    def get_base_unit(self) -> str:
        return app_state.base_unit()

    def get_base_amount(self, sv_value: int) -> str:
        return app_state.format_amount(sv_value)

    def _on_contact_added(self, contact: ContactEntry,
            identity: Optional[ContactIdentity]=None) -> None:
        self.contact_changed.emit(True, contact, identity)

    def _on_contact_removed(self, contact: ContactEntry,
            identity: Optional[ContactIdentity]=None) -> None:
        self.contact_changed.emit(False, contact, identity)

    # Notification related.

    def get_notification_rows(self) -> List[WalletEventRow]:
        return self.wallet_window._wallet.read_wallet_events(
            WalletEventFlag.UNREAD|WalletEventFlag.FEATURED)

    def update_notification_flags(self, updates: List[Tuple[WalletEventFlag, int]]) -> None:
        self.wallet_window._wallet.update_wallet_event_flags(updates)

    def post_notification(self, wallet_path: str, row: WalletEventRow) -> None:
        if wallet_path == self.wallet_window._wallet.get_storage_path():
            self.new_notification.emit(row)

    def dismiss_notification(self, wallet_path: str, row: WalletEventRow) -> None:
        if wallet_path == self.wallet_window._wallet.get_storage_path():
            self.dismissed_notification.emit(row)

    def prompt_to_show_secured_data(self, account_id: int) -> None:
        self.wallet_window.show_secured_data_signal.emit(account_id)

    def update_displayed_notification_count(self, entry_count: int) -> None:
        self.wallet_window._status_bar.notification_widget.set_notification_state(entry_count)

    def show_help(self, dirname: str, filename: str) -> None:
        from .help_dialog import HelpDialog
        h = HelpDialog(self.wallet_window.reference(), dirname, filename)
        h.run()
