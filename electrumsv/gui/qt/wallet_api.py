
from decimal import Decimal
from functools import partial
from typing import Any, Optional, Iterable, Tuple

from PyQt5.QtCore import pyqtSignal, QObject

from electrumsv.app_state import app_state
from electrumsv.contacts import (ContactEntry, ContactIdentity, IdentitySystem, IdentityCheckResult)


class WalletAPI(QObject):
    # TODO: ...
    fiat_rate_changed = pyqtSignal(Decimal)
    # TODO: ...
    fiat_currency_changed = pyqtSignal(str)

    contact_changed = pyqtSignal(bool, object, object)

    def __init__(self, wallet_window: 'ElectrumWindow') -> None:
        self.wallet_window = wallet_window

        super().__init__(wallet_window)

        app_state.app.identity_added_signal.connect(partial(self._on_contact_change, True))
        app_state.app.identity_removed_signal.connect(partial(self._on_contact_change, False))
        app_state.app.contact_added_signal.connect(partial(self._on_contact_change, True))
        app_state.app.contact_removed_signal.connect(partial(self._on_contact_change, False))

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

    # Balance related.

    def get_balance(self, account_id=None) -> int:
        c, u, x = self.wallet_window.wallet.get_balance()
        return c + u

    def get_fiat_unit(self) -> Optional[str]:
        fx = app_state.fx
        if fx and fx.is_enabled():
            return fx.get_currency()

    def get_amount_and_units(self, amount: int) -> Tuple[str, str]:
        return self.wallet_window.get_amount_and_units(amount)

    # Fiat related.

    def get_fiat_amount(self, sv_value: int) -> Optional[str]:
        fx = app_state.fx
        if fx and fx.is_enabled():
            return fx.format_amount(sv_value)

    def get_base_unit(self) -> str:
        return app_state.base_unit()

    def get_base_amount(self, sv_value: int) -> str:
        return self.wallet_window.format_amount(sv_value)

    def _on_contact_change(self, added: bool, contact: ContactEntry,
            identity: Optional[ContactIdentity]=None) -> None:
        self.contact_changed.emit(added, contact, identity)
