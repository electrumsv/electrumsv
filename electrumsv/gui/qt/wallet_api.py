
from decimal import Decimal
from functools import partial
from typing import Any, Optional

from PyQt5.QtCore import pyqtSignal, QObject

from electrumsv.app_state import app_state
from electrumsv.contacts import ContactEntry, ContactIdentity


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

    def get_identities(self):
        return self.wallet_window.contacts.get_contact_identities()

    def get_balance(self, account_id=None) -> int:
        c, u, x = self.wallet_window.wallet.get_balance()
        return c + u

    def get_fiat_unit(self) -> Optional[str]:
        fx = app_state.fx
        if fx and fx.is_enabled():
            return fx.get_currency()

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
