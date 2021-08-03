from typing import cast, TYPE_CHECKING

from ...constants import unpack_derivation_path
from ...wallet import AbstractAccount
from ...wallet_database.types import KeyListRow

from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from .digitalbitbox import DigitalBitboxPlugin, DigitalBitbox_KeyStore


if TYPE_CHECKING:
    from ...gui.qt.main_window import ElectrumWindow


class Plugin(DigitalBitboxPlugin, QtPluginBase):
    icon_paired = "icons8-usb-connected-80.png"
    icon_unpaired = "icons8-usb-disconnected-80.png"

    def create_handler(self, window: "ElectrumWindow") -> QtHandlerBase:
        return DigitalBitbox_Handler(window)

    def show_key(self, account: AbstractAccount, keydata: KeyListRow) -> None:
        if not self.is_mobile_paired():
            return

        keystore = cast(DigitalBitbox_KeyStore, account.get_keystore())
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        assert derivation_path is not None
        subpath = '/'.join(str(x) for x in derivation_path)
        keypath = f"{keystore.derivation}/{subpath}"
        client = self.get_client(keystore)
        assert client is not None
        xpub = client._get_xpub(keypath)
        assert xpub is not None
        verify_request_payload = {
            "type": 'p2pkh',
            "echo": xpub['echo'],
        }
        self.comserver_post_notification(verify_request_payload)


class DigitalBitbox_Handler(QtHandlerBase):
    def __init__(self, window: "ElectrumWindow") -> None:
        super(DigitalBitbox_Handler, self).__init__(window, 'Digital Bitbox')
