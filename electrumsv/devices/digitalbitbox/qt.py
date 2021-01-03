from typing import cast

from ...constants import unpack_derivation_path
from ...keystore import Hardware_KeyStore
from ...wallet import AbstractAccount
from ...wallet_database.types import KeyListRow

from ..hw_wallet.qt import QtHandlerBase, QtPluginBase, HandlerWindow
from .digitalbitbox import DigitalBitboxPlugin


class Plugin(DigitalBitboxPlugin, QtPluginBase):
    icon_paired = "icons8-usb-connected-80.png"
    icon_unpaired = "icons8-usb-disconnected-80.png"

    def create_handler(self, window: HandlerWindow) -> QtHandlerBase:
        return DigitalBitbox_Handler(window)

    def show_key(self, account: AbstractAccount, keydata: KeyListRow) -> None:
        if not self.is_mobile_paired():
            return

        keystore = cast(Hardware_KeyStore, account.get_keystore())
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        assert derivation_path is not None
        subpath = '/'.join(str(x) for x in derivation_path)
        keypath = f"{keystore.derivation}/{subpath}"
        xpub = self.get_client(keystore)._get_xpub(keypath)
        verify_request_payload = {
            "type": 'p2pkh',
            "echo": xpub['echo'],
        }
        self.comserver_post_notification(verify_request_payload)


class DigitalBitbox_Handler(QtHandlerBase):

    def __init__(self, win):
        super(DigitalBitbox_Handler, self).__init__(win, 'Digital Bitbox')
