from ..hw_wallet.qt import QtHandlerBase, QtPluginBase
from .digitalbitbox import DigitalBitboxPlugin


class Plugin(DigitalBitboxPlugin, QtPluginBase):
    icon_unpaired = "digitalbitbox_unpaired.png"
    icon_paired = "digitalbitbox.png"

    def create_handler(self, window):
        return DigitalBitbox_Handler(window)

    def show_address(self, wallet, address):
        if not self.is_mobile_paired():
            return

        keystore = wallet.keystore
        change, index = wallet.get_address_index(address)
        keypath = '%s/%d/%d' % (keystore.derivation, change, index)
        xpub = self.get_client(keystore)._get_xpub(keypath)
        verify_request_payload = {
            "type": 'p2pkh',
            "echo": xpub['echo'],
        }
        self.comserver_post_notification(verify_request_payload)


class DigitalBitbox_Handler(QtHandlerBase):

    def __init__(self, win):
        super(DigitalBitbox_Handler, self).__init__(win, 'Digital Bitbox')
