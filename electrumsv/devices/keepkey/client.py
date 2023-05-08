# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
# Copyright (C) 2019-2020 The ElectrumSV Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import time

from bitcoinx import (
    bip32_decompose_chain_string, BIP32Derivation, BIP32PublicKey, PublicKey, pack_be_uint32)

from keepkeylib.client import proto, BaseClient, ProtocolMixin, types

from electrumsv.exceptions import UserCancelled
from electrumsv.i18n import _
from electrumsv.keystore import bip39_normalize_passphrase
from electrumsv.logs import logs
from electrumsv.networks import Net

logger = logs.get_logger("keepkey.client")


class KeepKeyClient(ProtocolMixin, BaseClient):

    def __init__(self, transport, handler, plugin):
        BaseClient.__init__(self, transport)
        ProtocolMixin.__init__(self, transport)
        assert hasattr(self, 'tx_api')  # ProtocolMixin already constructed?
        self.proto = proto
        self.device = plugin.device
        self.handler = handler
        self.tx_api = plugin
        self.msg = None
        self.creating_wallet = False
        self.used()

    def __str__(self):
        return "%s/%s" % (self.label(), self.features.device_id)

    def label(self):
        '''The name given by the user to the device.'''
        return self.features.label

    def is_initialized(self):
        '''True if initialized, False if wiped.'''
        return self.features.initialized

    def is_pairable(self):
        return not self.features.bootloader_mode

    def has_usable_connection_with_device(self):
        try:
            res = self.ping("electrum pinging device")
            assert res == "electrum pinging device"
        except Exception:
            return False
        return True

    def used(self):
        self.last_operation = time.time()

    def prevent_timeouts(self):
        self.last_operation = float('inf')

    def timeout(self, cutoff):
        '''Time out the client if the last operation was before cutoff.'''
        if self.last_operation < cutoff:
            logger.error("timed out")
            self.clear_session()

    def cancel(self):
        '''Provided here as in keepkeylib but not trezorlib.'''
        self.transport.write(self.proto.Cancel())

    def get_master_public_key(self, bip32_path: str, creating: bool=False) -> BIP32PublicKey:
        address_n = bip32_decompose_chain_string(bip32_path)
        # This will be cleared by the wrapper around `get_public_node`.
        self.creating_wallet = creating
        node = self.get_public_node(address_n).node
        self.used()
        derivation = BIP32Derivation(chain_code=node.chain_code, depth=node.depth,
                                     parent_fingerprint=pack_be_uint32(node.fingerprint),
                                     n=node.child_num)
        return BIP32PublicKey(PublicKey.from_bytes(node.public_key), derivation, Net.COIN)

    def toggle_passphrase(self):
        if self.features.passphrase_protection:
            self.msg = _("Confirm on your {} device to disable passphrases")
        else:
            self.msg = _("Confirm on your {} device to enable passphrases")
        enabled = not self.features.passphrase_protection
        self.apply_settings(use_passphrase=enabled)

    def change_label(self, label):
        self.msg = _("Confirm the new label on your {} device")
        self.apply_settings(label=label)

    def change_homescreen(self, homescreen):
        self.msg = _("Confirm on your {} device to change your home screen")
        self.apply_settings(homescreen=homescreen)

    def set_pin(self, remove):
        if remove:
            self.msg = _("Confirm on your {} device to disable PIN protection")
        elif self.features.pin_protection:
            self.msg = _("Confirm on your {} device to change your PIN")
        else:
            self.msg = _("Confirm on your {} device to set a PIN")
        self.change_pin(remove)

    def clear_session(self):
        '''Clear the session to force pin (and passphrase if enabled)
        re-entry.  Does not leak exceptions.'''
        logger.debug("clear session: %s", self)
        self.prevent_timeouts()
        try:
            ProtocolMixin.clear_session(self)
        except Exception as e:
            # If the device was removed it has the same effect...
            logger.error("clear_session: ignoring error %s", e)

    def close(self):
        '''Called when Our wallet was closed or the device removed.'''
        logger.debug("closing client")
        self.clear_session()
        # Release the device
        self.transport.close()

    def firmware_version(self):
        f = self.features
        return (f.major_version, f.minor_version, f.patch_version)

    def atleast_version(self, major, minor=0, patch=0):
        return self.firmware_version() >= (major, minor, patch)

    @staticmethod
    def wrapper(func):
        '''Wrap methods to clear any message box they opened.'''

        def wrapped(self, *args, **kwargs):
            try:
                self.prevent_timeouts()
                return func(self, *args, **kwargs)
            finally:
                self.used()
                self.handler.finished()
                self.creating_wallet = False
                self.msg = None

        return wrapped

    @classmethod
    def wrap_methods(cls):
        for method in ['apply_settings', 'change_pin',
                       'get_address', 'get_public_node',
                       'load_device_by_mnemonic', 'load_device_by_xprv',
                       'recovery_device', 'reset_device', 'sign_message',
                       'sign_tx', 'wipe_device']:
            setattr(cls, method, cls.wrapper(getattr(ProtocolMixin, method)))

    #
    # GUI methods
    #

    messages = {
        types.ButtonRequest_ConfirmOutput: _("Confirm the transaction output on your {} device"),
        types.ButtonRequest_ResetDevice: _("Confirm internal entropy on your {} device to begin"),
        types.ButtonRequest_ConfirmWord: _("Write down the seed word shown on your {}"),
        types.ButtonRequest_WipeDevice: _("Confirm on your {} that you want to wipe it clean"),
        types.ButtonRequest_ProtectCall: _("Confirm on your {} device the message to sign"),
        types.ButtonRequest_SignTx: _("Confirm the total amount spent and the transaction fee "
            "on your {} device"),
        types.ButtonRequest_Address: _("Confirm wallet address on your {} device"),
        'default': _("Check your {} device to continue"),
    }

    def callback_Failure(self, msg):
        # BaseClient's unfortunate call() implementation forces us to
        # raise exceptions on failure in order to unwind the stack.
        # However, making the user acknowledge they cancelled
        # gets old very quickly, so we suppress those.  The NotInitialized
        # one is misnamed and indicates a passphrase request was cancelled.
        if msg.code in (types.Failure_PinCancelled, types.Failure_ActionCancelled,
                        types.Failure_NotInitialized):
            raise UserCancelled()
        raise RuntimeError(msg.message)

    def callback_ButtonRequest(self, msg):
        message = self.msg
        if not message:
            message = self.messages.get(msg.code, self.messages['default'])
        self.handler.show_message(message.format(self.device), self.cancel)
        return self.proto.ButtonAck()

    def callback_PinMatrixRequest(self, msg):
        if msg.type == types.PinMatrixRequestType_NewFirst:
            msg = _("Enter a new PIN for your {}:")
        elif msg.type == types.PinMatrixRequestType_NewSecond:
            msg = (_("Re-enter the new PIN for your {}.\n\n"
                     "NOTE: the positions of the numbers have changed!"))
        else:
            # PinMatrixRequestType_Current
            msg = _("Enter your current {} PIN:")
        pin = self.handler.get_pin(msg.format(self.device))
        if not pin:
            return self.proto.Cancel()
        return self.proto.PinMatrixAck(pin=pin)

    def callback_PassphraseRequest(self, req):
        if self.creating_wallet:
            msg = _("Enter a passphrase to generate this wallet.  Each time "
                    "you use this wallet your {} will prompt you for the "
                    "passphrase.  If you forget the passphrase you cannot "
                    "access the bitcoins in the wallet.").format(self.device)
        else:
            msg = _("Enter the passphrase to unlock this wallet:")
        passphrase = self.handler.get_passphrase(msg, self.creating_wallet)
        if passphrase is None:
            return self.proto.Cancel()
        passphrase = bip39_normalize_passphrase(passphrase)
        return self.proto.PassphraseAck(passphrase=passphrase)

    def callback_WordRequest(self, msg):
        self.step += 1
        msg = _("Step {}/24.  Enter seed word as explained on "
                "your {}:").format(self.step, self.device)
        word = self.handler.get_word(msg)
        # Unfortunately the device can't handle self.proto.Cancel()
        return self.proto.WordAck(word=word)

    def callback_CharacterRequest(self, msg):
        char_info = self.handler.get_char(msg)
        if not char_info:
            return self.proto.Cancel()
        return self.proto.CharacterAck(**char_info)


KeepKeyClient.wrap_methods()
