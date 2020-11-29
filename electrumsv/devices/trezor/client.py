import time

from bitcoinx import (
    bip32_decompose_chain_string, BIP32Derivation, BIP32PublicKey, PublicKey,
    pack_be_uint32,
)

from electrumsv.exceptions import UserCancelled
from electrumsv.i18n import _
from electrumsv.keystore import bip39_normalize_passphrase
from electrumsv.logs import logs
from electrumsv.networks import Net

from trezorlib.client import PASSPHRASE_ON_DEVICE, TrezorClient
from trezorlib.exceptions import TrezorFailure, Cancelled, OutdatedFirmwareError
from trezorlib.messages import ButtonRequestType, PinMatrixRequestType, RecoveryDeviceType, \
    WordRequestType
import trezorlib.btc
import trezorlib.device


logger = logs.get_logger("plugin.trezor")

MESSAGES = {
    ButtonRequestType.ConfirmOutput: _("Confirm the transaction output on your {} device"),
    ButtonRequestType.ResetDevice: _("Complete the initialization process on your {} device"),
    ButtonRequestType.ConfirmWord: _("Write down the seed word shown on your {}"),
    ButtonRequestType.WipeDevice: _("Confirm on your {} that you want to wipe it clean"),
    ButtonRequestType.ProtectCall: _("Confirm on your {} device the message to sign"),
    ButtonRequestType.SignTx:
        _("Confirm the total amount spent and the transaction fee on your {} device"),
    ButtonRequestType.Address: _("Confirm wallet address on your {} device"),
    ButtonRequestType._Deprecated_ButtonRequest_PassphraseType:
        _("Choose on your {} device where to enter your passphrase"),
    ButtonRequestType.PassphraseEntry: _("Please enter your passphrase on the {} device"),
    'default': _("Check your {} device to continue"),
}


class TrezorClientSV:

    def __init__(self, transport, handler, plugin):
        self.client = TrezorClient(transport, ui=self)
        self.plugin = plugin
        self.device = plugin.device
        self.handler = handler

        self.msg = None
        self.creating_wallet = False

        self.in_flow = False

        self.used()

    def run_flow(self, message=None, creating_wallet=False):
        if self.in_flow:
            raise RuntimeError("Overlapping call to run_flow")

        self.in_flow = True
        self.msg = message
        self.creating_wallet = creating_wallet
        self.prevent_timeouts()
        return self

    def end_flow(self):
        self.in_flow = False
        self.msg = None
        self.creating_wallet = False
        self.handler.finished()
        self.used()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.end_flow()
        if exc_value is not None:
            if issubclass(exc_type, Cancelled):
                raise UserCancelled from exc_value
            elif issubclass(exc_type, TrezorFailure):
                raise RuntimeError(str(exc_value)) from exc_value
            elif issubclass(exc_type, OutdatedFirmwareError):
                raise
            else:
                return False
        return True

    @property
    def features(self):
        return self.client.features

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
        if self.in_flow:
            return True

        try:
            res = self.client.ping("electrum pinging device")
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

    def get_master_public_key(self, bip32_path: str, creating=False) -> BIP32PublicKey:
        address_n = bip32_decompose_chain_string(bip32_path)
        with self.run_flow(creating_wallet=creating):
            node = trezorlib.btc.get_public_node(self.client, address_n).node
        self.used()
        derivation = BIP32Derivation(chain_code=node.chain_code, depth=node.depth,
                                     parent_fingerprint=pack_be_uint32(node.fingerprint),
                                     n=node.child_num)
        return BIP32PublicKey(PublicKey.from_bytes(node.public_key), derivation, Net.COIN)

    def toggle_passphrase(self):
        if self.features.passphrase_protection:
            msg = _("Confirm on your {} device to disable passphrases")
        else:
            msg = _("Confirm on your {} device to enable passphrases")
        enabled = not self.features.passphrase_protection
        with self.run_flow(msg):
            trezorlib.device.apply_settings(self.client, use_passphrase=enabled)

    def change_label(self, label):
        with self.run_flow(_("Confirm the new label on your {} device")):
            trezorlib.device.apply_settings(self.client, label=label)

    def change_homescreen(self, homescreen):
        with self.run_flow(_("Confirm on your {} device to change your home screen")):
            trezorlib.device.apply_settings(self.client, homescreen=homescreen)

    def set_pin(self, remove):
        if remove:
            msg = _("Confirm on your {} device to disable PIN protection")
        elif self.features.pin_protection:
            msg = _("Confirm on your {} device to change your PIN")
        else:
            msg = _("Confirm on your {} device to set a PIN")
        with self.run_flow(msg):
            trezorlib.device.change_pin(self.client, remove)

    def clear_session(self):
        '''Clear the session to force pin (and passphrase if enabled)
        re-entry.  Does not leak exceptions.'''
        logger.debug("clear session %s", self)
        self.prevent_timeouts()
        try:
            self.client.clear_session()
        except Exception as e:
            # If the device was removed it has the same effect...
            logger.error("clear_session: ignoring error %s", e)

    def close(self):
        '''Called when Our wallet was closed or the device removed.'''
        logger.debug("closing client")
        self.handler.clean_up()
        self.clear_session()

    def is_uptodate(self):
        if self.client.is_outdated():
            return False
        return self.client.version >= self.plugin.minimum_firmware

    def get_trezor_model(self):
        """Returns '1' for Trezor One, 'T' for Trezor T."""
        return self.features.model

    def show_address(self, derivation_text: str, script_type, multisig=None):
        coin_name = self.plugin.get_coin_name()
        address_n = bip32_decompose_chain_string(derivation_text)
        with self.run_flow():
            return trezorlib.btc.get_address(
                self.client,
                coin_name,
                address_n,
                show_display=True,
                script_type=script_type,
                multisig=multisig)

    def sign_message(self, address_str, message):
        coin_name = self.plugin.get_coin_name()
        address_n = bip32_decompose_chain_string(address_str)
        with self.run_flow():
            return trezorlib.btc.sign_message(
                self.client,
                coin_name,
                address_n,
                message)

    def recover_device(self, recovery_type, *args, **kwargs):
        input_callback = self.mnemonic_callback(recovery_type)
        with self.run_flow():
            return trezorlib.device.recover(
                self.client,
                *args,
                input_callback=input_callback,
                **kwargs)

    # ========= Unmodified trezorlib methods =========

    def sign_tx(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.btc.sign_tx(self.client, *args, **kwargs)

    def reset_device(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.device.reset(self.client, *args, **kwargs)

    def wipe_device(self, *args, **kwargs):
        with self.run_flow():
            return trezorlib.device.wipe(self.client, *args, **kwargs)

    # ========= UI methods ==========

    def button_request(self, code: int) -> None:
        message = self.msg or MESSAGES.get(code) or MESSAGES['default']
        self.handler.show_message(message.format(self.device), self.client.cancel)

    def get_pin(self, code: int) -> str:
        if code == PinMatrixRequestType.NewFirst:
            msg = _("Enter a new PIN for your {}:")
        elif code == PinMatrixRequestType.NewSecond:
            msg = (_("Re-enter the new PIN for your {}.\n\n"
                     "NOTE: the positions of the numbers have changed!"))
        else:
            # PinMatrixRequestType.Current
            # PinMatrixRequestType.WipeCodeFirst (likely irrelevant in this context)
            # PinMatrixRequestType.WipeCodeSecond (likely irrelevant in this context)
            msg = _("Enter your current {} PIN:")
        pin = self.handler.get_pin(msg.format(self.device))
        if not pin:
            raise Cancelled
        if len(pin) > 9:
            self.handler.show_error(_('The PIN cannot be longer than 9 characters.'))
            raise Cancelled
        return pin

    def get_passphrase(self, available_on_device: bool):
        if self.creating_wallet:
            msg = _("Enter a passphrase to generate this wallet.  Each time "
                    "you use this wallet your {} will prompt you for the "
                    "passphrase.  If you forget the passphrase you cannot "
                    "access the bitcoins in the wallet.").format(self.device)
        else:
            msg = _("Enter the passphrase to unlock this wallet:")
        self.handler.set_on_device_passphrase_result(
            PASSPHRASE_ON_DEVICE if available_on_device else None)
        passphrase = self.handler.get_passphrase(msg, self.creating_wallet)
        if passphrase is PASSPHRASE_ON_DEVICE:
            return passphrase
        if passphrase is None:
            raise Cancelled
        passphrase = bip39_normalize_passphrase(passphrase)
        length = len(passphrase)
        if length > 50:
            self.handler.show_error(_("Too long passphrase ({} > 50 chars).").format(length))
            raise Cancelled
        return passphrase

    def _matrix_char(self, matrix_type):
        num = 9 if matrix_type == WordRequestType.Matrix9 else 6
        char = self.handler.get_matrix(num)
        if char == 'x':
            raise Cancelled
        return char

    def mnemonic_callback(self, recovery_type):
        if recovery_type is None:
            return None

        if recovery_type == RecoveryDeviceType.Matrix:
            return self._matrix_char

        step = 0
        def word_callback(_ignored):
            nonlocal step
            step += 1
            msg = _("Step {}/24.  Enter seed word as explained on your {}:").format(
                step, self.device)
            word = self.handler.get_word(msg)
            if not word:
                raise Cancelled
            return word
        return word_callback
