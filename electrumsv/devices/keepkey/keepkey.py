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

import threading
from typing import cast, Dict, Generator, List, Optional, Tuple, TYPE_CHECKING, Union

from bitcoinx import Address, BIP32PublicKey, BIP32Derivation, bip32_decompose_chain_string, \
    Bitcoin, P2PKH_Address

from ...app_state import app_state
from ...constants import DerivationPath, unpack_derivation_path
from ...device import Device, DeviceInfo
from ...exceptions import UserCancelled
from ..hw_wallet.plugin import HW_PluginBase
from ...i18n import _
from ...keystore import Hardware_KeyStore
from ...logs import logs
from ...networks import Net
from ...standards.script_templates import classify_transaction_output_script
from ...transaction import HardwareSigningMetadata, Transaction, TransactionContext, XPublicKey, \
    XTxInput
from ...wallet import AbstractAccount
from ...wallet_database.types import KeyListRow

if TYPE_CHECKING:
    from ...gui.qt.account_wizard import AccountWizard
    from ..hw_wallet.qt import QtHandlerBase
    from .qt import Plugin, QtHandler


logger = logs.get_logger("plugin.keepkey")

try:
    from .client import KeepKeyClient
    import keepkeylib
    import keepkeylib.ckd_public
    from keepkeylib.client import types
    from keepkeylib.transport import Transport
    from usb1 import USBContext, USBDevice
    KEEPKEYLIB = True
except Exception:
    logger.exception("Failed to import keepkeylib")
    KEEPKEYLIB = False

# TREZOR initialization methods
TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY = range(0, 4)
KEEPKEY_PRODUCT_KEY = 'KeepKey'
NULL_DERIVATION = BIP32Derivation(chain_code=bytes(32), n=0, depth=0, parent_fingerprint=bytes(4))


class KeepKey_KeyStore(Hardware_KeyStore):
    hw_type = 'keepkey'
    device = KEEPKEY_PRODUCT_KEY

    def get_derivation(self) -> str:
        return self.derivation

    def requires_input_transactions(self) -> bool:
        # Keepkey has a 'tx_api' which is called to retrieve previous transactions, but it is
        # not called for BSV coins as they use BIP143, where the spent output's value is signed.
        return False

    def get_client(self, force_pair: bool=True) -> Optional[KeepKeyClient]:
        return cast(KeepKeyPlugin, self.plugin).get_client(self, force_pair)

    def decrypt_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        raise RuntimeError(_('Encryption and decryption are not implemented by {}').format(
            self.device))

    def sign_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        client = self.get_client()
        assert client is not None
        address_path = self.get_derivation() + "/%d/%d"%sequence
        address_n = bip32_decompose_chain_string(address_path)
        # returns protobuf mess
        msg_sig = client.sign_message(cast(KeepKeyPlugin, self.plugin).get_coin_name(client),
            address_n, message)
        return cast(bytes, msg_sig.signature)

    def sign_transaction(self, tx: Transaction, password: str,
            context: TransactionContext) -> None:
        if tx.is_complete():
            return

        assert not len(context.parent_transactions), \
            "This keystore does not require input transactions"
        # path of the xpubs that are involved
        xpub_path: Dict[str, str] = {}
        for txin in tx.inputs:
            for x_pubkey in txin.x_pubkeys.values():
                if not x_pubkey.is_bip32_key():
                    continue
                xpub = x_pubkey.bip32_extended_key()
                if xpub == self.get_master_public_key():
                    xpub_path[xpub] = self.get_derivation()

        assert self.plugin is not None
        cast(KeepKeyPlugin, self.plugin).sign_transaction(self, tx,
            context.hardware_signing_metadata, xpub_path)


class KeepKeyPlugin(HW_PluginBase):

    MAX_LABEL_LEN = 32

    firmware_URL = 'https://www.keepkey.com'
    libraries_URL = 'https://github.com/keepkey/python-keepkey'
    minimum_firmware = (4, 0, 0)
    keystore_class = KeepKey_KeyStore

    DEVICE_IDS = [ KEEPKEY_PRODUCT_KEY ]

    def __init__(self, name: str) -> None:
        super().__init__(name)

        self.libraries_available = KEEPKEYLIB
        if KEEPKEYLIB:
            try:
                self.usb_context = USBContext()
                self.usb_context.open()
            except Exception:
                self.libraries_available = False

        self.main_thread = threading.current_thread()

    def get_coin_name(self, client: KeepKeyClient) -> str:
        # No testnet support yet
        if client.features.major_version < 6:
            return "BitcoinCash"
        return "BitcoinSV"

    def _libusb_enumerate(self) -> Generator[USBDevice, None, None]:
        from keepkeylib.transport_webusb import DEVICE_IDS
        for dev in self.usb_context.getDeviceIterator(skip_on_error=True):
            usb_id = (dev.getVendorID(), dev.getProductID())
            if usb_id in DEVICE_IDS:
                yield dev

    def _enumerate_hid(self) -> List[Tuple[Optional[str], Optional[str], None]]:
        if KEEPKEYLIB:
            from keepkeylib.transport_hid import HidTransport
            return cast(List[Tuple[Optional[str], Optional[str], None]], HidTransport.enumerate())
        return []

    def _enumerate_web_usb(self) -> List[USBDevice]:
        if KEEPKEYLIB:
            from keepkeylib.transport_webusb import WebUsbTransport
            return list(self._libusb_enumerate())
        return []

    def _get_transport(self, device: Device) -> Transport:
        logger.debug("Trying to connect over USB...")

        if device.path.startswith('web_usb'):
            for d in self._enumerate_web_usb():
                if self._web_usb_path(d) == device.path:
                    from keepkeylib.transport_webusb import WebUsbTransport
                    return WebUsbTransport(d)
        else:
            for d in self._enumerate_hid():
                # TODO(no-merge) This needs to be resolved in hardware wallet testing.
                #   Is this bytes or string in d[0]?? Really, hid returns bytes but
                #   things use it as string, and converting it to a string makes it "b'...'" which
                #   just does not make sense.
                if str(d[0]) == device.path:
                    from keepkeylib.transport_hid import HidTransport
                    return HidTransport(d)

        raise RuntimeError(f'device {device} not found')

    def _device_for_path(self, path: str) -> Device:
        return Device(
            path=path,
            interface_number=-1,
            id_=path,
            product_key=KEEPKEY_PRODUCT_KEY,
            usage_page=0,
            transport_ui_string=path,
        )

    def _web_usb_path(self, device: USBDevice) -> str:
        return f'web_usb:{device.getBusNumber()}:{device.getPortNumberList()}'

    def enumerate_devices(self) -> List[Device]:
        devices: List[Device] = []

        for device in self._enumerate_web_usb():
            devices.append(self._device_for_path(self._web_usb_path(device)))

        for device in self._enumerate_hid():
            # Cast needed for older firmware
            devices.append(self._device_for_path(str(device[0])))

        return devices

    def create_client(self, device: Device, handler: "QtHandlerBase") -> Optional[KeepKeyClient]:
        # disable bridge because it seems to never returns if keepkey is plugged
        try:
            transport = self._get_transport(device)
        except Exception as e:
            logger.error("cannot connect to device")
            raise

        logger.debug("connected to device at %s", device.path)

        client = KeepKeyClient(transport, handler, self)

        # Try a ping for device sanity
        try:
            client.ping('t')
        except Exception as e:
            logger.error("ping failed %s", e)
            return None

        if not client.atleast_version(*self.minimum_firmware):
            msg = (_('Outdated {} firmware for device labelled {}. Please '
                     'download the updated firmware from {}')
                   .format(self.device, client.label(), self.firmware_URL))
            logger.error(msg)
            handler.show_error(msg)
            return None

        return client

    def get_client(self, keystore: KeepKey_KeyStore, force_pair: bool=True) \
            -> Optional[KeepKeyClient]:
        client = cast(Optional[KeepKeyClient],
            app_state.device_manager.client_for_keystore(self, keystore, force_pair))
        # returns the client for a given keystore. can use xpub
        if client:
            client.used()
        return client

    def initialize_device(self, device_id: str, wizard: "AccountWizard", handler: "QtHandler") \
            -> None:
        # Initialization method
        msg = _("Choose how you want to initialize your {}.\n\n"
                "The first two methods are secure as no secret information "
                "is entered into your computer.\n\n"
                "For the last two methods you input secrets on your keyboard "
                "and upload them to your {}, and so you should "
                "only do those on a computer you know to be trustworthy "
                "and free of malware."
        ).format(self.device, self.device)
        choices = [
            # Must be short as QT doesn't word-wrap radio button text
            _("Let the device generate a completely new seed randomly"),
            _("Recover from a seed you have previously written down"),
            _("Upload a BIP39 mnemonic to generate the seed"),
            _("Upload a master private key"),
        ]
        methods = [ TIM_NEW, TIM_RECOVER, TIM_MNEMONIC, TIM_PRIVKEY ]
        from ...gui.qt.util import window_query_choice
        choice_index = window_query_choice(wizard, _('Initialize Device'), msg, choices)
        if choice_index is not None:
            method = methods[choice_index]

            settings = cast("Plugin", self).request_trezor_init_settings(
                wizard, method, self.device)
            t = threading.Thread(target = self._initialize_device_safe,
                                 args=(settings, method, device_id, wizard, handler))
            t.setDaemon(True)
            t.start()
            # TODO(technical-debt) Broken account wizard. Old hardware wallet overlay code.
            # wizard.loop.exec()

    def _initialize_device_safe(self, settings: Tuple[Union[int, str], str, Union[bool, str], bool],
            method: int, device_id: str, wizard: "AccountWizard", handler: "QtHandler") -> None:
        exit_code = 0
        try:
            self._initialize_device(settings, method, device_id, wizard, handler)
        except UserCancelled:
            exit_code = 1
        except Exception as e:
            handler.show_error(str(e))
            exit_code = 1
        finally:
            # TODO(technical-debt) Broken account wizard. Old hardware wallet overlay code.
            pass
            # wizard.loop.exit(exit_code)

    def _initialize_device(self, settings: Tuple[Union[int, str], str, Union[bool, str], bool],
            method: int, device_id: str, wizard: "AccountWizard", handler: "QtHandler") -> None:
        item, label, pin_protection, passphrase_protection = settings

        language = 'english'
        client = cast(KeepKeyClient, app_state.device_manager.client_by_id(device_id))

        if method == TIM_NEW:
            assert isinstance(item, int)
            strength = 64 * (item + 2)  # 128, 192 or 256
            client.reset_device(True, strength, passphrase_protection,
                                pin_protection, label, language)
        elif method == TIM_RECOVER:
            assert isinstance(item, int)
            word_count = 6 * (item + 2)  # 12, 18 or 24
            client.step = 0
            client.recovery_device(
                False, # use_trezor_method
                word_count,
                passphrase_protection,
                pin_protection,
                label,
                language)
        elif method == TIM_MNEMONIC:
            pin = pin_protection  # It's the pin, not a boolean
            client.load_device_by_mnemonic(str(item), pin,
                                           passphrase_protection,
                                           label, language)
        else:
            pin = pin_protection  # It's the pin, not a boolean
            client.load_device_by_xprv(item, pin, passphrase_protection,
                                       label, language)

    def setup_device(self, device_info: DeviceInfo, wizard: "AccountWizard") -> None:
        '''Called when creating a new wallet.  Select the device to use.  If
        the device is uninitialized, go through the intialization
        process.'''
        device_id = device_info.device.id_
        client = cast(Optional[KeepKeyClient], app_state.device_manager.client_by_id(device_id))
        assert client is not None
        client.handler = cast("QtHandler", self.create_handler(wizard))
        if not device_info.initialized:
            self.initialize_device(device_id, wizard, client.handler)
        client.get_master_public_key('m', creating=True)

    def get_master_public_key(self, device_id: str, derivation: str, wizard: "AccountWizard") \
            -> BIP32PublicKey:
        client = cast(Optional[KeepKeyClient], app_state.device_manager.client_by_id(device_id))
        assert client is not None
        client.handler = cast("QtHandler", self.create_handler(wizard))
        return client.get_master_public_key(derivation)

    def sign_transaction(self, keystore: KeepKey_KeyStore, tx: Transaction,
            signing_metadata: List[HardwareSigningMetadata], xpub_path: Dict[str, str]) -> None:
        client = self.get_client(keystore)
        assert client is not None
        inputs = self.tx_inputs(tx, xpub_path)
        outputs = self.tx_outputs(keystore, keystore.get_derivation(), tx, signing_metadata)
        # NOTE(rt12) This will error on regtest, with "Failed to compile output". Chances are that
        #   that something like the xpub prefix are not supported.
        signatures, _ = cast(Tuple[List[bytes], bytes],
            client.sign_tx(self.get_coin_name(client), inputs, outputs, lock_time=tx.locktime))
        tx.update_signatures(signatures)

    def show_key(self, account: AbstractAccount, keydata: KeyListRow) -> None:
        keystore = cast(KeepKey_KeyStore, account.get_keystore())
        client = self.get_client(keystore)
        assert client is not None
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        assert derivation_path is not None
        subpath = '/'.join(str(x) for x in derivation_path)
        address_path = f"{keystore.derivation}/{subpath}"
        address_n = bip32_decompose_chain_string(address_path)
        script_type = types.SPENDADDRESS
        client.get_address(Net.KEEPKEY_DISPLAY_COIN_NAME, address_n,
                           True, script_type=script_type)

    def tx_inputs(self, tx: Transaction, xpub_path: Dict[str, str]) -> List[types.TxInputType]:
        inputs = []
        txin: XTxInput
        for txin in tx.inputs:
            txinputtype = types.TxInputType()

            path: DerivationPath
            if len(txin.x_pubkeys) == 1:
                x_pubkey = list(txin.x_pubkeys.values())[0]
                xpub, path = x_pubkey.bip32_extended_key_and_path()
                xpub_n = bip32_decompose_chain_string(xpub_path[xpub])
                txinputtype.address_n.extend(xpub_n)
                txinputtype.address_n.extend(path)
                txinputtype.script_type = types.SPENDADDRESS
            else:
                def f(x_pubkey: XPublicKey) -> types.HDNodePathType:
                    if x_pubkey.is_bip32_key():
                        xpub, path = x_pubkey.bip32_extended_key_and_path()
                    else:
                        xpub_key = BIP32PublicKey(x_pubkey.to_public_key(), NULL_DERIVATION,
                            Net.COIN)
                        xpub = xpub_key.to_extended_key_string()
                        path = cast(DerivationPath, ())
                    node = keepkeylib.ckd_public.deserialize(xpub)
                    return types.HDNodePathType(node=node, address_n=path)
                pubkeys: list[types.HDNodePathType] = []
                signatures: list[bytes] = []
                for public_key_bytes, x_pubkey in txin.x_pubkeys.items():
                    pubkeys.append(f(x_pubkey))
                    signatures.append(txin.signatures[public_key_bytes][:-1] if public_key_bytes
                        in txin.signatures else b'')
                multisig = types.MultisigRedeemScriptType(
                    pubkeys=pubkeys,
                    signatures=signatures,
                    m=txin.threshold,
                )
                script_type = types.SPENDMULTISIG
                txinputtype = types.TxInputType(
                    script_type=script_type,
                    multisig=multisig
                )
                # find which key is mine
                for x_pubkey in txin.x_pubkeys.values():
                    if x_pubkey.is_bip32_key():
                        xpub, path = x_pubkey.bip32_extended_key_and_path()
                        if xpub in xpub_path:
                            xpub_n = tuple(bip32_decompose_chain_string(xpub_path[xpub]))
                            txinputtype.address_n.extend(xpub_n)
                            txinputtype.address_n.extend(path)
                            break

            txinputtype.prev_hash = bytes(reversed(txin.prev_hash))
            txinputtype.prev_index = txin.prev_idx
            txinputtype.sequence = txin.sequence
            txinputtype.amount = txin.value

            inputs.append(txinputtype)

        return inputs

    def tx_outputs(self, keystore: KeepKey_KeyStore, derivation: str, tx: Transaction,
            signing_metadata: List[HardwareSigningMetadata]) -> List[types.TxOutputType]:
        has_change = False
        account_derivation = tuple(bip32_decompose_chain_string(derivation))
        keystore_fingerprint = keystore.get_fingerprint()

        outputs: List[types.TxOutputType] = []
        assert len(tx.outputs) == len(signing_metadata)
        for tx_output, output_metadatas in zip(tx.outputs, signing_metadata):
            info = output_metadatas.get(keystore_fingerprint)
            if info is not None and not has_change:
                has_change = True # no more than one change address
                key_derivation, xpubs, m = info
                if len(xpubs) == 1:
                    script_type = types.PAYTOADDRESS
                    txoutputtype = types.TxOutputType(
                        amount = tx_output.value,
                        script_type = script_type,
                        address_n = account_derivation + key_derivation,
                    )
                else:
                    script_type = types.PAYTOMULTISIG
                    nodes = [keepkeylib.ckd_public.deserialize(xpub) for xpub in xpubs]
                    pubkeys = [types.HDNodePathType(node=node, address_n=key_derivation)
                        for node in nodes]
                    multisig = types.MultisigRedeemScriptType(
                        pubkeys = pubkeys,
                        signatures = [b''] * len(pubkeys),
                        m = m)
                    txoutputtype = types.TxOutputType(
                        multisig = multisig,
                        amount = tx_output.value,
                        address_n = account_derivation + key_derivation,
                        script_type = script_type)
            else:
                txoutputtype = types.TxOutputType()
                txoutputtype.amount = tx_output.value
                _esv_script_type, _threshold, address = classify_transaction_output_script(
                    tx_output.script_pubkey)
                if isinstance(address, Address):
                    txoutputtype.script_type = types.PAYTOADDRESS
                    txoutputtype.address = address.to_string()
                    # NOTE(rt12) Bypass "Failed to compile output" failures on test networks.
                    # txoutputtype.address = self.get_string_for_address(address)

            outputs.append(txoutputtype)

        return outputs

    def get_string_for_address(self, address: Address) -> str:
        """
        There is no BSV Keepkey support in their firmware:
        https://github.com/keepkey/keepkey-firmware/blob/master/include/keepkey/firmware/coins.def

        This can be used to replace testnet addresses with mainnet addresses, but it is not checked
        in enabled as it is a bad idea to sign potential mainnet payments with a testnet
        application. The addresses that are passed to Keepkey for non-mainnet addresses are the
        text testnet addresses. These are not accepted by Keepkey and result in
        "Failed to compile output" with a code of 9.

        This function replaces them with mainnet addresses which sign correctly without error.
        It is possible Keepkey do not support testnet at all in their firmware.
        """
        if Net.is_mainnet():
            return cast(str, address.to_string())

        # NOTE(rt12) Ensure we do not pass the Keepkey non-mainnet addresses for now. We do not
        #     have to care about the user signing a P2SH spend as they can no longer be made
        #     anyway.
        assert isinstance(address, P2PKH_Address)
        return cast(str, P2PKH_Address(address.hash160(), Bitcoin).to_string())
