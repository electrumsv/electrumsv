import hashlib
from struct import pack, unpack
from typing import Any, Callable, cast, List, NamedTuple, NoReturn, Optional, Tuple, \
    TYPE_CHECKING, TypeVar, Union

from bitcoinx import (bip32_build_chain_string, BIP32Derivation, BIP32PublicKey, PublicKey,
    pack_be_uint32, pack_list, pack_le_int64, pack_le_uint32)

from ...app_state import app_state
from ...bitcoin import ScriptTemplate
from ...constants import DerivationPath, ScriptType, unpack_derivation_path
from ...device import Device, DeviceInfo, SVBaseClient
from ...i18n import _
from ...keystore import Hardware_KeyStore
from ...logs import logs
from ...networks import Net
from ...standards.script_templates import classify_transaction_output_script
from ...transaction import Transaction, TxContext, XTxOutput
from ...types import MasterKeyDataHardware, MasterKeyDataHardwareCfg
from ...util import versiontuple
from ...wallet import AbstractAccount
from ...wallet_database.types import KeyListRow

from ..hw_wallet.plugin import HW_PluginBase

if TYPE_CHECKING:
    from ...transaction import XTxInput
    from ...wallet_database.types import MasterKeyRow
    from ...gui.qt.account_wizard import AccountWizard
    from ..hw_wallet.qt import QtHandlerBase
    from .qt import Ledger_Handler, Plugin

try:
    import hid
    from btchip.btchipComm import HIDDongleHIDAPI
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key
    from btchip.btchipFirmwareWizard import checkFirmware
    from btchip.btchipException import BTChipException
    BTCHIP = True
    BTCHIP_DEBUG = logs.is_debug_level()
except ImportError:
    BTCHIP = False


logger = logs.get_logger("plugin.ledger")

BITCOIN_CASH_SUPPORT = (1, 1, 8)

D1 = TypeVar('D1', bound=Callable[..., Any])

def set_and_unset_signing(func: D1) -> D1:
    """Function decorator to set and unset self.signing."""
    def wrapper(self: "Ledger_KeyStore", *args: Any, **kwargs: Any) -> Any:
        try:
            self.signing = True
            # pylint: disable=not-callable
            return func(self, *args, **kwargs)
        finally:
            self.signing = False
    return cast(D1, wrapper)

class YInput(NamedTuple):
    value: Optional[int]
    script_sig: bytes
    public_key_bytes: bytes
    sequence: int



def test_pin_unlocked(func: D1) -> D1:
    """Function decorator to test the Ledger for being unlocked, and if not,
    raise a human-readable exception.
    """
    def catch_exception(self: "Ledger_Client", *args: Any, **kwargs: Any) -> Any:
        try:
            # pylint: disable=not-callable
            return func(self, *args, **kwargs)
        except BTChipException as e:
            if e.sw == 0x6982:
                raise Exception(_('Your Ledger is locked. Please unlock it.'))
            else:
                raise
    return cast(D1, catch_exception)


class Ledger_Client():
    handler: 'Ledger_Handler'

    def __init__(self, hidDevice: HIDDongleHIDAPI) -> None:
        self.dongleObject = btchip(hidDevice)
        self.preflightDone = False

    def is_pairable(self) -> bool:
        return True

    def close(self) -> None:
        self.dongleObject.dongle.close()

    def timeout(self, cutoff: float) -> None:
        pass

    def is_initialized(self) -> bool:
        return True

    def label(self) -> str:
        return ""

    def i4b(self, x: int) -> bytes:
        return pack('>I', x)

    def has_usable_connection_with_device(self) -> bool:
        try:
            self.dongleObject.getFirmwareVersion()
        except Exception:
            return False
        return True

    @test_pin_unlocked
    def get_master_public_key(self, bip32_path: str) -> BIP32PublicKey:
        self.checkDevice()
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        #self.get_client() # prompt for the PIN before displaying the dialog if necessary
        #self.handler_qt.show_message("Computing master public key")
        splitPath = bip32_path.split('/')
        if splitPath[0] == 'm':
            splitPath = splitPath[1:]
            bip32_path = bip32_path[2:]
        fingerprint = 0
        if len(splitPath) > 1:
            prevPath = "/".join(splitPath[0:len(splitPath) - 1])
            nodeData = self.dongleObject.getWalletPublicKey(prevPath)
            publicKey = compress_public_key(nodeData['publicKey'])
            h = hashlib.new('ripemd160')
            h.update(hashlib.sha256(publicKey).digest())
            fingerprint = unpack(">I", h.digest()[0:4])[0]
        nodeData = self.dongleObject.getWalletPublicKey(bip32_path)
        publicKey = bytes(compress_public_key(nodeData['publicKey']))
        depth = len(splitPath)
        lastChild = splitPath[len(splitPath) - 1].split('\'')
        childnum = int(lastChild[0]) if len(lastChild) == 1 else 0x80000000 | int(lastChild[0])

        derivation = BIP32Derivation(chain_code=nodeData['chainCode'], depth=depth,
                                     parent_fingerprint=pack_be_uint32(fingerprint),
                                     n=childnum)
        return BIP32PublicKey(PublicKey.from_bytes(publicKey), derivation, Net.COIN)

    def has_detached_pin_support(self, client: btchip) -> bool:
        try:
            client.getVerifyPinRemainingAttempts()
            return True
        except BTChipException as e:
            if e.sw == 0x6d00:
                return False
            raise e

    def is_pin_validated(self, client: btchip) -> bool:
        try:
            # Invalid SET OPERATION MODE to verify the PIN status
            client.dongle.exchange(bytearray([0xe0, 0x26, 0x00, 0x00, 0x01, 0xAB]))
        except BTChipException as e:
            if e.sw == 0x6982:
                return False
            if e.sw == 0x6A80:
                return True
            raise e
        return False

    def supports_bitcoin_cash(self) -> bool:
        return self.bitcoinCashSupported

    def perform_hw1_preflight(self) -> None:
        try:
            firmwareInfo = self.dongleObject.getFirmwareVersion()
            firmware = firmwareInfo['version']
            self.bitcoinCashSupported = versiontuple(firmware) >= BITCOIN_CASH_SUPPORT

            if not checkFirmware(firmwareInfo) or not self.supports_bitcoin_cash():
                self.dongleObject.dongle.close()
                raise Exception("HW1 firmware version too old. Please update at "
                                "https://www.ledgerwallet.com")
            try:
                self.dongleObject.getOperationMode()
            except BTChipException as e:
                if e.sw == 0x6985:
                    self.dongleObject.dongle.close()
                    self.handler.get_setup( )
                    # Acquire the new client on the next run
                else:
                    raise e
            if (self.has_detached_pin_support(self.dongleObject) and
                    not self.is_pin_validated(self.dongleObject) and (self.handler is not None)):
                remaining_attempts = self.dongleObject.getVerifyPinRemainingAttempts()
                if remaining_attempts != 1:
                    msg = "Enter your Ledger PIN - remaining attempts : " + str(remaining_attempts)
                else:
                    msg = ("Enter your Ledger PIN - WARNING : LAST ATTEMPT. "
                           "If the PIN is not correct, the dongle will be wiped.")
                confirmed, p, pin = self.password_dialog(msg)
                if not confirmed:
                    raise Exception('Aborted by user - please unplug the dongle '
                                    'and plug it again before retrying')
                assert pin is not None
                pin_bytes = pin.encode()
                self.dongleObject.verifyPin(pin_bytes)

        except BTChipException as e:
            if e.sw == 0x6faa:
                raise Exception("Dongle is temporarily locked - please unplug it and "
                                "replug it again")
            if (e.sw & 0xFFF0) == 0x63c0:
                raise Exception("Invalid PIN - please unplug the dongle and plug "
                                "it again before retrying")
            if e.sw == 0x6f00 and e.message == 'Invalid channel':
                # based on docs 0x6f00 might be a more general error, hence we also
                # compare message to be sure
                raise Exception("Invalid channel.\nPlease make sure that "
                                "'Browser support' is disabled on your device.")
            raise e

    def checkDevice(self) -> None:
        if not self.preflightDone:
            try:
                self.perform_hw1_preflight()
            except BTChipException as e:
                if e.sw == 0x6d00 or e.sw == 0x6700:
                    raise Exception(_("Device not in Bitcoin Cash mode")) from e
                raise e
            self.preflightDone = True

    def password_dialog(self, msg: str) -> Tuple[bool, Optional[str], Optional[str]]:
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response


class Ledger_KeyStore(Hardware_KeyStore):
    hw_type = 'ledger'
    device = 'Ledger'
    handler_qt: Optional['Ledger_Handler']
    plugin: Optional["Plugin"]

    def __init__(self, data: MasterKeyDataHardware, row: Optional['MasterKeyRow']) -> None:
        Hardware_KeyStore.__init__(self, data, row)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.force_watching_only = False
        self.signing = False
        self.cfg = cast(MasterKeyDataHardwareCfg, data.get('cfg', {'mode':0}))

    def to_derivation_data(self) -> MasterKeyDataHardware:
        obj = super().to_derivation_data()
        obj['cfg'] = self.cfg
        return obj

    def get_derivation(self) -> str:
        return self.derivation

    def get_client(self) -> btchip:
        assert self.plugin is not None
        client = self.plugin.get_client(self)
        assert client is not None
        return client.dongleObject

    def get_client_electrum(self) -> Optional[Ledger_Client]:
        assert self.plugin is not None
        return self.plugin.get_client(self)

    def give_error(self, message: str, clear_client: bool = False) -> NoReturn:
        logger.error(message)
        if not self.signing:
            assert self.handler_qt is not None
            self.handler_qt.show_error(message)
        else:
            self.signing = False
        if clear_client:
            self.client = None
        raise Exception(message)

    def decrypt_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        raise RuntimeError(_('Encryption and decryption are not supported for {}').format(
            self.device))

    @set_and_unset_signing
    def sign_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        signature: bytes
        assert self.handler_qt is not None
        message_hash = hashlib.sha256(message).hexdigest().upper()
        # prompt for the PIN before displaying the dialog if necessary
        client = self.get_client()
        address_path = self.get_derivation()[2:] + "/{:d}/{:d}".format(*sequence)
        self.handler_qt.show_message("Signing message ...\r\nMessage hash: "+message_hash)
        try:
            info = self.get_client().signMessagePrepare(address_path, message)
            pin: Union[str, bytes] = ""
            if info['confirmationNeeded']:
                # does the authenticate dialog and returns pin
                pin = self.handler_qt.get_auth(self, info) or ""
                if not pin:
                    raise UserWarning(_('Cancelled by user'))
                pin = str(pin).encode()
            signature = self.get_client().signMessageSign(pin)
        except BTChipException as e:
            if e.sw == 0x6a80:
                self.give_error(
                    "Unfortunately, this message cannot be signed by the Ledger wallet. "
                    "Only alphanumerical messages shorter than 140 characters are supported. "
                    "Please remove any extra characters (tab, carriage return) and retry.")
            elif e.sw == 0x6985:  # cancelled by user
                return b''
            else:
                self.give_error(str(e), True)
        except UserWarning:
            self.handler_qt.show_error(_('Cancelled by user'))
            return b''
        except Exception as e:
            self.give_error(str(e), True)
        finally:
            self.handler_qt.finished()
        # Parse the ASN.1 signature
        rLength = signature[3]
        r = signature[4 : 4 + rLength]
        sLength = signature[4 + rLength + 1]
        s = signature[4 + rLength + 2:]
        if rLength == 33:
            r = r[1:]
        if sLength == 33:
            s = s[1:]
        # And convert it
        return bytes([27 + 4 + (signature[0] & 0x01)]) + r + s

    @set_and_unset_signing
    def sign_transaction(self, tx: Transaction, password: str, context: TxContext) -> None:
        if tx.is_complete():
            return

        assert self.handler_qt is not None
        inputs: List[YInput] = []
        inputsPaths = []
        chipInputs = []
        redeemScripts = []
        signatures = []
        changePath = ""
        output = None
        pin = ""
        ledger_client = self.get_client() # prompt for the PIN before displaying dialog if necessary


        # Fetch inputs of the transaction to sign
        foundP2SHSpend = False
        allSpendsAreP2SH = True
        for txin in tx.inputs:
            foundP2SHSpend = foundP2SHSpend or txin.type() == ScriptType.MULTISIG_P2SH
            allSpendsAreP2SH = allSpendsAreP2SH and txin.type() == ScriptType.MULTISIG_P2SH

            for i, (public_key_bytes, x_pubkey) in enumerate(txin.x_pubkeys.items()):
                if self.is_signature_candidate(x_pubkey):
                    matched_public_key_bytes = public_key_bytes
                    inputPath = self.get_derivation()[2:] +"/"+ \
                        "/".join(str(pv) for pv in x_pubkey.bip32_path())
                    break
            else:
                self.give_error("No matching x_key for sign_transaction") # should never happen

            inputs.append(YInput(txin.value, Transaction.get_preimage_script_bytes(txin),
                matched_public_key_bytes, txin.sequence))
            inputsPaths.append(inputPath)

        # Sanity check
        if foundP2SHSpend and not allSpendsAreP2SH:
            self.give_error("P2SH / regular input mixed in same transaction not supported")

        # Concatenate all the tx outputs as binary
        txOutput = pack_list(tx.outputs, XTxOutput.to_bytes)

        # Recognize outputs - only one output and one change is authorized
        if not foundP2SHSpend:
            keystore_fingerprint = self.get_fingerprint()
            assert len(tx.outputs) == len(context.hw_signing_metadata)
            for tx_output, output_metadatas in zip(tx.outputs, context.hw_signing_metadata):
                info = output_metadatas.get(keystore_fingerprint)
                if (info is not None) and len(tx.outputs) != 1:
                    key_derivation, xpubs, m = info
                    key_subpath = bip32_build_chain_string(key_derivation)[1:]
                    changePath = self.get_derivation()[2:] + key_subpath
                else:
                    _esv_script_type, _threshold, output = classify_transaction_output_script(
                        tx_output.script_pubkey)

        self.handler_qt.show_message(_("Confirm Transaction on your Ledger device..."))
        try:
            tx_bytes = tx.to_bytes()

            for i, yinput in enumerate(inputs):
                txin = tx.inputs[i]
                sequence = pack_le_uint32(yinput.sequence).hex()
                prevout_bytes = txin.prevout_bytes()
                value_bytes = prevout_bytes + pack_le_int64(yinput.value)
                chipInputs.append({'value' : value_bytes, 'witness' : True, 'sequence' : sequence})
                redeemScripts.append(yinput.script_sig)

            # Sign all inputs
            inputIndex = 0
            ledger_client.enableAlternate2fa(False)
            ledger_client.startUntrustedTransaction(True, inputIndex, chipInputs,
                redeemScripts[inputIndex])
            outputData = ledger_client.finalizeInput(b'', 0, 0, changePath, tx_bytes)
            outputData['outputData'] = txOutput
            if outputData['confirmationNeeded']:
                outputData['address'] = cast(ScriptTemplate, output).to_string()
                self.handler_qt.finished()
                # the authenticate dialog and returns pin
                auth_pin = self.handler_qt.get_auth(self, outputData)
                if not auth_pin:
                    raise UserWarning()
                pin = auth_pin
                self.handler_qt.show_message(_("Confirmed. Signing Transaction..."))
            while inputIndex < len(inputs):
                singleInput = [ chipInputs[inputIndex] ]
                ledger_client.startUntrustedTransaction(
                    False, 0, singleInput, redeemScripts[inputIndex])
                inputSignature = ledger_client.untrustedHashSign(inputsPaths[inputIndex],
                                                                     pin, lockTime=tx.locktime,
                                                                     sighashType=tx.nHashType())
                inputSignature[0] = 0x30 # force for 1.4.9+
                signatures.append(inputSignature)
                inputIndex = inputIndex + 1
        except UserWarning:
            self.handler_qt.show_error(_('Cancelled by user'))
            return
        except BTChipException as e:
            if e.sw == 0x6985:  # cancelled by user
                return
            else:
                logger.exception("")
                self.give_error(str(e), True)
        except Exception as e:
            logger.exception("")
            self.give_error(str(e), True)
        finally:
            self.handler_qt.finished()

        for txin, input, signature in zip(tx.inputs, inputs, signatures):
            txin.signatures[input.public_key_bytes] = signature
            txin.finalize_if_complete()

    @set_and_unset_signing
    def show_address(self, derivation_subpath: str) -> None:
        client = self.get_client()
        # prompt for the PIN before displaying the dialog if necessary
        address_path = self.get_derivation()[2:] +"/"+ derivation_subpath
        assert self.handler_qt is not None
        self.handler_qt.show_message(_("Showing address ..."))
        try:
            client.getWalletPublicKey(address_path, showOnScreen=True)
        except Exception:
            pass
        finally:
            self.handler_qt.finished()


class LedgerPlugin(HW_PluginBase):
    libraries_available = BTCHIP
    keystore_class = Ledger_KeyStore
    client = None
    DEVICE_IDS: List[Tuple[int, int]] = [
        (0x2581, 0x1807), # HW.1 legacy btchip
        (0x2581, 0x2b7c), # HW.1 transitional production
        (0x2581, 0x3b7c), # HW.1 ledger production
        (0x2581, 0x4b7c), # HW.1 ledger test
        (0x2c97, 0x0000), # Blue
        (0x2c97, 0x0011), # Blue app-bitcoin >= 1.5.1
        (0x2c97, 0x0015), # Blue app-bitcoin >= 1.5.1
        (0x2c97, 0x0001), # Nano-S
        (0x2c97, 0x1011), # Nano-S app-bitcoin >= 1.5.1
        (0x2c97, 0x1015), # Nano-S app-bitcoin >= 1.5.1
        (0x2c97, 0x0004), # Nano-X
        (0x2c97, 0x4011), # Nano-X app-bitcoin >= 1.5.1
        (0x2c97, 0x4015), # Nano-X app-bitcoin >= 1.5.1
    ]

    def __init__(self, name: str) -> None:
        HW_PluginBase.__init__(self, name)
        self.logger = logger

    def enumerate_devices(self) -> List[Device]:
        if self.libraries_available:
            return app_state.device_manager.find_hid_devices(self.DEVICE_IDS)
        return []

    def get_btchip_device(self, device: Device) -> Optional[HIDDongleHIDAPI]:
        ledger = False
        if device.product_key[0] == 0x2581 and device.product_key[1] == 0x3b7c:
            ledger = True
        if device.product_key[0] == 0x2581 and device.product_key[1] == 0x4b7c:
            ledger = True
        if device.product_key[0] == 0x2c97:
            if device.interface_number == 0 or device.usage_page == 0xffa0:
                ledger = True
            else:
                return None  # non-compatible interface of a nano s or blue
        dev = hid.device()
        dev.open_path(device.path)
        dev.set_nonblocking(True)
        return HIDDongleHIDAPI(dev, ledger, BTCHIP_DEBUG)

    def create_client(self, device: Device, handler: "QtHandlerBase") -> Optional[Ledger_Client]:
        self.handler = cast("Ledger_Handler", handler)
        btchip_device = self.get_btchip_device(device)
        client: Optional[Ledger_Client] = None
        if btchip_device is not None:
            client = Ledger_Client(btchip_device)
        return client

    def setup_device(self, device_info: DeviceInfo, wizard: "AccountWizard") -> None:
        device_id = device_info.device.id_
        client = cast(Ledger_Client, app_state.device_manager.client_by_id(device_id))
        if client is None:
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Make sure it is in the correct state.'))
        client.handler = cast("Ledger_Handler", self.create_handler(wizard))
        # TODO replace by direct derivation once Nano S > 1.1
        client.get_master_public_key("m/44'/0'")

    def get_master_public_key(self, device_id: str, derivation: str, wizard: "AccountWizard") \
            -> BIP32PublicKey:
        client = cast(Optional[Ledger_Client], app_state.device_manager.client_by_id(device_id))
        assert client is not None
        client.handler = cast("Ledger_Handler", self.create_handler(wizard))
        client.checkDevice()
        return client.get_master_public_key(derivation)

    def get_client(self, keystore: Ledger_KeyStore, force_pair: bool=True) \
            -> Optional[Ledger_Client]:
        client = cast(Optional[Ledger_Client],
            app_state.device_manager.client_for_keystore(self, keystore, force_pair))
        if client:
            client.checkDevice()
        return client

    def show_key(self, account: AbstractAccount, keydata: KeyListRow) -> None:
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        assert derivation_path is not None
        subpath = '/'.join(str(x) for x in derivation_path)
        keystore = cast(Ledger_KeyStore, account.get_keystore())
        keystore.show_address(subpath)


SVBaseClient.register(Ledger_Client)
