import hashlib
from struct import pack, unpack

from electrumsv.app_state import app_state
from electrumsv.bitcoin import TYPE_ADDRESS, int_to_hex, var_int
from electrumsv.i18n import _
from electrumsv.keystore import Hardware_KeyStore
from electrumsv.logs import logs
from electrumsv.networks import Net
from electrumsv.transaction import Transaction
from electrumsv.util import bfh, bh2u, versiontuple

from ..hw_wallet import HW_PluginBase

from bitcoinx import (
    BIP32Derivation, BIP32PublicKey, PublicKey,
    pack_be_uint32,
)

try:
    import hid
    from btchip.btchipComm import HIDDongleHIDAPI
    from btchip.btchip import btchip
    from btchip.btchipUtils import compress_public_key
    from btchip.bitcoinTransaction import bitcoinTransaction
    from btchip.btchipFirmwareWizard import checkFirmware
    from btchip.btchipException import BTChipException
    BTCHIP = True
    BTCHIP_DEBUG = logs.is_debug_level()
except ImportError:
    BTCHIP = False


logger = logs.get_logger("plugin.ledger")

BITCOIN_CASH_SUPPORT = (1, 1, 8)

class Ledger_Client():

    def __init__(self, hidDevice):
        self.dongleObject = btchip(hidDevice)
        self.preflightDone = False

    def is_pairable(self):
        return True

    def close(self):
        self.dongleObject.dongle.close()

    def timeout(self, cutoff):
        pass

    def is_initialized(self):
        return True

    def label(self):
        return ""

    def i4b(self, x):
        return pack('>I', x)

    def has_usable_connection_with_device(self):
        try:
            self.dongleObject.getFirmwareVersion()
        except Exception:
            return False
        return True

    def test_pin_unlocked(func): # pylint: disable=no-self-argument
        """Function decorator to test the Ledger for being unlocked, and if not,
        raise a human-readable exception.
        """
        def catch_exception(self, *args, **kwargs):
            try:
                # pylint: disable=not-callable
                return func(self, *args, **kwargs)
            except BTChipException as e:
                if e.sw == 0x6982:
                    raise Exception(_('Your Ledger is locked. Please unlock it.'))
                else:
                    raise
        return catch_exception

    @test_pin_unlocked
    def get_xpub(self, bip32_path):
        self.checkDevice()
        # bip32_path is of the form 44'/0'/1'
        # S-L-O-W - we don't handle the fingerprint directly, so compute
        # it manually from the previous node
        # This only happens once so it's bearable
        #self.get_client() # prompt for the PIN before displaying the dialog if necessary
        #self.handler.show_message("Computing master public key")
        splitPath = bip32_path.split('/')
        if splitPath[0] == 'm':
            splitPath = splitPath[1:]
            bip32_path = bip32_path[2:]
        fingerprint = 0
        if len(splitPath) > 1:
            prevPath = "/".join(splitPath[0:len(splitPath) - 1])
            nodeData = self.dongleObject.getWalletPublicKey(prevPath)
            publicKey = bytes(compress_public_key(nodeData['publicKey']))
            h = hashlib.new('ripemd160')
            h.update(hashlib.sha256(publicKey).digest())
            fingerprint = unpack(">I", h.digest()[0:4])[0]
        nodeData = self.dongleObject.getWalletPublicKey(bip32_path)
        publicKey = compress_public_key(nodeData['publicKey'])
        depth = len(splitPath)
        lastChild = splitPath[len(splitPath) - 1].split('\'')
        childnum = int(lastChild[0]) if len(lastChild) == 1 else 0x80000000 | int(lastChild[0])

        derivation = BIP32Derivation(chain_code=nodeData['chainCode'], depth=depth,
                                     parent_fingerprint=pack_be_uint32(fingerprint),
                                     n=childnum)
        key = BIP32PublicKey(PublicKey.from_bytes(publicKey), derivation, Net.COIN)
        return key.extended_key_string()

    def has_detached_pin_support(self, client):
        try:
            client.getVerifyPinRemainingAttempts()
            return True
        except BTChipException as e:
            if e.sw == 0x6d00:
                return False
            raise e

    def is_pin_validated(self, client):
        try:
            # Invalid SET OPERATION MODE to verify the PIN status
            client.dongle.exchange(bytearray([0xe0, 0x26, 0x00, 0x00, 0x01, 0xAB]))
        except BTChipException as e:
            if e.sw == 0x6982:
                return False
            if e.sw == 0x6A80:
                return True
            raise e

    def supports_bitcoin_cash(self):
        return self.bitcoinCashSupported

    def perform_hw1_preflight(self):
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
                pin = pin.encode()
                self.dongleObject.verifyPin(pin)

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

    def checkDevice(self):
        if not self.preflightDone:
            try:
                self.perform_hw1_preflight()
            except BTChipException as e:
                if e.sw == 0x6d00 or e.sw == 0x6700:
                    raise Exception(_("Device not in Bitcoin Cash mode")) from e
                raise e
            self.preflightDone = True

    def password_dialog(self, msg=None):
        response = self.handler.get_word(msg)
        if response is None:
            return False, None, None
        return True, response, response


class Ledger_KeyStore(Hardware_KeyStore):
    hw_type = 'ledger'
    device = 'Ledger'

    def __init__(self, d):
        Hardware_KeyStore.__init__(self, d)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.force_watching_only = False
        self.signing = False
        self.cfg = d.get('cfg', {'mode':0,'pair':''})

    def dump(self):
        obj = Hardware_KeyStore.dump(self)
        obj['cfg'] = self.cfg
        return obj

    def get_derivation(self):
        return self.derivation

    def get_client(self):
        return self.plugin.get_client(self).dongleObject

    def get_client_electrum(self):
        return self.plugin.get_client(self)

    def give_error(self, message, clear_client = False):
        logger.error(message)
        if not self.signing:
            self.handler.show_error(message)
        else:
            self.signing = False
        if clear_client:
            self.client = None
        raise Exception(message)

    def set_and_unset_signing(func): # pylint: disable=no-self-argument
        """Function decorator to set and unset self.signing."""
        def wrapper(self, *args, **kwargs):
            try:
                self.signing = True
                # pylint: disable=not-callable
                return func(self, *args, **kwargs)
            finally:
                self.signing = False
        return wrapper

    def address_id_stripped(self, address):
        # Strip the leading "m/"
        change, index = self.get_address_index(address)
        derivation = self.derivation
        address_path = "{:s}/{:d}/{:d}".format(derivation, change, index)
        return address_path[2:]

    def decrypt_message(self, pubkey, message, password):
        raise RuntimeError(_('Encryption and decryption are not supported for {}').format(
            self.device))

    @set_and_unset_signing
    def sign_message(self, sequence, message, password):
        message = message.encode('utf8')
        message_hash = hashlib.sha256(message).hexdigest().upper()
        # prompt for the PIN before displaying the dialog if necessary
        client = self.get_client()
        address_path = self.get_derivation()[2:] + "/{:d}/{:d}".format(*sequence)
        self.handler.show_message("Signing message ...\r\nMessage hash: "+message_hash)
        try:
            info = self.get_client().signMessagePrepare(address_path, message)
            pin = ""
            if info['confirmationNeeded']:
                pin = self.handler.get_auth( info ) # does the authenticate dialog and returns pin
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
                self.give_error(e, True)
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return b''
        except Exception as e:
            self.give_error(e, True)
        finally:
            self.handler.finished()
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
    def sign_transaction(self, tx, password):
        if tx.is_complete():
            return
        client = self.get_client()
        inputs = []
        inputsPaths = []
        pubKeys = []
        chipInputs = []
        redeemScripts = []
        signatures = []
        preparedTrustedInputs = []
        changePath = ""
        changeAmount = None
        output = None
        outputAmount = None
        p2shTransaction = False
        pin = ""
        self.get_client() # prompt for the PIN before displaying the dialog if necessary

        # Fetch inputs of the transaction to sign
        derivations = self.get_tx_derivations(tx)
        for txin in tx.inputs():
            if txin['type'] == 'coinbase':
                self.give_error("Coinbase not supported")     # should never happen

            if txin['type'] in ['p2sh']:
                p2shTransaction = True

            pubkeys, x_pubkeys = tx.get_sorted_pubkeys(txin)
            for i, x_pubkey in enumerate(x_pubkeys):
                if x_pubkey in derivations:
                    signingPos = i
                    s = derivations.get(x_pubkey)
                    hwAddress = "{:s}/{:d}/{:d}".format(self.get_derivation()[2:], s[0], s[1])
                    break
            else:
                self.give_error("No matching x_key for sign_transaction") # should never happen

            redeemScript = Transaction.get_preimage_script(txin)
            inputs.append([txin['prev_tx'].raw, txin['prevout_n'], redeemScript,
                           txin['prevout_hash'], signingPos,
                           txin.get('sequence', 0xffffffff - 1)])
            inputsPaths.append(hwAddress)
            pubKeys.append(pubkeys)

        # Sanity check
        if p2shTransaction:
            for txin in tx.inputs():
                if txin['type'] != 'p2sh':   # should never happen
                    self.give_error(
                        "P2SH / regular input mixed in same transaction not supported")

        txOutput = var_int(len(tx.outputs()))
        for txout in tx.outputs():
            output_type, addr, amount = txout
            txOutput += int_to_hex(amount, 8)
            script = tx.pay_script(addr)
            txOutput += var_int(len(script)//2)
            txOutput += script
        txOutput = bfh(txOutput)

        # Recognize outputs - only one output and one change is authorized
        if not p2shTransaction:
            for _type, address, amount in tx.outputs():
                assert _type == TYPE_ADDRESS
                info = tx.output_info.get(address)
                if (info is not None) and (len(tx.outputs()) != 1):
                    index, xpubs, m = info
                    changePath = self.get_derivation()[2:] + "/{:d}/{:d}".format(*index)
                    changeAmount = amount
                else:
                    output = address
                    outputAmount = amount

        self.handler.show_message(_("Confirm Transaction on your Ledger device..."))
        try:
            # Get trusted inputs from the original transactions
            for utxo in inputs:
                sequence = int_to_hex(utxo[5], 4)
                txtmp = bitcoinTransaction(bfh(utxo[0]))
                tmp = bfh(utxo[3])[::-1]
                tmp += bfh(int_to_hex(utxo[1], 4))
                tmp += txtmp.outputs[utxo[1]].amount
                chipInputs.append({'value' : tmp, 'witness' : True, 'sequence' : sequence})
                redeemScripts.append(bfh(utxo[2]))

            # Sign all inputs
            inputIndex = 0
            rawTx = tx.serialize()
            self.get_client().enableAlternate2fa(False)
            self.get_client().startUntrustedTransaction(True, inputIndex,
                                                        chipInputs, redeemScripts[inputIndex])
            outputData = self.get_client().finalizeInputFull(txOutput)
            outputData['outputData'] = txOutput
            transactionOutput = outputData['outputData']
            if outputData['confirmationNeeded']:
                outputData['address'] = output
                self.handler.finished()
                pin = self.handler.get_auth( outputData ) # the authenticate dialog and returns pin
                if not pin:
                    raise UserWarning()
                if pin != 'paired':
                    self.handler.show_message(_("Confirmed. Signing Transaction..."))
            while inputIndex < len(inputs):
                singleInput = [ chipInputs[inputIndex] ]
                self.get_client().startUntrustedTransaction(
                    False, 0, singleInput, redeemScripts[inputIndex])
                inputSignature = self.get_client().untrustedHashSign(inputsPaths[inputIndex],
                                                                     pin, lockTime=tx.locktime,
                                                                     sighashType=tx.nHashType())
                inputSignature[0] = 0x30 # force for 1.4.9+
                signatures.append(inputSignature)
                inputIndex = inputIndex + 1
        except UserWarning:
            self.handler.show_error(_('Cancelled by user'))
            return
        except BTChipException as e:
            if e.sw == 0x6985:  # cancelled by user
                return
            else:
                logger.exception("")
                self.give_error(e, True)
        except Exception as e:
            logger.exception("")
            self.give_error(e, True)
        finally:
            self.handler.finished()

        for i, txin in enumerate(tx.inputs()):
            signingPos = inputs[i][4]
            txin['signatures'][signingPos] = bh2u(signatures[i])
        tx.raw = tx.serialize()

    @set_and_unset_signing
    def show_address(self, sequence):
        client = self.get_client()
        # prompt for the PIN before displaying the dialog if necessary
        address_path = self.get_derivation()[2:] + "/{:d}/{:d}".format(*sequence)
        self.handler.show_message(_("Showing address ..."))
        try:
            client.getWalletPublicKey(address_path, showOnScreen=True)
        except:
            pass
        finally:
            self.handler.finished()


class LedgerPlugin(HW_PluginBase):
    libraries_available = BTCHIP
    keystore_class = Ledger_KeyStore
    client = None
    DEVICE_IDS = [
                   (0x2581, 0x1807), # HW.1 legacy btchip
                   (0x2581, 0x2b7c), # HW.1 transitional production
                   (0x2581, 0x3b7c), # HW.1 ledger production
                   (0x2581, 0x4b7c), # HW.1 ledger test
                   (0x2c97, 0x0000), # Blue
                   (0x2c97, 0x0001), # Nano-S
                   (0x2c97, 0x0004), # Nano-X
                   (0x2c97, 0x0005), # RFU
                   (0x2c97, 0x0006), # RFU
                   (0x2c97, 0x0007), # RFU
                   (0x2c97, 0x0008), # RFU
                   (0x2c97, 0x0009), # RFU
                   (0x2c97, 0x000a)  # RFU
                 ]

    def __init__(self, name):
        HW_PluginBase.__init__(self, name)
        self.logger = logger

    def enumerate_devices(self):
        if self.libraries_available:
            return app_state.device_manager.find_hid_devices(self.DEVICE_IDS)
        return []

    def get_btchip_device(self, device):
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

    def create_client(self, device, handler):
        self.handler = handler

        client = self.get_btchip_device(device)
        if client is not None:
            client = Ledger_Client(client)
        return client

    def setup_device(self, device_info, wizard):
        device_id = device_info.device.id_
        client = app_state.device_manager.client_by_id(device_id)
        if client is None:
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Make sure it is in the correct state.'))
        client.handler = self.create_handler(wizard)
        # TODO replace by direct derivation once Nano S > 1.1
        client.get_xpub("m/44'/0'")

    def get_xpub(self, device_id, derivation, wizard):
        client = app_state.device_manager.client_by_id(device_id)
        client.handler = self.create_handler(wizard)
        client.checkDevice()
        xpub = client.get_xpub(derivation)
        return xpub

    def get_client(self, keystore, force_pair=True):
        client = app_state.device_manager.client_for_keystore(self, keystore, force_pair)
        if client:
            client.checkDevice()
        return client

    def show_address(self, wallet, address):
        sequence = wallet.get_address_index(address)
        wallet.get_keystore().show_address(sequence)
