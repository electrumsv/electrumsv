# ----------------------------------------------------------------------------------
# Electrum plugin for the Digital Bitbox hardware wallet by Shift Devices AG
# digitalbitbox.com
#

import base64
import hashlib
import hmac
import json
import math
import os
import re
import requests
import struct
import time
from typing import Any, cast, Dict, List, NoReturn, Optional, Tuple, TYPE_CHECKING

from bitcoinx import (bip32_build_chain_string, bip32_key_from_string, BIP32PublicKey,
    compact_signature_to_der, pack_signed_message, PublicKey)

from ...app_state import app_state
from ...constants import DerivationPath, ScriptType
from ...device import Device, DeviceInfo, SVBaseClient
from ...crypto import sha256d, EncodeAES_base64, EncodeAES_bytes, DecodeAES_bytes
from ...exceptions import UserCancelled
from ...i18n import _
from ...keystore import Hardware_KeyStore
from ...logs import logs
from ...platform import platform
from ...transaction import Transaction, TransactionContext
from ...types import MasterKeyDataHardware

from ..hw_wallet.qt import QtHandlerBase
from ..hw_wallet.plugin import HW_PluginBase

try:
    import hid
    DIGIBOX = True
except ImportError as e:
    DIGIBOX = False

if TYPE_CHECKING:
    from ...wallet_database.types import MasterKeyRow
    from ...gui.qt.account_wizard import AccountWizard
    from .qt import DigitalBitbox_Handler


logger = logs.get_logger("plugin.bitbox")

# ----------------------------------------------------------------------------------
# USB HID interface
#

def derive_keys(x: bytes) -> Tuple[bytes, bytes]:
    h = sha256d(x)
    h = hashlib.sha512(h).digest()
    return (h[:32],h[32:])

MIN_MAJOR_VERSION = 5

class DigitalBitbox_Client:
    handler: Optional["DigitalBitbox_Handler"] = None
    password: Optional[bytes]

    def __init__(self, plugin: "DigitalBitboxPlugin", hidDevice: hid.device) -> None:
        self.plugin = plugin
        self.dbb_hid: hid.device = hidDevice
        self.opened = True
        self.password = None
        self.isInitialized = False
        self.setupRunning = False
        self.usbReportSize = 64 # firmware > v2.0.0

    def close(self) -> None:
        if self.opened:
            try:
                self.dbb_hid.close()
            except Exception:
                pass
        self.opened = False

    def timeout(self, cutoff: float) -> None:
        pass

    def label(self) -> str:
        return " "

    def is_pairable(self) -> bool:
        return True

    def is_initialized(self) -> bool:
        return self.dbb_has_password()

    def is_paired(self) -> bool:
        return self.password is not None

    def has_usable_connection_with_device(self) -> bool:
        try:
            self.dbb_has_password()
        except Exception:
            return False
        return True

    def _get_xpub(self, bip32_path: str) -> Optional[Dict[str, Any]]:
        if self.check_device_dialog():
            return self.hid_send_encrypt(b'{"xpub": "%s"}' % bip32_path.encode('utf8'))
        return None

    def get_master_public_key(self, bip32_path: str) -> BIP32PublicKey:
        reply = self._get_xpub(bip32_path)
        if reply:
            return cast(BIP32PublicKey, bip32_key_from_string(reply['xpub']))
        else:
            raise Exception('no reply')

    def dbb_has_password(self) -> bool:
        reply = self.hid_send_plain(b'{"ping":""}')
        if 'ping' not in reply:
            raise Exception(_('Device communication error. Please unplug and '
                              'replug your Digital Bitbox.'))
        if reply['ping'] == 'password':
            return True
        return False

    def stretch_key(self, key: bytes) -> str:
        return hashlib.pbkdf2_hmac('sha512', key, b'Digital Bitbox', iterations = 20480).hex()

    def backup_password_dialog(self) -> Optional[bytes]:
        assert self.handler is not None
        msg = _("Enter the password used when the backup was created:")
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return None
            if len(password) < 4:
                msg = _("Password must have at least 4 characters.") \
                      + "\n\n" + _("Enter password:")
            elif len(password) > 64:
                msg = _("Password must have less than 64 characters.") \
                      + "\n\n" + _("Enter password:")
            else:
                return password.encode('utf8')

    def password_dialog(self, msg: str) -> bool:
        assert self.handler is not None
        while True:
            password = self.handler.get_passphrase(msg, False)
            if password is None:
                return False
            if len(password) < 4:
                msg = _("Password must have at least 4 characters.") + \
                      "\n\n" + _("Enter password:")
            elif len(password) > 64:
                msg = _("Password must have less than 64 characters.") + \
                      "\n\n" + _("Enter password:")
            else:
                self.password = password.encode('utf8')
                return True

    def check_device_dialog(self) -> bool:
        match = re.search(r'v([0-9])+\.[0-9]+\.[0-9]+', self.dbb_hid.get_serial_number_string())
        if match is None:
            raise Exception("error detecting firmware version")
        major_version = int(match.group(1))
        if major_version < MIN_MAJOR_VERSION:
            raise Exception("Please upgrade to the newest firmware using the BitBox Desktop app: "+
                            "https://shiftcrypto.ch/start")
        # Set password if fresh device
        if self.password is None and not self.dbb_has_password():
            if not self.setupRunning:
                return False # A fresh device cannot connect to an existing wallet
            msg = _("An uninitialized Digital Bitbox is detected.") + " " + \
                  _("Enter a new password below.") + "\n\n" + \
                  _("REMEMBER THE PASSWORD!") + "\n\n" + \
                  _("You cannot access your coins or a backup without the password.") + "\n" + \
                  _("A backup is saved automatically when generating a new wallet.")
            if self.password_dialog(msg):
                assert self.password is not None
                reply = self.hid_send_plain(b'{"password":"' + self.password + b'"}')
            else:
                return False

        # Get password from user if not yet set
        msg = _("Enter your Digital Bitbox password:")
        while self.password is None:
            if not self.password_dialog(msg):
                return False
            reply = self.hid_send_encrypt(b'{"led":"blink"}')
            if 'error' in reply:
                self.password = None
                if reply['error']['code'] == 109:
                    msg = _("Incorrect password entered.") + "\n\n" + \
                          reply['error']['message'] + "\n\n" + \
                          _("Enter your Digital Bitbox password:")
                else:
                    # Should never occur
                    msg = _("Unexpected error occurred.") + "\n\n" + \
                          reply['error']['message'] + "\n\n" + \
                          _("Enter your Digital Bitbox password:")

        # Initialize device if not yet initialized
        if not self.setupRunning:
            # Wallet exists. Electrum code later checks if the device matches the wallet
            self.isInitialized = True
        elif not self.isInitialized:
            reply = self.hid_send_encrypt(b'{"device":"info"}')
            if reply['device']['id'] != "":
                self.recover_or_erase_dialog() # Already seeded
            else:
                self.seed_device_dialog() # Seed if not initialized
            self.mobile_pairing_dialog()
        return self.isInitialized

    def recover_or_erase_dialog(self) -> None:
        assert self.handler is not None
        msg = _("The Digital Bitbox is already seeded. Choose an option:") + "\n"
        choices = [
            (_("Create a wallet using the current seed")),
            (_("Load a wallet from the micro SD card (the current seed is overwritten)")),
            (_("Erase the Digital Bitbox"))
        ]
        try:
            reply = self.handler.win.query_choice(msg, choices)
        except Exception:
            logger.exception('Exception caught')
            return # Back button pushed
        if reply == 2:
            self.dbb_erase()
        elif reply == 1:
            if not self.dbb_load_backup():
                return
        else:
            if self.hid_send_encrypt(b'{"device":"info"}')['device']['lock']:
                raise Exception(_("Full 2FA enabled. This is not supported yet."))
            # Use existing seed
        self.isInitialized = True

    def seed_device_dialog(self) -> None:
        assert self.handler is not None
        msg = _("Choose how to initialize your Digital Bitbox:") + "\n"
        choices = [
            (_("Generate a new random wallet")),
            (_("Load a wallet from the micro SD card"))
        ]
        try:
            reply = self.handler.win.query_choice(msg, choices)
        except Exception:
            logger.exception('Exception caught')
            return # Back button pushed
        if reply == 0:
            self.dbb_generate_wallet()
        else:
            if not self.dbb_load_backup(show_msg=False):
                return
        self.isInitialized = True

    def mobile_pairing_dialog(self) -> None:
        assert self.handler is not None
        try:
            with open(os.path.join(platform.dbb_user_dir(), "config.dat")) as f:
                dbb_config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return

        if 'encryptionprivkey' not in dbb_config or 'comserverchannelid' not in dbb_config:
            return

        choices = [
            _('Do not pair'),
            _('Import pairing from the Digital Bitbox desktop app'),
        ]
        try:
            reply = self.handler.win.query_choice(_('Mobile pairing options'), choices)
        except Exception:
            logger.exception('Exception caught')
            return # Back button pushed

        digitalbitbox_config = self.plugin.digitalbitbox_config
        if reply == 0:
            if self.plugin.is_mobile_paired():
                del digitalbitbox_config['encryptionprivkey']
                del digitalbitbox_config['comserverchannelid']
        elif reply == 1:
            # import pairing from dbb app
            digitalbitbox_config['encryptionprivkey'] = dbb_config['encryptionprivkey']
            digitalbitbox_config['comserverchannelid'] = dbb_config['comserverchannelid']
        app_state.config.set_key('digitalbitbox', digitalbitbox_config)

    def dbb_generate_wallet(self) -> None:
        assert self.password is not None
        key = self.stretch_key(self.password)
        filename = ("Electrum-" + time.strftime("%Y-%m-%d-%H-%M-%S") + ".pdf").encode('utf8')
        msg = (b'{"seed":{"source": "create", "key": "%s", "filename": "%s", "entropy": "%s"}}'
               % (key.encode("utf-8"), filename, b'Digital Bitbox Electrum Plugin'))
        reply = self.hid_send_encrypt(msg)
        if 'error' in reply:
            raise Exception(reply['error']['message'])

    def dbb_erase(self) -> None:
        assert self.handler is not None
        self.handler.show_message(
            _("Are you sure you want to erase the Digital Bitbox?") + "\n\n" +
            _("To continue, touch the Digital Bitbox's light for 3 seconds.") + "\n\n" +
            _("To cancel, briefly touch the light or wait for the timeout."))
        hid_reply = self.hid_send_encrypt(b'{"reset":"__ERASE__"}')
        self.handler.finished()
        if 'error' in hid_reply:
            raise Exception(hid_reply['error']['message'])
        else:
            self.password = None
            raise Exception('Device erased')

    def dbb_load_backup(self, show_msg: bool=True) -> bool:
        assert self.handler is not None
        backups = self.hid_send_encrypt(b'{"backup":"list"}')
        if 'error' in backups:
            raise Exception(backups['error']['message'])
        try:
            f = self.handler.win.query_choice(_("Choose a backup file:"), backups['backup'])
        except Exception:
            logger.exception('Exception caught')
            return False # Back button pushed
        key_bytes = self.backup_password_dialog()
        if key_bytes is None:
            raise Exception('Canceled by user')
        key = self.stretch_key(key_bytes)
        if show_msg:
            self.handler.show_message(
                _("Loading backup...") + "\n\n" +
                _("To continue, touch the Digital Bitbox's light for 3 seconds.") + "\n\n" +
                _("To cancel, briefly touch the light or wait for the timeout."))
        msg = '{"seed":{"source": "backup", "key": "%s", "filename": "%s"}}' \
            % (key, cast(str, backups['backup'][f]))
        hid_reply = self.hid_send_encrypt(msg.encode('utf8'))
        self.handler.finished()
        if 'error' in hid_reply:
            raise Exception(hid_reply['error']['message'])
        return True

    def hid_send_frame(self, data: bytes) -> None:
        HWW_CID = 0xFF000000
        HWW_CMD = 0x80 + 0x40 + 0x01
        data_len = len(data)
        seq = 0
        idx = 0
        write = b''
        while idx < data_len:
            if idx == 0:
                # INIT frame
                write = data[idx : idx + min(data_len, self.usbReportSize - 7)]
                self.dbb_hid.write(b'\0' + struct.pack(">IBH", HWW_CID, HWW_CMD, data_len & 0xFFFF)
                                   + write + b'\xEE' * (self.usbReportSize - 7 - len(write)))
            else:
                # CONT frame
                write = data[idx : idx + min(data_len, self.usbReportSize - 5)]
                self.dbb_hid.write(b'\0' + struct.pack(">IB", HWW_CID, seq)
                                   + write + b'\xEE' * (self.usbReportSize - 5 - len(write)))
                seq += 1
            idx += len(write)

    def hid_read_frame(self) -> bytearray:
        # INIT response
        read = bytearray(self.dbb_hid.read(self.usbReportSize))
        cid = ((read[0] * 256 + read[1]) * 256 + read[2]) * 256 + read[3]
        cmd = read[4]
        data_len = read[5] * 256 + read[6]
        data = read[7:]
        idx = len(read) - 7
        while idx < data_len:
            # CONT response
            read = bytearray(self.dbb_hid.read(self.usbReportSize))
            data += read[5:]
            idx += len(read) - 5
        return data

    def hid_send_plain(self, msg: bytes) -> Dict[str, Any]:
        reply: Dict[str, Any] = {}
        try:
            serial_number = self.dbb_hid.get_serial_number_string()
            if "v2.0." in serial_number or "v1." in serial_number:
                hidBufSize = 4096
                self.dbb_hid.write(b'\0' + msg + b'\0' * (hidBufSize - len(msg)))
                r = bytearray()
                while len(r) < hidBufSize:
                    r += bytearray(self.dbb_hid.read(hidBufSize))
            else:
                self.hid_send_frame(msg)
                r = self.hid_read_frame()
            r = r.rstrip(b' \t\r\n\0')
            r = r.replace(b"\0", b'')
            reply = cast(Dict[str, Any], json.loads(r.decode('utf8')))
        except Exception:
            logger.exception('Exception caught')
        return reply

    def hid_send_encrypt(self, msg: bytes) -> Dict[str, Any]:
        assert self.password is not None
        sha256_byte_len = 32
        reply: Dict[str, Any] = {}
        try:
            encryption_key, authentication_key = derive_keys(self.password)
            msg = EncodeAES_bytes(encryption_key, msg)
            hmac_digest = hmac.digest(authentication_key, msg, 'sha256')
            authenticated_msg = base64.b64encode(msg + hmac_digest)
            reply = self.hid_send_plain(authenticated_msg)
            if 'ciphertext' in reply:
                b64_unencoded = bytes(base64.b64decode(''.join(reply["ciphertext"])))
                reply_hmac = b64_unencoded[-sha256_byte_len:]
                hmac_calculated = hmac.digest(
                    authentication_key, b64_unencoded[:-sha256_byte_len], 'sha256')
                if not hmac.compare_digest(reply_hmac, hmac_calculated):
                    raise Exception("Failed to validate HMAC")
                reply_data = DecodeAES_bytes(encryption_key, b64_unencoded[:-sha256_byte_len])
                reply = cast(Dict[str, Any], json.loads(reply_data.decode('utf8')))
            if 'error' in reply:
                self.password = None
        except Exception:
            logger.exception('Exception caught')
        return reply



# ----------------------------------------------------------------------------------
#
#

class DigitalBitbox_KeyStore(Hardware_KeyStore):
    hw_type = 'digitalbitbox'
    device = 'DigitalBitbox'

    def __init__(self, data: MasterKeyDataHardware, row: 'MasterKeyRow') -> None:
        Hardware_KeyStore.__init__(self, data, row)
        self.force_watching_only = False
        self.maxInputs = 14 # maximum inputs per single sign command

    def get_derivation(self) -> str:
        return str(self.derivation)

    def is_p2pkh(self) -> bool:
        return self.derivation.startswith("m/44'/")

    def give_error(self, message: str, clear_client: bool=False) -> NoReturn:
        if clear_client:
            self.client = None
        raise Exception(message)

    def decrypt_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        raise RuntimeError(_('Encryption and decryption are not supported for {}').format(
            self.device))

    def sign_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        assert self.handler_qt is not None
        try:
            inputPath = self.get_derivation() + "/%d/%d" % sequence
            msg_hash = sha256d(pack_signed_message(message))
            inputHash = msg_hash.hex()
            hasharray = []
            hasharray.append({'hash': inputHash, 'keypath': inputPath})
            hasharray_text = json.dumps(hasharray)

            msg = b'{"sign":{"meta":"sign message", "data":%s}}' % hasharray_text.encode('utf8')

            assert self.plugin is not None
            dbb_client = cast(DigitalBitboxPlugin, self.plugin).get_client(self)
            assert dbb_client is not None

            if not dbb_client.is_paired():
                raise Exception(_("Bitbox does not appear to be connected."))

            reply = dbb_client.hid_send_encrypt(msg)
            self.handler_qt.show_message(
                _("Signing message ...") + "\n\n" +
                _("To continue, touch the Digital Bitbox's blinking light for "
                  "3 seconds.") + "\n\n" +
                _("To cancel, briefly touch the blinking light or wait for the timeout."))
            # Send twice, first returns an echo for smart verification (not implemented)
            reply = dbb_client.hid_send_encrypt(msg)
            self.handler_qt.finished()

            if 'error' in reply:
                raise Exception(reply['error']['message'])

            if 'sign' not in reply:
                raise Exception(_("Bitbox did not sign the message."))

            siginfo = reply['sign'][0]
            compact_sig = bytes.fromhex(siginfo['sig'])
            if 'recid' in siginfo:
                recids = [int(siginfo['recid'], 16)]
            else:
                recids = list(range(4))
            for recid in recids:
                # firmware > v2.1.1
                message_sig = bytes([recid + 27]) + compact_sig
                try:
                    pubkey = PublicKey.from_signed_message(message_sig, message)
                except Exception:
                    logger.exception("If Digital Bitbox signing failed, this may be why")
                    continue
                if pubkey.verify_message(message_sig, message):
                    return message_sig
            raise RuntimeError(_("Unable to sign as Bitbox failed to provide a valid signature"))
        except Exception as e:
            self.give_error(str(e))

    def sign_transaction(self, tx: Transaction, password: str, context: TransactionContext) \
            -> None:
        if tx.is_complete():
            return

        try:
            p2pkhTransaction = True
            inputhasharray = []
            hasharray = []
            pubkeyarray = []

            # Build hasharray from inputs
            for txin in tx.inputs:
                if txin.type() != ScriptType.P2PKH:
                    p2pkhTransaction = False

                for x_pubkey in txin.x_pubkeys.values():
                    if self.is_signature_candidate(x_pubkey):
                        key_derivation = x_pubkey.bip32_path()
                        assert len(key_derivation) == 2
                        inputPath = self.get_derivation() +"/"+ \
                            "/".join(str(pv) for pv in key_derivation)
                        inputHash = tx.preimage_hash(txin)
                        hasharray_i = {'hash': inputHash.hex(), 'keypath': inputPath}
                        hasharray.append(hasharray_i)
                        inputhasharray.append(inputHash)
                        break
                else:
                    self.give_error("No matching x_key for sign_transaction") # should never happen

            # Build pubkeyarray from annotated change outputs.
            # The user is on their own if they have unannotated non-change self-outputs.
            for txout in tx.outputs:
                for public_key_bytes, x_public_key in txout.x_pubkeys.items():
                    if self.is_signature_candidate(x_public_key):
                        key_path_text = bip32_build_chain_string(x_public_key.derivation_path)[1:]
                        changePath = self.get_derivation() + key_path_text # "/1/0", no "m"
                        pubkeyarray.append({
                            'pubkey': public_key_bytes.hex(),
                            'keypath': changePath,
                        })

            # Special serialization of the unsigned transaction for
            # the mobile verification app.
            # At the moment, verification only works for p2pkh transactions.
            tx_dbb_serialized: Optional[str]
            if p2pkhTransaction:
                tx_dbb_serialized = tx.serialize()
            else:
                # We only need this for the signing echo / verification.
                tx_dbb_serialized = None

            # Build sign command
            dbb_signatures: List[Dict[str, Any]] = []
            steps = math.ceil(1.0 * len(hasharray) / self.maxInputs)
            for step in range(int(steps)):
                hashes = hasharray[step * self.maxInputs : (step + 1) * self.maxInputs]

                msg_data: Dict[str, Any] = {
                    "sign": {
                        "data": hashes,
                        "checkpub": pubkeyarray,
                    },
                }
                if tx_dbb_serialized is not None:
                    msg_data["sign"]["meta"] = sha256d(tx_dbb_serialized).hex()
                msg = json.dumps(msg_data).encode('ascii')
                assert self.plugin is not None
                plugin = cast(DigitalBitboxPlugin, self.plugin)
                dbb_client: Optional[DigitalBitbox_Client] = plugin.get_client(self)
                assert dbb_client is not None

                if not dbb_client.is_paired():
                    raise Exception("Could not sign transaction.")

                reply = dbb_client.hid_send_encrypt(msg)
                if 'error' in reply:
                    raise Exception(reply['error']['message'])

                if 'echo' not in reply:
                    raise Exception("Could not sign transaction.")

                if plugin.is_mobile_paired() and tx_dbb_serialized is not None:
                    reply['tx'] = tx_dbb_serialized
                    plugin.comserver_post_notification(reply)

                handler = cast(QtHandlerBase, self.handler_qt)
                if steps > 1:
                    handler.show_message(
                        _("Signing large transaction. Please be patient ...") + "\n\n" +
                        _("To continue, touch the Digital Bitbox's blinking light for "
                          "3 seconds.") + " " +
                        _("(Touch {} of {})").format((step + 1), steps) + "\n\n" +
                        _("To cancel, briefly touch the blinking light or wait for the timeout.")
                        + "\n\n")
                else:
                    handler.show_message(
                        _("Signing transaction...") + "\n\n" +
                        _("To continue, touch the Digital Bitbox's blinking light for "
                          "3 seconds.") + "\n\n" +
                        _("To cancel, briefly touch the blinking light or wait for the timeout."))

                # Send twice, first returns an echo for smart verification
                reply = dbb_client.hid_send_encrypt(msg)
                handler.finished()

                if 'error' in reply:
                    if reply["error"].get('code') in (600, 601):
                        # aborted via LED short touch or timeout
                        raise UserCancelled()
                    raise Exception(reply['error']['message'])

                if 'sign' not in reply:
                    raise Exception("Could not sign transaction.")

                dbb_signatures.extend(reply['sign'])

            # Fill signatures
            if len(dbb_signatures) != len(tx.inputs):
                raise RuntimeError("Incorrect number of transactions signed")
            for txin, siginfo, pre_hash in zip(tx.inputs, dbb_signatures, inputhasharray):
                if txin.is_complete():
                    continue
                for public_key_bytes in txin.x_pubkeys:
                    compact_sig = bytes.fromhex(siginfo['sig'])
                    if 'recid' in siginfo:
                        # firmware > v2.1.1
                        recid = int(siginfo['recid'], 16)
                        recoverable_sig = compact_sig + bytes([recid])
                        public_key = PublicKey.from_recoverable_signature(recoverable_sig,
                            pre_hash, None)
                    elif 'pubkey' in siginfo:
                        # firmware <= v2.1.1
                        public_key = PublicKey.from_hex(siginfo['pubkey'])
                    else:
                        raise Exception("Bad sig info")
                    if public_key.to_bytes(compressed=True) == public_key_bytes:
                        full_sig = (compact_signature_to_der(compact_sig) +
                                    bytes([Transaction.nHashType() & 255]))
                        txin.signatures[public_key_bytes] = full_sig
        except UserCancelled:
            raise
        except Exception as e:
            self.give_error(str(e), True)
        else:
            logger.debug("Transaction is_complete %s", tx.is_complete())


class DigitalBitboxPlugin(HW_PluginBase):

    libraries_available = DIGIBOX
    keystore_class = DigitalBitbox_KeyStore
    client = None
    DEVICE_IDS: List[Tuple[int, int]] = [
        (0x03eb, 0x2402) # Digital Bitbox
    ]

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.logger = logger

        self.digitalbitbox_config = cast(Dict[str, Any], app_state.config.get('digitalbitbox', {}))

    def enumerate_devices(self) -> List[Device]:
        if self.libraries_available:
            return app_state.device_manager.find_hid_devices(self.DEVICE_IDS)
        return []

    def get_dbb_device(self, device: Device) -> hid.device:
        dev = hid.device()
        dev.open_path(device.path)
        return dev

    def create_client(self, device: Device, handler: "QtHandlerBase") \
            -> Optional[DigitalBitbox_Client]:
        if device.interface_number == 0 or device.usage_page == 0xffff:
            self.handler = cast("DigitalBitbox_Handler", handler)
            dbb_device = self.get_dbb_device(device)
            client: Optional[DigitalBitbox_Client] = None
            if dbb_device is not None:
                client = DigitalBitbox_Client(self, dbb_device)
            return client
        else:
            return None

    def setup_device(self, device_info: DeviceInfo, wizard: 'AccountWizard') -> None:
        device_id = device_info.device.id_
        client = cast(DigitalBitbox_Client, app_state.device_manager.client_by_id(device_id))
        if client is None:
            raise Exception(_('Failed to create a client for this device.') + '\n' +
                            _('Make sure it is in the correct state.'))
        client.handler = cast("DigitalBitbox_Handler", self.create_handler(wizard))
        client.setupRunning = True
        client.get_master_public_key("m/44'/0'")

    def is_mobile_paired(self) -> bool:
        return 'encryptionprivkey' in self.digitalbitbox_config

    def comserver_post_notification(self, payload: Dict[str, Any]) -> None:
        assert self.is_mobile_paired(), "unexpected mobile pairing error"
        url = 'https://digitalbitbox.com/smartverification/index.php'
        key_s = base64.b64decode(self.digitalbitbox_config['encryptionprivkey'])
        args = 'c=data&s=0&dt=0&uuid=%s&pl=%s' % (
            self.digitalbitbox_config['comserverchannelid'],
            EncodeAES_base64(key_s, json.dumps(payload).encode('ascii')).decode('ascii'),
        )
        try:
            requests.post(url, args)
        except Exception as e:
            self.handler.show_error(str(e))

    def get_master_public_key(self, device_id: str, derivation: str, wizard: "AccountWizard") \
            -> BIP32PublicKey:
        client = cast(DigitalBitbox_Client, app_state.device_manager.client_by_id(device_id))
        assert client is not None
        client.handler = cast("DigitalBitbox_Handler", self.create_handler(wizard))
        client.check_device_dialog()
        return client.get_master_public_key(derivation)

    def get_client(self, keystore: DigitalBitbox_KeyStore, force_pair: bool=True) \
            -> Optional[DigitalBitbox_Client]:
        client = cast(Optional[DigitalBitbox_Client],
            app_state.device_manager.client_for_keystore(self, keystore, force_pair))
        if client is not None:
            client.check_device_dialog()
        return client


SVBaseClient.register(DigitalBitbox_Client)
