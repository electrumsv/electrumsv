# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
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

import hashlib
import json
from typing import Any, cast, Dict, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING, Union

from bitcoinx import (
    PrivateKey, PublicKey, BIP32PrivateKey,
    int_to_be_bytes, be_bytes_to_int, CURVE_ORDER,
    bip32_key_from_string, bip32_decompose_chain_string, Base58Error, hash160,
    bip32_build_chain_string, BIP39Mnemonic, ElectrumMnemonic
)

from .i18n import _
from .app_state import app_state
from .constants import DerivationType, DerivationPath, KeystoreTextType, KeystoreType
from .crypto import sha256d, pw_encode, pw_decode
from .exceptions import InvalidPassword, OverloadedMultisigKeystore, IncompatibleWalletError
from .logs import logs
from .networks import Net
from .transaction import Transaction, TransactionContext, XPublicKey, XPublicKeyKind
from .types import MasterKeyDataBIP32, MasterKeyDataElectrumOld, MasterKeyDataHardware, \
    MasterKeyDataMultiSignature, MasterKeyDataTypes, DatabaseKeyDerivationData
from .wallet_database.types import KeyInstanceRow, MasterKeyRow


if TYPE_CHECKING:
    from .devices.hw_wallet.plugin import HW_PluginBase
    from .devices.hw_wallet.qt import QtHandlerBase, QtPluginBase


logger = logs.get_logger("keystore")

class KeyStore:
    derivation_type = DerivationType.NONE
    label: Optional[str] = None

    def __init__(self, row: Optional[MasterKeyRow]=None) -> None:
        self.set_row(row)

    def clean_up(self) -> None:
        pass

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        self._row = row

    def type(self) -> KeystoreType:
        return KeystoreType.UNSPECIFIED

    def subtype(self) -> Optional[str]:
        return None

    def get_label(self) -> Optional[str]:
        return self.label

    def set_label(self, label: Optional[str]) -> None:
        self.label = label

    def debug_name(self) -> str:
        name = self.type().value
        sub_type = self.subtype() # pylint: disable=assignment-from-none
        if sub_type is not None:
            name += "/"+ sub_type
        return name

    def get_id(self) -> int:
        """
        Get the database id for the masterkey record for this keystore.

        Will raise an AssertionError for imported keystores, as they do not have masterkeys.
        """
        assert self._row is not None
        return self._row.masterkey_id

    def get_fingerprint(self) -> bytes:
        raise NotImplementedError

    def has_masterkey(self) -> bool:
        return self._row is not None

    def has_seed(self) -> bool:
        return False

    def is_deterministic(self) -> bool:
        return False

    def can_change_password(self) -> bool:
        raise NotImplementedError

    def to_derivation_data(self) -> MasterKeyDataTypes:
        raise NotImplementedError

    def to_masterkey_row(self) -> MasterKeyRow:
        """
        The initial database row (with placeholder id) for this new keystore.
        """
        raise NotImplementedError

    def is_watching_only(self) -> bool:
        return False

    def can_import(self) -> bool:
        return False

    def can_export(self) -> bool:
        return False

    def get_master_public_key(self) -> Optional[str]:
        raise NotImplementedError

    def get_private_key(self, key_data: Any, password: str) -> Tuple[bytes, bool]:
        raise NotImplementedError

    def get_private_key_from_xpubkey(self, x_pubkey: XPublicKey,
            password: str) -> Tuple[bytes, bool]:
        raise NotImplementedError

    def is_signature_candidate(self, x_pubkey: XPublicKey) -> bool:
        raise NotImplementedError

    def can_sign(self, tx: Transaction) -> bool:
        if self.is_watching_only():
            return False
        return any(self.is_signature_candidate(x_pubkey) for txin in tx.inputs
            for x_pubkey in txin.unused_x_pubkeys())

    def requires_input_transactions(self) -> bool:
        return False

    def sign_transaction(self, tx: Transaction, password: str,
            context: TransactionContext) -> None:
        raise NotImplementedError


class Software_KeyStore(KeyStore):
    def __init__(self, row: Optional[MasterKeyRow]=None) -> None:
        KeyStore.__init__(self, row)

    def type(self) -> KeystoreType:
        return KeystoreType.SOFTWARE

    def sign_message(self, derivation_path: DerivationPath, message: bytes, password: str) -> bytes:
        privkey, compressed = self.get_private_key(derivation_path, password)
        key = PrivateKey(privkey, compressed)
        return cast(bytes, key.sign_message(message))

    def decrypt_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        privkey, compressed = self.get_private_key(sequence, password)
        key = PrivateKey(privkey)
        return cast(bytes, key.decrypt_message(message))

    def check_password(self, password: Optional[str]) -> None:
        raise NotImplementedError

    def sign_transaction(self, tx: Transaction, password: str,
            context: TransactionContext) -> None:
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs: Dict[XPublicKey, Tuple[bytes, bool]] = {}
        for txin in tx.inputs:
            for x_pubkey in txin.unused_x_pubkeys():
                if self.is_signature_candidate(x_pubkey):
                    keypairs[x_pubkey] = self.get_private_key_from_xpubkey(x_pubkey, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)


class Imported_KeyStore(Software_KeyStore):
    derivation_type = DerivationType.IMPORTED

    # keystore for imported private keys
    # private keys are encrypted versions of the WIF encoding

    def __init__(self, row: Optional[MasterKeyRow]=None) -> None:
        self._public_keys: Dict[int, PublicKey] = {}
        self._keypairs: Dict[PublicKey, str] = {}

        Software_KeyStore.__init__(self, row)

    def type(self) -> KeystoreType:
        return KeystoreType.IMPORTED_PRIVATE_KEY

    def set_state(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        self._keypairs.clear()
        self._public_keys.clear()

        for row in keyinstance_rows:
            data = json.loads(row.derivation_data)
            public_key = PublicKey.from_hex(data['pub'])
            self._public_keys[row.keyinstance_id] = public_key
            self._keypairs[public_key] = cast(str, data['prv'])

    def set_encrypted_prv(self, keyinstance_id: int, encrypted_prv: str) -> None:
        """
        Update a re-encrypted private key.

        This will occur when the wallet password has been changed
        """
        public_key = self._public_keys[keyinstance_id]
        self._keypairs[public_key] = encrypted_prv

    def can_change_password(self) -> bool:
        return True

    def get_master_public_key(self) -> Optional[str]:
        return None

    def to_derivation_data(self) -> MasterKeyDataTypes:
        raise IncompatibleWalletError("imported keystores do not map to a masterkey")

    def to_masterkey_row(self) -> MasterKeyRow:
        raise IncompatibleWalletError("imported keystores do not map to a masterkey")

    def can_import(self) -> bool:
        return True

    def sign_message(self, public_key: PublicKey, message: bytes, password: str) -> bytes:
        private_key_bytes, is_compressed = self.get_private_key(public_key, password)
        private_key = PrivateKey(private_key_bytes, is_compressed)
        return cast(bytes, private_key.sign_message(message))

    def decrypt_message(self, public_key: PublicKey, message: bytes, password: str) -> bytes:
        private_key_bytes, is_compressed = self.get_private_key(public_key, password)
        private_key = PrivateKey(private_key_bytes, is_compressed)
        return cast(bytes, private_key.decrypt_message(message))

    def remove_key(self, keyinstance_id: int) -> None:
        pubkey = self._public_keys.pop(keyinstance_id)
        self._keypairs.pop(pubkey)

    def check_password(self, password: Optional[str]) -> None:
        assert password is not None
        pubkey = list(self._keypairs.keys())[0]
        self.export_private_key(pubkey, password)

    def import_private_key(self, keyinstance_id: int, public_key: PublicKey,
            enc_prvkey: str) -> None:
        self._public_keys[keyinstance_id] = public_key
        self._keypairs[public_key] = enc_prvkey

    def export_private_key(self, pubkey: PublicKey, password: str) -> str:
        '''Returns a WIF string'''
        privkey_text = pw_decode(self._keypairs[pubkey], password)
        # this checks the password
        if pubkey != _public_key_from_private_key_text(privkey_text):
            raise InvalidPassword()
        return privkey_text

    def can_export(self) -> bool:
        return True

    def get_private_key(self, public_key: PublicKey, password: str) -> Tuple[bytes, bool]:
        '''Returns a (32 byte privkey, is_compressed) pair.'''
        private_key_text = self.export_private_key(public_key, password)
        private_key = PrivateKey.from_text(private_key_text)
        return private_key.to_bytes(), private_key.is_compressed()

    def get_private_key_from_xpubkey(self, x_public_key: XPublicKey,
            password: str) -> Tuple[bytes, bool]:
        public_key = x_public_key.to_public_key()
        return self.get_private_key(public_key, password)

    def is_signature_candidate(self, x_public_key: XPublicKey) -> bool:
        if x_public_key.kind() == XPublicKeyKind.PRIVATE_KEY:
            return x_public_key.to_public_key() in self._keypairs
        return False



class Deterministic_KeyStore(Software_KeyStore):
    seed: Optional[str] = None
    passphrase: Optional[str] = None
    label: Optional[str] = None

    def __init__(self, row: Optional[MasterKeyRow]=None) -> None:
        Software_KeyStore.__init__(self, row)

    def is_deterministic(self) -> bool:
        return True

    def has_seed(self) -> bool:
        return self.seed is not None

    def is_watching_only(self) -> bool:
        return not self.has_seed()

    def can_change_password(self) -> bool:
        return not self.is_watching_only()

    def get_seed(self, password: str) -> str:
        """
        Get the source private key data for this keystore.

        This may be the seed words where applicable, or whatever else the user originally entered.
        """
        assert isinstance(self.seed, str)
        return pw_decode(self.seed, password)

    def get_passphrase(self, password: str) -> str:
        if self.passphrase:
            return pw_decode(self.passphrase, password)
        return ''



class Xpub:
    def __init__(self) -> None:
        self.xpub: Optional[str] = None
        self._child_xpubs: Dict[DerivationPath, str] = {}

    def get_master_public_key(self) -> Optional[str]:
        return self.xpub

    def get_fingerprint(self) -> bytes:
        return cast(bytes, bip32_key_from_string(self.xpub).fingerprint())

    def derive_pubkey(self, derivation_path: DerivationPath) -> PublicKey:
        parent_path = derivation_path[:-1]
        xpub = self._child_xpubs.get(parent_path)
        if xpub is None:
            xpubkey = bip32_key_from_string(self.xpub)
            for n in parent_path:
                xpubkey = xpubkey.child_safe(n)
            xpub = xpubkey.to_extended_key_string()
            self._child_xpubs[parent_path] = xpub
        return self.get_pubkey_from_xpub(xpub, derivation_path[-1:])

    @classmethod
    def get_pubkey_from_xpub(cls, xpub: str, sequence: DerivationPath) -> PublicKey:
        pubkey = bip32_key_from_string(xpub)
        assert isinstance(pubkey, PublicKey)
        for n in sequence:
            pubkey = pubkey.child_safe(n)
        return pubkey

    def get_xpubkey(self, data: DatabaseKeyDerivationData) -> XPublicKey:
        return XPublicKey(bip32_xpub=self.xpub, derivation_data=data)

    def is_signature_candidate(self, x_pubkey: XPublicKey) -> bool:
        if x_pubkey.kind() == XPublicKeyKind.BIP32:
            return self.xpub == x_pubkey.bip32_extended_key()
        return False


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):
    derivation_type = DerivationType.BIP32

    def __init__(self, data: MasterKeyDataBIP32, row: Optional[MasterKeyRow]=None,
            parent_keystore: Optional[KeyStore]=None) -> None:
        Xpub.__init__(self)
        Deterministic_KeyStore.__init__(self, row)
        self._parent_keystore = parent_keystore

        self.seed: Optional[str] = data.get('seed')
        self.passphrase: Optional[str] = data.get('passphrase')
        self.label: Optional[str] = data.get('label')
        self.xpub: Optional[str] = data.get('xpub')
        self.xprv: Optional[str] = data.get('xprv')

    def type(self) -> KeystoreType:
        return KeystoreType.BIP32

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        Deterministic_KeyStore.set_row(self, row)

    def get_fingerprint(self) -> bytes:
        return Xpub.get_fingerprint(self)

    def to_derivation_data(self) -> MasterKeyDataBIP32:
        assert self.xpub is not None
        return {
            "seed": self.seed,
            "passphrase": self.passphrase,
            "label": self.label,
            "xpub": self.xpub,
            "xprv": self.xprv,
        }

    def to_masterkey_row(self) -> MasterKeyRow:
        derivation_data = json.dumps(self.to_derivation_data()).encode()
        return MasterKeyRow(-1, None, DerivationType.BIP32, derivation_data)

    def get_master_public_key(self) -> Optional[str]:
        return Xpub.get_master_public_key(self)

    def get_master_private_key(self, password: Optional[str]) -> str:
        assert self.xprv is not None
        return pw_decode(self.xprv, password)

    def check_password(self, password: Optional[str]) -> None:
        """
        Check if the password is valid for one of the pieces of encrypted data.

        It is assumed that all the encrypted data
        """
        assert self.xprv is not None
        xprv = pw_decode(self.xprv, password)
        try:
            assert (bip32_key_from_string(xprv).derivation().chain_code
                    == bip32_key_from_string(self.xpub).derivation().chain_code)
        except (ValueError, AssertionError, Base58Error):
            raise InvalidPassword()

    def is_watching_only(self) -> bool:
        return self.xprv is None

    def can_export(self) -> bool:
        return True

    def get_private_key(self, derivation_path: DerivationPath, password: str) -> Tuple[bytes, bool]:
        xprv = self.get_master_private_key(password)
        privkey = bip32_key_from_string(xprv)
        for n in derivation_path:
            privkey = privkey.child_safe(n)
        return privkey.to_bytes(), True

    def get_private_key_from_xpubkey(self, x_pubkey: XPublicKey,
            password: str) -> Tuple[bytes, bool]:
        return self.get_private_key(x_pubkey.derivation_path, password)

    # If we do not do this it falls through to the the base KeyStore method, not Xpub.
    def is_signature_candidate(self, x_pubkey: XPublicKey) -> bool:
        return Xpub.is_signature_candidate(self, x_pubkey)

    def set_encrypted_seed(self, encrypted_seed: str) -> None:
        assert self.seed is not None
        self.seed = encrypted_seed

    def set_encrypted_passphrase(self, encrypted_passphrase: str) -> None:
        assert self.passphrase is not None
        self.passphrase = encrypted_passphrase

    def set_encrypted_xprv(self, encrypted_xprv: str) -> None:
        assert self.xprv is not None
        self.xprv = encrypted_xprv


class Old_KeyStore(Deterministic_KeyStore):
    derivation_type = DerivationType.ELECTRUM_OLD

    def __init__(self, data: MasterKeyDataElectrumOld, row: Optional[MasterKeyRow]=None) -> None:
        super().__init__(row)

        self.seed = data['seed']
        self.mpk = data['mpk']

    def type(self) -> KeystoreType:
        return KeystoreType.OLD

    def _get_hex_seed_bytes(self, password: Optional[str]) -> bytes:
        assert self.seed is not None
        return pw_decode(self.seed, password).encode('utf8')

    @classmethod
    def _mpk_from_hex_seed(cls, hex_seed: str) -> str:
        secexp = cls.stretch_key(hex_seed.encode())
        master_private_key = PrivateKey(int_to_be_bytes(secexp, 32))
        return cast(str, master_private_key.public_key.to_hex(compressed=False)[2:])

    @classmethod
    def _mpk_to_PublicKey(cls, mpk: str) -> PublicKey:
        return PublicKey.from_hex('04' + mpk)

    @classmethod
    def from_mpk(cls, mpk: str) -> 'Old_KeyStore':
        return cls({ "mpk": mpk, "seed": None })

    def to_derivation_data(self) -> MasterKeyDataElectrumOld:
        return {
            "seed": self.seed,
            "mpk": self.mpk,
        }

    def to_masterkey_row(self) -> MasterKeyRow:
        derivation_lump = json.dumps(self.to_derivation_data()).encode()
        return MasterKeyRow(-1, None, DerivationType.ELECTRUM_OLD, derivation_lump)

    def get_seed(self, password: Optional[str]) -> str:
        """
        Get the old Electrum type mnemonic words for this keystore's master key.

        Raises ValueError if the hex seed is not either of 16 or 32 bytes.
        """
        s = self._get_hex_seed_bytes(password)
        return cast(str, ElectrumMnemonic.hex_seed_to_old(s))

    @classmethod
    def stretch_key(cls, seed: bytes) -> int:
        x = seed
        for i in range(100000):
            x = hashlib.sha256(x + seed).digest()
        return cast(int, be_bytes_to_int(x))

    @classmethod
    def get_sequence(cls, mpk: str, derivation_path: DerivationPath) -> int:
        old_sequence = derivation_path[1], derivation_path[0]
        return cast(int, be_bytes_to_int(sha256d(("%d:%d:"% old_sequence).encode('ascii') +
            bytes.fromhex(mpk))))

    @classmethod
    def get_pubkey_from_mpk(cls, mpk: str, derivation_path: DerivationPath) -> PublicKey:
        assert len(derivation_path) == 2
        z = cls.get_sequence(mpk, derivation_path)
        master_public_key = cls._mpk_to_PublicKey(mpk)
        public_key = master_public_key.add(int_to_be_bytes(z, 32))
        assert not public_key.is_compressed()
        return public_key

    def derive_pubkey(self, derivation_path: DerivationPath) -> PublicKey:
        assert len(derivation_path) == 2
        return self.get_pubkey_from_mpk(self.mpk, derivation_path)

    def get_private_key_from_stretched_exponent(self, derivation_path: DerivationPath,
            secexp: int) -> bytes:
        assert len(derivation_path) == 2
        secexp = (secexp + self.get_sequence(self.mpk, derivation_path)) % CURVE_ORDER
        return cast(bytes, int_to_be_bytes(secexp, 32))

    def can_export(self) -> bool:
        return True

    def get_private_key(self, derivation_path: DerivationPath, password: str) -> Tuple[bytes, bool]:
        seed = self._get_hex_seed_bytes(password)
        self.check_seed(seed)
        secexp = self.stretch_key(seed)
        pk = self.get_private_key_from_stretched_exponent(derivation_path, secexp)
        return pk, False

    def get_private_key_from_xpubkey(self, x_pubkey: XPublicKey,
            password: str) -> Tuple[bytes, bool]:
        mpk, path = x_pubkey.old_keystore_mpk_and_path()
        assert self.mpk == mpk.hex()
        return self.get_private_key(path, password)

    def check_seed(self, seed: bytes) -> None:
        secexp = self.stretch_key(seed)
        master_private_key = PrivateKey(int_to_be_bytes(secexp, 32))
        master_public_key = master_private_key.public_key.to_bytes(compressed=False)[1:]
        if master_public_key != bytes.fromhex(self.mpk):
            logger.error('invalid password (mpk) %s %s', self.mpk, master_public_key.hex())
            raise InvalidPassword()

    def check_password(self, password: Optional[str]) -> None:
        assert password is not None
        seed = self._get_hex_seed_bytes(password)
        self.check_seed(seed)

    def get_fingerprint(self) -> bytes:
        return cast(bytes, hash160(bytes.fromhex(self.mpk))[:4])

    def get_master_public_key(self) -> Optional[str]:
        return self.mpk

    def get_xpubkey(self, data: DatabaseKeyDerivationData) -> XPublicKey:
        assert data.derivation_path is not None and len(data.derivation_path) == 2
        return XPublicKey(old_mpk=bytes.fromhex(self.mpk), derivation_data=data)

    def is_signature_candidate(self, x_pubkey: XPublicKey) -> bool:
        """
        Check whether this keystore can sign for the given extended public key.
        """
        if x_pubkey.kind() == XPublicKeyKind.OLD:
            mpk, path = x_pubkey.old_keystore_mpk_and_path()
            return self.mpk == mpk.hex()
        return False

    def set_encrypted_seed(self, encrypted_seed: str) -> None:
        assert self.seed is not None
        self.seed = encrypted_seed


class Hardware_KeyStore(Xpub, KeyStore):
    derivation_type = DerivationType.HARDWARE

    # Derived classes must set:
    #   - device
    #   - wallet_type
    hw_type: str
    device: str
    plugin: Optional["HW_PluginBase"] = None
    handler_qt: Optional["QtHandlerBase"] = None

    def __init__(self, data: MasterKeyDataHardware, row: Optional[MasterKeyRow]=None) -> None:
        Xpub.__init__(self)
        KeyStore.__init__(self, row)

        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.xpub = data['xpub']
        self.derivation = data['derivation']
        # TODO(database-migration) Move this into a migration.
        # New hardware account bug stored the derivation as a decomposed list not a string.
        if isinstance(self.derivation, list):
            self.derivation = bip32_build_chain_string(self.derivation)
        self.hw_type = data['hw_type']
        self.label = data.get('label')

    def clean_up(self) -> None:
        assert self.xpub is not None
        app_state.device_manager.unpair_xpub(self.xpub)
        if self.handler_qt is not None:
            self.handler_qt.clean_up()

    def type(self) -> KeystoreType:
        return KeystoreType.HARDWARE

    def subtype(self) -> Optional[str]:
        return self.hw_type

    @property
    def plugin_qt(self) -> "QtPluginBase":
        assert self.plugin is not None
        return cast("QtPluginBase", self.plugin)

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        KeyStore.set_row(self, row)

    def is_deterministic(self) -> bool:
        return True

    def to_derivation_data(self) -> MasterKeyDataHardware:
        assert self.xpub is not None
        return {
            'hw_type': self.hw_type,
            'xpub': self.xpub,
            'derivation':self.derivation,
            'label':self.label,
            "cfg": None,
        }

    def to_masterkey_row(self) -> MasterKeyRow:
        derivation_lump = json.dumps(self.to_derivation_data()).encode()
        return MasterKeyRow(-1, None, DerivationType.HARDWARE, derivation_lump)

    def unpaired(self) -> None:
        '''A device paired with the wallet was diconnected.  This can be
        called in any thread context.'''
        logger.debug("unpaired")

    def paired(self) -> None:
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        logger.debug("paired")

    def is_watching_only(self) -> bool:
        '''The wallet is not watching-only; the user will be prompted for
        pin and passphrase as appropriate when needed.'''
        assert not self.has_seed()
        return False

    def can_change_password(self) -> bool:
        return False

    def can_export(self) -> bool:
        return False

    def sign_message(self, derivation_path: DerivationPath, message: bytes, password: str) -> bytes:
        raise NotImplementedError

    def decrypt_message(self, sequence: DerivationPath, message: bytes, password: str) -> bytes:
        raise NotImplementedError


SinglesigKeyStoreTypes = Union[BIP32_KeyStore, Hardware_KeyStore, Old_KeyStore]

class Multisig_KeyStore(KeyStore):
    # This isn't used, it's mostly included for consistency. Generally this attribute is used
    # only by this class, to classify derivation data of cosigner information.
    derivation_type = DerivationType.ELECTRUM_MULTISIG
    _cosigner_keystores: List[SinglesigKeyStoreTypes]

    def __init__(self, data: MasterKeyDataMultiSignature, row: Optional[MasterKeyRow]=None) -> None:
        self.set_row(row)

        self.m = data["m"]
        self.n = data["n"]

        self._cosigner_keystores = []
        for derivation_type, derivation_data in data["cosigner-keys"]:
            assert derivation_type in (DerivationType.BIP32, DerivationType.HARDWARE,
                DerivationType.ELECTRUM_OLD)
            keystore = instantiate_keystore(derivation_type, derivation_data)
            keystore = cast(SinglesigKeyStoreTypes, keystore)
            self.add_cosigner_keystore(keystore)

    def type(self) -> KeystoreType:
        return KeystoreType.MULTISIG

    def is_deterministic(self) -> bool:
        return True

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        self._row = row

    def to_derivation_data(self) -> MasterKeyDataMultiSignature:
        cosigner_keys = [
            (k.derivation_type, k.to_derivation_data())
            for k in self._cosigner_keystores
        ]
        return {
            'm': self.m,
            'n': self.n,
            'cosigner-keys': cosigner_keys,
        }

    def to_masterkey_row(self) -> MasterKeyRow:
        derivation_lump = json.dumps(self.to_derivation_data()).encode()
        return MasterKeyRow(-1, None, DerivationType.ELECTRUM_MULTISIG, derivation_lump)

    def is_watching_only(self) -> bool:
        return all(k.is_watching_only() for k in self.get_cosigner_keystores())

    def can_change_password(self) -> bool:
        return all(k.is_watching_only() for k in self.get_cosigner_keystores())

    def check_password(self, password: Optional[str]) -> None:
        if self.is_watching_only():
            return
        for keystore in self.get_cosigner_keystores():
            if keystore.can_change_password():
                assert not isinstance(keystore, Hardware_KeyStore)
                keystore.check_password(password)

    def get_cosigner_keystores(self) -> Sequence[SinglesigKeyStoreTypes]:
        return self._cosigner_keystores

    def add_cosigner_keystore(self, keystore: SinglesigKeyStoreTypes) -> None:
        if len(self._cosigner_keystores) == self.n:
            raise OverloadedMultisigKeystore()
        self._cosigner_keystores.append(keystore)


def bip44_derivation(account_id: int) -> str:
    return "m/44'/%d'/%d'" % (Net.BIP44_COIN_TYPE, int(account_id))


def bip44_derivation_cointype(cointype: int, account_id: int) -> str:
    return f"m/44'/{cointype:d}'/{account_id:d}'"


def private_key_from_bip32_seed(bip32_seed: bytes, derivation_text: str) -> BIP32PrivateKey:
    private_key = BIP32PrivateKey.from_seed(bip32_seed, Net.COIN)
    for n in bip32_decompose_chain_string(derivation_text):
        private_key = private_key.child_safe(n)
    return private_key


def bip32_master_key_data_from_seed(seed_phrase: str, passphrase: str, bip32_seed: bytes,
        derivation_text: str, password: Optional[str]) -> MasterKeyDataBIP32:
    private_key = private_key_from_bip32_seed(bip32_seed, derivation_text)
    optional_encrypted_seed = None
    optional_encrypted_passphrase = None
    optional_encrypted_xprv = None
    # If the key is not watch only, we store it but always encrypted.
    if password is not None:
        optional_encrypted_seed = pw_encode(seed_phrase, password)
        if len(passphrase):
            optional_encrypted_passphrase = pw_encode(passphrase, password)
        optional_encrypted_xprv = pw_encode(private_key.to_extended_key_string(), password)
    return {
        "seed": optional_encrypted_seed,
        "passphrase": optional_encrypted_passphrase,
        "label": None,
        "xprv": optional_encrypted_xprv,
        "xpub": private_key.public_key.to_extended_key_string(),
    }


def _public_key_from_private_key_text(text: str) -> PublicKey:
    return PrivateKey.from_text(text).public_key


def instantiate_keystore(derivation_type: DerivationType, data: MasterKeyDataTypes,
        parent_keystore: Optional[KeyStore]=None,
        row: Optional[MasterKeyRow]=None) -> KeyStore:
    keystore: KeyStore
    if derivation_type == DerivationType.BIP32:
        keystore = BIP32_KeyStore(cast(MasterKeyDataBIP32, data),
            row, parent_keystore)
    elif derivation_type == DerivationType.HARDWARE:
        assert parent_keystore is None
        keystore = app_state.device_manager.create_keystore(cast(MasterKeyDataHardware, data), row)
    elif derivation_type == DerivationType.ELECTRUM_MULTISIG:
        assert parent_keystore is None
        keystore = Multisig_KeyStore(cast(MasterKeyDataMultiSignature, data), row)
    elif derivation_type == DerivationType.ELECTRUM_OLD:
        assert parent_keystore is None
        keystore = Old_KeyStore(cast(MasterKeyDataElectrumOld, data), row)
    else:
        raise Exception(_("unknown masterkey type {}:{}").format(
            row.masterkey_id if row is not None else None, derivation_type))
    return keystore

KeystoreMatchType = Union[str, Set[str]]

def instantiate_keystore_from_text(text_type: KeystoreTextType, text_match: KeystoreMatchType,
        password: Optional[str]=None, derivation_text: Optional[str]=None,
        passphrase: str="", watch_only: bool=False) -> KeyStore:
    assert isinstance(passphrase, str)
    bip32_data: MasterKeyDataBIP32
    if text_type == KeystoreTextType.EXTENDED_PUBLIC_KEY:
        derivation_type = DerivationType.BIP32
        assert isinstance(text_match, str)
        assert not derivation_text
        assert watch_only
        assert not passphrase
        # `watch_only` is ignored.
        bip32_data = {
            "xpub": text_match,
            "seed": None,
            "passphrase": None,
            "label": None,
            "xprv": None,
        }
        return instantiate_keystore(derivation_type, bip32_data)
    elif text_type == KeystoreTextType.EXTENDED_PRIVATE_KEY:
        derivation_type = DerivationType.BIP32
        assert isinstance(text_match, str)
        assert not derivation_text
        assert not passphrase
        private_key = bip32_key_from_string(text_match)
        assert isinstance(private_key, PrivateKey)
        optional_encrypted_xprv = None
        if not watch_only:
            assert password is not None
            optional_encrypted_xprv = pw_encode(text_match, password)
        bip32_data = {
            "xpub": private_key.public_key.to_extended_key_string(),
            "seed": None,
            "passphrase": None,
            "label": None,
            "xprv": optional_encrypted_xprv,
        }
        return instantiate_keystore(derivation_type, bip32_data)
    elif text_type == KeystoreTextType.PRIVATE_KEYS:
        derivation_type = DerivationType.IMPORTED
        assert not derivation_text
        # watch_only?
    elif text_type == KeystoreTextType.ADDRESSES:
        derivation_type = DerivationType.IMPORTED
        assert not derivation_text
        # All address types have to be the same.
        pass
    elif text_type == KeystoreTextType.BIP39_SEED_WORDS:
        derivation_type = DerivationType.BIP32
        if derivation_text is None:
            derivation_text = bip44_derivation_cointype(0, 0)
        assert isinstance(text_match, str)
        bip32_seed = BIP39Mnemonic.to_seed(text_match, passphrase)
        data = bip32_master_key_data_from_seed(text_match, passphrase, bip32_seed, derivation_text,
            password)
        return instantiate_keystore(derivation_type, data)
    elif text_type == KeystoreTextType.ELECTRUM_SEED_WORDS:
        derivation_type = DerivationType.BIP32
        assert not derivation_text
        assert isinstance(text_match, str)
        assert password is not None
        derivation_text = "m"
        bip32_seed = ElectrumMnemonic.new_to_seed(text_match, passphrase, compatible=True)
        data = bip32_master_key_data_from_seed(text_match, passphrase, bip32_seed, derivation_text,
            password)
        return instantiate_keystore(derivation_type, data)
    elif text_type == KeystoreTextType.ELECTRUM_OLD_SEED_WORDS:
        derivation_type = DerivationType.ELECTRUM_OLD
        assert isinstance(text_match, str)
        assert not derivation_text
        assert not passphrase
        if ElectrumMnemonic.is_valid_old(text_match):
            assert password is not None
            try:
                bytes.fromhex(text_match)
            except ValueError:
                hex_seed = ElectrumMnemonic.old_to_hex_seed(text_match)
            else:
                hex_seed = text_match
            mpk = Old_KeyStore._mpk_from_hex_seed(hex_seed)
        else:
            watch_only = True
            hex_seed = None
            mpk = text_match
        optional_encrypted_seed = None
        if not watch_only:
            assert hex_seed is not None
            optional_encrypted_seed = pw_encode(hex_seed, password)
        old_data: MasterKeyDataElectrumOld = {
            "seed": optional_encrypted_seed,
            "mpk": mpk,
        }
        return instantiate_keystore(derivation_type, old_data)

    raise NotImplementedError("Unsupported text match type", text_type)


SignableKeystoreTypes = Union[Software_KeyStore, Hardware_KeyStore]
StandardKeystoreTypes = Union[Old_KeyStore, BIP32_KeyStore]
