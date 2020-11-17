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

from collections import defaultdict
import hashlib
import json
from typing import Any, cast, Dict, List, Optional, Sequence, Tuple, Union
from unicodedata import normalize

from bitcoinx import (
    PrivateKey, PublicKey, BIP32PrivateKey, BIP32PublicKey,
    int_to_be_bytes, be_bytes_to_int, CURVE_ORDER,
    bip32_key_from_string, bip32_decompose_chain_string, Base58Error, hash160
)

from .i18n import _
from .app_state import app_state
from .bitcoin import compose_chain_string, is_address_valid, is_seed, seed_type
from .constants import DerivationType, KeystoreTextType, KeystoreType
from .crypto import sha256d, pw_encode, pw_decode
from .exceptions import InvalidPassword, OverloadedMultisigKeystore, IncompatibleWalletError
from .logs import logs
from .mnemonic import Mnemonic, load_wordlist
from .networks import Net
from .transaction import Transaction, TransactionContext, XPublicKey, XPublicKeyType
from .wallet_database.tables import KeyInstanceRow, MasterKeyRow


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

    def update_password(self, new_password: str, old_password: Optional[str]=None) -> None:
        raise NotImplementedError

    def to_derivation_data(self) -> Dict[str, Any]:
        raise NotImplementedError

    def to_masterkey_row(self) -> MasterKeyRow:
        raise NotImplementedError

    def is_watching_only(self) -> bool:
        return False

    def can_import(self) -> bool:
        return False

    def can_export(self) -> bool:
        return False

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
            tx_context: TransactionContext) -> None:
        raise NotImplementedError


class Software_KeyStore(KeyStore):
    def __init__(self, row: Optional[MasterKeyRow]=None) -> None:
        KeyStore.__init__(self, row)

    def type(self) -> KeystoreType:
        return KeystoreType.SOFTWARE

    def sign_message(self, derivation_path: Sequence[int], message: bytes, password: str):
        privkey, compressed = self.get_private_key(derivation_path, password)
        key = PrivateKey(privkey, compressed)
        return key.sign_message(message)

    def decrypt_message(self, sequence, message, password: str):
        privkey, compressed = self.get_private_key(sequence, password)
        key = PrivateKey(privkey)
        return key.decrypt_message(message)

    def check_password(self, password: Optional[str]) -> None:
        raise NotImplementedError

    def sign_transaction(self, tx: Transaction, password: str,
            tx_context: TransactionContext) -> None:
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
    _keypairs: Dict[PublicKey, str]
    _public_keys: Dict[int, PublicKey]

    def __init__(self, row: Optional[MasterKeyRow]=None) -> None:
        self._keypairs = {}
        self._public_keys = {}

        Software_KeyStore.__init__(self, row)

    def type(self) -> KeystoreType:
        return KeystoreType.IMPORTED_PRIVATE_KEY

    def load_state(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        self._keypairs.clear()
        self._public_keys.clear()

        for row in keyinstance_rows:
            data = json.loads(row.derivation_data)
            # TODO(rt12): No way to set coin in the 'PublicKey.from_' call.
            public_key = PublicKey.from_hex(data['pub'])
            self._public_keys[row.keyinstance_id] = public_key
            self._keypairs[public_key] = cast(str, data['prv'])

    def get_keyinstance_derivation_data(self) -> List[Tuple[int, Dict[str, Any]]]:
        datas = []
        for key_id, pubkey in self._public_keys.items():
            datas.append((key_id, { "pub": pubkey.to_hex(), "prv": self._keypairs[pubkey] }))
        return datas

    def can_change_password(self) -> bool:
        return True

    def get_master_public_key(self) -> Optional[str]:
        return None

    def to_derivation_data(self) -> Dict[str, Any]:
        raise IncompatibleWalletError("imported keystores do not map to a masterkey")

    def to_masterkey_row(self) -> MasterKeyRow:
        raise IncompatibleWalletError("imported keystores do not map to a masterkey")

    def can_import(self) -> bool:
        return True

    def get_public_key_for_id(self, keyinstance_id: int) -> PublicKey:
        return self._public_keys[keyinstance_id]

    def get_keyinstance_id_for_public_key(self, pubkey: PublicKey) -> Optional[int]:
        for keyinstance_id, keypubkey in self._public_keys.items():
            if pubkey == keypubkey:
                return keyinstance_id
        return None

    def remove_key(self, keyinstance_id: int) -> None:
        pubkey = self._public_keys[keyinstance_id]
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

    def get_private_key(self, pubkey: PublicKey, password: str) -> Tuple[bytes, bool]:
        '''Returns a (32 byte privkey, is_compressed) pair.'''
        privkey_text = self.export_private_key(pubkey, password)
        privkey = PrivateKey.from_text(privkey_text)
        return privkey.to_bytes(), privkey.is_compressed()

    def get_private_key_from_xpubkey(self, x_pubkey: XPublicKey,
            password: str) -> Tuple[bytes, bool]:
        pubkey = x_pubkey.to_public_key()
        return self.get_private_key(pubkey, password)

    def is_signature_candidate(self, x_pubkey: XPublicKey) -> bool:
        if x_pubkey.kind() == XPublicKeyType.PRIVATE_KEY:
            return x_pubkey.to_public_key() in self._keypairs
        return False

    def update_password(self, new_password: str, old_password: Optional[str]=None) -> None:
        # Old keystores have never supported unpassworded private key data.
        assert old_password is not None
        self.check_password(old_password)
        assert new_password, "calling code must only do so with an actual new password"
        for k, v in self._keypairs.items():
            b = pw_decode(v, old_password)
            c = pw_encode(b, new_password)
            self._keypairs[k] = c



class Deterministic_KeyStore(Software_KeyStore):
    def __init__(self, data: Dict[str, Any], row: Optional[MasterKeyRow]=None) -> None:
        Software_KeyStore.__init__(self, row)

        self.seed = data.get('seed', None)
        self.passphrase = data.get('passphrase', None)
        self.label = data.get('label')

    def is_deterministic(self) -> bool:
        return True

    def to_derivation_data(self) -> Dict[str, Any]:
        d = {}
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
        if self.label:
            d['label'] = self.label
        return d

    def has_seed(self) -> bool:
        return bool(self.seed)

    def is_watching_only(self) -> bool:
        return not self.has_seed()

    def can_change_password(self) -> bool:
        return not self.is_watching_only()

    def add_seed(self, seed) -> None:
        if self.seed:
            raise Exception("a seed exists")
        self.seed = self.format_seed(seed)

    def get_seed(self, password):
        return pw_decode(self.seed, password)

    def get_passphrase(self, password):
        if self.passphrase:
            return pw_decode(self.passphrase, password)
        return ''

    def format_seed(self, seed: str) -> str:
        raise NotImplementedError


class DerivablePaths:
    def to_derivation_data(self) -> Dict[str, Any]:
        return {
            "subpaths": list(self._sequence_watermarks.items()),
        }

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        self._sequence_watermarks: Dict[Sequence[int], int] = {}

        if row is not None:
            sequence_watermarks: Dict[Sequence[int], int] = defaultdict(int)
            data = json.loads(row.derivation_data)
            for derivation_path, next_index in data["subpaths"]:
                sequence_watermarks[tuple(derivation_path)] = next_index
            self._sequence_watermarks.update(sequence_watermarks)

    def allocate_indexes(self, derivation_path: Sequence[int], count: int) -> int:
        next_index = self._sequence_watermarks.get(derivation_path, 0)
        self._sequence_watermarks[derivation_path] = next_index + count
        return next_index

    def get_next_index(self, derivation_path: Sequence[int]) -> int:
        return self._sequence_watermarks.get(derivation_path, 0)


class Xpub(DerivablePaths):
    def __init__(self) -> None:
        self.xpub: Optional[str] = None
        self._child_xpubs: Dict[Sequence[int], str] = {}

    def get_master_public_key(self) -> Optional[str]:
        return self.xpub

    def get_fingerprint(self) -> bytes:
        return bip32_key_from_string(self.xpub).fingerprint()

    def derive_pubkey(self, derivation_path: Sequence[int]) -> PublicKey:
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
    def get_pubkey_from_xpub(self, xpub: str, sequence: Sequence[int]) -> PublicKey:
        pubkey = bip32_key_from_string(xpub)
        for n in sequence:
            pubkey = pubkey.child_safe(n)
        return pubkey

    def get_xpubkey(self, derivation_path: Sequence[int]) -> XPublicKey:
        return XPublicKey(bip32_xpub=self.xpub, derivation_path=derivation_path)

    def is_signature_candidate(self, x_pubkey: XPublicKey) -> bool:
        if x_pubkey.kind() == XPublicKeyType.BIP32:
            return self.xpub == x_pubkey.bip32_extended_key()
        return False


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):
    derivation_type = DerivationType.BIP32

    def __init__(self, data: Dict[str, Any], row: Optional[MasterKeyRow]=None,
            parent_keystore: Optional[KeyStore]=None) -> None:
        Xpub.__init__(self)
        Deterministic_KeyStore.__init__(self, data, row)

        self._parent_keystore = parent_keystore
        self.xpub: Optional[str] = data.get('xpub')
        self.xprv: Optional[str] = data.get('xprv')

    def type(self) -> KeystoreType:
        return KeystoreType.BIP32

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        Xpub.set_row(self, row)
        Deterministic_KeyStore.set_row(self, row)

    def get_fingerprint(self) -> bytes:
        return Xpub.get_fingerprint(self)

    def format_seed(self, seed):
        return ' '.join(seed.split())

    def to_derivation_data(self) -> Dict[str, Any]:
        d = Deterministic_KeyStore.to_derivation_data(self)
        d.update(Xpub.to_derivation_data(self))
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        return d

    def to_masterkey_row(self) -> MasterKeyRow:
        derivation_data = json.dumps(self.to_derivation_data()).encode()
        return MasterKeyRow(-1, None, DerivationType.BIP32, derivation_data)

    def get_master_private_key(self, password: Optional[str]):
        assert self.xprv is not None
        return pw_decode(self.xprv, password)

    def check_password(self, password: Optional[str]) -> None:
        assert self.xprv is not None
        xprv = pw_decode(self.xprv, password)
        try:
            assert (bip32_key_from_string(xprv).derivation().chain_code
                    == bip32_key_from_string(self.xpub).derivation().chain_code)
        except (ValueError, AssertionError, Base58Error):
            raise InvalidPassword()

    def update_password(self, new_password: str, old_password: Optional[str]=None) -> None:
        self.check_password(old_password)
        assert new_password, "calling code must only do so with an actual new password"
        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode(decoded, new_password)
        if self.passphrase:
            decoded = self.get_passphrase(old_password)
            self.passphrase = pw_encode(decoded, new_password)
        if self.xprv is not None:
            b = pw_decode(self.xprv, old_password)
            self.xprv = pw_encode(b, new_password)

    def is_watching_only(self) -> bool:
        return self.xprv is None

    def add_xprv(self, xprv: BIP32PrivateKey) -> None:
        self.xprv = xprv.to_extended_key_string()
        self.xpub = xprv.public_key.to_extended_key_string()

    def add_xprv_from_seed(self, bip32_seed, derivation) -> None:
        xprv = BIP32PrivateKey.from_seed(bip32_seed, Net.COIN)
        for n in bip32_decompose_chain_string(derivation):
            xprv = xprv.child_safe(n)
        self.add_xprv(xprv)

    def can_export(self) -> bool:
        return True

    def get_private_key(self, derivation_path: Sequence[int], password: str) -> Tuple[bytes, bool]:
        xprv = self.get_master_private_key(password)
        privkey = bip32_key_from_string(xprv)
        for n in derivation_path:
            privkey = privkey.child_safe(n)
        return privkey.to_bytes(), True

    def get_private_key_from_xpubkey(self, x_pubkey: XPublicKey,
            password: str) -> Tuple[bytes, bool]:
        derivation_path = x_pubkey.derivation_path()
        return self.get_private_key(derivation_path, password)

    # If we do not do this it falls through to the the base KeyStore method, not Xpub.
    def is_signature_candidate(self, x_pubkey: XPublicKey) -> bool:
        return Xpub.is_signature_candidate(self, x_pubkey)


class Old_KeyStore(DerivablePaths, Deterministic_KeyStore):
    derivation_type = DerivationType.ELECTRUM_OLD

    def __init__(self, data: Dict[str, Any], row: Optional[MasterKeyRow]=None) -> None:
        super().__init__(data, row)

        self.mpk = data['mpk']

    def type(self) -> KeystoreType:
        return KeystoreType.OLD

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        DerivablePaths.set_row(self, row)
        Deterministic_KeyStore.set_row(self, row)

    def _get_hex_seed_bytes(self, password) -> bytes:
        return pw_decode(self.seed, password).encode('utf8')

    @classmethod
    def _seed_to_hex(cls, seed):
        from . import old_mnemonic, mnemonic
        seed = mnemonic.normalize_text(seed)
        # see if seed was entered as hex
        if seed:
            try:
                bytes.fromhex(seed)
                return seed
            except Exception:
                pass
        words = seed.split()
        seed = old_mnemonic.mn_decode(words)
        if not seed:
            raise Exception("Invalid seed")
        return seed

    @classmethod
    def _mpk_from_hex_seed(cls, hex_seed) -> str:
        secexp = cls.stretch_key(hex_seed.encode())
        master_private_key = PrivateKey(int_to_be_bytes(secexp, 32))
        return master_private_key.public_key.to_hex(compressed=False)[2:]

    @classmethod
    def _mpk_to_PublicKey(cls, mpk: str) -> PublicKey:
        return PublicKey.from_hex('04' + mpk)

    @classmethod
    def from_seed(cls, seed) -> 'Old_KeyStore':
        hex_seed = cls._seed_to_hex(seed)
        return cls({'seed': hex_seed, 'mpk': cls._mpk_from_hex_seed(hex_seed), 'subpaths': []})

    @classmethod
    def from_mpk(cls, mpk) -> 'Old_KeyStore':
        return cls({'mpk': mpk})

    @classmethod
    def is_hex_mpk(cls, text: str) -> bool:
        try:
            cls._mpk_to_PublicKey(text)
            return True
        except Exception:
            return False

    def to_derivation_data(self) -> Dict[str, Any]:
        d = Deterministic_KeyStore.to_derivation_data(self)
        d.update(DerivablePaths.to_derivation_data(self))
        d['mpk'] = self.mpk
        return d

    def to_masterkey_row(self) -> MasterKeyRow:
        derivation_lump = json.dumps(self.to_derivation_data()).encode()
        return MasterKeyRow(-1, None, DerivationType.ELECTRUM_OLD, derivation_lump)

    def get_seed(self, password: Optional[str]) -> str:
        from . import old_mnemonic
        s = self._get_hex_seed_bytes(password)
        return ' '.join(old_mnemonic.mn_encode(s))

    @classmethod
    def stretch_key(self, seed):
        x = seed
        for i in range(100000):
            x = hashlib.sha256(x + seed).digest()
        return be_bytes_to_int(x)

    @classmethod
    def get_sequence(cls, mpk: str, derivation_path: Sequence[int]) -> int:
        old_sequence = derivation_path[1], derivation_path[0]
        return be_bytes_to_int(sha256d(("%d:%d:"% old_sequence).encode('ascii') +
            bytes.fromhex(mpk)))

    @classmethod
    def get_pubkey_from_mpk(cls, mpk: str, derivation_path: Sequence[int]) -> PublicKey:
        assert len(derivation_path) == 2
        z = cls.get_sequence(mpk, derivation_path)
        master_public_key = cls._mpk_to_PublicKey(mpk)
        public_key = master_public_key.add(int_to_be_bytes(z, 32))
        assert not public_key.is_compressed()
        return public_key

    def derive_pubkey(self, derivation_path: Sequence[int]) -> PublicKey:
        assert len(derivation_path) == 2
        return self.get_pubkey_from_mpk(self.mpk, derivation_path)

    def get_private_key_from_stretched_exponent(self, derivation_path: Sequence[int],
            secexp) -> bytes:
        assert len(derivation_path) == 2
        secexp = (secexp + self.get_sequence(self.mpk, derivation_path)) % CURVE_ORDER
        return int_to_be_bytes(secexp, 32)

    def can_export(self) -> bool:
        return True

    def get_private_key(self, derivation_path: Sequence[int], password: str) -> Tuple[bytes, bool]:
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

    def check_seed(self, seed) -> None:
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
        return hash160(bytes.fromhex(self.mpk))[:4]

    def get_master_public_key(self) -> Optional[str]:
        return self.mpk

    def get_xpubkey(self, derivation_path: Sequence[int]) -> XPublicKey:
        assert len(derivation_path) == 2
        return XPublicKey(old_mpk=bytes.fromhex(self.mpk), derivation_path=derivation_path)

    def is_signature_candidate(self, x_pubkey: XPublicKey) -> bool:
        if x_pubkey.kind() == XPublicKeyType.OLD:
            mpk, path = x_pubkey.old_keystore_mpk_and_path()
            return self.mpk == mpk.hex()
        return False

    def update_password(self, new_password: str, old_password: Optional[str]=None) -> None:
        assert new_password, "calling code must only do so with an actual new password"
        if old_password:
            self.check_password(old_password)
        if self.has_seed():
            decoded = pw_decode(self.seed, old_password)
            self.seed = pw_encode(decoded, new_password)



class Hardware_KeyStore(Xpub, KeyStore):
    derivation_type = DerivationType.HARDWARE

    # Derived classes must set:
    #   - device
    #   - wallet_type
    hw_type: str
    device: str
    handler: Optional[Any]

    def __init__(self, data: Dict[str, Any], row: Optional[MasterKeyRow]=None) -> None:
        Xpub.__init__(self)
        KeyStore.__init__(self, row)

        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.xpub = data['xpub']
        self.derivation = data['derivation']
        # New hardware account bug stored the derivation as a decomposed list not a string.
        if isinstance(self.derivation, list):
            self.derivation = compose_chain_string(self.derivation)
        self.hw_type = data['hw_type']
        self.label = data.get('label')
        self.handler = None
        self.plugin = None

    def clean_up(self) -> None:
        app_state.device_manager.unpair_xpub(self.xpub)
        if self.handler is not None:
            self.handler.clean_up()

    def type(self) -> KeystoreType:
        return KeystoreType.HARDWARE

    def subtype(self) -> Optional[str]:
        return self.hw_type

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        Xpub.set_row(self, row)
        KeyStore.set_row(self, row)

    def is_deterministic(self) -> bool:
        return True

    def to_derivation_data(self) -> Dict[str, Any]:
        data = {
            'hw_type': self.hw_type,
            'xpub': self.xpub,
            'derivation':self.derivation,
            'label':self.label,
        }
        data.update(Xpub.to_derivation_data(self))
        return data

    def to_masterkey_row(self) -> MasterKeyRow:
        derivation_lump = json.dumps(self.to_derivation_data()).encode()
        return MasterKeyRow(-1, None, DerivationType.HARDWARE, derivation_lump)

    def unpaired(self):
        '''A device paired with the wallet was diconnected.  This can be
        called in any thread context.'''
        logger.debug("unpaired")

    def paired(self):
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

    def sign_message(self, derivation_path: Sequence[int], message: bytes, password: str):
        raise NotImplementedError

    def decrypt_message(self, sequence, message, password: str):
        raise NotImplementedError


MultisigChildKeyStoreTypes = Union[BIP32_KeyStore, Hardware_KeyStore, Old_KeyStore]

class Multisig_KeyStore(DerivablePaths, KeyStore):
    # This isn't used, it's mostly included for consistency. Generally this attribute is used
    # only by this class, to classify derivation data of cosigner information.
    derivation_type = DerivationType.ELECTRUM_MULTISIG
    _cosigner_keystores: List[MultisigChildKeyStoreTypes]

    def __init__(self, data: Dict[str, Any], row: Optional[MasterKeyRow]=None) -> None:
        self.set_row(row)

        self.m = data["m"]
        self.n = data["n"]

        self._cosigner_keystores = []
        cosigner_keys: List[Tuple[DerivationType, Dict[str, Any]]] = data["cosigner-keys"]
        for derivation_type, derivation_data in cosigner_keys:
            assert derivation_type in (DerivationType.BIP32, DerivationType.HARDWARE,
                DerivationType.ELECTRUM_OLD)
            keystore = instantiate_keystore(derivation_type, derivation_data)
            keystore = cast(MultisigChildKeyStoreTypes, keystore)
            self.add_cosigner_keystore(keystore)

    def type(self) -> KeystoreType:
        return KeystoreType.MULTISIG

    def is_deterministic(self) -> bool:
        return True

    def set_row(self, row: Optional[MasterKeyRow]=None) -> None:
        DerivablePaths.set_row(self, row)
        self._row = row

    def to_derivation_data(self) -> Dict[str, Any]:
        cosigner_keys = [ (k.derivation_type, k.to_derivation_data())
            for k in self._cosigner_keystores ]
        for cosigner_type, cosigner_data in cosigner_keys:
            del cosigner_data["subpaths"]

        data = {
            'm': self.m,
            'n': self.n,
            'cosigner-keys': cosigner_keys,
        }
        data.update(DerivablePaths.to_derivation_data(self))
        return data

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

    def update_password(self, new_password: str, old_password: Optional[str]=None) -> None:
        for keystore in self.get_cosigner_keystores():
            if keystore.can_change_password():
                keystore.update_password(new_password, old_password)

    def get_cosigner_keystores(self) -> Sequence[MultisigChildKeyStoreTypes]:
        return self._cosigner_keystores

    def add_cosigner_keystore(self, keystore: MultisigChildKeyStoreTypes) -> None:
        if len(self._cosigner_keystores) == self.n:
            raise OverloadedMultisigKeystore()
        self._cosigner_keystores.append(keystore)


def bip39_normalize_passphrase(passphrase):
    return normalize('NFKD', passphrase or '')

def bip39_to_seed(mnemonic, passphrase):
    PBKDF2_ROUNDS = 2048
    mnemonic = normalize('NFKD', ' '.join(mnemonic.split()))
    passphrase = bip39_normalize_passphrase(passphrase)
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'),
        b'mnemonic' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)

# returns tuple (is_checksum_valid, is_wordlist_valid)
def bip39_is_checksum_valid(mnemonic):
    words = [ normalize('NFKD', word) for word in mnemonic.split() ]
    words_len = len(words)
    wordlist = load_wordlist("english.txt")
    n = len(wordlist)
    checksum_length = 11*words_len//33
    entropy_length = 32*checksum_length
    i = 0
    words.reverse()
    while words:
        w = words.pop()
        try:
            k = wordlist.index(w)
        except ValueError:
            return False, False
        i = i*n + k
    if words_len not in [12, 15, 18, 21, 24]:
        return False, True
    entropy = i >> checksum_length
    checksum = i % 2**checksum_length
    h = '{:x}'.format(entropy)
    while len(h) < entropy_length/4:
        h = '0'+h
    b = bytearray.fromhex(h)
    hashed = int(hashlib.sha256(b).digest().hex(), 16)
    calculated_checksum = hashed >> (256 - checksum_length)
    return checksum == calculated_checksum, True

def from_bip39_seed(seed: str, passphrase: Optional[str], derivation_text: str) -> BIP32_KeyStore:
    k = BIP32_KeyStore({})
    bip32_seed = bip39_to_seed(seed, passphrase)
    k.add_xprv_from_seed(bip32_seed, derivation_text)
    return k


def is_address_list(text: str) -> bool:
    parts = text.split()
    return bool(parts) and all(is_address_valid(x) for x in parts)


def get_private_keys(text: str) -> List[str]:
    parts = text.split('\n')
    parts = [''.join(part.split()) for part in parts]
    parts = [part for part in parts if part]
    if parts and all(is_private_key(x) for x in parts):
        return parts
    return []

def is_private_key_list(text: str) -> bool:
    return bool(get_private_keys(text))


is_mpk = lambda x: Old_KeyStore.is_hex_mpk(x) or is_xpub(x)
is_private = lambda x: is_seed(x) or is_xprv(x) or is_private_key_list(x)
is_master_key = lambda x: Old_KeyStore.is_hex_mpk(x) or is_xprv(x) or is_xpub(x)
is_bip32_key = lambda x: is_xprv(x) or is_xpub(x)


def bip44_derivation(account_id: int) -> str:
    return "m/44'/%d'/%d'" % (Net.BIP44_COIN_TYPE, int(account_id))

def bip44_derivation_cointype(cointype: int, account_id: int) -> str:
    return f"m/44'/{cointype:d}'/{account_id:d}'"

def from_seed(seed, passphrase):
    t = seed_type(seed)
    if t == 'old':
        keystore = Old_KeyStore.from_seed(seed)
    elif t in ['standard']:
        keystore = BIP32_KeyStore({})
        keystore.add_seed(seed)
        keystore.passphrase = passphrase
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        der = "m"
        keystore.add_xprv_from_seed(bip32_seed, der)
    else:
        raise InvalidSeed()
    return keystore

class InvalidSeed(Exception):
    pass

def from_xpub(xpub) -> BIP32_KeyStore:
    k = BIP32_KeyStore({})
    k.xpub = xpub
    return k

def from_master_key(text: str) -> Union[BIP32_KeyStore, Old_KeyStore]:
    k: Union[BIP32_KeyStore, Old_KeyStore]
    if is_xprv(text):
        k = BIP32_KeyStore({})
        k.add_xprv(bip32_key_from_string(text))
    elif Old_KeyStore.is_hex_mpk(text):
        k = Old_KeyStore.from_mpk(text)
    elif is_xpub(text):
        k = from_xpub(text)
    else:
        raise Exception('Invalid key')
    return k


def is_xpub(text: str) -> bool:
    try:
        key = bip32_key_from_string(text)
        return isinstance(key, BIP32PublicKey)
    except Exception:
        return False


def is_xprv(text: str) -> bool:
    try:
        key = bip32_key_from_string(text)
        return isinstance(key, BIP32PrivateKey)
    except Exception:
        return False


def is_private_key(text: str) -> bool:
    try:
        PrivateKey.from_text(text)
        return True
    except ValueError:
        return False


def _public_key_from_private_key_text(text):
    return PrivateKey.from_text(text).public_key


def instantiate_keystore(derivation_type: DerivationType, data: Dict[str, Any],
        parent_keystore: Optional[KeyStore]=None,
        row: Optional[MasterKeyRow]=None) -> KeyStore:
    keystore: KeyStore
    if derivation_type == DerivationType.BIP32:
        keystore = BIP32_KeyStore(data, row, parent_keystore)
    elif derivation_type == DerivationType.HARDWARE:
        assert parent_keystore is None
        keystore = app_state.device_manager.create_keystore(data, row)
    elif derivation_type == DerivationType.ELECTRUM_MULTISIG:
        assert parent_keystore is None
        keystore = Multisig_KeyStore(data, row)
    elif derivation_type == DerivationType.ELECTRUM_OLD:
        assert parent_keystore is None
        keystore = Old_KeyStore(data, row)
    else:
        raise Exception(_("unknown masterkey type {}:{}").format(
            row.masterkey_id if row is not None else None, derivation_type))
    return keystore

def instantiate_keystore_from_text(text_type: KeystoreTextType, text_match: Union[str, List[str]],
        password: Optional[str], derivation_text: Optional[str]=None,
        passphrase: Optional[str]=None, watch_only: bool=False) -> KeyStore:
    derivation_type: Optional[DerivationType] = None
    data: Dict[str, Any] = {}
    if text_type == KeystoreTextType.EXTENDED_PUBLIC_KEY:
        derivation_type = DerivationType.BIP32
        assert isinstance(text_match, str)
        assert passphrase is None
        # `watch_only` is ignored.
        data['xpub'] = text_match
    elif text_type == KeystoreTextType.EXTENDED_PRIVATE_KEY:
        derivation_type = DerivationType.BIP32
        assert isinstance(text_match, str)
        assert passphrase is None
        if not watch_only:
            assert password is not None
            data['xprv'] = pw_encode(text_match, password)
        private_key = bip32_key_from_string(text_match)
        data['xpub'] = private_key.public_key.to_extended_key_string()
    elif text_type == KeystoreTextType.PRIVATE_KEYS:
        derivation_type = DerivationType.IMPORTED
        # watch_only?
    elif text_type == KeystoreTextType.ADDRESSES:
        derivation_type = DerivationType.IMPORTED
        # All address types have to be the same.
        pass
    elif text_type == KeystoreTextType.BIP39_SEED_WORDS:
        derivation_type = DerivationType.BIP32
        if derivation_text is None:
            derivation_text = bip44_derivation_cointype(0, 0)
        assert isinstance(text_match, str)
        bip32_seed = bip39_to_seed(text_match, passphrase)
        xprv = BIP32PrivateKey.from_seed(bip32_seed, Net.COIN)
        for n in bip32_decompose_chain_string(derivation_text):
            xprv = xprv.child_safe(n)
        if not watch_only:
            assert password is not None
            data['xprv'] = pw_encode(xprv.to_extended_key_string(), password)
            data['seed'] = pw_encode(text_match, password)
            if passphrase is not None:
                data['passphrase'] = pw_encode(passphrase, password)
        data['derivation'] = derivation_text
        data['xpub'] = xprv.public_key.to_extended_key_string()
    elif text_type == KeystoreTextType.ELECTRUM_SEED_WORDS:
        derivation_type = DerivationType.BIP32
        assert isinstance(text_match, str)
        bip32_seed = Mnemonic.mnemonic_to_seed(text_match, passphrase or '')
        derivation_text = "m"
        xprv = BIP32PrivateKey.from_seed(bip32_seed, Net.COIN)
        for n in bip32_decompose_chain_string(derivation_text):
            xprv = private_key.child_safe(n)
        if not watch_only:
            assert password is not None
            data['xprv'] = pw_encode(xprv.to_extended_key_string(), password)
            data['seed'] = pw_encode(text_match, password)
            if passphrase is not None:
                data['passphrase'] = pw_encode(passphrase, password)
        data['derivation'] = derivation_text
        data['xpub'] = xprv.public_key.to_extended_key_string()
    elif text_type == KeystoreTextType.ELECTRUM_OLD_SEED_WORDS:
        derivation_type = DerivationType.ELECTRUM_OLD
        assert isinstance(text_match, str)
        assert passphrase is None
        # `watch_only` is ignored.
        hex_seed = Old_KeyStore._seed_to_hex(text_match)
        assert password is not None
        data['seed'] = pw_encode(hex_seed, password)
        data['mpk'] = Old_KeyStore._mpk_from_hex_seed(hex_seed)
    else:
        raise NotImplementedError("Unsupported text match type", text_type)

    return instantiate_keystore(derivation_type, data)


SignableKeystoreTypes = Union[Software_KeyStore, Hardware_KeyStore]
StandardKeystoreTypes = Union[Old_KeyStore, BIP32_KeyStore]
