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
from unicodedata import normalize
from typing import Any, Dict, List, Tuple, Union

from bitcoinx import (
    PrivateKey, PublicKey, BIP32PrivateKey, BIP32PublicKey,
    int_to_be_bytes, be_bytes_to_int, CURVE_ORDER,
    bip32_key_from_string, bip32_decompose_chain_string,
    base58_decode_check, Address
)

from .app_state import app_state
from .bitcoin import bfh, is_seed, seed_type, int_to_hex, is_address_valid
from .crypto import sha256d, pw_encode, pw_decode
from .exceptions import InvalidPassword
from .logs import logs
from .mnemonic import Mnemonic, load_wordlist
from .networks import Net
from .transaction import XPublicKey


logger = logs.get_logger("keystore")


class KeyStore:
    def __init__(self) -> None:
        self.wallet_advice: Dict[Address, Tuple[bool, int]] = {}

    def has_seed(self) -> bool:
        return False

    def can_change_password(self) -> bool:
        raise NotImplementedError

    def may_have_password(self) -> bool:
        raise NotImplementedError

    def update_password(self, old_password, new_password):
        raise NotImplementedError

    def dump(self) -> Dict[str, Any]:
        raise NotImplementedError

    def is_watching_only(self) -> bool:
        return False

    def can_import(self) -> bool:
        return False

    def get_tx_derivations(self, tx):
        keypairs = {}
        for txin in tx.inputs:
            for x_pubkey in txin.unused_x_pubkeys():
                derivation = self.get_pubkey_derivation(x_pubkey)
                if not derivation:
                    continue
                keypairs[x_pubkey] = derivation
        return keypairs

    def can_sign(self, tx) -> bool:
        if self.is_watching_only():
            return False
        return bool(self.get_tx_derivations(tx))

    def set_wallet_advice(self, addr, advice) -> None:
        pass



class Software_KeyStore(KeyStore):
    def __init__(self):
        KeyStore.__init__(self)

    def may_have_password(self) -> bool:
        return not self.is_watching_only()

    def sign_message(self, sequence, message, password):
        privkey, compressed = self.get_private_key(sequence, password)
        key = PrivateKey(privkey, compressed)
        return key.sign_message(message)

    def decrypt_message(self, sequence, message, password):
        privkey, compressed = self.get_private_key(sequence, password)
        key = PrivateKey(privkey)
        return key.decrypt_message(message)

    def sign_transaction(self, tx, password):
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self.get_tx_derivations(tx)
        for k, v in keypairs.items():
            keypairs[k] = self.get_private_key(v, password)
        # Sign
        if keypairs:
            tx.sign(keypairs)


class Imported_KeyStore(Software_KeyStore):
    # keystore for imported private keys
    # private keys are encrypted versions of the WIF encoding

    def __init__(self, d):
        Software_KeyStore.__init__(self)
        keypairs = d.get('keypairs', {})
        self.keypairs = {PublicKey.from_hex(pubkey): enc_privkey
                         for pubkey, enc_privkey in keypairs.items()}
        self._sorted = None

    def is_deterministic(self) -> bool:
        return False

    def can_change_password(self) -> bool:
        return True

    def get_master_public_key(self):
        return None

    def dump(self) -> Dict[str, Any]:
        keypairs = {pubkey.to_hex(): enc_privkey
                    for pubkey, enc_privkey in self.keypairs.items()}
        return {
            'type': 'imported',
            'keypairs': keypairs,
        }

    def can_import(self) -> bool:
        return True

    def get_addresses(self):
        if not self._sorted:
            addresses = [pubkey.to_address(coin=Net.COIN) for pubkey in self.keypairs]
            self._sorted = sorted(addresses, key=lambda addr: addr.to_string())
        return self._sorted

    def address_to_pubkey(self, address):
        for pubkey in self.keypairs:
            if pubkey.to_address() == address:
                return pubkey
        return None

    def remove_address(self, address):
        pubkey = self.address_to_pubkey(address)
        if pubkey:
            self.keypairs.pop(pubkey)
            if self._sorted:
                self._sorted.remove(address)

    def check_password(self, password):
        pubkey = list(self.keypairs.keys())[0]
        self.export_private_key(pubkey, password)

    def import_privkey(self, privkey_text, password):
        pubkey = _public_key_from_private_key_text(privkey_text)
        self.keypairs[pubkey] = pw_encode(privkey_text, password)
        self._sorted = None
        return pubkey

    def delete_imported_key(self, key):
        self.keypairs.pop(key)

    def export_private_key(self, pubkey, password):
        '''Returns a WIF string'''
        privkey_text = pw_decode(self.keypairs[pubkey], password)
        # this checks the password
        if pubkey != _public_key_from_private_key_text(privkey_text):
            raise InvalidPassword()
        return privkey_text

    def get_private_key(self, pubkey, password):
        '''Returns a (32 byte privkey, is_compressed) pair.'''
        privkey_text = self.export_private_key(pubkey, password)
        privkey = PrivateKey.from_text(privkey_text)
        return privkey.to_bytes(), privkey.is_compressed()

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey.kind() in (0x02, 0x03, 0x04):
            pubkey = x_pubkey.to_public_key()
            if pubkey in self.keypairs:
                return pubkey
        elif x_pubkey.kind() == 0xfd:
            return self.address_to_pubkey(x_pubkey.to_address())

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        for k, v in self.keypairs.items():
            b = pw_decode(v, old_password)
            c = pw_encode(b, new_password)
            self.keypairs[k] = c



class Deterministic_KeyStore(Software_KeyStore):

    def __init__(self, d) -> None:
        Software_KeyStore.__init__(self)
        self.seed = d.get('seed', '')
        self.passphrase = d.get('passphrase', '')

    def is_deterministic(self) -> bool:
        return True

    def dump(self) -> Dict[str, Any]:
        d = {}
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
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


class Xpub:

    def __init__(self) -> None:
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None

    def get_master_public_key(self):
        return self.xpub

    def derive_pubkey(self, for_change: bool, n: int) -> str:
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            xpub = bip32_key_from_string(self.xpub)
            xpub = xpub.child(1 if for_change else 0).to_extended_key_string()
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        return self.get_pubkey_from_xpub(xpub, (n,))

    @classmethod
    def get_pubkey_from_xpub(self, xpub, sequence) -> str:
        pubkey = bip32_key_from_string(xpub)
        for n in sequence:
            pubkey = pubkey.child_safe(n)
        return pubkey.to_hex()

    def get_xpubkey(self, c, i):
        s = ''.join(int_to_hex(x,2) for x in (c, i))
        return XPublicKey('ff' + base58_decode_check(self.xpub).hex() + s)

    def get_pubkey_derivation_based_on_wallet_advice(self, x_pubkey):
        addr = x_pubkey.to_address()
        try:
            if addr in self.wallet_advice and self.wallet_advice[addr] is not None:
                return self.wallet_advice[addr]
        except NameError:
            # future-proofing the code: self.wallet_advice wasn't defined, which can happen
            # if this class is inherited in the future by non-KeyStore children
            pass
        return

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey.kind() == 0xfd:
            return self.get_pubkey_derivation_based_on_wallet_advice(x_pubkey)
        if x_pubkey.kind() != 0xff:
            return
        xpub, path = x_pubkey.bip32_extended_key_and_path()
        if self.xpub != xpub:
            return
        return path


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):

    def __init__(self, d):
        Xpub.__init__(self)
        Deterministic_KeyStore.__init__(self, d)
        self.xpub = d.get('xpub')
        self.xprv = d.get('xprv')

    def format_seed(self, seed):
        return ' '.join(seed.split())

    def dump(self) -> Dict[str, Any]:
        d = Deterministic_KeyStore.dump(self)
        d['type'] = 'bip32'
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        return d

    def get_master_private_key(self, password):
        return pw_decode(self.xprv, password)

    def check_password(self, password):
        xprv = pw_decode(self.xprv, password)
        try:
            assert (bip32_key_from_string(xprv).derivation().chain_code
                    == bip32_key_from_string(self.xpub).derivation().chain_code)
        except (ValueError, AssertionError):
            raise InvalidPassword()

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
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

    def add_xprv_from_seed(self, bip32_seed, derivation):
        xprv = BIP32PrivateKey.from_seed(bip32_seed, Net.COIN)
        for n in bip32_decompose_chain_string(derivation):
            xprv = xprv.child_safe(n)
        self.add_xprv(xprv)

    def get_private_key(self, sequence, password):
        xprv = self.get_master_private_key(password)
        privkey = bip32_key_from_string(xprv)
        for n in sequence:
            privkey = privkey.child_safe(n)
        return privkey.to_bytes(), True

    def set_wallet_advice(self, addr, advice) -> None:
        # overrides KeyStore.set_wallet_advice
        self.wallet_advice[addr] = advice


class Old_KeyStore(Deterministic_KeyStore):

    def __init__(self, d: Dict[str, Any]) -> None:
        super().__init__(d)
        self.mpk = d['mpk']

    def _get_hex_seed_bytes(self, password):
        return pw_decode(self.seed, password).encode('utf8')

    @classmethod
    def _seed_to_hex(cls, seed):
        from . import old_mnemonic, mnemonic
        seed = mnemonic.normalize_text(seed)
        # see if seed was entered as hex
        if seed:
            try:
                bfh(seed)
                return seed
            except Exception:
                pass
        words = seed.split()
        seed = old_mnemonic.mn_decode(words)
        if not seed:
            raise Exception("Invalid seed")
        return seed

    @classmethod
    def _mpk_from_hex_seed(cls, hex_seed):
        secexp = cls.stretch_key(hex_seed.encode())
        master_private_key = PrivateKey(int_to_be_bytes(secexp, 32))
        return master_private_key.public_key.to_hex(compressed=False)[2:]

    @classmethod
    def _mpk_to_PublicKey(cls, mpk):
        return PublicKey.from_hex('04' + mpk)

    @classmethod
    def from_seed(cls, seed):
        hex_seed = cls._seed_to_hex(seed)
        return cls({'seed': hex_seed, 'mpk': cls._mpk_from_hex_seed(hex_seed)})

    @classmethod
    def from_mpk(cls, mpk):
        return cls({'mpk': mpk})

    @classmethod
    def is_hex_mpk(cls, text):
        try:
            cls._mpk_to_PublicKey(text)
            return True
        except:
            return False

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['mpk'] = self.mpk
        d['type'] = 'old'
        return d

    def get_seed(self, password):
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
    def get_sequence(cls, mpk, for_change, n):
        return be_bytes_to_int(sha256d(("%d:%d:"%(n, for_change)).encode('ascii') + bfh(mpk)))

    @classmethod
    def get_pubkey_from_mpk(cls, mpk, for_change: bool, n: int) -> str:
        z = cls.get_sequence(mpk, for_change, n)
        master_public_key = cls._mpk_to_PublicKey(mpk)
        public_key2 = master_public_key.add(int_to_be_bytes(z, 32))
        return public_key2.to_hex(compressed=False)

    def derive_pubkey(self, for_change: bool, n: int) -> str:
        return self.get_pubkey_from_mpk(self.mpk, for_change, n)

    def get_private_key_from_stretched_exponent(self, for_change, n, secexp):
        secexp = (secexp + self.get_sequence(self.mpk, for_change, n)) % CURVE_ORDER
        return int_to_be_bytes(secexp, 32)

    def get_private_key(self, sequence, password):
        seed = self._get_hex_seed_bytes(password)
        self.check_seed(seed)
        for_change, n = sequence
        secexp = self.stretch_key(seed)
        pk = self.get_private_key_from_stretched_exponent(for_change, n, secexp)
        return pk, False

    def check_seed(self, seed):
        secexp = self.stretch_key(seed)
        master_private_key = PrivateKey(int_to_be_bytes(secexp, 32))
        master_public_key = master_private_key.public_key.to_bytes(compressed=False)[1:]
        if master_public_key != bfh(self.mpk):
            logger.error('invalid password (mpk) %s %s', self.mpk, master_public_key.hex())
            raise InvalidPassword()

    def check_password(self, password):
        seed = self._get_hex_seed_bytes(password)
        self.check_seed(seed)

    def get_master_public_key(self):
        return self.mpk

    def get_xpubkey(self, for_change, n):
        s = ''.join(int_to_hex(x,2) for x in (for_change, n))
        return XPublicKey('fe' + self.mpk + s)

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey.kind() != 0xfe:
            return
        mpk, path = x_pubkey.old_keystore_mpk_and_path()
        if self.mpk != mpk.hex():
            return
        return path

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = pw_decode(self.seed, old_password)
            self.seed = pw_encode(decoded, new_password)



class Hardware_KeyStore(KeyStore, Xpub):
    # Derived classes must set:
    #   - device
    #   - DEVICE_IDS
    #   - wallet_type
    device: str

    max_change_outputs = 1

    def __init__(self, d):
        Xpub.__init__(self)
        KeyStore.__init__(self)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.xpub = d.get('xpub')
        self.label = d.get('label')
        self.derivation = d.get('derivation')
        self.handler = None
        self.plugin = None
        self.libraries_available = False

    def set_label(self, label):
        self.label = label

    def may_have_password(self):
        return False

    def is_deterministic(self):
        return True

    def dump(self):
        return {
            'type': 'hardware',
            'hw_type': self.hw_type,
            'xpub': self.xpub,
            'derivation':self.derivation,
            'label':self.label,
        }

    def unpaired(self):
        '''A device paired with the wallet was diconnected.  This can be
        called in any thread context.'''
        logger.debug("unpaired")

    def paired(self):
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        logger.debug("paired")

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is not watching-only; the user will be prompted for
        pin and passphrase as appropriate when needed.'''
        assert not self.has_seed()
        return False

    def can_change_password(self):
        return False



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

def from_bip39_seed(seed, passphrase, derivation):
    k = BIP32_KeyStore({})
    bip32_seed = bip39_to_seed(seed, passphrase)
    k.add_xprv_from_seed(bip32_seed, derivation)
    return k


def load_keystore(keystore_data: Dict[str, Any]) -> KeyStore:
    keystore_type = keystore_data.get('type', None)
    if not keystore_type:
        raise ValueError('wallet format requires update')

    if keystore_type == 'old':
        return Old_KeyStore(keystore_data)
    elif keystore_type == 'imported':
        return Imported_KeyStore(keystore_data)
    elif keystore_type == 'bip32':
        return BIP32_KeyStore(keystore_data)
    elif keystore_type == 'hardware':
        return app_state.device_manager.create_keystore(keystore_data)
    raise ValueError('unknown keystore type', keystore_type)


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

def from_seed(seed, passphrase, is_p2sh):
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
