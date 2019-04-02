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

from bitcoinx import (
    PrivateKey, PublicKey, BIP32PrivateKey, BIP32PublicKey,
    int_to_be_bytes, be_bytes_to_int, CURVE_ORDER, unpack_le_uint16,
    bip32_key_from_string, bip32_decompose_chain_string,
    base58_encode_check, base58_decode_check
)

from .address import Address
from .app_state import app_state
from .bitcoin import (
    bfh, is_seed, seed_type, rev_hex, script_to_address, int_to_hex
)
from .crypto import sha256d, pw_encode, pw_decode
from .exceptions import InvalidPassword
from .logs import logs
from .mnemonic import Mnemonic, load_wordlist
from .networks import Net


logger = logs.get_logger("keystore")


class KeyStore:
    def __init__(self):
        self.wallet_advice = {}

    def has_seed(self):
        return False

    def is_watching_only(self):
        return False

    def can_import(self):
        return False

    def get_tx_derivations(self, tx):
        keypairs = {}
        for txin in tx.inputs():
            num_sig = txin.get('num_sig')
            if num_sig is None:
                continue
            x_signatures = txin['signatures']
            signatures = [sig for sig in x_signatures if sig]
            if len(signatures) == num_sig:
                # input is complete
                continue
            for k, x_pubkey in enumerate(txin['x_pubkeys']):
                if x_signatures[k] is not None:
                    # this pubkey already signed
                    continue
                derivation = self.get_pubkey_derivation(x_pubkey)
                if not derivation:
                    continue
                keypairs[x_pubkey] = derivation
        return keypairs

    def can_sign(self, tx):
        if self.is_watching_only():
            return False
        return bool(self.get_tx_derivations(tx))

    def set_wallet_advice(self, addr, advice):
        pass



class Software_KeyStore(KeyStore):

    def __init__(self):
        KeyStore.__init__(self)

    def may_have_password(self):
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

    def is_deterministic(self):
        return False

    def can_change_password(self):
        return True

    def get_master_public_key(self):
        return None

    def dump(self):
        keypairs = {pubkey.to_hex(): enc_privkey
                    for pubkey, enc_privkey in self.keypairs.items()}
        return {
            'type': 'imported',
            'keypairs': keypairs,
        }

    def can_import(self):
        return True

    def get_addresses(self):
        if not self._sorted:
            addresses = [Address.from_string(pubkey.to_address()) for pubkey in self.keypairs]
            self._sorted = sorted(addresses, key=Address.to_string)
        return self._sorted

    def address_to_pubkey(self, address):
        for pubkey in self.keypairs:
            if Address.from_string(pubkey.to_address()) == address:
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
        if x_pubkey[0:2] in ['02', '03', '04']:
            pubkey = PublicKey.from_hex(x_pubkey)
            if pubkey in self.keypairs:
                return pubkey
        elif x_pubkey[0:2] == 'fd':
            addr = script_to_address(x_pubkey[2:])
            return self.address_to_pubkey(addr)

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        for k, v in self.keypairs.items():
            b = pw_decode(v, old_password)
            c = pw_encode(b, new_password)
            self.keypairs[k] = c



class Deterministic_KeyStore(Software_KeyStore):

    def __init__(self, d):
        Software_KeyStore.__init__(self)
        self.seed = d.get('seed', '')
        self.passphrase = d.get('passphrase', '')

    def is_deterministic(self):
        return True

    def dump(self):
        d = {}
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
        return d

    def has_seed(self):
        return bool(self.seed)

    def is_watching_only(self):
        return not self.has_seed()

    def can_change_password(self):
        return not self.is_watching_only()

    def add_seed(self, seed):
        if self.seed:
            raise Exception("a seed exists")
        self.seed = self.format_seed(seed)

    def get_seed(self, password):
        return pw_decode(self.seed, password)

    def get_passphrase(self, password):
        if self.passphrase:
            return pw_decode(self.passphrase, password)
        return ''


class Xpub:

    def __init__(self):
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None

    def get_master_public_key(self):
        return self.xpub

    def derive_pubkey(self, for_change, n):
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
    def get_pubkey_from_xpub(self, xpub, sequence):
        pubkey = bip32_key_from_string(xpub)
        for n in sequence:
            pubkey = pubkey.child_safe(n)
        return pubkey.to_hex()

    def get_xpubkey(self, c, i):
        s = ''.join(int_to_hex(x,2) for x in (c, i))
        return 'ff' + base58_decode_check(self.xpub).hex() + s

    @classmethod
    def parse_xpubkey(self, pubkey):
        assert pubkey[0:2] == 'ff'
        assert len(pubkey) == 166
        pk = bytes.fromhex(pubkey)
        xkey = base58_encode_check(pk[1:79])
        return xkey, [unpack_le_uint16(pk[n: n+2])[0] for n in (79, 81)]

    def get_pubkey_derivation_based_on_wallet_advice(self, x_pubkey):
        _, addr = xpubkey_to_address(x_pubkey)
        try:
            if addr in self.wallet_advice and self.wallet_advice[addr] is not None:
                return self.wallet_advice[addr]
        except NameError:
            # future-proofing the code: self.wallet_advice wasn't defined, which can happen
            # if this class is inherited in the future by non-KeyStore children
            pass
        return

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] == 'fd':
            return self.get_pubkey_derivation_based_on_wallet_advice(x_pubkey)
        if x_pubkey[0:2] != 'ff':
            return
        xpub, derivation = self.parse_xpubkey(x_pubkey)
        if self.xpub != xpub:
            return
        return derivation


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):

    def __init__(self, d):
        Xpub.__init__(self)
        Deterministic_KeyStore.__init__(self, d)
        self.xpub = d.get('xpub')
        self.xprv = d.get('xprv')

    def format_seed(self, seed):
        return ' '.join(seed.split())

    def dump(self):
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

    def is_watching_only(self):
        return self.xprv is None

    def add_xprv(self, xprv: BIP32PrivateKey):
        self.xprv = xprv.to_extended_key_string()
        self.xpub = xprv.public_key.to_extended_key_string()

    def add_xprv_from_seed(self, bip32_seed, derivation):
        xprv = BIP32PrivateKey.from_seed(bip32_seed, coin=Net.COIN)
        for n in bip32_decompose_chain_string(derivation):
            xprv = xprv.child_safe(n)
        self.add_xprv(xprv)

    def get_private_key(self, sequence, password):
        xprv = self.get_master_private_key(password)
        privkey = bip32_key_from_string(xprv)
        for n in sequence:
            privkey = privkey.child_safe(n)
        return privkey.to_bytes(), True

    def set_wallet_advice(self, addr, advice): #overrides KeyStore.set_wallet_advice
        self.wallet_advice[addr] = advice


class Old_KeyStore(Deterministic_KeyStore):

    def __init__(self, d):
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
    def get_pubkey_from_mpk(cls, mpk, for_change, n):
        z = cls.get_sequence(mpk, for_change, n)
        master_public_key = cls._mpk_to_PublicKey(mpk)
        public_key2 = master_public_key.add(int_to_be_bytes(z, 32))
        return public_key2.to_hex(compressed=False)

    def derive_pubkey(self, for_change, n):
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
        return 'fe' + self.mpk + s

    @classmethod
    def parse_xpubkey(self, x_pubkey):
        assert x_pubkey[0:2] == 'fe'
        pk = x_pubkey[2:]
        mpk = pk[0:128]
        dd = pk[128:]
        s = []
        while dd:
            n = int(rev_hex(dd[0:4]), 16)
            dd = dd[4:]
            s.append(n)
        assert len(s) == 2
        return mpk, s

    def get_pubkey_derivation(self, x_pubkey):
        if x_pubkey[0:2] != 'fe':
            return
        mpk, derivation = self.parse_xpubkey(x_pubkey)
        if self.mpk != mpk:
            return
        return derivation

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

    def needs_prevtx(self):
        '''Returns true if this hardware wallet needs to know the input
        transactions to sign a transactions'''
        return True



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

# extended pubkeys

def is_xpubkey(x_pubkey):
    return x_pubkey[0:2] == 'ff'


def parse_xpubkey(x_pubkey):
    assert x_pubkey[0:2] == 'ff'
    return BIP32_KeyStore.parse_xpubkey(x_pubkey)


def xpubkey_to_address(x_pubkey):
    if x_pubkey[0:2] == 'fd':
        address = script_to_address(x_pubkey[2:])
        return x_pubkey, address
    if x_pubkey[0:2] in ['02', '03', '04']:
        pubkey = x_pubkey
    elif x_pubkey[0:2] == 'ff':
        xpub, s = BIP32_KeyStore.parse_xpubkey(x_pubkey)
        pubkey = BIP32_KeyStore.get_pubkey_from_xpub(xpub, s)
    elif x_pubkey[0:2] == 'fe':
        mpk, s = Old_KeyStore.parse_xpubkey(x_pubkey)
        pubkey = Old_KeyStore.get_pubkey_from_mpk(mpk, s[0], s[1])
    else:
        raise Exception("Cannot parse pubkey")
    if pubkey:
        address = Address.from_pubkey(pubkey)
    return pubkey, address

def xpubkey_to_pubkey(x_pubkey):
    pubkey, address = xpubkey_to_address(x_pubkey)
    return pubkey


def load_keystore(storage, name):
    w = storage.get('wallet_type', 'standard')
    d = storage.get(name, {})
    t = d.get('type')
    if not t:
        raise Exception('wallet format requires update')
    if t == 'old':
        k = Old_KeyStore(d)
    elif t == 'imported':
        k = Imported_KeyStore(d)
    elif t == 'bip32':
        k = BIP32_KeyStore(d)
    elif t == 'hardware':
        k = app_state.device_manager.create_keystore(d)
    else:
        raise Exception('unknown wallet type', t)
    return k


def is_address_list(text):
    parts = text.split()
    return parts and all(Address.is_valid(x) for x in parts)


def get_private_keys(text):
    parts = text.split('\n')
    parts = [''.join(part.split()) for part in parts]
    parts = [part for part in parts if part]
    if parts and all(is_private_key(x) for x in parts):
        return parts


def is_private_key_list(text):
    return bool(get_private_keys(text))


is_mpk = lambda x: Old_KeyStore.is_hex_mpk(x) or is_xpub(x)
is_private = lambda x: is_seed(x) or is_xprv(x) or is_private_key_list(x)
is_master_key = lambda x: Old_KeyStore.is_hex_mpk(x) or is_xprv(x) or is_xpub(x)
is_bip32_key = lambda x: is_xprv(x) or is_xpub(x)


def bip44_derivation(account_id):
    return "m/44'/%d'/%d'" % (Net.BIP44_COIN_TYPE, int(account_id))

def bip44_derivation_cointype(cointype, account_id):
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

def from_private_key_list(text):
    keystore = Imported_KeyStore({})
    for x in get_private_keys(text):
        keystore.import_key(x, None)
    return keystore

def from_xpub(xpub):
    k = BIP32_KeyStore({})
    k.xpub = xpub
    return k

def from_master_key(text):
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


def is_xpub(text):
    try:
        key = bip32_key_from_string(text)
        return isinstance(key, BIP32PublicKey)
    except Exception:
        return False


def is_xprv(text):
    try:
        key = bip32_key_from_string(text)
        return isinstance(key, BIP32PrivateKey)
    except Exception:
        return False


def is_private_key(text):
    try:
        PrivateKey.from_text(text)
        return True
    except ValueError:
        return False


def _public_key_from_private_key_text(text):
    return PrivateKey.from_text(text).public_key
