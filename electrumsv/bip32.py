# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2018 The Electrum developers
# Copyright (C) 2019 The ElectrumSV Developers
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
from typing import List

from bitcoinx import PrivateKey, PublicKey, be_bytes_to_int, int_to_be_bytes, CURVE_ORDER

from .bitcoin import rev_hex, int_to_hex, EncodeBase58Check, DecodeBase58Check
from .crypto import hash_160, hmac_oneshot
from .logs import logs
from .networks import Net
from .util import bfh


BIP32_PRIME = 0x80000000


class BIP32Error(Exception):
    pass


class InvalidMasterKeyVersionBytes(BIP32Error):
    pass


class InvalidECPointException(Exception):
    pass


def protect_against_invalid_ecpoint(func):
    def func_wrapper(*args):
        n = args[-1]
        while True:
            is_prime = n & BIP32_PRIME
            try:
                return func(*args[:-1], n=n)
            except InvalidECPointException:
                logs.root.warning('bip32 protect_against_invalid_ecpoint: skipping index')
                n += 1
                is_prime2 = n & BIP32_PRIME
                if is_prime != is_prime2:
                    raise OverflowError()
    return func_wrapper


# Child private key derivation function (from master private key)
# k = master private key (32 bytes)
# c = master chain code (extra entropy for key derivation) (32 bytes)
# n = the index of the key we want to derive. (only 32 bits will be used)
# If n is hardened (i.e. the 32nd bit is set), the resulting private key's
#  corresponding public key can NOT be determined without the master private key.
# However, if n is not hardened, the resulting private key's corresponding
#  public key can be determined without the master private key.
@protect_against_invalid_ecpoint
def CKD_priv(k, c, n):
    if n < 0:
        raise BIP32Error('the bip32 index needs to be non-negative')
    is_prime = n & BIP32_PRIME
    return _CKD_priv(k, c, bfh(rev_hex(int_to_hex(n, 4))), is_prime)


def _CKD_priv(k, c, s, is_prime):
    try:
        keypair = PrivateKey(k)
    except ValueError:
        raise BIP32Error('Impossible xprv (not within curve order)')
    cK = keypair.public_key.to_bytes(compressed=True)
    data = bytes([0]) + k + s if is_prime else cK + s
    I_full = hmac_oneshot(c, data, hashlib.sha512)
    I_left = be_bytes_to_int(I_full[0:32])
    k_n = (I_left + be_bytes_to_int(k)) % CURVE_ORDER
    if I_left >= CURVE_ORDER or k_n == 0:
        raise InvalidECPointException()
    k_n = int_to_be_bytes(k_n, 32)
    c_n = I_full[32:]
    return k_n, c_n


# Child public key derivation function (from public key only)
# K = master public key
# c = master chain code
# n = index of key we want to derive
# This function allows us to find the nth public key, as long as n is
#  not hardened. If n is hardened, we need the master private key to find it.
@protect_against_invalid_ecpoint
def CKD_pub(cK, c, n):
    if n < 0:
        raise BIP32Error('the bip32 index needs to be non-negative')
    if n & BIP32_PRIME:
        raise BIP32Error()
    return _CKD_pub(cK, c, bfh(rev_hex(int_to_hex(n, 4))))


# helper function, callable with arbitrary string.
# note: 's' does not need to fit into 32 bits here! (c.f. trustedcoin billing)
def _CKD_pub(cK, c, s):
    I_full = hmac_oneshot(c, cK + s, hashlib.sha512)
    try:
        pubkey = PublicKey.from_bytes(cK).add(I_full[0:32])
    except ValueError:
        raise InvalidECPointException()
    cK_n = pubkey.to_bytes(compressed=True)
    c_n = I_full[32:]
    return cK_n, c_n


def xprv_header(*, net=None):
    net = net or Net
    return bfh("%08x" % net.XPRV_HEADERS['standard'])


def xpub_header(*, net=None):
    net = net or Net
    return bfh("%08x" % net.XPUB_HEADERS['standard'])


def serialize_xprv(c, k, depth=0, fingerprint=b'\x00'*4,
                   child_number=b'\x00'*4, *, net=None):
    if not 0 < be_bytes_to_int(k) < CURVE_ORDER:
        raise BIP32Error('Impossible xprv (not within curve order)')
    xprv = b''.join((xprv_header(net=net), bytes([depth]), fingerprint,
                     child_number, c, bytes([0]), k))
    return EncodeBase58Check(xprv)


def serialize_xpub(c, cK, depth=0, fingerprint=b'\x00'*4,
                   child_number=b'\x00'*4, *, net=None):
    xpub = xpub_header(net=net) \
           + bytes([depth]) + fingerprint + child_number + c + cK
    return EncodeBase58Check(xpub)


def _deserialize_xkey(xkey, prv, *, net=None):
    net = net or Net
    xkey = DecodeBase58Check(xkey)
    if len(xkey) != 78:
        raise BIP32Error('Invalid length for extended key: {}'
                               .format(len(xkey)))
    depth = xkey[4]
    fingerprint = xkey[5:9]
    child_number = xkey[9:13]
    c = xkey[13:13+32]
    header = int.from_bytes(xkey[0:4], byteorder='big')
    headers = net.XPRV_HEADERS if prv else net.XPUB_HEADERS
    if header not in headers.values():
        raise InvalidMasterKeyVersionBytes('Invalid extended key format: {}'
                                           .format(hex(header)))
    n = 33 if prv else 32
    K_or_k = xkey[13+n:]
    if prv and not 0 < be_bytes_to_int(K_or_k) < CURVE_ORDER:
        raise BIP32Error('Impossible xprv (not within curve order)')
    return depth, fingerprint, child_number, c, K_or_k


def deserialize_xpub(xkey, *, net=None):
    return _deserialize_xkey(xkey, False, net=net)


def deserialize_xprv(xkey, *, net=None):
    return _deserialize_xkey(xkey, True, net=net)


def is_xpub(text):
    try:
        deserialize_xpub(text)
        return True
    except Exception:
        return False


def is_xprv(text):
    try:
        deserialize_xprv(text)
        return True
    except Exception:
        return False


def xpub_from_xprv(xprv):
    depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    cK = PrivateKey(k).public_key.to_bytes(compressed=True)
    return serialize_xpub(c, cK, depth, fingerprint, child_number)


def bip32_root(seed):
    I_full = hmac_oneshot(b"Bitcoin seed", seed, hashlib.sha512)
    master_k = I_full[0:32]
    master_c = I_full[32:]
    # create xprv first, as that will check if master_k is within curve order
    xprv = serialize_xprv(master_c, master_k)
    cK = PrivateKey(master_k).public_key.to_bytes(compressed=True)
    xpub = serialize_xpub(master_c, cK)
    return xprv, xpub


def xpub_from_pubkey(cK):
    if cK[0] not in (0x02, 0x03):
        raise BIP32Error('Unexpected first byte: {}'.format(cK[0]))
    return serialize_xpub(b'\x00'*32, cK)


def bip32_derivation(s: str) -> int:
    if not s.startswith('m/'):
        raise BIP32Error('invalid bip32 derivation path: {}'.format(s))
    s = s[2:]
    for n in s.split('/'):
        if n == '':
            continue
        i = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        yield i


def bip32_path_to_uints(n: str) -> List[int]:
    """Convert bip32 path to list of uint32 integers with prime flags
    m/0/-1/1' -> [0, 0x80000001, 0x80000001]

    based on code in trezorlib
    """
    path = []
    for x in n.split('/')[1:]:
        if x == '':
            continue
        prime = 0
        if x.endswith("'"):
            x = x.replace('\'', '')
            prime = BIP32_PRIME
        if x.startswith('-'):
            prime = BIP32_PRIME
        path.append(abs(int(x)) | prime)
    return path


def is_bip32_derivation(x: str) -> bool:
    try:
        list(bip32_derivation(x))
        return True
    except Exception:
        return False


def bip32_private_derivation(xprv, branch, sequence):
    if not sequence.startswith(branch):
        raise BIP32Error('incompatible branch ({}) and sequence ({})'
                         .format(branch, sequence))
    if branch == sequence:
        return xprv, xpub_from_xprv(xprv)
    depth, fingerprint, child_number, c, k = deserialize_xprv(xprv)
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '':
            continue
        i = int(n[:-1]) + BIP32_PRIME if n[-1] == "'" else int(n)
        parent_k = k
        k, c = CKD_priv(k, c, i)
        depth += 1
    parent_cK = PrivateKey(parent_k).public_key.to_bytes(compressed=True)
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = bfh("%08X" % i)
    cK = PrivateKey(k).public_key.to_bytes(compressed=True)
    xpub = serialize_xpub(c, cK, depth, fingerprint, child_number)
    xprv = serialize_xprv(c, k, depth, fingerprint, child_number)
    return xprv, xpub


def bip32_public_derivation(xpub, branch, sequence):
    depth, fingerprint, child_number, c, cK = deserialize_xpub(xpub)
    if not sequence.startswith(branch):
        raise BIP32Error('incompatible branch ({}) and sequence ({})'
                         .format(branch, sequence))
    sequence = sequence[len(branch):]
    for n in sequence.split('/'):
        if n == '':
            continue
        i = int(n)
        parent_cK = cK
        cK, c = CKD_pub(cK, c, i)
        depth += 1
    fingerprint = hash_160(parent_cK)[0:4]
    child_number = bfh("%08X" % i)
    return serialize_xpub(c, cK, depth, fingerprint, child_number)


def bip32_private_key(sequence, k, chain):
    for i in sequence:
        k, chain = CKD_priv(k, chain, i)
    return k
