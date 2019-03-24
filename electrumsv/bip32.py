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

from typing import List

from bitcoinx import PrivateKey, be_bytes_to_int, CURVE_ORDER

from .bitcoin import EncodeBase58Check, DecodeBase58Check
from .networks import Net
from .util import bfh


BIP32_PRIME = 0x80000000


class BIP32Error(Exception):
    pass


class InvalidMasterKeyVersionBytes(BIP32Error):
    pass


def xprv_header(*, net=None):
    net = net or Net
    return bfh("%08x" % net.XPRV_HEADERS['standard'])


def xpub_header(*, net=None):
    net = net or Net
    return bfh("%08x" % net.XPUB_HEADERS['standard'])


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
