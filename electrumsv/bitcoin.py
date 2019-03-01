# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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

from bitcoinx import Ops
import ecdsa
from ecdsa.ecdsa import curve_secp256k1, generator_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.util import string_to_number

from .crypto import hash_160, sha256d, hmac_oneshot, sha256
from .networks import Net
from .util import bfh, bh2u, assert_bytes, to_bytes, inv_dict
from . import version


################################## transactions

MAX_FEE_RATE = 20000

COINBASE_MATURITY = 100
COIN = 100000000

# supported types of transction outputs
TYPE_ADDRESS = 0
TYPE_PUBKEY  = 1
TYPE_SCRIPT  = 2


def rev_hex(s):
    return bh2u(bfh(s)[::-1])


def int_to_hex(i, length=1):
    """Converts int to little-endian hex string.
    `length` is the number of bytes available
    """
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    range_size = pow(256, length)
    if i < -(range_size//2) or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        # two's complement
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)


def var_int(i):
    # https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer
    if i<0xfd:
        return int_to_hex(i)
    elif i<=0xffff:
        return "fd"+int_to_hex(i,2)
    elif i<=0xffffffff:
        return "fe"+int_to_hex(i,4)
    else:
        return "ff"+int_to_hex(i,8)


def op_push(i: int) -> str:
    if i<0x4c:  # OP_PUSHDATA1
        return int_to_hex(i)
    elif i<=0xff:
        return '4c' + int_to_hex(i)
    elif i<=0xffff:
        return '4d' + int_to_hex(i,2)
    else:
        return '4e' + int_to_hex(i,4)


def push_script(data: str) -> str:
    """Returns pushed data to the script, automatically
    choosing canonical opcodes depending on the length of the data.
    hex -> hex

    ported from https://github.com/btcsuite/btcd
    """
    data = bfh(data)
    data_len = len(data)

    # "small integer" opcodes
    if data_len == 0 or data_len == 1 and data[0] == 0:
        return bh2u(bytes([Ops.OP_0]))
    elif data_len == 1 and data[0] <= 16:
        return bh2u(bytes([Ops.OP_1 - 1 + data[0]]))
    elif data_len == 1 and data[0] == 0x81:
        return bh2u(bytes([Ops.OP_1NEGATE]))

    return op_push(data_len) + bh2u(data)


hash_encode = lambda x: bh2u(x[::-1])
hash_decode = lambda x: bfh(x)[::-1]


def is_new_seed(x, prefix=version.SEED_PREFIX):
    from . import mnemonic
    x = mnemonic.normalize_text(x)
    s = bh2u(hmac_oneshot(b"Seed version", x.encode('utf8'), hashlib.sha512))
    return s.startswith(prefix)


def is_old_seed(seed):
    from . import old_mnemonic, mnemonic
    seed = mnemonic.normalize_text(seed)
    words = seed.split()
    try:
        # checks here are deliberately left weak for legacy reasons, see #3149
        old_mnemonic.mn_decode(words)
        uses_electrum_words = True
    except Exception:
        uses_electrum_words = False
    try:
        seed = bfh(seed)
        is_hex = (len(seed) == 16 or len(seed) == 32)
    except Exception:
        is_hex = False
    return is_hex or (uses_electrum_words and (len(words) == 12 or len(words) == 24))


def seed_type(x):
    if is_old_seed(x):
        return 'old'
    elif is_new_seed(x):
        return 'standard'
    return ''

is_seed = lambda x: bool(seed_type(x))

# pywallet openssl private key implementation

def i2o_ECPublicKey(pubkey, compressed=False):
    # public keys are 65 bytes long (520 bits)
    # 0x04 + 32-byte X-coordinate + 32-byte Y-coordinate
    # 0x00 = point at infinity, 0x02 and 0x03 = compressed, 0x04 = uncompressed
    # compressed keys: <sign> <x> where <sign> is 0x02 if y is even and 0x03 if y is odd
    if compressed:
        if pubkey.point.y() & 1:
            key = '03' + '%064x' % pubkey.point.x()
        else:
            key = '02' + '%064x' % pubkey.point.x()
    else:
        key = '04' + \
              '%064x' % pubkey.point.x() + \
              '%064x' % pubkey.point.y()

    return bfh(key)
# end pywallet openssl private key implementation


############ functions from pywallet #####################

def hash160_to_b58_address(h160, addrtype):
    s = bytes([addrtype])
    s += h160
    return base_encode(s + sha256d(s)[0:4], base=58)


def b58_address_to_hash160(addr):
    addr = to_bytes(addr, 'ascii')
    _bytes = base_decode(addr, 25, base=58)
    return _bytes[0], _bytes[1:21]


def hash160_to_p2pkh(h160):
    return hash160_to_b58_address(h160, Net.ADDRTYPE_P2PKH)

def hash160_to_p2sh(h160):
    return hash160_to_b58_address(h160, Net.ADDRTYPE_P2SH)

def public_key_to_p2pkh(public_key):
    return hash160_to_p2pkh(hash_160(public_key))

def pubkey_to_address(pubkey):
    return public_key_to_p2pkh(bfh(pubkey))

def script_to_address(script):
    from .transaction import get_address_from_output_script
    t, addr = get_address_from_output_script(bfh(script))
    assert t == TYPE_ADDRESS
    return addr

def public_key_to_p2pk_script(pubkey):
    script = push_script(pubkey)
    script += 'ac'                                           # op_checksig
    return script

__b58chars = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
assert len(__b58chars) == 58

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43


def base_encode(v, base):
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    assert base in (58, 43)
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * c
    result = bytearray()
    while long_value >= base:
        div, mod = divmod(long_value, base)
        result.append(chars[mod])
        long_value = div
    result.append(chars[long_value])
    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == 0x00:
            nPad += 1
        else:
            break
    result.extend([chars[0]] * nPad)
    result.reverse()
    return result.decode('ascii')


def base_decode(v, length, base):
    """ decode v into a string of len bytes."""
    # assert_bytes(v)
    v = to_bytes(v, 'ascii')
    assert base in (58, 43)
    chars = __b58chars
    if base == 43:
        chars = __b43chars
    long_value = 0
    for (i, c) in enumerate(v[::-1]):
        long_value += chars.find(bytes([c])) * (base**i)
    result = bytearray()
    while long_value >= 256:
        div, mod = divmod(long_value, 256)
        result.append(mod)
        long_value = div
    result.append(long_value)
    nPad = 0
    for c in v:
        if c == chars[0]:
            nPad += 1
        else:
            break
    result.extend(b'\x00' * nPad)
    if length is not None and len(result) != length:
        return None
    result.reverse()
    return bytes(result)


def EncodeBase58Check(vchIn):
    hash_ = sha256d(vchIn)
    return base_encode(vchIn + hash_[0:4], base=58)


def DecodeBase58Check(psz):
    vchRet = base_decode(psz, None, base=58)
    key = vchRet[0:-4]
    csum = vchRet[-4:]
    hash_ = sha256d(key)
    cs32 = hash_[0:4]
    if cs32 != csum:
        return None
    else:
        return key



SCRIPT_TYPES = {
    'p2pkh':0,
    'p2sh':5,
}


def serialize_privkey(secret, compressed, txin_type):
    prefix = bytes([(SCRIPT_TYPES[txin_type] + Net.WIF_PREFIX) & 255])
    suffix = b'\01' if compressed else b''
    vchIn = prefix + secret + suffix
    return EncodeBase58Check(vchIn)


def deserialize_privkey(key):
    # whether the pubkey is compressed should be visible from the keystore
    if is_minikey(key):
        return 'p2pkh', minikey_to_private_key(key), False
    vch = DecodeBase58Check(key)
    if vch:
        txin_type = inv_dict(SCRIPT_TYPES)[vch[0] - Net.WIF_PREFIX]
        assert len(vch) in [33, 34]
        compressed = len(vch) == 34
        return txin_type, vch[1:33], compressed
    else:
        raise Exception("cannot deserialize", key)


def GetPubKey(pubkey, compressed=False):
    return i2o_ECPublicKey(pubkey, compressed)


def GetSecret(pkey):
    return bfh('%064x' % pkey.secret)


def is_compressed(sec):
    return deserialize_privkey(sec)[2]


def is_private_key(key):
    try:
        k = deserialize_privkey(key)
        return k is not False
    except:
        return False


########### end pywallet functions #######################

def is_minikey(text):
    # Minikeys are typically 22 or 30 characters, but this routine
    # permits any length of 20 or more provided the minikey is valid.
    # A valid minikey must begin with an 'S', be in base58, and when
    # suffixed with '?' have its SHA256 hash begin with a zero byte.
    # They are widely used in Casascius physical bitcoins, where the
    # address corresponded to an uncompressed public key.
    return (len(text) >= 20 and text[0] == 'S'
            and all(ord(c) in __b58chars for c in text)
            and sha256(text + '?')[0] == 0x00)

def minikey_to_private_key(text):
    return sha256(text)


def msg_magic(message):
    length = bfh(var_int(len(message)))
    return b"\x18Bitcoin Signed Message:\n" + length + message


def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]


def ECC_YfromX(x,curved=curve_secp256k1, odd=True):
    _p = curved.p()
    _a = curved.a()
    _b = curved.b()
    for offset in range(128):
        Mx = x + offset
        My2 = pow(Mx, 3, _p) + _a * pow(Mx, 2, _p) + _b % _p
        My = pow(My2, (_p+1)//4, _p )

        if curved.contains_point(Mx,My):
            if odd == bool(My&1):
                return [My,offset]
            return [_p-My,offset]
    raise Exception('ECC_YfromX: No Y found')


def negative_point(P):
    return Point( P.curve(), P.x(), -P.y(), P.order() )


def point_to_ser(P, comp=True ):
    if comp:
        return bfh( ('%02x'%(2+(P.y()&1)))+('%064x'%P.x()) )
    return bfh( '04'+('%064x'%P.x())+('%064x'%P.y()) )


def ser_to_point(Aser):
    curve = curve_secp256k1
    generator = generator_secp256k1
    _r  = generator.order()
    assert Aser[0] in [0x02, 0x03, 0x04]
    if Aser[0] == 0x04:
        return Point( curve, string_to_number(Aser[1:33]), string_to_number(Aser[33:]), _r )
    Mx = string_to_number(Aser[1:])
    return Point( curve, Mx, ECC_YfromX(Mx, curve, Aser[0] == 0x03)[0], _r )


class MyVerifyingKey(ecdsa.VerifyingKey):
    @classmethod
    def from_signature(klass, sig, recid, h, curve):
        """ See http://www.secg.org/download/aid-780/sec1-v2.pdf, chapter 4.1.6 """
        from ecdsa import util, numbertheory
        from . import msqr
        curveFp = curve.curve
        G = curve.generator
        order = G.order()
        # extract r,s from signature
        r, s = util.sigdecode_string(sig, order)
        # 1.1
        x = r + (recid//2) * order
        # 1.3
        alpha = ( x * x * x  + curveFp.a() * x + curveFp.b() ) % curveFp.p()
        beta = msqr.modular_sqrt(alpha, curveFp.p())
        y = beta if (beta - recid) % 2 == 0 else curveFp.p() - beta
        # 1.4 the constructor checks that nR is at infinity
        R = Point(curveFp, x, y, order)
        # 1.5 compute e from message:
        e = string_to_number(h)
        minus_e = -e % order
        # 1.6 compute Q = r^-1 (sR - eG)
        inv_r = numbertheory.inverse_mod(r,order)
        Q = inv_r * ( s * R + minus_e * G )
        return klass.from_public_point( Q, curve )


def pubkey_from_signature(sig, h):
    if len(sig) != 65:
        raise Exception("Wrong encoding")
    nV = sig[0]
    if nV < 27 or nV >= 35:
        raise Exception("Bad encoding")
    if nV >= 31:
        compressed = True
        nV -= 4
    else:
        compressed = False
    recid = nV - 27
    return MyVerifyingKey.from_signature(sig[1:], recid, h, curve = SECP256k1), compressed
