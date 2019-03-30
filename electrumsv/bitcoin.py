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

from bitcoinx import Ops, PublicKey, base58_decode_check

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

############ functions from pywallet #####################

def hash160_to_b58_address(h160, addrtype):
    s = bytes([addrtype])
    s += h160
    return base_encode(s + sha256d(s)[0:4], base=58)


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


SCRIPT_TYPES = {
    'p2pkh':0,
    'p2sh':5,
}


def verify_message_and_address(signature, message, address):
    return PublicKey.verify_message_and_address(signature, message, address, coin=Net.COIN)


def deserialize_privkey(key):
    # whether the pubkey is compressed should be visible from the keystore
    if is_minikey(key):
        return 'p2pkh', minikey_to_private_key(key), False
    vch = base58_decode_check(key)
    if vch:
        txin_type = inv_dict(SCRIPT_TYPES)[vch[0] - Net.WIF_PREFIX]
        assert len(vch) in [33, 34]
        compressed = len(vch) == 34
        return txin_type, vch[1:33], compressed
    else:
        raise Exception("cannot deserialize", key)


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
