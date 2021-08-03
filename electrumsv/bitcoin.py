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

from typing import cast, Union

from bitcoinx import (hash_to_hex_str, sha256, Address, classify_output_script,
    OP_RETURN_Output, P2MultiSig_Output, P2PK_Output, P2PKH_Address, P2SH_Address,
    Script, Unknown_Output)

from .bip276 import bip276_decode, bip276_encode, PREFIX_BIP276_SCRIPT
from .networks import Net
from .util import assert_bytes

################################## transactions

COINBASE_MATURITY = 100
COIN = 100000000

############ functions from pywallet #####################

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43


def base_encode(v: bytes, base: int) -> str:
    """ encode v, which is a string of bytes, to base58."""
    assert_bytes(v)
    assert base == 43
    chars = __b43chars
    long_value: int = 0
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


def base_decode(value: str, base: int) -> bytes:
    """ decode v into a string of len bytes."""
    v = value.encode('ascii')
    assert base == 43
    chars = __b43chars
    long_value: int = 0
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
    result.reverse()
    return bytes(result)


########### end pywallet functions #######################

ScriptTemplate = Union[OP_RETURN_Output, P2MultiSig_Output, P2PK_Output, P2PKH_Address,
    P2SH_Address, Unknown_Output]

def script_template_to_string(template: ScriptTemplate, bip276: bool=False) -> str:
    if not bip276 and isinstance(template, Address):
        return cast(str, template.to_string())
    assert not isinstance(template, Unknown_Output)
    return bip276_encode(PREFIX_BIP276_SCRIPT, template.to_script_bytes(), Net.BIP276_VERSION)

def string_to_script_template(text: str) -> ScriptTemplate:
    # raises bip276.ChecksumMismatchError
    if text.startswith(PREFIX_BIP276_SCRIPT):
        prefix, version, network, data = bip276_decode(text, Net.BIP276_VERSION)
        assert network == Net.BIP276_VERSION, "incompatible network"
        return classify_output_script(Script(data), Net.COIN)
    return Address.from_string(text, Net.COIN)

def string_to_bip276_script(text: str) -> Script:
    if text.startswith(PREFIX_BIP276_SCRIPT):
        _prefix, _version, network, data = bip276_decode(text, Net.BIP276_VERSION)
        assert network == Net.BIP276_VERSION, "incompatible network"
        return Script(data)
    raise ValueError("string is not bip276")

def scripthash_bytes(script: Union[bytes, Script]) -> bytes:
    return cast(bytes, sha256(bytes(script)))

def scripthash_hex(item: Union[bytes, Script]) -> str:
    return cast(str, hash_to_hex_str(scripthash_bytes(item)))

def address_from_string(address: str) -> Address:
    return Address.from_string(address, Net.COIN)

def is_address_valid(address: str) -> bool:
    try:
        address_from_string(address)
        return True
    except ValueError:
        return False
