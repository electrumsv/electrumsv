# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2018 The ElectrumSV Developers
# Copyright (C) 2017 The Electron Cash Developers
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

# Many of the functions in this file are copied from ElectrumX

from collections import namedtuple

from bitcoinx import (
    Ops, PublicKey, base58_decode_check, base58_encode_check, hash_to_hex_str, cashaddr,
    push_item, Script, P2PKH_Address, P2SH_Address
)

from .crypto import hash_160, sha256
from .networks import Net


class AddressError(Exception):
    '''Exception used for Address errors.'''


# Utility functions

def to_bytes(x):
    '''Convert to bytes which is hashable.'''
    if isinstance(x, bytes):
        return x
    if isinstance(x, bytearray):
        return bytes(x)
    raise TypeError('{} is not bytes ({})'.format(x, type(x)))



class UnknownAddress(object):

    def to_string(self):
        return '<UnknownAddress>'

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return '<UnknownAddress>'


class ScriptOutput(namedtuple("ScriptAddressTuple", "script")):

    @classmethod
    def from_string(self, string):
        '''Instantiate from a mixture of opcodes and raw data.'''
        return Script.from_asm(string)

    def to_string(self):
        '''Convert to user-readable OP-codes (plus pushdata as text if possible)
        eg OP_RETURN (12) "Hello there!"
        '''
        return Script(self.script).to_asm()

    def to_script(self):
        return self.script

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return '<ScriptOutput {}>'.format(self.__str__())

    @classmethod
    def as_op_return(self, data_chunks):
        script = bytearray()
        script.append(Ops.OP_RETURN)
        for data_bytes in data_chunks:
            script.extend(push_item(data_bytes))
        return ScriptOutput(bytes(script))


# A namedtuple for easy comparison and unique hashing
class Address(namedtuple("AddressTuple", "hash160 kind")):

    # Address kinds
    ADDR_P2PKH = 0
    ADDR_P2SH = 1

    def __new__(cls, hash160value, kind):
        assert kind in (cls.ADDR_P2PKH, cls.ADDR_P2SH)
        hash160value = to_bytes(hash160value)
        assert len(hash160value) == 20
        return super().__new__(cls, hash160value, kind)

    @classmethod
    def from_cashaddr_string(cls, string):
        '''Construct from a cashaddress string.'''
        prefix = Net.CASHADDR_PREFIX
        if string.upper() == string:
            prefix = prefix.upper()
        if not string.startswith(prefix + ':'):
            string = ':'.join([prefix, string])
        addr_prefix, kind, addr_hash = cashaddr.decode(string)
        if addr_prefix != prefix:
            raise AddressError('address has unexpected prefix {}'
                               .format(addr_prefix))
        if kind == cashaddr.PUBKEY_TYPE:
            return cls(addr_hash, cls.ADDR_P2PKH)
        elif kind == cashaddr.SCRIPT_TYPE:
            return cls(addr_hash, cls.ADDR_P2SH)
        else:
            raise AddressError('address has unexpected kind {}'.format(kind))

    @classmethod
    def from_string(cls, string, net=Net):
        '''Construct from an address string.'''
        if len(string) > 35:
            try:
                return cls.from_cashaddr_string(string)
            except ValueError as e:
                raise AddressError(str(e))

        try:
            raw = base58_decode_check(string)
        except ValueError as e:
            raise AddressError(str(e))

        # Require version byte(s) plus hash160.
        if len(raw) != 21:
            raise AddressError('invalid address: {}'.format(string))

        verbyte, hash160_ = raw[0], raw[1:]
        if verbyte == net.ADDRTYPE_P2PKH:
            kind = cls.ADDR_P2PKH
        elif verbyte == net.ADDRTYPE_P2SH:
            kind = cls.ADDR_P2SH
        else:
            raise AddressError('unknown version byte: {}'.format(verbyte))

        return cls(hash160_, kind)

    @classmethod
    def is_valid(cls, string):
        try:
            cls.from_string(string)
            return True
        except Exception:
            return False

    @classmethod
    def from_strings(cls, strings):
        '''Construct a list from an iterable of strings.'''
        return [cls.from_string(string) for string in strings]

    @classmethod
    def from_pubkey(cls, pubkey):
        '''Returns a P2PKH address from a public key.  The public key can
        be bytes or a hex string.'''
        if isinstance(pubkey, str):
            pubkey = PublicKey.from_hex(pubkey)
        else:
            pubkey = PublicKey.from_bytes(pubkey)
        return cls(hash_160(pubkey.to_bytes()), cls.ADDR_P2PKH)

    @classmethod
    def from_P2PKH_hash(cls, hash160value):
        '''Construct from a P2PKH hash160.'''
        return cls(hash160value, cls.ADDR_P2PKH)

    @classmethod
    def from_P2SH_hash(cls, hash160value):
        '''Construct from a P2PKH hash160.'''
        return cls(hash160value, cls.ADDR_P2SH)

    @classmethod
    def from_multisig_script(cls, script):
        return cls(hash_160(script), cls.ADDR_P2SH)

    @classmethod
    def from_bytes(cls, raw: bytes) -> 'Address':
        verbyte, hash160_ = raw[0], raw[1:]
        if verbyte == Net.ADDRTYPE_P2PKH:
            kind = cls.ADDR_P2PKH
        elif verbyte == Net.ADDRTYPE_P2SH:
            kind = cls.ADDR_P2SH
        else:
            raise AddressError('unknown version byte: {}'.format(verbyte))

        return cls(hash160_, kind)

    def to_string(self) -> str:
        '''Converts to a string of the given format.'''
        if self.kind == self.ADDR_P2PKH:
            verbyte = Net.ADDRTYPE_P2PKH
        else:
            verbyte = Net.ADDRTYPE_P2SH

        return base58_encode_check(bytes([verbyte]) + self.hash160)

    def to_bytes(self) -> bytes:
        if self.kind == self.ADDR_P2PKH:
            verbyte = Net.ADDRTYPE_P2PKH
        else:
            verbyte = Net.ADDRTYPE_P2SH
        return bytes([ verbyte ]) + self.hash160

    def to_script(self):
        '''Return a binary script to pay to the address.'''
        if self.kind == self.ADDR_P2PKH:
            return P2PKH_Address(self.hash160).to_script_bytes()
        else:
            return P2SH_Address(self.hash160).to_script_bytes()

    def to_script_hex(self):
        '''Return a script to pay to the address as a hex string.'''
        return self.to_script().hex()

    def to_scripthash(self):
        '''Returns the hash of the script in binary.'''
        return sha256(self.to_script())

    def to_scripthash_hex(self):
        '''Like other bitcoin hashes this is reversed when written in hex.'''
        return hash_to_hex_str(self.to_scripthash())

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return '<Address {}>'.format(self.__str__())
