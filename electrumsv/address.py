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
import struct

from bitcoinx import Ops, PublicKey, base58_decode_check, base58_encode_check, hash_to_hex_str

from . import cashaddr
from .crypto import hash_160, sha256
from .networks import Net


class AddressError(Exception):
    '''Exception used for Address errors.'''

class ScriptError(Exception):
    '''Exception used for Script errors.'''


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
        script = bytearray()
        for word in string.split():
            if word.startswith('OP_'):
                try:
                    opcode = Ops[word]
                except KeyError:
                    raise AddressError(f'unknown opcode "{word}"') from None
                script.append(opcode)
            else:
                script.extend(Script.push_data(bytes.fromhex(word)))
        return ScriptOutput(bytes(script))

    def to_string(self):
        '''Convert to user-readable OP-codes (plus pushdata as text if possible)
        eg OP_RETURN (12) "Hello there!"
        '''
        try:
            ops = Script.get_ops(self.script)
        except ScriptError:
            # Truncated script -- so just default to hex string.
            return self.script.hex()

        def lookup(n):
            try:
                return Ops(n).name
            except ValueError:
                return f'({n})'

        parts = []
        for op in ops:
            if isinstance(op, tuple):
                op, data = op
                if data is None:
                    data = b''

                # Attempt to make a friendly string, or fail to hex
                try:
                    astext = data.decode('utf8')

                    friendlystring = repr(astext)

                    # if too many escaped characters, it's too ugly!
                    if friendlystring.count('\\')*3 > len(astext):
                        friendlystring = None
                except Exception:
                    friendlystring = None

                if not friendlystring:
                    friendlystring = data.hex()

                parts.append(lookup(op) + " " + friendlystring)
            else:
                parts.append(lookup(op))
        return ', '.join(parts)

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
            script.extend(Script.push_data(data_bytes))
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

    def to_string(self):
        '''Converts to a string of the given format.'''
        if self.kind == self.ADDR_P2PKH:
            verbyte = Net.ADDRTYPE_P2PKH
        else:
            verbyte = Net.ADDRTYPE_P2SH

        return base58_encode_check(bytes([verbyte]) + self.hash160)

    def to_script(self):
        '''Return a binary script to pay to the address.'''
        if self.kind == self.ADDR_P2PKH:
            return Script.P2PKH_script(self.hash160)
        else:
            return Script.P2SH_script(self.hash160)

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


def _match_ops(ops, pattern):
    if len(ops) != len(pattern):
        return False
    for op, pop in zip(ops, pattern):
        if pop != op:
            # -1 means 'data push', whose op is an (op, data) tuple
            if pop == -1 and isinstance(op, tuple):
                continue
            return False

    return True


class Script(object):

    @classmethod
    def P2SH_script(cls, hash160value):
        return (bytes([Ops.OP_HASH160])
                + cls.push_data(hash160value)
                + bytes([Ops.OP_EQUAL]))

    @classmethod
    def P2PKH_script(cls, hash160value):
        return (bytes([Ops.OP_DUP, Ops.OP_HASH160])
                + cls.push_data(hash160value)
                + bytes([Ops.OP_EQUALVERIFY, Ops.OP_CHECKSIG]))

    @classmethod
    def P2PK_script(cls, pubkey):
        return cls.push_data(pubkey) + bytes([Ops.OP_CHECKSIG])

    @classmethod
    def multisig_script(cls, m, pubkeys):
        '''Returns the script for a pay-to-multisig transaction.'''
        n = len(pubkeys)
        if not 1 <= m <= n <= 15:
            raise ScriptError('{:d} of {:d} multisig script not possible'
                              .format(m, n))
        for pubkey in pubkeys:
            PublicKey.from_bytes(pubkey)   # Can be compressed or not
        # See https://bitcoin.org/en/developer-guide
        # 2 of 3 is: OP_2 pubkey1 pubkey2 pubkey3 OP_3 OP_CHECKMULTISIG
        return (bytes([Ops.OP_1 + m - 1])
                + b''.join(cls.push_data(pubkey) for pubkey in pubkeys)
                + bytes([Ops.OP_1 + n - 1, Ops.OP_CHECKMULTISIG]))

    @classmethod
    def push_data(cls, data):
        '''Returns the Ops to push the data on the stack.'''
        assert isinstance(data, (bytes, bytearray))

        n = len(data)
        if n < Ops.OP_PUSHDATA1:
            return bytes([n]) + data
        if n < 256:
            return bytes([Ops.OP_PUSHDATA1, n]) + data
        if n < 65536:
            return bytes([Ops.OP_PUSHDATA2]) + struct.pack('<H', n) + data
        return bytes([Ops.OP_PUSHDATA4]) + struct.pack('<I', n) + data

    @classmethod
    def get_ops(cls, script):
        ops = []

        # The unpacks or script[n] below throw on truncated scripts
        try:
            n = 0
            while n < len(script):
                op = script[n]
                n += 1

                if op <= Ops.OP_PUSHDATA4:
                    # Raw bytes follow
                    if op < Ops.OP_PUSHDATA1:
                        dlen = op
                    elif op == Ops.OP_PUSHDATA1:
                        dlen = script[n]
                        n += 1
                    elif op == Ops.OP_PUSHDATA2:
                        dlen, = struct.unpack('<H', script[n: n + 2])
                        n += 2
                    else:
                        dlen, = struct.unpack('<I', script[n: n + 4])
                        n += 4
                    if n + dlen > len(script):
                        raise IndexError
                    op = (op, script[n:n + dlen])
                    n += dlen

                ops.append(op)
        except Exception:
            # Truncated script; e.g. tx_hash
            # ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767
            raise ScriptError('truncated script')

        return ops
