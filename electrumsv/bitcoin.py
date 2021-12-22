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

from __future__ import annotations
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from io import BufferedIOBase, BytesIO
from typing import cast, Generator, Optional, Tuple, Union

from bitcoinx import double_sha256, hash_to_hex_str, sha256, Address, classify_output_script, \
    OP_RETURN_Output, P2MultiSig_Output, P2PK_Output, P2PKH_Address, P2SH_Address, \
    pack_varint, read_varint, Script, Unknown_Output, unpack_header

from .bip276 import bip276_decode, bip276_encode, PREFIX_BIP276_SCRIPT
from .networks import Net

################################## transactions

COINBASE_MATURITY = 100
COIN = 100000000

############ functions from pywallet #####################

__b43chars = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:'
assert len(__b43chars) == 43


def base_encode(v: bytes, base: int) -> str:
    """ encode v, which is a string of bytes, to base58."""
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

############## start bitcoinx related functions ######################

from typing import List, TYPE_CHECKING

from bitcoinx import DisabledOpcode, InterpreterState, OpReturnError, Ops, pack_byte, \
    ScriptTooLarge, TruncatedScriptError, TxInputContext, UnbalancedConditional, \
    unpack_le_uint16, unpack_le_uint32
from bitcoinx.limited_stack import LimitedStack
from bitcoinx.script import (OP_1, OP_16, OP_1NEGATE, # pylint: disable=no-name-in-module
    OP_CODESEPARATOR, OP_ENDIF, OP_IF, # pylint: disable=no-name-in-module
    OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_RESERVED, # pylint: disable=no-name-in-module
    OP_RETURN) # pylint: disable=no-name-in-module

if TYPE_CHECKING:
    from bitcoinx import InterpreterLimits
    from bitcoinx.interpreter import Condition


# NOTE(typing) Untyped base class 'Class cannot subclass .. has type Any'
class CustomLimitedStack(LimitedStack): # type: ignore
    # This is provided so that type checking works for the inheriting class.
    def __init__(self, size_limit: int) -> None: # pylint: disable=useless-super-delegation
        super().__init__(size_limit)

    def make_child_stack(self) -> CustomLimitedStack:
        result = self.__class__(0)
        result.parent = self
        return result

    def make_copy(self) -> CustomLimitedStack:
        assert self.parent is None
        result = self.__class__(self.size_limit)
        result._size = self._size
        result._items = self._items.copy()
        return result


@dataclass
class ScriptMatch:
    op: int
    data: Optional[bytes]
    data_offset: Optional[int]
    data_length: Optional[int]
    code_separator: Optional[int]


def generate_matches(raw: bytes) -> Generator[ScriptMatch, None, None]:
    '''A generator.  Iterates over the script yielding (op, item) pairs, stopping when the end
    of the script is reached.

    op is an integer as it might not be a member of Ops.  Data is the data pushed as
    bytes, or None if the op does not push data.

    Raises TruncatedScriptError if the script was truncated.
    '''
    limit = len(raw)
    n = 0
    last_code_separator_offset = 0

    while n < limit:
        op = raw[n]
        n += 1
        data = None
        data_offset = None
        data_length = None

        if op <= OP_16:
            if op <= OP_PUSHDATA4:
                try:
                    if op < OP_PUSHDATA1:
                        dlen = op
                    elif op == OP_PUSHDATA1:
                        dlen = raw[n]
                        n += 1
                    elif op == OP_PUSHDATA2:
                        dlen, = unpack_le_uint16(raw[n: n + 2])
                        n += 2
                    else:
                        dlen, = unpack_le_uint32(raw[n: n + 4])
                        n += 4
                    data = raw[n: n + dlen]
                    n += dlen
                    assert len(data) == dlen
                except Exception:
                    raise TruncatedScriptError from None
            elif op >= OP_1:
                data = pack_byte(op - OP_1 + 1)
            elif op == OP_1NEGATE:
                data = b'\x81'
            else:
                assert op == OP_RESERVED

        if op == OP_CODESEPARATOR:
            last_code_separator_offset = n

        yield ScriptMatch(op, data, data_offset, data_length, last_code_separator_offset)


class NotReallyAnIterator:
    current_match: Optional[ScriptMatch] = None

    def __init__(self, script: Script) -> None:
        self._raw = bytes(script)

    def on_code_separator(self) -> None:
        '''Call when an OP_CODESEPARATOR is executed.'''
        # This is now tracked in `generate_matches`. The iterator is not in sync with execution.
        pass
        # self._cs = self._n

    def script_code(self) -> Script:
        '''Return the subscript that should be checked by OP_CHECKSIG et al.'''
        assert self.current_match is not None and self.current_match.code_separator is not None
        return Script(self._raw[self.current_match.code_separator:])


# NOTE(typing) Untyped base class 'Class cannot subclass .. has type Any'
class CustomInterpreterState(InterpreterState): # type: ignore
    STACK_CLS = CustomLimitedStack

    def __init__(self, limits: InterpreterLimits,
            tx_context: Optional[TxInputContext]=None) -> None:
        super().__init__(limits, tx_context)

        # This overrides the default way `InterpreterState` works.
        self.stack = self.STACK_CLS(self.limits.stack_memory_usage)
        self.alt_stack = self.stack.make_child_stack()

    def begin_evaluate_script(self, script: Script) -> None:
        if len(script) > self.limits.script_size:
            raise ScriptTooLarge(f'script length {len(script):,d} exceeds the limit of '
                                 f'{self.limits.script_size:,d} bytes')

        self.conditions: List[Condition] = []
        self.op_count = 0
        self.iterator = NotReallyAnIterator(script)
        self.non_top_level_return_after_genesis = False

    def step_evaluate_script(self, match: ScriptMatch) -> bool:
        # Check pushitem size first
        if match.data is not None:
            self.limits.validate_item_size(len(match.data))

        self.execute = (all(condition.execute for condition in self.conditions)
                        and (not self.non_top_level_return_after_genesis or match.op == OP_RETURN))

        # Pushitem and OP_RESERVED do not count towards op count.
        if match.op > OP_16:
            self.bump_op_count(1)

        # Some op codes are disabled.  For pre-genesis UTXOs these were an error in
        # unevaluated branches; for post-genesis UTXOs only if evaluated.
        if match.op in {Ops.OP_2MUL, Ops.OP_2DIV} and (self.execute or
                                                    not self.limits.is_utxo_after_genesis):
            raise DisabledOpcode(f'{Ops(match.op).name} is disabled')

        if self.execute and match.data is not None:
            self.limits.validate_minimal_push_opcode(match.op, match.data)
            self.stack.append(match.data)
        elif self.execute or OP_IF <= match.op <= OP_ENDIF:
            self.iterator.current_match = match
            try:
                self._handlers[match.op](self)
            except OpReturnError:
                if not self.limits.is_utxo_after_genesis:
                    raise
                # A top-level post-geneis OP_RETURN terminates successfully, ignoring
                # the rest of the script even in the presence of unbalanced IFs,
                # invalid opcodes etc.  Otherwise the grammar is checked.
                if not self.conditions:
                    return False
                self.non_top_level_return_after_genesis = True

        self.validate_stack_size()
        return True

    def end_evaluate_script(self) -> None:
        if self.conditions:
            raise UnbalancedConditional(f'unterminated {self.conditions[-1].opcode.name} '
                                        'at end of script')


############## end bitcoinx related functions ########################
############## start TSC standard related functions ##################

# See: https://tsc.bitcoinassociation.net/standards/merkle-proof-standardised-format/

class ProofTransactionFlags(IntFlag):
    TRANSACTION_HASH    = 0
    FULL_TRANSACTION    = 1 << 0
    MASK                = TRANSACTION_HASH | FULL_TRANSACTION

class ProofTargetFlags(IntFlag):
    BLOCK_HASH          = 0
    BLOCK_HEADER        = 1 << 1
    MERKLE_ROOT         = 1 << 2
    MASK                = BLOCK_HASH | BLOCK_HEADER | MERKLE_ROOT

class ProofTypeFlags(IntFlag):
    MERKLE_BRANCH       = 0
    MERKLE_TREE         = 1 << 3
    MASK                = MERKLE_BRANCH | MERKLE_TREE

class ProofCountFlags(IntFlag):
    SINGLE              = 0
    MULTIPLE            = 1 << 4
    MASK                = SINGLE | MULTIPLE

FLAG_MASK = ProofTransactionFlags.MASK | ProofTargetFlags.MASK | ProofTypeFlags.MASK | \
    ProofCountFlags.MASK


@dataclass
class TSCMerkleNode:
    type: int
    value_bytes: bytes = b''
    value_int: int = 0


class TSCMerkleNodeKind(IntEnum):
    HASH                = 0
    DUPLICATE           = 1
    INDEX               = 2


class TSCMerkleProofError(Exception):
    pass


def validate_proof_flags(flags: int) -> None:
    invalid_flags = flags & ~FLAG_MASK
    if invalid_flags:
        raise TSCMerkleProofError(f"Unexpected flags {invalid_flags:x}")

    if flags & ProofCountFlags.MASK != ProofCountFlags.SINGLE:
        raise TSCMerkleProofError("Proofs can currently only be singular")

    if flags & ProofTypeFlags.MASK != ProofTypeFlags.MERKLE_BRANCH:
        raise TSCMerkleProofError("Proofs can currently only be merkle branches")


def verify_proof(proof: TSCMerkleProof, expected_merkle_root_bytes: Optional[bytes]=None) -> bool:
    transaction_hash = proof.transaction_hash
    if transaction_hash is None:
        transaction_hash = double_sha256(proof.transaction_bytes)

    if proof.flags & ProofTargetFlags.MASK == ProofTargetFlags.BLOCK_HEADER:
        assert expected_merkle_root_bytes is None
        assert proof.block_header_bytes is not None
        try:
            _version, _prev_hash, expected_merkle_root_bytes, _timestamp, _bits, _nonce = \
                unpack_header(proof.block_header_bytes)
        except ValueError:
            raise TSCMerkleProofError("Invalid block header")
    elif proof.flags & ProofTargetFlags.MASK == ProofTargetFlags.MERKLE_ROOT:
        assert expected_merkle_root_bytes is None
        expected_merkle_root_bytes = proof.merkle_root_bytes
    else:
        # If the proof has a block hash, the caller needs to look up that header and get the
        # expected merkle root and provide it to us.
        assert expected_merkle_root_bytes is not None

    if len(proof.nodes) == 0:
        return transaction_hash == expected_merkle_root_bytes

    transaction_index = proof.transaction_index
    c = transaction_hash
    p: bytes
    for node in proof.nodes:
        c_is_left = transaction_index % 2 == 0

        if node.type == TSCMerkleNodeKind.HASH:
            p = node.value_bytes
        elif node.type == TSCMerkleNodeKind.DUPLICATE:
            if not c_is_left:
                raise TSCMerkleProofError("Duplicate node cannot be on right")
            p = c
        else:
            raise TSCMerkleProofError(f"Unsupported node type {node.type}")

        if c_is_left:
            c = double_sha256(c + p)
        else:
            c = double_sha256(p + c)

        transaction_index //= 2

    return c == expected_merkle_root_bytes


@dataclass
class TSCMerkleProof:
    flags: int
    transaction_index: int
    transaction_hash: Optional[bytes] = None
    transaction_bytes: Optional[bytes] = None
    block_hash: Optional[bytes] = None
    block_header_bytes: Optional[bytes] = None
    merkle_root_bytes: Optional[bytes] = None
    nodes: List[TSCMerkleNode] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, proof_bytes: bytes) -> TSCMerkleProof:
        stream = BytesIO(proof_bytes)
        return cls.from_stream(stream)

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> TSCMerkleProof:
        flags = ord(stream.read(1))
        validate_proof_flags(flags)

        transaction_index = read_varint(stream.read)
        transaction_hash: Optional[bytes] = None
        transaction_bytes: Optional[bytes] = None
        block_hash: Optional[bytes] = None
        block_header_bytes: Optional[bytes] = None
        merkle_root_bytes: Optional[bytes] = None

        if flags & ProofTransactionFlags.MASK == ProofTransactionFlags.TRANSACTION_HASH:
            # The serialised form is the transaction id (which is the reversed hash).
            transaction_hash = stream.read(32)
        else:
            transaction_length = read_varint(stream.read)
            if transaction_length == 0:
                raise TSCMerkleProofError("Embedded transaction length is zero")
            # TODO This will need a different model if we are ever dealing with really large
            #      transactions.
            transaction_bytes = stream.read(transaction_length)

        if flags & ProofTargetFlags.MASK == ProofTargetFlags.BLOCK_HEADER:
            block_header_bytes = stream.read(80)
        elif flags & ProofTargetFlags.MASK == ProofTargetFlags.MERKLE_ROOT:
            merkle_root_bytes = stream.read(32)
        else:
            block_hash = stream.read(32)

        node_count = read_varint(stream.read)
        nodes: List[TSCMerkleNode] = []
        for i in range(node_count):
            node_type = ord(stream.read(1))
            value_bytes = b''
            value_int = 0
            if node_type == TSCMerkleNodeKind.HASH:
                value_bytes = stream.read(32)
            elif node_type == TSCMerkleNodeKind.DUPLICATE:
                pass
            elif node_type == TSCMerkleNodeKind.INDEX:
                value_int = read_varint(stream.read)
            nodes.append(TSCMerkleNode(node_type, value_bytes, value_int))

        return cls(flags, transaction_index, transaction_hash, transaction_bytes, block_hash,
            block_header_bytes, merkle_root_bytes, nodes)

    def to_bytes(self) -> bytes:
        validate_proof_flags(self.flags)

        stream = BytesIO()
        stream.write(self.flags.to_bytes(1, 'little'))
        stream.write(pack_varint(self.transaction_index))

        if self.flags & ProofTransactionFlags.MASK == ProofTransactionFlags.FULL_TRANSACTION:
            if self.transaction_bytes is None:
                raise TSCMerkleProofError("No transaction bytes for embedded transaction")
            stream.write(pack_varint(len(self.transaction_bytes)))
            stream.write(self.transaction_bytes)
        else:
            if self.transaction_hash is None:
                raise TSCMerkleProofError("Expected transaction hash, was not set")
            stream.write(self.transaction_hash)

        if self.flags & ProofTargetFlags.MASK == ProofTargetFlags.BLOCK_HEADER:
            if self.block_header_bytes is None:
                raise TSCMerkleProofError("Expected block header bytes, was not set")
            stream.write(self.block_header_bytes)
        elif self.flags & ProofTargetFlags.MASK == ProofTargetFlags.MERKLE_ROOT:
            if self.merkle_root_bytes is None:
                raise TSCMerkleProofError("Expected merkle root bytes, was not set")
            stream.write(self.merkle_root_bytes)
        else:
            if self.block_hash is None:
                raise TSCMerkleProofError("Expected block hash, was not set")
            stream.write(self.block_hash)

        stream.write(pack_varint(len(self.nodes)))
        for node in self.nodes:
            stream.write(node.type.to_bytes(1, 'little'))
            if node.type == TSCMerkleNodeKind.HASH:
                stream.write(node.value_bytes)
            elif node.type == TSCMerkleNodeKind.DUPLICATE:
                pass
            elif node.type == TSCMerkleNodeKind.INDEX:
                stream.write(pack_varint(node.value_int))

        return stream.getvalue()


# TODO unit test this.
def separate_proof_and_embedded_transaction(proof_bytes: bytes, expected_transaction_hash: bytes) \
        -> Tuple[bytes, TSCMerkleProof]:
    proof = TSCMerkleProof.from_bytes(proof_bytes)

    transaction_bytes = proof.transaction_bytes
    assert transaction_bytes is not None
    transaction_hash = double_sha256(transaction_bytes)
    assert expected_transaction_hash == transaction_hash
    proof.transaction_bytes = None
    proof.transaction_hash = transaction_hash
    proof.flags &= ProofTransactionFlags.MASK
    proof.flags |= ProofTransactionFlags.TRANSACTION_HASH

    return transaction_bytes, proof


############## end TSC standard related functions ##################
