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
from dataclasses import dataclass
from typing import cast, Generator, Optional, Union

from bitcoinx import Address, hash_to_hex_str, classify_output_script, OP_RETURN_Output, \
    P2MultiSig_Output, P2PK_Output, P2PKH_Address, P2SH_Address, Script, sha256, Unknown_Output

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
