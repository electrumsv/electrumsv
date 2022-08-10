# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
# Copyright (C) 2019 Neil Booth
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
import dataclasses
import enum
from io import BytesIO
import struct
from struct import error as struct_error
from typing import Any, Callable, cast, Generator, Protocol, Sequence, TYPE_CHECKING, TypeVar

import attr
from bitcoinx import (
    Address, bip32_key_from_string, BIP32PublicKey, classify_output_script,
    der_signature_to_compact, double_sha256, hash160, hash_to_hex_str, InvalidSignature,
    Ops, P2PK_Output, P2SH_Address, pack_byte, pack_le_int32, pack_le_uint32, pack_list,
    PrivateKey, PublicKey, push_int, push_item, read_le_int32, read_le_int64, read_le_uint32,
    read_varint, Script, SigHash, Tx, TxInput, TxOutput, varint_len
)

from .bitcoin import ScriptTemplate
from .constants import DerivationPath, MULTI_SIGNER_SCRIPT_TYPES, ScriptType, \
    SINGLE_SIGNER_SCRIPT_TYPES
from .logs import logs
from .networks import Net
from .script import AccumulatorMultiSigOutput
from .types import DatabaseKeyDerivationData, FeeQuoteCommon, FeeQuoteTypeFee, \
    ServerAndCredential, TransactionSize, Outpoint


if TYPE_CHECKING:
    from .wallet import AbstractAccount


class SupportsToBytes(Protocol):
    def to_bytes(self) -> bytes:
       ...


NO_SIGNATURE = b'\xff'
dummy_public_key = PublicKey.from_bytes(bytes(range(3, 36)))
dummy_signature = bytes(72)

logger = logs.get_logger("transaction")


class TxSerialisationFormat(enum.IntEnum):
    RAW = 0
    HEX = 1
    JSON = 2
    JSON_WITH_PROOFS = 3


TxFileExtensions = {
    TxSerialisationFormat.RAW: "txn",
    TxSerialisationFormat.HEX: "txt",
    TxSerialisationFormat.JSON: "json",
    TxSerialisationFormat.JSON_WITH_PROOFS: "json",
}

TxSerialisedType = bytes | str | dict[str, Any]
ReadBytesFunc = Callable[[int], bytes]
TellFunc = Callable[[], int]
T = TypeVar('T')

# Duplicated and extended from the bitcoinx implementation.
def xread_list(read: ReadBytesFunc, tell: TellFunc,
        read_one: Callable[[ReadBytesFunc, TellFunc], T]) -> list[T]:
    '''Return a list of items.

    Each item is read with read_one, the stream begins with a count of the items.'''
    return [read_one(read, tell) for _ in range(read_varint(read))]

# Reimplemented from bitcoinx, to take the tell argument and return the offset.
def xread_varbytes(read: ReadBytesFunc, tell: TellFunc) -> tuple[bytes, int]:
    n = read_varint(read)
    offset = tell()
    result = read(n)
    if len(result) != n:
        raise struct_error(f'varbytes requires a buffer of {n:,d} bytes')
    return result, offset



def classify_tx_output(tx_output: TxOutput) -> ScriptTemplate:
    # This returns a P2PKH_Address, P2SH_Address, P2PK_Output, OP_RETURN_Output,
    # P2MultiSig_Output or Unknown_Output
    return classify_output_script(tx_output.script_pubkey, Net.COIN)


def script_to_display_text(script: Script, kind: ScriptTemplate) -> str:
    if isinstance(kind, Address):
        text = kind.to_string()
    elif isinstance(kind, P2PK_Output):
        text = kind.public_key.to_hex()
    else:
        text = script.to_asm(False)
    return cast(str, text)

def tx_output_to_display_text(tx_output: TxOutput) -> tuple[str, ScriptTemplate]:
    kind = classify_tx_output(tx_output)
    text = script_to_display_text(tx_output.script_pubkey, kind)
    return text, kind


HardwareSigningMetadata = dict[bytes, tuple[DerivationPath, tuple[str], int]]

@dataclasses.dataclass
class TransactionContext:
    invoice_id: int | None = dataclasses.field(default=None)
    account_descriptions: dict[int, str] = dataclasses.field(default_factory=dict)
    parent_transactions: dict[bytes, 'Transaction'] = dataclasses.field(default_factory=dict)
    hardware_signing_metadata: list[HardwareSigningMetadata] \
        = dataclasses.field(default_factory=list)
    spent_outpoint_values: dict[Outpoint, int] = dataclasses.field(default_factory=dict)
    key_datas_by_spent_outpoint: dict[Outpoint, DatabaseKeyDerivationData] \
        = dataclasses.field(default_factory=dict)
    key_datas_by_txo_index: dict[int, DatabaseKeyDerivationData] \
        = dataclasses.field(default_factory=dict)
    mapi_server_hint: ServerAndCredential | None = dataclasses.field(default=None)



class XPublicKeyKind(enum.IntEnum):
    UNKNOWN = 0
    OLD = 1
    BIP32 = 2
    PRIVATE_KEY = 3


class XPublicKey:
    """
    This is responsible for keeping the abstracted form of the public key, where relevant
    so that signing can reconcile where the public key comes from. It applies to three types of
    keystore, imported private keys, BIP32 and the old style.

    The derivation data fields for `masterkey_id`, `keyinstance_id` and `account_id` are only
    present when the associated transaction inputs and outputs are present in an incomplete
    transaction. In any other context, this metadata is not there. The exception is the
    derivation path, which is not directly coupled to the database unlike the id fields.
    """

    _old_mpk: bytes|None = None
    _bip32_xpub: str|None = None
    _pubkey_bytes: bytes|None = None
    # Logic should know when this field has populated id fields and when it does not. This is
    # addressed in the class docstring above. If the public key is a master public key, then this
    # field will have a value and only `derivation_path` will be provided externally.
    _derivation_data: DatabaseKeyDerivationData|None = None
    _keystore_fingerprint: bytes|None = None

    def __init__(self, pubkey_bytes: bytes|None=None, bip32_xpub: str|None=None,
            old_mpk: bytes|None=None, derivation_data: DatabaseKeyDerivationData|None=None,
            keystore_fingerprint: bytes|None=None) -> None:
        self._keystore_fingerprint = keystore_fingerprint

        if pubkey_bytes is not None:
            assert isinstance(pubkey_bytes, bytes)
            self._pubkey_bytes = pubkey_bytes
        elif bip32_xpub is not None:
            assert isinstance(bip32_xpub, str)
            self._bip32_xpub = bip32_xpub
            assert isinstance(derivation_data, DatabaseKeyDerivationData)
            self._derivation_data = derivation_data
        elif old_mpk is not None:
            assert isinstance(old_mpk, bytes)
            self._old_mpk = old_mpk
            assert isinstance(derivation_data, DatabaseKeyDerivationData)
            self._derivation_data = derivation_data
        else:
            raise NotImplementedError

    @classmethod
    def from_bytes(cls, raw: bytes) -> XPublicKey:
        assert raw[0] in {0x02, 0x03, 0x04}
        return cls(pubkey_bytes=raw)

    @classmethod
    def from_hex(cls, text: str) -> XPublicKey:
        return cls.from_bytes(bytes.fromhex(text))

    def to_bytes(self) -> bytes:
        return cast(bytes, self.to_public_key().to_bytes(compressed=True))

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, XPublicKey) and self._pubkey_bytes == other._pubkey_bytes and
            self._old_mpk == other._old_mpk and self._bip32_xpub == other._bip32_xpub and
            ((self._derivation_data is None and other._derivation_data is None) or
                (self._derivation_data is not None and other._derivation_data is not None and \
                    self._derivation_data.derivation_path == \
                        other._derivation_data.derivation_path)))

    def __hash__(self) -> int:
        # This just needs to be unique for dictionary indexing.
        return hash((self._pubkey_bytes, self._old_mpk, self._bip32_xpub,
            None if self._derivation_data is None else self._derivation_data.derivation_path))

    def kind(self) -> XPublicKeyKind:
        if self._bip32_xpub is not None:
            return XPublicKeyKind.BIP32
        elif self._old_mpk is not None:
            return XPublicKeyKind.OLD
        elif self._pubkey_bytes is not None:
            return XPublicKeyKind.PRIVATE_KEY
        return XPublicKeyKind.UNKNOWN

    def get_keystore_fingerprint(self) -> bytes|None:
        return self._keystore_fingerprint

    def get_derivation_data(self) -> DatabaseKeyDerivationData|None:
        return self._derivation_data

    @property
    def derivation_data(self) -> DatabaseKeyDerivationData:
        assert self._derivation_data is not None
        return self._derivation_data

    @property
    def derivation_path(self) -> DerivationPath:
        assert self._derivation_data is not None
        assert self._derivation_data.derivation_path is not None
        return self._derivation_data.derivation_path

    def is_bip32_key(self) -> bool:
        return self._bip32_xpub is not None

    def bip32_extended_key(self) -> str:
        assert self._bip32_xpub is not None
        return self._bip32_xpub

    def bip32_path(self) -> DerivationPath:
        assert self._bip32_xpub is not None
        assert self._derivation_data is not None
        assert self._derivation_data.derivation_path is not None
        return self._derivation_data.derivation_path

    def bip32_extended_key_and_path(self) -> tuple[str, DerivationPath]:
        assert self._bip32_xpub is not None
        assert self._derivation_data is not None
        assert self._derivation_data.derivation_path is not None
        return self._bip32_xpub, self._derivation_data.derivation_path

    def old_keystore_mpk_and_path(self) -> tuple[bytes, DerivationPath]:
        assert self._old_mpk is not None
        assert self._derivation_data is not None
        assert self._derivation_data.derivation_path is not None
        return self._old_mpk, self._derivation_data.derivation_path

    def to_public_key(self) -> BIP32PublicKey | PublicKey:
        '''Returns either a bitcoinx BIP32PublicKey or PublicKey instance.'''
        if self._pubkey_bytes is not None:
            return PublicKey.from_bytes(self._pubkey_bytes)
        elif self._bip32_xpub is not None:
            assert self._derivation_data is not None
            assert self._derivation_data.derivation_path is not None
            result = cast(BIP32PublicKey, bip32_key_from_string(self._bip32_xpub))
            for n in self._derivation_data.derivation_path:
                result = result.child(n)
            return result
        elif self._old_mpk is not None:
            assert self._derivation_data is not None
            assert self._derivation_data.derivation_path is not None
            path = self._derivation_data.derivation_path
            pubkey = PublicKey.from_bytes(pack_byte(4) + self._old_mpk)
            # pylint: disable=unsubscriptable-object
            delta = double_sha256(f'{path[1]}:{path[0]}:'.encode() + self._old_mpk)
            return pubkey.add(delta)
        raise ValueError("invalid key data")

    def to_public_key_bytes(self) -> bytes:
        assert self._pubkey_bytes is not None
        return self._pubkey_bytes

    def to_address(self) -> Address:
        return self.to_public_key().to_address(network=Net.COIN)

    def is_compressed(self) -> bool:
        if self._bip32_xpub:
            return True
        # pylint: disable=unsubscriptable-object
        if self._pubkey_bytes is not None and self._pubkey_bytes[0] != 0x04:
            return True
        return False

    def __repr__(self) -> str:
        return (f"XPublicKey(xpub={self._bip32_xpub!r}, old_mpk={self._old_mpk!r}), "
            f"derivation_data={self._derivation_data!r}, "
            f"pubkey={self._pubkey_bytes.hex() if self._pubkey_bytes is not None else None!r}")


# NOTE(typing) Disable the 'Class cannot subclass "Tx" (has type "Any")' message.
@attr.s(slots=True, repr=False)
class XTxInput(TxInput): # type: ignore[misc]
    '''An extended bitcoin transaction input.'''
    value: int | None = attr.ib(default=None)
    x_pubkeys: dict[bytes, XPublicKey] = attr.ib(default=attr.Factory(dict[bytes, XPublicKey]))
    threshold: int = attr.ib(default=0)
    signatures: dict[bytes, bytes] = attr.ib(default=attr.Factory(dict[bytes, bytes]))
    script_type: ScriptType = attr.ib(default=ScriptType.NONE)

    # Parsing metadata that we store in the database for easy script access.
    # TODO(script-offset-length) work out if this can be obtained without storing it on the class.
    #   It does not really belong here.
    script_offset: int = attr.ib(default=0)
    script_length: int = attr.ib(default=0)

    @classmethod
    def read(cls, read: ReadBytesFunc, tell: TellFunc) -> 'XTxInput':
        prev_hash = read(32)
        prev_idx = read_le_uint32(read)
        script_sig_bytes, script_sig_offset = xread_varbytes(read, tell)
        script_sig = Script(script_sig_bytes)
        sequence = read_le_uint32(read)

        # NOTE(rt12) workaround for mypy not recognising the base class init arguments.
        return cls(prev_hash, prev_idx, script_sig, sequence, # type: ignore[arg-type]
            script_offset=script_sig_offset, script_length=len(script_sig_bytes))

    def to_bytes(self) -> bytes:
        # NOTE(typing) I have no idea what is going on with this.
        #     Cannot determine type of "script_sig"  [has-type]
        existing_script_sig = cast(Script, self.script_sig) # type: ignore[has-type]
        if self.is_complete():
            assert len(existing_script_sig) > 0
        else:
            assert existing_script_sig == b""
            assert len(self.x_pubkeys) > 0
        return cast(bytes, super().to_bytes())

    def finalize_if_complete(self) -> None:
        # NOTE(typing) I have no idea what is going on with this.
        #     Cannot determine type of "script_sig"  [has-type]
        assert self.script_sig == b"" # type: ignore[has-type]
        if self.is_complete():
            script_sig = create_script_sig(self.script_type, self.threshold, self.x_pubkeys,
                self.signatures)
            assert script_sig is not None
            # NOTE(typing) Trying to assign name "script_sig" that is not in "__slots__" of type
            #     "electrumsv.transaction.XTxInput"  [misc]
            self.script_sig = script_sig # type: ignore[misc]

    def signatures_present(self) -> list[bytes]:
        '''Return a list of all signatures that are present.'''
        return list(self.signatures.values())

    def is_complete(self) -> bool:
        '''Return true if this input has all signatures present.'''
        if len(self.signatures) == 0 and len(self.x_pubkeys) == 0:
            return True
        return len(self.signatures_present()) >= self.threshold

    def unused_x_pubkeys(self) -> list[XPublicKey]:
        if self.is_complete():
            return []
        return [ x_pubkey for public_key_bytes, x_pubkey in self.x_pubkeys.items() if
            public_key_bytes not in self.signatures ]

    def estimated_size(self) -> TransactionSize:
        '''Return an estimated of serialized input size in bytes.'''
        # We substitute in signatures of a kind of realistic size. With high r and high s values
        # the size us 73 bytes. In reality with low s enforced because of "malleability hysteria"
        # the actual size would be 71 or 72 bytes.
        dummy_signature = bytearray(73)
        signature_by_key: dict[bytes, bytes] = {
            public_key_bytes: dummy_signature if public_key_bytes not in self.signatures else \
                self.signatures[public_key_bytes] for public_key_bytes in list(self.x_pubkeys) }
        script_sig = create_script_sig(self.script_type, self.threshold, self.x_pubkeys,
            signature_by_key)
        assert script_sig is not None
        saved_script_sig = self.script_sig
        self.script_sig = script_sig
        try:
            size = self.size()
        finally:
            self.script_sig = saved_script_sig
        return TransactionSize(size, 0)

    def size(self) -> int:
        return len(TxInput.to_bytes(self))

    def type(self) -> ScriptType:
        if self.is_coinbase():
            return ScriptType.COINBASE
        return self.script_type

    def __repr__(self) -> str:
        return (
            f'XTxInput(prev_hash="{hash_to_hex_str(self.prev_hash)}", prev_idx={self.prev_idx}, '
            f'script_sig="{self.script_sig}", sequence={self.sequence}), value={self.value}, '
            f'threshold={self.threshold}, script_type={self.script_type}, '
            f'x_pubkeys={self.x_pubkeys}), signatures={self.signatures}, '
            f'script_length={self.script_length}, script_offset={self.script_offset}'
        )


# NOTE(typing) Disable the 'Class cannot subclass "Tx" (has type "Any")' message.
@attr.s(slots=True, repr=False)
class XTxOutput(TxOutput): # type: ignore[misc]
    """
    An extended Bitcoin transaction output.

    This primarily adds information required to construct the output script. But it also includes
    spending key data if applicable, and the relevant transaction outputs are owned by a account
    in the wallet.
    """
    # Used for constructing output scripts.
    # Exchanged in incomplete transactions as useful metadata.
    script_type: ScriptType = attr.ib(default=ScriptType.NONE)
    x_pubkeys: dict[bytes, XPublicKey] = attr.ib(default=attr.Factory(dict[bytes, XPublicKey]))

    # Parsing metadata that we store in the database for easy script access.
    # TODO(script-offset-length) work out if this can be obtained without storing it on the class.
    #   It does not really belong here.
    script_offset: int = attr.ib(default=0)
    script_length: int = attr.ib(default=0)

    @classmethod
    def read(cls, read: ReadBytesFunc, tell: TellFunc) -> XTxOutput:
        value = read_le_int64(read)
        script_pubkey_bytes, script_pubkey_offset = xread_varbytes(read, tell)
        script_pubkey = Script(script_pubkey_bytes)
        return cls(value, script_pubkey,
            script_offset=script_pubkey_offset,
            script_length=len(script_pubkey_bytes))

    def estimated_size(self) -> TransactionSize:
        # 8               <value>
        # 1-9             <script size>
        # <script size>   <script bytes>
        script_bytes = self.script_pubkey.to_bytes()
        standard_size = 8 + varint_len(len(script_bytes))
        data_size = 0
        if script_bytes.startswith(DATA_PREFIX1) or script_bytes.startswith(DATA_PREFIX2):
            data_size += len(script_bytes)
        else:
            standard_size += len(script_bytes)
        return TransactionSize(standard_size, data_size)

    def __repr__(self) -> str:
        return (
            f'XTxOutput(value={self.value}, script_pubkey="{self.script_pubkey}", '
            f'script_type={self.script_type}, x_pubkeys={self.x_pubkeys}, '
            f'script_length={self.script_length} script_offset={self.script_offset})'
        )


def _script_GetOp(_bytes: bytes) -> Generator[tuple[int, bytes | None, int], None, None]:
    i = 0
    blen = len(_bytes)
    while i < blen:
        vch = None
        opcode = _bytes[i]
        i += 1

        if opcode <= Ops.OP_PUSHDATA4:
            nSize = opcode
            if opcode == Ops.OP_PUSHDATA1:
                nSize = _bytes[i] if i < blen else 0
                i += 1
            elif opcode == Ops.OP_PUSHDATA2:
                # tolerate truncated script
                (nSize,) = struct.unpack_from('<H', _bytes, i) if i+2 <= blen else (0,)
                i += 2
            elif opcode == Ops.OP_PUSHDATA4:
                (nSize,) = struct.unpack_from('<I', _bytes, i) if i+4 <= blen else (0,)
                i += 4
            # array slicing here never throws exception even if truncated script
            vch = _bytes[i:i + nSize]
            i += nSize

        yield opcode, vch, i


def _match_decoded(decoded: list[tuple[int, bytes | None, int]],
        to_match: list[int | Ops]) -> bool:
    if len(decoded) != len(to_match):
        return False
    for i in range(len(decoded)):
        # Ops below OP_PUSHDATA4 all just push data
        if (to_match[i] == Ops.OP_PUSHDATA4 and
                decoded[i][0] <= Ops.OP_PUSHDATA4 and decoded[i][0] > 0):
            continue
        if to_match[i] != decoded[i][0]:
            return False
    return True


def _extract_multisig_pattern(decoded: list[tuple[int, bytes | None, int]]) \
        -> tuple[int, int, list[int | Ops]]:
    m = decoded[0][0] - Ops.OP_1 + 1
    n = decoded[-2][0] - Ops.OP_1 + 1
    op_m = Ops.OP_1 + m - 1
    op_n = Ops.OP_1 + n - 1
    l: list[int | Ops] = [ op_m, *[Ops.OP_PUSHDATA4]*n, op_n, Ops.OP_CHECKMULTISIG ]
    return m, n, l


def to_bare_multisig_script_bytes(public_key_bytes_list: Sequence[bytes], threshold: int) -> bytes:
    assert 1 <= threshold <= len(public_key_bytes_list)
    parts = [push_int(threshold)]
    parts.extend(push_item(public_key_bytes) for public_key_bytes in public_key_bytes_list)
    parts.append(push_int(len(public_key_bytes_list)))
    parts.append(pack_byte(Ops.OP_CHECKMULTISIG))
    return b''.join(parts)


def create_script_sig(script_type: ScriptType, threshold: int,
        x_pubkeys: dict[bytes, XPublicKey], signature_by_key: dict[bytes, bytes],
        ordered_public_key_bytes: Sequence[bytes]|None=None) -> Script | None:
    # This should not be called unless we know of all the required signing keys.
    assert len(x_pubkeys) >= threshold
    if len(signature_by_key) < threshold:
        return None

    public_keys_bytes = list(signature_by_key)
    if script_type in SINGLE_SIGNER_SCRIPT_TYPES:
        if script_type == ScriptType.P2PK:
            assert len(public_keys_bytes) == 1
            public_key_bytes = public_keys_bytes[0]
            assert public_key_bytes in x_pubkeys
            return Script(push_item(signature_by_key[public_key_bytes]))
        elif script_type == ScriptType.P2PKH:
            assert len(public_keys_bytes) == 1
            public_key_bytes = public_keys_bytes[0]
            assert public_key_bytes in x_pubkeys
            return Script(push_item(signature_by_key[public_key_bytes]) +
                push_item(x_pubkeys[public_key_bytes].to_bytes()))
    elif script_type in MULTI_SIGNER_SCRIPT_TYPES:
        if script_type in (ScriptType.MULTISIG_P2SH, ScriptType.MULTISIG_BARE):
            signature_entries = list(signature_by_key.items())
            # Place the signatures in an order determined by the public key bytes.
            signature_entries = sorted(signature_entries[:threshold])

            if script_type == ScriptType.MULTISIG_P2SH:
                parts = [pack_byte(Ops.OP_0)]
                parts.extend(push_item(signature_bytes)
                    for public_key_bytes, signature_bytes in signature_entries)
                nested_script = to_bare_multisig_script_bytes([ public_key_bytes
                    for public_key_bytes, signature_bytes in signature_entries ], threshold)
                parts.append(push_item(nested_script))
                return Script(b''.join(parts))
            elif script_type == ScriptType.MULTISIG_BARE:
                parts = [pack_byte(Ops.OP_0)]
                parts.extend(push_item(signature_bytes)
                    for public_key_bytes, signature_bytes in signature_entries)
                return Script(b''.join(parts))
        elif script_type == ScriptType.MULTISIG_ACCUMULATOR:
            # These signatures must be in order, in this case we rely on insertion order.
            assert ordered_public_key_bytes is not None
            parts = []
            for public_key_bytes in ordered_public_key_bytes:
                if public_key_bytes in signature_by_key:
                    parts.append([
                        push_item(signature_by_key[public_key_bytes]),
                        push_item(public_key_bytes),
                        pack_byte(Ops.OP_TRUE),
                    ])
                else:
                    parts.append([ pack_byte(Ops.OP_FALSE) ])
            parts.reverse()
            return Script(b''.join([ value for l in parts for value in l ]))
    raise ValueError(f"unable to realize script {script_type}")


@dataclasses.dataclass
class ScriptSigData:
    signatures: dict[bytes, bytes] = dataclasses.field(default_factory=dict)
    threshold: int = dataclasses.field(default=0)
    x_pubkeys: dict[bytes, XPublicKey] = dataclasses.field(default_factory=dict)
    script_type: ScriptType = dataclasses.field(default=ScriptType.NONE)
    address: Address|None = dataclasses.field(default=None)


def parse_script_sig(script: bytes, to_x_public_key: Callable[[bytes], XPublicKey], *,
        signature_placeholder: bytes|None = None) -> ScriptSigData:
    """
    What we can identify just using the script signature is P2PKH and P2SH. It is probably a given
    that we will have the spent output and it's script to work with.
    """
    try:
        decoded = list(_script_GetOp(script))
    except Exception:
        # coinbase transactions raise an exception
        logger.exception("cannot find address in input script %s", script.hex())
        return ScriptSigData()

    x_pubkeys: dict[bytes, XPublicKey] = {}
    signatures: dict[bytes, bytes] = {}

    match: list[int|Ops]
    # P2PK
    # match = [ Ops.OP_PUSHDATA4 ]
    # if _match_decoded(decoded, match):
    #     signature_bytes = cast(bytes, decoded[0][1])
    #     return ScriptSigData(script_type=ScriptType.P2PK, threshold=1,
    #         signatures=[ signature_bytes ])

    # P2PKH inputs push a signature (around seventy bytes) and then their public key
    # (65 bytes) onto the stack
    match = [ Ops.OP_PUSHDATA4, Ops.OP_PUSHDATA4 ]
    if _match_decoded(decoded, match):
        signature_bytes = cast(bytes, decoded[0][1])
        public_key_bytes = decoded[1][1]
        assert public_key_bytes is not None
        x_public_key = to_x_public_key(public_key_bytes)
        x_pubkeys = { public_key_bytes: x_public_key }
        if signature_bytes != signature_placeholder:
            signatures[public_key_bytes] = signature_bytes
        return ScriptSigData(script_type=ScriptType.P2PKH, threshold=1,
            signatures=signatures, x_pubkeys=x_pubkeys, address=x_public_key.to_address())

    # p2sh transaction, m of n
    match = [ Ops.OP_0, *[ Ops.OP_PUSHDATA4 ] * (len(decoded) - 1) ]
    if not _match_decoded(decoded, match):
        logger.error("cannot find address in input script %s", script.hex())
        return ScriptSigData()

    nested_script = decoded[-1][1]
    assert nested_script is not None
    nested_decoded = [ x for x in _script_GetOp(nested_script) ]
    nested_decoded_inner = cast(list[tuple[int, bytes, int]], nested_decoded[1:-2])
    ordered_x_public_keys = [ to_x_public_key(x[1]) for x in nested_decoded_inner ]
    public_key_bytes_list = [ x_pubkey.to_bytes() for x_pubkey in ordered_x_public_keys ]

    m, n, match_multisig = _extract_multisig_pattern(nested_decoded)
    if not _match_decoded(nested_decoded, match_multisig):
        logger.error("cannot find address in input script %s", script.hex())
        return ScriptSigData()

    ordered_signature_bytes = [ cast(bytes, x[1]) for x in decoded[1:-1] ]
    assert len(ordered_x_public_keys) == len(ordered_signature_bytes)

    for order_index, public_key_bytes in enumerate(public_key_bytes_list):
        x_pubkeys[public_key_bytes] = ordered_x_public_keys[order_index]
        if ordered_signature_bytes[order_index] != signature_placeholder:
            signatures[public_key_bytes] = ordered_signature_bytes[order_index]
    return ScriptSigData(script_type=ScriptType.MULTISIG_P2SH, threshold=m, x_pubkeys=x_pubkeys,
        address=P2SH_Address(hash160(to_bare_multisig_script_bytes(public_key_bytes_list, m)),
        Net.COIN), signatures=signatures)


def tx_dict_from_text(text: str) -> dict[str, Any]:
    """
    Takes json or hexadecimal, returns a dictionary.

    Raises `ValueError` if the text is not valid.
    """
    import json
    text = text.strip()
    if not text:
        raise ValueError("empty string")

    try:
        bytes.fromhex(text)
    except ValueError:
        pass
    else:
        return { "hex": text }

    tx_dict = cast(dict[str, Any], json.loads(text))
    if "hex" not in tx_dict:
        raise ValueError("invalid transaction format")
    return tx_dict


DATA_PREFIX1 = bytes.fromhex("6a")
DATA_PREFIX2 = bytes.fromhex("006a")


# NOTE(typing) Disable the 'Class cannot subclass "Tx" (has type "Any")' message.
@attr.s(slots=True)
class Transaction(Tx): # type: ignore[misc]
    SIGHASH_FORKID = 0x40

    inputs: list[XTxInput] = attr.ib(default=attr.Factory(list))
    outputs: list[XTxOutput] = attr.ib(default=attr.Factory(list))

    @classmethod
    def from_io(cls, inputs: list[XTxInput], outputs: list[XTxOutput], locktime: int=0) \
            -> "Transaction":
        # NOTE(typing) Until the base class is fully typed it's attrs won't be found properly.
        return cls(version=1, locktime=locktime, # type: ignore[call-arg]
            inputs=inputs, outputs=outputs.copy())

    @classmethod
    def read(cls, read: Callable[[int], bytes], tell: Callable[[], int]) -> 'Transaction':
        '''Overridden to specialize reading the inputs.'''
        # NOTE(typing) Until the base class is fully typed it's attrs won't be found properly.
        return cls(
            version=read_le_int32(read), # type: ignore[call-arg]
            inputs=xread_list(read, tell, XTxInput.read),
            outputs=xread_list(read, tell, XTxOutput.read),
            locktime=read_le_uint32(read),
        )

    def to_bytes(self) -> bytes:
        # If the transaction is complete this should produce the expected transaction.
        # If the transaction is incomplete this will produce transaction with empty input scripts.
        return b''.join((
            pack_le_int32(self.version),
            pack_list(self.inputs, XTxInput.to_bytes),
            pack_list(self.outputs, XTxOutput.to_bytes),
            pack_le_uint32(self.locktime),
        ))

    @classmethod
    def from_bytes(cls, raw: bytes) -> Transaction:
        stream = BytesIO(raw)
        return cls.read(stream.read, stream.tell)

    def __str__(self) -> str:
        return self.serialize()

    def update_script_offsets(self) -> None:
        """Amend inputs and outputs in-situ to include script_offset and script_length data"""
        assert self.is_complete(), "script_offset can only be calculated from a signed transaction"
        tx_with_offsets = Transaction.from_bytes(self.to_bytes())
        for index, input in enumerate(tx_with_offsets.inputs):
            self.inputs[index].script_offset = input.script_offset
            self.inputs[index].script_length = input.script_length

        for index, output in enumerate(tx_with_offsets.outputs):
            self.outputs[index].script_offset = output.script_offset
            self.outputs[index].script_length = output.script_length

    def is_complete(self) -> bool:
        '''Return true if this input has all signatures present.'''
        return all(txin.is_complete() for txin in self.inputs)

    def update_signatures(self, signatures: list[bytes]) -> None:
        """Add new signatures to a transaction

        `signatures` is expected to be a list of binary sigs with signatures[i]
        intended for self.inputs[i], without the SIGHASH appended.

        NOTE: This is only used by hardware device code.
        """
        if self.is_complete():
            return
        if len(self.inputs) != len(signatures):
            raise RuntimeError('expected {} signatures; got {}'
                               .format(len(self.inputs), len(signatures)))
        txin: XTxInput
        signature: bytes
        for txin, signature in zip(self.inputs, signatures):
            full_sig = signature + bytes([self.nHashType()])
            if full_sig in txin.signatures.values():
                continue
            public_key_bytes_list = list(txin.x_pubkeys)
            pre_hash = self.preimage_hash(txin)
            rec_sig_base = der_signature_to_compact(signature)
            for recid in range(4):
                rec_sig = rec_sig_base + bytes([recid])
                try:
                    public_key = PublicKey.from_recoverable_signature(rec_sig, pre_hash, None)
                except (InvalidSignature, ValueError):
                    # the point might not be on the curve for some recid values
                    continue
                public_key_bytes = public_key.to_bytes(compressed=True)
                if public_key_bytes in public_key_bytes_list:
                    try:
                        public_key.verify_recoverable_signature(rec_sig, pre_hash, None)
                    except Exception:
                        logger.exception('')
                        continue
                    logger.debug('adding sig %s %r', public_key, full_sig)
                    txin.signatures[public_key_bytes] = full_sig
                    break
            txin.finalize_if_complete()

    @classmethod
    def get_preimage_script_bytes(cls, txin: XTxInput) -> bytes:
        _type = txin.type()
        if _type == ScriptType.P2PKH:
            assert len(txin.x_pubkeys) == 1
            public_key = PublicKey.from_bytes(list(txin.x_pubkeys)[0])
            return cast(bytes, public_key.P2PKH_script().to_bytes())
        elif _type == ScriptType.MULTISIG_P2SH or _type == ScriptType.MULTISIG_BARE:
            public_key_bytes_list = sorted(txin.x_pubkeys)
            return to_bare_multisig_script_bytes(public_key_bytes_list, txin.threshold)
        elif _type == ScriptType.MULTISIG_ACCUMULATOR:
            public_key_bytes_list = sorted(txin.x_pubkeys)
            output = AccumulatorMultiSigOutput(public_key_bytes_list, txin.threshold)
            return output.to_script_bytes()
        elif _type == ScriptType.P2PK:
            assert len(txin.x_pubkeys) == 1
            public_key = PublicKey.from_bytes(list(txin.x_pubkeys)[0])
            script = public_key.P2PK_script()
            return cast(bytes, script.to_bytes())
        else:
            raise RuntimeError('Unknown txin type', _type)

    def BIP_LI01_sort(self) -> None:
        # See https://github.com/kristovatlas/rfc/blob/master/bips/bip-li01.mediawiki
        self.inputs.sort(key = lambda txin: cast(bytes, txin.prevout_bytes()))
        self.outputs.sort(key = lambda output: (output.value, output.script_pubkey.to_bytes()))

    @classmethod
    def nHashType(cls) -> int:
        '''Hash type in hex.'''
        return 0x01 | cls.SIGHASH_FORKID

    def preimage_hash(self, txin: XTxInput) -> bytes:
        input_index = self.inputs.index(txin)
        script_code = self.get_preimage_script_bytes(txin)
        sighash = SigHash(self.nHashType())
        # Original BTC algorithm: https://en.bitcoin.it/wiki/OP_CHECKSIG
        # Current algorithm: https://github.com/electrumsv/bips/blob/master/bip-0143.mediawiki
        return cast(bytes,
            self.signature_hash(input_index, txin.value, script_code, sighash=sighash))

    def serialize(self) -> str:
        return self.to_bytes().hex()

    def txid(self) -> str | None:
        '''A hexadecimal string if complete, otherwise None.'''
        if self.is_complete():
            return cast(str, hash_to_hex_str(self.hash()))
        return None

    def input_value(self) -> int:
        """
        Get the total value of all the outputs spent to fund this transaction.

        Raises `ValueError` if we do not have the parent transaction metadata for input values.
        """
        input_value = 0
        for transaction_input in self.inputs:
            # In order to know the value of an input you have to have the parent transaction.
            if transaction_input.value is None:
                raise ValueError("Missing")
            input_value += transaction_input.value
        return input_value

    def output_value(self) -> int:
        return sum(output.value for output in self.outputs)

    def get_fee(self) -> int:
        """
        Calculate the fee value paid for this transaction to be mined. Be aware that we may not
        be able to calculate this if we do not have the parent transactions.

        Raises `ValueError` if we do not have the parent transaction metadata for input values.
        """
        return self.input_value() - self.output_value()

    def size(self) -> int:
        if self.is_complete():
            return len(self.to_bytes())
        return sum(self.estimated_size())

    def base_size(self) -> int:
        return 10

    def estimated_size(self) -> TransactionSize:
        '''Return an estimated tx size in bytes.'''
        is_complete = self.is_complete()
        # 4                 <version>
        # 1-9               <input count>
        # <input i size>    <input>
        # 1-9               <output count>
        # <output i size>   <output>
        # 4                 <locktime>
        standard_size = 4 + varint_len(len(self.inputs)) + varint_len(len(self.outputs)) + 4
        data_size = 0
        estimated_total_size = TransactionSize(standard_size, data_size)
        for input in self.inputs:
            if is_complete:
                estimated_total_size += TransactionSize(input.size(), 0)
            else:
                estimated_total_size += input.estimated_size()
        for output in self.outputs:
            estimated_total_size += output.estimated_size()
        return estimated_total_size

    def signature_count(self) -> tuple[int, int]:
        r = 0
        s = 0
        for txin in self.inputs:
            signatures = txin.signatures_present()
            s += len(signatures)
            r += txin.threshold
        return s, r

    def sign(self, keypairs: dict[XPublicKey, PrivateKey]) -> None:
        assert all(isinstance(key, XPublicKey) for key in keypairs)
        for txin in self.inputs:
            if txin.is_complete():
                continue
            for public_key_bytes, x_pubkey in sorted(txin.x_pubkeys.items()):
                if x_pubkey in keypairs:
                    logger.debug("adding signature for %s", x_pubkey)
                    txin.signatures[public_key_bytes] = self._sign_txin(txin, keypairs[x_pubkey])
            txin.finalize_if_complete()
        logger.debug("is_complete %s", self.is_complete())

    def _sign_txin(self, txin: XTxInput, private_key: PrivateKey) -> bytes:
        pre_hash = self.preimage_hash(txin)
        sig = cast(bytes, private_key.sign(pre_hash, None))
        return sig + cast(bytes, pack_byte(self.nHashType()))

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    def to_format(self, format: TxSerialisationFormat, context: TransactionContext,
            accounts: list[AbstractAccount]) \
            -> TxSerialisedType:
        # Will raise `NotImplementedError` on incomplete implementation of new formats.
        if format == TxSerialisationFormat.RAW:
            return self.to_bytes()
        elif format == TxSerialisationFormat.HEX:
            return self.to_hex()
        elif format in (TxSerialisationFormat.JSON, TxSerialisationFormat.JSON_WITH_PROOFS):
            # It is expected the caller may wish to extend this and they will take care of the
            # final serialisation step.
            # TODO(1.4.0) PSBT. Replace.
            from .standards.electrum_transaction_extended import transaction_to_electrumsv_dict
            return transaction_to_electrumsv_dict(self, context, accounts)
        raise NotImplementedError(f"unhanded format {format}")


class TransactionFeeEstimator:
    standard_fee_satoshis = 0
    standard_fee_bytes = 0
    data_fee_satoshis = 0
    data_fee_bytes = 0

    def __init__(self, fee_quote: FeeQuoteCommon,
            mapi_server_hint: ServerAndCredential | None=None) -> None:
        self._mapi_server_hint = mapi_server_hint

        standard_fee: FeeQuoteTypeFee | None = None
        data_fee: FeeQuoteTypeFee | None = None
        for fee in fee_quote["fees"]:
            if fee["feeType"] == "standard":
                standard_fee = fee["miningFee"]
            elif fee["feeType"] == "data":
                data_fee = fee["miningFee"]

        assert standard_fee is not None
        self.standard_fee_satoshis = standard_fee["satoshis"]
        self.standard_fee_bytes = standard_fee["bytes"]
        if data_fee is not None:
            self.data_fee_satoshis = data_fee["satoshis"]
            self.data_fee_bytes = data_fee["bytes"]

    def get_mapi_server_hint(self) -> ServerAndCredential | None:
        return self._mapi_server_hint

    def estimate_fee(self, transaction_size: TransactionSize) -> int:
        fee = 0
        standard_size = transaction_size.standard_size
        if self.data_fee_bytes:
            standard_size = transaction_size.standard_size
            fee += transaction_size.data_size * self.data_fee_satoshis // self.data_fee_bytes
        else:
            standard_size += transaction_size.data_size
        fee += standard_size * self.standard_fee_satoshis // self.standard_fee_bytes
        return fee
