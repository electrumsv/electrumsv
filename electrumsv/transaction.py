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

import enum
from io import BytesIO
import struct
from struct import error as struct_error
from typing import Any, Callable, cast, Dict, Generator, List, Optional, Tuple, TypeVar, Union

import attr
from bitcoinx import (
    Address, base58_encode_check, bip32_key_from_string, BIP32PublicKey, classify_output_script,
    der_signature_to_compact, double_sha256, hash160, hash_to_hex_str, InvalidSignature,
    Ops, P2PK_Output, P2SH_Address, pack_byte, pack_le_int32, pack_le_uint32, pack_list,
    PrivateKey, PublicKey, push_int, push_item, read_le_int32, read_le_int64, read_le_uint32,
    read_varint, Script, SigHash, Tx, TxInput, TxOutput, unpack_le_uint16, varint_len
)

from .bitcoin import ScriptTemplate
from .constants import DerivationPath, ScriptType
from .logs import logs
from .networks import Net
from .script import AccumulatorMultiSigOutput
from .types import TransactionSize
from .wallet_database.types import KeyDataType

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

TxSerialisedType = Union[bytes, str, Dict[str, Any]]
ReadBytesFunc = Callable[[int], bytes]
TellFunc = Callable[[], int]
T = TypeVar('T')

# Duplicated and extended from the bitcoinx implementation.
def xread_list(read: ReadBytesFunc, tell: TellFunc,
        read_one: Callable[[ReadBytesFunc, TellFunc], T]) -> List[T]:
    '''Return a list of items.

    Each item is read with read_one, the stream begins with a count of the items.'''
    return [read_one(read, tell) for _ in range(read_varint(read))]

# Reimplemented from bitcoinx, to take the tell argument and return the offset.
def xread_varbytes(read: ReadBytesFunc, tell: TellFunc) -> Tuple[bytes, int]:
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

def tx_output_to_display_text(tx_output: TxOutput) -> Tuple[str, ScriptTemplate]:
    kind = classify_tx_output(tx_output)
    text = script_to_display_text(tx_output.script_pubkey, kind)
    return text, kind


@attr.s(slots=True, repr=True)
class TransactionContext:
    invoice_id: Optional[int] = attr.ib(default=None)
    description: Optional[str] = attr.ib(default=None)
    prev_txs: Dict[bytes, 'Transaction'] = attr.ib(default=attr.Factory(dict))


class XPublicKeyType(enum.IntEnum):
    UNKNOWN = 0
    OLD = 1
    BIP32 = 2
    PRIVATE_KEY = 3


class XPublicKey:
    """
    This is responsible for keeping the abstracted form of the public key, where relevant
    so that anything signing can reconcile where the public key comes from. It applies to
    three types of keystore, imported private keys, BIP32 and the old style.
    """

    _old_mpk: Optional[bytes] = None
    _bip32_xpub: Optional[str] = None
    _derivation_path: Optional[DerivationPath] = None
    _pubkey_bytes: Optional[bytes] = None

    def __init__(self, **kwargs: Any) -> None:
        if "pubkey_bytes" in kwargs:
            assert isinstance(kwargs["pubkey_bytes"], bytes)
            self._pubkey_bytes = kwargs["pubkey_bytes"]
        elif "bip32_xpub" in kwargs:
            assert isinstance(kwargs["bip32_xpub"], str)
            self._bip32_xpub = kwargs["bip32_xpub"]
            self._derivation_path = tuple(kwargs["derivation_path"])
        elif "old_mpk" in kwargs:
            assert isinstance(kwargs["old_mpk"], bytes)
            self._old_mpk = kwargs["old_mpk"]
            self._derivation_path = tuple(kwargs["derivation_path"])
        else:
            raise ValueError(f'invalid XPublicKey: {kwargs!r}')
        self.to_public_key()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'XPublicKey':
        kwargs = data.copy()
        if "pubkey_bytes" in kwargs:
            kwargs["pubkey_bytes"] = bytes.fromhex(kwargs["pubkey_bytes"])
        if "old_mpk" in kwargs:
            kwargs["old_mpk"] = bytes.fromhex(kwargs["old_mpk"])
        return cls(**kwargs)

    @classmethod
    def from_bytes(cls, raw: bytes) -> 'XPublicKey':
        """ In addition to importing public keys, we also support the legacy Electrum
        serialisation, except for the case of addresses. """
        kwargs: Dict[str, Any] = {}
        kind = raw[0]
        if kind in {0x02, 0x03, 0x04}:
            kwargs['pubkey_bytes'] = raw
        elif kind == 0xff:
            # 83 is 79 + 2 + 2.
            assert len(raw) == 83, f"got {len(raw)}"
            kwargs["bip32_xpub"] = base58_encode_check(raw[1:79])
            kwargs["derivation_path"] = tuple(unpack_le_uint16(raw[n: n+2])[0]
                for n in (79, 81))
        elif kind == 0xfe:
            assert len(raw) == 69
            kwargs["old_mpk"] = raw[1:65]  # The public key bytes without the 0x04 prefix
            kwargs["derivation_path"] = tuple(unpack_le_uint16(raw[n: n+2])[0] for n in (65, 67))
        else:
            kwargs["extended_kind"] = hex(raw[0])
        return cls(**kwargs)

    @classmethod
    def from_hex(cls, text: str) -> 'XPublicKey':
        raw = bytes.fromhex(text)
        return cls.from_bytes(raw)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self._pubkey_bytes is not None:
            d["pubkey_bytes"] = self._pubkey_bytes.hex()
        if self._old_mpk is not None:
            d["old_mpk"] = self._old_mpk.hex()
            d["derivation_path"] = self._derivation_path
        if self._bip32_xpub is not None:
            d["bip32_xpub"] = self._bip32_xpub
            d["derivation_path"] = self._derivation_path
        return d

    def to_bytes(self) -> bytes:
        return cast(bytes, self.to_public_key().to_bytes())

    def __eq__(self, other: object) -> bool:
        return (isinstance(other, XPublicKey) and self._pubkey_bytes == other._pubkey_bytes and
            self._old_mpk == other._old_mpk and self._bip32_xpub == other._bip32_xpub and
            self._derivation_path == other._derivation_path)

    def __hash__(self) -> int:
        # This just needs to be unique for dictionary indexing.
        return hash((self._pubkey_bytes, self._old_mpk, self._bip32_xpub, self._derivation_path))

    def kind(self) -> XPublicKeyType:
        if self._bip32_xpub is not None:
            return XPublicKeyType.BIP32
        elif self._old_mpk is not None:
            return XPublicKeyType.OLD
        elif self._pubkey_bytes is not None:
            return XPublicKeyType.PRIVATE_KEY
        return XPublicKeyType.UNKNOWN

    def derivation_path(self) -> DerivationPath:
        assert self._derivation_path is not None
        return self._derivation_path

    def is_bip32_key(self) -> bool:
        return self._bip32_xpub is not None

    def bip32_extended_key(self) -> str:
        assert self._bip32_xpub is not None
        return self._bip32_xpub

    def bip32_path(self) -> DerivationPath:
        assert self._bip32_xpub is not None and self._derivation_path is not None
        return self._derivation_path

    def bip32_extended_key_and_path(self) -> Tuple[str, DerivationPath]:
        assert self._bip32_xpub is not None and self._derivation_path is not None
        return self._bip32_xpub, self._derivation_path

    def old_keystore_mpk_and_path(self) -> Tuple[bytes, DerivationPath]:
        assert self._old_mpk is not None and self._derivation_path is not None
        return self._old_mpk, self._derivation_path

    def to_public_key(self) -> Union[BIP32PublicKey, PublicKey]:
        '''Returns a PublicKey instance or an Address instance.'''
        kind = self.kind()
        if self._pubkey_bytes is not None:
            return PublicKey.from_bytes(self._pubkey_bytes)
        elif self._bip32_xpub is not None:
            assert self._derivation_path is not None
            result = bip32_key_from_string(self._bip32_xpub)
            for n in self._derivation_path:
                result = result.child(n)
            return result
        elif self._old_mpk is not None:
            assert self._derivation_path is not None
            path = self._derivation_path
            pubkey = PublicKey.from_bytes(pack_byte(4) + self._old_mpk)
            # pylint: disable=unsubscriptable-object
            delta = double_sha256(f'{path[1]}:{path[0]}:'.encode() + self._old_mpk)
            return pubkey.add(delta)
        raise ValueError("invalid key data")

    def to_public_key_bytes(self) -> bytes:
        assert self._pubkey_bytes is not None
        return self._pubkey_bytes

    def to_address(self) -> Address:
        return self.to_public_key().to_address(coin=Net.COIN)

    def is_compressed(self) -> bool:
        if self._bip32_xpub:
            return True
        # pylint: disable=unsubscriptable-object
        if self._pubkey_bytes is not None and self._pubkey_bytes[0] != 0x04:
            return True
        return False

    def __repr__(self) -> str:
        return (f"XPublicKey(xpub={self._bip32_xpub!r}, old_mpk={self._old_mpk!r}), "
            f"path={self._derivation_path!r}, "
            f"pubkey={self._pubkey_bytes.hex() if self._pubkey_bytes is not None else None!r}")


# NOTE(typing) The bitcoinx base class does not have typing information, so we need to ignore that.
@attr.s(slots=True, repr=False)
class XTxInput(TxInput): # type: ignore
    '''An extended bitcoin transaction input.'''
    # Used for signing metadata for hardware wallets.
    # Exchanged in incomplete transactions to aid in comprehending unknown inputs.
    value: Optional[int] = attr.ib(default=None)
    x_pubkeys: List[XPublicKey] = attr.ib(default=attr.Factory(list))
    threshold: int = attr.ib(default=0)
    signatures: List[bytes] = attr.ib(default=attr.Factory(list))
    script_type: ScriptType = attr.ib(default=ScriptType.NONE)

    # Key data.
    key_data: Optional[KeyDataType] = attr.ib(default=None)

    # Parsing metadata that we store in the database for easy script access.
    # TODO(script-offset-length) work out if this can be obtained without storing it on the class.
    #   It does not really belong here.
    script_offset: int = attr.ib(default=0)
    script_length: int = attr.ib(default=0)

    @classmethod
    def read(cls, read: ReadBytesFunc, tell: TellFunc) -> 'XTxInput':
        # This section is duplicated in `XTxInput.read_extended`
        prev_hash = read(32)
        prev_idx = read_le_uint32(read)
        script_sig_bytes, script_sig_offset = xread_varbytes(read, tell)
        script_sig = Script(script_sig_bytes)
        sequence = read_le_uint32(read)

        assert script_sig_offset != 0
        assert len(script_sig_bytes) != 0

        # NOTE(rt12) workaround for mypy not recognising the base class init arguments.
        return cls(prev_hash, prev_idx, script_sig, sequence, # type: ignore
            script_offset=script_sig_offset, script_length=len(script_sig_bytes))

    @classmethod
    def read_extended(cls, read: ReadBytesFunc, tell: TellFunc) -> 'XTxInput':
        # This section is duplicated in `XTxInput.read`
        prev_hash = read(32)
        prev_idx = read_le_uint32(read)
        script_sig_bytes, script_sig_offset = xread_varbytes(read, tell)
        script_sig = Script(script_sig_bytes)
        sequence = read_le_uint32(read)

        kwargs = {
            'x_pubkeys': [],
            'threshold': 0,
            'signatures': [],
            'script_offset': script_sig_offset,
            'script_length': len(script_sig_bytes),
        }
        assert script_sig_offset != 0
        assert len(script_sig_bytes) != 0

        if prev_hash != bytes(32):
            parse_script_sig(script_sig_bytes, kwargs)
            # NOTE(rt12) Why do we delete this?
            if 'address' in kwargs:
                del kwargs['address']
        # NOTE(rt12) workaround for mypy not recognising the base class init arguments.
        result = cls(prev_hash, prev_idx, script_sig, sequence, # type: ignore
            value=None, **kwargs) # type: ignore
        if not result.is_complete():
            result.value = read_le_int64(read)
        return result

    def to_bytes(self) -> bytes:
        if self.x_pubkeys:
            self.script_sig = create_script_sig(self.script_type, self.threshold, self.x_pubkeys,
                self.signatures)
        return cast(bytes, super().to_bytes())

    def signatures_present(self) -> List[bytes]:
        '''Return a list of all signatures that are present.'''
        return [sig for sig in self.signatures if sig != NO_SIGNATURE]

    def is_complete(self) -> bool:
        '''Return true if this input has all signatures present.'''
        if not self.signatures:
            return True
        return len(self.signatures_present()) >= self.threshold

    def stripped_signatures_with_blanks(self) -> List[bytes]:
        '''Strips the sighash byte.'''
        return [b'' if sig == NO_SIGNATURE else sig[:-1] for sig in self.signatures]

    def unused_x_pubkeys(self) -> List[XPublicKey]:
        if self.is_complete():
            return []
        return [x_pubkey for x_pubkey, signature in zip(self.x_pubkeys, self.signatures)
                if signature == NO_SIGNATURE]

    def estimated_size(self) -> TransactionSize:
        '''Return an estimated of serialized input size in bytes.'''
        saved_script_sig = self.script_sig
        # TODO(MAPI) Should this be the raw x_pubkeys not the public keys? It does not matter
        #   as the `create_script_sig` method only calls `to_bytes`.
        x_pubkeys = [x_pubkey.to_public_key() for x_pubkey in self.x_pubkeys]
        signatures = [dummy_signature] * self.threshold
        self.script_sig = create_script_sig(self.script_type, self.threshold, x_pubkeys, signatures)
        size = self.size()
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
            f'threshold={self.threshold}, '
            f'script_type={self.script_type}, x_pubkeys={self.x_pubkeys}), '
            f'key_data={self.key_data}, script_length={self.script_length}, '
            f'script_offset={self.script_offset}'
        )


# NOTE(typing) The bitcoinx base class does not have typing information, so we need to ignore that.
@attr.s(slots=True, repr=False)
class XTxOutput(TxOutput): # type: ignore
    """
    An extended Bitcoin transaction output.

    This primarily adds information required to construct the output script. But it also includes
    spending key data if applicable, and the relevant transaction outputs are owned by a account
    in the wallet.
    """
    # Used for constructing output scripts.
    # Exchanged in incomplete transactions as useful metadata.
    script_type: ScriptType = attr.ib(default=ScriptType.NONE)
    x_pubkeys: List[XPublicKey] = attr.ib(default=attr.Factory(list))

    # Key data.
    key_data: Optional[KeyDataType] = attr.ib(default=None)

    # Parsing metadata that we store in the database for easy script access.
    # TODO(script-offset-length) work out if this can be obtained without storing it on the class.
    #   It does not really belong here.
    script_offset: int = attr.ib(default=0)
    script_length: int = attr.ib(default=0)

    @classmethod
    def read(cls, read: ReadBytesFunc, tell: TellFunc) -> 'XTxOutput':
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
            f'script_offset={self.script_offset}, script_length={self.script_length})'
        )


def _script_GetOp(_bytes: bytes) -> Generator[Tuple[int, Optional[bytes], int], None, None]:
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


def _match_decoded(decoded: List[Tuple[int, Optional[bytes], int]],
        to_match: List[Union[int, Ops]]) -> bool:
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


def _extract_multisig_pattern(decoded: List[Tuple[int, Optional[bytes], int]]) \
        -> Tuple[int, int, List[Union[int, Ops]]]:
    m = decoded[0][0] - Ops.OP_1 + 1
    n = decoded[-2][0] - Ops.OP_1 + 1
    op_m = Ops.OP_1 + m - 1
    op_n = Ops.OP_1 + n - 1
    l: List[Union[int, Ops]] = [ op_m, *[Ops.OP_PUSHDATA4]*n, op_n, Ops.OP_CHECKMULTISIG ]
    return m, n, l


def multisig_script(x_pubkeys: List[XPublicKey], threshold: int) -> bytes:
    '''Returns bytes.

    x_pubkeys is an array of XPulicKey objects or an array of PublicKey objects.
    '''
    assert 1 <= threshold <= len(x_pubkeys)
    parts = [push_int(threshold)]
    parts.extend(push_item(x_pubkey.to_bytes()) for x_pubkey in x_pubkeys)
    parts.append(push_int(len(x_pubkeys)))
    parts.append(pack_byte(Ops.OP_CHECKMULTISIG))
    return b''.join(parts)

def bare_multisignatures(threshold: int, signatures: List[bytes]) -> List[bytes]:
    '''
    Forms of bare multi-signature need to only provide a number of signatures meeting the
    threshold level. The signing protocol keeps track of the signature of each co-signer
    which usually counts more than the threshold. If there are not enough signatures it is
    padded out with NO_SIGNATURE entries to keep the script in correct structure, this only
    happens for incomplete transactions.
    '''
    present_signatures = [ value for value in signatures if value != NO_SIGNATURE ][:threshold]
    while len(present_signatures) < threshold:
        present_signatures.append(NO_SIGNATURE)
    return present_signatures


def create_script_sig(script_type: ScriptType, threshold: int, x_pubkeys: List[XPublicKey],
        signatures: List[bytes]) -> Script:
    if script_type == ScriptType.P2PK:
        return Script(push_item(signatures[0]))
    elif script_type == ScriptType.P2PKH:
        return Script(push_item(signatures[0]) + push_item(x_pubkeys[0].to_bytes()))
    elif script_type == ScriptType.MULTISIG_P2SH:
        prepared_signatures = bare_multisignatures(threshold, signatures)
        parts = [pack_byte(Ops.OP_0)]
        parts.extend(push_item(signature) for signature in prepared_signatures)
        nested_script = multisig_script(x_pubkeys, threshold)
        parts.append(push_item(nested_script))
        return Script(b''.join(parts))
    elif script_type == ScriptType.MULTISIG_BARE:
        prepared_signatures = bare_multisignatures(threshold, signatures)
        parts = [pack_byte(Ops.OP_0)]
        parts.extend(push_item(signature) for signature in prepared_signatures)
        return Script(b''.join(parts))
    elif script_type == ScriptType.MULTISIG_ACCUMULATOR:
        parts = []
        for i, signature in enumerate(signatures):
            if signature == NO_SIGNATURE:
                parts.append([ pack_byte(Ops.OP_FALSE) ])
            else:
                parts.append([
                    push_item(signature),
                    push_item(x_pubkeys[i].to_bytes()),
                    pack_byte(Ops.OP_TRUE),
                ])
        parts.reverse()
        return Script(b''.join([ value for l in parts for value in l ]))
    raise ValueError(f"unable to realize script {script_type}")


def parse_script_sig(script: bytes, kwargs: Dict[str, Any]) -> None:
    try:
        decoded = list(_script_GetOp(script))
    except Exception:
        # coinbase transactions raise an exception
        logger.exception("cannot find address in input script %s", script.hex())
        return

    match: List[Union[int, Ops]]
    # P2PK
    match = [ Ops.OP_PUSHDATA4 ]
    if _match_decoded(decoded, match):
        item = decoded[0][1]
        kwargs['signatures'] = [item]
        kwargs['threshold'] = 1
        kwargs['script_type'] = ScriptType.P2PK
        return

    # P2PKH inputs push a signature (around seventy bytes) and then their public key
    # (65 bytes) onto the stack
    match = [ Ops.OP_PUSHDATA4, Ops.OP_PUSHDATA4 ]
    if _match_decoded(decoded, match):
        sig = decoded[0][1]
        bytes_ = decoded[1][1]
        assert bytes_ is not None
        x_pubkey = XPublicKey.from_bytes(bytes_)
        kwargs['signatures'] = [sig]
        kwargs['threshold'] = 1
        kwargs['x_pubkeys'] = [x_pubkey]
        kwargs['script_type'] = ScriptType.P2PKH
        kwargs['address'] = x_pubkey.to_address()
        return

    # p2sh transaction, m of n
    match = [ Ops.OP_0, *[ Ops.OP_PUSHDATA4 ] * (len(decoded) - 1) ]
    if not _match_decoded(decoded, match):
        logger.error("cannot find address in input script %s", script.hex())
        return

    nested_script = decoded[-1][1]
    assert nested_script is not None
    nested_decoded = [ x for x in _script_GetOp(nested_script) ]
    nested_decoded_inner = cast(List[Tuple[int, bytes, int]], nested_decoded[1:-2])
    x_pubkeys = [XPublicKey.from_bytes(x[1]) for x in nested_decoded_inner]
    m, n, match_multisig = _extract_multisig_pattern(nested_decoded)
    if not _match_decoded(nested_decoded, match_multisig):
        logger.error("cannot find address in input script %s", script.hex())
        return
    kwargs['script_type'] = ScriptType.MULTISIG_P2SH
    kwargs['x_pubkeys'] = x_pubkeys
    kwargs['threshold'] = m
    kwargs['address'] = P2SH_Address(hash160(multisig_script(x_pubkeys, m)), Net.COIN)
    kwargs['signatures'] = [x[1] for x in decoded[1:-1]]
    return


def tx_dict_from_text(text: str) -> Dict[str, Any]:
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

    tx_dict = cast(Dict[str, Any], json.loads(text))
    if "hex" not in tx_dict:
        raise ValueError("invalid transaction format")
    return tx_dict


DATA_PREFIX1 = bytes.fromhex("6a")
DATA_PREFIX2 = bytes.fromhex("006a")


# NOTE(typing) The bitcoinx base class does not have typing information, so we need to ignore that.
@attr.s(slots=True)
class Transaction(Tx): # type: ignore
    output_info: Optional[List[Dict[bytes, Tuple[DerivationPath, Tuple[str], int]]]] \
        = attr.ib(default=None)
    context: TransactionContext = attr.ib(default=attr.Factory(TransactionContext))
    is_extended: bool = attr.ib(default=False)

    SIGHASH_FORKID = 0x40

    @classmethod
    def from_io(cls, inputs: List[XTxInput], outputs: List[XTxOutput], locktime: int=0) \
            -> "Transaction":
        # NOTE(typing) attrs-based subclass lacks typing
        return cls(version=1, inputs=inputs, outputs=outputs.copy(), # type: ignore
            locktime=locktime)

    @classmethod
    def read(cls, read: Callable[[int], bytes], tell: Callable[[], int]) -> 'Transaction':
        '''Overridden to specialize reading the inputs.'''
        # NOTE(typing) workaround for mypy not recognising the base class init arguments.
        return cls( # type: ignore
            read_le_int32(read),
            xread_list(read, tell, XTxInput.read), # type: ignore
            xread_list(read, tell, XTxOutput.read), # type: ignore
            read_le_uint32(read),
        )

    @classmethod
    def read_extended(cls, read: Callable[[int], bytes], tell: Callable[[], int]) -> 'Transaction':
        '''Overridden to specialize reading the inputs.'''
        # NOTE(typing) workaround for mypy not recognising the base class init arguments.
        return cls( # type: ignore
            read_le_int32(read),
            xread_list(read, tell, XTxInput.read_extended), # type: ignore
            xread_list(read, tell, XTxOutput.read), # type: ignore
            read_le_uint32(read),
        )

    def to_bytes(self) -> bytes:
        return b''.join((
            pack_le_int32(self.version),
            pack_list(self.inputs, XTxInput.to_bytes),
            pack_list(self.outputs, XTxOutput.to_bytes),
            pack_le_uint32(self.locktime),
        ))

    @classmethod
    def from_bytes(cls, raw: bytes) -> 'Transaction':
        stream = BytesIO(raw)
        return cls.read(stream.read, stream.tell)

    @classmethod
    def from_extended_bytes(cls, raw: bytes) -> 'Transaction':
        stream = BytesIO(raw)
        return cls.read_extended(stream.read, stream.tell)

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

    def update_signatures(self, signatures: List[bytes]) -> None:
        """Add new signatures to a transaction

        `signatures` is expected to be a list of binary sigs with signatures[i]
        intended for self.inputs[i], without the SIGHASH appended.
        This is used by hardware device code.
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
            logger.warning(f'Signature: {full_sig.hex()}')
            if full_sig in txin.signatures:
                continue
            pubkeys = [x_pubkey.to_public_key() for x_pubkey in txin.x_pubkeys]
            pre_hash = self.preimage_hash(txin)
            rec_sig_base = der_signature_to_compact(signature)
            for recid in range(4):
                rec_sig = rec_sig_base + bytes([recid])
                try:
                    public_key = PublicKey.from_recoverable_signature(rec_sig, pre_hash, None)
                except (InvalidSignature, ValueError):
                    # the point might not be on the curve for some recid values
                    continue
                if public_key in pubkeys:
                    try:
                        public_key.verify_recoverable_signature(rec_sig, pre_hash, None)
                    except Exception:
                        logger.exception('')
                        continue
                    j = pubkeys.index(public_key)
                    logger.debug('adding sig %d %s %r', j, public_key, full_sig)
                    txin.signatures[j] = full_sig
                    break

    @classmethod
    def get_preimage_script_bytes(cls, txin: XTxInput) -> bytes:
        _type = txin.type()
        if _type == ScriptType.P2PKH:
            x_pubkey = txin.x_pubkeys[0]
            script = x_pubkey.to_public_key().P2PKH_script()
            return cast(bytes, script.to_bytes())
        elif _type == ScriptType.MULTISIG_P2SH or _type == ScriptType.MULTISIG_BARE:
            return multisig_script(txin.x_pubkeys, txin.threshold)
        elif _type == ScriptType.MULTISIG_ACCUMULATOR:
            return AccumulatorMultiSigOutput(
                [ v.to_bytes() for v in txin.x_pubkeys ], txin.threshold).to_script_bytes()
        elif _type == ScriptType.P2PK:
            x_pubkey = txin.x_pubkeys[0]
            script = x_pubkey.to_public_key().P2PK_script()
            return cast(bytes, script.to_bytes())
        else:
            raise RuntimeError('Unknown txin type', _type)

    def BIP_LI01_sort(self) -> None:
        # See https://github.com/kristovatlas/rfc/blob/master/bips/bip-li01.mediawiki
        self.inputs.sort(key = lambda txin: txin.prevout_bytes())
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
        # Current algorithm: https://github.com/moneybutton/bips/blob/master/bip-0143.mediawiki
        return cast(bytes,
            self.signature_hash(input_index, txin.value, script_code, sighash=sighash))

    def serialize(self) -> str:
        return self.to_bytes().hex()

    def txid(self) -> Optional[str]:
        '''A hexadecimal string if complete, otherwise None.'''
        if self.is_complete():
            return cast(str, hash_to_hex_str(self.hash()))
        return None

    def input_value(self) -> int:
        # This will raise if a value is None, which is expected.
        return sum(txin.value for txin in self.inputs)

    def output_value(self) -> int:
        return sum(output.value for output in self.outputs)

    def get_fee(self) -> int:
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
        for input in cast(List[XTxInput], self.inputs):
            if is_complete:
                estimated_total_size += TransactionSize(input.size(), 0)
            else:
                estimated_total_size += input.estimated_size()
        for output in cast(List[XTxOutput], self.outputs):
            estimated_total_size += output.estimated_size()
        return estimated_total_size

    def signature_count(self) -> Tuple[int, int]:
        r = 0
        s = 0
        for txin in self.inputs:
            signatures = txin.signatures_present()
            s += len(signatures)
            r += txin.threshold
        return s, r

    def sign(self, keypairs: Dict[XPublicKey, Tuple[bytes, bool]]) -> None:
        assert all(isinstance(key, XPublicKey) for key in keypairs)
        for txin in self.inputs:
            if txin.is_complete():
                continue
            for j, x_pubkey in enumerate(txin.x_pubkeys):
                if x_pubkey in keypairs:
                    logger.debug("adding signature for %s", x_pubkey)
                    sec, compressed = keypairs[x_pubkey]
                    txin.signatures[j] = self._sign_txin(txin, sec)
        logger.debug("is_complete %s", self.is_complete())

        # Multisig transactions may require further signatures and input script offsets cannot be
        # calculated until the transaction is fully signed.
        if self.is_complete():
            self.update_script_offsets()

    def _sign_txin(self, txin: XTxInput, privkey_bytes: bytes) -> bytes:
        pre_hash = self.preimage_hash(txin)
        privkey = PrivateKey(privkey_bytes)
        sig = cast(bytes, privkey.sign(pre_hash, None))
        return sig + cast(bytes, pack_byte(self.nHashType()))

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Transaction':
        version = data.get('version', 0)
        tx = cast('Transaction', cls.from_hex(data['hex']))
        if version == 1:
            input_data: Optional[List[Dict[str, Any]]] = data.get('inputs')
            if input_data is not None:
                assert len(tx.inputs) == len(input_data)
                for i, txin in enumerate(tx.inputs):
                    txin.script_type = ScriptType(input_data[i]['script_type'])
                    txin.threshold = int(input_data[i]['threshold'])
                    txin.value = int(input_data[i]['value'])
                    txin.signatures = [ bytes.fromhex(v) for v in input_data[i]['signatures'] ]
                    txin.x_pubkeys = [ XPublicKey.from_dict(v) for v in input_data[i]['x_pubkeys']]
            output_data: Optional[List[Dict[str, Any]]] = data.get('outputs')
            if output_data is not None:
                assert len(tx.outputs) == len(output_data)
                for i, txout in enumerate(tx.outputs):
                    txout.script_type = ScriptType(output_data[i]['script_type'])
                    txout.x_pubkeys = [ XPublicKey.from_dict(v)
                        for v in output_data[i]['x_pubkeys']]
            if 'description' in data:
                tx.context.description = str(data['description'])
            if 'prev_txs' in data:
                for tx_hex in data["prev_txs"]:
                    ptx = cls.from_hex(tx_hex)
                    tx.context.prev_txs[ptx.hash()] = ptx
            assert tx.is_complete() == data["complete"], "transaction completeness mismatch"
        elif version == 0:
            assert tx.is_complete(), "raw transactions must be complete"
        return tx

    def to_dict(self, force_signing_metadata: bool=False) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            'version': 1,
            'hex': self.to_hex(),
            'complete': self.is_complete(),
        }
        if self.context.description:
            out['description'] = self.context.description
        if force_signing_metadata or not out['complete']:
            out['inputs'] = []
            for txin in self.inputs:
                input_entry: Dict[str, Any] = {}
                input_entry['script_type'] = txin.script_type
                input_entry['threshold'] = txin.threshold
                input_entry['value'] = txin.value
                input_entry['signatures'] = [ sig.hex() for sig in txin.signatures ]
                input_entry['x_pubkeys'] = [ xpk.to_dict() for xpk in txin.x_pubkeys ]
                out['inputs'].append(input_entry)
            output_data = []
            if any(len(o.x_pubkeys) for o in self.outputs):
                for txout in self.outputs:
                    output_entry: Dict[str, Any] = {}
                    output_entry['script_type'] = txout.script_type
                    output_entry['x_pubkeys'] = [ xpk.to_dict() for xpk in txout.x_pubkeys ]
                    output_data.append(output_entry)
            if len(output_data):
                out['outputs'] = output_data
        return out

    def to_format(self, format: TxSerialisationFormat) -> TxSerialisedType:
        # Will raise `NotImplementedError` on incomplete implementation of new formats.
        if format == TxSerialisationFormat.RAW:
            return self.to_bytes()
        elif format == TxSerialisationFormat.HEX:
            return cast(str, self.to_hex())
        elif format in (TxSerialisationFormat.JSON, TxSerialisationFormat.JSON_WITH_PROOFS):
            # It is expected the caller may wish to extend this and they will take care of the
            # final serialisation step.
            return self.to_dict()
        raise NotImplementedError(f"unhanded format {format}")

