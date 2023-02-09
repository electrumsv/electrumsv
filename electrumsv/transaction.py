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
from struct import error as struct_error
from typing import Any, Callable, cast, Protocol, TypeVar

import attr
from bitcoinx import (
    Address, bip32_key_from_string, BIP32PublicKey, der_signature_to_compact, double_sha256,
    hash_to_hex_str, InvalidSignature, P2PK_Output, pack_byte, pack_le_int32, pack_le_uint32,
    pack_list, pack_varbytes, PrivateKey, PublicKey, read_le_int32, read_le_int64, read_le_uint32,
    read_varint, Script, SigHash, Tx, TxInput, TxOutput, varint_len
)

from .bitcoin import ScriptTemplate
from .constants import DerivationPath, ScriptType
from .logs import logs
from .networks import Net
from .script import AccumulatorMultiSigOutput
from .standards.script_templates import classify_transaction_output_script, create_script_sig, \
    to_bare_multisig_script_bytes
from .types import DatabaseKeyDerivationData, FeeQuoteCommon, FeeQuoteTypeFee, \
    ServerAndCredential, TransactionSize, Outpoint



class SupportsToBytes(Protocol):
    def to_bytes(self) -> bytes:
       ...


NO_SIGNATURE = b'\xff'
dummy_public_key = PublicKey.from_bytes(bytes(range(3, 36)))
dummy_signature = bytes(73)

logger = logs.get_logger("transaction")


class TxSerialisationFormat(enum.IntEnum):
    RAW = 0
    HEX = 1
    JSON = 2
    JSON_WITH_PROOFS = 3
    PSBT = 4


TxFileExtensions = {
    TxSerialisationFormat.RAW: "txn",
    TxSerialisationFormat.HEX: "txt",
    TxSerialisationFormat.PSBT: "psbt",
    TxSerialisationFormat.JSON: "json",
    TxSerialisationFormat.JSON_WITH_PROOFS: "json",
}

TxSerialisedType = bytes | str | dict[str, Any]
ReadBytesFunc = Callable[[int], bytes]
TellFunc = Callable[[], int]
T = TypeVar('T')

# Duplicated and extended from the bitcoinx implementation.
def xread_list(read: ReadBytesFunc, tell: TellFunc,
        read_one: Callable[[ReadBytesFunc, TellFunc, int], T], transaction_offset: int) -> list[T]:
    '''Return a list of items.

    Each item is read with read_one, the stream begins with a count of the items.'''
    return [read_one(read, tell, transaction_offset) for _ in range(read_varint(read))]

# Reimplemented from bitcoinx, to take the tell argument and return the offset.
def xread_varbytes(read: ReadBytesFunc, tell: TellFunc) -> tuple[bytes, int]:
    n = read_varint(read)
    offset = tell()
    result = read(n)
    if len(result) != n:
        raise struct_error(f'varbytes requires a buffer of {n:,d} bytes')
    return result, offset


def script_to_display_text(script: Script, kind: ScriptTemplate) -> str:
    if isinstance(kind, Address):
        text = kind.to_string()
    elif isinstance(kind, P2PK_Output):
        text = kind.public_key.to_hex()
    else:
        text = script.to_asm(False)
    return cast(str, text)

def tx_output_to_display_text(tx_output: TxOutput) -> tuple[str, ScriptTemplate]:
    _script_type, _threshold, script_template = classify_transaction_output_script(
        tx_output.script_pubkey)
    text = script_to_display_text(tx_output.script_pubkey, script_template)
    return text, script_template


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

    def type(self) -> ScriptType:
        if self.is_coinbase():
            return ScriptType.COINBASE
        return self.script_type

    @classmethod
    def read(cls, read: ReadBytesFunc, tell: TellFunc, transaction_offset: int) -> XTxInput:
        prev_hash = read(32)
        prev_idx = read_le_uint32(read)
        script_sig_bytes, script_sig_offset = xread_varbytes(read, tell)
        script_sig = Script(script_sig_bytes)
        sequence = read_le_uint32(read)

        # Adjust for transactions picked out mid-stream of a larger piece of data.
        script_sig_offset = script_sig_offset - transaction_offset

        # NOTE(rt12) workaround for mypy not recognising the base class init arguments.
        return cls(prev_hash=prev_hash, prev_idx=prev_idx, # type: ignore[call-arg]
            script_sig=script_sig, sequence=sequence,
            script_offset=script_sig_offset, script_length=len(script_sig_bytes))

    def to_bytes(self, substitute_script_sig: Script|None=None) -> bytes:
        # NOTE(typing) I have no idea what is going on with this.
        #     Cannot determine type of "script_sig"  [has-type]
        script_sig = substitute_script_sig if substitute_script_sig is not None \
            else self.script_sig # type: ignore[has-type]
        return b''.join((
            self.prevout_bytes(),
            pack_varbytes(bytes(script_sig)),
            pack_le_uint32(self.sequence),
        ))

    def size(self, substitute_script_sig: Script|None=None) -> int:
        return len(self.to_bytes(substitute_script_sig))

    def estimated_size(self) -> TransactionSize:
        '''Return an estimated of serialized input size in bytes.'''
        # We substitute in signatures of a kind of realistic size. With high r and high s values
        # the size us 73 bytes. In reality with low s enforced because of "malleability hysteria"
        # the actual size would be 71 or 72 bytes.
        signature_by_key: dict[bytes, bytes] = {
            public_key_bytes: dummy_signature if public_key_bytes not in self.signatures else \
                self.signatures[public_key_bytes] for public_key_bytes in list(self.x_pubkeys) }
        script_sig = create_script_sig(self.script_type, self.threshold, self.x_pubkeys,
            signature_by_key)
        assert script_sig is not None
        return TransactionSize(self.size(script_sig), 0)

    def is_complete(self) -> bool:
        '''Return true if this input has all signatures present.'''
        # NOTE(typing) I have no idea what is going on with this.
        #     Cannot determine type of "script_sig"  [has-type]
        return len(self.script_sig) > 0 # type: ignore[has-type]

    def finalize_if_complete(self) -> None:
        # NOTE(typing) I have no idea what is going on with this.
        #     Cannot determine type of "script_sig"  [has-type]
        assert len(self.script_sig) == 0 # type: ignore[has-type]
        if len(self.signatures) >= self.threshold:
            script_sig = create_script_sig(self.script_type, self.threshold, self.x_pubkeys,
                self.signatures)
            assert script_sig is not None
            # NOTE(typing) Trying to assign name "script_sig" that is not in "__slots__" of type
            #     "electrumsv.transaction.XTxInput"  [misc]
            self.script_sig = script_sig # type: ignore[misc]

    def unused_x_pubkeys(self) -> list[XPublicKey]:
        if len(self.signatures) >= self.threshold:
            return []
        return [ x_pubkey for public_key_bytes, x_pubkey in self.x_pubkeys.items()
            if public_key_bytes not in self.signatures ]

    def __repr__(self) -> str:
        return (
            f'XTxInput(prev_hash="{hash_to_hex_str(self.prev_hash)}", prev_idx={self.prev_idx}, '
            f'script_sig="{self.script_sig}", sequence={self.sequence}, value={self.value}, '
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
    def read(cls, read: ReadBytesFunc, tell: TellFunc, transaction_offset: int) -> XTxOutput:
        value = read_le_int64(read)
        script_pubkey_bytes, script_pubkey_offset = xread_varbytes(read, tell)
        script_pubkey = Script(script_pubkey_bytes)
        return cls(value, script_pubkey,
            script_offset=script_pubkey_offset-transaction_offset,
            script_length=len(script_pubkey_bytes))

    @classmethod
    def from_bytes(cls, raw: bytes) -> XTxOutput:
        stream = BytesIO(raw)
        return cls.read(stream.read, stream.tell, 0)

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
    inputs: list[XTxInput] = attr.ib(default=attr.Factory(list))
    outputs: list[XTxOutput] = attr.ib(default=attr.Factory(list))

    @classmethod
    def from_io(cls, inputs: list[XTxInput], outputs: list[XTxOutput], locktime: int=0) \
            -> Transaction:
        # NOTE(typing) Until the base class is fully typed it's attrs won't be found properly.
        return cls(version=1, locktime=locktime, # type: ignore[call-arg]
            inputs=inputs, outputs=outputs.copy())

    @classmethod
    def read(cls, read: Callable[[int], bytes], tell: Callable[[], int]) -> Transaction:
        '''Overridden to specialize reading the inputs.'''
        transaction_offset = tell()
        # NOTE(typing) Until the base class is fully typed it's attrs won't be found properly.
        return cls(
            version=read_le_int32(read), # type: ignore[call-arg]
            inputs=xread_list(read, tell, XTxInput.read, transaction_offset),
            outputs=xread_list(read, tell, XTxOutput.read, transaction_offset),
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
        return cast(str, self.to_hex())

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
        return cast(int, SigHash.ALL | SigHash.FORKID)

    def preimage_hash(self, txin: XTxInput) -> bytes:
        input_index = self.inputs.index(txin)
        script_code = self.get_preimage_script_bytes(txin)
        sighash = SigHash(self.nHashType())
        # Original BTC algorithm: https://en.bitcoin.it/wiki/OP_CHECKSIG
        # Current algorithm: https://github.com/electrumsv/bips/blob/master/bip-0143.mediawiki
        return cast(bytes,
            self.signature_hash(input_index, txin.value, script_code, sighash=sighash))

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
        signatures_required = 0
        signatures_present = 0
        for txin in self.inputs:
            signatures_present += len(txin.signatures)
            signatures_required += txin.threshold
        return signatures_present, signatures_required

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
