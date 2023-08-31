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
from io import BytesIO
from typing import TypedDict

from bitcoinx import base58_encode_check, pack_le_uint32, pack_list, pack_le_int32, read_le_int32, \
    read_le_int64, read_le_uint32, Script, unpack_le_uint16

from ..constants import DatabaseKeyDerivationType, DerivationPath
from ..transaction import NO_SIGNATURE, ReadBytesFunc, TellFunc, Transaction, XPublicKey, \
    xread_list, xread_varbytes, XTxInput, XTxOutput
from ..types import DatabaseKeyDerivationData

from .script_templates import create_script_sig, parse_script_sig

class SerialisedXPublicKeyDict(TypedDict, total=False):
    pubkey_bytes: str | None
    bip32_xpub: str | None
    old_mpk: str | None
    derivation_path: DerivationPath | None


def x_public_key_from_electrum_bytes(raw: bytes) -> XPublicKey:
    """ In addition to importing public keys, we also support the legacy Electrum
    serialisation, except for the case of addresses. """
    bip32_xpub: str | None = None
    pubkey_bytes: bytes | None = None
    old_mpk: bytes | None = None
    derivation_data: DatabaseKeyDerivationData | None = None
    kind = raw[0]
    if kind in {0x02, 0x03, 0x04}:
        pubkey_bytes = raw
    elif kind == 0xff:
        # 83 is 79 + 2 + 2.
        assert len(raw) == 83, f"got {len(raw)}"
        bip32_xpub = base58_encode_check(raw[1:79])
        derivation_data = DatabaseKeyDerivationData(
            derivation_path=tuple(unpack_le_uint16(raw[n: n+2])[0] for n in (79, 81)),
            source=DatabaseKeyDerivationType.IMPORTED)
    elif kind == 0xfe:
        assert len(raw) == 69
        old_mpk = raw[1:65]  # The public key bytes without the 0x04 prefix
        derivation_data = DatabaseKeyDerivationData(
            derivation_path=tuple(unpack_le_uint16(raw[n: n+2])[0] for n in (65, 67)),
            source=DatabaseKeyDerivationType.IMPORTED)
    else:
        raise NotImplementedError
    return XPublicKey(pubkey_bytes=pubkey_bytes, bip32_xpub=bip32_xpub, old_mpk=old_mpk,
        derivation_data=derivation_data)

def x_public_key_from_electrumsv_dict(data: SerialisedXPublicKeyDict) -> XPublicKey:
    bip32_xpub: str | None = data.get("bip32_xpub")
    pubkey_bytes: bytes | None = None
    pubkey_bytes_hex: str | None = data.get("pubkey_bytes", None)
    if pubkey_bytes_hex:
        pubkey_bytes = bytes.fromhex(pubkey_bytes_hex)
    old_mpk: bytes | None = None
    old_mpk_hex: str | None = data.get("old_mpk", None)
    if old_mpk_hex is not None:
        old_mpk = bytes.fromhex(old_mpk_hex)
    derivation_data: DatabaseKeyDerivationData | None = None
    derivation_path: DerivationPath | None = data.get("derivation_path")
    if derivation_path is not None:
        derivation_data = DatabaseKeyDerivationData(derivation_path=tuple(derivation_path),
            source=DatabaseKeyDerivationType.IMPORTED)
    return XPublicKey(pubkey_bytes=pubkey_bytes, bip32_xpub=bip32_xpub, old_mpk=old_mpk,
        derivation_data=derivation_data)

def transaction_input_to_electrum_bytes(transaction_input: XTxInput) -> bytes:
    if not transaction_input.is_complete():
        assert len(transaction_input.x_pubkeys) > 0
        signatures: dict[bytes, bytes] = {}
        for public_key_bytes in transaction_input.x_pubkeys:
            signatures[public_key_bytes] = \
                transaction_input.signatures.get(public_key_bytes, NO_SIGNATURE)
        script_sig = create_script_sig(transaction_input.script_type, transaction_input.threshold,
            transaction_input.x_pubkeys, signatures)
        assert script_sig is not None
        return transaction_input.to_bytes(script_sig)

    return transaction_input.to_bytes()


def transaction_to_electrum_bytes(transaction: Transaction) -> bytes:
    return b''.join((
        pack_le_int32(transaction.version),
        pack_list(transaction.inputs, transaction_input_to_electrum_bytes),
        pack_list(transaction.outputs, XTxOutput.to_bytes),
        pack_le_uint32(transaction.locktime),
    ))


def transaction_input_from_electrum_bytes_stream(read: ReadBytesFunc, tell: TellFunc,
        transaction_offset: int) -> XTxInput:
    # This section is duplicated in `XTxInput.read`
    prev_hash = read(32)
    prev_idx = read_le_uint32(read)
    script_sig_bytes, script_sig_offset = xread_varbytes(read, tell)
    script_sig = Script(script_sig_bytes)
    sequence = read_le_uint32(read)

    # Adjust for transactions picked out mid-stream of a larger piece of data.
    script_sig_offset = script_sig_offset - transaction_offset

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
        script_data = parse_script_sig(script_sig_bytes, x_public_key_from_electrum_bytes,
            signature_placeholder=NO_SIGNATURE)
        kwargs["x_pubkeys"] = script_data.x_pubkeys
        kwargs["threshold"] = script_data.threshold
        kwargs["signatures"] = script_data.signatures
        kwargs["script_type"] = script_data.script_type
        # Incomplete modern transaction inputs have an empty `script_sig`.
        if len(script_data.signatures) < script_data.threshold:
            script_sig = Script(b"")

    # NOTE(rt12) workaround for mypy not recognising the base class init arguments.
    result = XTxInput(prev_hash, prev_idx, script_sig, sequence, # type: ignore[arg-type]
        value=None, **kwargs) # type: ignore
    if not result.is_complete():
        result.value = read_le_int64(read)
    return result

def transaction_from_electrum_bytes(raw: bytes) -> Transaction:
    transaction_offset = 0
    stream = BytesIO(raw)
    return Transaction(
        # NOTE(typing) Until the base class is fully typed it's attrs won't be found properly.
        version=read_le_int32(stream.read), # type: ignore[call-arg]
        inputs=xread_list(stream.read, stream.tell, transaction_input_from_electrum_bytes_stream,
            transaction_offset),
        outputs=xread_list(stream.read, stream.tell, XTxOutput.read, transaction_offset),
        locktime=read_le_uint32(stream.read),
    )
