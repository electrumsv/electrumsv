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
from typing import Any, TYPE_CHECKING, TypedDict

from bitcoinx import base58_encode_check, pack_le_uint32, pack_list, pack_le_int32, read_le_int32, \
    read_le_int64, read_le_uint32, Script, unpack_le_uint16

from ..constants import DatabaseKeyDerivationType, DerivationPath, ScriptType
from ..transaction import NO_SIGNATURE, ReadBytesFunc, TellFunc, Transaction, TxContext, \
    XPublicKey, xread_list, xread_varbytes, XTxInput, XTxOutput
from ..types import DatabaseKeyDerivationData

from .script_templates import create_script_sig, parse_script_sig

if TYPE_CHECKING:
    from ..wallet import AbstractAccount

class SerialisedXPublicKeyDict(TypedDict, total=False):
    pubkey_bytes: str | None
    bip32_xpub: str | None
    old_mpk: str | None
    derivation_path: DerivationPath | None


def x_public_key_to_electrumsv_dict(x_public_key: XPublicKey) -> SerialisedXPublicKeyDict:
    d: SerialisedXPublicKeyDict = {}
    if x_public_key._pubkey_bytes is not None:
        d["pubkey_bytes"] = x_public_key._pubkey_bytes.hex()
        return d
    assert x_public_key._derivation_data is not None and \
        x_public_key._derivation_data.derivation_path is not None
    if x_public_key._old_mpk is not None:
        d["old_mpk"] = x_public_key._old_mpk.hex()
        d["derivation_path"] = x_public_key._derivation_data.derivation_path
        return d
    if x_public_key._bip32_xpub is not None:
        d["bip32_xpub"] = x_public_key._bip32_xpub
        d["derivation_path"] = x_public_key._derivation_data.derivation_path
        return d
    raise NotImplementedError


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

def transaction_to_electrumsv_dict(transaction: Transaction, context: TxContext,
        accounts: list[AbstractAccount], force_signing_metadata: bool=False) -> dict[str, Any]:
    account_by_id = { account.get_id(): account for account in accounts }

    out: dict[str, Any] = {
        'version': 2,
        'hex': transaction_to_electrum_bytes(transaction).hex(),
        'complete': transaction.is_complete(),
    }
    if len(context.account_labels):
        descriptions: list[tuple[str, str]] = []
        for account_id, account_description in context.account_labels.items():
            account = account_by_id.get(account_id, None)
            if account is not None:
                descriptions.append((account.get_fingerprint().hex(), account_description))
        out["descriptions"] = descriptions
    if force_signing_metadata or not out['complete']:
        input: XTxInput
        output: XTxOutput
        out['inputs'] = []
        for input in transaction.inputs:
            input_entry: dict[str, Any] = {}
            input_entry['script_type'] = input.script_type
            input_entry['threshold'] = input.threshold
            input_entry['value'] = input.value
            # This is old style Electrum extended transaction where the ordering of x_pubkeys
            # and signatures is the same, and one to one.
            signatures: list[str] = []
            x_pubkeys: list[SerialisedXPublicKeyDict] = []
            for public_key_bytes in sorted(input.x_pubkeys):
                x_pubkeys.append(x_public_key_to_electrumsv_dict(input.x_pubkeys[public_key_bytes]))
                signatures.append(input.signatures.get(public_key_bytes, NO_SIGNATURE).hex())
            input_entry['signatures'] = signatures
            input_entry['x_pubkeys'] = x_pubkeys
            out['inputs'].append(input_entry)
        output_data = []
        if any(len(output.x_pubkeys) for output in transaction.outputs):
            for output in transaction.outputs:
                output_entry: dict[str, Any] = {}
                output_entry['script_type'] = output.script_type
                output_entry['x_pubkeys'] = [ x_public_key_to_electrumsv_dict(xpk)
                    for xpk in output.x_pubkeys.values() ]
                output_data.append(output_entry)
        if len(output_data):
            out['outputs'] = output_data
    return out

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

def transaction_from_electrumsv_dict(data: dict[str, Any], accounts: list[AbstractAccount]) \
        -> tuple[Transaction, TxContext]:
    account_by_fingerprint = { account.get_fingerprint(): account for account in accounts }

    version = data.get('version', 0)
    tx = Transaction.from_hex(data['hex'])
    context = TxContext()
    if version == 2:
        if 'descriptions' in data:
            for account_fingerprint_hex, description in data["descriptions"]:
                account_fingerprint = bytes.fromhex(account_fingerprint_hex)
                account = account_by_fingerprint.get(account_fingerprint, None)
                # There's not much we can do if they do not have the account.
                if account is not None:
                    context.account_labels[account.get_id()] = description
    if version >= 1:
        input_data: list[dict[str, Any]]|None = data.get('inputs')
        if input_data is not None:
            assert len(tx.inputs) == len(input_data)
            for i, txin in enumerate(tx.inputs):
                txin.script_type = ScriptType(input_data[i]['script_type'])
                txin.threshold = int(input_data[i]['threshold'])
                txin.value = int(input_data[i]['value'])
                for j, x_pubkey_dict in enumerate(input_data[i]['x_pubkeys']):
                    x_pubkey = x_public_key_from_electrumsv_dict(x_pubkey_dict)
                    public_key_bytes = x_pubkey.to_bytes()
                    txin.x_pubkeys[public_key_bytes] = x_pubkey
                    signature_hex = input_data[i]['signatures'][j]
                    if len(signature_hex) > 0:
                        signature_bytes = bytes.fromhex(signature_hex)
                        if signature_bytes != NO_SIGNATURE:
                            txin.signatures[public_key_bytes] = signature_bytes
                txin.script_sig = Script(b"")
                txin.finalize_if_complete()
        output_data: list[dict[str, Any]]|None = data.get('outputs')
        if output_data is not None:
            assert len(tx.outputs) == len(output_data)
            for i, txout in enumerate(tx.outputs):
                txout.script_type = ScriptType(output_data[i]['script_type'])
                txout.x_pubkeys = {}
                for x_pubkey_dict in output_data[i]['x_pubkeys']:
                    x_pubkey = x_public_key_from_electrumsv_dict(x_pubkey_dict)
                    txout.x_pubkeys[x_pubkey.to_bytes()] = x_pubkey
        if 'description' in data:
            for account in accounts:
                if not account.is_petty_cash():
                    context.account_labels[account.get_id()] = str(data['description'])
        if 'prev_txs' in data:
            for tx_hex in data["prev_txs"]:
                ptx = Transaction.from_hex(tx_hex)
                context.parent_transactions[ptx.hash()] = ptx
        assert tx.is_complete() == data["complete"], "transaction completeness mismatch"
    elif version == 0:
        assert tx.is_complete(), "raw transactions must be complete"
    return tx, context

