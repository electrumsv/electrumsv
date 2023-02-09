from __future__ import annotations
import dataclasses
import struct
from typing import Callable, cast, Generator, Sequence, TYPE_CHECKING

from bitcoinx import Address, classify_output_script, hash160, Ops, P2MultiSig_Output, \
    P2PK_Output, P2PKH_Address, P2SH_Address, pack_byte, push_int, push_item, Script

from ..constants import ScriptType, SINGLE_SIGNER_SCRIPT_TYPES, MULTI_SIGNER_SCRIPT_TYPES
from ..logs import logs
from ..networks import Net

if TYPE_CHECKING:
    from ..bitcoin import ScriptTemplate
    from ..transaction import XPublicKey


logger = logs.get_logger("script-templates")


@dataclasses.dataclass
class ScriptSigData:
    signatures: dict[bytes, bytes] = dataclasses.field(default_factory=dict)
    threshold: int = dataclasses.field(default=0)
    x_pubkeys: dict[bytes, XPublicKey] = dataclasses.field(default_factory=dict)
    script_type: ScriptType = dataclasses.field(default=ScriptType.NONE)
    address: Address|None = dataclasses.field(default=None)


@dataclasses.dataclass
class CoinData:
    script_type: ScriptType
    threshold: int
    script_template: ScriptTemplate
    value: int


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
            assert len(public_keys_bytes) == 1, "superfluous signatures"
            public_key_bytes = public_keys_bytes[0]
            assert public_key_bytes in x_pubkeys
            return Script(push_item(signature_by_key[public_key_bytes]))
        elif script_type == ScriptType.P2PKH:
            assert len(public_keys_bytes) == 1, "superfluous signatures"
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


def parse_script_sig(script: bytes, to_x_public_key: Callable[[bytes], XPublicKey], *,
        signature_placeholder: bytes|None = None, coin_data: CoinData|None=None) -> ScriptSigData:
    """
    What we can identify just using the script signature is P2PKH and P2SH.
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
    match = [ Ops.OP_PUSHDATA4 ]
    if _match_decoded(decoded, match):
        # We can only match P2PK in a useful way if we have the spent output.
        assert coin_data is not None
        assert coin_data.script_type == ScriptType.P2PK
        assert isinstance(coin_data.script_template, P2PK_Output)
        public_key_bytes = coin_data.script_template.public_key.to_bytes()
        signature_bytes = cast(bytes, decoded[0][1])
        return ScriptSigData(script_type=ScriptType.P2PK, threshold=1,
            signatures={ public_key_bytes: signature_bytes })

    # P2PKH inputs push a signature (around seventy bytes) and then their public key
    # (65 bytes) onto the stack
    match = [ Ops.OP_PUSHDATA4, Ops.OP_PUSHDATA4 ]
    if _match_decoded(decoded, match):
        if coin_data is not None:
            assert coin_data.script_type == ScriptType.P2PKH
        signature_bytes = cast(bytes, decoded[0][1])
        raw_public_key_bytes = decoded[1][1]
        assert raw_public_key_bytes is not None
        # The raw public key bytes are not guaranteed to be the same as what we actually use.
        # They may be encoded Electrum extended keys or uncompressed public keys.
        x_public_key = to_x_public_key(raw_public_key_bytes)
        public_key_bytes = x_public_key.to_bytes()
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

    if coin_data is not None:
        assert coin_data.script_type == ScriptType.MULTISIG_P2SH

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


def classify_transaction_output_script(script: Script) \
        -> tuple[ScriptType | None, int | None, ScriptTemplate]:
    script_template = classify_output_script(script, Net.COIN)
    if isinstance(script_template, P2MultiSig_Output):
        return ScriptType.MULTISIG_BARE, script_template.threshold, script_template
    elif isinstance(script_template, P2PK_Output):
        return ScriptType.P2PK, 1, script_template
    elif isinstance(script_template, P2PKH_Address):
        return ScriptType.P2PKH, 1, script_template
    elif isinstance(script_template, P2SH_Address):
        return ScriptType.MULTISIG_P2SH, None, script_template
    return None, None, script_template
