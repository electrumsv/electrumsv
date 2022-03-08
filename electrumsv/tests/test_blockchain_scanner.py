# TODO(1.4.0) Restoration. This needs to be rewritten to test pushdata.

import asyncio
import os
from typing import Dict, List, NamedTuple, Sequence, Tuple, Optional
import unittest.mock

from bitcoinx import bip32_key_from_string, BIP32PublicKey, hash_to_hex_str, sha256
import pytest

from electrumsv.blockchain_scanner import (BIP32ParentPath, DEFAULT_GAP_LIMITS,
    BlockchainScanner, PushDataHasher, PushDataHashHandler, PushDataMatchResult, SearchEntry,
    SearchEntryKind, SearchKeyEnumerator)
from electrumsv.constants import (CHANGE_SUBPATH, RECEIVING_SUBPATH, ScriptType,
    SINGLE_SIGNER_SCRIPT_TYPES)
from electrumsv.network_support.general_api import RestorationFilterResult


xpub1_text = "xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk" \
    "8Rnts3Nbt97dPwT52CwBdDWroaZf8U"
xpub1 = bip32_key_from_string(xpub1_text)
xpub1_address_0_0 = "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf"
xpub1_address_1_0 = "1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D"
xpub1_pushdatahash_0_0 = "fad146b284f4b42b936b9a21567dd47da698d6ef9692912b4a921490e90ad950"
xpub1_pushdatahash_1_0 = "fe5e3a8f0fcf635b8e9c70324cd705467a209a1141697781edb0ba4e3d94b786"


def create_event() -> asyncio.Event:
    return asyncio.Event()


class InputLine(NamedTuple):
    result: Optional[RestorationFilterResult]
    index: int = -1
    keyinstance_id: int = -1
    script_type: ScriptType = ScriptType.NONE
    pushdata_hash: bytes = b''


async def generate_bip32_input_lines(script_types: Sequence[ScriptType]) \
        -> Tuple[List[InputLine], Dict[bytes, InputLine]]:
    global xpub1
    assert isinstance(xpub1, BIP32PublicKey)
    receiving_xpub = xpub1.child_safe(RECEIVING_SUBPATH[0])

    input_lines: List[InputLine] = []
    input_line_map: Dict[bytes, InputLine] = {}
    for i in range(10):
        public_key = receiving_xpub.child_safe(i)
        if i % len(script_types):
            script_type = ScriptType.P2PKH
            pushdata_hash = sha256(public_key.hash160())
        else:
            script_type = ScriptType.P2PK
            pushdata_hash = sha256(public_key.to_bytes())
        tx_hash1 = os.urandom(4)
        tx_hash2 = os.urandom(4)
        input_line = InputLine(index=i, script_type=script_type, pushdata_hash=pushdata_hash,
            result=RestorationFilterResult(0, f'{i}'.encode(), tx_hash1, i+100, tx_hash2, i+200))
        input_lines.append(input_line)
        input_line_map[pushdata_hash] = input_line
    return input_lines, input_line_map


@pytest.mark.asyncio
@pytest.mark.timeout(2)
@unittest.mock.patch('electrumsv.blockchain_scanner.app_state')
async def test_scanner_pump_mixed(app_state):
    """
    We register the receiving path and a few scripts.
    For the scanner to exit successfully, we need to generate a matching result for each script
    and a minimum number of entries from the receiving path.
    """
    input_lines_explicit = [
        InputLine(pushdata_hash=b'1', keyinstance_id=111,
            result=RestorationFilterResult(0, b'1', b'lock', 0, b'unlock', 2)),
        InputLine(pushdata_hash=b'2', keyinstance_id=222, result=None),
        InputLine(pushdata_hash=b'3', keyinstance_id=333, result=None),
    ]

    input_lines, input_line_map = await generate_bip32_input_lines(SINGLE_SIGNER_SCRIPT_TYPES)
    input_lines.extend(input_lines_explicit)
    input_line_map.update({ l.pushdata_hash: l for l in input_lines_explicit
        if l.result is not None })

    assert isinstance(xpub1, BIP32PublicKey)

    account = unittest.mock.Mock()
    network = unittest.mock.Mock()
    app_state.async_.event.side_effect = create_event

    range_index = 0
    expected_steps = [
        3 + 48,         # The 3 explicit entries and then 24 BIP32 derivations, which given there
                        # are two hashes generated from each derivation, pushes it 1 over the 50
                        # limit before the entries are capped at 51.
        50,             # 25 more BIP32 derivations to a total of 49 derivations and 98 entries.
        22,             # 2 more BIP32 derivations to a total of 50 derivations and 100 entries,
                        # then 10 more BIP32 derivations to place us 10 above the gap limit, for
                        # a total of 60 BIP32 derivations, 3 explicit derivations and this
                        # gives 123 entries.
    ]
    def extend_range_cb(new_range: int) -> None:
        nonlocal range_index, expected_steps
        range_index += 1
        assert new_range == sum(expected_steps[:range_index])

    item_hasher = PushDataHasher()
    search_enumerator = SearchKeyEnumerator(item_hasher)
    for input_line in input_lines_explicit:
        search_enumerator.add_explicit_item(input_line.keyinstance_id, ScriptType.P2PKH,
            input_line.pushdata_hash)
    search_enumerator.add_bip32_subpath(RECEIVING_SUBPATH, [ xpub1 ], 1, SINGLE_SIGNER_SCRIPT_TYPES)
    async def replacement_search_entries(entries: list[SearchEntry]) -> None:
        for entry in entries:
            if entry.item_hash in input_line_map:
                line = input_line_map[entry.item_hash]
                assert entry.item_hash == line.pushdata_hash
                assert line.result is not None
                scan_handler.record_match_for_entry(line.result, entry)
    scan_handler = PushDataHashHandler(network, account)
    scan_handler.search_entries = unittest.mock.Mock()
    scan_handler.search_entries.side_effect = replacement_search_entries
    scanner = BlockchainScanner(scan_handler, search_enumerator,
        extend_range_cb=extend_range_cb)

    await scanner.scan_for_usage()

    # Ensure the range callback was called.
    assert range_index > -1

    # Verify that the scanner found the all the fake results we provided to it.
    result_by_hash = { result.search_entry.item_hash: result.filter_result
        for result in scan_handler._results }
    for pushdata_hash, input_line in input_line_map.items():
        assert result_by_hash[pushdata_hash] == input_line.result


@pytest.mark.asyncio
@pytest.mark.timeout(2)
@unittest.mock.patch('electrumsv.blockchain_scanner.app_state')
async def test_scanner_pump_bip32(app_state):
    """
    We only register the receiving path.
    We fake a result for each and use our random script hash for several to verify they get placed.
    """
    assert isinstance(xpub1, BIP32PublicKey)

    account = unittest.mock.Mock()
    network = unittest.mock.Mock()
    app_state.async_.event.side_effect = create_event

    input_lines, input_line_map = await generate_bip32_input_lines(SINGLE_SIGNER_SCRIPT_TYPES)

    last_range = 0
    def extend_range_cb(new_range: int) -> None:
        nonlocal last_range
        last_range = new_range

    item_hasher = PushDataHasher()
    search_enumerator = SearchKeyEnumerator(item_hasher)
    receiving_path = search_enumerator.add_bip32_subpath(RECEIVING_SUBPATH, [ xpub1 ], 1,
        SINGLE_SIGNER_SCRIPT_TYPES)
    async def replacement_search_entries(entries: list[SearchEntry]) -> None:
        for i, entry in enumerate(entries):
            assert entry.kind == SearchEntryKind.BIP32
            if entry.item_hash in input_line_map:
                line = input_line_map[entry.item_hash]
                assert entry.item_hash == line.pushdata_hash
                assert line.result is not None
                scan_handler.record_match_for_entry(line.result, entry)
    scan_handler = PushDataHashHandler(network, account)
    scan_handler.search_entries = unittest.mock.Mock()
    scan_handler.search_entries.side_effect = replacement_search_entries
    scanner = BlockchainScanner(scan_handler, search_enumerator,
        extend_range_cb=extend_range_cb)

    await scanner.scan_for_usage()

    # Ensure the range callback was called.
    assert last_range == \
        (DEFAULT_GAP_LIMITS[RECEIVING_SUBPATH] + 10) * len(SINGLE_SIGNER_SCRIPT_TYPES)
    # Account for the gap being pushed out by 10 used keys.
    assert receiving_path.last_index + 1 == DEFAULT_GAP_LIMITS[RECEIVING_SUBPATH] + 10

    # Verify that the scanner found the all the fake results we provided to it.
    result_by_hash = { result.search_entry.item_hash: result.filter_result
        for result in scan_handler._results }
    for input_line in input_lines:
        assert result_by_hash[input_line.pushdata_hash] == input_line.result


@pytest.mark.asyncio
@pytest.mark.timeout(2)
@unittest.mock.patch('electrumsv.blockchain_scanner.app_state')
async def test_scanner_pump_script(app_state):
    input_lines = [
        InputLine(pushdata_hash=b'1', keyinstance_id=111,
            result=RestorationFilterResult(0, b'1', b'lock', 0, b'unlock', 2)),
        InputLine(pushdata_hash=b'2', keyinstance_id=222, result=None),
        InputLine(pushdata_hash=b'3', keyinstance_id=333, result=None),
    ]

    account = unittest.mock.Mock()
    network = unittest.mock.Mock()
    app_state.async_.event.side_effect = create_event

    extend_range_called = False
    def extend_range_cb(new_range: int) -> None:
        nonlocal extend_range_called, input_lines
        extend_range_called = True
        assert new_range == len(input_lines)

    item_hasher = PushDataHasher()
    search_enumerator = SearchKeyEnumerator(item_hasher)
    for input_line in input_lines:
        search_enumerator.add_explicit_item(input_line.keyinstance_id, ScriptType.P2PKH,
            input_line.pushdata_hash)
    scan_handler = PushDataHashHandler(network, account)
    scan_handler.search_entries = unittest.mock.Mock()
    async def replacement_search_entries(entries: list[SearchEntry]) -> None:
        for i, entry in enumerate(entries):
            line = input_lines[i]
            assert entry.kind == SearchEntryKind.EXPLICIT
            assert entry.item_hash == line.pushdata_hash
            if line.result is not None:
                scan_handler._results.append(PushDataMatchResult(line.result, entries[i]))

    scan_handler.search_entries.side_effect = replacement_search_entries
    scanner = BlockchainScanner(scan_handler, search_enumerator,
        extend_range_cb=extend_range_cb)

    await scanner.scan_for_usage()

    assert extend_range_called

    # Verify that the scanner has the expected results.
    scan_results = scan_handler.get_results()
    assert len(scan_results) == 1
    assert scan_results[0].search_entry.item_hash == input_lines[0].pushdata_hash
    assert scan_results[0].filter_result == input_lines[0].result


@unittest.mock.patch('electrumsv.blockchain_scanner.app_state')
def test_scanner_bip32_correctness(app_state):
    # app_state.subscriptions = unittest.mock.Mock()
    assert isinstance(xpub1, BIP32PublicKey)

    item_hasher = PushDataHasher()
    search_enumerator = SearchKeyEnumerator(item_hasher)

    receiving_xpub = xpub1.child_safe(RECEIVING_SUBPATH[0])
    receiving_path = BIP32ParentPath(RECEIVING_SUBPATH, 1, [ xpub1 ], (ScriptType.P2PKH,))
    assert receiving_path.subpath == RECEIVING_SUBPATH
    assert receiving_path.threshold == 1
    assert receiving_path.parent_public_keys == [ receiving_xpub ]
    assert receiving_path.script_types == (ScriptType.P2PKH,)

    assert not search_enumerator._get_bip32_path_count(receiving_path) == 0

    # Verify that the first entry provides the correct key and script.. and other stuff.
    entries = search_enumerator._obtain_entries_from_bip32_path(1, receiving_path)
    assert len(entries) == 1
    assert receiving_path.last_index == 0
    assert receiving_path.result_count == 0
    assert receiving_path.highest_used_index == -1

    entry = entries[0]
    assert entry.kind == SearchEntryKind.BIP32
    assert entry.keyinstance_id is None
    assert entry.script_type == ScriptType.P2PKH
    assert entry.parent_path == receiving_path
    assert entry.parent_index == 0
    assert hash_to_hex_str(entry.item_hash) == xpub1_pushdatahash_0_0

    # Verify that the second entry is not the first entry.
    entries = search_enumerator._obtain_entries_from_bip32_path(1, receiving_path)
    assert len(entries) == 1
    assert receiving_path.last_index == 1
    assert receiving_path.result_count == 0
    assert receiving_path.highest_used_index == -1
    entry = entries[0]
    assert entry.kind == SearchEntryKind.BIP32
    assert entry.keyinstance_id is None
    assert entry.script_type == ScriptType.P2PKH
    assert entry.parent_path == receiving_path
    assert entry.parent_index == 1
    assert hash_to_hex_str(entry.item_hash) != xpub1_pushdatahash_0_0

    # Just verify that the first change entry is correct where it counts.
    change_path = BIP32ParentPath(CHANGE_SUBPATH, 1, [ xpub1 ], (ScriptType.P2PKH,))
    entries = search_enumerator._obtain_entries_from_bip32_path(1, change_path)
    assert len(entries) == 1
    assert change_path.last_index == 0
    entry = entries[0]
    assert entry.parent_path == change_path
    assert entry.parent_index == 0
    assert hash_to_hex_str(entry.item_hash) == xpub1_pushdatahash_1_0

