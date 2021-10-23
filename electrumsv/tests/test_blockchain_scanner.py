import asyncio
import os
from typing import cast, Dict, List, NamedTuple, Sequence, Tuple
import unittest.mock

from bitcoinx import bip32_key_from_string, BIP32PublicKey, hash_to_hex_str
import pytest

from electrumsv.bitcoin import scripthash_bytes
from electrumsv.blockchain_scanner import (BIP32ParentPath, DEFAULT_GAP_LIMITS,
    BlockchainScanner, ScriptHasher, ScriptHashHandler, SearchEntryKind, SearchKeyEnumerator)
from electrumsv.constants import (CHANGE_SUBPATH, RECEIVING_SUBPATH, ScriptType,
    SINGLE_SIGNER_SCRIPT_TYPES, SubscriptionType)
from electrumsv.exceptions import SubscriptionStale
from electrumsv.types import (ElectrumXHistoryList, SubscriptionEntry,
    SubscriptionScannerScriptHashOwnerContext, SubscriptionOwner)


xpub1_text = "xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk" \
    "8Rnts3Nbt97dPwT52CwBdDWroaZf8U"
xpub1 = bip32_key_from_string(xpub1_text)
xpub1_address_0_0 = "1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf"
xpub1_address_1_0 = "1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D"
xpub1_scripthash_0_0 = "eb2d7db7f48de5b0fd5d209fc3fbf54dc334f1a28c8c8cc9f58832c5ec0b5282"
xpub1_scripthash_1_0 = "b0f7142914d4ab61ded86a05d40ca163314fc9e31537cfa04311e721a07d228a"


def create_event() -> asyncio.Event:
    return asyncio.Event()


# This is our helper task to awaken the blocked `scan_for_usage` call.
async def post_event(scanner: BlockchainScanner, entry: SubscriptionEntry, history: ElectrumXHistoryList) \
        -> None:
    assert entry.owner_context is not None
    await cast(ScriptHashHandler, scanner._handler)._on_script_hash_result(
        entry.key,
        cast(SubscriptionScannerScriptHashOwnerContext, entry.owner_context),
        history)


class InputLine(NamedTuple):
    history: ElectrumXHistoryList
    index: int = -1
    keyinstance_id: int = -1
    script_type: ScriptType = ScriptType.NONE
    script_hash: bytes = b''


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
            script_hash = scripthash_bytes(public_key.P2PKH_script())
        else:
            script_type = ScriptType.P2PK
            script_hash = scripthash_bytes(public_key.P2PK_script())
        tx_hash = os.urandom(4).hex()
        input_line = InputLine(index=i, script_type=script_type, script_hash=script_hash,
            history=[
                { "tx_hash": tx_hash, "height": (i + 1) * 1000 }
            ])
        input_lines.append(input_line)
        input_line_map[script_hash] = input_line
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
    input_lines_script = [
        InputLine(script_hash=b'1', keyinstance_id=111,
            history=[ { "tx_hash": "tx1", "height": 1111 } ]),
        InputLine(script_hash=b'2', keyinstance_id=222, history=[]),
        InputLine(script_hash=b'3', keyinstance_id=333, history=[]),
    ]

    input_lines, input_line_map = await generate_bip32_input_lines(SINGLE_SIGNER_SCRIPT_TYPES)
    input_lines.extend(input_lines_script)
    input_line_map.update({ l.script_hash: l for l in input_lines_script })

    worker_tasks: List[asyncio.Task] = []

    # This will get called to subscribe within `add_script`.
    def create_entries(entries: List[SubscriptionEntry], owner: SubscriptionOwner):
        nonlocal input_lines, scanner, worker_tasks
        for entry in entries:
            assert entry.key.value_type == SubscriptionType.SCRIPT_HASH
            input_line = input_line_map.get(entry.key.value)
            history: ElectrumXHistoryList = []
            if input_line is not None:
                assert entry.key.value == input_line.script_hash
                history = input_line.history
            worker_task = asyncio.create_task(post_event(scanner, entry, history))
            worker_tasks.append(worker_task)

    assert isinstance(xpub1, BIP32PublicKey)

    network = unittest.mock.Mock()
    network.subscriptions = unittest.mock.Mock()
    network.subscriptions.create_entries.side_effect = create_entries
    app_state.async_.event.side_effect = create_event

    range_index = -1
    expected_ranges = [
        3 + (2 * 49),   # 101 which is MINIMUM_ACTIVE_SUBSCRIPTIONS with one extra for a script type set
                        # where it should be 2 (script type count) * 50 (receiving gap) if there
                        # were no minimum limit.
        103 + (2 * 10), # The extra 2 scripts from the base gap limit, plus 10 more keys to fill
                        # out the gap given that 10 BIP32 keys are used.
    ]
    def extend_range_cb(new_range: int) -> None:
        nonlocal range_index, expected_ranges
        range_index += 1
        assert new_range == expected_ranges[range_index]

    item_hasher = ScriptHasher()
    search_enumerator = SearchKeyEnumerator(item_hasher)
    for input_line in input_lines_script:
        search_enumerator.add_explicit_item(input_line.keyinstance_id, ScriptType.P2PKH,
            input_line.script_hash)
    search_enumerator.add_bip32_subpath(RECEIVING_SUBPATH, [ xpub1 ], 1, SINGLE_SIGNER_SCRIPT_TYPES)
    scan_handler = ScriptHashHandler(network)
    scanner = BlockchainScanner(scan_handler, search_enumerator,
        extend_range_cb=extend_range_cb)

    await scanner.scan_for_usage()

    # Ensure the range callback was called.
    assert range_index > -1

    # Verify that the scanner has the expected script hash histories.
    for input_line in input_lines:
        assert scan_handler._results[input_line.script_hash].history == input_line.history

    # Clean up and verify that all the worker tasks exited with the expected result.
    for task in worker_tasks:
        with pytest.raises(SubscriptionStale):
            await task


@pytest.mark.asyncio
@pytest.mark.timeout(2)
@unittest.mock.patch('electrumsv.blockchain_scanner.app_state')
async def test_scanner_pump_bip32(app_state):
    """
    We only register the receiving path.
    We fake a result for each and use our random script hash for several to verify they get placed.
    """
    worker_tasks: List[asyncio.Task] = []

    # This will get called to subscribe within `add_script`.
    def create_entries(entries: List[SubscriptionEntry], _owner: SubscriptionOwner):
        nonlocal input_lines, scanner, worker_tasks
        for entry in entries:
            assert entry.key.value_type == SubscriptionType.SCRIPT_HASH
            input_line = input_line_map.get(entry.key.value)
            history: ElectrumXHistoryList = []
            if input_line is not None:
                assert entry.key.value == input_line.script_hash
                history = input_line.history
            worker_task = asyncio.create_task(post_event(scanner, entry, history))
            worker_tasks.append(worker_task)

    assert isinstance(xpub1, BIP32PublicKey)

    network = unittest.mock.Mock()
    network.subscriptions = unittest.mock.Mock()
    network.subscriptions.create_entries.side_effect = create_entries
    app_state.async_.event.side_effect = create_event

    input_lines, input_line_map = await generate_bip32_input_lines(SINGLE_SIGNER_SCRIPT_TYPES)

    range_index = -1
    expected_ranges = [
        DEFAULT_GAP_LIMITS[RECEIVING_SUBPATH] * len(SINGLE_SIGNER_SCRIPT_TYPES),
        # Account for the gap being pushed out by 10 used keys.
        (DEFAULT_GAP_LIMITS[RECEIVING_SUBPATH] + 10) * len(SINGLE_SIGNER_SCRIPT_TYPES),
    ]
    def extend_range_cb(new_range: int) -> None:
        nonlocal range_index, expected_ranges
        range_index += 1
        assert new_range == expected_ranges[range_index]

    item_hasher = ScriptHasher()
    search_enumerator = SearchKeyEnumerator(item_hasher)
    receiving_path = search_enumerator.add_bip32_subpath(RECEIVING_SUBPATH, [ xpub1 ], 1,
        SINGLE_SIGNER_SCRIPT_TYPES)
    scan_handler = ScriptHashHandler(network)
    scanner = BlockchainScanner(scan_handler, search_enumerator,
        extend_range_cb=extend_range_cb)

    await scanner.scan_for_usage()

    # Ensure the range callback was called.
    assert range_index > -1
    # Account for the gap being pushed out by 10 used keys.
    assert receiving_path.last_index + 1 == DEFAULT_GAP_LIMITS[RECEIVING_SUBPATH] + 10

    # Verify that the scanner has the expected script hash histories.
    for input_line in input_lines:
        assert scan_handler._results[input_line.script_hash].history == input_line.history

    # Clean up and verify that all the worker tasks exited with the expected result.
    for task in worker_tasks:
        with pytest.raises(SubscriptionStale):
            await task


@pytest.mark.asyncio
@pytest.mark.timeout(2)
@unittest.mock.patch('electrumsv.blockchain_scanner.app_state')
async def test_scanner_pump_script(app_state):
    input_lines = [
        InputLine(script_hash=b'1', keyinstance_id=111,
            history=[ { "tx_hash": "tx1", "height": 1111 } ]),
        InputLine(script_hash=b'2', keyinstance_id=222, history=[]),
        InputLine(script_hash=b'3', keyinstance_id=333, history=[]),
    ]
    worker_tasks: List[asyncio.Task] = []

    # This will get called to subscribe within `add_script`.
    def create_entries(entries: List[SubscriptionEntry], owner: SubscriptionOwner):
        nonlocal input_lines, scanner, worker_tasks
        assert len(entries) == 3
        for i, entry in enumerate(entries):
            assert entry.key.value_type == SubscriptionType.SCRIPT_HASH
            assert entry.key.value == input_lines[i].script_hash
            worker_task = asyncio.create_task(post_event(scanner, entry, input_lines[i].history))
            worker_tasks.append(worker_task)

    network = unittest.mock.Mock()
    network.subscriptions = unittest.mock.Mock()
    network.subscriptions.create_entries.side_effect = create_entries
    app_state.async_.event.side_effect = create_event

    extend_range_called = False
    def extend_range_cb(new_range: int) -> None:
        nonlocal extend_range_called, input_lines
        extend_range_called = True
        assert new_range == len(input_lines)

    item_hasher = ScriptHasher()
    search_enumerator = SearchKeyEnumerator(item_hasher)
    for input_line in input_lines:
        search_enumerator.add_explicit_item(input_line.keyinstance_id, ScriptType.P2PKH, input_line.script_hash)
    scan_handler = ScriptHashHandler(network)
    scanner = BlockchainScanner(scan_handler, search_enumerator,
        extend_range_cb=extend_range_cb)

    await scanner.scan_for_usage()

    assert extend_range_called

    # Verify that the scanner has the expected script hash histories.
    for input_line in input_lines:
        assert scan_handler._results[input_line.script_hash].history == input_line.history

    # Clean up and verify that all the worker tasks exited with the expected result.
    for task in worker_tasks:
        with pytest.raises(SubscriptionStale):
            await task


@unittest.mock.patch('electrumsv.blockchain_scanner.app_state')
def test_scanner_bip32_correctness(app_state):
    network = unittest.mock.Mock()
    app_state.subscriptions = unittest.mock.Mock()
    assert isinstance(xpub1, BIP32PublicKey)

    item_hasher = ScriptHasher()
    search_enumerator = SearchKeyEnumerator(item_hasher)
    scan_handler = ScriptHashHandler(network)
    scanner = BlockchainScanner(scan_handler, search_enumerator)

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
    assert hash_to_hex_str(entry.item_hash) == xpub1_scripthash_0_0

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
    assert hash_to_hex_str(entry.item_hash) != xpub1_scripthash_0_0

    # Just verify that the first change entry is correct where it counts.
    change_path = BIP32ParentPath(CHANGE_SUBPATH, 1, [ xpub1 ], (ScriptType.P2PKH,))
    entries = search_enumerator._obtain_entries_from_bip32_path(1, change_path)
    assert len(entries) == 1
    assert change_path.last_index == 0
    entry = entries[0]
    assert entry.parent_path == change_path
    assert entry.parent_index == 0
    assert hash_to_hex_str(entry.item_hash) == xpub1_scripthash_1_0

