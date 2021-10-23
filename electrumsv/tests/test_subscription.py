import asyncio
from typing import Any, cast, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from electrumsv.constants import ScriptType
from electrumsv.subscription import SubscriptionManager, SubscriptionOwner
from electrumsv.types import ElectrumXHistoryList, HashSubscriptionCallback, \
    HashSubscriptionEntry, \
    SubscriptionEntry, SubscriptionKey, SubscriptionKeyScriptHashOwnerContext, \
    SubscriptionOwnerContextType, SubscriptionOwnerPurpose, SubscriptionType


@patch('electrumsv.subscription.app_state')
def test_stop(app_state) -> None:
    manager = SubscriptionManager()
    manager.stop()
    assert manager._script_hash_notification_future.cancel.called

@patch('electrumsv.subscription.app_state')
def test_set_clear_script_callbacks(app_state) -> None:
    async def callback1(*args: Any): pass
    async def callback2(*args: Any): pass
    typed_callback1 = cast(HashSubscriptionCallback, callback1)
    typed_callback2 = cast(HashSubscriptionCallback, callback2)

    manager = SubscriptionManager()
    manager.set_script_hash_callbacks(typed_callback1, typed_callback2)
    assert manager._script_hashes_added_callback is not None and \
        manager._script_hashes_added_callback is typed_callback1
    assert manager._script_hashes_removed_callback is not None and \
        manager._script_hashes_removed_callback is typed_callback2

    manager.clear_script_hash_callbacks()
    assert manager._script_hashes_added_callback is None
    assert manager._script_hashes_removed_callback is None

@pytest.mark.asyncio
@patch('electrumsv.subscription.app_state')
async def test_history_event_delivery(app_state) -> None:
    # The mocked app_state will put a mock in place of the async queue if we do not ensure it is
    # created by replacing the relevant function. We want to be sure the function is using the
    # queue correctly, not that it appears to use a queue.
    app_state.async_.queue.side_effect = asyncio.Queue

    SUBSCRIPTION_ID = 1
    SCRIPT_HASH = b'123456'
    RESULTS: ElectrumXHistoryList = [{ "A": "z" }]

    manager = SubscriptionManager()
    await manager.on_script_hash_history(SUBSCRIPTION_ID, SCRIPT_HASH, RESULTS)

    assert manager._script_hash_notification_queue.qsize() == 1
    results = manager._script_hash_notification_queue.get_nowait()
    assert results == (SUBSCRIPTION_ID, SCRIPT_HASH, RESULTS)

@pytest.mark.asyncio
@patch('electrumsv.subscription.app_state')
async def test_history_event_processing(app_state) -> None:
    SUBSCRIPTION_ID_A = 1
    SUBSCRIPTION_ID_B = 2
    SCRIPT_HASH_A = b'AAAAAA'
    SCRIPT_HASH_B = b'BBBBBB'
    RESULTS_A: ElectrumXHistoryList = [{ "A": "z" }]
    RESULTS_B: ElectrumXHistoryList = [{ "A": "z" }]

    WALLET_ID = 1000
    ACCOUNT_ID = 2000
    SUBSCRIPTION_PURPOSE = SubscriptionOwnerPurpose.ACTIVE_KEYS
    SUBSCRIPTION_OWNER1 = SubscriptionOwner(WALLET_ID+1, ACCOUNT_ID+1, SUBSCRIPTION_PURPOSE)
    SUBSCRIPTION_OWNER2 = SubscriptionOwner(WALLET_ID+2, ACCOUNT_ID+2, SUBSCRIPTION_PURPOSE)
    KEYINSTANCE_ID = 3000

    # Called when `SUBSCRIPTION_OWNER1` is notified of an event.
    owner_callback1_called = False
    owner_callback1_entered = False
    async def owner_callback1(key: SubscriptionKey, context_type: SubscriptionOwnerContextType,
            results: ElectrumXHistoryList) -> None:
        nonlocal owner_callback1_called, owner_callback1_entered
        owner_callback1_entered = True
        assert key.value_type == SubscriptionType.SCRIPT_HASH
        assert key.value == SCRIPT_HASH_A
        assert isinstance(context_type, SubscriptionKeyScriptHashOwnerContext)
        context = cast(SubscriptionKeyScriptHashOwnerContext, context_type)
        assert context.keyinstance_id == KEYINSTANCE_ID+1
        assert context.script_type == ScriptType.P2PKH
        assert results == RESULTS_A
        owner_callback1_called = True

    # Called when `SUBSCRIPTION_OWNER2` is notified of an event.
    owner_callback2_called = False
    owner_callback2_entered = False
    async def owner_callback2(key: SubscriptionKey, context_type: SubscriptionOwnerContextType,
            results: ElectrumXHistoryList) -> None:
        nonlocal owner_callback2_called, owner_callback2_entered
        owner_callback2_entered = True
        assert key.value_type == SubscriptionType.SCRIPT_HASH
        assert key.value in (SCRIPT_HASH_A, SCRIPT_HASH_B)
        assert isinstance(context_type, SubscriptionKeyScriptHashOwnerContext)
        context = cast(SubscriptionKeyScriptHashOwnerContext, context_type)
        assert context.keyinstance_id in (KEYINSTANCE_ID+2, KEYINSTANCE_ID+20)
        assert context.script_type == ScriptType.P2PKH
        assert results in (RESULTS_A, RESULTS_B)
        owner_callback2_called = True

    manager = SubscriptionManager()
    manager.set_owner_callback(SUBSCRIPTION_OWNER1, owner_callback1)
    manager.set_owner_callback(SUBSCRIPTION_OWNER2, owner_callback2)
    assert len(manager._owner_callbacks) == 2

    # These are not used. The callback spawning is mocked out, but callbacks need to be present
    # to provide results on the mock itself, see `collect_additions`.
    async def add_callback(*args: Any) -> None:
        pass
    async def remove_callback(*args: Any) -> None:
        pass

    typed_add_callback = cast(HashSubscriptionCallback, add_callback)
    typed_remove_callback = cast(HashSubscriptionCallback, remove_callback)
    manager.set_script_hash_callbacks(typed_add_callback, typed_remove_callback)

    subscription_entries1: List[SubscriptionEntry] = [
        SubscriptionEntry(
            SubscriptionKey(SubscriptionType.SCRIPT_HASH, SCRIPT_HASH_A),
            SubscriptionKeyScriptHashOwnerContext(KEYINSTANCE_ID+1, ScriptType.P2PKH)),
    ]
    subscription_entries2: List[SubscriptionEntry] = [
        SubscriptionEntry(
            SubscriptionKey(SubscriptionType.SCRIPT_HASH, SCRIPT_HASH_A),
            SubscriptionKeyScriptHashOwnerContext(KEYINSTANCE_ID+2, ScriptType.P2PKH)),
        SubscriptionEntry(
            SubscriptionKey(SubscriptionType.SCRIPT_HASH, SCRIPT_HASH_B),
            SubscriptionKeyScriptHashOwnerContext(KEYINSTANCE_ID+20, ScriptType.P2PKH)),
    ]

    collected_additions: List[List[HashSubscriptionEntry]] = []
    def collect_additions(func: Any, entries: List[HashSubscriptionEntry]) -> MagicMock:
        collected_additions.append(entries)
        return MagicMock()

    app_state.app.run_coro.side_effect = collect_additions

    future = manager.create_entries(subscription_entries1, SUBSCRIPTION_OWNER1)
    # This just proves the addition callback path was followed.
    assert future is not None
    assert len(collected_additions) == 1
    additions = collected_additions.pop()
    assert additions[0].entry_id == 1
    assert additions[0].hash_value == SCRIPT_HASH_A

    future = manager.create_entries(subscription_entries2, SUBSCRIPTION_OWNER2)
    assert future is not None
    assert len(collected_additions) == 1
    additions = collected_additions.pop()
    assert additions[0].entry_id == 2
    assert additions[0].hash_value == SCRIPT_HASH_B

    async def queue_get_1() -> Tuple[int, bytes, ElectrumXHistoryList]:
        return SUBSCRIPTION_ID_A, SCRIPT_HASH_A, RESULTS_A
    manager._script_hash_notification_queue.get.side_effect = queue_get_1

    await manager._process_scripthash_notifications()
    assert len(manager._scripthash_result_cache) == 1
    assert manager._scripthash_result_cache == {
        SubscriptionKey(SubscriptionType.SCRIPT_HASH, SCRIPT_HASH_A): RESULTS_A }
    assert owner_callback1_called
    assert owner_callback2_called

    owner_callback1_entered = owner_callback2_entered = False
    owner_callback1_called = owner_callback2_called = False
    manager._scripthash_result_cache.clear()

    async def queue_get_2() -> Tuple[int, bytes, ElectrumXHistoryList]:
        return SUBSCRIPTION_ID_B, SCRIPT_HASH_B, RESULTS_B
    manager._script_hash_notification_queue.get.side_effect = queue_get_2

    await manager._process_scripthash_notifications()
    assert len(manager._scripthash_result_cache) == 1
    assert manager._scripthash_result_cache == {
        SubscriptionKey(SubscriptionType.SCRIPT_HASH, SCRIPT_HASH_B): RESULTS_B }
    # If the irrelevant first callback is called it will error and the exception will be swallowed
    # and logged, and we will not know.
    assert not owner_callback1_entered
    assert not owner_callback1_called
    assert owner_callback2_entered
    assert owner_callback2_called

