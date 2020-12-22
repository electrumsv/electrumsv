"""
While we solely rely on the indexer, it makes sense to centralise subscriptions. This ensures that
there is no overlap between accounts within any of the different wallets that may be open, given
that subscriptions can only be made once.

In the longer run it is expected that each wallet might have it's own connection to a service or
services that provide the required data, and a funding account for use of it. This would move the
subscription management from the global application to the per-wallet context.
"""

import threading
from typing import Any, Dict, List, Optional, Set, Tuple
import weakref

from bitcoinx import hash_to_hex_str

from .constants import SubscriptionType
from .logs import logs
from .types import (SubscriptionEntry, SubscriptionKey, ScriptHashSubscriptionCallback,
    ScriptHashSubscriptionEntry, ScriptHashResultCallback, SubscriptionOwner,
    SubscriptionOwnerContextType)


logger = logs.get_logger("subscriptions")


# TODO(nocheckin) Need to unit test this class after it's been hooked into the different use
#     cases and proven to suit the needs.
class SubscriptionManager:
    _script_hashes_added_callback: Optional[ScriptHashSubscriptionCallback] = None
    _script_hashes_removed_callback: Optional[ScriptHashSubscriptionCallback] = None

    def __init__(self) -> None:
        # The network needs to be sure that it will not miss events, and any creation events
        # that start after it's read, are additive to that read. The worst case is that new
        # subscriptions would get missed and the wallets would never get events. Additionally,
        # given the servers have rate limiting that can get quite aggressive some times, not
        # doing double subscriptions benefits us there.
        self._lock = threading.RLock()

        # A sequence of ids for subscription entries.
        self._next_id = 1
        self._subscription_ids: Dict[SubscriptionKey, int] = {}
        self._subscriptions: Dict[SubscriptionKey, Set[SubscriptionOwner]] = {}
        self._owner_subscriptions: Dict[SubscriptionOwner, Set[SubscriptionKey]] = {}
        self._owner_subscription_context: Dict[Tuple[SubscriptionOwner, SubscriptionKey],
            SubscriptionOwnerContextType] = {}
        self._owner_callbacks: weakref.WeakValueDictionary[SubscriptionOwner,
            ScriptHashResultCallback] = weakref.WeakValueDictionary()

    def set_owner_callback(self, owner: SubscriptionOwner, callback: ScriptHashResultCallback) \
            -> None:
        self._owner_callbacks[owner] = callback

    def remove_owner(self, owner: SubscriptionOwner) -> None:
        with self._lock:
            if owner in self._owner_callbacks:
                del self._owner_callbacks[owner]

            if owner in self._owner_subscriptions:
                subscribed_entries = [ SubscriptionEntry(key, None)
                    for key in self._owner_subscriptions[owner] ]
                self.delete(subscribed_entries, owner)
                del self._owner_subscriptions[owner]

    def set_script_hash_callbacks(self, added_callback: ScriptHashSubscriptionCallback,
            removed_callback: ScriptHashSubscriptionCallback) -> None:
        self._script_hashes_added_callback = added_callback
        self._script_hashes_removed_callback = removed_callback

    def clear_script_hash_callbacks(self) -> None:
        self._script_hashes_added_callback = None
        self._script_hashes_removed_callback = None

    def _add_subscription(self, entry: SubscriptionEntry, owner: SubscriptionOwner) \
            -> Optional[int]:
        """
        Add the owner's subscription for the given subscription key.
        """
        key = entry.key
        if key.value_type == SubscriptionType.SCRIPT_HASH:
            assert type(key.value) is bytes, "subscribed script hashes must be bytes"
        assert entry.owner_context is not None
        self._owner_subscription_context[(owner, key)] = entry.owner_context
        owner_subscriptions = self._owner_subscriptions.setdefault(owner, set())
        if key in self._subscription_ids:
            # This is an existing subscription, it should already be subscribed.
            self._subscriptions[key].add(owner)
            owner_subscriptions.add(key)
            return None
        # This is a new subscription, it needs to be subscribed.
        subscription_id = self._next_id
        self._next_id = self._next_id + 1
        self._subscription_ids[key] = subscription_id
        self._subscriptions[key] = { owner }
        owner_subscriptions.add(key)
        return subscription_id

    def _remove_subscription(self, entry: SubscriptionEntry, owner: SubscriptionOwner) \
            -> Optional[int]:
        """
        Remove the owner's subscription for the given subscription key.

        This expects that the owner is calling this method in good faith and that the subscription
        was registered and exists. If all subscriptions for this key are now removed, the
        subscription is deleted and the unique ID of the key's subscription returned to reflect
        it.
        """
        key = entry.key
        if key.value_type == SubscriptionType.SCRIPT_HASH:
            assert type(key.value) is bytes, "subscribed script hashes must be bytes"
        subscription_id = self._subscription_ids[key]
        subscriptions = self._subscriptions[key]
        subscriptions.remove(owner)
        self._owner_subscriptions[owner].remove(key)
        del self._owner_subscription_context[(owner, key)]
        if len(subscriptions) == 0:
            del self._subscription_ids[key]
            del self._subscriptions[key]
            return subscription_id
        return None

    def create(self, entries: List[SubscriptionEntry], owner: SubscriptionOwner) -> None:
        """
        Add subscriptions from the given owner.
        """
        with self._lock:
            script_hash_entries: List[ScriptHashSubscriptionEntry] = []
            for entry in entries:
                subscription_id = self._add_subscription(entry, owner)
                if subscription_id is not None:
                    if entry.key.value_type == SubscriptionType.SCRIPT_HASH:
                        script_hash_entries.append(
                            ScriptHashSubscriptionEntry(subscription_id, entry.key.value))
                    else:
                        raise NotImplementedError(f"{entry.key.value_type} not supported")
            if self._script_hashes_added_callback is not None and len(script_hash_entries):
                from .app_state import app_state
                app_state.async_.spawn_and_wait(self._script_hashes_added_callback,
                    script_hash_entries)

    def read_script_hashes(self) -> List[ScriptHashSubscriptionEntry]:
        """
        Get all the existing script hash subscriptions.

        This is primarily useful for the networking when the main server changes and all the
        subscriptions need to be remade.
        """
        with self._lock:
            script_hash_entries: List[ScriptHashSubscriptionEntry] = []
            for key, subscription_id in self._subscription_ids.items():
                script_hash_entries.append(ScriptHashSubscriptionEntry(subscription_id, key.value))
            return script_hash_entries

    def delete(self, entries: List[SubscriptionEntry], owner: SubscriptionOwner) -> None:
        """
        Remove subscriptions from the given owner.
        """
        with self._lock:
            script_hash_entries: List[ScriptHashSubscriptionEntry] = []
            for entry in entries:
                subscription_id = self._remove_subscription(entry, owner)
                if subscription_id is not None:
                    # All subscriptions for this key are removed, notify unsubscribing is possible.
                    if entry.key.value_type == SubscriptionType.SCRIPT_HASH:
                        script_hash_entries.append(
                            ScriptHashSubscriptionEntry(subscription_id, entry.key.value))
                    else:
                        raise NotImplementedError(f"{entry.key.value_type} not supported")
            if self._script_hashes_removed_callback is not None and len(script_hash_entries):
                from .app_state import app_state
                app_state.async_.spawn_and_wait(self._script_hashes_removed_callback,
                    script_hash_entries)

    async def on_script_hash_history(self, subscription_id: int, script_hash: bytes,
            result: Optional[Dict[str, Any]]) -> None:
        subscription_key = SubscriptionKey(SubscriptionType.SCRIPT_HASH, script_hash)
        existing_subscription_id = self._subscription_ids.get(subscription_key)
        if existing_subscription_id != subscription_id:
            logger.error("Mismatched subscription for %s, expected %d got %s",
                hash_to_hex_str(script_hash), subscription_id, existing_subscription_id)
            return

        # Copy the list in case an owner unregisters mid-callback and the iterator does not
        # like it.
        for owner, callback in list(self._owner_callbacks.items()):
            if owner in self._subscriptions[subscription_key]:
                await callback(SubscriptionType.SCRIPT_HASH, script_hash, result)