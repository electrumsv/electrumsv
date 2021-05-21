"""
While we solely rely on the indexer, it makes sense to centralise subscriptions. This ensures that
there is no overlap between accounts within any of the different wallets that may be open, given
that subscriptions can only be made once.

In the longer run it is expected that each wallet might have it's own connection to a service or
services that provide the required data, and a funding account for use of it. This would move the
subscription management from the global application to the per-wallet context.
"""

import concurrent.futures
import threading
from typing import Dict, List, Optional, Set, Tuple

from bitcoinx import hash_to_hex_str

from .constants import SubscriptionType
from .exceptions import SubscriptionStale
from .logs import logs
from .types import (ElectrumXHistoryList, SubscriptionEntry, SubscriptionKey,
    ScriptHashSubscriptionCallback, ScriptHashSubscriptionEntry, ScriptHashResultCallback,
    SubscriptionOwner, SubscriptionOwnerContextType)


logger = logs.get_logger("subscriptions")


# TODO(no-merge) Need to unit test this class after it's been hooked into the different use
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
        # The current result arrives as a response to an initial subcription, any subscriber for
        # another purpose who arrives later will miss it. For this reason we store the last result
        # for a subscription entry and give it to later concurrent subscribers.
        self._subscription_results: Dict[SubscriptionKey, ElectrumXHistoryList] = {}
        self._owner_subscriptions: Dict[SubscriptionOwner, Set[SubscriptionKey]] = {}
        self._owner_subscription_context: Dict[Tuple[SubscriptionOwner, SubscriptionKey],
            SubscriptionOwnerContextType] = {}
        self._owner_callbacks: Dict[SubscriptionOwner, ScriptHashResultCallback] = {}

    def set_owner_callback(self, owner: SubscriptionOwner, callback: ScriptHashResultCallback) \
            -> None:
        self._owner_callbacks[owner] = callback

    def remove_owner(self, owner: SubscriptionOwner) -> Optional[concurrent.futures.Future]:
        future: Optional[concurrent.futures.Future] = None
        with self._lock:
            if owner in self._owner_callbacks:
                del self._owner_callbacks[owner]

            if owner in self._owner_subscriptions:
                subscribed_entries = [ SubscriptionEntry(key, None)
                    for key in self._owner_subscriptions[owner] ]
                future = self.delete_entries(subscribed_entries, owner)
                del self._owner_subscriptions[owner]
        return future

    def set_script_hash_callbacks(self, added_callback: ScriptHashSubscriptionCallback,
            removed_callback: ScriptHashSubscriptionCallback) -> None:
        self._script_hashes_added_callback = added_callback
        self._script_hashes_removed_callback = removed_callback

    def clear_script_hash_callbacks(self) -> None:
        self._script_hashes_added_callback = None
        self._script_hashes_removed_callback = None

    def _add_subscription(self, entry: SubscriptionEntry, owner: SubscriptionOwner) \
            -> Tuple[int, bool]:
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
            return self._subscription_ids[key], False
        # This is a new subscription, it needs to be subscribed.
        subscription_id = self._next_id
        self._next_id = self._next_id + 1
        self._subscription_ids[key] = subscription_id
        self._subscriptions[key] = { owner }
        owner_subscriptions.add(key)
        return subscription_id, True

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

    def create_entries(self, entries: List[SubscriptionEntry], owner: SubscriptionOwner) -> None:
        """
        Add subscriptions from the given owner.
        """
        with self._lock:
            script_hash_entries: List[ScriptHashSubscriptionEntry] = []
            for entry in entries:
                subscription_id, is_new = self._add_subscription(entry, owner)
                if is_new:
                    if entry.key.value_type == SubscriptionType.SCRIPT_HASH:
                        script_hash_entries.append(
                            ScriptHashSubscriptionEntry(subscription_id, entry.key.value))
                    else:
                        raise NotImplementedError(f"{entry.key.value_type} not supported")
                elif self._script_hashes_added_callback is not None:
                    # This should not block and will spawn a task to do the notification.
                    self.check_notify_script_hash_history(entry.key, owner)
            if self._script_hashes_added_callback is not None and len(script_hash_entries):
                from .app_state import app_state
                # TODO(no-merge) This used to be spawn and wait but was changed to spawn to not
                #   block the caller. Is this acceptable behaviour?
                app_state.app.run_coro(self._script_hashes_added_callback,
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

    def delete_entries(self, entries: List[SubscriptionEntry], owner: SubscriptionOwner) \
            -> Optional[concurrent.futures.Future]:
        """
        Remove subscriptions from the given owner.
        """
        future: Optional[concurrent.futures.Future] = None
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
                # TODO(no-merge) This used to be spawn and wait but was changed to spawn to not
                #   block the caller. Is this acceptable behaviour? In this case, the caller would
                #   sometimes be the network thread and it would block it indefinitely, so we did
                #   not have an option.
                future = app_state.app.run_coro(self._script_hashes_removed_callback,
                    script_hash_entries)
        return future

    async def on_script_hash_history(self, subscription_id: int, script_hash: bytes,
            result: ElectrumXHistoryList) -> None:
        subscription_key = SubscriptionKey(SubscriptionType.SCRIPT_HASH, script_hash)
        existing_subscription_id = self._subscription_ids.get(subscription_key)
        if existing_subscription_id != subscription_id:
            logger.error("Mismatched subscription for %s, expected %d got %s",
                hash_to_hex_str(script_hash), subscription_id, existing_subscription_id)
            return

        self._subscription_results[subscription_key] = result

        for owner, callback in list(self._owner_callbacks.items()):
            await self._notify_script_hash_history(subscription_key, owner, callback, result)

    async def _notify_script_hash_history(self, subscription_key: SubscriptionKey,
            owner: SubscriptionOwner, callback: ScriptHashResultCallback,
            result: ElectrumXHistoryList) -> None:
        if owner in self._subscriptions[subscription_key]:
            # This may modify the contents of the owner context for this subscription.
            context = self._owner_subscription_context[(owner, subscription_key)]
            try:
                await callback(subscription_key, context, result)
            except SubscriptionStale:
                logger.debug("Removing a stale subscription for %s/%s", subscription_key,
                    owner)
                # TODO(no-merge) This needs to be unit tested.
                self.delete_entries([ SubscriptionEntry(subscription_key, context) ],
                    owner)
            except Exception:
                # Prevent unexpected exceptions raising up and killing the async.
                logger.exception("Failed dispatching subscription callback")

    def check_notify_script_hash_history(self, subscription_key: SubscriptionKey,
            owner: SubscriptionOwner) -> None:
        result = self._subscription_results.get(subscription_key)
        if result is None:
            return

        callback = self._owner_callbacks.get(owner)
        if callback is None:
            return

        from .app_state import app_state
        app_state.app.run_coro(self._notify_script_hash_history,
            subscription_key, owner, callback, result)

