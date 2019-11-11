"""
Due to database latency and concurrency problems that will result in race conditions, all access
needs to be authoritatively cached above the database. This also reduces the locking overhead as
there will be no reads or
"""

import threading
import time
from typing import Optional, Dict, Set, Iterable, List, Tuple

from bitcoinx import double_sha256, hash_to_hex_str

from ..constants import TxFlags
from ..logs import logs
from ..transaction import Transaction
from .tables import (byte_repr, CompletionCallbackType, InvalidDataError, MissingRowError,
    TransactionTable, TxData, TxProof)


class TransactionCacheEntry:
    def __init__(self, metadata: TxData, flags: int, bytedata: Optional[bytes]=None,
            time_loaded: Optional[float]=None, is_bytedata_cached: bool=True) -> None:
        self._transaction = None
        self.metadata = metadata
        self.bytedata = bytedata
        self._is_bytedata_cached = is_bytedata_cached
        assert bytedata is None or is_bytedata_cached, \
            f"bytedata consistency check {bytedata} {is_bytedata_cached}"
        self.flags = flags
        self.time_loaded = time.time() if time_loaded is None else time_loaded

    def is_metadata_cached(self):
        # At this time the metadata blob is always loaded, either by itself, or accompanying
        # the bytedata.
        return self.metadata is not None

    def is_bytedata_cached(self):
        # This indicates if we have read the underlying full entry, and not just the metadata.
        # Hence it is set by default, and only clear on explicit reads of the metadata.
        return self._is_bytedata_cached

    @property
    def transaction(self) -> None:
        if self._transaction is None:
            if self.bytedata is None:
                return None
            self._transaction = Transaction.from_bytes(self.bytedata)
        return self._transaction

    def __repr__(self):
        return (f"TransactionCacheEntry({self.metadata}, {TxFlags.to_repr(self.flags)}, "
            f"{byte_repr(self.bytedata)}, {self._is_bytedata_cached})")


class TransactionCache:
    def __init__(self, store: TransactionTable) -> None:
        self._logger = logs.get_logger("cache-tx")
        self._cache: Dict[bytes, TransactionCacheEntry] = {}
        self._store = store

        self._lock = threading.RLock()

        self._logger.debug("caching all metadata records")
        self.get_metadatas()
        self._logger.debug("cached %d metadata records", len(self._cache))
        self._logger.debug("caching all unsettled transaction bytedata")
        entries = self.get_entries(flags=TxFlags.HasByteData,
            mask=TxFlags.HasByteData | TxFlags.StateSettled)
        self._logger.debug("matched %d unsettled transactions", len(entries))

    def set_store(self, store: TransactionTable) -> None:
        self._store = store

    def _validate_transaction_bytes(self, tx_hash: bytes, bytedata: Optional[bytes]) -> bool:
        if bytedata is None:
            return True
        return tx_hash == double_sha256(bytedata)

    def _entry_visible(self, entry_flags: int, flags: Optional[int]=None,
            mask: Optional[int]=None) -> bool:
        """
        Filter an entry based on it's flag bits compared to an optional comparison flag and flag
        mask value.
        - No flag and no mask: keep.
        - No flag and mask: keep if any masked bits are set.
        - Flag and no mask: keep if any masked bits are set.
        - Flag and mask: keep if the masked bits are the flags.
        """
        if flags is None:
            if mask is None:
                return True
            return (entry_flags & mask) != 0
        if mask is None:
            return (entry_flags & flags) != 0
        return (entry_flags & mask) == flags

    @staticmethod
    def _adjust_field_flags(data: TxData, flags: TxFlags) -> TxFlags:
        flags &= ~TxFlags.METADATA_FIELD_MASK
        flags |= TxFlags.HasFee if data.fee is not None else 0
        flags |= TxFlags.HasHeight if data.height is not None else 0
        flags |= TxFlags.HasPosition if data.position is not None else 0
        return flags

    @staticmethod
    def _validate_new_flags(flags: TxFlags) -> None:
        # All current states are expected to have bytedata.
        if (flags & TxFlags.STATE_MASK) == 0 or (flags & TxFlags.HasByteData) != 0:
            return
        raise InvalidDataError(f"setting uncleared state without bytedata {flags}")

    def add_missing_transaction(self, tx_hash: bytes, height: int, fee: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # TODO: Consider setting state based on height.
        date_added = self._store._get_current_timestamp()
        self.add([ (tx_hash,
            TxData(height=height, fee=fee, date_added=date_added, date_updated=date_added),
            None, TxFlags.Unset) ], completion_callback=completion_callback)

    def add_transaction(self, tx: Transaction, flags: Optional[TxFlags]=TxFlags.Unset,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        tx_hash = tx.hash()
        tx_hex = str(tx)
        bytedata = bytes.fromhex(tx_hex)
        date_updated = self._store._get_current_timestamp()
        self.update_or_add([ (tx_hash, TxData(date_added=date_updated, date_updated=date_updated),
            bytedata, flags | TxFlags.HasByteData) ], completion_callback=completion_callback)

    def add(self, inserts: List[Tuple[str, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        with self._lock:
            return self._add(inserts, completion_callback=completion_callback)

    def _add(self, inserts: List[Tuple[bytes, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        date_added = self._store._get_current_timestamp()
        for i, (tx_hash, metadata, bytedata, add_flags) in enumerate(inserts):
            assert tx_hash not in self._cache, f"Tx {tx_hash} found in cache unexpectedly"
            flags = self._adjust_field_flags(metadata, add_flags)
            if bytedata is not None:
                flags |= TxFlags.HasByteData
            assert ((add_flags & TxFlags.METADATA_FIELD_MASK) == 0 or
                flags == add_flags), f"{TxFlags.to_repr(flags)} != {TxFlags.to_repr(add_flags)}"
            self._validate_new_flags(flags)
            metadata = TxData(metadata.height, metadata.position,
                metadata.fee, date_added, date_added)
            self._cache[tx_hash] = TransactionCacheEntry(metadata, flags, bytedata)
            assert bytedata is None or self._cache[tx_hash].is_bytedata_cached(), \
                "bytedata not flagged as cached"
            inserts[i] = (tx_hash, metadata, bytedata, flags, None)

        self._store.create(inserts, completion_callback=completion_callback)

    def update(self, updates: List[Tuple[str, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        with self._lock:
            self._update(updates, completion_callback=completion_callback)

    def _update(self, updates: List[Tuple[str, TxData, Optional[bytes], TxFlags]],
            update_all: bool=True,
            completion_callback: Optional[CompletionCallbackType]=None) -> Set[str]:
        # NOTE: This does not set state flags at this time, from update flags.
        # We would need to pass in a per-row mask for that to work, perhaps.

        update_map = { t[0]: t for t in updates }
        desired_update_hashes = set(update_map)
        skipped_update_hashes = set([])
        actual_updates = {}
        date_updated = self._store._get_current_timestamp()
        # self._logger.debug("_update: desired_update_ids=%s", desired_update_ids)
        for tx_hash, entry in self._get_entries(tx_hashes=desired_update_hashes,
                require_all=update_all):
            _discard, metadata, bytedata, flags = update_map[tx_hash]
            # No-one should ever pass in field flags in normal circumstances.
            # In this case we use this to selectively merge the flagged fields in the update
            # to the cache entry data.
            fee = metadata.fee if flags & TxFlags.HasFee else entry.metadata.fee
            height = metadata.height if flags & TxFlags.HasHeight else entry.metadata.height
            position = metadata.position if flags & TxFlags.HasPosition else entry.metadata.position
            new_bytedata = bytedata if flags & TxFlags.HasByteData else entry.bytedata
            new_metadata = TxData(height, position, fee, entry.metadata.date_added,
                date_updated)
            # Take the existing entry flags and set the state ones based on metadata present.
            new_flags = self._adjust_field_flags(new_metadata,
                entry.flags & ~TxFlags.STATE_MASK)
            # Take the declared metadata flags that apply and set them.
            if flags & TxFlags.STATE_MASK != 0:
                new_flags |= flags & TxFlags.STATE_MASK
            else:
                new_flags |= entry.flags & TxFlags.STATE_MASK
            if new_bytedata is None:
                new_flags &= ~TxFlags.HasByteData
            else:
                new_flags |= TxFlags.HasByteData
            if (entry.metadata == new_metadata and entry.bytedata == new_bytedata and
                    entry.flags == new_flags):
                # self._logger.debug("_update: skipped %s %r %s %r %s %s", tx_hash, metadata,
                #     TxFlags.to_repr(flags), new_metadata, byte_repr(new_bytedata),
                #     entry.is_bytedata_cached())
                skipped_update_hashes.add(tx_hash)
            else:
                self._validate_new_flags(new_flags)
                is_full_entry = entry.is_bytedata_cached() or new_bytedata is not None
                new_entry = TransactionCacheEntry(new_metadata, new_flags, new_bytedata,
                    entry.time_loaded, is_full_entry)
                self._logger.debug("_update: %s %r %s %s %r %r HIT %s", hash_to_hex_str(tx_hash),
                    metadata, TxFlags.to_repr(flags), byte_repr(bytedata),
                    entry, new_entry, new_bytedata is None and (new_flags & TxFlags.HasByteData))
                actual_updates[tx_hash] = new_entry

        if len(actual_updates):
            self.set_cache_entries(actual_updates)
            update_entries = [
                (tx_hash, entry.metadata, entry.bytedata, entry.flags)
                for tx_hash, entry in actual_updates.items()
            ]
            self._store.update(update_entries, completion_callback=completion_callback)

        return set(actual_updates) | set(skipped_update_hashes)

    def update_or_add(self, upadds: List[Tuple[bytes, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # We do not require that all updates are applied, because the subset that do not
        # exist will be inserted.
        with self._lock:
            updated_ids = self._update(upadds, update_all=False,
                completion_callback=completion_callback)
            if len(updated_ids) != len(upadds):
                self._add([ t for t in upadds if t[0] not in updated_ids ],
                    completion_callback=completion_callback)
            return updated_ids

    def update_flags(self, tx_hash: bytes, flags: int, mask: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> TxFlags:
        # This is an odd function. It logical ors metadata flags, but replaces the other
        # flags losing their values.
        if mask is None:
            mask = TxFlags.METADATA_FIELD_MASK
        else:
            mask |= TxFlags.METADATA_FIELD_MASK

        with self._lock:
            date_updated = self._store._get_current_timestamp()
            entry = self._get_entry(tx_hash)
            entry.flags = (entry.flags & mask) | (flags & ~TxFlags.METADATA_FIELD_MASK)
            self._validate_new_flags(entry.flags)
            # Update the cached metadata for the new modification date.
            metadata = entry.metadata
            entry.metadata = TxData(metadata.height, metadata.position, metadata.fee,
                metadata.date_added, date_updated)
            self._store.update_flags([ (tx_hash, flags, mask, date_updated) ],
                completion_callback=completion_callback)
        return entry.flags

    def update_proof(self, tx_hash: bytes, proof: TxProof,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        with self._lock:
            date_updated = self._store._get_current_timestamp()
            entry = self._get_entry(tx_hash)
            metadata = entry.metadata
            entry.metadata = TxData(metadata.height, metadata.position, metadata.fee,
                metadata.date_added, date_updated)
            self._store.update_proof([ (tx_hash, proof, date_updated) ],
                completion_callback=completion_callback)

    def delete(self, tx_hash: bytes,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        with self._lock:
            self._logger.debug("cache_deletion: %s", hash_to_hex_str(tx_hash))
            del self._cache[tx_hash]

            self._store.delete([ tx_hash ], completion_callback=completion_callback)

    def get_flags(self, tx_hash: bytes) -> Optional[int]:
        # We cache all metadata, so this can avoid touching the database.
        entry = self.get_cached_entry(tx_hash)
        if entry is not None:
            return entry.flags

    def set_cache_entries(self, entries: Dict[bytes, TransactionCacheEntry]) -> None:
        for tx_hash, new_entry in entries.items():
            assert new_entry.metadata.date_added is not None
            if tx_hash in self._cache:
                entry = self._cache[tx_hash]
                if entry.is_bytedata_cached() and not new_entry.is_bytedata_cached():
                    self._logger.debug(f"set_cache_entries, bytedata conflict v1 {tx_hash}")
                    raise RuntimeError(f"bytedata conflict 1 for {tx_hash}")
                if entry.bytedata is not None and new_entry.bytedata is None:
                    self._logger.debug(f"set_cache_entries, bytedata conflict v2 {tx_hash}")
                    raise RuntimeError(f"bytedata conflict 2 for {tx_hash}")
        self._cache.update(entries)

    # NOTE: Only used by unit tests at this time.
    def is_cached(self, tx_hash: bytes) -> bool:
        return tx_hash in self._cache

    def get_cached_entry(self, tx_hash: bytes) -> Optional[TransactionCacheEntry]:
        if tx_hash in self._cache:
            return self._cache[tx_hash]

    def get_entry(self, tx_hash: bytes, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[TransactionCacheEntry]:
        with self._lock:
            return self._get_entry(tx_hash, flags, mask)

    def _get_entry(self, tx_hash: bytes, flags: Optional[int]=None,
            mask: Optional[int]=None,
            force_store_fetch: bool=False) -> Optional[TransactionCacheEntry]:
        # We want to hit the cache, but only if we can give them what they want. Generally if
        # something is cached, then all we may lack is the bytedata.
        if not force_store_fetch and tx_hash in self._cache:
            entry = self._cache[tx_hash]
            # If they filter the entry they request, we only give them a matched result.
            if not self._entry_visible(entry.flags, flags, mask):
                return None
            # If they don't want bytedata, or they do and we have it cached, give them the entry.
            if mask is not None and (mask & TxFlags.HasByteData) == 0 or entry.is_bytedata_cached():
                return entry
            force_store_fetch = True
        if not force_store_fetch:
            return None

        matches = self._store.read(flags, mask, tx_hashes=[tx_hash])
        if len(matches):
            tx_hash_, bytedata, flags_get, metadata = matches[0]
            if bytedata is None or self._validate_transaction_bytes(tx_hash, bytedata):
                # Overwrite any existing entry for this transaction. Due to the lock, and lack of
                # flushing we can assume that we will not be clobbering any fresh changes.
                entry = TransactionCacheEntry(metadata, flags_get, bytedata)
                self.set_cache_entries({ tx_hash: entry })
                self._logger.debug("get_entry/cache_change: %r", (tx_hash.hex(), entry,
                    TxFlags.to_repr(flags), TxFlags.to_repr(mask)))
                # If they filter the entry they request, we only give them a matched result.
                return entry if self._entry_visible(entry.flags, flags, mask) else None
            raise InvalidDataError(tx_hash)

        # TODO: If something is requested that does not exist, it will miss the cache and wait
        # on the store access every time. It should be possible to cache misses and also maintain/
        # update them on other accesses. A complication is the flag/mask filtering, which will
        # not indicate presence of entries for the tx_hash.
        return None

    def get_metadata(self, tx_hash: bytes, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[TxData]:
        with self._lock:
            return self._get_metadata(tx_hash, flags, mask)

    def _get_metadata(self, tx_hash: bytes, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[TransactionCacheEntry]:
        if tx_hash in self._cache:
            entry = self._cache[tx_hash]
            return entry.metadata if self._entry_visible(entry.flags, flags, mask) else None
        return None

    def have_transaction_data(self, tx_hash: bytes) -> bool:
        entry = self.get_cached_entry(tx_hash)
        return entry is not None and (entry.flags & TxFlags.HasByteData) != 0

    def get_transaction(self, tx_hash: bytes, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[Transaction]:
        # Ensure people do not ever use this to effectively request metadata and not require the
        # bytedata, meaning they get a result but it lacks what they expect it to have calling
        # this method.
        assert mask is None or (mask & TxFlags.HasByteData) != 0, "filter excludes transaction"
        entry = self.get_entry(tx_hash, flags, mask)
        if entry is not None:
            return entry.transaction

    def get_entries(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_hashes: Optional[Iterable[bytes]]=None,
            require_all: bool=True) -> List[Tuple[bytes, TransactionCacheEntry]]:
        with self._lock:
            return self._get_entries(flags, mask, tx_hashes, require_all)

    def _get_entries(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_hashes: Optional[Iterable[bytes]]=None,
            require_all: bool=True) -> List[Tuple[str, TransactionCacheEntry]]:
        # Raises MissingRowError if any transaction id in `tx_hashes` is not in the cache afterward,
        # if `require_all` is set.
        require_all = require_all and tx_hashes is not None

        store_tx_hashes = set()
        cache_tx_hashes = set()
        # We want to hit the cache, but only if we can give them what they want. Generally
        # if something is cached, then all we may lack is the bytedata.
        if tx_hashes is not None:
            for tx_hash in tx_hashes:
                # If it's not in the cache at least as metadata, then it does not exist.
                if tx_hash not in self._cache:
                    continue
                entry = self._cache[tx_hash]
                # If they filter the entry they request, we only give them a matched result.
                if not self._entry_visible(entry.flags, flags, mask):
                    continue
                # If they don't want bytedata, or they do and we have it cached, give them the
                # entry.
                if mask is not None and (mask & TxFlags.HasByteData) == 0 or \
                        entry.is_bytedata_cached():
                    cache_tx_hashes.add(tx_hash)
                    continue
                store_tx_hashes.add(tx_hash)
        else:
            tx_hashes = []
            for tx_hash, entry in self._cache.items():
                # If they filter the entry they request, we only give them a matched result.
                if not self._entry_visible(entry.flags, flags, mask):
                    continue
                # If they don't want bytedata, or they do and we have it cached, give them the
                # entry.
                if mask is not None and (mask & TxFlags.HasByteData) == 0 or \
                        entry.is_bytedata_cached():
                    cache_tx_hashes.add(tx_hash)
                    continue
                store_tx_hashes.add(tx_hash)
            tx_hashes.extend(cache_tx_hashes)
            tx_hashes.extend(store_tx_hashes)

        cache_additions = {}
        if len(store_tx_hashes):
            # self._logger.debug("get_entries specific=%s flags=%s mask=%s", store_tx_hashes,
            #     flags and TxFlags.to_repr(flags), mask and TxFlags.to_repr(mask))
            # We either fetch a known set of transactions, indicated by a non-empty set, or we
            # fetch all transactions matching the filter, indicated by an empty set.
            for tx_hash, bytedata, get_flags, metadata in self._store.read(
                    flags, mask, list(store_tx_hashes)):
                # Ensure the bytedata is valid.
                if bytedata is not None and not self._validate_transaction_bytes(tx_hash, bytedata):
                    raise InvalidDataError(tx_hash)
                # TODO: assert if the entry is there, or it is there and we are not just getting the
                # missing bytedata.
                cache_additions[tx_hash] = TransactionCacheEntry(metadata, get_flags, bytedata)
            self._logger.debug("get_entries/cache_additions: adds=%d", len(cache_additions))
            self.set_cache_entries(cache_additions)

        access_time = time.time()
        results = []
        for tx_hash in store_tx_hashes | cache_tx_hashes:
            entry = self._cache.get(tx_hash)
            assert entry is not None
            results.append((tx_hash, entry))

        if require_all:
            wanted_hashes = set(tx_hashes)
            have_hashes = set(t[0] for t in results)
            if wanted_hashes != have_hashes:
                raise MissingRowError(wanted_hashes - have_hashes)

        return results

    def get_metadatas(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_hashes: Optional[Iterable[bytes]]=None,
            require_all: bool=True) -> List[Tuple[bytes, TxData]]:
        with self._lock:
            return self._get_metadatas(flags=flags, mask=mask, tx_hashes=tx_hashes,
                require_all=require_all)

    def _get_metadatas(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_hashes: Optional[Iterable[bytes]]=None,
            require_all: bool=True) -> List[Tuple[bytes, TxData]]:
        if self._cache:
            if tx_hashes is not None:
                matches = []
                for tx_hash in tx_hashes:
                    entry = self._cache[tx_hash]
                    if self._entry_visible(entry.flags, flags, mask):
                        matches.append((tx_hash, entry.metadata))
                return matches
            return [ (t[0], t[1].metadata) for t in self._cache.items()
                if self._entry_visible(t[1].flags, flags, mask) ]

        store_tx_hashes = None
        if tx_hashes is not None:
            store_tx_hashes = [ tx_hash for tx_hash in tx_hashes if tx_hash not in self._cache ]

        cache_additions = {}
        new_matches = []
        existing_matches = []
        # tx_hashes will be None and store_tx_hashes will be None.
        # tx_hashes will be a list, and store_tx_hashes will be a list.
        if tx_hashes is None or len(store_tx_hashes):
            for tx_hash, flags_get, metadata in self._store.read_metadata(
                    flags, mask, store_tx_hashes):
                # We have no way of knowing if the match already exists, and if it does we should
                # take the possibly full/complete with bytedata cached version, rather than
                # corrupt the cache with the limited metadata version.
                if tx_hash in self._cache:
                    existing_matches.append((tx_hash, self._cache[tx_hash].metadata))
                else:
                    new_matches.append((tx_hash, metadata))
                    cache_additions[tx_hash] = TransactionCacheEntry(metadata, flags_get,
                        is_bytedata_cached=False)
            if len(cache_additions) > 0 or len(existing_matches) > 0:
                self._logger.debug("get_metadatas/cache_additions: adds=%d haves=%d %r...",
                    len(cache_additions),
                    len(existing_matches), existing_matches[:5])
            self.set_cache_entries(cache_additions)

        results = []
        if store_tx_hashes is not None and len(store_tx_hashes):
            for tx_hash in tx_hashes:
                entry = self._cache.get(tx_hash)
                if entry is None:
                    if require_all:
                        raise MissingRowError(tx_hash)
                elif self._entry_visible(entry.flags, flags, mask):
                    results.append((tx_hash, entry.metadata))
        else:
            results = new_matches + existing_matches
        return results

    def get_transactions(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_hashes: Optional[Iterable[bytes]]=None) -> List[Tuple[bytes, Transaction]]:
        # TODO: This should require that if bytedata is not cached for any entry, that that
        # entry has it's bytedata fetched and cached.
        results = []
        for tx_hash, entry in self.get_entries(flags, mask, tx_hashes):
            transaction = entry.transaction
            if transaction is not None:
                results.append((tx_hash, transaction))
        return results

    def get_height(self, tx_hash: bytes) -> Optional[int]:
        entry = self.get_cached_entry(tx_hash)
        if entry is not None and entry.flags & (TxFlags.StateSettled|TxFlags.StateCleared):
            return entry.metadata.height

    def get_unsynced_hashes(self) -> List[bytes]:
        entries = self.get_metadatas(flags=TxFlags.Unset, mask=TxFlags.HasByteData)
        return [ t[0] for t in entries ]

    def get_unverified_entries(self, watermark_height: int) -> Dict[bytes, int]:
        results = self.get_metadatas(
             flags=TxFlags.HasByteData | TxFlags.HasHeight,
            mask=TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.HasHeight)
        return [ (tx_hash, self._cache[tx_hash]) for (tx_hash, metadata) in results
            if 0 < metadata.height <= watermark_height ]

    def apply_reorg(self, reorg_height: int,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        fetch_flags = TxFlags.StateSettled
        fetch_mask = TxFlags.StateSettled
        unverify_mask = ~(TxFlags.HasHeight | TxFlags.HasPosition | TxFlags.HasProofData |
            TxFlags.STATE_MASK)

        with self._lock:
            date_updated = self._store._get_current_timestamp()
            # This does not request bytedata so if all metadata is cached, will not hit the
            # database.
            store_updates = []
            for (tx_hash, metadata) in self.get_metadatas(fetch_flags, fetch_mask):
                if metadata.height > reorg_height:
                    # Update the cached version to match the changes we are going to apply.
                    entry = self.get_cached_entry(tx_hash)
                    entry.flags = (entry.flags & unverify_mask) | TxFlags.StateCleared
                    # TODO(rt12) BACKLOG the real unconfirmed height may be -1 unconf parent
                    entry.metadata = TxData(height=0, fee=metadata.fee,
                        date_added=metadata.date_added,
                        date_updated=date_updated)
                    store_updates.append((tx_hash, entry.metadata, entry.flags))
            if len(store_updates):
                self._store.update_metadata(store_updates,
                    completion_callback=completion_callback)
            return len(store_updates)

