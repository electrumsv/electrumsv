"""
Due to database latency and concurrency problems that will result in race conditions, all access
needs to be authoritatively cached above the database. This also reduces the locking overhead as
there will be no reads or
"""

import threading
import time
from typing import cast, Dict, Iterable, List, Optional, Sequence, Tuple

from bitcoinx import double_sha256, hash_to_hex_str

from ..constants import TxFlags, MAXIMUM_TXDATA_CACHE_SIZE_MB
from ..logs import logs
from ..transaction import Transaction
from .tables import (CompletionCallbackType, InvalidDataError, MAGIC_UNTOUCHED_BYTEDATA,
    MissingRowError, TransactionTable, TxData, TxProof, TransactionRow)
from ..util.cache import LRUCache


class TransactionCacheEntry:
    def __init__(self, metadata: TxData, flags: TxFlags, time_loaded: Optional[float]=None) -> None:
        self.metadata = metadata
        self.flags = flags
        self.time_loaded = time.time() if time_loaded is None else time_loaded

    def __repr__(self):
        return f"TransactionCacheEntry({self.metadata}, {TxFlags.to_repr(self.flags)})"


class TransactionCache:
    def __init__(self, store: TransactionTable, txdata_cache_size: Optional[int]=None) -> None:
        if txdata_cache_size is None:
            txdata_cache_size = MAXIMUM_TXDATA_CACHE_SIZE_MB * (1024 * 1024)

        self._logger = logs.get_logger("cache-tx")
        self._cache: Dict[bytes, TransactionCacheEntry] = {}
        self._txdata_cache = LRUCache(max_size=txdata_cache_size)
        self._store = store

        self._lock = threading.RLock()

        self._logger.debug("caching all metadata records")
        self.get_metadatas()
        self._logger.debug("cached %d metadata records", len(self._cache))

        if txdata_cache_size > 0:
            # How many of these can actually be cached is limited by the cache size.
            self._logger.debug("attempting to cache unsettled transaction bytedata")
            rows = self._store.read(TxFlags.HasByteData, TxFlags.HasByteData|TxFlags.StateSettled)
            for row in rows:
                self._txdata_cache.set(row[0], Transaction.from_bytes(row[1]))
            self._logger.debug("matched/cached %d unsettled transactions", len(rows))

    def set_store(self, store: TransactionTable) -> None:
        self._store = store

    def set_maximum_cache_size_for_bytedata(self, maximum_size: int,
            force_resize: bool=False) -> None:
        self._txdata_cache.set_maximum_size(maximum_size, force_resize)

    def _validate_transaction_bytes(self, tx_hash: bytes, bytedata: Optional[bytes]) -> bool:
        if bytedata is None:
            return True
        return tx_hash == double_sha256(bytedata)

    def _entry_visible(self, entry_flags: int, flags: Optional[TxFlags]=None,
            mask: Optional[TxFlags]=None) -> bool:
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
    def _adjust_metadata_flags(data: TxData, flags: TxFlags) -> TxFlags:
        flags &= ~TxFlags.METADATA_FIELD_MASK
        flags |= TxFlags.HasFee if data.fee is not None else 0
        flags |= TxFlags.HasHeight if data.height is not None else 0
        flags |= TxFlags.HasPosition if data.position is not None else 0
        return flags

    @staticmethod
    def _validate_new_flags(tx_hash: bytes, flags: TxFlags) -> None:
        # All current states are expected to have bytedata.
        if (flags & TxFlags.STATE_MASK) == 0 or (flags & TxFlags.HasByteData) != 0:
            return
        tx_id = hash_to_hex_str(tx_hash)
        raise InvalidDataError("setting uncleared state without bytedata "
            f"{tx_id} {TxFlags.to_repr(flags)}")

    def add_transaction(self, tx_hash: bytes, tx: Transaction,
            flags: TxFlags=TxFlags.Unset,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        assert isinstance(tx, Transaction)

        with self._lock:
            date_updated = self._store._get_current_timestamp()
            if tx_hash in self._cache:
                self.update([ (tx_hash, TxData(date_added=date_updated, date_updated=date_updated),
                    tx, flags | TxFlags.HasByteData) ], completion_callback=completion_callback)
            else:
                self.add([(tx_hash, TxData(date_added=date_updated, date_updated=date_updated),
                        tx, flags | TxFlags.HasByteData, None)],
                    completion_callback=completion_callback)

    def add(self, inserts: List[Tuple[bytes, TxData, Transaction, TxFlags, Optional[str]]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        with self._lock:
            return self._add(inserts, completion_callback=completion_callback)

    def _add(self, inserts: List[Tuple[bytes, TxData, Transaction, TxFlags, Optional[str]]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        """
        This infers the bytedata flag from the bytedata value for a given input row, and
        alters the flags to reflect that inference. This differs from update, which uses
        the input row's flag to indicate whether to retain the existing bytedata value/flag or
        overwrite them.
        """
        date_added = self._store._get_current_timestamp()
        for i, (tx_hash, metadata, tx, add_flags, description) in enumerate(inserts):
            assert tx_hash not in self._cache, \
                f"Tx {hash_to_hex_str(tx_hash)} found in cache unexpectedly"
            flags = self._adjust_metadata_flags(metadata, add_flags)
            if tx is not None:
                flags |= TxFlags.HasByteData
            assert ((add_flags & TxFlags.METADATA_FIELD_MASK) == 0 or flags == add_flags), \
                f"{TxFlags.to_repr(flags)} != {TxFlags.to_repr(add_flags)}"
            self._validate_new_flags(tx_hash, flags)
            metadata = TxData(metadata.height, metadata.position, metadata.fee, date_added,
                date_added)
            self._cache[tx_hash] = TransactionCacheEntry(metadata, flags)
            bytedata = None
            if tx is not None:
                self._txdata_cache.set(tx_hash, tx)
                bytedata = tx.to_bytes()
            inserts[i] = TransactionRow(  # type:ignore
                tx_hash, metadata, bytedata, flags, description)
        self._store.create(inserts, completion_callback=completion_callback)  # type:ignore

    def update(self, updates: List[Tuple[bytes, TxData, Optional[Transaction], TxFlags]],
            completion_callback: Optional[CompletionCallbackType]=None) -> int:
        with self._lock:
            return self._update(updates, completion_callback=completion_callback)

    def _update(self, updates: List[Tuple[bytes, TxData, Optional[Transaction], TxFlags]],
            update_all: bool=True,
            completion_callback: Optional[CompletionCallbackType]=None) -> int:
        """
        The flagged changes are applied to the existing entry, leaving the unflagged aspects
        as they were. An example of this is bytedata, the bytedata in the existing entry should
        remain the same (and it's flag) if the update row's bytedata flag is clear. If the update
        row's bytedata flag is set, then the entry will get the update row's bytedata value and
        the appropriate flag to indicate whether it is None or not (overwriting the existing
        entry's bytedata/bytedata flag). This differs from add, which sets the flag based on
        the bytedata.
        """
        # For any given update entry there are some nuances to how the update is applied w/ flags.
        update_map = { t[0]: t for t in updates }
        desired_update_hashes = set(update_map)
        updated_entries: List[Tuple[bytes, TxData, Optional[bytes], TxFlags]] = []

        date_updated = self._store._get_current_timestamp()
        for tx_hash, entry in self._get_entries(tx_hashes=desired_update_hashes,
                require_all=update_all):
            _tx_hash, incoming_metadata, incoming_tx, incoming_flags = update_map[
                tx_hash]

            # Apply metadata changes.
            fee = incoming_metadata.fee if incoming_flags & TxFlags.HasFee else entry.metadata.fee
            height = incoming_metadata.height if incoming_flags & TxFlags.HasHeight \
                else entry.metadata.height
            position = incoming_metadata.position if incoming_flags & TxFlags.HasPosition \
                else entry.metadata.position
            new_metadata = TxData(height, position, fee, entry.metadata.date_added, date_updated)
            flags = self._adjust_metadata_flags(new_metadata, entry.flags & ~TxFlags.STATE_MASK)

            # incoming_flags & STATE_MASK declares if the state flags are touched by the update.
            if incoming_flags & TxFlags.STATE_MASK != 0:
                flags |= incoming_flags & TxFlags.STATE_MASK
            else:
                flags |= entry.flags & TxFlags.STATE_MASK

            # incoming_flags & HasByteData declares if the bytedata is touched by the update.
            flags &= ~TxFlags.HasByteData
            if incoming_flags & TxFlags.HasByteData:
                flags |= TxFlags.HasByteData if incoming_tx is not None else TxFlags.Unset
            else:
                flags |= entry.flags & TxFlags.HasByteData

            if entry.metadata == new_metadata and entry.flags == flags:
                continue

            self._validate_new_flags(tx_hash, flags)
            new_entry = TransactionCacheEntry(new_metadata, flags, entry.time_loaded)
            self._logger.debug("_update: %s %r %s %r %r", hash_to_hex_str(tx_hash),
                incoming_metadata, TxFlags.to_repr(incoming_flags), entry, new_entry)
            self._cache[tx_hash] = new_entry
            if incoming_tx:  # serialize txs -> binary before all db writes
                incoming_bytedata: Optional[bytes] = incoming_tx.to_bytes()
            else:
                incoming_bytedata = None

            if incoming_flags & TxFlags.HasByteData:
                self._txdata_cache.set(tx_hash, incoming_tx)
            elif flags & TxFlags.HasByteData:
                # Indicate the user is not changing the bytedata, it's a metadata/flags update.
                incoming_bytedata = MAGIC_UNTOUCHED_BYTEDATA
            updated_entries.append((tx_hash, new_metadata, incoming_bytedata, flags))

        # The reason we don't dispatch metadata and entry updates as separate calls
        # is that there's no way of reusing a completion context for more than one thing.
        if len(updated_entries):
            self._store.update(updated_entries, completion_callback=completion_callback)
        return len(updated_entries)

    # TODO: This is problematic as it discards non-metadata flags unless the caller provides a mask
    # that preserves the ones that should be preserved. Perhaps mask should be obligatory.
    def update_flags(self, tx_hash: bytes, flags: TxFlags, mask: Optional[TxFlags]=None,
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
            assert entry is not None
            entry.flags = (entry.flags & mask) | (flags & ~TxFlags.METADATA_FIELD_MASK)
            self._validate_new_flags(tx_hash, entry.flags)
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
            assert entry is not None
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
            self._txdata_cache.set(tx_hash, None)
            self._store.delete([ tx_hash ], completion_callback=completion_callback)

    def get_flags(self, tx_hash: bytes) -> Optional[TxFlags]:
        # We cache all metadata, so this can avoid touching the database.
        entry = self._cache.get(tx_hash)
        if entry is not None:
            return entry.flags
        return None

    # NOTE: Only used by unit tests at this time.
    def is_cached(self, tx_hash: bytes) -> bool:
        return tx_hash in self._cache

    # This should not be used to get
    def get_entry(self, tx_hash: bytes, flags: Optional[TxFlags]=None,
            mask: Optional[TxFlags]=None) -> Optional[TransactionCacheEntry]:
        with self._lock:
            return self._get_entry(tx_hash, flags, mask)

    def _get_entry(self, tx_hash: bytes, flags: Optional[TxFlags]=None,
            mask: Optional[TxFlags]=None,
            force_store_fetch: bool=False) -> Optional[TransactionCacheEntry]:
        # We want to hit the cache, but only if we can give them what they want. Generally if
        # something is cached, then all we may lack is the bytedata.
        if not force_store_fetch and tx_hash in self._cache:
            entry = self._cache[tx_hash]
            # If they filter the entry they request, we only give them a matched result.
            if not self._entry_visible(entry.flags, flags, mask):
                return None
            # If they don't want bytedata give them the entry.
            if mask is not None and (mask & TxFlags.HasByteData) == 0:
                return entry
            # If they do, and we have it cached, then give them the entry.
            tx = self._txdata_cache.get(tx_hash)
            if tx is not None:
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
                entry = TransactionCacheEntry(metadata, flags_get)
                self._cache.update({ tx_hash: entry })
                if bytedata is not None:
                    self._txdata_cache.set(tx_hash, Transaction.from_bytes(bytedata))
                self._logger.debug("get_entry/cache_change: %r", (hash_to_hex_str(tx_hash),
                    entry, TxFlags.to_repr(flags), TxFlags.to_repr(mask)))
                # If they filter the entry they request, we only give them a matched result.
                if self._entry_visible(entry.flags, flags, mask):
                    return entry
                return None
            raise InvalidDataError(tx_hash)

        # TODO: If something is requested that does not exist, it will miss the cache and wait
        # on the store access every time. It should be possible to cache misses and also maintain/
        # update them on other accesses. A complication is the flag/mask filtering, which will
        # not indicate presence of entries for the tx_hash.
        return None

    def get_metadata(self, tx_hash: bytes, flags: Optional[TxFlags]=None,
            mask: Optional[TxFlags]=None) -> Optional[TxData]:
        with self._lock:
            return self._get_metadata(tx_hash, flags, mask)

    def _get_metadata(self, tx_hash: bytes, flags: Optional[TxFlags]=None,
            mask: Optional[TxFlags]=None) -> Optional[TxData]:
        if tx_hash in self._cache:
            entry = self._cache[tx_hash]
            return entry.metadata if self._entry_visible(entry.flags, flags, mask) else None
        return None

    def have_transaction_data(self, tx_hash: bytes) -> bool:
        entry = self._cache.get(tx_hash)
        return entry is not None and (entry.flags & TxFlags.HasByteData) != 0

    def have_transaction_data_cached(self, tx_hash: bytes) -> bool:
        return tx_hash in self._txdata_cache

    def get_transaction(self, tx_hash: bytes, flags: Optional[TxFlags]=None,
            mask: Optional[TxFlags]=None) -> Optional[Transaction]:
        assert mask is None or (mask & TxFlags.HasByteData) != 0, "filter excludes transaction"
        results = self.get_transactions(flags, mask, [ tx_hash ])
        if len(results):
            return results[0][1]
        return None

    def get_transactions(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Iterable[bytes]]=None) -> List[Tuple[bytes, Transaction]]:
        with self._lock:
            results = []
            for tx_hash, tx in self.get_transaction_datas(flags, mask, tx_hashes):
                results.append((tx_hash, tx))
            return results

    def get_transaction_data(self, tx_hash: bytes, flags: Optional[TxFlags]=None,
            mask: Optional[TxFlags]=None) -> Optional[bytes]:
        assert mask is None or (mask & TxFlags.HasByteData) != 0, "filter excludes transaction"
        results = self.get_transaction_datas(flags, mask, [ tx_hash ])
        if len(results):
            return results[0][1]
        return None

    def get_transaction_datas(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Iterable[bytes]]=None) -> List[Tuple[bytes, Transaction]]:
        with self._lock:
            results = []
            missing_tx_hashes = []
            for tx_hash, entry in self._get_entries(flags, mask, tx_hashes):
                if entry.flags & TxFlags.HasByteData == 0:
                    continue
                tx = self._txdata_cache.get(tx_hash)
                if tx is not None:
                    results.append((tx_hash, tx))
                else:
                    missing_tx_hashes.append(tx_hash)

            if len(missing_tx_hashes):
                for row in self._store.read(flags, mask, missing_tx_hashes):
                    if row[2] & TxFlags.HasByteData != 0:
                        bytedata = cast(bytes, row[1])
                        tx = Transaction.from_bytes(bytedata)
                        results.append((row[0], tx))  # type: ignore
                        self._txdata_cache.set(row[0], tx)
        return results

    def get_entries(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Iterable[bytes]]=None,
            require_all: bool=True) -> List[Tuple[bytes, TransactionCacheEntry]]:
        "Get the metadata and flags for the matched transactions."
        with self._lock:
            return self._get_entries(flags, mask, tx_hashes, require_all)

    def _get_entries(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Iterable[bytes]]=None,
            require_all: bool=True) -> List[Tuple[bytes, TransactionCacheEntry]]:
        # Raises MissingRowError if any transaction id in `tx_hashes` is not in the cache afterward,
        # if `require_all` is set.
        require_all = require_all and tx_hashes is not None

        results = []
        if tx_hashes is not None:
            for tx_hash in tx_hashes:
                entry = self._cache.get(tx_hash)
                if entry is not None and self._entry_visible(entry.flags, flags, mask):
                    results.append((tx_hash, entry))

            if require_all:
                wanted_hashes = set(tx_hashes)
                have_hashes = set(t[0] for t in results)
                if wanted_hashes != have_hashes:
                    raise MissingRowError(wanted_hashes - have_hashes)
        else:
            for tx_hash, entry in self._cache.items():
                if self._entry_visible(entry.flags, flags, mask):
                    results.append((tx_hash, entry))

        return results

    def get_metadatas(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Sequence[bytes]]=None,
            require_all: bool=True) -> List[Tuple[bytes, TxData]]:
        with self._lock:
            return self._get_metadatas(flags=flags, mask=mask, tx_hashes=tx_hashes,
                require_all=require_all)

    def _get_metadatas(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Sequence[bytes]]=None,
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

        store_tx_hashes: Optional[Sequence[bytes]] = None
        if tx_hashes is not None:
            store_tx_hashes = [ tx_hash for tx_hash in tx_hashes if tx_hash not in self._cache ]

        cache_additions = {}
        new_matches = []
        existing_matches = []
        # tx_hashes will be None and store_tx_hashes will be None.
        # tx_hashes will be a list, and store_tx_hashes will be a list.
        if tx_hashes is None or len(cast(Sequence[bytes], store_tx_hashes)):
            for tx_hash, flags_get, metadata in self._store.read_metadata(
                    flags, mask, store_tx_hashes):
                # We have no way of knowing if the match already exists, and if it does we should
                # take the possibly full/complete with bytedata cached version, rather than
                # corrupt the cache with the limited metadata version.
                if tx_hash in self._cache:
                    existing_matches.append((tx_hash, self._cache[tx_hash].metadata))
                else:
                    new_matches.append((tx_hash, metadata))
                    cache_additions[tx_hash] = TransactionCacheEntry(metadata, flags_get)
            if len(cache_additions) > 0 or len(existing_matches) > 0:
                self._logger.debug("get_metadatas/cache_additions: adds=%d haves=%d %r...",
                    len(cache_additions),
                    len(existing_matches), existing_matches[:5])
            self._cache.update(cache_additions)

        results = []
        if store_tx_hashes is not None and len(store_tx_hashes):
            assert tx_hashes is not None
            for tx_hash in tx_hashes:
                entry2 = self._cache.get(tx_hash)
                if entry2 is None:
                    if require_all:
                        raise MissingRowError(tx_hash)
                elif self._entry_visible(entry2.flags, flags, mask):
                    results.append((tx_hash, entry2.metadata))
        else:
            results = new_matches + existing_matches
        return results

    def get_height(self, tx_hash: bytes) -> Optional[int]:
        entry = self._cache.get(tx_hash)
        if entry is not None and entry.flags & (TxFlags.StateSettled|TxFlags.StateCleared):
            return entry.metadata.height
        return None

    def get_unsynced_hashes(self) -> List[bytes]:
        entries = self.get_metadatas(flags=TxFlags.Unset, mask=TxFlags.HasByteData)
        return [ t[0] for t in entries ]

    def get_unverified_entries(self, watermark_height: int) \
            -> List[Tuple[bytes, TransactionCacheEntry]]:
        results = self.get_metadatas(
            flags=TxFlags.HasByteData | TxFlags.HasHeight,
            mask=TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.HasHeight)
        if len(results) > 200:
            results = results[:200]
        return [ (tx_hash, self._cache[tx_hash]) for (tx_hash, metadata) in results
            if 0 < cast(int, metadata.height) <= watermark_height ]

    def apply_reorg(self, reorg_height: int,
            completion_callback: Optional[CompletionCallbackType]=None) \
            -> Tuple[int, List[bytes]]:
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
                if cast(int, metadata.height) > reorg_height:
                    # Update the cached version to match the changes we are going to apply.
                    entry = self._cache[tx_hash]
                    entry.flags = (entry.flags & unverify_mask) | TxFlags.StateCleared
                    # TODO(rt12) BACKLOG the real unconfirmed height may be -1 unconf parent
                    entry.metadata = TxData(height=0, fee=metadata.fee,
                        date_added=metadata.date_added, date_updated=date_updated)
                    store_updates.append((tx_hash, entry.metadata, entry.flags))
            if len(store_updates):
                self._store.update_metadata(store_updates,
                    completion_callback=completion_callback)
            return len(store_updates), [tx_hash for tx_hash, metadata, flags in store_updates]
