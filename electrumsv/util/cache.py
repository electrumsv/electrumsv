import sys
from threading import RLock
from typing import Dict, List, Optional, Tuple

from .misc import obj_size
from ..transaction import Transaction
from ..constants import MAXIMUM_TXDATA_CACHE_SIZE_MB, MINIMUM_TXDATA_CACHE_SIZE_MB


class Node:
    previous: 'Node'
    next: 'Node'
    key: bytes
    value: Transaction

    def __init__(self, previous: Optional['Node']=None, next: Optional['Node']=None,
            key: bytes=b'', value=None,  value_size: int=0) -> None:
        """
        The only node which can have an empty key or value is the root node. None of the added
        nodes will have empty links, keys or values.
        """
        self.previous = previous if previous is not None else self
        self.next = next if next is not None else self
        self.key = key
        self.value = value
        self.value_size = value_size


# Derived from functools.lrucache, LRUCache should be considered licensed under Python license.
# This intentionally does not have a dictionary interface for now.
class LRUCache:
    def __init__(self, max_count: Optional[int]=None, max_size: Optional[int]=None) -> None:
        self._cache: Dict[bytes, Node] = {}

        assert max_count is not None or max_size is not None, "need some limit"
        if max_size is None:
            max_size = MAXIMUM_TXDATA_CACHE_SIZE_MB * (1024 * 1024)
        assert MINIMUM_TXDATA_CACHE_SIZE_MB * (1024 * 1024) <= max_size <= \
            MAXIMUM_TXDATA_CACHE_SIZE_MB * (1024 * 1024), \
            f"maximum size {max_size} not within min/max constraints"
        self._max_size = max_size
        self._max_count: int = max_count if max_count is not None else sys.maxsize
        self.current_size = 0

        self.hits = self.misses = 0
        self._lock = RLock()
        # This will be a node in a bi-directional circular linked list with itself as sole entry.
        self._root = Node()

    def set_maximum_size(self, maximum_size: int, resize: bool=True) -> None:
        self._max_size = maximum_size
        if resize:
            with self._lock:
                self._resize()

    def get_sizes(self) -> Tuple[int, int]:
        return (self.current_size, self._max_size)

    def _add(self, key: bytes, value: Transaction, size: int) -> Node:
        most_recent_node = self._root.previous
        new_node = Node(most_recent_node, self._root, key, value, size)
        most_recent_node.next = self._root.previous = self._cache[key] = new_node
        self.current_size += size
        return new_node

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, key: bytes) -> bool:
        return key in self._cache

    def set(self, key: bytes, value: Optional[Transaction]) -> Tuple[bool, List[Tuple[
            bytes, Transaction]]]:
        added = False
        removals: List[Tuple[bytes, Transaction]] = []
        with self._lock:
            node = self._cache.get(key, None)
            if node is not None:
                # This will either remove the entry if the value is `None` or reorder the entry
                # to be the most recent by removing and readding it (meaning it will get flushed
                # from the cache after less recent transactions if space is needed).
                previous_node, next_node, old_value = node.previous, node.next, node.value
                previous_node.next = next_node
                next_node.previous = previous_node
                self.current_size -= node.value_size
                del self._cache[key]
                removals.append((key, old_value))

            size = obj_size(value)
            if value is not None and size <= self._max_size:
                added_node = self._add(key, value, size)
                a, b, c, d = len(self._cache)-1, self._max_count, self.current_size, self._max_size
                resize_removals = self._resize()
                assert all(t[0] != added_node.key for t in resize_removals), \
                    f"removed added node {a} {b} {c} {d}"
                removals.extend(resize_removals)
                added = True

        return added, removals

    def get(self, key: bytes) -> Optional[Transaction]:
        with self._lock:
            node = self._cache.get(key)
            if node is not None:
                previous_node, next_node, value = node.previous, node.next, node.value
                previous_node.next = next_node
                next_node.previous = previous_node
                most_recent_node = self._root.previous
                most_recent_node.next = self._root.previous = node
                node.previous = most_recent_node
                node.next = self._root
                self.hits += 1
                return value
            self.misses += 1
        return None

    def _resize(self) -> List[Tuple[bytes, Transaction]]:
        removals = []
        # Discount the root node when considering count.
        while len(self._cache) > self._max_count or self.current_size > self._max_size:
            node = self._root.next
            previous_node, next_node, discard_key, discard_value = \
                node.previous, node.next, node.key, node.value
            previous_node.next = next_node
            next_node.previous = previous_node
            self.current_size -= node.value_size
            del self._cache[discard_key]
            removals.append((discard_key, discard_value))
        return removals
