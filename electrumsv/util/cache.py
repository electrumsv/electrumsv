import bitcoinx
from collections import deque
from itertools import chain
import sys
from sys import getsizeof
from threading import RLock
from typing import Dict, List, Optional, Tuple

from ..transaction import Transaction, XPublicKey, XTxOutput, XTxInput
from ..constants import MAXIMUM_TXDATA_CACHE_SIZE_MB, MINIMUM_TXDATA_CACHE_SIZE_MB, \
    ScriptType


class Node:
    previous: 'Node'
    next: 'Node'
    key: bytes
    value: Transaction

    def __init__(self, previous: Optional['Node']=None, next: Optional['Node']=None,
            key: bytes=b'', value=None) -> None:
        self.previous = previous if previous is not None else self
        self.next = previous if previous is not None else self
        self.key = key
        self.value = value


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
        new_node = Node(most_recent_node, self._root, key, value)
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
                previous_node, next_node, old_value = node.previous, node.next, node.value
                assert value != old_value, "duplicate set not supported"
                previous_node.next = next_node
                next_node.previous = previous_node
                self.current_size -= self.obj_size(old_value)
                del self._cache[key]
                removals.append((key, old_value))

            size = self.obj_size(value)
            if value is not None and size <= self._max_size:
                added_node = self._add(key, value, size)
                added = True
                # Discount the root node when considering count.
                resize_removals = self._resize()
                assert all(t[0] != added_node.key for t in resize_removals), "removed added node"
                removals.extend(resize_removals)

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
        while len(self._cache)-1 >= self._max_count or self.current_size > self._max_size:
            node = self._root.next
            previous_node, next_node, discard_key, discard_value = \
                node.previous, node.next, node.key, node.value
            previous_node.next = next_node
            next_node.previous = previous_node
            self.current_size -= self.obj_size(discard_value)
            del self._cache[discard_key]
            removals.append((discard_key, discard_value))
        return removals

    def obj_size(self, o):
        """This is a modified version of: https://code.activestate.com/recipes/577504/
        to suit our bitcoin-specific needs

        Returns the approximate memory footprint of an object and all of its contents.

        Automatically finds the contents of the following builtin containers and
        their subclasses:  tuple, list, deque, dict, set.

        Additionally calculates the size of:
        - electrumsv.transaction.Transaction
        - electrumsv.transaction.XTxInput
        - electrumsv.transaction.XTxOutput
        - electrumsv.constants.ScriptType
        - bitcoinx.Script
        - bitcoinx.XPublicKey - approximation based on their serialized bytes footprint
        """
        dict_handler = lambda d: chain.from_iterable(d.items())

        def attrs_object_iterator(obj):
            """This is for iterating over attributes on classes produced via the 3rd
            party library "attrs"""
            return (getattr(obj, field.name) for field in obj.__attrs_attrs__)

        all_handlers = {
            tuple: iter,
            list: iter,
            deque: iter,
            dict: dict_handler,
            set: iter,
            Transaction: attrs_object_iterator,
            XTxInput: attrs_object_iterator,
            XTxOutput: attrs_object_iterator}

        seen = set()  # track which object id's have already been seen
        default_size = getsizeof(0)  # estimate sizeof object without __sizeof__

        def sizeof(o):

            if id(o) in seen:  # do not double count the same object
                return 0
            seen.add(id(o))
            s = getsizeof(o, default_size)

            if isinstance(o, bitcoinx.Script):
                s = len(o)

            if isinstance(o, ScriptType):
                s = 28

            if isinstance(o, XPublicKey):
                s = len(o.to_bytes())  # easiest approximation

            for typ, handler in all_handlers.items():
                if isinstance(o, typ):
                    s += sum(map(sizeof, handler(o)))
                    break

            return s

        return sizeof(o)
