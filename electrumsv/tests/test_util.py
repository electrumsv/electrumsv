import pytest
import unittest

from electrumsv.util import format_satoshis, get_identified_release_signers
from electrumsv.util.cache import LRUCache

from .conftest import get_tx_datacarrier_size, get_tx_small_size


SIZEOF_TEST_TX_DATA = get_tx_datacarrier_size()
SIZEOF_TEST_TX_SMALL = get_tx_small_size()


class TestUtil(unittest.TestCase):
    def test_format_satoshis(self):
        result = format_satoshis(1234)
        expected = "0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_zero(self):
        result = format_satoshis(0)
        expected = "0."
        self.assertEqual(expected, result)

    def test_format_satoshis_negative(self):
        result = format_satoshis(-1234)
        expected = "-0.00001234"
        self.assertEqual(expected, result)

    def test_format_fee(self):
        result = format_satoshis(1700/1000, 0, 0)
        expected = "1.7"
        self.assertEqual(expected, result)

    def test_format_fee_precision(self):
        result = format_satoshis(1666/1000, 0, 0, precision=6)
        expected = "1.666"
        self.assertEqual(expected, result)

        result = format_satoshis(1666/1000, 0, 0, precision=1)
        expected = "1.7"
        self.assertEqual(expected, result)

    def test_format_satoshis_whitespaces(self):
        result = format_satoshis(12340, whitespaces=True)
        expected = "     0.0001234 "
        self.assertEqual(expected, result)

        result = format_satoshis(1234, whitespaces=True)
        expected = "     0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_whitespaces_negative(self):
        result = format_satoshis(-12340, whitespaces=True)
        expected = "    -0.0001234 "
        self.assertEqual(expected, result)

        result = format_satoshis(-1234, whitespaces=True)
        expected = "    -0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_positive(self):
        result = format_satoshis(1234, is_diff=True)
        expected = "+0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_negative(self):
        result = format_satoshis(-1234, is_diff=True)
        expected = "-0.00001234"
        self.assertEqual(expected, result)


def test_get_identified_release_signers():
    entry = {
	"version": "1.2.0",
	"date": "2019-03-20T18:00:00.000000+13:00",
	"signatures": [
    "IPHe+QklAmNmIdROtaMXt8YSomu9edExbQSg+Rm8Ckc8Mm1iAvb1yYIo1eqhJvndT9b6gaVtgtjzXaNAnfyKa20=",
    "IOpCqrDwQsOjOyMfr4FiHMeY6ekyHZz/qUJ/eas0KWN/XDl9HegERwL7Qcz+jKWg66X+2k9nT3KBvV0OopNpZd8="
    ]
    }

    assert get_identified_release_signers(entry) == {'kyuupichan', 'rt121212121'}

    entry['version'] = "1.2"
    assert not get_identified_release_signers(entry)


def test_lrucache_no_limit():
    with pytest.raises(AssertionError):
        cache = LRUCache()

@pytest.mark.parametrize("max_count,max_size", [ (10, None), (None, 10), (10, 10) ])
def test_lrucache_count_empty(max_count: int, max_size: int):
    cache = LRUCache(max_count=max_count, max_size=max_size)
    assert cache.hits == 0
    assert cache.misses == 0
    assert cache.current_size == 0

    v = cache.get(b'2')
    assert v is None
    assert cache.hits == 0
    assert cache.misses == 1

@pytest.mark.parametrize("max_count,max_size", [ (10, None), (None, 10 * SIZEOF_TEST_TX_DATA),
    (10, 10 * SIZEOF_TEST_TX_DATA) ])
def test_lrucache_add_single(max_count: int, max_size: int, test_tx_datacarrier) -> None:
    k = b'1'
    v = test_tx_datacarrier
    cache = LRUCache(max_count=max_count, max_size=max_size)
    added, removals = cache.set(k, v)
    assert added
    assert len(removals) == 0
    assert cache.current_size == SIZEOF_TEST_TX_DATA

    cached_value = cache.get(k)
    assert cached_value == v
    assert cache.hits == 1
    assert cache.misses == 0

    # Ensure a second fetch works given the order shuffling.
    cached_value = cache.get(k)
    assert cached_value == v
    assert cache.hits == 2
    assert cache.misses == 0

@pytest.mark.parametrize("max_count,max_size", [ (3, None), (None, 3*SIZEOF_TEST_TX_DATA),
    (3, 3*SIZEOF_TEST_TX_DATA) ])
def test_lrucache_add_to_limit(max_count: int, max_size: int, test_tx_datacarrier):
    entries = []
    cache = LRUCache(max_count=max_count, max_size=max_size)
    for i in range(1, 1+3):
        k = chr(i).encode()
        v = test_tx_datacarrier
        entries.append((k, v))
        added, removals = cache.set(k, v)
        assert added
        assert len(removals) == 0
    assert cache.current_size == 3*SIZEOF_TEST_TX_DATA
    assert cache.hits == 0
    assert cache.misses == 0

    for i, (k, v) in enumerate(entries):
        cached_value = cache.get(k)
        assert cached_value == v
        assert cache.hits == i+1
        assert cache.misses == 0

    v = cache.get(b'miss')
    assert v is None
    assert cache.misses == 1

@pytest.mark.parametrize("max_count,max_size", [ (3, None), (None, 3*SIZEOF_TEST_TX_DATA),
    (3, 3*SIZEOF_TEST_TX_DATA) ])
def test_lrucache_add_past_limit(max_count: int, max_size: int, test_tx_datacarrier) -> None:
    entries = []
    cache = LRUCache(max_count=max_count, max_size=max_size)
    for i in range(1, 1+4):
        k = chr(i).encode()
        v = test_tx_datacarrier
        entries.append((k, v))
        added, removals = cache.set(k, v)
        if i < 4:
            assert len(removals) == 0
        else:
            assert len(removals) == 1
            assert removals[0] == entries[0]
    assert cache.current_size == 3*SIZEOF_TEST_TX_DATA
    assert cache.hits == 0
    assert cache.misses == 0

    # Test the first entry is a miss.
    cached_value = cache.get(entries[0][0])
    assert cached_value is None
    assert cache.hits == 0
    assert cache.misses == 1

    # Test the other entries are hits.
    for i, (k, v) in enumerate(entries):
        if i == 0:
            continue
        cached_value = cache.get(k)
        assert cached_value == v
        assert cache.hits == i
        assert cache.misses == 1

@pytest.mark.parametrize("max_count,max_size", [ (3, None), (None, 3*SIZEOF_TEST_TX_DATA),
    (3, 3*SIZEOF_TEST_TX_DATA) ])
def test_lrucache_add_replacement(max_count: int, max_size: int) -> None:
    cache = LRUCache(max_count=max_count, max_size=max_size)
    added, removals = cache.set(b'1', b'2')
    assert added
    assert len(removals) == 0
    added, removals = cache.set(b'1', b'3')
    assert added
    assert removals == [(b'1', b'2')]
    assert cache.get(b'1') == b'3'

# Have key value smaller than max size, set key value larger than max size, neither set.
def test_lrucache_size_add_replacement_fails(test_tx_small, test_tx_datacarrier) -> None:
    cache = LRUCache(max_size=SIZEOF_TEST_TX_SMALL)
    added, removals = cache.set(b'1', test_tx_small)
    assert added
    assert len(removals) == 0
    assert cache.current_size == SIZEOF_TEST_TX_SMALL

    added, removals = cache.set(b'1', test_tx_datacarrier)  # same key larger than max size of cache
    assert not added
    assert removals == [(b'1', test_tx_small)]
    assert cache.get(b'1') is None
    assert cache.current_size == 0

def test_lrucache_size_add_fails(test_tx_datacarrier) -> None:
    cache = LRUCache(max_size=1000)
    added, removals = cache.set(b'1', test_tx_datacarrier)
    assert not added
    assert len(removals) == 0
    assert cache.current_size == 0

def test_lrucache_contains(test_tx_small) -> None:
    cache = LRUCache(10, 10*SIZEOF_TEST_TX_SMALL)
    assert b'1' not in cache
    cache.set(b'1', test_tx_small)
    assert b'1' in cache

@pytest.mark.parametrize("max_count,max_size", [ (3, None), (None, 3*SIZEOF_TEST_TX_SMALL),
    (3, 3*SIZEOF_TEST_TX_SMALL) ])
def test_lrucache_add_past_limit_lru_ordering(max_count: int, max_size: int, test_tx_small) -> None:
    cache = LRUCache(max_count=max_count, max_size=max_size)
    cache.set(b'1', test_tx_small)
    cache.set(b'2', test_tx_small)
    cache.set(b'3', test_tx_small)
    assert cache.get(b'1') == test_tx_small
    assert cache.get(b'3') == test_tx_small
    added, removals = cache.set(b'4', test_tx_small)
    assert added
    assert removals == [(b'2', test_tx_small)]
    assert cache.get(b'3') == test_tx_small
    added, removals = cache.set(b'5', test_tx_small)
    assert added
    assert removals == [(b'1', test_tx_small)]
    added, removals = cache.set(b'6', test_tx_small)
    assert added
    assert removals == [(b'4', test_tx_small)]
