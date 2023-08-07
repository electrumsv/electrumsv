import bitcoinx
from bitcoinx import Chain, Headers, pack_le_uint32
from collections.abc import Iterator
import os
from os import urandom
import random
import shutil
import tempfile
from typing import Callable
import unittest

from electrumsv import cached_headers
from electrumsv.networks import SVRegTestnet
import pytest

from ..cached_headers import HeaderPersistenceCursor
from .util import TEST_BLOCKCHAINS_PATH, TEST_HEADERS_PATH

HEADER_115_3677F4_PATH = os.path.join(TEST_HEADERS_PATH, "headers3_blockchain_115_3677f4")


some_good_bits = [486604799, 472518933, 453281356, 436956491]


def random_raw_header(prev_hash=None, good_bits=None):
    good_bits = good_bits or some_good_bits
    raw_header = bytearray(urandom(80))
    raw_header[72:76] = pack_le_uint32(random.choice(good_bits))
    if prev_hash:
        raw_header[4:36] = prev_hash
    return bytes(raw_header)


@pytest.fixture
def make_regtest_headers_copy() -> Iterator[Callable[[str|None],
        tuple[Headers, HeaderPersistenceCursor, str]]]:

    created_headers_objects: list[tuple[str, Headers]] = []
    def _make_regtest_headers(bitcoinx_headerfile_path: str|None) \
            -> tuple[Headers, HeaderPersistenceCursor, str]:
        nonlocal created_headers_objects
        temporary_path = tempfile.mkdtemp()
        temporary_file_path = os.path.join(temporary_path, "temporary_headers_file")
        if bitcoinx_headerfile_path is not None:
            shutil.copyfile(bitcoinx_headerfile_path, temporary_file_path)
        headers_object, cursor = cached_headers.read_cached_headers(SVRegTestnet.COIN,
            temporary_file_path)
        created_headers_objects.append((temporary_file_path, headers_object))
        return headers_object, cursor, temporary_file_path

    yield _make_regtest_headers

    for copied_file_path, headers_object in created_headers_objects:
        os.remove(copied_file_path)


@pytest.fixture
def read_header_bytes() -> Iterator[Callable[[str], Iterator[bytes]]]:
    # This is a exported blockchain headers file, which is each header on the
    # active chain in hex form line by line.
    def _make_header_bytes_generator(blockchain_name: str) -> Iterator[bytes]:
        blockchain_path = os.path.join(TEST_BLOCKCHAINS_PATH, blockchain_name)
        blockchain_headerlist_path = os.path.join(blockchain_path, "headers.txt")
        with open(blockchain_headerlist_path, "r") as f:
            block_id = f.readline().strip()
            while block_id:
                assert len(block_id) == 64
                blockfile_path = os.path.join(blockchain_path, block_id)
                assert os.path.isfile(blockfile_path)
                with open(blockfile_path, "rb") as block_file:
                    header_bytes = block_file.read(80)
                    # if True:
                    #     block_hash = hex_str_to_hash(block_id)
                    #     assert double_sha256(header_bytes) == block_hash
                    yield header_bytes
                block_id = f.readline().strip()

    yield _make_header_bytes_generator


def test_cached_headers_file_read_and_write(make_regtest_headers_copy: Callable[[str | None],
        tuple[Headers, HeaderPersistenceCursor, str]]) -> None:
    """
    Testing that `write_cached_headers_data` and `read_cached_headers_data` restore the same
    state that is present in the original object.
    """
    # Sanity check to make sure the headers we are getting are the ones we want.
    headers, cursor, temporary_file_path = make_regtest_headers_copy(HEADER_115_3677F4_PATH)
    assert headers.chain_count() == 1
    assert headers.longest_chain().tip().height == 115
    assert len(headers) == 116

    def _mock_headers_filename():
        return temporary_file_path

    app_state = unittest.mock.MagicMock()
    app_state.headers_filename = _mock_headers_filename
    assert app_state.headers_filename() == temporary_file_path

    # This will write a file with a .raw extension that didn't previously exist
    cached_headers.write_cached_headers(headers, cursor, app_state)

    # Is the chain data we read the same as what was written? It is not our job to verify that
    # `Headers` is working correctly, just that we recover the data it already had.
    headers2, cursor_from_read = cached_headers.read_cached_headers(SVRegTestnet.COIN,
        temporary_file_path)
    assert headers2.longest_chain().tip().hash == headers.longest_chain().tip().hash
    assert headers2.chain_count() == headers.chain_count()
    assert len(headers2) == 116


def compare_headers_instances(headers1: Headers, headers2: Headers):
    chain_other: Chain | None = None
    for chain, tip_hash in headers1.tips.items():
        for chain_other, tip_hash_copy in headers2.tips.items():
            if tip_hash == tip_hash_copy:
                break
        assert chain_other is not None
        if chain.parent is not None or chain_other.parent is not None:
            assert chain.parent.first_height == chain_other.parent.first_height
        assert chain.tip() == chain_other.tip()
        assert chain.chainwork == chain_other.chainwork
        assert chain.first_height == chain_other.first_height


def test_cached_headers_two_chains_and_incremental_updates(
        make_regtest_headers_copy: Callable[[str|None], Headers],
        read_header_bytes: Callable[[str], Iterator[bytes]]) -> None:
    """
    1. Make a copy of the stock single chain regtest blockchain.
    2. Inject 10 headers forking from Genesis, forming a second chain.
    3. Write the two chains representation to a file.
    4. Read the two chains representation from the file.
    5. Compare the modified copy to the original version and verify they are equivalent.
    6. Add a new random header and verify that
    """
    headers: Headers
    headers, cursor, temporary_file_path = make_regtest_headers_copy(HEADER_115_3677F4_PATH)
    # assert cursor == {}
    assert headers.chain_count() == 1
    assert headers.longest_chain().tip().height == 115
    assert len(headers) == 116

    for header_index, header_bytes in enumerate(read_header_bytes("blockchain_200_7d15f7")):
        # Connecting the genesis header will error. It is not supported.
        if header_index == 0:
            continue
        headers.connect(header_bytes)
        if header_index == 10:
            break

    assert headers.chain_count() == 2
    new_headers_filepath = temporary_file_path + "new"
    def _mock_headers_filename():
        return new_headers_filepath
    app_state = unittest.mock.MagicMock()
    app_state.headers_filename = _mock_headers_filename
    assert app_state.headers_filename() == new_headers_filepath
    cursor = {}
    cursor = cached_headers.write_cached_headers(headers, cursor, app_state)

    # Is the chain data we read the same as what was written? It is not our job to verify that
    # `Headers` is working correctly, just that we recover the data it already had.
    headers2, cursor2 = cached_headers.read_cached_headers(SVRegTestnet.COIN,
        new_headers_filepath)
    assert len(cursor2) == 2
    assert list(cursor2.values()) == [115, 10]
    assert len(cursor) == 2
    assert list(cursor.values()) == [115, 10]
    # The Chain objects are new instances so a reference to the original cursor must always be used
    assert cursor2.keys() != cursor.keys()
    assert headers2.chain_count() == 2
    compare_headers_instances(headers, headers2)

    # Append a random new header to the second, short chain (not yet persisted to disc)
    shortest_chain: Chain | None = None
    chain: Chain
    for chain, tip_hash in headers.tips.items():
        if shortest_chain is None:
            shortest_chain = chain
        elif shortest_chain.tip().height > chain.tip().height:
            shortest_chain = chain
    prev_hash = shortest_chain.tip().hash
    random_header = random_raw_header(prev_hash)
    new_expected_tip_hash = bitcoinx.double_sha256(random_header)
    headers.connect(random_header, check_work=False)
    assert shortest_chain.tip().hash == new_expected_tip_hash
    assert headers.unpersisted_headers(cursor) == random_header
    assert len(headers.cursor()) == 2
    assert list(headers.cursor().values()) == [115, 11]

    # Persist the new header to disc and read it back into headers3
    cursor = cached_headers.write_cached_headers(headers, cursor, app_state)
    headers3, cursor3 = cached_headers.read_cached_headers(SVRegTestnet.COIN, new_headers_filepath)
    assert list(cursor3.values()) == list(cursor.values())
    compare_headers_instances(headers, headers3)
