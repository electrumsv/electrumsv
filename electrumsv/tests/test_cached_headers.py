from collections.abc import Iterator
import io
import os
import shutil
import tempfile
from typing import Callable
import unittest

from bitcoinx import Headers
import pytest

from electrumsv import cached_headers
from electrumsv.cached_headers import ElectrumSVHeaders
from electrumsv.networks import SVRegTestnet

from .util import TEST_BLOCKCHAINS_PATH, TEST_HEADERS_PATH

HEADER_115_3677F4_PATH = os.path.join(TEST_HEADERS_PATH, "headers_blockchain_115_3677f4")


@pytest.fixture
def make_regtest_headers_copy() -> Iterator[Callable[[str|None], Headers]]:
    created_headers_objects: list[tuple[str, Headers]] = []
    def _make_regtest_headers(bitcoinx_headerfile_path: str|None) -> Headers:
        nonlocal created_headers_objects
        temporary_path = tempfile.mkdtemp()
        temporary_file_path = os.path.join(temporary_path, "temporary_headers_file")
        if bitcoinx_headerfile_path is not None:
            shutil.copyfile(bitcoinx_headerfile_path, temporary_file_path)
            if os.path.exists(bitcoinx_headerfile_path +".chain_data"):
                shutil.copyfile(bitcoinx_headerfile_path +".chain_data",
                    temporary_file_path +".chain_data")
        headers_object = cached_headers.read_cached_headers(SVRegTestnet.COIN, temporary_file_path,
            SVRegTestnet.CHECKPOINT)
        created_headers_objects.append((temporary_file_path, headers_object))
        return headers_object

    yield _make_regtest_headers

    for copied_file_path, headers_object in created_headers_objects:
        headers_object._storage.close()
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


def test_cached_headers_metadata() -> None:
    """
    Testing that `write_cached_headers_metadata` and `read_cached_headers_metadata` restores with
    the same values.
    """
    file_length = 1000
    file_hash = bytes.fromhex("fe61e3351ea6d71e9d1cb4bdaa5e11bcd92892e82cb0f8bc0bdda62302890785")

    file = io.BytesIO()
    buffered_file = io.BufferedRandom(file)
    cached_headers.write_cached_headers_metadata(buffered_file, file_length, file_hash)

    buffered_file.seek(0, os.SEEK_SET)
    assert file.read().hex() == "0100e8030000fe61e3351ea6d71e9d1cb4bdaa5e11bcd92892e82cb0f8bc0bdda62302890785"

    buffered_file.seek(0, os.SEEK_SET)
    metadata = cached_headers.read_cached_headers_metadata(buffered_file)
    assert metadata.version == 1
    assert metadata.headerfile_length == file_length
    assert metadata.headerfile_hash == file_hash

def test_cached_headers_data(make_regtest_headers_copy: Callable[[str|None], Headers]) -> None:
    """
    Testing that `write_cached_headers_data` and `read_cached_headers_data` restore the same
    state that is present in the original object.
    """
    # Sanity check to make sure the headers we are getting are the ones we want.
    headers = make_regtest_headers_copy(HEADER_115_3677F4_PATH)
    assert headers.chain_count() == 1
    assert headers.longest_chain().tip.height == 115
    assert len(headers) == 116

    file = io.BytesIO()
    buffered_file = io.BufferedRandom(file)
    cached_headers.write_cached_headers_data(buffered_file, headers)

    # Is the chain data we read the same as what was written? It is not our job to verify that
    # `Headers` is working correctly, just that we recover the data it already had.
    buffered_file.seek(0, os.SEEK_SET)
    data = cached_headers.read_cached_headers_data(buffered_file)
    assert data.last_index == len(headers)-1
    assert data.short_hashes == headers._short_hashes
    assert data.heights == headers._heights
    assert data.chain_indices == headers._chain_indices

def test_cached_chains_data_one_chain(make_regtest_headers_copy: Callable[[str|None], Headers]) -> None:
    """
    Test that `write_cached_chains_data` and `read_cached_chains_data` restore the same state that
    is present in the original single "from genesis" chain.
    """
    # Sanity check to make sure the headers we are getting are the ones we want.
    headers = make_regtest_headers_copy(HEADER_115_3677F4_PATH)
    assert headers.chain_count() == 1
    assert headers.longest_chain().tip.height == 115
    assert len(headers) == 116

    file = io.BytesIO()
    buffered_file = io.BufferedRandom(file)
    cached_headers.write_cached_chains_data(buffered_file, headers)

    # Is the chain data we read the same as what was written? It is not our job to verify that
    # `Headers` is working correctly, just that we recover the data it already had.
    new_headers = ElectrumSVHeaders(SVRegTestnet.COIN, HEADER_115_3677F4_PATH,
        SVRegTestnet.CHECKPOINT)
    buffered_file.seek(0, os.SEEK_SET)
    cached_headers.read_cached_chains_data(buffered_file, new_headers)
    assert len(new_headers._chains) == 1

    chain = headers._chains[0]
    chain_copy = new_headers._chains[0]
    assert chain.parent == chain_copy.parent
    assert chain.tip == chain_copy.tip
    assert chain.work == chain_copy.work
    assert chain.first_height == chain_copy.first_height
    assert chain._header_indices == chain_copy._header_indices
    assert chain.index == chain_copy.index


def test_cached_chains_data_two_chains(make_regtest_headers_copy: Callable[[str|None], Headers],
        read_header_bytes: Callable[[str], Iterator[bytes]]) -> None:
    """
    1. Make a copy of the stock single chain regtest blockchain.
    2. Inject 10 headers forking from Genesis, forming a second chain.
    3. Write the two chain headers chains representation to a file.
    4. Read the two chain headers chains representation from the file.
    5. Compare the modified copy to the original version and verify they are equivalent.
    """
    headers = make_regtest_headers_copy(HEADER_115_3677F4_PATH)
    assert headers.chain_count() == 1
    assert headers.longest_chain().tip.height == 115
    assert len(headers) == 116

    for header_index, header_bytes in enumerate(read_header_bytes("blockchain_200_7d15f7")):
        # Connecting the genesis header will error. It is not supported.
        if header_index == 0:
            continue

        headers.connect(header_bytes)
        if header_index == 10:
            break

    assert headers.chain_count() == 2

    file = io.BytesIO()
    buffered_file = io.BufferedRandom(file)
    cached_headers.write_cached_chains_data(buffered_file, headers)

    # Is the chain data we read the same as what was written? It is not our job to verify that
    # `Headers` is working correctly, just that we recover the data it already had.
    new_headers = ElectrumSVHeaders(SVRegTestnet.COIN, HEADER_115_3677F4_PATH,
        SVRegTestnet.CHECKPOINT)
    buffered_file.seek(0, os.SEEK_SET)
    cached_headers.read_cached_chains_data(buffered_file, new_headers)

    assert len(new_headers._chains) == 2
    for chain_index, chain in enumerate(headers._chains):
        chain_copy = new_headers._chains[chain_index]
        if chain.parent is not None or chain_copy.parent is not None:
            assert chain.parent.index == chain_copy.parent.index
        assert chain.tip == chain_copy.tip
        assert chain.work == chain_copy.work
        assert chain.first_height == chain_copy.first_height
        assert chain._header_indices == chain_copy._header_indices
        assert chain.index == chain_copy.index


def test_incremental_update(make_regtest_headers_copy: Callable[[str|None], Headers],
        read_header_bytes: Callable[[str], Iterator[bytes]]) -> None:
    """
    We want to compare a incrementally continued restore of a bitcoinx headers store to the
    original fully processed version.

    1. Write a chain data file for the original headers object with its 115 header chain.
    2. Connect 10 extra headers to the original headers object.
    3. Duplicate the both the headers file and the paired chain data file for the original headers
       object into a duplicate headers object.
    4. Verify that the loading of the duplicate headers object loaded the chain data, identified
       that which header in the headers file was the last processed, and processed the remaining
       headers that had been connected and written but not persisted.
    """
    # Load the single chain 115 headers store.
    headers1 = make_regtest_headers_copy(HEADER_115_3677F4_PATH)
    cached_headers.write_cached_headers(headers1)
    assert os.path.exists(headers1._storage.filename +".chain_data")
    original_headers1_tip = headers1._chains[0].tip

    # Extend it to be double chain, 115 and 10 headers respectively.
    for header_index, header_bytes in enumerate(read_header_bytes("blockchain_200_7d15f7")):
        # Connecting the genesis header will error. It is not supported.
        if header_index == 0:
            continue

        # We only connect 10 as connecting more proves nothing.
        if header_index <= 10:
            headers1.connect(header_bytes)
            continue
        break
    headers1.flush()

    original_read_cached_chains_data = cached_headers.read_cached_chains_data
    original_read_unprocessed_headers = cached_headers.read_unprocessed_headers
    with unittest.mock.patch("electrumsv.cached_headers.read_cached_chains_data") as mock_read, \
            unittest.mock.patch("electrumsv.cached_headers.read_unprocessed_headers") \
                as mock_read_file:
        def mocked_read_cached_chains_data(f: io.BufferedReader, headers: ElectrumSVHeaders) \
                -> None:
            original_read_cached_chains_data(f, headers)
            # Verify that the restored state at this point matches the chain data we saved.
            assert len(headers._chains) == 1
            assert headers._chains[0].tip == original_headers1_tip
        mock_read.side_effect = mocked_read_cached_chains_data

        def mocked_read_unprocessed_headers(local_headers2: Headers, last_index: int) -> None:
            # Verify that the extended headers are present, but the chain data knows it's
            # state is only up to the pre-extension header index. The incremental read that
            # we are intercepting will process the outstanding headers.
            assert len(local_headers2._storage) == 1 + 115 + 10
            assert last_index == 115
            original_read_unprocessed_headers(local_headers2, last_index)
            assert len(local_headers2._storage) == 1 + 115 + 10
        mock_read_file.side_effect = mocked_read_unprocessed_headers

        # This should be a full processed copy of the double chain headers store.
        headers2 = make_regtest_headers_copy(headers1._storage.filename)

        mock_read.assert_called_once()
        mock_read_file.assert_called_once()

        # These should be all the internal data structures in a headers object.
        assert headers1._short_hashes == headers2._short_hashes
        assert headers1._heights == headers2._heights
        assert headers1._chain_indices == headers2._chain_indices

        # Verify that the unextended chain data was used as a base and the extra headers
        # connected to give the same result as the original extended headers object.
        assert len(headers2._chains) == 2
        for chain_index, chain in enumerate(headers1._chains):
            chain_copy = headers2._chains[chain_index]
            if chain.parent is not None or chain_copy.parent is not None:
                assert chain.parent.index == chain_copy.parent.index
            assert chain.tip == chain_copy.tip
            assert chain.work == chain_copy.work
            assert chain.first_height == chain_copy.first_height
            assert chain._header_indices == chain_copy._header_indices
            assert chain.index == chain_copy.index
