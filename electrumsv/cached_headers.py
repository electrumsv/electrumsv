from __future__ import annotations
import array
from hashlib import sha256
import io
import os
from typing import cast, NamedTuple

import bitcoinx
from bitcoinx import Chain, CheckPoint, Headers, Network, pack_le_uint16, pack_le_uint32, \
    read_le_uint16, read_le_uint32

from .logs import logs


logger = logs.get_logger("app_state")


def flush_headers_object(headers: Headers) -> None:
    # `mmap.flush` exceptions (The Python developers do not document these):
    # Raises `ValueError` for invalid offset and size arguments relating to type and range,
    #     and if `flush` is not supported on `UNIX` (MacOS inclusive) or `MS_WINDOWS`
    #     operating systems.
    # Raises `OSError` for specific OS-related Unix and Windows errors.
    # We do not catch `ValueError` as we do not pass arguments and we do not support
    # operating systems without `mmap.flush` support. We do not catch `OSError` as this
    # is representative of problems that are so severe the user's wallet (at the least
    # the headers file) is likely corrupted and we should never hide this.
    headers.flush()


def close_headers_object(headers: Headers) -> None:
    flush_headers_object(headers)
    # We close the header storage to prevent further writes. These should never happen but
    # we want to avoid past problems which seem to be where unflushed writes are lost
    # and the header file corrupted.
    # rt12: 20230306 bitcoinx does not currently expose this.
    headers._storage.close()


def read_unprocessed_headers(headers: Headers, last_index: int) -> None:
    """
    Read in all the headers from storage, starting from the next storage index above where we
    left off. This must pick up any additional headers written to the header storage that were
    not included in the last written metadata.
    """
    logger.debug("Reading unprocessed headers: %d to %d", last_index+1, len(headers)-1)
    read_header = headers._read_header
    for header_index in range(last_index + 1, len(headers)):
        read_header(header_index)



# NOTE(typing) `bitcoinx.Headers` is untyped. We have to ignore the typing error telling us that.
class ElectrumSVHeaders(Headers): # type: ignore[misc]
    """
    We only use this class if we are reconstituting the metadata from a matching data file.
    """
    def __init__(self, network: Network, file_path: str, checkpoint: CheckPoint) -> None:
        """
        The core reason for using this is to bypass the initial processing of the headers file
        so that we can use the chain data instead.
        """
        self.common_setup(network, file_path, checkpoint)

        self._chains: list[Chain] = []
        self._short_hashes = bytearray()
        self._heights = array.array('I')
        self._chain_indices = array.array('H')


def hash_headerfile(file_path: str, file_length: int) -> bytes:
    sha256_hash = sha256()
    with open(file_path, "rb") as hf:
        reserved_bytes = hf.read(bitcoinx.chain._HeaderStorage.struct_reserved.size)
        actual_reserved_size, header_store_version, header_store_count = \
            bitcoinx.chain._HeaderStorage.struct_reserved.unpack(reserved_bytes)
        # NOTE(rt12) If this starts erroring you need to consider what it means for our
        #     incremental chain data. bitcoinx would hopefully migrate.
        assert header_store_version == 0
        file_length -= bitcoinx.chain._HeaderStorage.struct_reserved.size

        while file_length > 0:
            headers_chunk = hf.read(min(65536, file_length))
            if not headers_chunk:
                assert file_length == 0
                break
            sha256_hash.update(headers_chunk)
            file_length -= len(headers_chunk)
    return sha256_hash.digest()


class CachedHeadersMetadata(NamedTuple):
    version: int
    headerfile_length: int
    headerfile_hash: bytes

class CachedHeadersChainData(NamedTuple):
    parent_first_height: int
    first_height: int
    tip_height: int
    tip_header_bytes: bytes
    work: int
    header_indices: array.array[int]

class CachedHeadersData(NamedTuple):
    last_index: int
    short_hashes: bytearray
    heights: array.array[int]
    chain_indices: array.array[int]


def read_cached_headers_metadata(f: io.BufferedReader) -> CachedHeadersMetadata:
    chaindata_version = read_le_uint16(f.read)
    assert chaindata_version == 1
    headerfile_length = read_le_uint32(f.read)
    headerfile_hash = f.read(32)
    assert len(headerfile_hash) == 32
    return CachedHeadersMetadata(chaindata_version, headerfile_length, headerfile_hash)

def write_cached_headers_metadata(f: io.BufferedWriter, file_length: int, file_hash: bytes) -> None:
    f.write(pack_le_uint16(1))
    f.write(pack_le_uint32(file_length))
    f.write(file_hash)

def read_cached_headers_data(f: io.BufferedReader) -> CachedHeadersData:
    last_index = read_le_uint32(f.read)
    short_hashes_length = read_le_uint32(f.read)
    short_hashes = bytearray(f.read(short_hashes_length))
    heights_count = read_le_uint32(f.read)
    heights = array.array("I")
    heights.fromfile(f, heights_count)
    chain_indices_count = read_le_uint32(f.read)
    chain_indices = array.array("H")
    chain_indices.fromfile(f, chain_indices_count)
    return CachedHeadersData(last_index, short_hashes, heights, chain_indices)

def write_cached_headers_data(f: io.BufferedWriter, headers: Headers) -> None:
    f.write(pack_le_uint32(len(headers)-1))
    f.write(pack_le_uint32(len(headers._short_hashes)))
    f.write(headers._short_hashes)
    f.write(pack_le_uint32(len(headers._heights)))
    headers._heights.tofile(f)
    f.write(pack_le_uint32(len(headers._chain_indices)))
    headers._chain_indices.tofile(f)

def read_cached_chain_data(f: io.BufferedReader) -> CachedHeadersChainData:
    parent_first_height = read_le_uint32(f.read)
    first_height = read_le_uint32(f.read)
    tip_height = read_le_uint32(f.read)
    tip_header_bytes = f.read(80)
    chain_work = int.from_bytes(f.read(32), "little")
    header_indices_count = read_le_uint32(f.read)
    header_indices = array.array("I")
    header_indices.fromfile(f, header_indices_count)
    return CachedHeadersChainData(parent_first_height, first_height, tip_height, tip_header_bytes,
        chain_work, header_indices)

def write_cached_chain_data(f: io.BufferedWriter, chain: Chain) -> None:
    # Genesis block is the first header/height of the first chain.
    f.write(pack_le_uint32(chain.parent.first_height if chain.parent is not None else 0))
    f.write(pack_le_uint32(chain.first_height))
    f.write(pack_le_uint32(chain.tip.height))
    f.write(chain.tip.raw)
    f.write(chain.work.to_bytes(32, "little"))
    # The number of items in the array (not the length of the data).
    f.write(pack_le_uint32(len(chain._header_indices)))
    chain._header_indices.tofile(f)

def read_cached_chains_data(f: io.BufferedReader, headers: ElectrumSVHeaders) -> None:
    chains_by_first_height: dict[int, Chain] = {}
    chains: list[Chain] = []

    chain_count = read_le_uint32(f.read)
    while len(chains) < chain_count:
        data = read_cached_chain_data(f)
        tip_header = headers.network.deserialized_header(data.tip_header_bytes, data.tip_height)
        parent_chain: Chain|None = None
        if data.first_height > 0:
            parent_chain = chains_by_first_height[data.parent_first_height]

        # It does not matter what we pass other than `parent_chain` as we will overwrite the rest.
        chain = Chain(parent_chain, tip_header, data.header_indices[-1], 0)
        # Overwrite the extra variables initialised in `Chain.__init__`.
        chain.tip = tip_header
        chain.work = data.work
        chain.first_height = data.first_height
        chain._header_indices = data.header_indices
        # Provide external value otherwise set in `Headers._add_chain`.
        chain.index = len(chains)
        chains.append(chain)
        chains_by_first_height[data.first_height] = chain
    headers._chains = chains

def write_cached_chains_data(f: io.BufferedWriter, headers: Headers) -> None:
    f.write(pack_le_uint32(len(headers._chains)))
    for chain in headers._chains:
        write_cached_chain_data(f, chain)


def write_cached_headers(headers: Headers) -> None:
    # Ensure all mmap modifications are written to disk. We can do this after the headers object
    # is closed down, and should only use runtime state.
    if not headers._storage.mmap.closed:
        headers.flush()

    headers_path = headers._storage.filename
    headerfile_size = headers._storage.reserved_size + headers._storage.header_count * 80
    headerfile_hash = hash_headerfile(headers_path, headerfile_size)

    chaindata_filename = headers_path +".chain_data"
    if os.path.exists(chaindata_filename):
        with open(chaindata_filename, "rb") as f:
            expected_headerfile_hash = f.read(32)
        if headerfile_hash == expected_headerfile_hash:
            logger.debug("header file is unchanged; skipping write")
            return

    with open(chaindata_filename, "wb") as f:
        write_cached_headers_metadata(f, headerfile_size, headerfile_hash)
        write_cached_headers_data(f, headers)
        write_cached_chains_data(f, headers)



def read_cached_headers(coin: Network, file_path: str, checkpoint: CheckPoint) -> Headers:
    chaindata_filename = file_path +".chain_data"
    if os.path.exists(chaindata_filename):
        logger.debug("cached chain data file found")

        with open(chaindata_filename, "rb") as f:
            metadata = read_cached_headers_metadata(f)
            actual_headerfile_hash = hash_headerfile(file_path, metadata.headerfile_length)
            if metadata.headerfile_hash == actual_headerfile_hash:
                logger.debug("Cached chain data file matches: %s", actual_headerfile_hash.hex())
                headers = ElectrumSVHeaders(coin, file_path, checkpoint)

                # Overwrite the headers fields.
                headers_data = read_cached_headers_data(f)
                headers._short_hashes = headers_data.short_hashes
                headers._heights = headers_data.heights
                headers._chain_indices = headers_data.chain_indices

                # Overwrite the headers chains.
                read_cached_chains_data(f, headers)

                read_unprocessed_headers(headers, headers_data.last_index)
                return cast(Headers, headers)

            logger.debug("Cached chain data file does not match: %s", actual_headerfile_hash.hex())
    else:
        logger.debug("Cached chain data file not found")

    return cast(Headers, Headers(coin, file_path, checkpoint))

