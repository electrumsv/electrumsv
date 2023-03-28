from __future__ import annotations
import array
from hashlib import sha256
import io
import os
from typing import cast, NamedTuple

from bitcoinx import Chain, CheckPoint, Headers, Network, pack_le_uint16, read_le_uint16, \
    pack_le_uint32, read_le_uint32

from .logs import logs


logger = logs.get_logger("app_state")


# NOTE(typing) `bitcoinx.Headers` is untyped. We have to ignore the typing error telling us that.
class ElectrumSVHeaders(Headers): # type: ignore[misc]
    """
    We only use this class if we are reconstituting the metadata from a matching data file.
    """
    def __init__(self, network: Network, file_path: str, checkpoint: CheckPoint) -> None:
        self.common_setup(network, file_path, checkpoint)

        self._chains: list[Chain] = []
        self._short_hashes = bytearray()
        self._heights = array.array('I')
        self._chain_indices = array.array('H')

    def read_incremental_file(self, last_index: int) -> None:
        """
        Read in all the headers from storage, starting from the next storage index above where we
        left off. This must pick up any additional headers written to the header storage that were
        not included in the last written metadata.
        """
        read_header = self._read_header
        for header_index in range(last_index + 1, len(self)):
            read_header(header_index)


def hash_headerfile(file_path: str, file_length: int) -> bytes:
    sha256_hash = sha256()
    with open(file_path, "rb") as hf:
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
    chaindata_version = read_le_uint16(f)
    assert chaindata_version == 1
    headerfile_length = read_le_uint32(f)
    headerfile_hash = f.read(32)
    assert len(headerfile_hash) == 32
    return CachedHeadersMetadata(chaindata_version, headerfile_length, headerfile_hash)

def write_cached_headers_metadata(f: io.BufferedWriter, file_length: int, file_hash: bytes) -> None:
    f.write(pack_le_uint16(1))
    f.write(pack_le_uint32(file_length))
    f.write(file_hash)

def read_cached_headers_data(f: io.BufferedReader) -> CachedHeadersData:
    last_index = read_le_uint32(f)
    short_hashes_length = read_le_uint32(f)
    short_hashes = bytearray(f.read(short_hashes_length))
    heights_count = read_le_uint32(f)
    heights = array.array("I")
    heights.fromfile(f, heights_count)
    chain_indices_count = read_le_uint32(f)
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
    parent_first_height = read_le_uint32(f)
    first_height = read_le_uint32(f)
    tip_height = read_le_uint32(f)
    tip_header_bytes = f.read(80)
    chain_work = read_le_uint32(f)
    header_indices_count = read_le_uint32(f)
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
    f.write(pack_le_uint32(chain.work))
    # The number of items in the array (not the length of the data).
    f.write(pack_le_uint32(len(chain._header_indices)))
    chain._header_indices.tofile(f)

def read_cached_chains_data(f: io.BufferedReader, headers: ElectrumSVHeaders) -> None:
    chains_by_first_height: dict[int, Chain] = {}
    chains: list[Chain] = []

    chain_count = read_le_uint32(f)
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
    # Ensure all mmap modifications are written to disk.
    headers.flush()

    headers_path = headers._storage.filename
    headerfile_size = os.path.getsize(headers_path)
    headerfile_hash = hash_headerfile(headers_path, headerfile_size)

    chaindata_filename = headers +".chain_data"
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

                headers.read_incremental_file(headers_data.last_index)
                return cast(Headers, headers)

            logger.debug("Cached chain data file does not match: %s", actual_headerfile_hash.hex())
    else:
        logger.debug("Cached chain data file not found")

    return cast(Headers, Headers(coin, file_path, checkpoint))

