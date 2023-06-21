"""
When bitcoinx loads a headers file, it processes all headers on startup and builds a picture of
the chain state for those headers. What forks there are and at what heights. Unfortunately at the
time of writing this, this can take up to 40 seconds to do and is an unacceptable and perplexing
user experience. Either bitcoinx has to persist the chain state to avoid recalculating it or we do.
It makes little difference so we do it for now.

We need to know which headers in the headers file the chain data applies to. As the headers file is
only ever appended to we can associate the chain data with a partial hash covering the headers that
have been factored into the chain data. We also know the index of the last header processed and can
process the headers after that point which should only be a few blocks at most and incur no
noticeable startup delay.

Additional notes:

* bitcoinx processes all headers above a hard-coded checkpoint. We used to set a checkpoint and
  fetch headers on demand. We stopped because this was a poor user experience and it is much simpler
  to bundle the full headers and have them ready to use immediately. Now our checkpoint is always
  the Genesis block. The checkpoint mechanic could be removed from our perspective.

* The headers file has a leading reserved space with values like the header count. We exclude that
  from the hashing to ensure that the hash is deterministic even with additional appended headers.

ElectrumSV decisions:

* We try and write out the chain data on two different events. On application shutdown and after
  completing initial header synchronisation with a header server. The former is what we normally
  expect, and the latter is the minimum we can possibly do to make the user experience for users
  who decide to kill the process less painful.
"""

from __future__ import annotations

import os
import typing
from typing import cast

import bitcoinx
from bitcoinx import Headers, Network, double_sha256, Chain, MissingHeader, hash_to_hex_str

from .logs import logs

if typing.TYPE_CHECKING:
    from .app_state import AppStateProxy

logger = logs.get_logger("app_state")


# A reference to this cursor must be maintained and passed to the Headers.unpersisted_headers
# function in order to determine which newly appended headers still need to be appended
# to disc
HeaderPersistenceCursor = dict[bitcoinx.Chain, int]


def write_cached_headers(headers: Headers, cursor: HeaderPersistenceCursor,
        app_state: 'AppStateProxy') -> HeaderPersistenceCursor:
    headers_file_path = app_state.headers_filename()
    with open(headers_file_path, "ab") as hf:
        hf.write(headers.unpersisted_headers(cursor))
    return cast(HeaderPersistenceCursor, headers.cursor())


def modified_connect(headers: Headers, raw_header: bytes, block_hash: bytes) -> Chain:
    """Modified / optimised version of bitcoinx.Headers.connect (with check_headers=False).
    It is faster because we provide the pre-computed block_hash rather than double-hashing
    ~800,000 block headers"""
    hashes = headers.hashes
    tips = headers.tips

    hdr_hash = block_hash  # This is the performance win (instead of hashing the header)
    prev_hash = raw_header[4:36]
    chain, height = hashes.get(prev_hash, (None, -1))
    height += 1

    if not chain:
        if raw_header != headers.network.genesis_header:
            raise MissingHeader(f'previous header {hash_to_hex_str(prev_hash)} not present')
        # Handle duplicate genesis block
        if headers.hashes:
            chain, _ = hashes[hdr_hash]
            return chain
        chain = Chain(None, height)
    elif tips[chain] != prev_hash:
        # Silently ignore duplicate headers
        duplicate, _ = hashes.get(hdr_hash, (None, -1))
        if duplicate:
            return duplicate
        # Form a new chain
        chain = Chain(chain, height)

    chain.append(raw_header)
    hashes[hdr_hash] = (chain, height)
    tips[chain] = hdr_hash
    return chain


def read_cached_headers(coin: Network, file_path: str, base_headers: bytes | None = None,
        base_hashes: list[bytes] | None = None) -> tuple[Headers, HeaderPersistenceCursor]:
    # See app_state._migrate. A 'headers3' file should always be present.
    assert os.path.exists(file_path)
    logger.debug("New headers storage file: %s found", file_path)
    with open(file_path, "rb") as f:
        raw_headers = f.read()
    headers = Headers(coin)

    # This `modified_connect` reduces startup time from 2.5 seconds to 1.5 seconds
    # by avoiding hashing of every header in the base chain. Subsequent new headers
    # need to be connected the standard way.
    if base_headers is not None and base_hashes is not None:
        genesis_hash = double_sha256(coin.genesis_header)
        chain, height = headers.lookup(genesis_hash)
        assert chain.tip().hash == genesis_hash

        header_size = 80
        base_headers_list = [base_headers[i:i+80] for i in range(0, len(base_headers), header_size)]
        for block_hash, raw_header in zip(base_hashes, base_headers_list):
            modified_connect(headers, raw_header, block_hash)  # 1.5 seconds
            # headers.connect(raw_header, check_work=False)  # 2.5 seconds

        # discard the already connected base_headers from raw_headers
        assert raw_headers[:len(base_headers)] == base_headers
        raw_headers = raw_headers[len(base_headers):]

    cursor = headers.connect_many(raw_headers, check_work=False)
    return headers, cursor
