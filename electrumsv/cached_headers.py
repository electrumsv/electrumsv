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
from bitcoinx import Headers, Network

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


def read_cached_headers(coin: Network, file_path: str) -> tuple[Headers, HeaderPersistenceCursor]:
    # See app_state._migrate. A 'headers3' file should always be present on mainnet
    if coin.name == 'mainnet':
        assert os.path.exists(file_path)
    elif not os.path.exists(file_path):
        open(file_path, 'wb').close()
    logger.debug("New headers storage file: %s found", file_path)
    with open(file_path, "rb") as f:
        raw_headers = f.read()
    headers = Headers(coin)
    cursor = headers.connect_many(raw_headers, check_work=False)
    return headers, cursor
