# Open BSV License version 4
#
# Copyright (c) 2021 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import annotations
import enum
import json
import struct
from typing import Any, AsyncIterable, List, NamedTuple, Optional, TypedDict, TYPE_CHECKING

import aiohttp
from bitcoinx import hash_to_hex_str, MissingHeader

from ..app_state import app_state
from ..bitcoin import TSCMerkleProof, TSCMerkleProofError, verify_proof
from ..constants import ServerCapability
from ..exceptions import ServerConnectionError
from ..logs import logs
from .api_server import pick_server_for_account


if TYPE_CHECKING:
    from ..network import Network
    from ..wallet import AbstractAccount


logger = logs.get_logger("general-api")


class MatchFlags(enum.IntFlag):
    # The match is in a transaction output.
    IN_OUTPUT = 1 << 0
    # The match is in a transaction input.
    IN_INPUT = 1 << 1


class RestorationFilterRequest(TypedDict):
    filterKeys: List[str]

class RestorationFilterJSONResponse(TypedDict):
    flags: int
    pushDataHashHex: str
    lockingTransactionId: str
    lockingTransactionIndex: int
    unlockingTransactionId: Optional[str]
    unlockingInputIndex: int

class RestorationFilterResult(NamedTuple):
    flags: int
    push_data_hash: bytes
    locking_transaction_hash: bytes
    locking_output_index: int
    unlocking_transaction_hash: bytes  # null hash
    unlocking_input_index: int  # 0


RESULT_UNPACK_FORMAT = ">B32s32sI32sI"
FILTER_RESPONSE_SIZE = 1 + 32 + 32 + 4 + 32 + 4
assert struct.calcsize(RESULT_UNPACK_FORMAT) == FILTER_RESPONSE_SIZE


class GeneralAPIError(Exception):
    pass

class FilterResponseInvalidError(GeneralAPIError):
    pass

class FilterResponseIncompleteError(GeneralAPIError):
    pass

class TransactionNotFoundError(GeneralAPIError):
    pass

async def post_restoration_filter_request_json(url: str, request_data: RestorationFilterRequest) \
        -> AsyncIterable[RestorationFilterJSONResponse]:
    """
    This will stream matches for the given push data hashes from the server in JSON
    structures until there are no more matches.

    Raises `HTTPError` if the response status code indicates an error occurred.
    Raises `FilterResponseInvalidError` if the response content type does not match what we accept.
    """
    headers={
        'Content-Type':     'application/json',
        'Accept':           'application/json',
        'User-Agent':       'ElectrumSV'
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.post(url, json=request_data) as response:
            if response.status != 200:
                raise FilterResponseInvalidError(f"Bad response status code {response.status}")

            content_type, *content_type_extra = response.headers["Content-Type"].split(";")
            if content_type != "application/octet-stream":
                raise FilterResponseInvalidError(
                    "Invalid response content type, got {}, expected {}".format(content_type,
                        "octet-stream"))
            async for response_line in response.content:
                yield json.loads(response_line)


async def post_restoration_filter_request_binary(url: str, request_data: RestorationFilterRequest) \
        -> AsyncIterable[bytes]:
    """
    This will stream matches for the given push data hashes from the server in packed binary
    structures until there are no more matches.

    Raises `FilterResponseInvalidError` if the response content type does not match what we accept.
    Raises `FilterResponseIncompleteError` if a response packet is incomplete. This likely means
      that the connection was closed mid-transmission.
    Raises `ServerConnectionError` if the remote computer does not accept
      the connection.
    """
    headers={
        'Content-Type':     'application/json',
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV'
    }
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.post(url, json=request_data) as response:
                if response.status != 200:
                    raise FilterResponseInvalidError(f"Bad response status code {response.status}")

                content_type, *content_type_extra = response.headers["Content-Type"].split(";")
                if content_type != "application/octet-stream":
                    raise FilterResponseInvalidError(
                        "Invalid response content type, got {}, expected {}".format(content_type,
                            "octet-stream"))
                packet_bytes: bytes
                async for packet_bytes in response.content.iter_chunked(FILTER_RESPONSE_SIZE):
                    if len(packet_bytes) != FILTER_RESPONSE_SIZE:
                        if len(packet_bytes) == 1 and packet_bytes == b"\0":
                            # Sending a null byte indicates a successful end of matches.
                            break
                        raise FilterResponseIncompleteError("Only received ")
                    yield packet_bytes
    except aiohttp.ClientError:
        raise ServerConnectionError()


def unpack_binary_restoration_entry(entry_data: bytes) -> RestorationFilterResult:
    assert len(entry_data) == FILTER_RESPONSE_SIZE
    return RestorationFilterResult(*struct.unpack(RESULT_UNPACK_FORMAT, entry_data))


STREAM_CHUNK_SIZE = 16*1024


async def _request_binary_merkle_proof_async(server_url: str, tx_hash: bytes,
        include_transaction: bool=False, target_type: str="hash") -> bytes:
    """
    Get a TSC merkle proof with optional embedded transaction.

    At a later time this will need to stream the proof given potentially 4 GiB large transactions,
    but it is more likely that we will simply separate the transaction and proof in the response
    for ease of access.

    Raises `FilterResponseInvalidError` if the response content type does not match what we accept.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert target_type in { "hash", "header", "merkleroot" }
    params = {
        "targetType": target_type,
    }
    if include_transaction:
        params["includeFullTx"] = "1"

    headers={
        'Content-Type':     'application/json',
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV'
    }

    url = server_url if server_url.endswith("/") else server_url + "/"
    url += hash_to_hex_str(tx_hash)
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, params=params) as response:
                if response.status != 200:
                    raise FilterResponseInvalidError(f"Bad response status code {response.status}")

                content_type, *content_type_extra = response.headers["Content-Type"].split(";")
                if content_type != "application/octet-stream":
                    raise FilterResponseInvalidError(
                        "Invalid response content type, got {}, expected {}".format(content_type,
                            "octet-stream"))

                return await response.content.read()
    except aiohttp.ClientError:
        raise ServerConnectionError(f"Failed to connect to server at: {server_url}")


class MerkleProofError(Exception):
    def __init__(self, proof: TSCMerkleProof, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self.merkle_proof = proof

class MerkleProofVerificationError(MerkleProofError):
    ...

class MerkleProofMissingHeaderError(MerkleProofError):
    ...


async def request_binary_merkle_proof_async(network: Optional[Network], account: AbstractAccount,
        tx_hash: bytes, include_transaction: bool=False) -> TSCMerkleProof:
    """
    Requests the merkle proof from a given server, verifies it and returns it.

    Raises `ServerConnectionError` if the remote server is not online (and other networking
        problems).
    Raises `TSCMerkleProofError` if the proof structure is illegitimate.
    Raises `MerkleProofVerificationError` if the proof verification fails (this is unexpected if
        we are requesting proofs from a legitimate server).
    Raises `MerkleProofMissingHeaderError` if the header for the block the transaction is in
        is not known to the application.
    """
    assert network is not None
    assert app_state.headers is not None

    base_server_url = pick_server_for_account(network, account,
        ServerCapability.MERKLE_PROOF_REQUEST)
    server_url = f"{base_server_url}api/v1/merkle-proof/"
    tsc_proof_bytes = await _request_binary_merkle_proof_async(server_url, tx_hash,
        include_transaction=include_transaction)
    logger.debug("Read %d bytes of merkle proof", len(tsc_proof_bytes))
    try:
        tsc_proof = TSCMerkleProof.from_bytes(tsc_proof_bytes)
    except TSCMerkleProofError:
        # TODO(1.4.0) Signal caller if applicable.
        logger.error("Provided merkle proof invalid %s", hash_to_hex_str(tx_hash))
        raise

    try:
        header, _chain = app_state.headers.lookup(tsc_proof.block_hash)
    except MissingHeader:
        # TODO(1.4.0) Is this possible? What should we do?
        raise MerkleProofMissingHeaderError(tsc_proof)

    if not verify_proof(tsc_proof, header.merkle_root):
        # TODO(1.4.0) Signal caller if applicable.
        logger.error("Provided merkle proof fails verification %s",
            hash_to_hex_str(tx_hash))
        raise MerkleProofVerificationError(tsc_proof)

    return tsc_proof


async def request_transaction_data_async(network: Optional[Network], account: AbstractAccount,
        tx_hash: bytes) -> bytes:
    """Selects a suitable server and requests the raw transaction.

    Raises `ServerConnectionError` if the remote server is not online (and other networking
        problems).
    Raises `GeneralAPIError` if a connection was established but the request errored.
    """
    assert network is not None
    base_server_url = pick_server_for_account(network, account,
        ServerCapability.TRANSACTION_REQUEST)
    server_url = f"{base_server_url}api/v1/transaction/"
    headers = {
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV'
    }
    url = server_url if server_url.endswith("/") else server_url + "/"
    url += hash_to_hex_str(tx_hash)

    session = await network.get_aiohttp_session()
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == 404:
                logger.error(f"Transaction for hash {hash_to_hex_str(tx_hash)} "
                    f"not found")
                raise TransactionNotFoundError()

            if response.status != 200:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            content_type, *content_type_extra = response.headers["Content-Type"].split(";")
            if content_type != "application/octet-stream":
                raise GeneralAPIError("Invalid response content type, "
                    f"got {content_type}, expected 'application/octet-stream'")

            return await response.content.read()
    except aiohttp.ClientError:
        raise ServerConnectionError(f"Failed to connect to server at: {base_server_url}")
