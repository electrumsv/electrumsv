# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
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
import asyncio
import enum
from http import HTTPStatus
import json
import struct
from typing import Any, AsyncIterable, cast, List, NamedTuple, Optional, TypedDict, \
    TYPE_CHECKING, Union

import aiohttp
from aiohttp import WSServerHandshakeError
from bitcoinx import Chain, hash_to_hex_str, Header, MissingHeader

from .exceptions import FilterResponseInvalidError, FilterResponseIncompleteError, \
    TransactionNotFoundError, GeneralAPIError
from ..app_state import app_state
from ..bitcoin import TSCMerkleProof, TSCMerkleProofError, verify_proof
from ..constants import ServerCapability
from ..exceptions import ServerConnectionError
from ..logs import logs
from ..types import Outpoint, outpoint_struct, outpoint_struct_size, \
    output_spend_struct, output_spend_struct_size, OutputSpend

from .api_server import pick_server_for_account
from .esv_client_types import AccountMessageKind, ServerConnectionState, \
    WebsocketUnauthorizedException


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


async def post_restoration_filter_request_json(url: str, request_data: RestorationFilterRequest) \
        -> AsyncIterable[RestorationFilterJSONResponse]:
    """
    This will stream matches for the given push data hashes from the server in JSON
    structures until there are no more matches.

    Raises `HTTPError` if the response status code indicates an error occurred.
    Raises `FilterResponseInvalidError` if the response is not valid.
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


async def post_restoration_filter_request_binary(url: str, request_data: RestorationFilterRequest,
        access_token: str) -> AsyncIterable[bytes]:
    """
    This will stream matches for the given push data hashes from the server in packed binary
    structures until there are no more matches.

    Raises `FilterResponseInvalidError` if the response is not valid.
    Raises `FilterResponseIncompleteError` if a response packet is incomplete. This likely means
      that the connection was closed mid-transmission.
    Raises `ServerConnectionError` if the remote computer does not accept
      the connection.
    """
    headers = {
        'Content-Type':     'application/json',
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV',
        'Authorization':    f'Bearer {access_token}'
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=json.dumps(request_data), headers=headers) \
                    as response:
                if response.status != 200:
                    raise FilterResponseInvalidError(f"Bad response status code {response.status} "
                        f"reason: {response.reason}")

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
        include_transaction: bool=False, target_type: str="hash", access_token: str="") -> bytes:
    """
    Get a TSC merkle proof with optional embedded transaction.

    At a later time this will need to stream the proof given potentially 4 GiB large transactions,
    but it is more likely that we will simply separate the transaction and proof in the response
    for ease of access.

    Raises `FilterResponseInvalidError` if the response is not valid.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert target_type in { "hash", "header", "merkleroot" }
    params = {
        "targetType": target_type,
    }
    if include_transaction:
        params["includeFullTx"] = "1"

    headers = {
        'Content-Type':     'application/json',
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV',
        'Authorization':    f'Bearer {access_token}'
    }

    # TODO(1.4.0) Servers. Trailing slash cleanup.
    url = server_url if server_url.endswith("/") else server_url + "/"
    url += hash_to_hex_str(tx_hash)
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(url, params=params) as response:
                if response.status != HTTPStatus.OK:
                    raise FilterResponseInvalidError(
                        f"Bad response status={response.status}, reason={response.reason}")

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
        tx_hash: bytes, include_transaction: bool=False) \
            -> tuple[TSCMerkleProof, tuple[Header, Chain]]:
    """
    Requests the merkle proof from a given server, verifies it and returns it.

    Raises `FilterResponseInvalidError` if the response is not valid.
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

    # TODO(1.4.0) Networking. Discuss this with Roger the fact that we want to pin to one main
    #  server for consistent chain state.

    # base_server_url = pick_server_for_account(account, ServerCapability.MERKLE_PROOF_REQUEST)
    main_server = account.get_wallet().main_server
    assert main_server is not None
    base_server_url = main_server._state.server.url

    assert main_server._state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(main_server._state.credential_id)

    server_url = f"{base_server_url}api/v1/merkle-proof/"
    tsc_proof_bytes = await _request_binary_merkle_proof_async(server_url, tx_hash,
        include_transaction=include_transaction, access_token=master_token)
    logger.debug("Read %d bytes of merkle proof", len(tsc_proof_bytes))
    try:
        tsc_proof = TSCMerkleProof.from_bytes(tsc_proof_bytes)
    except TSCMerkleProofError:
        logger.error("Provided merkle proof invalid %s", hash_to_hex_str(tx_hash))
        raise

    try:
        header, chain = app_state.headers.lookup(tsc_proof.block_hash)
    except MissingHeader:
        raise MerkleProofMissingHeaderError(tsc_proof)

    if not verify_proof(tsc_proof, header.merkle_root):
        logger.error("Provided merkle proof fails verification %s", hash_to_hex_str(tx_hash))
        raise MerkleProofVerificationError(tsc_proof)

    return tsc_proof, (header, chain)


async def request_transaction_data_async(network: Optional[Network], account: AbstractAccount,
        tx_hash: bytes) -> bytes:
    """Selects a suitable server and requests the raw transaction.

    Raises `ServerConnectionError` if the remote server is not online (and other networking
        problems).
    Raises `GeneralAPIError` if a connection was established but the request errored.
    """
    assert network is not None
    base_server_url = pick_server_for_account(account, ServerCapability.TRANSACTION_REQUEST)
    server_url = f"{base_server_url}api/v1/transaction/"
    headers = {
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV'
    }
    # TODO(1.4.0) Servers. Trailing slash cleanup.
    url = server_url if server_url.endswith("/") else server_url + "/"
    url += hash_to_hex_str(tx_hash)

    session = network.get_aiohttp_session()
    try:
        async with session.get(url, headers=headers) as response:
            if response.status == HTTPStatus.NOT_FOUND:
                logger.error("Transaction for hash %s not found", hash_to_hex_str(tx_hash))
                raise TransactionNotFoundError()

            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            content_type, *content_type_extra = response.headers["Content-Type"].split(";")
            if content_type != "application/octet-stream":
                raise GeneralAPIError("Invalid response content type, "
                    f"got {content_type}, expected 'application/octet-stream'")

            return await response.content.read()
    except aiohttp.ClientError:
        raise ServerConnectionError(f"Failed to connect to server at: {base_server_url}")


def unpack_server_message_bytes(message_bytes: bytes) \
        -> tuple[AccountMessageKind, Union[str, OutputSpend]]:
    message_kind = AccountMessageKind(struct.unpack_from(">I", message_bytes, 0)[0])
    if message_kind == AccountMessageKind.PEER_CHANNEL_MESSAGE:
        return message_kind, json.loads(message_bytes[4:].decode("utf-8"))
    elif message_kind == AccountMessageKind.SPENT_OUTPUT_EVENT:
        spent_output = OutputSpend(*output_spend_struct.unpack(message_bytes[4:]))
        return message_kind, spent_output
    else:
        raise NotImplementedError(f"Packing message kind {message_kind} is unsupported")


async def maintain_server_connection_async(state: ServerConnectionState) -> None:
    """
    Keep a persistent connection to this ElectrumSV reference server alive.
    """
    while True:
        await manage_server_websocket_async(state)
        # When we establish a new websocket we will register all the outstanding output spend
        # registrations that we need, so whatever is left in the queue at this point is redundant.
        while not state.output_spend_registration_queue.empty():
            state.output_spend_registration_queue.get_nowait()
        # TODO(1.4.0) Networking. This is an arbitrary timeout, we should factor when this
        #     happens into the UI and how we manage server usage.
        await asyncio.sleep(10)


async def manage_server_websocket_async(state: ServerConnectionState) -> None:
    """
    Manage an open websocket to this ElectrumSV reference server.
    """
    # TODO(1.4.0) Credentials. When we implement access token support for servers on account
    #     creation, we should not store it in memory unencrypted.
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    websocket_url_template = state.server.url + "api/v1/web-socket?token={access_token}"
    websocket_url = websocket_url_template.format(access_token=master_token)
    headers = {
        "Accept": "application/octet-stream"
    }
    try:
        async with state.session.ws_connect(websocket_url, headers=headers, timeout=5.0) \
                as server_websocket:
            logger.info('Connected to server websocket, url=%s', websocket_url_template)
            register_output_spends_async(state)
            output_spends_future = app_state.async_.spawn(manage_output_spends_async, state)
            try:
                websocket_message: aiohttp.WSMessage
                async for websocket_message in server_websocket:
                    if websocket_message.type == aiohttp.WSMsgType.BINARY:
                        message_bytes = cast(bytes, websocket_message.data)
                        message_kind, message = unpack_server_message_bytes(message_bytes)
                        if message_kind == AccountMessageKind.PEER_CHANNEL_MESSAGE:
                            assert isinstance(message, dict) # ChannelNotification
                            state.peer_channel_message_queue.put_nowait(message)
                        elif message_kind == AccountMessageKind.SPENT_OUTPUT_EVENT:
                            assert isinstance(message, OutputSpend)
                            state.output_spend_result_queue.put_nowait([ message ])
                        else:
                            logger.error("Unhandled binary server websocket message %r",
                                websocket_message)
                    elif websocket_message.type in (aiohttp.WSMsgType.CLOSE,
                            aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSED,
                            aiohttp.WSMsgType.CLOSING):
                        logger.info("Server websocket closed")
                        break
                    else:
                        logger.error("Unhandled server websocket message type %r",
                            websocket_message)
            finally:
                output_spends_future.cancel()
    except aiohttp.ClientConnectorError:
        logger.debug("Unable to connect to server websocket")
    except WSServerHandshakeError as e:
        if e.status == HTTPStatus.UNAUTHORIZED:
            # TODO(1.4.0) Networking. Need to handle the case that our credentials are stale or
            #     incorrect.
            raise WebsocketUnauthorizedException()
        # TODO(1.4.0) Networking. What is being raised here? Why?
        raise


def register_output_spends_async(state: ServerConnectionState) -> None:
    """
    Feed the initial state into the registration worker task.

    It is critical that this is executed first thing after the websocket connection is established.
    These registrations only persist as long as that websocket connection is alive.
    """
    # Feed the initial state into the worker task.
    # TODO(1.4.0) Petty cash. This should when we support multiple petty cash accounts we
    #     should specify which grouping of accounts are funded by a given petty cash
    #     account. It is possible we may end up mapping the petty cash account id to
    #     those accounts in the database.
    assert state.wallet_data is not None
    output_spends = state.wallet_data.read_spent_outputs_to_monitor()
    logger.debug("Registering %d existing output spend notification requirements",
        len(output_spends))
    if len(output_spends):
        spent_outpoints = list({ Outpoint(output_spend.out_tx_hash, output_spend.out_index)
            for output_spend in output_spends })
        state.output_spend_registration_queue.put_nowait(spent_outpoints)



async def manage_output_spends_async(state: ServerConnectionState) -> None:
    """
    This in theory manages spent output registrations and notifications on behalf of a given
    petty cash account, and the non-petty cash accounts that are funded by it.
    """
    api_url = f"{state.server.url}api/v1/output-spend/notifications"

    async def process_registration_batch_async() -> None:
        logger.debug("Waiting for spent output registrations")
        outpoints = await state.output_spend_registration_queue.get()
        logger.debug("Processing %d spent output registrations", len(outpoints))
        # Pack the binary array of outpoints into the bytearray.
        byte_buffer = bytearray(len(outpoints) * outpoint_struct_size)
        for output_index, outpoint in enumerate(outpoints):
            outpoint_struct.pack_into(byte_buffer, output_index * outpoint_struct_size, *outpoint)
        headers = {
            'Content-Type':     'application/octet-stream',
            'Accept':           'application/octet-stream',
            'User-Agent':       'ElectrumSV'
        }
        spent_outputs: List[OutputSpend] = []
        # TODO(1.4.0) Networking. If any of the error cases below occur we should requeue the
        #     outpoints, but it is not as simple as just doing it. What we want to avoid is being
        #     in an infinite loop of failed attempts.
        async with state.session.post(api_url, headers=headers, data=byte_buffer) as response:
            if response.status != HTTPStatus.OK:
                logger.error("Websocket spent output registration failed "
                    "status=%d, reason=%s", response.status, response.reason)
                # TODO(1.4.0) Networking. Spent output registration failure.
                #     We need to handle all possible variations of this error:
                #     - It may be lack of funding.
                #     - It may be short or long term server unavailability or errors.
                #     - ??? add anything else that comes to mind.
                return

            content_type, *content_type_extra = response.headers["Content-Type"].split(";")
            if content_type != "application/octet-stream":
                logger.error("Spent output registration response content type got %s, "
                    "expected 'application/octet-stream'", content_type)
                # TODO(1.4.0) Networking. Bad server not respecting the spent output request. We
                #     should stop using it, and the user should have to manually flag it as valid
                #     again.
                # TODO(bad-server)
                return

            response_bytes = await response.content.read(output_spend_struct_size)
            while len(response_bytes) > 0:
                if len(response_bytes) != output_spend_struct_size:
                    logger.error("Spent output registration record clipped, expected %d "
                        "bytes, got %d bytes", output_spend_struct_size, len(response_bytes))
                    # TODO(1.4.0) Networking. The server is unreliable? Should we mark the server
                    #     as to be avoided? Or flag it and stop using it if it happens more than
                    #     once or twice?
                    return

                spent_output = OutputSpend.from_network(*output_spend_struct.unpack(response_bytes))
                logger.debug("Spent output registration returned %r", spent_output)
                spent_outputs.append(spent_output)

                response_bytes = await response.content.read(output_spend_struct_size)

        await state.output_spend_result_queue.put(spent_outputs)

    logger.debug("Entering process_registration_batch_async")
    try:
        while True:
            await process_registration_batch_async()
    finally:
        logger.debug("Exiting process_registration_batch_async")
