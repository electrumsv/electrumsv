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
from concurrent.futures import Future
from datetime import datetime, timezone
import enum
from http import HTTPStatus
import json
import struct
import time
from typing import Any, AsyncIterable, cast, List, NamedTuple, Optional, TypedDict, Union

import aiohttp
from aiohttp import WSServerHandshakeError
from bitcoinx import Chain, hash_to_hex_str, hex_str_to_hash, Header, MissingHeader, PrivateKey

from .exceptions import AuthenticationError, FilterResponseInvalidError, \
    FilterResponseIncompleteError, GeneralAPIError, InvalidStateError, TransactionNotFoundError
from ..app_state import app_state
from ..bitcoin import TSCMerkleProof, TSCMerkleProofError, verify_proof
from ..constants import PushDataHashRegistrationFlag, PushDataMatchFlag, ServerCapability, \
    ServerConnectionFlag, ServerPeerChannelFlag, PeerChannelAccessTokenFlag
from ..crypto import pw_encode
from ..exceptions import ServerConnectionError
from ..i18n import _
from ..logs import logs
from ..types import Outpoint, outpoint_struct, output_spend_struct, OutputSpend, \
    tip_filter_list_struct, tip_filter_registration_struct, TipFilterListEntry
from ..util import get_posix_timestamp
from ..wallet_database.types import PushDataMatchRow, PushDataHashRegistrationRow, \
    ServerPeerChannelRow, ServerPeerChannelAccessTokenRow

from .esv_client import PeerChannel
from .esv_client_types import AccountMessageKind, GenericPeerChannelMessage, \
    IndexerServerSettings, MAPICallbackResponse, \
    PeerChannelAPITokenViewModelGet, PeerChannelToken, \
    PeerChannelViewModelGet,  \
    RetentionViewModel, ServerConnectionState, TipFilterPushDataMatchesData, \
    TipFilterRegistrationResponse, TokenPermissions, \
    VerifiableKeyData, WebsocketUnauthorizedException


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


async def post_restoration_filter_request_json(state: ServerConnectionState,
        request_data: RestorationFilterRequest) -> AsyncIterable[RestorationFilterJSONResponse]:
    """
    This will stream matches for the given push data hashes from the server in JSON
    structures until there are no more matches.

    Raises `HTTPError` if the response status code indicates an error occurred.
    Raises `FilterResponseInvalidError` if the response is not valid.
    """
    url = f"{state.server.url}api/v1/restoration/search"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers={
        'Content-Type':     'application/json',
        'Accept':           'application/json',
        'User-Agent':       'ElectrumSV',
        'Authorization':    f'Bearer {master_token}'
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=request_data, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise FilterResponseInvalidError(f"Bad response status code {response.status}")

            content_type, *content_type_extra = response.headers["Content-Type"].split(";")
            if content_type != "application/octet-stream":
                raise FilterResponseInvalidError(
                    "Invalid response content type, got {}, expected {}".format(content_type,
                        "octet-stream"))
            async for response_line in response.content:
                yield json.loads(response_line)


async def post_restoration_filter_request_binary(state: ServerConnectionState,
        request_data: RestorationFilterRequest) -> AsyncIterable[bytes]:
    """
    This will stream matches for the given push data hashes from the server in packed binary
    structures until there are no more matches.

    Raises `FilterResponseInvalidError` if the response is not valid.
    Raises `FilterResponseIncompleteError` if a response packet is incomplete. This likely means
      that the connection was closed mid-transmission.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    url = f"{state.server.url}api/v1/restoration/search"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {
        'Content-Type':     'application/json',
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV',
        'Authorization':    f'Bearer {master_token}'
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=request_data, headers=headers) as response:
                if response.status != HTTPStatus.OK:
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
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {url}")


def unpack_binary_restoration_entry(entry_data: bytes) -> RestorationFilterResult:
    assert len(entry_data) == FILTER_RESPONSE_SIZE
    return RestorationFilterResult(*struct.unpack(RESULT_UNPACK_FORMAT, entry_data))


STREAM_CHUNK_SIZE = 16*1024


async def _request_binary_merkle_proof_async(state: ServerConnectionState, tx_hash: bytes,
        include_transaction: bool=False, target_type: str="hash") -> bytes:
    """
    Get a TSC merkle proof with optional embedded transaction.

    At a later time this will need to stream the proof given potentially 4 GiB large transactions,
    but it is more likely that we will simply separate the transaction and proof in the response
    for ease of access.

    Raises `FilterResponseInvalidError` if the response is not valid.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert state.credential_id is not None
    assert target_type in { "hash", "header", "merkleroot" }
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    server_url = f"{state.server.url}api/v1/merkle-proof/{hash_to_hex_str(tx_hash)}"
    params = {
        "targetType": target_type,
    }
    if include_transaction:
        params["includeFullTx"] = "1"

    headers = {
        'Content-Type':     'application/json',
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV',
        'Authorization':    f'Bearer {master_token}'
    }

    try:
        async with state.session.get(server_url, params=params, headers=headers) as response:
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
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {server_url}")


class MerkleProofError(Exception):
    def __init__(self, proof: TSCMerkleProof, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)

        self.merkle_proof = proof


class MerkleProofVerificationError(MerkleProofError):
    ...

class MerkleProofMissingHeaderError(MerkleProofError):
    ...


async def request_binary_merkle_proof_async(state: ServerConnectionState, tx_hash: bytes,
        include_transaction: bool=False) -> tuple[TSCMerkleProof, tuple[Header, Chain]]:
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
    assert app_state.headers is not None
    assert state.credential_id is not None

    tsc_proof_bytes = await _request_binary_merkle_proof_async(state, tx_hash,
        include_transaction=include_transaction)
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


async def request_transaction_data_async(state: ServerConnectionState, tx_hash: bytes) -> bytes:
    """Selects a suitable server and requests the raw transaction.

    Raises `ServerConnectionError` if the remote server is not online (and other networking
        problems).
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    """
    tx_id = hash_to_hex_str(tx_hash)
    server_url = f"{state.server.url}api/v1/transaction/"+ tx_id
    headers = {
        'Accept':           'application/octet-stream',
        'User-Agent':       'ElectrumSV'
    }
    try:
        async with state.session.get(server_url, headers=headers) as response:
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
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {state.server.url}")


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
    assert state.connection_flags == ServerConnectionFlag.INITIALISED

    # We do not set `stage_change_event` for this flag.
    state.connection_flags |= ServerConnectionFlag.STARTING

    try:
        while state.connection_flags & ServerConnectionFlag.EXITING == 0:
            state.connection_flags &= ServerConnectionFlag.MASK_COMMON_INITIAL

            try:
                if not await manage_server_connection_async(state):
                    break
            except ServerConnectionError:
                pass

            logger.debug("Server disconnected, clearing state, waiting to retry")
            state.clear_for_reconnection()

            # TODO(1.4.0) Networking. This is an arbitrary timeout, we should factor when this
            #     happens into the UI and how we manage server usage.
            await asyncio.sleep(10)
    finally:
        logger.error("maintain_server_connection_async encountered connection issue")
        state.connection_flags = ServerConnectionFlag.EXITED
        state.connection_exit_event.set()
    # TODO(1.4.0) Servers. The connection management logic needs work. This code is related.


async def create_server_account_if_necessary(state: ServerConnectionState) -> None:
    """
    Raises `GeneralAPIError` if non-successful response encountered.
    Raises `AuthenticationError` if response does not give valid payment keys or api keys.
    """
    assert state.wallet_proxy is not None
    assert state.wallet_data is not None

    # Check if the existing credentials are still valid.
    if state.credential_id is not None:
        master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
        headers = {"Authorization": f"Bearer {master_token}"}
        account_metadata_url = f"{state.server.url}api/v1/account"
        # TODO(1.4.0) Servers. Need to identify other aiohttp exceptions raised here and handle.
        try:
            async with state.session.get(account_metadata_url, headers=headers) as response:
                if response.status != 200:
                    logger.error("Unexpected status in payment key endpoint response (vkd) %d (%s)",
                        response.status, response.reason)
                    raise GeneralAPIError(
                        f"Bad response status code: {response.status}, reason: {response.reason}")

                # `metadata` is currently {"public_key_key": ..., "api_key": ...}
                metadata = await response.json()
                logger.debug("Existing credentials verified for server %s", state.server.server_id)
                return
        except aiohttp.ClientConnectorError:
            logger.debug("Failed to connect to server at: %s", account_metadata_url, exc_info=True)
            raise ServerConnectionError()

    # We lookup the password here before we do anything that will change server-side state.
    # If the user is asked to enter it, should it not be in the cache, then we may abort
    # the connection if they refuse.
    wallet_path = state.wallet_proxy.get_storage_path()
    password = app_state.credentials.get_wallet_password(wallet_path)
    if password is None:
        password = await app_state.credentials.get_or_request_wallet_password_async(wallet_path,
            _("The wallet has no existing credentials it can use to connect to '{}'. Please enter "
            "your password to allow access.").format(state.server.url))
        if password is None:
            raise InvalidStateError("Unable to access password to connect")

    obtain_server_key_url = f"{state.server.url}api/v1/account/key"

    timestamp_text = datetime.utcnow().isoformat()
    message_text = f"{obtain_server_key_url} {timestamp_text}"
    identity_private_key = PrivateKey.from_hex(app_state.credentials.get_indefinite_credential(
        state.wallet_proxy.identity_private_key_credential_id))
    signature_bytes = identity_private_key.sign_message(message_text.encode())
    key_data: VerifiableKeyData = {
        "public_key_hex": state.wallet_proxy._identity_public_key.to_hex(),
        "signature_hex": signature_bytes.hex(),
        "message_hex": message_text.encode().hex(),
    }

    payment_key_bytes: Optional[bytes] = None
    api_key: Optional[str] = None
    # TODO(1.4.0) Servers. Need to identify aiohttp exceptions raised here and handle them.
    try:
        async with state.session.post(obtain_server_key_url, json=key_data) as response:
            if response.status != HTTPStatus.OK:
                logger.error("Unexpected status in payment key endpoint response (vkd) %d (%s)",
                    response.status, response.reason)
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            # TODO(1.4.0) Servers. Need to identify aiohttp exceptions raised here and handle them.
            reader = aiohttp.MultipartReader.from_response(response)
            while True:
                part = cast(Optional[aiohttp.BodyPartReader], await reader.next())
                if part is None:
                    break
                elif part.name == "key":
                    payment_key_bytes = bytes(await part.read(decode=True))
                elif part.name == "api-key":
                    api_key = await part.text()
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we catch exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Failed to connect to server at: %s", obtain_server_key_url, exc_info=True)
        raise ServerConnectionError()

    # TODO(1.4.0) Servers. The user should be shown this as the auth failure reason.
    if payment_key_bytes is None:
        raise AuthenticationError("No payment key received for server")

    # TODO(1.4.0) Servers. The user should be shown this as the auth failure reason.
    if api_key is None:
        raise AuthenticationError("No api key received for server")

    encrypted_api_key = pw_encode(api_key, password)
    # This gets persisted on wallet exit so we need to update the cached row.
    state.server.database_rows[None] = state.server.database_rows[None]._replace(
        encrypted_api_key=encrypted_api_key)
    await state.wallet_data.update_network_server_credentials_async(state.server.server_id,
        encrypted_api_key, payment_key_bytes)
    state.credential_id = app_state.credentials.add_indefinite_credential(api_key)
    logger.debug("Obtained new credentials for server %s", state.server.server_id)

async def manage_server_connection_async(state: ServerConnectionState) -> bool:
    """
    Manage an open websocket to this ElectrumSV reference server.
    """
    await create_server_account_if_necessary(state)
    assert state.credential_id is not None
    await validate_server_data(state)

    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    websocket_url_template = state.server.url + "api/v1/web-socket?token={access_token}"
    websocket_url = websocket_url_template.format(access_token=master_token)
    headers = {
        "Accept": "application/octet-stream"
    }
    output_spends_future: Optional[Future[None]] = None
    tip_filter_future: Optional[Future[None]] = None
    peer_channel_messages_future: Optional[Future[None]] = None
    try:
        async with state.session.ws_connect(websocket_url, headers=headers, timeout=5.0) \
                as server_websocket:
            logger.info('Connected to server websocket, url=%s', websocket_url_template)
            if ServerCapability.TIP_FILTER in state.utilised_capabilities:
                register_output_spends_async(state)
                output_spends_future = app_state.async_.spawn(manage_output_spends_async, state)
                tip_filter_future = app_state.async_.spawn(manage_tip_filter_registrations_async,
                    state)

            if ServerCapability.PEER_CHANNELS in state.utilised_capabilities:
                peer_channel_messages_future = app_state.async_.spawn(
                    process_incoming_peer_channel_messages_async, state)

            state.connection_flags |= ServerConnectionFlag.WEB_SOCKET_CONNECTED
            state.stage_change_event.set()
            state.stage_change_event.clear()

            try:
                websocket_message: aiohttp.WSMessage
                async for websocket_message in server_websocket:
                    if websocket_message.type == aiohttp.WSMsgType.BINARY:
                        message_bytes = cast(bytes, websocket_message.data)
                        message_kind, message = unpack_server_message_bytes(message_bytes)
                        if message_kind == AccountMessageKind.PEER_CHANNEL_MESSAGE:
                            assert isinstance(message, dict) # ChannelNotification
                            logger.debug("Queued incoming peer channel message")
                            state.peer_channel_message_queue.put_nowait(message["id"])
                        elif message_kind == AccountMessageKind.SPENT_OUTPUT_EVENT:
                            assert isinstance(message, OutputSpend)
                            logger.debug("Queued incoming output spend message")
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
                if output_spends_future is not None:
                    output_spends_future.cancel()
                if tip_filter_future is not None:
                    tip_filter_future.cancel()
                if peer_channel_messages_future is not None:
                    peer_channel_messages_future.cancel()
    except aiohttp.ClientConnectorError:
        logger.debug("Unable to connect to server websocket")
    except WSServerHandshakeError as e:
        if e.status == HTTPStatus.UNAUTHORIZED:
            # TODO(1.4.0) Networking. Need to handle the case that our credentials are stale or
            #     incorrect.
            raise WebsocketUnauthorizedException()
        # TODO(1.4.0) Networking. What is being raised here? Why?
        raise

    return True


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
        byte_buffer = bytearray(len(outpoints) * outpoint_struct.size)
        for output_index, outpoint in enumerate(outpoints):
            outpoint_struct.pack_into(byte_buffer, output_index * outpoint_struct.size, *outpoint)
        assert state.credential_id is not None
        master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
        headers = {
            'Content-Type':     'application/octet-stream',
            'Accept':           'application/octet-stream',
            'User-Agent':       'ElectrumSV',
            "Authorization":    f"Bearer {master_token}",
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

            response_bytes = await response.content.read(output_spend_struct.size)
            while len(response_bytes) > 0:
                if len(response_bytes) != output_spend_struct.size:
                    logger.error("Spent output registration record clipped, expected %d "
                        "bytes, got %d bytes", output_spend_struct.size, len(response_bytes))
                    # TODO(1.4.0) Networking. The server is unreliable? Should we mark the server
                    #     as to be avoided? Or flag it and stop using it if it happens more than
                    #     once or twice?
                    return

                spent_output = OutputSpend.from_network(*output_spend_struct.unpack(response_bytes))
                logger.debug("Spent output registration returned %r", spent_output)
                spent_outputs.append(spent_output)

                response_bytes = await response.content.read(output_spend_struct.size)

        await state.output_spend_result_queue.put(spent_outputs)

    state.connection_flags |= ServerConnectionFlag.OUTPUT_SPENDS_READY
    state.stage_change_event.set()
    state.stage_change_event.clear()

    logger.debug("Entering process_registration_batch_async")
    try:
        while state.connection_flags & ServerConnectionFlag.EXITING == 0:
            await process_registration_batch_async()
    finally:
        logger.debug("Exiting process_registration_batch_async")


async def manage_tip_filter_registrations_async(state: ServerConnectionState) -> None:
    """
    All tip filter registrations are done as jobs in this task. The reason for this is that they
    can be cleanly allowed to finished or immediately ended as needed, when the server is
    correspondingly cleanly shutdown or immediately shutdown.
    """
    # This should only be clear for non-indexer servers.
    assert state.indexer_settings is not None

    async def process_registrations_worker_async() -> None:
        assert state.wallet_proxy is not None
        assert state.wallet_data is not None

        # Before an indexing server will accept tip filter registrations from us we need to
        # have registered a notifications peer channel with it, through which it will deliver
        # any matches.
        await prepare_server_tip_filter_peer_channel(state)

        # TODO(optimisation) We could make jobs happen in parallel if this becomes a bottleneck.
        #     At this time, this is not important as we will likely only be creating these
        #     registrations very seldomly (as the primary use case is the declining monitor the
        #     blockchain legacy payment situation).

        # TODO(1.4.0) Servers. Clean shutdown versus immediate shutdown.
        #     An immediate shutdown will kill this task.
        #     A clean shutdown should allow this to finish the current

        # The main `maintain_server_connection_async` task will be waiting on this event and
        # will process it.
        state.connection_flags |= ServerConnectionFlag.TIP_FILTER_READY
        state.stage_change_event.set()
        state.stage_change_event.clear()

        logger.debug("Waiting for tip filtering registrations, server_id=%d",
            state.server.server_id)
        while state.connection_flags & ServerConnectionFlag.EXITING == 0:
            job = await state.tip_filter_new_registration_queue.get()
            assert len(job.entries) > 0

            logger.debug("Processing %d tip filter registrations", len(job.entries))
            job.start_event.set()

            date_created = int(get_posix_timestamp())
            db_insert_rows = list[PushDataHashRegistrationRow]()
            server_rows = list[tuple[bytes, int]]()
            no_date_registered = None
            for pushdata_hash, duration_seconds, keyinstance_id in job.entries:
                logger.debug("Preparing pre-registration entry for pushdata hash %s",
                    pushdata_hash.hex())
                db_insert_rows.append(PushDataHashRegistrationRow(state.server.server_id,
                    keyinstance_id, pushdata_hash, PushDataHashRegistrationFlag.REGISTERING,
                    duration_seconds, no_date_registered, date_created, date_created))
                server_rows.append((pushdata_hash, duration_seconds))
            await state.wallet_data.create_tip_filter_pushdata_registrations_async(db_insert_rows,
                upsert=True)

            try:
                job.date_registered = await create_tip_filter_registrations_async(state,
                    server_rows)
            except (GeneralAPIError, ServerConnectionError) as exception:
                job.failure_reason = str(exception)
                date_updated = int(get_posix_timestamp())
                await state.wallet_data.update_registered_tip_filter_pushdatas_flags_async([
                    (PushDataHashRegistrationFlag.REGISTRATION_FAILED, date_updated,
                        state.server.server_id, keyinstance_id)
                    for (pushdata_hash_, duration_seconds_, keyinstance_id) in job.entries
                ])
            else:
                # At this point we have all the information we need to record the registrations
                # as being active on this server and complete the job. This removes the
                # `REGISTERING` flag.
                date_updated = int(get_posix_timestamp())
                await state.wallet_data.update_registered_tip_filter_pushdatas_async([
                    (job.date_registered, date_updated, ~PushDataHashRegistrationFlag.REGISTERING,
                        PushDataHashRegistrationFlag.NONE, state.server.server_id, keyinstance_id)
                    for (pushdata_hash_, duration_seconds_, keyinstance_id) in job.entries
                ])

                logger.debug("Processed %d tip filter registrations", len(job.entries))
            job.completed_event.set()

    logger.debug("Entering manage_tip_filter_registrations_async, server_id=%d",
        state.server.server_id)
    try:
        while state.connection_flags & ServerConnectionFlag.EXITING == 0:
            await process_registrations_worker_async()
    finally:
        logger.debug("Exiting manage_tip_filter_registrations_async, server_id=%d",
            state.server.server_id)


async def process_incoming_peer_channel_messages_async(state: ServerConnectionState) -> None:
    assert state.wallet_proxy is not None
    assert state.wallet_data is not None
    assert state.cached_peer_channel_rows is not None

    logger.debug("Entering process_incoming_peer_channel_messages_async, server_id=%d",
        state.server.server_id)

    while state.connection_flags & ServerConnectionFlag.EXITING == 0:
        remote_channel_id = await state.peer_channel_message_queue.get()

        peer_channel_row = state.cached_peer_channel_rows.get(remote_channel_id)
        if peer_channel_row is None:
            # TODO(1.4.0) Servers. Error handling for unknown peer channel.
            #     a) The server is buggy and has sent us a message intended for someone else.
            #     b) We are buggy and we have not correctly tracked peer channels.
            #     We should flag this to the user in some user-friendly way as a reliability
            #       indicator.
            logger.error("Received peer channel notification for unknown channel '%s'",
                remote_channel_id)
            continue

        assert peer_channel_row.peer_channel_id is not None
        messages = await list_peer_channel_messages_async(state, peer_channel_row.peer_channel_id,
            remote_channel_id, unread_only=True)
        if len(messages) == 0:
            logger.error("Asked peer channel %d for new messages and received none",
                peer_channel_row.peer_channel_id)
            continue
        # TODO(1.4.0) Peer channels. It might be worth tying toggling messages read when we
        #     know we have them in the database.
        #     - If for instance we inserted the pushdata match database here, then marked the
        #       messages as read after the loop.
        #     - We would want to do the same for the mapi callbacks.
        #     - Maybe we should even delete the messages.
        max_sequence = max(message["sequence"] for message in messages)
        await mark_peer_channel_read_or_unread(state, peer_channel_row.peer_channel_id,
            remote_channel_id, max_sequence, older=True, is_read=True)

        for message in messages:
            if message["content_type"] == "application/json":
                purpose = peer_channel_row.peer_channel_flags & ServerPeerChannelFlag.MASK_PURPOSE
                if purpose == ServerPeerChannelFlag.TIP_FILTER_DELIVERY:
                    if not isinstance(message["payload"], dict):
                        # TODO(1.4.0) Servers. Unreliable server (peer channel message) show user.
                        logger.error("Peer channel message payload invalid: '%s'", message)
                        continue
                    pushdata_matches = cast(TipFilterPushDataMatchesData, message["payload"])
                    if "blockId" not in pushdata_matches:
                        # TODO(1.4.0) Servers. Unreliable server (peer channel message) show user.
                        logger.error("Peer channel message payload invalid: '%s'", message)
                        continue

                    date_created = get_posix_timestamp()
                    rows = list[PushDataMatchRow]()
                    block_hash: Optional[bytes] = None
                    if pushdata_matches["blockId"] is not None:
                        block_hash = hex_str_to_hash(pushdata_matches["blockId"])
                    for tip_filter_match in pushdata_matches["matches"]:
                        pushdata_hash = bytes.fromhex(tip_filter_match["pushDataHashHex"])
                        transaction_hash = hex_str_to_hash(tip_filter_match["transactionId"])
                        transaction_index = tip_filter_match["transactionIndex"]
                        match_flags = PushDataMatchFlag(tip_filter_match["flags"])
                        # TODO(1.4.0) Tip filters. See `read_pushdata_match_metadata`
                        match_flags |= PushDataMatchFlag.UNPROCESSED
                        row = PushDataMatchRow(state.server.server_id, pushdata_hash,
                            transaction_hash, transaction_index, block_hash, match_flags,
                            date_created)
                        rows.append(row)

                    logger.debug("Writing %d pushdata matches to the database", len(rows))
                    await state.wallet_data.create_pushdata_matches_async(rows)
                    state.tip_filter_new_matches_event.set()
                    state.tip_filter_new_matches_event.clear()
                elif purpose == ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK:
                    if not isinstance(message["payload"], dict):
                        # TODO(1.4.0) Servers. Unreliable server (peer channel message) show user.
                        logger.error("Peer channel message payload invalid: '%s'", message)
                        continue
                    mapi_callback_response = cast(MAPICallbackResponse, message["payload"])
                    if "callbackTxId" not in mapi_callback_response:
                        # TODO(1.4.0) Servers. Unreliable server (peer channel message) show user.
                        logger.error("Peer channel message payload invalid: '%s'", message)
                        continue

                    if "callbackReason" in mapi_callback_response and \
                            mapi_callback_response["callbackReason"] in \
                                ("doubleSpendAttempt", "merkleProof"):
                        await state.mapi_callback_response_queue.put(mapi_callback_response)
                    else:
                        # TODO(1.4.0) Servers. Unreliable server (peer channel message) show user.
                        logger.error("Peer channel message not recognised: '%s'", message)
                else:
                    # TODO(1.4.0) Servers. Unreliable server (peer channel message) show user.
                    logger.error("Received peer channel %d message of unhandled purpose '%s'",
                        peer_channel_row.peer_channel_id, purpose)
            else:
                # TODO(1.4.0) Servers. Unreliable server (peer channel message) show user.
                logger.error("Received peer channel %d message with unexpected content type '%s'",
                    peer_channel_row.peer_channel_id, message['content_type'])

    logger.debug("Exiting process_incoming_peer_channel_messages_async, server_id=%d",
        state.server.server_id)


async def validate_server_data(state: ServerConnectionState) -> None:
    """
    There are a set of tasks we should perform before we start using the server to verify the
    remote state matches the local state.

    Requirements:
    - Check the indexer settings are valid and match our local state.
    - Check which peer channels exist and which the wallet believes to exist.
    - Check what pushdata hash registrations exist for tip filtering.

    Use cases (not necessarily complete):
    - A backup is restored and the prepayment for a peer channel to be hosted was spent and the
      channel closed. We may have some system depending on an expected result, like a merkle proof
      that will now never be received.
    """
    assert state.wallet_proxy is not None
    assert state.wallet_data is not None

    if ServerCapability.TIP_FILTER in state.utilised_capabilities:
        assert state.indexer_settings is None
        state.indexer_settings = await get_server_indexer_settings(state)

    if ServerCapability.PEER_CHANNELS in state.utilised_capabilities:
        existing_channel_rows = state.wallet_data.read_server_peer_channels(state.server.server_id)
        peer_channels = await list_peer_channels_async(state)

        peer_channels_by_id = { channel.channel_id: channel for channel in peer_channels }
        peer_channel_rows_by_id = { cast(str, row.remote_channel_id): row
            for row in existing_channel_rows }
        # TODO(1.4.0) Servers. Known peer channels differ from actual server peer channels.
        # - Could be caused by a shared API key with another wallet.
        # - This is likely to be caused by bad user choice and the wallet should only be
        #   responsible for fixing anything related to it's mistakes.
        if set(peer_channels_by_id) != set(peer_channel_rows_by_id):
            raise InvalidStateError("Mismatched peer channels, local and server")

        state.cached_peer_channels = peer_channels_by_id
        state.cached_peer_channel_rows = peer_channel_rows_by_id

        for peer_channel_row in existing_channel_rows:
            assert peer_channel_row.remote_channel_id is not None
            await state.peer_channel_message_queue.put(peer_channel_row.remote_channel_id)

    if ServerCapability.TIP_FILTER in state.utilised_capabilities:
        # By passing the timestamp, we only get the non-expired registrations. The indexing
        # server should have purged these itself, giving us current registrations on both sides.
        current_timestamp = int(time.time())
        existing_tip_filter_rows = state.wallet_data.read_tip_filter_pushdata_registrations(
            state.server.server_id, current_timestamp)
        server_tip_filters = await list_tip_filter_registrations_async(state)

        server_tip_filter_by_pushdata_hash = { server_tip_filter.pushdata_hash: server_tip_filter
            for server_tip_filter in server_tip_filters }
        tip_filter_row_by_pushdata_hash = dict[bytes, PushDataHashRegistrationRow]()
        matched_server_filter_pushdata_hashes = set[bytes]()
        correctable_local_tip_filters = list[tuple[int, int, int, int, int, int]]()
        deletable_local_tip_filters = list[tuple[int, int]]()
        # Start by checking that all the local registrations are matched on the server.
        # Remember, these are added to the database after successful creation on that server..
        for tip_filter_row in existing_tip_filter_rows:
            pushdata_hash = tip_filter_row.pushdata_hash
            tip_filter_row_by_pushdata_hash[pushdata_hash] = tip_filter_row

            # 1. Does the server have this tip filter registration?
            if pushdata_hash not in server_tip_filter_by_pushdata_hash:
                if tip_filter_row.pushdata_flags & PushDataHashRegistrationFlag.REGISTERING:
                    # The pushdata hash is not registered on the server.
                    # - We assume that the registration was interrupted before it did more than
                    #   initial local changes. We will remove the flag and make it appear as if it
                    #   were not registered.
                    deletable_local_tip_filters.append((tip_filter_row.server_id,
                        tip_filter_row.keyinstance_id))
                    continue

                # TODO(1.4.0) Tip filters. Server lacks registration. Needs handling.
                #     - Using the same wallet in different installations?
                #     - Expiry date edge case? Clock error?
                #     - Purged account due to abuse or other reason?
                raise InvalidStateError(
                    f"TODO(1.4.0) Handle missing server tip filter registration {tip_filter_row}")

            server_tip_filter = server_tip_filter_by_pushdata_hash[pushdata_hash]
            # 2. Does the server tip filter have the same registration duration?
            if tip_filter_row.duration_seconds != server_tip_filter.duration_seconds:
                # TODO(1.4.0) Tip filters. Server registration mismatch in expiry duration.
                #     - Maybe the user changed the duration on the registration?
                #       - If the user did this, we would want to update both at the same time
                #         and coordinate it. Do not allow it if they are offline.
                raise InvalidStateError("TODO(1.4.0) Handle filter duration mismatch")

            if tip_filter_row.pushdata_flags & PushDataHashRegistrationFlag.REGISTERING:
                # The pushdata hash is registered on the server.
                # - We assume that the registration was interrupted before we received and
                #   finished updating the local state. We will update the local state.
                correctable_local_tip_filters.append((server_tip_filter.date_created,
                    current_timestamp, ~PushDataHashRegistrationFlag.REGISTERING,
                    PushDataHashRegistrationFlag.NONE, tip_filter_row.server_id,
                    tip_filter_row.keyinstance_id))
                # This can fall through and become a match.
            elif tip_filter_row.date_registered != server_tip_filter.date_created:
                # TODO(1.4.0) Tip filters. Server registration mismatch in date registered.
                #     - Using the same wallet in different installations?
                raise InvalidStateError("TODO(1.4.0) Handle filter date created mismatch")
            matched_server_filter_pushdata_hashes.add(pushdata_hash)

        # Apply the deletions and updates to the database.
        await state.wallet_data.delete_registered_tip_filter_pushdatas_async(
            deletable_local_tip_filters)
        await state.wallet_data.update_registered_tip_filter_pushdatas_async(
            correctable_local_tip_filters)

        # Next check if all server filters exist locally.
        for server_tip_filter in server_tip_filters:
            if server_tip_filter.pushdata_hash not in matched_server_filter_pushdata_hashes:
                # Allow some leeway in filters that are expiring literally now / are expired.
                # In this case, any that expire in less than 5 seconds.
                expiry_time = server_tip_filter.date_created + server_tip_filter.duration_seconds
                if expiry_time - get_posix_timestamp() < 5:
                    continue
                # TODO(1.4.0) Tip filters. Server has registered pushdatas we do not know about.
                #     - Using the same wallet in different installations?
                raise InvalidStateError("TODO(1.4.0) Handle orphaned server registration mismatch")


async def prepare_server_tip_filter_peer_channel(indexing_server_state: ServerConnectionState) \
        -> None:
    """
    Raises `InvalidStateError` if a situation arises where either the remote server or the local
        wallet look problematic.

    Peer channel creation, indexer settings:
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert indexing_server_state.wallet_proxy is not None
    assert indexing_server_state.wallet_data is not None

    # This should only be clear for non-indexer servers.
    assert indexing_server_state.indexer_settings is not None
    assert ServerCapability.TIP_FILTER in indexing_server_state.utilised_capabilities

    peer_channel_server_state = indexing_server_state.wallet_proxy.get_server_state_for_capability(
        ServerCapability.PEER_CHANNELS)
    assert peer_channel_server_state is not None
    assert peer_channel_server_state.wallet_data is not None

    while peer_channel_server_state is not indexing_server_state:
        # The peer channel server is a different server. We do not know that it is ready. Either
        # we should wait for it to become ready, or we should retry this call when it is.
        # TODO(1.4.0) Servers. Handle `TimeoutError` in a better way, and this edge case.
        #     If there is no workable peer channel server, then the user should be notified and
        #     they should have to rectify it.
        if peer_channel_server_state.connection_flags & ServerConnectionFlag.WEB_SOCKET_CONNECTED \
                == 0:
            await asyncio.wait_for(peer_channel_server_state.stage_change_event.wait(), 10)
        if peer_channel_server_state.connection_flags & ServerConnectionFlag.WEB_SOCKET_CONNECTED \
                == 0:
            raise InvalidStateError(f"Tip filter unable to find peer channel server")

    indexing_server_id = indexing_server_state.server.server_id
    peer_channel_server_id = peer_channel_server_state.server.server_id
    peer_channel_id = indexing_server_state.server.get_tip_filter_peer_channel_id(
        indexing_server_state.petty_cash_account_id)
    # This will be the same for any server state object as they belong to the same wallet.
    wallet_data = indexing_server_state.wallet_data

    peer_channel_row: Optional[ServerPeerChannelRow] = None
    if peer_channel_id is not None:
        # TODO(1.4.0) Tip filters. It looks like we created a peer channel locally, but either
        #     never got around to creating it remotely or got interrupted before we could
        #     store the details retrieved from the remote server (remote id/url/...).
        assert peer_channel_server_state.cached_peer_channel_rows is not None
        for peer_channel_row_n in peer_channel_server_state.cached_peer_channel_rows.values():
            if peer_channel_row_n.peer_channel_id == peer_channel_id:
                peer_channel_row = peer_channel_row_n
                break
        else:
            # There is nothing we can do in this case. Just error.
            raise InvalidStateError(f"Peer channel {peer_channel_id} lacks matching row")
        # TODO(1.4.0) Tip filters. Server unreliability case OR user unreliability
        #     clashing wallets open using servers with the same account.
        if peer_channel_row.peer_channel_flags & ServerPeerChannelFlag.TIP_FILTER_DELIVERY == 0:
            raise InvalidStateError(f"Peer channel {peer_channel_id} lacks tip filter flag")

    tip_filter_callback_url = indexing_server_state.indexer_settings.get("tipFilterCallbackUrl")
    if tip_filter_callback_url is not None:
        if peer_channel_id is None:
            # TODO(1.4.0) Tip filters. Server unreliability case OR user unreliability
            #     clashing wallets open using servers with the same account.
            raise InvalidStateError("Unreliability. Remote callback with no local channel")

        assert peer_channel_row is not None
        if peer_channel_row.remote_url != tip_filter_callback_url:
            # TODO(1.4.0) Tip filters. Server unreliability case OR user unreliability
            #     clashing wallets open using servers with the same account.
            raise InvalidStateError("Unreliability. Mismatching channel url "+
                f"{tip_filter_callback_url} != {peer_channel_row.remote_url}")
        # At this point we know the peer channel is correctly set up.
        return

    if peer_channel_id is not None:
        # What we know here is that the server was not given a notification URL but we do have
        # the peer channel set up. We should verify that the settings are correct. These should
        # have been set when the ...
        assert peer_channel_row is not None
        assert peer_channel_row.peer_channel_id is not None
        # These fields should have been set this way by the `update_server_peer_channel_async` call.
        if peer_channel_row.remote_url is None or peer_channel_row.remote_channel_id is None:
            raise InvalidStateError(f"Unreliability. Broken peer channel {peer_channel_row}")
        assert peer_channel_row.peer_channel_flags & ServerPeerChannelFlag.ALLOCATING == 0

        assert peer_channel_server_state.cached_peer_channels is not None
        # We know this peer channel is present because `validate` passed.
        peer_channel = peer_channel_server_state.cached_peer_channels[
            peer_channel_row.remote_channel_id]

        # Look for the access token that would have been created with the channel.
        db_access_tokens = peer_channel_server_state.wallet_data \
            .read_server_peer_channel_access_tokens(peer_channel_row.peer_channel_id,
                PeerChannelAccessTokenFlag.FOR_TIP_FILTER_SERVER,
                PeerChannelAccessTokenFlag.FOR_TIP_FILTER_SERVER)
        assert len(db_access_tokens) == 1
        tip_filter_access_token = db_access_tokens[0]
    else:
        date_created = get_posix_timestamp()
        peer_channel_row = ServerPeerChannelRow(None, peer_channel_server_id, None, None,
            ServerPeerChannelFlag.ALLOCATING | ServerPeerChannelFlag.TIP_FILTER_DELIVERY,
            date_created, date_created)
        peer_channel_id = await wallet_data.create_server_peer_channel_async(peer_channel_row,
            indexing_server_id)
        peer_channel_row = peer_channel_row._replace(peer_channel_id=peer_channel_id)
        indexing_server_state.server.set_tip_filter_peer_channel_id(
            indexing_server_state.petty_cash_account_id, peer_channel_id)

        # Peer channel server: create the remotely hosted peer channel.
        peer_channel = await create_peer_channel_async(peer_channel_server_state)
        assert peer_channel_server_state.cached_peer_channel_rows is not None
        peer_channel_server_state.cached_peer_channel_rows[peer_channel.channel_id] = \
            peer_channel_row

        # Peer channel server: create a custom write-only access token for the channel, for
        #    the use of the indexing server.
        peer_channel_api_key = await create_peer_channel_api_token_async(peer_channel_server_state,
            peer_channel.channel_id, can_read=False, can_write=True, description="private")
        assert peer_channel_row.peer_channel_id is not None
        assert len(peer_channel.tokens) == 1
        tip_filter_access_token = ServerPeerChannelAccessTokenRow(peer_channel_row.peer_channel_id,
            peer_channel_api_key.remote_token_id,
            PeerChannelAccessTokenFlag.FOR_TIP_FILTER_SERVER, peer_channel_api_key.permissions,
            peer_channel_api_key.api_key)
        peer_channel_token = peer_channel.tokens[0]
        local_access_token = ServerPeerChannelAccessTokenRow(peer_channel_row.peer_channel_id,
            peer_channel_token.remote_token_id,
            PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE, peer_channel_token.permissions,
            peer_channel_token.api_key)

        # Local database: Update for the server-side peer channel. Drop the `ALLOCATING` flag and
        #     add the access token.
        await wallet_data.update_server_peer_channel_async(peer_channel.channel_id,
            peer_channel.url, ServerPeerChannelFlag.TIP_FILTER_DELIVERY, peer_channel_id,
            addable_access_tokens=[tip_filter_access_token, local_access_token])

    # Indexing server: Notify that we now have a tip filter callback url.
    # The update is a subset of the overall indexer server settings that we want to update.
    settings_delta_object = cast(IndexerServerSettings, {})
    settings_delta_object["tipFilterCallbackUrl"] = peer_channel.url
    settings_delta_object["tipFilterCallbackToken"] = tip_filter_access_token.access_token
    settings_object = await update_server_indexer_settings(indexing_server_state,
        settings_delta_object)
    # NOTE(typing) Type is incompatible with same type, who knows? Error message as follows:
    # `Argument 1 to "update" of "TypedDict" has incompatible type "IndexerServerSettings";
    # expected "TypedDict({'tipFilterCallbackUrl'?: Optional[str]})"  [typeddict-item]`
    indexing_server_state.indexer_settings.update(settings_delta_object) # type: ignore
    if settings_object != indexing_server_state.indexer_settings:
        # TODO(1.4.0) Tip filters. Server unreliability case OR user unreliability with
        #     clashing wallets open using servers with the same account.
        raise InvalidStateError("Unreliability. Local/remote indexer settings mismatch "+
            f"{settings_object} != {indexing_server_state.indexer_settings}")


async def get_server_indexer_settings(state: ServerConnectionState) -> IndexerServerSettings:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/indexer"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    try:
        async with state.session.get(server_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            return cast(IndexerServerSettings, await response.json())
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {server_url}")


async def update_server_indexer_settings(state: ServerConnectionState,
        settings_delta: IndexerServerSettings) -> IndexerServerSettings:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/indexer"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {
        "Authorization":    f"Bearer {master_token}"
    }
    try:
        async with state.session.post(server_url, json=settings_delta, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            return cast(IndexerServerSettings, await response.json())
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {server_url}")


async def create_peer_channel_async(state: ServerConnectionState,
        public_read: bool=False, public_write: bool=True,
        sequenced: bool=True, retention: Optional[RetentionViewModel]=None) -> PeerChannel:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    url = f"{state.server.url}api/v1/channel/manage"
    body = {
        "public_read": public_read,
        "public_write": public_write,
        "sequenced": sequenced,
        "retention": {
            "min_age_days": 0,
            "max_age_days": 0,
            "auto_prune": True
        }
    }
    if retention:
        body.update(retention)

    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    try:
        async with state.session.post(url, headers=headers, json=body) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            json_response: PeerChannelViewModelGet = await response.json()
            peer_channel = PeerChannel.from_json(json_response, state)
            # Cache the new peer channel object for now.
            assert state.cached_peer_channels is not None
            state.cached_peer_channels[peer_channel.channel_id] = peer_channel
            return peer_channel
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {url}")


async def mark_peer_channel_read_or_unread(state: ServerConnectionState, channel_id: int,
        remote_channel_id: str, sequence: int, older: bool, is_read: bool) -> None:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert state.wallet_proxy is not None
    assert state.wallet_data is not None

    # TODO(1.4.0) Credentials. Access tokens should be encrypted in the credentials cache.
    db_access_tokens = state.wallet_data.read_server_peer_channel_access_tokens(channel_id,
        PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE,
        PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE)
    assert len(db_access_tokens) == 1
    owner_access_token = db_access_tokens[0]

    url = f"{state.server.url}api/v1/channel/{remote_channel_id}/{sequence}"
    headers = {
        "Authorization": f"Bearer {owner_access_token.access_token}"
    }
    query_parameters: dict[str, str] = {}
    if older:
        query_parameters["older"] = "true"
    body_object: dict[str, Any] = { "read": is_read }
    try:
        async with state.session.post(url, headers=headers, params=query_parameters,
                json=body_object) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {url}")


async def list_peer_channels_async(state: ServerConnectionState) -> List[PeerChannel]:
    """
    Use the reference peer channel implementation API for listing peer channels.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/channel/manage/list"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    try:
        async with state.session.get(server_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            result = []
            for peer_channel_json in await response.json():
                peer_channel_obj = PeerChannel.from_json(peer_channel_json, state)
                result.append(peer_channel_obj)
            return result
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {server_url}")


async def list_peer_channel_messages_async(state: ServerConnectionState, channel_id: int,
        remote_channel_id: str, unread_only: bool=False) -> list[GenericPeerChannelMessage]:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.

    WARNING: This does not set the messages to read when it reads them.. that needs to be done
        manually after this call with another to `mark_peer_channel_read_or_unread`.
    """
    assert state.wallet_proxy is not None
    assert state.wallet_data is not None

    # TODO(1.4.0) Credentials. Access tokens should be encrypted in the credentials cache.
    db_access_tokens = state.wallet_data.read_server_peer_channel_access_tokens(channel_id,
        PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE,
        PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE)
    assert len(db_access_tokens) == 1
    owner_access_token = db_access_tokens[0]

    url = f"{state.server.url}api/v1/channel/{remote_channel_id}"
    headers = {
        "Authorization": f"Bearer {owner_access_token.access_token}"
    }
    query_parameters: dict[str, str] = {}
    if unread_only:
        query_parameters["unread"] = "true"
    try:
        async with state.session.get(url, headers=headers, params=query_parameters) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            return cast(list[GenericPeerChannelMessage], await response.json())
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {url}")


async def create_peer_channel_api_token_async(state: ServerConnectionState, channel_id: str,
        can_read: bool=True, can_write: bool=True, description: str="standard token") \
            -> PeerChannelToken:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    url = f"{state.server.url}api/v1/channel/manage/{channel_id}/api-token"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    body = {
        "description": description,
        "can_read": can_read,
        "can_write": can_write
    }
    try:
        async with state.session.post(url, headers=headers, json=body) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            json_token: PeerChannelAPITokenViewModelGet = await response.json()
            permissions: TokenPermissions = TokenPermissions.NONE
            if json_token['can_read']:
                permissions |= TokenPermissions.READ_ACCESS
            if json_token['can_write']:
                permissions |= TokenPermissions.WRITE_ACCESS
            return PeerChannelToken(json_token["id"], permissions=permissions,
                api_key=json_token['token'])
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {url}")


async def create_tip_filter_registrations_async(state: ServerConnectionState,
        registration_datas: list[tuple[bytes, int]]) -> int:
    """
    Use the reference server indexer API for listing tip filter registration.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/transaction/filter"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {
        'Accept':           'application/json',
        "Authorization":    f"Bearer {master_token}"
    }
    # Pack the binary array of registrations into the bytearray.
    byte_buffer = bytearray(len(registration_datas) * tip_filter_registration_struct.size)
    for data_index, registration_data in enumerate(registration_datas):
        tip_filter_registration_struct.pack_into(byte_buffer,
            data_index * tip_filter_registration_struct.size, registration_data[0],
                registration_data[1])
    json_object: TipFilterRegistrationResponse
    try:
        async with state.session.post(server_url, data=byte_buffer, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            json_object = await response.json()
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {server_url}")

    # For now we unpack the object and return the elements as a tuple.
    date_created = datetime.fromisoformat(json_object["dateCreated"]).replace(tzinfo=timezone.utc)
    return int(date_created.timestamp())


async def list_tip_filter_registrations_async(state: ServerConnectionState) \
        -> list[TipFilterListEntry]:
    """
    Use the reference server indexer API for listing tip filter registration.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/transaction/filter"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {
        'Accept':           'application/octet-stream',
        "Authorization":    f"Bearer {master_token}"
    }
    try:
        async with state.session.get(server_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            body_bytes = await response.content.read()
    except aiohttp.ClientError:
        # TODO(1.4.0) Servers. We do not want to lose error details, when we wrap exceptions
        #     like this, we should do something to make sure that does not happen. Debug log?
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Failed to connect to server at: {server_url}")

    list_entries = list[TipFilterListEntry]()
    for entry_index in range(len(body_bytes) // tip_filter_list_struct.size):
        entry = TipFilterListEntry(*tip_filter_list_struct.unpack_from(body_bytes,
            entry_index * tip_filter_list_struct.size))
        list_entries.append(entry)
    return list_entries
