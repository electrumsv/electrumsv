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
from functools import partial
from http import HTTPStatus
import json
import struct
import time
from typing import AsyncIterable, cast, NamedTuple, TypedDict

import aiohttp
from aiohttp import WSServerHandshakeError
from bitcoinx import hash_to_hex_str, PrivateKey, PublicKey

from ..app_state import app_state
from ..constants import NetworkServerFlag, PeerChannelAccessTokenFlag, \
    PushDataHashRegistrationFlag, ScriptType, ServerConnectionFlag, ServerPeerChannelFlag
from ..exceptions import BadServerError, ServerConnectionError
from ..logs import logs
from ..types import IndefiniteCredentialId, Outpoint, outpoint_struct, output_spend_struct, \
    OutputSpend, tip_filter_list_struct, tip_filter_registration_struct, \
    tip_filter_unregistration_struct, TipFilterListEntry
from ..util import get_posix_timestamp
from ..wallet_database.types import PushDataHashRegistrationRow, ServerPeerChannelAccessTokenRow, \
    ServerPeerChannelMessageRow, ServerPeerChannelRow

from .constants import ServerProblemKind
from .exceptions import AuthenticationError, FilterResponseInvalidError, \
    FilterResponseIncompleteError, GeneralAPIError, IndexerResponseMissingError, \
    InvalidStateError, TransactionNotFoundError
from .peer_channel import create_peer_channel_api_token_async, create_peer_channel_async, \
    delete_peer_channel_message_async, get_permissions_from_peer_channel_token, \
    list_peer_channels_async, list_peer_channel_messages_async, \
    convert_peer_channel_messages_to_rows
from .types import AccountMessageKind, ChannelNotification, GenericPeerChannelMessage, \
    IndexerServerSettings, ServerConnectionState, ServerConnectionProblems, \
    TipFilterRegistrationJob, TipFilterRegistrationJobEntry, TipFilterRegistrationJobOutput, \
    TipFilterRegistrationResponse, VerifiableKeyData, _on_server_connection_worker_task_done

logger = logs.get_logger("general-api")


class MatchFlags(enum.IntFlag):
    # The match is in a transaction output.
    IN_OUTPUT = 1 << 0
    # The match is in a transaction input.
    IN_INPUT = 1 << 1


class RestorationFilterRequest(TypedDict):
    filterKeys: list[str]

class RestorationFilterJSONResponse(TypedDict):
    flags: int
    pushDataHashHex: str
    lockingTransactionId: str
    lockingTransactionIndex: int
    unlockingTransactionId: str | None
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
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {url}")


def unpack_binary_restoration_entry(entry_data: bytes) -> RestorationFilterResult:
    assert len(entry_data) == FILTER_RESPONSE_SIZE
    return RestorationFilterResult(*struct.unpack(RESULT_UNPACK_FORMAT, entry_data))


STREAM_CHUNK_SIZE = 16*1024


async def request_binary_merkle_proof_async(state: ServerConnectionState, tx_hash: bytes,
        include_transaction: bool=False, target_type: str="hash") -> bytes:
    """
    Get a TSC merkle proof with optional embedded transaction.

    At a later time this will need to stream the proof given potentially 4 GiB large transactions,
    but it is more likely that we will simply separate the transaction and proof in the response
    for ease of access.

    Raises `FilterResponseInvalidError` if the response is not valid.
    Raises `IndexerResponseMissingError` if the resource does not exist.
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
            if response.status == HTTPStatus.NOT_FOUND:
                raise IndexerResponseMissingError()
            elif response.status != HTTPStatus.OK:
                raise FilterResponseInvalidError(
                    f"Bad response status={response.status}, reason={response.reason}")

            content_type, *content_type_extra = response.headers["Content-Type"].split(";")
            if content_type != "application/octet-stream":
                raise FilterResponseInvalidError(
                    "Invalid response content type, got {}, expected {}".format(content_type,
                        "octet-stream"))

            return await response.content.read()
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")



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
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {state.server.url}")


def process_reference_server_message_bytes(state: ServerConnectionState, message_bytes: bytes) \
        -> tuple[AccountMessageKind, ChannelNotification | OutputSpend]:
    """
    Decode and validate incoming message bytes from the reference server.

    This takes an incoming message encoded as bytes, checks that the server should be sending it
    given what we use this server for, checks that it can decode the message and that it contains
    correct-looking data. We do not however verify the correctness of the contents of the message,
    beyond these relevance and "looks correct" checks.

    Raises `BadServerError` if the server sends obviously bad data.
    Raises `NotImplementedError` if the server sends us a message type we know about but the
        programmer has not correctly hooked up. We just let this raise and assume the release
        is buggy.
    """
    try:
        message_kind_value: int = struct.unpack_from(">I", message_bytes, 0)[0]
    except (TypeError, struct.error):
        # `struct.error`: The bytes to be unpacked do not start with valid data for the requested
        #   type.
        raise BadServerError("Received an invalid message type")

    try:
        message_kind = AccountMessageKind(message_kind_value)
    except ValueError:
        # `ValueError`: The value is not a member of the enum.
        raise BadServerError(f"Received an unknown message type ({message_kind_value})")

    if message_kind == AccountMessageKind.PEER_CHANNEL_MESSAGE:
        if state.usage_flags & NetworkServerFlag.USE_MESSAGE_BOX == 0:
            raise BadServerError("Received a peer channel message from a server you "
                "are not using for peer channels")

        try:
            message = json.loads(message_bytes[4:].decode("utf-8"))
        except (TypeError, json.decoder.JSONDecodeError):
            raise BadServerError("Received an invalid peer channel message from a "
                "server you are using for peer channels (cannot decode as JSON)")

        # Verify that this at least looks like a valid `ChannelNotification` message.
        if not isinstance(message, dict) or len(message) != 2 or \
                not isinstance(message.get("id", None), str) or \
                not isinstance(message.get("notification", None), str):
            raise BadServerError("Received an invalid peer channel message from a "
                "server you are using (unrecognised structure)")

        return message_kind, cast(ChannelNotification, message)
    elif message_kind == AccountMessageKind.SPENT_OUTPUT_EVENT:
        if state.usage_flags & NetworkServerFlag.USE_BLOCKCHAIN == 0:
            raise BadServerError("Received a blockchain services related message "
                "from a server you you are not using for blockchain services (tip filtering "
                "related)")

        try:
            spent_output_fields = output_spend_struct.unpack_from(message_bytes, 4)
        except (TypeError, struct.error):
            # `TypeError`: This is raised when the arguments passed are not one bytes object.
            # `struct.error`: This is raised when the bytes object is invalid, whether not long
            #     enough or of incompatible types.
            raise BadServerError("Received an invalid blockchain services message "
                "from a server you are using (unable to decode)")

        return message_kind, OutputSpend.from_network(*spent_output_fields)
    else:
        # If this ever happens it is because the programmer who added a new entry to
        # `AccountMessageKind` did not hook it up here.
        raise NotImplementedError(f"Packing message kind {message_kind} is unsupported")


async def maintain_server_connection_async(state: ServerConnectionState) \
        -> ServerConnectionProblems:
    """
    Keep a persistent connection to this ElectrumSV reference server alive.
    """
    assert state.connection_flags == ServerConnectionFlag.INITIALISED

    # We do not set `stage_change_event` for this flag.
    state.connection_flags |= ServerConnectionFlag.STARTING

    try:
        while state.connection_flags & ServerConnectionFlag.EXITING == 0:
            state.connection_flags &= ServerConnectionFlag.MASK_COMMON_INITIAL

            # Both the connection management task and worker tasks.
            future = app_state.async_.spawn(_manage_server_connection_async(state))
            future.add_done_callback(partial(_on_server_connection_worker_task_done, state))

            # This will block until this task is cancelled, or there is a problem establishing
            # a connection with the server not necessarily in the web socket connection itself,
            # but also secondary calls.

            problem_kind, problem_text = await state.disconnection_event_queue.get()
            future.cancel()

            # We yield to so that the cancellation error can get raised on the manage task.
            await asyncio.sleep(0)

            server_problems = { problem_kind: [ problem_text ] }
            # Drain the queue of disconnection problems.
            while not state.disconnection_event_queue.empty():
                problem_kind, problem_text = state.disconnection_event_queue.get_nowait()
                server_problems[problem_kind].append(problem_text)

            if ServerProblemKind.BAD_SERVER in server_problems:
                # We do not try and recover from this problem. It goes up to the user.
                return server_problems

            logger.debug("Server disconnected, clearing state, waiting to retry")
            state.clear_for_reconnection(ServerConnectionFlag.DISCONNECTED)

            # TODO(1.4.0) Unreliable server, issue#841. Disconnected or cannot connect to server.
            #     This is an arbitrary timeout, we should factor when this happens into the UI and
            #     how we manage server usage.
            await asyncio.sleep(10)
    finally:
        logger.error("maintain_server_connection_async encountered connection issue")
        state.connection_flags = ServerConnectionFlag.EXITED

    return {}


async def verify_reference_server_credentials_async(state: ServerConnectionState) -> None:
    """
    Returns nothing.
    Raises `GeneralAPIError` if non-successful response encountered.
    Raises `ServerConnectionError` if the server could not be reliably connected to.
    """
    assert state.credential_id is not None

    # Check if the existing credentials are still valid.
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    account_metadata_url = f"{state.server.url}api/v1/account"
    # TODO(technical-debt) aiohttp exceptions. What aiohttp exceptions are raised here??
    try:
        async with state.session.get(account_metadata_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                logger.error("Unexpected status in payment key endpoint response (vkd) %d (%s)",
                    response.status, response.reason)
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            # `metadata` is currently {"public_key_key": ..., "api_key": ...}
            metadata = await response.json()
            logger.debug("Existing credentials verified for server %s", state.server.server_id)
            return
    except aiohttp.ClientConnectorError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError("Unable to establish server connection")


async def create_reference_server_account_async(server_url: str, session: aiohttp.ClientSession,
        identity_public_key: PublicKey,
        identity_private_key_credential_id: IndefiniteCredentialId) -> tuple[str, bytes]:
    """
    Returns `tuple[str, bytes]`, a tuple of API key and the server's payment key bytes.
    Raises `AuthenticationError` if response does not give valid payment keys or api keys.
    Raises `GeneralAPIError` if non-successful response encountered.
    Raises `InvalidPassword` if wallet password is not provided by the user.
    Raises `ServerConnectionError` if the server could not be reliably connected to.
    """
    # TODO(1.4.0) Server connection, issue#912. Review and finalise account creation.
    obtain_server_key_url = f"{server_url}api/v1/account/key"

    timestamp_text = datetime.utcnow().isoformat()
    message_text = f"{obtain_server_key_url} {timestamp_text}"
    identity_private_key = PrivateKey.from_hex(app_state.credentials.get_indefinite_credential(
        identity_private_key_credential_id))
    signature_bytes = identity_private_key.sign_message(message_text.encode())
    key_data: VerifiableKeyData = {
        "public_key_hex": identity_public_key.to_hex(),
        "signature_hex": signature_bytes.hex(),
        "message_hex": message_text.encode().hex(),
    }

    payment_key_bytes: bytes | None = None
    api_key: str | None = None
    # TODO(technical-debt) aiohttp exceptions. What aiohttp exceptions are raised here??
    try:
        async with session.post(obtain_server_key_url, json=key_data) as response:
            if response.status != HTTPStatus.OK:
                logger.error("Unexpected status in payment key endpoint response (vkd) %d (%s)",
                    response.status, response.reason)
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            # TODO(technical-debt) aiohttp exceptions. What aiohttp exceptions are raised here??
            reader = aiohttp.MultipartReader.from_response(response)
            while True:
                part = cast(aiohttp.BodyPartReader | None, await reader.next())
                if part is None:
                    break
                elif part.name == "key":
                    payment_key_bytes = bytes(await part.read(decode=True))
                elif part.name == "api-key":
                    api_key = await part.text()
    except aiohttp.ClientError as client_error:
        raise ServerConnectionError("Unable to establish server connection") from client_error

    # TODO(1.4.0) Unreliable server, issue#841. Server account creation response lacks payment key.
    if payment_key_bytes is None:
        raise AuthenticationError("No payment key received for server")

    # TODO(1.4.0) Unreliable server, issue#841. Server account creation response lacks API key.
    if api_key is None:
        raise AuthenticationError("No api key received for server")

    return api_key, payment_key_bytes


async def _manage_server_connection_async(state: ServerConnectionState) -> None:
    """
    Manage an open websocket to any server type.

    - This might be a reference server compatible.
    - This might be a peer channel we do not own but have the API key for and access to.

    Raises `BadServerError` if the server sends us data that we know it should not be sending.
    Raises `NotImplementedError` if we encounter cases that more than likely are caused by
        partially implemented features.
    """
    assert state.wallet_data is not None
    assert len(state.websocket_futures) == 0

    if not state.used_with_reference_server_api:
        # NOTE(rt12) This will be other people's peer channels we have access to, as one yet to
        #     be implemented use case we will need to support at some point.
        raise NotImplementedError("A programmer added support for another type of server "
            "connection but did not flesh out the web socket connection logic")
    assert state.credential_id is not None

    # Snapshot the usage flags before changing the state.
    existing_usage_flags = state.usage_flags

    state.connection_flags |= ServerConnectionFlag.VERIFYING
    state.stage_change_event.set()
    state.stage_change_event.clear()

    await _upgrade_server_preconnection_async(state, existing_usage_flags)

    state.connection_flags |= ServerConnectionFlag.ESTABLISHING_WEB_SOCKET
    state.stage_change_event.set()
    state.stage_change_event.clear()

    access_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    websocket_url_template = state.server.url + "api/v1/web-socket?token={access_token}"
    websocket_url = websocket_url_template.format(access_token=access_token)
    headers = {
        "Accept": "application/octet-stream"
    }
    try:
        async with state.session.ws_connect(websocket_url, headers=headers, timeout=5.0) \
                as server_websocket:
            logger.info('Connected to server websocket, url=%s', websocket_url_template)

            # Snapshot the usage flags before changing the state.
            existing_usage_flags = state.usage_flags

            state.connection_flags |= ServerConnectionFlag.PREPARING_WEB_SOCKET
            state.stage_change_event.set()
            state.stage_change_event.clear()

            await _upgrade_server_connection_async(state, existing_usage_flags)

            state.connection_flags |= ServerConnectionFlag.WEB_SOCKET_READY
            state.stage_change_event.set()
            state.stage_change_event.clear()

            try:
                websocket_message: aiohttp.WSMessage
                async for websocket_message in server_websocket:
                    if websocket_message.type == aiohttp.WSMsgType.TEXT:
                        if state.used_with_reference_server_api:
                            # This will be headers.
                            logger.debug("Ignoring websocket text: %s", websocket_message.data)
                            # raise BadServerError("We received a message in format "
                            #     "not expected from this server (text message)")
                        else:
                            raise NotImplementedError("")
                    elif websocket_message.type == aiohttp.WSMsgType.BINARY:
                        if state.used_with_reference_server_api:
                            # In processing the message `BadServerError` will be raised if this
                            # server cannot handle the incoming message, or it is malformed.
                            message_bytes = cast(bytes, websocket_message.data)
                            message_kind, message = process_reference_server_message_bytes(state,
                                message_bytes)
                        else:
                            raise BadServerError("We received a message in format "
                                "not expected from this server (binary message)")

                        if message_kind == AccountMessageKind.PEER_CHANNEL_MESSAGE:
                            channel_message = cast(ChannelNotification, message)
                            logger.debug("Queued incoming peer channel message %s", channel_message)
                            state.peer_channel_message_queue.put_nowait(channel_message["id"])
                        elif message_kind == AccountMessageKind.SPENT_OUTPUT_EVENT:
                            spent_output_message = cast(OutputSpend, message)
                            logger.debug("Queued incoming output spend message")
                            state.output_spend_result_queue.put_nowait([ spent_output_message ])
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
                for websocket_future in state.websocket_futures:
                    websocket_future.cancel()
                state.websocket_futures.clear()
    except WSServerHandshakeError as e:
        if e.status == HTTPStatus.UNAUTHORIZED:
            # We have already checked the credentials. There is no reason why this should fail.
            # So for now we classify this as an indicator of a bad server.
            raise BadServerError("Connection credentials unexpectedly invalid")

        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError("Unable to establish websocket connection")
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError("Unable to establish server connection")


async def upgrade_server_connection_async(state: ServerConnectionState,
        update_usage_flags: NetworkServerFlag) -> None:
    """
    Externally apply any upgrades needed for use cases that have been added to a server connection.

    Raises nothing.
    """
    logger.debug("Upgrading server %d connection", state.server.server_id)
    await _upgrade_server_preconnection_async(state, update_usage_flags)
    await _upgrade_server_connection_async(state, update_usage_flags)


async def _upgrade_server_preconnection_async(state: ServerConnectionState,
        update_usage_flags: NetworkServerFlag) -> None:
    # We do not need to upgrade the connection if it has not reached the point it applies it's
    # own upgrade for it's use cases.
    if state.connection_flags & ServerConnectionFlag.VERIFYING != 0:
        async with state.upgrade_lock:
            if update_usage_flags & NetworkServerFlag.USE_MESSAGE_BOX:
                await peer_channel_preconnection_async(state)

            if update_usage_flags & NetworkServerFlag.USE_BLOCKCHAIN:
                await blockchain_services_preconnection_async(state)


async def _upgrade_server_connection_async(state: ServerConnectionState,
        update_usage_flags: NetworkServerFlag) -> None:
    # We do not need to upgrade the connection if it has not reached the point it applies it's
    # own upgrade for it's use cases.
    if state.connection_flags & ServerConnectionFlag.PREPARING_WEB_SOCKET != 0:
        async with state.upgrade_lock:
            if update_usage_flags & NetworkServerFlag.USE_BLOCKCHAIN:
                for future in await blockchain_services_server_connected_async(state):
                    future.add_done_callback(partial(_on_server_connection_worker_task_done, state))

            if update_usage_flags & NetworkServerFlag.USE_MESSAGE_BOX:
                for future in await peer_channel_server_connected_async(state):
                    future.add_done_callback(partial(_on_server_connection_worker_task_done, state))


async def check_local_vs_remote_state_ok(state: ServerConnectionState,
        existing_channel_rows: list[ServerPeerChannelRow]) -> None:
    peer_channel_jsons = await list_peer_channels_async(state)
    peer_channel_ids = { channel_json["id"] for channel_json in peer_channel_jsons }
    owned_peer_channel_rows_by_id = { cast(str, row.remote_channel_id): row
        for row in existing_channel_rows }
    # TODO(1.4.0) Unreliable server, issue#841. Our peer channels differ from the server's.
    # - Could be caused by a shared API key with another wallet.
    # - This is likely to be caused by bad user choice and the wallet should only be
    #   responsible for fixing anything related to it's mistakes.
    # - Expired peer channels may need to be excluded.
    # - We should mark peer channels as `CLOSING` and we can pick those up here and close
    #   any we couldn't close when they were marked as such because of connection issues.
    if set(peer_channel_ids) != set(owned_peer_channel_rows_by_id):
        raise InvalidStateError("Mismatched peer channels, local and server")
    return


async def peer_channel_preconnection_async(state: ServerConnectionState) -> None:
    """
    Do pre-connection checks and calls on the peer channel server, to prepare to connect and
    also to validate that the server looks compatible.
    raises `InvalidStateError` if local vs remote state check fails
    """
    assert state.wallet_data is not None
    existing_channel_rows = state.wallet_data.read_server_peer_channels(state.server.server_id)
    all_peer_channel_rows_by_id = { cast(str, row.remote_channel_id): row
        for row in existing_channel_rows}
    if state.used_with_reference_server_api:
        await check_local_vs_remote_state_ok(state, existing_channel_rows)
    state.cached_peer_channel_rows = all_peer_channel_rows_by_id
    for peer_channel_row in existing_channel_rows:
        assert peer_channel_row.remote_channel_id is not None
        await state.peer_channel_message_queue.put(peer_channel_row.remote_channel_id)


async def peer_channel_server_connected_async(state: ServerConnectionState) -> list[Future[None]]:
    """
    Start up peer channel processing logic for a server we have just connected to.

    Raises nothing.

    NOTE: Analogue to `peer_channel.py:externally_owned_peer_channel_server_connected_async`
    """
    # All websocket futures are cancelled on server disconnection. This will interrupt the
    # underlying task. These functions have been written so that they are either stateless or
    # have other recovery logic elsewhere.

    future = app_state.async_.spawn(process_incoming_peer_channel_messages_async(state))
    state.websocket_futures.append(future)

    return [ future ]


async def process_incoming_peer_channel_messages_async(state: ServerConnectionState) -> None:
    """
    We raise server-related exceptions up and expect the connection management to deal with them.
    All exceptions raised by this in the context of a connect are processed by
    `_on_server_connection_worker_task_done`.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.

    NOTE: This is analagous to `process_externally_owned_peer_channel_messages_async` but for
    "owned" peer channels for which we have administrator priviledges on the server
    """

    # Typing related assertions.
    assert state.wallet_data is not None
    assert state.wallet_proxy is not None
    logger.debug("Entering process_incoming_peer_channel_messages_async, server_url=%s "
                 "(Wallet='%s')", state.server_url, state.wallet_proxy.name())

    while state.connection_flags & ServerConnectionFlag.EXITING == 0:
        remote_channel_id = await state.peer_channel_message_queue.get()
        peer_channel_id = state.peer_channel_id(remote_channel_id)
        peer_channel_flags = state.peer_channel_flags(remote_channel_id)
        if peer_channel_id is None:
            # TODO(1.4.0) Unreliable server, issue#841. Unexpected server peer channel activity.
            #     a) The server is buggy and has sent us a message intended for someone else.
            #     b) We are buggy and we have not correctly tracked peer channels.
            #     We should flag this to the user in some user-friendly way as a reliability
            #       indicator.
            logger.error("Wallet: '%s' received peer channel notification for unknown channel '%s'",
                state.wallet_proxy.name(), remote_channel_id)
            continue
        else:
            logger.debug("Processing message for remote_channel_id=%s", remote_channel_id)
        assert peer_channel_id is not None

        db_access_tokens = state.wallet_data.read_server_peer_channel_access_tokens(
            peer_channel_id, None,
            PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE)
        assert len(db_access_tokens) == 1

        messages = await list_peer_channel_messages_async(state, remote_channel_id,
            db_access_tokens[0].access_token, unread_only=True)
        if len(messages) == 0:
            # This may happen legitimately if we had several new message notifications backlogged
            # for the same channel, but processing a leading notification picks up the messages
            # for the trailing notification.
            logger.debug("Asked peer channel %d for new messages and received none",
                peer_channel_id)
            continue

        creation_message_rows = convert_peer_channel_messages_to_rows(messages,
            peer_channel_id)
        message_map = dict[int, GenericPeerChannelMessage]()
        for message in messages:
            message_map[message["sequence"]] = message

        # These cached values are passed on to whatever other system processes these types of
        # messages.
        message_entries = list[tuple[ServerPeerChannelMessageRow, GenericPeerChannelMessage]]()
        created_message_rows = await \
            state.wallet_data.create_server_peer_channel_messages_async(creation_message_rows)

        assert created_message_rows is not None
        for message_row in created_message_rows:
            message_entries.append((message_row, message_map[message_row.sequence]))

        # Now that we have all these messages stored locally we can delete the remote copies.
        for sequence in message_map:
            await delete_peer_channel_message_async(state, remote_channel_id,
                    db_access_tokens[0].access_token, sequence)

        assert peer_channel_flags is not None
        peer_channel_purpose = \
            peer_channel_flags & ServerPeerChannelFlag.MASK_PURPOSE
        if peer_channel_purpose == ServerPeerChannelFlag.TIP_FILTER_DELIVERY:
            await state.tip_filter_matches_queue.put(message_entries)
        elif peer_channel_purpose == ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK:
            state.mapi_callback_response_queue.put_nowait(message_entries)
            state.mapi_callback_response_event.set()
        else:
            # TODO(1.4.0) Unreliable server, issue#841. Peer channel message is not expected.
            logger.error("Wallet: '%s' received peer channel %d messages of unhandled purpose '%s'",
                state.wallet_proxy.name(), peer_channel_id, peer_channel_purpose)

    logger.debug("Exiting process_incoming_peer_channel_messages_async, server_url=%s",
        state.server_url)


def register_output_spends_async(state: ServerConnectionState) -> None:
    """
    Feed the initial state into the registration worker task.

    It is critical that this is executed first thing after the websocket connection is established.
    These registrations only persist as long as that websocket connection is alive.
    """
    # Feed the initial state into the worker task.
    # TODO(petty-cash) This should when we support multiple petty cash accounts we should specify
    #     which grouping of accounts are funded by a given petty cash account. It is possible we
    #     may end up mapping the petty cash account id to those accounts in the database.
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

    At this time this task can be cancelled/killed with no side effects when the server is
    disconnected. Our remote output spend registrations are associated with any current web
    socket connection and are dropped by the server when we disconnect.

    We raise server-related exceptions up and expect the connection management to deal with them.
    All exceptions raised by this in the context of a connect are processed by
    `_on_server_connection_worker_task_done`.

    Raises `BadServerError` if the server sends responses that are indicative of badness.
    Raises `ServerConnectionError` if the server cannot be connected to.
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

        spent_outputs: list[OutputSpend] = []
        try:
            async with state.session.post(api_url, headers=headers, data=byte_buffer) as response:
                if response.status != HTTPStatus.OK:
                    logger.error("Websocket spent output registration failed "
                        "status=%d, reason=%s", response.status, response.reason)
                    # TODO(1.4.0) Unreliable server, issue#841. Spent output registration failure.
                    #     We need to handle all possible variations of this error:
                    #     - It may be lack of funding.
                    #     - It may be short or long term server unavailability or errors.
                    #     - ??? add anything else that comes to mind.
                    return

                content_type, *content_type_extra = response.headers["Content-Type"].split(";")
                if content_type != "application/octet-stream":
                    logger.error("Spent output registration response content type got %s, "
                        "expected 'application/octet-stream'", content_type)
                    # TODO(1.4.0) Unreliable server, issue#841. Spent output registration content
                    #     type. Bad server not respecting the spent output request. We should stop
                    #     using it, and the user should have to manually flag it as valid again.
                    raise BadServerError("Invalid server response "
                        f"(got '{content_type}', expected 'application/octet-stream')")

                response_bytes = await response.content.read(output_spend_struct.size)
                while len(response_bytes) > 0:
                    if len(response_bytes) != output_spend_struct.size:
                        logger.error("Spent output registration record clipped, expected %d "
                            "bytes, got %d bytes", output_spend_struct.size, len(response_bytes))
                        # TODO(1.4.0) Unreliable server, issue#841. Spent output response invalid.
                        #     The server is unreliable? Should we mark the server as to be avoided?
                        #     Or flag it and stop using it if it happens more than once or twice?
                        raise BadServerError("Invalid spent output notification "
                            " received from server")

                    spent_output = OutputSpend.from_network(
                        *output_spend_struct.unpack(response_bytes))
                    spent_outputs.append(spent_output)

                    response_bytes = await response.content.read(output_spend_struct.size)
        except aiohttp.ClientError:
            # Requeue the outpoints to be registered for the next attempt.
            state.output_spend_registration_queue.put_nowait(outpoints)
            # NOTE(exception-details) We log this because we are not sure yet that we do not need
            #     this detail. At a later stage if we are confident that all the exceptions here
            #     are reasonable and expected, we can remove this.
            logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
            raise ServerConnectionError(f"Unable to establish server connection: {api_url}")

        logger.debug("Spent output registration returned %d results", len(spent_outputs))
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
    Manage the processing of tip filter registrations.

    This will ensure that there is ongoing processing of tip filter registration jobs. Each
    registration attempt will be recorded in the database, then the server will be asked to
    do the actual registration and finally the database will be updated to record the successful
    registration.

    At this time this task can be cancelled/killed and any state will be cleaned up elsewhere.
    Search for `PushDataHashRegistrationFlag.REGISTERING` to see where it is reconciled.

    We raise server-related exceptions up and expect the connection management to deal with them.
    All exceptions raised by this in the context of a connect are processed by
    `_on_server_connection_worker_task_done`.
    """
    assert state.usage_flags & NetworkServerFlag.USE_BLOCKCHAIN

    logger.debug("Entering manage_tip_filter_registrations_async, server_id=%d",
        state.server.server_id)

    # Before an indexing server will accept tip filter registrations from us we need to
    # have registered a notifications peer channel with it, through which it will deliver
    # any matches. This may block indefinitely until the user signs up with a message
    # box server, we offer them that opportunity when they go to use something that needs one
    # like subscribing to tip filter notifications.
    await prepare_server_tip_filter_peer_channel(state)

    # The main `maintain_server_connection_async` task will be waiting on this event and
    # will process it.
    state.connection_flags |= ServerConnectionFlag.TIP_FILTER_READY
    state.stage_change_event.set()
    state.stage_change_event.clear()

    # TODO(optimisation) We could make jobs happen in parallel if this becomes a bottleneck.
    #     At this time, this is not important as we will likely only be creating these
    #     registrations very seldomly (as the primary use case is the declining monitor the
    #     blockchain legacy payment situation).
    try:
        while state.connection_flags & ServerConnectionFlag.EXITING == 0:
            await _manage_tip_filter_registrations_async(state)
    finally:
        logger.debug("Exiting manage_tip_filter_registrations_async, server_id=%d",
            state.server.server_id)


async def _manage_tip_filter_registrations_async(state: ServerConnectionState) -> None:
    """
    This is a queue worker for registering tip filters with a blockchain services server.

    See `manage_tip_filter_registrations_async` for details.
    """
    assert state.usage_flags & NetworkServerFlag.USE_BLOCKCHAIN
    assert state.wallet_data is not None

    logger.debug("Waiting for tip filtering registrations, server_id=%d", state.server.server_id)
    while state.connection_flags & ServerConnectionFlag.EXITING == 0:
        job = await state.tip_filter_new_registration_queue.get()
        assert len(job.entries) > 0

        logger.debug("Processing %d tip filter registrations", len(job.entries))
        job.output.start_event.set()

        date_created = int(time.time())
        db_insert_rows: list[PushDataHashRegistrationRow] = []
        server_rows: list[tuple[bytes, int]] = []
        no_date_registered = None
        for pushdata_hash, duration_seconds, keyinstance_id, script_type in job.entries:
            logger.debug("Preparing pre-registration entry for pushdata hash %s",
                pushdata_hash.hex())
            db_insert_rows.append(PushDataHashRegistrationRow(state.server.server_id,
                keyinstance_id, script_type, pushdata_hash,
                PushDataHashRegistrationFlag.REGISTERING, duration_seconds, no_date_registered,
                date_created, date_created))
            server_rows.append((pushdata_hash, duration_seconds))
        await state.wallet_data.create_tip_filter_pushdata_registrations_async(db_insert_rows,
            upsert=True)

        try:
            job.output.date_registered = await create_tip_filter_registrations_async(state,
                server_rows)
        except (GeneralAPIError, ServerConnectionError) as exception:
            job.output.failure_reason = str(exception)
            date_updated = int(get_posix_timestamp())
            await state.wallet_data.update_registered_tip_filter_pushdatas_flags_async([
                (PushDataHashRegistrationFlag.REGISTRATION_FAILED, date_updated,
                    state.server.server_id, keyinstance_id)
                for (pushdata_hash_, duration_seconds_, keyinstance_id, script_type) in job.entries
            ])
        else:
            # At this point we have all the information we need to record the registrations
            # as being active on this server and complete the job. This removes the
            # `REGISTERING` flag.
            date_updated = int(get_posix_timestamp())
            await state.wallet_data.update_registered_tip_filter_pushdatas_async([
                (job.output.date_registered, date_updated,
                    ~PushDataHashRegistrationFlag.REGISTERING, PushDataHashRegistrationFlag.NONE,
                    state.server.server_id, keyinstance_id)
                for (pushdata_hash_, duration_seconds_, keyinstance_id, script_type) in job.entries
            ])

            logger.debug("Processed %d tip filter registrations", len(job.entries))
        job.output.completed_event.set()


async def create_tip_filter_registration_async(state: ServerConnectionState,
        pushdata_hash: bytes, date_expires: int, keyinstance_id: int,
        script_type: ScriptType) -> TipFilterRegistrationJob:
    # The reference server needs to be updated to take a UTC expiry date.
    expiry_seconds = date_expires - int(time.time())
    job = TipFilterRegistrationJob([
        TipFilterRegistrationJobEntry(pushdata_hash, expiry_seconds, keyinstance_id,
            script_type) ],
        TipFilterRegistrationJobOutput())
    state.tip_filter_new_registration_queue.put_nowait(job)
    return job


async def blockchain_services_preconnection_async(state: ServerConnectionState) -> None:
    assert state.wallet_data is not None

    # We can store settings on the server some of which are required to use certain functionality,
    # like the peer channel callback URL for the tip filter.
    assert state.indexer_settings is None
    state.indexer_settings = await get_server_indexer_settings(state)

    # By passing the timestamp, we only get the non-expired registrations. The indexing
    # server should have purged these itself, giving us current registrations on both sides.
    current_timestamp = int(time.time())
    existing_tip_filter_rows = state.wallet_data.read_tip_filter_pushdata_registrations(
        state.server.server_id, current_timestamp, flags=PushDataHashRegistrationFlag.NONE,
        mask=PushDataHashRegistrationFlag.DELETED)
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

            # TODO(1.4.0) Unreliable server, issue#841. Server lacks our expected tip filter.
            #     - Using the same wallet in different installations?
            #     - Expiry date edge case? Clock error?
            #     - Purged account due to abuse or other reason?
            raise InvalidStateError(
                f"Handle missing server tip filter registration {tip_filter_row}")

        server_tip_filter = server_tip_filter_by_pushdata_hash[pushdata_hash]
        # 2. Does the server tip filter have the same registration duration?
        if tip_filter_row.duration_seconds != server_tip_filter.duration_seconds:
            # TODO(1.4.0) Unreliable server, issue#841. Server tip filter expiration differs.
            #     - Maybe the user changed the duration on the registration?
            #       - If the user did this, we would want to update both at the same time
            #         and coordinate it. Do not allow it if they are offline.
            raise InvalidStateError("Handle filter duration mismatch")

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
            # TODO(1.4.0) Unreliable server, issue#841. Server tip filter registration differs.
            #     - Using the same wallet in different installations?
            raise InvalidStateError("Handle filter date created mismatch")
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
            # TODO(1.4.0) Unreliable server, issue#841. Server has unknown registrations.
            #     - Using the same wallet in different installations?
            raise InvalidStateError("Handle orphaned server registration mismatch")


async def blockchain_services_server_connected_async(state: ServerConnectionState) \
        -> list[Future[None]]:
    """
    Start up blockchain services processing logic for a server we have just connected to.

    Raises nothing.
    """
    register_output_spends_async(state)

    # All websocket futures are cancelled on server disconnection. This will interrupt the
    # underlying task. These functions have been written so that they are either stateless or
    # have other recovery logic elsewhere.

    futures: list[Future[None]] = []

    output_spends_future = app_state.async_.spawn(manage_output_spends_async(state))
    futures.append(output_spends_future)
    state.websocket_futures.append(output_spends_future)

    tip_filter_future = app_state.async_.spawn(manage_tip_filter_registrations_async(state))
    futures.append(tip_filter_future)
    state.websocket_futures.append(tip_filter_future)

    return futures


async def prepare_server_tip_filter_peer_channel(indexing_server_state: ServerConnectionState) \
        -> None:
    """
    Create or verify that we have a peer channel on our peer channel hosting service to use
    specifically for tip filtering results. We also notify the blockchain services server
    of any new or updated peer channel.

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
    assert indexing_server_state.usage_flags & NetworkServerFlag.USE_BLOCKCHAIN

    # We block until this task can locate a message box service.
    # TODO(peer-channels) If a wallet can have access to multiple message box servers then we need
    #     to make sure that the one we are looking for here is the one that will be used against
    #     this blockchains server.
    peer_channel_server_state = \
        await indexing_server_state.wallet_proxy.wait_for_connection_state_for_usage(
            NetworkServerFlag.USE_MESSAGE_BOX)
    while peer_channel_server_state is not indexing_server_state:
        # The peer channel server is a different server. We do not know that it is ready. Either
        # we should wait for it to become ready, or we should retry this call when it is.
        # TODO(1.4.0) Tip filtering, issue#904. Handle this `TimeoutError` in a better way.
        #     If there is no workable peer channel server, then the user should be notified and
        #     they should have to rectify it.
        if peer_channel_server_state.connection_flags & ServerConnectionFlag.WEB_SOCKET_READY \
                == 0:
            await asyncio.wait_for(peer_channel_server_state.stage_change_event.wait(), 10)
        if peer_channel_server_state.connection_flags & ServerConnectionFlag.WEB_SOCKET_READY \
                == 0:
            raise InvalidStateError("Tip filter unable to find peer channel server")
    assert peer_channel_server_state.wallet_data

    indexing_server_id = indexing_server_state.server.server_id
    peer_channel_id = indexing_server_state.server.get_tip_filter_peer_channel_id(
        indexing_server_state.petty_cash_account_id)

    peer_channel_row: ServerPeerChannelRow | None = None
    if peer_channel_id is not None:
        # TODO(1.4.0) Tip filters, issue#904. It looks like we created a peer channel locally, but
        #     either never got around to creating it remotely or got interrupted before we could
        #     store the details retrieved from the remote server (remote id/url/...).
        assert peer_channel_server_state.cached_peer_channel_rows is not None

        for peer_channel_row_n in peer_channel_server_state.cached_peer_channel_rows.values():
            if peer_channel_row_n.peer_channel_id == peer_channel_id:
                peer_channel_row = peer_channel_row_n
                break
        else:
            # TODO(1.4.0) Tip filters, issue#904. It looks like we created a peer channel locally,
            #     either never got around to creating it remotely or got interrupted before we could
            #     store the details retrieved from the remote server (remote id/url/...). Could
            #     also be user-caused problem with duplicate wallet usage or other reason.
            raise InvalidStateError(f"Peer channel {peer_channel_id} lacks matching row")
        # The indexing server tip filter peer channel is not flagged correctly. There is
        # nothing we can do in this case as it is completely unexpected (database corruption?).
        if peer_channel_row.peer_channel_flags & ServerPeerChannelFlag.TIP_FILTER_DELIVERY == 0:
            raise InvalidStateError(f"Peer channel {peer_channel_id} lacks tip filter flag")

    tip_filter_callback_url = indexing_server_state.indexer_settings.get("tipFilterCallbackUrl")
    if tip_filter_callback_url is not None:
        if peer_channel_id is None:
            # TODO(1.4.0) Unreliable server, issue#841. The server is configured to send us tip
            #     filter notifications but we do not have a peer channel set on the server in the
            #     database to receive them. Likely user using wallet on different machines.
            raise InvalidStateError("Unreliability. Remote callback with no local channel")

        assert peer_channel_row is not None
        if peer_channel_row.remote_url != tip_filter_callback_url:
            # TODO(1.4.0) Unreliable server, issue#841. Differing tip filter notification callback
            #     URLs. Likely user using wallet on different machines.
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

        # Look for the access token that would have been created with the channel.
        db_access_tokens = peer_channel_server_state.wallet_data \
            .read_server_peer_channel_access_tokens(peer_channel_row.peer_channel_id,
                PeerChannelAccessTokenFlag.FOR_TIP_FILTER_SERVER,
                PeerChannelAccessTokenFlag.FOR_TIP_FILTER_SERVER)
        assert len(db_access_tokens) == 1
        tip_filter_access_token = db_access_tokens[0]
    else:
        assert peer_channel_server_state.cached_peer_channel_rows is not None
        peer_channel_row, tip_filter_access_token, read_only_access_token = \
            await create_peer_channel_locally_and_remotely_async(
                peer_channel_server_state, ServerPeerChannelFlag.TIP_FILTER_DELIVERY,
                PeerChannelAccessTokenFlag.FOR_TIP_FILTER_SERVER,
                indexing_server_id=indexing_server_id)
        assert peer_channel_row.peer_channel_id is not None
        indexing_server_state.server.set_tip_filter_peer_channel_id(
            indexing_server_state.petty_cash_account_id, peer_channel_row.peer_channel_id)

    # Indexing server: Notify that we now have a tip filter callback url.
    # The update is a subset of the overall indexer server settings that we want to update.
    settings_delta_object = cast(IndexerServerSettings, {})
    settings_delta_object["tipFilterCallbackUrl"] = peer_channel_row.remote_url
    settings_delta_object["tipFilterCallbackToken"] = \
        f"Bearer {tip_filter_access_token.access_token}"
    settings_object = await update_server_indexer_settings(indexing_server_state,
        settings_delta_object)

    # NOTE(typing) Type is incompatible with same type, who knows? Error message as follows:
    # `Argument 1 to "update" of "TypedDict" has incompatible type "IndexerServerSettings";
    # expected "TypedDict({'tipFilterCallbackUrl'?: str | None})"  [typeddict-item]`
    indexing_server_state.indexer_settings.update(settings_delta_object) # type: ignore
    if settings_object != indexing_server_state.indexer_settings:
        # TODO(1.4.0) Unreliable server, issue#841. Differing server indexer settings after setup.
        #     Server unreliability case OR user unreliability with clashing wallets open using
        #     servers with the same account.
        raise InvalidStateError("Unreliability. Local/remote indexer settings mismatch "+
            f"{settings_object} != {indexing_server_state.indexer_settings}")


async def create_peer_channel_locally_and_remotely_async(
        peer_channel_server_state: ServerConnectionState,
        write_only_peer_channel_flag: ServerPeerChannelFlag,
        write_only_access_token_flag: PeerChannelAccessTokenFlag,
        read_only_peer_channel_flag: ServerPeerChannelFlag | None=None,
        read_only_access_token_flag: PeerChannelAccessTokenFlag | None=None,
        indexing_server_id: int | None=None) \
            -> tuple[ServerPeerChannelRow, ServerPeerChannelAccessTokenRow,
                     ServerPeerChannelAccessTokenRow | None]:
    """
    Via both `create_peer_channel_async` and `create_peer_channel_api_token_async`:
        Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
        Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert peer_channel_server_state.wallet_proxy is not None
    assert peer_channel_server_state.wallet_data is not None

    wallet_data = peer_channel_server_state.wallet_data
    peer_channel_server_id = peer_channel_server_state.server.server_id

    date_created = get_posix_timestamp()
    peer_channel_row = ServerPeerChannelRow(None, peer_channel_server_id, None, None,
        ServerPeerChannelFlag.ALLOCATING | write_only_peer_channel_flag,
        date_created, date_created)
    peer_channel_id = await wallet_data.create_server_peer_channel_async(peer_channel_row,
        indexing_server_id)
    peer_channel_row = peer_channel_row._replace(peer_channel_id=peer_channel_id)

    # Peer channel server: create the remotely hosted peer channel.
    peer_channel_json = await create_peer_channel_async(peer_channel_server_state)
    remote_peer_channel_id = peer_channel_json["id"]
    peer_channel_row = peer_channel_row._replace(remote_channel_id=remote_peer_channel_id)
    peer_channel_url = peer_channel_json["href"]
    logger.debug("Created peer channel %s for %r", remote_peer_channel_id,
        peer_channel_row.peer_channel_flags)
    assert peer_channel_server_state.cached_peer_channel_rows is not None
    peer_channel_server_state.cached_peer_channel_rows[remote_peer_channel_id] = \
        peer_channel_row

    # Peer channel server: create a custom write-only access token for the channel, for
    #    the use of the indexing server.
    writeonly_token_json = await create_peer_channel_api_token_async(peer_channel_server_state,
        remote_peer_channel_id, can_read=False, can_write=True, description="private")
    assert peer_channel_row.peer_channel_id is not None
    assert len(peer_channel_json["access_tokens"]) == 1
    writeonly_access_token = ServerPeerChannelAccessTokenRow(peer_channel_row.peer_channel_id,
        write_only_access_token_flag,
        get_permissions_from_peer_channel_token(writeonly_token_json),
        writeonly_token_json["token"])

    read_only_access_token = None
    if read_only_peer_channel_flag is not None and read_only_access_token_flag is not None:
        read_only_token_json = await create_peer_channel_api_token_async(peer_channel_server_state,
            remote_peer_channel_id, can_read=True, can_write=False, description="readonly token")
        assert peer_channel_row.peer_channel_id is not None
        assert len(peer_channel_json["access_tokens"]) == 1
        read_only_access_token = ServerPeerChannelAccessTokenRow(peer_channel_row.peer_channel_id,
            read_only_access_token_flag,
            get_permissions_from_peer_channel_token(read_only_token_json),
            read_only_token_json["token"])

    default_channel_token = peer_channel_json["access_tokens"][0]
    default_access_token = ServerPeerChannelAccessTokenRow(peer_channel_row.peer_channel_id,
        PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE,
        get_permissions_from_peer_channel_token(default_channel_token),
        default_channel_token["token"])

    # Local database: Update for the server-side peer channel. Drop the `ALLOCATING` flag and
    #     add the access token.
    addable_access_tokens = [writeonly_access_token, default_access_token]
    if read_only_access_token is not None:
        addable_access_tokens.append(read_only_access_token)
    peer_channel_row = await wallet_data.update_server_peer_channel_async(remote_peer_channel_id,
        peer_channel_url, write_only_peer_channel_flag, peer_channel_id,
        addable_access_tokens=addable_access_tokens)

    return peer_channel_row, writeonly_access_token, read_only_access_token


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
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


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
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


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
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")

    # For now we unpack the object and return the elements as a tuple.
    date_created = datetime.fromisoformat(json_object["dateCreated"]).replace(tzinfo=timezone.utc)
    return int(date_created.timestamp())


async def delete_tip_filter_registration_async(state: ServerConnectionState,
        registration_datas: list[tuple[bytes, int]]) -> None:
    """
    Use the reference server indexer API for listing tip filter registration.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert state.wallet_data is not None
    assert state.credential_id is not None

    server_url = f"{state.server.url}api/v1/transaction/filter:delete"
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {
        "Content-Type":     "application/octet-stream",
        "Authorization":    f"Bearer {master_token}"
    }
    # This is a binary array of the pushdata hashes.
    byte_buffer = bytearray(len(registration_datas) * 32)
    for data_index, registration_data in enumerate(registration_datas):
        tip_filter_unregistration_struct.pack_into(byte_buffer, data_index * 32,
            registration_data[0])
    try:
        async with state.session.post(server_url, data=byte_buffer, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")
            # The standard response expected from the server is 200 with no body.
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")

    date_updated = int(time.time())
    await state.wallet_data.update_registered_tip_filter_pushdatas_flags_async([
        (PushDataHashRegistrationFlag.DELETED, date_updated,
            state.server.server_id, keyinstance_id)
        for (pushdata_hash, keyinstance_id) in registration_datas
    ])



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
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")

    list_entries = list[TipFilterListEntry]()
    for entry_index in range(len(body_bytes) // tip_filter_list_struct.size):
        entry = TipFilterListEntry(*tip_filter_list_struct.unpack_from(body_bytes,
            entry_index * tip_filter_list_struct.size))
        list_entries.append(entry)
    return list_entries
