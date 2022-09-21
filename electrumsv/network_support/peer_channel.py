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
from datetime import datetime
from functools import partial
from http import HTTPStatus
import json
from typing import Any, cast

import aiohttp
from aiohttp import WSServerHandshakeError

from ..app_state import app_state
from ..constants import ServerConnectionFlag, PeerChannelAccessTokenFlag, PeerChannelMessageFlag, \
    ServerPeerChannelFlag
from ..exceptions import ServerConnectionError, BadServerError
from ..logs import logs
from ..util import get_posix_timestamp
from ..wallet_database.types import PeerChannelMessageRow

from .constants import ServerProblemKind
from .disconnection import _on_server_connection_worker_task_done
from .exceptions import GeneralAPIError
from .types import ServerStateProtocol, GenericPeerChannelMessage, MessageViewModelGetBinary, \
    PeerChannelAPITokenViewModelGet, PeerChannelViewModelGet, RetentionViewModel, \
    TokenPermissions, PeerChannelServerState, ServerConnectionProblems


logger = logs.get_logger("peer-channels")


def get_permissions_from_peer_channel_token(json_token: PeerChannelAPITokenViewModelGet) \
        -> TokenPermissions:
    permissions: TokenPermissions = TokenPermissions.NONE
    if json_token['can_read']:
        permissions |= TokenPermissions.READ_ACCESS
    if json_token['can_write']:
        permissions |= TokenPermissions.WRITE_ACCESS
    return permissions


async def create_peer_channel_async(state: ServerStateProtocol,
        public_read: bool=False, public_write: bool=True, sequenced: bool=True,
        retention: RetentionViewModel | None=None) -> PeerChannelViewModelGet:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    url = f"{state.server_url}api/v1/channel/manage"
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

            return cast(PeerChannelViewModelGet, await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {url}")


async def mark_peer_channel_read_or_unread_async(state: ServerStateProtocol,
        remote_channel_id: str, access_token: str, sequence: int, older: bool, is_read: bool) \
            -> None:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    url = f"{state.server_url}api/v1/channel/{remote_channel_id}/{sequence}"
    headers = {
        "Authorization": f"Bearer {access_token}"
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
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {url}")


async def get_peer_channel_async(state: ServerStateProtocol, remote_channel_id: str) \
        -> PeerChannelViewModelGet:
    """
    Use the reference peer channel implementation API for getting a specific peer channel.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server_url}api/v1/channel/manage/{remote_channel_id}"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    try:
        async with state.session.get(server_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")
            return cast(PeerChannelViewModelGet, await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def list_peer_channels_async(state: ServerStateProtocol) -> list[PeerChannelViewModelGet]:
    """
    Use the reference peer channel implementation API for listing peer channels.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server_url}api/v1/channel/manage/list"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    try:
        async with state.session.get(server_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            return cast(list[PeerChannelViewModelGet], await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def delete_peer_channel_async(state: ServerStateProtocol, remote_channel_id: str) \
        -> None:
    """
    Use the reference peer channel implementation API for deleting peer channels.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server_url}api/v1/channel/manage/{remote_channel_id}"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    try:
        async with state.session.delete(server_url, headers=headers) as response:
            if response.status != HTTPStatus.NO_CONTENT:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def create_peer_channel_message_json_async(state: ServerStateProtocol,
        remote_channel_id: str, access_token: str, message: dict[str, Any]) \
            -> GenericPeerChannelMessage | None:
    """returns sequence number"""
    server_url = f"{state.server_url}api/v1/channel/{remote_channel_id}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}"
    }

    json_no_whitespace = json.dumps(message, separators=(",", ":"))
    try:
        async with state.session.post(server_url, headers=headers, data=json_no_whitespace) \
                as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")
            return cast(GenericPeerChannelMessage, await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def create_peer_channel_message_binary_async(state: ServerStateProtocol,
        remote_channel_id: str, access_token: str, message: bytes) -> MessageViewModelGetBinary:
    """returns sequence number"""
    server_url = f"{state.server_url}api/v1/channel/{remote_channel_id}"
    headers = {
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {access_token}"
    }

    try:
        async with state.session.post(server_url, headers=headers, data=message) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")
            return cast(MessageViewModelGetBinary, await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def list_peer_channel_messages_async(state: ServerStateProtocol, remote_channel_id: str,
        access_token: str, unread_only: bool=False) -> list[GenericPeerChannelMessage]:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.

    WARNING: This does not set the messages to read when it reads them.. that needs to be done
        manually after this call with another to `mark_peer_channel_read_or_unread`.
    """
    url = f"{state.server_url}api/v1/channel/{remote_channel_id}"
    headers = {
        "Authorization": f"Bearer {access_token}"
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
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {url}")


async def delete_peer_channel_message_async(state: ServerStateProtocol, remote_channel_id: str,
        access_token: str, sequence: int) -> None:
    """
    Use the reference peer channel implementation API for deleting a message in a peer channel.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server_url}api/v1/channel/{remote_channel_id}/{sequence}"
    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        async with state.session.delete(server_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def create_peer_channel_api_token_async(state: ServerStateProtocol, channel_id: str,
        can_read: bool=True, can_write: bool=True, description: str="standard token") \
            -> PeerChannelAPITokenViewModelGet:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    url = f"{state.server_url}api/v1/channel/manage/{channel_id}/api-token"
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

            return cast(PeerChannelAPITokenViewModelGet, await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {url}")


async def list_peer_channel_api_tokens_async(state: ServerStateProtocol, remote_channel_id: str) \
        -> list[PeerChannelAPITokenViewModelGet]:
    """
    Use the reference peer channel implementation API for listing peer channel access tokens.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server_url}api/v1/channel/manage/{remote_channel_id}/api-token"
    assert state.credential_id is not None
    master_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    headers = {"Authorization": f"Bearer {master_token}"}
    try:
        async with state.session.get(server_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")

            return cast(list[PeerChannelAPITokenViewModelGet], await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def get_peer_channel_max_sequence_number_async(state: ServerStateProtocol,
        remote_channel_id: str, access_token: str) -> int | None:
    server_url = f"{state.server_url}api/v1/channel/{remote_channel_id}"
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        async with state.session.head(server_url, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                raise GeneralAPIError(
                    f"Bad response status code: {response.status}, reason: {response.reason}")
            return int(response.headers['ETag'])
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def process_externally_owned_peer_channel_messages_async(state: PeerChannelServerState) \
        -> None:
    """
    We raise server-related exceptions up and expect the connection management to deal with them.
    All exceptions raised by this in the context of a connect are processed by
    `_on_server_connection_worker_task_done`.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """

    # Typing related assertions.
    assert state.wallet_data is not None
    assert state.wallet_proxy is not None
    logger.debug("Entering process_externally_owned_peer_channel_messages_async, server_url=%s "
                 "(Wallet='%s')", state.server_url, state.wallet_proxy.name())

    while state.connection_flags & ServerConnectionFlag.EXITING == 0:
        remote_channel_id = await state.peer_channel_message_queue.get()
        external_channel_row = state.external_channel_row
        logger.debug("Processing message for remote_channel_id=%s", remote_channel_id)

        assert external_channel_row.peer_channel_id is not None
        db_access_tokens = state.wallet_data.read_external_peer_channel_access_tokens(
            external_channel_row.peer_channel_id, None, PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE)
        assert len(db_access_tokens) == 1

        messages = await list_peer_channel_messages_async(state, remote_channel_id,
            db_access_tokens[0].access_token, unread_only=True)
        if len(messages) == 0:
            # This may happen legitimately if we had several new message notifications backlogged
            # for the same channel, but processing a leading notification picks up the messages
            # for the trailing notification.
            logger.debug("Asked peer channel %d for new messages and received none",
                external_channel_row.peer_channel_id)
            continue

        date_created = get_posix_timestamp()
        creation_message_rows = list[PeerChannelMessageRow]()
        message_map = dict[int, GenericPeerChannelMessage]()
        for message in messages:
            message_json_bytes = json.dumps(message).encode()
            received_iso8601_text = message["received"].replace("Z", "+00:00")
            received_datetime = datetime.fromisoformat(received_iso8601_text)
            creation_message_rows.append(PeerChannelMessageRow(None,
                external_channel_row.peer_channel_id, message_json_bytes,
                PeerChannelMessageFlag.UNPROCESSED, message["sequence"],
                int(received_datetime.timestamp()),
                date_created, date_created))
            message_map[message["sequence"]] = message

        # These cached values are passed on to whatever other system processes these types of
        # messages.
        message_entries = list[tuple[PeerChannelMessageRow, GenericPeerChannelMessage]]()
        created_message_rows = await \
            state.wallet_data.create_external_peer_channel_messages_async(creation_message_rows)
        for message_row in created_message_rows:
            message_entries.append((message_row, message_map[message_row.sequence]))

        # Now that we have all these messages stored locally we can delete the remote copies.
        for sequence in message_map:
            await delete_peer_channel_message_async(state, remote_channel_id,
                    db_access_tokens[0].access_token, sequence)

        peer_channel_purpose = \
            external_channel_row.peer_channel_flags & ServerPeerChannelFlag.MASK_PURPOSE
        if peer_channel_purpose == ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK:
            state.mapi_callback_response_queue.put_nowait(message_entries)
            state.mapi_callback_response_event.set()
        else:
            # TODO(1.4.0) Unreliable server, issue#841. Peer channel message is not expected.
            logger.error("Wallet: '%s' received peer channel %d messages of unhandled purpose '%s'",
                state.wallet_proxy.name(), external_channel_row.peer_channel_id,
                peer_channel_purpose)

    logger.debug("Exiting process_externally_owned_peer_channel_messages_async, server_url=%s",
        state.server_url)


async def maintain_external_peer_channel_connection_async(state: PeerChannelServerState) \
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
            future = app_state.async_.spawn(_manage_external_peer_channel_connection_async(state))
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
        logger.error("maintain_external_peer_channel_connection_async encountered connection issue")
        state.connection_flags = ServerConnectionFlag.EXITED

    return {}

async def _manage_external_peer_channel_connection_async(state: PeerChannelServerState) -> None:
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
    assert state.credential_id is not None

    state.connection_flags |= ServerConnectionFlag.VERIFYING
    state.connection_flags |= ServerConnectionFlag.ESTABLISHING_WEB_SOCKET

    access_token = app_state.credentials.get_indefinite_credential(state.credential_id)
    assert state.external_channel_row.remote_url is not None
    websocket_url_template = state.external_channel_row.remote_url.rstrip("/") + \
        "/api/v1/channel/{remote_channel_id}/notify?token={access_token}"
    websocket_url = websocket_url_template.format(remote_channel_id=state.remote_channel_id,
        access_token=access_token)
    headers = {"Accept": "application/octet-stream"}
    try:
        async with state.session.ws_connect(websocket_url, headers=headers, timeout=5.0) \
                as server_websocket:
            logger.info('Connected to server websocket, url=%s', websocket_url_template)

            state.connection_flags |= ServerConnectionFlag.WEB_SOCKET_READY

            future = app_state.async_.spawn(
                process_externally_owned_peer_channel_messages_async(state))
            state.websocket_futures.append(future)
            future.add_done_callback(partial(_on_server_connection_worker_task_done, state))

            try:
                websocket_message: aiohttp.WSMessage
                async for websocket_message in server_websocket:
                    # ---------- Peer Channel Specific Websocket Handling ---------- #
                    if websocket_message.type == aiohttp.WSMsgType.TEXT:
                        assert state.remote_channel_id is not None
                        # Expected message contents = 'New message arrived' (or something similar)
                        logger.debug(
                            "Queued incoming peer channel message (non-general websocket) "
                            "%s", websocket_message)
                        state.peer_channel_message_queue.put_nowait(state.remote_channel_id)
                    elif websocket_message.type == aiohttp.WSMsgType.BINARY:
                        logger.debug("Ignoring websocket binary: %s", websocket_message.data)
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

