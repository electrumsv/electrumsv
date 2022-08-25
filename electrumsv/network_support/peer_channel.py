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
from datetime import datetime
from http import HTTPStatus
import json
from typing import Any, cast, TYPE_CHECKING

import aiohttp

from ..app_state import app_state
from ..constants import NetworkServerFlag, PeerChannelAccessTokenFlag, PeerChannelMessageFlag, \
    ServerConnectionFlag, ServerPeerChannelFlag
from ..dpp_messages import PeerChannelDict
from ..exceptions import ServerConnectionError
from ..logs import logs
from ..util import get_posix_timestamp
from ..wallet_database.types import ServerPeerChannelRow, ServerPeerChannelAccessTokenRow, \
    ServerPeerChannelMessageRow

from .exceptions import GeneralAPIError, InvalidStateError
from .types import GenericPeerChannelMessage, MessageViewModelGetBinary, \
    PeerChannelAPITokenViewModelGet, PeerChannelViewModelGet,  RetentionViewModel, \
    ServerConnectionState, TokenPermissions


if TYPE_CHECKING:
    from concurrent.futures import Future


logger = logs.get_logger("peer-channels")


def get_permissions_from_peer_channel_token(json_token: PeerChannelAPITokenViewModelGet) \
        -> TokenPermissions:
    permissions: TokenPermissions = TokenPermissions.NONE
    if json_token['can_read']:
        permissions |= TokenPermissions.READ_ACCESS
    if json_token['can_write']:
        permissions |= TokenPermissions.WRITE_ACCESS
    return permissions


async def peer_channel_preconnection_async(state: ServerConnectionState) -> None:
    """
    Do pre-connection checks and calls on the peer channel server, to prepare to connect and
    also to validate that the server looks compatible.
    """
    assert state.wallet_data is not None

    existing_channel_rows = state.wallet_data.read_server_peer_channels(state.server.server_id)
    peer_channel_jsons = await list_peer_channels_async(state)

    peer_channel_ids = { channel_json["id"] for channel_json in peer_channel_jsons }
    peer_channel_rows_by_id = { cast(str, row.remote_channel_id): row
        for row in existing_channel_rows
        if row.peer_channel_flags & ServerPeerChannelFlag.EXTERNALLY_OWNED == 0}
    # TODO(1.4.0) Unreliable server, issue#841. Our peer channels differ from the server's.
    # - Could be caused by a shared API key with another wallet.
    # - This is likely to be caused by bad user choice and the wallet should only be
    #   responsible for fixing anything related to it's mistakes.
    # - Expired peer channels may need to be excluded.
    # - We should mark peer channels as `CLOSING` and we can pick those up here and close
    #   any we couldn't close when they were marked as such because of connection issues.
    if set(peer_channel_ids) != set(peer_channel_rows_by_id):
        raise InvalidStateError("Mismatched peer channels, local and server")

    state.cached_peer_channel_rows = peer_channel_rows_by_id

    for peer_channel_row in existing_channel_rows:
        assert peer_channel_row.remote_channel_id is not None
        await state.peer_channel_message_queue.put(peer_channel_row.remote_channel_id)


async def peer_channel_server_connected_async(state: ServerConnectionState) -> list[Future[None]]:
    """
    Start up peer channel processing logic for a server we have just connected to.

    Raises nothing.
    """
    # All websocket futures are cancelled on server disconnection. This will interrupt the
    # underlying task. These functions have been written so that they are either stateless or
    # have other recovery logic elsewhere.

    future = app_state.async_.spawn(process_incoming_peer_channel_messages_async(state))
    state.websocket_futures.append(future)

    return [ future ]


async def add_external_peer_channel(
        peer_channel_server_state: ServerConnectionState,
        peer_channel_info: PeerChannelDict,
        indexing_server_id: int | None=None) \
            -> tuple[ServerPeerChannelRow, ServerPeerChannelAccessTokenRow]:
    """
    This is similar in function to the `create_peer_channel_locally_and_remotely_async` except
    that we are not the creator of the remote peer channel (the payee already created it)
    """
    assert peer_channel_server_state.wallet_proxy is not None
    assert peer_channel_server_state.wallet_data is not None

    wallet_data = peer_channel_server_state.wallet_data
    peer_channel_server_id = peer_channel_server_state.server.server_id

    date_created = get_posix_timestamp()
    remote_peer_channel_id = peer_channel_info['channel_id']
    remote_url = peer_channel_info['host']
    peer_channel_flags = ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK | \
                         ServerPeerChannelFlag.EXTERNALLY_OWNED
    peer_channel_row = ServerPeerChannelRow(None, peer_channel_server_id, remote_peer_channel_id,
        remote_url, peer_channel_flags, date_created, date_created)
    peer_channel_id = await wallet_data.create_server_peer_channel_async(peer_channel_row,
        indexing_server_id)
    peer_channel_row = peer_channel_row._replace(peer_channel_id=peer_channel_id)

    logger.debug("Added peer channel %s with flags: %s", remote_peer_channel_id,
        peer_channel_row.peer_channel_flags)
    assert peer_channel_server_state.cached_peer_channel_rows is not None
    peer_channel_server_state.cached_peer_channel_rows[remote_peer_channel_id] = \
        peer_channel_row

    # Record peer channel token in the database if it doesn't exist there already
    assert peer_channel_row.peer_channel_id is not None
    readonly_access_token_flag = PeerChannelAccessTokenFlag.FOR_EXTERNAL_USAGE
    readonly_access_token = ServerPeerChannelAccessTokenRow(peer_channel_row.peer_channel_id,
        readonly_access_token_flag, TokenPermissions.READ_ACCESS, peer_channel_info['token'])

    # Local database: Update for the server-side peer channel. Drop the `ALLOCATING` flag and
    #     add the access token.
    readonly_peer_channel_flag = ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK
    peer_channel_row = await wallet_data.update_server_peer_channel_async(remote_peer_channel_id,
        remote_url, readonly_peer_channel_flag, peer_channel_id,
        addable_access_tokens=[readonly_access_token])

    return peer_channel_row, readonly_access_token



async def create_peer_channel_locally_and_remotely_async(
        peer_channel_server_state: ServerConnectionState,
        writeonly_peer_channel_flag: ServerPeerChannelFlag,
        writeonly_access_token_flag: PeerChannelAccessTokenFlag,
        readonly_peer_channel_flag: ServerPeerChannelFlag | None=None,
        readonly_access_token_flag: PeerChannelAccessTokenFlag | None=None,
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
        ServerPeerChannelFlag.ALLOCATING | writeonly_peer_channel_flag,
        date_created, date_created)
    peer_channel_id = await wallet_data.create_server_peer_channel_async(peer_channel_row,
        indexing_server_id)
    peer_channel_row = peer_channel_row._replace(peer_channel_id=peer_channel_id)

    # Peer channel server: create the remotely hosted peer channel.
    peer_channel_json = await create_peer_channel_async(peer_channel_server_state)
    remote_peer_channel_id = peer_channel_json["id"]
    peer_channel_url = peer_channel_json["href"]
    logger.debug("Created peer channel %s for %s", remote_peer_channel_id,
        writeonly_peer_channel_flag)
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
        writeonly_access_token_flag,
        get_permissions_from_peer_channel_token(writeonly_token_json),
        writeonly_token_json["token"])

    read_only_access_token = None
    if readonly_peer_channel_flag is not None and readonly_access_token_flag is not None:
        read_only_token_json = await create_peer_channel_api_token_async(peer_channel_server_state,
            remote_peer_channel_id, can_read=True, can_write=False, description="readonly token")
        assert peer_channel_row.peer_channel_id is not None
        assert len(peer_channel_json["access_tokens"]) == 1
        read_only_access_token = ServerPeerChannelAccessTokenRow(peer_channel_row.peer_channel_id,
            readonly_access_token_flag,
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
        peer_channel_url, writeonly_peer_channel_flag, peer_channel_id,
        addable_access_tokens=addable_access_tokens)

    return peer_channel_row, writeonly_access_token, read_only_access_token


async def process_incoming_peer_channel_messages_async(state: ServerConnectionState) -> None:
    """
    We raise server-related exceptions up and expect the connection management to deal with them.
    All exceptions raised by this in the context of a connect are processed by
    `_on_server_connection_worker_task_done`.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert state.usage_flags & NetworkServerFlag.USE_MESSAGE_BOX

    # Typing related assertions.
    assert state.wallet_data is not None
    assert state.cached_peer_channel_rows is not None

    assert state.wallet_proxy is not None
    logger.debug("Entering process_incoming_peer_channel_messages_async, server_id=%d "
                 "(Wallet='%s')", state.server.server_id, state.wallet_proxy.name())

    while state.connection_flags & ServerConnectionFlag.EXITING == 0:
        remote_channel_id = await state.peer_channel_message_queue.get()

        peer_channel_row = state.cached_peer_channel_rows.get(remote_channel_id)
        if peer_channel_row is None:
            # TODO(1.4.0) Unreliable server, issue#841. Unexpected server peer channel activity.
            #     a) The server is buggy and has sent us a message intended for someone else.
            #     b) We are buggy and we have not correctly tracked peer channels.
            #     We should flag this to the user in some user-friendly way as a reliability
            #       indicator.
            logger.error("Wallet: '%s' received peer channel notification for unknown channel '%s'",
                state.wallet_proxy.name(), remote_channel_id)
            continue

        assert peer_channel_row.peer_channel_id is not None
        db_access_tokens = state.wallet_data.read_server_peer_channel_access_tokens(
            peer_channel_row.peer_channel_id, PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE,
            PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE)
        assert len(db_access_tokens) == 1

        messages = await list_peer_channel_messages_async(state, remote_channel_id,
            db_access_tokens[0].access_token, unread_only=True)
        if len(messages) == 0:
            # This may happen legitimately if we had several new message notifications backlogged
            # for the same channel, but processing a leading notification picks up the messages
            # for the trailing notification.
            logger.debug("Asked peer channel %d for new messages and received none",
                peer_channel_row.peer_channel_id)
            continue

        date_created = get_posix_timestamp()
        creation_message_rows = list[ServerPeerChannelMessageRow]()
        message_map = dict[int, GenericPeerChannelMessage]()
        for message in messages:
            message_json_bytes = json.dumps(message).encode()
            received_iso8601_text = message["received"].replace("Z", "+00:00")
            received_datetime = datetime.fromisoformat(received_iso8601_text)
            creation_message_rows.append(ServerPeerChannelMessageRow(None,
                peer_channel_row.peer_channel_id, message_json_bytes,
                PeerChannelMessageFlag.UNPROCESSED, message["sequence"],
                int(received_datetime.timestamp()),
                date_created, date_created))
            message_map[message["sequence"]] = message

        # These cached values are passed on to whatever other system processes these types of
        # messages.
        message_entries = list[tuple[ServerPeerChannelMessageRow, GenericPeerChannelMessage]]()
        for message_row in await state.wallet_data.create_server_peer_channel_messages_async(
                creation_message_rows):
            message_entries.append((message_row, message_map[message_row.sequence]))

        # Now that we have all these messages stored locally we can delete the remote copies.
        for sequence in message_map:
            await delete_peer_channel_message_async(state, remote_channel_id,
                db_access_tokens[0].access_token, sequence)

        peer_channel_purpose = \
            peer_channel_row.peer_channel_flags & ServerPeerChannelFlag.MASK_PURPOSE
        if peer_channel_purpose == ServerPeerChannelFlag.TIP_FILTER_DELIVERY:
            await state.tip_filter_matches_queue.put(message_entries)
        elif peer_channel_purpose == ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK:
            state.mapi_callback_response_queue.put_nowait(message_entries)
            state.mapi_callback_response_event.set()
        else:
            # TODO(1.4.0) Unreliable server, issue#841. Peer channel message is not expected.
            logger.error("Wallet: '%s' received peer channel %d messages of unhandled purpose '%s'",
                state.wallet_proxy.name(), peer_channel_row.peer_channel_id, peer_channel_purpose)

    logger.debug("Exiting process_incoming_peer_channel_messages_async, server_id=%d",
        state.server.server_id)


async def create_peer_channel_async(state: ServerConnectionState,
        public_read: bool=False, public_write: bool=True, sequenced: bool=True,
        retention: RetentionViewModel | None=None) -> PeerChannelViewModelGet:
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

            return cast(PeerChannelViewModelGet, await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {url}")


async def mark_peer_channel_read_or_unread_async(state: ServerConnectionState,
        remote_channel_id: str, access_token: str, sequence: int, older: bool, is_read: bool) \
            -> None:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert state.wallet_proxy is not None
    assert state.wallet_data is not None

    url = f"{state.server.url}api/v1/channel/{remote_channel_id}/{sequence}"
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


async def get_peer_channel_async(state: ServerConnectionState, remote_channel_id: str) \
        -> PeerChannelViewModelGet:
    """
    Use the reference peer channel implementation API for getting a specific peer channel.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/channel/manage/{remote_channel_id}"
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


async def list_peer_channels_async(state: ServerConnectionState) -> list[PeerChannelViewModelGet]:
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

            return cast(list[PeerChannelViewModelGet], await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {server_url}")


async def delete_peer_channel_async(state: ServerConnectionState, remote_channel_id: str) \
        -> None:
    """
    Use the reference peer channel implementation API for deleting peer channels.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/channel/manage/{remote_channel_id}"
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


async def create_peer_channel_message_json_async(state: ServerConnectionState,
        remote_channel_id: str, access_token: str, message: dict[str, Any]) \
            -> GenericPeerChannelMessage | None:
    """returns sequence number"""
    server_url = f"{state.server.url}api/v1/channel/{remote_channel_id}"
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


async def create_peer_channel_message_binary_async(state: ServerConnectionState,
        remote_channel_id: str, access_token: str, message: bytes) -> MessageViewModelGetBinary:
    """returns sequence number"""
    server_url = f"{state.server.url}api/v1/channel/{remote_channel_id}"
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


async def list_peer_channel_messages_async(state: ServerConnectionState, remote_channel_id: str,
        access_token: str, unread_only: bool=False) -> list[GenericPeerChannelMessage]:
    """
    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.

    WARNING: This does not set the messages to read when it reads them.. that needs to be done
        manually after this call with another to `mark_peer_channel_read_or_unread`.
    """
    url = f"{state.server.url}api/v1/channel/{remote_channel_id}"
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


async def delete_peer_channel_message_async(state: ServerConnectionState, remote_channel_id: str,
        access_token: str, sequence: int) -> None:
    """
    Use the reference peer channel implementation API for deleting a message in a peer channel.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/channel/{remote_channel_id}/{sequence}"
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


async def create_peer_channel_api_token_async(state: ServerConnectionState, channel_id: str,
        can_read: bool=True, can_write: bool=True, description: str="standard token") \
            -> PeerChannelAPITokenViewModelGet:
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

            return cast(PeerChannelAPITokenViewModelGet, await response.json())
    except aiohttp.ClientError:
        # NOTE(exception-details) We log this because we are not sure yet that we do not need
        #     this detail. At a later stage if we are confident that all the exceptions here
        #     are reasonable and expected, we can remove this.
        logger.debug("Wrapped aiohttp exception (do we need to preserve this?)", exc_info=True)
        raise ServerConnectionError(f"Unable to establish server connection: {url}")


async def list_peer_channel_api_tokens_async(state: ServerConnectionState, remote_channel_id: str) \
        -> list[PeerChannelAPITokenViewModelGet]:
    """
    Use the reference peer channel implementation API for listing peer channel access tokens.

    Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
    Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_url = f"{state.server.url}api/v1/channel/manage/{remote_channel_id}/api-token"
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


async def get_peer_channel_max_sequence_number_async(state: ServerConnectionState,
        remote_channel_id: str, access_token: str) -> int | None:
    server_url = f"{state.server.url}api/v1/channel/{remote_channel_id}"
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
