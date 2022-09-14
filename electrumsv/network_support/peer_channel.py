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
from http import HTTPStatus
import json
from typing import Any, cast

import aiohttp

from ..app_state import app_state
from ..exceptions import ServerConnectionError
from ..logs import logs

from .exceptions import GeneralAPIError
from .types import ServerStateProtocol, GenericPeerChannelMessage, MessageViewModelGetBinary, \
    PeerChannelAPITokenViewModelGet, PeerChannelViewModelGet,  RetentionViewModel, \
    TokenPermissions


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
