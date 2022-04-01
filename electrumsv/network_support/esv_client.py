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
import base64
import http
import json
from typing import List, Union, Optional, AsyncIterable, Dict, cast

import aiohttp
import bitcoinx
from aiohttp import web, WSServerHandshakeError
from bitcoinx import double_sha256, Chain, Header, hash_to_hex_str

from ..app_state import app_state
from ..bitcoin import TSCMerkleProof
from electrumsv.exceptions import ServiceUnavailableError
from electrumsv.network_support.exceptions import HeaderNotFoundError, HeaderResponseError
from ..logs import logs
from ..network_support.esv_client_types import (APITokenViewModelGet, ChannelId,
    ChannelNotification, GenericJSON, MessageViewModelGetBinary, MessageViewModelGetJSON,
    MAPICallbackResponse, PeerChannelToken, PeerChannelMessage, PeerChannelViewModelGet,
    RetentionViewModel, TokenPermissions, TipResponse, ServerConnectionState, TSCMerkleProofJson,
    tsc_merkle_proof_json_to_binary)


# TODO(1.4.0) Networking. Logging should be per server as before.
logger = logs.get_logger("esv-client")


class PeerChannel:
    """Represents a single Peer Channel instance"""

    def __init__(self, state: ServerConnectionState, channel_id: str,
            tokens: List[PeerChannelToken]) -> None:
        assert len(base64.urlsafe_b64decode(channel_id)) == 64, "Channel id should be 64 bytes"
        for permissions, api_key in tokens:
            assert len(base64.urlsafe_b64decode(api_key)) == 64, "Peer channel tokens should be " \
                                                                 "64 bytes"
        self.channel_id = channel_id
        self.tokens = tokens
        self.state = state

    def __repr__(self) -> str:
        return f"PeerChannel(channel_id={self.channel_id})"

    @classmethod
    def from_json(cls, json: PeerChannelViewModelGet, state: ServerConnectionState) -> PeerChannel:
        access_tokens = json['access_tokens']
        tokens = []
        for token in access_tokens:
            permissions = TokenPermissions.NONE
            if token['can_read']:
                permissions |= TokenPermissions.READ_ACCESS
            if token['can_write']:
                permissions |= TokenPermissions.WRITE_ACCESS
            tokens.append(PeerChannelToken(permissions=permissions, api_key=token['token']))

        return cls(channel_id=json['id'], tokens=tokens, state=state)

    def get_callback_url(self) -> str:
        return f"{self.state.server.url}api/v1/channel/{self.channel_id}"

    def get_write_token(self) -> Optional[PeerChannelToken]:
        for token in self.tokens:
            if token.permissions & TokenPermissions.WRITE_ACCESS == TokenPermissions.WRITE_ACCESS:
                return token
        return None

    def get_read_token(self) -> Optional[PeerChannelToken]:
        for token in self.tokens:
            if token.permissions & TokenPermissions.READ_ACCESS == TokenPermissions.READ_ACCESS:
                return token
        return None

    async def get_messages(self) -> Optional[List[PeerChannelMessage]]:
        """Return cases:
            - Empty list means there are no unread messages.
            - Null means we do not have a valid read token - should be handled by the caller."""
        url = f"{self.state.server.url}api/v1/channel/{self.channel_id}"
        read_token = self.get_read_token()
        if read_token is None:
            logger.error("A valid read token was not found for 'get_messages' request to: %s", url)
            return None

        headers = {"Authorization": f"Bearer {read_token.api_key}"}

        async with self.state.session.get(url, headers=headers) as response:
            if response.status != http.HTTPStatus.OK:
                logger.error("get_messages failed with status: %s, reason: %s",
                    response.status, response.reason)
                return None
            result: List[PeerChannelMessage] = await response.json()
            return result

    async def get_max_sequence_number(self) -> Optional[int]:
        url = f"{self.state.server.url}api/v1/channel/{self.channel_id}"
        read_token = self.get_read_token()
        if read_token is None:
            logger.error("A valid read token was not found for 'get_messages' request to: %s", url)
            return None

        headers = {"Authorization": f"Bearer {read_token.api_key}"}

        async with self.state.session.head(url, headers=headers) as response:
            if response.status != http.HTTPStatus.OK:
                logger.error("get_max_sequence_number failed with status: %s, reason: %s",
                    response.status, response.reason)
                return None
            return int(response.headers['ETag'])

    async def write_message(self, message: Union[GenericJSON, bytes],
            mime_type: str="application/octet-stream") \
                -> Optional[Union[MessageViewModelGetJSON, MessageViewModelGetBinary]]:
        """returns sequence number"""
        url = f"{self.state.server.url}api/v1/channel/{self.channel_id}"
        write_token = self.get_write_token()
        if write_token is None:
            logger.error("A valid write token was not found for 'get_messages' request to: %s", url)
            return None
        headers = {"Authorization": f"Bearer {write_token.api_key}"}

        if mime_type == "application/json":
            assert isinstance(message, dict)
            headers.update({"Content-Type": mime_type})
            json_no_whitespace = json.dumps(message, separators=(",", ":"))
            async with self.state.session.post(url, headers=headers, data=json_no_whitespace) \
                    as response:
                response.raise_for_status()  # Todo - remove and handle outcomes when we use this
                json_response: MessageViewModelGetJSON = await response.json()
                return json_response
        else:
            assert isinstance(message, bytes)
            headers.update({"Content-Type": mime_type})
            async with self.state.session.post(url, headers=headers, json=message) as response:
                response.raise_for_status()  # Todo - remove and handle outcomes when we use this
                bin_response: MessageViewModelGetBinary = await response.json()
                return bin_response

    async def create_api_token(self, can_read: bool=True, can_write: bool=True,
            description: str="standard token") -> PeerChannelToken:
        url = f"{self.state.server.url}api/v1/channel/manage/{self.channel_id}/api-token"
        assert self.state.credential_id is not None
        master_token = app_state.credentials.get_indefinite_credential(self.state.credential_id)
        headers = {"Authorization": f"Bearer {master_token}"}
        body = {
          "description": description,
          "can_read": can_read,
          "can_write": can_write
        }
        async with self.state.session.post(url, headers=headers, json=body) as response:
            response.raise_for_status()  # Todo - remove and handle outcomes when we use this
            json_token: APITokenViewModelGet = await response.json()
            permissions: TokenPermissions = TokenPermissions.NONE
            if json_token['can_read']:
                permissions |= TokenPermissions.READ_ACCESS
            if json_token['can_write']:
                permissions |= TokenPermissions.WRITE_ACCESS
            return PeerChannelToken(permissions=permissions, api_key=json_token['token'])

    async def list_api_tokens(self) -> list[PeerChannelToken]:
        url = f"{self.state.server.url}api/v1/channel/manage/{self.channel_id}/api-token"
        assert self.state.credential_id is not None
        master_token = app_state.credentials.get_indefinite_credential(self.state.credential_id)
        headers = {"Authorization": f"Bearer {master_token}"}
        async with self.state.session.get(url, headers=headers) as response:
            response.raise_for_status()  # Todo - remove and handle outcomes when we use this
            json_tokens: list[APITokenViewModelGet] = await response.json()

            result = []
            for json_token in json_tokens:
                permissions = TokenPermissions.NONE
                if json_token['can_read']:
                    permissions |= TokenPermissions.READ_ACCESS
                if json_token['can_write']:
                    permissions |= TokenPermissions.WRITE_ACCESS
                result.append(PeerChannelToken(permissions=permissions,
                    api_key=json_token['token']))
            return result



class ESVClient:
    """This is a lightweight client for the ElectrumSVReferenceServer.

    The only state is the base_url and master_token. Therefore instances of ESVClient can be
    re-generated on-demand - no need for caching of ESVClient instances."""

    def __init__(self, state: ServerConnectionState) -> None:
        self._state = state
        self._FETCH_JOBS_COUNT = 4
        self._merkle_proofs_queue: asyncio.Queue[MAPICallbackResponse] = asyncio.Queue()
        self._peer_channel_cache: Dict[ChannelId, PeerChannel] = {}

        # must be updated manually via update_tip_and_chain - used for Network server management
        self.chain: Optional[Chain] = None
        self.tip: Optional[Header] = None

    def update_tip_and_chain(self, tip_obj: Header, chain: Chain) -> None:
        self.tip = tip_obj
        self.chain = chain

    # ----- General Websocket ----- #
    async def _fetch_peer_channel_message_job(self,
            peer_channel_message_queue: asyncio.Queue[ChannelNotification]) -> None:
        """Can run multiple of these concurrently to fetch new peer channel messages

        NOTE(AustEcon): This function is not tested yet. It is only intended to show
        general intent at this stage."""
        while True:
            message: ChannelNotification = await peer_channel_message_queue.get()
            channel_id: ChannelId = message['id']

            peer_channel = await self.get_single_peer_channel_cached(channel_id)
            if not peer_channel:
                logger.error("Could not get peer channel details for %s", channel_id)
                # Todo - Retry logic...
                continue

            messages: Optional[list[PeerChannelMessage]] = await peer_channel.get_messages()
            if messages is not None:
                for pc_message in messages:
                    if pc_message['content_type'] == 'application/json':
                        # Todo should probably check for PeerChannelType.MERCHANT_API before cast
                        json_payload: MAPICallbackResponse = cast(MAPICallbackResponse,
                            pc_message['payload'])
                        if json_payload.get("callbackReason") \
                                and json_payload["callbackReason"] == "merkleProof"\
                                or json_payload["callbackReason"] == "doubleSpendAttempt":
                            self._merkle_proofs_queue.put_nowait(json_payload)
                        else:
                            logger.error(f"PeerChannelMessage not recognised: {pc_message}")

                    if pc_message['content_type'] == 'application/octet-stream':
                        logger.error(f"Binary format PeerChannelMessage received - "
                                     f"not supported yet")
            else:
                logger.error("No messages could be returned from channel_id: %s, "
                             "do you have a valid read token?", channel_id)

    # TODO(1.4.0) Merkle Proofs. Write tests for this function
    # TODO(1.4.0) Merkle Proofs. Make sure that the proof data is added to the TransactionProofs
    #  table regardless of whether or not it is an orphaned proof
    async def wait_for_merkle_proofs_and_double_spends(self, state: ServerConnectionState) \
            -> AsyncIterable[TSCMerkleProof]:
        """NOTE(AustEcon): This function is not tested yet. It is only intended to show
        general intent at this stage."""
        child_tasks = []
        for i in range(self._FETCH_JOBS_COUNT):
            child_tasks.append(asyncio.create_task(
                self._fetch_peer_channel_message_job(state.peer_channel_message_queue)))

        try:
            while True:
                # Todo run select query on MAPIBroadcastCallbacks to get libsodium encryption key
                callback_response: MAPICallbackResponse = await self._merkle_proofs_queue.get()
                tsc_merkle_proof: TSCMerkleProofJson = \
                    json.loads(callback_response['callbackPayload'])

                # NOTE(AustEcon) mAPI defaults to targetType == 'header' but the TSC spec defaults
                # to 'hash' if the targetType field is omitted.
                target_type = cast(str, tsc_merkle_proof.get('targetType', 'hash'))
                yield tsc_merkle_proof_json_to_binary(tsc_merkle_proof, target_type=target_type)
        finally:
            for task in child_tasks:
                task.cancel()

    # ----- HeaderSV APIs ----- #
    async def get_single_header(self, block_hash: bytes) -> bytes:
        url = f"{self._state.server.url}api/v1/headers/{hash_to_hex_str(block_hash)}"
        headers = {"Accept": "application/octet-stream"}
        try:
            async with self._state.session.get(url, headers=headers) as response:
                if response.status == http.HTTPStatus.NOT_FOUND:
                    raise HeaderNotFoundError("Header with block hash "
                                              f"{hash_to_hex_str(block_hash)} not found")
                elif response.status != http.HTTPStatus.OK:
                    raise HeaderResponseError("Failed to get header with status: "
                                              f"{response.status} reason: {response.reason}")
                return await response.read()
        except aiohttp.ClientConnectionError:
            logger.error(f"Cannot connect to ElectrumSV-Reference Server at %s", url)
            raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")

    async def get_batched_headers_by_height(self, from_height: int, count: Optional[int]=None) \
            -> bytes:
        url = f"{self._state.server.url}api/v1/headers/by-height?height={from_height}"
        if count:
            url += f"&count={count}"
        headers = {"Accept": "application/octet-stream"}
        try:
            async with self._state.session.get(url, headers=headers) as response:
                if response.status != http.HTTPStatus.OK:
                    error_message = f"get_batched_headers_by_height failed with status: " \
                                    f"{response.status}, reason: {response.reason}"
                    logger.error(error_message)
                    raise HeaderResponseError(error_message)
                raw_headers_array = await response.read()
                return raw_headers_array
        except aiohttp.ClientConnectionError:
            logger.error(f"Cannot connect to ElectrumSV-Reference Server at %s", url)
            raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")

    async def get_chain_tips(self) -> bytes:
        url = f"{self._state.server.url}api/v1/headers/tips"
        headers = {"Accept": "application/octet-stream"}
        try:
            async with self._state.session.get(url, headers=headers) as response:
                if response.status in {http.HTTPStatus.SERVICE_UNAVAILABLE,
                        http.HTTPStatus.NOT_FOUND}:
                    logger.error("The Header API is not enabled for this instance of "
                                 "ElectrumSV-Reference-Server")
                    raise ServiceUnavailableError("The Header API is not enabled for this instance "
                        "of ElectrumSV-Reference-Server")

                if response.status != http.HTTPStatus.OK:
                    error_message = f"get_chain_tips failed with status: {response.status}, " \
                                    f"reason: {response.reason}"
                    logger.error(error_message)
                    raise HeaderResponseError(error_message)
                headers_array: bytes = await response.content.read()
                return headers_array
        except aiohttp.ClientConnectionError:
            raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")

    async def subscribe_to_headers(self) -> AsyncIterable[TipResponse]:
        url =  f"{self._state.server.url}api/v1/headers/tips/websocket"
        try:
            async with self._state.session.ws_connect(url, headers={}, timeout=5.0) as ws:
                logger.debug("Connected to %s", url)
                async for msg in ws:
                    content = cast(bytes, msg.data)
                    raw_header = content[0:80]
                    block_hash = hash_to_hex_str(double_sha256(raw_header))
                    logger.info("Message new chain tip hash: %s", block_hash)
                    height = bitcoinx.le_bytes_to_int(content[80:84])
                    yield TipResponse(raw_header, height)
                    if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
        except WSServerHandshakeError:
            raise ServiceUnavailableError("Websocket handshake ElectrumSV-Reference Server failed")
        except (aiohttp.ClientConnectionError, ConnectionRefusedError):
            logger.error(f"Cannot connect to ElectrumSV-Reference Server at %s", url)
            raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")

    # ----- Peer Channel APIs ----- #
    async def create_peer_channel(self, public_read: bool=True, public_write: bool=True,
            sequenced: bool=True, retention: Optional[RetentionViewModel]=None) -> PeerChannel:
        url = f"{self._state.server.url}api/v1/channel/manage"
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

        assert self._state.credential_id is not None
        master_token = app_state.credentials.get_indefinite_credential(self._state.credential_id)
        headers = {"Authorization": f"Bearer {master_token}"}

        async with self._state.session.post(url, headers=headers, json=body) as response:
            response.raise_for_status()
            json_response: PeerChannelViewModelGet = await response.json()
            peer_channel = PeerChannel.from_json(json_response, self._state)
            self._peer_channel_cache[peer_channel.channel_id] = peer_channel  # cache
            return peer_channel

    async def delete_peer_channel(self, peer_channel: PeerChannel) -> None:
        url = f"{self._state.server.url}api/v1/channel/manage/{peer_channel.channel_id}"
        assert self._state.credential_id is not None
        master_token = app_state.credentials.get_indefinite_credential(self._state.credential_id)
        headers = {"Authorization": f"Bearer {master_token}"}
        async with self._state.session.delete(url, headers=headers) as resp:
            resp.raise_for_status()
            assert resp.status == web.HTTPNoContent.status_code

    async def list_peer_channels(self) -> List[PeerChannel]:
        url = f"{self._state.server.url}api/v1/channel/manage/list"
        assert self._state.credential_id is not None
        master_token = app_state.credentials.get_indefinite_credential(self._state.credential_id)
        headers = {"Authorization": f"Bearer {master_token}"}
        async with self._state.session.get(url, headers=headers) as response:
            response.raise_for_status()
            result = []
            for peer_channel_json in await response.json():
                peer_channel_obj = PeerChannel.from_json(peer_channel_json, self._state)
                self._peer_channel_cache[peer_channel_obj.channel_id] = peer_channel_obj  # cache
                result.append(peer_channel_obj)
            return result

    async def get_single_peer_channel(self, channel_id: str) -> Optional[PeerChannel]:
        url = f"{self._state.server.url}api/v1/channel/manage/{channel_id}"
        assert self._state.credential_id is not None
        master_token = app_state.credentials.get_indefinite_credential(self._state.credential_id)
        headers = {"Authorization": f"Bearer {master_token}"}
        async with self._state.session.get(url, headers=headers) as response:
            if response.status != http.HTTPStatus.OK:
                logger.error("get_single_peer_channel failed with status: %s, reason: %s",
                    response.status, response.reason)
                return None

            peer_channel = PeerChannel.from_json(await response.json(), self._state)
            self._peer_channel_cache[channel_id] = peer_channel  # cache
            return peer_channel

    async def get_single_peer_channel_cached(self, channel_id: str) -> Optional[PeerChannel]:
        # NOTE(AustEcon) - if new channel tokens are subsequently generated, you must remember to
        # update this cache
        if self._peer_channel_cache.get(channel_id):
            return self._peer_channel_cache[channel_id]
        else:
            return await self.get_single_peer_channel(channel_id)
