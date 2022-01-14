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

import asyncio
import base64
import http
import json
from typing import List, Union, Optional, AsyncIterable, Dict, cast

import aiohttp
import bitcoinx
from aiohttp import web, WSServerHandshakeError
from bitcoinx import hash_to_hex_str, Header, unpack_header, double_sha256

from electrumsv.exceptions import ServiceUnavailableError
from electrumsv.network_support.exceptions import HeaderNotFoundError, HeaderResponseError
from ..bitcoin import TSCMerkleProof
from ..logs import logs

from electrumsv.network_support.esv_client_types import (PeerChannelToken, TokenPermissions,
    MessageViewModelGetBinary, GenericJSON, MessageViewModelGetJSON, APITokenViewModelGet,
    PeerChannelViewModelGet, RetentionViewModel, GeneralNotification, ChannelId,
    WebsocketUnauthorizedException, PeerChannelMessage, MAPICallbackResponse, TSCMerkleProofJson,
    tsc_merkle_proof_json_to_binary, TipResponse)

logger = logs.get_logger("esv-client")

# REGTEST_MASTER_TOKEN is a special case bearer token in the ESV-Reference-Server that is
# configured to allow bypassing the account creation process for testing purposes
# It has an associated infinite balance i.e. unlimited use is permitted without payment.
REGTEST_MASTER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa" \
                       "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="


def chain_tip_to_header_obj(tip: bytes) -> Header:
    raw_header = tip[0:80]
    height = bitcoinx.le_bytes_to_int(tip[80:84])
    header_fields = unpack_header(raw_header)
    return Header(*header_fields, raw=raw_header, height=height, hash=double_sha256(raw_header))


class PeerChannel:
    """Represents a single Peer Channel instance"""

    def __init__(self, channel_id: str, tokens: List[PeerChannelToken], base_url: str,
            session: aiohttp.ClientSession, master_token: str) -> None:
        assert len(base64.urlsafe_b64decode(channel_id)) == 64, "Channel id should be 64 bytes"
        for permissions, api_key in tokens:
            assert len(base64.urlsafe_b64decode(api_key)) == 64, "Peer channel tokens should be " \
                                                                 "64 bytes"
        self.channel_id = channel_id
        self.tokens = tokens
        self.base_url = base_url
        self.session = session
        self.master_token = master_token  # master bearer token for the server account

    def __repr__(self) -> str:
        return f"<PeerChannel channel_id={self.channel_id}/>"

    def get_callback_url(self) -> str:
        return self.base_url + f"api/v1/channel/{self.channel_id}"

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
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        read_token = self.get_read_token()
        if read_token is None:
            logger.error("A valid read token was not found for 'get_messages' request to: %s", url)
            return None

        headers = {"Authorization": f"Bearer {read_token.api_key}"}
        async with self.session.get(url, headers=headers) as resp:
            if resp.status != http.HTTPStatus.OK:
                logger.error("get_messages failed with status: %s, reason: %s",
                    resp.status, resp.reason)
                return None
            result: List[PeerChannelMessage] = await resp.json()
            return result

    async def get_max_sequence_number(self) -> Optional[int]:
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        read_token = self.get_read_token()
        if read_token is None:
            logger.error("A valid read token was not found for 'get_messages' request to: %s", url)
            return None

        headers = {"Authorization": f"Bearer {read_token.api_key}"}
        async with self.session.head(url, headers=headers) as resp:
            if resp.status != http.HTTPStatus.OK:
                logger.error("get_max_sequence_number failed with status: %s, reason: %s",
                    resp.status, resp.reason)
                return None
            return int(resp.headers['ETag'])

    async def write_message(self, message: Union[GenericJSON, bytes],
            mime_type: str="application/octet-stream") \
                -> Optional[Union[MessageViewModelGetJSON, MessageViewModelGetBinary]]:
        """returns sequence number"""
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        write_token = self.get_write_token()
        if write_token is None:
            logger.error("A valid write token was not found for 'get_messages' request to: %s", url)
            return None
        headers = {"Authorization": f"Bearer {write_token.api_key}"}

        if mime_type == "application/json":
            assert isinstance(message, dict)
            headers.update({"Content-Type": mime_type})
            json_no_whitespace = json.dumps(message, separators=(",", ":"))
            async with self.session.post(url, headers=headers, data=json_no_whitespace) as resp:
                resp.raise_for_status()  # Todo - remove and handle outcomes when we use this
                json_response: MessageViewModelGetJSON = await resp.json()
                return json_response
        else:
            assert isinstance(message, bytes)
            headers.update({"Content-Type": mime_type})
            async with self.session.post(url, headers=headers, json=message) as resp:
                resp.raise_for_status()  # Todo - remove and handle outcomes when we use this
                bin_response: MessageViewModelGetBinary = await resp.json()
                return bin_response

    async def create_api_token(self, can_read: bool=True, can_write: bool=True,
            description: str="standard token") -> PeerChannelToken:
        url = self.base_url + "api/v1/channel/manage/{channelid}/api-token".format(
            channelid=self.channel_id)
        headers = {"Authorization": f"Bearer {self.master_token}"}
        body = {
          "description": description,
          "can_read": can_read,
          "can_write": can_write
        }
        async with self.session.post(url, headers=headers, json=body) as resp:
            resp.raise_for_status()  # Todo - remove and handle outcomes when we use this
            json_token: APITokenViewModelGet = await resp.json()
            permissions: TokenPermissions = TokenPermissions.NONE
            if json_token['can_read']:
                permissions |= TokenPermissions.READ_ACCESS
            if json_token['can_write']:
                permissions |= TokenPermissions.WRITE_ACCESS
            return PeerChannelToken(permissions=permissions, api_key=json_token['token'])

    async def list_api_tokens(self) -> list[PeerChannelToken]:
        url = self.base_url + "api/v1/channel/manage/{channelid}/api-token".format(
            channelid=self.channel_id)
        headers = {"Authorization": f"Bearer {self.master_token}"}
        async with self.session.get(url, headers=headers) as resp:
            resp.raise_for_status()  # Todo - remove and handle outcomes when we use this
            json_tokens: list[APITokenViewModelGet] = await resp.json()

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

    def __init__(self, base_url: str, session: aiohttp.ClientSession, master_token: str):
        self.base_url = base_url
        self.session = session
        self.master_token = master_token
        self.headers = {"Authorization": f"Bearer {self.master_token}"}

        self._message_fetcher_is_alive = False
        self._FETCH_JOBS_COUNT = 4
        self._merkle_proofs_queue: asyncio.Queue[MAPICallbackResponse] = asyncio.Queue()
        self._peer_channel_cache: Dict[ChannelId, PeerChannel] = {}

    def _replace_http_with_ws(self, url: str) -> str:
        if url.startswith("http://"):
            url = self.base_url.replace("http://", "ws://")
        if self.base_url.startswith("https://"):
            url = url.replace("https://", "wss://")
        return url

    def _peer_channel_json_to_obj(self, peer_channel_json: PeerChannelViewModelGet) \
            -> PeerChannel:
        access_tokens = peer_channel_json['access_tokens']
        tokens = []
        for token in access_tokens:
            permissions = TokenPermissions.NONE
            if token['can_read']:
                permissions |= TokenPermissions.READ_ACCESS
            if token['can_write']:
                permissions |= TokenPermissions.WRITE_ACCESS
            tokens.append(PeerChannelToken(permissions=permissions, api_key=token['token']))

        return PeerChannel(channel_id=peer_channel_json['id'], tokens=tokens,
            base_url=self.base_url, session=self.session, master_token=self.master_token)

    # ----- General Websocket ----- #
    async def _fetch_peer_channel_message_job(self,
            peer_channel_notification_queue: asyncio.Queue[GeneralNotification]) -> None:
        """Can run multiple of these concurrently to fetch new peer channel messages

        NOTE(AustEcon): This function is not tested yet. It is only intended to show
        general intent at this stage."""
        while True:
            message: GeneralNotification = await peer_channel_notification_queue.get()
            channel_id: ChannelId = message['result']['id']

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

    async def _message_fetcher_job(self) -> None:
        """NOTE(AustEcon): This function is not tested yet. It is only intended to show
        general intent at this stage.

        Idempotent - if spawned twice, the second time will do nothing"""
        if not self._message_fetcher_is_alive:
            peer_channel_notification_queue: asyncio.Queue[GeneralNotification] = asyncio.Queue()
            for i in range(self._FETCH_JOBS_COUNT):
                asyncio.create_task(
                    self._fetch_peer_channel_message_job(peer_channel_notification_queue))

            async for notification in self.subscribe_to_general_notifications():
                peer_channel_notification_queue.put_nowait(notification)

    async def wait_for_merkle_proofs_and_double_spends(self) -> AsyncIterable[TSCMerkleProof]:
        """NOTE(AustEcon): This function is not tested yet. It is only intended to show
        general intent at this stage."""
        if not self._message_fetcher_is_alive:
            asyncio.create_task(self._message_fetcher_job())

        # https://github.com/bitcoin-sv-specs/brfc-merchantapi#callback-notifications
        while True:
            # Todo run select query on MAPIBroadcastCallbacks to get libsodium encryption key
            callback_response: MAPICallbackResponse = await self._merkle_proofs_queue.get()
            tsc_merkle_proof: TSCMerkleProofJson = json.loads(callback_response['callbackPayload'])

            # NOTE(AustEcon) mAPI defaults to targetType == 'header' but the TSC spec defaults to
            # 'hash' if the targetType field is omitted.
            target_type = cast(str, tsc_merkle_proof.get('targetType', 'hash'))
            yield tsc_merkle_proof_json_to_binary(tsc_merkle_proof, target_type=target_type)

    async def subscribe_to_general_notifications(self) -> AsyncIterable[GeneralNotification]:
        """Concurrent fetching of peer channel messages is left to the caller in order to keep
        this class very simple"""
        ws_base_url = self._replace_http_with_ws(self.base_url)
        url = ws_base_url + "api/v1/web-socket" + f"?token={self.master_token}"
        try:
            async with self.session.ws_connect(url, headers={}, timeout=5.0) as ws:
                logger.info('Connected to %s', url)
                msg: aiohttp.WSMessage
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        notification: GeneralNotification = json.loads(msg.data)
                        yield notification

                    if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR,
                            aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                        logger.info("General purpose websocket closed")
                        break
        except WSServerHandshakeError as e:
            if e.status == http.HTTPStatus.UNAUTHORIZED:
                raise WebsocketUnauthorizedException()
            raise ServiceUnavailableError("Websocket handshake ElectrumSV-Reference Server failed")
        except aiohttp.ClientConnectionError:
            # NOTE(AustEcon) we must never include the api token in logs or exceptions
            logger.error(f"Cannot connect to ElectrumSV-Reference Server at %s",
                ws_base_url + "api/v1/web-socket")
            raise ServiceUnavailableError("Cannot connect to ElectrumSV-Reference Server "
                f"at {ws_base_url + 'api/v1/web-socket'}")

    # ----- HeaderSV APIs ----- #
    async def get_single_header(self, block_hash: bytes) -> Optional[bytes]:
        url = self.base_url + f"api/v1/headers/{hash_to_hex_str(block_hash)}"
        headers = {}
        headers.update(self.headers)
        headers.update({"Accept": "application/octet-stream"})
        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == http.HTTPStatus.NOT_FOUND:
                    raise HeaderNotFoundError("Header with block hash "
                                              f"{hash_to_hex_str(block_hash)} not found")
                elif resp.status != http.HTTPStatus.OK:
                    raise HeaderResponseError("Failed to get header with status: "
                                              f"{resp.status} reason: {resp.reason}")
                return await resp.read()
        except aiohttp.ClientConnectionError:
            logger.error(f"Cannot connect to ElectrumSV-Reference Server at %s", url)
            raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")

    async def get_headers_by_height(self, from_height: int, count: Optional[int]=None) \
            -> bytes:
        url = self.base_url + "api/v1/headers/by-height" + f"?height={from_height}"
        if count:
            url += f"&count={count}"
        headers = {}
        headers.update(self.headers)
        headers.update({"Accept": "application/octet-stream"})
        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status != http.HTTPStatus.OK:
                    error_message = f"get_headers_by_height failed with status: {resp.status}, " \
                                    f"reason: {resp.reason}"
                    logger.error(error_message)
                    raise HeaderResponseError(error_message)
                raw_headers_array = await resp.read()
                return raw_headers_array
        except aiohttp.ClientConnectionError:
            logger.error(f"Cannot connect to ElectrumSV-Reference Server at %s", url)
            raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")

    async def get_chain_tips(self, longest_chain_only: bool=False) -> bytes:
        url = self.base_url + "api/v1/headers/tips"
        if longest_chain_only:
            url += "?longest_chain=1"
        headers = {}
        headers.update(self.headers)
        headers.update({"Accept": "application/octet-stream"})
        try:
            async with self.session.get(url, headers=headers) as resp:
                if resp.status == http.HTTPStatus.SERVICE_UNAVAILABLE:
                    logger.error("The Header API is not enabled for this instance of "
                                 "ElectrumSV-Reference-Server")
                    raise ServiceUnavailableError("The Header API is not enabled for this instance "
                        "of ElectrumSV-Reference-Server")

                if resp.status != http.HTTPStatus.OK:
                    error_message = f"get_chain_tips failed with status: {resp.status}, " \
                                    f"reason: {resp.reason}"
                    logger.error(error_message)
                    raise HeaderResponseError(error_message)
                headers_array: bytes = await resp.content.read()
                return headers_array
        except aiohttp.ClientConnectionError:
            logger.error(f"Cannot connect to ElectrumSV-Reference Server at %s", url)
            raise ServiceUnavailableError(f"Cannot connect to ElectrumSV-Reference Server at {url}")

    async def subscribe_to_headers(self) -> AsyncIterable[TipResponse]:
        ws_base_url = self._replace_http_with_ws(self.base_url)
        url = ws_base_url + "api/v1/headers/tips/websocket"
        try:
            async with self.session.ws_connect(url, headers={}, timeout=5.0) as ws:
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
        url = self.base_url + "api/v1/channel/manage"
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

        async with self.session.post(url, headers=self.headers, json=body) as resp:
            resp.raise_for_status()
            json_response: PeerChannelViewModelGet = await resp.json()
            peer_channel = self._peer_channel_json_to_obj(json_response)
            self._peer_channel_cache[peer_channel.channel_id] = peer_channel  # cache
            return self._peer_channel_json_to_obj(json_response)

    async def delete_peer_channel(self, peer_channel: PeerChannel) -> None:
        url = self.base_url + "api/v1/channel/manage/{channelid}"
        url = url.format(channelid=peer_channel.channel_id)
        async with self.session.delete(url, headers=self.headers) as resp:
            resp.raise_for_status()
            assert resp.status == web.HTTPNoContent.status_code

    async def list_peer_channels(self) -> List[PeerChannel]:
        base_url = self.base_url if self.base_url.endswith("/") else self.base_url + "/"
        url = base_url + "api/v1/channel/manage/list"
        async with self.session.get(url, headers=self.headers) as resp:
            resp.raise_for_status()
            result = []
            for peer_channel_json in await resp.json():
                peer_channel_obj = self._peer_channel_json_to_obj(peer_channel_json)
                self._peer_channel_cache[peer_channel_obj.channel_id] = peer_channel_obj  # cache
                result.append(peer_channel_obj)
            return result

    async def get_single_peer_channel(self, channel_id: str) -> Optional[PeerChannel]:
        base_url = self.base_url if self.base_url.endswith("/") else self.base_url + "/"
        url = base_url + "api/v1/channel/manage/{channelid}".format(channelid=channel_id)
        async with self.session.get(url, headers=self.headers) as resp:
            if resp.status != http.HTTPStatus.OK:
                logger.error("get_single_peer_channel failed with status: %s, reason: %s",
                    resp.status, resp.reason)
                return None

            peer_channel = self._peer_channel_json_to_obj(await resp.json())
            self._peer_channel_cache[channel_id] = peer_channel  # cache
            return peer_channel

    async def get_single_peer_channel_cached(self, channel_id: str) -> Optional[PeerChannel]:
        # NOTE(AustEcon) - if new channel tokens are subsequently generated, you must remember to
        # update this cache
        if self._peer_channel_cache.get(channel_id):
            return self._peer_channel_cache[channel_id]
        else:
            return await self.get_single_peer_channel(channel_id)


if __name__ == "__main__":
    async def main() -> None:
        session = aiohttp.ClientSession()
        try:
            BASE_URL = "http://127.0.0.1:47124/"  # ESVReferenceServer
            REGTEST_BEARER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa" \
                                   "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="
            esv_client = ESVClient(BASE_URL, session, REGTEST_BEARER_TOKEN)

            peer_channel = await esv_client.create_peer_channel()
            assert isinstance(peer_channel, PeerChannel)

            seq = await peer_channel.get_max_sequence_number()
            assert isinstance(seq, int)

            messages = await peer_channel.get_messages()
            assert isinstance(messages, list)

            message_to_write = {"key": "value"}
            message = await peer_channel.write_message(message_to_write,
                mime_type="application/json")
            assert isinstance(message, dict)

            peer_channel_token = await peer_channel.create_api_token()
            assert isinstance(peer_channel_token, PeerChannelToken)

            peer_channel_tokens = await peer_channel.list_api_tokens()
            assert isinstance(peer_channel_tokens, list)
            assert isinstance(peer_channel_tokens[0], PeerChannelToken)
            assert len(peer_channel_tokens) == 2

            list_peer_channels = await esv_client.list_peer_channels()
            assert isinstance(list_peer_channels, list)
            assert isinstance(list_peer_channels[0], PeerChannel)

            fetched_peer_channel = await esv_client.get_single_peer_channel(
                peer_channel.channel_id)
            assert isinstance(fetched_peer_channel, PeerChannel)

            result = await esv_client.delete_peer_channel(peer_channel)
            assert result is None
        finally:
            if session:
                await session.close()

    asyncio.run(main())
