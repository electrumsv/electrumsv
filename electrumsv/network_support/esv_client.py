import aiohttp
from aiohttp import web, WSServerHandshakeError
import asyncio
import base64
import json
from typing import List, Union, Optional, AsyncIterable, Dict

from electrumsv.bitcoin import TSCMerkleProof
from electrumsv.logs import logs
from electrumsv.network_support.esv_client_types import (
    PeerChannelToken, TokenPermissions, MessageViewModelGetBinary, GenericJSON,
    MessageViewModelGetJSON, APITokenViewModelGet, PeerChannelViewModelGet, RetentionViewModel,
    TipResponse, Error, GeneralNotification,
    ChannelId, WebsocketUnauthorizedException, PeerChannelMessage, MAPICallbackResponse
)

logger = logs.get_logger("esv-client")

REGTEST_MASTER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa" \
                       "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="


class PeerChannel:
    """Represents a single Peer Channel instance"""

    def __init__(self, channel_id: str, tokens: List[PeerChannelToken], base_url: str,
            session: aiohttp.ClientSession, master_token: str) -> None:
        assert len(base64.urlsafe_b64decode(channel_id)) == 64
        for permissions, api_key in tokens:
            assert len(base64.urlsafe_b64decode(api_key)) == 64
        self.channel_id = channel_id
        self.tokens = tokens
        self.base_url = base_url
        self.session = session
        self.master_token = master_token  # master bearer token for the server account

    def __repr__(self) -> str:
        return f"<PeerChannel channel_id={self.channel_id}/>"

    def get_callback_url(self) -> str:
        return self.base_url + f"api/v1/channel/{self.channel_id}"

    def get_write_token(self) -> PeerChannelToken:
        for token in self.tokens:
            if token.permissions & TokenPermissions.WRITE_ACCESS == TokenPermissions.WRITE_ACCESS:
                return token
        raise ValueError("Write token not found")

    def get_read_token(self) -> PeerChannelToken:
        for token in self.tokens:
            if token.permissions & TokenPermissions.READ_ACCESS == TokenPermissions.READ_ACCESS:
                return token
        raise ValueError("Read token not found")

    async def get_messages(self) -> List[PeerChannelMessage]:
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        read_token = self.get_read_token()
        headers = {"Authorization": f"Bearer {read_token.api_key}"}
        async with self.session.get(url, headers=headers) as resp:
            resp.raise_for_status()
            result: List[PeerChannelMessage] = await resp.json()
            return result

    async def get_max_sequence_number(self) -> int:
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        read_token = self.get_read_token()
        headers = {"Authorization": f"Bearer {read_token.api_key}"}
        async with self.session.head(url, headers=headers) as resp:
            resp.raise_for_status()
            return int(resp.headers['ETag'])

    async def write_message(self, message: Union[GenericJSON, bytes],
            mime_type: str="application/octet-stream") \
                -> Union[MessageViewModelGetJSON, MessageViewModelGetBinary]:
        """returns sequence number"""
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        write_token = self.get_write_token()
        headers = {"Authorization": f"Bearer {write_token.api_key}"}

        if mime_type == "application/json":
            assert isinstance(message, dict)
            headers.update({"Content-Type": mime_type})
            async with self.session.post(url, headers=headers, json=message) as resp:
                resp.raise_for_status()
                json_response: MessageViewModelGetJSON = await resp.json()
                return json_response
        else:
            assert isinstance(message, bytes)
            headers.update({"Content-Type": mime_type})
            async with self.session.post(url, headers=headers, json=message) as resp:
                resp.raise_for_status()
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
            resp.raise_for_status()
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
            resp.raise_for_status()
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
            peer_channel_notification_queue: asyncio.Queue) -> None:
        """Can run multiple of these concurrently to fetch new peer channel messages"""
        message: GeneralNotification = await peer_channel_notification_queue.get()
        channel_id: ChannelId = message['result']['id']

        peer_channel = await self.get_single_peer_channel_cached(channel_id)
        messages: list[PeerChannelMessage] = await peer_channel.get_messages()  # network io
        for pc_message in messages:
            if pc_message['content_type'] == 'application/json':

                json_payload: MAPICallbackResponse = pc_message['payload']
                if json_payload.get("callbackReason") \
                        and json_payload["callbackReason"] == "merkleProof"\
                        or json_payload["callbackReason"] == "doubleSpendAttempt":
                    self._merkle_proofs_queue.put_nowait(json_payload)
                else:
                    logger.error(f"PeerChannelMessage not recognised: {pc_message}")


            if pc_message['content_type'] == 'application/octet-stream':
                logger.error(f"Binary format PeerChannelMessage received - not supported yet")

    async def _message_fetcher_job(self):
        """Idempotent - if spawned twice, the second time will do nothing"""
        if not self._message_fetcher_is_alive:
            peer_channel_notification_queue: asyncio.Queue[ChannelId] = asyncio.Queue()
            for i in range(self._FETCH_JOBS_COUNT):
                asyncio.create_task(
                    self._fetch_peer_channel_message_job(peer_channel_notification_queue))

            async for notification in self.subscribe_to_general_notifications():
                peer_channel_notification_queue.put_nowait(notification)

    async def wait_for_merkle_proofs_and_double_spends(self) -> AsyncIterable[GeneralNotification]:
        if not self._message_fetcher_is_alive:
            asyncio.create_task(self._message_fetcher_job())

        # https://github.com/bitcoin-sv-specs/brfc-merchantapi#callback-notifications
        while True:
            # Todo run select query on MAPIBroadcastCallbacks to get libsodium encryption key
            callback_response = await self._merkle_proofs_queue.get()
            tsc_merkle_proof: TSCMerkleProof = json.loads(callback_response['callbackPayload'])

            # Todo caller to delete entry in MAPIBroadcastCallbacks when processed
            yield tsc_merkle_proof

    async def subscribe_to_general_notifications(self) -> AsyncIterable[GeneralNotification]:
        """Concurrent fetching of peer channel messages is left to the caller in order to keep
        this class very simple"""
        ws_base_url = self._replace_http_with_ws(self.base_url)
        url = ws_base_url + "/api/v1/web-socket" + f"?token={self.master_token}"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.ws_connect(url, timeout=5.0) as ws:
                    logger.info(f'Connected to {url}')
                    async for msg in ws:
                        msg: aiohttp.WSMessage
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            notification: GeneralNotification = json.loads(msg.data)
                            yield notification

                        if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR,
                                aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING):
                            logger.info("CLOSED")
                            break
            except WSServerHandshakeError as e:
                if e.status == 401:
                    raise WebsocketUnauthorizedException()

    # ----- HeaderSV APIs ----- #
    async def get_single_header(self, block_hash: bytes) -> bytes:
        url = self.base_url + "api/v1/headers/{block_hash}".format(block_hash=block_hash)
        headers = {}
        headers.update(self.headers)
        headers.update({"Accept": "application/octet-stream"})
        async with self.session.get(url, headers=self.headers) as resp:
            resp.raise_for_status()
            raw_header = await resp.read()
            return raw_header

    async def get_headers_by_height(self, from_height: int, count: Optional[int]=None) \
            -> bytes:
        url = self.base_url + "api/v1/headers" + f"?height={from_height}"
        if count:
            url += f"&count={count}"
        headers = {}
        headers.update(self.headers)
        headers.update({"Accept": "application/octet-stream"})
        async with self.session.get(url, headers=self.headers) as resp:
            resp.raise_for_status()
            raw_headers_array = await resp.read()
            return raw_headers_array

    async def get_chain_tips(self) -> TipResponse:
        url = self.base_url + "api/v1/headers/tips"
        headers = {}
        headers.update(self.headers)
        headers.update({"Accept": "application/json"})
        async with self.session.get(url, headers=self.headers) as resp:
            resp.raise_for_status()
            json_tip_response: TipResponse = await resp.json()
            return json_tip_response

    async def subscribe_to_headers(self) -> AsyncIterable[TipResponse]:
        ws_base_url = self._replace_http_with_ws(self.base_url)
        url = ws_base_url + "/api/v1/headers/tips/websocket"

        async with self.session as session:
            async with session.ws_connect(url, headers={}, timeout=5.0) as ws:
                logger.debug(f'Connected to {url}')
                async for msg in ws:
                    content: Union[TipResponse, Error] = json.loads(msg.data)
                    logger.debug('Message new chain tip hash: ', content)
                    if isinstance(content, dict) and content.get('error'):
                        error: Error = Error.from_websocket_dict(content)
                        logger.debug(f"Websocket error: {error}")
                        if error.status == web.HTTPUnauthorized.status_code:
                            raise web.HTTPUnauthorized()
                    else:
                        yield content

                    if msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break

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

    async def get_single_peer_channel(self, channel_id: str) -> PeerChannel:
        base_url = self.base_url if self.base_url.endswith("/") else self.base_url + "/"
        url = base_url + "api/v1/channel/manage/{channelid}".format(channelid=channel_id)
        async with self.session.get(url, headers=self.headers) as resp:
            resp.raise_for_status()
            peer_channel = self._peer_channel_json_to_obj(await resp.json())
            self._peer_channel_cache[channel_id] = peer_channel  # cache
            return peer_channel

    async def get_single_peer_channel_cached(self, channel_id: str) -> PeerChannel:
        # NOTE(AustEcon) - if new channel tokens are subsequently generated, you must remember to
        # update this cache
        if self._peer_channel_cache.get(channel_id):
            return self._peer_channel_cache[channel_id]
        else:
            await self.get_single_peer_channel(channel_id)


if __name__ == "__main__":
    async def main() -> None:
        session = aiohttp.ClientSession()
        try:
            BASE_URL = "http://127.0.0.1:47124/"  # ESVReferenceServer
            REGTEST_BEARER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa" \
                                   "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="
            peer_channel_manager = ESVClient(BASE_URL, session, REGTEST_BEARER_TOKEN)

            peer_channel = await peer_channel_manager.create_peer_channel()
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

            list_peer_channels = await peer_channel_manager.list_peer_channels()
            assert isinstance(list_peer_channels, list)
            assert isinstance(list_peer_channels[0], PeerChannel)

            fetched_peer_channel = await peer_channel_manager.get_single_peer_channel(
                peer_channel.channel_id)
            assert isinstance(fetched_peer_channel, PeerChannel)

            result = await peer_channel_manager.delete_peer_channel(peer_channel)
            assert result is None
        finally:
            if session:
                await session.close()

    asyncio.run(main())
