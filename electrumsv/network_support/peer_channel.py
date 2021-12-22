import aiohttp
from aiohttp import web
import asyncio
import base64
from enum import IntFlag
from typing import List, NamedTuple, TypedDict, Union, Dict, Optional, Any


class TokenPermissions(IntFlag):
    NONE = 0
    READ_ACCESS = 1 << 1
    WRITE_ACCESS = 1 << 2


class PeerChannelToken(NamedTuple):
    permissions: TokenPermissions
    api_key: str


ChannelId = str
GenericJSON = Dict[Any, Any]


# NOTE(AustEcon) Many of the following types are copied from the ESVReferenceServer
# msg_box/models.py
class RetentionViewModel(TypedDict):
    min_age_days: int
    max_age_days: int
    auto_prune: bool


class PeerChannelAPITokenViewModelGet(TypedDict):
    id: int
    token: str
    description: str
    can_read: bool
    can_write: bool


class PeerChannelViewModelGet(TypedDict):
    id: str
    href: str
    public_read: bool
    public_write: bool
    sequenced: bool
    locked: bool
    head_sequence: int
    retention: RetentionViewModel
    access_tokens: List[PeerChannelAPITokenViewModelGet]


class APITokenViewModelGet(TypedDict):
    id: str
    token: str
    description: str
    can_read: bool
    can_write: bool


# These are both for json but they represent an
# underlying json vs binary payload
class MessageViewModelGetJSON(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: GenericJSON


class MessageViewModelGetBinary(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: str  # hex


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

    def _get_write_token(self) -> PeerChannelToken:
        for token in self.tokens:
            if token.permissions & TokenPermissions.WRITE_ACCESS == TokenPermissions.WRITE_ACCESS:
                return token
        raise ValueError("Write token not found")

    def _get_read_token(self) -> PeerChannelToken:
        for token in self.tokens:
            if token.permissions & TokenPermissions.READ_ACCESS == TokenPermissions.READ_ACCESS:
                return token
        raise ValueError("Read token not found")

    async def get_messages(self) -> List[MessageViewModelGetBinary]:
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        read_token = self._get_read_token()
        headers = {"Authorization": f"Bearer {read_token.api_key}"}
        async with self.session.get(url, headers=headers) as resp:
            resp.raise_for_status()
            result: List[MessageViewModelGetBinary] = await resp.json()
            return result

    async def get_max_sequence_number(self) -> int:
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        read_token = self._get_read_token()
        headers = {"Authorization": f"Bearer {read_token.api_key}"}
        async with self.session.head(url, headers=headers) as resp:
            resp.raise_for_status()
            return int(resp.headers['ETag'])

    async def write_message(self, message: Union[GenericJSON, bytes],
            mime_type: str="application/octet-stream") \
                -> Union[MessageViewModelGetJSON, MessageViewModelGetBinary]:
        """returns sequence number"""
        url = self.base_url + "api/v1/channel/{channelid}".format(channelid=self.channel_id)
        write_token = self._get_write_token()
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


class PeerChannelManager:

    def __init__(self, base_url: str, session: aiohttp.ClientSession, master_token: str):
        self.base_url = base_url
        self.session = session
        self.master_token = master_token
        self.headers = {"Authorization": f"Bearer {self.master_token}"}

    def _parse_peer_channel_json_to_obj(self, peer_channel_json: PeerChannelViewModelGet) \
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
            return self._parse_peer_channel_json_to_obj(json_response)

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
                peer_channel_obj = self._parse_peer_channel_json_to_obj(peer_channel_json)
                result.append(peer_channel_obj)
            return result

    async def get_single_peer_channel(self, channel_id: str) -> PeerChannel:
        base_url = self.base_url if self.base_url.endswith("/") else self.base_url + "/"
        url = base_url + "api/v1/channel/manage/{channelid}".format(channelid=channel_id)
        async with self.session.get(url, headers=self.headers) as resp:
            resp.raise_for_status()
            return self._parse_peer_channel_json_to_obj(await resp.json())


if __name__ == "__main__":
    async def main() -> None:
        session = aiohttp.ClientSession()
        try:
            BASE_URL = "http://127.0.0.1:47124/"  # ESVReferenceServer
            REGTEST_BEARER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa" \
                                   "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="
            peer_channel_manager = PeerChannelManager(BASE_URL, session, REGTEST_BEARER_TOKEN)

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
