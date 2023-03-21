import base64
import json
import logging
from typing import Any, cast
import unittest.mock
import uuid

from aiohttp import web
from aiohttp import ClientSession
from aiohttp.web_ws import WebSocketResponse
import bitcoinx
from bitcoinx import double_sha256, hash_to_hex_str

from electrumsv.app_state import AppStateProxy
from electrumsv.constants import NetworkServerType, ServerCapability
from electrumsv.network_support.api_server import NewServer
from electrumsv.network_support.types import ChannelNotification, ServerConnectionState, \
    ServerWebsocketNotification, TokenPermissions
from electrumsv.network_support.general_api import unpack_binary_restoration_entry
from electrumsv.network_support.headers import get_batched_headers_by_height_async, \
    get_chain_tips_async, get_single_header_async, HeaderServerState, subscribe_to_headers_async, \
    filter_tips_for_longest_chain
from electrumsv.network_support.peer_channel import create_peer_channel_async, \
    create_peer_channel_api_token_async, create_peer_channel_message_json_async, \
    delete_peer_channel_async, get_peer_channel_max_sequence_number_async, \
    get_peer_channel_async, list_peer_channels_async, list_peer_channel_api_tokens_async, \
    list_peer_channel_messages_async
from electrumsv.types import ServerAccountKey

from .data.reference_server.headers_data import GENESIS_TIP_NOTIFICATION_BINARY, GENESIS_HEADER


logger = logging.getLogger("test-esv-client")

BASE_URL = "/"  # no host or port for aiohttp pytest framework
REGTEST_BEARER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa" \
                       "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="

# Mock Channel
MOCK_CHANNEL_ID = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
permissions: TokenPermissions = cast(TokenPermissions,
    TokenPermissions.WRITE_ACCESS | TokenPermissions.READ_ACCESS)
api_key = base64.urlsafe_b64encode(bytes.fromhex("bb") * 64).decode()
MOCK_GET_TOKEN_RESPONSE = {
    "id": 1,
    "token": api_key,
    "description": "Owner",
    "can_read": True,
    "can_write": True
}
MOCK_CREATE_CHANNEL_REQUEST = {
    'public_read': False,
    'public_write': True,
    'sequenced': True,
    'retention': {
        'min_age_days': 0,
        'max_age_days': 0,
        'auto_prune': True
    },
}
MOCK_CREATE_TOKEN_REQUEST = {
  "description": "custom description",
  "can_read": True,
  "can_write": True
}

PEER_CHANNEL_OBJECT = {
    # It does not really matter what is in here.
    "placeholderNumber": 111,
    "placeholderText": "will this error?",
}

MOCK_MESSAGE = {
    "sequence": 1,
    "received": "2021-12-30T06:33:40.374Z",
    "content_type": "application/json",
    "payload": PEER_CHANNEL_OBJECT
}


def _make_mock_channel_json(channel_id: str, host: str, port: int, access_token: str):
    return {
        "id": channel_id,
        "href": f"http://{host}:{port}/api/v1/channel/{channel_id}",
        "public_read": True,
        "public_write": True,
        "sequenced": True,
        "locked": False,
        "head_sequence": 0,
        "retention":
            {
                "min_age_days": 0,
                "max_age_days": 0,
                "auto_prune": 1
            },
        "access_tokens": [
            {
                "id": 1,
                "token": access_token,
                "description": "Owner",
                "can_read": True,
                "can_write": True
            }
        ]
    }


CREDENTIAL_ID = uuid.uuid4()

def _get_server_state(test_session: ClientSession) -> ServerConnectionState:
    # All the `None` fields are unsupported at this time.
    mock_server = unittest.mock.Mock()
    mock_server.url = BASE_URL
    server = cast(NewServer, mock_server)
    return ServerConnectionState(
        1,
        { ServerCapability.PEER_CHANNELS, ServerCapability.TIP_FILTER },
        wallet_proxy=None,
        wallet_data=None,
        session=test_session,
        server=server,
        peer_channel_message_queue=None,
        output_spend_result_queue=None,
        output_spend_registration_queue=None,
        credential_id=CREDENTIAL_ID)


# ----- Mock Handlers BEGIN ----- #
async def mock_get_single_header(request: web.Request):
    try:
        accept_type = request.headers.get('Accept', 'application/json')
        assert accept_type == 'application/octet-stream'
        blockhash = request.match_info.get('hash')
        assert blockhash == hash_to_hex_str(bytes.fromhex("deadbeef"))

        raw_header = bytes.fromhex("aa"*80)
        return web.Response(body=raw_header)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_get_batched_headers_by_height(request: web.Request):
    try:
        accept_type = request.headers.get('Accept', 'application/json')
        assert accept_type == 'application/octet-stream'
        params = request.rel_url.query
        height = params['height']
        assert int(height) == 0
        count = params['count']
        assert int(count) == 2
        headers = bytearray()
        headers += bytes.fromhex("aa" * 80)
        headers += bytes.fromhex("bb" * 80)
        return web.Response(body=headers)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_get_chain_tips(request: web.Request):
    try:
        accept_type = request.headers.get('Accept')
        assert accept_type == 'application/octet-stream'
        headers_array = GENESIS_HEADER + bitcoinx.pack_le_int32(0)
        return web.Response(body=headers_array, content_type='application/octet-stream')
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_headers_websocket(request: web.Request) -> WebSocketResponse:
    """The communication for this is one-way - for header notifications only.
    Client messages will be ignored"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    try:
        await ws.send_bytes(GENESIS_TIP_NOTIFICATION_BINARY)
        return ws
    finally:
        if not ws.closed:
            await ws.close()


async def mock_general_websocket(request: web.Request) -> WebSocketResponse:
    """The communication for this is one-way - for header notifications only.
    Client messages will be ignored"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    try:
        result = ChannelNotification(id=MOCK_CHANNEL_ID, notification="New message arrived")
        notification = ServerWebsocketNotification(message_type="bsv.api.channels.notification",
            result=result)
        await ws.send_json(notification)
        return ws
    finally:
        if not ws.closed:
            await ws.close()


async def mock_create_peer_channel(request: web.Request) -> web.Response:
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

        body_content = await request.json()
        assert body_content == MOCK_CREATE_CHANNEL_REQUEST
        response_data = _make_mock_channel_json(MOCK_CHANNEL_ID, request.url.host,
            request.url.port, api_key)
        return web.json_response(response_data)
    except AssertionError as e:
        logger.error("!QQQQQ '%s'", str(e))
        raise web.HTTPBadRequest(reason=str(e))


async def mock_delete_peer_channel(request: web.Request) -> web.Response:
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id
        raise web.HTTPNoContent()
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_list_peer_channels(request: web.Request) -> web.Response:
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"
        response = [
            _make_mock_channel_json(MOCK_CHANNEL_ID, request.url.host, request.url.port,
                api_key)
        ]
        return web.json_response(response)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_get_single_peer_channel(request: web.Request) -> web.Response:
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"
        response = _make_mock_channel_json(MOCK_CHANNEL_ID, request.url.host, request.url.port,
            api_key)
        return web.json_response(response)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_get_messages(request: web.Request) -> web.Response:
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {api_key}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id
        if request.method.upper() == 'HEAD':
            max_sequence = 1
            response_headers = {}
            response_headers.update({'Access-Control-Expose-Headers': 'authorization,etag'})
            response_headers.update({'ETag': str(max_sequence)})
            raise web.HTTPOk(headers=response_headers)
        else:
            return web.json_response([MOCK_MESSAGE])
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_write_message(request: web.Request) -> web.Response:
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {api_key}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id

        request_body = await request.text()
        assert request_body == json.dumps(PEER_CHANNEL_OBJECT, separators=(",", ":"))

        response_json = {
            "sequence": 1,
            "received": "2021-12-30T07:02:15.159Z",
            "content_type": "application/json",
            "payload": PEER_CHANNEL_OBJECT
        }
        return web.json_response(response_json)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_create_token(request: web.Request) -> web.Response:
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id

        request_body = await request.json()
        assert request_body == MOCK_CREATE_TOKEN_REQUEST

        return web.json_response(MOCK_GET_TOKEN_RESPONSE)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_list_api_tokens(request: web.Request) -> web.Response:
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id

        return web.json_response([MOCK_GET_TOKEN_RESPONSE])
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))

# ----- Mock Handlers END ----- #



def create_app() -> web.Application:
    app = web.Application()
    app.add_routes([
        web.get("/api/v1/web-socket", mock_general_websocket),

        # Headers
        web.get("/api/v1/headers/by-height", mock_get_batched_headers_by_height),
        web.get("/api/v1/headers/tips", mock_get_chain_tips),
        web.get("/api/v1/headers/{hash}", mock_get_single_header),
        web.get("/api/v1/headers/tips/websocket", mock_headers_websocket),

        # Peer Channel Management APIs
        web.post("/api/v1/channel/manage", mock_create_peer_channel),
        web.delete("/api/v1/channel/manage/{channelid}", mock_delete_peer_channel),
        web.get("/api/v1/channel/manage/list", mock_list_peer_channels),
        web.get("/api/v1/channel/manage/{channelid}", mock_get_single_peer_channel),

        # Token Management APIs
        web.post("/api/v1/channel/manage/{channelid}/api-token", mock_create_token),
        web.get("/api/v1/channel/manage/{channelid}/api-token", mock_list_api_tokens),

        # Individual Peer Channel APIs
        web.get("/api/v1/channel/{channelid}", mock_get_messages),
        web.post("/api/v1/channel/{channelid}", mock_write_message)
    ])
    return app


@unittest.mock.patch('electrumsv.network_support.general_api.app_state')
async def test_get_single_header_async(mock_app_state: AppStateProxy, aiohttp_client):
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = HeaderServerState(ServerAccountKey(BASE_URL, NetworkServerType.GENERAL, None), None)
    result = await get_single_header_async(state, test_session,
        block_hash=bytes.fromhex('deadbeef'))
    assert result == bytes.fromhex("aa"*80)


@unittest.mock.patch('electrumsv.network_support.general_api.app_state')
async def test_get_batched_headers_by_height(mock_app_state: AppStateProxy, aiohttp_client):
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = HeaderServerState(ServerAccountKey(BASE_URL, NetworkServerType.GENERAL, None), None)
    result = await get_batched_headers_by_height_async(state, test_session, from_height=0, count=2)
    assert result == bytes.fromhex("aa"*80) + bytes.fromhex("bb"*80)


@unittest.mock.patch('electrumsv.network_support.general_api.app_state')
async def test_get_chain_tips(mock_app_state: AppStateProxy, aiohttp_client):
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    bitcoinx.unpack_header(GENESIS_HEADER)

    expected_response = bitcoinx.Header(*bitcoinx.unpack_header(GENESIS_HEADER),
        hash=double_sha256(GENESIS_HEADER), raw=GENESIS_HEADER, height=0)
    test_session = await aiohttp_client(create_app())
    state = HeaderServerState(ServerAccountKey(BASE_URL, NetworkServerType.GENERAL, None), None)
    tip_headers = await get_chain_tips_async(state, test_session)
    tip_header = filter_tips_for_longest_chain(tip_headers)
    assert tip_header == expected_response
    assert tip_header.height == 0
    assert tip_header.raw == GENESIS_HEADER


@unittest.mock.patch('electrumsv.network_support.general_api.app_state')
async def test_subscribe_to_headers(mock_app_state: AppStateProxy, aiohttp_client):
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = HeaderServerState(ServerAccountKey(BASE_URL, NetworkServerType.GENERAL, None), None)
    async for tip in subscribe_to_headers_async(state, test_session):
        if tip:
            logger.debug(tip)
            assert True
            return


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_create_peer_channel_async(mock_app_state: AppStateProxy, aiohttp_client) -> None:
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_data = await create_peer_channel_async(state)
    assert isinstance(peer_channel_data, dict)


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_delete_peer_channel_async(mock_app_state: AppStateProxy, aiohttp_client) -> None:
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    await delete_peer_channel_async(state, MOCK_CHANNEL_ID)


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_list_peer_channels_async(mock_app_state: AppStateProxy, aiohttp_client):
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_jsons = await list_peer_channels_async(state)
    assert isinstance(peer_channel_jsons, list)
    for peer_channel_json in peer_channel_jsons:
        assert peer_channel_json["id"] == MOCK_CHANNEL_ID
        assert peer_channel_json["access_tokens"] == [ MOCK_GET_TOKEN_RESPONSE ]


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_get_peer_channel_async(mock_app_state: AppStateProxy, aiohttp_client):
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_data = await get_peer_channel_async(state, MOCK_CHANNEL_ID)
    assert peer_channel_data["id"] == MOCK_CHANNEL_ID
    assert peer_channel_data["access_tokens"] == [ MOCK_GET_TOKEN_RESPONSE ]


# Test PeerChannel class
@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_peer_channel_instance_attrs(mock_app_state: AppStateProxy, aiohttp_client):
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    # All http endpoints are all mocked so that tests execute fast and they are hassle-free to run
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_data = await create_peer_channel_async(state)
    assert peer_channel_data["id"] == MOCK_CHANNEL_ID
    assert peer_channel_data["access_tokens"] == [ MOCK_GET_TOKEN_RESPONSE ]


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_list_peer_channel_messages_async(mock_app_state: AppStateProxy, aiohttp_client) \
        -> None:
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_data = await create_peer_channel_async(state)
    access_token_data = peer_channel_data["access_tokens"][0]
    message_datas = await list_peer_channel_messages_async(state, peer_channel_data["id"],
        access_token_data["token"])
    assert len(message_datas) == 1
    assert message_datas[0]['sequence'] == 1
    assert message_datas[0]['received'] == '2021-12-30T06:33:40.374Z'
    assert message_datas[0]['content_type'] == 'application/json'
    assert message_datas[0]['payload'] == PEER_CHANNEL_OBJECT
    logger.debug("messages=%s", message_datas)


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_get_peer_channel_max_sequence_number_async(mock_app_state: AppStateProxy,
        aiohttp_client) -> None:
    mock_app_state.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_data = await create_peer_channel_async(state)
    access_token_data = peer_channel_data["access_tokens"][0]
    seq = await get_peer_channel_max_sequence_number_async(state, peer_channel_data["id"],
        access_token_data["token"])
    assert isinstance(seq, int)
    logger.debug("seq=%d", seq)


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_create_peer_channel_message_json_async(mock_app_state1: AppStateProxy,
        aiohttp_client) -> None:
    mock_app_state1.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_data = await create_peer_channel_async(state)
    message = await create_peer_channel_message_json_async(state, peer_channel_data["id"],
        peer_channel_data["access_tokens"][0]["token"],
        message=cast(dict[str, Any], PEER_CHANNEL_OBJECT))
    assert isinstance(message, dict)
    assert message['sequence'] == 1
    # assert message['received']  # datetime.now()
    assert message['content_type'] == 'application/json'
    assert message['payload'] == PEER_CHANNEL_OBJECT
    logger.debug("written message info=%s", message)


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_create_peer_channel_api_token_async(mock_app_state1: AppStateProxy,
        aiohttp_client) -> None:
    mock_app_state1.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_data = await create_peer_channel_async(state)
    token_json = await create_peer_channel_api_token_async(state,
        peer_channel_data["id"], description="custom description")
    assert isinstance(token_json["token"], str)
    logger.debug("api_token=%s", token_json)


@unittest.mock.patch('electrumsv.network_support.peer_channel.app_state')
async def test_list_peer_channel_api_tokens_async(mock_app_state1: AppStateProxy,
        aiohttp_client) -> None:
    mock_app_state1.credentials.get_indefinite_credential = lambda *args: REGTEST_BEARER_TOKEN
    test_session = await aiohttp_client(create_app())
    state = _get_server_state(test_session)
    peer_channel_data = await create_peer_channel_async(state)
    access_tokens_data = await list_peer_channel_api_tokens_async(state, peer_channel_data["id"])
    assert access_tokens_data == peer_channel_data["access_tokens"]
    logger.debug("api_tokens=%s", access_tokens_data)



BINARY_RESTORATION_RESPONSE = bytes.fromhex(
    "0186c73b803ee5229044621b2fb6fb61b7001a92cbfdab1c7314da27a2fee72948fd57f50c35251a260a0317a4"
    "975579047e89f5544d9a8841f10b3c9d4b73024600000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000")

MATCH_FLAGS = 1
PUSHDATA_HASH = bytes.fromhex('86c73b803ee5229044621b2fb6fb61b7001a92cbfdab1c7314da27a2fee72948')
TRANSACTION_HASH = bytes.fromhex('fd57f50c35251a260a0317a4975579047e89f5544d9a8841f10b3c9d4b730246')
SPEND_TRANSACTION_HASH = b"\0" * 32
TRANSACTION_OUTPUT_INDEX = 0
SPEND_INPUT_INDEX = 0

def test_unpack_binary_restoration_entry() -> None:
    result = unpack_binary_restoration_entry(BINARY_RESTORATION_RESPONSE)
    assert result.flags == MATCH_FLAGS
    assert result.push_data_hash == PUSHDATA_HASH
    assert result.locking_transaction_hash == TRANSACTION_HASH
    assert result.locking_output_index == TRANSACTION_OUTPUT_INDEX
    assert result.unlocking_transaction_hash == SPEND_TRANSACTION_HASH
    assert result.unlocking_input_index == SPEND_INPUT_INDEX
