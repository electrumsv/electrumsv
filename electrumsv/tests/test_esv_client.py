import base64
import logging
from typing import cast

import pytest
from aiohttp import web, ClientResponseError
from aiohttp import ClientSession
from aiohttp.web_ws import WebSocketResponse
from bitcoinx import hash_to_hex_str

from electrumsv.network_support.esv_client import ESVClient, PeerChannel
from electrumsv.network_support.esv_client_types import PeerChannelToken, TokenPermissions, \
    GeneralNotification, ChannelNotification
from electrumsv.tests.data.reference_server.headers_data import GENESIS_TIP

logger = logging.getLogger("test-esv-client")
logging.basicConfig(format='%(asctime)s %(levelname)-8s %(name)-24s %(message)s',
    level=logging.DEBUG, datefmt='%Y-%m-%d %H:%M:%S')

BASE_URL = "/"  # no host or port for aiohttp pytest framework
REGTEST_BEARER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa" \
                       "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="

# Mock Channel
MOCK_CHANNEL_ID = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
permissions: TokenPermissions = cast(TokenPermissions,
    TokenPermissions.WRITE_ACCESS | TokenPermissions.READ_ACCESS)
api_key = base64.urlsafe_b64encode(bytes.fromhex("bb") * 64).decode()
MOCK_TOKENS = [PeerChannelToken(permissions=permissions, api_key=api_key)]


async def _get_esv_client(test_session: ClientSession) -> ESVClient:
    esv_client = ESVClient(BASE_URL, test_session, REGTEST_BEARER_TOKEN)
    return esv_client


# ----- Mock Handlers BEGIN ----- #
async def mock_get_single_header(request: web.Request):
    try:
        print(f"Called get_single_header")
        accept_type = request.headers.get('Accept', 'application/json')
        assert accept_type == 'application/octet-stream'
        blockhash = request.match_info.get('hash')
        assert blockhash == hash_to_hex_str(bytes.fromhex("deadbeef"))

        raw_header = bytes.fromhex("aa"*80)
        return web.Response(body=raw_header)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_get_headers_by_height(request: web.Request):
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
        assert accept_type != 'application/octet-stream'
        tips = [GENESIS_TIP]
        return web.json_response(tips)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_headers_websocket(request: web.Request) -> WebSocketResponse:
    """The communication for this is one-way - for header notifications only.
    Client messages will be ignored"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    try:
        await ws.send_json(GENESIS_TIP)
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
        notification = GeneralNotification(message_type="bsv.api.channels.notification",
            result=result)
        await ws.send_json(notification)
        return ws
    finally:
        if not ws.closed:
            await ws.close()


async def mock_create_peer_channel(request: web.Request):
    auth_string = request.headers.get('Authorization', None)
    assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

    body_content = await request.json()
    assert body_content == {
        'public_read': True,
        'public_write': True,
        'sequenced': True,
        'retention':
            {
                'min_age_days': 0,
                'max_age_days': 0,
                'auto_prune': True
            }
    }
    response_body = {
        "id": "uHx2GOPwn3FYny_JhVp1bq5KeL0HRwE55HZStGhXGomIh39QDN0b-lA6BJGVtpVtethc6anExXLdvJ7gRmeceg==",
        "href": "http://127.0.0.1:47124/api/v1/channel/uHx2GOPwn3FYny_JhVp1bq5KeL0HRwE55HZStGhXGomIh39QDN0b-lA6BJGVtpVtethc6anExXLdvJ7gRmeceg==",
        "public_read": True,
        "public_write": True,
        "sequenced": True,
        "locked": False,
        "head_sequence": 0,
        "retention": {
            "min_age_days": 0,
            "max_age_days": 0,
            "auto_prune": 1
        },
        "access_tokens": [
            {
                "id": 1,
                "token": "xUzNwBxIMXy78si7G7aKEgoWRYtmtHFOwJ3whcafirQ_M90R2FNENk2Vh8chcM3OpO9awTOLun7V8EgrSj6nJg==",
                "description": "Owner",
                "can_read": True,
                "can_write": True
            }
        ]
    }
    return web.json_response(response_body)


async def mock_delete_peer_channel(request: web.Request):
    auth_string = request.headers.get('Authorization', None)
    assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

    channel_id = request.match_info['channelid']
    mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
    assert channel_id == mock_channel_id
    return web.HTTPNoContent()


async def mock_list_peer_channels(request: web.Request):
    auth_string = request.headers.get('Authorization', None)
    assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"
    response = [
        {
            "id": MOCK_CHANNEL_ID,
            "href": f"http://{request.url.host}:{request.url.port}/api/v1/channel/{MOCK_CHANNEL_ID}",
            "public_read": True,
            "public_write": True,
            "sequenced": True,
            "locked": False,
            "head_sequence": 0,
            "retention": {
                "min_age_days": 0,
                "max_age_days": 0,
                "auto_prune": 1
            },
            "access_tokens": [
                {
                    "id": 1,
                    "token": MOCK_TOKENS[0].api_key,
                    "description": "Owner",
                    "can_read": True,
                    "can_write": True
                }
            ]
        }
    ]
    return web.json_response(response)


async def mock_get_single_peer_channel(request: web.Request):
    auth_string = request.headers.get('Authorization', None)
    assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"
    response = {
        "id": MOCK_CHANNEL_ID,
        "href": f"http://{request.url.host}:{request.url.port}/api/v1/channel/{MOCK_CHANNEL_ID}",
        "public_read": True,
        "public_write": True,
        "sequenced": True,
        "locked": False,
        "head_sequence": 0,
        "retention": {
            "min_age_days": 0,
            "max_age_days": 0,
            "auto_prune": 1
        },
        "access_tokens": [
            {
                "id": 1,
                "token": MOCK_TOKENS[0].api_key,
                "description": "Owner",
                "can_read": True,
                "can_write": True
            }
        ]
    }
    return web.json_response(response)
# ----- Mock Handlers END ----- #



def create_app(loop):
    app = web.Application(loop=loop)
    app.add_routes([
        web.get("/api/v1/web-socket", mock_general_websocket),

        # Headers
        web.get("/api/v1/headers/by-height", mock_get_headers_by_height),
        web.get("/api/v1/headers/tips", mock_get_chain_tips),
        web.get("/api/v1/headers/{hash}", mock_get_single_header),
        web.view("/api/v1/headers/tips/websocket", mock_headers_websocket),

        # Peer Channels
        web.post("/api/v1/channel/manage", mock_create_peer_channel),
        web.delete("/api/v1/channel/manage/{channelid}", mock_delete_peer_channel),
        web.get("/api/v1/channel/manage/list", mock_list_peer_channels),
        web.get("/api/v1/channel/manage/{channelid}", mock_get_single_peer_channel),
    ])
    return app


async def test_get_single_header(test_client):
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        result = await esv_client.get_single_header(block_hash=bytes.fromhex('deadbeef'))
        assert result == bytes.fromhex("aa"*80)
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_get_headers_by_height(test_client):
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        result = await esv_client.get_headers_by_height(from_height=0, count=2)
        assert result == bytes.fromhex("aa"*80) + bytes.fromhex("bb"*80)
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_get_chain_tips(test_client):
    expected_response = [GENESIS_TIP]
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        result = await esv_client.get_chain_tips()
        assert result == expected_response
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_subscribe_to_headers(test_client):
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        async for tip in esv_client.subscribe_to_headers():
            if tip:
                logger.debug(tip)
                assert True
                return
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_create_peer_channel(test_client):
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        peer_channel: PeerChannel = await esv_client.create_peer_channel()
        assert isinstance(peer_channel, PeerChannel)
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_delete_peer_channel(test_client):
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        # Setup Channel for deletion
        peer_channel = PeerChannel(channel_id=MOCK_CHANNEL_ID, tokens=MOCK_TOKENS,
            base_url=BASE_URL, session=test_session, master_token=REGTEST_BEARER_TOKEN)
        await esv_client.delete_peer_channel(peer_channel)
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_list_peer_channels(test_client):
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        peer_channels = await esv_client.list_peer_channels()
        assert isinstance(peer_channels, list)
        for peer_channel in peer_channels:
            assert isinstance(peer_channel, PeerChannel)
            assert peer_channel.channel_id == MOCK_CHANNEL_ID
            assert peer_channel.tokens == MOCK_TOKENS
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_get_single_peer_channel(test_client):
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        peer_channel = await esv_client.get_single_peer_channel(MOCK_CHANNEL_ID)
        assert isinstance(peer_channel, PeerChannel)
        assert peer_channel.channel_id == MOCK_CHANNEL_ID
        assert peer_channel.tokens == MOCK_TOKENS
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_subscribe_to_general_notifications(test_client):
    try:
        test_session = await test_client(create_app)
        esv_client: ESVClient = await _get_esv_client(test_session)
        notification: GeneralNotification
        async for notification in esv_client.subscribe_to_general_notifications():
            if notification:
                assert notification['message_type'] == 'bsv.api.channels.notification'
                assert notification['result']['id'] == MOCK_CHANNEL_ID
                assert notification['result']['notification'] == 'New message arrived'
                return
    except ClientResponseError as e:
        raise pytest.fail(str(e))
