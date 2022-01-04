import base64
import json
import logging
from typing import cast

import pytest
from aiohttp import web, ClientResponseError
from aiohttp import ClientSession
from aiohttp.web_ws import WebSocketResponse
from bitcoinx import hash_to_hex_str

from electrumsv.network_support.esv_client import ESVClient, PeerChannel
from electrumsv.network_support.esv_client_types import PeerChannelToken, TokenPermissions, \
    GeneralNotification, ChannelNotification, MAPICallbackResponse
from electrumsv.tests.data.reference_server.headers_data import GENESIS_TIP

logger = logging.getLogger("test-esv-client")

BASE_URL = "/"  # no host or port for aiohttp pytest framework
REGTEST_BEARER_TOKEN = "t80Dp_dIk1kqkHK3P9R5cpDf67JfmNixNscexEYG0_xa" \
                       "CbYXKGNm4V_2HKr68ES5bytZ8F19IS0XbJlq41accQ=="

# Mock Channel
MOCK_CHANNEL_ID = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
permissions: TokenPermissions = cast(TokenPermissions,
    TokenPermissions.WRITE_ACCESS | TokenPermissions.READ_ACCESS)
api_key = base64.urlsafe_b64encode(bytes.fromhex("bb") * 64).decode()
MOCK_TOKENS = [PeerChannelToken(permissions=permissions, api_key=api_key)]
MOCK_CREATE_CHANNEL_REQUEST = {
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
MOCK_CREATE_TOKEN_REQUEST = {
  "description": "custom description",
  "can_read": True,
  "can_write": True
}
MOCK_GET_TOKEN_RESPONSE = {
    "id": 0,
    "token": MOCK_TOKENS[0].api_key,
    "description": "string",
    "can_read": True,
    "can_write": True
}

MERKLE_PROOF_CALLBACK_PAYLOAD = '{"flags":2,"index":1,"txOrId":"acad8d40b3a17117026ace82ef56d269283753d310ddaeabe7b5d226e8dbe973","target":{"hash":"0e9a2af27919b30a066383d512d64d4569590f935007198dacad9824af643177","confirmations":1,"height":152,"version":536870912,"versionHex":"20000000","merkleroot":"0298acf415976238163cd82b9aab9826fb8fbfbbf438e55185a668d97bf721a8","num_tx":2,"time":1604409778,"mediantime":1604409777,"nonce":0,"bits":"207fffff","difficulty":4.656542373906925e-10,"chainwork":"0000000000000000000000000000000000000000000000000000000000000132","previousblockhash":"62ae67b463764d045f4cbe54f1f7eb63ccf70d52647981ffdfde43ca4979a8ee"},"nodes":["5b537f8fba7b4057971f7e904794c59913d9a9038e6900669d08c1cf0cc48133"]}'
MERKLE_PROOF_CALLBACK: MAPICallbackResponse = {
    "callbackPayload": MERKLE_PROOF_CALLBACK_PAYLOAD,
    "apiVersion": "1.4.0",
    "timestamp": "2021-11-03T13:22:42.1341243Z",
    "minerId": "030d1fe5c1b560efe196ba40540ce9017c20daa9504c4c4cec6184fc702d9f274e",
    "blockHash": "0e9a2af27919b30a066383d512d64d4569590f935007198dacad9824af643177",
    "blockHeight": 152,
    "callbackTxId": "acad8d40b3a17117026ace82ef56d269283753d310ddaeabe7b5d226e8dbe973",
    "callbackReason": "merkleProof"
}
MOCK_MESSAGE = {
    "sequence": 1,
    "received": "2021-12-30T06:33:40.374Z",
    "content_type": "application/json",
    "payload": MERKLE_PROOF_CALLBACK
}



def _make_mock_channel_json(channel_id: str, host: str, port: int, tokens: list[PeerChannelToken]):
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
                "token": tokens[0].api_key,
                "description": "Owner",
                "can_read": True,
                "can_write": True
            }
        ]
    }


async def _create_peer_channel_instance(test_client) -> PeerChannel:
    test_session = await test_client(create_app)
    esv_client: ESVClient = await _get_esv_client(test_session)
    peer_channel: PeerChannel = await esv_client.create_peer_channel()
    return peer_channel


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
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

        body_content = await request.json()
        assert body_content == MOCK_CREATE_CHANNEL_REQUEST
        response_data = _make_mock_channel_json(MOCK_CHANNEL_ID, request.url.host,
            request.url.port, MOCK_TOKENS)
        return web.json_response(response_data)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_delete_peer_channel(request: web.Request):
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id
        return web.HTTPNoContent()
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_list_peer_channels(request: web.Request):
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"
        response = [
            _make_mock_channel_json(MOCK_CHANNEL_ID, request.url.host, request.url.port, MOCK_TOKENS)
        ]
        return web.json_response(response)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_get_single_peer_channel(request: web.Request):
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"
        response = _make_mock_channel_json(MOCK_CHANNEL_ID, request.url.host, request.url.port,
            MOCK_TOKENS)
        return web.json_response(response)
    except AssertionError as e:
        raise web.HTTPBadRequest(reason=str(e))


async def mock_get_messages(request: web.Request):
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {MOCK_TOKENS[0].api_key}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id
        if request.method.upper() == 'HEAD':
            max_sequence = 1
            response_headers = {}
            response_headers.update({'Access-Control-Expose-Headers': 'authorization,etag'})
            response_headers.update({'ETag': str(max_sequence)})
            return web.HTTPOk(headers=response_headers)
        else:
            return web.json_response([MOCK_MESSAGE])
    except AssertionError as e:
        return web.HTTPBadRequest(reason=str(e))


async def mock_write_message(request: web.Request):
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {MOCK_TOKENS[0].api_key}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id

        request_body = await request.text()
        assert request_body == json.dumps(MERKLE_PROOF_CALLBACK, separators=(",", ":"))

        response_json = {
            "sequence": 1,
            "received": "2021-12-30T07:02:15.159Z",
            "content_type": "application/json",
            "payload": MERKLE_PROOF_CALLBACK
        }
        return web.json_response(response_json)
    except AssertionError as e:
        return web.HTTPBadRequest(reason=str(e))


async def mock_create_token(request: web.Request):
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
        return web.HTTPBadRequest(reason=str(e))


async def mock_list_api_tokens(request: web.Request):
    try:
        auth_string = request.headers.get('Authorization', None)
        assert auth_string == f"Bearer {REGTEST_BEARER_TOKEN}"

        channel_id = request.match_info['channelid']
        mock_channel_id = base64.urlsafe_b64encode(bytes.fromhex("aa") * 64).decode()
        assert channel_id == mock_channel_id

        return web.json_response([MOCK_GET_TOKEN_RESPONSE])
    except AssertionError as e:
        return web.HTTPBadRequest(reason=str(e))

# ----- Mock Handlers END ----- #



def create_app(loop):
    app = web.Application(loop=loop)
    app.add_routes([
        web.get("/api/v1/web-socket", mock_general_websocket),

        # Headers
        web.get("/api/v1/headers/by-height", mock_get_headers_by_height),
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


# Test PeerChannel class
async def test_peer_channel_instance_attrs(test_client):
    # All http endpoints are all mocked so that tests execute fast and they are hassle-free to run
    try:
        peer_channel = await _create_peer_channel_instance(test_client)
        assert isinstance(peer_channel, PeerChannel)
        assert peer_channel.channel_id == MOCK_CHANNEL_ID
        assert peer_channel.tokens == MOCK_TOKENS
        callback_url = peer_channel.get_callback_url()
        assert MOCK_CHANNEL_ID in callback_url
        logger.debug(f"callback_url={callback_url}")
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_peer_channel_instance_get_write_token(test_client):
    try:
        peer_channel = await _create_peer_channel_instance(test_client)
        write_token = peer_channel.get_write_token()
        assert isinstance(write_token, PeerChannelToken)
        assert write_token.permissions & TokenPermissions.WRITE_ACCESS \
               == TokenPermissions.WRITE_ACCESS
        logger.debug(f"write_token={write_token}")
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_peer_channel_instance_get_read_token(test_client):
    try:
        peer_channel = await _create_peer_channel_instance(test_client)
        read_token = peer_channel.get_read_token()
        assert isinstance(read_token, PeerChannelToken)
        assert read_token.permissions & TokenPermissions.READ_ACCESS \
               == TokenPermissions.READ_ACCESS
        logger.debug(f"read_token={read_token}")
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_peer_channel_instance_get_messages(test_client):
    try:
        peer_channel = await _create_peer_channel_instance(test_client)
        messages = await peer_channel.get_messages()
        assert len(messages) == 1
        assert messages[0]['sequence'] == 1
        assert messages[0]['received'] == '2021-12-30T06:33:40.374Z'
        assert messages[0]['content_type'] == 'application/json'
        assert messages[0]['payload'] == MERKLE_PROOF_CALLBACK
        logger.debug(f"messages={messages}")
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_peer_channel_instance_get_max_sequence_number(test_client):
    try:
        peer_channel = await _create_peer_channel_instance(test_client)
        seq = await peer_channel.get_max_sequence_number()
        assert isinstance(seq, int)
        logger.debug(f"seq={seq}")
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_peer_channel_instance_write_message(test_client):
    try:
        peer_channel = await _create_peer_channel_instance(test_client)
        message = await peer_channel.write_message(message=MERKLE_PROOF_CALLBACK,
            mime_type='application/json')
        assert isinstance(message, dict)
        assert message['sequence'] == 1
        # assert message['received']  # datetime.now()
        assert message['content_type'] == 'application/json'
        assert message['payload'] == MERKLE_PROOF_CALLBACK
        logger.debug(f"written message info={message}")
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_peer_channel_instance_create_api_token(test_client):
    try:
        peer_channel = await _create_peer_channel_instance(test_client)
        api_token: PeerChannelToken = await peer_channel.create_api_token(
            description="custom description")
        assert isinstance(api_token.api_key, str)
        assert isinstance(api_token.permissions, TokenPermissions)
        logger.debug(f"api_token={api_token}")
    except ClientResponseError as e:
        raise pytest.fail(str(e))


async def test_peer_channel_instance_list_api_tokens(test_client):
    try:
        peer_channel = await _create_peer_channel_instance(test_client)
        api_tokens: list[PeerChannelToken] = await peer_channel.list_api_tokens()
        for api_token in api_tokens:
            assert isinstance(api_token.api_key, str)
            assert isinstance(api_token.permissions, TokenPermissions)
        logger.debug(f"api_tokens={api_tokens}")
    except ClientResponseError as e:
        raise pytest.fail(str(e))
