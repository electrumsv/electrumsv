# # TODO Add tests for

from __future__ import annotations
import asyncio
from http import HTTPStatus
import json
import os
from typing import TYPE_CHECKING
import unittest.mock

import aiohttp
from aiohttp.test_utils import TestClient
from aiohttp import web
import pytest

from electrumsv.app_state import AppStateProxy
from electrumsv import nodeapi

if TYPE_CHECKING:
    from electrumsv.wallet import Wallet


@pytest.fixture
def server_tester(event_loop, aiohttp_client):
    """mock client - see: https://docs.aiohttp.org/en/stable/client_quickstart.html"""
    web_application = web.Application()
    mock_server = unittest.mock.Mock()
    web_application["server"] = mock_server
    nodeapi.setup_web_application(web_application)
    return event_loop.run_until_complete(aiohttp_client(web_application))


@unittest.mock.patch('electrumsv.nodeapi.app_state')
def test_get_wallet_from_request_implicit_fail_none(app_state_nodeapi: AppStateProxy) -> None:
    # Expectation: The user is using the implicit single loaded wallet API.
    # Expectation: There are no wallets loaded and none to choose.
    mock_request = unittest.mock.Mock()
    mock_request.match_info.get.side_effect = lambda *args: None

    app_state_nodeapi.daemon.wallets = {}
    wallet = nodeapi.get_wallet_from_request(mock_request, 444)
    assert wallet is None

@unittest.mock.patch('electrumsv.nodeapi.app_state')
def test_get_wallet_from_request_implicit_fail_many(app_state_nodeapi: AppStateProxy) -> None:
    # Expectation: The user is using the implicit single loaded wallet API.
    # Expectation: There are too many wallets loaded to choose one.
    mock_request = unittest.mock.Mock()
    mock_request.match_info.get.side_effect = lambda *args: None

    wallets: dict[str, Wallet] = {}
    for i in range(2):
        irrelevant_path = os.urandom(32).hex()
        wallets[irrelevant_path] = unittest.mock.Mock()
    app_state_nodeapi.daemon.wallets = wallets

    wallet = nodeapi.get_wallet_from_request(mock_request, 444)
    assert wallet is None

@unittest.mock.patch('electrumsv.nodeapi.app_state')
def test_get_wallet_from_request_implicit_success(app_state_nodeapi: AppStateProxy) -> None:
    # Expectation: The user is using the implicit single loaded wallet API.
    # Expectation: With only one wallet loaded it will be found.
    mock_request = unittest.mock.Mock()
    mock_request.match_info.get.side_effect = lambda *args: None

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallets[irrelevant_path] = unittest.mock.Mock()
    app_state_nodeapi.daemon.wallets = wallets

    wallet = nodeapi.get_wallet_from_request(mock_request, 444)
    assert wallet is wallets[irrelevant_path]

@unittest.mock.patch('electrumsv.nodeapi.app_state')
def test_get_wallet_from_request_explicit_fail_no_path(app_state_nodeapi: AppStateProxy) -> None:
    # Expectation: The user is using the explicit named loaded wallet API.
    # Expectation: The case where ElectrumSV has an invalid data directory is checked.
    mock_request = unittest.mock.Mock()
    mock_request.match_info.get.side_effect = lambda *args: "my_wallet"

    def dummy_get_path() -> str:
        raise FileNotFoundError()
    app_state_nodeapi.config.get_preferred_wallet_dirpath.side_effect = dummy_get_path

    with pytest.raises(web.HTTPInternalServerError) as exception_value:
        nodeapi.get_wallet_from_request(mock_request, 444)
    response = exception_value.value
    assert isinstance(response.body, bytes)
    object = json.loads(response.body)
    assert len(object) == 3
    assert object["id"] == 444
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -18
    assert object["error"]["message"] == "No preferred wallet path"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
def test_get_wallet_from_request_explicit_success(app_state_nodeapi: AppStateProxy) -> None:
    # Expectation: The user is using the explicit named loaded wallet API.
    # Expectation: The case where the file name is not matched.
    mock_request = unittest.mock.Mock()
    mock_request.match_info.get.side_effect = lambda *args: "my_wallet"

    dummy_wallet = unittest.mock.Mock()
    expected_path = os.path.join("leading_path", "my_wallet")

    def dummy_get_path() -> str:
        return "leading_path"
    app_state_nodeapi.config.get_preferred_wallet_dirpath.side_effect = dummy_get_path
    def dummy_get_wallet(file_name: str) -> Wallet | None:
        nonlocal dummy_wallet
        if file_name == expected_path:
            return dummy_wallet
        return None
    app_state_nodeapi.daemon.get_wallet.side_effect = dummy_get_wallet

    wallet = nodeapi.get_wallet_from_request(mock_request, 444)
    assert dummy_wallet is wallet

async def test_nodeapi_startup_async() -> None:
    server = nodeapi.NodeAPIServer()
    asyncio.create_task(server.run_async())
    try:
        # This will raise an `asyncio.TimeoutError` if it does not succeed leading to a test fail.
        await asyncio.wait_for(server.startup_event.wait(), 2)
    finally:
        await server.shutdown_async()

async def test_server_authentication_fail_async(server_tester: TestClient) -> None:
    # Expectation: We should see authorization fail (as there is no header).
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    mock_server._password = "unmatched password"
    response = await server_tester.request(path="/", method="POST", json={})
    assert response.status == HTTPStatus.UNAUTHORIZED

async def test_server_authentication_passwordless_success_async(server_tester: TestClient) -> None:
    # Expectation: We should see authorization succeed (as there is not password).
    # Expectation: Our `json` value was rejected as it was not a valid JSON-RPC call/batch value.
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    mock_server._password = ""
    response = await server_tester.request(path="/", method="POST", json=1)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] is None
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32700
    assert object["error"]["message"] == "Top-level object parse error"

async def test_server_authentication_bad_password_async(server_tester: TestClient) -> None:
    # Expectation: We should see authorization fail (as there is a header with bad credentials).
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    mock_server._username = "A unmatched username"
    mock_server._password = "A unmatched password"
    response = await server_tester.request(path="/", method="POST", json=1,
        auth=aiohttp.BasicAuth("B matched username", "B matched password"))
    assert response.status == HTTPStatus.UNAUTHORIZED

async def test_server_authentication_good_password_async(server_tester: TestClient) -> None:
    # Expectation: We should see authorization pass (as there is a header with good credentials).
    # Expectation: Our `json` value was rejected as it was not a valid JSON-RPC call/batch value.
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    mock_server._username = "matched username"
    mock_server._password = "matched password"
    response = await server_tester.request(path="/", method="POST", json=1,
        auth=aiohttp.BasicAuth("matched username", "matched password"))
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] is None
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32700
    assert object["error"]["message"] == "Top-level object parse error"


@pytest.mark.parametrize("id_value,expected_success", ((111, True), ("23232", True), (None, True),
    ({}, False)))
async def test_server_authentication_call_id_types_async(id_value: nodeapi.RequestIdType,
        expected_success: bool, server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    mock_server._password = ""
    call_object = {
        "id": id_value,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.BAD_REQUEST
    object = await response.json()
    assert len(object) == 3
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32600
    if expected_success:
        # Passed invalid id type guard.
        assert object["id"] == id_value
        assert object["error"]["message"] == "Missing method"
    else:
        # Hit invalid id type guard.
        assert object["id"] is None
        assert object["error"]["message"] == "Id must be int, string or null"

async def test_server_authentication_method_type_fail_async(server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    mock_server._password = ""
    call_object = {
        "id": 2323,
        "method": 1,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.BAD_REQUEST
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 2323
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32600
    assert object["error"]["message"] == "Method must be a string"

async def test_server_authentication_method_unknown_fail_async(server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    mock_server._password = ""
    call_object = {
        "id": 2323,
        "method": "non-existent method",
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.NOT_FOUND
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 2323
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32601
    assert object["error"]["message"] == "Method not found"
