from __future__ import annotations
import asyncio
from http import HTTPStatus
import json
import os
from typing import Any, Callable, cast
import unittest.mock

import aiohttp
from aiohttp.test_utils import TestClient
from aiohttp import web
import bitcoinx
import pytest

from electrumsv.app_state import AppStateProxy
from electrumsv.constants import AccountCreationType, KeystoreTextType, PaymentFlag
from electrumsv.exceptions import InvalidPassword
from electrumsv.keystore import instantiate_keystore_from_text
from electrumsv.network_support.types import ServerConnectionState, TipFilterRegistrationJobOutput
from electrumsv import nodeapi
from electrumsv.storage import WalletStorage
from electrumsv.types import FeeEstimatorProtocol, KeyStoreResult, TransactionSize
from electrumsv.wallet import StandardAccount, Wallet
from electrumsv.wallet_database.types import PaymentRequestRow, PaymentRequestOutputRow

from .util import _create_mock_app_state2, MockStorage


@pytest.fixture
def server_tester(event_loop, aiohttp_client):
    """mock client - see: https://docs.aiohttp.org/en/stable/client_quickstart.html"""
    web_application = web.Application()
    mock_server = unittest.mock.Mock()
    web_application["server"] = mock_server
    nodeapi.setup_web_application(web_application)
    return event_loop.run_until_complete(aiohttp_client(web_application))

def test_transform_parameters_valid_array() -> None:
    parameters = nodeapi.transform_parameters(444, [ "a", "b"], [])
    assert parameters == []

def test_transform_parameters_valid_match() -> None:
    parameters = nodeapi.transform_parameters(444, [ "b", "a"], { "a": "aa", "b": 5 })
    assert parameters == [ 5, "aa" ]

def test_transform_parameters_invalid_mismatch() -> None:
    with pytest.raises(web.HTTPInternalServerError) as exception_value:
        nodeapi.transform_parameters(444, [ "b" ], { "a": 1 })
    response = exception_value.value
    assert isinstance(response.body, bytes)
    object = json.loads(response.body)
    assert len(object) == 3
    assert object["id"] == 444
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -8 # INVALID_PARAMETER
    assert object["error"]["message"] == "Unknown named parameter a"

def test_get_parameter_string_success() -> None:
    assert nodeapi.get_string_parameter(444, "definitely a string") == "definitely a string"

@pytest.mark.parametrize("parameter_value", (111, None, 1.1))
def test_get_parameter_string_fail(parameter_value: Any) -> None:
    with pytest.raises(web.HTTPInternalServerError) as exception_value:
        nodeapi.get_string_parameter(444, parameter_value)
    response = exception_value.value
    assert isinstance(response.body, bytes)
    object = json.loads(response.body)
    assert len(object) == 3
    assert object["id"] == 444
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32700 # PARSE_ERROR
    assert object["error"]["message"] == "JSON value is not a string as expected"

@pytest.mark.parametrize("parameter_value,expected_value",
    # Integer, fixed point string, floating point.
    ((111, 11100000000), ("123.231", 12323100000), (123.231, 12323100000),
    # Higher bound valid range, lower bound valid range.
    (21000000, 21000000 * 100000000), (0, 0)))
def test_get_amount_parameter_success(parameter_value: Any, expected_value: int) -> None:
    assert nodeapi.get_amount_parameter(444, parameter_value) == expected_value

@pytest.mark.parametrize("parameter_value,error_text", (("dfdf", "Invalid amount"),
    (None, "Amount is not a number or string"),
    # Just over higher and lower bound range values.
    (21000001, "Amount out of range"), (-1, "Amount out of range")))
def test_get_amount_parameter_parse_failure(parameter_value: Any, error_text: str) -> None:
    with pytest.raises(web.HTTPInternalServerError) as exception_value:
        nodeapi.get_amount_parameter(444, parameter_value)
    response = exception_value.value
    assert isinstance(response.body, bytes)
    object = json.loads(response.body)
    assert len(object) == 3
    assert object["id"] == 444
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -3 # TYPE_ERROR
    assert object["error"]["message"] == error_text

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
def test_get_wallet_from_request_implicit_fail_ensure_none(app_state_nodeapi: AppStateProxy) \
        -> None:
    # Expectation: The user is using the implicit single loaded wallet API.
    # Expectation: There are no wallets loaded and none to select implicitly.
    # Expectation: We want to ensure a wallet is returned or return an error.
    mock_request = unittest.mock.Mock()
    mock_request.match_info.get.side_effect = lambda *args: None

    app_state_nodeapi.daemon.wallets = {}
    with pytest.raises(web.HTTPNotFound) as exception_value:
        nodeapi.get_wallet_from_request(mock_request, 444, ensure_available=True)
    response = exception_value.value
    assert isinstance(response.body, bytes)
    object = json.loads(response.body)
    assert len(object) == 3
    assert object["id"] == 444
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32601
    assert object["error"]["message"] == "Method not found (wallet method is disabled because " \
        "no wallet is loaded"

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
def test_get_wallet_from_request_implicit_fail_ensure_many(app_state_nodeapi: AppStateProxy) \
        -> None:
    # Expectation: The user is using the implicit single loaded wallet API.
    # Expectation: There are too many wallets loaded to choose one.
    # Expectation: We want to ensure a wallet is returned or return an error.
    mock_request = unittest.mock.Mock()
    mock_request.match_info.get.side_effect = lambda *args: None

    wallets: dict[str, Wallet] = {}
    for i in range(2):
        irrelevant_path = os.urandom(32).hex()
        wallets[irrelevant_path] = unittest.mock.Mock()
    app_state_nodeapi.daemon.wallets = wallets

    with pytest.raises(web.HTTPInternalServerError) as exception_value:
        nodeapi.get_wallet_from_request(mock_request, 444, ensure_available=True)
    response = exception_value.value
    assert isinstance(response.body, bytes)
    object = json.loads(response.body)
    assert len(object) == 3
    assert object["id"] == 444
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -19
    assert object["error"]["message"] == "Wallet file not specified (must request wallet RPC " \
        "through /wallet/<filename> uri-path)"

@pytest.mark.parametrize("ensure_available", (True, False))
@unittest.mock.patch('electrumsv.nodeapi.app_state')
def test_get_wallet_from_request_implicit_success(app_state_nodeapi: AppStateProxy,
        ensure_available: bool) -> None:
    # Expectation: The user is using the implicit single loaded wallet API.
    # Expectation: With only one wallet loaded it will be found.
    mock_request = unittest.mock.Mock()
    mock_request.match_info.get.side_effect = lambda *args: None

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallets[irrelevant_path] = unittest.mock.Mock()
    app_state_nodeapi.daemon.wallets = wallets

    wallet = nodeapi.get_wallet_from_request(mock_request, 444, ensure_available)
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
    # Ensure the server does not require authorization to make a call.
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
    # Ensure the server does not require authorization to make a call.
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
    # Ensure the server does not require authorization to make a call.
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
    # Ensure the server does not require authorization to make a call.
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

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getnewaddress_no_available_server_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    def get_tip_filter_server_state() -> None:
        return None
    wallet.get_tip_filter_server_state.side_effect = get_tip_filter_server_state

    call_object = {
        "id": 232,
        "method": "getnewaddress",
        "params": [],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4
    assert object["error"]["message"] == "No connected blockchain server"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getnewaddress_no_account_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    server_state = unittest.mock.Mock(spec=ServerConnectionState)
    def get_tip_filter_server_state() -> ServerConnectionState:
        nonlocal server_state
        return server_state
    wallet.get_tip_filter_server_state.side_effect = get_tip_filter_server_state

    # mock_account = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        return []
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    call_object = {
        "id": 232,
        "method": "getnewaddress",
        "params": [],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4
    assert object["error"]["message"] == "Ambiguous account (found 0, expected 1)"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getnewaddress_too_many_accounts_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    server_state = unittest.mock.Mock(spec=ServerConnectionState)
    def get_tip_filter_server_state() -> ServerConnectionState:
        nonlocal server_state
        return server_state
    wallet.get_tip_filter_server_state.side_effect = get_tip_filter_server_state

    mock_account1 = unittest.mock.Mock(spec=StandardAccount)
    mock_account2 = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        return [ mock_account1, mock_account2 ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    call_object = {
        "id": 232,
        "method": "getnewaddress",
        "params": [],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4
    assert object["error"]["message"] == "Ambiguous account (found 2, expected 1)"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getnewaddress_monitor_failure_no_server_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    server_state = unittest.mock.Mock(spec=ServerConnectionState)
    def get_tip_filter_server_state() -> ServerConnectionState:
        nonlocal server_state
        return server_state
    wallet.get_tip_filter_server_state.side_effect = get_tip_filter_server_state

    account = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        nonlocal account
        return [ account ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    payment_request_row = unittest.mock.Mock(spec=PaymentRequestRow)
    payment_request_output_row = unittest.mock.Mock(spec=PaymentRequestOutputRow)
    payment_request_output_row.output_script_bytes = \
        bytes.fromhex("76a9149935f2eaa7bb881c1cf728e940bcc0fda408f01b88ac")

    async def create_payment_request_async(amount: int | None,
            internal_description: str | None,
            merchant_reference: str | None, date_expires: int | None = None,
            server_id: int | None = None, dpp_invoice_id: str | None=None,
            dpp_ack_json: str | None=None, encrypted_key_text: str | None=None,
            flags: PaymentFlag=PaymentFlag.NONE) \
                -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow]]:
        # These are all expected values.
        assert amount is None
        assert internal_description is None
        assert merchant_reference is None
        assert server_id is None
        assert dpp_invoice_id is None
        assert dpp_ack_json is None
        assert  encrypted_key_text is None
        assert flags & PaymentFlag.MASK_TYPE == PaymentFlag.MONITORED
        nonlocal payment_request_row, payment_request_output_row
        return payment_request_row, [ payment_request_output_row ]
    account.create_payment_request_async = create_payment_request_async

    # job_data = unittest.mock.Mock(spec=TipFilterRegistrationJobOutput)
    async def monitor_blockchain_payment_async(request_id: int) \
            -> TipFilterRegistrationJobOutput | None:
        return None
    account.monitor_blockchain_payment_async = monitor_blockchain_payment_async

    call_object = {
        "id": 232,
        "method": "getnewaddress",
        "params": [],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4
    assert object["error"]["message"] == \
        "Blockchain server address monitoring request not successful"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getnewaddress_monitor_server_error_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    server_state = unittest.mock.Mock(spec=ServerConnectionState)
    def get_tip_filter_server_state() -> ServerConnectionState:
        nonlocal server_state
        return server_state
    wallet.get_tip_filter_server_state.side_effect = get_tip_filter_server_state

    account = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        nonlocal account
        return [ account ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    payment_request_row = unittest.mock.Mock(spec=PaymentRequestRow)
    payment_request_output_row = unittest.mock.Mock(spec=PaymentRequestOutputRow)
    payment_request_output_row.output_script_bytes = \
        bytes.fromhex("76a9149935f2eaa7bb881c1cf728e940bcc0fda408f01b88ac")

    async def create_payment_request_async(amount: int | None,
            internal_description: str | None,
            merchant_reference: str | None, date_expires: int | None = None,
            server_id: int | None = None, dpp_invoice_id: str | None=None,
            dpp_ack_json: str | None=None, encrypted_key_text: str | None=None,
            flags: PaymentFlag=PaymentFlag.NONE) \
                -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow]]:
        # These are all expected values.
        assert amount is None
        assert internal_description is None
        assert merchant_reference is None
        assert server_id is None
        assert dpp_invoice_id is None
        assert dpp_ack_json is None
        assert  encrypted_key_text is None
        assert flags & PaymentFlag.MASK_TYPE == PaymentFlag.MONITORED
        nonlocal payment_request_row, payment_request_output_row
        return payment_request_row, [ payment_request_output_row ]
    account.create_payment_request_async = create_payment_request_async

    job_data = unittest.mock.Mock(spec=TipFilterRegistrationJobOutput)
    job_data.completed_event = unittest.mock.Mock(spec=asyncio.Event)
    job_data.date_registered = None
    job_data.failure_reason = "The server had a problem test message"
    async def monitor_blockchain_payment_async(request_id: int) \
            -> TipFilterRegistrationJobOutput | None:
        nonlocal job_data
        return job_data
    account.monitor_blockchain_payment_async = monitor_blockchain_payment_async

    call_object = {
        "id": 232,
        "method": "getnewaddress",
        "params": [],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4
    assert object["error"]["message"] == job_data.failure_reason

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getnewaddress_success_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    server_state = unittest.mock.Mock(spec=ServerConnectionState)
    def get_tip_filter_server_state() -> ServerConnectionState:
        nonlocal server_state
        return server_state
    wallet.get_tip_filter_server_state.side_effect = get_tip_filter_server_state

    account = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        nonlocal account
        return [ account ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    payment_request_row = unittest.mock.Mock(spec=PaymentRequestRow)
    payment_request_output_row = unittest.mock.Mock(spec=PaymentRequestOutputRow)
    payment_request_output_row.output_script_bytes = \
        bytes.fromhex("76a9149935f2eaa7bb881c1cf728e940bcc0fda408f01b88ac")

    async def create_payment_request_async(amount: int | None,
            internal_description: str | None,
            merchant_reference: str | None, date_expires: int | None = None,
            server_id: int | None = None, dpp_invoice_id: str | None=None,
            dpp_ack_json: str | None=None, encrypted_key_text: str | None=None,
            flags: PaymentFlag=PaymentFlag.NONE) \
                -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow]]:
        # These are all expected values.
        assert amount is None
        assert internal_description is None
        assert merchant_reference is None
        assert server_id is None
        assert dpp_invoice_id is None
        assert dpp_ack_json is None
        assert  encrypted_key_text is None
        assert flags & PaymentFlag.MASK_TYPE == PaymentFlag.MONITORED
        nonlocal payment_request_row, payment_request_output_row
        return payment_request_row, [ payment_request_output_row ]
    account.create_payment_request_async = create_payment_request_async

    job_data = unittest.mock.Mock(spec=TipFilterRegistrationJobOutput)
    job_data.completed_event = unittest.mock.Mock(spec=asyncio.Event)
    job_data.date_registered = 11111
    job_data.failure_reason = None
    async def monitor_blockchain_payment_async(request_id: int) \
            -> TipFilterRegistrationJobOutput | None:
        nonlocal job_data
        return job_data
    account.monitor_blockchain_payment_async = monitor_blockchain_payment_async

    call_object = {
        "id": 232,
        "method": "getnewaddress",
        "params": [],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] == "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2"
    assert object["error"] is None

@unittest.mock.patch('electrumsv.keystore.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_sendtoaddress_failure_no_account_async(app_state_nodeapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_keystore: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallet_password = "password"
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: wallet_password
    app_state_keystore.credentials.get_wallet_password = lambda wallet_path: wallet_password
    tmp_storage = cast(WalletStorage, MockStorage(wallet_password))
    wallet = Wallet(tmp_storage)

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    call_object = {
        "id": 232,
        "method": "sendtoaddress",
        "params": [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4 # WALLET_ERROR
    assert object["error"]["message"] == "Ambiguous account (found 0, expected 1)"

@unittest.mock.patch('electrumsv.keystore.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_sendtoaddress_failure_too_many_accounts_async(app_state_nodeapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_keystore: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallet_password = "password"
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: wallet_password
    app_state_keystore.credentials.get_wallet_password = lambda wallet_path: wallet_password
    tmp_storage = cast(WalletStorage, MockStorage(wallet_password))
    wallet = Wallet(tmp_storage)

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    for i in range(2):
        data = os.urandom(64)
        coin = bitcoinx.BitcoinRegtest
        xprv = bitcoinx.BIP32PrivateKey._from_parts(data[:32], data[32:], coin)
        text_match = xprv.to_extended_key_string()
        assert text_match is not None # typing bug
        keystore = instantiate_keystore_from_text(KeystoreTextType.EXTENDED_PRIVATE_KEY,
            text_match, wallet_password, derivation_text=None, passphrase="", watch_only=False)
        wallet.create_account_from_keystore(
            KeyStoreResult(AccountCreationType.IMPORTED, keystore))

    call_object = {
        "id": 232,
        "method": "sendtoaddress",
        "params": [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4 # WALLET_ERROR
    assert object["error"]["message"] == "Ambiguous account (found 2, expected 1)"

# The keystore app_state is required for credential caching by wallet logic.
@unittest.mock.patch('electrumsv.keystore.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_sendtoaddress_walletpassphrase_required_async(app_state_nodeapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_keystore: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallet_password = "password"
    # Setup: ensure the `Wallet` instantiation code can find the password when instantiating the
    #     petty cash account (and any other applicable points).
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: wallet_password
    tmp_storage = cast(WalletStorage, MockStorage(wallet_password))
    wallet = Wallet(tmp_storage)

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    # Setup: create one account in the wallet.
    data = os.urandom(64)
    coin = bitcoinx.BitcoinRegtest
    xprv = bitcoinx.BIP32PrivateKey._from_parts(data[:32], data[32:], coin)
    text_match = xprv.to_extended_key_string()
    assert text_match is not None # typing bug
    keystore = instantiate_keystore_from_text(KeystoreTextType.EXTENDED_PRIVATE_KEY,
        text_match, wallet_password, derivation_text=None, passphrase="", watch_only=False)
    wallet.create_account_from_keystore(
        KeyStoreResult(AccountCreationType.IMPORTED, keystore))

    # Setup: Ensure the API password check does not find a password.
    app_state_nodeapi.credentials.get_wallet_password = lambda wallet_path: None

    # Test: Make the call and check the result.
    call_object = {
        "id": 232,
        "method": "sendtoaddress",
        "params": [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -13 # WALLET_UNLOCK_NEEDED
    assert object["error"]["message"] == "Error: Please enter the wallet passphrase with " \
        "walletpassphrase first."

# The keystore app_state is required for credential caching by wallet logic.
@unittest.mock.patch('electrumsv.keystore.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_sendtoaddress_failure_no_message_box_server_async(
        app_state_nodeapi: AppStateProxy, app_state_wallet: AppStateProxy,
        app_state_keystore: AppStateProxy, server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallet_password = "password"
    # Setup: ensure the `Wallet` instantiation code can find the password when instantiating the
    #     petty cash account (and any other applicable points).
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: wallet_password
    tmp_storage = cast(WalletStorage, MockStorage(wallet_password))
    wallet = Wallet(tmp_storage)

    # Setup: create one account in the wallet.
    data = os.urandom(64)
    coin = bitcoinx.BitcoinRegtest
    xprv = bitcoinx.BIP32PrivateKey._from_parts(data[:32], data[32:], coin)
    text_match = xprv.to_extended_key_string()
    assert text_match is not None # typing bug
    keystore = instantiate_keystore_from_text(KeystoreTextType.EXTENDED_PRIVATE_KEY,
        text_match, wallet_password, derivation_text=None, passphrase="", watch_only=False)
    wallet.create_account_from_keystore(
        KeyStoreResult(AccountCreationType.IMPORTED, keystore))

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    # Setup: The nodeapi checks the password is present before our failure point.
    app_state_nodeapi.credentials.get_wallet_password = lambda wallet_path: wallet_password

    call_object = {
        "id": 232,
        "method": "sendtoaddress",
        "params": [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4 # WALLET_ERROR
    assert object["error"]["message"] == "No configured peer channel server"

@unittest.mock.patch('electrumsv.keystore.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_sendtoaddress_failure_invalid_parameters_async(
        app_state_nodeapi: AppStateProxy,app_state_wallet: AppStateProxy,
        app_state_keystore: AppStateProxy, server_tester: TestClient,
        funded_wallet_factory: Callable[[], Wallet]) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallet_password = "123456"
    # The `funded_wallet_factory` fixture copies and opens the wallet and requires the password.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: wallet_password
    app_state_keystore.credentials.get_wallet_password = lambda wallet_path: wallet_password

    wallet = funded_wallet_factory()

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    call_object = {
        "id": 232,
        "method": "sendtoaddress",
        "params": [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -4 # WALLET_ERROR
    assert object["error"]["message"] == "No configured peer channel server"

# @unittest.mock.patch('electrumsv.keystore.app_state', new_callable=_create_mock_app_state2)
# @unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state2)
# @unittest.mock.patch('electrumsv.nodeapi.app_state')
# async def test_call_sendtoaddress_failure_invalid_parameters_async(
#         app_state_nodeapi: AppStateProxy,app_state_wallet: AppStateProxy,
#         app_state_keystore: AppStateProxy, server_tester: TestClient,
#         funded_wallet_factory: Callable[[], Wallet]) -> None:
#     assert server_tester.app is not None
#     mock_server = server_tester.app["server"]
#     # Ensure the server does not require authorization to make a call.
#     mock_server._password = ""

#     wallet_password = "123456"
#     # The `funded_wallet_factory` fixture copies and opens the wallet and requires the password.
#     app_state_wallet.credentials.get_wallet_password = lambda wallet_path: wallet_password
#     app_state_keystore.credentials.get_wallet_password = lambda wallet_path: wallet_password

#     wallet = funded_wallet_factory()

#     wallets: dict[str, Wallet] = {}
#     irrelevant_path = os.urandom(32).hex()
#     wallets[irrelevant_path] = wallet
#     app_state_nodeapi.daemon.wallets = wallets

#     call_object = {
#         "id": 232,
#         "method": "sendtoaddress",
#         "params": [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000 ],
#     }
#     response = await server_tester.request(path="/", method="POST", json=call_object)
#     assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
#     object = await response.json()
#     assert len(object) == 3
#     assert object["id"] == 232
#     assert object["result"] is None
#     assert len(object["error"]) == 2
#     assert object["error"]["code"] == -4 # WALLET_ERROR
#     assert object["error"]["message"] == "No configured peer channel server"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_walletpassphrase_password_incorrect_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    def check_password(checked_password: str) -> None:
        raise InvalidPassword()
    wallet.check_password.side_effect = check_password

    call_object = {
        "id": 232,
        "method": "walletpassphrase",
        "params": [ "blubber", 20 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -14
    assert object["error"]["message"] == "Error: The wallet passphrase entered was incorrect"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_walletpassphrase_password_wrong_type_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    def check_password(checked_password: str) -> None:
        raise InvalidPassword()
    wallet.check_password.side_effect = check_password

    call_object = {
        "id": 232,
        "method": "walletpassphrase",
        "params": [ 111, 20 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32700
    assert object["error"]["message"] == "JSON value is not a string as expected"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_walletpassphrase_password_too_short_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    def check_password(checked_password: str) -> None:
        raise InvalidPassword()
    wallet.check_password.side_effect = check_password

    call_object = {
        "id": 232,
        "method": "walletpassphrase",
        "params": [ "", 20 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32700
    assert object["error"]["message"] == "Invalid parameters, see documentation for this call"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_walletpassphrase_duration_wrong_type_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    def check_password(checked_password: str) -> None:
        raise InvalidPassword()
    wallet.check_password.side_effect = check_password

    call_object = {
        "id": 232,
        "method": "walletpassphrase",
        "params": [ "password string", "fff" ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == -32700
    assert object["error"]["message"] == "JSON value is not an integer as expected"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_walletpassphrase_password_correct_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    call_object = {
        "id": 232,
        "method": "walletpassphrase",
        "params": [ "blubber", 20 ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert object["error"] is None

