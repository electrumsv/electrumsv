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
from electrumsv.constants import AccountCreationType, KeystoreTextType, DerivationType, \
    PaymentFlag, ScriptType, TransactionOutputFlag, TxFlags
from electrumsv.exceptions import InvalidPassword
from electrumsv.keystore import instantiate_keystore_from_text
from electrumsv.network_support.types import ServerConnectionState, TipFilterRegistrationJobOutput
from electrumsv import nodeapi
from electrumsv.storage import WalletStorage
from electrumsv.types import KeyStoreResult
from electrumsv.wallet import StandardAccount, Wallet
from electrumsv.wallet_database.types import AccountTransactionOutputSpendableRowExtended, \
    PaymentRequestOutputRow, PaymentRequestRow

from .util import _create_mock_app_state2, MockStorage


PUBLIC_KEY_1_HEX = "02573afa26acf04e7cdafe46b39f8cba25f05c76d9a0cf500b9e196d72020931db"
PUBLIC_KEY_1 = bitcoinx.PublicKey.from_hex(PUBLIC_KEY_1_HEX)
P2PKH_ADDRESS_1 = PUBLIC_KEY_1.to_address()
FAKE_DERIVATION_DATA2 = b"sdsdsd"
FAKE_BLOCK_HASH = b"block hash"
FAKE_TRANSACTION_HASH = b"txhash"


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
    app_state_nodeapi.config.get_wallet_directory_path.side_effect = dummy_get_path

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
    app_state_nodeapi.config.get_wallet_directory_path.side_effect = dummy_get_path
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

@pytest.mark.parametrize("endpoint_name", ("getnewaddress","listunspent","sendtoaddress"))
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_endpoints_no_account_async(app_state_nodeapi: AppStateProxy,
        endpoint_name: str, server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    def get_visible_accounts() -> list[StandardAccount]:
        return []
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    call_object = {
        "id": 232,
        "method": endpoint_name,
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

@pytest.mark.parametrize("endpoint_name", ("getnewaddress","listunspent","sendtoaddress"))
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_endpoints_too_many_accounts_async(app_state_nodeapi: AppStateProxy,
        endpoint_name: str, server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    mock_account1 = unittest.mock.Mock(spec=StandardAccount)
    mock_account2 = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        return [ mock_account1, mock_account2 ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    call_object = {
        "id": 232,
        "method": endpoint_name,
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

# We are checking that methods check their parameters. We do not need to check every permutation of
# every type check, as the unit testing of the type checking functions already does that.
@pytest.mark.parametrize("endpoint_name,parameter_list,error_code,error_text", [
    ## ``listunspent``: ``minconf`` parameter
    # Error case: RPC_PARSE_ERROR / String in place of minimum confirmation count.
    ("listunspent", [ "string" ], -32700,
        "JSON value is not an integer as expected"),
    # Error case: RPC_PARSE_ERROR / String in place of maximum confirmation count.
    ("listunspent", [ 0, "string" ], -32700,
        "JSON value is not an integer as expected"),
    # Error case: RPC_TYPE_ERROR / Non-list in place of filter address list.
    ("listunspent", [ None, None, 1 ], -3,
        "Expected type list, got int"),
    # Error case: RPC_PARSE_ERROR / Non-string in filter address list.
    ("listunspent", [ None, None, [ 1 ] ], -32700,
        "JSON value is not a string as expected"),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Testnet address in filter address list.
    ("listunspent", [ None, None, [ "mneqqWSAQCg6tTP4BUdnPDBRanFqaaryMM" ] ], -5,
        "Invalid Bitcoin address: unknown version byte 111 for network mainnet"),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Non-address string in filter address list.
    ("listunspent", [ None, None, [ "non-address" ] ], -5,
        "Invalid Bitcoin address: invalid base 58 character \"-\""),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Presumably base58 non-address instead of address.
    ("listunspent", [ None, None, [ "test" ] ], -5,
        "Invalid Bitcoin address: invalid base 58 checksum for test"),
    # Error case: RPC_INVALID_PARAMETER / Duplicate address in list.
    ("listunspent", [ None, None, [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2",
            "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2" ] ], -8,
        "Invalid parameter, duplicated address: 1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2"),
    # Error case: RPC_INVALID_PARAMETER / Integer instead of boolean for `include_unsafe`.
    ("listunspent", [ None, None, None, 1 ], -32700,
        "JSON value is not a boolean as expected"),

    ## ``sendtoaddress``: ``address`` parameter
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Testnet version byte in address.
    ("sendtoaddress", [ "mneqqWSAQCg6tTP4BUdnPDBRanFqaaryMM", 10000 ], -5,
        "Invalid address: unknown version byte 111 for network mainnet"),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Non-base58 address text.
    ("sendtoaddress", [ "non-address", 10000 ], -5,
        "Invalid address: invalid base 58 character \"-\""),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Presumably base58 non-address instead of address.
    ("sendtoaddress", [ "test", 10000 ], -5,
        "Invalid address: invalid base 58 checksum for test"),
    # Error case: RPC_PARSE_ERROR / Integer instead of string for address.
    ("sendtoaddress", [ 1, 10000 ], -32700,
        "JSON value is not a string as expected"),
    ## ``sendtoaddress``: ``amount`` parameter
    # Error case: RPC_TYPE_ERROR / Negative amount to send.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", -100 ], -3,
        "Amount out of range"),
    # Error case: RPC_TYPE_ERROR / Too large amount to send.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 1e10 ], -3,
        "Amount out of range"),
    # Error case: RPC_TYPE_ERROR / Zero amount to send.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 0 ], -3,
        "Invalid amount for send"),
    ## ``sendtoaddress``: ``comment`` parameter
    # Error case: RPC_PARSE_ERROR / Integer instead of string for comment.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000, 1 ], -32700,
        "JSON value is not a string as expected"),
    ## ``sendtoaddress``: ``commentto`` parameter
    # Error case: RPC_PARSE_ERROR / Integer instead of string for comment to.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000, "null", 1 ], -32700,
        "JSON value is not a string as expected"),
    ## ``sendtoaddress``: ``subtract_fee_from_amount`` parameter
    # Error case: RPC_INVALID_PARAMETER / Enabled .
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000, None, None, True ], -8,
        "Subtract fee from amount not currently supported"),
])
@unittest.mock.patch('electrumsv.keystore.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_endpoints_failure_invalid_parameter_list_async(app_state_nodeapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_keystore: AppStateProxy,
        endpoint_name: str, parameter_list: list[Any], error_code: int, error_text: str,
        server_tester: TestClient, funded_wallet_factory: Callable[[], Wallet]) -> None:
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
        "method": endpoint_name,
        "params": parameter_list,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] is None
    assert len(object["error"]) == 2
    assert object["error"]["code"] == error_code
    assert object["error"]["message"] == error_text

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getnewaddress_no_connected_blockchain_server_async(
        app_state_nodeapi: AppStateProxy, server_tester: TestClient) -> None:
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
async def test_call_getnewaddress_remote_monitoring_failure_async(
        app_state_nodeapi: AppStateProxy, server_tester: TestClient) -> None:
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

@pytest.mark.parametrize("local_height,block_height,parameters,results", [
    # Filter for an address and match it.
    (100, 10, [ None, None, [ str(P2PKH_ADDRESS_1) ] ], [
        {
            "address": str(P2PKH_ADDRESS_1),
            "amount": 0.00001000,
            "confirmations": 90,
            "safe": True,
            "scriptPubKey": P2PKH_ADDRESS_1.to_script().to_hex(),
            "solvable": True,
            "spendable": True,
            "txid": bitcoinx.hash_to_hex_str(FAKE_TRANSACTION_HASH),
            "vout": 0,
        }
    ]),
    # Filter for an address, filter out another and match nothing.
    (100, 10, [ None, None, [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2" ] ], []),
    # Filter for >=91 confirmations, filter out the 90 confirmations and match nothing.
    (100, 10, [ 91, None ], []),
    # Filter for >=90 confirmations, match the 90 confirmations entry.
    (100, 10, [ 90, None ], [
        {
            "amount": 0.00001000,
            "confirmations": 90,
            "safe": True,
            "scriptPubKey": P2PKH_ADDRESS_1.to_script().to_hex(),
            "solvable": True,
            "spendable": True,
            "txid": bitcoinx.hash_to_hex_str(FAKE_TRANSACTION_HASH),
            "vout": 0,
        }
    ]),
    # Filter for <=90 confirmations, match the 90 confirmations entry.
    (100, 10, [ None, 90 ], [
        {
            "amount": 0.00001000,
            "confirmations": 90,
            "safe": True,
            "scriptPubKey": P2PKH_ADDRESS_1.to_script().to_hex(),
            "solvable": True,
            "spendable": True,
            "txid": bitcoinx.hash_to_hex_str(FAKE_TRANSACTION_HASH),
            "vout": 0,
        }
    ]),
    # Filter for <=89 confirmations, filter out the 90 confirmations and match nothing.
    (100, 10, [ None, 89 ], []),
])
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_listunspent_success_async(
        app_state_nodeapi: AppStateProxy, local_height: int, block_height: int,
        parameters: list[Any], results: list[dict[str, Any]],
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

    account = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        nonlocal account
        return [ account ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    def get_transaction_outputs_with_key_and_tx_data(exclude_frozen: bool=True,
            confirmed_only: bool|None=None, keyinstance_ids: list[int]|None=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        assert exclude_frozen is True
        assert confirmed_only is True
        assert keyinstance_ids is None
        return [
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 1000, 1111111,
                ScriptType.P2PKH, TransactionOutputFlag.NONE, 1, 1, DerivationType.BIP32_SUBPATH,
                FAKE_DERIVATION_DATA2, TxFlags.STATE_SETTLED, FAKE_BLOCK_HASH)
        ]
    account.get_transaction_outputs_with_key_and_tx_data.side_effect = \
        get_transaction_outputs_with_key_and_tx_data
    account.is_watching_only = lambda: False

    # Prepare the state so we can fake confirmations.
    wallet.get_local_height = lambda: local_height

    def lookup_header_for_hash(block_hash: bytes) -> tuple[bitcoinx.Header, bitcoinx.Chain]|None:
        assert FAKE_BLOCK_HASH == block_hash
        header = unittest.mock.Mock(spec=bitcoinx.Header)
        header.height = block_height
        chain = unittest.mock.Mock(spec=bitcoinx.Chain)
        return header, chain
    wallet.lookup_header_for_hash = lookup_header_for_hash

    # Inject the public key / address for the row (we ignore its derivation data).
    def get_public_keys_for_derivation(derivation_type: DerivationType,
            derivation_data2: bytes|None) -> list[bitcoinx.PublicKey]:
        assert derivation_type == DerivationType.BIP32_SUBPATH
        assert derivation_data2 == FAKE_DERIVATION_DATA2
        return [ PUBLIC_KEY_1 ]
    account.get_public_keys_for_derivation.side_effect = \
        get_public_keys_for_derivation

    call_object = {
        "id": 232,
        "method": "listunspent",
        "params": parameters,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] == results
    assert object["error"] is None

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_listunspent_no_matches_success_async(
        app_state_nodeapi: AppStateProxy, server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallet = unittest.mock.Mock()
    wallets[irrelevant_path] = wallet
    app_state_nodeapi.daemon.wallets = wallets

    account = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        nonlocal account
        return [ account ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    account.get_transaction_outputs_with_key_and_tx_data.side_effect = lambda *args, **kwargs: []

    call_object = {
        "id": 232,
        "method": "listunspent",
        "params": [],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] == []
    assert object["error"] is None

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

@unittest.mock.patch('electrumsv.keystore.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state2)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_sendtoaddress_failure_no_configured_peer_channel_server_async(
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

