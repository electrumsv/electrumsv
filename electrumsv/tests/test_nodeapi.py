from __future__ import annotations
import asyncio
import concurrent
import sqlite3
from decimal import Decimal
from http import HTTPStatus
import json
import os
from pathlib import Path
from typing import Any, Callable, cast
from unittest import mock

from typing_extensions import NotRequired, TypedDict
import unittest.mock

import aiohttp
from aiohttp.test_utils import TestClient
from aiohttp import web
import bitcoinx
from bitcoinx import Chain, Header, Headers, hash_to_hex_str, hex_str_to_hash, Bitcoin, \
    BitcoinRegtest, MissingHeader
import pytest

from electrumsv.app_state import AppStateProxy
from electrumsv.constants import AccountCreationType, DerivationType, KeystoreTextType, \
    ScriptType, TransactionOutputFlag, TxFlag
from electrumsv.exceptions import InvalidPassword, NoViableServersError
from electrumsv.keystore import instantiate_keystore_from_text
from electrumsv.network_support.types import ServerConnectionState, TipFilterRegistrationJobOutput
from electrumsv import nodeapi
from electrumsv.nodeapi import RPCError
from electrumsv.standards.script_templates import classify_transaction_output_script, \
    create_script_sig
from electrumsv.storage import WalletStorage
from electrumsv.transaction import Transaction, TransactionContext, XTxInput, XPublicKey
from electrumsv.types import KeyStoreResult, Outpoint
from electrumsv.wallet import StandardAccount, Wallet
from electrumsv.wallet_database.types import AccountHistoryOutputRow, \
    AccountTransactionOutputSpendableRowExtended, KeyData, PaymentRequestOutputRow, \
    PaymentRequestRow, TransactionOutputSpendableProtocol, \
    TransactionOutputSpendRow, TransactionRow, WalletBalance
from .conftest import get_small_tx

from .util import _create_mock_app_state2, MockStorage, TEST_DATA_PATH
from ..bitcoin import COIN
from ..cached_headers import read_cached_headers

TEST_NODEAPI_PATH = os.path.join(TEST_DATA_PATH, "node_api")
TEST_WALLET_PATH = os.path.join(TEST_DATA_PATH, "wallets")


def coins_to_satoshis(value: float) -> int:
    amount_coins = Decimal(value)
    satoshis_per_coin = 100000000
    max_satoshis = 21000000 * satoshis_per_coin
    amount_satoshis = int(amount_coins * satoshis_per_coin)
    assert amount_satoshis >= 0 and amount_satoshis <= max_satoshis
    return amount_satoshis


PUBLIC_KEY_1_HEX = "02573afa26acf04e7cdafe46b39f8cba25f05c76d9a0cf500b9e196d72020931db"
PUBLIC_KEY_1 = bitcoinx.PublicKey.from_hex(PUBLIC_KEY_1_HEX)
P2PKH_ADDRESS_1 = PUBLIC_KEY_1.to_address()
FAKE_DERIVATION_DATA2 = b"sdsdsd"
FAKE_BLOCK_HASH = b"block hash"
FAKE_BLOCK_HASH2 = b"block hash 2"
FAKE_TRANSACTION_HASH = b"txhash"

P2PKH_TRANSACTION_HEX = \
    "02000000012240c035d2eb02308aa988fc953a46b07cf80fc109121c192a01e667f7d5b" \
    "41b0000000000ffffffff0140420f00000000001976a91443423852c99cb9825c2637f7" \
    "5ec386619132899088ac00000000"


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
    assert object["error"]["code"] == RPCError.INVALID_PARAMETER
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
    assert object["error"]["code"] == RPCError.PARSE_ERROR
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
    assert object["error"]["code"] == RPCError.TYPE_ERROR
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
    assert object["error"]["code"] == RPCError.METHOD_NOT_FOUND
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
    assert object["error"]["code"] == RPCError.WALLET_NOT_SPECIFIED
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
    assert object["error"]["code"] == RPCError.WALLET_NOT_FOUND
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
    assert object["error"]["code"] == RPCError.PARSE_ERROR
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
    assert object["error"]["code"] == RPCError.PARSE_ERROR
    assert object["error"]["message"] == "Top-level object parse error"

@pytest.mark.parametrize("id_value,expected_success", ((111, True), ("23232", True), (None, True),
    ({}, False)))
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_server_authentication_call_id_types_async(app_state_nodeapi: AppStateProxy,
        id_value: nodeapi.RequestIdType, expected_success: bool, server_tester: TestClient) -> None:
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
    assert object["error"]["code"] == RPCError.INVALID_REQUEST
    if expected_success:
        # Passed invalid id type guard.
        assert object["id"] == id_value
        assert object["error"]["message"] == "Missing method"
    else:
        # Hit invalid id type guard.
        assert object["id"] is None
        assert object["error"]["message"] == "Id must be int, string or null"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_server_authentication_method_type_fail_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
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
    assert object["error"]["code"] == RPCError.INVALID_REQUEST
    assert object["error"]["message"] == "Method must be a string"

@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_server_authentication_method_unknown_fail_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    assert server_tester.app is not None
    mock_server = server_tester.app["server"]
    # Ensure the server does not require authorization to make a call.
    mock_server._password = ""

    wallets: dict[str, Wallet] = {}
    irrelevant_path = os.urandom(32).hex()
    wallets[irrelevant_path] = unittest.mock.Mock()
    app_state_nodeapi.daemon.wallets = wallets

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
    assert object["error"]["code"] == RPCError.METHOD_NOT_FOUND
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
    assert object["error"]["code"] == RPCError.WALLET_ERROR
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
    assert object["error"]["code"] == RPCError.WALLET_ERROR
    assert object["error"]["message"] == "Ambiguous account (found 2, expected 1)"

endpoint_error_parameter_list = [
    ## ``createrawtransaction``: general parameters
    # Error case: RPC_INVALID_PARAMS / Need at least 2 parameters not 0.
    ("createrawtransaction", [ ], RPCError.INVALID_PARAMS,
        "Invalid parameters, see documentation for this call"),
    # Error case: RPC_INVALID_PARAMS / Need at least 2 parameters not 1.
    ("createrawtransaction", [ "x" ], RPCError.INVALID_PARAMS,
        "Invalid parameters, see documentation for this call"),
    # Error case: RPC_INVALID_PARAMS / Need at most 3 parameters not more.
    ("createrawtransaction", [ "x", "x", "x", "x" ], RPCError.INVALID_PARAMS,
        "Invalid parameters, see documentation for this call"),
    ## ``createrawtransaction``: ``inputs`` parameter
    # Error case: RPC_INVALID_PARAMETER / Need a non-null for ``inputs``.
    ("createrawtransaction", [ None, {}  ], RPCError.INVALID_PARAMETER,
        "Invalid parameter, arguments 1 and 2 must be non-null"),
    # Error case: RPC_TYPE_ERROR / Need a list for ``inputs``.
    ("createrawtransaction", [ 1, {}  ], RPCError.TYPE_ERROR,
        "Expected array, got int"),
    # Error case: RPC_PARSE_ERROR / Need dict entries for ``inputs``.
    ("createrawtransaction", [ [ 1 ], {}  ], RPCError.PARSE_ERROR,
        "JSON value is not an object as expected"),
    # Error case: RPC_INVALID_PARAMETER / Need a valid hex ``prev_hash`` for ``inputs``.
    ("createrawtransaction", [ [ { "txid": "a" } ], {} ], RPCError.INVALID_PARAMETER,
        "txid must be hexadecimal string (not 'a') and length of it must be divisible by 2"),
    # Error case: RPC_INVALID_PARAMETER / Need a valid hex ``prev_hash`` for ``inputs``.
    ("createrawtransaction", [ [ { "txid": "aa" } ], {} ], RPCError.INVALID_PARAMETER,
        "txid must be of length 64 (not 2)"),
    # Error case: RPC_INVALID_PARAMETER / Need a valid hash length for ``inputs``.
    ("createrawtransaction", [ [ { "txid":
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } ], {} ],
        RPCError.INVALID_PARAMETER, "Invalid parameter, missing vout key"),
    # Error case: RPC_INVALID_PARAMETER / Need a positive sequence for ``inputs``.
    ("createrawtransaction", [ [ { "txid":
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "vout": 10,
        "sequence": -1 } ], {} ], RPCError.INVALID_PARAMETER,
        "Invalid parameter, sequence number is out of range"),
    # Error case: RPC_INVALID_PARAMETER / Need a capped sequence for ``inputs``.
    ("createrawtransaction", [ [ { "txid":
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "vout": 10,
        "sequence": 0xFFFFFFFF+1 } ], {} ], RPCError.INVALID_PARAMETER,
        "Invalid parameter, sequence number is out of range"),
    ## ``createrawtransaction``: ``outputs`` parameter
    # Error case: RPC_INVALID_PARAMETER / Need a non-null for ``outputs``.
    ("createrawtransaction", [ [], None  ], RPCError.INVALID_PARAMETER,
        "Invalid parameter, arguments 1 and 2 must be non-null"),
    # Error case: RPC_TYPE_ERROR / Need a dict for ``outputs``.
    ("createrawtransaction", [ [], "sds"  ], RPCError.TYPE_ERROR,
        "Expected object, got str"),
    # Error case: RPC_INVALID_PARAMETER / Need a valid hex opreturn payload for ``outputs``.
    ("createrawtransaction", [ [], { "data": "a" } ], RPCError.INVALID_PARAMETER,
        "Data must be hexadecimal string (not 'a') and length of it must be divisible by 2"),
    # Error case: RPC_INVALID_PARAMETER / Need a valid hex opreturn payload for ``outputs``.
    ("createrawtransaction", [ [], { "data": "zz" } ], RPCError.INVALID_PARAMETER,
        "Data must be hexadecimal string (not 'zz') and length of it must be divisible by 2"),
    # Error case: RPC_INVALID_PARAMETER / Need a valid address for ``outputs``.
    ("createrawtransaction", [ [], { 1: 1 } ], RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid Bitcoin address: invalid base 58 checksum for 1"),
    # Error case: RPC_TYPE_ERROR / Invalid type.
    ("createrawtransaction", [ [], { "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2": [] } ],
        RPCError.TYPE_ERROR, "Amount is not a number or string"),
    # Error case: RPC_TYPE_ERROR / Negative amount to send.
    ("createrawtransaction", [ [], { "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2": -100 } ],
        RPCError.TYPE_ERROR, "Amount out of range"),
    # Error case: RPC_TYPE_ERROR / Too large amount to send.
    ("createrawtransaction", [ [], { "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2": 1e10 } ],
        RPCError.TYPE_ERROR, "Amount out of range"),
    ## ``createrawtransaction``: ``locktime`` parameter
    # Error case: RPC_INVALID_PARAMETER / Need a positive value.
    ("createrawtransaction", [ [], {}, -3  ], RPCError.INVALID_PARAMETER,
        "Invalid parameter, locktime out of range"),
    # Error case: RPC_INVALID_PARAMETER / Need a value <= the limit.
    ("createrawtransaction", [ [], {}, 0xFFFFFFFF+1  ], RPCError.INVALID_PARAMETER,
        "Invalid parameter, locktime out of range"),

    ## ``gettransaction``: ``txid`` general parameters
    # Error case: RPC_INVALID_PARAMS / Need at least 1 argument.
    ("gettransaction", [], RPCError.INVALID_PARAMS,
        "Invalid parameters, see documentation for this call"),
    # Error case: RPC_INVALID_PARAMS / Cannot have more than 2 arguments.
    ("gettransaction", ["string", None, None], RPCError.INVALID_PARAMS,
        "Invalid parameters, see documentation for this call"),
    # Error case: RPC_PARSE_ERROR / txid needs to be a string
    ("gettransaction", [12345], RPCError.PARSE_ERROR,
        "JSON value is not a string as expected"),
    # Error case: RPC_PARSE_ERROR / second argument needs to be null
    ("gettransaction", ["string", "string"], RPCError.PARSE_ERROR,
        "JSON value is not a null as expected"),
    # Error case: INVALID_ADDRESS_OR_KEY / txid needs to match with an existing wallet transaction
    ("gettransaction", ["aaaa"], RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid or non-wallet transaction id"),
    # Error case: INVALID_ADDRESS_OR_KEY / invalid hex txids give this error on the node
    ("gettransaction", ["----"], RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid or non-wallet transaction id"),

    ## ``listtransaction``: ``txid`` general parameters
    # Error case: PARSE_ERROR / account param must be null as a placeholder
    ("listtransaction", ["string",], RPCError.PARSE_ERROR,
        "JSON value is not a null as expected"),
    # Error case: PARSE_ERROR / account param must be null as a placeholder
    ("listtransaction", ["",], RPCError.PARSE_ERROR,
        "JSON value is not a null as expected"),
    # Error case: PARSE_ERROR / count param must be an integer
    ("listtransaction", [None, "string"], RPCError.PARSE_ERROR,
        "JSON value is not an integer as expected"),
    # Error case: PARSE_ERROR / skip param must be an integer
    ("listtransaction", [None, 10, "string"], RPCError.PARSE_ERROR,
        "JSON value is not an integer as expected"),
    # Error case: PARSE_ERROR / include_watchonly param must be null as a placeholder
    ("listtransaction", [None, 10, "string"], RPCError.PARSE_ERROR,
    "JSON value is not an integer as expected"),

    ## ``getbalance``: ``minconf`` parameter
    # Error case: RPC_PARSE_ERROR / String in place of account - not supported.
    ("getbalance", ["string"], RPCError.PARSE_ERROR, "JSON value is not a null as expected"),
    # Error case: RPC_PARSE_ERROR / String in place of include_watchonly - not supported.
    ("getbalance", [None, 1, "string"], RPCError.PARSE_ERROR,
        "JSON value is not a null as expected"),
    # Error case: RPC_PARSE_ERROR / String in place of minconf - should be an integer.
    ("getbalance", [None, "string", None], RPCError.PARSE_ERROR,
        "JSON value is not an integer as expected"),

    ## ``listunspent``: ``minconf`` parameter
    # Error case: RPC_PARSE_ERROR / String in place of minimum confirmation count.
    ("listunspent", [ "string" ], RPCError.PARSE_ERROR,
        "JSON value is not an integer as expected"),
    # Error case: RPC_PARSE_ERROR / String in place of maximum confirmation count.
    ("listunspent", [ 0, "string" ], RPCError.PARSE_ERROR,
        "JSON value is not an integer as expected"),
    # Error case: RPC_TYPE_ERROR / Non-list in place of filter address list.
    ("listunspent", [ None, None, 1 ], RPCError.TYPE_ERROR,
        "Expected type list, got int"),
    # Error case: RPC_PARSE_ERROR / Non-string in filter address list.
    ("listunspent", [ None, None, [ 1 ] ], RPCError.PARSE_ERROR,
        "JSON value is not a string as expected"),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Testnet address in filter address list.
    ("listunspent", [ None, None, [ "mneqqWSAQCg6tTP4BUdnPDBRanFqaaryMM" ] ],
        RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid Bitcoin address: unknown version byte 111 for network mainnet"),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Non-address string in filter address list.
    ("listunspent", [ None, None, [ "non-address" ] ], RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid Bitcoin address: invalid base 58 character \"-\""),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Presumably base58 non-address instead of address.
    ("listunspent", [ None, None, [ "test" ] ], RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid Bitcoin address: invalid base 58 checksum for test"),
    # Error case: RPC_INVALID_PARAMETER / Duplicate address in list.
    ("listunspent", [ None, None, [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2",
            "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2" ] ], RPCError.INVALID_PARAMETER,
        "Invalid parameter, duplicated address: 1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2"),
    # Error case: RPC_INVALID_PARAMETER / Integer instead of boolean for `include_unsafe`.
    ("listunspent", [ None, None, None, 1 ], RPCError.PARSE_ERROR,
        "JSON value is not a boolean as expected"),

    ## ``sendtoaddress``: ``address`` parameter
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Testnet version byte in address.
    ("sendtoaddress", [ "mneqqWSAQCg6tTP4BUdnPDBRanFqaaryMM", 10000 ],
        RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid address: unknown version byte 111 for network mainnet"),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Non-base58 address text.
    ("sendtoaddress", [ "non-address", 10000 ], RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid address: invalid base 58 character \"-\""),
    # Error case: RPC_INVALID_ADDRESS_OR_KEY / Presumably base58 non-address instead of address.
    ("sendtoaddress", [ "test", 10000 ], RPCError.INVALID_ADDRESS_OR_KEY,
        "Invalid address: invalid base 58 checksum for test"),
    # Error case: RPC_PARSE_ERROR / Integer instead of string for address.
    ("sendtoaddress", [ 1, 10000 ], RPCError.PARSE_ERROR,
        "JSON value is not a string as expected"),
    ## ``sendtoaddress``: ``amount`` parameter
    # Error case: RPC_TYPE_ERROR / Negative amount to send.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", -100 ], RPCError.TYPE_ERROR,
        "Amount out of range"),
    # Error case: RPC_TYPE_ERROR / Too large amount to send.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 1e10 ], RPCError.TYPE_ERROR,
        "Amount out of range"),
    # Error case: RPC_TYPE_ERROR / Zero amount to send.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 0 ], RPCError.TYPE_ERROR,
        "Invalid amount for send"),
    ## ``sendtoaddress``: ``comment`` parameter
    # Error case: RPC_PARSE_ERROR / Integer instead of string for comment.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000, 1 ], RPCError.PARSE_ERROR,
        "JSON value is not a string as expected"),
    ## ``sendtoaddress``: ``commentto`` parameter
    # Error case: RPC_PARSE_ERROR / Integer instead of string for comment to.
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000, "null", 1 ],
        RPCError.PARSE_ERROR, "JSON value is not a string as expected"),
    ## ``sendtoaddress``: ``subtract_fee_from_amount`` parameter
    # Error case: RPC_INVALID_PARAMETER / Enabled .
    ("sendtoaddress", [ "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2", 10000, None, None, True ],
        RPCError.INVALID_PARAMETER, "Subtract fee from amount not currently supported"),

    ## ``signrawtransaction``: general parameters
    # Error case: RPC_INVALID_PARAMS / Need >= 1 and <= 4 parameters.
    ("signrawtransaction", [ ], RPCError.INVALID_PARAMS,
        "Invalid parameters, see documentation for this call"),
    # Error case: RPC_INVALID_PARAMETER / First parameter needs to be a string.
    ("signrawtransaction", [ None ], RPCError.INVALID_PARAMETER,
        "argument 1 must be hexadecimal string (not 'None') and length of it must be divisible "
        "by 2"),
    # Error case: Second parameter needs to be a list.
    ("signrawtransaction", [ "aa", "" ], RPCError.TYPE_ERROR,
        "Expected type list, got str"),
    # Error case: Third parameter needs to be a list.
    ("signrawtransaction", [ "aa", [], "" ], RPCError.TYPE_ERROR,
        "Expected type list, got str"),
    # Error case: Fourth parameter needs to be a string.
    ("signrawtransaction", [ "aa", [], [], [] ], RPCError.TYPE_ERROR,
        "Expected type str, got list"),
    # Error case: Fourth parameter needs to include SIGHASH_FORKID.
    ("signrawtransaction", [ P2PKH_TRANSACTION_HEX, [], [], "ALL" ], RPCError.INVALID_PARAMETER,
        "Signature must use SIGHASH_FORKID"),
    ("signrawtransaction", [ P2PKH_TRANSACTION_HEX, [], [], "ALL|ANYONECANPAY" ],
        RPCError.INVALID_PARAMETER, "Signature must use SIGHASH_FORKID"),
    ("signrawtransaction", [ P2PKH_TRANSACTION_HEX, [], [], "NONE" ], RPCError.INVALID_PARAMETER,
        "Signature must use SIGHASH_FORKID"),
    ("signrawtransaction", [ P2PKH_TRANSACTION_HEX, [], [], "NONE|ANYONECANPAY" ],
        RPCError.INVALID_PARAMETER, "Signature must use SIGHASH_FORKID"),
    ("signrawtransaction", [ P2PKH_TRANSACTION_HEX, [], [], "SINGLE" ], RPCError.INVALID_PARAMETER,
        "Signature must use SIGHASH_FORKID"),
    ("signrawtransaction", [ P2PKH_TRANSACTION_HEX, [], [], "SINGLE|ANYONECANPAY" ],
        RPCError.INVALID_PARAMETER, "Signature must use SIGHASH_FORKID"),
    # Error case: Fourth parameter needs to be both FORKID and a valid known identifier.
    ("signrawtransaction", [ P2PKH_TRANSACTION_HEX, [], [], "SIGHASH_FORKID" ],
        RPCError.INVALID_PARAMETER, "Invalid sighash param"),
]


# We are checking that methods check their parameters. We do not need to check every permutation of
# every type check, as the unit testing of the type checking functions already does that.
@pytest.mark.parametrize("endpoint_name,parameter_list,error_code,error_text",
    endpoint_error_parameter_list)
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

class CreateInputDict(TypedDict):
    txid: str
    vout: int
    sequence: NotRequired[int]

createrawtransaction_success_parameters: list[tuple[tuple[list[CreateInputDict], dict, int|None],
        str]] = [
    # Input 0 will get a final sequence due to no locktime.
    ((
        [
            { "txid": "aa"*32, "vout": 12 },
            { "txid": "bb"*32, "vout": 24, "sequence": 0 },
        ],
        {
                "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2": 11,
        },
        None
    ), "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0c00000000"
    "ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb180000000000000"
    "0000100ab9041000000001976a9149935f2eaa7bb881c1cf728e940bcc0fda408f01b88ac00000000"),
    # Input 0 will get a default non-final sequence due to locktime.
    ((
        [
            { "txid": "aa"*32, "vout": 12 },
            { "txid": "bb"*32, "vout": 24, "sequence": 0 },
        ],
        {
                "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2": 11,
        },
        243242342
    ), "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0c00000000"
    "feffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb180000000000000"
    "0000100ab9041000000001976a9149935f2eaa7bb881c1cf728e940bcc0fda408f01b88ac66957f0e"),
    # Input 0 will get a default non-final sequence due to locktime.
    ((
        [
            { "txid": "aa"*32, "vout": 12 },
            { "txid": "bb"*32, "vout": 24 },
        ],
        {
                "1Ey71nXGETcEvzpQyhwEaPn7UdGmDyrGF2": 11,
                "data": b"This is a test".hex(),
        },
        None
    ), "0100000002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0c00000000"
    "ffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1800000000fffff"
    "fff0200ab9041000000001976a9149935f2eaa7bb881c1cf728e940bcc0fda408f01b88ac00000000000000"
    "0011006a0e546869732069732061207465737400000000")
]

@pytest.mark.parametrize("parameter_list,resulting_hex", createrawtransaction_success_parameters)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_createrawtransaction_success_async(
        app_state_nodeapi: AppStateProxy, server_tester: TestClient,
        parameter_list: list[CreateInputDict], resulting_hex: str) -> None:
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
        "method": "createrawtransaction",
        "params": parameter_list,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["result"] == resulting_hex
    assert object["error"] is None

TEST_RAWTX = "0100000002adac3845690644e6519ba5bdf1f449431f28dae28091304a63458f56034713b602000000" \
             "6a47304402200c9b6cd76a27f21739ef9c06c8e241f54b2614448da650590bb45b43167e7279022052" \
             "9fc7ea40616c0a2807e734c430d878a111c87ce3dcd9abf93d4292adf432b8412103cbcade5f584e63" \
             "08211224afe817c1995a0ce29fcc6d58b0042c19c527e03572ffffffff447322a683361f9af624847c" \
             "5646928f745bca2e7cc3427025ddb77b4d39e036010000006a473044022020404cfffbe14e14154bd1" \
             "5402d071db805d793ddc7e597f84bfd6cfaf0b2d0402206ff51625db1d50e5332dc8a54031e4277027" \
             "afc7d3b849a1f21e4d1ff3e5bcdc412102a2943c7929d4fda0ce9a4094fc496342c683dfaa19e6c31c" \
             "b9b77ea6f459ae44ffffffff0310270000000000001976a914635fa798e35ab0aa2289684129ff61d3" \
             "d26ec17588ac10270000000000001976a914a71d74f7bacad8f1626cf44680114b9170d3397b88ac3b" \
             "300000000000001976a914e92f00553d65610200efecceffb26c2b286eb81488ac00000000"

@pytest.mark.parametrize("parameters,result", [
    (["e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063"], {
            'amount': -5.5,
            'blockhash': '6c5ecfe2277cd134a5f9dadaa556bb322cbd89c3c6b144794ae3d3b3e0d47101',
            'blockindex': 1,
            'blocktime': 1680047960,
            'confirmations': 1,
            'details': [
                {
                    'account': '',
                    'address': '152bd5gLonDrPbCwncG2JH7XBcni4JRBeo',
                    'abandoned': False,
                    'amount': -0.5,
                    'category': 'send',
                    'fee': -3e-06,
                    'vout': 1,
                    'label': '',
                },
                {
                    'account': '',
                    'address': '1AC2b7ALEF5jvVDBi6zQit42NrSC4nLkmo',
                    'abandoned': False,
                    'amount': -2.0,
                    'category': 'send',
                    'fee': -3e-06,
                    'vout': 2,
                    'label': '',
                },
                {
                    'account': '',
                    'address': '1CYJd9bHUD4tsjCpcoAgjcw15ZWbVnuwky',
                    'abandoned': False,
                    'amount': -3.0,
                    'category': 'send',
                    'fee': -3e-06,
                    'vout': 3,
                    'label': '',
                }
            ],
            'fee': -300 / COIN,
            'hex': TEST_RAWTX,
            'time': 1680047951,
            'timereceived': 1680047951,
            'txid': 'e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063',
            'walletconflicts': []
        },
    ),
    # Note: Block hash 425a970f3375ef9bf31a2486ff7d7e0332834363c765861fceabb8a02e319db8 is known
    # to be on the longest chain at height 13 for headers3_paytomany bitcoinx.Headers store
    (['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], {
                'amount': 0.5,
                'blockhash': '425a970f3375ef9bf31a2486ff7d7e0332834363c765861fceabb8a02e319db8',
                'blockindex': 1,
                'blocktime': 1680045772,
                'confirmations': 102,
                'details': [
                    {
                        'account': '',
                        'address': '152bd5gLonDrPbCwncG2JH7XBcni4JRBeo',
                        'amount': 0.5,
                        'category': 'generate',
                        'vout': 1,
                        'label': '',
                    }
                ],
                'hex': get_small_tx().to_hex(),
                'time': 1680047951,
                'timereceived': 1680047951,
                'txid': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'walletconflicts': [],
                'generated': True
        },
    ),
    (["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"], {
            'amount': 2.0,
            # 'blockhash': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            # 'blockindex': 1,
            # 'blocktime': None,
            'confirmations': 0,
            'details': [
                {
                    'account': '',
                    'address': '1AC2b7ALEF5jvVDBi6zQit42NrSC4nLkmo',
                    'amount': 2.0,
                    'category': 'orphan',
                    'vout': 2,
                    'label': '',
                }
            ],
            'hex': get_small_tx().to_hex(),
            'time': 1680047951,
            'trusted': True,
            'timereceived': 1680047951,
            'txid': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            'walletconflicts': [],
            'generated': True
        },
    ),
    # Note: Block hash 639709e003c203e8bf9aad26bdaa7415c8a1ec06ae3405cb67d5a9d8059ba58f is known
    # to be on the longest chain at height 50 for headers3_paytomany bitcoinx.Headers store
    (["cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"], {
            'amount': 3.0,
            'blockhash': '639709e003c203e8bf9aad26bdaa7415c8a1ec06ae3405cb67d5a9d8059ba58f',
            'blockindex': 1,
            'blocktime': 1680045779,
            'confirmations': 65,
            'details': [
                {
                    'account': '',
                    'address': '1CYJd9bHUD4tsjCpcoAgjcw15ZWbVnuwky',
                    'amount': 3.0,
                    'category': 'immature',
                    'vout': 3,
                    'label': '',
                }
            ],
            'hex': get_small_tx().to_hex(),
            'time': 1680047951,
            'timereceived': 1680047951,
            'txid': 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
            'walletconflicts': [],
            'generated': True
        },
    )
])
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_gettransaction_success_async(app_state_nodeapi: AppStateProxy,
        parameters: list[Any], result: dict[str, Any],
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

    def get_local_height() -> int:
        return 114

    wallet.get_local_height.side_effect = get_local_height

    MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
    file_path = str(MODULE_DIR / "data" / "headers" / "headers3_paytomany")
    headers, cursor = read_cached_headers(BitcoinRegtest, file_path)

    # This is not mocking and I don't know why!
    wallet.get_current_chain.side_effect = headers.longest_chain

    def lookup_header_for_hash(block_hash: bytes) -> tuple[Header, Chain] | None:
        # The bitcoinx Headers.lookup method API has changed in v0.8
        # it used to return a tuple[Header, Chain] and raise MissingHeader if no header
        # was found. This allows us to expose the same API from app_state.lookup as before.
        chain: Chain
        chain, height = headers.lookup(block_hash)
        if chain is None:
            raise MissingHeader(f"No header found for hash: "
                                f"{hash_to_hex_str(block_hash)}")
        header = chain.header_at_height(height)
        return header, chain

    wallet.lookup_header_for_hash.side_effect = lookup_header_for_hash

    def get_transaction(transaction_hash: bytes) -> Transaction:
        if transaction_hash == \
                hex_str_to_hash("e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063"):
            return Transaction.from_hex(TEST_RAWTX)
        return get_small_tx()

    wallet.get_transaction.side_effect = get_transaction

    def read_transaction_fee(tx_hash: bytes) -> float | None:
        if tx_hash == \
                hex_str_to_hash("e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063"):
            return -300 / COIN
        return

    wallet.data.read_transaction_fee.side_effect = read_transaction_fee

    # TODO, use the test wallet with multiple rows for a single transaction
    #  this will allow testing of the multiple details array
    file_path = os.path.join(TEST_WALLET_PATH, "node_api_gettransaction_mock_data.json")

    def convert_json_to_row(json_data: list[dict[str, Any]]) -> list[AccountHistoryOutputRow]:
        rows: list[AccountHistoryOutputRow] = []
        for x in json_data:
            row = AccountHistoryOutputRow(
                tx_hash=hex_str_to_hash(x["tx_id"]),
                txo_index=x["txo_index"],
                script_pubkey_bytes=bytes.fromhex(x["script_pubkey_hex"]),
                is_mine=x["is_mine"],
                is_coinbase=x["is_coinbase"],
                value=x["value"],
                block_hash=hex_str_to_hash(x["block_id"]),
                block_height=x["block_height"],
                block_position=x["block_position"],
                date_created=x["date_created"],
            )
            rows.append(row)
        return rows

    wallet.data.read_history_for_outputs.side_effect = lambda *args, **kwargs: \
        [x for x in convert_json_to_row(json.loads(open(file_path, "r").read()))
            if hash_to_hex_str(x.tx_hash) == parameters[0]]

    # Return a mock list[TransactionOutputSpendRow] - the only field that is used is the `tx_hash`
    wallet.data.read_parent_transaction_outputs_with_key_data.side_effect = \
        lambda *args, **kwargs: [
            TransactionOutputSpendRow(
                txi_index=0,
                tx_hash=parameters[0],
                txo_index=0,
                value=0,
                keyinstance_id=1,
                script_type=ScriptType.P2PKH,
                flags=TransactionOutputFlag.SPENT,
                account_id=2,
                masterkey_id=2,
                derivation_type=DerivationType.BIP32,
                derivation_data2=b"aaaaaaaa"
            )]

    # Params as an empty list
    call_object = {
        "id": 343,
        "method": "gettransaction",
        "params": parameters,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 343
    assert object["result"] == result
    assert isinstance(object["result"], dict)
    assert object["error"] is None


@pytest.mark.parametrize("parameters,result", [
    ([], [
        {
            'abandoned': False,
            'account': '',
            'amount': -5.5,
            'blockhash': '6c5ecfe2277cd134a5f9dadaa556bb322cbd89c3c6b144794ae3d3b3e0d47101',
            'blockindex': 1,
            'blocktime': 1680047960,
            'category': 'send',
            'confirmations': 1,
            'fee': -3e-06,
            'time': 1680047951,
            'timereceived': 1680047951,
            'txid': 'e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063',
            'walletconflicts': []
            # These fields are omitted as expected - see readthedocs page:
            # - generated
            # - trusted
            # - address
            # - vout
        }
    ])
])
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_listtransaction_success_async(app_state_nodeapi: AppStateProxy,
        parameters: list[Any], result: dict[str, Any],
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

    def read_transaction_hashes(account_id: int | None = None, limit_count: int | None = None,
            skip_count: int = 0) -> list[TransactionRow]:
        return [
            hex_str_to_hash("e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063")
        ]
    wallet.data.read_transaction_hashes.side_effect = read_transaction_hashes

    def get_local_height() -> int:
        return 114

    wallet.get_local_height.side_effect = get_local_height

    MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
    headers, cursor = read_cached_headers(BitcoinRegtest,
        file_path=str(MODULE_DIR / "data" / "headers" / "headers3_paytomany"))

    # This is not mocking and I don't know why!
    wallet.get_current_chain.side_effect = headers.longest_chain

    def lookup_header_for_hash(block_hash: bytes) -> tuple[Header, Chain] | None:
        # The bitcoinx Headers.lookup method API has changed in v0.8
        # it used to return a tuple[Header, Chain] and raise MissingHeader if no header
        # was found. This allows us to expose the same API from app_state.lookup as before.
        chain: Chain
        chain, height = headers.lookup(block_hash)
        if chain is None:
            raise MissingHeader(f"No header found for hash: "
                                f"{hash_to_hex_str(block_hash)}")
        header = chain.header_at_height(height)
        return header, chain

    wallet.lookup_header_for_hash.side_effect = lookup_header_for_hash

    def get_transaction(transaction_hash: bytes) -> Transaction:
        if transaction_hash == \
                hex_str_to_hash("e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063"):
            return Transaction.from_hex(TEST_RAWTX)
        return get_small_tx()

    wallet.get_transaction.side_effect = get_transaction

    def read_transaction_fee(tx_hash: bytes) -> float | None:
        if tx_hash == \
                hex_str_to_hash("e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063"):
            return -300 / COIN
        return

    wallet.data.read_transaction_fee.side_effect = read_transaction_fee

    file_path = os.path.join(TEST_WALLET_PATH, "node_api_gettransaction_mock_data.json")

    def convert_json_to_row(json_data: list[dict[str, Any]]) -> list[AccountHistoryOutputRow]:
        rows: list[AccountHistoryOutputRow] = []
        for x in json_data:
            row = AccountHistoryOutputRow(
                tx_hash=hex_str_to_hash(x["tx_id"]),
                txo_index=x["txo_index"],
                script_pubkey_bytes=bytes.fromhex(x["script_pubkey_hex"]),
                is_mine=x["is_mine"],
                is_coinbase=x["is_coinbase"],
                value=x["value"],
                block_hash=hex_str_to_hash(x["block_id"]),
                block_height=x["block_height"],
                block_position=x["block_position"],
                date_created=x["date_created"],
            )
            rows.append(row)
        return rows

    wallet.data.read_history_for_outputs.side_effect = lambda *args, **kwargs: \
        [x for x in convert_json_to_row(json.loads(open(file_path, "r").read()))
            if hash_to_hex_str(x.tx_hash) ==
               "e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063"]

    # Return a mock list[TransactionOutputSpendRow] - the only field that is used is the `tx_hash`
    wallet.data.read_parent_transaction_outputs_with_key_data.side_effect = \
        lambda *args, **kwargs: [
            TransactionOutputSpendRow(
                txi_index=0,
                tx_hash=parameters[0],
                txo_index=0,
                value=0,
                keyinstance_id=1,
                script_type=ScriptType.P2PKH,
                flags=TransactionOutputFlag.SPENT,
                account_id=2,
                masterkey_id=2,
                derivation_type=DerivationType.BIP32,
                derivation_data2=b"aaaaaaaa"
            )]

    # Params as an empty list
    call_object = {
        "id": 343,
        "method": "listtransaction",
        "params": parameters,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 343
    assert object["result"] == result
    assert isinstance(object["result"], list)
    assert object["error"] is None


@pytest.mark.parametrize("local_height,block_height,parameters,results", [
    # Empty parameters array.
    (101, 100, [], 1.0),
    # Params as jsonrpc v2.0 dictionary
    (101, 100, {"account": None, "minconf": 1, "include_watchonly": None}, 1.0),
    # Miniconf=0 should include the unconfirmed UTXO
    (101, 100, {"account": None, "minconf": 0, "include_watchonly": None}, 3.0),
])
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getbalance_success_async(app_state_nodeapi: AppStateProxy, local_height: int,
        block_height: int, parameters: list[Any], results: list[dict[str, Any]],
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

    confirmed: int = 100000000
    unconfirmed: int = 200000000
    unmatured: int = 300000000
    allocated: int = 0
    account.get_balance.side_effect = lambda *args, **kwargs: WalletBalance(confirmed, unconfirmed,
        unmatured, allocated)

    def get_transaction_outputs_with_key_and_tx_data(exclude_frozen: bool=True,
            confirmed_only: bool|None=None, keyinstance_ids: list[int]|None=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        assert exclude_frozen is True
        assert keyinstance_ids is None
        utxos = []
        if not confirmed_only:
            # Unconfirmed UTXO
            utxos.append(
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 200000000,
                1111111, ScriptType.P2PKH, TransactionOutputFlag.NONE, 1, 1,
                DerivationType.BIP32_SUBPATH, FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED,
                None, b""),)
        utxos.extend([
            # Confirmed UTXO
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 50000000,
                1111111, ScriptType.P2PKH, TransactionOutputFlag.NONE, 1, 1,
                DerivationType.BIP32_SUBPATH,
                FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED, FAKE_BLOCK_HASH, b""),
            # Unmatured UTXO
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 300000000,
                1111111, ScriptType.P2PKH, TransactionOutputFlag.COINBASE, 1, 1,
                DerivationType.BIP32_SUBPATH, FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED,
                FAKE_BLOCK_HASH, b""),
            # Matured UTXO (coinbase that has matured) - FAKE_BLOCK_HASH2 has height == 1
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 50000000,
                1111111, ScriptType.P2PKH, TransactionOutputFlag.COINBASE, 1, 1,
                DerivationType.BIP32_SUBPATH, FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED,
                FAKE_BLOCK_HASH2, b""),
        ])
        return utxos

    account.get_transaction_outputs_with_key_and_tx_data.side_effect = \
        get_transaction_outputs_with_key_and_tx_data

    # Prepare the state so we can fake confirmations.
    wallet.get_local_height = lambda: local_height
    def lookup_header_for_hash(block_hash: bytes) -> tuple[bitcoinx.Header, bitcoinx.Chain]|None:
        if block_hash == FAKE_BLOCK_HASH:
            header = unittest.mock.Mock(spec=bitcoinx.Header)
            header.height = block_height
            chain = unittest.mock.Mock(spec=bitcoinx.Chain)
            return header, chain
        # FAKE_BLOCK_HASH2 is used to put this utxo in an early block to mature the coinbase UTXO
        elif block_hash == FAKE_BLOCK_HASH2:
            header = unittest.mock.Mock(spec=bitcoinx.Header)
            header.height = 1
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

    # Params as an empty list
    call_object = {
        "id": 343,
        "method": "getbalance",
        "params": parameters,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 343
    assert object["result"] == results
    assert isinstance(object["result"], float)
    assert object["error"] is None


@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getbalance_unsupported_derivation_type_async(app_state_nodeapi: AppStateProxy,
        server_tester: TestClient) -> None:
    local_height = 100
    block_height = 10
    parameters = {"account": None, "minconf": 1, "include_watchonly": None}
    results = 0.0

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

    confirmed: int = 100000000
    unconfirmed: int = 200000000
    unmatured: int = 300000000
    allocated: int = 0
    account.get_balance.side_effect = lambda *args, **kwargs: WalletBalance(confirmed, unconfirmed,
        unmatured, allocated)

    def get_transaction_outputs_with_key_and_tx_data(exclude_frozen: bool=True,
            confirmed_only: bool|None=None, keyinstance_ids: list[int]|None=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        assert exclude_frozen is True
        assert keyinstance_ids is None
        utxos = []
        if not confirmed_only:
            # Unconfirmed UTXO
            utxos.append(
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 200000000,
                1111111, ScriptType.P2PKH, TransactionOutputFlag.NONE, 1, 1,
                DerivationType.ELECTRUM_OLD, FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED,
                None, b""),)
        utxos.extend([
            # Confirmed UTXO
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 50000000,
                1111111, ScriptType.P2PKH, TransactionOutputFlag.NONE, 1, 1,
                DerivationType.ELECTRUM_OLD,
                FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED, FAKE_BLOCK_HASH, b""),
            # Unmatured UTXO
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 300000000,
                1111111, ScriptType.P2PKH, TransactionOutputFlag.COINBASE, 1, 1,
                DerivationType.ELECTRUM_OLD, FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED,
                FAKE_BLOCK_HASH, b""),
            # Matured UTXO (coinbase that has matured) - FAKE_BLOCK_HASH2 has height == 1
            AccountTransactionOutputSpendableRowExtended(FAKE_TRANSACTION_HASH, 0, 50000000,
                1111111, ScriptType.P2PKH, TransactionOutputFlag.COINBASE, 1, 1,
                DerivationType.ELECTRUM_OLD, FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED,
                FAKE_BLOCK_HASH2, b""),
        ])
        return utxos

    account.get_transaction_outputs_with_key_and_tx_data.side_effect = \
        get_transaction_outputs_with_key_and_tx_data

    # Prepare the state so we can fake confirmations.
    wallet.get_local_height = lambda: local_height
    def lookup_header_for_hash(block_hash: bytes) -> tuple[bitcoinx.Header, bitcoinx.Chain]|None:
        if block_hash == FAKE_BLOCK_HASH:
            header = unittest.mock.Mock(spec=bitcoinx.Header)
            header.height = block_height
            chain = unittest.mock.Mock(spec=bitcoinx.Chain)
            return header, chain
        # FAKE_BLOCK_HASH2 is used to put this utxo in an early block to mature the coinbase UTXO
        elif block_hash == FAKE_BLOCK_HASH2:
            header = unittest.mock.Mock(spec=bitcoinx.Header)
            header.height = 1
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

    # Params as an empty list
    call_object = {
        "id": 343,
        "method": "getbalance",
        "params": parameters,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 343
    assert object['result'] is None
    assert isinstance(object["error"], dict)
    assert object['error'] == {
        'code': -8,
        'message': 'Invalid parameter, unexpected utxo type: DerivationType.ELECTRUM_OLD'
    }


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
    assert object["error"]["code"] == RPCError.WALLET_ERROR
    assert object["error"]["message"] == "No connected blockchain server"

@unittest.mock.patch('electrumsv.nodeapi.app_state', new_callable=_create_mock_app_state2)
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

    async def create_monitored_blockchain_payment_async(contact_id: int|None,
            amount_satoshis: int | None, internal_description: str | None,
            merchant_reference: str | None, date_expires: int | None = None) \
                -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow],
                    TipFilterRegistrationJobOutput]:
        assert amount_satoshis is None
        assert internal_description is None
        assert merchant_reference is None
        raise NoViableServersError
    account.create_monitored_blockchain_payment_async = \
        create_monitored_blockchain_payment_async

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
    assert object["error"]["code"] == RPCError.WALLET_ERROR
    assert object["error"]["message"] == \
        "Blockchain server address monitoring request not successful"

@unittest.mock.patch('electrumsv.nodeapi.app_state', new_callable=_create_mock_app_state2)
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

    job_data = unittest.mock.Mock(spec=TipFilterRegistrationJobOutput)
    job_data.completed_event = unittest.mock.Mock(spec=asyncio.Event)
    job_data.date_registered = None
    job_data.failure_reason = "The server had a problem test message"

    async def create_monitored_blockchain_payment_async(contact_id: int|None,
            amount_satoshis: int | None, internal_description: str | None,
            merchant_reference: str | None, date_expires: int | None = None) \
                -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow],
                    TipFilterRegistrationJobOutput]:
        assert amount_satoshis is None
        assert internal_description is None
        assert merchant_reference is None
        return payment_request_row, [ payment_request_output_row ], job_data
    account.create_monitored_blockchain_payment_async = \
        create_monitored_blockchain_payment_async

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
    assert object["error"]["code"] == RPCError.WALLET_ERROR
    assert object["error"]["message"] == job_data.failure_reason

@unittest.mock.patch('electrumsv.nodeapi.app_state', new_callable=_create_mock_app_state2)
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

    job_data = unittest.mock.Mock(spec=TipFilterRegistrationJobOutput)
    job_data.completed_event = unittest.mock.Mock(spec=asyncio.Event)
    job_data.date_registered = 11111
    job_data.failure_reason = None

    async def create_monitored_blockchain_payment_async(contact_id: int|None,
            amount_satoshis: int | None, internal_description: str | None,
            merchant_reference: str | None, date_expires: int | None = None) \
                -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow],
                    TipFilterRegistrationJobOutput]:
        assert amount_satoshis is None
        assert internal_description is None
        assert merchant_reference is None
        return payment_request_row, [ payment_request_output_row ], job_data
    account.create_monitored_blockchain_payment_async = \
        create_monitored_blockchain_payment_async

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


@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_getrawchangeaddress_success_async(app_state_nodeapi: AppStateProxy,
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

    account.reserve_unassigned_key.side_effect = lambda *args, **kwargs: \
        KeyData(1, 0, 1, DerivationType.PUBLIC_KEY_HASH, FAKE_DERIVATION_DATA2)
    account.get_default_script_type.side_effect = lambda *args, **kwargs: ScriptType.P2PKH
    account.get_script_for_derivation.side_effect = lambda *args, **kwargs: \
        bitcoinx.Script(bytes.fromhex("76a9149935f2eaa7bb881c1cf728e940bcc0fda408f01b88ac"))

    call_object = {
        "id": 232,
        "method": "getrawchangeaddress",
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
    # Filter for <=90 confirmations, match the 90 confirmations entry.
    (100, 10, [ None, 90 ], [
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
                FAKE_DERIVATION_DATA2, 1, TxFlag.STATE_SETTLED, FAKE_BLOCK_HASH, b"")
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
    assert object["error"]["code"] == RPCError.WALLET_UNLOCK_NEEDED
    assert object["error"]["message"] == "Error: Please enter the wallet passphrase with " \
        "walletpassphrase first."

class SignRawTransactionMockDataDict(TypedDict):
    # Mapping of compressed public key hex to signature hex.
    signatures: dict[str, str]

with open(os.path.join(TEST_NODEAPI_PATH, "signrawtransaction_ok.json"), "r") as f:
    signrawtransaction_parameters = json.load(f)

@pytest.mark.parametrize("testcase_description,parameter_list,mock_data,response_payload_object",
    signrawtransaction_parameters)
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_signrawtransaction_ok_async(
        app_state_nodeapi: AppStateProxy, server_tester: TestClient,
        testcase_description: str, parameter_list: list[Any],
        mock_data: SignRawTransactionMockDataDict,
        response_payload_object: nodeapi.SignRawTransactionResultDict) -> None:
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

    account = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        nonlocal account
        return [ account ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    x_public_keys_by_coin: dict[Outpoint, dict[bytes, XPublicKey]] = {}

    def get_transaction_outputs_with_key_and_tx_data(exclude_frozen: bool=True,
            confirmed_only: bool|None=None, keyinstance_ids: list[int]|None=None,
            outpoints: list[Outpoint]|None=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        """
        Convert the JSON pretend database coins to mocked database rows.
        """
        nonlocal mock_data, x_public_keys_by_coin
        mock_coin_rows: list[AccountTransactionOutputSpendableRowExtended] = []
        for mock_prevout in mock_data.get("prevouts", []):
            mock_row = unittest.mock.Mock(spec=AccountTransactionOutputSpendableRowExtended)
            mock_row.tx_hash = bitcoinx.hex_str_to_hash(mock_prevout["txid"])
            mock_row.txo_index = mock_prevout["vout"]
            mock_row.script_bytes = bytes.fromhex(mock_prevout["scriptPubKey"])
            script = bitcoinx.Script(mock_row.script_bytes)
            script_type, threshold, script_template = classify_transaction_output_script(script)
            mock_row.script_type = script_type
            mock_row.value = coins_to_satoshis(mock_prevout["amount"])
            mock_row.block_hash = None
            if mock_prevout.get("is_spent"):
                mock_row.flags = TransactionOutputFlag.SPENT
            else:
                mock_row.flags = TransactionOutputFlag.NONE
            mock_coin_rows.append(mock_row)

            outpoint = Outpoint(mock_row.tx_hash, mock_row.txo_index)
            x_public_keys_by_coin[outpoint] = {}
            for public_key_hex in mock_prevout.get("public_keys_hex", []):
                x_public_key = XPublicKey.from_hex(public_key_hex)
                x_public_keys_by_coin[outpoint][x_public_key.to_bytes()] = x_public_key

        return mock_coin_rows
    account.get_transaction_outputs_with_key_and_tx_data = \
        get_transaction_outputs_with_key_and_tx_data

    def get_threshold() -> int:
        return 1
    account.get_threshold = get_threshold

    def get_extended_input_for_spendable_output(row: TransactionOutputSpendableProtocol) \
            -> XTxInput:
        """
        Propagate the mocked database rows to extended transaction input metadata.
        """
        extended_transaction_input = XTxInput(row.tx_hash, row.txo_index, bitcoinx.Script(),
            0xFFFFFFFF)
        extended_transaction_input.script_type = row.script_type
        extended_transaction_input.value = row.value
        outpoint = Outpoint(row.tx_hash, row.txo_index)
        extended_transaction_input.x_pubkeys = x_public_keys_by_coin[outpoint]
        return extended_transaction_input
    account.get_extended_input_for_spendable_output = get_extended_input_for_spendable_output

    def sign_transaction(tx: Transaction, password: str, context: TransactionContext|None=None) \
            -> concurrent.futures.Future[None] | None:
        nonlocal mock_data
        """
        We are not testing that the wallet is signing correctly. We are taking JSON pretend
        metadata and putting it in place and checking that the nodeapi endpoint is behaving
        correctly.
        """
        assert isinstance(tx, Transaction)
        # We're not actually signing here, we are injecting data that looks like signing.
        future = concurrent.futures.Future()
        future.set_result(False)

        generated_signatures: dict[bytes, bytes] = {}
        for public_key_hex, signature_hex in mock_data.get("signatures", {}).items():
            generated_signatures[bytes.fromhex(public_key_hex)] = bytes.fromhex(signature_hex)
        for transaction_input in tx.inputs:
            # We do not sign inputs that are already signed.
            if len(transaction_input.script_sig) > 0:
                continue
            # We need to have been given the public key metadata to know what public keys were
            # used in signing this.
            if len(transaction_input.x_pubkeys) == 0:
                continue

            # Sanity test our mocking has resulted in the correct data.
            assert transaction_input.script_type != ScriptType.NONE
            assert len(transaction_input.signatures) == 0

            # We do not handle other script types at this time.
            assert transaction_input.script_type == ScriptType.P2PKH

            relevant_generated_signatures: dict[bytes, bytes] = {}
            for public_key_bytes, signature_bytes in generated_signatures.items():
                if public_key_bytes in transaction_input.x_pubkeys:
                    relevant_generated_signatures[public_key_bytes] = signature_bytes

            if len(relevant_generated_signatures) > 0:
                script_sig = create_script_sig(transaction_input.script_type, 1,
                    transaction_input.x_pubkeys, relevant_generated_signatures)
                assert script_sig is not None
                transaction_input.script_sig = script_sig

        return future
    account.sign_transaction = sign_transaction

    call_object = {
        "id": 232,
        "method": "signrawtransaction",
        "params": parameter_list,
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.OK
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["error"] is None
    assert object["result"] == response_payload_object

@pytest.mark.parametrize("transactions_hex,privkeys,sighashtype,mock_data,error_code,"
    "error_message", (
        ("0100000000000000000001000000000000000000", None, None, {},
            RPCError.DESERIALIZATION_ERROR,
            "Compatibility difference (multiple transactions not accepted)"),
        ("01000000000000000000", [ "fakekey" ], None, {},
            RPCError.INVALID_PARAMETER, "Compatibility difference (external keys not accepted)"),
        ("01000000000000000000", None, "ALL|FORKID|ANYONECANPAY", {},
            RPCError.INVALID_PARAMETER,
            "Compatibility difference (only ALL|FORKID sighash accepted)"),
        ("010000000141414141414141414141414141414141414141414141414141414141414141410a0000000500"
            "00000000ffffffff0000000000", None, None, {
                "prevouts": [
                    {
                        "txid": "4141414141414141414141414141414141414141414141414141414141414141",
                        "vout": 10,
                        # Multisig, 3 of 4.
                        "scriptPubKey": '5321036aa35b68bdd1b27a0f74a36ccb92bfae30ae49c5d73271dd4a1c36c10710e0ba2102599b3edd084f0f03cf9fee18baeed1e0d888f21b07044599c477ed6806e919e82103b700b196d242dfd97491441765425f41097c61660c65d1e6f71f21f33659b292210210045649324d7a8bd6810b9025b2f411655c492c6885b7f1dd101b24582ae8cb54ae',
                        "amount": 0.01,
                    }
                ]
            },
            RPCError.DESERIALIZATION_ERROR,
            "Compatibility difference (non-P2PKH coins not accepted)"),
    ))
@unittest.mock.patch('electrumsv.nodeapi.app_state')
async def test_call_signrawtransaction_incompatibility_async(
        app_state_nodeapi: AppStateProxy, transactions_hex: str, privkeys: list[str],
        sighashtype: str, mock_data: SignRawTransactionMockDataDict,
        error_code: RPCError, error_message: str,
        server_tester: TestClient) -> None:
    """
    While the `signrawtransaction` node API endpoint ...
    """
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

    account = unittest.mock.Mock(spec=StandardAccount)
    def get_visible_accounts() -> list[StandardAccount]:
        nonlocal account
        return [ account ]
    wallet.get_visible_accounts.side_effect = get_visible_accounts

    def get_transaction_outputs_with_key_and_tx_data(exclude_frozen: bool=True,
            confirmed_only: bool|None=None, keyinstance_ids: list[int]|None=None,
            outpoints: list[Outpoint]|None=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        nonlocal mock_data
        mock_coin_rows: list[AccountTransactionOutputSpendableRowExtended] = []
        for mock_prevout in mock_data.get("prevouts", []):
            mock_row = unittest.mock.Mock(spec=AccountTransactionOutputSpendableRowExtended)
            mock_row.tx_hash = bitcoinx.hex_str_to_hash(mock_prevout["txid"])
            mock_row.txo_index = mock_prevout["vout"]
            mock_row.script_bytes = bytes.fromhex(mock_prevout["scriptPubKey"])
            script = bitcoinx.Script(mock_row.script_bytes)
            script_type, threshold, script_template = classify_transaction_output_script(script)
            mock_row.script_type = script_type
            mock_row.value = coins_to_satoshis(mock_prevout["amount"])
            mock_row.block_hash = None
            if mock_prevout.get("is_spent"):
                mock_row.flags = TransactionOutputFlag.SPENT
            else:
                mock_row.flags = TransactionOutputFlag.NONE
            mock_coin_rows.append(mock_row)
        return mock_coin_rows
    account.get_transaction_outputs_with_key_and_tx_data = \
        get_transaction_outputs_with_key_and_tx_data

    def get_extended_input_for_spendable_output(row: TransactionOutputSpendableProtocol) \
            -> XTxInput:
        """
        Propagate the mocked database rows to extended transaction input metadata.
        """
        extended_transaction_input = XTxInput(row.tx_hash, row.txo_index, bitcoinx.Script(),
            0xFFFFFFFF)
        extended_transaction_input.script_type = row.script_type
        extended_transaction_input.value = row.value
        return extended_transaction_input
    account.get_extended_input_for_spendable_output = get_extended_input_for_spendable_output

    call_object = {
        "id": 232,
        "method": "signrawtransaction",
        "params": [ transactions_hex, None, privkeys, sighashtype ],
    }
    response = await server_tester.request(path="/", method="POST", json=call_object)
    assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
    object = await response.json()
    assert len(object) == 3
    assert object["id"] == 232
    assert object["error"] == { "code": error_code, "message": error_message }
    assert object["result"] is None


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
    assert object["error"]["code"] == RPCError.PARSE_ERROR
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
    assert object["error"]["code"] == RPCError.PARSE_ERROR
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
    assert object["error"]["code"] == RPCError.PARSE_ERROR
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

