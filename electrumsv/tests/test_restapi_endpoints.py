from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Any, cast
import unittest.mock

from aiohttp import web
from bitcoinx import PrivateKey
import pytest

from electrumsv.app_state import AppStateProxy
from electrumsv.restapi_endpoints import LocalEndpoints
from electrumsv.storage import WalletStorage
from electrumsv.wallet import Wallet


# Endpoint: load wallet

@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_load_wallet_async_daemon_fail(mock_app_state: AppStateProxy, tmp_path: Path) -> None:
    """ Load a wallet unsuccessfully because it appears unloaded. """
    # Inject a wallet path so our folder path isn't a stringified magic mock.
    mock_app_state.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    # Inject a failed wallet load so the daemon does not have to exist.
    mock_app_state.daemon.load_wallet = lambda wallet_path: None # type: ignore
    request = unittest.mock.Mock()

    local_endpoints = LocalEndpoints()
    request.match_info = {
        "network": "mainnet",
        "wallet": "wallet_file_name",
    }
    with pytest.raises(web.HTTPBadRequest) as exception_info:
        await local_endpoints.load_wallet_async(cast(web.Request, request))
    assert "Wallet file does not exist 'wallet_file_name'" == exception_info.value.args[0]

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_load_wallet_async_daemon_success(app_state_restapi: AppStateProxy,
        app_state_migration29: AppStateProxy, app_state_wallet: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Load a wallet successfully. """
    wallet: Wallet | None = None
    # Inject a wallet path so our folder path isn't a stringified magic mock.
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    # Inject the wallet so the daemon does not have to exist.
    app_state_restapi.daemon.load_wallet = lambda wallet_path: wallet # type: ignore
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"

    canonical_wallet_path = WalletStorage.canonical_path(str(tmp_path / "wallet_file_name"))
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    wallet_storage = WalletStorage.create(canonical_wallet_path, password_token)
    wallet = Wallet(wallet_storage, "123456")

    local_endpoints = LocalEndpoints()
    request = unittest.mock.Mock()
    request.match_info = {
        "network": "mainnet",
        "wallet": "wallet_file_name",
    }
    response = await local_endpoints.load_wallet_async(cast(web.Request, request))
    wallet_data = json.loads(cast(bytes, response.body))
    assert wallet_data["ephemeral_wallet_id"] == wallet.get_id()
    assert wallet_data["wallet_path"] == canonical_wallet_path
    assert wallet_data["account_ids"] == []

# Endpoint: create wallet

@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_wallet_async_invalid_body(mock_app_state: AppStateProxy, tmp_path: Path) \
        -> None:
    """ Create a wallet with an invalid body. """
    mock_app_state.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    request = unittest.mock.Mock()
    request.match_info = {
        "network": "mainnet",
    }
    async def request_json_async() -> dict[str, Any]:
        return {}
    request.json = request_json_async

    local_endpoints = LocalEndpoints()
    with pytest.raises(web.HTTPBadRequest) as exception_info:
        await local_endpoints.create_wallet_async(cast(web.Request, request))
    assert "Invalid request body" == exception_info.value.args[0]

@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_wallet_async_invalid_file_name(mock_app_state: AppStateProxy,
        tmp_path: Path) -> None:
    """ Create a wallet with invalid file name in the body. """
    mock_app_state.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    request = unittest.mock.Mock()
    request.match_info = {
        "network": "mainnet",
    }
    async def request_json_async() -> dict[str, Any]:
        return {
            "file_name": None,
            "password": "123456",
        }
    request.json = request_json_async

    local_endpoints = LocalEndpoints()
    with pytest.raises(web.HTTPBadRequest) as exception_info:
        await local_endpoints.create_wallet_async(cast(web.Request, request))
    assert "Invalid request body 'file_name'" == exception_info.value.args[0]

@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_wallet_async_invalid_password(mock_app_state: AppStateProxy, tmp_path: Path) \
        -> None:
    """ Create a wallet with invalid password in the body. """
    mock_app_state.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    request = unittest.mock.Mock()
    request.match_info = {
        "network": "mainnet",
    }
    async def request_json_async() -> dict[str, Any]:
        return {
            "file_name": "wallet_file_name",
            "password": None,
        }
    request.json = request_json_async

    local_endpoints = LocalEndpoints()
    with pytest.raises(web.HTTPBadRequest) as exception_info:
        await local_endpoints.create_wallet_async(cast(web.Request, request))
    assert "Invalid request body 'password'" == exception_info.value.args[0]

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_wallet_async_success_no_seed(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create a wallet and do not provide a public key so we get just the basic data back. """
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore
    request = unittest.mock.Mock()
    request.match_info = {
        "network": "mainnet",
    }
    async def request_json_async() -> dict[str, Any]:
        return {
            "file_name": "wallet_file_name",
            "password": "123456",
        }
    request.json = request_json_async
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"

    local_endpoints = LocalEndpoints()
    response = await local_endpoints.create_wallet_async(cast(web.Request, request))
    wallet_data = json.loads(cast(bytes, response.body))
    wallet_path = str(tmp_path / "wallet_file_name")
    expected_wallet_path = WalletStorage.canonical_path(wallet_path)

    assert len(wallet_data) == 3
    assert isinstance(wallet_data["ephemeral_wallet_id"], int)
    assert wallet_data["wallet_path"] == expected_wallet_path
    assert wallet_data["account_ids"] == []

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_wallet_async_success_encrypted_seed(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create a wallet but provide a public key so we get the encrypted seed words back. """
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore
    private_key = PrivateKey.from_random()
    public_key = private_key.public_key
    request = unittest.mock.Mock()
    request.match_info = {
        "network": "mainnet",
    }
    async def request_json_async() -> dict[str, Any]:
        return {
            "file_name": "wallet_file_name",
            "password": "123456",
            "encryption_key_hex": public_key.to_hex(),
        }
    request.json = request_json_async
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"

    local_endpoints = LocalEndpoints()
    response = await local_endpoints.create_wallet_async(cast(web.Request, request))
    wallet_data = json.loads(cast(bytes, response.body))
    wallet_path = str(tmp_path / "wallet_file_name")
    expected_wallet_path = WalletStorage.canonical_path(wallet_path)

    assert len(wallet_data) == 4
    assert isinstance(wallet_data["ephemeral_wallet_id"], int)
    assert wallet_data["wallet_path"] == expected_wallet_path
    assert wallet_data["account_ids"] == []
    assert "wallet_seed" in wallet_data

    encrypted_wallet_seed_hex = wallet_data["wallet_seed"]
    seed_words_text = private_key.decrypt_message(bytes.fromhex(encrypted_wallet_seed_hex)).decode()
    words = seed_words_text.split(" ")
    # We do not know what these words are, and we do not care. This is good enough to check.
    assert len(words) == 12

# Endpoint: create account

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_account_async_success(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create an account. """
    # BOILERPLATE STARTS
    # Inject a wallet path so our folder path isn't a stringified magic mock.
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    # # Inject the wallet so the daemon does not have to exist.
    # app_state_restapi.daemon.load_wallet = lambda wallet_path: wallet # type: ignore
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore

    canonical_wallet_path = WalletStorage.canonical_path(str(tmp_path / "wallet_file_name"))
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    wallet_storage = WalletStorage.create(canonical_wallet_path, password_token)
    local_wallet = Wallet(wallet_storage, "123456")

    def get_wallet_by_id(wallet_id: int) -> Wallet:
        nonlocal local_wallet
        assert local_wallet.get_id() == wallet_id
        return local_wallet
    app_state_restapi.daemon.get_wallet_by_id = get_wallet_by_id
    # BOILERPLATE ENDS

    account_request = unittest.mock.Mock()
    # Fake routing.
    account_request.match_info = {
        "network": "mainnet",
        "wallet": str(local_wallet.get_id()),
    }
    # Fake query string.
    account_request.query = {
        "password": "123456",
    }

    local_endpoints = LocalEndpoints()
    response = await local_endpoints.create_account_async(cast(web.Request, account_request))
    account_data = json.loads(cast(bytes, response.body))
    assert len(account_data) == 1
    assert "account_id" in account_data
    assert isinstance(account_data["account_id"], int)

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_account_async_fail_no_wallet(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create an account and fail because the referenced wallet does not exist. """
    def get_wallet_by_id(wallet_id: int) -> Wallet | None:
        return None

    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    app_state_restapi.daemon.get_wallet_by_id = get_wallet_by_id
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"
    local_endpoints = LocalEndpoints()

    account_request = unittest.mock.Mock()
    # Fake routing.
    account_request.match_info = {
        "network": "mainnet",
        "wallet": "223232",
    }
    # Fake query string.
    account_request.query = {
        "password": "123456",
    }

    local_endpoints = LocalEndpoints()
    with pytest.raises(web.HTTPBadRequest) as exception_info:
        await local_endpoints.create_account_async(cast(web.Request, account_request))
    assert "Wallet with ID '223232' not currently loaded" == exception_info.value.args[0]

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_account_async_bad_wallet_id(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create an account. """
    # BOILERPLATE STARTS
    # Inject a wallet path so our folder path isn't a stringified magic mock.
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    # # Inject the wallet so the daemon does not have to exist.
    # app_state_restapi.daemon.load_wallet = lambda wallet_path: wallet # type: ignore
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore

    canonical_wallet_path = WalletStorage.canonical_path(str(tmp_path / "wallet_file_name"))
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    wallet_storage = WalletStorage.create(canonical_wallet_path, password_token)
    local_wallet = Wallet(wallet_storage, "123456")

    def get_wallet_by_id(wallet_id: int) -> Wallet:
        nonlocal local_wallet
        assert local_wallet.get_id() == wallet_id
        return local_wallet
    app_state_restapi.daemon.get_wallet_by_id = get_wallet_by_id
    # BOILERPLATE ENDS

    account_request = unittest.mock.Mock()
    # Fake routing.
    account_request.match_info = {
        "network": "mainnet",
        "wallet": "none",           # NOTE: The existing wallet proves that it is not matched.
    }
    # Fake query string.
    account_request.query = {
        "password": "123456",
    }

    local_endpoints = LocalEndpoints()
    with pytest.raises(web.HTTPBadRequest) as exception_info:
        await local_endpoints.create_account_async(cast(web.Request, account_request))
    assert "URL 'wallet' value invalid" == exception_info.value.args[0]

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_account_async_fail_wallet_password(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create an account. """
    # BOILERPLATE STARTS
    # Inject a wallet path so our folder path isn't a stringified magic mock.
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    # # Inject the wallet so the daemon does not have to exist.
    # app_state_restapi.daemon.load_wallet = lambda wallet_path: wallet # type: ignore
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore

    canonical_wallet_path = WalletStorage.canonical_path(str(tmp_path / "wallet_file_name"))
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    wallet_storage = WalletStorage.create(canonical_wallet_path, password_token)
    local_wallet = Wallet(wallet_storage, "123456")

    def get_wallet_by_id(wallet_id: int) -> Wallet:
        nonlocal local_wallet
        assert local_wallet.get_id() == wallet_id
        return local_wallet
    app_state_restapi.daemon.get_wallet_by_id = get_wallet_by_id
    # BOILERPLATE ENDS

    account_request = unittest.mock.Mock()
    # Fake routing.
    account_request.match_info = {
        "network": "mainnet",
        "wallet": str(local_wallet.get_id()),
    }
    # Fake query string.
    account_request.query = {
        "password": "BAD_123456",
    }
    password_token.password = "BAD_123456"
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "BAD_123456"

    local_endpoints = LocalEndpoints()
    with pytest.raises(web.HTTPBadRequest) as exception_info:
        await local_endpoints.create_account_async(cast(web.Request, account_request))
    assert "Wallet password is not correct" == exception_info.value.args[0]

# Endpoint: create a hosted invoice

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_hosted_invoice_async_success(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create a hosted invoice. """
    # BOILERPLATE STARTS
    # Inject a wallet path so our folder path isn't a stringified magic mock.
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    # # Inject the wallet so the daemon does not have to exist.
    # app_state_restapi.daemon.load_wallet = lambda wallet_path: wallet # type: ignore
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore

    canonical_wallet_path = WalletStorage.canonical_path(str(tmp_path / "wallet_file_name"))
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    wallet_storage = WalletStorage.create(canonical_wallet_path, password_token)
    local_wallet = Wallet(wallet_storage, "123456")
    keystore_result = local_wallet.derive_child_keystore(for_account=True, password="123456")
    account = local_wallet.create_account_from_keystore(keystore_result)

    def get_wallet_by_id(wallet_id: int) -> Wallet:
        nonlocal local_wallet
        assert local_wallet.get_id() == wallet_id
        return local_wallet
    app_state_restapi.daemon.get_wallet_by_id = get_wallet_by_id
    # BOILERPLATE ENDS

    local_endpoints = LocalEndpoints()

    invoice_request = unittest.mock.Mock()
    invoice_request.match_info = {
        "network": "mainnet",
        "wallet": str(local_wallet.get_id()),
        "account": str(account.get_id()),
    }
    async def request_json_async() -> dict[str, Any]:
        return {
            "satoshis": 10010,
        }
    invoice_request.json = request_json_async
    mock_server_state = unittest.mock.Mock()
    mock_server_state.server.server_id = 100
    with unittest.mock.patch("electrumsv.wallet.find_connectable_dpp_server") as \
            find_connectable_dpp_server:
        find_connectable_dpp_server.side_effect = lambda *args: mock_server_state
        with unittest.mock.patch("electrumsv.wallet.create_dpp_server_connection_async") as \
                create_dpp_server_connection_async:
            response = await local_endpoints.create_hosted_invoice_async(
                cast(web.Request, invoice_request))

    invoice_data = json.loads(cast(bytes, response.body))
    assert len(invoice_data) == 1
    assert "id" in invoice_data

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_hosted_invoice_async_fail_no_servers(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create a hosted invoice. """
    # BOILERPLATE STARTS
    # Inject a wallet path so our folder path isn't a stringified magic mock.
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    # # Inject the wallet so the daemon does not have to exist.
    # app_state_restapi.daemon.load_wallet = lambda wallet_path: wallet # type: ignore
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore

    canonical_wallet_path = WalletStorage.canonical_path(str(tmp_path / "wallet_file_name"))
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    wallet_storage = WalletStorage.create(canonical_wallet_path, password_token)
    local_wallet = Wallet(wallet_storage, "123456")
    keystore_result = local_wallet.derive_child_keystore(for_account=True, password="123456")
    account = local_wallet.create_account_from_keystore(keystore_result)

    def get_wallet_by_id(wallet_id: int) -> Wallet:
        nonlocal local_wallet
        assert local_wallet.get_id() == wallet_id
        return local_wallet
    app_state_restapi.daemon.get_wallet_by_id = get_wallet_by_id
    # BOILERPLATE ENDS

    local_endpoints = LocalEndpoints()

    invoice_request = unittest.mock.Mock()
    invoice_request.match_info = {
        "network": "mainnet",
        "wallet": str(local_wallet.get_id()),
        "account": str(account.get_id()),
    }
    async def request_json_async() -> dict[str, Any]:
        return {
            "satoshis": 10010,
        }
    invoice_request.json = request_json_async
    with unittest.mock.patch("electrumsv.wallet.find_connectable_dpp_server") as \
            find_connectable_dpp_server:
        find_connectable_dpp_server.side_effect = lambda *args: None
        with pytest.raises(web.HTTPBadRequest) as exception_value:
            await local_endpoints.create_hosted_invoice_async(cast(web.Request, invoice_request))
        assert "Failed with error code -1" == exception_value.value.args[0]

@unittest.mock.patch('electrumsv.keystore.app_state')
@unittest.mock.patch(
    'electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state')
@unittest.mock.patch('electrumsv.wallet.app_state')
@unittest.mock.patch('electrumsv.restapi_endpoints.app_state')
async def test_create_hosted_invoice_async_fail_connect_timeout(app_state_restapi: AppStateProxy,
        app_state_wallet: AppStateProxy, app_state_migration: AppStateProxy,
        app_state_keystore: AppStateProxy, tmp_path: Path) -> None:
    """ Create a hosted invoice. """
    # BOILERPLATE STARTS
    # Inject a wallet path so our folder path isn't a stringified magic mock.
    app_state_restapi.config.get_preferred_wallet_dirpath = lambda: str(tmp_path)
    # # Inject the wallet so the daemon does not have to exist.
    # app_state_restapi.daemon.load_wallet = lambda wallet_path: wallet # type: ignore
    # Ensure the wallet can access the password when being loaded.
    app_state_wallet.credentials.get_wallet_password = lambda wallet_path: "123456"
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    app_state_restapi.credentials.set_wallet_password = lambda *args: password_token # type: ignore

    canonical_wallet_path = WalletStorage.canonical_path(str(tmp_path / "wallet_file_name"))
    password_token = unittest.mock.Mock()
    password_token.password = "123456"
    wallet_storage = WalletStorage.create(canonical_wallet_path, password_token)
    local_wallet = Wallet(wallet_storage, "123456")
    keystore_result = local_wallet.derive_child_keystore(for_account=True, password="123456")
    account = local_wallet.create_account_from_keystore(keystore_result)

    def get_wallet_by_id(wallet_id: int) -> Wallet:
        nonlocal local_wallet
        assert local_wallet.get_id() == wallet_id
        return local_wallet
    app_state_restapi.daemon.get_wallet_by_id = get_wallet_by_id
    # BOILERPLATE ENDS

    local_endpoints = LocalEndpoints()

    invoice_request = unittest.mock.Mock()
    invoice_request.match_info = {
        "network": "mainnet",
        "wallet": str(local_wallet.get_id()),
        "account": str(account.get_id()),
    }
    async def request_json_async() -> dict[str, Any]:
        return {
            "satoshis": 10010,
        }
    invoice_request.json = request_json_async
    mock_server_state = unittest.mock.Mock()
    mock_server_state.server.server_id = 100
    with unittest.mock.patch("electrumsv.wallet.find_connectable_dpp_server") as \
            find_connectable_dpp_server:
        find_connectable_dpp_server.side_effect = lambda *args: mock_server_state
        with unittest.mock.patch("electrumsv.wallet.create_dpp_server_connection_async") as \
                create_dpp_server_connection_async:
            def side_effect(*args, **kwargs) -> None:
                raise asyncio.TimeoutError()
            create_dpp_server_connection_async.side_effect = side_effect
            with pytest.raises(web.HTTPBadRequest) as exception_value:
                await local_endpoints.create_hosted_invoice_async(
                    cast(web.Request, invoice_request))
            assert "Failed with error code -2" == exception_value.value.args[0]
