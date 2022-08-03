"""This is designed with extensibility in mind - see examples/applications/restapi. """
from __future__ import annotations
from datetime import datetime
import json
import os
import time
from types import NoneType
from typing import cast
from typing_extensions import NotRequired, TypedDict

from aiohttp import web
from bitcoinx import PublicKey

from .logs import logs
from .app_state import app_state
from .constants import CredentialPolicyFlag
from .exceptions import InvalidPassword
from .networks import Net
from .restapi import get_network_type
from .storage import WalletStorage
from .wallet import AbstractAccount, Wallet


logger = logs.get_logger("restapi-endpoints")


def check_network_for_request(request: web.Request) -> None:
    network = request.match_info.get("network")
    if network == "mainnet":
        is_valid = Net.is_mainnet()
    elif network == "testnet":
        is_valid = Net.is_testnet()
    elif network == "scalingtestnet":
        is_valid = Net.is_scaling_testnet()
    elif network == "regtest":
        is_valid = Net.is_regtest()
    else:
        raise web.HTTPBadRequest(reason=f"URL 'network' value '{network}' unrecognised")

    if not is_valid:
        raise web.HTTPBadRequest(reason=f"URL 'network' value '{network}' incorrect")

def get_wallet_from_request(request: web.Request) -> Wallet:
    wallet_id_text = request.match_info.get("wallet")
    if wallet_id_text is None:
        raise web.HTTPBadRequest(reason="URL 'wallet' not specified in URL")

    try:
        wallet_id = int(wallet_id_text)
    except ValueError:
        raise web.HTTPBadRequest(reason="URL 'wallet' value invalid")

    wallet = app_state.daemon.get_wallet_by_id(wallet_id)
    if wallet is None:
        raise web.HTTPBadRequest(reason=f"Wallet with ID '{wallet_id}' not currently loaded")

    return wallet

def get_account_from_request(request: web.Request) -> tuple[Wallet, AbstractAccount]:
    wallet = get_wallet_from_request(request)

    account_id_text = request.match_info.get("account")
    if account_id_text is None:
        raise web.HTTPBadRequest(reason="URL 'account' not specified in URL")

    try:
        account_id = int(account_id_text)
    except ValueError:
        raise web.HTTPBadRequest(reason="URL 'account' value invalid")

    account = wallet.get_account(account_id)
    if account is None:
        raise web.HTTPBadRequest(reason=f"Wallet does not have an account with ID '{account_id}'")

    return wallet, account


class DefaultEndpoints:
    def __init__(self) -> None:
        super().__init__()

        self._local_endpoints = LocalEndpoints()
        self._daemon_endpoints = DaemonEndpoints()

        self.routes = list[web.RouteDef]()
        self.routes.extend(self._local_endpoints.routes)
        self.routes.extend(self._daemon_endpoints.routes)


class DaemonEndpoints:
    """
    These endpoints are provided for ElectrumSV to use through it's daemon. While whoever has
    installed ElectrumSV can use them, they should work out if they should.
    """

    @property
    def routes(self) -> list[web.RouteDef]:
        return [
            web.post("/v1/rpc/ping", self.daemon_ping),
            web.post("/v1/rpc/gui", self.gui_command),
            web.post("/v1/rpc/daemon", self.daemon_command),
            web.post("/v1/rpc/cmdline", self.command_line_command),
        ]

    async def daemon_ping(self, request: web.Request) -> web.Response:
        return web.json_response(True)

    async def gui_command(self, request: web.Request) -> web.Response:
        """
        This is used to remotely start a GUI window on the daemon host.
        """
        body_bytes = await request.read()
        body_text = body_bytes.decode("utf-8")
        config_options = json.loads(body_text)
        assert type(config_options) is dict
        result = await app_state.daemon.run_gui(config_options)
        return web.json_response(result)

    async def daemon_command(self, request: web.Request) -> web.Response:
        """
        This is used to do commands related to remote daemon status.
        """
        body_bytes = await request.read()
        body_text = body_bytes.decode("utf-8")
        config_options = json.loads(body_text)
        assert type(config_options) is dict
        result = await app_state.daemon.run_daemon(config_options)
        return web.json_response(result)

    async def command_line_command(self, request: web.Request) -> web.Response:
        """
        This is used to do general remote commands.
        """
        body_bytes = await request.read()
        body_text = body_bytes.decode("utf-8")
        config_options = json.loads(body_text)
        assert type(config_options) is dict
        result = await app_state.daemon.run_cmdline(config_options)
        return web.json_response(result)



class LocalEndpoints:
    """
    These endpoints are exposed for the use of whoever has installed the wallet.
    """
    @property
    def routes(self) -> list[web.RouteDef]:
        return [
            web.get("/", self.status),
            web.get("/v1/{network}/ping", self.ping_async),

            web.post("/v1/{network}/wallet", self.create_wallet_async),
            web.get("/v1/{network}/{wallet}", self.load_wallet_async),
            web.post("/v1/{network}/{wallet}/account", self.create_account_async),

            web.post("/v1/{network}/{wallet}/{account}/pay", self.pay_invoice_async),
            web.post("/v1/{network}/{wallet}/{account}/invoices",
                self.create_hosted_invoice_async),
            web.delete("/v1/{network}/{wallet}/{account}/invoices/{invoice_id}",
                self.delete_hosted_invoice_async),
        ]

    async def status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "network": get_network_type(),
        })

    async def ping_async(self, request: web.Request) -> web.Response:
        check_network_for_request(request)
        return web.json_response(True)

    async def load_wallet_async(self, request: web.Request) -> web.Response:
        """ Load an existing wallet or get the loaded status of it if it is already loaded. """
        check_network_for_request(request)
        try:
            wallet_folder_path = app_state.config.get_preferred_wallet_dirpath()
        except FileNotFoundError:
            raise web.HTTPInternalServerError(reason="No preferred wallet path")

        raw_file_name = request.query.get("file_name")
        if raw_file_name is None or len(raw_file_name) == 0:
            raise web.HTTPBadRequest(reason="Invalid parameter 'file_name'")

        wallet_password = request.query.get("password")
        if wallet_password is None or len(wallet_password) < 6:
            raise web.HTTPBadRequest(reason="Invalid parameter 'password'")

        file_name = WalletStorage.canonical_path(raw_file_name)
        wallet_path = os.path.join(wallet_folder_path, file_name)
        wallet_path = os.path.normpath(wallet_path)
        if not os.path.exists(wallet_path):
            raise web.HTTPBadRequest(reason=f"Wallet file does not exist '{raw_file_name}'")

        app_state.credentials.set_wallet_password(wallet_path, wallet_password,
            CredentialPolicyFlag.FLUSH_AFTER_WALLET_LOAD)
        # This will load any wallet that is not already loaded and return an already loaded one.
        wallet = app_state.daemon.load_wallet(wallet_path)
        if wallet is None:
            # The reason for this will be in the debug log.
            raise web.HTTPBadRequest(reason=f"Unable to load wallet '{raw_file_name}'")

        accounts_ids = [ account.get_id() for account in wallet.get_visible_accounts() ]

        wallet_status: WalletStatusDict = {
            "ephemeral_wallet_id": wallet.get_id(),
            "wallet_path": wallet_path,
            "account_ids": accounts_ids,
        }
        return web.json_response(wallet_status)

    async def create_wallet_async(self, request: web.Request) -> web.Response:
        """ Creates a new wallet using a specified file name and password. """
        check_network_for_request(request)
        try:
            wallet_folder_path = app_state.config.get_preferred_wallet_dirpath()
        except FileNotFoundError:
            raise web.HTTPInternalServerError(reason="No preferred wallet path")

        body_data = request.json()
        if not isinstance(body_data, dict) or "file_name" not in body_data or \
                "password" not in body_data:
            raise web.HTTPBadRequest(reason="Invalid request body")
        body_dict = cast(CreateWalletRequestDict, body_data)

        file_name = body_dict["file_name"]
        if not isinstance(file_name, str):
            raise web.HTTPBadRequest(reason="Invalid request body 'file_name'")

        wallet_password = body_dict["password"]
        if not isinstance(wallet_password, str) or len(wallet_password) < 6:
            raise web.HTTPBadRequest(reason="Invalid request body 'password'")

        encryption_public_key: PublicKey | None = None
        encryption_key_hex = body_dict.get("encryption_key_hex", None)
        if encryption_key_hex is not None:
            try:
                encryption_key_bytes = bytes.fromhex(encryption_key_hex)
                encryption_public_key = PublicKey.from_bytes(encryption_key_bytes)
            except ValueError:
                raise web.HTTPBadRequest(reason="Invalid request body 'encryption_key_hex'")

        raw_wallet_path = os.path.normpath(os.path.join(wallet_folder_path, file_name))
        wallet_path = WalletStorage.canonical_path(raw_wallet_path)
        if os.path.exists(wallet_path):
            raise web.HTTPBadRequest(reason=f"Wallet file already exists '{file_name}'")

        password_token = app_state.credentials.set_wallet_password(wallet_path, wallet_password,
            CredentialPolicyFlag.FLUSH_ALMOST_IMMEDIATELY1)
        assert password_token is not None
        storage = WalletStorage.create(wallet_path, password_token)
        wallet = Wallet(storage, wallet_password)
        # Register the wallet with the daemon so that it is effectively loaded after this call.
        app_state.daemon.start_wallet(wallet)

        wallet_status: WalletStatusDict = {
            "ephemeral_wallet_id": wallet.get_id(),
            "wallet_path": wallet_path,
            "account_ids": [],
        }
        # If the API client provided an encryption public key we return the wallet seed words,
        # but ECIES encrypted so that they do not pass over the wire unencrypted.
        if encryption_public_key is not None:
            wallet_keystore = wallet.get_master_keystore()
            wallet_status["wallet_seed"] = encryption_public_key.encrypt_message(
                wallet_keystore.get_seed(wallet_password)).hex()
        return web.json_response(wallet_status)

    async def create_account_async(self, request: web.Request) -> web.Response:
        """ Create a new standard account in the wallet. """
        check_network_for_request(request)
        wallet = get_wallet_from_request(request)

        wallet_password = request.query.get("password")
        if wallet_password is None or len(wallet_password) < 6:
            raise web.HTTPBadRequest(reason="Invalid parameter 'password'")

        try:
            keystore_result = wallet.derive_child_keystore(for_account=True,
                password=wallet_password)
        except InvalidPassword:
            raise web.HTTPBadRequest(reason="Wallet password is not correct")

        account = wallet.create_account_from_keystore(keystore_result)

        account_status: AccountStatusDict = {
            "account_id": account.get_id(),
        }
        return web.json_response(account_status)

    async def create_hosted_invoice_async(self, request: web.Request) -> web.Response:
        """ Create a new invoice with the expectation it is hosted for it to succeed. """
        # Process the route.
        check_network_for_request(request)
        _wallet, account = get_account_from_request(request)

        # Process the body.
        body_data = request.json()
        if not isinstance(body_data, dict) or "satoshis" not in body_data:
            raise web.HTTPBadRequest(reason="Invalid request body")
        body_dict = cast(CreateInvoiceRequestDict, body_data)

        payment_amount = body_dict["satoshis"]
        if not isinstance(payment_amount, int):
            raise web.HTTPBadRequest(reason="Invalid request body 'satoshis'")

        expiry_date_text = body_dict.get("expiresAt")
        if not isinstance(expiry_date_text, (NoneType, str)):
            raise web.HTTPBadRequest(reason="Invalid request body 'expiresAt'")

        description = body_dict.get("description")
        if not isinstance(description, (NoneType, str)):
            raise web.HTTPBadRequest(reason="Invalid request body 'description'")

        merchant_reference = body_dict.get("reference")
        if not isinstance(merchant_reference, (NoneType, str)):
            raise web.HTTPBadRequest(reason="Invalid request body 'reference'")

        date_expires = int(time.time()) + 5 * 60
        if expiry_date_text is not None:
            expiry_iso8601_text = expiry_date_text.replace("Z", "+00:00")
            date_expires = int(datetime.fromisoformat(expiry_iso8601_text).timestamp())

        result, error_code = await account.create_hosted_invoice_async(payment_amount,
            date_expires, description, merchant_reference)
        if result is None:
            raise web.HTTPBadRequest(reason=f"Failed with error code {error_code}")

        assert result[0].paymentrequest_id is not None
        create_data: CreateInvoiceResponseDict = {
            "id": result[0].paymentrequest_id,
        }
        return web.json_response(create_data)

    async def delete_hosted_invoice_async(self, request: web.Request) -> web.Response:
        """ Close the hosted invoice out and stop hosting it. """
        # Process the route.
        check_network_for_request(request)
        wallet, account = get_account_from_request(request)

        invoice_id_text = request.match_info.get("invoice")
        if invoice_id_text is None:
            raise web.HTTPBadRequest(reason="URL 'invoice' value not present")
        try:
            invoice_id = int(invoice_id_text)
        except ValueError:
            raise web.HTTPBadRequest(reason=f"URL 'invoice' value '{invoice_id_text}' invalid")

        # TODO Create the `delete_hosted_invoice` function.
        # TODO Handle any exceptions.
        await account.delete_hosted_invoice_async(invoice_id)

        # TODO Extract input parameters
        return web.json_response(True)

    async def pay_invoice_async(self, request: web.Request) -> web.Response:
        """ Pay someone else's invoice using the given account. """
        # Process the route.
        check_network_for_request(request)
        wallet, account = get_account_from_request(request)

        body_data = request.json()
        if not isinstance(body_data, dict) or "payToURL" not in body_data:
            raise web.HTTPBadRequest(reason="Invalid request body")
        body_dict = cast(PayRequestDict, body_data)
        await account.pay_hosted_invoice_async(body_dict["payToURL"])

        return web.json_response(True)


class CreateWalletRequestDict(TypedDict):
    file_name: str
    password: str
    encryption_key_hex: NotRequired[str]

class WalletStatusDict(TypedDict):
    ephemeral_wallet_id: int
    wallet_path: str
    account_ids: list[int]
    wallet_seed: NotRequired[str]

class AccountStatusDict(TypedDict):
    account_id: int

class CreateInvoiceRequestDict(TypedDict):
    satoshis: int
    # The ISO 8601 date string for when the invoice expires.
    expiresAt: NotRequired[str]
    # The label that will be given to the payment transactions in the database.
    description: NotRequired[str]
    # The reference for the payment to be given to the merchant.
    reference: NotRequired[str]

class CreateInvoiceResponseDict(TypedDict):
    id: int

class PayRequestDict(TypedDict):
    payToURL: str

