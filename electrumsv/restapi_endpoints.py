"""This is designed with extensibility in mind - see examples/applications/restapi. """
from __future__ import annotations
import json
from types import NoneType
from typing import cast, TYPE_CHECKING
from typing_extensions import NotRequired, TypedDict

from aiohttp import web

from .logs import logs
from .app_state import app_state
from .networks import Net
from .restapi import get_network_type

if TYPE_CHECKING:
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
            web.get("/v1/{network}/ping", self.ping),

            web.get("/v1/{network}/wallet", self.wallet_status),
            web.post("/v1/{network}/wallet", self.create_wallet),
            web.post("/v1/{network}/{wallet}/account", self.create_account),

            web.post("/v1/{network}/{wallet}/{account}/pay", self.pay_invoice),
            web.post("/v1/{network}/{wallet}/{account}/invoices", self.create_hosted_invoice),
            web.delete("/v1/{network}/{wallet}/{account}/invoices/{invoice_id}",
                self.delete_hosted_invoice),
        ]

    async def status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "network": get_network_type(),
        })

    async def ping(self, request: web.Request) -> web.Response:
        check_network_for_request(request)
        return web.json_response(True)

    async def wallet_status(self, request: web.Request) -> web.Response:
        """ ... """
        load_flag_text = request.match_info.get("load")
        load_flag = load_flag_text is not None and load_flag_text.lower() == "yes"
        return web.json_response(True)

    async def create_wallet(self, request: web.Request) -> web.Response:
        """ ... """
        return web.json_response(True)

    async def create_account(self, request: web.Request) -> web.Response:
        return web.json_response(True)

    async def create_hosted_invoice(self, request: web.Request) -> web.Response:
        """ Create a new invoice with the expectation it is hosted for it to succeed. """
        # Process the route.
        check_network_for_request(request)
        wallet, account = get_account_from_request(request)

        # Process the body.
        body_data = request.json()
        if not isinstance(body_data, dict) or "satoshis" not in body_data:
            raise web.HTTPBadRequest(reason="Invalid request body")
        body_dict = cast(CreateInvoiceRequestDict, body_data)

        payment_amount = body_dict["satoshis"]
        if not isinstance(payment_amount, int):
            raise web.HTTPBadRequest(reason="Invalid request body 'expiresAt'")

        expiry_date_text = body_dict.get("expiresAt", None)
        if not isinstance(expiry_date_text, (NoneType, str)):
            raise web.HTTPBadRequest(reason="Invalid request body 'expiresAt'")

        description = body_dict.get("description", None)
        if not isinstance(description, (NoneType, str)):
            raise web.HTTPBadRequest(reason="Invalid request body 'description'")

        merchant_reference = body_dict.get("reference", None)
        if not isinstance(merchant_reference, (NoneType, str)):
            raise web.HTTPBadRequest(reason="Invalid request body 'reference'")

        # TODO Create the `create_hosted_invoice` function.
        # TODO Handle any exceptions.
        invoice_data = account.create_hosted_invoice(payment_amount, expiry_date_text, description,
            merchant_reference)

        # TODO Convert the invoice data to a response.
        return web.json_response(True)

    async def delete_hosted_invoice(self, request: web.Request) -> web.Response:
        """ Close the hosted invoice out and stop hosting it. """
        # Process the route.
        check_network_for_request(request)
        wallet, account = get_account_from_request(request)

        invoice_id = request.match_info.get("invoice")
        if invoice_id is None or len(invoice_id) == 0:
            raise web.HTTPBadRequest(reason="URL 'invoice' value not present")

        # TODO Create the `delete_hosted_invoice` function.
        # TODO Handle any exceptions.
        account.delete_hosted_invoice(invoice_id)

        # TODO Extract input parameters
        return web.json_response(True)

    async def pay_invoice(self, request: web.Request) -> web.Response:
        # Process the route.
        check_network_for_request(request)
        wallet, account = get_account_from_request(request)

        body_data = request.json()
        if not isinstance(body_data, dict) or "payToURL" not in body_data:
            raise web.HTTPBadRequest(reason="Invalid request body")
        body_dict = cast(PayRequestDict, body_data)
        pay_url = body_dict["payToURL"]

        return web.json_response(True)


class CreateInvoiceRequestDict(TypedDict):
    satoshis: int
    # The ISO 8601 date string for when the invoice expires.
    expiresAt: NotRequired[str]
    # The label that will be given to the payment transactions in the database.
    description: NotRequired[str]
    # The reference for the payment to be given to the merchant.
    reference: NotRequired[str]


class PayRequestDict(TypedDict):
    payToURL: str
