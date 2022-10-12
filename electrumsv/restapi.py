from __future__ import annotations
import asyncio
from base64 import b64decode
import binascii
from typing import Awaitable, cast, Callable, TYPE_CHECKING

from aiohttp import web
# NOTE(typing) `cors_middleware` is not explicitly exported, so mypy strict fails. No idea.
from aiohttp_middlewares import cors_middleware # type: ignore

from .app_state import app_state, AppStateProxy
from .logs import logs
from .networks import Net, NetworkNames
from .util import constant_time_compare

if TYPE_CHECKING:
    from .wallet import AbstractAccount, Wallet


# Supported networks in restapi url
MAINNET = 'main'
TESTNET = 'test'
SCALINGTESTNET = 'stn'
REGTESTNET = 'regtest'


def get_app_state() -> AppStateProxy:
    # to monkeypatch app_state in tests
    return app_state


def get_network_type() -> str:
    app_state = get_app_state()
    if app_state.config.get('testnet'):
        return TESTNET
    elif app_state.config.get('scalingtestnet'):
        return SCALINGTESTNET
    elif app_state.config.get('regtest'):
        return REGTESTNET
    else:
        return MAINNET


def check_network_for_request(request: web.Request) -> None:
    network = cast(NetworkNames, request.match_info.get("network"))
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


class BaseAiohttpServer:
    is_running: bool = False

    def __init__(self, host: str = "localhost", port: int = 9999) -> None:
        self.runner: web.AppRunner | None = None
        self.shutdown_event = asyncio.Event()
        self.app = web.Application(middlewares=[
            cors_middleware(
                origins=["http://localhost"],
                allow_methods=("GET","POST"),
                allow_headers=["authorization"])
        ])
        self.app.on_startup.append(self._on_startup_async)
        self.app.on_shutdown.append(self._on_shutdown_async)
        self.host = host
        self.port = port
        self.logger = logs.get_logger("rest-server")

    async def _on_startup_async(self, app: web.Application) -> None:
        self.logger.debug("starting...")

    async def _on_shutdown_async(self, app: web.Application) -> None:
        self.logger.debug("cleaning up...")
        self.is_running = False
        self.shutdown_event.set()
        self.logger.debug("stopped")

    async def _start_async(self) -> None:
        self.runner = web.AppRunner(self.app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port, reuse_address=True)
        await site.start()

    async def stop(self) -> None:
        assert self.runner is not None
        await self.runner.cleanup()


HandlerType = Callable[[web.Request], Awaitable[web.StreamResponse]]


class AiohttpServer(BaseAiohttpServer):
    def __init__(self, host: str="localhost", port: int=9999, username: str|None=None,
            password: str|None=None) -> None:
        super().__init__(host=host, port=port)
        self.username = username
        self.password = password
        self.network = get_network_type()
        self.app.middlewares.extend([web.normalize_path_middleware(append_slash=False,
            remove_slash=True), self.authenticate, self.check_network])

    @web.middleware
    async def check_network(self, request: web.Request, handler: HandlerType) -> web.StreamResponse:
        network = request.match_info.get('network', None)

        # paths without {network} are okay
        if network is None:
            response = await handler(request)
            return response

        # check if network matches daemon
        if self.network != network:
            raise web.HTTPBadRequest(reason=f"Invalid network {network}")

        response = await handler(request)
        return response

    @web.middleware
    async def authenticate(self, request: web.Request, handler: HandlerType) -> web.StreamResponse:
        if self.password == '':
            # authentication is disabled
            return await handler(request)

        auth_string = request.headers.get('Authorization', None)
        if auth_string is None:
            raise web.HTTPUnauthorized(reason="Missing credentials")

        (authorization_type, _, authorization_key) = auth_string.partition(' ')
        # TODO(deprecation) @DeprecateRESTBasicAuth We should switch anything that uses this
        #     over to the simpler `Bearer` authorization. Once that is done we can remove `Basic`.
        if authorization_type == 'Basic':
            encoded = authorization_key.encode('utf8')
            try:
                credentials = b64decode(encoded).decode('utf8')
            except binascii.Error:
                raise web.HTTPBadRequest(reason="Invalid 'Basic' credentials (base64)")

            (username, _, password) = credentials.partition(':')
            assert self.username is not None and self.password is not None
            if not (constant_time_compare(username, self.username)
                    and constant_time_compare(password, self.password)):
                raise web.HTTPForbidden(reason="Invalid 'Basic' credentials (username/password)")
        elif authorization_type == 'Bearer':
            assert self.password is not None
            if not constant_time_compare(authorization_key, self.password):
                raise web.HTTPForbidden(reason="Invalid 'Bearer' access token")
        else:
            raise web.HTTPUnauthorized(reason="Only basic or bearer authentication supported")

        return await handler(request)

    def add_routes(self, routes: list[web.RouteDef]) -> None:
        self.app.router.add_routes(routes)

    async def run_async(self) -> None:
        await self._start_async()
        self.is_running = True
        self.logger.debug("started on http://%s:%s", self.host, self.port)
        await self.shutdown_event.wait()
