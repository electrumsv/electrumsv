import asyncio
from typing import Awaitable, Callable

from base64 import b64decode
from aiohttp import web
# NOTE(typing) `cors_middleware` is not explicitly exported, so mypy strict fails. No idea.
from aiohttp_middlewares import cors_middleware # type: ignore

from .logs import logs
from .app_state import app_state, AppStateProxy
from .util import constant_time_compare

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


class BaseAiohttpServer:

    def __init__(self, host: str = "localhost", port: int = 9999) -> None:
        self.runner: web.AppRunner | None = None
        self.is_alive = False
        self.app = web.Application(middlewares=[
            cors_middleware(
                origins=["http://localhost"],
                allow_methods=("GET","POST"),
                allow_headers=["authorization"])
        ])
        self.app.on_startup.append(self.on_startup)
        self.app.on_shutdown.append(self.on_shutdown)
        self.host = host
        self.port = port
        self.logger = logs.get_logger("rest-server")

    async def on_startup(self, app: web.Application) -> None:
        self.logger.debug("starting...")

    async def on_shutdown(self, app: web.Application) -> None:
        self.logger.debug("cleaning up...")
        self.is_alive = False
        self.logger.debug("stopped.")

    async def start(self) -> None:
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
            response = await handler(request)
            return response

        auth_string = request.headers.get('Authorization', None)
        if auth_string is None:
            raise web.HTTPUnauthorized(reason="Missing credentials")

        (basic, _, encoded_text) = auth_string.partition(' ')
        if basic != 'Basic':
            raise web.HTTPUnauthorized(reason="Only 'Basic' authentication supported")

        encoded = encoded_text.encode('utf8')
        credentials = b64decode(encoded).decode('utf8')
        (username, _, password) = credentials.partition(':')
        assert self.username is not None and self.password is not None
        if not (constant_time_compare(username, self.username)
                and constant_time_compare(password, self.password)):
            raise web.HTTPForbidden(reason="Invalid 'Basic' credentials (username or password)")

        # passed authentication
        response = await handler(request)
        return response

    def add_routes(self, routes: list[web.RouteDef]) -> None:
        self.app.router.add_routes(routes)

    async def launcher(self) -> None:
        await self.start()
        self.is_alive = True
        self.logger.debug("started on http://%s:%s", self.host, self.port)
        while True:
            await asyncio.sleep(0.5)
