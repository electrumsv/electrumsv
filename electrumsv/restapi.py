import asyncio
from typing import Any, Dict, Callable, List, Optional
from aiohttp import web
import logging


class BaseAiohttpServer:

    def __init__(self, host: str = "localhost", port: int = 9999):
        self.runner = None
        self.is_alive = False
        self.app = web.Application()
        self.app.on_startup.append(self.on_startup)
        self.app.on_shutdown.append(self.on_shutdown)
        self.host = host
        self.port = port
        self.logger = logging.getLogger("aiohttp-rest-api")

    async def on_startup(self, app):
        self.logger.debug("starting...")

    async def on_shutdown(self, app):
        self.logger.debug("cleaning up...")
        self.is_alive = False
        self.logger.debug("stopped.")

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()

    async def stop(self):
        await self.runner.cleanup()


class AiohttpServer(BaseAiohttpServer):

    def __init__(self, host: str="localhost", port: int=9999, username: Optional[str]=None,
            password: str=None, extension_endpoints: Dict[str, Any]=None) -> None:
        super().__init__(host=host, port=port)
        self.username = username
        self.password = password

    def add_routes(self, routes):
        self.app.router.add_routes(routes)

    def add_methods(self, methods: List[Callable]):
        for method in methods:
            self.__setattr__(method.__name__, method)

    def register_new_endpoints(self, extension_endpoints: Dict[str, Any]):
        """Takes a dictionary of {urls: methods} for registration as new endpoints"""
        routes = [web.get(endpoint, method) for endpoint, method in extension_endpoints.items()]
        methods = [method for endpoint, method in extension_endpoints.items()]
        self.app.add_routes(routes)
        self.add_methods(methods)

    async def launcher(self):
        await self.start()
        self.is_alive = True
        self.logger.debug("started on http://%s:%s", self.host, self.port)
        while True:
            await asyncio.sleep(0.5)
