"""This is designed with extensibility in mind - see examples/applications/restapi. """
import json
from typing import Dict, List

from aiohttp import web

from .logs import logs
from .app_state import app_state
from .restapi import good_response, get_network_type

# PATHS
VERSION = "/v1"
NETWORK = "/{network}"
BASE = VERSION + NETWORK
DAEMON = VERSION +"/rpc"

# Request variables
class VARNAMES:
    pass


# Request types
ARGTYPES: Dict[str, type] = {}


class HandlerUtils:
    pass

    # ---- Utility Functions ----- #


class DefaultEndpoints(HandlerUtils):

    routes: List[web.RouteDef] = []

    def __init__(self) -> None:
        super().__init__()
        self.logger = logs.get_logger("restapi-default-endpoints")
        self.app_state = app_state  # easier to monkeypatch for testing
        self.add_routes()

    # ----- Built-in External API ----- #

    def add_routes(self) -> None:
        self.routes = [
            web.get("/", handler=self.status),
            web.get(BASE + "/ping", handler=self.ping),

            web.post(DAEMON + "/ping", handler=self.daemon_ping),
            web.post(DAEMON + "/gui", handler=self.gui_command),
            web.post(DAEMON + "/daemon", handler=self.daemon_command),
            web.post(DAEMON + "/cmdline", handler=self.command_line_command),
        ]

    async def status(self, request: web.Request) -> web.Response:
        return good_response({"status": "success",
                              "network": f"{get_network_type()}"})

    async def ping(self, request: web.Request) -> web.Response:
        return good_response({"value": "pong"})

    # These REST API endpoints were added to replace the JSON-RPC daemon server/endpoints.

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
        result = await self.app_state.daemon.run_gui(config_options)
        return web.json_response(result)

    async def daemon_command(self, request: web.Request) -> web.Response:
        """
        This is used to do commands related to remote daemon status.
        """
        body_bytes = await request.read()
        body_text = body_bytes.decode("utf-8")
        config_options = json.loads(body_text)
        assert type(config_options) is dict
        result = await self.app_state.daemon.run_daemon(config_options)
        return web.json_response(result)

    async def command_line_command(self, request: web.Request) -> web.Response:
        """
        This is used to do general remote commands.
        """
        body_bytes = await request.read()
        body_text = body_bytes.decode("utf-8")
        config_options = json.loads(body_text)
        assert type(config_options) is dict
        result = await self.app_state.daemon.run_cmdline(config_options)
        return web.json_response(result)

    # ----- Extended in examples/applications/restapi ----- #
