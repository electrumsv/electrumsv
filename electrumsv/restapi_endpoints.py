"""This is designed with extensibility in mind - see examples/applications/restapi. """
from aiohttp import web
from .logs import logs
from .app_state import app_state
from .restapi import good_response

# PATHS
VERSION = "/v1"
NETWORK = "/{network}"
BASE = VERSION + NETWORK


# Request variables
class VARNAMES:
    pass


# Request types
ARGTYPES = {}


def __init__(self):
    pass


class HandlerUtils:
    pass

    # ---- Utility Functions ----- #


class DefaultEndpoints(HandlerUtils):

    routes = []

    def __init__(self):
        super().__init__()
        self.logger = logs.get_logger("restapi-default-endpoints")
        self.app_state = app_state  # easier to monkeypatch for testing
        self.add_routes()

    # ----- Built-in External API ----- #

    def add_routes(self):
        self.routes = [
            web.get("/", handler=self.status),
            web.get(BASE + "/ping", handler=self.ping)
        ]

    async def status(self, request):
        return good_response({"status": "success"})

    async def ping(self, request):
        return good_response({"value": "pong"})

    # ----- Extended in examples/applications/restapi ----- #
