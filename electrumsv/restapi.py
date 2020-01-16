import asyncio
import json
from base64 import b64decode
from json import JSONDecodeError
from typing import Optional, ClassVar, Dict, Union, Any, Tuple
from aiohttp import web
from aiohttp.web_urldispatcher import UrlDispatcher
import logging
from .constants import MAX_MESSAGE_BYTES
from .app_state import app_state
from .util import to_bytes, to_string, constant_time_compare


def get_app_state():
    # to monkeypatch app_state in tests
    return app_state


def get_network_type():
    app_state = get_app_state()
    if app_state.config.get('testnet'):
        return 'test'
    if app_state.config.get('scalingtestnet'):
        return 'stn'
    else:
        return 'main'


class Errors:
    # http 400 bad requests
    GENERIC_BAD_REQUEST_CODE = 40000
    URL_INVALID_NETWORK_CODE = 40001
    URL_NETWORK_MISMATCH_CODE = 40002
    JSON_DECODE_ERROR_CODE = 40003
    LOAD_BEFORE_GET_CODE = 40004
    EMPTY_REQUEST_BODY_CODE = 40005
    NO_COINS_CODE = 40006
    DATA_TOO_BIG_CODE = 40007
    BAD_WALLET_NAME_CODE = 40008
    WALLET_NOT_LOADED_CODE = 40009
    INSUFFICIENT_FUNDS_CODE = 40010
    ALREADY_SENT_TRANSACTION_CODE = 40011
    AIORPCX_ERROR_CODE = 40012

    # http 401 unauthorized
    AUTH_CREDENTIALS_MISSING_CODE = 40102
    AUTH_UNSUPPORTED_TYPE_CODE = 40103

    # http 402 - 402xx series
    # http 403 - 403xx series
    AUTH_CREDENTIALS_INVALID_CODE = 40301

    # http 404 not found
    WALLET_NOT_FOUND_CODE = 40401
    HEADER_VAR_NOT_PROVIDED_CODE = 40402
    BODY_VAR_NOT_PROVIDED_CODE = 40403

    # http 500 internal server error
    GENERIC_INTERNAL_SERVER_ERROR = 50000

    AUTH_CREDENTIALS_INVALID_MESSAGE = "Authentication failed (bad credentials)."
    AUTH_CREDENTIALS_MISSING_MESSAGE = "Authentication failed (missing credentials)."
    AUTH_UNSUPPORTED_TYPE_MESSAGE = "Authentication failed (only basic auth is supported)."
    URL_INVALID_NETWORK_MESSAGE = "Only {} networks are supported. You entered: '{}' network."
    URL_NETWORK_MISMATCH_MESSAGE = "Wallet is on '{}' network. You requested: '{}' network."
    WALLET_NOT_FOUND_MESSAGE = "Wallet: '{}' does not exist."
    LOAD_BEFORE_GET_MESSAGE = "Must load wallet (POST request to " \
                              "http://127.0.0.1:9999/v1/{}/wallets/{}" \
                              "/load_wallet)"
    EMPTY_REQUEST_BODY_MESSAGE = "Request body was empty"
    HEADER_VAR_NOT_PROVIDED_MESSAGE = "Required header variable: '{}' was not provided."
    BODY_VAR_NOT_PROVIDED_MESSAGE = "Required body variable: '{}' was not provided."
    NO_COINS_MESSAGE = "Wallet has no coins"
    DATA_TOO_BIG_MESSAGE = "Message is too large (>%s bytes))." % MAX_MESSAGE_BYTES
    BAD_WALLET_NAME_MESSAGE = "Wallet name invalid."
    WALLET_NOT_LOADED_MESSAGE = "Wallet was unable to be loaded (bad password?)"
    INSUFFICIENT_FUNDS_MESSAGE = "You have insufficient funds for this transaction"


class Fault(Exception):
    """Restapi error class"""

    def __init__(self, code=Errors.GENERIC_BAD_REQUEST_CODE, message='Server error'):
        self.code = code
        self.message = message

    def __repr__(self):
        return "Fault(%s, '%s')" % (self.code, self.message)


def bad_request(code: int, message: str) -> web.Response:
    response_obj = {'code': code,
                    'message': message}
    return web.json_response(data=response_obj, status=400)


def unauthorized(code: int, message: str) -> web.Response:
    response_obj = {'code': code,
                    'message': message}
    return web.json_response(data=response_obj, status=401)


def forbidden(code: int, message: str) -> web.Response:
    response_obj = {'code': code,
                    'message': message}
    return web.json_response(data=response_obj, status=403)


def not_found(code: int, message: str) -> web.Response:
    response_obj = {'code': code,
                    'message': message}
    return web.json_response(data=response_obj, status=404)


def internal_server_error(code: int, message: str) -> web.Response:
    response_obj = {'code': code,
                    'message': message}
    return web.json_response(data=response_obj, status=500)


def good_response(response: Dict) -> web.Response:
    return web.Response(text=json.dumps(response, indent=2), content_type="application/json")


async def decode_request_body(request) -> Union[Dict[Any, Any], Fault]:
    body = await request.read()
    if body == b"" or body == b"{}":
        return {}
    try:
        request_body = json.loads(body.decode('utf-8'))
    except JSONDecodeError as e:
        message = "JSONDecodeError " + str(e)
        raise Fault(Errors.JSON_DECODE_ERROR_CODE, message)
    return request_body


def fault_to_http_response(fault: Union[Fault]):
    if fault.code < 0:  # bitcoin rpc error codes
        return bad_request(fault.code, fault.message)

    if 40000 <= fault.code < 50000:  # ESV rest_api.Errors 4xx codes
        if 40400 <= fault.code < 40500:
            return not_found(fault.code, fault.message)
        return bad_request(fault.code, fault.message)

    if 50000 <= fault.code < 60000:  # ESV rest_api.Errors 5xx codes
        return internal_server_error(fault.code, fault.message)

    else:  # other
        return bad_request(fault.code, fault.message)


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
        self.runner = web.AppRunner(self.app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port, reuse_address=True)
        await site.start()

    async def stop(self):
        await self.runner.cleanup()


class AiohttpServer(BaseAiohttpServer):

    def __init__(self, host: str="localhost", port: int=9999, username: Optional[str]=None,
            password: str=None) -> None:
        super().__init__(host=host, port=port)
        self.username = username
        self.password = password
        self.network = get_network_type()
        self.app.middlewares.extend([web.normalize_path_middleware(append_slash=False,
            remove_slash=True), self.authenticate, self.check_network])

    @web.middleware
    async def check_network(self, request, handler):
        supported_networks = ['main', 'stn', 'test']
        network = request.match_info.get('network', None)

        # paths without {network} are okay
        if network is None:
            response = await handler(request)
            return response

        # check if supported network
        else:
            if network not in supported_networks:
                code =    Errors.URL_INVALID_NETWORK_CODE
                message = Errors.URL_INVALID_NETWORK_MESSAGE.format(supported_networks, network)
                return bad_request(code, message)

        # check if network matches daemon
        if self.network != network:
            code =    Errors.URL_NETWORK_MISMATCH_CODE
            message = Errors.URL_NETWORK_MISMATCH_MESSAGE.format(self.network, network)
            return bad_request(code, message)

        response = await handler(request)
        return response

    @web.middleware
    async def authenticate(self, request, handler):

        if self.password == '':
            # authentication is disabled
            response = await handler(request)
            return response

        auth_string = request.headers.get('Authorization', None)
        if auth_string is None:
            return unauthorized(Errors.AUTH_CREDENTIALS_MISSING_CODE,
                                Errors.AUTH_CREDENTIALS_MISSING_MESSAGE)

        (basic, _, encoded) = auth_string.partition(' ')
        if basic != 'Basic':
            return unauthorized(Errors.AUTH_UNSUPPORTED_TYPE_CODE,
                                Errors.AUTH_UNSUPPORTED_TYPE_MESSAGE)

        encoded = to_bytes(encoded, 'utf8')
        credentials = to_string(b64decode(encoded), 'utf8')
        (username, _, password) = credentials.partition(':')
        if not (constant_time_compare(username, self.username)
                and constant_time_compare(password, self.password)):
            await asyncio.sleep(0.050)
            return forbidden(Errors.AUTH_CREDENTIALS_INVALID_CODE,
                                Errors.AUTH_CREDENTIALS_INVALID_MESSAGE)

        # passed authentication
        response = await handler(request)
        return response

    def add_routes(self, routes):
        self.app.router.add_routes(routes)

    async def launcher(self):
        await self.start()
        self.is_alive = True
        self.logger.debug("started on http://%s:%s", self.host, self.port)
        while True:
            await asyncio.sleep(0.5)

    def register_routes(self, endpoints) -> None:
        self.app.router.add_routes(endpoints.routes)
