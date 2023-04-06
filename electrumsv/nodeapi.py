"""
This is a project to provide a compatible JSON-RPC API for businesses that were using the
Bitcoin SV node JSON-RPC API to access node wallet.
"""

# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import annotations
import asyncio
from base64 import b64decode
import binascii
from decimal import Decimal
from enum import IntEnum
import json
import os
import random
import re
import subprocess
import threading
import time
from types import NoneType
from typing import Any, Awaitable, Callable, cast, NamedTuple, TYPE_CHECKING, TypeVar
from typing_extensions import NotRequired, TypedDict

from aiohttp import web
# NOTE(typing) `cors_middleware` is not explicitly exported, so mypy strict fails. No idea.
from aiohttp_middlewares import cors_middleware # type: ignore
from bitcoinx import Address, hash_to_hex_str, hex_str_to_hash, Ops, pack_byte, \
    push_item, Script, SigHash, Tx, TxInput, TxInputContext, TxOutput, MissingHeader

from .app_state import app_state
from .bitcoin import COIN, COINBASE_MATURITY, script_template_to_string
from .constants import CHANGE_SUBPATH, CredentialPolicyFlag, DerivationType, KeyInstanceFlag, \
    ScriptType, TransactionImportFlag, TransactionOutputFlag, TxFlags
from .exceptions import BroadcastError, InvalidPassword, NotEnoughFunds, NoViableServersError, \
    ServiceUnavailableError
from .logs import logs
from .networks import Net
from .standards.node_transaction import transactions_from_node_bytes
from .standards.script_templates import classify_transaction_output_script
from .transaction import TransactionContext, TransactionFeeEstimator, XTxInput, XTxOutput
from .types import Outpoint

from .util import constant_time_compare
from .wallet_database.types import AccountHistoryOutputRow

if TYPE_CHECKING:
    from .wallet import Wallet

HandlerType = Callable[[web.Request], Awaitable[web.StreamResponse]]
T = TypeVar("T")

logger = logs.get_logger("nodeapi")

# We use typed dictionaries inline rather than layering functions to abstract this in order to try
# to make the code easier to read.


# aiohttp does not provide this. Define it locally.
class HTTPTooEarly(web.HTTPClientError):
    status_code = 425


class ErrorDict(TypedDict):
    code: int
    message: str

# The node does not check the type but we limit the call id type to the basic types.
# NOTE(typing) `isinstance(value, (int, str, NoneType))` will give `value` the inferred type
#     `int | str | NoneType` and it cannot be assigned to `variable: int | str | None` according
#     to at least the pylance type checker. However this composite union type works correctly.
RequestIdType = int | str | None
RequestParametersType = list | dict

class ResponseDict(TypedDict):
    result: Any
    error: ErrorDict | None
    id: RequestIdType


class RPCError(IntEnum):
    INVALID_REQUEST   = -32600              # Use the bad request (400) status code.
    METHOD_NOT_FOUND  = -32601              # Use the not found (404) status code.
    INVALID_PARAMS    = -32602              # Internal server error (500) status code.
    PARSE_ERROR       = -32700              # Internal server error (500) status code.

    TYPE_ERROR                      = -3    # Internal server error (500) status code.
    WALLET_ERROR                    = -4    # Internal server error (500) status code.
    INVALID_ADDRESS_OR_KEY          = -5    # Internal server error (500) status code.
    WALLET_INSUFFICIENT_FUNDS       = -6    # Internal server error (500) status code.
    INVALID_PARAMETER               = -8    # Internal server error (500) status code.
    WALLET_KEYPOOL_RAN_OUT          = -12   # Internal server error (500) status code.
    WALLET_UNLOCK_NEEDED            = -13   # Internal server error (500) status code.
    WALLET_PASSPHRASE_INCORRECT     = -14   # Internal server error (500) status code.
    WALLET_NOT_FOUND                = -18   # Internal server error (500) status code.
    WALLET_NOT_SPECIFIED            = -19   # Internal server error (500) status code.
    DESERIALIZATION_ERROR           = -22   # Internal server error (500) status code.
    VERIFY_ERROR                    = -25   # Internal server error (500) status code.
    VERIFY_REJECTED                 = -26   # Internal server error (500) status code.
    VERIFY_ALREADY_IN_CHAIN         = -27   # Internal server error (500) status code.


SIGHASH_MAPPING: dict[str, int] = {
    "ALL": SigHash.ALL,
    "ALL|ANYONECANPAY": SigHash.ALL | SigHash.ANYONE_CAN_PAY,
    "ALL|FORKID": SigHash.ALL | SigHash.FORKID,
    "ALL|FORKID|ANYONECANPAY": SigHash.ALL | SigHash.FORKID | SigHash.ANYONE_CAN_PAY,
    "NONE": SigHash.NONE,
    "NONE|ANYONECANPAY": SigHash.NONE | SigHash.ANYONE_CAN_PAY,
    "NONE|FORKID": SigHash.NONE | SigHash.FORKID,
    "NONE|FORKID|ANYONECANPAY": SigHash.NONE | SigHash.FORKID | SigHash.ANYONE_CAN_PAY,
    "SINGLE": SigHash.SINGLE,
    "SINGLE|ANYONECANPAY": SigHash.SINGLE | SigHash.ANYONE_CAN_PAY,
    "SINGLE|FORKID": SigHash.SINGLE | SigHash.FORKID,
    "SINGLE|FORKID|ANYONECANPAY": SigHash.SINGLE | SigHash.FORKID | SigHash.ANYONE_CAN_PAY,
}


class NodeAPIServer:
    is_running = False

    def __init__(self, host: str="localhost", port: int=8332, username: str|None=None,
            password: str|None=None) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password

        self._logger = logs.get_logger("nodeapi-server")
        self.startup_event = asyncio.Event()
        self.shutdown_event = asyncio.Event()

        self._runner: web.AppRunner | None = None
        self._web_application = web.Application(middlewares=[
            cors_middleware(origins=["http://localhost"],
                # The node JSON-RPC server only allowed POST requests.
                allow_methods=("POST",),
                allow_headers=("authorization",))
        ])
        self._web_application.on_startup.append(self._on_startup_async)
        self._web_application.on_shutdown.append(self._on_shutdown_async)

        self._web_application["server"] = self
        setup_web_application(self._web_application)

    async def _on_startup_async(self, _application: web.Application) -> None:
        self._logger.debug("starting...")

    async def _on_shutdown_async(self, _application: web.Application) -> None:
        self._logger.debug("cleaning up...")
        self.is_running = False
        self.shutdown_event.set()
        self._logger.debug("stopped")

    async def _start_async(self) -> None:
        self._runner = web.AppRunner(self._web_application, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port, reuse_address=True)
        await site.start()

    async def run_async(self) -> None:
        await self._start_async()
        self.is_running = True
        self._logger.info("JSON-RPC wallet API started on http://%s:%s", self._host, self._port)
        self.startup_event.set()
        await self.shutdown_event.wait()

    async def shutdown_async(self) -> None:
        assert self._runner is not None
        await self._runner.cleanup()

    def event_transaction_change(self, transaction_hash: bytes) -> None:
        """
        Called by various wallet code as an explicit JSON-RPC API hook.

        - When a transaction is added.
        - When a transaction is verified (mined or post-reorg).

        This is non-blocking and launches a thread to run the notification command in. The user
        can pass multiple commands to run for each notification, and while the node only allows
        one it doesn't really make any difference and it's more work to try and limit the
        command-line argument passing than just handle it.
        """
        if "walletnotify" not in app_state.config.cmdline_options:
            return

        transaction_id = hash_to_hex_str(transaction_hash)
        for command_line in app_state.config.cmdline_options["walletnotify"]:
            command_line = command_line.replace("%s", transaction_id)
            run_walletnotify_script(command_line)


def run_walletnotify_script(command_line: str) -> None:
    """
    For every `-walletnotify` command-line that the user passes to the wallet, we start a daemon
    thread that runs the script. If the user has long-running or stalled or erroneous scripts
    we do not care, the use of daemon threads should ensure they are all cleaned up on exit.
    """
    def execute_walletnotify_script() -> None:
        try:
            # The command line is a whole string with command and arguments together. For this
            # to run, the `shell` argument must be `True`. `check` ensures that if the command
            # errors we get an exception raised with details that will get logged.
            subprocess.run(command_line, shell=True, check=True)
        except Exception:
            logger.exception("Failed executing 'walletnotify' command of '%s'", command_line)

    thread = threading.Thread(target=execute_walletnotify_script)
    thread.setDaemon(True)
    thread.start()


@web.middleware
async def authentication_middleware_async(request: web.Request, handler: HandlerType) \
        -> web.StreamResponse:
    """
    Bitcoin node API behaviours:
    * Returns `Unauthorized` if there is no `"Authorization"` header.
    * Returns `Unauthorized` if the `"Authorization"` header is not a valid credential.
    """
    nodeapi_server = cast(NodeAPIServer, request.app["server"])
    assert nodeapi_server is not None

    if nodeapi_server._password == '':
        # authentication is disabled
        return await handler(request)

    auth_string = request.headers.get('Authorization', None)
    if auth_string is None:
        raise web.HTTPUnauthorized(reason="Missing credentials")

    (authorization_type, _, authorization_key) = auth_string.partition(' ')
    if authorization_type != 'Basic':
        raise web.HTTPUnauthorized()

    encoded = authorization_key.encode('utf8')
    try:
        credentials = b64decode(encoded).decode('utf8')
    except binascii.Error:
        raise web.HTTPUnauthorized()

    (username, _, password) = credentials.partition(':')
    assert nodeapi_server._username is not None and nodeapi_server._password is not None
    if not (constant_time_compare(username, nodeapi_server._username)
            and constant_time_compare(password, nodeapi_server._password)):
        raise web.HTTPUnauthorized()

    return await handler(request)


def setup_web_application(application: web.Application) -> None:
    application.middlewares.extend([
        web.normalize_path_middleware(append_slash=False, remove_slash=True),
        authentication_middleware_async ])

    # In theory all node JSON-RPC endpoints can be called by either of these handlers
    # but the wallet ones will be the only ones that use the `/wallet/<wallet name>/` part.
    application.router.add_routes([
        web.post("/", jsonrpc_handler_async),
        web.post("/wallet/{wallet}", jsonrpc_handler_async),
    ])

async def jsonrpc_handler_async(request: web.Request) -> web.Response:
    """
    This is intended to be the central handler for JSON-RPC requests.
    """
    try:
        body_data = await request.json()
    except json.JSONDecodeError:
        # Node `HTTPReq_JSONRPC` failed JSON parsing via `UniValue.read` error.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=None, result=None,
                    error=ErrorDict(code=RPCError.PARSE_ERROR, message="Parse error"))))

    if isinstance(body_data, dict):
        call_id, value = await execute_jsonrpc_call_async(request, body_data)
        return web.json_response(data=ResponseDict(id=call_id, result=value, error=None))
    elif isinstance(body_data, list):
        response_object: list[ResponseDict] = []
        for entry_data in body_data:
            call_id, entry_value = await execute_jsonrpc_call_async(request, entry_data)
            response_object.append(ResponseDict(id=call_id, result=entry_value, error=None))
        return web.json_response(data=response_object)

    # Node `HTTPReq_JSONRPC` not a single or batched call fallthrough error.
    raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=None, result=None,
                error=ErrorDict(code=RPCError.PARSE_ERROR,
                    message="Top-level object parse error"))))


async def execute_jsonrpc_call_async(request: web.Request, object_data: Any) \
        -> tuple[RequestIdType, Any]:
    """
    This should only raise `aiohttp` related web exceptions which should not need to be caught:
    - HTTPBadRequest
    - HTTPNotFound
    - HTTPTooEarly
    """
    if app_state.daemon.network is not None:
        if not app_state.daemon.network.is_initial_headers_sync_complete():
            raise HTTPTooEarly(headers={"Content-Type": "application/json"},
                text=json.dumps(ResponseDict(id=None, result=None,
                    error=ErrorDict(code=RPCError.WALLET_ERROR,
                        message="Initial header synchronization in progress. Try again soon."))))

    if not isinstance(object_data, dict):
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=None, result=None,
                error=ErrorDict(code=RPCError.INVALID_REQUEST,
                    message="Invalid Request object"))))

    raw_request_id = object_data.get("id")
    if not isinstance(raw_request_id, int | str | NoneType):
        # The node does not enforce typing for `id` in `JSONRPCRequest::parse` and returns
        # whatever it is passed. We enforce that `id` has to be a simple type because it
        # seems like a reasonable middle ground.
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=None, result=None,
                error=ErrorDict(code=RPCError.INVALID_REQUEST,
                    message="Id must be int, string or null"))))
    request_id = cast(RequestIdType, raw_request_id)

    method_name = object_data.get("method", ...)
    if method_name is ...:
        # Node `JSONRPCRequest::parse` error case.
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_REQUEST, message="Missing method"))))
    elif type(method_name) is not str:
        # Node `JSONRPCRequest::parse` error case.
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_REQUEST, message="Method must be a string"))))

    params = object_data.get("params")
    if params is None:
        params = []
    elif not isinstance(params, (dict, list)):
        # Node `JSONRPCRequest::parse` error case.
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_REQUEST,
                    message="Params must be an array or object"))))

    # These calls are intentionally explicitly dispatched inline so that we avoid any
    # unforeseen dynamic dispatching problems and also it means you can be more likely to be
    # able to just read the code and understand it without layers of abstraction.
    if method_name == "createrawtransaction":
        return request_id, await jsonrpc_createrawtransaction_async(request, request_id, params)
    elif method_name == "gettransaction":
        return request_id, await jsonrpc_gettransaction_async(request, request_id, params)
    elif method_name == "getbalance":
        return request_id, await jsonrpc_getbalance_async(request, request_id, params)
    elif method_name == "getnewaddress":
        return request_id, await jsonrpc_getnewaddress_async(request, request_id, params)
    elif method_name == "getrawchangeaddress":
        return request_id, await jsonrpc_getrawchangeaddress_async(request, request_id, params)
    elif method_name == "listunspent":
        return request_id, await jsonrpc_listunspent_async(request, request_id, params)
    elif method_name == "sendtoaddress":
        return request_id, await jsonrpc_sendtoaddress_async(request, request_id, params)
    elif method_name == "sendmany":
        return request_id, await jsonrpc_sendmany_async(request, request_id, params)
    elif method_name == "signrawtransaction":
        return request_id, await jsonrpc_signrawtransaction_async(request, request_id, params)
    elif method_name == "walletpassphrase":
        return request_id, await jsonrpc_walletpassphrase_async(request, request_id, params)

    raise web.HTTPNotFound(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.METHOD_NOT_FOUND, message="Method not found"))))


def get_wallet_from_request(request: web.Request, request_id: RequestIdType,
        ensure_available: bool=False) -> Wallet | None:
    """
    The node JSON-RPC API exposes the calls under both the non-wallet-specific `/` top-level
    and the wallet-specific `/wallet/<wallet-name>` paths. If there is only one wallet loaded
    the non-wallet-specific path will just work for that or otherwise not find a wallet.

    Raises `HTTPNotFound` for the implicit case of no wallet loaded.
    Raises `HTTPInternalServerError` for the implicit cases of too many wallets and the explicit
        cases of bad wallet path and and wallet not being loaded.
    """
    wallet_name = request.match_info.get("wallet")
    if wallet_name is None:
        # Preserve the node `GetWalletForJSONRPCRequest` functionality of returning the loaded
        # wallet in this case, but only if there is one and only one loaded.
        if len(app_state.daemon.wallets) == 1:
            return list(app_state.daemon.wallets.values())[0]

        if ensure_available:
            if len(app_state.daemon.wallets) == 0:
                raise web.HTTPNotFound(headers={ "Content-Type": "application/json" },
                        text=json.dumps(ResponseDict(id=request_id, result=None,
                            error=ErrorDict(code=RPCError.METHOD_NOT_FOUND,
                                message="Method not found (wallet method is disabled because "
                                    "no wallet is loaded"))))

            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.WALLET_NOT_SPECIFIED,
                            message="Wallet file not specified (must request wallet RPC "
                                "through /wallet/<filename> uri-path)"))))

        return None

    try:
        wallet_folder_path = app_state.config.get_wallet_directory_path()
    except FileNotFoundError:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.WALLET_NOT_FOUND,
                        message="No preferred wallet path"))))

    # It does not matter if the user loads in all sorts of things like extra slashes and parent
    # directory symbols, because we just map this to the already loaded wallets and it won't
    # find anything unless the path is one for a real loaded wallet.
    wallet_path = os.path.join(wallet_folder_path, wallet_name)
    wallet_path = os.path.normpath(wallet_path)

    wallet = app_state.daemon.get_wallet(wallet_path)
    if wallet is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.WALLET_NOT_FOUND,
                        message="Requested wallet does not exist or is not loaded"))))
    return wallet

def transform_parameters(request_id: RequestIdType, parameters_names: list[str],
        parameters: RequestParametersType) -> list[Any]:
    """
    Modelled after how the node accepts a "javascript" object or array, and transforms the object
    into the given array of parameter names.
    """
    if isinstance(parameters, list):
        # Node does not call this with arrays, just objects. Arrays are able to mismatch the
        # expected parameters. The lengths and types will be checked in the given call method.
        return parameters

    parameter_values: list[Any] = []
    for parameter_name in parameters_names:
        if parameter_name in parameters:
            parameter_values.append(parameters[parameter_name])
        else:
            parameter_values.append(None)

    disallowed_names = list(set(parameters) - set(parameters_names))
    if len(disallowed_names) > 0:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message=f"Unknown named parameter {disallowed_names[0]}"))))

    return parameter_values

def get_integer_parameter(request_id: RequestIdType, parameter_value: Any) -> int:
    if not isinstance(parameter_value, int):
        # The node maps the C++ exception on a non-integer value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.PARSE_ERROR,
                        message="JSON value is not an integer as expected"))))
    return parameter_value

def get_string_parameter(request_id: RequestIdType, parameter_value: Any) -> str:
    if not isinstance(parameter_value, str):
        # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.PARSE_ERROR,
                    message="JSON value is not a string as expected"))))
    return parameter_value

def get_bool_parameter(request_id: RequestIdType, parameter_value: Any) -> bool:
    if not isinstance(parameter_value, bool):
        # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.PARSE_ERROR,
                    message="JSON value is not a boolean as expected"))))
    return parameter_value

def get_amount_parameter(request_id: RequestIdType, parameter_value: Any) -> int:
    """
    Convert the parameter to satoshis if possible.
    """
    if not isinstance(parameter_value, (int, float, str)):
        # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.TYPE_ERROR,
                    message="Amount is not a number or string"))))

    amount_coins: Decimal
    if isinstance(parameter_value, int):
        amount_coins = Decimal(parameter_value)
    elif isinstance(parameter_value, str):
        if re.match(r"(\d+)?(\.\d+)?$", parameter_value) is None:
            # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.TYPE_ERROR,
                        message="Invalid amount"))))
        amount_coins = Decimal(parameter_value)
    elif isinstance(parameter_value, float):
        # Get rid of the floating point error.
        amount_coins = round(Decimal(parameter_value), 8)
    else:
        raise NotImplementedError("Programmer error")

    satoshis_per_coin = 100000000
    max_satoshis = 21000000 * satoshis_per_coin
    amount_satoshis = int(amount_coins * satoshis_per_coin)
    if amount_satoshis < 0 or amount_satoshis > max_satoshis:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.TYPE_ERROR,
                    message="Amount out of range"))))
    return amount_satoshis

def node_RPCTypeCheckArgument(request_id: RequestIdType, parameter_value: Any, type_value: Any) \
        -> None:
    if not isinstance(parameter_value, type_value):
        actual_name = type(parameter_value).__name__
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.TYPE_ERROR,
                    message=f"Expected type {type_value.__name__}, got {actual_name}"))))

def node_ParseHexV(request_id: RequestIdType, field_name: str, value: Any) -> bytes:
    result: bytes|None = None
    if isinstance(value, str) and len(value) > 0:
        try:
            result = bytes.fromhex(value)
        except ValueError:
            # Ignore non-hexadecimal characters.
            # Ignore incorrect length for hexadecimal.
            pass
    if result is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                    message=f"{field_name} must be hexadecimal string (not '{value}') and "
                        "length of it must be divisible by 2"))))
    return result

def node_ParseHashV(request_id: RequestIdType, field_name: str, value: Any) -> bytes:
    bytes_value = node_ParseHexV(request_id, field_name, value)
    if len(bytes_value) != 32:
        # We are talking about the hexadecimal length to the user as their value is that.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                    message=f"{field_name} must be of length 64 (not {len(bytes_value)*2})"))))
    # Do not forget to reverse the hash.
    return bytes_value[::-1]

async def jsonrpc_createrawtransaction_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    """
    Returns a hex-encoded transaction with the given payment output. The transaction input scripts
    are empty.

    Raises `HTTPInternalServerError` for related errors to return to the API using application.
    """
    # Compatibility: Raises RPC_INVALID_PARAMETER if we were given unlisted named parameters.
    parameter_values = transform_parameters(request_id, [ "inputs", "outputs", "locktime" ],
        parameters)
    if len(parameter_values) < 2 or len(parameter_values) > 3:
        # Node returns help. We do not. The user should see the documentation.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_PARAMS,
                    message="Invalid parameters, see documentation for this call"))))

    if parameter_values[0] is None or parameter_values[1] is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                    message="Invalid parameter, arguments 1 and 2 must be non-null"))))

    if not isinstance(parameter_values[0], list):
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.TYPE_ERROR,
                    message=f"Expected array, got {type(parameter_values[0]).__name__}"))))

    if not isinstance(parameter_values[1], dict):
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.TYPE_ERROR,
                    message=f"Expected object, got {type(parameter_values[1]).__name__}"))))

    locktime: int = 0
    if len(parameter_values) > 2 and parameter_values[2] is not None:
        locktime = get_integer_parameter(request_id, parameter_values[2])
        if locktime < 0 or locktime > 0xFFFFFFFF:
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Invalid parameter, locktime out of range"))))

    transaction_inputs: list[TxInput] = []
    for input_entry in parameter_values[0]:
        if not isinstance(input_entry, dict):
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.PARSE_ERROR,
                            message="JSON value is not an object as expected"))))

        prev_hash = node_ParseHashV(request_id, "txid", input_entry.get("txid"))

        prev_idx = input_entry.get("vout")
        if not isinstance(prev_idx, int):
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Invalid parameter, missing vout key"))))

        if prev_idx < 0:
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Invalid parameter, vout must be positive"))))

        # Remember that locktime is only observed for non-final transactions.
        if locktime == 0:
            sequence = 0xFFFFFFFF # Finalised input.
        else:
            sequence = 0xFFFFFFFE # Non-finalised input.
        sequence_value = input_entry.get("sequence")
        if isinstance(sequence_value, int):
            if sequence_value < 0 or sequence_value > 0xFFFFFFFF:
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                            message="Invalid parameter, sequence number is out of range"))))
            sequence = sequence_value

        transaction_inputs.append(TxInput(prev_hash, prev_idx, Script(), sequence))

    transaction_outputs: list[TxOutput] = []
    seen_addresses: set[Address] = set()
    for key_name, item_value in parameter_values[1].items():
        value: int = 0
        script: Script
        if key_name == "data":
            payload_bytes = node_ParseHexV(request_id, "Data", item_value)
            script_bytes = pack_byte(Ops.OP_0) + pack_byte(Ops.OP_RETURN) + push_item(
                payload_bytes)
            script = Script(script_bytes)
        else:
            assert isinstance(key_name, str)
            try:
                address = Address.from_string(key_name, Net.COIN)
            except ValueError as value_error:
                # Compatibility: Raises RPC_INVALID_ADDRESS_OR_KEY if the address is invalid.
                # rpcwallet.cpp:sendtoaddress (effective check)
                # Note that we show our error message text not what the node says so that we can
                # give hints like "wrong verbyte" or "p2sh not accepted" for direct context.
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.INVALID_ADDRESS_OR_KEY,
                            message=f"Invalid Bitcoin address: {value_error}"))))

            if address in seen_addresses:
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                            message=f"Invalid parameter, duplicated address: {key_name}"))))

            seen_addresses.add(address)
            script = address.to_script()
            value = get_amount_parameter(request_id, item_value)
        transaction_outputs.append(TxOutput(value, script))

    return Tx(1, transaction_inputs, transaction_outputs, locktime).to_hex()


class TransactionInfo(TypedDict, total=False):
    amount: float
    blockhash: str | None
    blockindex: int | None
    blocktime: int | None
    confirmations: int
    details: list[TransactionDetails]
    fee: float | None
    generated: bool | None
    hex: str
    time: int
    timereceived: int
    trusted: bool | None
    txid: str
    walletconflicts: list[str]


class TransactionDetails(TypedDict, total=False):
    account: str
    address: str | None
    amount: float
    category: str
    fee: float | None
    vout: int


async def jsonrpc_gettransaction_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    """
    Get detailed information about a transaction in the wallet.
    """
    # Ensure the user is accessing either an explicit or implicit wallet.
    wallet = get_wallet_from_request(request, request_id)
    assert wallet is not None
    # Similarly the user must only have one account (and we will ignore any
    # automatically created petty cash accounts which we do not use yet).
    accounts = wallet.get_visible_accounts()
    if len(accounts) != 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))

    account = accounts[0]
    # Compatibility: Raises RPC_INVALID_PARAMETER if we were given unlisted named parameters.
    parameter_values = transform_parameters(request_id, [ "txid", "include_watchonly" ],
        parameters)
    txid = parameter_values[0]
    node_RPCTypeCheckArgument(request_id, txid, str)
    node_ParseHexV(request_id, "txid", txid)
    # INCOMPATIBILITY: Raises RPC_INVALID_PARAMETER to indicate current lack of support for the
    # "include_watchonly" parameter - it should always be null.
    if len(parameter_values) > 1 and parameter_values[1] is not None:
        raise web.HTTPInternalServerError(headers={"Content-Type": "application/json"},
            text=json.dumps(ResponseDict(id=request_id, result=None,
            error=ErrorDict(code=RPCError.PARSE_ERROR,
            message="JSON value is not a null as expected"))))

    account_history_output_rows: list[AccountHistoryOutputRow] = \
        wallet.data.read_history_for_outputs(account.get_id(),
            transaction_hash=hex_str_to_hash(txid))

    transaction_info_obj: dict[bytes, TransactionInfo] = {}

    def build_transaction_details(row: AccountHistoryOutputRow) -> TransactionDetails:
        assert wallet is not None
        # "immature", "orphan", "generate" not implemented yet
        category = "receive" if row.value > 0 else "send"
        if row.is_coinbase:
            wallet_height = wallet.get_local_height()
            if row.block_hash is not None and wallet_height > 0:
                try:
                    lookup_result = wallet.lookup_header_for_hash(row.block_hash)
                except MissingHeader:
                    category = "orphan"
                else:
                    assert lookup_result is not None
                    header, chain = lookup_result
                    confirmations = wallet_height - header.height
                    if chain != wallet.get_current_chain():
                        category = "orphan"
                    elif confirmations < COINBASE_MATURITY:
                        category = "immature"
                    else:
                        category = "generate"
            else:
                category = "immature"

        # INCOMPATIBILITY: The 'account' field is always "" as we do not support this feature in
        # any way
        # INCOMPATIBILITY: The 'comment' field relates to data that cannot be modified. There are
        # therefore no plans to support this property.
        # INCOMPATIBILITY: The 'label' field relates to data that cannot be modified and the
        # original bitcoind API does not add this property for vouts with no label/comment.
        # There are therefore no plans to support this
        # property.
        # INCOMPATIBILITY: The 'abandoned' is always false as we always exclude deleted
        # transactions from results  in the wallet proper.
        # INCOMPATIBILITY: The involvesWatchonly field in details objects is never included as
        # the node wallet API does not support watch-only accounts at this time.
        address = ""
        script_type, _threshold, script_template = classify_transaction_output_script(
            Script(row.script_pubkey_bytes))
        if script_type == ScriptType.P2PKH:
            address = script_template.to_string()

        transaction_details = TransactionDetails(
            address=address,
            # abandoned=None,  # not implemented yet
            account="",
            amount=row.value / COIN,  # Convert from satoshis to bitcoins
            category=category,
            # fee=None,  # not implemented yet
            vout=row.txo_index,
        )
        return transaction_details

    details: list[TransactionDetails] = []
    for row in account_history_output_rows:
        if txid != hash_to_hex_str(row.tx_hash):
            continue

        transaction_details = build_transaction_details(row)
        details.append(transaction_details)


        # INCOMPATIBILITY: The time field in the main transaction object is always the same as the
        # timereceived value. bitcoind computes a “smart time” but we do not support that at this
        # time.
        # INCOMPATIBILITY: The walletconflicts field in the main transaction object is always []
        # as we do not
        # currently support this field.
        transaction_info = TransactionInfo(
            amount=row.value / COIN,
            blockhash=hash_to_hex_str(row.block_hash) if row.block_hash else None,
            blockindex=row.block_position if row.block_hash else None,
            # blocktime=None,  # not implemented yet
            # confirmations=None,  # not implemented yet
            details=details,
            # fee=None,  # not implemented yet
            hex="",
            time=row.date_created,
            timereceived=row.date_created,
            # trusted=None,  # not implemented yet
            txid=hash_to_hex_str(row.tx_hash),
            walletconflicts=[],
        )
        if row.is_coinbase:
            transaction_info['generated'] = True

        transaction_info_already_added = transaction_info_obj.get(row.tx_hash, None)
        # If there are multiple rows for a single tx_hash, overwrite the previous entry after
        # updating the amount
        if transaction_info_already_added:
            transaction_info['amount'] = transaction_info_already_added['amount'] + \
                (row.value / COIN)
        transaction_info_obj[row.tx_hash] = transaction_info

    return list(transaction_info_obj.values())


async def jsonrpc_getbalance_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    """
    Get the balance of the default account in the loaded wallet filtered for the desired number
    of confirmations.

    Raises `HTTPInternalServerError` for related errors to return to the API using application.
    """
    # Ensure the user is accessing either an explicit or implicit wallet.
    wallet = get_wallet_from_request(request, request_id)
    assert wallet is not None

    # Similarly the user must only have one account (and we will ignore any
    # automatically created petty cash accounts which we do not use yet).
    accounts = wallet.get_visible_accounts()
    if len(accounts) != 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))
    account = accounts[0]

    # Compatibility: Raises RPC_INVALID_PARAMETER if we were given unlisted named parameters.
    parameter_values = transform_parameters(request_id, [ "account", "minconf",
        "include_watchonly" ], parameters)

    # INCOMPATIBILITY: Raises RPC_INVALID_PARAMETER to indicate current lack of support for the
    # "account" parameter - it should always be null.
    if len(parameter_values) > 0 and parameter_values[0] is not None:
        raise web.HTTPInternalServerError(headers={"Content-Type": "application/json"},
            text=json.dumps(ResponseDict(id=request_id, result=None,
            error=ErrorDict(code=RPCError.PARSE_ERROR,
            message="JSON value is not a null as expected"))))

    minconf = 1
    if len(parameter_values) > 1 and parameter_values[1] is not None:
        # INCOMPATIBILITY: It is not necessary to do a `node_RPCTypeCheckArgument` as the node does.
        minconf = get_integer_parameter(request_id, parameter_values[1])

    # INCOMPATIBILITY: Raises RPC_INVALID_PARAMETER to indicate current lack of support for the
    # "include_watchonly" parameter - it should always be null.
    if len(parameter_values) > 2 and parameter_values[2] is not None:
        raise web.HTTPInternalServerError(headers={"Content-Type": "application/json"},
            text=json.dumps(ResponseDict(id=request_id, result=None,
            error=ErrorDict(code=RPCError.PARSE_ERROR,
            message="JSON value is not a null as expected"))))

    # Compatibility: Unmatured coins should be excluded from the final balance
    # see GetLegacyBalance: `https://github.com/bitcoin-sv/bitcoin-sv/
    # blob/b489c32ef55d428c5c3825d5526de018031a20af/src/wallet/wallet.cpp#L2238`
    if len(parameter_values) == 0:
        balance = account.get_balance()
        total_balance = balance.confirmed
        return total_balance/COIN

    confirmed_only = minconf > 0
    wallet_height = wallet.get_local_height()
    total_balance = 0
    # NOTE: This code block is replicated from the listunspent endpoint
    for utxo_data in account.get_transaction_outputs_with_key_and_tx_data(
            exclude_frozen=True, confirmed_only=confirmed_only):
        assert utxo_data.derivation_data2 is not None
        if utxo_data.derivation_type != DerivationType.BIP32_SUBPATH:
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Invalid parameter, unexpected utxo type: "+
                            str(utxo_data.derivation_type)))))

        public_keys = account.get_public_keys_for_derivation(utxo_data.derivation_type,
            utxo_data.derivation_data2)
        assert len(public_keys) == 1, "not a single-signature account"

        confirmations = 0
        if utxo_data.block_hash is not None and wallet_height > 0:
            lookup_result = wallet.lookup_header_for_hash(utxo_data.block_hash)
            if lookup_result is not None:
                header, _chain = lookup_result
                confirmations = wallet_height - header.height

        if confirmations < minconf:
            continue

        # Condition 1:
        # - Not if the given transaction is non-final.
        #   ElectrumSV take: All transactions in the database as of 2022-12 are final.

        # Condition 2:
        # - Not if the given transaction is an immature coinbase transaction.
        if utxo_data.flags & TransactionOutputFlag.COINBASE != 0 and confirmations < 100:
            continue

        # Condition 3 / 4:
        # - Not if the given transaction's depth in the main chain less than zero.
        #   wallet.cpp:GetDepthInMainChain
        #   - If there is no block hash the height is the MEMPOOL_HEIGHT constant.
        #     - Any local signed transaction is presumably broadcastable or abandoned.
        #   - If the transaction is on a block on the wallet's chain, then the depth is
        #     the positive height of that anointed as legitimate block.
        #   - If the transaction is on a block on a fork, then the depth is the negative height
        #     of that forked block.
        # - Not if the given transaction's depth is 0 but it's not in our mempool.

        # ElectrumSV take: We only set `block_hash` (and `STATE_SETTLED`) on transactions on the
        #     wallet's main chain. We can only know if a transaction is in a mempool if
        #     we have broadcast it (and set `STATE_CLEARED`). Our best equivalent to this is
        #     `MASK_STATE_BROADCAST` which is just both those flags.
        if utxo_data.tx_flags & TxFlags.MASK_STATE_BROADCAST == 0:
            continue

        total_balance += utxo_data.value

    return total_balance/COIN

async def jsonrpc_getnewaddress_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    """
    Create a new receiving address, register it successfully with the provisioned blockchain
    service and then return it to the caller.

    Raises `HTTPInternalServerError` for related errors to return to the API using application.
    """
    # Regarding cleaning up on errors these are all @FutureDatabasePruning cases. This applies to
    # both created payment request rows and tip filter registration rows.

    # Ensure the user is accessing either an explicit or implicit wallet.
    wallet = get_wallet_from_request(request, request_id)
    assert wallet is not None

    # While this is checked when we go to monitor the payment it is unlikely that it will become
    # unavailable between now and then. By checking it before doing anything we can avoid doing
    # things we would otherwise need to clean up.
    server_state = wallet.get_tip_filter_server_state()
    if server_state is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message="No connected blockchain server"))))

    # Similarly the user must only have one account (and we will ignore any
    # automatically created petty cash accounts which we do not use yet).
    accounts = wallet.get_visible_accounts()
    if len(accounts) != 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))
    account = accounts[0]

    # By not setting an actual value for the amount the code that would otherwise close the
    # payment request when the expected value to be received is met, ignores the payment for
    # this payment request. See @BlindPaymentRequests.
    date_expires = int(time.time()) + 24 * 60 * 60
    future = app_state.async_.spawn(account.create_monitored_blockchain_payment_async(None, None,
        merchant_reference=None, date_expires=date_expires))
    try:
        request_row, request_output_rows, job_data = await asyncio.wrap_future(future)
    except (NoViableServersError, ServiceUnavailableError):
        # If we did not check for this case above before we created the payment request we
        # would probably clean up here. But the chance of this happening is so slight and
        # the unmonitored and never returned payment request should expire.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message="Blockchain server address monitoring request not successful"))))

    if job_data.date_registered is None:
        # The failure reason is the stringified text for the exception encountered. The details
        # are also present in the logs. It should be a relayed error from the blockchain server.
        assert job_data.failure_reason is not None
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR, message=job_data.failure_reason))))

    # Strictly speaking we return the address of whatever this is. It is almost guaranteed to be
    # a base58 encoded P2PKH address that we return.
    output_script = Script(request_output_rows[0].output_script_bytes)
    script_type, threshold, script_template = classify_transaction_output_script(
        output_script)
    return script_template_to_string(script_template)


async def jsonrpc_getrawchangeaddress_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    """
    Reserve the next unused change address (otherwise known as external key) and return it as
    a P2PKH address. This differs from the getnewaddress endpoint in that there is no blockchain
    monitoring for this address.

    Raises `HTTPInternalServerError` for related errors to return to the API using application.
    """
    # Ensure the user is accessing either an explicit or implicit wallet.
    wallet = get_wallet_from_request(request, request_id)
    assert wallet is not None

    # Similarly the user must only have one account (and we will ignore any
    # automatically created petty cash accounts which we do not use yet).
    accounts = wallet.get_visible_accounts()
    if len(accounts) != 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))
    account = accounts[0]
    key_data = account.reserve_unassigned_key(CHANGE_SUBPATH,
        KeyInstanceFlag.IS_RAW_CHANGE_ADDRESS)

    # Strictly speaking we return the address of whatever this is. It is almost guaranteed to be
    # a base58 encoded P2PKH address that we return.
    script_type: ScriptType | None = account.get_default_script_type()
    assert script_type is not None
    output_script = account.get_script_for_derivation(script_type, key_data.derivation_type,
        key_data.derivation_data2)
    script_type, threshold, script_template = classify_transaction_output_script(
        output_script)
    return script_template_to_string(script_template)


async def jsonrpc_listunspent_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    """
    Returns a list of unspent transaction outputs with the desired number of confirmations.

    Raises `HTTPInternalServerError` for related errors to return to the API using application.
    """
    # Ensure the user is accessing either an explicit or implicit wallet.
    wallet = get_wallet_from_request(request, request_id)
    assert wallet is not None

    # Similarly the user must only have one account (and we will ignore any
    # automatically created petty cash accounts which we do not use yet).
    accounts = wallet.get_visible_accounts()
    if len(accounts) != 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))
    account = accounts[0]

    # Compatibility: Raises RPC_INVALID_PARAMETER if we were given unlisted named parameters.
    parameter_values = transform_parameters(request_id, [ "minconf", "maxconf", "addresses",
        "include_unsafe" ], parameters)

    minimum_confirmations = 1
    if len(parameter_values) > 0 and parameter_values[0] is not None:
        # INCOMPATIBILITY: It is not necessary to do a `node_RPCTypeCheckArgument` as the node does.
        minimum_confirmations = get_integer_parameter(request_id, parameter_values[0])

    maximum_confirmations = 9999999
    if len(parameter_values) > 1 and parameter_values[1] is not None:
        # INCOMPATIBILITY: It is not necessary to do a `node_RPCTypeCheckArgument` as the node does.
        maximum_confirmations = get_integer_parameter(request_id, parameter_values[1])

    filter_addresses: set[Address]|None = None
    if len(parameter_values) > 2 and parameter_values[2] is not None:
        # Compatibility: Returns a `RPC_TYPE_ERROR` response if the parameter is not a list.
        node_RPCTypeCheckArgument(request_id, parameter_values[2], list)

        filter_addresses = set()
        for entry_value in parameter_values[2]:
            address_text = get_string_parameter(request_id, entry_value)
            try:
                address = Address.from_string(address_text, Net.COIN)
            except ValueError as value_error:
                # Compatibility: Raises RPC_INVALID_ADDRESS_OR_KEY if the address is invalid.
                # rpcwallet.cpp:sendtoaddress (effective check)
                # Note that we show our error message text not what the node says so that we can
                # give hints like "wrong verbyte" or "p2sh not accepted" for direct context.
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.INVALID_ADDRESS_OR_KEY,
                            message=f"Invalid Bitcoin address: {value_error}"))))

            if address in filter_addresses:
                # Compatibility: Raises RPC_INVALID_PARAMETER if the address is invalid.
                # rpcwallet.cpp:sendtoaddress (effective check)
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                            message=f"Invalid parameter, duplicated address: {entry_value}"))))
            filter_addresses.add(address)

    only_safe = True
    if len(parameter_values) > 3 and parameter_values[3] is not None:
        include_unsafe = get_bool_parameter(request_id, parameter_values[3])
        only_safe = not include_unsafe

    class NodeUnspentOutputDict(TypedDict):
        # The UTXO outpoint.
        txid: str
        vout: int

        address: str
        # The UTXO locking script.
        scriptPubKey: str
        amount: float
        confirmations: int
        spendable: bool
        solvable: bool
        safe: bool

    confirmed_only = minimum_confirmations > 0
    wallet_height = wallet.get_local_height()
    results: list[NodeUnspentOutputDict] = []
    # NOTE: This code block is replicated in the getbalance endpoint (but without Condition 5 check)
    for utxo_data in account.get_transaction_outputs_with_key_and_tx_data(
            exclude_frozen=True, confirmed_only=confirmed_only):
        assert utxo_data.derivation_data2 is not None
        if utxo_data.derivation_type != DerivationType.BIP32_SUBPATH:
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Invalid parameter, unexpected utxo type: "+
                            str(utxo_data.derivation_type)))))

        public_keys = account.get_public_keys_for_derivation(utxo_data.derivation_type,
            utxo_data.derivation_data2)
        assert len(public_keys) == 1, "not a single-signature account"
        address = public_keys[0].to_address(network=Net.COIN)

        if filter_addresses is not None and address not in filter_addresses:
            continue

        confirmations = 0
        if utxo_data.block_hash is not None and wallet_height > 0:
            lookup_result = wallet.lookup_header_for_hash(utxo_data.block_hash)
            if lookup_result is not None:
                header, _chain = lookup_result
                confirmations = wallet_height - header.height

        if confirmations < minimum_confirmations or confirmations > maximum_confirmations:
            continue

        # Condition 1:
        # - Not if the given transaction is non-final.
        #   ElectrumSV take: All transactions in the database as of 2022-12 are final.

        # Condition 2:
        # - Not if the given transaction is an immature coinbase transaction.
        if utxo_data.flags & TransactionOutputFlag.COINBASE != 0 and confirmations < 100:
            continue

        # Condition 3 / 4:
        # - Not if the given transaction's depth in the main chain less than zero.
        #   wallet.cpp:GetDepthInMainChain
        #   - If there is no block hash the height is the MEMPOOL_HEIGHT constant.
        #     - Any local signed transaction is presumably broadcastable or abandoned.
        #   - If the transaction is on a block on the wallet's chain, then the depth is
        #     the positive height of that anointed as legitimate block.
        #   - If the transaction is on a block on a fork, then the depth is the negative height
        #     of that forked block.
        # - Not if the given transaction's depth is 0 but it's not in our mempool.

        # ElectrumSV take: We only set `block_hash` (and `STATE_SETTLED`) on transactions on the
        #     wallet's main chain. We can only know if a transaction is in a mempool if
        #     we have broadcast it (and set `STATE_CLEARED`). Our best equivalent to this is
        #     `MASK_STATE_BROADCAST` which is just both those flags.
        if utxo_data.tx_flags & TxFlags.MASK_STATE_BROADCAST == 0:
            continue

        # Condition 5: Is the given transaction trusted? (wallet.cpp:CWalletTx::IsTrusted)
        # - Not if the given transaction is non-final.
        # - Yes if the given transaction has at least one confirmation.
        # - Not if the given transaction is in a block on another fork.
        # - Not if the wallet is configured to not spend "zero confirmation change" (which the node
        #   wallet defaults to setting to spend).
        # - Not if the given transaction is not funded by ourselves (note that this is not tied to
        #   the use of a change derivation path).
        # - Not if the given known to be unconfirmed transaction is not in "this node's"  mempool.
        # - Not if any of the funding does not come from us.
        # - Not if our funding is not spendable by us (we can produce a signature / have the key).

        # ElectrumSV take:
        # - We do not get non-final transactions here.
        # - We have already filtered out non-broadcast/non-mined transactions.
        # - We do not have a setting for whether to spend "zero confirmation change" or not but we
        #   do have a setting for "only spend confirmed coins" (we default this to no). These are
        #   not the same thing.
        #   - Read all the funding TXOs, if we have them all and they have keys, then we are
        #     meeting this constraint.
        # - Basically it comes down to the latter. A trusted coin is one from any confirmed
        #   transaction or one that comes from an coin in an unconfirmed transaction that we
        #   completely funded ourselves. We treat "zero confirmation change" as true and do not
        #   provide a way to disable it.
        safe = True
        if confirmations == 0:
            for funding_row in wallet.data.read_parent_transaction_outputs_with_key_data(
                    utxo_data.tx_hash, include_absent=True):
                # This will exit on funding by unknown transactions and also on funding by external
                # transactions we do not have the keys for.
                if funding_row.keyinstance_id is None:
                    safe = False
                    break

        if only_safe and not safe:
            continue

        utxo_entry: NodeUnspentOutputDict = {
            "txid": hash_to_hex_str(utxo_data.tx_hash),
            "vout": utxo_data.txo_index,

            "address": address.to_string(),
            "scriptPubKey": address.to_script_bytes().hex(),
            "amount": utxo_data.value/COIN,
            "confirmations": confirmations,
            # From the node: "Whether we have the private keys to spend this output."
            "spendable": utxo_data.keyinstance_id is not None,
            # From the node: "Whether we know how to spend this output, ignoring the lack of keys."
            "solvable": True,
            # From the node: "Whether this output is considered safe to spend. Unconfirmed
            #     transactions from outside keys are considered unsafe and will not be used to fund
            #     new spending transactions."
            "safe": safe,
        }
        results.append(utxo_entry)

    return results

async def jsonrpc_sendtoaddress_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    """
    Raises `HTTPNotFoundError` for wallet location failure.
    Raises `HTTPInternalServerError` for wallet location failure, parameter processing failure.
    """
    # Ensure the user is accessing either an explicit or implicit wallet.
    wallet = get_wallet_from_request(request, request_id)
    assert wallet is not None

    # Similarly the user must only have one account (and we will ignore any
    # automatically created petty cash accounts which we do not use yet).
    accounts = wallet.get_visible_accounts()
    if len(accounts) != 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))
    account = accounts[0]

    wallet_password = app_state.credentials.get_wallet_password(wallet.get_storage_path())
    if wallet_password is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_UNLOCK_NEEDED,
                    message="Error: Please enter the wallet passphrase with " \
                        "walletpassphrase first."))))

    # Compatibility: Raises RPC_INVALID_PARAMETER if we were given unlisted named parameters.
    parameter_values = transform_parameters(request_id, [ "address", "amount", "comment",
        "commentto", "subtractfeefromamount" ], parameters)
    if len(parameter_values) < 2 or len(parameter_values) > 5:
        # Node returns help. We do not. The user should see the documentation.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_PARAMS,
                    message="Invalid parameters, see documentation for this call"))))

    # Compatibility: Raises RPC_PARSE_ERROR for non-string.
    address_text = get_string_parameter(request_id, parameter_values[0])
    try:
        address = Address.from_string(address_text, Net.COIN)
    except ValueError as value_error:
        # Compatibility: Raises RPC_INVALID_ADDRESS_OR_KEY if the address is invalid.
        # rpcwallet.cpp:sendtoaddress (effective check)
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_ADDRESS_OR_KEY,
                    message=f"Invalid address: {value_error}"))))

    # Compatibility: Raises RPC_PARSE_ERROR for invalid type.
    amount_satoshis = get_amount_parameter(request_id, parameter_values[1])
    if amount_satoshis < 1:
        # Compatibility: Raises RPC_TYPE_ERROR for invalid amounts (zero or less).
        # rpcwallet.cpp:sendtoaddress (effective check)
        # rpcwallet.cpp:SendMoney (redundant check)
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.TYPE_ERROR, message="Invalid amount for send"))))

    comment_sections: list[str] = []
    if len(parameter_values) >= 3 and parameter_values[2] is not None:
        # Compatibility: Raises RPC_PARSE_ERROR for invalid type.
        text = get_string_parameter(request_id, parameter_values[2])
        if len(text) > 0:
            comment_sections.append(text)
    if len(parameter_values) >= 4 and parameter_values[3] is not None:
        # Compatibility: Raises RPC_PARSE_ERROR for invalid type.
        text = get_string_parameter(request_id, parameter_values[3])
        if len(text) > 0:
            comment_sections.append(f"(to: {text})")

    comment_text: str | None = None
    if len(comment_sections) > 0:
        comment_text = " ".join(comment_sections)

    subtract_fee_from_amount = False
    if len(parameter_values) >= 5:
        # Compatibility: Raises RPC_PARSE_ERROR for invalid type.
        subtract_fee_from_amount = get_bool_parameter(request_id, parameter_values[4])
        if subtract_fee_from_amount:
            # INCOMPATIBILITY: Raises RPC_INVALID_PARAMETER to indicate current lack of support.
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Subtract fee from amount not currently supported"))))

    # @MAPIFeeQuote @TechnicalDebt Non-ideal way to ensure the fee quotes are cached.
    viable_fee_contexts = await wallet.update_mapi_fee_quotes_async(account.get_id())
    if len(viable_fee_contexts) == 0:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message="No suitable MAPI server for broadcast"))))

    selected_fee_context = random.choice(viable_fee_contexts)
    mapi_fee_estimator = TransactionFeeEstimator(selected_fee_context.fee_quote,
        selected_fee_context.server_and_credential)

    coins = account.get_transaction_outputs_with_key_data()
    outputs = [ XTxOutput(amount_satoshis, address.to_script()) ] # type: ignore[arg-type]
    try:
        transaction, transaction_context = account.make_unsigned_transaction(coins, outputs,
            mapi_fee_estimator)
    except NotEnoughFunds:
        # rpcwallet.cpp:SendMoney
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_INSUFFICIENT_FUNDS,
                    message="Insufficient funds"))))

    if comment_text is not None:
        transaction_context.account_descriptions[account.get_id()] = comment_text
    future = account.sign_transaction(transaction, wallet_password, context=transaction_context,
        import_flags=TransactionImportFlag.UNSET)
    # We are okay with an assertion here because we should be confident it is impossible for this
    # to happen outside of approved circumstances.
    assert future is not None
    await asyncio.wrap_future(future)

    # The only mechanism we have to know if the transaction ends up in a block is the peer
    # channel registration.
    mapi_server_hint = wallet.get_mapi_broadcast_context(account.get_id(), transaction)
    if mapi_server_hint is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message="No suitable MAPI server for broadcast"))))

    transaction_context.mapi_server_hint = mapi_server_hint
    try:
        broadcast_result = await wallet.broadcast_transaction_async(transaction,
            transaction_context)
    except BroadcastError as broadcast_error:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR, message=str(broadcast_error)))))

    # At this point the transaction should be signed.
    transaction_id = transaction.txid()
    assert transaction_id is not None
    return transaction_id

async def jsonrpc_sendmany_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    # wallet = get_wallet_from_request(request, request_id)
    return "jsonrpc_sendmany_async"

class SignRawTransactionErrorDict(TypedDict):
    txid: str
    vout: int
    scriptSig: str
    sequence: int
    error: str

class SignRawTransactionResultDict(TypedDict):
    hex: str
    complete: bool
    errors: NotRequired[list[SignRawTransactionErrorDict]]

class PrevOutDict(TypedDict):
    # The UTXO outpoint.
    txid: str
    vout: int
    scriptPubKey: str
    amount: NotRequired[int | str | float]

class PreviousOutputData(NamedTuple):
    transaction_hash: bytes
    output_index: int
    script_bytes: bytes
    value: int
    block_hash: bytes|None = None
    flags: TransactionOutputFlag = TransactionOutputFlag.NONE


async def jsonrpc_signrawtransaction_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    """
    Raises `HTTPNotFoundError` for wallet location failure.
    Raises `HTTPInternalServerError` for wallet location failure, parameter processing failure.
    """
    # Ensure the user is accessing either an explicit or implicit wallet.
    wallet = get_wallet_from_request(request, request_id)
    assert wallet is not None

    # Similarly the user must only have one account (and we will ignore any
    # automatically created petty cash accounts which we do not use yet).
    accounts = wallet.get_visible_accounts()
    if len(accounts) != 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))
    account = accounts[0]

    wallet_password = app_state.credentials.get_wallet_password(wallet.get_storage_path())
    if wallet_password is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.WALLET_UNLOCK_NEEDED,
                    message="Error: Please enter the wallet passphrase with " \
                        "walletpassphrase first."))))

    # Compatibility: Raises RPC_INVALID_PARAMETER if we were given unlisted named parameters.
    parameter_values = transform_parameters(request_id, [ "hexstring", "prevtxs", "privkeys",
        "sighashtype" ], parameters)
    if len(parameter_values) < 1 or len(parameter_values) > 4:
        # Node returns help. We do not. The user should see the documentation.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_PARAMS,
                    message="Invalid parameters, see documentation for this call"))))

    # Compatibility: Raises RPC_TYPE_ERROR for non-string (node check allows nulls).
    if parameter_values[0] is not None:
        node_RPCTypeCheckArgument(request_id, parameter_values[0], str)

    # Compatibility: Raises RPC_TYPE_ERROR for non-list (node check allows nulls).
    if len(parameter_values) > 1 and parameter_values[1] is not None:
        node_RPCTypeCheckArgument(request_id, parameter_values[1], list)

    # Compatibility: Raises RPC_TYPE_ERROR for non-list (node check allows nulls).
    if len(parameter_values) > 2 and parameter_values[2] is not None:
        node_RPCTypeCheckArgument(request_id, parameter_values[2], list)

    # Compatibility: Raises RPC_TYPE_ERROR for non-string (node check allows nulls).
    if len(parameter_values) > 3 and parameter_values[3] is not None:
        node_RPCTypeCheckArgument(request_id, parameter_values[3], str)

    # Compatibility: Raises RPC_INVALID_PARAMETER for non-string or invalid hexadecimal value.
    concatenated_transaction_bytes = node_ParseHexV(request_id, "argument 1", parameter_values[0])

    # NOTE(rt12) We do not allow `Exception` to be caught if we can identify what will be
    #     raised. In this case, there are numerous possibilities from various things choking
    #     on short reads or unpacking structs or invalid values and so on. It would be a task
    #     in itself to write code to identify these and even then I am not sure it is possible
    #     to know for sure. In an ideal world the code we use should document/declare it.
    try:
        transactions = transactions_from_node_bytes(concatenated_transaction_bytes, {})
    except Exception:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.DESERIALIZATION_ERROR,
                    message="Tx decode failed"))))

    if len(transactions) == 0:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.DESERIALIZATION_ERROR,
                    message="Missing transaction"))))

    # INCOMPATIBILITY: We do not currently accept more than one transaction variation.
    if len(transactions) > 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.DESERIALIZATION_ERROR,
                    message="Compatibility difference (multiple transactions not accepted)"))))

    # INCOMPATIBILITY: We do not currently accept external keys for signing.
    if len(parameter_values) > 2 and parameter_values[2] is not None and \
            len(parameter_values[2]) > 0:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                    message="Compatibility difference (external keys not accepted)"))))

    # Note that these transactions are the base transaction and other versions of that base
    # transaction which may include signatures not included elsewhere. We consider all transactions
    # left in the list at this point to be the secondary ones with potential additional signatures.
    base_transaction = transactions.pop(0)

    # Like the original node wallet, we use the first transaction as a base point. It should be
    # representative of the set of previous outputs involved and the spending of being signed for.
    outpoints = [ Outpoint(transaction_input.prev_hash, transaction_input.prev_idx)
        for transaction_input in base_transaction.inputs ]
    coin_rows = account.get_transaction_outputs_with_key_and_tx_data(outpoints=outpoints)
    coins_view: dict[Outpoint, PreviousOutputData] = {}
    for coin_row in coin_rows:
        outpoint = Outpoint(coin_row.tx_hash, coin_row.txo_index)
        input_index = outpoints.index(outpoint)
        original_input = base_transaction.inputs[input_index]
        assert isinstance(original_input, XTxInput)
        database_transaction_input = account.get_extended_input_for_spendable_output(coin_row)
        original_input.x_pubkeys = database_transaction_input.x_pubkeys
        original_input.script_type = database_transaction_input.script_type
        original_input.value = database_transaction_input.value
        original_input.threshold = database_transaction_input.threshold
        # INCOMPATIBILITY: We do not currently sign for non-P2PKH spends.
        if original_input.script_type != ScriptType.P2PKH:
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.DESERIALIZATION_ERROR,
                        message="Compatibility difference (non-P2PKH coins not accepted)"))))
        coins_view[outpoint] = PreviousOutputData(coin_row.tx_hash, coin_row.txo_index,
            coin_row.script_bytes, coin_row.value, coin_row.block_hash, coin_row.flags)

    if len(parameter_values) > 1 and parameter_values[1] is not None and \
            len(parameter_values[1]) > 0:
        prevout_datas = cast(list[PrevOutDict], parameter_values[1])
        # Pre-validate all the data in the input prevout objects.
        # INCOMPATIBILITY: This moves all validation of outpoint and scriptpubkey entries above
        #    any additional processing. This is a minor detail and not important.
        for prevout_data in prevout_datas:
            if not isinstance(prevout_data, dict):
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.DESERIALIZATION_ERROR,
                            message="expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}"))))

            transaction_id: str|None  = prevout_data.get("txid")
            if transaction_id is None:
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.TYPE_ERROR, message="Missing txid"))))
            if not isinstance(transaction_id, str):
                type_name = type(transaction_id).__name__
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.TYPE_ERROR,
                            message=f"Expected type string for txid, got {type_name}"))))

            output_index: int|None = prevout_data.get("vout")
            if output_index is None:
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.TYPE_ERROR, message="Missing vout"))))
            if not isinstance(output_index, int):
                type_name = type(output_index).__name__
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.TYPE_ERROR,
                            message=f"Expected type integer for vout, got {type_name}"))))

            output_script_hex: str|None = prevout_data.get("scriptPubKey")
            if output_script_hex is None:
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.TYPE_ERROR, message="Missing scriptPubKey"))))
            if not isinstance(output_script_hex, str):
                type_name = type(output_script_hex).__name__
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.TYPE_ERROR,
                            message=f"Expected type string for scriptPubKey, got {type_name}"))))
            # Verify that the output script is valid hex, we will use it later.
            node_ParseHexV(request_id, "scriptPubKey", output_script_hex)

            transaction_hash = node_ParseHashV(request_id, "txid", transaction_id)
            if output_index < 0:
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.DESERIALIZATION_ERROR,
                            message="vout must be positive"))))

            prevout_outpoint = Outpoint(transaction_hash, output_index)

            # We already validated that this was a string above.
            external_script_bytes = bytes.fromhex(prevout_data["scriptPubKey"])
            txo_row = coins_view.get(prevout_outpoint)
            if txo_row is not None and txo_row.flags & TransactionOutputFlag.SPENT == 0 and \
                    txo_row.script_bytes != external_script_bytes:
                their_script_asm = Script(external_script_bytes).to_asm(True)
                our_script_asm = Script(txo_row.script_bytes).to_asm(True)
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.DESERIALIZATION_ERROR,
                            message="Previous output scriptPubKey mismatch:\n"+ our_script_asm +
                                "\nvs\n"+ their_script_asm))))

            if "amount" not in prevout_data:
                raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                            message="Missing amount"))))

            amount = get_amount_parameter(request_id, prevout_data["amount"])

            # Compatibility: The node wallet fetches the coins view, merges it with the mempool
            #     view and then produces some kind of cache. Any manually provided coins are added
            #     to the cache overwriting those fetched from the database.
            coins_view[prevout_outpoint] = PreviousOutputData(transaction_hash, output_index,
                external_script_bytes, amount)

    sighash_value: int = SigHash.ALL | SigHash.FORKID
    if len(parameter_values) > 3 and parameter_values[3] is not None:
        sighash_text = get_string_parameter(request_id, parameter_values[3])
        if sighash_text not in SIGHASH_MAPPING:
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Invalid sighash param"))))
        sighash_value = SIGHASH_MAPPING[sighash_text]
        if sighash_value & SigHash.FORKID == 0:
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Signature must use SIGHASH_FORKID"))))

        # INCOMPATIBILITY: We do not currently sign accept sighash variations (not tested!).
        if sighash_value != SigHash.ALL | SigHash.FORKID:
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMETER,
                        message="Compatibility difference (only ALL|FORKID sighash accepted)"))))

    errors: list[SignRawTransactionErrorDict] = []
    transaction_input: XTxInput

    # The node wallet does this validation pass for each input before it signs that specific input.
    # As we can only sign the whole transaction, we do it for all inputs before proceeding. We will
    # restore the input scripts for the specific inputs that failed the validation.
    preserved_signatures: dict[int, dict[bytes, bytes]] = {}
    for input_index, transaction_input in enumerate(base_transaction.inputs):
        outpoint = Outpoint(transaction_input.prev_hash, transaction_input.prev_idx)
        coin_data = coins_view.get(outpoint)
        if coin_data is None or coin_data.flags & TransactionOutputFlag.SPENT:
            errors.append({
                "txid": hash_to_hex_str(transaction_input.prev_hash),
                "vout": transaction_input.prev_idx,
                "scriptSig": transaction_input.script_sig.to_hex(),
                "sequence": transaction_input.sequence,
                "error": "Input not found or already spent",
            })
            # The node wallet does not sign inputs that fail validation. We will preserve that
            # behaviour.
            preserved_signatures[input_index] = transaction_input.signatures.copy()

    transaction_context = TransactionContext()
    future = account.sign_transaction(base_transaction, wallet_password,
        context=transaction_context, import_flags=TransactionImportFlag.UNSET)
    # We are okay with an assertion here because we should be confident it is impossible for this
    # to happen outside of approved circumstances.
    assert future is not None
    # Link state is only returned for complete transactions. Incomplete or not fully signed
    # transactions are the only case at time of writing (20230125) that return `None`.
    _link_result = await asyncio.wrap_future(future)

    def is_utxo_after_genesis(wallet: Wallet, block_hash: bytes|None) -> bool:
        """
        Caveats:
        - It is assumed the blockchain is synchronised and this wallet is also synchronised.
          If this is not the case, it is possible for the caller to provide transactions that
          are in unprocessed heights and pre-genesis.
        """
        if block_hash is not None:
            header_and_chain = wallet.lookup_header_for_hash(block_hash)
            if header_and_chain is not None:
                header, chain = header_and_chain
                # NOTE(typing) bitcoinx provides both `.COIN` and `Header` neither of which are
                #     typed. We need to cast the resulting "non-boolean" from the comparison.
                return cast(bool, header.height >= Net.COIN.genesis_height)
        # Presumably this is an off-chain transaction or a transaction in the mempool.
        return True

    if len(errors) > 0:
        # If any inputs failed validation earlier we do not sign them to align ourselves with node
        # wallet behaviour. Restore those scripts here.
        for input_index, preexisting_signatures in preserved_signatures.items():
            base_transaction.inputs[input_index].signatures = preexisting_signatures
            # INCOMPATIBILITY: Multi-signature needs to generate a `script_sig` for the input
            #     with placeholders for the empty signatures.
            base_transaction.inputs[input_index].script_sig = Script(b"")
    else:
        # Iterate over the other transactions we were given by the caller and merge in any
        # signatures we can use from them. The node has different handling depending on the type
        # of script in the spent output. Our incomplete transaction already have signature
        # metadata so we can avoid getting transaction template specific here.
        for input_index, transaction_input in enumerate(base_transaction.inputs):
            outpoint = Outpoint(transaction_input.prev_hash, transaction_input.prev_idx)
            db_txo_row = coins_view.get(outpoint)
            # We would already have an error entry for this input if the spent txo is not present.
            if db_txo_row is None:
                continue

            new_input_signatures: dict[bytes, bytes] = {}
            all_input_signatures: list[tuple[bytes, bytes]] = \
                list(transaction_input.signatures.items())
            for mergeable_transaction in transactions:
                if input_index < len(mergeable_transaction.inputs):
                    mergeable_input = mergeable_transaction.inputs[input_index]
                    all_input_signatures.extend(mergeable_input.signatures.items())

            output_script = Script(db_txo_row.script_bytes)
            output = XTxOutput(db_txo_row.value, output_script) # type: ignore[arg-type]
            input_context = TxInputContext(base_transaction, input_index, output,
                is_utxo_after_genesis(wallet, db_txo_row.block_hash))

            for public_key_bytes, signature_bytes in all_input_signatures:
                # NOTE(rt12) The script code we pass to the signature verification should be the
                #     portion that is being signed, which is `OP_CODESEPARATOR` related. Handling
                #     that complexity is outside the scope of this
                if input_context.check_sig(signature_bytes, public_key_bytes,
                        db_txo_row.script_bytes):
                    new_input_signatures[public_key_bytes] = signature_bytes
                    break

            transaction_input.signatures = new_input_signatures

    result: SignRawTransactionResultDict = {
        "hex": base_transaction.to_hex(),
        "complete": base_transaction.is_complete(),
    }
    if len(errors) > 0:
        result["errors"] = errors
    return result

async def jsonrpc_walletpassphrase_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    wallet = get_wallet_from_request(request, request_id, ensure_available=True)
    assert wallet is not None

    parameter_values = transform_parameters(request_id, [ "passphrase", "timeout" ], parameters)
    if len(parameter_values) != 2:
        # Node returns help. We do not. The user should see the documentation.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.INVALID_PARAMS,
                        message="Invalid parameters, see documentation for this call"))))

    wallet_password = parameter_values[0]
    if not isinstance(wallet_password, str):
        # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.PARSE_ERROR,
                        message="JSON value is not a string as expected"))))

    cache_duration = get_integer_parameter(request_id, parameter_values[1])

    if len(wallet_password) == 0:
        # The node maps the C++ exception on a non-integer value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.PARSE_ERROR,
                        message="Invalid parameters, see documentation for this call"))))

    try:
        wallet.check_password(wallet_password)
    except InvalidPassword:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=RPCError.WALLET_PASSPHRASE_INCORRECT,
                        message="Error: The wallet passphrase entered was incorrect"))))

    wallet_path = wallet.get_storage_path()
    app_state.credentials.set_wallet_password(
        wallet_path, wallet_password, CredentialPolicyFlag.FLUSH_AFTER_CUSTOM_DURATION,
        cache_duration)

    return None

