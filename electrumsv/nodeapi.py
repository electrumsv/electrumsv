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
import json
import os
import re
import subprocess
import threading
import time
from types import NoneType
from typing import Any, Awaitable, Callable, cast, TYPE_CHECKING, TypedDict

from aiohttp import web
# NOTE(typing) `cors_middleware` is not explicitly exported, so mypy strict fails. No idea.
from aiohttp_middlewares import cors_middleware # type: ignore
from bitcoinx import Address, hash_to_hex_str, Script

from .app_state import app_state
from .bitcoin import script_template_to_string
from .constants import CredentialPolicyFlag, NetworkServerFlag, PaymentFlag, TransactionImportFlag
from .exceptions import InvalidPassword
from .logs import logs
from .networks import Net
from .transaction import classify_transaction_output_script, XTxOutput
from .util import constant_time_compare

if TYPE_CHECKING:
    from .wallet import Wallet

HandlerType = Callable[[web.Request], Awaitable[web.StreamResponse]]


logger = logs.get_logger("nodeapi")

# We use typed dictionaries inline rather than layering functions to abstract this in order to try
# to make the code easier to read.

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


INVALID_REQUEST   = -32600              # Use the bad request (400) status code.
METHOD_NOT_FOUND  = -32601              # Use the not found (404) status code.
INVALID_PARAMS    = -32602              # Internal server error (500) status code.
PARSE_ERROR       = -32700              # Internal server error (500) status code.

TYPE_ERROR                      = -3    # Internal server error (500) status code.
WALLET_ERROR                    = -4    # Internal server error (500) status code.
INVALID_ADDRESS_OR_KEY          = -5    # Internal server error (500) status code.
INVALID_PARAMETER               = -8    # Internal server error (500) status code.
WALLET_KEYPOOL_RAN_OUT          = -12   # Internal server error (500) status code.
WALLET_UNLOCK_NEEDED            = -13   # Internal server error (500) status code.
WALLET_PASSPHRASE_INCORRECT     = -14   # Internal server error (500) status code.
WALLET_NOT_FOUND                = -18   # Internal server error (500) status code.
WALLET_NOT_SPECIFIED            = -19   # Internal server error (500) status code.

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
        self._logger.debug("started on http://%s:%s", self._host, self._port)
        self.startup_event.set()
        await self.shutdown_event.wait()

    async def shutdown_async(self) -> None:
        assert self._runner is not None
        await self._runner.cleanup()

    def event_transaction_added(self, transaction_hash: bytes) -> None:
        """
        Called by `Wallet._import_transaction_async` as an explicit JSON-RPC API hook.

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
                    error=ErrorDict(code=PARSE_ERROR, message="Parse error"))))

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
                error=ErrorDict(code=PARSE_ERROR, message="Top-level object parse error"))))


async def execute_jsonrpc_call_async(request: web.Request, object_data: Any) \
        -> tuple[RequestIdType, Any]:
    """
    This should only raise `aiohttp` web exceptions which should not need to be caught:
    - HTTPBadRequest
    """
    if not isinstance(object_data, dict):
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=None, result=None,
                error=ErrorDict(code=INVALID_REQUEST,
                    message="Invalid Request object"))))

    raw_request_id = object_data.get("id")
    if not isinstance(raw_request_id, int | str | NoneType):
        # The node does not enforce typing for `id` in `JSONRPCRequest::parse` and returns
        # whatever it is passed. We enforce that `id` has to be a simple type because it
        # seems like a reasonable middle ground.
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=None, result=None,
                error=ErrorDict(code=INVALID_REQUEST,
                    message="Id must be int, string or null"))))
    request_id = cast(RequestIdType, raw_request_id)

    method_name = object_data.get("method", ...)
    if method_name is ...:
        # Node `JSONRPCRequest::parse` error case.
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=INVALID_REQUEST, message="Missing method"))))
    elif type(method_name) is not str:
        # Node `JSONRPCRequest::parse` error case.
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=INVALID_REQUEST, message="Method must be a string"))))

    params = object_data.get("params")
    if params is None:
        params = []
    elif not isinstance(params, (dict, list)):
        # Node `JSONRPCRequest::parse` error case.
        raise web.HTTPBadRequest(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=INVALID_REQUEST,
                    message="Params must be an array or object"))))

    # These calls are intentionally explicitly dispatched inline so that we avoid any
    # unforeseen dynamic dispatching problems and also it means you can be more likely to be
    # able to just read the code and understand it without layers of abstraction.
    if method_name == "getnewaddress":
        return request_id, await jsonrpc_getnewaddress_async(request, request_id, params)
    elif method_name == "sendtoaddress":
        return request_id, await jsonrpc_sendtoaddress_async(request, request_id, params)
    elif method_name == "sendmany":
        return request_id, await jsonrpc_sendmany_async(request, request_id, params)
    elif method_name == "walletpassphrase":
        return request_id, await jsonrpc_walletpassphrase_async(request, request_id, params)

    raise web.HTTPNotFound(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=METHOD_NOT_FOUND, message="Method not found"))))


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
                            error=ErrorDict(code=METHOD_NOT_FOUND,
                                message="Method not found (wallet method is disabled because "
                                    "no wallet is loaded"))))

            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                    text=json.dumps(ResponseDict(id=request_id, result=None,
                        error=ErrorDict(code=WALLET_NOT_SPECIFIED,
                            message="Wallet file not specified (must request wallet RPC "
                                "through /wallet/<filename> uri-path)"))))

        return None

    try:
        wallet_folder_path = app_state.config.get_preferred_wallet_dirpath()
    except FileNotFoundError:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=WALLET_NOT_FOUND,
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
                    error=ErrorDict(code=WALLET_NOT_FOUND,
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
                    error=ErrorDict(code=INVALID_PARAMETER,
                        message=f"Unknown named parameter {disallowed_names[0]}"))))

    return parameter_values

def get_string_parameter(request_id: RequestIdType, parameter_value: Any) -> str:
    if not isinstance(parameter_value, str):
        # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=PARSE_ERROR,
                    message="JSON value is not a string as expected"))))
    return parameter_value

def get_amount_parameter(request_id: RequestIdType, parameter_value: Any) -> int:
    """
    Convert the parameter to satoshis if possible.
    """
    if not isinstance(parameter_value, (int, float, str)):
        # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=TYPE_ERROR,
                    message="Amount is not a number or string"))))

    amount_coins: Decimal
    if isinstance(parameter_value, int):
        amount_coins = Decimal(parameter_value)
    elif isinstance(parameter_value, str):
        if re.match(r"(\d+)?(\.\d+)?$", parameter_value) is None:
            # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
            raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=TYPE_ERROR,
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
                error=ErrorDict(code=TYPE_ERROR,
                    message="Amount out of range"))))
    return amount_satoshis

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
                error=ErrorDict(code=WALLET_ERROR, message="No connected tip filter server"))))

    # Similarly the user must only have one account (and we will ignore any
    # automatically created petty cash accounts which we do not use yet).
    accounts = wallet.get_visible_accounts()
    if len(accounts) != 1:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))
    account = accounts[0]

    # By not setting an actual value for the amount the code that would otherwise close the
    # payment request when the expected value to be received is met, ignores the payment for
    # this payment request. See @BlindPaymentRequests.
    date_expires = int(time.time()) + 24 * 60 * 60
    request_row, request_output_rows = await account.create_payment_request_async(None,
        None, merchant_reference=None, date_expires=date_expires, flags=PaymentFlag.MONITORED)
    assert request_row.paymentrequest_id is not None

    job_data = await account.monitor_blockchain_payment_async(request_row.paymentrequest_id)
    if job_data is None:
        # If we did not check for this case above before we created the payment request we
        # would probably clean up here. But the chance of this happening is so slight and
        # the unmonitored and never returned payment request should expire.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=WALLET_ERROR, message="No connected tip filter server"))))

    # We do not want to continue until the tip filter registration is successfully placed with
    # the blockchain server.
    await job_data.completed_event.wait()

    if job_data.date_registered is None:
        # The failure reason is the stringified text for the exception encountered. The details
        # are also present in the logs. It should be a relayed error from the blockchain server.
        assert job_data.failure_reason is not None
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=WALLET_ERROR, message=job_data.failure_reason))))

    # Strictly speaking we return the address of whatever this is. It is almost guaranteed to be
    # a base58 encoded P2PKH address that we return.
    output_script = Script(request_output_rows[0].output_script_bytes)
    script_type, threshold, script_template = classify_transaction_output_script(
        output_script)
    return script_template_to_string(script_template)

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
                error=ErrorDict(code=WALLET_ERROR,
                    message=f"Ambiguous account (found {len(accounts)}, expected 1)"))))
    account = accounts[0]

    wallet_password = app_state.credentials.get_wallet_password(wallet.get_storage_path())
    if wallet_password is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=WALLET_UNLOCK_NEEDED,
                    message="Error: Please enter the wallet passphrase with " \
                        "walletpassphrase first."))))

    peer_channel_server_state = wallet.get_connection_state_for_usage(
        NetworkServerFlag.USE_MESSAGE_BOX)
    if peer_channel_server_state is None:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=WALLET_ERROR,
                    message="No configured peer channel server"))))

    parameter_values = transform_parameters(request_id, [ "address", "amount", "comment",
        "commentto", "subtractfeefromamount" ], parameters)
    if len(parameter_values) < 2 or len(parameter_values) > 5:
        # Node returns help. We do not. The user should see the documentation.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=INVALID_PARAMS,
                    message="Invalid parameters, see documentation for this call"))))

    address_text = get_string_parameter(request_id, parameter_values[0])
    try:
        address = Address.from_string(address_text, Net.COIN)
    except ValueError:
        # The node maps the C++ exception on a non-integer value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=INVALID_ADDRESS_OR_KEY,
                    message="Invalid address"))))

    amount_satoshis = get_amount_parameter(request_id, parameter_values[1])
    if amount_satoshis < 1:
        # The node maps the C++ exception on a non-integer value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
            text=json.dumps(ResponseDict(id=request_id, result=None,
                error=ErrorDict(code=TYPE_ERROR, message="Invalid amount for send"))))

    comment_sections: list[str] = []
    if len(parameter_values) >= 4 and isinstance(parameter_values[3], str):
        comment_sections.append(parameter_values[3])
    if len(parameter_values) >= 3 and isinstance(parameter_values[2], str):
        comment_sections.append(parameter_values[2])

    comment_text: str | None = None
    if len(comment_sections) > 0:
        comment_text = ": ".join(comment_sections)

    coins = account.get_transaction_outputs_with_key_data()
    assert len(coins) > 1
    outputs = [ XTxOutput(-1, address.to_script()) ] # type: ignore[arg-type]

    # TODO MAPI fee estimator (ensure it is involved and no mapi estimates an error).

    transaction, transaction_context = account.make_unsigned_transaction(coins, outputs)
    if comment_text is not None:
        transaction_context.account_descriptions[account.get_id()] = comment_text
    future = account.sign_transaction(transaction, wallet_password, context=transaction_context,
        import_flags=TransactionImportFlag.UNSET)
    assert future is not None
    await asyncio.wrap_future(future)

    # The only mechanism we have to know if the transaction ends up in a block is the peer
    # channel registration.
    # TODO we will get a merkle proof for the payments we send but not the ones we receive?
    # TODO we will get the merkle proof for the payments we recieve ...
    broadcast_result = await wallet.broadcast_transaction_async(transaction, transaction_context)
    mapi_result = broadcast_result.mapi
    assert mapi_result is not None

    # ...

    # At this point the transaction should be signed.

    transaction_id = transaction.txid()
    assert transaction_id is not None
    return transaction_id

async def jsonrpc_sendmany_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    # wallet = get_wallet_from_request(request, request_id)
    return "jsonrpc_sendmany_async"

async def jsonrpc_walletpassphrase_async(request: web.Request, request_id: RequestIdType,
        parameters: RequestParametersType) -> Any:
    wallet = get_wallet_from_request(request, request_id, ensure_available=True)
    assert wallet is not None

    parameter_values = transform_parameters(request_id, [ "passphrase", "timeout" ], parameters)
    if len(parameter_values) != 2:
        # Node returns help. We do not. The user should see the documentation.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=INVALID_PARAMS,
                        message="Invalid parameters, see documentation for this call"))))

    wallet_password = parameter_values[0]
    if not isinstance(wallet_password, str):
        # The node maps the C++ exception on a non-string value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=PARSE_ERROR,
                        message="JSON value is not a string as expected"))))

    cache_duration = parameter_values[1]
    if not isinstance(cache_duration, int):
        # The node maps the C++ exception on a non-integer value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=PARSE_ERROR,
                        message="JSON value is not an integer as expected"))))

    if len(wallet_password) == 0:
        # The node maps the C++ exception on a non-integer value to an RPC_PARSE_ERROR.
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=PARSE_ERROR,
                        message="Invalid parameters, see documentation for this call"))))

    try:
        wallet.check_password(wallet_password)
    except InvalidPassword:
        raise web.HTTPInternalServerError(headers={ "Content-Type": "application/json" },
                text=json.dumps(ResponseDict(id=request_id, result=None,
                    error=ErrorDict(code=WALLET_PASSPHRASE_INCORRECT,
                        message="Error: The wallet passphrase entered was incorrect"))))

    wallet_path = wallet.get_storage_path()
    app_state.credentials.set_wallet_password(
        wallet_path, wallet_password, CredentialPolicyFlag.FLUSH_AFTER_CUSTOM_DURATION,
        cache_duration)

    return None

