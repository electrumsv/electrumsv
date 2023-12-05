#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
import base64
import concurrent.futures
import json
from typing import Any, cast
import os
import time

from bitcoinx import be_bytes_to_int
import requests

from .app_state import app_state
from .commands import known_commands, Commands
from .constants import CredentialPolicyFlag, DaemonSubcommandLiteral, DaemonSubcommands, \
    DATABASE_EXT, NetworkServerFlag, SERVER_USES, ServerConnectionFlag, StorageKind
from .exchange_rate import FxTask
from .exceptions import InvalidPassword, ServerConnectionError
from .logs import logs
from .network import Network
from .network_support.api_server import get_viable_servers
from .network_support.exceptions import AuthenticationError, GeneralAPIError
from .nodeapi import NodeAPIServer
from .restapi import AiohttpServer
from .restapi_endpoints import DefaultEndpoints
from .simple_config import SimpleConfig
from .storage import categorise_file, WalletStorage
from .types import DaemonStatusDict
from .util import json_decode, DaemonThread, get_wallet_name_from_path
from .version import PACKAGE_VERSION
from .wallet import Wallet


logger = logs.get_logger("daemon")


def get_lockfile_path(config: SimpleConfig) -> str:
    return os.path.join(config.path, 'daemon')


def remove_lockfile(lockfile_path: str) -> None:
    logger.debug("Removing lockfile")
    try:
        os.unlink(lockfile_path)
    except OSError:
        pass


def get_lockfile_fd(config: SimpleConfig) -> int | None:
    """
    Tries to create the lockfile using O_EXCL to prevent races.  If it succeeds it returns the
    file descriptor. Otherwise it tries to connect to the server specified in the lockfile and if
    this succeeds, `None` is returned.  Otherwise, the lockfile is removed and we loop.
    """
    lockfile_path = get_lockfile_path(config)
    while True:
        try:
            return os.open(lockfile_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except OSError:
            pass

        result = remote_daemon_request(config, "/v1/rpc/ping")
        if not isinstance(result, dict) or "error" not in result:
            # This is a valid response.
            return None
        # Couldn't connect; remove lockfile and try again.
        remove_lockfile(lockfile_path)


def remote_daemon_request(config: SimpleConfig, url_path: str, json_value: Any=None) -> Any:
    lockfile_path = get_lockfile_path(config)
    if not os.path.exists(lockfile_path):
        return { "error": "Daemon not running" }

    with open(lockfile_path) as f:
        text = f.read()
        if text == "":
            return { "error": "corrupt lockfile" }
        (host, port), _create_time = json.loads(text)

    assert not url_path.startswith("http") and host not in url_path
    url = f"http://{host}:{port}{url_path}"
    # @RESTAPICredentials We expect the credentials to be persisted in the `config` file due to
    #     the workaround done in `get_api_credentials` when they are generated.
    restapi_credential = get_api_credentials(config)
    try:
        response = requests.post(url, json=json_value, auth=restapi_credential, timeout=10)
    except requests.exceptions.ConnectionError:
        return { "error": "Daemon not connectable" }
    except requests.exceptions.ReadTimeout:
        return { "error": "Daemon subcommand timed out" }
    if not response.ok:
        return { "error": f"Daemon errored processing the subcommand: '{response.reason}'" }
    return response.json()


def get_api_credentials(config: SimpleConfig) -> tuple[str, str]:
    """
    We share the credentials between the REST API and the node-compatible JSON-RPC API.
    To use the REST API the user should provide the `rpcpassword` as a bearer token, and does
    not need to provide `rpcuser`. The JSON-RPC API should only be used with basic auth and
    both `rpcuser` and `rpcpassword` values should be combined in the standard way.
    """
    global logger
    def random_integer(nbits: int) -> int:
        nbytes = (nbits + 7) // 8
        return cast(int, be_bytes_to_int(os.urandom(nbytes)) % (1 << nbits))

    # TODO(deprecation) @DeprecateRESTBasicAuth
    username_value = cast(str | None, config.get("restapi_username", None))
    password_value = cast(str | None, config.get("restapi_password", None))
    if username_value is None or password_value is None:
        username_value = 'user'

        nbits = 128
        pw_int = random_integer(nbits)
        pw_b64 = base64.b64encode(
            pw_int.to_bytes(nbits // 8, 'big'), b'-_')
        password_value = pw_b64.decode('ascii')

        # The only time we ever persist credentials is where we generate them and the user
        # will want to pick them out of the config.
        config._set_key_in_user_config("restapi_username", username_value)
        config._set_key_in_user_config("restapi_password", password_value, save=True)
    elif password_value == "":
        logger.warning("No password set for REST API. No credentials required for access.")
    return username_value, password_value


class Daemon(DaemonThread):
    # Note that the dynamic app_state object does not propagate typing information, so application
    # logic will need to cast to ensure correct type checking.
    #
    #   e.g. network = cast(Network, app_state.daemon.network)

    network: Network | None = None
    fx_task: concurrent.futures.Future[None] | None = None
    rest_server: AiohttpServer | None = None
    nodeapi_server: NodeAPIServer | None = None
    cmd_runner: Commands

    def __init__(self, fd: int, is_gui: bool) -> None:
        super().__init__('daemon')

        self.is_gui = is_gui
        self.wallets: dict[str, Wallet] = {}

        app_state.daemon = self
        app_state.read_headers()

        config = app_state.config
        self.config: SimpleConfig = config
        if not config.get('offline'):
            self.network = Network()

            app_state.fx = FxTask(app_state.config, self.network)
            self.fx_task = app_state.async_.spawn(app_state.fx.refresh_loop())

        # self.init_thread_watcher()

        self._init_nodeapi_server(config)
        self._init_restapi_server(config, fd)

    # @NodeWalletAPI
    def _init_nodeapi_server(self, config: SimpleConfig) -> None:
        # The operator has to explicitly enable this API by providing the required command-line
        # argument `--enable-node-wallet-api`. This flag will be fetched from the non-persisted
        # command-line options.
        if not config.get_explicit_type(bool, "enable_nodeapi", False):
            return

        host = cast(str, os.environ.get("NODEAPI_HOST")) if os.environ.get("NODEAPI_HOST") \
            else config.get_explicit_type(str, "nodeapi_host", "127.0.0.1")
        port = int(cast(str, os.environ.get('NODEAPI_PORT'))) if os.environ.get('NODEAPI_PORT') \
            else int(cast(str | int, config.get("nodeapi_port", 8332)))

        # TODO(deprecation) @DeprecateRESTBasicAuth
        username_value = cast(str | None, config.get("nodeapi_username", None))
        password_value = cast(str | None, config.get("nodeapi_password", None))
        # If the password is given and given as empty, then we do not check credentials.
        if password_value == "":
            logger.warning("No password set for JSON-RPC wallet API. "
                "No credentials required for access.")
        elif username_value is None or password_value is None:
            logger.error("JSON-RPC wallet API server not running: invalid user name or password")
            return

        self.nodeapi_server = NodeAPIServer(host=host, port=port, username=username_value,
            password=password_value)

    def _init_restapi_server(self, config: SimpleConfig, fd: int) -> None:
        host = cast(str, os.environ.get("RESTAPI_HOST")) if os.environ.get("RESTAPI_HOST") \
            else config.get_explicit_type(str, "restapi_host", "127.0.0.1")
        port = int(cast(str, os.environ.get("RESTAPI_PORT"))) if os.environ.get("RESTAPI_PORT") \
            else int(cast(str | int, config.get("restapi_port", 9999)))

        username, password = get_api_credentials(config)
        self.rest_server = AiohttpServer(host=host, port=port, username=username,
            password=password)

        # The daemon functionality is accessible via the REST API.
        # The old JSON-RPC used to require the daemon server to be up at least one second before
        # accepting it. We keep the timestamp for diagnostic purposes, if we have to get a user
        # to look at a lockfile.
        lockfile_text = json.dumps([ [host, port], time.time() ])
        os.write(fd, lockfile_text.encode())
        os.close(fd)

        self.default_rest_api = DefaultEndpoints()
        self.rest_server.add_routes(self.default_rest_api.routes)

    def init_thread_watcher(self) -> None:
        import threading
        import sys
        import traceback

        def _watcher() -> None:
            while True:
                print("---- ---- ---- ----")
                for i, th in enumerate(threading.enumerate()):
                    # th_text = str(th)
                    # if "GUI" not in th_text:
                    #     continue
                    print(f"---- {i}: {th}")
                    # NOTE(typing) Optional debugging code, not too invested in the typing error.
                    traceback.print_stack(sys._current_frames()[th.ident]) # type: ignore
                    print()
                time.sleep(5.0)

        t = threading.Thread(target=_watcher)
        t.setDaemon(True)
        t.start()

    def ping(self) -> bool:
        return True

    async def run_subcommand_async(self, config_options: dict[str, Any]) \
            -> bool | str | DaemonStatusDict:
        """
        When ElectrumSV is running it is implicitly a wallet server and can be controlled from
        the command-line using what we call daemon subcommands.

        We run the wallet server with either the gui::

            > ./electrum-sv
            ... The application continues running.

        Or we run the wallet server headlessly::

            > ./electrum-sv daemon
            ... The application continues running.

        Now in another console the user can run subcommands and direct the wallet server
        to do things without having to use the REST API.

        Load a wallet::

            | > ./electrum-sv daemon load_wallet
            -w .electrum-sv/INSTANCE1/regtest/wallets/testwallet.sqlite
            | Password:
            | true

        In the above case the command connected to the wallet server, invoked this function and
        the returned `True` was printed out to the user encoded as JSON (which explains why we
        see `true` not `True`).

        Query the wallet server status::

            $ ./electrum-sv daemon status
            {
                "blockchain_height": 0,
                "fee_per_kb": 500,
                "path": "INSTANCE1/regtest",
                "version": "1.4.0",
                "wallets": {
                    ".electrum-sv/INSTANCE1/regtest/wallets/testwallet.sqlite": true
                }
            }
        """
        config = SimpleConfig(config_options)
        subcommand = cast(DaemonSubcommandLiteral | None, config.get('subcommand'))
        assert subcommand is None or subcommand in DaemonSubcommands

        if subcommand in [None, "start"]:
            return "Daemon already running."

        if subcommand == "load_wallet":
            command_line_wallet_path = cast(str|None, config.get("wallet_path"))
            if command_line_wallet_path is None:
                return "Error: Wallet file required. " \
                    "Use -w <filename> to specify a wallet filename."

            wallet_path = config.resolve_existing_wallet_path(command_line_wallet_path)
            if wallet_path is None:
                return f"Error: Wallet file not found: '{command_line_wallet_path}'."

            if self.get_wallet(wallet_path):
                return f"Wallet '{command_line_wallet_path}' already loaded."

            wallet_path = WalletStorage.canonical_path(wallet_path)
            wallet_password = config_options.get('password')
            assert wallet_password is not None
            app_state.credentials.set_wallet_password(
                wallet_path, wallet_password, CredentialPolicyFlag.FLUSH_AFTER_WALLET_LOAD)
            wallet = self.load_wallet(wallet_path)
            if wallet is None:
                return f"Error: Unable to load wallet '{command_line_wallet_path}'."

            logger.info("Loaded wallet '%s'", wallet_path)
            return True

        if subcommand == "unload_wallet":
            command_line_wallet_path = cast(str|None, config.get("wallet_path"))
            assert command_line_wallet_path is not None
            wallet_path = config.resolve_existing_wallet_path(command_line_wallet_path)
            if wallet_path is None:
                return f"Error: Wallet file not found: '{command_line_wallet_path}'."

            wallet_path = WalletStorage.canonical_path(wallet_path)
            assert os.path.isabs(wallet_path)
            if wallet_path in self.wallets:
                # This is running in the async thread. If we do a blocking stop function that
                # needs to do async cleanup we are going to deadlock. Run the stop function in a
                # thread so we can yield the scheduler to handle the cleanup work.
                await asyncio.to_thread(self.stop_wallet_at_path, wallet_path)
                logger.info("Unloaded wallet '%s'", wallet_path)
                return True

            return False

        if subcommand == "service_signup":
            command_line_wallet_path = cast(str|None, config.get("wallet_path"))
            if command_line_wallet_path is None:
                return "Error: Wallet file required. " \
                    "Use -w <filename> to specify a wallet filename."

            wallet_path = config.resolve_existing_wallet_path(command_line_wallet_path)
            if wallet_path is None:
                return f"Error: Wallet file not found: '{command_line_wallet_path}'."

            wallet = self.get_wallet(wallet_path)
            if wallet is None:
                return f"Error: Wallet '{command_line_wallet_path}' not loaded. " \
                    "Use the 'load_wallet' daemon subcommand to load a wallet."

            wallet_password = config_options.get('password')
            assert wallet_password is not None
            password, password_policy_flag = app_state.credentials.get_wallet_password_and_policy(
                wallet_path)
            if password is None:
                app_state.credentials.set_wallet_password(
                    wallet_path, wallet_password, CredentialPolicyFlag.FLUSH_AFTER_CUSTOM_DURATION,
                    10.0)

            # Strictly speaking we should not be using servers already
            usage_flags = NetworkServerFlag.USE_BLOCKCHAIN | NetworkServerFlag.USE_MESSAGE_BOX
            for _server, server_flags in wallet.get_wallet_servers():
                for usage_flag in SERVER_USES:
                    if server_flags & usage_flag != 0:
                        usage_flags &= ~usage_flag

            if 0 == usage_flags:
                return "All services appear to be signed up for."

            message_lines: list[str] = [
                "Registering..",
                "  For services:",
            ]
            if usage_flags & NetworkServerFlag.USE_BLOCKCHAIN:
                message_lines.append("    Blockchain.")
            if usage_flags & NetworkServerFlag.USE_MESSAGE_BOX:
                message_lines.append("    Message box.")

            # This should only find one server for all usage flags, on regtest the reference
            # server with simple indexer, and on mainnet the BA reference server with indexer
            # behind it.
            servers_by_usage_flag = wallet.get_unused_reference_servers(usage_flags)
            servers = get_viable_servers(servers_by_usage_flag, usage_flags)
            if len(servers) == 0:
                message_lines.append("Error: No available servers.")
            elif len(servers) == 1:
                server, server_flags = servers[0]
                message_lines.extend([
                    "  With server:",
                    "    "+ server.url,
                ])

                try:
                    await wallet.create_server_account_async(server, server_flags)
                except InvalidPassword:
                    message_lines.append("Error: Wallet password incorrect during server "
                        "account creation.")
                except AuthenticationError as authentication_error:
                    logger.error("Unexpected server authentication error", exc_info=True)
                    message_lines.append(
                        f"Error: Server authentication failed '{authentication_error}'")
                except GeneralAPIError as api_error:
                    logger.error("Unexpected server API error", exc_info=True)
                    message_lines.append(
                        f"Error: Server communication error '{api_error}'")
                except ServerConnectionError as connection_error:
                    logger.error("Unexpected server connection error", exc_info=True)
                    message_lines.append(
                        f"Error: Server connection failed '{connection_error}'")
                else:
                    # Starting the connection continues in an async task and does not block this
                    # call (at least not for the actual connecting part).
                    state = await wallet.start_reference_server_connection_async(server,
                        server_flags)
                    while state.connection_flags & ServerConnectionFlag.MASK_EXIT == 0:
                        if state.connection_flags & ServerConnectionFlag.WEB_SOCKET_READY != 0:
                            # The connection was established successfully.
                            break
                        await state.stage_change_event.wait()

                    message_lines.append("Done.")
            else:
                message_lines.append("Error: Detected inconsistency with available servers.")
                for server, server_flag in servers:
                    message_lines.append("  - "+ server.url)

            return os.linesep.join(message_lines)

        if subcommand == "status":
            status_object: DaemonStatusDict = {
                "network": "offline",
                "path": self.config.path,
                "version": PACKAGE_VERSION,
                "wallets": { k: w.status() for k, w in self.wallets.items() },
            }

            if self.network is not None:
                network_status = self.network.status()
                status_object["network"] = "online"
                status_object["blockchain_height"] = network_status["blockchain_height"]

            return status_object

        if subcommand == 'stop':
            # This is running in the async thread. If we do a blocking stop function that
            # needs to do async cleanup we are going to deadlock. Run the stop function in a
            # thread so we can yield the scheduler to handle the cleanup work.
            await asyncio.to_thread(self.stop)
            return "Daemon stopped."

        return False

    async def run_gui(self, config_options: dict[str, Any]) -> str:
        assert app_state.app is not None

        config = SimpleConfig(config_options)
        if hasattr(app_state, 'windows'):
            path = config.get_commandline_wallet_path()
            app_state.app.new_window(path, config.get('url'))
            return "ok"

        return "Error: ElectrumSV is running in daemon mode; stop the daemon first."

    def load_wallet(self, wallet_filepath: str) -> Wallet | None:
        wallet_categorisation = categorise_file(wallet_filepath)
        if wallet_categorisation.kind == StorageKind.DATABASE:
            wallet_filepath = wallet_categorisation.wallet_filepath + DATABASE_EXT
        elif wallet_categorisation.kind != StorageKind.FILE:
            return None

        assert os.path.isabs(wallet_filepath), wallet_filepath
        if wallet_filepath in self.wallets:
            return self.wallets[wallet_filepath]

        storage = WalletStorage(wallet_filepath)
        if storage.requires_split():
            storage.close()
            logger.debug("Wallet '%s' requires an split", wallet_filepath)
            return None
        if storage.requires_upgrade():
            storage.close()
            logger.debug("Wallet '%s' requires an upgrade", wallet_filepath)
            return None

        wallet_password = app_state.credentials.get_wallet_password(
            wallet_filepath)
        if wallet_password is None:
            logger.debug("Wallet '%s' password is not cached", wallet_filepath)
            return None
        if not storage.is_password_valid(wallet_password):
            logger.debug("Wallet '%s' password does not match", wallet_filepath)
            return None

        wallet = Wallet(storage)
        self.start_wallet(wallet)
        return wallet

    def get_wallet(self, path: str) -> Wallet | None:
        wallet_filepath = WalletStorage.canonical_path(path)
        assert os.path.isabs(wallet_filepath), wallet_filepath
        return self.wallets.get(wallet_filepath)

    def get_wallet_by_id(self, wallet_id: int) -> Wallet | None:
        for wallet in self.wallets.values():
            if wallet.get_id() == wallet_id:
                return wallet
        return None

    def start_wallet(self, wallet: Wallet) -> None:
        # We expect the storage path to be exact, including the database extension. So it should
        # match the canonical path used elsewhere.
        wallet_filepath = wallet.get_storage_path()
        assert os.path.isabs(wallet_filepath), wallet_filepath
        self.wallets[wallet_filepath] = wallet
        wallet.start(self.network)

    def stop_wallet_at_path(self, path: str) -> None:
        wallet_filepath = WalletStorage.canonical_path(path)
        assert os.path.isabs(wallet_filepath), wallet_filepath
        # Issue #659 wallet may already be stopped.
        if wallet_filepath in self.wallets:
            wallet = self.wallets.pop(wallet_filepath)
            wallet.stop()

    def stop_wallets(self) -> None:
        for path in list(self.wallets):
            self.stop_wallet_at_path(path)

    async def run_command_line_async(self, config_options: dict[str, Any]) -> Any:
        """
        Another ElectrumSV instance has performed a "daemon subcommand" and we are receiving the
        state to act on, including which command and whatever other command-line arguments were
        given, within `config_options`.
        """
        config = SimpleConfig(config_options)
        cmdname = cast(str, config.get('cmd'))
        cmd = known_commands[cmdname]
        if cmd.requires_wallet:
            # This should get the path given by the user to the external instance. This comes from
            # the passes `config_options` which include the external `cwd` and `wallet_path` values.
            cmdline_wallet_filepath = config.get_commandline_wallet_path()
            assert cmdline_wallet_filepath is not None
            wallet_path = WalletStorage.canonical_path(cmdline_wallet_filepath)
            assert os.path.isabs(wallet_path)
            wallet = self.wallets.get(wallet_path)
            if wallet is None:
                return {
                    "error": f"Wallet '{get_wallet_name_from_path(wallet_path)}' is not loaded" }
        else:
            wallet = None

        # arguments passed to function
        args = [cast(str, config.get(x)) for x in cmd.params]
        # decode json arguments
        args = [json_decode(i) for i in args]
        # options
        kwargs = {}
        for x in cmd.options:
            kwargs[x] = (config_options.get(x) if x in ['password', 'new_password']
                         else config.get(x))
        # TODO(async) This should be async, but the Commands object is used for things like
        #   the console.
        cmd_runner = Commands(config, wallet, self.network)
        func = getattr(cmd_runner, cmd.name)
        result = await func(*args, **kwargs)
        return result

    def on_stop(self) -> None:
        if self.rest_server and self.rest_server.is_running:
            logger.info("Waiting for REST API shutdown")
            app_state.async_.spawn_and_wait(self.rest_server.stop())
        if self.nodeapi_server is not None:
            logger.info("Waiting for JSON-RPC API shutdown")
            app_state.async_.spawn_and_wait(self.nodeapi_server.shutdown_async())
        self.logger.info("Stopped")

    def run(self) -> None:
        assert self.rest_server is not None
        assert not self.rest_server.is_running
        app_state.async_.spawn(self.rest_server.run_async())

        if self.nodeapi_server is not None:
            assert not self.nodeapi_server.is_running
            app_state.async_.spawn(self.nodeapi_server.run_async())

        self.wait_for_shutdown()

        app_state.shutdown()
        if self.network is not None:
            logger.info("Waiting for network shutdown")
            assert self.fx_task is not None, "fx task should be valid if network is"
            self.fx_task.cancel()
            app_state.async_.spawn_and_wait(self.network.shutdown_wait())
        else:
            logger.info("No longer running")
        app_state.on_stop()
        self.on_stop()

    def stop(self) -> None:
        logger.info("Stopping")
        super().stop()
        self.stop_wallets()
        remove_lockfile(get_lockfile_path(self.config))
