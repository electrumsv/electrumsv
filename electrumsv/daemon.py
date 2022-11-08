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
from .constants import CredentialPolicyFlag, DATABASE_EXT, StorageKind
from .exchange_rate import FxTask
from .logs import logs
from .network import Network
from .nodeapi import NodeAPIServer
from .restapi import AiohttpServer
from .restapi_endpoints import DefaultEndpoints
from .simple_config import SimpleConfig
from .storage import categorise_file, WalletStorage
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
                for th in threading.enumerate():
                    th_text = str(th)
                    # if "GUI" not in th_text:
                    #     continue
                    print(th)
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
            -> bool | str | dict[str, Any]:
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
                "spv_nodes": 1,
                "version": "1.4.0b1",
                "wallets": {
                    ".electrum-sv/INSTANCE1/regtest/wallets/testwallet.sqlite": true
                }
            }
        """
        config = SimpleConfig(config_options)
        subcommand = cast(str | None, config.get('subcommand'))
        assert subcommand in [None, 'start', 'stop', 'status', 'load_wallet', 'close_wallet']
        if subcommand in [None, 'start']:
            return "Daemon already running"
        elif subcommand == "load_wallet":
            cmdline_wallet_filepath = config.get_cmdline_wallet_filepath()
            assert cmdline_wallet_filepath is not None
            wallet_path = WalletStorage.canonical_path(cmdline_wallet_filepath)
            wallet_password = config_options.get('password')
            assert wallet_password is not None
            app_state.credentials.set_wallet_password(
                wallet_path, wallet_password, CredentialPolicyFlag.FLUSH_AFTER_WALLET_LOAD)
            wallet = self.load_wallet(wallet_path)
            if wallet is None:
                return "Unable to load wallet"
            return True
        elif subcommand == "close_wallet":
            cmdline_wallet_filepath = config.get_cmdline_wallet_filepath()
            assert cmdline_wallet_filepath is not None
            path = WalletStorage.canonical_path(cmdline_wallet_filepath)
            if path in self.wallets:
                self.stop_wallet_at_path(path)
                return True
            return False
        elif subcommand == 'status':
            if self.network:
                status_object = self.network.status()
                status_object.update({
                    'fee_per_kb': self.config.fee_per_kb(),
                    'path': self.config.path,
                    'version': PACKAGE_VERSION,
                    'wallets': {k: w.is_synchronized() for k, w in self.wallets.items()},
                })
                return status_object
            return "Daemon offline"
        elif subcommand == 'stop':
            # This is running in the async thread. If we do a blocking stop function that
            # needs to do async cleanup we are going to deadlock. Run the stop function in a
            # thread so we can yield the scheduler to handle the cleanup work.
            await asyncio.to_thread(self.stop)
            return "Daemon stopped"
        return False

    async def run_gui(self, config_options: dict[str, Any]) -> str:
        assert app_state.app is not None

        config = SimpleConfig(config_options)
        if hasattr(app_state, 'windows'):
            path = config.get_cmdline_wallet_filepath()
            app_state.app.new_window(path, config.get('url'))
            return "ok"

        return "error: ElectrumSV is running in daemon mode; stop the daemon first."

    def load_wallet(self, wallet_filepath: str) -> Wallet | None:
        wallet_categorisation = categorise_file(wallet_filepath)
        if wallet_categorisation.kind == StorageKind.DATABASE:
            wallet_filepath = wallet_categorisation.wallet_filepath + DATABASE_EXT
        elif wallet_categorisation.kind != StorageKind.FILE:
            return None

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
        return self.wallets.get(wallet_filepath)

    def get_wallet_by_id(self, wallet_id: int) -> Wallet | None:
        for wallet in self.wallets.values():
            if wallet.get_id() == wallet_id:
                return wallet
        return None

    def start_wallet(self, wallet: Wallet) -> None:
        # We expect the storage path to be exact, including the database extension. So it should
        # match the canonical path used elsewhere.
        self.wallets[wallet.get_storage_path()] = wallet
        wallet.start(self.network)

    def stop_wallet_at_path(self, path: str) -> None:
        wallet_filepath = WalletStorage.canonical_path(path)
        # Issue #659 wallet may already be stopped.
        if wallet_filepath in self.wallets:
            wallet = self.wallets.pop(wallet_filepath)
            wallet.stop()

    def stop_wallets(self) -> None:
        for path in list(self.wallets):
            self.stop_wallet_at_path(path)

    async def run_cmdline(self, config_options: dict[str, Any]) -> Any:
        config = SimpleConfig(config_options)
        cmdname = cast(str, config.get('cmd'))
        cmd = known_commands[cmdname]
        if cmd.requires_wallet:
            cmdline_wallet_filepath = config.get_cmdline_wallet_filepath()
            assert cmdline_wallet_filepath is not None
            wallet_path = WalletStorage.canonical_path(cmdline_wallet_filepath)
            wallet = self.wallets.get(wallet_path)
            if wallet is None:
                return {'error': 'Wallet "%s" is not loaded. Use "electrum-sv daemon load_wallet"'
                        % get_wallet_name_from_path(wallet_path)}
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
