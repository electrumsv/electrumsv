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


def get_lockfile(config: SimpleConfig) -> str:
    return os.path.join(config.path, 'daemon')


def remove_lockfile(lockfile: str) -> None:
    logger.debug("removing lockfile")
    try:
        os.unlink(lockfile)
    except OSError:
        pass


def get_lockfile_fd(config: SimpleConfig) -> int | None:
    '''Tries to create the lockfile, using O_EXCL to
    prevent races.  If it succeeds it returns the FD.
    Otherwise try and connect to the server specified in the lockfile.
    If this succeeds, the server is returned.  Otherwise remove the
    lockfile and try again.'''
    lockfile = get_lockfile(config)
    while True:
        try:
            return os.open(lockfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except OSError:
            pass

        result = remote_daemon_request(config, "/v1/rpc/ping")
        if not isinstance(result, dict) or "error" not in result:
            # This is a valid response.
            return None
        # Couldn't connect; remove lockfile and try again.
        remove_lockfile(lockfile)


def remote_daemon_request(config: SimpleConfig, url: str, json_value: Any=None) -> Any:
    lockfile_path = get_lockfile(config)
    with open(lockfile_path) as f:
        text = f.read()
        if text == "":
            return { "error": "corrupt lockfile" }
        (host, port), _create_time = json.loads(text)
    assert not url.startswith("http") and host not in url
    full_url = f"http://{host}:{port}{url}"
    rpc_user, rpc_password = get_rpc_credentials(config, is_restapi=True)
    try:
        response = requests.post(full_url, json=json_value, auth=(rpc_user, rpc_password))
    except requests.exceptions.ConnectionError:
        return { "error": "Daemon not running" }
    return response.json()


def get_rpc_credentials(config: SimpleConfig, is_restapi: bool=False) -> tuple[str, str]:
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
    rpc_user = cast(str | None, config.get('rpcuser', None))
    api_password = cast(str | None, config.get('rpcpassword', None))
    if rpc_user is None or api_password is None:
        rpc_user = 'user'
        nbits = 128
        pw_int = random_integer(nbits)
        pw_b64 = base64.b64encode(
            pw_int.to_bytes(nbits // 8, 'big'), b'-_')
        api_password = pw_b64.decode('ascii')
        config.set_key('rpcuser', rpc_user)
        config.set_key('rpcpassword', api_password, save=True)
    elif api_password == '':
        which = "REST API" if is_restapi else "JSON-RPC API"
        logger.warning("No password set for %s. Access is therefore granted to any users.", which)
    return rpc_user, api_password


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

    def _init_nodeapi_server(self, config: SimpleConfig) -> None:
        host = config.get_explicit_type(str, "nodeapi_host", '127.0.0.1')
        if os.environ.get('NODEAPI_HOST'):
            host = cast(str, os.environ.get('NODEAPI_HOST'))

        port = int(cast(str | int, config.get('nodeapi_port', 8332)))
        if os.environ.get('NODEAPI_PORT'):
            port = int(cast(str, os.environ.get('NODEAPI_PORT')))

        username, password = get_rpc_credentials(config, is_restapi=False)
        self.nodeapi_server = NodeAPIServer(host=host, port=port, username=username,
            password=password)

    def _init_restapi_server(self, config: SimpleConfig, fd: int) -> None:
        host = config.get_explicit_type(str, "restapi_host", '127.0.0.1')
        if os.environ.get('RESTAPI_HOST'):
            host = cast(str, os.environ.get('RESTAPI_HOST'))

        port = int(cast(str | int, config.get('restapi_port', 9999)))
        if os.environ.get('RESTAPI_PORT'):
            port = int(cast(str, os.environ.get('RESTAPI_PORT')))

        username, password = get_rpc_credentials(config, is_restapi=True)
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

    async def run_daemon(self, config_options: dict[str, Any]) -> bool | str | dict[str, Any]:
        config = SimpleConfig(config_options)
        sub = config.get('subcommand')
        assert sub in [None, 'start', 'stop', 'status', 'load_wallet', 'close_wallet']
        response: bool | str | dict[str, Any]
        if sub in [None, 'start']:
            response = "Daemon already running"
        elif sub == 'load_wallet':
            cmdline_wallet_filepath = config.get_cmdline_wallet_filepath()
            assert cmdline_wallet_filepath is not None
            wallet_path = WalletStorage.canonical_path(cmdline_wallet_filepath)
            wallet_password = config_options.get('password')
            assert wallet_password is not None
            app_state.credentials.set_wallet_password(
                wallet_path, wallet_password, CredentialPolicyFlag.FLUSH_AFTER_WALLET_LOAD)
            wallet = self.load_wallet(wallet_path)
            if wallet is None:
                response = "Unable to load wallet"
            else:
                response = True
        elif sub == 'close_wallet':
            cmdline_wallet_filepath = config.get_cmdline_wallet_filepath()
            assert cmdline_wallet_filepath is not None
            path = WalletStorage.canonical_path(cmdline_wallet_filepath)
            if path in self.wallets:
                self.stop_wallet_at_path(path)
                response = True
            else:
                response = False
        elif sub == 'status':
            if self.network:
                response = self.network.status()
                response.update({
                    'fee_per_kb': self.config.fee_per_kb(),
                    'path': self.config.path,
                    'version': PACKAGE_VERSION,
                    'wallets': {k: w.is_synchronized() for k, w in self.wallets.items()},
                })
            else:
                response = "Daemon offline"
        elif sub == 'stop':
            self.stop()
            response = "Daemon stopped"
        else:
            response = False
        return response

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
            app_state.async_.spawn_and_wait(self.rest_server.stop())
        if self.nodeapi_server is not None:
            app_state.async_.spawn_and_wait(self.nodeapi_server.shutdown_async())
        self.logger.debug("stopped")

    def run(self) -> None:
        assert self.rest_server is not None
        assert not self.rest_server.is_running
        app_state.async_.spawn(self.rest_server.run_async())

        assert self.nodeapi_server is not None
        assert not self.nodeapi_server.is_running
        app_state.async_.spawn(self.nodeapi_server.run_async())

        self.wait_for_shutdown()

        logger.warning("no longer running")
        app_state.shutdown()
        if self.network:
            logger.warning("waiting for network shutdown")
            assert self.fx_task is not None, "fx task should be valid if network is"
            self.fx_task.cancel()
            app_state.async_.spawn_and_wait(self.network.shutdown_wait())
        app_state.on_stop()
        self.on_stop()

    def stop(self) -> None:
        logger.warning("stopping")
        super().stop()
        self.stop_wallets()
        remove_lockfile(get_lockfile(self.config))
