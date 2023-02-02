# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2018-2021 The ElectrumSV Developers
#
# Electrum Cash - lightweight Bitcoin Cash client
# Copyright (C) 2017-2018 The Electron Cash Developers
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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
import os
from os import urandom
import sys
import time
from typing import Any, cast

import bitcoinx

from . import daemon, web
from .app_state import app_state, AppStateProxy, DefaultApp
from .commands import Command, Commands, config_variables, get_parser, known_commands
from .constants import AccountCreationType, CredentialPolicyFlag, KeystoreTextType
from .exceptions import IncompatibleWalletError, InvalidPassword
from .keystore import instantiate_keystore_from_text
from .logs import logs
from .networks import Net, SVTestnet, SVScalingTestnet, SVRegTestnet
from .platform import platform
from .simple_config import SimpleConfig
from . import startup
from .storage import WalletStorage
from .types import KeyStoreResult
from .util import json_encode, json_decode, setup_thread_excepthook
from .wallet import Wallet


if sys.platform == "win32":
    # aiodns forces us to do override the default proactor loop with the selector loop.
    # https://github.com/saghul/aiodns/issues/78
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def prompt_password(prompt: str, confirm: bool=True) -> str|None:
    # NOTE(shoddy-windows-getpass-support) Search for this named note for more information.
    import getpass
    password = getpass.getpass(prompt)
    if password and confirm:
        password2 = getpass.getpass("Confirm: ")
        if password != password2:
            sys.exit("Error: passwords do not match")
    if not password:
        return None
    return password


def run_non_RPC(config: SimpleConfig) -> None:
    """Most commands should go through the daemon or RPC, especially commands that operate on
    wallets."""
    cmdname = config.get_optional_type(str, 'cmd')

    def get_wallet_path() -> str:
        wallet_path = config.get_commandline_wallet_path()
        if wallet_path is None:
            sys.exit("error: no wallet path provided")

        final_path = WalletStorage.canonical_path(wallet_path)
        if WalletStorage.files_are_matched_by_path(wallet_path):
            sys.exit(f"error: wallet already exists: {final_path}")

        return final_path

    if cmdname in {"create_wallet", "create_jsonrpc_wallet", "create_account"}:
        app_state.read_headers()
        password: str|None
        if not config.cmdline_options.get('nopasswordcheck'):
            password = prompt_password("Password: ")
            password = password.strip() if password is not None else password
        else:
            password = config.cmdline_options.get("wallet_password")
        if not password:
            sys.exit("error: wallet/account creation requires a password")

        if cmdname == "create_wallet":
            # This is either the explicit path the user provided or the current directory of
            # the caller.
            wallet_path = get_wallet_path()

            password_token = app_state.credentials.set_wallet_password(wallet_path, password,
                CredentialPolicyFlag.FLUSH_ALMOST_IMMEDIATELY)
            assert password_token is not None
            storage = WalletStorage.create(wallet_path, password_token)
            storage.close()

            print(f"Wallet saved in '{wallet_path}'")
            print("WARNING: This wallet requires an account to be added.")
            print("WARNING: This wallet is unsuitable for use with the node wallet API.")
            sys.exit(0)

        elif cmdname == "create_jsonrpc_wallet":
            # This is the wallet path in the data directory.
            wallet_folder_path = config.get_wallet_directory_path()
            # The calling context already checked that the filename is provided.
            wallet_filename = cast(str, config.get('wallet_path'))
            # As we expect wallet files usable with the JSON-RPC API to be located in the
            # "wallets" subdirectory in the data directory, the filename must have no path.
            if os.path.dirname(wallet_filename):
                sys.exit(f"Error: wallet file name '{wallet_filename}' must just be the name")

            wallet_path = WalletStorage.canonical_path(os.path.join(wallet_folder_path,
                wallet_filename))
            if WalletStorage.files_are_matched_by_path(wallet_path):
                sys.exit(f"Error: wallet file '{wallet_path}' already exists")

            # Create the empty wallet.
            password_token = app_state.credentials.set_wallet_password(wallet_path, password,
                CredentialPolicyFlag.FLUSH_ALMOST_IMMEDIATELY)
            assert password_token is not None
            storage = WalletStorage.create(wallet_path, password_token)

            # Add a standard account to the wallet.
            wallet = Wallet(storage)
            keystore_result = wallet.derive_child_keystore(for_account=True, password=password)
            wallet.create_account_from_keystore(keystore_result)

            print(f"Wallet saved in '{wallet_path}'")
            print("NOTE: This wallet is ready for use with the node wallet API.")
            sys.exit(0)

        elif cmdname == "create_account":
            wallet_path = cast(str, config.get_commandline_wallet_path())
            password_token = app_state.credentials.set_wallet_password(wallet_path, password,
                CredentialPolicyFlag.FLUSH_ALMOST_IMMEDIATELY)
            assert password_token is not None
            storage = WalletStorage.create(wallet_path, password_token)
            wallet = Wallet(storage, password)

            # create an account for the Wallet (only random new seeds supported - no importing)
            text_type = KeystoreTextType.EXTENDED_PRIVATE_KEY

            text_match = os.getenv("ELECTRUMSV_ACCOUNT_XPRV")
            if not text_match:  # generate a random account seed
                data = urandom(64)
                coin = bitcoinx.BitcoinRegtest
                xprv = bitcoinx.BIP32PrivateKey._from_parts(data[:32], data[32:], coin)
                text_match = xprv.to_extended_key_string()
            assert text_match is not None # typing bug
            keystore = instantiate_keystore_from_text(text_type, text_match, password,
                derivation_text=None, passphrase="", watch_only=False)
            wallet.create_account_from_keystore(
                KeyStoreResult(AccountCreationType.IMPORTED, keystore))
            wallet.stop()
            print(f"New standard (bip32) account created for: '{wallet_path}'")
            sys.exit(0)

    else:
        sys.exit(f"error: unrecognised command '{cmdname}'")


def process_daemon_subcommand(config_options: dict[str, Any], subcommand: str) -> None:
    if subcommand in ("load_wallet", "service_signup"):
        config = SimpleConfig(config_options)

        command_line_wallet_path = cast(str, config.get("wallet_path"))
        wallet_path = config.resolve_existing_wallet_path(command_line_wallet_path)
        if wallet_path is None:
            sys.exit(f"Wallet file not found: '{command_line_wallet_path}'.")

        assert wallet_path is not None
        # Check that the located file loads as a supported form of wallet storage.
        storage = WalletStorage(wallet_path)
        try:
            if "wallet_password" in config_options:
                print('Warning: unlocking wallet with commandline argument \"--walletpassword\"')
                password = config_options["wallet_password"]
            elif config.get("password"):
                password = config.get("password")
            else:
                password = prompt_password("Password: ", confirm=False)
                if not password:
                    sys.exit("Error: password required.")

            assert isinstance(password, str)
            if not storage.is_password_valid(password):
                sys.exit("Error: wallet password incorrect.")
        finally:
            storage.close()

        config_options["password"] = password


def init_cmdline(config_options: dict[str, Any]) -> tuple[Command, str|None]:
    # The config object should be read-only. Do not change it.
    config = SimpleConfig(config_options)
    cmdname = config.get('cmd')
    assert isinstance(cmdname, str)
    cmd = known_commands[cmdname.replace("-", "_")]

    wallet_path = config.get_commandline_wallet_path()
    if cmd.requires_wallet and not WalletStorage.files_are_matched_by_path(wallet_path):
        sys.exit("Error: wallet file not found")

    # commands needing password
    password: str|None
    if cmd.requires_wallet or cmd.requires_password: # `cmd.requires_wallet or server is None`
        if config.get("password"):
            password = config.get_optional_type(str, "password")
        else:
            password = prompt_password('Password:', False)
            if not password:
                sys.exit("Error: password required")
    else:
        password = None

    config_options["password"] = password

    if cmd.name == "password":
        new_password = prompt_password('New password:')
        config_options['new_password'] = new_password

    return cmd, password


def run_offline_command(config: SimpleConfig, config_options: dict[str, Any]) -> Any:
    cmdname = config.get_explicit_type(str, 'cmd', "?")
    cmd = known_commands[cmdname]
    password = config_options.get("password")
    wallet: Wallet|None

    if cmd.requires_wallet:
        wallet_path = config.get_commandline_wallet_path()
        if not WalletStorage.files_are_matched_by_path(wallet_path):
            sys.exit("Error: wallet does not exist at given path")

        assert wallet_path is not None
        storage = WalletStorage(wallet_path)
        wallet = Wallet(storage)
    else:
        wallet = None

    if cmd.requires_password:
        assert wallet is not None and password is not None
        try:
            wallet.check_password(password)
        except (InvalidPassword, IncompatibleWalletError):
            sys.exit("Error: invalid password for wallet")

    if cmd.requires_network:
        print("Warning: running command offline")

    # arguments passed to function
    args = [cast(str, config.get(x)) for x in cmd.params]
    # decode json arguments
    if cmdname not in ('setconfig',):
        args = [json_decode(arg) for arg in args]
    # options
    kwargs = {}
    for x in cmd.options:
        kwargs[x] = (config_options.get(x) if x in ["password", 'new_password'] else config.get(x))
    cmd_runner = Commands(config, wallet, None)
    func = getattr(cmd_runner, cmd.name)
    result = func(*args, **kwargs)
    if wallet:
        wallet.stop()
    return result


def load_app_module(module_name: str, config: SimpleConfig) -> None:
    from importlib import import_module
    try:
        module = import_module(module_name)
    except Exception as e:
        print(f"Module '{module_name}' cannot be imported: {e}", file=sys.stderr)
        sys.exit(1)

    for memberValue in module.__dict__.values():
        if (memberValue is not AppStateProxy and type(memberValue) is type(AppStateProxy) and
                issubclass(memberValue, AppStateProxy)):
            memberValue(config, 'daemon-app')
            if not app_state.has_app():
                print(f'Daemon app {module_name} has_app() is False', file=sys.stderr)
                sys.exit(1)
            return

    print(f'Module {module_name} does not appear to be a daemon app', file=sys.stderr)
    sys.exit(1)


def run_app_with_daemon(fd: int, is_gui: bool=False) -> None:
    assert app_state.app is not None

    with app_state.async_ as async_:
        d = daemon.Daemon(fd, is_gui)
        app_state.app.setup_app()

        d.start()
        try:
            app_state.app.run_app()
        except KeyboardInterrupt:
            pass
        finally:
            # Shut down the daemon before exiting the async loop
            d.stop()
            d.join()
    sys.exit(0)


def enforce_requirements() -> None:
    if sys.version_info[:3] < (3, 10, 0) or sys.version_info[:3] >= (3, 11, 0):
        sys.exit("Error: ElectrumSV requires Python version 3.10")

    # Are we running from source, and do we have the requirements?  If not we do not apply.
    requirement_path = os.path.join(
        startup.base_dir, "contrib", "requirements", "requirements.txt")
    if not os.path.exists(requirement_path):
        return

    import pkg_resources
    from pkg_resources import DistributionNotFound, VersionConflict
    with open(requirement_path, 'r') as f:
        try:
            pkg_resources.require(f.readlines())
        except VersionConflict as e:
            # e.g. "Dependency version conflict, got 'bitcoinX 0.0.4', expected 'bitcoinX==0.0.5'"
            sys.exit(f"Dependency version conflict, got '{e.args[0]}', expected '{e.args[1]}'")
        except DistributionNotFound as e:
            # e.g. "The 'qrcode' distribution was not found and is required by the application"
            sys.exit(str(e))


def read_cli_args() -> None:
    # read arguments from stdin pipe and prompt
    for i, arg in enumerate(sys.argv):
        if arg == '-':
            if not sys.stdin.isatty():
                sys.argv[i] = sys.stdin.read()
                break
            else:
                raise Exception('Cannot get argument from stdin')
        elif arg == '?':
            sys.argv[i] = input("Enter argument:")
        elif arg == ':':
            hidden_text = prompt_password('Enter argument (will not echo):', confirm=False)
            assert hidden_text is not None
            sys.argv[i] = hidden_text


def get_config_options() -> dict[str, Any]:
    read_cli_args()
    parser = get_parser()
    args = parser.parse_args()

    # config is an object passed to various constructors
    config_options = args.__dict__
    config_options = {
        key: value for key, value in config_options.items()
        if value is not None and key not in config_variables.get(args.cmd, {})
    }
    return config_options


def main() -> None:
    enforce_requirements()
    if sys.platform == "win32" and getattr(sys, "frozen", False):
        # NOTE(shoddy-windows-getpass-support) This replaces `sys.stdin` and a side effect is
        # that `getpass.getpass` bails out of the Windows support to the fallback support which
        # does not hide the input and shows a confusing warning. The Windows support does work
        # with this replacement, but we need to replace `getpass.getpass` to ensure it is used.
        from electrumsv.winconsole import setup_windows_console
        setup_windows_console()

    # The hook will only be used in the Qt GUI right now
    setup_thread_excepthook()

    # on osx, delete Process Serial Number arg generated for apps launched in Finder
    sys.argv = [x for x in sys.argv if not x.startswith('-psn')]

    config_options = get_config_options()
    logs.set_level(config_options['verbose'])

    # The applications working directory should never change. The reason we store this is because
    # `config_options` is passed to the daemon with daemon subcommand calls and this is useful
    # context.
    config_options['cwd'] = os.getcwd()

    # fixme: this can probably be achieved with a runtime hook (pyinstaller)
    portable_base_path = None
    try:
        # NOTE(typing) `MEIPASS` is a PyInstaller installed module attribute, not standard.
        if startup.is_bundle and \
                os.path.exists(os.path.join(sys._MEIPASS, 'is_portable')): # type: ignore
            config_options['portable'] = True
            # Ensure the wallet data is stored in the same directory as the executable.
            portable_base_path = os.path.dirname(sys.executable)
    except AttributeError:
        config_options['portable'] = False

    if config_options.get('portable'):
        if portable_base_path is None:
            # Default to the same directory the 'electrum-sv' script is in.
            portable_base_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        if 'electrum_sv_path' not in config_options:
            config_options['electrum_sv_path'] = os.path.join(portable_base_path,
                'electrum_sv_data')

    if config_options.get('file_logging'):
        if 'electrum_sv_path' in config_options:
            log_path = os.path.join(config_options['electrum_sv_path'], "logs")
        else:
            log_path = os.path.join(platform.user_dir(prefer_local=True), "logs")
        os.makedirs(log_path, exist_ok=True)
        log_path = os.path.join(log_path, time.strftime("%Y%m%d-%H%M%S") + ".log")
        logs.add_file_output(log_path)

    if config_options.get('testnet'):
        Net.set_to(SVTestnet)
    elif config_options.get('scalingtestnet'):
        Net.set_to(SVScalingTestnet)
    elif config_options.get('regtest'):
        Net.set_to(SVRegTestnet)

    # check uri
    uri = config_options.get('url')
    if uri and not web.is_URI(uri):
        sys.exit(f"unknown command: '{uri}'")

    # This takes a copy of `config_options`, any changes to `config_options` past this point will
    # not be present in `config`'s copy.
    config = SimpleConfig(config_options)
    # Set the app state proxy
    cmdname = config.get_optional_type(str, 'cmd')
    if cmdname == 'gui':
        try:
            from electrumsv.gui.qt.app_state import QtAppStateProxy
        except ImportError as e:
            platform.missing_import(e)
            raise
        QtAppStateProxy(config, "qt")
    elif cmdname == "daemon" and "daemon_app_module" in config_options:
        load_app_module(config_options["daemon_app_module"], config)
    else:
        AppStateProxy(config, "cmdline")
        app_state.set_app(DefaultApp())

    # run non-RPC commands separately
    if cmdname in { "create_wallet", "create_jsonrpc_wallet", "create_account" }:
        run_non_RPC(config)
        sys.exit(0)

    result: str | dict[Any, Any] = ""
    if cmdname == "gui":
        lockfile_fd = daemon.get_lockfile_fd(config)
        if lockfile_fd:
            run_app_with_daemon(lockfile_fd, is_gui=True)
        else:
            result = daemon.remote_daemon_request(config, "/v1/rpc/gui", config_options)

    elif cmdname == "daemon":
        subcommand = config.get_optional_type(str, "subcommand")
        if subcommand in [None, "start"]:
            lockfile_fd = daemon.get_lockfile_fd(config)
            if lockfile_fd:
                if not app_state.has_app():
                    sys.exit("No application present to run.")

                if subcommand == "start":
                    fork = getattr(os, "fork")
                    if fork is None:
                        sys.exit(f"Starting the daemon is not supported on {sys.platform}.")

                    pid = fork()
                    if pid:
                        print("Starting daemon (PID %d)" % pid, file=sys.stderr)
                        sys.exit(0)

                run_app_with_daemon(lockfile_fd)
                return

            result = daemon.remote_daemon_request(config, "/v1/rpc/daemon", config_options)
        else:
            assert subcommand is not None
            process_daemon_subcommand(config_options, subcommand)
            result = daemon.remote_daemon_request(config, "/v1/rpc/daemon", config_options)
    else:
        # command line
        init_cmdline(config_options)
        assert isinstance(cmdname, str)
        cmd = known_commands[cmdname]
        if cmd.requires_network:
            result = daemon.remote_daemon_request(config, "/v1/rpc/cmdline", config_options)
            # NOTE(rt12) No idea when this happens or why we exit with an error despite the call.
            sys.exit("Daemon not running")
        else:
            result = run_offline_command(config, config_options)

    if isinstance(result, str):
        print(result)
        if result.startswith("Error:"):
            sys.exit(1)
    elif type(result) is dict and result.get('error'):
        print(result.get('error'), file=sys.stderr)
        sys.exit(1)
    elif result is not None:
        print(json_encode(result))
    sys.exit(0)
