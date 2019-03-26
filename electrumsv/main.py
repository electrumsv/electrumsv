# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2018-2019 The ElectrumSV Developers
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

import os
import sys
import time

from electrumsv import daemon, keystore, web
from electrumsv.app_state import app_state, AppStateProxy
from electrumsv.commands import get_parser, known_commands, Commands, config_variables
from electrumsv.exceptions import InvalidPassword
from electrumsv.exchange_rate import FxTask
from electrumsv.logs import logs
from electrumsv.mnemonic import Mnemonic
from electrumsv.network import Network
from electrumsv.networks import Net, SVTestnet
from electrumsv.platform import platform
from electrumsv.simple_config import SimpleConfig
from electrumsv import startup
from electrumsv.storage import WalletStorage
from electrumsv.util import json_encode, json_decode, setup_thread_excepthook
from electrumsv.wallet import Wallet, ImportedPrivkeyWallet, ImportedAddressWallet


# get password routine
def prompt_password(prompt, confirm=True):
    import getpass
    password = getpass.getpass(prompt, stream=None)
    if password and confirm:
        password2 = getpass.getpass("Confirm: ")
        if password != password2:
            sys.exit("Error: Passwords do not match.")
    if not password:
        password = None
    return password


def run_non_RPC(config):
    cmdname = config.get('cmd')

    storage = WalletStorage(config.get_wallet_path())
    if storage.file_exists():
        sys.exit("Error: Remove the existing wallet first!")

    def password_dialog():
        return prompt_password("Password (hit return if you do not wish to encrypt your wallet):")

    if cmdname == 'restore':
        text = config.get('text').strip()
        passphrase = config.get('passphrase', '')
        password = password_dialog() if keystore.is_private(text) else None
        if keystore.is_address_list(text):
            wallet = ImportedAddressWallet.from_text(storage, text)
        elif keystore.is_private_key_list(text):
            wallet = ImportedPrivkeyWallet.from_text(storage, text, password)
        else:
            if keystore.is_seed(text):
                k = keystore.from_seed(text, passphrase, False)
            elif keystore.is_master_key(text):
                k = keystore.from_master_key(text)
            else:
                sys.exit("Error: Seed or key not recognized")
            if password:
                k.update_password(None, password)
            storage.put('keystore', k.dump())
            storage.put('wallet_type', 'standard')
            storage.put('use_encryption', bool(password))
            storage.write()
            wallet = Wallet(storage)
        if not config.get('offline'):
            network = Network()
            network.add_wallet(wallet)
            print("Recovering wallet...")
            wallet.synchronize()
            msg = ("Recovery successful" if wallet.is_found()
                   else "Found no history for this wallet")
        else:
            msg = ("This wallet was restored offline. "
                   "It may contain more addresses than displayed.")
        print(msg)

    elif cmdname == 'create':
        password = password_dialog()
        passphrase = config.get('passphrase', '')
        seed_type = 'standard'
        seed = Mnemonic('en').make_seed(seed_type)
        k = keystore.from_seed(seed, passphrase, False)
        storage.put('keystore', k.dump())
        storage.put('wallet_type', 'standard')
        wallet = Wallet(storage)
        wallet.update_password(None, password, True)
        wallet.synchronize()
        print("Your wallet generation seed is:\n\"%s\"" % seed)
        print("Please keep it in a safe place; if you lose it, "
              "you will not be able to restore your wallet.")

    wallet.storage.write()
    print("Wallet saved in '%s'" % wallet.storage.path)
    sys.exit(0)


def init_daemon(config_options):
    config = SimpleConfig(config_options)
    storage = WalletStorage(config.get_wallet_path())
    if not storage.file_exists():
        print("Error: Wallet file not found.")
        print("Type 'electrum-sv create' to create a new wallet, "
              "or provide a path to a wallet with the -w option")
        sys.exit(0)
    if storage.is_encrypted():
        if 'wallet_password' in config_options:
            print('Warning: unlocking wallet with commandline argument \"--walletpassword\"')
            password = config_options['wallet_password']
        elif config.get('password'):
            password = config.get('password')
        else:
            password = prompt_password('Password:', False)
            if not password:
                print("Error: Password required")
                sys.exit(1)
    else:
        password = None
    config_options['password'] = password


def init_cmdline(config_options, server):
    config = SimpleConfig(config_options)
    cmdname = config.get('cmd')
    cmd = known_commands[cmdname]

    if cmdname == 'signtransaction' and config.get('privkey'):
        cmd.requires_wallet = False
        cmd.requires_password = False

    if cmdname in ['payto', 'paytomany'] and config.get('unsigned'):
        cmd.requires_password = False

    if cmdname in ['payto', 'paytomany'] and config.get('broadcast'):
        cmd.requires_network = True

    # instanciate wallet for command-line
    storage = WalletStorage(config.get_wallet_path())

    if cmd.requires_wallet and not storage.file_exists():
        print("Error: Wallet file not found.")
        print("Type 'electrum-sv create' to create a new wallet, "
              "or provide a path to a wallet with the -w option")
        sys.exit(0)

    # important warning
    if cmd.name in ['getprivatekeys']:
        print("WARNING: ALL your private keys are secret.", file=sys.stderr)
        print("Exposing a single private key can compromise your entire wallet!", file=sys.stderr)
        print("In particular, DO NOT use 'redeem private key' services "
              "proposed by third parties.", file=sys.stderr)

    # commands needing password
    if ((cmd.requires_wallet and storage.is_encrypted() and server is None)
        or (cmd.requires_password
            and (storage.get('use_encryption') or storage.is_encrypted()))):
        if config.get('password'):
            password = config.get('password')
        else:
            password = prompt_password('Password:', False)
            if not password:
                print("Error: Password required")
                sys.exit(1)
    else:
        password = None

    config_options['password'] = password

    if cmd.name == 'password':
        new_password = prompt_password('New password:')
        config_options['new_password'] = new_password

    return cmd, password


def run_offline_command(config, config_options):
    cmdname = config.get('cmd')
    cmd = known_commands[cmdname]
    password = config_options.get('password')
    if cmd.requires_wallet:
        storage = WalletStorage(config.get_wallet_path())
        if storage.is_encrypted():
            storage.decrypt(password)
        wallet = Wallet(storage)
    else:
        wallet = None
    # check password
    if cmd.requires_password and storage.get('use_encryption'):
        try:
            seed = wallet.check_password(password)
        except InvalidPassword:
            print("Error: This password does not decode this wallet.")
            sys.exit(1)
    if cmd.requires_network:
        print("Warning: running command offline")
    # arguments passed to function
    args = [config.get(x) for x in cmd.params]
    # decode json arguments
    if cmdname not in ('setconfig',):
        args = [json_decode(arg) for arg in args]
    # options
    kwargs = {}
    for x in cmd.options:
        kwargs[x] = (config_options.get(x) if x in ['password', 'new_password'] else config.get(x))
    cmd_runner = Commands(config, wallet, None)
    func = getattr(cmd_runner, cmd.name)
    result = func(*args, **kwargs)
    # save wallet
    if wallet:
        wallet.storage.write()
    return result


def load_app_module(module_name, config):
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


def run_app_with_daemon(fd, is_gui, config_options):
    with app_state.async_ as async_:
        d = daemon.Daemon(fd, is_gui)
        d.start()
        try:
            if not app_state.config.get('offline'):
                app_state.fx = FxTask(app_state.config, d.network)
                app_state.async_.spawn(app_state.fx.refresh_loop)
            app_state.app.run_app()
        finally:
            # Shut down the daemon before exiting the async loop
            d.stop()
            d.join()
    sys.exit(0)


def enforce_requirements():
    # Are we running from source, and do we have the requirements?  If not we do not apply.
    requirement_path = os.path.join(
        startup.base_dir, "contrib", "requirements", "requirements.txt")
    if not os.path.exists(requirement_path):
        return

    # The method below only checks installed Python packages. It does not check the packages in
    # the local 'packages' directory created by `./contrib/make_packages`.
    if os.path.exists(startup.packages_dir):
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


def main():
    enforce_requirements()

    # The hook will only be used in the Qt GUI right now
    setup_thread_excepthook()
    # on osx, delete Process Serial Number arg generated for apps launched in Finder
    sys.argv = [x for x in sys.argv if not x.startswith('-psn')]

    # old 'help' syntax
    if len(sys.argv) > 1 and sys.argv[1] == 'help':
        sys.argv.remove('help')
        sys.argv.append('-h')

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
            sys.argv[i] = prompt_password('Enter argument (will not echo):', False)

    # parse command line
    parser = get_parser()
    args = parser.parse_args()

    # config is an object passed to various constructors
    config_options = args.__dict__
    config_options = {
        key: value for key, value in config_options.items()
        if value is not None and key not in config_variables.get(args.cmd, {})
    }

    logs.set_level(config_options['verbose'])

    if config_options.get('server'):
        config_options['auto_connect'] = False
    config_options['cwd'] = os.getcwd()

    # fixme: this can probably be achieved with a runtime hook (pyinstaller)
    portable_base_path = None
    try:
        if startup.is_bundle and os.path.exists(os.path.join(sys._MEIPASS, 'is_portable')):
            config_options['portable'] = True
            # Ensure the wallet data is stored in the same directory as the executable.
            portable_base_path = os.path.dirname(sys.executable)
    except AttributeError:
        config_options['portable'] = False

    if config_options.get('portable'):
        if portable_base_path is None:
            # Default to the same directory the 'electrum-sv' script is in.
            portable_base_path = os.path.dirname(os.path.realpath(sys.argv[0]))
        config_options['electrum_sv_path'] = os.path.join(portable_base_path, 'electrum_sv_data')

    if config_options.get('file_logging'):
        log_path = os.path.join(platform.user_dir(prefer_local=True), "logs")
        os.makedirs(log_path, exist_ok=True)
        log_path = os.path.join(log_path, time.strftime("%Y%m%d-%H%M%S") + ".log")
        logs.add_file_output(log_path)

    if config_options.get('testnet'):
        Net.set_to(SVTestnet)

    # check uri
    uri = config_options.get('url')
    if uri:
        if not web.is_URI(uri):
            print('unknown command:', uri, file=sys.stderr)
            sys.exit(1)
        config_options['url'] = uri

    # todo: defer this to gui
    config = SimpleConfig(config_options)
    cmdname = config.get('cmd')

    # Set the app state proxy
    if cmdname == 'gui':
        try:
            from electrumsv.gui.qt.app_state import QtAppStateProxy
        except ImportError as e:
            platform.missing_import(e)
        QtAppStateProxy(config, 'qt')
    elif cmdname == 'daemon' and 'daemon_app_module' in config_options:
        load_app_module(config_options['daemon_app_module'], config)
    else:
        AppStateProxy(config, 'cmdline')

    # run non-RPC commands separately
    if cmdname in ['create', 'restore']:
        run_non_RPC(config)
        sys.exit(0)

    if cmdname == 'gui':
        fd, server = daemon.get_fd_or_server(config)
        if fd is not None:
            run_app_with_daemon(fd, True, config_options)
        else:
            result = server.gui(config_options)

    elif cmdname == 'daemon':
        subcommand = config.get('subcommand')
        if subcommand in ['load_wallet']:
            init_daemon(config_options)

        if subcommand in [None, 'start']:
            fd, server = daemon.get_fd_or_server(config)
            if fd is not None:
                if subcommand == 'start':
                    pid = os.fork()
                    if pid:
                        print("starting daemon (PID %d)" % pid, file=sys.stderr)
                        sys.exit(0)

                if 'daemon_app_module' in config_options:
                    run_app_with_daemon(fd, False, config_options)
                else:
                    d = daemon.Daemon(fd, False)
                    d.start()
                    d.join()
                sys.exit(0)
            else:
                result = server.daemon(config_options)
        else:
            server = daemon.get_server(config)
            if server is not None:
                result = server.daemon(config_options)
            else:
                print("Daemon not running")
                sys.exit(1)
    else:
        # command line
        server = daemon.get_server(config)
        init_cmdline(config_options, server)
        if server is not None:
            result = server.run_cmdline(config_options)
        else:
            cmd = known_commands[cmdname]
            if cmd.requires_network:
                print("Daemon not running; try 'electrum-sv daemon start'")
                sys.exit(1)
            else:
                result = run_offline_command(config, config_options)
                # print result
    if isinstance(result, str):
        print(result)
    elif type(result) is dict and result.get('error'):
        print(result.get('error'), file=sys.stderr)
    elif result is not None:
        print(json_encode(result))
    sys.exit(0)
