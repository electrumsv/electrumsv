from __future__ import annotations
from copy import deepcopy
import json
import os
import stat
import threading
from typing import Any, Callable, cast, Type, TypeVar

from mypy_extensions import DefaultArg

from .logs import logs
from .platform import platform
from .util import make_dir


logger = logs.get_logger("config")


FINAL_CONFIG_VERSION = 2

T = TypeVar('T')


class SimpleConfig:
    """
    The SimpleConfig class is responsible for handling operations involving
    configuration files.

    There are two different sources of possible configuration values:
        1. Command line options.
        2. User configuration (in the user's config directory)
    They are taken in order (1. overrides config options set in 2.)
    """

    def __init__(self, options: dict[str, Any]|None=None,
            read_user_config_function: Callable[[str], dict[str, Any]]|None=None,
            read_user_dir_function: Callable[[DefaultArg(bool, 'prefer_local')], str]|None=None) \
                -> None:

        if options is None:
            options = {}

        # This lock needs to be acquired for updating and reading the config in
        # a thread-safe way.
        self.lock = threading.RLock()

        # The following two functions are there for dependency injection when
        # testing.
        if read_user_config_function is None:
            read_user_config_function = read_user_config
        if read_user_dir_function is None:
            self.user_dir = platform.user_dir
        else:
            self.user_dir = read_user_dir_function

        # The command line options
        self.cmdline_options = deepcopy(options)
        # don't allow to be set on CLI:
        self.cmdline_options.pop('config_version', None)

        # Set self.path and read the user config
        self.user_config = {}  # for self.get in electrum_path()
        self.path = self.electrum_path()
        self.user_config = read_user_config_function(self.path)
        if not self.user_config:
            # avoid new config getting upgraded
            self.user_config = {'config_version': FINAL_CONFIG_VERSION}

        # config "upgrade" - CLI options
        self.rename_config_keys(
            self.cmdline_options, {'auto_cycle': 'auto_connect'}, True)

        # config upgrade - user config
        if self.requires_upgrade():
            self.upgrade()

    def electrum_path(self) -> str:
        # Read electrum_cash_path from command line
        # Otherwise use the user's default data directory.
        path = cast(str, self.get('electrum_sv_path'))
        if path is None:
            path = self.user_dir()

        make_dir(path)
        if self.get('testnet'):
            path = os.path.join(path, 'testnet')
            make_dir(path)

        if self.get('scalingtestnet'):
            path = os.path.join(path, 'scalingtestnet')
            make_dir(path)

        if self.get('regtest'):
            path = os.path.join(path, 'regtest')
            make_dir(path)

        obsolete_file = os.path.join(path, 'recent_servers')
        if os.path.exists(obsolete_file):
            os.remove(obsolete_file)
        logger.debug("electrum-sv directory '%s'", path)
        return os.path.abspath(path)

    def file_path(self, file_name: str) -> str|None:
        if self.path:
            return os.path.join(self.path, file_name)
        return None

    def rename_config_keys(self, config: dict[str, Any], keypairs: dict[str, str],
            deprecation_warning: bool=False) -> bool:
        """Migrate old key names to new ones"""
        updated = False
        for old_key, new_key in keypairs.items():
            if old_key in config:
                if new_key not in config:
                    config[new_key] = config[old_key]
                    if deprecation_warning:
                        logger.warning('Note that the %s variable has been deprecated. '
                              'You should use %s instead.', old_key, new_key)
                del config[old_key]
                updated = True
        return updated

    def set_key(self, key: str, value: Any, save: bool=True) -> None:
        if not self.is_modifiable(key):
            logger.warning("Not changing config key '%s' set on the command line", key)
            return
        self._set_key_in_user_config(key, value, save)

    def _set_key_in_user_config(self, key: str, value: Any, save: bool=True) -> None:
        with self.lock:
            if value is not None:
                self.user_config[key] = value
            else:
                self.user_config.pop(key, None)
            if save:
                self.save_user_config()

    def get(self, key: str, default: Any=None) -> Any|None:
        with self.lock:
            out = self.cmdline_options.get(key)
            if out is None:
                out = self.user_config.get(key, default)
        return out

    def get_optional_type(self, return_type: Type[T], key: str, default: T|None=None) -> T|None:
        with self.lock:
            value = self.cmdline_options.get(key)
            if value is None:
                value = self.user_config.get(key, default)
        assert value == default or isinstance(value, return_type)
        return cast(T, value)

    def get_explicit_type(self, return_type: Type[T], key: str, default: T) -> T:
        with self.lock:
            value: T|None = self.cmdline_options.get(key)
            if value is None:
                value = cast(T, self.user_config.get(key, default))
        assert isinstance(value, return_type)
        return value

    def requires_upgrade(self) -> bool:
        return self.get_config_version() < FINAL_CONFIG_VERSION

    def upgrade(self) -> None:
        with self.lock:
            logger.debug('upgrading config')

            self.convert_version_2()

            self.set_key('config_version', FINAL_CONFIG_VERSION, save=True)

    def convert_version_2(self) -> None:
        if not self._is_upgrade_method_needed(1, 1):
            return

        self.rename_config_keys(self.user_config, {'auto_cycle': 'auto_connect'})

        try:
            # migrate server string FROM host:port:proto TO host:port
            server_str = self.user_config.get('server')
            host, port, protocol = str(server_str).rsplit(':', 2)
            assert protocol in ('s', 't')
            int(port)  # Throw if cannot be converted to int
            server_str = str('{}:{}'.format(host, port))
            self._set_key_in_user_config('server', server_str)
        except Exception:
            self._set_key_in_user_config('server', None)

        self.set_key('config_version', 2)

    def _is_upgrade_method_needed(self, min_version: int, max_version: int) -> bool:
        cur_version = self.get_config_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise Exception(
                ('config upgrade: unexpected version %d (should be %d-%d)'
                 % (cur_version, min_version, max_version)))
        else:
            return True

    def get_config_version(self) -> int:
        config_version = self.get_explicit_type(int, 'config_version', 1)
        if config_version > FINAL_CONFIG_VERSION:
            logger.warning('WARNING: config version (%s) is higher than ours (%s)',
                             config_version, FINAL_CONFIG_VERSION)
        return config_version

    def is_modifiable(self, key: str) -> bool:
        return key not in self.cmdline_options

    def save_user_config(self) -> None:
        if not self.path:
            return
        path = os.path.join(self.path, "config")
        s = json.dumps(self.user_config, indent=4, sort_keys=True)
        with open(path, "w", encoding='utf-8') as f:
            f.write(s)
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)

    def resolve_existing_wallet_path(self, wallet_path: str) -> str|None:
        """
        This returns the absolute path of the given wallet file, if it exists.

        1. If it is an absolute path to an existing wallet file already, we return it back.
        2. If it is a relative path to an existing wallet file based on the _config working
           directory_, then we return its absolute path.
        3. If it is a file name and not a path and exists in the wallet folder under the
           application data directory, then we return its absolute path.

        Raises `FileNotFoundError` if it reaches step 3 and the application data directory does
            not exist.
        """
        from .storage import WalletStorage

        # Remember that this only combines relative paths, absolute paths are left as is.
        absolute_wallet_path = os.path.join(cast(str, self.get('cwd')), wallet_path)
        if WalletStorage.files_are_matched_by_path(absolute_wallet_path):
            return absolute_wallet_path

        # If this is going to be in the data directory wallet folder, it needs to just be a name.
        if os.path.basename(wallet_path) == wallet_path:
            absolute_wallet_path = os.path.join(self.get_wallet_directory_path(), wallet_path)
            if WalletStorage.files_are_matched_by_path(absolute_wallet_path):
                return absolute_wallet_path

        return None

    def get_wallet_directory_path(self) -> str:
        """
        This returns the path of the wallet directory in the data directory, and it makes sure that
        the path exists if it has not already been created.

        Raises `FileNotFoundError` if `self.path` is not found.
        """
        if not os.path.exists(self.path):
            raise FileNotFoundError("ElectrumSV data directory does not exist. Was it deleted "
                f"while running?\nShould be at {self.path}")

        path = os.path.join(self.path, "wallets")
        make_dir(path)
        return path

    def get_commandline_wallet_path(self) -> str|None:
        """
        If the user has specified a wallet file to open, return its absolute path. We only use this
        if we are wanting that wallet path. We do not care about the directory it is in. 99.999% of
        users use the GUI and not the command-line to open wallets, and if they provide a wallet
        path it's the one they precisely want to open.
        """
        if self.get('wallet_path'):
            # If the precise wallet path given on the command-line is absolute, note that the
            # join will ignore the current working directory automatically so this will work
            # correctly for both relative and absolute command-line wallet paths.
            return os.path.join(cast(str, self.get('cwd')), cast(str, self.get('wallet_path')))
        return None

    def set_session_timeout(self, seconds: int) -> None:
        logger.debug("session timeout -> %d seconds", seconds)
        self.set_key('session_timeout', seconds)

    def get_session_timeout(self) -> int:
        return self.get_explicit_type(int, 'session_timeout', 300)

    def get_video_device(self) -> bytes:
        device_id_hex = self.get_explicit_type(str, "video_device", "default")
        try:
            return bytes.fromhex(device_id_hex)
        except ValueError:
            return b''


def read_user_config(path: str) -> dict[str, Any]:
    """Parse and return the user config settings as a dictionary."""
    if not path:
        return {}
    config_path = os.path.join(path, "config")
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding='utf-8') as f:
            data = f.read()
        result = json.loads(data)
    except Exception:
        logger.exception("Cannot read config file %s.", config_path)
        return {}
    if not type(result) is dict:
        return {}
    return result
