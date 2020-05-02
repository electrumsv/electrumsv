from copy import deepcopy
import os
import stat
import threading
from typing import Optional

from . import util
from .bitcoin import MAX_FEE_RATE
from .constants import DEFAULT_FEE
from .logs import logs
from .platform import platform
from .util import make_dir, JSON


logger = logs.get_logger("config")


FINAL_CONFIG_VERSION = 2


class SimpleConfig:
    """
    The SimpleConfig class is responsible for handling operations involving
    configuration files.

    There are two different sources of possible configuration values:
        1. Command line options.
        2. User configuration (in the user's config directory)
    They are taken in order (1. overrides config options set in 2.)
    """

    def __init__(self, options=None, read_user_config_function=None,
                 read_user_dir_function=None):

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

    def electrum_path(self):
        # Read electrum_cash_path from command line
        # Otherwise use the user's default data directory.
        path = self.get('electrum_sv_path')
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
        return path

    def file_path(self, file_name):
        if self.path:
            return os.path.join(self.path, file_name)
        return None

    def rename_config_keys(self, config, keypairs, deprecation_warning=False):
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

    def set_key(self, key, value, save=True):
        if not self.is_modifiable(key):
            logger.warning("not changing config key '%s' set on the command line", key)
            return
        self._set_key_in_user_config(key, value, save)

    def _set_key_in_user_config(self, key, value, save=True):
        with self.lock:
            if value is not None:
                self.user_config[key] = value
            else:
                self.user_config.pop(key, None)
            if save:
                self.save_user_config()

    def get(self, key, default=None):
        with self.lock:
            out = self.cmdline_options.get(key)
            if out is None:
                out = self.user_config.get(key, default)
        return out

    def requires_upgrade(self):
        return self.get_config_version() < FINAL_CONFIG_VERSION

    def upgrade(self):
        with self.lock:
            logger.debug('upgrading config')

            self.convert_version_2()

            self.set_key('config_version', FINAL_CONFIG_VERSION, save=True)

    def convert_version_2(self):
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

    def _is_upgrade_method_needed(self, min_version, max_version):
        cur_version = self.get_config_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise Exception(
                ('config upgrade: unexpected version %d (should be %d-%d)'
                 % (cur_version, min_version, max_version)))
        else:
            return True

    def get_config_version(self):
        config_version = self.get('config_version', 1)
        if config_version > FINAL_CONFIG_VERSION:
            logger.warning('WARNING: config version (%s) is higher than ours (%s)',
                             config_version, FINAL_CONFIG_VERSION)
        return config_version

    def is_modifiable(self, key):
        return key not in self.cmdline_options

    def save_user_config(self):
        if not self.path:
            return
        path = os.path.join(self.path, "config")
        s = JSON.dumps(self.user_config, indent=4, sort_keys=True)
        with open(path, "w", encoding='utf-8') as f:
            f.write(s)
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)

    def get_preferred_wallet_dirpath(self) -> str:
        wallet_path = self.get_cmdline_wallet_filepath()
        if wallet_path is not None:
            return os.path.dirname(os.path.abspath(wallet_path))
        return self.get_default_wallet_dirpath()

    def get_default_wallet_dirpath(self) -> str:
        util.assert_datadir_available(self.path)
        path = os.path.join(self.path, "wallets")
        make_dir(path)
        return path

    def get_cmdline_wallet_filepath(self) -> Optional[str]:
        if self.get('wallet_path'):
            return os.path.join(self.get('cwd'), self.get('wallet_path'))
        return None

    def set_session_timeout(self, seconds):
        logger.debug("session timeout -> %d seconds", seconds)
        self.set_key('session_timeout', seconds)

    def get_session_timeout(self):
        return self.get('session_timeout', 300)

    def open_last_wallet(self):
        if self.get('wallet_path') is None:
            last_wallet = self.get('gui_last_wallet')
            if last_wallet is not None and os.path.exists(last_wallet):
                self.cmdline_options['default_wallet_path'] = last_wallet

    def save_last_wallet(self, wallet):
        if self.get('wallet_path') is None:
            path = wallet.get_storage_path()
            self.set_key('gui_last_wallet', path)

    def max_fee_rate(self):
        f = self.get('max_fee_rate', MAX_FEE_RATE)
        if f==0:
            f = MAX_FEE_RATE
        return f

    def custom_fee_rate(self):
        f = self.get('customfee')
        return f

    def fee_per_kb(self):
        retval = self.get('customfee')
        if retval is None:
            retval = self.get('fee_per_kb')
        if retval is None:
            retval = DEFAULT_FEE  # New wallet
        return retval

    def has_custom_fee_rate(self):
        i = -1
        # Defensive programming below.. to ensure the custom fee rate is valid ;) This
        # function mainly controls the appearance (or disappearance) of the fee slider in
        # the send tab in Qt GUI It is tied to the GUI preferences option 'Custom fee
        # rate'.
        try:
            i = int(self.custom_fee_rate())
        except (ValueError, TypeError):
            pass
        return i >= 0

    def estimate_fee(self, size):
        return int(self.fee_per_kb() * size / 1000.)

    def get_video_device(self):
        device = self.get("video_device", "default")
        if device == 'default':
            device = ''
        return device


def read_user_config(path):
    """Parse and return the user config settings as a dictionary."""
    if not path:
        return {}
    config_path = os.path.join(path, "config")
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r", encoding='utf-8') as f:
            data = f.read()
        result = JSON.loads(data)
    except Exception:
        logger.error("Cannot read config file %s.", config_path)
        return {}
    if not type(result) is dict:
        return {}
    return result
