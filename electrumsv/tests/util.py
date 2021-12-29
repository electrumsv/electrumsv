import os

from electrumsv.app_state import AppStateProxy
from electrumsv.credentials import PasswordTokenProtocol
from electrumsv.simple_config import SimpleConfig
from electrumsv.wallet_database.sqlite_support import DatabaseContext
from electrumsv.wallet_database import functions as db_functions


class AppStateProxyTest(AppStateProxy):

    def __init__(self):
        config = UnittestSimpleConfig()
        super().__init__(config, 'qt')

    def _migrate(self) -> None:
        pass


proxy = None

def setup_async():
    global proxy
    proxy = AppStateProxyTest()
    proxy.async_.__enter__()


def tear_down_async():
    global proxy
    proxy.async_.__exit__(None, None, None)
    proxy = None

TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
TEST_WALLET_PATH = os.path.join(TEST_DATA_PATH, "wallets")


class PasswordToken(PasswordTokenProtocol):
    def __init__(self, password: str) -> None:
        self._password = password

    @property
    def password(self) -> str:
        return self._password



class MockStorage:
    def __init__(self, password: str) -> None:
        self.unique_name = os.urandom(8).hex()
        self.path = DatabaseContext.shared_memory_uri(self.unique_name)
        self.db_context = DatabaseContext(self.path)
        # We hold onto an open connection to ensure that the database persists for the
        # lifetime of the tests.
        self.db = self.db_context.acquire_connection()

        password_token = PasswordToken(password)
        from electrumsv.wallet_database.migration import create_database, update_database
        create_database(self.db)
        update_database(self.db, password_token)

        self._data = {}
        for row in db_functions.read_wallet_datas(self.db_context):
            self._data[row[0]] = row[1]

    def get(self, attr_name, default=None):
        return self._data.get(attr_name, default)

    def get_explicit_type(self, discard, attr_name, default=None):
        return self._data.get(attr_name, default)

    def put(self, attr_name, value):
        self._data[attr_name] = value

    def set_password(self, new_password: str) -> None:
        pass

    def get_path(self) -> str:
        return self.path

    def get_db_context(self):
        return self.db_context


class UnittestSimpleConfig(SimpleConfig):
    def electrum_path(self) -> str:
        # An invalid path as we should never end up using install data nor saving config files!
        return r"Q:\fluff"


