import os
import tempfile

from electrumsv.simple_config import SimpleConfig
from electrumsv.app_state import AppStateProxy
from electrumsv.wallet_database.sqlite_support import DatabaseContext


class AppStateProxyTest(AppStateProxy):

    def __init__(self):
        config = SimpleConfig()
        super().__init__(config, 'qt')

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


class MockStorage:
    def __init__(self) -> None:
        unique_name = os.urandom(8).hex()
        self.path = DatabaseContext.shared_memory_uri(unique_name)
        self.db_context = DatabaseContext(self.path)
        # We hold onto an open connection to ensure that the database persists for the
        # lifetime of the tests.
        self.db = self.db_context.acquire_connection()

        from electrumsv.wallet_database.migration import create_database, update_database
        create_database(self.db)
        update_database(self.db)

        self._data = {}

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

