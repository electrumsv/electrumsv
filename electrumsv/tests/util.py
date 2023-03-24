from __future__ import annotations
import asyncio
import json
import os
from typing import Any, Coroutine, NoReturn, TypeVar
import unittest.mock

import bitcoinx

from electrumsv.app_state import AppStateProxy
from electrumsv.credentials import PasswordTokenProtocol
from electrumsv_database.sqlite import DatabaseContext
from electrumsv.simple_config import SimpleConfig
from electrumsv.wallet_database import functions as db_functions


T1 = TypeVar("T1")


class AppStateProxyTest(AppStateProxy):

    def __init__(self):
        config = UnittestSimpleConfig()
        super().__init__(config, 'qt')

        self.daemon = unittest.mock.Mock()
        self.daemon.nodeapi_server = None

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
TEST_TRANSACTION_PATH = os.path.join(TEST_DATA_PATH, "transactions")


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

        with unittest.mock.patch(
            "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state") \
            as migration29_app_state:
                migration29_app_state.headers = mock_headers()
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


def _no_header(chain: bitcoinx.Chain, height: int) -> NoReturn:
    raise bitcoinx.MissingHeader()

def mock_headers() -> unittest.mock.Mock:
    longest_chain = unittest.mock.Mock()
    headers = unittest.mock.Mock()
    headers.longest_chain = lambda: longest_chain
    headers.header_at_height = _no_header
    return headers


def _create_mock_app_state() -> unittest.mock.MagicMock:
    # The primary goal of this is to avoid the warnings about never awaited coroutines.
    def _spawn(coro: Coroutine[Any, Any, Any], on_done=None) -> Any:
        coro.close()
    def _spawn_and_wait(coroutine: Coroutine[Any, Any, T1], timeout: int | None=None) -> T1:
        coroutine.close()
    mock = unittest.mock.MagicMock()
    mock.async_.spawn = _spawn
    mock.async_.spawn_and_wait = _spawn_and_wait
    return mock

def _create_mock_app_state2() -> unittest.mock.MagicMock:
    # The primary goal of this is to avoid the warnings about never awaited coroutines.
    def _spawn(coro: Coroutine[Any, Any, Any], on_done=None) -> Any:
        return asyncio.create_task(coro)
    def _spawn_and_wait(coroutine: Coroutine[Any, Any, T1], timeout: int | None=None) -> T1:
        task = asyncio.create_task(coroutine)
        1/0
    mock = unittest.mock.MagicMock()
    mock.async_.spawn = _spawn
    mock.async_.spawn_and_wait = _spawn_and_wait
    return mock

def read_testdata_for_wallet(wallet_path: str, context_text: str, *,
        testdata_object_for_write: dict|list[dict]|None=None) -> dict:
    """
    Parameters:
        - `wallet_path`: The full path of the wallet. The test data file will be alongside it.
        - `context_text`: Used in the custom suffix for the test data file name. If `"history_full"`
          would result in a suffix of `"_history_full.json"`.
        - `testdata_object_for_write`: The new test data to overwrite the existing test data with.
    Raises nothing.
    """
    testdata_folder_path, testdata_wallet_filename = os.path.split(wallet_path)
    wallet_basename, _wallet_suffix = os.path.splitext(testdata_wallet_filename)
    testdata_path = os.path.join(testdata_folder_path, f"{wallet_basename}_{context_text}.json")

    if testdata_object_for_write is not None:
        with open(testdata_path, "w") as f:
            json.dump(testdata_object_for_write, f, indent=4)

    assert os.path.exists(testdata_path)

    with open(testdata_path, "r") as f:
        return json.load(f)
