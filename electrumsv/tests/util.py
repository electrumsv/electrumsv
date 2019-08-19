import os

from electrumsv.simple_config import SimpleConfig
from electrumsv.app_state import AppStateProxy


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
