from electrumsv.simple_config import SimpleConfig
from electrumsv.app_state import AppStateProxy
from electrumsv.async_ import ASync


class AppStateProxyTest(AppStateProxy):

    def __init__(self):
        config = SimpleConfig()
        super().__init__(config, 'qt')
        self.async_ = ASync()

proxy = None

def setup_async():
    global proxy
    proxy = AppStateProxyTest()
    proxy.async_.__enter__()


def tear_down_async():
    global proxy
    proxy.async_.__exit__(None, None, None)
    proxy = None
