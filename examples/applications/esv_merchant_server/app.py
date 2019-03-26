import time

from electrumsv.app_state import app_state

from .rpc import LocalRPCFunctions


class MerchantApplication:
    def __init__(self):
        pass

    def run_app(self):
        app_state.daemon.server.register_instance(LocalRPCFunctions())
        while True:
            time.sleep(0.5)
