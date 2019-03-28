import time

from electrumsv.app_state import app_state

from .rpc import LocalRPCFunctions


class FileUploadApplication:
    def __init__(self):
        pass

    def run_app(self):
        app_state.daemon.server.register_instance(LocalRPCFunctions())
        try:
            while True:
                time.sleep(0.2)
        finally:
            for wallet_path in list(app_state.daemon.wallets.keys()):
                app_state.daemon.stop_wallet_at_path(wallet_path)
