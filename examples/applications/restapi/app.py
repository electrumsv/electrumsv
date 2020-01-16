import logging
import time
from electrumsv.app_state import app_state
from .handlers import ExtensionEndpoints


class RESTAPIApplication:

    def __init__(self):
        self.logger = logging.getLogger("wallet-app")

    def run_app(self):
        self.logger.debug("entering application main loop")
        try:
            while app_state.async_.loop.is_running():
                time.sleep(0.1)  # sole purpose is timely cleanup on KeyboardInterrupt
        finally:
            self._teardown_app()
            self.logger.debug("exited application main loop")

    def setup_app(self) -> None:
        # app_state.daemon is initialised after app. Setup things dependent on daemon here.
        self.logger.debug("setting up daemon-app")
        app_state.daemon.rest_server.register_routes(ExtensionEndpoints())

    def _teardown_app(self) -> None:
        pass
