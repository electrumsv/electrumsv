from electrumsv.async_ import ASync
from electrumsv.app_state import AppStateProxy

from .app import RESTAPIApplication


class LocalAppStateProxy(AppStateProxy):
    def __init__(self, *args) -> None:
        super().__init__(*args)
        self.async_ = ASync()
        self.app = RESTAPIApplication()

    def has_app(self):
        return True
