from electrumsv.app_state import AppStateProxy

from .app import MerchantApplication


class MerchantAppStateProxy(AppStateProxy):
    def __init__(self, *args) -> None:
        super().__init__(*args)

        self.app = MerchantApplication()

    def has_app(self):
        return True
