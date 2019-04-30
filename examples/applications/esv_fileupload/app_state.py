from electrumsv.app_state import AppStateProxy

from .app import FileUploadApplication


class LocalAppStateProxy(AppStateProxy):
    def __init__(self, *args) -> None:
        super().__init__(*args)

        self.app = FileUploadApplication()

    def has_app(self):
        return True
