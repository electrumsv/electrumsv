from typing import Protocol

class FrozenEditProtocol(Protocol):
    def setText(self, _text: str) -> None:
        ...

    def setFrozen(self, flag: bool) -> None:
        ...


class WizardPageProtocol(Protocol):
    def on_enter(self) -> None:
        ...

    def on_leave(self) -> None:
        ...
