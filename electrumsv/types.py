from typing import Callable, NamedTuple, Optional, TYPE_CHECKING

from bitcoinx import hash_to_hex_str
from mypy_extensions import Arg, DefaultArg

if TYPE_CHECKING:
    from .keystore import KeyStore
    from .wallet import AbstractAccount


class TxoKeyType(NamedTuple):
    tx_hash: bytes
    tx_index: int

    def __repr__(self) -> str:
        return f'TxoKeyType("{hash_to_hex_str(self.tx_hash)}",{self.tx_index})'


WaitingUpdateCallback = Callable[[Arg(bool, "advance"), DefaultArg(Optional[str], "message")], None]
