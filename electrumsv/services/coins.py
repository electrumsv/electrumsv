from typing import List, TYPE_CHECKING
import weakref

from electrumsv.types import TxoKeyType
from electrumsv.wallet_database.tables import TransactionOutputRow

if TYPE_CHECKING:
    from electrumsv.wallet import Wallet

class CoinService:
    def __init__(self, wallet: "Wallet") -> None:
        self._wallet = weakref.proxy(wallet)

    def get_outputs(self, txo_keys: List[TxoKeyType]) -> List[TransactionOutputRow]:
        with self._wallet.get_transactionoutput_table() as table:
            return table.read_txokeys(txo_keys)

