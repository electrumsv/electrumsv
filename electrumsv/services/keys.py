from typing import Sequence, List, Optional, TYPE_CHECKING
import weakref

from electrumsv.wallet_database.tables import TransactionDeltaKeySummaryRow

if TYPE_CHECKING:
    from electrumsv.wallet import AbstractAccount

class KeyService:
    def __init__(self, account: "AbstractAccount") -> None:
        self._account = weakref.proxy(account)

    def get_key_summaries(self, keyinstance_ids: Optional[Sequence[int]]=None) \
            -> List[TransactionDeltaKeySummaryRow]:
        wallet = self._account.get_wallet()
        with wallet.get_transaction_delta_table() as table:
            return table.read_key_summary(self._account.get_id(), keyinstance_ids)

