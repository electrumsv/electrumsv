from typing import Any, Awaitable, Callable, Dict, List, NamedTuple, Optional, TYPE_CHECKING, Union

from bitcoinx import hash_to_hex_str
from mypy_extensions import Arg, DefaultArg

from .constants import NetworkServerType, ScriptType, SubscriptionOwnerPurpose, SubscriptionType


if TYPE_CHECKING:
    from .wallet_database.types import TransactionSubscriptionRow


ElectrumXHistoryEntry = Dict[str, Union[int, str]]
ElectrumXHistoryList = List[ElectrumXHistoryEntry]


class SubscriptionOwner(NamedTuple):
    wallet_id: int
    account_id: int
    purpose: SubscriptionOwnerPurpose


class SubscriptionKey(NamedTuple):
    value_type: SubscriptionType
    value: Any


class SubscriptionKeyScriptHashOwnerContext(NamedTuple):
    keyinstance_id: int
    script_type: ScriptType


class SubscriptionTransactionScriptHashOwnerContext(NamedTuple):
    tx_rows: List["TransactionSubscriptionRow"]


class SubscriptionScannerScriptHashOwnerContext(NamedTuple):
    value: Any


SubscriptionOwnerContextType = Union[SubscriptionKeyScriptHashOwnerContext,
    SubscriptionScannerScriptHashOwnerContext,
    SubscriptionTransactionScriptHashOwnerContext]


class SubscriptionEntry(NamedTuple):
    key: SubscriptionKey
    owner_context: Optional[SubscriptionOwnerContextType]


class ScriptHashSubscriptionEntry(NamedTuple):
    entry_id: int
    script_hash: bytes


ScriptHashSubscriptionCallback = Callable[[List[ScriptHashSubscriptionEntry]],
    Awaitable[None]]
ScriptHashResultCallback = Callable[[SubscriptionKey, SubscriptionOwnerContextType,
    ElectrumXHistoryList], Awaitable[None]]


class TxoKeyType(NamedTuple):
    tx_hash: bytes
    txo_index: int

    def __repr__(self) -> str:
        return f'TxoKeyType("{hash_to_hex_str(self.tx_hash)}",{self.txo_index})'


WaitingUpdateCallback = Callable[[Arg(bool, "advance"), DefaultArg(Optional[str], "message")], None]


class ServerAccountKey(NamedTuple):
    """ For now the each client may have different access to a MAPI server. """
    url: str
    server_type: NetworkServerType
    account_id: int = -1

    @staticmethod
    def groupby(key: "ServerAccountKey") -> "ServerAccountKey":
        return ServerAccountKey(key.url, key.server_type)
