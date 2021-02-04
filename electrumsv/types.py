from typing import (Any, Awaitable, Callable, Dict, List, NamedTuple, Optional, TYPE_CHECKING,
    Union)

from bitcoinx import hash_to_hex_str
from mypy_extensions import Arg, DefaultArg

from .constants import ScriptType, SubscriptionOwnerPurpose, SubscriptionType
from .wallet_database.types import TransactionSubscriptionRow

if TYPE_CHECKING:
    from .keystore import KeyStore
    from .wallet import AbstractAccount


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
    tx_rows: List[TransactionSubscriptionRow]


SubscriptionOwnerContextType = Union[SubscriptionKeyScriptHashOwnerContext,
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
    tx_index: int

    def __repr__(self) -> str:
        return f'TxoKeyType("{hash_to_hex_str(self.tx_hash)}",{self.tx_index})'


WaitingUpdateCallback = Callable[[Arg(bool, "advance"), DefaultArg(Optional[str], "message")], None]
