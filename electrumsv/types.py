import dataclasses
from types import TracebackType
from typing import Any, Callable, cast, Coroutine, Dict, List, NamedTuple, Optional, Tuple, \
    Type, TYPE_CHECKING, TypedDict, Union
import uuid

from bitcoinx import hash_to_hex_str
from mypy_extensions import Arg, DefaultArg

from .constants import DatabaseKeyDerivationType, DerivationType, DerivationPath, \
    NetworkServerType, ScriptType, SubscriptionOwnerPurpose, SubscriptionType, \
    unpack_derivation_path


if TYPE_CHECKING:
    from .wallet_database.types import KeyDataProtocol, NetworkServerRow, NetworkServerAccountRow, \
        TransactionSubscriptionRow


ElectrumXHistoryEntry = Dict[str, Union[int, str]]
ElectrumXHistoryList = List[ElectrumXHistoryEntry]


@dataclasses.dataclass(frozen=True)
class SubscriptionDerivationData:
    masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data2: Optional[bytes]


@dataclasses.dataclass(frozen=True)
class DatabaseKeyDerivationData:
    derivation_path: Optional[DerivationPath]
    account_id: Optional[int] = dataclasses.field(default=None)
    masterkey_id: Optional[int] = dataclasses.field(default=None)
    keyinstance_id: Optional[int] = dataclasses.field(default=None)
    source: DatabaseKeyDerivationType = dataclasses.field(default=DatabaseKeyDerivationType.UNKNOWN)

    @classmethod
    def from_key_data(cls, row: "KeyDataProtocol",
            source: DatabaseKeyDerivationType=DatabaseKeyDerivationType.UNKNOWN) \
                -> "DatabaseKeyDerivationData":
        derivation_path: Optional[DerivationPath] = None
        if row.derivation_type == DerivationType.BIP32_SUBPATH:
            assert isinstance(row.derivation_data2, bytes)
            derivation_path = unpack_derivation_path(row.derivation_data2)
        return DatabaseKeyDerivationData(derivation_path=derivation_path,
            account_id=row.account_id, masterkey_id=row.masterkey_id,
            keyinstance_id=row.keyinstance_id, source=source)


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

    def merge(self, other_object: object) -> None:
        assert type(self) is type(other_object)
        raise NotImplementedError


class SubscriptionTransactionScriptHashOwnerContext(NamedTuple):
    tx_rows: List["TransactionSubscriptionRow"]

    def merge(self, other_object: object) -> None:
        """
        This will happen for reused keys, where there are multiple transactions using those keys
        for the same scripts.
        """
        assert type(self) is type(other_object)
        other = cast(SubscriptionTransactionScriptHashOwnerContext, other_object)
        for tx_row in other.tx_rows:
            if tx_row not in self.tx_rows:
                self.tx_rows.append(tx_row)


class SubscriptionScannerScriptHashOwnerContext(NamedTuple):
    value: Any

    def merge(self, other_object: object) -> None:
        assert type(self) is type(other_object)
        raise NotImplementedError


class SubscriptionDerivationScriptHashOwnerContext(NamedTuple):
    derivation_type_data: SubscriptionDerivationData
    script_type: ScriptType

    def merge(self, other_object: object) -> None:
        assert type(self) is type(other_object)
        raise NotImplementedError


SubscriptionOwnerContextType = Union[
    SubscriptionKeyScriptHashOwnerContext,
    SubscriptionScannerScriptHashOwnerContext,
    SubscriptionTransactionScriptHashOwnerContext,
    SubscriptionDerivationScriptHashOwnerContext]


class SubscriptionEntry(NamedTuple):
    key: SubscriptionKey
    owner_context: Optional[SubscriptionOwnerContextType]


class HashSubscriptionEntry(NamedTuple):
    entry_id: int
    hash_value: bytes


HashSubscriptionCallback = Callable[[List[HashSubscriptionEntry]],
    Coroutine[Any, Any, None]]
ScriptHashResultCallback = Callable[[SubscriptionKey, SubscriptionOwnerContextType,
    ElectrumXHistoryList], Coroutine[Any, Any, None]]
PushdataHashResultCallback = Callable[[SubscriptionKey, SubscriptionOwnerContextType,
    bytes], Coroutine[Any, Any, None]]


@dataclasses.dataclass
class SubscriptionCallbacks:
    script_hash_result_callback: Optional[ScriptHashResultCallback] = None
    pushdata_hash_result_callback: Optional[PushdataHashResultCallback] = None


class Outpoint(NamedTuple):
    tx_hash: bytes
    txo_index: int

    def __repr__(self) -> str:
        return f'Outpoint("{hash_to_hex_str(self.tx_hash)}",{self.txo_index})'


ExceptionInfoType = Tuple[Type[BaseException], BaseException, TracebackType]

WaitingUpdateCallback = Callable[[Arg(bool, "advance"), DefaultArg(Optional[str], "message")], None]


class ServerAccountKey(NamedTuple):
    """ For now the each client may have different access to a MAPI server. """
    url: str
    server_type: NetworkServerType
    account_id: int = -1

    @staticmethod
    def groupby(key: "ServerAccountKey") -> "ServerAccountKey":
        return ServerAccountKey(key.url, key.server_type)

    @classmethod
    def for_server_row(cls, row: "NetworkServerRow") -> "ServerAccountKey":
        return cls(row.url, row.server_type)

    @classmethod
    def for_account_row(cls, row: "NetworkServerAccountRow") -> "ServerAccountKey":
        return cls(row.url, row.server_type, row.account_id)

    def to_server_key(self) -> "ServerAccountKey":
        if self.account_id == -1:
            return self
        return ServerAccountKey(self.url, self.server_type)


IndefiniteCredentialId = uuid.UUID


class NetworkServerState(NamedTuple):
    key: ServerAccountKey
    credential_id: Optional[IndefiniteCredentialId]
    # MAPI specific, used for JSONEnvelope serialised transaction fee quotes.
    mapi_fee_quote_json: Optional[str] = None
    date_last_try: int = 0
    date_last_good: int = 0


class MasterKeyDataBIP32(TypedDict):
    xpub: str
    seed: Optional[str]
    passphrase: Optional[str]
    label: Optional[str]
    xprv: Optional[str]


class MasterKeyDataElectrumOld(TypedDict):
    seed: Optional[str]
    mpk: str


class MasterKeyDataHardwareCfg(TypedDict):
    mode: int


class MasterKeyDataHardware(TypedDict):
    hw_type: str
    xpub: str
    derivation: str
    label: Optional[str]
    cfg: Optional[MasterKeyDataHardwareCfg]


MultiSignatureMasterKeyDataTypes = Union[MasterKeyDataBIP32, MasterKeyDataElectrumOld,
    MasterKeyDataHardware]
CosignerListType = List[Tuple[DerivationType, MultiSignatureMasterKeyDataTypes]]


_MasterKeyDataMultiSignature = TypedDict(
    '_MasterKeyDataMultiSignature',
    { 'cosigner-keys': CosignerListType },
    total=True,
)

class MasterKeyDataMultiSignature(_MasterKeyDataMultiSignature):
    m: int
    n: int


MasterKeyDataTypes = Union[MasterKeyDataBIP32, MasterKeyDataElectrumOld,
    MasterKeyDataHardware, MasterKeyDataMultiSignature]


class KeyInstanceDataBIP32SubPath(TypedDict):
    subpath: DerivationPath


class KeyInstanceDataHash(TypedDict):
    hash: str


class KeyInstanceDataPrivateKey(TypedDict):
    pub: str
    prv: str


KeyInstanceDataTypes = Union[KeyInstanceDataBIP32SubPath, KeyInstanceDataHash,
    KeyInstanceDataPrivateKey]


DerivationDataTypes = Union[KeyInstanceDataTypes, MasterKeyDataTypes]


class TransactionSize(NamedTuple):
    # This follow the breakdown in different transaction sizes used by MAPI.
    standard_size: int                              # feeType = "standard"
    data_size: int = 0                              # feeType = "data"
    # Duplicated to avoid typing warnings when we assign `__radd__ = __add__`
    def __add__(self, other: object) -> "TransactionSize":
        if isinstance(other, int):
            return TransactionSize(self.standard_size + other, self.data_size)
        elif isinstance(other, TransactionSize):
            return TransactionSize(self.standard_size + other.standard_size,
                self.data_size + other.data_size)
        else:
            raise NotImplementedError(f"Do not support {type(other)}")
    def __radd__(self, other: object) -> "TransactionSize":
        if isinstance(other, int):
            return TransactionSize(self.standard_size + other, self.data_size)
        elif isinstance(other, TransactionSize):
            return TransactionSize(self.standard_size + other.standard_size,
                self.data_size + other.data_size)
        else:
            raise NotImplementedError(f"Do not support {type(other)}")
    def __mul__(self, other: object) -> "TransactionSize":
        assert isinstance(other, int)
        return TransactionSize(self.standard_size * other, self.data_size * other)
    # Duplicated to avoid typing warnings when we assign `__rmul__ = __mul__`
    def __rmul__(self, other: object) -> "TransactionSize":
        assert isinstance(other, int)
        return TransactionSize(self.standard_size * other, self.data_size * other)


TransactionFeeEstimator = Callable[[TransactionSize], int]
