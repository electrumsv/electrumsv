from __future__ import annotations
import dataclasses
import struct
from types import TracebackType
from typing import Any, Callable, Coroutine, List, NamedTuple, Optional, Tuple, \
    Type, TYPE_CHECKING, TypedDict, Union
import uuid

from bitcoinx import hash_to_hex_str
from mypy_extensions import Arg, DefaultArg

from .constants import AccountCreationType, DatabaseKeyDerivationType, DerivationType, \
    DerivationPath, NetworkServerType, NO_BLOCK_HASH, ScriptType, SubscriptionOwnerPurpose, \
    SubscriptionType, unpack_derivation_path


if TYPE_CHECKING:
    from .keystore import KeyStore
    from .wallet_database.types import KeyDataProtocol, NetworkServerRow


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
    SubscriptionDerivationScriptHashOwnerContext]


class SubscriptionEntry(NamedTuple):
    key: SubscriptionKey
    owner_context: Optional[SubscriptionOwnerContextType]


class HashSubscriptionEntry(NamedTuple):
    entry_id: int
    hash_value: bytes


class ScriptHashHistoryEntry(NamedTuple):
    something: int

ScriptHashHistoryList = List[ScriptHashHistoryEntry]


HashSubscriptionCallback = Callable[[List[HashSubscriptionEntry]],
    Coroutine[Any, Any, None]]
ScriptHashResultCallback = Callable[[SubscriptionKey, SubscriptionOwnerContextType,
    ScriptHashHistoryList], Coroutine[Any, Any, None]]
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


class OutputSpend(NamedTuple):
    out_tx_hash: bytes
    out_index: int
    in_tx_hash: bytes
    in_index: int
    block_hash: Optional[bytes]

    @classmethod
    def from_network(cls, out_tx_hash: bytes, out_index: int, in_tx_hash: bytes, in_index: int,
            block_hash: Optional[bytes]) -> OutputSpend:
        """
        Convert the binary representation to the Python representation.
        """
        if block_hash == NO_BLOCK_HASH:
            block_hash = None
        return OutputSpend(out_tx_hash, out_index, in_tx_hash, in_index, block_hash)

    def __repr__(self) -> str:
        return f'OutputSpend("{hash_to_hex_str(self.out_tx_hash)}", {self.out_index}, ' \
            f'"{hash_to_hex_str(self.in_tx_hash)}", {self.in_index}, ' + \
            (f'"{hash_to_hex_str(self.block_hash)}"' if self.block_hash else 'None') +')'


OUTPOINT_FORMAT = ">32sI"
outpoint_struct = struct.Struct(OUTPOINT_FORMAT)
outpoint_struct_size = outpoint_struct.size

OUTPUT_SPEND_FORMAT = ">32sI32sI32s"
output_spend_struct = struct.Struct(OUTPUT_SPEND_FORMAT)
output_spend_struct_size = output_spend_struct.size


ExceptionInfoType = Tuple[Type[BaseException], BaseException, TracebackType]

WaitingUpdateCallback = Callable[[Arg(bool, "advance"), DefaultArg(Optional[str], "message")], None]


class ServerAccountKey(NamedTuple):
    """ For now the each client may have different access to a MAPI server. """
    url: str
    server_type: NetworkServerType
    account_id: Optional[int]

    @staticmethod
    def groupby(key: "ServerAccountKey") -> "ServerAccountKey":
        return ServerAccountKey(key.url, key.server_type, None)

    @classmethod
    def from_row(cls, row: "NetworkServerRow") -> "ServerAccountKey":
        return cls(row.url, row.server_type, row.account_id)

    def to_server_key(self) -> "ServerAccountKey":
        if self.account_id is None:
            return self
        return ServerAccountKey(self.url, self.server_type, None)


IndefiniteCredentialId = uuid.UUID


class NetworkServerState(NamedTuple):
    server_id: int
    key: ServerAccountKey
    credential_id: Optional[IndefiniteCredentialId]
    # MAPI specific, used for JSONEnvelope serialised transaction fee quotes.
    mapi_fee_quote_json: Optional[str] = None
    date_last_try: int = 0
    date_last_good: int = 0


class MasterKeyDataBIP32(TypedDict):
    xpub: str
    seed: Optional[str]
    # If there is a seed / no parent masterkey, the xpub/xprv are derived from the seed using this.
    # - For master keys with Electrum seeds this will always be 'm'
    # If there is no seed, the xpub/xprv are derived from the parent masterkey using this.
    derivation: Optional[str]
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


class KeyStoreResult(NamedTuple):
    account_creation_type: AccountCreationType
    keystore: Optional[KeyStore] = None
    account_id: int = -1


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
