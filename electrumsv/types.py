from __future__ import annotations
import asyncio
import dataclasses
import struct
from types import TracebackType
from typing import Callable, List, NamedTuple, Optional, Protocol, Tuple, Type, TYPE_CHECKING, \
    TypedDict, Union
import uuid

from bitcoinx import Chain, hash_to_hex_str, Header
from mypy_extensions import Arg, DefaultArg

from .constants import AccountCreationType, DatabaseKeyDerivationType, DerivationPath, \
    DerivationType, NetworkServerType, NO_BLOCK_HASH, unpack_derivation_path


if TYPE_CHECKING:
    from .keystore import KeyStore
    from .network_support.api_server import NewServer
    from .standards.tsc_merkle_proof import TSCMerkleProof
    from .wallet_database.types import KeyDataProtocol, NetworkServerRow, MerkleProofRow



@dataclasses.dataclass
class ConnectHeaderlessProofWorkerState:
    header_event: asyncio.Event
    proof_event: asyncio.Event
    header_queue: asyncio.Queue[tuple[Header, Chain]]
    proof_queue: asyncio.Queue[tuple[TSCMerkleProof, MerkleProofRow]]
    block_transactions: dict[bytes, list[tuple[TSCMerkleProof, MerkleProofRow]]]
    requires_reload: bool = False

    def reset(self) -> None:
        while self.header_queue.qsize() > 0:
            self.header_queue.get_nowait()
            self.header_queue.task_done()
        self.header_event.clear()

        while self.proof_queue.qsize() > 0:
            self.proof_queue.get_nowait()
            self.proof_queue.task_done()
        self.proof_event.clear()

        self.block_transactions.clear()


@dataclasses.dataclass(frozen=True)
class DatabaseKeyDerivationData:
    derivation_path: Optional[DerivationPath]
    account_id: Optional[int] = dataclasses.field(default=None)
    masterkey_id: Optional[int] = dataclasses.field(default=None)
    keyinstance_id: Optional[int] = dataclasses.field(default=None)
    source: DatabaseKeyDerivationType = dataclasses.field(default=DatabaseKeyDerivationType.UNKNOWN)

    @classmethod
    def from_key_data(cls, row: KeyDataProtocol,
            source: DatabaseKeyDerivationType=DatabaseKeyDerivationType.UNKNOWN) \
                -> DatabaseKeyDerivationData:
        derivation_path: Optional[DerivationPath] = None
        if row.derivation_type == DerivationType.BIP32_SUBPATH:
            assert isinstance(row.derivation_data2, bytes)
            derivation_path = unpack_derivation_path(row.derivation_data2)
        return DatabaseKeyDerivationData(derivation_path=derivation_path,
            account_id=row.account_id, masterkey_id=row.masterkey_id,
            keyinstance_id=row.keyinstance_id, source=source)


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
        return f'OutputSpend(out_tx_hash="{hash_to_hex_str(self.out_tx_hash)}", ' \
            f'out_index={self.out_index}, in_tx_hash="{hash_to_hex_str(self.in_tx_hash)}", ' \
            f'in_index={self.in_index}, block_hash=' + \
            (f'"{hash_to_hex_str(self.block_hash)}"' if self.block_hash else 'None') +')'


class TipFilterRegistrationEntry(NamedTuple):
    pushdata_hash: bytes
    duration_seconds: int

    def __repr__(self) -> str:
        return f"TipFilterRegistrationEntry({self.pushdata_hash.hex()}, {self.duration_seconds})"


class TipFilterListEntry(NamedTuple):
    pushdata_hash: bytes
    date_created: int
    duration_seconds: int

    def __repr__(self) -> str:
        return f"TipFilterListEntry({self.pushdata_hash.hex()}, {self.date_created}, " \
            f"{self.duration_seconds})"


outpoint_struct = struct.Struct(">32sI")
output_spend_struct = struct.Struct(">32sI32sI32s")
tip_filter_registration_struct = struct.Struct(">32sI")
tip_filter_unregistration_struct = struct.Struct(">32s")
tip_filter_list_struct = struct.Struct(">32sII")


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

    def to_base_key(self) -> "ServerAccountKey":
        if self.account_id is None:
            return self
        return ServerAccountKey(self.url, self.server_type, None)


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


class FeeQuoteTypeFee(TypedDict):
    satoshis: int
    bytes: int


class FeeQuoteTypeEntry(TypedDict):
    feeType: str
    miningFee: FeeQuoteTypeFee
    relayFee: FeeQuoteTypeFee


@dataclasses.dataclass
class TransactionBroadcastContext:
    server_id: int
    credential_id: int | None
    fee_quote_json: str | None


class FeeQuoteCommon(TypedDict):
    fees: list[FeeQuoteTypeEntry]


class FeeEstimatorProtocol(Protocol):
    def get_mapi_server_hint(self) -> ServerAndCredential | None:
        ...

    def estimate_fee(self, transaction_size: TransactionSize) -> int:
        ...


IndefiniteCredentialId = uuid.UUID


class ServerAndCredential(NamedTuple):
    server: NewServer
    credential_id: IndefiniteCredentialId | None


@dataclasses.dataclass
class TransactionFeeContext:
    """
    The selected fee criteria to be used for building a transaction.
    """

    fee_quote: FeeQuoteCommon
    server_and_credential: ServerAndCredential

