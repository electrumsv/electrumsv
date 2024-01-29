from __future__ import annotations
import asyncio
import dataclasses
import io
import struct
from types import TracebackType
from typing import Callable, Literal, NamedTuple, Protocol, Type, TYPE_CHECKING
from typing_extensions import NotRequired, TypedDict
import uuid

from bitcoinx import Chain, hash_to_hex_str, Header
from mypy_extensions import Arg, DefaultArg

from .constants import AccountCreationType, DatabaseKeyDerivationType, DerivationPath, \
    DerivationType, TxImportFlag, NetworkServerType, NO_BLOCK_HASH, ScriptType, \
    TxFlag, unpack_derivation_path


if TYPE_CHECKING:
    from .keystore import KeyStore
    from .network_support.api_server import NewServer
    from .standards.mapi import MAPIBroadcastResponse
    from .standards.tsc_merkle_proof import TSCMerkleProof
    from .transaction import Transaction
    from .wallet_database.types import AccountRow, AccountPaymentRow,\
        KeyDataProtocol, KeyInstanceRow, MasterKeyRow, MerkleProofRow, NetworkServerRow,\
        PaymentRow, TransactionInputRow, TransactionOutputRow, TransactionRow


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
    derivation_path: DerivationPath|None
    account_id: int|None = dataclasses.field(default=None)
    masterkey_id: int|None = dataclasses.field(default=None)
    keyinstance_id: int|None = dataclasses.field(default=None)
    source: DatabaseKeyDerivationType = dataclasses.field(default=DatabaseKeyDerivationType.UNKNOWN)

    @classmethod
    def from_key_data(cls, row: KeyDataProtocol,
            source: DatabaseKeyDerivationType=DatabaseKeyDerivationType.UNKNOWN) \
                -> DatabaseKeyDerivationData:
        derivation_path: DerivationPath|None = None
        if row.derivation_type == DerivationType.BIP32_SUBPATH:
            assert isinstance(row.derivation_data2, bytes)
            derivation_path = unpack_derivation_path(row.derivation_data2)
        return DatabaseKeyDerivationData(derivation_path=derivation_path,
            account_id=row.account_id, masterkey_id=row.masterkey_id,
            keyinstance_id=row.keyinstance_id, source=source)


class RestorationTransactionKeyUsage(NamedTuple):
    pushdata_hash: bytes
    # This will only be `None` before restoration result generation completes.
    keyinstance_id: int | None
    script_type: ScriptType
    derivation_path: DerivationPath | None = None

class ImportTransactionKeyUsage(NamedTuple):
    pushdata_hash: bytes
    keyinstance_id: int
    script_type: ScriptType

class MissingTransactionMetadata(NamedTuple):
    transaction_hash: bytes
    match_metadatas: set[ImportTransactionKeyUsage]
    with_proof: bool


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
    block_hash: bytes|None

    @classmethod
    def from_network(cls, out_tx_hash: bytes, out_index: int, in_tx_hash: bytes, in_index: int,
            block_hash: bytes|None) -> OutputSpend:
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


ExceptionInfoType = tuple[Type[BaseException], BaseException, TracebackType]

WaitingUpdateCallback = Callable[[Arg(bool, "advance"), DefaultArg(str|None, "message")], None]


class ServerAccountKey(NamedTuple):
    """ For now the each client may have different access to a MAPI server. """
    url: str
    server_type: NetworkServerType
    account_id: int | None

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
    seed: str|None
    # If there is a seed / no parent masterkey, the xpub/xprv are derived from the seed using this.
    # - For master keys with Electrum seeds this will always be 'm'
    # If there is no seed, the xpub/xprv are derived from the parent masterkey using this.
    derivation: str|None
    passphrase: str|None
    label: str|None
    xprv: str|None


class MasterKeyDataElectrumOld(TypedDict):
    seed: str|None
    mpk: str


class MasterKeyDataHardwareCfg(TypedDict):
    mode: int


class MasterKeyDataHardware(TypedDict):
    hw_type: str
    xpub: str
    derivation: str
    label: str|None
    cfg: MasterKeyDataHardwareCfg|None


MultiSignatureMasterKeyDataTypes = MasterKeyDataBIP32 | MasterKeyDataElectrumOld | \
    MasterKeyDataHardware
CosignerListType = list[tuple[DerivationType, MultiSignatureMasterKeyDataTypes]]


_MasterKeyDataMultiSignature = TypedDict(
    '_MasterKeyDataMultiSignature',
    { 'cosigner-keys': CosignerListType },
    total=True,
)

class MasterKeyDataMultiSignature(_MasterKeyDataMultiSignature):
    m: int
    n: int


MasterKeyDataTypes = MasterKeyDataBIP32 | MasterKeyDataElectrumOld | MasterKeyDataHardware | \
    MasterKeyDataMultiSignature


class KeyInstanceDataBIP32SubPath(TypedDict):
    subpath: DerivationPath


class KeyInstanceDataHash(TypedDict):
    hash: str


class KeyInstanceDataPrivateKey(TypedDict):
    pub: str
    prv: str


KeyInstanceDataTypes = KeyInstanceDataBIP32SubPath | KeyInstanceDataHash | \
    KeyInstanceDataPrivateKey


DerivationDataTypes = KeyInstanceDataBIP32SubPath | KeyInstanceDataHash | \
    KeyInstanceDataPrivateKey | MasterKeyDataTypes


class KeyStoreResult(NamedTuple):
    account_creation_type: AccountCreationType
    keystore: KeyStore|None = None


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


class FeeQuoteTypeEntry1(TypedDict):
    feeType: str
    miningFee: FeeQuoteTypeFee

class FeeQuoteTypeEntry2(TypedDict):
    data: FeeQuoteTypeFee
    standard: FeeQuoteTypeFee

@dataclasses.dataclass
class PaymentCtx:
    # Input/output.
    payment_id: int|None = None
    # Input.
    timestamp: int = 0
    description: str|None = None
    # Output.
    account_ids: set[int] = dataclasses.field(default_factory=set)

@dataclasses.dataclass
class TxImportCtx:
    # If not set by the higher level importing code this will be replaced with the current time.
    date_created: int = 0
    # Modifies the imported transaction outputs and links them to existing allocated keyinstances.
    output_key_usage: dict[int, tuple[int, ScriptType]] = dataclasses.field(default_factory=dict)
    flags: TxImportFlag = TxImportFlag.UNSET
    # Updated by the database import and returned to the caller.
    has_spend_conflicts: bool = False
    feeQuote: FeeQuoteTypeFee|None = None


class TxImportEntry(NamedTuple):
    tx_hash: bytes
    tx: Transaction
    flags: TxFlag
    block_height: int
    block_hash: bytes|None
    block_position: int|None

@dataclasses.dataclass
class TransactionBroadcastContext:
    server_id: int
    credential_id: int | None
    fee_quote_json: str | None


@dataclasses.dataclass
class BroadcastResult:
    success: bool
    mapi_response: MAPIBroadcastResponse|None
    error_text: str|None


IndefiniteCredentialId = uuid.UUID


class ServerAndCredential(NamedTuple):
    server: NewServer
    credential_id: IndefiniteCredentialId | None


@dataclasses.dataclass
class MAPIFeeContext:
    """
    The selected fee criteria to be used for building a transaction.
    """

    fee_quote: FeeQuoteTypeEntry2
    server_and_credential: ServerAndCredential


class NetworkStatusDict(TypedDict):
    blockchain_height: int

class WalletStatusDict(TypedDict):
    servers: dict[str, list[str]]

class DaemonStatusDict(TypedDict):
    blockchain_height: NotRequired[int]
    network: Literal["online", "offline"]
    path: str
    version: str
    wallets: dict[str, WalletStatusDict]

class ChunkState(NamedTuple):
    length_offset: int

class BackupWritingProtocol(Protocol):
    @staticmethod
    def write_chunk_start(stream: io.BytesIO, chunk_id: bytes) -> ChunkState: ...
    @staticmethod
    def write_chunk_end(stream: io.BytesIO, state: ChunkState) -> None: ...
    @staticmethod
    def write_backup_header_to_stream(stream: io.BytesIO, db_migration: int) -> None: ...
    @staticmethod
    def write_masterkey_to_stream(stream: io.BytesIO, row: MasterKeyRow) -> None: ...
    @staticmethod
    def write_account_to_stream(stream: io.BytesIO, row: AccountRow) -> None: ...
    @staticmethod
    def write_payment_to_stream(stream: io.BytesIO, row: PaymentRow,
        link_rows: list[AccountPaymentRow]) -> None: ...
    @staticmethod
    def write_account_payment_to_stream(stream: io.BytesIO, row: AccountPaymentRow) -> None: ...
    @staticmethod
    def write_transaction_to_stream(stream: io.BytesIO, row: TransactionRow,
            input_rows: list[TransactionInputRow], output_rows: list[TransactionOutputRow],
            key_rows: list[KeyInstanceRow]) -> None: ...
    @staticmethod
    def write_transaction_input_to_stream(stream: io.BytesIO, row: TransactionInputRow) -> None:
        ...
    @staticmethod
    def write_transaction_output_to_stream(stream: io.BytesIO, row: TransactionOutputRow) -> None:
        ...
    @staticmethod
    def write_keyinstances_to_stream(stream: io.BytesIO, rows: list[KeyInstanceRow]) -> None: ...
