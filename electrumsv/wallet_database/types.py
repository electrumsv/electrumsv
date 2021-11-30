import dataclasses
from typing import Any, Dict, List, NamedTuple, Optional, Protocol, Sequence, Set, Tuple, Union

from bitcoinx import hash_to_hex_str

from ..constants import (AccountTxFlags, DerivationType, KeyInstanceFlag, NetworkServerFlag,
    NetworkServerType, PaymentFlag, ScriptType, TransactionOutputFlag, TxFlags, WalletEventFlag,
    WalletEventType)
from ..types import MasterKeyDataTypes


class AccountRow(NamedTuple):
    account_id: int
    default_masterkey_id: Optional[int]
    default_script_type: ScriptType
    account_name: str


class AccountTransactionDescriptionRow(NamedTuple):
    account_id: int
    tx_hash: bytes
    description: Optional[str]


class AccountTransactionRow(NamedTuple):
    account_id: int
    tx_hash: bytes
    flags: AccountTxFlags
    description: Optional[str]


class HistoryListRow(NamedTuple):
    tx_hash: bytes
    tx_flags: TxFlags
    block_height: Optional[int]
    block_position: Optional[int]
    description: Optional[str]
    value_delta: int
    date_created: int


class InvoiceAccountRow(NamedTuple):
    invoice_id: int
    payment_uri: str
    description: Optional[str]
    flags: PaymentFlag
    value: int
    date_expires: Optional[int]
    date_created: int


class InvoiceRow(NamedTuple):
    invoice_id: int
    account_id: int
    tx_hash: Optional[bytes]
    payment_uri: str
    description: Optional[str]
    flags: PaymentFlag
    value: int
    invoice_data: bytes
    date_expires: Optional[int]
    date_created: int = -1


class KeyDataProtocol(Protocol):
    # Overlapping common output/spendable type field.
    @property
    def keyinstance_id(self) -> int:
        ...
    # Spendable type fields.
    @property
    def account_id(self) -> int:
        pass
    @property
    def masterkey_id(self) -> Optional[int]:
        pass
    @property
    def derivation_type(self) -> DerivationType:
        pass
    @property
    def derivation_data2(self) -> Optional[bytes]:
        pass


@dataclasses.dataclass
class KeyData:
    """
    At the time of writing, no database operation uses this. It is a helper abstraction that
    allows non-database types that do not have to be contiguous immutable rows to encapsulate the
    key data fields.
    """
    keyinstance_id: int                 # Overlapping common output/spendable type field.
    account_id: int                     # Spendable type field.
    masterkey_id: Optional[int]         # Spendable type field.
    derivation_type: DerivationType     # Spendable type field.
    derivation_data2: Optional[bytes]   # Spendable type field.


class KeyInstanceFlagRow(NamedTuple):
    keyinstance_id: int
    flags: KeyInstanceFlag


class KeyInstanceFlagChangeRow(NamedTuple):
    keyinstance_id: int
    flags_old: KeyInstanceFlag
    flags_new: KeyInstanceFlag=KeyInstanceFlag.NONE


class KeyInstanceRow(NamedTuple):
    keyinstance_id: int                 # Overlapping common output/spendable type field.
    account_id: int                     # Spendable type field.
    masterkey_id: Optional[int]         # Spendable type field.
    derivation_type: DerivationType     # Spendable type field.
    derivation_data: bytes
    derivation_data2: Optional[bytes]   # Spendable type field.
    flags: KeyInstanceFlag
    description: Optional[str]


class KeyInstanceScriptHashRow(NamedTuple):
    keyinstance_id: int
    script_type: ScriptType
    script_hash: bytes


class KeyListRow(NamedTuple):
    account_id: int
    keyinstance_id: int                 # Overlapping common output/spendable type field.
    masterkey_id: Optional[int]         # Spendable type field.
    derivation_type: DerivationType     # Spendable type field.
    derivation_data: bytes
    derivation_data2: Optional[bytes]   # Spendable type field.
    flags: KeyInstanceFlag
    description: Optional[str]
    date_updated: int
    txo_value: int
    txo_count: int


class MasterKeyRow(NamedTuple):
    masterkey_id: int
    parent_masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes


# WARNING The order of the fields in this data structure are implicitly linked to the query.
class NetworkServerRow(NamedTuple):
    url: str
    server_type: NetworkServerType
    encrypted_api_key: Optional[str] = None
    flags: NetworkServerFlag = NetworkServerFlag.NONE
    # MAPI specific: used for JSONEnvelope serialised transaction fee quotes.
    mapi_fee_quote_json: Optional[str] = None
    date_last_try: int = 0
    date_last_good: int = 0
    date_created: int = -1
    date_updated: int = -1


class NetworkServerAccountRow(NamedTuple):
    url: str
    server_type: NetworkServerType
    account_id: int
    encrypted_api_key: Optional[str] = None
    mapi_fee_quote_json: Optional[str] = None
    date_last_try: int = 0
    date_last_good: int = 0
    date_created: int = -1
    date_updated: int = -1


class PasswordUpdateResult(NamedTuple):
    password_token: str
    account_private_key_updates: Dict[int, List[Tuple[int, str]]]
    masterkey_updates: List[Tuple[int, DerivationType, MasterKeyDataTypes]]


class PaymentRequestReadRow(NamedTuple):
    paymentrequest_id: int
    keyinstance_id: int
    state: PaymentFlag
    requested_value: Optional[int]
    received_value: Optional[int]
    expiration: Optional[int]
    description: Optional[str]
    date_created: int = -1


class PaymentRequestRow(NamedTuple):
    paymentrequest_id: int
    keyinstance_id: int
    state: PaymentFlag
    requested_value: Optional[int]
    expiration: Optional[int]
    description: Optional[str]
    date_created: int = -1


class PaymentRequestUpdateRow(NamedTuple):
    state: PaymentFlag
    value: Optional[int]
    expiration: Optional[int]
    description: Optional[str]
    paymentrequest_id: int


SpendConflictType = Tuple[bytes, int, bytes, int]


class TransactionBlockRow(NamedTuple):
    block_height: int
    block_hash: Optional[bytes]
    tx_hash: bytes


class TransactionDeltaSumRow(NamedTuple):
    account_id: int
    total: int
    match_count: int


class TransactionDescriptionResult(NamedTuple):
    tx_hash: bytes
    description: str


class TransactionExistsRow(NamedTuple):
    tx_hash: bytes
    flags: TxFlags
    block_height: int
    account_id: Optional[int]


class TransactionInputAddRow(NamedTuple):
    tx_hash: bytes
    txi_index: int
    spent_tx_hash: bytes
    spent_txo_index: int
    sequence: int
    flags: int
    script_offset: int
    script_length: int
    date_created: int
    date_updated: int


class TransactionLinkState:
    # Parameters.
    rollback_on_spend_conflict: bool = False
    # Results.
    has_spend_conflicts: bool = False
    account_ids: Optional[Set[int]] = None


class TransactionMetadata(NamedTuple):
    block_height: int
    block_position: Optional[int]
    fee_value: Optional[int]
    date_created: int


class TransactionOutputCommonProtocol(Protocol):
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: Optional[int]               # Overlapping common output/spendable type field.
    flags: TransactionOutputFlag
    script_type: ScriptType


class TransactionOutputAddRow(NamedTuple):
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: Optional[int]               # Overlapping common output/spendable type field.
    script_type: ScriptType
    flags: TransactionOutputFlag
    script_hash: bytes
    script_offset: int
    script_length: int
    date_created: int
    date_updated: int


class TransactionOutputShortRow(NamedTuple):
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: Optional[int]               # Overlapping common output/spendable type field.
    flags: TransactionOutputFlag
    script_type: ScriptType
    # Extension fields for this type.
    script_hash: bytes


class TransactionOutputFullRow(NamedTuple):
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: Optional[int]               # Overlapping common output/spendable type field.
    flags: TransactionOutputFlag
    script_type: ScriptType
    # Extension fields for this type.
    script_hash: bytes
    script_offset: int
    script_length: int
    spending_tx_hash: Optional[bytes]
    spending_txi_index: Optional[int]


class AccountTransactionOutputSpendableRow(NamedTuple):
    """
    Transaction output data with the additional key instance information required for spending it.
    """
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: Optional[int]               # Overlapping common output/spendable type field.
    script_type: ScriptType
    flags: TransactionOutputFlag
    # KeyInstance fields.
    account_id: int                             # Spendable type field.
    masterkey_id: Optional[int]                 # Spendable type field.
    derivation_type: DerivationType             # Spendable type field.
    derivation_data2: Optional[bytes]           # Spendable type field.


class AccountTransactionOutputSpendableRowExtended(NamedTuple):
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: Optional[int]               # Overlapping common output/spendable type field.
    script_type: ScriptType
    flags: TransactionOutputFlag
    # KeyInstance fields.
    account_id: int                             # Spendable type field.
    masterkey_id: Optional[int]                 # Spendable type field.
    derivation_type: DerivationType             # Spendable type field.
    derivation_data2: Optional[bytes]           # Spendable type field.
    # Extension fields for this type.
    tx_flags: TxFlags
    block_height: Optional[int]


class TransactionOutputSpendableRow(NamedTuple):
    """
    Transaction output data with the additional key instance information required for spending it.
    """
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: Optional[int]               # Overlapping common output/spendable type field.
    script_type: ScriptType
    flags: TransactionOutputFlag
    # KeyInstance fields.
    account_id: Optional[int]                   # Spendable type field.
    masterkey_id: Optional[int]                 # Spendable type field.
    derivation_type: Optional[DerivationType]   # Spendable type field.
    derivation_data2: Optional[bytes]           # Spendable type field.

    # def to_account_row(self) -> AccountTransactionOutputSpendableRow:
    #     assert self.account_id is not None
    #     assert self.derivation_type is not None
    #     return AccountTransactionOutputSpendableRow(tx_hash=self.tx_hash,
    #           txo_index=self.txo_index,
    #         value=self.value, keyinstance_id=self.keyinstance_id, script_type=self.script_type,
    #         flags=self.flags, account_id=self.account_id, masterkey_id=self.masterkey_id,
    #         derivation_type=self.derivation_type, derivation_data2=self.derivation_data2)


# NOTE(TypeUnionsForCommonFields) NamedTuple does not support subclassing, Mypy recommends data
# classes but data classes do not do proper immutability. There's a larger problem here in that
# all our database row classes require copying of the tuple that the database query returns and
# that would ideally factor into any change in storage type. Anyway, this is the reason for these
# union types. The type checker should pick out use of any attributes that are not common to all
# included types.

# Types which have the common output fields.
TransactionOutputTypes = Union[
    TransactionOutputShortRow,
    TransactionOutputFullRow,
    TransactionOutputSpendableRow,
    AccountTransactionOutputSpendableRowExtended]
# Some lower comment.


class TransactionOutputSpendableProtocol(Protocol):
    # Standard transaction output fields.
    @property
    def tx_hash(self) -> bytes:
        pass
    @property
    def txo_index(self) -> int:
        pass
    @property
    def value(self) -> int:
        pass
    @property
    def script_type(self) -> ScriptType:
        pass
    @property
    def keyinstance_id(self) -> Optional[int]:
        pass
    @property
    def account_id(self) ->  int:
        pass
    @property
    def masterkey_id(self) ->  Optional[int]:
        pass
    @property
    def derivation_type(self) ->  DerivationType:
        pass
    @property
    def derivation_data2(self) -> Optional[bytes]:
        pass


class TransactionRow(NamedTuple):
    tx_hash: bytes
    tx_bytes: Optional[bytes]
    flags: TxFlags
    block_hash: Optional[bytes]
    block_height: int
    block_position: Optional[int]
    fee_value: Optional[int]
    description: Optional[str]
    version: Optional[int]
    locktime: Optional[int]
    date_created: int=-1
    date_updated: int=-1


class TransactionSubscriptionRow(NamedTuple):
    tx_hash: bytes
    # 1 = Transaction output, 2 = Transaction output.
    put_type: int
    # TODO Document why this is present.
    keyinstance_id: int
    # TODO Document why this is present.
    script_hash: bytes

    def __repr__(self) -> str:
        return f"TransactionSubscriptionRow(tx_hash='{hash_to_hex_str(self.tx_hash)}' " \
            f"put_type={self.put_type} keyinstance_id={self.keyinstance_id} " \
            f"script_hash='{hash_to_hex_str(self.script_hash)}')"


class TransactionValueRow(NamedTuple):
    tx_hash: bytes
    value: int
    flags: TxFlags
    block_height: Optional[int]
    date_created: int
    date_updated: int


class TxProof(NamedTuple):
    position: int
    branch: Sequence[bytes]


class TxProofResult(NamedTuple):
    tx_hash: bytes
    proof: Optional[bytes]

    def unpack_proof(self) -> TxProof:
        assert self.proof is not None
        from .util import unpack_proof
        return unpack_proof(self.proof)


class WalletBalance(NamedTuple):
    confirmed: int = 0
    unconfirmed: int = 0
    unmatured: int = 0
    allocated: int = 0

    def __add__(self, other: object) -> "WalletBalance":
        if not isinstance(other, WalletBalance):
            raise NotImplementedError
        return WalletBalance(self.confirmed + other.confirmed, self.unconfirmed + other.unconfirmed,
            self.unmatured + other.unmatured, self.allocated + other.allocated)

    def __radd__(self, other: object) -> "WalletBalance":
        if not isinstance(other, WalletBalance):
            raise NotImplementedError
        return WalletBalance(self.confirmed + other.confirmed, self.unconfirmed + other.unconfirmed,
            self.unmatured + other.unmatured, self.allocated + other.allocated)


class WalletDataRow(NamedTuple):
    key: str
    value: Any


class WalletEventRow(NamedTuple):
    event_id: int
    event_type: WalletEventType
    account_id: Optional[int]
    # NOTE(rt12): sqlite3 python module only allows custom typing if the column name is unique.
    event_flags: WalletEventFlag
    date_created: int
