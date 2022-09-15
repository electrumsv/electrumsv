import json
import dataclasses
from datetime import datetime, timezone
from typing import Any, NamedTuple, Protocol, Union

from ..constants import (AccountFlags, AccountTxFlags, DerivationType, KeyInstanceFlag,
    MAPIBroadcastFlag, MasterKeyFlags, NetworkServerFlag, NetworkServerType, PaymentFlag,
    PeerChannelAccessTokenFlag, PeerChannelMessageFlag, PushDataMatchFlag,
    PushDataHashRegistrationFlag, ScriptType,
    ServerPeerChannelFlag, TransactionOutputFlag, TxFlags, WalletEventFlag, WalletEventType)
from ..types import MasterKeyDataTypes


class AccountRow(NamedTuple):
    account_id: int
    default_masterkey_id: int | None
    default_script_type: ScriptType
    account_name: str
    flags: AccountFlags
    blockchain_server_id: int | None
    peer_channel_server_id: int | None


class AccountTransactionDescriptionRow(NamedTuple):
    account_id: int
    tx_hash: bytes
    description: str | None


class AccountTransactionRow(NamedTuple):
    account_id: int
    tx_hash: bytes
    flags: AccountTxFlags
    description: str | None
    date_created: int
    date_updated: int


class SpentOutputRow(NamedTuple):
    spent_tx_hash: bytes
    spent_txo_index: int
    spending_tx_hash: bytes
    spending_txi_index: int
    block_hash: bytes | None
    flags: TxFlags
    mapi_broadcast_flags: MAPIBroadcastFlag


class HistoryListRow(NamedTuple):
    tx_hash: bytes
    tx_flags: TxFlags
    block_hash: bytes | None
    block_height: int
    block_position: int | None
    description: str | None
    value_delta: int
    date_created: int


class InvoiceAccountRow(NamedTuple):
    invoice_id: int
    payment_uri: str
    description: str | None
    flags: PaymentFlag
    value: int
    date_expires: int | None
    date_created: int


class InvoiceRow(NamedTuple):
    invoice_id: int
    account_id: int
    tx_hash: bytes | None
    payment_uri: str
    description: str | None
    flags: PaymentFlag
    value: int
    invoice_data: bytes
    date_expires: int | None
    date_created: int = -1


class KeyDataProtocol(Protocol):
    # Overlapping common output/spendable type field.
    @property
    def keyinstance_id(self) -> int:
        ...
    # Spendable type fields.
    @property
    def account_id(self) -> int:
        ...
    @property
    def masterkey_id(self) -> int | None:
        ...
    @property
    def derivation_type(self) -> DerivationType:
        ...
    @property
    def derivation_data2(self) -> bytes | None   :
        ...


# @dataclasses.dataclass
class KeyData(NamedTuple):
    keyinstance_id: int                 # Overlapping common output/spendable type field.
    account_id: int                     # Spendable type field.
    masterkey_id: int | None         # Spendable type field.
    derivation_type: DerivationType     # Spendable type field.
    derivation_data2: bytes | None      # Spendable type field.


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
    masterkey_id: int | None            # Spendable type field.
    derivation_type: DerivationType     # Spendable type field.
    derivation_data: bytes
    derivation_data2: bytes | None      # Spendable type field.
    flags: KeyInstanceFlag
    description: str | None


class KeyListRow(NamedTuple):
    account_id: int
    keyinstance_id: int                 # Overlapping common output/spendable type field.
    masterkey_id: int | None            # Spendable type field.
    derivation_type: DerivationType     # Spendable type field.
    derivation_data: bytes
    derivation_data2: bytes | None      # Spendable type field.
    flags: KeyInstanceFlag
    description: str | None
    date_updated: int
    txo_value: int
    txo_count: int


class MasterKeyRow(NamedTuple):
    masterkey_id: int
    parent_masterkey_id: int | None
    derivation_type: DerivationType
    derivation_data: bytes
    flags: MasterKeyFlags


# WARNING The order of the fields in this data structure are implicitly linked to the query.
class NetworkServerRow(NamedTuple):
    # If this is `None` on an INSERT, SQLite will substitute it for a real primary key value.
    server_id: int | None
    server_type: NetworkServerType
    url: str
    account_id: int | None
    server_flags: NetworkServerFlag
    api_key_template: str | None
    encrypted_api_key: str | None
    payment_key_bytes: bytes | None
    # MAPI specific: used for JSONEnvelope serialised transaction fee quotes.
    mapi_fee_quote_json: str | None
    # Indexer server specific: used for tip filter notifications.
    tip_filter_peer_channel_id: int | None
    date_last_try: int
    date_last_good: int
    date_created: int
    date_updated: int


class PasswordUpdateResult(NamedTuple):
    password_token: str
    account_private_key_updates: dict[int, list[tuple[int, str]]]
    masterkey_updates: list[tuple[int, DerivationType, MasterKeyDataTypes]]


class PushDataRegistrationRow(NamedTuple):
    pushdata_flags: int
    date_created: int
    duration_seconds: int


class PaymentRequestRow(NamedTuple):
    # This is `None` for the `INSERT` as this makes SQLite allocate the primary key value for us.
    paymentrequest_id: int | None
    state: PaymentFlag
    requested_value: int | None
    date_expires: int | None
    # The local label we apply to transactions (seen in the history tab) received.
    description: str | None
    server_id: int | None
    dpp_invoice_id: str | None
    # What we put in any outgoing payment terms to describe what the payee is paying for.
    merchant_reference: str | None
    encrypted_key_text: str | None
    date_created: int
    date_updated: int


class PaymentRequestUpdateRow(NamedTuple):
    state: PaymentFlag
    value: int | None
    date_expires: int | None
    description: str | None
    merchant_reference: str | None
    paymentrequest_id: int


class PaymentRequestOutputRow(NamedTuple):
    # This is `None` for the `INSERT` as this makes SQLite allocate the primary key value for us.
    paymentrequest_id: int | None
    transaction_index: int
    output_index: int
    output_script_type: ScriptType
    output_script_bytes: bytes
    pushdata_hash: bytes
    output_value: int
    keyinstance_id: int
    date_created: int
    date_updated: int


SpendConflictType = tuple[bytes, int, bytes, int]


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
    account_id: int | None


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


@dataclasses.dataclass
class TransactionLinkState:
    # Parameters.
    rollback_on_spend_conflict: bool = False
    # Results.
    has_spend_conflicts: bool = False
    account_ids: set[int] | None = None


class TransactionOutputCommonProtocol(Protocol):
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: int | None               # Overlapping common output/spendable type field.
    flags: TransactionOutputFlag
    script_type: ScriptType


class TransactionOutputAddRow(NamedTuple):
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: int | None               # Overlapping common output/spendable type field.
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
    keyinstance_id: int | None               # Overlapping common output/spendable type field.
    flags: TransactionOutputFlag
    script_type: ScriptType
    # Extension fields for this type.
    script_hash: bytes


class TransactionOutputFullRow(NamedTuple):
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: int | None               # Overlapping common output/spendable type field.
    flags: TransactionOutputFlag
    script_type: ScriptType
    # Extension fields for this type.
    script_hash: bytes
    script_offset: int
    script_length: int
    spending_tx_hash: bytes | None
    spending_txi_index: int | None


class AccountTransactionOutputSpendableRow(NamedTuple):
    """
    Transaction output data with the additional key instance information required for spending it.
    """
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: int | None               # Overlapping common output/spendable type field.
    script_type: ScriptType
    flags: TransactionOutputFlag
    # KeyInstance fields.
    account_id: int                             # Spendable type field.
    masterkey_id: int | None                 # Spendable type field.
    derivation_type: DerivationType             # Spendable type field.
    derivation_data2: bytes | None              # Spendable type field.


class AccountTransactionOutputSpendableRowExtended(NamedTuple):
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: int | None               # Overlapping common output/spendable type field.
    script_type: ScriptType
    flags: TransactionOutputFlag
    # KeyInstance fields.
    account_id: int                             # Spendable type field.
    masterkey_id: int | None                    # Spendable type field.
    derivation_type: DerivationType             # Spendable type field.
    derivation_data2: bytes | None              # Spendable type field.
    # Extension fields for this type.
    tx_flags: TxFlags
    block_hash: bytes | None


class TransactionOutputSpendableRow(NamedTuple):
    """
    Transaction output data with the additional key instance information required for spending it.
    """
    # Standard transaction output fields.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: int | None               # Overlapping common output/spendable type field.
    script_type: ScriptType
    flags: TransactionOutputFlag
    # KeyInstance fields.
    account_id: int | None                   # Spendable type field.
    masterkey_id: int | None                 # Spendable type field.
    derivation_type: DerivationType | None   # Spendable type field.
    derivation_data2: bytes | None           # Spendable type field.

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
        ...
    @property
    def txo_index(self) -> int:
        ...
    @property
    def value(self) -> int:
        ...
    @property
    def script_type(self) -> ScriptType:
        ...
    @property
    def keyinstance_id(self) -> int | None:
        ...
    @property
    def account_id(self) ->  int:
        ...
    @property
    def masterkey_id(self) ->  int | None:
        ...
    @property
    def derivation_type(self) ->  DerivationType:
        ...
    @property
    def derivation_data2(self) -> bytes | None   :
        ...


class TransactionRow(NamedTuple):
    tx_hash: bytes
    tx_bytes: bytes | None
    flags: TxFlags
    block_hash: bytes | None
    block_height: int
    block_position: int | None
    fee_value: int | None
    description: str | None
    version: int | None
    locktime: int | None
    date_created: int               = -1
    date_updated: int               = -1


class MerkleProofRow(NamedTuple):
    block_hash: bytes
    block_position: int
    block_height: int
    proof_data: bytes
    tx_hash: bytes


class MerkleProofUpdateRow(NamedTuple):
    block_height: int
    block_hash: bytes
    tx_hash: bytes


class TransactionProofUpdateRow(NamedTuple):
    block_hash: bytes | None
    block_height: int
    block_position: int | None
    tx_flags: TxFlags
    date_updated: int
    tx_hash: bytes


class TransactionProoflessRow(NamedTuple):
    tx_hash: bytes
    account_id: int


class TransactionValueRow(NamedTuple):
    tx_hash: bytes
    value: int
    flags: TxFlags
    block_hash: bytes | None
    date_created: int
    date_updated: int


class TxProofData(NamedTuple):
    tx_hash: bytes
    flags: TxFlags
    block_hash: bytes | None
    proof_bytes: bytes | None
    tx_block_height: int
    tx_block_position: int | None
    proof_block_height: int
    proof_block_position: int


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


class WalletEventInsertRow(NamedTuple):
    event_type: WalletEventType
    account_id: int | None
    # NOTE(rt12): sqlite3 python module only allows custom typing if the column name is unique.
    event_flags: WalletEventFlag
    date_created: int
    date_updated: int


class WalletEventRow(NamedTuple):
    event_id: int
    event_type: WalletEventType
    account_id: int | None
    # NOTE(rt12): sqlite3 python module only allows custom typing if the column name is unique.
    event_flags: WalletEventFlag
    date_created: int
    date_updated: int


class MAPIBroadcastRow(NamedTuple):
    broadcast_id: int | None
    tx_hash: bytes
    broadcast_server_id: int
    mapi_broadcast_flags: MAPIBroadcastFlag
    peer_channel_id: int | None
    date_created: int
    date_updated: int


class ServerPeerChannelRow(NamedTuple):
    peer_channel_id: int | None
    server_id: int
    remote_channel_id: str | None
    remote_url: str | None
    peer_channel_flags: ServerPeerChannelFlag
    date_created: int
    date_updated: int


class ExternalPeerChannelRow(NamedTuple):
    peer_channel_id: int | None
    invoice_id: int
    remote_channel_id: str | None
    remote_url: str | None
    peer_channel_flags: ServerPeerChannelFlag
    date_created: int
    date_updated: int


# Used for both owned and externally owned peer channel tables
class ServerPeerChannelAccessTokenRow(NamedTuple):
    peer_channel_id: int
    token_flags: PeerChannelAccessTokenFlag
    permission_flags: int
    access_token: str


# Used for both owned and externally owned peer channel tables
class ServerPeerChannelMessageRow(NamedTuple):
    message_id: int | None
    peer_channel_id: int
    message_data: bytes
    message_flags: PeerChannelMessageFlag
    sequence: int
    date_received: int
    date_created: int
    date_updated: int


class InvoiceMessageRow(NamedTuple):
    message_id: int | None
    peer_channel_id: int
    message_data: bytes
    message_flags: PeerChannelMessageFlag
    sequence: int
    date_received: int
    date_created: int
    date_updated: int


class DPPMessageRow(NamedTuple):
    message_id: str
    paymentrequest_id: int
    dpp_invoice_id: str
    correlation_id: str
    app_id: int
    client_id: int
    user_id: int
    expiration: int | None
    body: bytes
    timestamp: str
    type: str

    def to_json(self, ) -> str:
        ts = datetime.now(tz=timezone.utc).isoformat().replace('+00:00', 'Z')
        dpp_message_dict: dict[str, Any] = {}
        dpp_message_dict['correlationId'] = self.correlation_id
        dpp_message_dict['appId'] = self.app_id
        dpp_message_dict['clientID'] = self.client_id
        dpp_message_dict['userId'] = self.user_id
        dpp_message_dict['expiration'] = self.expiration
        dpp_message_dict['body'] = json.loads(self.body.decode())
        dpp_message_dict['messageId'] = self.message_id
        dpp_message_dict['channelId'] = self.dpp_invoice_id
        dpp_message_dict['timestamp'] = ts
        dpp_message_dict['type'] = self.type
        dpp_message_dict['headers'] = {}
        return json.dumps(dpp_message_dict)


class PushDataHashRegistrationRow(NamedTuple):
    server_id: int
    # There are two kinds of registration based on key usage.
    # 1. Payment requests where an address or payment destination generated for the purpose is
    #    given out to another party.
    # 2. Where advanced users have gone to the keys tab and designated a key as forced active.
    #    this is not currently supported.
    keyinstance_id: int
    script_type: ScriptType
    pushdata_hash: bytes
    pushdata_flags: PushDataHashRegistrationFlag
    # How many seconds from `date_created` the registration expires.
    duration_seconds: int
    # The date the server returned as the posix timestamp the registration counts from.
    date_registered: int | None
    date_created: int
    date_updated: int


class PushDataMatchRow(NamedTuple):
    server_id: int
    pushdata_hash: bytes
    transaction_hash: bytes
    transaction_index: int
    block_hash: bytes | None
    match_flags: PushDataMatchFlag
    date_created: int


class PushDataMatchMetadataRow(NamedTuple):
    account_id: int
    pushdata_hash: bytes
    keyinstance_id: int
    script_type: ScriptType
    transaction_hash: bytes
    block_hash: bytes | None


class PaymentRequestTransactionHashRow(NamedTuple):
    paymentrequest_id: int
    transaction_hash: bytes
