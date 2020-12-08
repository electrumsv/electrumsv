from typing import NamedTuple, Optional, Sequence

from ..constants import DerivationType, KeyInstanceFlag, PaymentFlag, ScriptType, \
    TransactionOutputFlag, TxFlags


class AccountRow(NamedTuple):
    account_id: int
    default_masterkey_id: Optional[int]
    default_script_type: ScriptType
    account_name: str


class KeyInstanceRow(NamedTuple):
    keyinstance_id: int
    account_id: int
    masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes
    derivation_data2: Optional[bytes]
    flags: KeyInstanceFlag
    description: Optional[str]


class KeyListRow(NamedTuple):
    keyinstance_id: int
    masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes
    flags: KeyInstanceFlag
    date_updated: int
    tx_hash: Optional[bytes]
    txo_script_type: Optional[ScriptType]
    txo_index: Optional[int]
    txo_value: Optional[int]


class MasterKeyRow(NamedTuple):
    masterkey_id: int
    parent_masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes


class PaymentRequestRow(NamedTuple):
    paymentrequest_id: int
    keyinstance_id: int
    state: PaymentFlag
    value: Optional[int]
    expiration: Optional[int]
    description: Optional[str]
    date_created: int


class TransactionDeltaSumRow(NamedTuple):
    account_id: int
    total: int


class TransactionOutputRow(NamedTuple):
    tx_hash: bytes
    tx_index: int
    value: int
    keyinstance_id: Optional[int]
    script_type: ScriptType
    script_hash: bytes
    flags: TransactionOutputFlag


class TxData(NamedTuple):
    height: Optional[int] = None
    position: Optional[int] = None
    fee: Optional[int] = None
    date_added: Optional[int] = None
    date_updated: Optional[int] = None

    def __repr__(self):
        return (f"TxData(height={self.height},position={self.position},fee={self.fee},"
            f"date_added={self.date_added},date_updated={self.date_updated})")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TxData):
            return NotImplemented
        return (self.height == other.height and self.position == other.position
            and self.fee == other.fee)


class TxProof(NamedTuple):
    position: int
    branch: Sequence[bytes]


class TransactionRow(NamedTuple):
    tx_hash: bytes
    tx_bytes: Optional[bytes]
    flags: TxFlags
    block_height: Optional[int]
    block_position: Optional[int]
    fee_value: Optional[int]
    description: Optional[str]
    version: Optional[int]
    locktime: Optional[int]
    date_created: int=-1
    date_updated: int=-1
