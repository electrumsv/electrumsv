"""
Keeps backwards compatible logic for storage migration.
"""
# TODO(nocheckin) write a decision document for why we have this.
try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.7.8 builds and version of 3.31.1.
    import sqlite3 # type: ignore
import time
from typing import Iterable, NamedTuple, Optional, Sequence

from ..constants import (DerivationType, KeyInstanceFlag, PaymentFlag, ScriptType,
    TransactionOutputFlag, TxFlags)
from .sqlite_support import CompletionCallbackType, DatabaseContext
from .types import TxData
from .util import get_timestamp


class AccountRow1(NamedTuple):
    account_id: int
    default_masterkey_id: Optional[int]
    default_script_type: ScriptType
    account_name: str


class KeyInstanceRow1(NamedTuple):
    keyinstance_id: int
    account_id: int
    masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes
    script_type: ScriptType
    flags: KeyInstanceFlag
    description: Optional[str]


class MasterKeyRow1(NamedTuple):
    masterkey_id: int
    parent_masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes


class PaymentRequestRow1(NamedTuple):
    paymentrequest_id: int
    keyinstance_id: int
    state: PaymentFlag
    value: Optional[int]
    expiration: Optional[int]
    description: Optional[str]
    date_created: int


class TransactionOutputRow1(NamedTuple):
    tx_hash: bytes
    tx_index: int
    value: int
    keyinstance_id: Optional[int]
    flags: TransactionOutputFlag


class TxProof1(NamedTuple):
    position: int
    branch: Sequence[bytes]


class TransactionRow1(NamedTuple):
    tx_hash: bytes
    tx_data: TxData
    tx_bytes: Optional[bytes]
    flags: TxFlags
    description: Optional[str]
    version: Optional[int]
    locktime: Optional[int]


def create_accounts1(db_context: DatabaseContext, entries: Iterable[AccountRow1],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    timestamp = get_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO Accounts (account_id, default_masterkey_id, default_script_type, "
        "account_name, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal query, datas
        db.executemany(query, datas)
    db_context.queue_write(_write, completion_callback)


def create_keys1(db_context: DatabaseContext, entries: Iterable[KeyInstanceRow1],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    timestamp = int(time.time())
    datas = [ (*t, timestamp, timestamp) for t in entries]
    query = ("INSERT INTO KeyInstances (keyinstance_id, account_id, masterkey_id, "
        "derivation_type, derivation_data, script_type, flags, description, date_created, "
        "date_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal query, datas
        db.executemany(query, datas)
    db_context.queue_write(_write, completion_callback)


def create_master_keys1(db_context: DatabaseContext, entries: Iterable[MasterKeyRow1],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    timestamp = get_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal query, datas
        db.executemany(query, datas)
    db_context.queue_write(_write, completion_callback)


def create_payment_requests1(db_context: DatabaseContext, entries: Iterable[PaymentRequestRow1],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    # Duplicate the last column for date_updated = date_created
    query = ("INSERT INTO PaymentRequests "
        "(paymentrequest_id, keyinstance_id, state, value, expiration, description, date_created, "
        "date_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    datas = [ (*t, t[-1]) for t in entries ]
    def _write(db: sqlite3.Connection):
        nonlocal query, datas
        db.executemany(query, datas)
    db_context.queue_write(_write, completion_callback)


def create_transaction_outputs1(db_context: DatabaseContext,
        entries: Iterable[TransactionOutputRow1],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    timestamp = int(time.time())
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, "
        "flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal query, datas
        db.executemany(query, datas)
    db_context.queue_write(_write, completion_callback)


def create_transactions1(db_context: DatabaseContext, entries: Iterable[TransactionRow1],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    query = ("INSERT INTO Transactions (tx_hash, tx_data, flags, "
        "block_height, block_position, fee_value, description, version, locktime, "
        "date_created, date_updated) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)")

    datas = []
    for tx_hash, metadata, bytedata, flags, description, version, locktime in entries:
        assert type(tx_hash) is bytes and bytedata is not None
        assert (flags & TxFlags.HasByteData) == 0, "this flag is not applicable"
        flags &= ~TxFlags.METADATA_FIELD_MASK
        if metadata.height is not None:
            flags |= TxFlags.HasHeight
        if metadata.fee is not None:
            flags |= TxFlags.HasFee
        if metadata.position is not None:
            flags |= TxFlags.HasPosition
        assert metadata.date_added is not None and metadata.date_updated is not None
        datas.append((tx_hash, bytedata, flags, metadata.height, metadata.position,
            metadata.fee, description, version, locktime, metadata.date_added,
            metadata.date_updated))

    def _write(db: sqlite3.Connection) -> None:
        nonlocal query, datas
        db.executemany(query, datas)
    db_context.queue_write(_write, completion_callback)
