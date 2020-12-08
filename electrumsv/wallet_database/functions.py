try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.7.8 builds and version of 3.31.1.
    import sqlite3 # type: ignore
from typing import Any, Iterable, List, NamedTuple, Optional, Sequence

from bitcoinx import pack_be_uint32

from ..constants import DerivationType, KeyInstanceFlag, TxFlags
from ..logs import logs

from .sqlite_support import (CompletionCallbackType, DatabaseContext,
    replace_db_context_with_connection)
from .types import (KeyInstanceRow, KeyListRow, MasterKeyRow, TransactionDeltaSumRow,
    TransactionOutputRow, TransactionRow)
from .util import flag_clause, get_timestamp, read_rows_by_id


logger = logs.get_logger("db-functions")


def create_keys(db_context: DatabaseContext, entries: Iterable[KeyInstanceRow],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    timestamp = get_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries]
    query = ("INSERT INTO KeyInstances "
        "(keyinstance_id, account_id, masterkey_id, derivation_type, derivation_data, "
        "derivation_data2, flags, description, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal query, datas
        db.executemany(query, datas)
    db_context.queue_write(_write, completion_callback)


def create_master_keys(db_context: DatabaseContext, entries: Iterable[MasterKeyRow],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    timestamp = get_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal query, datas
        db.executemany(query, datas)
    db_context.queue_write(_write, completion_callback)


def create_transaction_outputs(db_context: DatabaseContext,
        entries: Iterable[TransactionOutputRow],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    query = ("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, "
        "script_type, script_hash, flags, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    timestamp = get_timestamp()
    db_rows = [ (*t, timestamp, timestamp) for t in entries ]
    def _write(db: sqlite3.Connection):
        nonlocal query, db_rows
        db.executemany(query, db_rows)
    db_context.queue_write(_write, completion_callback)


def create_transactions(db_context: DatabaseContext, rows: List[TransactionRow],
        completion_callback: Optional[CompletionCallbackType]=None) -> None:
    query = ("INSERT INTO Transactions (tx_hash, tx_data, flags, "
        "block_height, block_position, fee_value, description, version, locktime, "
        "date_created, date_updated) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)")

    for i, row in enumerate(rows):
        assert type(row.tx_hash) is bytes and row.tx_bytes is not None
        assert (row.flags & TxFlags.HasByteData) == 0, "this flag is not applicable"
        assert row.date_created > 0 and row.date_updated > 0
        # TODO(nocheckin) flags for height fee and position should go away
        flags = row.flags & ~TxFlags.METADATA_FIELD_MASK
        if row.block_height is not None:
            flags |= TxFlags.HasHeight
        if row.fee_value is not None:
            flags |= TxFlags.HasFee
        if row.block_position is not None:
            flags |= TxFlags.HasPosition
        rows[i] = row._replace(flags=flags)

    def _write(db: sqlite3.Connection) -> None:
        nonlocal query, rows
        logger.debug("add %d transactions", len(rows))
        db.executemany(query, rows)
    db_context.queue_write(_write, completion_callback)


@replace_db_context_with_connection
def read_account_balance(db: sqlite3.Connection, account_id: int, flags: Optional[int]=None,
        mask: Optional[int]=None) -> TransactionDeltaSumRow:
    query = ("SELECT TXV.account_id, TOTAL(TXV.value), COUNT(DISTINCT TXV.tx_hash) "
        "FROM TransactionValues TXV "
        "{} "
        "WHERE TXV.account_id = ? "
        "{}"
        "GROUP BY TXV.account_id")
    params: List[Any] = [ account_id ]
    clause, extra_params = flag_clause("TX.flags", flags, mask)
    if clause:
        query = query.format("INNER JOIN Transactions TX ON TX.tx_hash=TXV.tx_hash ",
            f" AND {clause} ")
        params.extend(extra_params)
    else:
        query = query.format("", "")
    cursor = db.execute(query, params)
    row = cursor.fetchone()
    cursor.close()
    if row is None:
        return TransactionDeltaSumRow(account_id, 0)
    return TransactionDeltaSumRow(*row)


class HistoryListRow(NamedTuple):
    tx_hash: bytes
    tx_flags: TxFlags
    block_height: Optional[int]
    block_position: Optional[int]
    value_delta: int


@replace_db_context_with_connection
def read_history_list(db: sqlite3.Connection, account_id: int,
        keyinstance_ids: Optional[Sequence[int]]=None) -> List[HistoryListRow]:
    if keyinstance_ids:
        # Used for the address dialog.
        query = ("SELECT TXV.tx_hash, TX.flags, TX.block_height, TX.block_position, "
                "TOTAL(TD.value), TX.date_added "
            "FROM TransactionValues TXV "
            "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
            "WHERE TXV.account_id=? AND TD.keyinstance_id IN ({}) AND "
                f"(T.flags & {TxFlags.STATE_MASK})!=0"
            "GROUP BY TXV.tx_hash")
        return read_rows_by_id(HistoryListRow, db, query, [ account_id ], keyinstance_ids)

    # Used for the history list and export.
    query = ("SELECT TXV.tx_hash, TX.flags, TX.block_height, TX.block_position, "
            "TOTAL(TD.value), TX.date_added "
        "FROM TransactionValues TXV "
        "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
        f"WHERE TXV.account_id=? AND (T.flags & {TxFlags.STATE_MASK})!=0"
        "GROUP BY TXV.tx_hash")
    cursor = db.execute(query, [account_id])
    rows = cursor.fetchall()
    cursor.close()
    return [ HistoryListRow(*t) for t in rows ]


@replace_db_context_with_connection
def read_key_list(db: sqlite3.Connection, account_id: int,
        keyinstance_ids: Optional[Sequence[int]]=None) -> List[KeyListRow]:
    params = [ account_id ]
    if keyinstance_ids is not None:
        query = ("SELECT KI.keyinstance_id, KI.masterkey_id, KI.derivation_type, "
                "KI.derivation_data, KI.flags, KI.date_updated, TXO.tx_hash, TXO.tx_index, "
                "TXO.script_type, TXO.value  "
            "FROM KeyInstances AS KI "
            "LEFT JOIN TransactionOutputs TXO ON TXO.keyinstance_id = TXO.keyinstance_id "
            "WHERE KI.account_id = ? AND KI.keyinstance_id IN ({}) "
            "GROUP BY KI.keyinstance_id")
        return read_rows_by_id(KeyListRow, db, query, [ account_id ], keyinstance_ids)

    query = ("SELECT KI.keyinstance_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.flags, KI.date_updated, TXO.tx_hash, TXO.tx_index, "
            "TXO.script_type, TXO.value "
        "FROM KeyInstances AS KI "
        "LEFT JOIN TransactionOutputs TXO ON TXO.keyinstance_id = TXO.keyinstance_id "
        "WHERE KI.account_id = ?")
    cursor = db.execute(query, [account_id])
    rows = cursor.fetchall()
    cursor.close()
    return [ KeyListRow(*t) for t in rows ]


@replace_db_context_with_connection
def read_paid_requests(db: sqlite3.Connection, account_id: int, keyinstance_ids: Sequence[int]) \
        -> List[int]:
    # TODO(nocheckin) ensure this is filtering out transactions or transaction outputs that
    # are not relevant.
    query = ("SELECT PR.keyinstance_id "
        "FROM PaymentRequests PR "
        "INNER JOIN TransactionOutputs TXO ON TXO.keyinstance_id=PR.keyinstance_id "
        "INNER JOIN AccountTransactions ATX ON ATX.tx_hash=TXO.tx_hash AND ATX.account_id = ?"
        "WHERE PR.keyinstance_id IN ({}) AND (PR.state & {PaymentFlag.UNPAID}) != 0 "
        "GROUP BY PR.keyinstance_id "
        "HAVING PR.value IS NULL OR PR.value <= TOTAL(TXO.value)")
    return read_rows_by_id(int, db, query, [ account_id ], keyinstance_ids)


@replace_db_context_with_connection
def count_unused_bip32_keys(db: sqlite3.Connection, account_id: int, masterkey_id: int,
        derivation_path: Sequence[int]) -> int:
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = b''.join(pack_be_uint32(v) for v in derivation_path)
    # Keys are created in order of sequence enumeration, so we shouldn't need to order by
    # the derivation_data2 bytes to get them ordered from oldest to newest, just id.
    query = ("SELECT COUNT(*) FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? "
            f"AND (flags&{KeyInstanceFlag.ALLOCATED_MASK})=0 "
            "AND length(derivation_data2)=? AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id")
    cursor = db.execute(query, (account_id, masterkey_id,
        len(prefix_bytes)+4,  # The length of the parent path and sequence index.
        len(prefix_bytes),    # Just the length of the parent path.
        prefix_bytes))        # The packed parent path bytes.
    rows = cursor.fetchone()
    cursor.close()
    return rows[0]


@replace_db_context_with_connection
def read_unused_bip32_keys(db: sqlite3.Connection, account_id: int, masterkey_id: int,
        derivation_path: Sequence[int], limit: int) -> List[KeyInstanceRow]:
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = b''.join(pack_be_uint32(v) for v in derivation_path)
    # Keys are created in order of sequence enumeration, so we shouldn't need to order by
    # the derivation_data2 bytes to get them ordered from oldest to newest, just id.
    query = ("SELECT keyinstance_id, account_id, masterkey_id, derivation_type, "
        "derivation_data, derivation_data2, flags, description FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? "
            f"AND (flags&{KeyInstanceFlag.ALLOCATED_MASK})=0 "
            "AND length(derivation_data2)=? AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id "
        f"LIMIT {limit}")
    cursor = db.execute(query, (account_id, masterkey_id,
        len(prefix_bytes)+4,  # The length of the parent path and sequence index.
        len(prefix_bytes),    # Just the length of the parent path.
        prefix_bytes))        # The packed parent path bytes.
    rows = cursor.fetchall()
    cursor.close()

    # TODO(nocheckin) work out if we need all this, or just keyinstance_id and the derivation
    # path in derivation_data2.
    return [ KeyInstanceRow(row[0], row[1], row[2], DerivationType(row[3]), row[4], row[5],
        KeyInstanceFlag(row[6]), row[7]) for row in rows ]


@replace_db_context_with_connection
def read_transaction_value(db: sqlite3.Connection, tx_hash: bytes,
        account_id: Optional[int]=None) -> List[TransactionDeltaSumRow]:
    if account_id is None:
        query = ("SELECT account_id, TOTAL(value) "
            "FROM TransactionValues "
            "WHERE tx_hash=? "
            "GROUP BY account_id")
        cursor = db.execute(query, [tx_hash])
    else:
        query = ("SELECT account_id, TOTAL(value) "
            "FROM TransactionValues "
            "WHERE account_id=? AND tx_hash=? "
            "GROUP BY account_id")
        cursor = db.execute(query, [account_id, tx_hash])
    rows = cursor.fetchall()
    cursor.close()
    return [ TransactionDeltaSumRow(*row) for row in rows ]
