import concurrent
try:
    # Linux expects the latest package version of 3.34.0 (as of pysqlite-binary 0.4.5)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.34.0 (as of 2021-01-13).
    # Windows builds use the official Python 3.9.1 builds and bundled version of 3.33.0.
    import sqlite3 # type: ignore
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from ..bitcoin import COINBASE_MATURITY
from ..constants import (DerivationType, KeyInstanceFlag, pack_derivation_path,
    TransactionOutputFlag, TxFlags)
from ..logs import logs
from ..types import TxoKeyType

from .exceptions import DatabaseUpdateError, TransactionRemovalError
from .sqlite_support import DatabaseContext, replace_db_context_with_connection
from .types import (AccountRow, AccountTransactionRow, HistoryListRow, KeyInstanceRow,
    KeyInstanceScriptHashRow, KeyListRow, MasterKeyRow, TransactionOutputSpendableRow,
    TransactionDeltaSumRow, TransactionValueRow, TransactionMetadata,
    TransactionOutputFullRow, TransactionOutputShortRow,
    TransactionOutputSpendableRow2, TransactionRow, TxProof, WalletBalance)
from .util import (flag_clause, get_timestamp, pack_proof, read_rows_by_id,
    read_rows_by_ids, update_rows_by_id, update_rows_by_ids)


logger = logs.get_logger("db-functions")


@replace_db_context_with_connection
def count_unused_bip32_keys(db: sqlite3.Connection, account_id: int, masterkey_id: int,
        derivation_path: Sequence[int]) -> int:
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = pack_derivation_path(derivation_path)
    # Keys are created in order of sequence enumeration, so we shouldn't need to order by
    # the derivation_data2 bytes to get them ordered from oldest to newest, just id.
    sql = ("SELECT COUNT(*) FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? "
            f"AND (flags&{KeyInstanceFlag.ALLOCATED_MASK})=0 "
            "AND length(derivation_data2)=? AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id")
    cursor = db.execute(sql, (account_id, masterkey_id,
        len(prefix_bytes)+4,  # The length of the parent path and sequence index.
        len(prefix_bytes),    # Just the length of the parent path.
        prefix_bytes))        # The packed parent path bytes.
    rows = cursor.fetchone()
    cursor.close()
    return rows[0]


def create_accounts(db_context: DatabaseContext, entries: Iterable[AccountRow]) \
        -> concurrent.futures.Future:
    timestamp = get_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO Accounts (account_id, default_masterkey_id, default_script_type, "
        "account_name, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal query, datas
        db.executemany(query, datas)
    return db_context.post_to_thread(_write)


def create_account_transactions(db_context: DatabaseContext,
        entries: Iterable[AccountTransactionRow]) -> concurrent.futures.Future:
    sql = (
        "INSERT INTO AccountTransactions "
        "(account_id, tx_hash, flags, description, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?)")
    timestamp = get_timestamp()
    rows = [ (*t, timestamp, timestamp) for t in entries ]
    def _write(db: sqlite3.Connection):
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_keys(db_context: DatabaseContext, entries: Iterable[KeyInstanceRow]) \
        -> concurrent.futures.Future:
    timestamp = get_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries]
    sql = ("INSERT INTO KeyInstances "
        "(keyinstance_id, account_id, masterkey_id, derivation_type, derivation_data, "
        "derivation_data2, flags, description, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal sql, datas
        db.executemany(sql, datas)
    return db_context.post_to_thread(_write)


def create_key_scripthashes(db_context: DatabaseContext,
        entries: Iterable[KeyInstanceScriptHashRow]) -> concurrent.futures.Future:
    timestamp = get_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries]
    sql = ("INSERT INTO KeyInstanceScripts "
        "(keyinstance_id, script_type, script_hash, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal sql, datas
        db.executemany(sql, datas)
    return db_context.post_to_thread(_write)


def create_master_keys(db_context: DatabaseContext, entries: Iterable[MasterKeyRow]) \
        -> concurrent.futures.Future:
    timestamp = get_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    sql = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection):
        nonlocal sql, datas
        db.executemany(sql, datas)
    return db_context.post_to_thread(_write)


def create_transaction_outputs(db_context: DatabaseContext,
        entries: Iterable[TransactionOutputShortRow]) -> concurrent.futures.Future:
    sql = ("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, "
        "flags, script_type, script_hash, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    timestamp = get_timestamp()
    db_rows = [ (*t, timestamp, timestamp) for t in entries ]
    def _write(db: sqlite3.Connection):
        nonlocal sql, db_rows
        db.executemany(sql, db_rows)
    return db_context.post_to_thread(_write)


def create_transactions(db_context: DatabaseContext, rows: List[TransactionRow]) \
        -> concurrent.futures.Future:
    sql = ("INSERT INTO Transactions (tx_hash, tx_data, flags, "
        "block_height, block_position, fee_value, description, version, locktime, "
        "date_created, date_updated) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)")

    for row in rows:
        assert type(row.tx_hash) is bytes and row.tx_bytes is not None
        assert (row.flags & TxFlags.HAS_BYTEDATA) == 0, "this flag is not applicable"
        assert row.date_created > 0 and row.date_updated > 0

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        logger.debug("add %d transactions", len(rows))
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def delete_payment_request(db_context: DatabaseContext, paymentrequest_id: int,
        keyinstance_id: int) -> concurrent.futures.Future:
    timestamp = get_timestamp()

    sql1 = ("UPDATE KeyInstances SET date_updated=?, "
        f"flags=flags&{~KeyInstanceFlag.IS_PAYMENT_REQUEST} WHERE keyinstance_id=?")
    sql1_values = (timestamp, keyinstance_id)

    sql2 = "DELETE FROM PaymentRequests WHERE paymentrequest_id=?"
    sql2_values = (paymentrequest_id,)

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql1, sql1_values, sql2, sql2_values
        db.execute(sql1, sql1_values)
        db.execute(sql2, sql2_values)
    return db_context.post_to_thread(_write)


@replace_db_context_with_connection
def read_account_balance(db: sqlite3.Connection, account_id: int, local_height: int,
        filter_bits: Optional[TransactionOutputFlag]=None,
        filter_mask: Optional[TransactionOutputFlag]=None) -> WalletBalance:
    coinbase_mask = TransactionOutputFlag.IS_COINBASE
    if filter_bits is None:
        filter_bits = TransactionOutputFlag.NONE
    if filter_mask is None:
        filter_mask = TransactionOutputFlag.IS_SPENT|TransactionOutputFlag.IS_FROZEN
    # NOTE(linked-balance-calculations) the general formula is used elsewhere
    sql = (
        "SELECT "
            # Confirmed.
            "TOTAL(CASE WHEN block_height > 0 "
                f"AND (flags&{coinbase_mask}=0 OR block_height+{COINBASE_MATURITY}<=?) "
                "THEN value ELSE 0 END), "
            # Unconfirmed total.
            "TOTAL(CASE WHEN block_height IS NULL OR block_height < 1 THEN value ELSE 0 END), "
            # Unmatured total.
            f"TOTAL(CASE WHEN block_height > 0 AND flags&{coinbase_mask} "
                f"AND block_height+{COINBASE_MATURITY}>? THEN value ELSE 0 END) "
        "FROM AccountTransactions ATX "
        "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=ATX.tx_hash"
        f"WHERE ATX.account_id=? AND (TXO.flags&{filter_bits})=0")
    cursor = db.execute(sql, (account_id, local_height))
    row = cursor.fetchone()
    cursor.close()
    return WalletBalance(*row)


@replace_db_context_with_connection
def read_account_balance_raw(db: sqlite3.Connection, account_id: int, flags: Optional[int]=None,
        mask: Optional[int]=None) -> TransactionDeltaSumRow:
    sql = ("SELECT TXV.account_id, TOTAL(TXV.value), COUNT(DISTINCT TXV.tx_hash) "
        "FROM TransactionValues TXV "
        "{} "
        "WHERE TXV.account_id = ? "
        "{}"
        "GROUP BY TXV.account_id")
    sql_values: List[Any] = [ account_id ]
    clause, extra_sql_values = flag_clause("TX.flags", flags, mask)
    if clause:
        sql = sql.format("INNER JOIN Transactions TX ON TX.tx_hash=TXV.tx_hash ",
            f" AND {clause} ")
        sql_values.extend(extra_sql_values)
    else:
        sql = sql.format("", "")
    cursor = db.execute(sql, sql_values)
    row = cursor.fetchone()
    cursor.close()
    if row is None:
        return TransactionDeltaSumRow(account_id, 0)
    return TransactionDeltaSumRow(*row)


@replace_db_context_with_connection
def read_account_transaction_outputs(db: sqlite3.Connection, account_id: int,
        flags: TransactionOutputFlag, mask: TransactionOutputFlag,
        require_key_usage: bool=False, tx_hash: Optional[bytes]=None,
        keyinstance_ids: Optional[List[int]]=None) -> List[TransactionOutputSpendableRow2]:
    sql = (
        "SELECT TXO.tx_hash, TXO.tx_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
            "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, KI.derivation_data2 "
            "TX.flags AS tx_flags, TX.block_height"
        "FROM AccountTransactions ATX "
        "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=ATX.tx_hash "
        "INNER JOIN KeyInstances KI ON TXO.keyinstance_id=TXO.keyinstance_id "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash"
        f"WHERE ATX.account_id=? AND TXO.flags&{mask}={flags} ")
    sql_values: List[Any] = [ account_id ]
    if tx_hash is not None:
        sql += "AND ATX.tx_hash=? "
        sql_values.append(tx_hash)
    else:
        sql_values = [account_id]
    if keyinstance_ids is not None:
        sql += "AND TXO.keyinstance_id IN ({}) "
    elif require_key_usage:
        sql += "AND TXO.keyinstance_id IS NOT NULL "

    if keyinstance_ids is not None:
        rows = read_rows_by_id(TransactionOutputSpendableRow2, db, sql, sql_values, keyinstance_ids)
    else:
        cursor = db.execute(sql, sql_values)
        rows = [ TransactionOutputSpendableRow2(*row) for row in cursor.fetchall() ]
        cursor.close()
    return rows


# TODO(nocheckin) test default
# TODO(nocheckin) test exclude_frozen
# TODO(nocheckin) test confirmed_only
# TODO(nocheckin) test mature
@replace_db_context_with_connection
def read_account_transaction_outputs_spendable(db: sqlite3.Connection, account_id: int,
        confirmed_only: bool=False, mature_height: Optional[int]=None, exclude_frozen: bool=False,
        keyinstance_ids: Optional[List[int]]=None) -> List[TransactionOutputSpendableRow]:
    """
    Get the unspent coins in the given account.

    confirmed_only: only return unspent coins in confirmed transactions.
    mature_height:  if immature coinbase coins should be excluded, then the current blockchain
                    height (local height) should be provided here.
    exclude_frozen: only return unspent coins that are not frozen.
    """
    # Default to selecting all unallocated unspent transaction outputs.
    txo_flags = TransactionOutputFlag.NONE
    txo_mask = TransactionOutputFlag.IS_SPENT | TransactionOutputFlag.IS_ALLOCATED
    if exclude_frozen:
        txo_mask |= TransactionOutputFlag.IS_FROZEN

    sql_values = [ account_id ]
    sql = (
        "SELECT TXO.tx_hash, TXO.tx_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
            "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, KI.derivation_data2 "
        "FROM TransactionOutputs TXO "
        "INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id ")
    if confirmed_only or mature_height is not None:
        sql += "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
    sql += f"WHERE KI.account_id=? AND TXO.flags&{txo_mask}={txo_flags}"
    if confirmed_only:
        sql += f" AND TX.flags&{TxFlags.StateSettled}!=0"
    if mature_height is not None:
        coinbase_mask = TransactionOutputFlag.IS_COINBASE
        sql += f" AND (TXO.flags&{coinbase_mask}=0 OR TX.block_height+{COINBASE_MATURITY}<=?)"
        sql_values = [ account_id, mature_height ]
    if keyinstance_ids is not None:
        sql += " AND TXO.keyinstance_id IN ({})"
        rows = read_rows_by_id(TransactionOutputSpendableRow, db, sql, sql_values, keyinstance_ids)
    else:
        cursor = db.execute(sql, sql_values)
        rows = [ TransactionOutputSpendableRow(*row) for row in cursor.fetchall() ]
        cursor.close()
    return rows


# TODO(nocheckin) test default
# TODO(nocheckin) test exclude_frozen
# TODO(nocheckin) test confirmed_only
# TODO(nocheckin) test mature
@replace_db_context_with_connection
def read_account_transaction_outputs_spendable_extended(db: sqlite3.Connection, account_id: int,
        confirmed_only: bool=False, mature_height: Optional[int]=None, exclude_frozen: bool=False,
        keyinstance_ids: Optional[List[int]]=None) -> List[TransactionOutputSpendableRow2]:
    """
    Get the unspent coins in the given account extended with transaction fields.

    confirmed_only: only return unspent coins in confirmed transactions.
    mature_height:  if immature coinbase coins should be excluded, then the current blockchain
                    height (local height) should be provided here.
    exclude_frozen: only return unspent coins that are not frozen.
    """
    # Default to selecting all unallocated unspent transaction outputs.
    txo_flags = TransactionOutputFlag.NONE
    txo_mask = TransactionOutputFlag.IS_SPENT | TransactionOutputFlag.IS_ALLOCATED
    if exclude_frozen:
        txo_mask |= TransactionOutputFlag.IS_FROZEN

    sql_values = [ account_id ]
    sql = (
        "SELECT TXO.tx_hash, TXO.tx_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
            "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, KI.derivation_data2, "
            "TX.flags, TX.block_height "
        "FROM TransactionOutputs TXO "
        "INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
        f"WHERE KI.account_id=? AND TXO.flags&{txo_mask}={txo_flags}")
    if confirmed_only:
        sql += f" AND TX.flags&{TxFlags.StateSettled}!=0"
    if mature_height is not None:
        coinbase_mask = TransactionOutputFlag.IS_COINBASE
        sql += f" AND (TXO.flags&{coinbase_mask}=0 OR TX.block_height+{COINBASE_MATURITY}<=?)"
        sql_values = [ account_id, mature_height ]
    if keyinstance_ids is not None:
        sql += " AND TXO.keyinstance_id IN ({})"
        rows = read_rows_by_id(TransactionOutputSpendableRow2, db, sql, sql_values, keyinstance_ids)
    else:
        cursor = db.execute(sql, sql_values)
        rows = [ TransactionOutputSpendableRow2(*row) for row in cursor.fetchall() ]
        cursor.close()
    return rows


@replace_db_context_with_connection
def read_history_list(db: sqlite3.Connection, account_id: int,
        keyinstance_ids: Optional[Sequence[int]]=None) -> List[HistoryListRow]:
    if keyinstance_ids:
        # Used for the address dialog.
        sql = ("SELECT TXV.tx_hash, TX.flags, TX.block_height, TX.block_position, "
                "TOTAL(TD.value), TX.date_created "
            "FROM TransactionValues TXV "
            "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
            "WHERE TXV.account_id=? AND TD.keyinstance_id IN ({}) AND "
                f"(T.flags & {TxFlags.STATE_MASK})!=0"
            "GROUP BY TXV.tx_hash")
        return read_rows_by_id(HistoryListRow, db, sql, [ account_id ], keyinstance_ids)

    # Used for the history list and export.
    sql = ("SELECT TXV.tx_hash, TX.flags, TX.block_height, TX.block_position, "
            "TOTAL(TD.value), TX.date_created "
        "FROM TransactionValues TXV "
        "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
        f"WHERE TXV.account_id=? AND (T.flags & {TxFlags.STATE_MASK})!=0"
        "GROUP BY TXV.tx_hash")
    cursor = db.execute(sql, [account_id])
    rows = cursor.fetchall()
    cursor.close()
    return [ HistoryListRow(*t) for t in rows ]


@replace_db_context_with_connection
def read_key_list(db: sqlite3.Connection, account_id: int,
        keyinstance_ids: Optional[Sequence[int]]=None) -> List[KeyListRow]:
    """
    Find all existing keys for the given account and their usages.

    This will return at least one row for every matched key instance. If there are no transaction
    outputs that use that key, then the row will have NULL for the TXO sourced fields. Otherwise
    for every transaction output that uses the key, there will be a row and the TXO sourced fields
    will be for that transaction output.

    If a `keyinstance_ids` value is given, then the results will only reflect usage of those
    keys.
    """
    sql_values = (account_id,)
    sql = ("SELECT KI.keyinstance_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.date_updated, TXO.tx_hash, "
            "TXO.tx_index, TXO.script_type, TXO.value "
        "FROM KeyInstances AS KI "
        "LEFT JOIN TransactionOutputs TXO ON TXO.keyinstance_id = TXO.keyinstance_id "
        "WHERE KI.account_id = ?")
    if keyinstance_ids is not None:
        sql += " AND KI.keyinstance_id IN ({})"
        return read_rows_by_id(KeyListRow, db, sql, sql_values, keyinstance_ids)

    cursor = db.execute(sql, sql_values)
    rows = cursor.fetchall()
    cursor.close()
    return [ KeyListRow(*t) for t in rows ]


@replace_db_context_with_connection
def read_keyinstances(db: sqlite3.Connection, *, account_id: Optional[int]=None,
        keyinstance_ids: Optional[Sequence[int]]=None) -> List[KeyInstanceRow]:
    """
    Read explicitly requested keyinstances.
    """
    sql_values = []
    sql = ("SELECT KI.keyinstance_id, KI.account_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.description "
        "FROM KeyInstances AS KI")
    if account_id is None:
        conjunction = "WHERE"
    else:
        sql += " WHERE account_id=?"
        sql_values = [ account_id ]
        conjunction = "AND"

    if keyinstance_ids is not None:
        sql += " "+ conjunction +" KI.keyinstance_id IN ({})"
        return read_rows_by_id(KeyInstanceRow, db, sql, sql_values, keyinstance_ids)

    cursor = db.execute(sql, sql_values)
    rows = cursor.fetchall()
    cursor.close()
    return [ KeyInstanceRow(*t) for t in rows ]


@replace_db_context_with_connection
def read_keyinstance_for_derivation(db: sqlite3.Connection, account_id: int,
        derivation_type: DerivationType, derivation_data2: bytes,
        masterkey_id: Optional[int]=None) -> Optional[KeyInstanceRow]:
    """
    Locate the keyinstance with the given `derivation_data2` field.
    """
    sql = ("SELECT KI.keyinstance_id, KI.account_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.description "
        "FROM KeyInstances AS KI "
        "WHERE account_id=? and derivation_type=?")
    if masterkey_id is not None:
        sql += " AND masterkey_id=?"
        cursor = db.execute(sql, (account_id, derivation_type, masterkey_id))
    else:
        sql += " AND masterkey_id IS NULL"
        cursor = db.execute(sql, (account_id, derivation_type))

    row = cursor.fetchone()
    cursor.close()
    return KeyInstanceRow(*row) if row is not None else None


@replace_db_context_with_connection
def read_paid_requests(db: sqlite3.Connection, account_id: int, keyinstance_ids: Sequence[int]) \
        -> List[int]:
    # TODO(nocheckin) ensure this is filtering out transactions or transaction outputs that
    # are not relevant.
    sql = ("SELECT PR.keyinstance_id "
        "FROM PaymentRequests PR "
        "INNER JOIN TransactionOutputs TXO ON TXO.keyinstance_id=PR.keyinstance_id "
        "INNER JOIN AccountTransactions ATX ON ATX.tx_hash=TXO.tx_hash AND ATX.account_id = ?"
        "WHERE PR.keyinstance_id IN ({}) AND (PR.state & {PaymentFlag.UNPAID}) != 0 "
        "GROUP BY PR.keyinstance_id "
        "HAVING PR.value IS NULL OR PR.value <= TOTAL(TXO.value)")
    return read_rows_by_id(int, db, sql, [ account_id ], keyinstance_ids)


@replace_db_context_with_connection
def read_parent_transaction_outputs(db: sqlite3.Connection, tx_hash: bytes) \
        -> List[TransactionOutputShortRow]:
    """
    When we have the spending transaction in the database, we can look up the outputs using
    the database and do not have to provide the spent output keys.
    """
    sql_values = (tx_hash,)
    sql = (
        "SELECT TXO.tx_hash, TXO.tx_index, TXO.value, TXO.keyinstance_id, TXO.flags, "
            "TXO.script_type, TXO.script_hash "
        "FROM TransactionInputs TXI "
        "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=TXI.spent_tx_hash "
        "WHERE TXI.tx_hash=?")
    cursor = db.execute(sql, sql_values)
    rows = [ TransactionOutputShortRow(*row) for row in cursor.fetchall() ]
    cursor.close()
    return rows


@replace_db_context_with_connection
def read_parent_transaction_outputs_spendable(db: sqlite3.Connection, tx_hash: bytes) \
        -> List[TransactionOutputSpendableRow]:
    """
    When we have the spending transaction in the database, we can look up the outputs using
    the database and do not have to provide the spent output keys.
    """
    sql_values = (tx_hash,)
    sql = (
        "SELECT TXO.tx_hash, TXO.tx_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
            "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data2 "
        "FROM TransactionInputs TXI "
        "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=TXI.spent_tx_hash "
        "LEFT JOIN KeyInstances KI ON KI=keyinstance_id=TXO.keyinstance_id "
        "WHERE TXI.tx_hash=?")
    cursor = db.execute(sql, sql_values)
    rows = [ TransactionOutputSpendableRow(*row) for row in cursor.fetchall() ]
    cursor.close()
    return rows


@replace_db_context_with_connection
def read_reorged_transactions(db: sqlite3.Connection, reorg_height: int) -> List[bytes]:
    """
    Identify all transactions that were verified in the orphaned chain as part of a reorg.
    """
    sql = (
        "SELECT tx_hash "
        "FROM Transactions "
        f"WHERE block_height>? AND flags&{TxFlags.StateSettled}!=0"
    )
    sql_values = (reorg_height,)
    cursor = db.execute(sql, sql_values)
    rows = [ tx_hash for (tx_hash,) in cursor.fetchall() ]
    cursor.close()
    return rows


@replace_db_context_with_connection
def read_transaction_bytes(db: sqlite3.Connection, tx_hash: bytes) -> Optional[bytes]:
    cursor = db.execute("SELECT tx_data FROM Transactions WHERE tx_hash=?", (tx_hash,))
    row = cursor.fetchone()
    if row is not None:
        return row[0]
    return None


@replace_db_context_with_connection
def read_transaction_block_info(db: sqlite3.Connection, tx_hash: bytes) -> Tuple[Optional[int],
        Optional[int]]:
    sql = "SELECT block_height, block_position FROM Transactions WHERE tx_hash=?"
    cursor = db.execute(sql, (tx_hash,))
    row = cursor.fetchone()
    cursor.close()
    if row is None:
        return None, None
    return row


@replace_db_context_with_connection
def read_transaction_flags(db: sqlite3.Connection, tx_hash: bytes) -> Optional[TxFlags]:
    sql = ("SELECT flags FROM Transactions WHERE tx_hash=?")
    cursor = db.execute(sql, (tx_hash,))
    row = cursor.fetchone()
    cursor.close()
    if row is None:
        return None
    return row[0]


@replace_db_context_with_connection
def read_transaction_hashes(db: sqlite3.Connection, account_id: Optional[int]=None) -> List[bytes]:
    if account_id is None:
        sql = "SELECT tx_hash FROM Transactions"
        cursor = db.execute(sql)
    else:
        sql = "SELECT tx_hash FROM AccountTransactions WHERE account_id=?"
        cursor = db.execute(sql, (account_id,))
    return [ tx_hash for (tx_hash,) in cursor.fetchall() ]


@replace_db_context_with_connection
def read_transaction_metadata(db: sqlite3.Connection, tx_hash: bytes) \
        -> Optional[TransactionMetadata]:
    sql = ("SELECT block_height, block_position, fee_value, date_created "
        "FROM Transactions WHERE tx_hash=?")
    cursor = db.execute(sql, (tx_hash,))
    row = cursor.fetchone()
    cursor.close()
    if row is None:
        return None
    return row


@replace_db_context_with_connection
def read_transaction_outputs_explicit(db: sqlite3.Connection, output_ids: List[TxoKeyType]) \
        -> List[TransactionOutputShortRow]:
    """
    Read all the transaction outputs for the given outpoints if they exist.
    """
    sql = (
        "SELECT tx_hash, tx_index, value, keyinstance_id, flags, script_type, script_hash "
        "FROM TransactionOutputs")
    sql_condition = "tx_hash=? AND tx_index=?"
    return read_rows_by_ids(TransactionOutputShortRow, db, sql, sql_condition, [], output_ids)


@replace_db_context_with_connection
def read_transaction_outputs_full(db: sqlite3.Connection,
        output_ids: Optional[List[TxoKeyType]]=None) -> List[TransactionOutputFullRow]:
    """
    Read all the transaction outputs for the given outpoints if they exist.
    """
    sql = (
        "SELECT tx_hash, tx_index, value, keyinstance_id, flags, script_type, script_hash, "
            "script_offset, script_length, spending_tx_hash, spending_txi_index "
        "FROM TransactionOutputs")
    if output_ids is not None:
        sql_condition = "tx_hash=? AND tx_index=?"
        return read_rows_by_ids(TransactionOutputFullRow, db, sql, sql_condition, [], output_ids)

    cursor = db.execute(sql)
    rows = cursor.fetchall()
    cursor.close()
    return [ TransactionOutputFullRow(*row) for row in rows ]


@replace_db_context_with_connection
def read_transaction_outputs_spendable_explicit(db: sqlite3.Connection, *,
        account_id: Optional[int]=None,
        tx_hash: Optional[bytes]=None,
        txo_keys: Optional[List[TxoKeyType]]=None,
        require_spends: bool=False) -> List[TransactionOutputSpendableRow]:
    """
    Read all the transaction outputs with spend information for the given outpoints if they exist.
    """
    join_term = "INNER" if require_spends else "LEFT"
    if tx_hash:
        assert txo_keys is None
        # TODO(nocheckin) What uses this? We should left join.
        sql = (
            "SELECT TXO.tx_hash, TXO.tx_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
                "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, "
                "KI.derivation_data2 "
            "FROM TransactionOutputs TXO "
            f"{join_term} JOIN KeyInstances KI ON KI=keyinstance_id=TXO.keyinstance_id "
            "WHERE TXO.tx_hash=?")
        if account_id is not None:
            sql += " AND KI.account_id=?"
            cursor = db.execute(sql, (tx_hash, account_id))
        else:
            cursor = db.execute(sql, (tx_hash,))
        rows = cursor.fetchall()
        cursor.close()
        return [ TransactionOutputSpendableRow(*row) for row in rows ]
    elif txo_keys:
        assert tx_hash is None
        # The left join is necessary here because we are looking for just the output information if
        # an output is not ours, but also the key data fields if the output is ours. An example of
        # this is that we always want to know the value of an output being spent. Remember that
        # the wallet only adds account relevant transactions to the database.
        sql = (
            "SELECT TXO.tx_hash, TXO.tx_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
                "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, "
                "KI.derivation_data2 "
            "FROM TransactionOutputs TXO "
            f"{join_term} JOIN KeyInstances KI ON KI=keyinstance_id=TXO.keyinstance_id")
        sql_condition = "TXO.tx_hash=? AND TXO.tx_index=?"
        return read_rows_by_ids(TransactionOutputSpendableRow, db, sql, sql_condition, [], txo_keys)
    else:
        raise NotImplementedError()


@replace_db_context_with_connection
def read_transaction_value_entries(db: sqlite3.Connection, account_id: int,
        tx_hashes: Optional[List[bytes]]=None, mask: Optional[TxFlags]=None) \
            -> List[TransactionValueRow]:
    # TODO(nocheckin) filter out irrelevant transactions (deleted, etc)
    if tx_hashes is None:
        sql = ("SELECT TXV.tx_hash, TOTAL(TXV.value), TX.flags, TX.block_height, "
                "TX.date_created, TX.date_updated "
            "FROM TransactionValues TXV "
            "INNER JOIN Transactions TX ON TX.tx_hash=TXV.tx_hash "
            f"WHERE account_id=? ")
        if mask is not None:
            sql += f"AND TX.flags&{mask}!=0 "
        sql += "GROUP BY tx_hash"
        cursor = db.execute(sql, (account_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [ TransactionValueRow(*v) for v in rows ]

    sql = ("SELECT TXV.tx_hash, TOTAL(TXV.value), TX.flags, TX.block_height, "
            "TX.date_created, TX.date_updated "
        "FROM TransactionValues TXV "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXV.tx_hash "
        "WHERE account_id=? AND tx_hash IN ({}) ")
    if mask is not None:
        sql += f"AND TX.flags&{mask}!=0 "
    sql += "GROUP BY tx_hash"
    return read_rows_by_id(TransactionValueRow, db, sql, [ account_id ], tx_hashes)


@replace_db_context_with_connection
def read_transaction_values(db: sqlite3.Connection, tx_hash: bytes,
        account_id: Optional[int]=None) -> List[TransactionDeltaSumRow]:
    if account_id is None:
        sql = ("SELECT account_id, TOTAL(value) "
            "FROM TransactionValues "
            "WHERE tx_hash=? "
            "GROUP BY account_id")
        cursor = db.execute(sql, [tx_hash])
    else:
        sql = ("SELECT account_id, TOTAL(value) "
            "FROM TransactionValues "
            "WHERE account_id=? AND tx_hash=? "
            "GROUP BY account_id")
        cursor = db.execute(sql, [account_id, tx_hash])
    rows = cursor.fetchall()
    cursor.close()
    return [ TransactionDeltaSumRow(*row) for row in rows ]


@replace_db_context_with_connection
def read_bip32_keys_unused(db: sqlite3.Connection, account_id: int, masterkey_id: int,
        derivation_path: Sequence[int], limit: int) -> List[KeyInstanceRow]:
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = pack_derivation_path(derivation_path)
    # Keys are created in order of sequence enumeration, so we shouldn't need to order by
    # the derivation_data2 bytes to get them ordered from oldest to newest, just id.
    sql = ("SELECT keyinstance_id, account_id, masterkey_id, derivation_type, "
        "derivation_data, derivation_data2, flags, description FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? "
            f"AND (flags&{KeyInstanceFlag.ALLOCATED_MASK})=0 "
            "AND length(derivation_data2)=? AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id "
        f"LIMIT {limit}")
    cursor = db.execute(sql, (account_id, masterkey_id,
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
def read_unverified_transactions(db: sqlite3.Connection, local_height: int) \
        -> List[Tuple[bytes, int]]:
    """
    Obtain a batch of unverified transactions.

    Remembering that transactions are not settled until we obtain the merkle proof and verify
    that it is correct for our local blockchain headers, we get a batch of transactions that
    need to be verified and settled for the caller.
    """
    # TODO There is a chance that this will pick up transactions in the database that are
    # not related to accounts.
    sql = (
        "SELECT tx_hash, block_height "
        "FROM Transactions "
        f"WHERE flags={TxFlags.StateCleared} AND block_height>0 "
            "AND block_height<? AND proof_data IS NONE "
        "ORDER BY date_added "
        "LIMIT 200"
    )
    cursor = db.execute(sql, (local_height,))
    results = list(cursor.fetchall())
    cursor.close()
    return results


@replace_db_context_with_connection
def read_wallet_balance(db: sqlite3.Connection, local_height: int,
        filter_bits: Optional[TransactionOutputFlag]=None,
        filter_mask: Optional[TransactionOutputFlag]=None) -> WalletBalance:
    coinbase_mask = TransactionOutputFlag.IS_COINBASE
    if filter_bits is None:
        filter_bits = TransactionOutputFlag.NONE
    if filter_mask is None:
        filter_mask = TransactionOutputFlag.IS_SPENT|TransactionOutputFlag.IS_FROZEN
    # NOTE(linked-balance-calculations) the general formula is used elsewhere
    sql = (
        "SELECT "
            # Confirmed.
            "TOTAL(CASE WHEN block_height > 0 "
                f"AND (flags&{coinbase_mask}=0 OR block_height+{COINBASE_MATURITY}<=?) "
                "THEN value ELSE 0 END), "
            # Unconfirmed total.
            "TOTAL(CASE WHEN block_height IS NULL OR block_height < 1 THEN value ELSE 0 END), "
            # Unmatured total.
            f"TOTAL(CASE WHEN block_height > 0 AND flags&{coinbase_mask} "
                f"AND block_height+{COINBASE_MATURITY}>? THEN value ELSE 0 END) "
        "FROM TransactionOutputs TXO "
        f"WHERE (TXO.flags&{filter_bits})=0")
    cursor = db.execute(sql, (local_height,))
    return WalletBalance(*cursor.fetchone())


def remove_transaction(db_context: DatabaseContext, tx_hash: bytes) -> concurrent.futures.Future:
    """
    Unlink a transaction from any accounts it is associated with and mark it as removed.
    """
    tx_flags = read_transaction_flags(db_context, tx_hash)
    assert tx_flags is not None
    # We do not currently allow broadcast transactions to be deleted, and may never allow it.
    if tx_flags & TxFlags.STATE_BROADCAST_MASK != 0:
        raise TransactionRemovalError("Unable to delete broadcast transactions")

    timestamp = get_timestamp()
    # Back out the association of the transaction with accounts. We do not bother clearing the
    # key id and script type from the transaction outputs at this time.
    sql1 = "DELETE FROM AccountTransactions WHERE tx_hash=?"
    sql1_values = (tx_hash,)
    sql2 = ("UPDATE TransactionOutputs "
        f"SET date_updated=?, spending_tx_hash=NULL, spending_txi_index=NULL "
        "WHERE tx_hash=? OR spending_tx_hash=?")
    sql2_values = (timestamp, tx_hash, tx_hash)
    sql3 = "UPDATE Invoices SET date_updated=?, tx_hash=NULL WHERE tx_hash=?"
    sql3_values = (timestamp, tx_hash)
    sql4 = (f"UPDATE Transactions SET date_updated=?, flags=flags|{TxFlags.REMOVED} "
        "WHERE tx_hash=?")
    sql4_values = (timestamp, tx_hash)

    def _write(db: sqlite3.Connection) -> bool:
        nonlocal sql1, sql1_values, sql2, sql2_values, sql3, sql3_values, sql4, sql4_values
        db.execute(sql1, sql1_values)
        db.execute(sql2, sql2_values)
        db.execute(sql3, sql3_values)
        cursor = db.execute(sql4, sql4_values)
        assert cursor.rowcount == 1
        return True
    return db_context.post_to_thread(_write)


def set_invoice_transaction(db_context: DatabaseContext, invoice_id: int,
        tx_hash: Optional[bytes]=None) -> concurrent.futures.Future:
    """
    Set (or clear) the transaction associated with an invoice.
    """
    timestamp = get_timestamp()
    sql1 = "UPDATE Invoices SET date_updated=?, tx_hash=? WHERE invoice_id=?"
    sql1_values = (timestamp, tx_hash, invoice_id)

    def _write(db: sqlite3.Connection) -> bool:
        nonlocal sql1, sql1_values
        cursor = db.execute(sql1, sql1_values)
        assert cursor.rowcount == 1
        return True
    return db_context.post_to_thread(_write)


def set_keyinstance_flags(db_context: DatabaseContext, key_ids: List[int],
        flags: KeyInstanceFlag, mask: Optional[KeyInstanceFlag]=None) \
            -> concurrent.futures.Future:
    if mask is None:
        # NOTE(typing) There is no gain in casting to KeyInstanceFlag.
        mask = ~flags # type: ignore
    sql = (
        "UPDATE KeyInstances "
        f"SET date_updated=?, flags=(flags&{mask})|{flags} "
        "WHERE keyinstance_id IN {}")
    # Ensure that we rollback if we are applying changes that are already in place. We expect to
    # update all the rows we are asked to update, and this will filter out the rows that already
    # have any of the flags we intend to set.
    # NOTE If any caller wants to do overwrites or partial updates then that should be a standard
    # policy optionally passed into all update calls.
    sql_values = [ get_timestamp() ]

    def _write(db: sqlite3.Connection) -> bool:
        nonlocal sql, sql_values, key_ids
        rows_updated = update_rows_by_id(db, sql, sql_values, key_ids)
        if rows_updated != len(key_ids):
            raise DatabaseUpdateError(f"Rollback as only {rows_updated} of {len(key_ids)} "
                "rows were updated")
        return True
    return db_context.post_to_thread(_write)


def set_transaction_dispatched(db_context: DatabaseContext, tx_hash: bytes) \
        -> concurrent.futures.Future:
    """
    Set a transaction to dispatched state.

    If the transaction is in a pre-dispatched state, this should succeed and will return `True`.
    If the transaction is not in a pre-dispatched state, then this will return `False` and no
    change will be made.
    """
    mask_bits = ~TxFlags.STATE_MASK
    set_bits = TxFlags.StateDispatched
    ignore_bits = TxFlags.StateDispatched | TxFlags.STATE_BROADCAST_MASK
    timestamp = get_timestamp()
    sql = ("UPDATE Transactions "
        f"SET date_updated=?, flags=(flags&{mask_bits})|{set_bits} "
        f"WHERE tx_hash=? AND flags&{ignore_bits}=0")

    def _write(db: sqlite3.Connection) -> bool:
        nonlocal sql, timestamp, tx_hash
        cursor = db.execute(sql, (timestamp, tx_hash))
        if cursor.rowcount == 0:
            # Rollback the database transaction (nothing to rollback but upholding the convention).
            raise DatabaseUpdateError("Rollback as nothing updated")
        return True
    return db_context.post_to_thread(_write)


def set_transactions_reorged(db_context: DatabaseContext, tx_hashes: List[bytes]) \
        -> concurrent.futures.Future:
    """
    Reset transactions back to unverified state as a batch.

    NOTE This may not restore the correct block height, which is prohibitive. 0 is unconfirmed,
    and -1 is unconfirmed parents. We do not have the information to know if it has unconfirmed
    parents.
    """
    timestamp = get_timestamp()
    sql = ("UPDATE Transactions "
        f"SET date_updated=?, flags=(flags&?)|?, block_height=0 "
        "WHERE tx_hash IN {}")
    sql_values = [ timestamp, TxFlags.StateCleared, ~TxFlags.StateSettled ]

    def _write(db: sqlite3.Connection) -> bool:
        nonlocal sql, sql_values, tx_hashes
        rows_updated = update_rows_by_id(db, sql, sql_values, tx_hashes)
        if rows_updated < len(tx_hashes):
            # Rollback the database transaction (nothing to rollback but upholding the convention).
            raise DatabaseUpdateError("Rollback as nothing updated")
        return True
    return db_context.post_to_thread(_write)


def set_transaction_output_flags(db_context: DatabaseContext, txo_keys: List[TxoKeyType],
        flags: TransactionOutputFlag, mask: Optional[TransactionOutputFlag]=None) \
            -> concurrent.futures.Future:
    if mask is None:
        # NOTE(typing) There is no gain in casting to TransactionOutputFlag.
        mask = ~flags # type: ignore
    sql = ("UPDATE TransactionOutputs "
        f"SET date_updated=?, flags=(flags&{mask})|{flags}")
    sql_id_expression = "tx_hash=? AND tx_index=?"
    sql_values = [ get_timestamp() ]

    def _write(db: sqlite3.Connection) -> bool:
        nonlocal sql, sql_id_expression, sql_values, txo_keys
        rows_updated = update_rows_by_ids(db, sql, sql_id_expression, sql_values, txo_keys)
        if rows_updated != len(txo_keys):
            raise DatabaseUpdateError(f"Rollback as only {rows_updated} of {len(txo_keys)} "
                "rows were updated")
        return True
    return db_context.post_to_thread(_write)


def set_transaction_proof(db_context: DatabaseContext, tx_hash: bytes, block_height: int,
        block_position: int, proof: TxProof) -> concurrent.futures.Future:
    def _write(db: sqlite3.Connection) -> bool:
        nonlocal tx_hash, block_height, block_position, proof
        _set_transaction_proof(db, tx_hash, block_height, block_position, proof)
        return True
    return db_context.post_to_thread(_write)


def _set_transaction_proof(db: sqlite3.Connection, tx_hash: bytes, block_height: int,
        block_position: int, proof: TxProof) -> None:
    """
    Execute the query that sets the proof data for a transaction.

    This should only be called in the context of the writer thread.
    """
    timestamp = get_timestamp()
    clear_bits = ~TxFlags.STATE_MASK
    set_bits = TxFlags.StateSettled
    query = ("UPDATE Transactions "
        "SET date_updated=?, proof_data=?, block_height=?, block_position=?, "
            f"flags=(flags&{clear_bits})|{set_bits} "
        "WHERE tx_hash=?")
    # NOTE(rt12) at some later point we will have a standard binary packed proof format
    # that we can use, i.e. bitcoin association's specification.
    db.execute(query, (timestamp, pack_proof(proof), block_height, block_position, tx_hash))

