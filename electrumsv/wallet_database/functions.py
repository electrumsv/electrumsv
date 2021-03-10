import concurrent.futures
import json
try:
    # Linux expects the latest package version of 3.34.0 (as of pysqlite-binary 0.4.5)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.34.0 (as of 2021-01-13).
    # Windows builds use the official Python 3.9.1 builds and bundled version of 3.33.0.
    import sqlite3 # type: ignore
from typing import Any, cast, Iterable, List, Optional, Sequence, Tuple

from ..bitcoin import COINBASE_MATURITY
from ..constants import (DerivationType, KeyInstanceFlag, pack_derivation_path,
    PaymentFlag, ScriptType, TransactionOutputFlag, TxFlags, unpack_derivation_path,
    WalletEventFlag)
from ..logs import logs
from ..types import TxoKeyType

from .exceptions import (DatabaseUpdateError, KeyInstanceNotFoundError,
    TransactionAlreadyExistsError, TransactionRemovalError)
from .sqlite_support import DatabaseContext, replace_db_context_with_connection
from .types import (AccountRow, AccountTransactionRow, AccountTransactionDescriptionRow,
    HistoryListRow, InvoiceAccountRow, InvoiceRow, KeyInstanceRow,
    KeyInstanceScriptHashRow, KeyListRow, MasterKeyRow, PaymentRequestRow,
    PaymentRequestUpdateRow, SpendConflictType, TransactionBlockRow,
    TransactionDeltaSumRow, TransactionExistsRow, TransactionInputAddRow, TransactionLinkState,
    # TransactionDescriptionResult,
    TransactionOutputAddRow, TransactionOutputSpendableRow,
    TransactionValueRow, TransactionMetadata,
    TransactionOutputFullRow, TransactionOutputShortRow,
    TransactionOutputSpendableRow2, TransactionRow,
    TransactionSubscriptionRow, TxProof, TxProofResult,
    WalletBalance, WalletDataRow, WalletEventRow)
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
            f"AND (flags&{KeyInstanceFlag.IS_ASSIGNED})=0 "
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


def create_invoices(db_context: DatabaseContext, entries: Iterable[InvoiceRow]) \
        -> concurrent.futures.Future:
    sql = ("INSERT INTO Invoices "
        "(account_id, tx_hash, payment_uri, description, invoice_flags, value, "
        "invoice_data, date_expires, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    # Discard the first column for the id.
    timestamp = get_timestamp()
    rows = [ (*entry[1:], timestamp) for entry in entries ]
    def _write(db: sqlite3.Connection):
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_keyinstances(db_context: DatabaseContext, entries: Iterable[KeyInstanceRow]) \
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


def create_keyinstance_scripts(db_context: DatabaseContext,
        entries: Iterable[KeyInstanceScriptHashRow]) -> concurrent.futures.Future:
    sql = ("INSERT INTO KeyInstanceScripts "
        "(keyinstance_id, script_type, script_hash, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?)")
    timestamp = get_timestamp()
    rows = [ (*t, timestamp, timestamp) for t in entries]
    def _write(db: sqlite3.Connection):
        nonlocal sql, rows
        db.executemany(sql, rows)
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


def create_payment_requests(db_context: DatabaseContext,
        entries: Iterable[PaymentRequestRow]) -> concurrent.futures.Future:
    sql = (
        "INSERT INTO PaymentRequests "
        "(paymentrequest_id, keyinstance_id, state, value, expiration, description, date_created, "
            "date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    timestamp = get_timestamp()
    sql_values = [ (*t[:-1], timestamp, timestamp) for t in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, sql_values
        db.executemany(sql, sql_values)
    return db_context.post_to_thread(_write)


def create_transaction_outputs(db_context: DatabaseContext,
        entries: Iterable[TransactionOutputShortRow]) -> concurrent.futures.Future:
    sql = ("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, "
        "flags, script_type, script_hash, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    timestamp = get_timestamp()
    db_rows = [ (*t, timestamp, timestamp) for t in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, db_rows
        db.executemany(sql, db_rows)
    return db_context.post_to_thread(_write)


def create_transactions(db_context: DatabaseContext, rows: List[TransactionRow]) \
        -> concurrent.futures.Future:
    sql = ("INSERT INTO Transactions (tx_hash, tx_data, flags, block_hash, "
        "block_height, block_position, fee_value, description, version, locktime, "
        "date_created, date_updated) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")

    for row in rows:
        assert type(row.tx_hash) is bytes and row.tx_bytes is not None
        assert (row.flags & TxFlags.HAS_BYTEDATA) == 0, "this flag is not applicable"
        assert row.date_created > 0 and row.date_updated > 0

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        logger.debug("add %d transactions", len(rows))
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_wallet_datas(db_context: DatabaseContext, entries: Iterable[WalletDataRow]) \
        -> concurrent.futures.Future:
    sql = ("INSERT INTO WalletData (key, value, date_created, date_updated) "
        "VALUES (?, ?, ?, ?)")
    timestamp = get_timestamp()
    rows = []
    for entry in entries:
        assert type(entry.key) is str, f"bad key '{entry.key}'"
        data = json.dumps(entry.value)
        rows.append([ entry.key, data, timestamp, timestamp])

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_wallet_events(db_context: DatabaseContext, entries: Iterable[WalletEventRow]) \
        -> concurrent.futures.Future:
    sql = (
        "INSERT INTO WalletEvents "
            "(event_id, event_type, account_id, event_flags, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?)")
    # Duplicate the last column for date_updated = date_created
    rows = [ (*t, t[-1]) for t in entries ]
    def _write(db: sqlite3.Connection):
        nonlocal rows, sql
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def delete_invoices(db_context: DatabaseContext, entries: Iterable[Tuple[int]]) \
        -> concurrent.futures.Future:
    # TODO(optimisation) This should be batched deletion not multiple single deletions
    sql = "DELETE FROM Invoices WHERE invoice_id=?"
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, entries
        db.executemany(sql, entries)
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


def delete_wallet_data(db_context: DatabaseContext, key: str) -> concurrent.futures.Future:
    sql = "DELETE FROM WalletData WHERE key=?"
    timestamp = get_timestamp()

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, key
        db.execute(sql, (key,))
    return db_context.post_to_thread(_write)


@replace_db_context_with_connection
def read_account_balance(db: sqlite3.Connection, account_id: int, local_height: int,
        filter_bits: Optional[TransactionOutputFlag]=None,
        filter_mask: Optional[TransactionOutputFlag]=None) -> WalletBalance:
    coinbase_mask = TransactionOutputFlag.IS_COINBASE
    # This defaults to . . .
    if filter_bits is None:
        filter_bits = TransactionOutputFlag.NONE
    if filter_mask is None:
        filter_mask = TransactionOutputFlag.IS_SPENT|TransactionOutputFlag.IS_FROZEN
    # NOTE(linked-balance-calculations) the general formula is used elsewhere
    sql = (
        "SELECT "
            # Confirmed.
            "CAST(TOTAL(CASE WHEN TX.block_height > 0 "
                f"AND (TX.flags&{coinbase_mask}=0 OR TX.block_height+{COINBASE_MATURITY}<=?) "
                "THEN TXO.value ELSE 0 END) AS INT), "
            # Unconfirmed total.
            "CAST(TOTAL(CASE WHEN TX.block_height < 1 THEN TXO.value ELSE 0 END) AS INT), "
            # Unmatured total.
            f"CAST(TOTAL(CASE WHEN TX.block_height > 0 AND TX.flags&{coinbase_mask} "
                f"AND TX.block_height+{COINBASE_MATURITY}>? THEN TXO.value ELSE 0 END) AS INT) "
        "FROM AccountTransactions ATX "
        "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=ATX.tx_hash "
        "INNER JOIN Transactions TX ON TX.tx_hash=ATX.tx_hash "
        "WHERE ATX.account_id=? AND TXO.keyinstance_id IS NOT NULL AND "
            f"(TXO.flags&{filter_mask})={filter_bits}")
    row = db.execute(sql, (local_height, local_height, account_id)).fetchone()
    if row is None:
        return WalletBalance(0, 0, 0)
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
        return TransactionDeltaSumRow(account_id, 0, 0)
    return TransactionDeltaSumRow(*row)


@replace_db_context_with_connection
def read_account_transaction_descriptions(db: sqlite3.Connection, account_id: Optional[int]=None) \
        -> List[AccountTransactionDescriptionRow]:
    sql = (
        "SELECT account_id, tx_hash, description "
        "FROM AccountTransactions "
        "WHERE description IS NOT NULL")
    sql_values: List[Any] = []
    if account_id is not None:
        sql += " AND account_id=?"
        sql_values = [ account_id ]
    return [ AccountTransactionDescriptionRow(*row)
        for row in db.execute(sql, sql_values).fetchall() ]


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


# TODO(no-merge) test default
# TODO(no-merge) test exclude_frozen
# TODO(no-merge) test confirmed_only
# TODO(no-merge) test mature
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
        sql += f" AND TX.flags&{TxFlags.STATE_SETTLED}!=0"
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


# TODO(no-merge) test default
# TODO(no-merge) test exclude_frozen
# TODO(no-merge) test confirmed_only
# TODO(no-merge) test mature
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
        sql += f" AND TX.flags&{TxFlags.STATE_SETTLED}!=0"
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
def read_accounts(db: sqlite3.Connection) -> List[AccountRow]:
    sql = (
        "SELECT account_id, default_masterkey_id, default_script_type, account_name "
        "FROM Accounts")
    return [ AccountRow(*row) for row in db.execute(sql).fetchall() ]


@replace_db_context_with_connection
def read_history_list(db: sqlite3.Connection, account_id: int,
        keyinstance_ids: Optional[Sequence[int]]=None) -> List[HistoryListRow]:
    if keyinstance_ids:
        # Used for the address dialog.
        sql = ("SELECT TXV.tx_hash, TX.flags, TX.block_height, TX.block_position, "
                "TOTAL(TXV.value), TX.date_created "
            "FROM TransactionValues TXV "
            "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
            "WHERE TXV.account_id=? AND TXV.keyinstance_id IN ({}) AND "
                f"(TX.flags & {TxFlags.MASK_STATE})!=0 "
            "GROUP BY TXV.tx_hash")
        return read_rows_by_id(HistoryListRow, db, sql, [ account_id ], keyinstance_ids)

    # Used for the history list and export.
    sql = ("SELECT TXV.tx_hash, TX.flags, TX.block_height, TX.block_position, "
            "TOTAL(TXV.value), TX.date_created "
        "FROM TransactionValues TXV "
        "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
        f"WHERE TXV.account_id=? AND (TX.flags & {TxFlags.MASK_STATE})!=0 "
        "GROUP BY TXV.tx_hash")
    cursor = db.execute(sql, (account_id,))
    rows = cursor.fetchall()
    cursor.close()
    return [ HistoryListRow(*t) for t in rows ]


@replace_db_context_with_connection
def read_invoice(db: sqlite3.Connection, *, invoice_id: Optional[int]=None,
        tx_hash: Optional[bytes]=None, payment_uri: Optional[str]=None) -> Optional[InvoiceRow]:
    sql = ("SELECT invoice_id, account_id, tx_hash, payment_uri, description, "
        "invoice_flags, value, invoice_data, date_expires, date_created FROM Invoices")
    sql_values: List[Any]
    if invoice_id is not None:
        sql += " WHERE invoice_id=?"
        sql_values = [ invoice_id ]
    elif tx_hash is not None:
        sql += " WHERE tx_hash=?"
        sql_values = [ tx_hash ]
    elif payment_uri is not None:
        sql += " WHERE payment_uri=?"
        sql_values = [ payment_uri ]
    else:
        raise NotImplementedError("no valid parameters")
    t = db.execute(sql, sql_values).fetchone()
    if t is not None:
        return InvoiceRow(t[0], t[1], t[2], t[3], t[4], PaymentFlag(t[5]), t[6], t[7], t[8], t[9])
    return None


@replace_db_context_with_connection
def read_invoice_duplicate(db: sqlite3.Connection, value: int, payment_uri: str) \
        -> Optional[InvoiceRow]:
    sql = (
        "SELECT invoice_id, account_id, tx_hash, payment_uri, description, invoice_flags, value, "
            "invoice_data, date_expires, date_created "
        "FROM Invoices "
        "WHERE value=? AND payment_uri=?")
    sql_values = [ value, payment_uri ]
    t = db.execute(sql, sql_values).fetchone()
    if t is not None:
        return InvoiceRow(t[0], t[1], t[2], t[3], t[4], PaymentFlag(t[5]), t[6], t[7], t[8], t[9])
    return None


@replace_db_context_with_connection
def read_invoices_for_account(db: sqlite3.Connection, account_id: int, flags: Optional[int]=None,
        mask: Optional[int]=None) -> List[InvoiceAccountRow]:
    sql = ("SELECT invoice_id, payment_uri, description, invoice_flags, value, "
        "date_expires, date_created FROM Invoices WHERE account_id=?")
    sql_values: List[Any] = [ account_id ]
    # We keep the filtering in case we want to let the user define whether to show only
    # invoices in a certain state. If we never do that, we can remove this.
    clause, extra_values = flag_clause("invoice_flags", flags, mask)
    if clause:
        sql += f" AND {clause}"
        sql_values.extend(extra_values)
    rows = db.execute(sql, sql_values).fetchall()
    return [ InvoiceAccountRow(t[0], t[1], t[2], PaymentFlag(t[3]), t[4], t[5], t[6])
        for t in rows ]


@replace_db_context_with_connection
def read_keys_for_transaction_subscriptions(db: sqlite3.Connection, account_id: int) \
        -> List[TransactionSubscriptionRow]:
    """
    Find all script hashes we need to monitor for our transaction-related script hash subscriptions.

    For any account-related transaction we would want the script hash of the first output to
    be a canary for events related to this transaction whether it was malleated or not. However:
    - ElectrumX does not index OP_FALSE OP_RETURN and we do not have a way to tell if the first
      output is or is not that, if the output is not ours.
    - We may not have any outputs in the transaction, and may solely be spending in it.
    - There may not be any non-OP_FALSE OP_RETURN outputs in the transaction at all, regardless of
      whose they are.
    For these reasons we stick to our outputs (whether spends or receives) related to any given
    transaction.

    We are not concerned about reorgs, the reorg processing should happen independently and even
    on account/wallet load before these subscriptions are made.
    """
    sql_values = [account_id, account_id]
    sql = ("""
        WITH summary AS (
            SELECT TXO.tx_hash,
                1 AS put_type,
                TXO.keyinstance_id,
                TXO.script_hash,
                ROW_NUMBER() OVER(PARTITION BY TXO.tx_hash
                                      ORDER BY TXO.tx_index ASC) AS rk
            FROM TransactionOutputs TXO
            INNER JOIN AccountTransactions ATX ON ATX.tx_hash = TXO.tx_hash
            INNER JOIN Transactions TX ON TX.tx_hash = TXO.tx_hash
            WHERE TXO.keyinstance_id IS NOT NULL AND ATX.account_id=? AND TX.proof_data IS NULL
            UNION
            SELECT TXI.tx_hash,
                2 AS put_type,
                TXO.keyinstance_id,
                TXO.script_hash,
                ROW_NUMBER() OVER(PARTITION BY TXI.tx_hash
                                      ORDER BY TXI.txi_index ASC) AS rk
            FROM TransactionInputs TXI
            INNER JOIN AccountTransactions ATX ON ATX.tx_hash = TXI.tx_hash
            INNER JOIN Transactions TX ON TX.tx_hash = TXI.tx_hash
            INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=TXI.spent_tx_hash
                AND TXO.tx_index=TXI.spent_txo_index
            WHERE TXO.keyinstance_id IS NOT NULL AND ATX.account_id=? AND TX.proof_data IS NULL)
        SELECT s.tx_hash, s.put_type, s.keyinstance_id, s.script_hash
        FROM summary s
        WHERE s.rk = 1
        ORDER BY s.put_type""")

    rows = db.execute(sql, sql_values).fetchall()
    return [ TransactionSubscriptionRow(*t) for t in rows ]


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
    sql_values = [account_id]
    sql = (
        "SELECT KI.keyinstance_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.description, KI.date_updated, "
            "TXO.tx_hash, TXO.tx_index, TXO.flags, TXO.script_type, coalesce(TXO.value, 0) "
        "FROM KeyInstances AS KI "
        "LEFT JOIN TransactionOutputs TXO ON TXO.keyinstance_id = KI.keyinstance_id "
        "WHERE KI.account_id = ?")
    if keyinstance_ids is not None:
        sql += " AND KI.keyinstance_id IN ({})"
        return read_rows_by_id(KeyListRow, db, sql, sql_values, keyinstance_ids)

    cursor = db.execute(sql, sql_values)
    rows = cursor.fetchall()
    cursor.close()
    return [ KeyListRow(*t) for t in rows ]


@replace_db_context_with_connection
def read_keyinstance_scripts(db: sqlite3.Connection, keyinstance_ids: Sequence[int]) \
        -> List[KeyInstanceScriptHashRow]:
    sql = (
        "SELECT keyinstance_id, script_type, script_hash "
        "FROM KeyInstanceScripts "
        "WHERE keyinstance_id IN ({})")
    return read_rows_by_id(KeyInstanceScriptHashRow, db, sql, [], keyinstance_ids)


@replace_db_context_with_connection
def read_keyinstance(db: sqlite3.Connection, *, account_id: Optional[int]=None,
        keyinstance_id: Optional[Sequence[int]]=None) -> Optional[KeyInstanceRow]:
    """
    Read one explicitly requested keyinstance.
    """
    sql_values: List[Any] = [ keyinstance_id ]
    sql = (
        "SELECT KI.keyinstance_id, KI.account_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.description "
        "FROM KeyInstances AS KI "
        "WHERE keyinstance_id=?")
    if account_id is not None:
        sql += " AND account_id=?"
        sql_values.append(account_id)
    row = db.execute(sql, sql_values).fetchone()
    # TODO(?) Should we just union these values with int, and avoid the copy that comes with
    #   repackaging the tuple we get from the database?
    return KeyInstanceRow(row[0], row[1], row[2], DerivationType(row[3]), row[4], row[5],
        KeyInstanceFlag(row[6]), row[7]) if row is not None else None


@replace_db_context_with_connection
def read_keyinstances(db: sqlite3.Connection, *, account_id: Optional[int]=None,
        keyinstance_ids: Optional[Sequence[int]]=None, flags: Optional[KeyInstanceFlag]=None,
        mask: Optional[KeyInstanceFlag]=None) -> List[KeyInstanceRow]:
    """
    Read explicitly requested keyinstances.
    """
    sql_values = []
    sql = (
        "SELECT KI.keyinstance_id, KI.account_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.description "
        "FROM KeyInstances AS KI")
    if account_id is None:
        conjunction = "WHERE"
    else:
        sql += " WHERE account_id=?"
        sql_values.append(account_id)
        conjunction = "AND"

    clause, extra_values = flag_clause("KI.flags", flags, mask)
    if clause:
        sql += f" {conjunction} {clause}"
        sql_values.extend(extra_values)
        conjunction = "AND"

    if keyinstance_ids is not None:
        sql += " "+ conjunction +" KI.keyinstance_id IN ({})"
        return read_rows_by_id(KeyInstanceRow, db, sql, sql_values, keyinstance_ids)

    return [ KeyInstanceRow(*row) for row in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_keyinstance_derivation_index_last(db: sqlite3.Connection, account_id: int,
        masterkey_id: int, derivation_path: Sequence[int]) -> Optional[int]:
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = pack_derivation_path(derivation_path)
    # Keys are created in order of sequence enumeration, so we shouldn't need to order by
    # the derivation_data2 bytes to get them ordered from oldest to newest, just id.
    sql = ("SELECT derivation_data2 FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? "
            f"AND (flags&{KeyInstanceFlag.IS_ASSIGNED})=0 "
            "AND length(derivation_data2)=? AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id DESC "
        "LIMIT 1")
    cursor = db.execute(sql, (account_id, masterkey_id,
        len(prefix_bytes)+4,  # The length of the parent path and sequence index.
        len(prefix_bytes),    # Just the length of the parent path.
        prefix_bytes))        # The packed parent path bytes.
    row = cursor.fetchone()
    if row is not None:
        return unpack_derivation_path(row[0])[-1]
    return None


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
def read_masterkeys(db: sqlite3.Connection) -> List[MasterKeyRow]:
    sql = (
        "SELECT masterkey_id, parent_masterkey_id, derivation_type, derivation_data "
        "FROM MasterKeys")
    return [ MasterKeyRow(*row) for row in db.execute(sql).fetchall() ]


@replace_db_context_with_connection
def read_paid_requests(db: sqlite3.Connection, account_id: int, keyinstance_ids: Sequence[int]) \
        -> List[int]:
    # TODO(no-merge) ensure this is filtering out transactions or transaction outputs that
    # are not relevant.
    sql = ("SELECT PR.keyinstance_id "
        "FROM PaymentRequests PR "
        "INNER JOIN TransactionOutputs TXO ON TXO.keyinstance_id=PR.keyinstance_id "
        "INNER JOIN AccountTransactions ATX ON ATX.tx_hash=TXO.tx_hash AND ATX.account_id = ? "
        "WHERE PR.keyinstance_id IN ({}) "
            f"AND (PR.state & {PaymentFlag.UNPAID}) != 0 "
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
def read_payment_request(db: sqlite3.Connection, *, request_id: Optional[int]=None,
        keyinstance_id: Optional[int]=None) -> Optional[PaymentRequestRow]:
    sql = (
        "SELECT paymentrequest_id, keyinstance_id, state, value, expiration, "
            "description, date_created "
        "FROM PaymentRequests")
    if request_id is not None:
        sql += f" WHERE paymentrequest_id=?"
        sql_values = [ request_id ]
    elif keyinstance_id is not None:
        sql += f" WHERE keyinstance_id=?"
        sql_values = [ keyinstance_id ]
    else:
        # TODO(no-merge) do not raise Exception
        raise NotImplementedError("request_id and keyinstance_id not supported")
    t = db.execute(sql, sql_values).fetchone()
    if t is not None:
        return PaymentRequestRow(t[0], t[1], PaymentFlag(t[2]), t[3], t[4], t[5], t[6])
    return None


@replace_db_context_with_connection
def read_payment_requests(db: sqlite3.Connection, account_id: Optional[int]=None,
        flags: Optional[int]=None, mask: Optional[int]=None) -> List[PaymentRequestRow]:
    sql = (
        "SELECT P.paymentrequest_id, P.keyinstance_id, P.state, P.value, P.expiration, "
            "P.description, P.date_created FROM PaymentRequests P")
    sql_values: List[Any] = []
    conjunction = "WHERE"
    if account_id is not None:
        sql = sql +" INNER JOIN KeyInstances K USING(keyinstance_id) WHERE K.account_id=?"
        sql_values.append(account_id)
        conjunction = "AND"
    clause, extra_values = flag_clause("P.state", flags, mask)
    if clause:
        sql += f" {conjunction} {clause}"
        sql_values.extend(extra_values)
        conjunction = "AND"
    return [ PaymentRequestRow(t[0], t[1], PaymentFlag(t[2]), t[3], t[4], t[5], t[6])
        for t in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_reorged_transactions(db: sqlite3.Connection, reorg_height: int) -> List[bytes]:
    """
    Identify all transactions that were verified in the orphaned chain as part of a reorg.
    """
    sql = (
        "SELECT tx_hash "
        "FROM Transactions "
        f"WHERE block_height>? AND flags&{TxFlags.STATE_SETTLED}!=0"
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


# TODO(no-merge) descriptions have moved to AccountTransactions
# @replace_db_context_with_connection
# def read_transaction_descriptions(db: sqlite3.Connection,
#         tx_hashes: Optional[Sequence[bytes]]=None) -> List[TransactionDescriptionResult]:
#     # Shared wallet data between all accounts.
#     def read_descriptions(self,
#             ) -> :
#         query = self.READ_DESCRIPTION_SQL
#         return self._get_many_common(query, None, None, tx_hashes)
#     sql = (
#         "SELECT tx_hash, T.description "
#         "FROM Transactions T "
#         "WHERE T.description IS NOT NULL")
#     sql = "SELECT block_height, block_position FROM Transactions WHERE tx_hash=?"
#     cursor = db.execute(sql, (tx_hash,))
#     row = cursor.fetchone()
#     cursor.close()
#     if row is None:
#         return None, None
#     return row

@replace_db_context_with_connection
def read_transactions_exist(db: sqlite3.Connection, tx_hashes: Sequence[bytes],
        account_id: Optional[int]=None) -> List[TransactionExistsRow]:
    """
    Return the subset of transactions that are already present in the database.
    """
    if account_id is None:
        sql = ("SELECT tx_hash, flags, NULL "
            "FROM Transactions "
            "WHERE tx_hash IN ({})")
        return read_rows_by_id(TransactionExistsRow, db, sql, [ ], tx_hashes)

    sql = ("SELECT T.tx_hash, T.flags, ATX.account_id "
        "FROM Transactions T "
        "LEFT JOIN AccountTransactions ATX ON ATX.tx_hash=T.tx_hash AND ATX.account_id=? "
        "WHERE T.tx_hash IN ({})")
    return read_rows_by_id(TransactionExistsRow, db, sql, [ account_id ], tx_hashes)


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
    row = db.execute(sql, (tx_hash,)).fetchone()
    return None if row is None else TransactionMetadata(*row)


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
        # TODO(no-merge) What uses this? We should left join.
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
            f"{join_term} JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id")
        sql_condition = "TXO.tx_hash=? AND TXO.tx_index=?"
        return read_rows_by_ids(TransactionOutputSpendableRow, db, sql, sql_condition, [], txo_keys)
    else:
        raise NotImplementedError()


@replace_db_context_with_connection
def read_transaction_proof(db: sqlite3.Connection, tx_hashes: Sequence[bytes]) \
        -> List[TxProofResult]:
    sql = "SELECT tx_hash, proof_data FROM Transactions WHERE tx_hash IN ({})"
    return read_rows_by_id(TxProofResult, db, sql, [], tx_hashes)


@replace_db_context_with_connection
def read_transaction_value_entries(db: sqlite3.Connection, account_id: int, *,
        tx_hashes: Optional[List[bytes]]=None, mask: Optional[TxFlags]=None) \
            -> List[TransactionValueRow]:
    # TODO(no-merge) filter out irrelevant transactions (deleted, etc)
    if tx_hashes is None:
        sql = ("SELECT TXV.tx_hash, TOTAL(TXV.value), TX.flags, TX.block_height, "
                "TX.date_created, TX.date_updated "
            "FROM TransactionValues TXV "
            "INNER JOIN Transactions TX ON TX.tx_hash=TXV.tx_hash "
            f"WHERE account_id=? ")
        if mask is not None:
            sql += f"AND TX.flags&{mask}!=0 "
        sql += "GROUP BY TXV.tx_hash"
        cursor = db.execute(sql, (account_id,))
        rows = cursor.fetchall()
        cursor.close()
        return [ TransactionValueRow(*v) for v in rows ]

    sql = ("SELECT TXV.tx_hash, TOTAL(TXV.value), TX.flags, TX.block_height, "
            "TX.date_created, TX.date_updated "
        "FROM TransactionValues TXV "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXV.tx_hash "
        "WHERE account_id=? AND TX.tx_hash IN ({}) ")
    if mask is not None:
        sql += f"AND TX.flags&{mask}!=0 "
    sql += "GROUP BY TXV.tx_hash"
    return read_rows_by_id(TransactionValueRow, db, sql, [ account_id ], tx_hashes)


@replace_db_context_with_connection
def read_transaction_values(db: sqlite3.Connection, tx_hash: bytes,
        account_id: Optional[int]=None) -> List[TransactionDeltaSumRow]:
    if account_id is None:
        sql = ("SELECT account_id, TOTAL(value), COUNT(value) "
            "FROM TransactionValues "
            "WHERE tx_hash=? "
            "GROUP BY account_id")
        cursor = db.execute(sql, [tx_hash])
    else:
        sql = ("SELECT account_id, TOTAL(value), COUNT(value) "
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
            f"AND (flags&{KeyInstanceFlag.IS_ASSIGNED})=0 "
            "AND length(derivation_data2)=? AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id "
        f"LIMIT {limit}")
    cursor = db.execute(sql, (account_id, masterkey_id,
        len(prefix_bytes)+4,  # The length of the parent path and sequence index.
        len(prefix_bytes),    # Just the length of the parent path.
        prefix_bytes))        # The packed parent path bytes.
    rows = cursor.fetchall()
    cursor.close()

    # TODO(no-merge) work out if we need all this, or just keyinstance_id and the derivation
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
    # TODO(no-merge) There is a chance that this will pick up transactions in the database that
    # are not related to accounts. If a transaction has is associated with a block and an account
    # we should probably fetch the proof.
    sql = (
        "SELECT tx_hash, block_height "
        "FROM Transactions "
        f"WHERE flags={TxFlags.STATE_CLEARED} AND block_height>0 "
            "AND block_height<? AND proof_data IS NULL "
        "ORDER BY date_created "
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
            "CAST(TOTAL(CASE WHEN TX.block_height > 0 "
                f"AND (TX.flags&{coinbase_mask}=0 OR TX.block_height+{COINBASE_MATURITY}<=?) "
                "THEN TXO.value ELSE 0 END) AS INT), "
            # Unconfirmed total.
            "CAST(TOTAL(CASE WHEN TX.block_height < 1 THEN TXO.value ELSE 0 END) AS INT), "
            # Unmatured total.
            f"CAST(TOTAL(CASE WHEN TX.block_height > 0 AND TX.flags&{coinbase_mask} "
                f"AND TX.block_height+{COINBASE_MATURITY}>? THEN TXO.value ELSE 0 END) AS INT) "
        "FROM TransactionOutputs TXO "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
        f"WHERE TXO.keyinstance_id IS NOT NULL AND (TXO.flags&{filter_mask})={filter_bits}")
    cursor = db.execute(sql, (local_height, local_height))
    return WalletBalance(*cursor.fetchone())


@replace_db_context_with_connection
def read_wallet_datas(db: sqlite3.Connection) -> Any:
    sql = "SELECT key, value FROM WalletData"
    cursor = db.execute(sql)
    rows = cursor.fetchall()
    return [ WalletDataRow(row[0], json.loads(row[1])) for row in rows ]


@replace_db_context_with_connection
def read_wallet_events(db: sqlite3.Connection, account_id: Optional[int]=None,
        mask: WalletEventFlag=WalletEventFlag.NONE) -> List[WalletEventRow]:
    sql_values: List[Any]
    if mask is None:
        sql_values = []
        sql = (
            "SELECT event_id, event_type, account_id, event_flags, date_created "
            "FROM WalletEvents")
        if account_id is not None:
            sql += "WHERE account_id=? "
            sql_values.append(account_id)
        sql += "ORDER BY date_created"
    else:
        sql_values = [ mask, mask ]
        sql = (
            "SELECT event_id, event_type, account_id, event_flags, date_created "
            "FROM WalletEvents "
            "WHERE (event_flags&?)=? ")
        if account_id is not None:
            sql += "AND account_id=? "
            sql_values.append(account_id)
        sql += "ORDER BY date_created"
    return [ WalletEventRow(*row) for row in db.execute(sql, sql_values).fetchall() ]


def remove_transaction(db_context: DatabaseContext, tx_hash: bytes) -> concurrent.futures.Future:
    """
    Unlink a transaction from any accounts it is associated with and mark it as removed.
    """
    tx_flags = read_transaction_flags(db_context, tx_hash)
    assert tx_flags is not None
    # We do not currently allow broadcast transactions to be deleted, and may never allow it.
    if tx_flags & TxFlags.MASK_STATE_BROADCAST != 0:
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


def reserve_keyinstance(db_context: DatabaseContext, account_id: int, masterkey_id: int,
        derivation_path: Sequence[int], allocation_flags: Optional[KeyInstanceFlag]=None) \
            -> concurrent.futures.Future:
    """
    Allocate one keyinstance for the caller's usage.

    Returns the allocated `keyinstance_id` if successful.
    Raises `KeyInstanceNotFoundError` if there are no available key instances.
    Raises `DatabaseUpdateError` if something else allocated the selected keyinstance first.
    """
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = pack_derivation_path(derivation_path)
    if allocation_flags is None:
        allocation_flags = KeyInstanceFlag.NONE
    allocation_flags |= KeyInstanceFlag.IS_ACTIVE | KeyInstanceFlag.IS_ASSIGNED
    # We need to do this in two steps to get the id of the keyinstance we allocated.
    sql_read = (
        "SELECT keyinstance_id "
        "FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? AND length(derivation_data2)=? AND "
            f"(flags&{KeyInstanceFlag.IS_ASSIGNED})=0 AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id ASC "
        "LIMIT 1")
    sql_read_values = [ account_id, masterkey_id,
        len(prefix_bytes)+4,  # The length of the parent path and sequence index.
        len(prefix_bytes),    # Just the length of the parent path.
        prefix_bytes ]        # The packed parent path bytes.
    sql_write = (
        "UPDATE KeyInstances "
        f"SET flags=flags|{allocation_flags} "
        f"WHERE keyinstance_id=? AND flags&{KeyInstanceFlag.IS_ASSIGNED}=0")

    def _write(db: sqlite3.Connection) -> Tuple[int, KeyInstanceFlag]:
        nonlocal allocation_flags, sql_read, sql_read_values, sql_write

        keyinstance_row = db.execute(sql_read, sql_read_values).fetchone()
        if keyinstance_row is None:
            raise KeyInstanceNotFoundError()

        # The result of the read operation just happens to be the parameters we need for the write.
        cursor = db.execute(sql_write, keyinstance_row)
        if cursor.rowcount != 1:
            # The key was allocated by something else between the read and the write.
            raise DatabaseUpdateError()

        return cast(int, keyinstance_row[0]), cast(KeyInstanceFlag, allocation_flags)

    return db_context.post_to_thread(_write)


def set_keyinstance_flags(db_context: DatabaseContext, key_ids: Sequence[int],
        flags: KeyInstanceFlag, mask: Optional[KeyInstanceFlag]=None) \
            -> concurrent.futures.Future:
    if mask is None:
        # NOTE(typing) There is no gain in casting to KeyInstanceFlag.
        mask = ~flags # type: ignore
    sql = (
        "UPDATE KeyInstances "
        f"SET date_updated=?, flags=(flags&{mask})|{flags} "
        "WHERE keyinstance_id IN ({})")
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
    mask_bits = ~TxFlags.MASK_STATE
    set_bits = TxFlags.STATE_DISPATCHED
    ignore_bits = TxFlags.STATE_DISPATCHED | TxFlags.MASK_STATE_BROADCAST
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
        "WHERE tx_hash IN ({})")
    sql_values = [ timestamp, TxFlags.STATE_CLEARED, ~TxFlags.STATE_SETTLED ]

    def _write(db: sqlite3.Connection) -> bool:
        nonlocal sql, sql_values, tx_hashes
        rows_updated = update_rows_by_id(db, sql, sql_values, tx_hashes)
        if rows_updated < len(tx_hashes):
            # Rollback the database transaction (nothing to rollback but upholding the convention).
            raise DatabaseUpdateError("Rollback as nothing updated")
        return True
    return db_context.post_to_thread(_write)


def update_transaction_output_flags(db_context: DatabaseContext, txo_keys: List[TxoKeyType],
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


def set_wallet_datas(db_context: DatabaseContext, entries: Iterable[WalletDataRow]) \
        -> concurrent.futures.Future:
    sql = ("INSERT INTO WalletData (key, value, date_created, date_updated) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, date_updated=excluded.date_updated")
    timestamp = get_timestamp()
    rows = []
    for entry in entries:
        rows.append((entry.key, json.dumps(entry.value), timestamp, timestamp))

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


# TODO(no-merge) descriptions have moved to AccountTransactions
# def update_transaction_descriptions(db_context: DatabaseContext,
#         entries: Iterable[Tuple[str, bytes]]) -> concurrent.futures.Future:
#     sql = "UPDATE Transactions SET date_updated=?, description=? WHERE tx_hash=?"
#     timestamp = get_timestamp()
#     rows = [ (timestamp,) + entry for entry in entries ]
#     def _write(db: sqlite3.Connection) -> None:
#         nonlocal rows, sql
#         db.executemany(sql, rows)
#     return db_context.post_to_thread(_write)


def update_transaction_block_many(db_context: DatabaseContext,
        entries: Iterable[TransactionBlockRow]) -> concurrent.futures.Future:
    timestamp = get_timestamp()
    rows: List[Tuple[int, int, Optional[bytes], bytes, int, Optional[bytes]]] = []
    for entry in entries:
        # NOTE(typing) Type checker does not understand unpacking `entry`.
        rows.append((timestamp, *entry, entry.block_height, entry.block_hash)) # type: ignore
    sql = (
        "UPDATE Transactions "
        "SET date_updated=?, block_height=?, block_hash=?, proof_data=NULL, "
            f"flags=flags&{~TxFlags.MASK_STATE}|{TxFlags.STATE_CLEARED} "
        "WHERE tx_hash=? AND (block_height!=? OR block_hash!=?)")

    def _write(db: sqlite3.Connection) -> int:
        nonlocal sql, rows
        cursor = db.executemany(sql, rows)
        return cursor.rowcount
    return db_context.post_to_thread(_write)


def update_transaction_proof(db_context: DatabaseContext, tx_hash: bytes, block_height: int,
        block_position: int, proof: TxProof) -> concurrent.futures.Future:
    def _write(db: sqlite3.Connection) -> bool:
        nonlocal tx_hash, block_height, block_position, proof
        _update_transaction_proof(db, tx_hash, block_height, block_position, proof)
        return True
    return db_context.post_to_thread(_write)


def _update_transaction_proof(db: sqlite3.Connection, tx_hash: bytes, block_height: int,
        block_position: int, proof: TxProof) -> None:
    """
    Execute the query that sets the proof data for a transaction.

    This should only be called in the context of the writer thread.
    """
    timestamp = get_timestamp()
    clear_bits = ~TxFlags.MASK_STATE
    set_bits = TxFlags.STATE_SETTLED
    query = ("UPDATE Transactions "
        "SET date_updated=?, proof_data=?, block_height=?, block_position=?, "
            f"flags=(flags&{clear_bits})|{set_bits} "
        "WHERE tx_hash=?")
    # NOTE(rt12) at some later point we will have a standard binary packed proof format
    # that we can use, i.e. bitcoin association's specification.
    db.execute(query, (timestamp, pack_proof(proof), block_height, block_position, tx_hash))


def update_account_names(db_context: DatabaseContext, entries: Iterable[Tuple[str, int]]) \
        -> concurrent.futures.Future:
    sql = "UPDATE Accounts SET date_updated=?, account_name=? WHERE account_id=?"
    timestamp = get_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_account_script_types(db_context: DatabaseContext,
        entries: Iterable[Tuple[ScriptType, int]]) -> concurrent.futures.Future:
    sql = "UPDATE Accounts SET date_updated=?, default_script_type=? WHERE account_id=?"
    timestamp = get_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_account_transaction_descriptions(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[str], int, bytes]]) -> concurrent.futures.Future:
    timestamp = get_timestamp()
    sql = "UPDATE AccountTransactions SET date_updated=?, description=? " \
        "WHERE account_id=? AND tx_hash=?"
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_transactions(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[bytes], int]]) -> concurrent.futures.Future:
    sql = "UPDATE Invoices SET date_updated=?, tx_hash=? WHERE invoice_id=?"
    timestamp = get_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_descriptions(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[str], int]]) -> concurrent.futures.Future:
    sql = ("UPDATE Invoices SET date_updated=?, description=? "
        "WHERE invoice_id=?")
    timestamp = get_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_flags(db_context: DatabaseContext,
        entries: Iterable[Tuple[PaymentFlag, PaymentFlag, int]]) -> concurrent.futures.Future:
    sql = ("UPDATE Invoices SET date_updated=?, "
            "invoice_flags=((invoice_flags&?)|?) "
        "WHERE invoice_id=?")
    timestamp = get_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_keyinstance_derivation_datas(db_context: DatabaseContext,
        entries: Iterable[Tuple[bytes, int]]) -> concurrent.futures.Future:
    sql = ("UPDATE KeyInstances SET date_updated=?, derivation_data=? WHERE keyinstance_id=?")

    timestamp = get_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_keyinstance_descriptions(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[str], int]]) -> concurrent.futures.Future:
    sql = ("UPDATE KeyInstances SET date_updated=?, description=? WHERE keyinstance_id=?")
    timestamp = get_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_masterkey_derivation_datas(db_context: DatabaseContext,
        entries: Iterable[Tuple[bytes, int]]) -> concurrent.futures.Future:
    sql = "UPDATE MasterKeys SET derivation_data=?, date_updated=? WHERE masterkey_id=?"
    timestamp = get_timestamp()
    rows = []
    for entry in entries:
        rows.append((entry[0], timestamp, entry[1]))

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_payment_request_states(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[PaymentFlag], int]]) -> concurrent.futures.Future:
    sql = (f"""UPDATE PaymentRequests SET date_updated=?,
        state=(state&{~PaymentFlag.MASK_STATE})|? WHERE keyinstance_id=?""")
    timestamp = get_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_payment_requests(db_context: DatabaseContext,
        entries: Iterable[PaymentRequestUpdateRow]) -> concurrent.futures.Future:
    sql = ("UPDATE PaymentRequests SET date_updated=?, state=?, value=?, expiration=?, "
        "description=? WHERE paymentrequest_id=?")
    timestamp = get_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]

    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_wallet_event_flags(db_context: DatabaseContext,
        entries: Iterable[Tuple[WalletEventFlag, int]]) -> concurrent.futures.Future:
    sql = "UPDATE WalletEvents SET date_updated=?, event_flags=? WHERE event_id=?"
    timestamp = get_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal rows, sql
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


# TODO This should not be a class. It should be flattened to functions.
class AsynchronousFunctions:
    LOGGER_NAME: str = "async-functions"

    def __init__(self, db_context: DatabaseContext) -> None:
        self._logger = logs.get_logger(self.LOGGER_NAME)
        self._db_context = db_context
        self._db: sqlite3.Connection = db_context.acquire_connection()

    def close(self) -> None:
        self._db_context.release_connection(self._db)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    async def import_transaction_async(self, tx_row: TransactionRow,
            txi_rows: List[TransactionInputAddRow], txo_rows: List[TransactionOutputAddRow],
            link_state: TransactionLinkState) -> bool:
        """
        Wrap the database operations required to import a transaction so the processing is
        offloaded to the SQLite writer thread while this task is blocked.
        """
        return await self._db_context.run_in_thread_async(self._import_transaction, tx_row,
            txi_rows, txo_rows, link_state)

    def _import_transaction(self, db: sqlite3.Connection, tx_row: TransactionRow,
            txi_rows: List[TransactionInputAddRow], txo_rows: List[TransactionOutputAddRow],
            link_state: TransactionLinkState) -> bool:
        """
        Insert the transaction data and attempt to link it to any accounts it may be involved with.

        If any unexpected constraints are violated, an exception should be raised out of this
        function and should be caught rolling back this transaction.

        This should only be called in the context of the writer thread.
        """
        try:
            self._insert_transaction(db, tx_row, txi_rows, txo_rows)
        except TransactionAlreadyExistsError:
            # If the transaction already exists there is no point in re-importing it, unless
            # it is unlinked (removed / conflicted) and we want to import it and link it.
            if not self._reset_transaction_for_import(db, tx_row.tx_hash):
                raise

        self._link_transaction(db, tx_row.tx_hash, link_state)
        # Returning commits the changes applied in this function.
        return True

    def _insert_transaction(self, db: sqlite3.Connection, tx_row: TransactionRow,
            txi_rows: List[TransactionInputAddRow], txo_rows: List[TransactionOutputAddRow]) -> Any:
        """
        Insert the base data for a parsed transaction into the database.

        Raises an `IntegrityError` if any constraint checks fail. This should be executed in a
        database transaction, which the SQLite writer thread currently takes care of. The exception
        should raise back out to the caller and all changes discarded through the rolling back
        of the transaction.
        """
        # Rationale: We used to allow transactions we knew about but did not yet have to be added
        # to the database, this had `tx_data=None`. Now all transactions inserted must be parsed
        # with inputs and outputs.
        assert tx_row.tx_bytes is not None
        assert (tx_row.flags & TxFlags.HAS_BYTEDATA) == 0, "this flag is not applicable"

        # Constraint: tx_hash should be unique.
        try:
            db.execute("INSERT INTO Transactions (tx_hash, tx_data, flags, block_hash, "
                "block_height, block_position, fee_value, description, version, locktime, "
                "date_created, date_updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", tx_row)
        except sqlite3.IntegrityError as e:
            if e.args[0] == "UNIQUE constraint failed: Transactions.tx_hash":
                raise TransactionAlreadyExistsError()

        # Constraint: (tx_hash, tx_index) should be unique.
        db.executemany("INSERT INTO TransactionInputs (tx_hash, txi_index, spent_tx_hash, "
            "spent_txo_index, sequence, flags, script_offset, script_length, date_created, "
            "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?)", txi_rows)

        # Constraint: (tx_hash, tx_index) should be unique.
        db.executemany("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, "
            "script_type, flags, script_hash, script_offset, script_length, date_created, "
            "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?,?)", txo_rows)

        return True

    def _reset_transaction_for_import(self, db: sqlite3.Connection, tx_hash: bytes) -> bool:
        """
        Determine if it is valid for this transaction to be reimported.

        The transaction is already in the database, but for some reason it is not linked to
        any account. If that reason is one where the user might want to try and link it again
        then we can remove the flags and allow the re-linking attempt to proceed.
        """
        # The transaction is already present. If it is deleted, we can reinstate it. Otherwise
        # we
        cursor = db.execute("SELECT flags FROM Transactions WHERE tx_hash=?", (tx_hash,))
        if cursor.fetchone()[0] & TxFlags.MASK_UNLINKED == 0:
            return False
        db.execute(f"UPDATE Transactions SET flags=flags&{~TxFlags.MASK_UNLINKED} WHERE tx_hash=?",
            (tx_hash,))
        return True

    async def link_transaction_async(self, tx_hash: bytes,
            link_state: TransactionLinkState) -> bool:
        """
        Wrap the database operations required to link a transaction so the processing is
        offloaded to the SQLite writer thread while this task is blocked.
        """
        return await self._db_context.run_in_thread_async(self._link_transaction, tx_hash,
            link_state)

    def _link_transaction(self, db: sqlite3.Connection, tx_hash: bytes,
            link_state: TransactionLinkState) -> None:
        """
        Populate the metadata for the given transaction in the database.

        Given this happens in a sequential writer thread we know that there cannot be
        race conditions in the database where transactions being added in parallel might miss
        spends. However, in real world usage that should only ever be ordered spends. Unordered
        spends should only occur in synchronisation, and we can special case that at a higher
        level.
        """
        _rowcount1 = self._link_transaction_key_usage(db, tx_hash)
        _rowcount2 = self._link_transaction_to_accounts(db, tx_hash)

        # NOTE We do not handle removing the conflict flag here. That whole process can be
        # done elsewhere.
        if self._reconcile_transaction_output_spends(db, tx_hash):
            sql1 = "SELECT account_id FROM AccountTransactions WHERE tx_hash=?"
            sql1_values = (tx_hash,)
            link_state.account_ids = \
                set(account_id for (account_id,) in db.execute(sql1, sql1_values))
        else:
            link_state.has_spend_conflicts = True

            # This should rollback the whole transaction including the insertion of the transaction
            # itself. This is important in the case where the user is spending their own coins
            # and some race condition has resulted in the transaction attempting to spend already
            # spent coins.
            if link_state.rollback_on_spend_conflict:
                raise DatabaseUpdateError("Transaction rolled back due to spend conflicts")

            sql2 = "UPDATE Transactions SET flags=flags|? WHERE tx_hash=?"
            sql2_values = (TxFlags.CONFLICTING, tx_hash)
            db.execute(sql2, sql2_values)

    def _link_transaction_key_usage(self, db: sqlite3.Connection, tx_hash: bytes) -> int:
        """
        Link transaction outputs to key usage.

        This function can be repeatedly called, which might be useful if for some reason keys
        were not created when it was first called for a transaction.
        """
        timestamp = get_timestamp()
        sql = (
            "UPDATE TransactionOutputs AS TXO "
            "SET date_updated=?, keyinstance_id=KIS.keyinstance_id, script_type=KIS.script_type "
            "FROM KeyInstanceScripts KIS "
            "WHERE TXO.tx_hash=? AND TXO.script_hash=KIS.script_hash")
            # "UPDATE TransactionOutputs "
            # "SET date_updated=?, keyinstance_id=KIS.keyinstance_id, script_type=KIS.script_type "
            # "FROM TransactionOutputs TXO "
            # "INNER JOIN KeyInstanceScripts KIS ON TXO.script_hash=KIS.script_hash "
            # "WHERE TXO.tx_hash=?")
        sql_values = (timestamp, tx_hash)
        cursor = db.execute(sql, sql_values)
        return cursor.rowcount

    def _link_transaction_to_accounts(self, db: sqlite3.Connection, tx_hash: bytes) -> int:
        """
        Link transaction outpout key usage to account involvement.

        This function can be repeatedly called, which might be useful if for some reason keys
        were not created when it was first called for a transaction.
        """
        timestamp = get_timestamp()

        # Assuming transactions are mapped to key usage, we can insert transaction mappings to
        # accounts they are associated with. The reason we do this is that we want per-account
        # transaction state.
        cursor = db.execute(
            "INSERT OR IGNORE INTO AccountTransactions "
                "(tx_hash, account_id, date_created, date_updated) "
            "WITH transaction_accounts(account_id) AS ("
                # Link based on any received key usage of this transaction.
                "SELECT DISTINCT KI.account_id "
                "FROM TransactionOutputs TXO "
                "INNER JOIN KeyInstances KI ON KI.keyinstance_id = TXO.keyinstance_id "
                "WHERE TXO.tx_hash=? "
                "UNION "
                # Link based on any spending key usage of this transaction.
                "SELECT DISTINCT KI.account_id "
                "FROM TransactionInputs TXI "
                "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash = TXI.spent_tx_hash "
                "INNER JOIN KeyInstances KI ON KI.keyinstance_id = TXO.keyinstance_id "
                "WHERE TXI.tx_hash=? "
            ")"
            "SELECT ?, TA.account_id, ?, ? "
            "FROM transaction_accounts TA",
            (tx_hash, tx_hash, tx_hash, timestamp, timestamp))
        return cursor.rowcount

    def _reconcile_transaction_output_spends(self, db: sqlite3.Connection, tx_hash: bytes,
            self_spends: bool=False) -> bool:
        """
        Spend the transaction outputs of the parent and even our own if applicable.

        We process the first or both of the following:
        - Spends by this transaction of parent transactions that arrived first in correct order.
        - Spends of this transaction by child transactions that arrived first out of order.

        We care about spend conflicts for parent transactions because we do not want clashing
        database records. The existence of a spend conflict means that we should not link in
        this transaction as relevant, nor as a spender, and should leave it up to the user to
        reconcile the problem.

        We do not care about spend conflicts with child transactions as this would only happen
        if there were multiple child transactions already present having arrived out of order
        before this transaction. This seems unlikely and if it ever happens, it is possible that
        we might address the cause and choose not to handle it.
        """
        timestamp = get_timestamp()
        # The base SQL is just the spends of parent transaction outputs.
        sql = (
            "SELECT TXI.tx_hash, TXI.txi_index, TXO.tx_hash, TXO.tx_index, TXO.spending_tx_hash "
            "FROM TransactionInputs TXI "
            "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash = TXI.spent_tx_hash AND "
                "TXO.tx_index = TXI.spent_txo_index "
            "WHERE TXI.tx_hash=?")
        # The caller can specify that there might be out of order spends of this transaction.
        if self_spends:
            sql += " OR TXI.spent_tx_hash=?"
            cursor = db.execute(sql, (tx_hash, tx_hash))
        else:
            cursor = db.execute(sql, (tx_hash,))

        spend_conflicts: List[SpendConflictType] = []
        spent_rows: List[Tuple[int, bytes, int, bytes, int]] = []
        for (txi_hash, txi_index, txo_hash, txo_index, txo_spending_tx_hash) in cursor.fetchall():
            if txo_spending_tx_hash is not None:
                # This output is already being spent by something. We accept repeated calls and
                # recognise if the work is already done and it is not a conflict.
                if txo_spending_tx_hash == tx_hash:
                    # This transaction already spends the given parent output.
                    pass
                elif txo_hash == tx_hash:
                    # This is our output and it is already spent. Multiple spenders are ignored
                    # for now as per the function doc string.
                    pass
                else:
                    spend_conflicts.append((txo_hash, txo_index, txi_hash, txi_index))
            else:
                spent_rows.append((timestamp, txi_hash, txi_index, txo_hash, txo_index))

        if spend_conflicts:
            return False

        db.execute("SAVEPOINT txo_spends")

        # If there were no spend conflicts, we can consider ourselves to be valid and can mark
        # the spent coins as spent. As allocation is an indication of unavailability pending use
        # we can clear it when we set the output as spent.
        clear_bits = TransactionOutputFlag.IS_ALLOCATED
        set_bits = TransactionOutputFlag.IS_SPENT
        cursor = db.executemany("UPDATE TransactionOutputs "
            "SET date_updated=?, spending_tx_hash=?, spending_txi_index=?, "
                f"flags=(flags&{~clear_bits})|{set_bits} "
            f"WHERE spending_tx_hash IS NULL AND tx_hash=? AND tx_index=?", spent_rows)
        # Detect if we did not update all of the rows we expected to update.
        if cursor.rowcount != len(spent_rows):
            # If we do not update all the rows we expect to update, then we rollback any updates
            # that were made.
            db.execute("ROLLBACK TO SAVEPOINT txo_spends")

            self._logger.error("Failed to spend %d transaction outputs, as something else "
                "unexpectedly spent them. This should never happen.",
                len(spent_rows) - cursor.rowcount)
            return False

        return True

    async def update_transaction_proof_async(self, tx_hash: bytes, block_height: int,
            block_position: int, proof: TxProof) -> None:
        await self._db_context.run_in_thread_async(_update_transaction_proof, tx_hash,
            block_height, block_position, proof)
