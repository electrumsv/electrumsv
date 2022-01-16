from collections import defaultdict
import concurrent.futures
import json
import os
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3
else:
    sqlite3 = pysqlite3
from types import TracebackType
from typing import Any, cast, Iterable, List, Optional, Sequence, Set, Tuple, Type, Union

from ..constants import (DerivationType, DerivationPath, KeyInstanceFlag,
    NetworkServerType, pack_derivation_path, PaymentFlag, ScriptType, TransactionOutputFlag,
    TxFlags, unpack_derivation_path, WalletEventFlag)
from ..crypto import pw_decode, pw_encode
from ..i18n import _
from ..logs import logs
from ..types import KeyInstanceDataPrivateKey, MasterKeyDataBIP32, MasterKeyDataElectrumOld, \
    MasterKeyDataMultiSignature, MasterKeyDataTypes, Outpoint, OutputSpend, ServerAccountKey
from ..util import get_posix_timestamp

from .exceptions import (DatabaseUpdateError, KeyInstanceNotFoundError,
    TransactionAlreadyExistsError, TransactionRemovalError)
from .sqlite_support import DatabaseContext, replace_db_context_with_connection
from .types import (AccountRow, AccountTransactionRow, AccountTransactionDescriptionRow,
    AccountTransactionOutputSpendableRow, AccountTransactionOutputSpendableRowExtended,
    HistoryListRow, InvoiceAccountRow, InvoiceRow, KeyInstanceFlagRow, KeyInstanceFlagChangeRow,
    KeyInstanceRow, KeyInstanceScriptHashRow, KeyListRow, MasterKeyRow, MAPIBroadcastCallbackRow,
    MapiBroadcastStatusFlags, NetworkServerRow, NetworkServerAccountRow, PasswordUpdateResult,
    PaymentRequestReadRow, PaymentRequestRow,PaymentRequestUpdateRow, SpendConflictType,
    SpentOutputRow, TransactionDeltaSumRow, TransactionExistsRow,
    TransactionInputAddRow, TransactionLinkState, TransactionOutputAddRow,
    TransactionOutputSpendableRow, TransactionValueRow, TransactionMetadata,
    TransactionOutputFullRow, TransactionOutputShortRow, TransactionProoflessRow, TxProofData,
    TxProofResult, TransactionRow, WalletBalance, WalletDataRow, WalletEventRow)
from .util import flag_clause, read_rows_by_id, read_rows_by_ids, execute_sql_by_id, \
    update_rows_by_ids

logger = logs.get_logger("db-functions")


def create_accounts(db_context: DatabaseContext, entries: Iterable[AccountRow]) \
        -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO Accounts (account_id, default_masterkey_id, default_script_type, "
        "account_name, flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(query, datas)
    return db_context.post_to_thread(_write)


def create_invoices(db_context: DatabaseContext, entries: Iterable[InvoiceRow]) \
        -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO Invoices "
        "(account_id, tx_hash, payment_uri, description, invoice_flags, value, "
        "invoice_data, date_expires, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    timestamp = get_posix_timestamp()
    # Discard the first column for the id and the last column for date updated.
    rows = [ (*entry[1:-1], timestamp, timestamp) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_keyinstances(db_context: DatabaseContext, entries: Iterable[KeyInstanceRow]) \
        -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries]
    sql = ("INSERT INTO KeyInstances "
        "(keyinstance_id, account_id, masterkey_id, derivation_type, derivation_data, "
        "derivation_data2, flags, description, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, datas)
    return db_context.post_to_thread(_write)


def create_keyinstance_scripts(db_context: DatabaseContext,
        entries: Iterable[KeyInstanceScriptHashRow]) -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO KeyInstanceScripts "
        "(keyinstance_id, script_type, script_hash, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?)")
    timestamp = get_posix_timestamp()
    rows = [ (*t, timestamp, timestamp) for t in entries]
    def _write(db: sqlite3.Connection) -> None:
        nonlocal sql, rows
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_master_keys(db_context: DatabaseContext, entries: Iterable[MasterKeyRow]) \
        -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    sql = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)")
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, datas)
    return db_context.post_to_thread(_write)


def create_payment_requests(db_context: DatabaseContext, entries: List[PaymentRequestRow]) \
        -> concurrent.futures.Future[List[PaymentRequestRow]]:
    sql = (
        "INSERT INTO PaymentRequests "
        "(paymentrequest_id, keyinstance_id, state, value, expiration, description, date_created, "
            "date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    timestamp = get_posix_timestamp()
    sql_values = [ (*t[:-1], timestamp, timestamp) for t in entries ]
    def _write(db: sqlite3.Connection) -> List[PaymentRequestRow]:
        db.executemany(sql, sql_values)
        return entries
    return db_context.post_to_thread(_write)


def create_transaction_outputs(db_context: DatabaseContext,
        entries: Iterable[TransactionOutputShortRow]) -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO TransactionOutputs (tx_hash, txo_index, value, keyinstance_id, "
        "flags, script_type, script_hash, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    timestamp = get_posix_timestamp()
    db_rows = [ (*t, timestamp, timestamp) for t in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, db_rows)
    return db_context.post_to_thread(_write)


# This is currently only used from unit tests.
def create_account_transactions_UNITTEST(db_context: DatabaseContext,
        rows: List[AccountTransactionRow]) -> concurrent.futures.Future[None]:
    sql = """
        INSERT INTO AccountTransactions
            (account_id, tx_hash, flags, description, date_created, date_updated)
        VALUES (?,?,?,?,?,?)
    """
    def _write(db: sqlite3.Connection) -> None:
        logger.debug("add %d account transactions", len(rows))
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


# This is currently only used from unit tests.
def create_transactions_UNITTEST(db_context: DatabaseContext, rows: List[TransactionRow]) \
        -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO Transactions (tx_hash, tx_data, flags, block_hash, "
        "block_position, fee_value, description, version, locktime, proof_data, "
        "date_created, date_updated) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")

    for row in rows:
        assert type(row.tx_hash) is bytes and row.tx_bytes is not None
        assert row.date_created > 0 and row.date_updated > 0

    def _write(db: sqlite3.Connection) -> None:
        logger.debug("add %d transactions", len(rows))
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_wallet_datas(db_context: DatabaseContext, entries: Iterable[WalletDataRow]) \
        -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO WalletData (key, value, date_created, date_updated) "
        "VALUES (?, ?, ?, ?)")
    timestamp = get_posix_timestamp()
    rows = []
    for entry in entries:
        assert type(entry.key) is str, f"bad key '{entry.key}'"
        data = json.dumps(entry.value)
        rows.append([ entry.key, data, timestamp, timestamp])

    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_wallet_events(db_context: DatabaseContext, entries: Iterable[WalletEventRow]) \
        -> concurrent.futures.Future[None]:
    sql = (
        "INSERT INTO WalletEvents "
            "(event_id, event_type, account_id, event_flags, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?)")
    # Duplicate the last column for date_updated = date_created
    rows = [ (*t, t[-1]) for t in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def delete_invoices(db_context: DatabaseContext, entries: Iterable[Tuple[int]]) \
        -> concurrent.futures.Future[None]:
    sql = "DELETE FROM Invoices WHERE invoice_id=?"
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, entries)
    return db_context.post_to_thread(_write)


def delete_payment_request(db_context: DatabaseContext, paymentrequest_id: int,
        keyinstance_id: int) -> concurrent.futures.Future[KeyInstanceFlag]:
    timestamp = get_posix_timestamp()
    expected_key_flags = KeyInstanceFlag.ACTIVE | KeyInstanceFlag.IS_PAYMENT_REQUEST
    read_sql1 = "SELECT flags from KeyInstances WHERE keyinstance_id=?"
    read_sql1_values = (keyinstance_id,)
    write_sql1 = "UPDATE KeyInstances SET date_updated=?, flags=flags&? WHERE keyinstance_id=?"
    write_sql2 = "DELETE FROM PaymentRequests WHERE paymentrequest_id=?"
    write_sql2_values = (paymentrequest_id,)

    def _write(db: sqlite3.Connection) -> KeyInstanceFlag:
        # We need the flags for the key instance to work out why it is active.
        flags = db.execute(read_sql1, read_sql1_values).fetchone()[0]
        assert flags & expected_key_flags == expected_key_flags, "not a valid payment request key"
        # If there are other reasons the key is active, do not remove `ACTIVE`.
        key_flags_mask = KeyInstanceFlag.IS_PAYMENT_REQUEST
        if flags & KeyInstanceFlag.MASK_ACTIVE_REASON == KeyInstanceFlag.IS_PAYMENT_REQUEST:
            # We have confirmed this is the sole reason the key is active. Remove `ACTIVE`.
            key_flags_mask = expected_key_flags
        db.execute(write_sql1, (timestamp, ~key_flags_mask, keyinstance_id))
        db.execute(write_sql2, write_sql2_values)
        return key_flags_mask
    return db_context.post_to_thread(_write)


def delete_wallet_data(db_context: DatabaseContext, key: str) -> concurrent.futures.Future[None]:
    sql = "DELETE FROM WalletData WHERE key=?"
    def _write(db: sqlite3.Connection) -> None:
        db.execute(sql, (key,))
    return db_context.post_to_thread(_write)


# TODO Maybe at some stage this should include a frozen balance, but it needs some thinking
#   through. Each case statement would need to filter out frozen UTXOs, and a frozen case
#   would need to be added.
@replace_db_context_with_connection
def read_account_balance(db: sqlite3.Connection, account_id: int,
        txo_flags: TransactionOutputFlag=TransactionOutputFlag.NONE,
        txo_mask: TransactionOutputFlag=TransactionOutputFlag.SPENT,
        exclude_frozen: bool=True) -> WalletBalance:
    if exclude_frozen:
        txo_mask |= TransactionOutputFlag.FROZEN
    # NOTE(linked-balance-calculations) the general formula is used elsewhere
    sql = (
        "SELECT "
            # Confirmed.
            "CAST(TOTAL(CASE WHEN TX.flags&? AND TXO.flags&?=? THEN TXO.value ELSE 0 END) AS INT), "
            # Unconfirmed total.
            "CAST(TOTAL(CASE WHEN TX.flags&? THEN TXO.value ELSE 0 END) AS INT), "
            # Unmatured total.
            "CAST(TOTAL(CASE WHEN TX.flags&? AND TXO.flags&?=? THEN TXO.value ELSE 0 END) AS INT), "
            # Allocated total.
            "CAST(TOTAL(CASE WHEN TX.flags&? THEN TXO.value ELSE 0 END) AS INT) "
        "FROM AccountTransactions ATX "
        "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=ATX.tx_hash ")
    if exclude_frozen:
        sql += "INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id "
    sql += ("INNER JOIN Transactions TX ON TX.tx_hash=ATX.tx_hash "
        "WHERE ATX.account_id=? AND TXO.keyinstance_id IS NOT NULL AND "
            "TXO.flags&?=?")
    # The `COINBASE_IMMATURE` flag is expected to be set on insert unless it is known the
    # transaction is mature.
    coinbase_filter_mask = TransactionOutputFlag.COINBASE_IMMATURE
    sql_values = [
        TxFlags.STATE_SETTLED, coinbase_filter_mask, TransactionOutputFlag.NONE,
        TxFlags.STATE_CLEARED,
        TxFlags.STATE_SETTLED, coinbase_filter_mask, coinbase_filter_mask,
        TxFlags.MASK_STATE_UNCLEARED,
        account_id, txo_mask, txo_flags ]
    if exclude_frozen:
        sql += " AND KI.flags&?=0"
        sql_values.append(KeyInstanceFlag.FROZEN)
    row = db.execute(sql, sql_values).fetchone()
    if row is None:
        return WalletBalance(0, 0, 0, 0)
    return WalletBalance(*row)


@replace_db_context_with_connection
def read_account_transaction_outputs_with_key_data(db: sqlite3.Connection, account_id: int,
        confirmed_only: bool=False, exclude_immature: bool=False, exclude_frozen: bool=False,
        keyinstance_ids: Optional[List[int]]=None) -> List[AccountTransactionOutputSpendableRow]:
    """
    Get the unspent coins in the given account.

    confirmed_only: only return unspent coins in confirmed transactions.
    exclude_immature: only return unspent coins that are not coinbase < maturity height.
    exclude_frozen: only return unspent coins that are not frozen.
    """
    # Default to selecting all unallocated unspent transaction outputs.
    tx_mask = TxFlags.REMOVED
    tx_flags = TxFlags.UNSET
    if confirmed_only:
        tx_mask |= TxFlags.STATE_SETTLED
        tx_flags |= TxFlags.STATE_SETTLED

    txo_mask = TransactionOutputFlag.SPENT | TransactionOutputFlag.ALLOCATED
    if exclude_frozen:
        txo_mask |= TransactionOutputFlag.FROZEN
    if exclude_immature:
        txo_mask |= TransactionOutputFlag.COINBASE_IMMATURE

    sql = (
        "SELECT TXO.tx_hash, TXO.txo_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
            "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, KI.derivation_data2 "
        "FROM TransactionOutputs TXO "
        "INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
        "WHERE KI.account_id=? AND TXO.flags&?=0 AND TX.flags&?=?")
    sql_values: List[Any] = [ account_id, txo_mask, tx_mask, tx_flags ]
    if exclude_frozen:
        sql += " AND KI.flags&?=0"
        sql_values.append(KeyInstanceFlag.FROZEN)
    if keyinstance_ids is not None:
        sql += " AND TXO.keyinstance_id IN ({})"
        rows = read_rows_by_id(AccountTransactionOutputSpendableRow, db, sql, sql_values,
            keyinstance_ids)
    else:
        cursor = db.execute(sql, sql_values)
        rows = [ AccountTransactionOutputSpendableRow(*row) for row in cursor.fetchall() ]
        cursor.close()
    return rows


@replace_db_context_with_connection
def read_account_transaction_outputs_with_key_and_tx_data(db: sqlite3.Connection, account_id: int,
        confirmed_only: bool=False, exclude_immature: bool=False, exclude_frozen: bool=False,
        keyinstance_ids: Optional[List[int]]=None) \
            -> List[AccountTransactionOutputSpendableRowExtended]:
    """
    Get the unspent coins in the given account extended with transaction fields.

    confirmed_only: only return unspent coins in confirmed transactions.
    exclude_immature: only return unspent coins that are not coinbase < maturity height.
    exclude_frozen: only return unspent coins that are not frozen.
    """
    # Default to selecting all unallocated unspent transaction outputs.
    tx_mask = TxFlags.REMOVED
    tx_flags = TxFlags.UNSET
    if confirmed_only:
        tx_mask |= TxFlags.STATE_SETTLED
        tx_flags |= TxFlags.STATE_SETTLED

    txo_mask = TransactionOutputFlag.SPENT | TransactionOutputFlag.ALLOCATED
    if exclude_frozen:
        txo_mask |= TransactionOutputFlag.FROZEN
    if exclude_immature:
        txo_mask |= TransactionOutputFlag.COINBASE_IMMATURE

    sql = (
        "SELECT TXO.tx_hash, TXO.txo_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
            "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, KI.derivation_data2, "
            "TX.flags, TX.block_hash "
        "FROM TransactionOutputs TXO "
        "INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
        "WHERE KI.account_id=? AND TXO.flags&?=0 AND TX.flags&?=?")
    sql_values: List[Any] = [ account_id, txo_mask, tx_mask, tx_flags ]
    if exclude_frozen:
        sql += " AND KI.flags&?=0"
        sql_values.append(KeyInstanceFlag.FROZEN)
    if keyinstance_ids is not None:
        sql += " AND TXO.keyinstance_id IN ({})"
        rows = read_rows_by_id(AccountTransactionOutputSpendableRowExtended, db, sql, sql_values,
            keyinstance_ids)
    else:
        cursor = db.execute(sql, sql_values)
        rows = [ AccountTransactionOutputSpendableRowExtended(*row) for row in cursor.fetchall() ]
        cursor.close()
    return rows


@replace_db_context_with_connection
def read_accounts(db: sqlite3.Connection) -> List[AccountRow]:
    sql = (
        "SELECT account_id, default_masterkey_id, default_script_type, account_name, flags "
        "FROM Accounts")
    return [ AccountRow(*row) for row in db.execute(sql).fetchall() ]


@replace_db_context_with_connection
def read_account_ids_for_transaction(db: sqlite3.Connection, tx_hash: bytes) -> List[int]:
    sql = "SELECT account_id FROM AccountTransactions WHERE tx_hash=?"
    sql_values = (tx_hash,)
    return [ row[0] for row in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_history_list(db: sqlite3.Connection, account_id: int,
        keyinstance_ids: Optional[Sequence[int]]=None) -> List[HistoryListRow]:
    if keyinstance_ids:
        # Used for the address dialog.
        sql = ("SELECT TXV.tx_hash, TX.flags, TX.block_hash, TX.block_position, "
                "ATX.description, TOTAL(TXV.value), TX.date_created "
            "FROM TransactionValues TXV "
            "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
            "INNER JOIN AccountTransactions AS ATX ON ATX.tx_hash=TXV.tx_hash "
            "WHERE TXV.account_id=? AND (TX.flags&?)!=0 AND TXV.keyinstance_id IN ({}) "
            "GROUP BY TXV.tx_hash")
        return read_rows_by_id(HistoryListRow, db, sql, [ account_id, TxFlags.MASK_STATE ],
            keyinstance_ids)

    # Used for the history list and export.
    sql = ("SELECT TXV.tx_hash, TX.flags, TX.block_hash, TX.block_position,"
            "ATX.description, TOTAL(TXV.value), TX.date_created "
        "FROM TransactionValues TXV "
        "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
        "INNER JOIN AccountTransactions AS ATX ON ATX.tx_hash=TXV.tx_hash "
        "WHERE TXV.account_id=? AND (TX.flags&?)!=0 "
        "GROUP BY TXV.tx_hash")
    cursor = db.execute(sql, (account_id, TxFlags.MASK_STATE))
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


# TODO(1.4.0) Find all the transactions we need merkle proofs but are not getting them
#      via other avenues (i.e. MAPI), order in terms of priority and take the
#      first. Is this sufficient? No, it is not, in fact we may not even want to do this
#      case.
@replace_db_context_with_connection
def read_proofless_transactions(db: sqlite3.Connection) -> List[TransactionProoflessRow]:
    # TODO: We associate the proofless transaction with the first account that it was linked to.
    # This is not ideal, but in reality it is unlikely many users will care about the nuances
    # and we can change the behaviour later.
    sql_values: List[Any] = []
    sql = f"""
    WITH matches AS (
        SELECT TX.tx_hash, ATX.account_id,
            row_number() OVER (PARTITION BY TX.tx_hash ORDER BY ATX.date_created) as rank
        FROM Transactions TX
        LEFT JOIN AccountTransactions ATX ON ATX.tx_hash=TX.tx_hash
        WHERE TX.flags&{TxFlags.MASK_STATE}={TxFlags.STATE_SETTLED} AND TX.proof_data IS NULL OR
              TX.flags&{TxFlags.MASK_STATE}={TxFlags.STATE_CLEARED} AND TX.block_hash IS NOT NULL
                  AND TX.proof_data is NULL

    )
    SELECT tx_hash, account_id FROM matches WHERE account_id IS NOT NULL AND rank=1
    """
    rows = db.execute(sql, sql_values).fetchall()
    return [ TransactionProoflessRow(*row) for row in rows ]


@replace_db_context_with_connection
def read_spent_outputs_to_monitor(db: sqlite3.Connection) -> List[OutputSpend]:
    """
    Retrieve all the outpoints we need to monitor (and why) via the 'output-spend' API. Remember
    that the goal is to detect either the appearance of these in the mempool or a block.
    """
    sql = f"""
    SELECT TXI.spent_tx_hash, TXI.spent_txo_index, TXI.tx_hash, TXI.txi_index
    FROM TransactionInputs TXI
    INNER JOIN Transactions TX ON TX.tx_hash=TXI.tx_hash AND TX.flags&{TxFlags.MASK_STATE}!=0 AND
        TX.flags&{TxFlags.STATE_SETTLED}=0
    """
    # LEFT JOIN MAPIBroadcastCallbacks MBC ON MBC.tx_hash=TXI.tx_hash
    #     AND MBC.status_flags={MapiBroadcastStatusFlags.SUCCEEDED}
    # WHERE MBC.tx_hash IS NULL
    rows = db.execute(sql).fetchall()
    return [ OutputSpend(*row) for row in rows ]


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
    sql = (
        "SELECT KI.account_id, KI.keyinstance_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.description, KI.date_updated, "
            "TOTAL(CASE WHEN TXO.flags&?=0 THEN TXO.value ELSE 0 END), "
            "TOTAL(CASE WHEN TXO.flags IS NULL THEN 0 ELSE 1 END) "
        "FROM KeyInstances AS KI "
        "LEFT JOIN TransactionOutputs TXO ON TXO.keyinstance_id = KI.keyinstance_id "
        "WHERE KI.account_id = ?")
    sql_values = [ TransactionOutputFlag.SPENT, account_id ]
    if keyinstance_ids is not None:
        sql += " AND KI.keyinstance_id IN ({})"
    sql += " GROUP BY KI.keyinstance_id"

    if keyinstance_ids is not None:
        return read_rows_by_id(KeyListRow, db, sql, sql_values, keyinstance_ids)

    cursor = db.execute(sql, sql_values)
    rows = cursor.fetchall()
    cursor.close()
    return [ KeyListRow(*t) for t in rows ]


@replace_db_context_with_connection
def read_keyinstance_scripts_by_id(db: sqlite3.Connection, keyinstance_ids: Sequence[int]) \
        -> List[KeyInstanceScriptHashRow]:
    sql = (
        "SELECT keyinstance_id, script_type, script_hash "
        "FROM KeyInstanceScripts "
        "WHERE keyinstance_id IN ({})")
    return read_rows_by_id(KeyInstanceScriptHashRow, db, sql, [], keyinstance_ids)


@replace_db_context_with_connection
def read_keyinstance_scripts_by_hash(db: sqlite3.Connection, script_hashes: Sequence[bytes]) \
        -> List[KeyInstanceScriptHashRow]:
    sql = (
        "SELECT keyinstance_id, script_type, script_hash "
        "FROM KeyInstanceScripts "
        "WHERE script_hash IN ({})")
    return read_rows_by_id(KeyInstanceScriptHashRow, db, sql, [], script_hashes)


@replace_db_context_with_connection
def read_keyinstance(db: sqlite3.Connection, *, account_id: Optional[int]=None,
        keyinstance_id: Optional[int]=None) -> Optional[KeyInstanceRow]:
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
def read_keyinstance_derivation_indexes_last(db: sqlite3.Connection, account_id: int) \
        -> List[Tuple[int, bytes, bytes]]:
    # Keys are created in order of sequence enumeration, so we shouldn't need to order by
    # the derivation_data2 bytes to get them ordered from oldest to newest, just id.
    sql = """
    SELECT masterkey_id,
        substring(derivation_data2, 1, length(derivation_data2)-4) AS derivation_subpath,
        max(substring(derivation_data2, length(derivation_data2)-3,
        length(derivation_data2))) AS derivation_index
    FROM KeyInstances
    WHERE account_id=? AND derivation_type=?
    GROUP BY masterkey_id, derivation_subpath
    """
    sql_values = [ account_id, DerivationType.BIP32_SUBPATH ]
    return cast(List[Tuple[int, bytes, bytes]], db.execute(sql, sql_values).fetchall())


@replace_db_context_with_connection
def read_keyinstance_derivation_index_last(db: sqlite3.Connection, account_id: int,
        masterkey_id: int, derivation_subpath: DerivationPath) -> Optional[int]:
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = pack_derivation_path(derivation_subpath)
    # Keys are created in order of sequence enumeration, so we shouldn't need to order by
    # the derivation_data2 bytes to get them ordered from oldest to newest, just id.
    sql = ("SELECT derivation_data2 FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? "
            "AND length(derivation_data2)=? AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id DESC "
        "LIMIT 1")
    sql_values = [ account_id, masterkey_id,
        len(prefix_bytes)+4,  # The length of the parent path and sequence index.
        len(prefix_bytes),    # Just the length of the parent path.
        prefix_bytes          # The packed parent path bytes.
    ]
    row = db.execute(sql, sql_values).fetchone()
    if row is not None:
        return unpack_derivation_path(row[0])[-1]
    return None


@replace_db_context_with_connection
def read_keyinstances_for_derivations(db: sqlite3.Connection, account_id: int,
        derivation_type: DerivationType, derivation_data2s: List[bytes],
        masterkey_id: Optional[int]=None) -> List[KeyInstanceRow]:
    """
    Locate the keyinstance with the given `derivation_data2` field.
    """
    sql = ("SELECT KI.keyinstance_id, KI.account_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.description "
        "FROM KeyInstances AS KI "
        "WHERE account_id=? AND derivation_type=?")
    sql_values: List[Any] = [ account_id, derivation_type ]
    if masterkey_id is not None:
        sql += " AND masterkey_id=?"
        sql_values.append(masterkey_id)
    else:
        sql += " AND masterkey_id IS NULL"
    # This needs to be last as the batch read message appends the "id" values after the sql values.
    sql += " AND derivation_data2 IN ({})"
    return read_rows_by_id(KeyInstanceRow, db, sql, sql_values, derivation_data2s)


@replace_db_context_with_connection
def read_masterkeys(db: sqlite3.Connection) -> List[MasterKeyRow]:
    sql = (
        "SELECT masterkey_id, parent_masterkey_id, derivation_type, derivation_data, flags "
        "FROM MasterKeys")
    return [ MasterKeyRow(*row) for row in db.execute(sql).fetchall() ]


@replace_db_context_with_connection
def read_parent_transaction_outputs_with_key_data(db: sqlite3.Connection, tx_hash: bytes) \
        -> List[TransactionOutputSpendableRow]:
    """
    When we have the spending transaction in the database, we can look up the outputs using
    the database and do not have to provide the spent output keys.
    """
    sql_values = (tx_hash,)
    sql = (
        "SELECT TXO.tx_hash, TXO.txo_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
            "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data2 "
        "FROM TransactionInputs TXI "
        "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=TXI.spent_tx_hash "
            "AND TXO.txo_index=TXI.spent_txo_index "
        "LEFT JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id "
        "WHERE TXI.tx_hash=?")
    cursor = db.execute(sql, sql_values)
    rows = [ TransactionOutputSpendableRow(*row) for row in cursor.fetchall() ]
    cursor.close()
    return rows


@replace_db_context_with_connection
def read_payment_request(db: sqlite3.Connection, *, request_id: Optional[int]=None,
        keyinstance_id: Optional[int]=None) -> Optional[PaymentRequestReadRow]:
    sql = """
        WITH key_payments AS (
            SELECT KI.keyinstance_id, TOTAL(TXO.value) AS total_value
            FROM KeyInstances KI
            LEFT JOIN TransactionOutputs TXO ON KI.keyinstance_id=TXO.keyinstance_id
            GROUP BY KI.keyinstance_id
        )

        SELECT PR.paymentrequest_id, PR.keyinstance_id, PR.state, PR.value, KP.total_value,
            PR.expiration, PR.description, PR.date_created
        FROM PaymentRequests PR
        INNER JOIN key_payments KP USING(keyinstance_id)
    """
    if request_id is not None:
        sql += f" WHERE PR.paymentrequest_id=?"
        sql_values = [ request_id ]
    elif keyinstance_id is not None:
        sql += f" WHERE PR.keyinstance_id=?"
        sql_values = [ keyinstance_id ]
    else:
        raise NotImplementedError("request_id and keyinstance_id not supported")
    t = db.execute(sql, sql_values).fetchone()
    if t is not None:
        return PaymentRequestReadRow(t[0], t[1], PaymentFlag(t[2]), t[3], t[4], t[5], t[6], t[7])
    return None


@replace_db_context_with_connection
def read_payment_requests(db: sqlite3.Connection, account_id: int,
        flags: Optional[PaymentFlag]=None, mask: Optional[PaymentFlag]=None) \
            -> List[PaymentRequestReadRow]:
    sql = """
    WITH key_payments AS (
        SELECT KI.keyinstance_id, TOTAL(TXO.value) AS total_value
        FROM KeyInstances KI
        LEFT JOIN TransactionOutputs TXO ON KI.keyinstance_id=TXO.keyinstance_id
        WHERE KI.account_id=?
        GROUP BY KI.keyinstance_id
    )

    SELECT PR.paymentrequest_id, PR.keyinstance_id, PR.state, PR.value, KP.total_value,
        PR.expiration, PR.description, PR.date_created FROM PaymentRequests PR
    INNER JOIN key_payments KP USING(keyinstance_id)
    """
    sql_values: List[Any] = [ account_id ]
    clause, extra_values = flag_clause("PR.state", flags, mask)
    if clause:
        sql += f" WHERE {clause}"
        sql_values.extend(extra_values)
    return [ PaymentRequestReadRow(t[0], t[1], PaymentFlag(t[2]), t[3], t[4], t[5], t[6], t[7])
        for t in db.execute(sql, sql_values).fetchall() ]


# TODO(1.4.0) Remove when we have replaced with a reference server equivalent.
# @replace_db_context_with_connection
# def read_reorged_transactions(db: sqlite3.Connection, reorg_height: int) -> List[bytes]:
#     """
#     Identify all transactions that were verified in the orphaned chain as part of a reorg.
#     """
#     sql = (
#         "SELECT tx_hash "
#         "FROM Transactions "
#         f"WHERE block_height>? AND flags&{TxFlags.STATE_SETTLED}!=0"
#     )
#     sql_values = (reorg_height,)
#     cursor = db.execute(sql, sql_values)
#     rows = [ tx_hash for (tx_hash,) in cursor.fetchall() ]
#     cursor.close()
#     return rows


@replace_db_context_with_connection
def read_transaction_bytes(db: sqlite3.Connection, tx_hash: bytes) -> Optional[bytes]:
    cursor = db.execute("SELECT tx_data FROM Transactions WHERE tx_hash=?", (tx_hash,))
    row = cursor.fetchone()
    if row is not None:
        return cast(bytes, row[0])
    return None


@replace_db_context_with_connection
def read_transaction_descriptions(db: sqlite3.Connection, account_id: Optional[int]=None,
        tx_hashes: Optional[Sequence[bytes]]=None) -> List[AccountTransactionDescriptionRow]:
    sql = (
        "SELECT account_id, tx_hash, description "
        "FROM AccountTransactions "
        "WHERE description IS NOT NULL")
    sql_values: List[Any] = []
    if account_id is not None:
        sql += " AND account_id=?"
        sql_values = [ account_id ]
    if tx_hashes:
        sql += " AND tx_hash IN ({})"
        return read_rows_by_id(AccountTransactionDescriptionRow, db, sql, sql_values, tx_hashes)
    return [ AccountTransactionDescriptionRow(*row)
        for row in db.execute(sql, sql_values).fetchall() ]


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
    return TxFlags(row[0])


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
    sql = ("SELECT block_hash, block_position, fee_value, date_created "
        "FROM Transactions WHERE tx_hash=?")
    row = db.execute(sql, (tx_hash,)).fetchone()
    return None if row is None else TransactionMetadata(*row)


@replace_db_context_with_connection
def read_transaction_outputs_explicit(db: sqlite3.Connection, output_ids: List[Outpoint]) \
        -> List[TransactionOutputShortRow]:
    """
    Read all the transaction outputs for the given outpoints if they exist.
    """
    sql = (
        "SELECT tx_hash, txo_index, value, keyinstance_id, flags, script_type, script_hash "
        "FROM TransactionOutputs")
    sql_condition = "tx_hash=? AND txo_index=?"
    return read_rows_by_ids(TransactionOutputShortRow, db, sql, sql_condition, [], output_ids)


@replace_db_context_with_connection
def read_transaction_inputs_full(db: sqlite3.Connection) -> List[TransactionInputAddRow]:
    """
    Read all the transaction outputs for the given outpoints if they exist.
    """
    sql = (
        "SELECT tx_hash, txi_index, spent_tx_hash, spent_txo_index, sequence, flags, "
            "script_offset, script_length, date_created, date_updated "
        "FROM TransactionInputs")

    cursor = db.execute(sql)
    rows = cursor.fetchall()
    cursor.close()
    return [ TransactionInputAddRow(*row) for row in rows ]


@replace_db_context_with_connection
def read_transaction_outputs_full(db: sqlite3.Connection,
        output_ids: Optional[List[Outpoint]]=None) -> List[TransactionOutputFullRow]:
    """
    Read all the transaction outputs for the given outpoints if they exist.
    """
    sql = (
        "SELECT tx_hash, txo_index, value, keyinstance_id, flags, script_type, script_hash, "
            "script_offset, script_length, spending_tx_hash, spending_txi_index "
        "FROM TransactionOutputs")
    if output_ids is not None:
        sql_condition = "tx_hash=? AND txo_index=?"
        return read_rows_by_ids(TransactionOutputFullRow, db, sql, sql_condition, [], output_ids)

    cursor = db.execute(sql)
    rows = cursor.fetchall()
    cursor.close()
    return [ TransactionOutputFullRow(*row) for row in rows ]


@replace_db_context_with_connection
def read_transaction_outputs_with_key_data(db: sqlite3.Connection, *,
        account_id: Optional[int]=None,
        tx_hash: Optional[bytes]=None,
        txo_keys: Optional[List[Outpoint]]=None,
        derivation_data2s: Optional[List[bytes]]=None,
        require_keys: bool=False) -> List[TransactionOutputSpendableRow]:
    """
    Read all the transaction outputs with spend information for the given outpoints if they exist.
    """
    sql_values: List[Any] = []
    if derivation_data2s:
        sql = (
            "SELECT TXO.tx_hash, TXO.txo_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
                "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, "
                "KI.derivation_data2 "
            "FROM TransactionOutputs TXO "
            "INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id ")
        if account_id is not None:
            sql += " AND KI.account_id=?"
            sql_values.append(account_id)
        if tx_hash:
            sql += " WHERE TXO.tx_hash=? AND KI.derivation_data2 IN ({})"
            sql_values.append(tx_hash)
        else:
            sql += " WHERE KI.derivation_data2 IN ({})"
        return read_rows_by_id(TransactionOutputSpendableRow, db, sql, sql_values,
            derivation_data2s)
    elif tx_hash:
        assert txo_keys is None
        join_term = "INNER" if require_keys else "LEFT"
        sql = (
            "SELECT TXO.tx_hash, TXO.txo_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
                "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, "
                "KI.derivation_data2 "
            "FROM TransactionOutputs TXO "
            f"{join_term} JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id "
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
        join_term = "INNER" if require_keys else "LEFT"
        # The left join is necessary here because we are looking for just the output information if
        # an output is not ours, but also the key data fields if the output is ours. An example of
        # this is that we always want to know the value of an output being spent. Remember that
        # the wallet only adds account relevant transactions to the database.
        sql = (
            "SELECT TXO.tx_hash, TXO.txo_index, TXO.value, TXO.keyinstance_id, TXO.script_type, "
                "TXO.flags, KI.account_id, KI.masterkey_id, KI.derivation_type, "
                "KI.derivation_data2 "
            "FROM TransactionOutputs TXO "
            f"{join_term} JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id")
        if account_id is not None:
            sql += " AND KI.account_id=?"
            sql_values.append(account_id)
        sql_condition = "TXO.tx_hash=? AND TXO.txo_index=?"
        return read_rows_by_ids(TransactionOutputSpendableRow, db, sql, sql_condition,
            sql_values, txo_keys)
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
    if tx_hashes is None:
        sql = ("SELECT TXV.tx_hash, TOTAL(TXV.value), TX.flags, TX.block_hash, "
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

    sql = ("SELECT TXV.tx_hash, TOTAL(TXV.value), TX.flags, TX.block_hash, "
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
        derivation_path: DerivationPath, limit: int) -> List[KeyInstanceRow]:
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = pack_derivation_path(derivation_path)
    # Keys are created in order of sequence enumeration, so we shouldn't need to order by
    # the derivation_data2 bytes to get them ordered from oldest to newest, just id.
    sql = ("SELECT keyinstance_id, account_id, masterkey_id, derivation_type, "
        "derivation_data, derivation_data2, flags, description FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? "
            "AND (flags&?)=0 AND length(derivation_data2)=? AND substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id "
        f"LIMIT {limit}")
    cursor = db.execute(sql, (account_id, masterkey_id,
        KeyInstanceFlag.USED,
        len(prefix_bytes)+4,  # The length of the parent path and sequence index.
        len(prefix_bytes),    # Just the length of the parent path.
        prefix_bytes))        # The packed parent path bytes.
    rows = cursor.fetchall()
    cursor.close()

    # TODO Looking at the callers of this as of the time this comment was written, it appears that
    #    only the keydata related fields are used by those callers. It should be possible to drop
    #    the non-keydata fields and return a more limited keydata-specific result.
    return [ KeyInstanceRow(row[0], row[1], row[2], DerivationType(row[3]), row[4], row[5],
        KeyInstanceFlag(row[6]), row[7]) for row in rows ]



@replace_db_context_with_connection
def read_bip32_keys_gap_size(db: sqlite3.Connection, account_id: int,
        masterkey_id: int, prefix_bytes: bytes) -> int:
    """
    Identify the trailing BIP32 gap (of unused keys) at the end of a derivation sequence.

    For now we create keys in a BIP32 sequence sequentially with no gaps, so we can take the
    `window_size` from the query as indicating how many unused keys are in the trailing BIP32
    gap.
    """
    sql = """
    SELECT derivation_data2, flags, window_size FROM
        (SELECT KI.keyinstance_id, KI.derivation_data2, KI.flags, COUNT(*) OVER win AS window_size,
            row_number() OVER win AS window_row
        FROM KeyInstances KI
        WHERE account_id=? AND masterkey_id=? AND length(KI.derivation_data2)=?
            AND substr(KI.derivation_data2,1,?)=?
        WINDOW win AS (PARTITION BY flags&? ORDER BY keyinstance_id DESC
            RANGE BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING))
    WHERE window_row=1
    ORDER BY keyinstance_id DESC
    LIMIT 1
    """
    sql_values = [ account_id, masterkey_id, len(prefix_bytes)+4, len(prefix_bytes), prefix_bytes,
        KeyInstanceFlag.USED ]
    read_rows = db.execute(sql, sql_values).fetchall()
    if not len(read_rows):
        return 0
    # This should be the last sequence in the given derivation path, and the number of
    # entries with the given USED status.
    flags, gap_size = KeyInstanceFlag(read_rows[0][1]), cast(int, read_rows[0][2])
    if flags & KeyInstanceFlag.USED:
        return 0
    return gap_size



@replace_db_context_with_connection
def read_network_servers(db: sqlite3.Connection,
        server_key: Optional[Tuple[NetworkServerType, str]]=None) \
        -> Tuple[List[NetworkServerRow], List[NetworkServerAccountRow]]:
    read_server_row_sql = "SELECT url, server_type, encrypted_api_key, flags, fee_quote_json, " \
            "date_last_tried, date_last_connected, date_created, date_updated " \
        "FROM Servers"
    read_account_rows_sql = "SELECT url, server_type, account_id, encrypted_api_key, " \
            "fee_quote_json, date_last_tried, date_last_connected, date_created, date_updated " \
        "FROM ServerAccounts"
    params: Sequence[Any] = ()
    if server_key is not None:
        read_server_row_sql += f" WHERE server_type=? AND url=?"
        read_account_rows_sql += f" WHERE server_type=? AND url=?"
        params = server_key
    cursor = db.execute(read_server_row_sql, params)
    # WARNING The order of the fields in this data structure are implicitly linked to the query.
    server_rows = [ NetworkServerRow(*r) for r in cursor.fetchall() ]
    cursor = db.execute(read_account_rows_sql, params)
    account_rows = [ NetworkServerAccountRow(*r) for r in cursor.fetchall() ]
    return server_rows, account_rows


@replace_db_context_with_connection
def read_wallet_balance(db: sqlite3.Connection,
        txo_flags: TransactionOutputFlag=TransactionOutputFlag.NONE,
        txo_mask: TransactionOutputFlag=TransactionOutputFlag.SPENT,
        exclude_frozen: bool=True) -> WalletBalance:
    if exclude_frozen:
        txo_mask |= TransactionOutputFlag.FROZEN
    # NOTE(linked-balance-calculations) the general formula is used elsewhere
    sql = (
        "SELECT "
            # Confirmed.
            "CAST(TOTAL(CASE WHEN TX.flags&? AND TXO.flags&?=? THEN TXO.value ELSE 0 END) AS INT), "
            # Unconfirmed total.
            "CAST(TOTAL(CASE WHEN TX.flags&? THEN TXO.value ELSE 0 END) AS INT), "
            # Unmatured total.
            "CAST(TOTAL(CASE WHEN TX.flags&? AND TXO.flags&?=? THEN TXO.value ELSE 0 END) AS INT), "
            # Allocated total.
            "CAST(TOTAL(CASE WHEN TX.flags&? THEN TXO.value ELSE 0 END) AS INT) "
        "FROM TransactionOutputs TXO "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
        "INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id "
        "WHERE TXO.flags&?=?")
    # The `COINBASE_IMMATURE` flag is expected to be set on insert unless it is known the
    # transaction is mature.
    coinbase_filter_mask = TransactionOutputFlag.COINBASE_IMMATURE
    sql_values = [
        TxFlags.STATE_SETTLED, coinbase_filter_mask, TransactionOutputFlag.NONE,
        TxFlags.STATE_CLEARED,
        TxFlags.STATE_SETTLED, coinbase_filter_mask, coinbase_filter_mask,
        TxFlags.MASK_STATE_UNCLEARED,
        txo_mask, txo_flags ]
    if exclude_frozen:
        sql += " AND KI.flags&?=0"
        sql_values.append(KeyInstanceFlag.FROZEN)
    cursor = db.execute(sql, sql_values)
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


def remove_transaction(db_context: DatabaseContext, tx_hash: bytes) \
        -> concurrent.futures.Future[bool]:
    """
    Unlink a transaction from any accounts it is associated with and mark it as removed.
    """
    tx_flags = read_transaction_flags(db_context, tx_hash)
    assert tx_flags is not None
    # We do not currently allow broadcast transactions to be deleted, and may never allow it.
    if tx_flags & TxFlags.MASK_STATE_BROADCAST != 0:
        raise TransactionRemovalError("Unable to delete broadcast transactions")

    check_sql1 = "SELECT COUNT(*) FROM TransactionOutputs " \
        "WHERE tx_hash=? AND spending_tx_hash IS NOT NULL"

    # TODO(database) There should be a cleaner way of doing this, whether a context manager or
    #   whatever.
    db = db_context.acquire_connection()
    try:
        cursor = db.execute(check_sql1, (tx_hash,))
        if cursor.fetchone()[0] > 0:
            raise TransactionRemovalError(_("Another transaction spends this transaction. Try "
                "removing that transaction first."))
    finally:
        db_context.release_connection(db)

    timestamp = get_posix_timestamp()
    tx_out_mask = ~TransactionOutputFlag.SPENT
    # Back out the association of the transaction with accounts. We do not bother clearing the
    # key id and script type from the transaction outputs at this time.
    sql1 = "DELETE FROM AccountTransactions WHERE tx_hash=?"
    sql1_values = (tx_hash,)
    sql2 = ("UPDATE TransactionOutputs "
        f"SET date_updated=?, flags=flags&?, spending_tx_hash=NULL, spending_txi_index=NULL "
        "WHERE spending_tx_hash=?")
    sql2_values = (timestamp, tx_out_mask, tx_hash)
    sql3 = "UPDATE Invoices SET date_updated=?, tx_hash=NULL WHERE tx_hash=?"
    sql3_values = (timestamp, tx_hash)
    # The block height is left as it was, and can be any value unrepresentative of the state
    # of the transaction should it still exist elsewhere. Filtering for rows without the `REMOVED`
    # flag will make this correct behaviour.
    sql4 = (f"UPDATE Transactions SET date_updated=?, flags=flags|{TxFlags.REMOVED} "
        "WHERE tx_hash=?")
    sql4_values = (timestamp, tx_hash)

    def _write(db: sqlite3.Connection) -> bool:
        db.execute(sql1, sql1_values)
        db.execute(sql2, sql2_values)
        db.execute(sql3, sql3_values)
        cursor = db.execute(sql4, sql4_values)
        assert cursor.rowcount == 1
        return True
    return db_context.post_to_thread(_write)


def reserve_keyinstance(db_context: DatabaseContext, account_id: int, masterkey_id: int,
        derivation_path: DerivationPath, allocation_flags: KeyInstanceFlag) \
            -> concurrent.futures.Future[Tuple[int, DerivationType, bytes, KeyInstanceFlag]]:
    """
    Allocate one keyinstance for the caller's usage.

    See the account `reserve_keyinstance` docstring for more detail about how to correctly use this.

    Returns the allocated `keyinstance_id` if successful.
    Raises `KeyInstanceNotFoundError` if there are no available key instances.
    Raises `DatabaseUpdateError` if something else allocated the selected keyinstance first.
    """
    assert allocation_flags & KeyInstanceFlag.USED == 0
    # The derivation path is the relative parent path from the master key.
    prefix_bytes = pack_derivation_path(derivation_path)
    allocation_flags |= KeyInstanceFlag.USED
    # We need to do this in two steps to get the id of the keyinstance we allocated.
    sql_read = (
        "SELECT keyinstance_id, derivation_type, derivation_data2 "
        "FROM KeyInstances "
        "WHERE account_id=? AND masterkey_id=? AND (flags&?)=0 AND length(derivation_data2)=? AND "
            "substr(derivation_data2,1,?)=? "
        "ORDER BY keyinstance_id ASC "
        "LIMIT 1")
    sql_read_values = [ account_id, masterkey_id,
        KeyInstanceFlag.USED,           # Filter out rows with these flags.
        len(prefix_bytes)+4,            # The length of the parent path and sequence index.
        len(prefix_bytes),              # Just the length of the parent path.
        prefix_bytes ]                  # The packed parent path bytes.
    sql_write = "UPDATE KeyInstances SET flags=flags|? WHERE keyinstance_id=? AND flags&?=0"

    def _write(db: sqlite3.Connection) -> Tuple[int, DerivationType, bytes, KeyInstanceFlag]:
        keyinstance_row = db.execute(sql_read, sql_read_values).fetchone()
        if keyinstance_row is None:
            raise KeyInstanceNotFoundError()

        # The result of the read operation just happens to be the parameters we need for the write.
        cursor = db.execute(sql_write, (allocation_flags, keyinstance_row[0], KeyInstanceFlag.USED))
        if cursor.rowcount != 1:
            # The key was allocated by something else between the read and the write.
            raise DatabaseUpdateError()

        return cast(int, keyinstance_row[0]), DerivationType(keyinstance_row[1]), \
            keyinstance_row[2], allocation_flags

    return db_context.post_to_thread(_write)


def set_keyinstance_flags(db_context: DatabaseContext, key_ids: Sequence[int],
        flags: KeyInstanceFlag, mask: Optional[KeyInstanceFlag]=None) \
            -> concurrent.futures.Future[List[KeyInstanceFlagChangeRow]]:
    if mask is None:
        # NOTE(typing) There is no gain in casting to KeyInstanceFlag.
        mask = ~flags # type: ignore
    # We need to clear the `ACTIVE` flag if all the reasons why this key is `ACTIVE` are cleared
    # with the update for the given role.
    sql_write = (
        "UPDATE KeyInstances "
        "SET date_updated=?, flags=CASE "
            "WHEN ((flags&?)|?)&?=? THEN ((flags&?)|?)&? "
            "ELSE (flags&?)|? "
            "END "
        "WHERE keyinstance_id IN ({}) "
        "RETURNING keyinstance_id, flags")
    # Ensure that we rollback if we are applying changes that are already in place. We expect to
    # update all the rows we are asked to update, and this will filter out the rows that already
    # have any of the flags we intend to set.
    # NOTE If any caller wants to do overwrites or partial updates then that should be a standard
    # policy optionally passed into all update calls.
    sql_write_values = [ get_posix_timestamp(),
        mask, flags, KeyInstanceFlag.MASK_ACTIVE_REASON | KeyInstanceFlag.ACTIVE,
            KeyInstanceFlag.ACTIVE,
        mask, flags, ~KeyInstanceFlag.ACTIVE,
        mask, flags,
    ]

    sql_read = (
        "SELECT keyinstance_id, flags "
        "FROM KeyInstances "
        "WHERE keyinstance_id IN ({})")

    def _write(db: sqlite3.Connection) -> List[KeyInstanceFlagChangeRow]:
        # TODO(optimisation) It is potentially possible to combine this into the update by using
        #   a join or a sub-select. But whether this works with Sqlite, is another matter.
        #   Reference: https://stackoverflow.com/a/7927957
        old_rows = read_rows_by_id(KeyInstanceFlagRow, db, sql_read, [], key_ids)
        if len(old_rows) != len(key_ids):
            raise DatabaseUpdateError(f"Rollback as only {len(old_rows)} of {len(key_ids)} "
                "rows were located")

        # Sqlite is not guaranteed to set `rowcount` reliably. We have `new_rows` anyway.
        rows_updated, new_rows = execute_sql_by_id(db, sql_write, sql_write_values, key_ids,
            return_type=KeyInstanceFlagRow)
        if len(new_rows) != len(key_ids):
            raise DatabaseUpdateError(f"Rollback as only {len(new_rows)} of {len(key_ids)} "
                "rows were updated")

        final_rows: List[KeyInstanceFlagChangeRow] = []
        rows_by_keyinstance_id = { row.keyinstance_id: row for row in old_rows }
        for new_row in new_rows:
            old_row = rows_by_keyinstance_id[new_row.keyinstance_id]
            final_rows.append(KeyInstanceFlagChangeRow(new_row.keyinstance_id,
                old_row.flags, new_row.flags))

        return final_rows
    return db_context.post_to_thread(_write)


def set_transaction_state(db_context: DatabaseContext, tx_hash: bytes, flag: TxFlags,
        ignore_mask: Optional[TxFlags]=None) -> concurrent.futures.Future[bool]:
    """
    Set a transaction to given state.

    If the transaction is in an pre-dispatched state, this should succeed and will return `True`.
    If the transaction is not in a pre-dispatched state, then this will return `False` and no
    change will be made.
    """
    # TODO(python-3.10) Python 3.10 has `flag.bitcount()` supposedly.
    assert bin(flag).count("1") == 1, "only one state can be specified at a time"
    # We will clear any existing state bits.
    mask_bits = ~TxFlags.MASK_STATE
    if ignore_mask is None:
        ignore_mask = flag
    timestamp = get_posix_timestamp()
    sql = (
        "UPDATE Transactions SET date_updated=?, flags=(flags&?)|? "
        "WHERE tx_hash=? AND flags&?=0")
    sql_values = [ timestamp, mask_bits, flag, tx_hash, ignore_mask ]

    def _write(db: sqlite3.Connection) -> bool:
        cursor = db.execute(sql, sql_values)
        if cursor.rowcount == 0:
            # Rollback the database transaction (nothing to rollback but upholding the convention).
            raise DatabaseUpdateError("Rollback as nothing updated")
        return True
    return db_context.post_to_thread(_write)


# TODO(1.4.0) Remove when we have replaced with a reference server equivalent.
# def set_transactions_reorged(db_context: DatabaseContext, tx_hashes: List[bytes]) \
#         -> concurrent.futures.Future[bool]:
#     """
#     Reset transactions back to unverified state as a batch.

#     NOTE This may not restore the correct block height, which is prohibitive. 0 is unconfirmed,
#     and -1 is unconfirmed parents. We do not have the information to know if it has unconfirmed
#     parents.
#     """
#     timestamp = get_posix_timestamp()
#     sql = (
#         "UPDATE Transactions "
#         "SET date_updated=?, flags=(flags&?)|?, block_hash=NULL, block_position=NULL, "
#             "fee_value=NULL, proof_data=NULL "
#         "WHERE tx_hash IN ({})")
#     sql_values = [ timestamp, ~TxFlags.MASK_STATE, TxFlags.STATE_CLEARED ]

#     def _write(db: sqlite3.Connection) -> bool:
#         rows_updated = execute_sql_by_id(db, sql, sql_values, tx_hashes)[0]
#         if rows_updated < len(tx_hashes):
#             # Rollback the database transaction (nothing to rollback but upholding the convention)
#             raise DatabaseUpdateError("Rollback as nothing updated")
#         return True
#     return db_context.post_to_thread(_write)


def update_transaction_output_flags(db_context: DatabaseContext, txo_keys: List[Outpoint],
        flags: TransactionOutputFlag, mask: Optional[TransactionOutputFlag]=None) \
            -> concurrent.futures.Future[bool]:
    if mask is None:
        # NOTE(typing) There is no gain in casting to TransactionOutputFlag.
        mask = ~flags # type: ignore
    sql = "UPDATE TransactionOutputs SET date_updated=?, flags=(flags&?)|?"
    sql_id_expression = "tx_hash=? AND txo_index=?"
    sql_values = [ get_posix_timestamp(), mask, flags ]

    def _write(db: sqlite3.Connection) -> bool:
        nonlocal sql, sql_id_expression, sql_values, txo_keys
        rows_updated = update_rows_by_ids(db, sql, sql_id_expression, sql_values, txo_keys)
        if rows_updated != len(txo_keys):
            raise DatabaseUpdateError(f"Rollback as only {rows_updated} of {len(txo_keys)} "
                "rows were updated")
        return True
    return db_context.post_to_thread(_write)


def set_wallet_datas(db_context: DatabaseContext, entries: Iterable[WalletDataRow]) \
        -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO WalletData (key, value, date_created, date_updated) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, date_updated=excluded.date_updated")
    timestamp = get_posix_timestamp()
    rows = []
    for entry in entries:
        rows.append((entry.key, json.dumps(entry.value), timestamp, timestamp))

    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_account_names(db_context: DatabaseContext, entries: Iterable[Tuple[str, int]]) \
        -> concurrent.futures.Future[None]:
    sql = "UPDATE Accounts SET date_updated=?, account_name=? WHERE account_id=?"
    timestamp = get_posix_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_account_script_types(db_context: DatabaseContext,
        entries: Iterable[Tuple[ScriptType, int]]) -> concurrent.futures.Future[None]:
    sql = "UPDATE Accounts SET date_updated=?, default_script_type=? WHERE account_id=?"
    timestamp = get_posix_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_account_transaction_descriptions(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[str], int, bytes]]) -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    sql = "UPDATE AccountTransactions SET date_updated=?, description=? " \
        "WHERE account_id=? AND tx_hash=?"
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_transactions(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[bytes], int]]) -> concurrent.futures.Future[None]:
    sql = "UPDATE Invoices SET date_updated=?, tx_hash=? WHERE invoice_id=?"
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_descriptions(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[str], int]]) -> concurrent.futures.Future[None]:
    sql = ("UPDATE Invoices SET date_updated=?, description=? "
        "WHERE invoice_id=?")
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_flags(db_context: DatabaseContext,
        entries: Iterable[Tuple[PaymentFlag, PaymentFlag, int]]) -> concurrent.futures.Future[None]:
    sql = ("UPDATE Invoices SET date_updated=?, "
            "invoice_flags=((invoice_flags&?)|?) "
        "WHERE invoice_id=?")
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_keyinstance_derivation_datas(db_context: DatabaseContext,
        entries: Iterable[Tuple[bytes, int]]) -> concurrent.futures.Future[None]:
    sql = ("UPDATE KeyInstances SET date_updated=?, derivation_data=? WHERE keyinstance_id=?")

    timestamp = get_posix_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]

    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_keyinstance_descriptions(db_context: DatabaseContext,
        entries: Iterable[Tuple[Optional[str], int]]) -> concurrent.futures.Future[None]:
    sql = ("UPDATE KeyInstances SET date_updated=?, description=? WHERE keyinstance_id=?")
    timestamp = get_posix_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_password(db_context: DatabaseContext, old_password: str, new_password: str) \
        -> concurrent.futures.Future[PasswordUpdateResult]:
    """
    Update the wallet password and all data encrypted with it as an atomic action.

    The idea is that if something fails, then the process is aborted and nothing is changed. This
    cannot be guaranteed if it is done piecemeal at a higher level. Results are returned to the
    calling wallet context, so that it can notify systems where applicable of changes. Given that
    the database is authoritative where possible, these changes should be minimal.
    """
    token_update_sql = "UPDATE WalletData SET date_updated=?, value=? WHERE key=?"
    keyinstance_read_sql = "SELECT keyinstance_id, account_id, derivation_data FROM KeyInstances " \
        f"WHERE derivation_type={DerivationType.PRIVATE_KEY}"
    keyinstance_update_sql = "UPDATE KeyInstances SET date_updated=?, derivation_data=? " \
        "WHERE keyinstance_id=?"
    masterkey_read_sql = "SELECT masterkey_id, derivation_type, derivation_data FROM MasterKeys"
    masterkey_update_sql = "UPDATE MasterKeys SET date_updated=?, derivation_data=? " \
        "WHERE masterkey_id=?"
    server_read_sql = "SELECT url, server_type, encrypted_api_key FROM Servers " \
        "WHERE encrypted_api_key IS NOT NULL"
    server_update_sql = "UPDATE Servers SET date_updated=?, encrypted_api_key=? " \
        "WHERE url=? AND server_type=?"
    server_account_read_sql = "SELECT url, server_type, account_id, encrypted_api_key " \
        "FROM ServerAccounts"
    server_account_update_sql = "UPDATE ServerAccounts SET date_updated=?, encrypted_api_key=? " \
        "WHERE url=? AND server_type=? AND account_id=?"

    date_updated = get_posix_timestamp()

    def _write(db: sqlite3.Connection) -> PasswordUpdateResult:
        password_token = pw_encode(os.urandom(32).hex(), new_password)

        cursor = db.execute(token_update_sql, (date_updated, password_token, "password-token"))
        assert cursor.rowcount == 1

        # This tracks the updated encrypted values for the wallet to replace cached versions of
        # these with.
        result = PasswordUpdateResult(
            password_token=password_token,
            masterkey_updates=[],
            account_private_key_updates=defaultdict(list))

        def reencrypt_bip32_masterkey(data: MasterKeyDataBIP32) -> bool:
            modified = False
            for entry_name in ("seed", "passphrase", "xprv"):
                entry_value = cast(Optional[str], data.get(entry_name, None))
                if not entry_value:
                    continue
                if entry_name == "seed":
                    data["seed"] = pw_encode(pw_decode(entry_value, old_password), new_password)
                elif entry_name == "passphrase":
                    data["passphrase"] = pw_encode(pw_decode(entry_value, old_password),
                        new_password)
                elif entry_name == "xprv":
                    data["xprv"] = pw_encode(pw_decode(entry_value, old_password),
                        new_password)
                modified = True
            return modified

        def reencrypt_old_masterkey(data: MasterKeyDataElectrumOld) -> bool:
            seed = data.get("seed")
            if seed is None:
                return False
            data["seed"] = pw_encode(pw_decode(seed, old_password), new_password)
            return True

        def reencrypt_masterkey_data(masterkey_id: int, masterkey_derivation_type: DerivationType,
                source_derivation_data: bytes, result: PasswordUpdateResult) -> Optional[bytes]:
            modified = False
            data = cast(MasterKeyDataTypes, json.loads(source_derivation_data))
            if masterkey_derivation_type == DerivationType.ELECTRUM_MULTISIG:
                cosigner_keys = cast(MasterKeyDataMultiSignature, data)["cosigner-keys"]
                for derivation_type, cosigner_derivation_data in cosigner_keys:
                    if derivation_type == DerivationType.BIP32:
                        modified |= reencrypt_bip32_masterkey(
                            cast(MasterKeyDataBIP32, cosigner_derivation_data))
                    elif derivation_type == DerivationType.ELECTRUM_OLD:
                        modified |= reencrypt_old_masterkey(
                            cast(MasterKeyDataElectrumOld, cosigner_derivation_data))
                    elif derivation_type != DerivationType.HARDWARE:
                        raise NotImplementedError(f"Unhandled signer type {derivation_type}")
            elif masterkey_derivation_type == DerivationType.BIP32:
                modified = reencrypt_bip32_masterkey(cast(MasterKeyDataBIP32, data))
            elif masterkey_derivation_type == DerivationType.ELECTRUM_OLD:
                modified = reencrypt_old_masterkey(cast(MasterKeyDataElectrumOld, data))
            if modified:
                result.masterkey_updates.append((masterkey_id, masterkey_derivation_type, data))
                return json.dumps(data).encode()
            return None

        keyinstance_id: int
        masterkey_id: int
        account_id: int
        source_derivation_data: bytes

        # Re-encrypt the stored private keys with the new password.
        keyinstance_updates: List[Tuple[int, bytes, int]] = []
        for keyinstance_id, account_id, source_derivation_data in db.execute(keyinstance_read_sql):
            data = cast(KeyInstanceDataPrivateKey, json.loads(source_derivation_data))
            data["prv"] = pw_encode(pw_decode(data["prv"], old_password), new_password)
            keyinstance_updates.append((date_updated, json.dumps(data).encode(),
                keyinstance_id))
            result.account_private_key_updates[account_id].append((keyinstance_id, data["prv"]))
        if len(keyinstance_updates):
            db.executemany(keyinstance_update_sql, keyinstance_updates)

        # Re-encrypt masterkey data (seed, passphrase, xprv) with the new password.
        masterkey_updates: List[Tuple[int, bytes, int]] = []
        for (masterkey_id, derivation_type, source_derivation_data) in \
                db.execute(masterkey_read_sql):
            updated_data = reencrypt_masterkey_data(masterkey_id, derivation_type,
                source_derivation_data, result)
            if updated_data is None:
                continue
            masterkey_updates.append((date_updated, updated_data, masterkey_id))
        if len(masterkey_updates):
            db.executemany(masterkey_update_sql, masterkey_updates)

        url: str
        raw_server_type: int
        server_type: NetworkServerType
        encrypted_api_key: str

        # Re-encrypt network server api keys with the new password.
        server_updates: List[Tuple[int, str, str, int]] = []
        for url, raw_server_type, encrypted_api_key in db.execute(server_read_sql):
            server_type = NetworkServerType(raw_server_type)
            encrypted_api_key2 = pw_encode(pw_decode(encrypted_api_key, old_password), new_password)
            server_updates.append((date_updated, encrypted_api_key2, url, server_type))
        if len(server_updates):
            db.executemany(server_update_sql, server_updates)

        # Re-encrypt network server account api keys with the new password.
        server_account_updates: List[Tuple[int, str, str, int, int]] = []
        for url, raw_server_type, account_id, encrypted_api_key in \
                db.execute(server_account_read_sql):
            server_type = NetworkServerType(raw_server_type)
            encrypted_api_key2 = pw_encode(pw_decode(encrypted_api_key, old_password), new_password)
            server_account_updates.append((date_updated, encrypted_api_key2, url, server_type,
                account_id))
        if len(server_account_updates):
            db.executemany(server_account_update_sql, server_account_updates)

        return result
    return db_context.post_to_thread(_write)


def _close_paid_payment_requests(db: sqlite3.Connection) \
        -> Tuple[Set[int], List[Tuple[int, int, int]], List[Tuple[str, int, bytes]]]:
    timestamp = get_posix_timestamp()
    sql_read_1 = """
    WITH key_payments AS (
        SELECT TXO.keyinstance_id, SUM(TXO.value) AS total_value
        FROM TransactionOutputs TXO
        INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id
        WHERE KI.flags&?!=0
        GROUP BY TXO.keyinstance_id
    )

    SELECT PR.paymentrequest_id, PR.keyinstance_id
    FROM PaymentRequests AS PR
    INNER JOIN key_payments KP ON KP.keyinstance_id=PR.keyinstance_id
    WHERE PR.state&?=? AND (PR.value IS NULL OR PR.value <= KP.total_value)
    """
    sql_read_1_values = [
        KeyInstanceFlag.IS_PAYMENT_REQUEST,
        PaymentFlag.MASK_STATE, PaymentFlag.UNPAID,
    ]
    read_rows = db.execute(sql_read_1, sql_read_1_values).fetchall()
    paymentrequest_ids = { row[0] for row in read_rows }
    keyinstance_rows: List[Tuple[int, int, int]] = []
    txdesc_rows: List[Tuple[str, int, bytes]] = []

    if len(read_rows):
        paymentrequest_update_rows = []
        for paymentrequest_id, keyinstance_id in read_rows:
            paymentrequest_update_rows.append((timestamp, PaymentFlag.CLEARED_MASK_STATE,
                PaymentFlag.PAID, paymentrequest_id))
        sql_write_1 = "UPDATE PaymentRequests SET date_updated=?, state=(state&?)|? " \
            "WHERE paymentrequest_id=?"
        db.executemany(sql_write_1, paymentrequest_update_rows).rowcount

        # NOTE(sqlite-update-returning-executemany) We cannot do an `executemany` here, as
        # it doesn't handle whatever adding the `RETURNING` made this, given that it worked
        # before we added it.
        keyinstance_update_row = [
            timestamp,
            KeyInstanceFlag.MASK_ACTIVE_REASON, KeyInstanceFlag.IS_PAYMENT_REQUEST,
            ~(KeyInstanceFlag.IS_PAYMENT_REQUEST|KeyInstanceFlag.ACTIVE),
            ~KeyInstanceFlag.IS_PAYMENT_REQUEST,
        ]
        keyinstance_update_row.extend(row[1] for row in read_rows)
        sql_write_2 = f"""
        UPDATE KeyInstances SET date_updated=?, flags=CASE
            WHEN flags&?=? THEN flags&? ELSE flags&? END
        WHERE keyinstance_id IN ({",".join("?" for v in read_rows)})
        RETURNING account_id, keyinstance_id, flags
        """
        keyinstance_rows = db.execute(sql_write_2, keyinstance_update_row).fetchall()

        sql_write_3a = """
        UPDATE AccountTransactions AS ATX
        SET description=PR.description
        FROM TransactionOutputs TXO
        INNER JOIN PaymentRequests PR ON PR.keyinstance_id=TXO.keyinstance_id
        WHERE TXO.tx_hash=ATX.tx_hash AND ATX.description IS NULL AND PR.paymentrequest_id IN ({})
        RETURNING description, account_id, tx_hash
        """
        sql_write_3b = sql_write_3a.format(",".join("?" for k in paymentrequest_ids))
        txdesc_rows = db.execute(sql_write_3b, list(paymentrequest_ids)).fetchall()

    return paymentrequest_ids, keyinstance_rows, txdesc_rows


async def close_paid_payment_requests_async(db_context: DatabaseContext) \
        -> Tuple[Set[int], List[Tuple[int, int, int]], List[Tuple[str, int, bytes]]]:
    """
    Wrap the database operations required to link a transaction so the processing is
    offloaded to the SQLite writer thread while this task is blocked.
    """
    return await db_context.run_in_thread_async(_close_paid_payment_requests)


def update_payment_requests(db_context: DatabaseContext,
        entries: Iterable[PaymentRequestUpdateRow]) -> concurrent.futures.Future[None]:
    sql = ("UPDATE PaymentRequests SET date_updated=?, state=?, value=?, expiration=?, "
        "description=? WHERE paymentrequest_id=?")
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]

    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_wallet_event_flags(db_context: DatabaseContext,
        entries: Iterable[Tuple[WalletEventFlag, int]]) -> concurrent.futures.Future[None]:
    sql = "UPDATE WalletEvents SET date_updated=?, event_flags=? WHERE event_id=?"
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_network_servers(db_context: DatabaseContext,
        added_server_rows: Optional[List[NetworkServerRow]]=None,
        added_server_account_rows: Optional[List[NetworkServerAccountRow]]=None,
        updated_server_rows: Optional[List[NetworkServerRow]]=None,
        updated_server_account_rows: Optional[List[NetworkServerAccountRow]]=None,
        deleted_server_keys: Optional[List[ServerAccountKey]]=None,
        deleted_server_account_keys: Optional[List[ServerAccountKey]]=None) \
            -> concurrent.futures.Future[None]:
    """
    Add, update and remove server definitions for this wallet.
    """
    delete_server_accounts_sql = "DELETE FROM ServerAccounts WHERE url=? AND server_type=?"
    delete_server_sql = "DELETE FROM Servers WHERE url=? AND server_type=?"
    delete_server_accounts_sql2 = "DELETE FROM ServerAccounts WHERE url=? AND server_type=? AND "\
        "account_id=?"
    insert_server_sql = "INSERT INTO Servers (url, server_type, encrypted_api_key, " \
        "flags, fee_quote_json, date_last_connected, date_last_tried, date_created, date_updated) "\
        "VALUES (?,?,?,?,?,?,?,?,?)"
    insert_server_accounts_sql = "INSERT INTO ServerAccounts (url, server_type, account_id, " \
        "encrypted_api_key, fee_quote_json, date_last_connected, date_last_tried, date_created, " \
        "date_updated) VALUES (?,?,?,?,?,?,?,?,?)"
    update_server_sql = "UPDATE Servers SET date_updated=?, encrypted_api_key=?, " \
        "flags=? WHERE url=? AND server_type=?"
    update_server_account_sql = "UPDATE ServerAccounts SET date_updated=?, encrypted_api_key=? " \
        "WHERE url=? AND server_type=? AND account_id=?"

    timestamp_utc = get_posix_timestamp()
    update_server_rows = []
    if updated_server_rows:
        update_server_rows = [ (timestamp_utc, server_row.encrypted_api_key, server_row.flags,
            server_row.url, server_row.server_type) for server_row in updated_server_rows ]
    update_server_account_rows = []
    if updated_server_account_rows:
        update_server_account_rows = [ (timestamp_utc, account_row.encrypted_api_key,
            account_row.url, account_row.server_type, account_row.account_id)
            for account_row in updated_server_account_rows ]
    delete_server_keys = []
    if deleted_server_keys:
        delete_server_keys = [ (v.url, v.server_type) for v in deleted_server_keys ]

    def _write(db: sqlite3.Connection) -> None:
        if delete_server_keys:
            db.executemany(delete_server_accounts_sql, delete_server_keys)
            db.executemany(delete_server_sql, delete_server_keys)
        if deleted_server_account_keys:
            db.executemany(delete_server_accounts_sql2, deleted_server_account_keys)
        if added_server_rows:
            db.executemany(insert_server_sql, added_server_rows)
        if added_server_account_rows:
            db.executemany(insert_server_accounts_sql, added_server_account_rows)
        if update_server_rows:
            db.executemany(update_server_sql, update_server_rows)
        if update_server_account_rows:
            db.executemany(update_server_account_sql, update_server_account_rows)
    return db_context.post_to_thread(_write)


def update_network_server_states(db_context: DatabaseContext,
        updated_server_rows: List[NetworkServerRow],
        updated_server_account_rows: List[NetworkServerAccountRow]) \
            -> concurrent.futures.Future[None]:
    """
    Update the state fields for server definitions on this wallet.

    Note that we pick and choose from the fields on the passed in rows, and use the standard rows
    to save having numerous row types with minimal variations each.
    """
    update_server_sql = "UPDATE Servers SET date_updated=?, fee_quote_json=?, " \
        "date_last_connected=?, date_last_tried=? WHERE url=? AND server_type=?"
    update_server_account_sql = "UPDATE ServerAccounts SET date_updated=?, fee_quote_json=?, " \
        "date_last_connected=?, date_last_tried=? WHERE url=? AND server_type=? AND account_id=?"

    timestamp_utc = get_posix_timestamp()
    update_server_rows = [ (timestamp_utc, server_row.mapi_fee_quote_json,
        server_row.date_last_good, server_row.date_last_try, server_row.url, server_row.server_type)
        for server_row in updated_server_rows ]
    update_server_account_rows = [ (timestamp_utc, account_row.mapi_fee_quote_json,
        account_row.date_last_good, account_row.date_last_try,
        account_row.url, account_row.server_type, account_row.account_id)
        for account_row in updated_server_account_rows ]

    def _write(db: sqlite3.Connection) -> None:
        if update_server_rows:
            db.executemany(update_server_sql, update_server_rows)
        if update_server_account_rows:
            db.executemany(update_server_account_sql, update_server_account_rows)
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

    def __enter__(self) -> "AsynchronousFunctions":
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]],
            exc_value: Optional[BaseException], traceback: Optional[TracebackType]) \
                -> None:
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
        for input in txi_rows:
            assert input.script_offset != 0
            assert input.script_length != 0
        for output in txo_rows:
            assert output.script_offset != 0
            assert output.script_length != 0

        # Constraint: tx_hash should be unique.
        try:
            db.execute("INSERT INTO Transactions (tx_hash, tx_data, flags, block_hash, "
                "block_position, fee_value, description, version, locktime, proof_data, "
                "date_created, date_updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", tx_row)
        except sqlite3.IntegrityError as e:
            if e.args[0] == "UNIQUE constraint failed: Transactions.tx_hash":
                raise TransactionAlreadyExistsError()

        # Constraint: (tx_hash, tx_index) should be unique.
        db.executemany("INSERT INTO TransactionInputs (tx_hash, txi_index, spent_tx_hash, "
            "spent_txo_index, sequence, flags, script_offset, script_length, date_created, "
            "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?)", txi_rows)

        # Constraint: (tx_hash, tx_index) should be unique.
        db.executemany("INSERT INTO TransactionOutputs (tx_hash, txo_index, value, keyinstance_id, "
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
            link_state: TransactionLinkState) -> None:
        """
        Wrap the database operations required to link a transaction so the processing is
        offloaded to the SQLite writer thread while this task is blocked.
        """
        await self._db_context.run_in_thread_async(self._link_transaction, tx_hash,
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
        self._link_transaction_key_usage(db, tx_hash, link_state)
        self._link_transaction_to_accounts(db, tx_hash)

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

    def _link_transaction_key_usage(self, db: sqlite3.Connection, tx_hash: bytes,
            link_state: TransactionLinkState) -> Tuple[int, int]:
        """
        Link transaction outputs to key usage.

        This function can be repeatedly called, which might be useful if for some reason keys
        were not created when it was first called for a transaction.
        """
        timestamp = get_posix_timestamp()
        sql_write_1 = (
            "UPDATE TransactionOutputs AS TXO "
            "SET date_updated=?, keyinstance_id=KIS.keyinstance_id, script_type=KIS.script_type "
            "FROM KeyInstanceScripts KIS "
            "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
            "WHERE TX.flags&?=0 AND TXO.tx_hash=? AND TXO.script_hash=KIS.script_hash")
        sql_write_1_values = (timestamp, TxFlags.MASK_UNLINKED, tx_hash)
        cursor_1 = db.execute(sql_write_1, sql_write_1_values)

        # We explicitly mark keys as used when we use them. See `KeyInstanceFlag.USED`
        # for a rationale. We want to know that keys were marked as used by this so that
        # the calling logic can use it, if need be. An example of this would be maintaining
        # a gap limit of unused addresses.
        sql_write_2 = (
            "UPDATE KeyInstances AS KI "
            "SET date_updated=?, flags=KI.flags|? "
            "FROM TransactionOutputs TXO "
            "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
            "WHERE TXO.keyinstance_id=KI.keyinstance_id AND TX.flags&?=0 AND TXO.tx_hash=? "
            "RETURNING account_id, masterkey_id, derivation_type, derivation_data2")
        sql_write_2_values = [timestamp, KeyInstanceFlag.USED,
            TxFlags.MASK_UNLINKED|KeyInstanceFlag.USED, tx_hash]
        cursor_2 = db.execute(sql_write_2, sql_write_2_values)

        return cursor_1.rowcount, cursor_2.rowcount

    def _link_transaction_to_accounts(self, db: sqlite3.Connection, tx_hash: bytes) -> int:
        """
        Link transaction output key usage to account involvement.

        This function can be repeatedly called, which might be useful if for some reason keys
        were not created when it was first called for a transaction.
        """
        timestamp = get_posix_timestamp()

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
        # NOTE(typing) error: Redundant cast to "int"  [redundant-cast]
        return cast(int, cursor.rowcount)  # type: ignore

    def _reconcile_transaction_output_spends(self, db: sqlite3.Connection, tx_hash: bytes) -> bool:
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
        timestamp = get_posix_timestamp()
        # The base SQL is just the spends of parent transaction outputs.
        sql = (
            "SELECT TXI.tx_hash, TXI.txi_index, TXO.tx_hash, TXO.txo_index, TXO.spending_tx_hash "
            "FROM TransactionInputs TXI "
            "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash = TXI.spent_tx_hash AND "
                "TXO.txo_index = TXI.spent_txo_index "
            "WHERE TXI.tx_hash=? OR TXI.spent_tx_hash=?")
        cursor = db.execute(sql, (tx_hash, tx_hash))

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
        clear_bits = TransactionOutputFlag.ALLOCATED
        set_bits = TransactionOutputFlag.SPENT
        cursor = db.executemany("UPDATE TransactionOutputs "
            "SET date_updated=?, spending_tx_hash=?, spending_txi_index=?, "
                f"flags=(flags&{~clear_bits})|{set_bits} "
            f"WHERE spending_tx_hash IS NULL AND tx_hash=? AND txo_index=?", spent_rows)
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

    # TODO(1.4.0) Read functions should not be async.
    async def read_pending_header_transactions_async(self) \
            -> list[tuple[bytes, Optional[bytes], bytes]]:
        """
        Transactions that are in state CLEARED and have proof are guaranteed to be those who
        we obtained proof for, but lacked the header to verify the proof. We need to
        reconcile these with headers as the headers arrive, and verify them when that happens.
        """
        return await self._db_context.run_in_thread_async(
            self._read_pending_header_transactions)

    def _read_pending_header_transactions(self, db: sqlite3.Connection) \
            -> list[tuple[bytes, Optional[bytes], bytes]]:
        sql = f"""
            SELECT tx_hash, block_hash, proof_data
            FROM Transactions
            WHERE flags&{TxFlags.MASK_STATE}={TxFlags.STATE_CLEARED} AND proof_data IS NOT NULL
        """
        rows = db.execute(sql).fetchall()
        return [ (row[0], row[1], row[2]) for row in rows ]

    # TODO(1.4.0) Read functions should not be async.
    async def read_spent_outputs_async(self, outpoints: Sequence[Outpoint]) -> List[SpentOutputRow]:
        """
        Get the metadata for how any of the given outpoints are spent. This is used to reconcile
        against any incoming state from a service about those given outpoints.
        """
        return await self._db_context.run_in_thread_async(self._read_spent_outputs,
            outpoints)

    def _read_spent_outputs(self, db: sqlite3.Connection, outpoints: Sequence[Outpoint]) \
            -> List[SpentOutputRow]:
        sql = f"""
        SELECT TXI.spent_tx_hash, TXI.spent_txo_index, TXI.tx_hash, TXI.txi_index, TX.block_hash,
            TX.flags
        FROM TransactionInputs TXI
        INNER JOIN Transactions TX ON TX.tx_hash=TXI.tx_hash
        """
        sql_condition = "TXI.spent_tx_hash=? AND TXI.spent_txo_index=?"
        return read_rows_by_ids(SpentOutputRow, db, sql, sql_condition, [], outpoints)

    # TODO(1.4.0) Read functions should not be async.
    async def read_transaction_proof_data_async(self, tx_hashes: List[bytes]) -> List[TxProofData]:
        return await self._db_context.run_in_thread_async(self._read_transaction_proof_data,
            tx_hashes)

    def _read_transaction_proof_data(self, db: sqlite3.Connection, tx_hashes: List[bytes]) \
            -> List[TxProofData]:
        sql = """
            SELECT tx_hash, flags, block_hash, proof_data FROM Transactions WHERE tx_hash IN ({})
        """
        sql_values = ()
        return read_rows_by_id(TxProofData, db, sql, sql_values, tx_hashes)

    async def update_transaction_flags_async(self, tx_hash: bytes, flags: TxFlags,
            mask: Union[int, TxFlags]) -> bool:
        return await self._db_context.run_in_thread_async(self._update_transaction_flags, tx_hash,
            flags, mask)

    def _update_transaction_flags(self, db: sqlite3.Connection, tx_hash: bytes,
            flags: TxFlags, mask: Union[int, TxFlags]) -> bool:
        sql = "UPDATE Transactions SET flags=(flags&?)|? WHERE tx_hash=?"
        sql_values: List[Any] = [ tx_hash, flags, mask ]
        cursor = db.execute(sql, sql_values)
        return cursor.rowcount == 1

    async def update_transaction_proof_async(self, tx_hash: bytes, block_hash: Optional[bytes],
            block_position: Optional[int], proof_data: Optional[bytes],
            tx_flags: TxFlags=TxFlags.STATE_SETTLED) -> None:
        await self._db_context.run_in_thread_async(self._update_transaction_proof, tx_hash,
            block_hash, block_position, proof_data, tx_flags)

    def _update_transaction_proof(self, db: sqlite3.Connection, tx_hash: bytes,
            block_hash: Optional[bytes], block_position: Optional[int],
            proof_data: Optional[bytes], tx_flags: TxFlags) -> None:
        """
        Set the proof related fields for a transaction.

        There are two cases where this is called.
        - We have a CLEARED transaction and have just obtained and verified the proof, where
          we should set it to SETTLED.
        - We have a CLEARED transaction and have just obtained but could not verify the proof,
          where we leave it as CLEARED (or set it to CLEARED if it is in another state).
        - We have any local (SIGNED, DISPATCHED, RECEIVED) or broadcast (CLEARED) transaction
          that we now have reason to believe is in a block.

        One case where it may be in SETTLED but not have proof data, and then get proof data that
        cannot be verified yet, is after migration 29 where we cleared all the legacy pre-TSC
        proof data but left the transactions as SETTLED in order for a better user experience
        (see the migration for further detail).

        This should only be called in the context of the writer thread.
        """
        assert tx_flags & ~TxFlags.MASK_STATE == 0      # No non-state flags should be set.
        assert tx_flags & TxFlags.MASK_STATE != 0       # A state flag should be set.

        timestamp = get_posix_timestamp()
        clear_state_mask = ~TxFlags.MASK_STATE
        sql = ("UPDATE Transactions "
            "SET date_updated=?, proof_data=?, block_hash=?, block_position=?, flags=(flags&?)|? "
            "WHERE tx_hash=?")
        sql_values = [ timestamp, proof_data, block_hash, block_position, clear_state_mask,
            tx_flags, tx_hash ]
        db.execute(sql, sql_values)


def create_mapi_broadcast_callbacks(db_context: DatabaseContext,
        rows: Iterable[MAPIBroadcastCallbackRow]) -> concurrent.futures.Future[None]:
    sql = """
        INSERT INTO MAPIBroadcastCallbacks
        (tx_hash, peer_channel_id, broadcast_date, encrypted_private_key, server_id, status_flags)
        VALUES (?, ?, ?, ?, ?, ?)"""

    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


@replace_db_context_with_connection
def read_mapi_broadcast_callbacks(db: sqlite3.Connection) -> List[MAPIBroadcastCallbackRow]:
    sql = f"""
        SELECT tx_hash, peer_channel_id, broadcast_date, encrypted_private_key, server_id,
            status_flags
        FROM MAPIBroadcastCallbacks
    """
    return [ MAPIBroadcastCallbackRow(*row) for row in db.execute(sql).fetchall() ]


def update_mapi_broadcast_callbacks(db_context: DatabaseContext,
        entries: Iterable[Tuple[MapiBroadcastStatusFlags, bytes]]) \
            -> concurrent.futures.Future[None]:
    sql = "UPDATE MAPIBroadcastCallbacks SET status_flags=? WHERE tx_hash=?"
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, entries)
    return db_context.post_to_thread(_write)


def delete_mapi_broadcast_callbacks(db_context: DatabaseContext, tx_hashes: Iterable[bytes]) \
        -> concurrent.futures.Future[None]:
    sql = "DELETE FROM MAPIBroadcastCallbacks WHERE tx_hash=?"
    def _write(db: sqlite3.Connection) -> None:
        db.executemany(sql, [(tx_hash,) for tx_hash in tx_hashes])
    return db_context.post_to_thread(_write)
