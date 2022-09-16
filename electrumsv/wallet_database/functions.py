"""
Copyright(c) 2021, 2022 Bitcoin Association.
Distributed under the Open BSV software license, see the accompanying file LICENSE

Note on typing
--------------

Write database functions are run in the SQLite writer thread using the helper functions from
the `sqlite_database` package, and because of this have to follow the pattern where the database
is an optional last argument.

    ```
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        ...
    ```

This is not required for reading functions as they should run generally run inline unless they
are long running, in which case they should be handed off to a worker thread.

"""

import concurrent.futures
import json
import os
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore[no-redef]
import time
from typing import Any, cast, Iterable, Optional, Sequence

from electrumsv_database.sqlite import bulk_insert_returning, DatabaseContext, execute_sql_by_id, \
    read_rows_by_id, read_rows_by_ids, replace_db_context_with_connection, update_rows_by_ids

from ..constants import (BlockHeight, DerivationType, DerivationPath, KeyInstanceFlag,
    MAPIBroadcastFlag, NetworkServerFlag, pack_derivation_path, PaymentFlag,
    PeerChannelAccessTokenFlag, PeerChannelMessageFlag, PushDataHashRegistrationFlag, ScriptType,
    ServerPeerChannelFlag, TransactionOutputFlag, TxFlags, unpack_derivation_path, WalletEventFlag)
from ..crypto import pw_decode, pw_encode
from ..i18n import _
from ..logs import logs
from ..types import KeyInstanceDataPrivateKey, MasterKeyDataBIP32, MasterKeyDataElectrumOld, \
    MasterKeyDataMultiSignature, MasterKeyDataTypes, Outpoint, OutputSpend, \
    ServerAccountKey
from ..util import get_posix_timestamp
from .exceptions import (DatabaseUpdateError, KeyInstanceNotFoundError,
    IncompleteProofDataSubmittedError, TransactionAlreadyExistsError, TransactionRemovalError)
from .types import (AccountRow, AccountTransactionRow, AccountTransactionDescriptionRow,
    AccountTransactionOutputSpendableRow, AccountTransactionOutputSpendableRowExtended,
    HistoryListRow, InvoiceAccountRow, InvoiceRow, KeyInstanceFlagRow, KeyInstanceFlagChangeRow,
    KeyInstanceRow, KeyListRow, MasterKeyRow, MAPIBroadcastRow, NetworkServerRow,
    PasswordUpdateResult, PaymentRequestRow, PaymentRequestOutputRow,
    PaymentRequestTransactionHashRow, PaymentRequestUpdateRow, PeerChannelIds, MerkleProofUpdateRow,
    PushDataMatchMetadataRow, PushDataMatchRow, PushDataHashRegistrationRow,
    ServerPeerChannelAccessTokenRow, ServerPeerChannelRow, ServerPeerChannelMessageRow,
    SpendConflictType, SpentOutputRow, TransactionDeltaSumRow, TransactionExistsRow,
    TransactionInputAddRow, TransactionLinkState, TransactionOutputAddRow,
    TransactionOutputSpendableRow, TransactionValueRow, TransactionOutputFullRow,
    TransactionOutputShortRow, TransactionProoflessRow, TxProofData, TransactionProofUpdateRow,
    TransactionRow, MerkleProofRow, WalletBalance, WalletDataRow, WalletEventInsertRow,
    WalletEventRow, DPPMessageRow, ExternalPeerChannelRow)
from .util import flag_clause

logger = logs.get_logger("db-functions")


def create_accounts(db_context: DatabaseContext, entries: Iterable[AccountRow]) \
        -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO Accounts (account_id, default_masterkey_id, default_script_type, "
        "account_name, flags, blockchain_server_id, peer_channel_server_id, date_created, "
        "date_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
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
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
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
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, datas)
    return db_context.post_to_thread(_write)


def create_master_keys(db_context: DatabaseContext, entries: Iterable[MasterKeyRow]) \
        -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    sql = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, flags, date_created, date_updated) "
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, datas)
    return db_context.post_to_thread(_write)


def create_payment_request_write(request_row: PaymentRequestRow,
        request_output_rows: list[PaymentRequestOutputRow], db: sqlite3.Connection | None=None) \
            -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow]]:
    assert db is not None and isinstance(db, sqlite3.Connection)
    request_sql = \
    """
    INSERT INTO PaymentRequests (paymentrequest_id, state, value, date_expires, description,
    server_id, dpp_invoice_id, merchant_reference, encrypted_key_text, date_created,
    date_updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
    """
    cursor = db.execute(request_sql, request_row)
    paymentrequest_id = cast(int | None, cursor.lastrowid)
    assert paymentrequest_id is not None
    # If the caller provided a pre-determined primary key check SQLite preserved it.
    if request_row.paymentrequest_id is not None:
        assert request_row.paymentrequest_id == paymentrequest_id
    request_row = request_row._replace(paymentrequest_id=paymentrequest_id)

    for row_index, request_output_row in enumerate(request_output_rows):
        request_output_rows[row_index] = request_output_row._replace(
            paymentrequest_id=paymentrequest_id)
    request_output_sql = \
    """
    INSERT INTO PaymentRequestOutputs (paymentrequest_id, transaction_index, output_index,
    output_script_type, output_script, pushdata_hash, output_value, keyinstance_id, date_created,
    date_updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
    """
    cursor = db.executemany(request_output_sql, request_output_rows)
    assert cursor.rowcount == len(request_output_rows)
    return request_row, request_output_rows


def create_dpp_messages(entries: list[DPPMessageRow], db: Optional[sqlite3.Connection]=None) \
        -> None:
    assert db is not None
    sql = """
        INSERT INTO DPPMessages (message_id, paymentrequest_id, dpp_invoice_id, correlation_id,
            app_id, client_id, user_id, expiration, body, timestamp, type)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT(message_id) DO NOTHING;
    """
    db.executemany(sql, entries)


def create_transaction_outputs(db_context: DatabaseContext,
        entries: Iterable[TransactionOutputShortRow]) -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO TransactionOutputs (tx_hash, txo_index, value, keyinstance_id, "
        "flags, script_type, script_hash, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    timestamp = get_posix_timestamp()
    db_rows = [ (*t, timestamp, timestamp) for t in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, db_rows)
    return db_context.post_to_thread(_write)


# This is currently only used from unit tests.
def create_account_transactions_UNITTEST(db_context: DatabaseContext,
        rows: list[AccountTransactionRow]) -> concurrent.futures.Future[None]:
    sql = """
        INSERT INTO AccountTransactions
            (account_id, tx_hash, flags, description, date_created, date_updated)
        VALUES (?,?,?,?,?,?)
    """
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        logger.debug("add %d account transactions", len(rows))
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


# This is currently only used from unit tests.
def create_transactions_UNITTEST(db_context: DatabaseContext, rows: list[TransactionRow]) \
        -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO Transactions (tx_hash, tx_data, flags, block_hash, block_height, "
        "block_position, fee_value, description, version, locktime, "
        "date_created, date_updated) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")

    for row in rows:
        assert type(row.tx_hash) is bytes and row.tx_bytes is not None
        assert row.date_created > 0 and row.date_updated > 0

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        logger.debug("add %d transactions", len(rows))
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


@replace_db_context_with_connection
def read_transaction(db: sqlite3.Connection, tx_hash: bytes) -> TransactionRow | None:
    sql = "SELECT tx_hash, tx_data, flags, block_hash, block_height, block_position, fee_value, " \
        "description, version, locktime, date_created, date_updated FROM Transactions " \
        "WHERE tx_hash=?1"
    row = db.execute(sql, (tx_hash,)).fetchone()
    if row is None:
        return None
    return TransactionRow(row[0], row[1], TxFlags(row[2]), row[3], row[4], row[5], row[6], row[7],
        row[8], row[9], row[10], row[11])


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

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def create_wallet_events(db_context: DatabaseContext, entries: list[WalletEventInsertRow]) \
        -> concurrent.futures.Future[list[WalletEventRow]]:
    sql_prefix = "INSERT INTO WalletEvents (event_type, account_id, event_flags, date_created, " \
        "date_updated) VALUES"
    sql_suffix = "RETURNING event_id, event_type, account_id, event_flags, date_created, " \
        "date_updated"
    def _write(db: Optional[sqlite3.Connection]=None) -> list[WalletEventRow]:
        assert db is not None and isinstance(db, sqlite3.Connection)
        return bulk_insert_returning(WalletEventRow, db, sql_prefix, sql_suffix, entries)

    return db_context.post_to_thread(_write)


def delete_invoices(db_context: DatabaseContext, entries: Iterable[tuple[int]]) \
        -> concurrent.futures.Future[None]:
    invoice_ids: list[int] = [row[0] for row in entries]
    sql1 = "DELETE FROM ExternalPeerChannels WHERE invoice_id=?"
    sql2 = "DELETE FROM Invoices WHERE invoice_id=?"
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        delete_external_peer_channels_for_invoice_ids(db, invoice_ids)
        db.executemany(sql1, entries)
        db.executemany(sql2, entries)
    return db_context.post_to_thread(_write)


def delete_external_peer_channels_for_invoice_ids(db: sqlite3.Connection,
        invoice_ids: list[int]) -> None:
    read_sql = "SELECT peer_channel_id FROM ExternalPeerChannels WHERE invoice_id IN ({})"

    row_matches = read_rows_by_id(PeerChannelIds, db, read_sql, [], invoice_ids)
    peer_channel_ids = [(row.peer_channel_id,) for row in row_matches]

    sql1 = "DELETE FROM ExternalPeerChannelMessages WHERE peer_channel_id=?"
    sql2 = "DELETE FROM ExternalPeerChannelAccessTokens WHERE peer_channel_id=?"
    sql3 = "DELETE FROM ExternalPeerChannels WHERE invoice_id=?"

    db.executemany(sql1, peer_channel_ids)
    db.executemany(sql2, peer_channel_ids)
    db.executemany(sql3, peer_channel_ids)


def delete_peer_channels_for_peer_channel_ids(db_context: DatabaseContext,
        peer_channel_ids: list[int]) -> concurrent.futures.Future[None]:
    sql_values = [(peer_channel_id,) for peer_channel_id in peer_channel_ids]
    sql1 = "DELETE FROM ServerPeerChannelMessages WHERE peer_channel_id=?"
    sql2 = "DELETE FROM ServerPeerChannelAccessTokens WHERE peer_channel_id=?"
    sql3 = "DELETE FROM ServerPeerChannels WHERE peer_channel_id=?"

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql1, sql_values)
        db.executemany(sql2, sql_values)
        db.executemany(sql3, sql_values)
    return db_context.post_to_thread(_write)


def delete_payment_request_write(paymentrequest_id: int, db: sqlite3.Connection | None=None) \
        -> dict[int, list[int]]:
    assert db is not None and isinstance(db, sqlite3.Connection)

    request_key_rows = db.execute("SELECT PRO.transaction_index, PRO.output_index, "
        "PRO.keyinstance_id, KI.flags, KI.account_id FROM PaymentRequestOutputs PRO "
        "INNER JOIN KeyInstances KI ON KI.keyinstance_id=PRO.keyinstance_id "
        "WHERE PRO.paymentrequest_id=?", (paymentrequest_id,)).fetchall()
    assert len(request_key_rows) > 0

    date_updated = int(time.time())
    keyinstance_updates: list[tuple[int, int, int]] = []
    account_keyinstance_ids: dict[int, list[int]] = {}
    expected_keyinstance_flags = KeyInstanceFlag.ACTIVE | KeyInstanceFlag.IS_PAYMENT_REQUEST
    for _transaction_index, _output_index, keyinstance_id, flags, account_id in request_key_rows:
        assert flags & expected_keyinstance_flags == expected_keyinstance_flags
        if flags & KeyInstanceFlag.MASK_ACTIVE_REASON == KeyInstanceFlag.IS_PAYMENT_REQUEST:
            # There are no other reasons for the key to be left active, clear both flags.
            keyinstance_updates.append((~expected_keyinstance_flags, date_updated, keyinstance_id))
        else:
            # Just clear the specific payment request flag, it is also active for some other reason.
            keyinstance_updates.append((~KeyInstanceFlag.IS_PAYMENT_REQUEST, date_updated,
                keyinstance_id))
        if account_id not in account_keyinstance_ids:
            account_keyinstance_ids[account_id] = []
        account_keyinstance_ids[account_id].append(keyinstance_id)

    cursor = db.executemany("UPDATE KeyInstances SET flags=flags&?1, date_updated=?2 "
        "WHERE keyinstance_id=?3", keyinstance_updates)
    assert cursor.rowcount == len(keyinstance_updates)

    db.execute("DELETE FROM DPPMessages WHERE paymentrequest_id=?", (paymentrequest_id,))
    db.execute("DELETE FROM PaymentRequestOutputs WHERE paymentrequest_id=?", (paymentrequest_id,))
    db.execute("DELETE FROM PaymentRequests WHERE paymentrequest_id=?", (paymentrequest_id,))

    return account_keyinstance_ids


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
        TxFlags.MASK_STATE_LOCAL,
        account_id, txo_mask, txo_flags ]
    if exclude_frozen:
        sql += " AND KI.flags&?=0"
        sql_values.append(KeyInstanceFlag.FROZEN)
    row = db.execute(sql, sql_values).fetchone()
    if row is None:
        return WalletBalance(0, 0, 0, 0)
    return WalletBalance(*row)


@replace_db_context_with_connection
def read_transaction_block_hashes(db: sqlite3.Connection) -> list[bytes]:
    sql = """SELECT block_hash from Transactions"""
    cursor = db.execute(sql)
    rows = cursor.fetchall()
    block_hashes: list[bytes] = []
    for row in rows:
        block_hash: bytes = row[0]
        if block_hash:
            block_hashes.append(block_hash)
    return block_hashes


@replace_db_context_with_connection
def read_account_transaction_outputs_with_key_data(db: sqlite3.Connection, account_id: int,
        confirmed_only: bool=False, exclude_immature: bool=False, exclude_frozen: bool=False,
        keyinstance_ids: Optional[list[int]]=None) -> list[AccountTransactionOutputSpendableRow]:
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
    sql_values: list[Any] = [ account_id, txo_mask, tx_mask, tx_flags ]
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
        keyinstance_ids: Optional[list[int]]=None) \
            -> list[AccountTransactionOutputSpendableRowExtended]:
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
    sql_values: list[Any] = [ account_id, txo_mask, tx_mask, tx_flags ]
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
def read_accounts(db: sqlite3.Connection) -> list[AccountRow]:
    sql = """
        SELECT account_id, default_masterkey_id, default_script_type, account_name, flags,
            blockchain_server_id, peer_channel_server_id
        FROM Accounts
    """
    return [ AccountRow(*row) for row in db.execute(sql).fetchall() ]


def update_account_server_ids_write(blockchain_server_id: Optional[int],
        peer_channel_server_id: Optional[int], account_id: int,
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
        UPDATE Accounts
        SET blockchain_server_id=?, peer_channel_server_id=?
        WHERE account_id=?
    """
    cursor = db.execute(sql, (blockchain_server_id, peer_channel_server_id, account_id))
    assert cursor.rowcount == 1


@replace_db_context_with_connection
def read_account_ids_for_transaction(db: sqlite3.Connection, tx_hash: bytes) -> list[int]:
    sql = "SELECT account_id FROM AccountTransactions WHERE tx_hash=?"
    sql_values = (tx_hash,)
    return [ row[0] for row in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_history_list(db: sqlite3.Connection, account_id: int,
        keyinstance_ids: Optional[Sequence[int]]=None) -> list[HistoryListRow]:
    if keyinstance_ids:
        # Used for the address dialog.
        sql = ("SELECT TXV.tx_hash, TX.flags, TX.block_hash, TX.block_height, TX.block_position, "
                "ATX.description, TOTAL(TXV.value), TX.date_created "
            "FROM TransactionValues TXV "
            "INNER JOIN Transactions AS TX ON TX.tx_hash=TXV.tx_hash "
            "INNER JOIN AccountTransactions AS ATX ON ATX.tx_hash=TXV.tx_hash "
            "WHERE TXV.account_id=? AND (TX.flags&?)!=0 AND TXV.keyinstance_id IN ({}) "
            "GROUP BY TXV.tx_hash")
        return read_rows_by_id(HistoryListRow, db, sql, [ account_id, TxFlags.MASK_STATE ],
            keyinstance_ids)

    # Used for the history list and export.
    sql = ("SELECT TXV.tx_hash, TX.flags, TX.block_hash, TX.block_height, TX.block_position,"
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
    sql_values: list[Any]
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
        mask: Optional[int]=None) -> list[InvoiceAccountRow]:
    sql = ("SELECT invoice_id, payment_uri, description, invoice_flags, value, "
        "date_expires, date_created FROM Invoices WHERE account_id=?")
    sql_values: list[Any] = [ account_id ]
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
def read_proofless_transactions(db: sqlite3.Connection) -> list[TransactionProoflessRow]:
    """
    Identify transactions that we need proofs for.

    These will be:
    - Transactions that predate storage of the proof, whether from Electron Cash or Electrum
      Core, or perhaps ElectrumSV before it stored these.
    - Transactions that we have received output spend notifications indicating they are mined.

    The range of transactions are those that:
    - Have the `STATE_SETTLED` flag and no block hash (pre-date proof storage).
    - Have the `STATE_CLEARED` flag and a block hash (notified local transaction was mined).
    """
    # TODO: This action is billed against a petty cash account on behalf of the account that
    # requires the proof. However, it is possible that a transaction may in the longer term be
    # linked to multiple accounts, which complicates things. For now we take the simplest approach
    # and bill it to the first account that it was linked to. This is not ideal, but in reality
    # it is unlikely many users will care about the nuances and we can change the behaviour later.
    sql_values: list[Any] = [
        TxFlags.MASK_STATE, TxFlags.STATE_SETTLED,
        TxFlags.MASK_STATE, TxFlags.STATE_CLEARED
    ]
    sql = """
    WITH matches AS (
        SELECT TX.tx_hash, ATX.account_id,
            row_number() OVER (PARTITION BY TX.tx_hash ORDER BY ATX.date_created) as rank
        FROM Transactions TX
        LEFT JOIN AccountTransactions ATX ON ATX.tx_hash=TX.tx_hash
        WHERE TX.flags&?=? AND TX.block_hash IS NULL
           OR TX.flags&?=? AND TX.block_hash IS NOT NULL
    )
    SELECT tx_hash, account_id FROM matches WHERE account_id IS NOT NULL AND rank=1
    """
    rows = db.execute(sql, sql_values).fetchall()
    return [ TransactionProoflessRow(*row) for row in rows ]


@replace_db_context_with_connection
def read_spent_outputs_to_monitor(db: sqlite3.Connection) -> list[OutputSpend]:
    """
    Retrieve all the outpoints we need to monitor (and why) via the 'output-spend' API. Remember
    that the goal is to detect either the appearance of these in the mempool or a block.

    We intentionally do not monitor output spends for MAPI broadcasts.
    """
    sql = f"""
    SELECT TXI.spent_tx_hash, TXI.spent_txo_index, TXI.tx_hash, TXI.txi_index, TX.block_hash
    FROM TransactionInputs TXI
    INNER JOIN Transactions TX ON TX.tx_hash=TXI.tx_hash AND TX.flags&{TxFlags.MASK_STATE}!=0 AND
        TX.flags&{TxFlags.STATE_SETTLED}=0
    LEFT JOIN MAPIBroadcasts MBC ON MBC.tx_hash=TXI.tx_hash
        AND MBC.mapi_broadcast_flags&{MAPIBroadcastFlag.BROADCAST|MAPIBroadcastFlag.DELETED}
            ={MAPIBroadcastFlag.BROADCAST}
    WHERE MBC.tx_hash IS NULL
    """
    rows = db.execute(sql).fetchall()
    return [ OutputSpend(*row) for row in rows ]


@replace_db_context_with_connection
def read_existing_output_spends(db: sqlite3.Connection, outpoints: list[Outpoint]) \
        -> list[SpentOutputRow]:
    """
    Get metadata for any existing spends of the provided outpoints.
    """
    sql = f"""
    SELECT TXI.spent_tx_hash, TXI.spent_txo_index, TXI.tx_hash, TXI.txi_index, TX.block_hash,
        TX.flags, MBC.mapi_broadcast_flags
    FROM TransactionInputs TXI
    INNER JOIN Transactions TX ON TX.tx_hash=TXI.tx_hash
    LEFT JOIN MAPIBroadcasts MBC ON MBC.tx_hash=TXI.tx_hash
        AND MBC.mapi_broadcast_flags&{MAPIBroadcastFlag.BROADCAST|MAPIBroadcastFlag.DELETED}
            ={MAPIBroadcastFlag.BROADCAST}
    """
    sql_condition = "TXI.spent_tx_hash=? AND TXI.spent_txo_index=?"
    return read_rows_by_ids(SpentOutputRow, db, sql, sql_condition, [], outpoints)


@replace_db_context_with_connection
def UNITTEST_read_transaction_proof_data(db: sqlite3.Connection, tx_hashes: Sequence[bytes]) \
        -> list[TxProofData]:
    sql = """
        SELECT TX.tx_hash, TX.flags, TX.block_hash, TXP.proof_data, TX.block_height,
            TX.block_position, TXP.block_height, TXP.block_position
        FROM Transactions TX
        INNER JOIN TransactionProofs TXP ON TXP.tx_hash=TX.tx_hash AND TXP.block_hash=TX.block_hash
        WHERE TX.tx_hash IN ({})
    """
    sql_values = ()
    return read_rows_by_id(TxProofData, db, sql, sql_values, tx_hashes)


@replace_db_context_with_connection
def read_key_list(db: sqlite3.Connection, account_id: int,
        keyinstance_ids: Optional[Sequence[int]]=None) -> list[KeyListRow]:
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
def read_keyinstance(db: sqlite3.Connection, *, account_id: Optional[int]=None,
        keyinstance_id: Optional[int]=None) -> Optional[KeyInstanceRow]:
    """
    Read one explicitly requested keyinstance.
    """
    sql_values: list[Any] = [ keyinstance_id ]
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
def read_keyinstances(db: sqlite3.Connection, *, account_id: int | None=None,
        keyinstance_ids: Sequence[int] | None=None, flags: KeyInstanceFlag | None=None,
        mask: KeyInstanceFlag | None=None) -> list[KeyInstanceRow]:
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
        -> list[tuple[int, bytes, bytes]]:
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
    return cast(list[tuple[int, bytes, bytes]], db.execute(sql, sql_values).fetchall())


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
        derivation_type: DerivationType, derivation_data2s: list[bytes],
        masterkey_id: Optional[int]=None) -> list[KeyInstanceRow]:
    """
    Locate the keyinstance with the given `derivation_data2` field.
    """
    sql = ("SELECT KI.keyinstance_id, KI.account_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.derivation_data2, KI.flags, KI.description "
        "FROM KeyInstances AS KI "
        "WHERE account_id=? AND derivation_type=?")
    sql_values: list[Any] = [ account_id, derivation_type ]
    if masterkey_id is not None:
        sql += " AND masterkey_id=?"
        sql_values.append(masterkey_id)
    else:
        sql += " AND masterkey_id IS NULL"
    # This needs to be last as the batch read message appends the "id" values after the sql values.
    sql += " AND derivation_data2 IN ({})"
    return read_rows_by_id(KeyInstanceRow, db, sql, sql_values, derivation_data2s)


@replace_db_context_with_connection
def read_masterkeys(db: sqlite3.Connection) -> list[MasterKeyRow]:
    sql = (
        "SELECT masterkey_id, parent_masterkey_id, derivation_type, derivation_data, flags "
        "FROM MasterKeys")
    return [ MasterKeyRow(*row) for row in db.execute(sql).fetchall() ]


@replace_db_context_with_connection
def read_parent_transaction_outputs_with_key_data(db: sqlite3.Connection, tx_hash: bytes) \
        -> list[TransactionOutputSpendableRow]:
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


def read_payment_request_transactions_hashes(paymentrequest_ids: list[int],
        db: sqlite3.Connection | None=None) -> dict[int, list[bytes]]:
    sql = """
    SELECT DISTINCT PR.paymentrequest_id, TXO.tx_hash
    FROM PaymentRequests PR
    INNER JOIN PaymentRequestOutputs PRO ON PR.paymentrequest_id=PRO.paymentrequest_id
    LEFT JOIN TransactionOutputs TXO ON PRO.keyinstance_id=TXO.keyinstance_id
    WHERE PR.paymentrequest_id IN ({}) AND TXO.tx_hash IS NOT NULL
    """

    transaction_hashes_by_paymentrequest_id: dict[int, list[bytes]] = {}
    for row in read_rows_by_id(PaymentRequestTransactionHashRow, db, sql, (), paymentrequest_ids):
        if row[0] not in transaction_hashes_by_paymentrequest_id:
            transaction_hashes_by_paymentrequest_id[row[0]] = []
        transaction_hashes_by_paymentrequest_id[row[0]].append(row[1])
    return transaction_hashes_by_paymentrequest_id


@replace_db_context_with_connection
def read_payment_request(db: sqlite3.Connection, request_id: int) \
        -> tuple[PaymentRequestRow | None, list[PaymentRequestOutputRow]]:
    request_sql = """
        SELECT PR.paymentrequest_id, PR.state, PR.value, PR.date_expires, PR.description,
            PR.server_id, PR.dpp_invoice_id, PR.merchant_reference, PR.encrypted_key_text,
            PR.date_created, PR.date_updated
        FROM PaymentRequests PR
        WHERE PR.paymentrequest_id=?
    """
    t = db.execute(request_sql, (request_id,)).fetchone()
    if t is None:
        return None, []
    request_row = PaymentRequestRow(t[0], PaymentFlag(t[1]), t[2], t[3], t[4], t[5], t[6], t[7],
        t[8], t[9], t[10])

    request_outputs_sql = """
        SELECT paymentrequest_id, transaction_index, output_index, output_script_type,
            output_script, pushdata_hash, output_value, keyinstance_id, date_created,
            date_updated FROM PaymentRequestOutputs WHERE paymentrequest_id=?
    """
    request_output_rows: list[PaymentRequestOutputRow] = []
    for t in db.execute(request_outputs_sql, (request_id,)).fetchall():
        request_output_rows.append(PaymentRequestOutputRow(*t))
    return request_row, request_output_rows

@replace_db_context_with_connection
def read_payment_requests(db: sqlite3.Connection, *, account_id: int | None=None,
        flags: PaymentFlag | None=None, mask: PaymentFlag | None=None,
        server_id: int | None=None) -> list[PaymentRequestRow]:
    sql = "SELECT PR.paymentrequest_id, PR.state, PR.value, PR.date_expires, PR.description, " \
        "PR.server_id, PR.dpp_invoice_id, PR.merchant_reference, PR.encrypted_key_text, " \
        "PR.date_created, PR.date_updated FROM PaymentRequests PR"
    sql_values: list[Any] = []
    used_where = False
    if account_id is not None:
        sql += " WHERE PR.paymentrequest_id IN " \
            "(SELECT DISTINCT PRO.paymentrequest_id FROM PaymentRequestOutputs PRO " \
            "INNER JOIN KeyInstances KI ON PRO.keyinstance_id=KI.keyinstance_id AND " \
                "KI.account_id=?)"
        sql_values.append(account_id)
        used_where = True
    clause, extra_values = flag_clause("PR.state", flags, mask)
    if clause:
        if used_where:
            sql += f" AND {clause}"
        else:
            sql += f" WHERE {clause}"
        sql_values.extend(extra_values)
        used_where = True
    if server_id is not None:
        if used_where:
            sql += " AND server_id=?"
        else:
            sql += " WHERE server_id=?"
            used_where = True
        sql_values.append(server_id)
    return [ PaymentRequestRow(t[0], PaymentFlag(t[1]), t[2], t[3], t[4], t[5], t[6], t[7],
        t[8], t[9], t[10]) for t in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_payment_request_outputs(db: sqlite3.Connection, paymentrequest_ids: list[int]) \
        -> list[PaymentRequestOutputRow]:
    sql = """
        SELECT paymentrequest_id, transaction_index, output_index, output_script_type,
            output_script, pushdata_hash, output_value, keyinstance_id, date_created,
            date_updated
        FROM PaymentRequestOutputs
        WHERE paymentrequest_id IN ({})
    """
    return read_rows_by_id(PaymentRequestOutputRow, db, sql, (), paymentrequest_ids)


def create_pushdata_matches_write(rows: list[PushDataMatchRow], processed_message_ids: list[int],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
    INSERT INTO ServerPushDataMatches (server_id, pushdata_hash, transaction_hash,
        transaction_index, block_hash, match_flags, date_created)
    VALUES (?,?,?,?,?,?,?)
    """
    db.executemany(sql, rows)

    if len(processed_message_ids) > 0:
        update_server_peer_channel_message_flags_write(processed_message_ids, db)


@replace_db_context_with_connection
def read_pushdata_match_metadata(db: sqlite3.Connection, for_missing_transactions: bool) \
        -> list[PushDataMatchMetadataRow]:
    # TODO(1.4.0) Tip filters, issue#904. There should be some flag which filters out processed
    #     entries and the tx import should toggle that flag accordingly.
    sql = ("SELECT KI.account_id, SPDR.pushdata_hash, SPDR.keyinstance_id, SPDR.script_type, "
        "SPDM.transaction_hash, SPDM.block_hash FROM ServerPushDataRegistrations SPDR "
        "INNER JOIN KeyInstances KI ON KI.keyinstance_id=SPDR.keyinstance_id "
        "INNER JOIN ServerPushDataMatches SPDM ON SPDM.pushdata_hash = SPDR.pushdata_hash")
    if for_missing_transactions:
        sql += (" LEFT JOIN Transactions TX ON TX.tx_hash=SPDM.transaction_hash "
            f"AND TX.flags!={TxFlags.REMOVED} "
            "WHERE TX.tx_hash IS NULL")
    sql_values: tuple[Any, ...] = ()
    return [ PushDataMatchMetadataRow(row[0], row[1], row[2], ScriptType(row[3]), row[4],
        row[5]) for row in db.execute(sql, sql_values) ]


def create_tip_filter_pushdata_registrations_write(rows: list[PushDataHashRegistrationRow],
        upsert: bool, db: sqlite3.Connection | None=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    assert len(rows) > 0
    assert len(rows[0]) == 8
    assert rows[0].date_created > 0
    assert rows[0].date_created == rows[0].date_updated
    assert rows[0].duration_seconds > 5 * 60
    sql = ("INSERT INTO ServerPushDataRegistrations (server_id, keyinstance_id, script_type, "
        "pushdata_hash, pushdata_flags, duration_seconds, date_registered, date_created, "
        "date_updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")
    if upsert:
        sql += """
        ON CONFLICT (server_id, pushdata_hash) DO UPDATE SET
            pushdata_hash=excluded.pushdata_hash, pushdata_flags=excluded.pushdata_flags,
            duration_seconds=excluded.duration_seconds, date_registered=excluded.date_registered,
            date_updated=excluded.date_updated
        WHERE excluded.server_id=ServerPushDataRegistrations.server_id AND
              excluded.pushdata_hash=ServerPushDataRegistrations.pushdata_hash
        """
    db.executemany(sql, rows)


def delete_registered_tip_filter_pushdatas_write(rows: list[tuple[int, int]],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "DELETE FROM ServerPushDataRegistrations WHERE server_id=? AND keyinstance_id=?"
    db.executemany(sql, rows)


@replace_db_context_with_connection
def read_tip_filter_pushdata_registrations(db: sqlite3.Connection, server_id: int,
        expiry_timestamp: Optional[int]=None, flags: Optional[PushDataHashRegistrationFlag]=None,
        mask: Optional[PushDataHashRegistrationFlag]=None) -> list[PushDataHashRegistrationRow]:
    """
    We have registered pushdata hashes with an indexing service to watch for occurences of
    them in new transactions observed either in the mempool or new blocks. These will always
    have a duration `duration_seconds` observed from a start time `date_created`, which were
    both provided to the indexing service.
    """
    sql = ("SELECT server_id, keyinstance_id, script_type, pushdata_hash, pushdata_flags, "
            "duration_seconds, date_registered, date_created, date_updated "
        "FROM ServerPushDataRegistrations "
        "WHERE server_id=?")
    sql_values: list[Any] = [ server_id ]
    clause, extra_values = flag_clause("pushdata_flags", flags, mask)
    if clause:
        sql += f" AND {clause}"
        sql_values.extend(extra_values)
    if expiry_timestamp is not None:
        # It really does not matter if we do `>` or `>=` here the caller still needs to check.
        sql += " AND date_created + duration_seconds >= ?"
        sql_values.append(expiry_timestamp)
    return [ PushDataHashRegistrationRow(*row) for row in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_unregistered_tip_filter_pushdatas(db: sqlite3.Connection) -> list[tuple[bytes, int, int]]:
    """
    We have given out an output script or address for some other party to pay to, and we need
    to watch for usage of it on the blockchain in order to identify which transaction it is used
    in. This function identifies those we have given out, but do not have a record they are
    monitored.

    There are two use cases for this:
    1. The user has forced a key to be flagged as active.
    2. The user has created a payment request and given out an address or output script to another
       party for them to pay to.

    We are going to ignore the first case with key forced to active. That can be deferred, the main
    case we want to support is the second one, where there is a payment request.
    """
    # TODO(forced-active-keys) We have deferred keys that have been forced active, and need to
    #     disallow that for now. It is not likely we will ever support it.
    # TODO(petty-cash) This should likely limit results to a given petty cash account
    sql = """
        SELECT PR.pushdata_hash, PR.date_expires, PR.keyinstance_id
        FROM PaymentRequests PR
        INNER JOIN KeyInstances KI ON KI.keyinstance_id=PR.keyinstance_id
        LEFT JOIN ServerPushDataRegistrations PDR ON KI.keyinstance_id=PDR.keyinstance_id
        WHERE PDR.keyinstance_id IS NULL AND KI.flags&?=?
    """
    sql_values = (KeyInstanceFlag.ACTIVE, KeyInstanceFlag.ACTIVE)
    return [ cast(tuple[bytes, int, int], row) for row in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_registered_tip_filter_pushdata_for_request(db: sqlite3.Connection, request_id: int) \
        -> Optional[PushDataHashRegistrationRow]:
    sql = ("SELECT PDR.server_id, PDR.keyinstance_id, PDR.script_type, PDR.pushdata_hash, "
            "PDR.pushdata_flags, PDR.duration_seconds, PDR.date_registered, PDR.date_created, "
            "PDR.date_updated "
        "FROM PaymentRequests PR "
        "INNER JOIN KeyInstances KI ON KI.keyinstance_id=PR.keyinstance_id "
        "LEFT JOIN ServerPushDataRegistrations PDR ON KI.keyinstance_id=PDR.keyinstance_id "
        "WHERE PR.paymentrequest_id=?")
    row = db.execute(sql, (request_id,)).fetchone()
    assert row is not None
    if row[0] is None:
        return None
    return PushDataHashRegistrationRow(*row)


def update_registered_tip_filter_pushdatas_write(rows: list[tuple[int, int, int, int, int, int]],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "UPDATE ServerPushDataRegistrations SET date_registered=?, date_updated=?, " \
        "pushdata_flags=(pushdata_flags&?)|? WHERE server_id=? AND keyinstance_id=?"
    db.executemany(sql, rows)


def update_registered_tip_filter_pushdatas_flags_write(rows: list[tuple[int, int, int, int]],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "UPDATE ServerPushDataRegistrations SET pushdata_flags=?, date_updated=? " \
        "WHERE server_id=? AND keyinstance_id=?"
    db.executemany(sql, rows)


@replace_db_context_with_connection
def read_transaction_bytes(db: sqlite3.Connection, tx_hash: bytes) -> Optional[bytes]:
    cursor = db.execute("SELECT tx_data FROM Transactions WHERE tx_hash=?", (tx_hash,))
    row = cursor.fetchone()
    if row is not None:
        return cast(bytes, row[0])
    return None


@replace_db_context_with_connection
def read_transaction_descriptions(db: sqlite3.Connection, account_id: Optional[int]=None,
        tx_hashes: Optional[Sequence[bytes]]=None) -> list[AccountTransactionDescriptionRow]:
    sql = (
        "SELECT account_id, tx_hash, description "
        "FROM AccountTransactions "
        "WHERE description IS NOT NULL")
    sql_values: list[Any] = []
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
        account_id: Optional[int]=None) -> list[TransactionExistsRow]:
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
def read_transaction_hashes(db: sqlite3.Connection, account_id: Optional[int]=None) -> list[bytes]:
    if account_id is None:
        sql = "SELECT tx_hash FROM Transactions"
        cursor = db.execute(sql)
    else:
        sql = "SELECT tx_hash FROM AccountTransactions WHERE account_id=?"
        cursor = db.execute(sql, (account_id,))
    return [ tx_hash for (tx_hash,) in cursor.fetchall() ]


@replace_db_context_with_connection
def read_transaction_outputs_explicit(db: sqlite3.Connection, output_ids: list[Outpoint]) \
        -> list[TransactionOutputShortRow]:
    """
    Read all the transaction outputs for the given outpoints if they exist.
    """
    sql = (
        "SELECT tx_hash, txo_index, value, keyinstance_id, flags, script_type, script_hash "
        "FROM TransactionOutputs")
    sql_condition = "tx_hash=? AND txo_index=?"
    return read_rows_by_ids(TransactionOutputShortRow, db, sql, sql_condition, [], output_ids)


@replace_db_context_with_connection
def read_transaction_inputs_full(db: sqlite3.Connection) -> list[TransactionInputAddRow]:
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
        output_ids: Optional[list[Outpoint]]=None) -> list[TransactionOutputFullRow]:
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
        txo_keys: Optional[list[Outpoint]]=None,
        derivation_data2s: Optional[list[bytes]]=None,
        require_keys: bool=False) -> list[TransactionOutputSpendableRow]:
    """
    Read all the transaction outputs with spend information for the given outpoints if they exist.
    """
    sql_values: list[Any] = []
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
def read_transaction_value_entries(db: sqlite3.Connection, account_id: int, *,
        tx_hashes: Optional[list[bytes]]=None, mask: Optional[TxFlags]=None) \
            -> list[TransactionValueRow]:
    if tx_hashes is None:
        sql = ("SELECT TXV.tx_hash, TOTAL(TXV.value), TX.flags, TX.block_hash, "
                "TX.date_created, TX.date_updated "
            "FROM TransactionValues TXV "
            "INNER JOIN Transactions TX ON TX.tx_hash=TXV.tx_hash "
            "WHERE account_id=? ")
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
        account_id: Optional[int]=None) -> list[TransactionDeltaSumRow]:
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
        derivation_path: DerivationPath, limit: int) -> list[KeyInstanceRow]:
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
        server_key: Optional[ServerAccountKey]=None) -> list[NetworkServerRow]:
    read_server_row_sql = "SELECT server_id, server_type, url, account_id, server_flags, " \
        "api_key_template, encrypted_api_key, payment_key_bytes, fee_quote_json, " \
        "tip_filter_peer_channel_id, date_last_tried, date_last_connected, date_created, " \
        "date_updated FROM Servers"
    params: Sequence[Any] = ()
    if server_key is not None:
        read_server_row_sql += " WHERE server_type=? AND url=?"
        params = (server_key.server_type, server_key.url)
    cursor = db.execute(read_server_row_sql, params)
    # WARNING The order of the fields in this data structure are implicitly linked to the query.
    return [ NetworkServerRow(*r) for r in cursor.fetchall() ]


def create_server_peer_channel_write(row: ServerPeerChannelRow,
        tip_filter_server_id: Optional[int]=None,
        db: Optional[sqlite3.Connection]=None) -> int:
    assert db is not None and isinstance(db, sqlite3.Connection)
    flags = row.peer_channel_flags
    # Ensure the inserted record gets an automatically allocated primary key.
    assert row.peer_channel_id is None
    # Ensure the remote id is only non-`None` outside of allocation operations.
    assert row.remote_channel_id is None or flags & ServerPeerChannelFlag.ALLOCATING == 0
    # Ensure the remote id is only `None` in an allocation operation.
    assert row.remote_channel_id is not None or flags & ServerPeerChannelFlag.ALLOCATING != 0

    sql = """
        INSERT INTO ServerPeerChannels (peer_channel_id, server_id, remote_channel_id,
            remote_url, peer_channel_flags, date_created, date_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING peer_channel_id
    """
    insert_result_1 = db.execute(sql, row).fetchone()
    if insert_result_1 is None:
        raise DatabaseUpdateError(f"Failed creating new server peer channel {row}")

    # TODO(1.4.0) Tip filters, issue#904. Can we get delete the `tip_filter_peer_channel_id` field?
    #     We should just be able to do a preread based on the flags and enforce it.
    peer_channel_id = cast(int, insert_result_1[0])
    if row.peer_channel_flags & ServerPeerChannelFlag.TIP_FILTER_DELIVERY:
        assert tip_filter_server_id is not None
        sql = """
            UPDATE Servers
            SET tip_filter_peer_channel_id=?
            WHERE server_id=? AND tip_filter_peer_channel_id IS NULL
        """
        cursor = db.execute(sql, (peer_channel_id, tip_filter_server_id))
        if cursor.rowcount != 1:
            raise DatabaseUpdateError(f"Server {tip_filter_server_id} already has tip filter "
                "peer channel")

    return peer_channel_id


def create_external_peer_channel_write(row: ExternalPeerChannelRow,
        db: Optional[sqlite3.Connection]=None) -> int:
    assert db is not None and isinstance(db, sqlite3.Connection)
    flags = row.peer_channel_flags
    # Ensure the inserted record gets an automatically allocated primary key.
    assert row.peer_channel_id is None
    # Ensure the remote id is only non-`None` outside of allocation operations.
    assert row.remote_channel_id is None or flags & ServerPeerChannelFlag.ALLOCATING == 0
    # Ensure the remote id is only `None` in an allocation operation.
    assert row.remote_channel_id is not None or flags & ServerPeerChannelFlag.ALLOCATING != 0

    sql = """
        INSERT INTO ExternalPeerChannels (peer_channel_id, invoice_id, remote_channel_id,
            remote_url, peer_channel_flags, date_created, date_updated)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING peer_channel_id
    """
    insert_result_1 = db.execute(sql, row).fetchone()
    if insert_result_1 is None:
        raise DatabaseUpdateError(f"Failed creating new server peer channel {row}")
    peer_channel_id = cast(int, insert_result_1[0])
    return peer_channel_id


@replace_db_context_with_connection
def read_server_peer_channels(db: sqlite3.Connection, server_id: int | None=None,
        peer_channel_id: int | None=None) -> list[ServerPeerChannelRow]:
    sql = """
        SELECT peer_channel_id, server_id, remote_channel_id, remote_url, peer_channel_flags,
            date_created, date_updated
        FROM ServerPeerChannels
        """
    sql_values = []
    where_clause = False
    if server_id is not None:
        sql += "WHERE server_id=? "
        sql_values.append(server_id)
        where_clause = True

    if peer_channel_id is not None:
        if where_clause:
            sql += "AND peer_channel_id=?"
            sql_values.append(peer_channel_id)
        else:
            sql += "WHERE peer_channel_id=? "
            sql_values.append(peer_channel_id)
            where_clause = True

    cursor = db.execute(sql, sql_values)
    return [ ServerPeerChannelRow(row[0], row[1], row[2], row[3], ServerPeerChannelFlag(row[4]),
        row[5], row[6]) for row in cursor.fetchall() ]


@replace_db_context_with_connection
def read_external_peer_channels(db: sqlite3.Connection, remote_channel_id: str | None=None,
        peer_channel_flags: ServerPeerChannelFlag | None = None,
        mask: ServerPeerChannelFlag | None = None) -> list[ExternalPeerChannelRow]:
    sql = """
        SELECT peer_channel_id, invoice_id, remote_channel_id, remote_url, peer_channel_flags,
            date_created, date_updated
        FROM ExternalPeerChannels
        """
    sql_values: list[Any] = []
    where_clause = False
    if remote_channel_id is not None:
        sql += "WHERE remote_channel_id=? "
        sql_values.append(remote_channel_id)
        where_clause = True

    clause, extra_values = flag_clause("peer_channel_flags", peer_channel_flags, mask)
    if clause:
        if where_clause:
            sql += f"AND {clause}"
        else:
            sql += f"WHERE {clause} "
            where_clause = True
        sql_values.extend(extra_values)

    cursor = db.execute(sql, sql_values)
    return [ ExternalPeerChannelRow(row[0], row[1], row[2], row[3], ServerPeerChannelFlag(row[4]),
        row[5], row[6]) for row in cursor.fetchall() ]


def update_server_peer_channel_write(remote_channel_id: Optional[str],
        remote_url: Optional[str], peer_channel_flags: ServerPeerChannelFlag,
        peer_channel_id: int, addable_access_tokens: list[ServerPeerChannelAccessTokenRow],
        db: Optional[sqlite3.Connection]=None) -> ServerPeerChannelRow:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
        UPDATE ServerPeerChannels
        SET remote_channel_id=?, remote_url=?, peer_channel_flags=?
        WHERE peer_channel_id=?
        RETURNING peer_channel_id, server_id, remote_channel_id, remote_url, peer_channel_flags,
            date_created, date_updated
    """
    cursor = db.execute(sql, (remote_channel_id, remote_url, peer_channel_flags,
        peer_channel_id))
    assert cursor.rowcount == 1
    row = cursor.fetchone()
    result_row = ServerPeerChannelRow(row[0], row[1], row[2], row[3], ServerPeerChannelFlag(row[4]),
            row[5], row[6])

    if len(addable_access_tokens) > 0:
        sql = "INSERT INTO ServerPeerChannelAccessTokens (peer_channel_id, " \
            "token_flags, permission_flags, access_token) VALUES (?,?,?,?)"
        cursor = db.executemany(sql, addable_access_tokens)
        assert cursor.rowcount == len(addable_access_tokens)

    return result_row



def update_external_peer_channel_write(remote_channel_id: Optional[str],
        remote_url: Optional[str], peer_channel_flags: ServerPeerChannelFlag,
        peer_channel_id: int, addable_access_tokens: list[ServerPeerChannelAccessTokenRow],
        db: Optional[sqlite3.Connection]=None) -> ExternalPeerChannelRow:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = """
        UPDATE ExternalPeerChannels
        SET remote_channel_id=?, remote_url=?, peer_channel_flags=?
        WHERE peer_channel_id=?
        RETURNING peer_channel_id, invoice_id, remote_channel_id, remote_url, peer_channel_flags,
            date_created, date_updated
    """
    cursor = db.execute(sql, (remote_channel_id, remote_url, peer_channel_flags,
        peer_channel_id))
    assert cursor.rowcount == 1
    row = cursor.fetchone()
    result_row = ExternalPeerChannelRow(row[0], row[1], row[2], row[3],
        ServerPeerChannelFlag(row[4]), row[5], row[6])

    if len(addable_access_tokens) > 0:
        sql = "INSERT INTO ExternalPeerChannelAccessTokens (peer_channel_id, " \
            "token_flags, permission_flags, access_token) VALUES (?,?,?,?)"
        cursor = db.executemany(sql, addable_access_tokens)
        assert cursor.rowcount == len(addable_access_tokens)

    return result_row



def update_server_peer_channel_message_flags_write(processed_message_ids: list[int],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "UPDATE ServerPeerChannelMessages SET message_flags=message_flags&? " \
        "WHERE message_id IN ({})"
    sql_values = [ ~PeerChannelMessageFlag.UNPROCESSED ]
    execute_sql_by_id(db, sql, sql_values, processed_message_ids)


@replace_db_context_with_connection
def read_server_peer_channel_access_tokens(db: sqlite3.Connection, peer_channel_id: int,
        mask: Optional[PeerChannelAccessTokenFlag], flags: Optional[PeerChannelAccessTokenFlag]) \
            -> list[ServerPeerChannelAccessTokenRow]:
    sql = "SELECT peer_channel_id, token_flags, permission_flags, access_token " \
        "FROM ServerPeerChannelAccessTokens WHERE peer_channel_id=?"
    sql_values: list[Any] = [peer_channel_id]
    clause, extra_values = flag_clause("token_flags", flags, mask)
    if clause:
        sql += " AND "+ clause
        sql_values.extend(extra_values)

    return [ ServerPeerChannelAccessTokenRow(*row)
        for row in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_external_peer_channel_access_tokens(db: sqlite3.Connection, peer_channel_id: int,
        mask: Optional[PeerChannelAccessTokenFlag], flags: Optional[PeerChannelAccessTokenFlag]) \
            -> list[ServerPeerChannelAccessTokenRow]:
    sql = "SELECT peer_channel_id, token_flags, permission_flags, access_token " \
        "FROM ExternalPeerChannelAccessTokens WHERE peer_channel_id=?"
    sql_values: list[Any] = [peer_channel_id]
    clause, extra_values = flag_clause("token_flags", flags, mask)
    if clause:
        sql += " AND "+ clause
        sql_values.extend(extra_values)

    return [ ServerPeerChannelAccessTokenRow(*row)
        for row in db.execute(sql, sql_values).fetchall() ]


def create_server_peer_channel_messages_write(create_rows: list[ServerPeerChannelMessageRow],
        db: Optional[sqlite3.Connection]=None) -> list[ServerPeerChannelMessageRow]:
    assert db is not None

    insert_prefix_sql = """
        INSERT INTO ServerPeerChannelMessages (message_id, peer_channel_id, message_data,
            message_flags, sequence, date_received, date_created, date_updated)
        VALUES
    """
    insert_suffix_sql = """
        RETURNING message_id, peer_channel_id, message_data, message_flags, sequence,
            date_received, date_created, date_updated
    """
    # Remember we cannot just return the `message_id` and substitute it into the source row
    # because SQLite cannot guarantee the row order matches the returned assigned id order.
    return bulk_insert_returning(ServerPeerChannelMessageRow, db, insert_prefix_sql,
        insert_suffix_sql, create_rows)


def create_external_peer_channel_messages_write(create_rows: list[ServerPeerChannelMessageRow],
        db: Optional[sqlite3.Connection]=None) -> list[ServerPeerChannelMessageRow]:
    assert db is not None

    insert_prefix_sql = """
        INSERT INTO ExternalPeerChannelMessages (message_id, peer_channel_id, message_data,
            message_flags, sequence, date_received, date_created, date_updated)
        VALUES
    """
    insert_suffix_sql = """
        RETURNING message_id, peer_channel_id, message_data, message_flags, sequence,
            date_received, date_created, date_updated
    """
    # Remember we cannot just return the `message_id` and substitute it into the source row
    # because SQLite cannot guarantee the row order matches the returned assigned id order.
    return bulk_insert_returning(ServerPeerChannelMessageRow, db, insert_prefix_sql,
        insert_suffix_sql, create_rows)


@replace_db_context_with_connection
def read_server_peer_channel_messages(db: sqlite3.Connection,
        message_flags: Optional[PeerChannelMessageFlag],
        message_mask: Optional[PeerChannelMessageFlag],
        channel_flags: Optional[ServerPeerChannelFlag],
        channel_mask: Optional[ServerPeerChannelFlag]) -> list[ServerPeerChannelMessageRow]:
    sql = """
        SELECT SPCM.message_id, SPCM.peer_channel_id, SPCM.message_data, SPCM.message_flags,
            SPCM.sequence, SPCM.date_received, SPCM.date_created, SPCM.date_updated
        FROM ServerPeerChannelMessages AS SPCM
        INNER JOIN ServerPeerChannels AS SPC ON SPC.peer_channel_id=SPCM.peer_channel_id
    """
    sql_values = list[Any]()
    clause, extra_values1 = flag_clause("SPCM.message_flags", message_flags, message_mask)
    if clause:
        sql += f" AND ({clause})"
        sql_values.extend(extra_values1)
    clause, extra_values2 = flag_clause("SPC.peer_channel_flags", channel_flags, channel_mask)
    if clause:
        sql += f" AND ({clause})"
        sql_values.extend(extra_values2)
    return [ ServerPeerChannelMessageRow(*row) for row in db.execute(sql, sql_values).fetchall() ]


@replace_db_context_with_connection
def read_dpp_messages_by_pr_id(db: sqlite3.Connection, paymentrequest_ids: list[int]) \
        -> list[DPPMessageRow]:
    sql = """
        SELECT DPPM.message_id, DPPM.paymentrequest_id, DPPM.dpp_invoice_id, DPPM.correlation_id,
            DPPM.app_id, DPPM.client_id, DPPM.user_id, DPPM.expiration, DPPM.body, DPPM.timestamp,
            DPPM.type
        FROM DPPMessages AS DPPM
        WHERE paymentrequest_id in ({})
    """
    return read_rows_by_id(DPPMessageRow, db, sql, [ ], paymentrequest_ids)


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
        TxFlags.MASK_STATE_LOCAL,
        txo_mask, txo_flags ]
    if exclude_frozen:
        sql += " AND KI.flags&?=0"
        sql_values.append(KeyInstanceFlag.FROZEN)
    cursor = db.execute(sql, sql_values)
    return WalletBalance(*cursor.fetchone())


@replace_db_context_with_connection
def read_wallet_datas(db: sqlite3.Connection) -> list[WalletDataRow]:
    sql = "SELECT key, value FROM WalletData"
    cursor = db.execute(sql)
    rows = cursor.fetchall()
    return [ WalletDataRow(row[0], json.loads(row[1])) for row in rows ]


@replace_db_context_with_connection
def read_wallet_events(db: sqlite3.Connection, account_id: Optional[int]=None,
        mask: WalletEventFlag=WalletEventFlag.NONE) -> list[WalletEventRow]:
    sql_values: list[Any]
    if mask is None:
        sql_values = []
        sql = (
            "SELECT event_id, event_type, account_id, event_flags, date_created, date_updated "
            "FROM WalletEvents")
        if account_id is not None:
            sql += "WHERE account_id=? "
            sql_values.append(account_id)
        sql += "ORDER BY date_created"
    else:
        sql_values = [ mask, mask ]
        sql = (
            "SELECT event_id, event_type, account_id, event_flags, date_created, date_updated "
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
        "SET date_updated=?, flags=flags&?, spending_tx_hash=NULL, spending_txi_index=NULL "
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

    def _write(db: Optional[sqlite3.Connection]=None) -> bool:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.execute(sql1, sql1_values)
        db.execute(sql2, sql2_values)
        db.execute(sql3, sql3_values)
        cursor = db.execute(sql4, sql4_values)
        assert cursor.rowcount == 1
        return True
    return db_context.post_to_thread(_write)


def reserve_keyinstance(db_context: DatabaseContext, account_id: int, masterkey_id: int,
        derivation_path: DerivationPath, allocation_flags: KeyInstanceFlag) \
            -> concurrent.futures.Future[tuple[int, DerivationType, bytes, KeyInstanceFlag]]:
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

    def _write(db: Optional[sqlite3.Connection]=None) \
            -> tuple[int, DerivationType, bytes, KeyInstanceFlag]:
        assert db is not None and isinstance(db, sqlite3.Connection)
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
            -> concurrent.futures.Future[list[KeyInstanceFlagChangeRow]]:
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

    def _write(db: Optional[sqlite3.Connection]=None) -> list[KeyInstanceFlagChangeRow]:
        assert db is not None and isinstance(db, sqlite3.Connection)
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

        final_rows: list[KeyInstanceFlagChangeRow] = []
        rows_by_keyinstance_id = { row.keyinstance_id: row for row in old_rows }
        for new_row in new_rows:
            old_row = rows_by_keyinstance_id[new_row.keyinstance_id]
            final_rows.append(KeyInstanceFlagChangeRow(new_row.keyinstance_id,
                old_row.flags, new_row.flags))

        return final_rows
    return db_context.post_to_thread(_write)


def set_transaction_state_write(tx_hash: bytes, flag: TxFlags, ignore_mask: TxFlags | None,
        db: Optional[sqlite3.Connection]=None) -> bool:
    """
    Set a transaction to given state.

    If the transaction is in an pre-dispatched state, this should succeed and will return `True`.
    If the transaction is not in a pre-dispatched state, then this will return `False` and no
    change will be made.
    """
    assert db is not None and isinstance(db, sqlite3.Connection)
    assert flag.bit_count() == 1, "only one state can be specified at a time"
    # We will clear any existing state bits.
    mask_bits = ~TxFlags.MASK_STATE
    if ignore_mask is None:
        ignore_mask = flag
    timestamp = get_posix_timestamp()
    sql = "UPDATE Transactions SET date_updated=?, flags=(flags&?)|? WHERE tx_hash=? AND flags&?=0"
    sql_values = [ timestamp, mask_bits, flag, tx_hash, ignore_mask ]

    rowcount = cast(int, db.execute(sql, sql_values).rowcount)
    return rowcount > 0


def update_transaction_flags_write(entries: list[tuple[TxFlags, TxFlags, bytes]], \
        db: Optional[sqlite3.Connection]=None) -> int:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "UPDATE Transactions SET flags=(flags&?)|? WHERE tx_hash=?"
    cursor = db.executemany(sql, entries)
    return cast(int, cursor.rowcount)


def update_transaction_output_flags(db_context: DatabaseContext, txo_keys: list[Outpoint],
        flags: TransactionOutputFlag, mask: Optional[TransactionOutputFlag]=None) \
            -> concurrent.futures.Future[bool]:
    if mask is None:
        # NOTE(typing) There is no gain in casting to TransactionOutputFlag.
        mask = ~flags # type: ignore
    sql = "UPDATE TransactionOutputs SET date_updated=?, flags=(flags&?)|?"
    sql_id_expression = "tx_hash=? AND txo_index=?"
    sql_values = [ get_posix_timestamp(), mask, flags ]

    def _write(db: Optional[sqlite3.Connection]=None) -> bool:
        nonlocal sql, sql_id_expression, sql_values, txo_keys
        assert db is not None and isinstance(db, sqlite3.Connection)
        rows_updated = update_rows_by_ids(db, sql, sql_id_expression, sql_values, txo_keys)
        if rows_updated != len(txo_keys):
            raise DatabaseUpdateError(f"Rollback as only {rows_updated} of {len(txo_keys)} "
                "rows were updated")
        return True
    return db_context.post_to_thread(_write)


def update_transaction_proof_write(tx_update_rows: list[TransactionProofUpdateRow],
        proof_rows: list[MerkleProofRow], proof_update_rows: list[MerkleProofUpdateRow],
        processed_message_ids: list[int], db: Optional[sqlite3.Connection]=None) -> None:
    """
    Set the proof related fields for a transaction. We also insert the proof into the proofs table.

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
    assert db is not None
    for update_row in tx_update_rows:
        assert update_row.tx_flags & ~TxFlags.MASK_STATE == 0  # No non-state flags should be set.
        assert update_row.tx_flags & TxFlags.MASK_STATE != 0   # A state flag should be set.

    sql = f"""
        UPDATE Transactions
        SET block_hash=?, block_height=?, block_position=?, flags=(flags&{~TxFlags.MASK_STATE})|?,
            date_updated=?
        WHERE tx_hash=?
    """
    db.executemany(sql, tx_update_rows)

    # This can be called for clearing transaction proofs. If it is called for setting a
    # transaction proof, we keep the proof.
    if len(proof_rows) > 0:
        sql = "INSERT OR IGNORE INTO TransactionProofs " \
            "(block_hash, block_position, block_height, proof_data, tx_hash) " \
            "VALUES (?,?,?,?,?)"
        db.executemany(sql, proof_rows)

    if len(proof_update_rows) > 0:
        sql = "UPDATE TransactionProofs SET block_height=? WHERE block_hash=? AND tx_hash=?"
        db.executemany(sql, proof_update_rows)

    if len(processed_message_ids) > 0:
        update_server_peer_channel_message_flags_write(processed_message_ids, db)


def update_transaction_proof_and_flag_write(tx_update_rows: list[TransactionProofUpdateRow],
        flag_entries: list[tuple[TxFlags, TxFlags, bytes]],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None
    update_transaction_proof_write(tx_update_rows, [], [], [], db)
    update_transaction_flags_write(flag_entries, db)


def post_update_wallet_datas(db_context: DatabaseContext, entries: Iterable[WalletDataRow]) \
        -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO WalletData (key, value, date_created, date_updated) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, date_updated=excluded.date_updated")
    timestamp = get_posix_timestamp()
    rows = []
    for entry in entries:
        rows.append((entry.key, json.dumps(entry.value), timestamp, timestamp))

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def post_delete_wallet_data(db_context: DatabaseContext, key: str) \
        -> concurrent.futures.Future[None]:
    sql = "DELETE FROM WalletData WHERE key=?"
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.execute(sql, (key,))
    return db_context.post_to_thread(_write)


def update_account_names(db_context: DatabaseContext, entries: Iterable[tuple[str, int]]) \
        -> concurrent.futures.Future[None]:
    sql = "UPDATE Accounts SET date_updated=?, account_name=? WHERE account_id=?"
    timestamp = get_posix_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_account_script_types(db_context: DatabaseContext,
        entries: Iterable[tuple[ScriptType, int]]) -> concurrent.futures.Future[None]:
    sql = "UPDATE Accounts SET date_updated=?, default_script_type=? WHERE account_id=?"
    timestamp = get_posix_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_account_transaction_descriptions(db_context: DatabaseContext,
        entries: Iterable[tuple[Optional[str], int, bytes]]) -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    sql = "UPDATE AccountTransactions SET date_updated=?, description=? " \
        "WHERE account_id=? AND tx_hash=?"
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_transactions(db_context: DatabaseContext,
        entries: Iterable[tuple[Optional[bytes], int]]) -> concurrent.futures.Future[None]:
    sql = "UPDATE Invoices SET date_updated=?, tx_hash=? WHERE invoice_id=?"
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_descriptions(db_context: DatabaseContext,
        entries: Iterable[tuple[Optional[str], int]]) -> concurrent.futures.Future[None]:
    sql = ("UPDATE Invoices SET date_updated=?, description=? "
        "WHERE invoice_id=?")
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_invoice_flags(entries: Iterable[tuple[PaymentFlag, PaymentFlag, int]],
        db: sqlite3.Connection | None=None) -> None:
    assert db is not None
    sql = "UPDATE Invoices SET date_updated=?, invoice_flags=(invoice_flags&?)|? " \
        "WHERE invoice_id=?"
    timestamp = int(time.time())
    rows = [ (timestamp, *entry) for entry in entries ]
    db.executemany(sql, rows)


def update_keyinstance_derivation_datas(db_context: DatabaseContext,
        entries: Iterable[tuple[bytes, int]]) -> concurrent.futures.Future[None]:
    sql = ("UPDATE KeyInstances SET date_updated=?, derivation_data=? WHERE keyinstance_id=?")

    timestamp = get_posix_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_keyinstance_descriptions(db_context: DatabaseContext,
        entries: Iterable[tuple[Optional[str], int]]) -> concurrent.futures.Future[None]:
    sql = ("UPDATE KeyInstances SET date_updated=?, description=? WHERE keyinstance_id=?")
    timestamp = get_posix_timestamp()
    rows = [ (timestamp,) + entry for entry in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
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
    server_read_sql = "SELECT server_id, encrypted_api_key FROM Servers " \
        "WHERE encrypted_api_key IS NOT NULL"
    server_update_sql = "UPDATE Servers SET date_updated=?, encrypted_api_key=? " \
        "WHERE server_id=?"

    date_updated = get_posix_timestamp()

    def _write(db: Optional[sqlite3.Connection]=None) -> PasswordUpdateResult:
        assert db is not None and isinstance(db, sqlite3.Connection)
        password_token = pw_encode(os.urandom(32).hex(), new_password)

        cursor = db.execute(token_update_sql, (date_updated, password_token, "password-token"))
        assert cursor.rowcount == 1

        # This tracks the updated encrypted values for the wallet to replace cached versions of
        # these with.
        result = PasswordUpdateResult(
            password_token=password_token,
            masterkey_updates=[],
            account_private_key_updates={})

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
        keyinstance_updates = list[tuple[int, bytes, int]]()
        for keyinstance_id, account_id, source_derivation_data in db.execute(keyinstance_read_sql):
            data = cast(KeyInstanceDataPrivateKey, json.loads(source_derivation_data))
            data["prv"] = pw_encode(pw_decode(data["prv"], old_password), new_password)
            keyinstance_updates.append((date_updated, json.dumps(data).encode(),
                keyinstance_id))
            if account_id in result.account_private_key_updates:
                result.account_private_key_updates[account_id].append((keyinstance_id, data["prv"]))
            else:
                result.account_private_key_updates[account_id] = [ (keyinstance_id, data["prv"]) ]
        if len(keyinstance_updates):
            db.executemany(keyinstance_update_sql, keyinstance_updates)

        # Re-encrypt masterkey data (seed, passphrase, xprv) with the new password.
        masterkey_updates = list[tuple[int, bytes, int]]()
        for (masterkey_id, derivation_type, source_derivation_data) in \
                db.execute(masterkey_read_sql):
            updated_data = reencrypt_masterkey_data(masterkey_id, derivation_type,
                source_derivation_data, result)
            if updated_data is None:
                continue
            masterkey_updates.append((date_updated, updated_data, masterkey_id))
        if len(masterkey_updates):
            db.executemany(masterkey_update_sql, masterkey_updates)

        # Re-encrypt network server api keys with the new password.
        encrypted_api_key: str
        server_updates = list[tuple[int, str, int]]()
        for server_id, encrypted_api_key in db.execute(server_read_sql):
            encrypted_api_key2 = pw_encode(pw_decode(encrypted_api_key, old_password), new_password)
            server_updates.append((date_updated, encrypted_api_key2, server_id))
        if len(server_updates):
            db.executemany(server_update_sql, server_updates)

        return result
    return db_context.post_to_thread(_write)


def close_paid_payment_request(request_id: int, db: sqlite3.Connection | None=None) \
        -> list[tuple[str, int, bytes]]:
    assert db is not None and isinstance(db, sqlite3.Connection)

    read_sql = "SELECT state, value FROM PaymentRequests WHERE paymentrequest_id=?"
    read_row = db.execute(read_sql, (request_id,)).fetchone()
    if read_row is None:
        raise DatabaseUpdateError("Payment request does not exist")
    current_state = cast(PaymentFlag, read_row[0])
    if current_state & PaymentFlag.MASK_STATE != PaymentFlag.UNPAID:
        raise DatabaseUpdateError("Payment request not unpaid")

    request_expected_value = cast(int, read_row[1])
    received_value = 0

    read_outputs_sql = """
    SELECT PRO.keyinstance_id, PRO.transaction_index, PRO.output_index, PRO.output_value,
        TXO.tx_hash, TXO.txo_index, TXO.value
    FROM PaymentRequestOutputs PRO
    LEFT JOIN TransactionOutputs TXO ON TXO.keyinstance_id=PRO.keyinstance_id
    WHERE PRO.paymentrequest_id=?
    """
    transaction_hash_by_index: dict[int, bytes] = {}
    keyinstance_ids: list[int] = []
    for keyinstance_id, transaction_index, output_index, expected_value, transaction_hash, \
            txo_index, actual_value in db.execute(read_outputs_sql, (request_id,)).fetchall():
        if expected_value != actual_value:
            raise DatabaseUpdateError("Bad transaction key payment with incorrect value")
        if transaction_index in transaction_hash_by_index:
            if transaction_hash != transaction_hash_by_index[transaction_index]:
                raise DatabaseUpdateError("Bad transaction mapping")
        else:
            transaction_hash_by_index[transaction_index] = transaction_hash
        received_value += actual_value
        keyinstance_ids.append(keyinstance_id)

    if request_expected_value != received_value:
        raise DatabaseUpdateError("Received value incorrect")

    date_updated = int(time.time())

    update_sql = "UPDATE PaymentRequests SET state=(state&?)|?, date_updated=? " \
        "WHERE paymentrequest_id=?"
    cursor = db.execute(update_sql, (~PaymentFlag.MASK_STATE, PaymentFlag.PAID, date_updated,
        request_id))
    if cursor.rowcount != 1:
        raise DatabaseUpdateError("Update payment request failed")

    update_keyinstances_values = [
        date_updated,
        KeyInstanceFlag.MASK_ACTIVE_REASON, KeyInstanceFlag.IS_PAYMENT_REQUEST,
        ~(KeyInstanceFlag.IS_PAYMENT_REQUEST|KeyInstanceFlag.ACTIVE),
        ~KeyInstanceFlag.IS_PAYMENT_REQUEST,
    ]
    update_keyinstances_values.extend(keyinstance_ids)
    update_keyinstances_sql = f"""
    UPDATE KeyInstances SET date_updated=?, flags=CASE
        WHEN flags&?=? THEN flags&? ELSE flags&? END
    WHERE keyinstance_id IN ({",".join("?" for v in keyinstance_ids)})
    RETURNING account_id, keyinstance_id, flags
    """
    cursor = db.execute(update_keyinstances_sql, update_keyinstances_values)
    if cursor.rowcount != len(keyinstance_ids):
        raise DatabaseUpdateError("Update keyinstances failed")

    update_descriptions_sql = """
    UPDATE AccountTransactions AS ATX
    SET description=PR.description
    FROM TransactionOutputs TXO
    INNER JOIN PaymentRequestOutputs PRO ON PRO.keyinstance_id=TXO.keyinstance_id
    INNER JOIN PaymentRequests PR ON PR.paymentrequest_id=PRO.paymentrequest_id
    WHERE TXO.tx_hash=ATX.tx_hash AND ATX.description IS NULL AND PR.paymentrequest_id=?1
    RETURNING description, account_id, tx_hash
    """
    description_rows = db.execute(update_descriptions_sql, (request_id,)).fetchall()
    return cast(list[tuple[str, int, bytes]], description_rows)


def update_payment_requests_write(entries: Iterable[PaymentRequestUpdateRow],
        db: sqlite3.Connection | None=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = ("UPDATE PaymentRequests SET date_updated=?, state=?, value=?, date_expires=?, "
        "description=?, merchant_reference=? WHERE paymentrequest_id=?")
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    db.executemany(sql, rows)


def update_wallet_event_flags(db_context: DatabaseContext,
        entries: Iterable[tuple[WalletEventFlag, int]]) -> concurrent.futures.Future[None]:
    sql = "UPDATE WalletEvents SET date_updated=?, event_flags=? WHERE event_id=?"
    timestamp = get_posix_timestamp()
    rows = [ (timestamp, *entry) for entry in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


def update_network_server_credentials_write(server_id: int, encrypted_api_key: Optional[str],
        payment_key_bytes: Optional[bytes], updated_flags: NetworkServerFlag,
        updated_flags_mask: NetworkServerFlag, db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    update_sql = "UPDATE Servers SET date_updated=?, encrypted_api_key=?, payment_key_bytes=?, " \
        "server_flags=(server_flags&?)|? WHERE server_id=?"
    sql_values = (int(get_posix_timestamp()), encrypted_api_key, payment_key_bytes,
        updated_flags_mask, updated_flags, server_id)
    cursor = db.execute(update_sql, sql_values)
    assert cursor.rowcount == 1


def update_network_server_flags_write(server_id: int,
        server_flags: NetworkServerFlag, server_flags_mask: NetworkServerFlag,
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    sql = "UPDATE Servers SET date_updated=?, server_flags=(server_flags&?)|? WHERE server_id=?"
    cursor = db.execute(sql, (int(get_posix_timestamp()), server_flags_mask, server_flags,
        server_id))
    assert cursor.rowcount == 1


def update_network_server_peer_channel_id_write(server_id: int,
        server_peer_channel_id: Optional[int], db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)
    update_sql = "UPDATE Servers SET date_updated=?, server_peer_channel_id=? WHERE server_id=?"
    cursor = db.execute(update_sql, (int(get_posix_timestamp()), server_peer_channel_id, server_id))
    assert cursor.rowcount == 1


def update_network_servers_transaction(db_context: DatabaseContext,
        create_rows: list[NetworkServerRow], update_rows: list[NetworkServerRow],
        deleted_server_ids: list[int], deleted_server_keys: list[ServerAccountKey]) \
            -> concurrent.futures.Future[list[NetworkServerRow]]:
    """
    Add, update and remove server definitions for this wallet.
    """
    # These columns should be in the same order as the `NetworkServerRow` tuple.
    insert_prefix_sql = "INSERT INTO Servers (server_id, server_type, url, account_id, " \
        "server_flags, api_key_template, encrypted_api_key, payment_key_bytes, fee_quote_json, " \
        "tip_filter_peer_channel_id, date_last_connected, date_last_tried, date_created, " \
        "date_updated) VALUES"
    insert_suffix_sql = "RETURNING server_id, server_type, url, account_id, " \
        "server_flags, api_key_template, encrypted_api_key, payment_key_bytes, fee_quote_json, " \
        "tip_filter_peer_channel_id, date_last_connected, date_last_tried, " \
        "date_created, date_updated"
    update_sql = "UPDATE Servers SET date_updated=?, api_key_template=?, encrypted_api_key=?, " \
        "server_flags=? WHERE server_id=?"
    delete_ids_sql = "DELETE FROM Servers WHERE server_id=?"
    delete_server_keys_sql = "DELETE FROM Servers WHERE server_type=? AND url=?"
    delete_account_keys_sql = "DELETE FROM Servers WHERE server_type=? AND url=? AND " \
        "account_id=?"

    timestamp_utc = get_posix_timestamp()
    final_update_rows = [ (timestamp_utc, server_row.api_key_template, server_row.encrypted_api_key,
        server_row.server_flags, server_row.server_id)
        for server_row in update_rows ]
    final_delete_ids_rows = [ (server_id,) for server_id in deleted_server_ids ]
    final_delete_server_keys_rows = [ (key.server_type, key.url)
        for key in deleted_server_keys if key.account_id is None]
    final_delete_account_keys_rows = [ (key.server_type, key.url, key.account_id)
        for key in deleted_server_keys if key.account_id is not None]

    def _write(db: Optional[sqlite3.Connection]=None) -> list[NetworkServerRow]:
        assert db is not None and isinstance(db, sqlite3.Connection)
        if final_delete_ids_rows:
            cursor = db.executemany(delete_ids_sql, final_delete_ids_rows)
            if cursor.rowcount != len(final_delete_ids_rows):
                raise DatabaseUpdateError
        if final_delete_server_keys_rows:
            cursor = db.executemany(delete_server_keys_sql, final_delete_server_keys_rows)
            # We do not know how many this will match. It will be the base server row and any
            # account rows.
            if cursor.rowcount == 0:
                raise DatabaseUpdateError
        if final_delete_account_keys_rows:
            cursor = db.executemany(delete_account_keys_sql, final_delete_account_keys_rows)
            if cursor.rowcount == len(final_delete_account_keys_rows):
                raise DatabaseUpdateError
        if final_update_rows:
            cursor = db.executemany(update_sql, final_update_rows)
            if cursor.rowcount != len(final_update_rows):
                raise DatabaseUpdateError(f"Expected to update {len(final_update_rows)} rows"
                    f", updated {cursor.rowcount}")
        if create_rows:
            return bulk_insert_returning(NetworkServerRow, db, insert_prefix_sql,
                insert_suffix_sql, create_rows)
        return []
    return db_context.post_to_thread(_write)


def update_network_servers(db_context: DatabaseContext, rows: list[NetworkServerRow]) \
        -> concurrent.futures.Future[None]:
    """
    Update the state fields for server definitions on this wallet.

    Note that we pick and choose from the fields on the passed in rows, and use the standard rows
    to save having numerous row types with minimal variations each.
    """
    update_sql = "UPDATE Servers SET date_updated=?, fee_quote_json=?, " \
        "date_last_connected=?, date_last_tried=? WHERE server_id=?"

    timestamp_utc = get_posix_timestamp()
    update_rows = [ (timestamp_utc, row.mapi_fee_quote_json, row.date_last_good,
        row.date_last_try, row.server_id) for row in rows ]

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(update_sql, update_rows)
    return db_context.post_to_thread(_write)


def create_mapi_broadcasts_write(rows: list[MAPIBroadcastRow],
        db: Optional[sqlite3.Connection]=None) -> list[MAPIBroadcastRow]:
    assert db is not None
    sql_prefix = "INSERT INTO MAPIBroadcasts (broadcast_id, tx_hash, broadcast_server_id, " \
        "mapi_broadcast_flags, peer_channel_id, date_created, date_updated) VALUES"
    sql_suffix = "RETURNING broadcast_id, tx_hash, broadcast_server_id, mapi_broadcast_flags, " \
            "peer_channel_id, date_created, date_updated"
    # NOTE(database) `executemany` does not support `RETURNING` so we have this bulk insert call.
    return bulk_insert_returning(MAPIBroadcastRow, db, sql_prefix, sql_suffix, rows)


@replace_db_context_with_connection
def read_mapi_broadcasts(db: sqlite3.Connection, tx_hashes: list[bytes] | None=None) \
        -> list[MAPIBroadcastRow]:
    sql = f"""
    SELECT broadcast_id, tx_hash, broadcast_server_id, mapi_broadcast_flags, peer_channel_id,
        date_created, date_updated
    FROM MAPIBroadcasts
    WHERE mapi_broadcast_flags&{MAPIBroadcastFlag.DELETED}=0
    """
    if not tx_hashes:
        return [ MAPIBroadcastRow(*row) for row in db.execute(sql).fetchall() ]

    sql += "AND tx_hash in ({})"
    return read_rows_by_id(MAPIBroadcastRow, db, sql, [ ], tx_hashes)


def update_mapi_broadcasts(db_context: DatabaseContext,
        entries: Iterable[tuple[MAPIBroadcastFlag, bytes, int, int]]) \
            -> concurrent.futures.Future[None]:
    sql = "UPDATE MAPIBroadcasts SET mapi_broadcast_flags=?, response_data=?, date_updated=? "\
        "WHERE broadcast_id=?"
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, entries)
    return db_context.post_to_thread(_write)


def delete_mapi_broadcasts(db_context: DatabaseContext, broadcast_ids: Iterable[int]) \
        -> concurrent.futures.Future[None]:
    date_updated = int(time.time())
    sql = "UPDATE MAPIBroadcasts " \
        f"SET mapi_broadcast_flags=mapi_broadcast_flags|{MAPIBroadcastFlag.DELETED}, " \
            "date_updated=? WHERE broadcast_id=?"
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None
        db.executemany(sql, [(date_updated, broadcast_id) for broadcast_id in broadcast_ids])
    return db_context.post_to_thread(_write)


def create_merkle_proofs_write(creation_rows: list[MerkleProofRow],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None
    # If we already have the transaction proof it's not going to change so we can safely ignore it.
    sql = "INSERT OR IGNORE INTO TransactionProofs " \
        "(block_hash, block_position, block_height, proof_data, tx_hash) " \
        "VALUES (?,?,?,?,?)"
    db.executemany(sql, creation_rows)


@replace_db_context_with_connection
def read_merkle_proofs(db: sqlite3.Connection, tx_hashes: list[bytes]) \
        -> list[MerkleProofRow]:
    sql = """
        SELECT block_hash, block_position, block_height, proof_data, tx_hash
        FROM TransactionProofs
        WHERE tx_hash in ({})
    """
    return read_rows_by_id(MerkleProofRow, db, sql, [ ], tx_hashes)


@replace_db_context_with_connection
def read_unconnected_merkle_proofs(db: sqlite3.Connection) -> list[MerkleProofRow]:
    """
    Transactions that are in state CLEARED and have proof are guaranteed to be those who
    we obtained proof for, but lacked the header to verify the proof. We need to
    reconcile these with headers as the headers arrive, and verify them when that happens.
    """
    sql = f"""
    SELECT TXP.block_hash, TXP.block_position, TXP.block_height, TXP.proof_data, TXP.tx_hash
    FROM TransactionProofs TXP
    INNER JOIN Transactions TX ON TX.tx_hash=TXP.tx_hash AND TX.block_hash=TXP.block_hash
    WHERE TX.flags&{TxFlags.MASK_STATE}={TxFlags.STATE_CLEARED} AND TX.block_position IS NULL
    """
    rows = db.execute(sql).fetchall()
    return [ MerkleProofRow(*row) for row in rows ]


def update_merkle_proofs_write(update_rows: list[MerkleProofUpdateRow],
        db: Optional[sqlite3.Connection]=None) -> None:
    assert db is not None
    sql = "UPDATE TransactionProofs SET block_height=? WHERE block_hash=? AND tx_hash=?"
    db.executemany(sql, update_rows)


def update_reorged_transactions_write(orphaned_block_hashes: list[bytes],
        db: Optional[sqlite3.Connection]=None) -> list[bytes]:
    assert db is not None

    # We are looking at transactions in one of two states:
    # - Cleared transactions with proof related columns set are ones we current lack the header for.
    # - Settled transactions with proof related columns set are ones we verified using the header.
    sql = """
        UPDATE Transactions
        SET date_updated=?, flags=(flags&?)|?, block_hash=NULL, block_height=?, block_position=NULL
        WHERE flags&?!=0 AND block_hash IN ({})
        RETURNING tx_hash
    """
    sql_values = [ get_posix_timestamp(), ~TxFlags.MASK_STATE, TxFlags.STATE_CLEARED,
        BlockHeight.MEMPOOL, TxFlags.STATE_CLEARED | TxFlags.STATE_SETTLED ]
    # We are doing something unusual here with the return type, so it is worth explaining it.
    # Usually a subclass of `NamedTuple` is passed that gets the returned values passed into it,
    # this means that if there is one returned value of type `T`, there still needs to be another
    # pass to flatten `list[NamedTupleSubclass]` to `list[T]`. But in this case we can rely on
    # the fact that say `bytes(*t)` where `t` is length 1 and already `bytes` returns `t`.
    # So what we get is `list[<some-type>]` and there is no need for flattening.
    _rows_updated, updated_tx_hashes = execute_sql_by_id(db, sql, sql_values, orphaned_block_hashes,
        return_type=bytes)
    return updated_tx_hashes


# SCOPE: Transaction import and linking to key usage and accounts.

def import_transaction(tx_row: TransactionRow, txi_rows: list[TransactionInputAddRow],
        txo_rows: list[TransactionOutputAddRow], proof_row: MerkleProofRow | None,
        rollback_on_spend_conflict: bool, db: sqlite3.Connection | None=None) \
            -> TransactionLinkState:
    """
    Insert the transaction data and attempt to link it to any accounts it may be involved with.

    If any unexpected constraints are violated, an exception should be raised out of this
    function and should be caught rolling back this transaction.

    This should only be called in the context of the writer thread.
    """
    try:
        _insert_transaction(db, tx_row, txi_rows, txo_rows, proof_row)
    except TransactionAlreadyExistsError:
        # If the transaction already exists there is no point in re-importing it, unless
        # it is unlinked (removed / conflicted) and we want to import it and link it.
        if not _reset_transaction_for_import(db, tx_row.tx_hash):
            raise

    return link_transaction(tx_row.tx_hash, rollback_on_spend_conflict, db)


def _insert_transaction(db: sqlite3.Connection, tx_row: TransactionRow,
        txi_rows: list[TransactionInputAddRow], txo_rows: list[TransactionOutputAddRow],
        proof_row: MerkleProofRow | None) -> Any:
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
            "block_height, block_position, fee_value, description, version, locktime, "
            "date_created, date_updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", tx_row)
    except sqlite3.IntegrityError as e:
        if e.args[0] == "UNIQUE constraint failed: Transactions.tx_hash":
            raise TransactionAlreadyExistsError(_("This transaction is already imported."))

    # Constraint: (tx_hash, tx_index) should be unique.
    db.executemany("INSERT INTO TransactionInputs (tx_hash, txi_index, spent_tx_hash, "
        "spent_txo_index, sequence, flags, script_offset, script_length, date_created, "
        "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?)", txi_rows)

    # Constraint: (tx_hash, tx_index) should be unique.
    db.executemany("INSERT INTO TransactionOutputs (tx_hash, txo_index, value, keyinstance_id, "
        "script_type, flags, script_hash, script_offset, script_length, date_created, "
        "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?,?)", txo_rows)

    if tx_row.block_hash is not None:
        if tx_row.block_position is not None:
            # We know the transaction is on a block and we have the merkle proof.
            assert tx_row.flags & TxFlags.MASK_STATE == TxFlags.STATE_SETTLED
            if proof_row is None:
                raise IncompleteProofDataSubmittedError()
            # We know there is no existing row because the `tx_hash` foreign key ensures this.
            db.execute("INSERT INTO TransactionProofs "
                "(tx_hash, block_hash, block_position, block_height, proof_data) "
                "VALUES (?,?,?,?,?)", (proof_row.tx_hash,
                    proof_row.block_hash, proof_row.block_position, proof_row.block_height,
                    proof_row.proof_data))
        else:
            # The transaction is in any state other than `SETTLED`. This may be that we know
            # the transaction is in a block but we do not have the merkle proof (yet).
            assert tx_row.flags & TxFlags.MASK_STATE != TxFlags.STATE_SETTLED

    return True

def _reset_transaction_for_import(db: sqlite3.Connection, tx_hash: bytes) -> bool:
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

def link_transaction(tx_hash: bytes, rollback_on_spend_conflict: bool,
        db: sqlite3.Connection | None=None) -> TransactionLinkState:
    """
    Populate the metadata for the given transaction in the database.

    Given this happens in a sequential writer thread we know that there cannot be
    race conditions in the database where transactions being added in parallel might miss
    spends. However, in real world usage that should only ever be ordered spends. Unordered
    spends should only occur in synchronisation, and we can special case that at a higher
    level.
    """
    assert db is not None and isinstance(db, sqlite3.Connection)

    _update_transaction_key_usage(db, tx_hash)
    _link_transaction_to_accounts(db, tx_hash)

    link_state = TransactionLinkState()
    # NOTE We do not handle removing the conflict flag here. That whole process can be
    # done elsewhere.
    if _reconcile_transaction_output_spends(db, tx_hash):
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
        if rollback_on_spend_conflict:
            raise DatabaseUpdateError("Transaction rolled back due to spend conflicts")

        sql2 = "UPDATE Transactions SET flags=flags|? WHERE tx_hash=?"
        sql2_values = (TxFlags.CONFLICTING, tx_hash)
        db.execute(sql2, sql2_values)

    return link_state

def _update_transaction_key_usage(db: sqlite3.Connection, tx_hash: bytes) -> None:
    assert db is not None and isinstance(db, sqlite3.Connection)

    timestamp = int(time.time())
    # We explicitly mark keys as used when we use them. See `KeyInstanceFlag.USED`
    # for a rationale. We want to know that keys were marked as used by this so that
    # the calling logic can use it, if need be. An example of this would be maintaining
    # a gap limit of unused addresses.
    keyinstance_update_sql = (
        "UPDATE KeyInstances AS KI "
        "SET date_updated=?, flags=KI.flags|? "
        "FROM TransactionOutputs TXO "
        "INNER JOIN Transactions TX ON TX.tx_hash=TXO.tx_hash "
        "WHERE TXO.keyinstance_id=KI.keyinstance_id AND TX.flags&?=0 AND TXO.tx_hash=?")
    keyinstance_update_values = (timestamp, KeyInstanceFlag.USED,
        TxFlags.MASK_UNLINKED|KeyInstanceFlag.USED, tx_hash)
    db.execute(keyinstance_update_sql, keyinstance_update_values)


def _link_transaction_to_accounts(db: sqlite3.Connection, tx_hash: bytes) -> int:
    """
    Link transaction output key usage to account involvement.

    This function can be repeatedly called, which might be useful if for some reason keys
    were not created when it was first called for a transaction.
    """
    timestamp = int(time.time())

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
            "WHERE TXO.tx_hash=?1 "
            "UNION "
            # Link based on any spending key usage of this transaction.
            "SELECT DISTINCT KI.account_id "
            "FROM TransactionInputs TXI "
            "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash = TXI.spent_tx_hash "
            "INNER JOIN KeyInstances KI ON KI.keyinstance_id = TXO.keyinstance_id "
            "WHERE TXI.tx_hash=?1 "
        ")"
        "SELECT ?1, TA.account_id, ?2, ?2 "
        "FROM transaction_accounts TA",
        (tx_hash, timestamp))
    return cast(int, cursor.rowcount)

def _reconcile_transaction_output_spends(db: sqlite3.Connection, tx_hash: bytes) -> bool:
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

    spend_conflicts: list[SpendConflictType] = []
    spent_rows: list[tuple[int, bytes, int, bytes, int]] = []
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

        logger.error("Failed to spend %d transaction outputs, as something else "
            "unexpectedly spent them. This should never happen.",
            len(spent_rows) - cursor.rowcount)
        return False

    return True

