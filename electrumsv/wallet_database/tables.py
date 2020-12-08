from collections import defaultdict
from io import BytesIO
import json
try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.7.8 builds and version of 3.31.1.
    import sqlite3 # type: ignore
import time
from typing import Any, Dict, Iterable, NamedTuple, Optional, List, Sequence, Tuple

import bitcoinx
from bitcoinx import hash_to_hex_str

from ..constants import (AccountTxFlags, DerivationType, KeyInstanceFlag,
    TransactionOutputFlag, PaymentFlag, ScriptType, TxFlags, WalletEventFlag,
    WalletEventType)
from ..logs import logs
from ..types import TxoKeyType

from .sqlite_support import (SQLITE_EXPR_TREE_DEPTH, SQLITE_MAX_VARS, DatabaseContext,
    CompletionCallbackType)
from .types import (AccountRow, KeyInstanceRow, MasterKeyRow, PaymentRequestRow,
    TransactionOutputRow, TxData, TxProof)
from .util import collect_results, flag_clause, update_rows_by_id


__all__ = [
    "MissingRowError", "DataPackingError", "TransactionTable", "TransactionOutputTable",
    "MasterKeyTable", "KeyInstanceTable", "WalletDataTable",
    "AccountTable",
]


class DataPackingError(Exception):
    pass


class MissingRowError(Exception):
    pass


class InvalidDataError(Exception):
    pass

class InvalidUpsertError(Exception):
    pass


TXDATA_VERSION = 1
TXPROOF_VERSION = 1


def byte_repr(value):
    if value is None:
        return str(value)
    return f"ByteData(length={len(value)})"


class BaseDatabaseAPI:
    LOGGER_NAME: str

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

    def _get_current_timestamp(self) -> int:
        "Get the current timestamp in a form suitable for database column storage."
        return int(time.time())


class WalletDataRow(NamedTuple):
    key: str
    value: Any


class WalletDataTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-walletdata"

    CREATE_SQL = ("INSERT INTO WalletData (key, value, date_created, date_updated) "
        "VALUES (?, ?, ?, ?)")
    READ_SQL = "SELECT key, value FROM WalletData"
    UPDATE_SQL = ("UPDATE WalletData SET value=?, date_updated=? WHERE key=?")
    UPSERT_SQL = (CREATE_SQL +" ON CONFLICT(key) DO UPDATE "
        "SET value=excluded.value, date_updated=excluded.date_updated")
    DELETE_SQL = "DELETE FROM WalletData WHERE key=?"
    DELETE_VALUE_SQL = "DELETE FROM WalletData WHERE key=? AND value=?"

    def create(self, entries: Iterable[WalletDataRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = []
        for entry in entries:
            assert type(entry.key) is str, f"bad key '{entry.key}'"
            data = json.dumps(entry.value)
            datas.append([ entry.key, data, timestamp, timestamp])

        def _write(db: sqlite3.Connection) -> None:
            print(2)
            self._logger.debug("create '%s'", [t.key for t in entries])
            db.executemany(self.CREATE_SQL, datas)

        self._db_context.queue_write(_write, completion_callback)

    def get_value(self, key: str) -> Optional[Any]:
        cursor = self._db.execute(self.READ_SQL +" WHERE key=?", [key])
        row = cursor.fetchone()
        return json.loads(row[1]) if row is not None else None

    def read(self, keys: Optional[Sequence[str]]=None) -> List[WalletDataRow]:
        results: List[WalletDataRow] = []
        def _collect_results(cursor, results):
            rows = cursor.fetchall()
            cursor.close()
            for row in rows:
                results.append(WalletDataRow(row[0], json.loads(row[1])))

        if keys is None:
            cursor = self._db.execute(self.READ_SQL, [])
            _collect_results(cursor, results)
        else:
            batch_size = SQLITE_MAX_VARS
            while len(keys):
                batch_keys = keys[:batch_size]
                batch_query = (self.READ_SQL +
                    " WHERE key IN ({0})".format(",".join("?" for k in batch_keys)))
                cursor = self._db.execute(batch_query, batch_keys)
                _collect_results(cursor, results)
                keys = keys[batch_size:]

        return results

    def get_row(self, key: str) -> Optional[WalletDataRow]:
        cursor = self._db.execute(self.READ_SQL +" WHERE key=?", [key])
        row = cursor.fetchone()
        cursor.close()
        if row is not None:
            return WalletDataRow(row[0], json.loads(row[1]))
        return None

    def upsert(self, entries: Iterable[WalletDataRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = []
        for entry in entries:
            datas.append((entry.key, json.dumps(entry.value), timestamp, timestamp))

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("upsert %s", [ t.key for t in entries ])
            db.executemany(self.UPSERT_SQL, datas)

        self._db_context.queue_write(_write, completion_callback)

    def update(self, entries: Iterable[WalletDataRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = []
        for t in entries:
            datas.append((json.dumps(t.value), timestamp, t.key))

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("update %s", [t.key for t in entries])
            db.executemany(self.UPDATE_SQL, datas)

        self._db_context.queue_write(_write, completion_callback)

    def delete(self, key: str,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("deleted %s", key)
            db.execute(self.DELETE_SQL, [key])

        self._db_context.queue_write(_write, completion_callback)


class TransactionTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-tx"

    READ_DESCRIPTION_SQL = ("SELECT tx_hash, T.description FROM Transactions T "
        "WHERE description IS NOT NULL")
    READ_MANY_BASE_SQL = ("SELECT tx_hash, tx_data, T.flags, block_height, block_position, "
        "fee_value, T.date_created, T.date_updated FROM Transactions T")
    READ_METADATA_BASE_SQL = ("SELECT T.flags, block_height, block_position, fee_value, "
        "T.date_created, T.date_updated FROM Transactions T WHERE tx_hash=?")
    READ_METADATA_MANY_BASE_SQL = ("SELECT tx_hash, T.flags, block_height, block_position, "
        "fee_value, T.date_created, T.date_updated FROM Transactions T")
    READ_PROOF_SQL = "SELECT tx_hash, proof_data FROM Transactions T"
    UPDATE_DESCRIPTION_SQL = "UPDATE Transactions SET date_updated=?, description=? WHERE tx_hash=?"
    UPDATE_FLAGS_SQL = "UPDATE Transactions SET flags=((flags&?)|?),date_updated=? WHERE tx_hash=?"
    UPDATE_MANY_SQL = ("UPDATE Transactions SET tx_data=?,flags=?,block_height=?,"
        "block_position=?,fee_value=?,date_updated=? WHERE tx_hash=?")
    UPDATE_METADATA_MANY_SQL = ("UPDATE Transactions SET flags=?,block_height=?,"
        "block_position=?,fee_value=?,date_updated=? WHERE tx_hash=?")
    UPDATE_PROOF_SQL = ("UPDATE Transactions SET proof_data=?,date_updated=?,flags=(flags|?) "
        "WHERE tx_hash=?")
    DELETE_SQL = "DELETE FROM Transactions WHERE tx_hash=?"

    @staticmethod
    def _pack_proof(proof: TxProof) -> bytes:
        raw = bitcoinx.pack_varint(1)
        raw += bitcoinx.pack_varint(proof.position)
        raw += bitcoinx.pack_varint(len(proof.branch))
        for hash in proof.branch:
            raw += bitcoinx.pack_varbytes(hash)
        return raw

    @staticmethod
    def _unpack_proof(raw: bytes) -> TxProof:
        io = BytesIO(raw)
        pack_version = bitcoinx.read_varint(io.read)
        if pack_version == 1:
            position = bitcoinx.read_varint(io.read)
            branch_count = bitcoinx.read_varint(io.read)
            merkle_branch = [ bitcoinx.read_varbytes(io.read) for i in range(branch_count) ]
            return TxProof(position, merkle_branch)
        raise DataPackingError(f"Unhandled packing format {pack_version}")

    def _get_many_common(self, query: str, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_hashes: Optional[Sequence[bytes]]=None, account_id: Optional[int]=None) -> List[Any]:
        params = []
        clause, extra_params = flag_clause("T.flags", flags, mask)

        conjunction = "WHERE"
        if " WHERE " in query:
            assert account_id is None, "This query is incompatible with account filtering"
            conjunction = "AND"

        if account_id is not None:
            query += " INNER JOIN AccountTransactions ATX USING(tx_hash) WHERE ATX.account_id=?"
            params.append(account_id)
            conjunction = "AND"

        if clause:
            query += f" {conjunction} {clause}"
            params.extend(extra_params)
            conjunction = "AND"

        if tx_hashes is None or not len(tx_hashes):
            cursor = self._db.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()
            return rows

        results = []
        batch_size = SQLITE_MAX_VARS - len(params)
        while len(tx_hashes):
            batch_tx_hashes = tx_hashes[:batch_size]
            batch_query = (query +" "+ conjunction +" "+
                "tx_hash IN ({0})".format(",".join("?" for k in batch_tx_hashes)))
            cursor = self._db.execute(batch_query, params + batch_tx_hashes) # type: ignore
            rows = cursor.fetchall()
            cursor.close()
            results.extend(rows)
            tx_hashes = tx_hashes[batch_size:]
        return results

    def read(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Sequence[bytes]]=None, account_id: Optional[int]=None) \
            -> List[Tuple[bytes, bytes, TxFlags, TxData]]:
        query = self.READ_MANY_BASE_SQL
        return [ (row[0], row[1], TxFlags(row[2]), TxData(row[3], row[4], row[5], row[6], row[7]))
            for row in self._get_many_common(query, flags, mask, tx_hashes, account_id) ]

    def read_metadata(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Sequence[bytes]]=None, account_id: Optional[int]=None) \
                -> List[Tuple[bytes, TxFlags, TxData]]:
        query = self.READ_METADATA_MANY_BASE_SQL
        return [ (row[0], TxFlags(row[1]), TxData(row[2], row[3], row[4], row[5], row[6]))
            for row in self._get_many_common(query, flags, mask, tx_hashes, account_id) ]

    # Shared wallet data between all accounts.
    def read_descriptions(self,
            tx_hashes: Optional[Sequence[bytes]]=None) -> List[Tuple[bytes, str]]:
        query = self.READ_DESCRIPTION_SQL
        return self._get_many_common(query, None, None, tx_hashes)

    # Not called outside of the unit tests (at this time).
    def read_proof(self, tx_hashes: Sequence[bytes]) -> List[Tuple[bytes, Optional[TxProof]]]:
        query = self.READ_PROOF_SQL
        return [ (row[0], self._unpack_proof(row[1]) if row[1] is not None else None)
            for row in self._get_many_common(query, None, None, tx_hashes) ]

    def update(self, entries: List[Tuple[bytes, TxData, Optional[bytes], TxFlags]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        data_rows = []
        metadata_rows = []
        for tx_hash, metadata, bytedata, flags in entries:
            assert type(tx_hash) is bytes
            assert type(bytedata) is bytes or bytedata is None
            flags &= ~TxFlags.METADATA_FIELD_MASK
            if metadata.height is not None:
                flags |= TxFlags.HasHeight
            if metadata.fee is not None:
                flags |= TxFlags.HasFee
            if metadata.position is not None:
                flags |= TxFlags.HasPosition
            if bytedata is None:
                # This is where we are updating a row which has existing bytedata that is not
                # changing, but we don't want to still have to  pass it into the update call to
                # avoid changing it.
                metadata_rows.append((flags, metadata.height, metadata.position,
                    metadata.fee, metadata.date_updated, tx_hash))
            else:
                data_rows.append((bytedata, flags, metadata.height, metadata.position,
                    metadata.fee, metadata.date_updated, tx_hash))

        def _write(db: sqlite3.Connection) -> None:
            if len(entries) < 20:
                self._logger.debug("update %d transactions: %s", len(entries),
                    [ (hash_to_hex_str(a), b, TxFlags.to_repr(d)) for (a, b, c, d)
                    in entries ])
            else:
                self._logger.debug("update %d transactions (too many to show)", len(entries))
            if len(data_rows):
                db.executemany(self.UPDATE_MANY_SQL, data_rows)
            if len(metadata_rows):
                db.executemany(self.UPDATE_METADATA_MANY_SQL, metadata_rows)

        self._db_context.queue_write(_write, completion_callback)

    def update_metadata(self, entries: List[Tuple[bytes, TxData, TxFlags]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = []
        for tx_hash, metadata, flags in entries:
            assert type(tx_hash) is bytes
            flags &= ~TxFlags.METADATA_FIELD_MASK
            if metadata.height is not None:
                flags |= TxFlags.HasHeight
            if metadata.fee is not None:
                flags |= TxFlags.HasFee
            if metadata.position is not None:
                flags |= TxFlags.HasPosition
            datas.append((flags, metadata.height, metadata.position,
                metadata.fee, metadata.date_updated, tx_hash))
        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("update %d tx metadatas: %s", len(entries),
                [ (hash_to_hex_str(a), b, TxFlags.to_repr(c)) for (a, b, c) in entries ])
            db.executemany(self.UPDATE_METADATA_MANY_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_flags(self, entries: Iterable[Tuple[bytes, TxFlags, TxFlags, int]],
            # tx_hash: bytes, flags: int, mask: int, date_updated: int,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = [ (mask, flags, date_updated, tx_hash)
            for (tx_hash, flags, mask, date_updated) in entries ]
        def _write(db: sqlite3.Connection) -> None:
            log_entries = [ (*entry[:3], hash_to_hex_str(entry[3])) for entry in datas ]
            self._logger.debug("update_flags %r", log_entries)
            db.executemany(self.UPDATE_FLAGS_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_descriptions(self, entries: Iterable[Tuple[str, bytes]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [ (date_updated,) + entry for entry in entries ]
        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("updating %d transaction descriptions", len(datas))
            db.executemany(self.UPDATE_DESCRIPTION_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_proof(self, entries: Iterable[Tuple[bytes, TxProof, int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = [ (self._pack_proof(proof), date_updated, TxFlags.HasProofData, tx_hash)
            for (tx_hash, proof, date_updated) in entries ]
        def _write(db: sqlite3.Connection) -> None:
            tx_ids = [ hash_to_hex_str(entry[0]) for entry in entries ]
            self._logger.debug("updating %d transaction proof '%s'", 1, tx_ids)
            db.executemany(self.UPDATE_PROOF_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, tx_hashes: Sequence[bytes],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = [(tx_hash,) for tx_hash in tx_hashes]
        def _write(db: sqlite3.Connection):
            self._logger.debug("deleting transactions %s", [hash_to_hex_str(b[0]) for b in datas])
            db.executemany(TransactionOutputTable.DELETE_TRANSACTION_SQL, datas)
            db.executemany(self.DELETE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)


class MasterKeyTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-masterkey"

    READ_SQL = ("SELECT masterkey_id, parent_masterkey_id, derivation_type, derivation_data "
        "FROM MasterKeys")
    UPDATE_SQL = "UPDATE MasterKeys SET derivation_data=?, date_updated=? WHERE masterkey_id=?"
    DELETE_SQL = "DELETE FROM MasterKeys WHERE masterkey_id=?"

    def read(self) -> List[MasterKeyRow]:
        cursor = self._db.execute(self.READ_SQL)
        rows = cursor.fetchall()
        cursor.close()
        return [ MasterKeyRow(*t) for t in rows ]

    def update_derivation_data(self, entries: Iterable[Tuple[bytes, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = []
        for t in entries:
            datas.append((t[0], date_updated, t[1]))
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, key_ids: Iterable[int],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        manyparams = [ (key_id,) for key_id in key_ids ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, manyparams)
        self._db_context.queue_write(_write, completion_callback)


class AccountTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-account"

    CREATE_SQL = ("INSERT INTO Accounts (account_id, default_masterkey_id, default_script_type, "
        "account_name, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    READ_SQL = ("SELECT account_id, default_masterkey_id, default_script_type, account_name "
        "FROM Accounts")
    UPDATE_MASTERKEY_SQL = ("UPDATE Accounts SET date_updated=?, default_masterkey_id=?, "
        "default_script_type=? WHERE account_id=?")
    UPDATE_NAME_SQL = ("UPDATE Accounts SET date_updated=?, account_name=? "
        "WHERE account_id=?")
    UPDATE_SCRIPT_TYPE_SQL = ("UPDATE Accounts SET date_updated=?, default_script_type=? "
        "WHERE account_id=?")
    DELETE_SQL = "DELETE FROM Accounts WHERE account_id=?"

    def create(self, entries: Iterable[AccountRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = [ (*t, timestamp, timestamp) for t in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def read(self) -> List[AccountRow]:
        cursor = self._db.execute(self.READ_SQL)
        rows = cursor.fetchall()
        cursor.close()
        return [ AccountRow(*t) for t in rows ]

    def update_masterkey(self, entries: Iterable[Tuple[Optional[int], ScriptType, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        date_updated = self._get_current_timestamp() if date_updated is None else date_updated
        datas = []
        for masterkey_id, script_type, account_id in entries:
            datas.append((date_updated, masterkey_id, script_type, account_id))
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_MASTERKEY_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_name(self, entries: Iterable[Tuple[int, str]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        date_updated = self._get_current_timestamp() if date_updated is None else date_updated
        datas = []
        for account_id, account_name in entries:
            datas.append((date_updated, account_name, account_id))
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_NAME_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_script_type(self, entries: Iterable[Tuple[ScriptType, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        date_updated = self._get_current_timestamp() if date_updated is None else date_updated
        datas = []
        for entry in entries:
            datas.append((date_updated, *entry))
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_SCRIPT_TYPE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, account_ids: Iterable[int],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        manyparams = [ (account_id,) for account_id in account_ids ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, manyparams)
        self._db_context.queue_write(_write, completion_callback)


class KeyInstanceTable(BaseDatabaseAPI):
    """
    `script_type` is deprecated and was moved to the `TransactionOutputs` table.
    """

    LOGGER_NAME = "db-table-keyinstance"

    READ_SQL = ("SELECT keyinstance_id, account_id, masterkey_id, derivation_type, "
        "derivation_data, derivation_data2, flags, description FROM KeyInstances")
    UPDATE_DERIVATION_DATA_SQL = ("UPDATE KeyInstances SET date_updated=?, derivation_data=? "
        "WHERE keyinstance_id=?")
    UPDATE_DESCRIPTION_SQL = ("UPDATE KeyInstances SET date_updated=?, description=? "
        "WHERE keyinstance_id=?")
    UPDATE_FLAGS_SQL = ("UPDATE KeyInstances SET date_updated=?, flags=? "
        "WHERE keyinstance_id=?")
    DELETE_SQL = "DELETE FROM KeyInstances WHERE keyinstance_id=?"

    # We cannot take Sequence in place of List, because Sequences are not addable.
    def read(self, mask: Optional[KeyInstanceFlag]=None, key_ids: Optional[List[int]]=None) \
            -> List[KeyInstanceRow]:
        results: List[KeyInstanceRow] = []
        def _collect_results(cursor: sqlite3.Cursor, results: List[KeyInstanceRow]) -> None:
            rows = cursor.fetchall()
            cursor.close()
            for row in rows:
                results.append(KeyInstanceRow(row[0], row[1], row[2], DerivationType(row[3]),
                    row[4], row[5], KeyInstanceFlag(row[6]), row[7]))

        query = self.READ_SQL
        params: List[int] = []
        if mask is not None:
            query += " WHERE (flags & ?) != 0"
            params = [ mask ]
        if key_ids:
            keyword = " AND" if len(params) else " WHERE"
            batch_size = SQLITE_MAX_VARS - len(params)
            while len(key_ids):
                batch_ids = key_ids[:batch_size]
                param_str = ",".join("?" for k in batch_ids)
                batch_query = query + f"{keyword} keyinstance_id IN ({param_str})"
                cursor = self._db.execute(batch_query, params + batch_ids)
                _collect_results(cursor, results)
                key_ids = key_ids[batch_size:]
        else:
            cursor = self._db.execute(query, params)
            _collect_results(cursor, results)

        return results

    def update_derivation_data(self, entries: Iterable[Tuple[bytes, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [(date_updated,) + entry for entry in entries]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_DERIVATION_DATA_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_descriptions(self, entries: Iterable[Tuple[str, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [(date_updated,) + entry for entry in entries]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_DESCRIPTION_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_flags(self, entries: Iterable[Tuple[KeyInstanceFlag, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [(date_updated,) + entry for entry in entries]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_FLAGS_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, key_ids: Iterable[int],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = [ (key_id,) for key_id in key_ids ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)



class TransactionOutputTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-txoutput"

    READ_SQL = ("SELECT tx_hash, tx_index, value, keyinstance_id, script_type, script_hash, flags "
        "FROM TransactionOutputs")
    UPDATE_FLAGS_SQL = ("UPDATE TransactionOutputs SET date_updated=?, flags=? "
        "WHERE tx_hash=? AND tx_index=?")
    DELETE_SQL = "DELETE FROM TransactionOutputs WHERE tx_hash=? AND tx_index=?"
    DELETE_TRANSACTION_SQL = "DELETE FROM TransactionOutputs WHERE tx_hash=?"

    # We cannot take Sequence in place of List, because Sequences are not addable.
    def read(self, mask: Optional[TransactionOutputFlag]=None,
            key_ids: Optional[List[int]]=None) -> Iterable[TransactionOutputRow]:
        results: List[TransactionOutputRow] = []

        query = self.READ_SQL
        params: List[int] = []
        if mask is not None:
            query += " WHERE (flags & ?) != 0"
            params = [ mask ]

        if key_ids:
            keyword = " AND" if len(params) else " WHERE"
            batch_size = SQLITE_MAX_VARS - len(params)
            while len(key_ids):
                batch_ids = key_ids[:batch_size]
                param_str = ",".join("?" for k in batch_ids)
                batch_query = query + f"{keyword} keyinstance_id IN ({param_str})"
                cursor = self._db.execute(batch_query, params + batch_ids)
                collect_results(TransactionOutputRow, cursor, results)
                key_ids = key_ids[batch_size:]
        else:
            cursor = self._db.execute(query, params)
            collect_results(TransactionOutputRow, cursor, results)

        return results

    def read_txokeys(self, txo_keys: List[TxoKeyType]) -> List[TransactionOutputRow]:
        results: List[TransactionOutputRow] = []

        # As we are dealing with expressions not a raw list of variables, we have to use the
        # least of the max variables and expression tree depth constraints.
        batch_size = min(SQLITE_MAX_VARS, SQLITE_EXPR_TREE_DEPTH) // 2
        condition_section = "tx_hash=? AND tx_index=?"
        while len(txo_keys):
            batch = txo_keys[:batch_size]
            batch_values: List[Any] = []
            for batch_entry in batch:
                batch_values.extend(batch_entry)
            conditions = [ condition_section ] * len(batch)
            batch_query = (self.READ_SQL +" WHERE "+ " OR ".join(conditions))
            cursor = self._db.execute(batch_query, batch_values)
            collect_results(TransactionOutputRow, cursor, results)
            txo_keys = txo_keys[batch_size:]

        return results

    def update_flags(self, entries: Iterable[Tuple[int, bytes, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [(date_updated,) + entry for entry in entries]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_FLAGS_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, entries: Iterable[Tuple[bytes, int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, entries)
        self._db_context.queue_write(_write, completion_callback)


class PaymentRequestTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-prequest"

    CREATE_SQL = ("INSERT INTO PaymentRequests "
        "(paymentrequest_id, keyinstance_id, state, value, expiration, description, date_created, "
        "date_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    READ_ALL_SQL = ("SELECT P.paymentrequest_id, P.keyinstance_id, P.state, P.value, P.expiration, "
        "P.description, P.date_created FROM PaymentRequests P")
    READ_ACCOUNT_SQL = (READ_ALL_SQL +" INNER JOIN KeyInstances K USING(keyinstance_id) "
        "WHERE K.account_id=?")
    UPDATE_SQL = ("UPDATE PaymentRequests SET date_updated=?, state=?, value=?, expiration=?, "
        "description=? WHERE paymentrequest_id=?")
    UPDATE_STATE_SQL = (f"""UPDATE PaymentRequests SET date_updated=?,
        state=(state&{~PaymentFlag.STATE_MASK})|? WHERE keyinstance_id=?""")
    DELETE_SQL = "DELETE FROM PaymentRequests WHERE paymentrequest_id=?"

    def create(self, entries: Iterable[PaymentRequestRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # Duplicate the last column for date_updated = date_created
        datas = [ (*t, t[-1]) for t in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def read_one(self, request_id: Optional[int]=None, keyinstance_id: Optional[int]=None) \
            -> Optional[PaymentRequestRow]:
        query = self.READ_ALL_SQL
        if request_id is not None:
            query += f" WHERE P.paymentrequest_id=?"
            params = [ request_id ]
        elif keyinstance_id is not None:
            query += f" WHERE P.keyinstance_id=?"
            params = [ keyinstance_id ]
        else:
            raise Exception("bad read, no id")
        cursor = self._db.execute(query, params)
        t = cursor.fetchone()
        cursor.close()
        if t is not None:
            return PaymentRequestRow(t[0], t[1], PaymentFlag(t[2]), t[3], t[4], t[5], t[6])
        return None

    def read(self, account_id: Optional[int]=None, flags: Optional[int]=None,
            mask: Optional[int]=None) -> List[PaymentRequestRow]:
        query = self.READ_ALL_SQL
        params: List[Any] = []
        conjunction = "WHERE"
        if account_id is not None:
            query = self.READ_ACCOUNT_SQL
            params.append(account_id)
            conjunction = "AND"
        clause, extra_params = flag_clause("state", flags, mask)
        if clause:
            query += f" {conjunction} {clause}"
            params.extend(extra_params)
            conjunction = "AND"
        cursor = self._db.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return [ PaymentRequestRow(t[0], t[1], PaymentFlag(t[2]), t[3], t[4], t[5], t[6])
            for t in rows ]

    def update(self,
            entries: Iterable[Tuple[Optional[PaymentFlag], Optional[int], int, Optional[str], int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [ (date_updated, *entry) for entry in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_state(self,
            entries: Iterable[Tuple[Optional[PaymentFlag], int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [ (date_updated, *entry) for entry in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_STATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, entries: Iterable[Tuple[int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, entries)
        self._db_context.queue_write(_write, completion_callback)


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
    date_created: int


class InvoiceAccountRow(NamedTuple):
    invoice_id: int
    payment_uri: str
    description: Optional[str]
    flags: PaymentFlag
    value: int
    date_expires: Optional[int]
    date_created: int


class InvoiceTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-invoice"

    # For recording the invoice after it is selected and the PaymentRequest is fetched.
    CREATE_SQL = ("INSERT INTO Invoices "
        "(account_id, tx_hash, payment_uri, description, invoice_flags, value, "
        "invoice_data, date_expires, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    READ_ALL_SQL = ("SELECT invoice_id, account_id, tx_hash, payment_uri, description, "
        "invoice_flags, value, invoice_data, date_expires, date_created FROM Invoices")
    # For the displayed listing of all the invoices for the current account.
    READ_ACCOUNT_SQL = ("SELECT invoice_id, payment_uri, description, invoice_flags, value, "
        "date_expires, date_created FROM Invoices WHERE account_id=?")
    UPDATE_DESCRIPTION_SQL = ("UPDATE Invoices SET date_updated=?, description=? "
        "WHERE invoice_id=?")
    UPDATE_FLAGS_SQL = ("UPDATE Invoices SET date_updated=?, invoice_flags=((invoice_flags&?)|?) "
        "WHERE invoice_id=?")
    UPDATE_TRANSACTION_SQL = "UPDATE Invoices SET date_updated=?, tx_hash=? WHERE invoice_id=?"
    CLEAR_TRANSACTION_SQL = "UPDATE Invoices SET date_updated=?, tx_hash=NULL WHERE tx_hash=?"
    DELETE_SQL = "DELETE FROM Invoices WHERE invoice_id=?"
    ARCHIVE_SQL = f"""
    UPDATE Invoices SET state=state|{PaymentFlag.ARCHIVED} WHERE invoice_id=%d
    """

    def create(self, entries: Iterable[InvoiceRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # Discard the first column for the id.
        # Duplicate the last column for date_updated = date_created
        datas = [ (*t[1:], t[-1]) for t in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def _read_one(self, query: str, params: List[Any]) -> Optional[InvoiceRow]:
        cursor = self._db.execute(query, params)
        t = cursor.fetchone()
        cursor.close()
        if t is not None:
            return InvoiceRow(t[0], t[1], t[2], t[3], t[4], PaymentFlag(t[5]), t[6], t[7], t[8],
                t[9])
        return None

    def read_one(self, invoice_id: Optional[int]=None, tx_hash: Optional[bytes]=None,
            payment_uri: Optional[str]=None) -> Optional[InvoiceRow]:
        query = self.READ_ALL_SQL
        params: List[Any]
        if invoice_id is not None:
            query += f" WHERE invoice_id=?"
            params = [ invoice_id ]
        elif tx_hash is not None:
            query += f" WHERE tx_hash=?"
            params = [ tx_hash ]
        elif payment_uri is not None:
            query += f" WHERE payment_uri=?"
            params = [ payment_uri ]
        else:
            raise Exception("bad read, no id")
        return self._read_one(query, params)

    def read_duplicate(self, value: int, payment_uri: str) -> Optional[InvoiceRow]:
        query = self.READ_ALL_SQL
        query += f" WHERE value=? AND payment_uri=?"
        params = [ value, payment_uri ]
        return self._read_one(query, params)

    def read_account(self, account_id: int, flags: Optional[int]=None,
            mask: Optional[int]=None) -> List[InvoiceAccountRow]:
        params: List[Any] = [ account_id ]
        query = self.READ_ACCOUNT_SQL
        # We keep the filtering in case we want to let the user define whether to show only
        # invoices in a certain state. If we never do that, we can remove this.
        clause, extra_params = flag_clause("invoice_flags", flags, mask)
        if clause:
            query += f" AND {clause}"
            params.extend(extra_params)
        cursor = self._db.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return [ InvoiceAccountRow(t[0], t[1], t[2], PaymentFlag(t[3]), t[4], t[5], t[6])
            for t in rows ]

    def clear_transaction(self, entries: Iterable[Tuple[bytes]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        payment_datas = [ (date_updated, *entry) for entry in entries ]
        def _write(db: sqlite3.Connection) -> None:
            nonlocal payment_datas
            db.executemany(self.CLEAR_TRANSACTION_SQL, payment_datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_transaction(self, entries: Iterable[Tuple[Optional[bytes], int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        payment_datas = [ (date_updated, *entry) for entry in entries ]
        def _write(db: sqlite3.Connection) -> None:
            nonlocal payment_datas
            db.executemany(self.UPDATE_TRANSACTION_SQL, payment_datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_description(self, entries: Iterable[Tuple[Optional[str], int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [ (date_updated, *entry) for entry in entries ]
        def _write(db: sqlite3.Connection) -> None:
            db.executemany(self.UPDATE_DESCRIPTION_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def update_flags(self, entries: Iterable[Tuple[PaymentFlag, PaymentFlag, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [ (date_updated, *entry) for entry in entries ]
        def _write(db: sqlite3.Connection) -> None:
            db.executemany(self.UPDATE_FLAGS_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, entries: Iterable[Tuple[int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        def _write(db: sqlite3.Connection) -> None:
            db.executemany(self.DELETE_SQL, entries)
        self._db_context.queue_write(_write, completion_callback)


class WalletEventRow(NamedTuple):
    event_id: int
    event_type: WalletEventType
    account_id: Optional[int]
    # NOTE(rt12): sqlite3 python module only allows custom typing if the column name is unique.
    event_flags: WalletEventFlag
    date_created: int


class WalletEventTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-walletevent"

    CREATE_SQL = ("INSERT INTO WalletEvents "
        "(event_id, event_type, account_id, event_flags, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?)")
    READ_ALL_SQL = ("SELECT event_id, event_type, account_id, event_flags, date_created "
        "FROM WalletEvents ORDER BY date_created")
    READ_ALL_MASK_SQL = ("SELECT event_id, event_type, account_id, event_flags, date_created "
        "FROM WalletEvents WHERE (event_flags&?)=? ORDER BY date_created")
    READ_ACCOUNT_SQL = ("SELECT event_id, event_type, account_id, event_flags, date_created "
        "FROM WalletEvents WHERE account_id=? ORDER BY date_created")
    READ_ACCOUNT_MASK_SQL = ("SELECT event_id, event_type, account_id, event_flags, date_created "
        "FROM WalletEvents WHERE (event_flags&?)=? AND account_id=? ORDER BY date_created")
    # READ_UNREAD_SQL = ("SELECT event_id, event_type, account_id, event_flags FROM WalletEvents "
    #     "WHERE event_flags1 ORDER BY date_created")
    UPDATE_FLAGS_SQL = "UPDATE WalletEvents SET date_updated=?, event_flags=? WHERE event_id=?"
    DELETE_SQL = "DELETE FROM WalletEvents WHERE event_id=?"

    def create(self, entries: Iterable[WalletEventRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # Duplicate the last column for date_updated = date_created
        datas = [ (*t, t[-1]) for t in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def read(self, account_id: Optional[int]=None,
            mask: WalletEventFlag=WalletEventFlag.NONE) -> List[WalletEventRow]:
        query = self.READ_ALL_SQL if mask == WalletEventFlag.NONE else self.READ_ALL_MASK_SQL
        params: List[int] = [] if mask == WalletEventFlag.NONE else [mask, mask]
        if account_id is not None:
            query = self.READ_ACCOUNT_SQL if mask == WalletEventFlag.NONE else \
                self.READ_ACCOUNT_MASK_SQL
            params.append(account_id)
        cursor = self._db.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return [ WalletEventRow(*t) for t in rows ]

    def update_flags(self, entries: Iterable[Tuple[WalletEventFlag, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [ (date_updated, *entry) for entry in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_FLAGS_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, entries: Iterable[Tuple[int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, entries)
        self._db_context.queue_write(_write, completion_callback)


class AccountTransactionRow(NamedTuple):
    account_id: int
    tx_hash: bytes
    flags: AccountTxFlags
    description: Optional[str]

class AccountTransactionBasicRow(NamedTuple):
    account_id: int
    tx_hash: bytes

class AccountTransactionDescriptionRow(NamedTuple):
    account_id: int
    tx_hash: bytes
    description: Optional[str]


class AccountTransactionTable(BaseDatabaseAPI):
    LOGGER_NAME = "db-table-accttx"

    CREATE_SQL = ("INSERT INTO AccountTransactions "
        "(account_id, tx_hash, flags, description, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?)")
    READ_BASIC_SQL = ("SELECT account_id, tx_hash FROM AccountTransactions AT")
    READ_DESCRIPTION_SQL = ("SELECT account_id, tx_hash, AT.description "
        "FROM AccountTransactions AT WHERE description IS NOT NULL")
    UPDATE_DESCRIPTION_SQL = "UPDATE AccountTransactions SET date_updated=?, description=? " \
        "WHERE account_id=? AND tx_hash=?"
    DELETE_SQL = "DELETE FROM AccountTransactions WHERE account_id=? AND tx_hash=?"

    def _get_many_common(self, query: str, flags: Optional[int]=None, mask: Optional[int]=None,
            account_id: Optional[int]=None, tx_hashes: Optional[Sequence[bytes]]=None) -> List[Any]:
        params = []
        clause, extra_params = flag_clause("AT.flags", flags, mask)

        conjunction = "WHERE"
        if " WHERE " in query:
            assert account_id is None, "This query is incompatible with account filtering"
            conjunction = "AND"

        if account_id is not None:
            query += f" {conjunction} AT.account_id=?"
            params.append(account_id)
            conjunction = "AND"

        if clause:
            query += f" {conjunction} {clause}"
            params.extend(extra_params)
            conjunction = "AND"

        if tx_hashes is None or not len(tx_hashes):
            cursor = self._db.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()
            return rows

        results = []
        batch_size = SQLITE_MAX_VARS - len(params)
        while len(tx_hashes):
            batch_tx_hashes = tx_hashes[:batch_size]
            batch_query = (query +" "+ conjunction +" "+
                "tx_hash IN ({0})".format(",".join("?" for k in batch_tx_hashes)))
            cursor = self._db.execute(batch_query, params + batch_tx_hashes) # type: ignore
            rows = cursor.fetchall()
            cursor.close()
            results.extend(rows)
            tx_hashes = tx_hashes[batch_size:]
        return results

    def create(self, entries: Iterable[AccountTransactionRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = [ (*t, timestamp, timestamp) for t in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    # def read(self, account_id: int) -> List[AccountTransactionRow]:
    #     query = self.READ_BASIC_SQL
    #     return [ AccountTransactionDescriptionRow(row) for row in
    #         self._get_many_common(query, account_id=account_id) ]

    def read_basic(self, account_id) -> List[AccountTransactionBasicRow]:
        query = self.READ_BASIC_SQL
        return [ AccountTransactionBasicRow(*row) for row in
            self._get_many_common(query, account_id=account_id) ]

    def read_descriptions(self, account_id: Optional[int]=None) \
            -> List[AccountTransactionDescriptionRow]:
        query = self.READ_DESCRIPTION_SQL
        return [ AccountTransactionDescriptionRow(*row) for row in
            self._get_many_common(query, account_id=account_id) ]

    def update_descriptions(self, entries: Iterable[Tuple[str, int, bytes]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [ (date_updated,) + entry for entry in entries ]
        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("updating %d transaction descriptions", len(datas))
            db.executemany(self.UPDATE_DESCRIPTION_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)


class AddTransactionRow(NamedTuple):
    tx_hash: bytes
    version: Optional[int]
    locktime: Optional[int]
    tx_bytes: Optional[bytes]
    flags: TxFlags
    block_height: Optional[int]
    block_position: Optional[int]
    description: Optional[str]
    fee: Optional[int]
    date_created: int
    date_updated: int


class AddTransactionInputRow(NamedTuple):
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


class AddTransactionOutputRow(NamedTuple):
    tx_hash: bytes
    tx_index: int
    value: int
    keyinstance_id: Optional[int]
    script_type: ScriptType
    flags: TransactionOutputFlag
    script_hash: bytes
    script_offset: int
    script_length: int
    date_created: int
    date_updated: int


SpendConflictType = Tuple[bytes, int]


class AsynchronousFunctions(BaseDatabaseAPI):
    LOGGER_NAME: str = "async-functions"

    def _insert_transaction(self, db: sqlite3.Connection, tx_row: AddTransactionRow,
            txi_rows: List[AddTransactionInputRow], txo_rows: List[TransactionOutputRow]) -> Any:
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
        assert (tx_row.flags & TxFlags.HasByteData) == 0, "this flag is not applicable"

        # Constraint: tx_hash should be unique.
        db.execute("INSERT INTO Transactions (tx_hash, tx_data, flags, "
            "block_height, block_position, fee_value, version, locktime, description, "
            "date_created, date_updated) VALUES (?,?,?,?,?,?,?,?,?,?,?)", tx_row)

        # Constraint: (tx_hash, tx_index) should be unique.
        db.executemany("INSERT INTO TransactionInputs (tx_hash, txi_index, spent_tx_hash, "
            "spent_txo_index, sequence, flags, script_offset, script_length, date_created, "
            "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?)", txi_rows)

        # Constraint: (tx_hash, tx_index) should be unique.
        db.executemany("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, "
            "script_type, flags, script_hash, script_offset, script_length, date_created, "
            "date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)", txo_rows)

        return True

    def _link_transaction_key_usage(self, db: sqlite3.Connection,
            txo_rows: List[TransactionOutputRow]) -> int:
        timestamp = self._get_current_timestamp()

        # Link the transaction outputs to key usage.
        rowcount = update_rows_by_id(bytes, db, "UPDATE TransactionOutputs TXO "
            "SET TXO.keyinstance_id=KIS.keyinstance_id, TXO.script_type=KIS.script_type, "
                "TXO.date_updated=? "
            "FROM KeyInstanceScripts KIS "
            "WHERE TXO.script_hash = KIS.script_hash AND KIS.script_hash IN ({})", [timestamp],
            tuple(t.script_hash for t in txo_rows))
        return rowcount

    def _create_account_transaction_mappings(self, db: sqlite3.Connection, tx_hash: bytes) -> int:
        timestamp = self._get_current_timestamp()

        # Assuming transactions are mapped to key usage, we can insert transaction mappings to
        # accounts they are associated with. The reason we do this is that we want per-account
        # transaction state.
        cursor = db.execute("INSERT INTO AccountTransactions "
            "(tx_hash, account_id, date_created, date_updated) "
            "WITH transaction_accounts(tx_hash, account_id) AS ("
                "SELECT DISTINCT KI.account_id "
                "FROM TransactionOutputs TXO "
                "INNER JOIN KeyInstances KI ON KI.keyinstance_id = TXO.keyinstance_id "
                "WHERE TXO.tx_hash=? "
                "UNION "
                "SELECT DISTINCT KI.account_id "
                "FROM TransactionInputs TXI "
                "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash = TXI.spent_tx_hash "
                "INNER JOIN KeyInstances KI ON KI.keyinstance_id = TXO.keyinstance_id "
                "WHERE TXI.spent_tx_hash=? "
            ")"
            "SELECT ?, TA.account_id, ?, ? "
            "FROM transaction_accounts TA",
            (tx_hash, tx_hash, tx_hash, timestamp, timestamp))
        return cursor.rowcount

    def _spend_parent_transaction_outputs(self, db: sqlite3.Connection, tx_hash: bytes,
            tx_deltas: Dict[Tuple[bytes, int], int]) -> List[SpendConflictType]:
        """
        Spend all parent transaction outputs.

        This can be considered ordered spending, where a new transaction spends coins from
        parent transactions the wallet should already have. It is expected that any conflicts
        in the form of this transaction spending coins already spent by other transactions should
        be identified.
        """
        timestamp = self._get_current_timestamp()
        cursor = db.execute(
            "SELECT TXO.tx_hash, TXO.tx_index, TXO.flags, TXO.keyinstance_id, TXO.value "
            "FROM TransactionInputs TXI "
            "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash = TXI.spent_tx_hash AND "
                "TXO.tx_index = TXI.spent_txo_index "
            "INNER JOIN KeyInstances KI ON KI.keyinstance_id = TXO.keyinstance_id "
            "WHERE TXI.tx_hash=?", (tx_hash,))

        spend_conflicts: List[SpendConflictType] = []
        spent_rows: List[Tuple[int, bytes, int]] = []
        for spent_tx_hash, spent_tx_index, raw_txo_flags, txo_keyinstance_id, txo_value \
                in cursor.fetchall():
            if raw_txo_flags & TransactionOutputFlag.IS_SPENT:
                # TODO(nocheckin) . . .
                spend_conflicts.append((spent_tx_hash, spent_tx_index))
            else:
                spent_rows.append((timestamp, spent_tx_hash, spent_tx_index))
                tx_deltas[(tx_hash, txo_keyinstance_id)] -= txo_value

        # If there were no spend conflicts, we can consider ourselves to be valid and can mark
        # the spent coins as spent.
        if not spend_conflicts:
            clear_bits = TransactionOutputFlag.IS_ALLOCATED
            set_bits = TransactionOutputFlag.IS_SPENT
            cursor = db.executemany("UPDATE TransactionOutputs "
                f"SET date_updated=?, flags=(flags&{~clear_bits})|{set_bits}"
                f"WHERE (flags&{set_bits})=0 AND tx_hash=? AND TXO.tx_index=?", spent_rows)
            # Detect if we did not update the rows we expected to update.
            if cursor.rowcount != len(spent_rows):
                self._logger.error("Failed marking parent outputs as spent, expected to update "
                    "%d outputs, actually updated %d outputs", len(spent_rows), cursor.rowcount)

        return spend_conflicts

    def _spend_child_transaction_outputs(self, db: sqlite3.Connection, tx_hash: bytes,
            tx_deltas: Dict[Tuple[bytes, int], int]) -> Any:
        """
        Spend all child transaction outputs.

        This can be considered unordered spending, where the child transactions arrived before
        this transaction which is their parent transaction.
        """
        cursor = db.execute("SELECT TXI.tx_hash, TXI.txi_index, TXI.flags, TXO.keyinstance_id, "
                "TXO.value "
            "FROM TransactionOutputs TXO "
            "INNER JOIN TransactionInputs TXI ON TXI.spent_tx_hash = TXO.tx_hash "
                "AND TXO.tx_hash = ?", (tx_hash,))
        for spending_tx_hash, txi_index, raw_txi_flags, txo_keyinstance_id, txo_value \
                in cursor.fetchall():
            tx_deltas[(spending_tx_hash, txo_keyinstance_id)] -= txo_value

    def _link_transaction(self, db: sqlite3.Connection, tx_row: AddTransactionRow,
            txi_rows: List[AddTransactionInputRow], txo_rows: List[TransactionOutputRow]) -> Any:
        """
        Given this happens in a sequential writer thread we know that there cannot be
        race conditions in the database where transactions being added in parallel might miss
        spends. However, in real world usage that should only ever be ordered spends. Unordered
        spends should only occur in synchronisation, and we can special case that at a higher
        level.
        """
        timestamp = self._get_current_timestamp()

        # Fill in `keyinstance_id` and `script_type` for the outputs.
        _key_usage_count = self._link_transaction_key_usage(db, txo_rows)

        # Ensure there are per-account rows for this transaction.
        _account_count = self._create_account_transaction_mappings(db, tx_row.tx_hash)

        db.execute("SAVEPOINT spends")

        tx_deltas: Dict[Tuple[bytes, int], int] = defaultdict(int)
        spend_conflicts = self._spend_parent_transaction_outputs(db, tx_row.tx_hash, tx_deltas)
        if not spend_conflicts:
            self._spend_child_transaction_outputs(db, tx_row.tx_hash, tx_deltas)

        if spend_conflicts:
            db.execute("ROLLBACK TO SAVEPOINT spends")

            # TODO(nocheckin) need to work out the correct and complete model for conflicting
            # transactions. An example is that conflicting transactions should not be considered
            # or affected in queries.
            db.execute("UPDATE Transactions "
                f"SET flags=flags|{TxFlags.Conflicting}"
                "WHERE tx_hash=?", (tx_row.tx_hash,))

        pass
        # List what needs to be changed:
        # - TransactionInputs
        #   - detect spends of parent transactions that are already present
        # - TransactionOutputs
        #   - DONE update column: keyinstance_id
        #   - DONE update column: script_type
        #   - detect spends by child transactions that are already present
        # - AccountTransactions
        #   - DONE insert mapping for detected key usage
        # - TransactionDeltas
        #   - insert receipts from this transaction.
        #   - insert spends of any parent transactions.
        #   - insert spends by any child transactions.
        pass

        # Also needs to detect conflicts and rollback any linkage.

    def _import_transaction(self, db: sqlite3.Connection, tx_row: AddTransactionRow,
            txi_rows: List[AddTransactionInputRow], txo_rows: List[TransactionOutputRow]) -> Any:
        """
        If any constraints are violated, an exception will be raised out of this function
        and should be caught and rollback this transaction.
        """
        self._insert_transaction(db, tx_row, txi_rows, txo_rows)
        self._link_transaction(db, tx_row, txi_rows, txo_rows)
        # Returning commits the transaction non-rolled back parts of the transaction.

    async def import_transaction(self, tx_row: AddTransactionRow,
            txi_rows: List[AddTransactionInputRow], txo_rows: List[AddTransactionOutputRow]) -> Any:
        """
        Wrap the database operations required to import a transaction so the processing is
        offloaded to the SQLite writer thread while this task is blocked.
        """
        # TODO(nocheckin) work out what we are returning and update the return type.
        return await self._db_context.run_in_thread(self._import_transaction, tx_row, txi_rows,
            txo_rows)
