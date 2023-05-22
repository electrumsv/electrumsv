from io import BytesIO
import json
try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.9.13 builds and version of 3.37.2.
    import sqlite3 # type: ignore
import time
from typing import Any, Dict, Iterable, NamedTuple, Optional, List, Sequence, Tuple, Type, TypeVar

import bitcoinx
from bitcoinx import hash_to_hex_str

from ..constants import (TxFlags, ScriptType, DerivationType, TransactionOutputFlag,
    KeyInstanceFlag, PaymentFlag, WalletEventFlag, WalletEventType)
from ..logs import logs
from .sqlite_support import SQLITE_EXPR_TREE_DEPTH, SQLITE_MAX_VARS, DatabaseContext, \
    CompletionCallbackType
from ..types import TxoKeyType


# TODO(rt12) The rows should be turned into NamedTuples?
# TODO(rt12) Do not read the `date_created` / `date_updated` columns for non-transactions. They
#            are never used and are good for debugging purposes only.

__all__ = [
    "MissingRowError", "DataPackingError", "TransactionTable", "TransactionOutputTable",
    "TransactionDeltaTable", "MasterKeyTable", "KeyInstanceTable", "WalletDataTable",
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


T = TypeVar('T')

def flag_clause(column: str, flags: Optional[T], mask: Optional[T]) -> Tuple[str, List[T]]:
    if flags is None:
        if mask is None:
            return "", []
        return f"({column} & ?) != 0", [mask]

    if mask is None:
        return f"({column} & ?) != 0", [flags]

    return f"({column} & ?) == ?", [mask, flags]

def collect_results(result_type: Type[T], cursor: sqlite3.Cursor, results: List[T]) -> None:
    rows = cursor.fetchall()
    cursor.close()
    results.extend(result_type(*row) for row in rows)


def read_rows_by_id(return_type: Type[T], db: sqlite3.Connection, sql: str, params: List[Any], \
        ids: Sequence[int]) -> List[T]:
    results = []
    batch_size = SQLITE_MAX_VARS - len(params)
    while len(ids):
        batch_ids = ids[:batch_size]
        query = sql.format(",".join("?" for k in batch_ids))
        cursor = db.execute(query, params + batch_ids) # type: ignore
        rows = cursor.fetchall()
        cursor.close()
        results.extend(rows)
        ids = ids[batch_size:]
    return [ return_type(*t) for t in results ]


class BaseWalletStore:
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

    def _get_column_types(self, db: sqlite3.Connection, table_name: str) -> Dict[str, Any]:
        column_types = {}
        for row in db.execute(f"PRAGMA table_info({table_name});"):
            _discard, column_name, column_type, _discard, _discard, _discard = row
            column_types[column_name] = column_type
        return column_types

    def _get_current_timestamp(self) -> int:
        "Get the current timestamp in a form suitable for database column storage."
        return int(time.time())


class WalletDataRow(NamedTuple):
    key: str
    value: Any


class WalletDataTable(BaseWalletStore):
    LOGGER_NAME = "db-table-walletdata"

    CREATE_SQL = ("INSERT INTO WalletData (key, value, date_created, date_updated) "
        "VALUES (?, ?, ?, ?)")
    READ_SQL = "SELECT key, value FROM WalletData"
    UPDATE_SQL = "UPDATE WalletData SET value=?, date_updated=? WHERE key=?"
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

MAGIC_UNTOUCHED_BYTEDATA = b''

class TxProof(NamedTuple):
    position: int
    branch: Sequence[bytes]

class TransactionRow(NamedTuple):
    tx_hash: bytes
    tx_data: TxData
    tx_bytes: Optional[bytes]
    flags: TxFlags
    description: Optional[str]


class TransactionTable(BaseWalletStore):
    LOGGER_NAME = "db-table-tx"

    CREATE_SQL = ("INSERT INTO Transactions (tx_hash, tx_data, flags, "
        "block_height, block_position, fee_value, description, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
    READ_DESCRIPTION_SQL = ("SELECT tx_hash, description FROM Transactions T "
        "WHERE description IS NOT NULL")
    READ_MANY_BASE_SQL = ("SELECT tx_hash, tx_data, flags, block_height, block_position, "
        "fee_value, date_created, date_updated FROM Transactions T")
    READ_METADATA_BASE_SQL = ("SELECT flags, block_height, block_position, fee_value, "
        "date_created, date_updated FROM Transactions T WHERE tx_hash=?")
    READ_METADATA_MANY_BASE_SQL = ("SELECT tx_hash, flags, block_height, block_position, "
        "fee_value, date_created, date_updated FROM Transactions T")
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
    def _apply_flags(data: TxData, flags: TxFlags) -> TxFlags:
        flags &= ~TxFlags.METADATA_FIELD_MASK
        if data.height is not None:
            flags |= TxFlags.HasHeight
        if data.fee is not None:
            flags |= TxFlags.HasFee
        if data.position is not None:
            flags |= TxFlags.HasPosition
        return flags

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
        clause, extra_params = flag_clause("flags", flags, mask)

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

    def create(self, entries: List[TransactionRow], completion_callback: Optional[
            CompletionCallbackType]=None) -> None:
        datas = []
        size_hint = 0
        for tx_hash, metadata, bytedata, flags, description in entries:
            assert type(tx_hash) is bytes
            flags &= ~TxFlags.HasByteData
            if bytedata is not None:
                flags |= TxFlags.HasByteData
                size_hint += len(bytedata)
            flags = self._apply_flags(metadata, flags)
            assert metadata.date_added is not None and metadata.date_updated is not None
            datas.append((tx_hash, bytedata, flags, metadata.height, metadata.position,
                metadata.fee, description, metadata.date_added, metadata.date_updated))

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("add %d transactions", len(datas))
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback, size_hint)

    def read(self, flags: Optional[TxFlags]=None, mask: Optional[TxFlags]=None,
            tx_hashes: Optional[Sequence[bytes]]=None, account_id: Optional[int]=None) \
            -> List[Tuple[bytes, Optional[bytes], TxFlags, TxData]]:
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
        # This can be used directly as the query results map to the return type.
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
        size_hint = 0
        for tx_hash, metadata, bytedata, flags in entries:
            assert type(tx_hash) is bytes
            assert type(bytedata) is bytes or bytedata is None
            flags = self._apply_flags(metadata, flags)
            if bytedata == MAGIC_UNTOUCHED_BYTEDATA:
                # This is where we are updating a row which has existing bytedata that is not
                # changing, but we don't want to still have to  pass it into the update call to
                # avoid changing it.
                assert flags & TxFlags.HasByteData != 0, f"{hash_to_hex_str(tx_hash)} flag wrong"
                metadata_rows.append((flags, metadata.height, metadata.position,
                    metadata.fee, metadata.date_updated, tx_hash))
            else:
                if bytedata is None:
                    assert flags & TxFlags.HasByteData == 0, f"{hash_to_hex_str(tx_hash)} no flag"
                else:
                    assert flags & TxFlags.HasByteData != 0, f"{hash_to_hex_str(tx_hash)} flag"
                    size_hint += len(bytedata)
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

        self._db_context.queue_write(_write, completion_callback, size_hint)

    def update_metadata(self, entries: List[Tuple[bytes, TxData, TxFlags]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = []
        for tx_hash, metadata, flags in entries:
            assert type(tx_hash) is bytes
            datas.append((self._apply_flags(metadata, flags), metadata.height, metadata.position,
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
        size_hint = sum(len(t[0]) for t in datas)
        def _write(db: sqlite3.Connection) -> None:
            tx_ids = [ hash_to_hex_str(entry[0]) for entry in entries ]
            self._logger.debug("updating %d transaction proof '%s'", 1, tx_ids)
            db.executemany(self.UPDATE_PROOF_SQL, datas)
        self._db_context.queue_write(_write, completion_callback, size_hint)

    def delete(self, tx_hashes: Sequence[bytes],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = [(tx_hash,) for tx_hash in tx_hashes]
        def _write(db: sqlite3.Connection):
            self._logger.debug("deleting transactions %s", [hash_to_hex_str(b[0]) for b in datas])
            db.executemany(TransactionDeltaTable.DELETE_TRANSACTION_SQL, datas)
            db.executemany(TransactionOutputTable.DELETE_TRANSACTION_SQL, datas)
            db.executemany(self.DELETE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)


class MasterKeyRow(NamedTuple):
    masterkey_id: int
    parent_masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes


class MasterKeyTable(BaseWalletStore):
    LOGGER_NAME = "db-table-masterkey"

    CREATE_SQL = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    READ_SQL = ("SELECT masterkey_id, parent_masterkey_id, derivation_type, derivation_data "
        "FROM MasterKeys")
    UPDATE_SQL = "UPDATE MasterKeys SET derivation_data=?, date_updated=? WHERE masterkey_id=?"
    DELETE_SQL = "DELETE FROM MasterKeys WHERE masterkey_id=?"

    def create(self, entries: Iterable[MasterKeyRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = [ (*t, timestamp, timestamp) for t in entries ]
        size_hint = sum(len(t[3]) for t in entries)
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback, size_hint)

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
        size_hint = 0
        for t in entries:
            datas.append((t[0], date_updated, t[1]))
            size_hint += len(t[0])
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback, size_hint)

    def delete(self, key_ids: Iterable[int],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        manyparams = [ (key_id,) for key_id in key_ids ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, manyparams)
        self._db_context.queue_write(_write, completion_callback)


class AccountRow(NamedTuple):
    account_id: int
    default_masterkey_id: Optional[int]
    default_script_type: ScriptType
    account_name: str


class AccountTable(BaseWalletStore):
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


class KeyInstanceRow(NamedTuple):
    keyinstance_id: int
    account_id: int
    masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes
    script_type: ScriptType
    flags: KeyInstanceFlag
    description: Optional[str]


class KeyInstanceTable(BaseWalletStore):
    LOGGER_NAME = "db-table-keyinstance"

    CREATE_SQL = ("INSERT INTO KeyInstances "
        "(keyinstance_id, account_id, masterkey_id, derivation_type, derivation_data, "
        "script_type, flags, description, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    READ_SQL = ("SELECT keyinstance_id, account_id, masterkey_id, derivation_type, "
        "derivation_data, script_type, flags, description FROM KeyInstances")
    UPDATE_DERIVATION_DATA_SQL = ("UPDATE KeyInstances SET date_updated=?, derivation_data=? "
        "WHERE keyinstance_id=?")
    UPDATE_DESCRIPTION_SQL = ("UPDATE KeyInstances SET date_updated=?, description=? "
        "WHERE keyinstance_id=?")
    UPDATE_FLAGS_SQL = ("UPDATE KeyInstances SET date_updated=?, flags=? "
        "WHERE keyinstance_id=?")
    UPDATE_SCRIPT_TYPE_SQL = ("UPDATE KeyInstances SET date_updated=?, script_type=? "
        "WHERE keyinstance_id=?")

    DELETE_SQL = "DELETE FROM KeyInstances WHERE keyinstance_id=?"

    def create(self, entries: Iterable[KeyInstanceRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = [ (*t, timestamp, timestamp) for t in entries]
        size_hint = sum(len(t[4]) for t in entries)
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback, size_hint)

    # We cannot take Sequence in place of List, because Sequences are not addable.
    def read(self, mask: Optional[KeyInstanceFlag]=None, key_ids: Optional[List[int]]=None) \
            -> List[KeyInstanceRow]:
        results: List[KeyInstanceRow] = []
        def _collect_results(cursor: sqlite3.Cursor, results: List[KeyInstanceRow]) -> None:
            rows = cursor.fetchall()
            cursor.close()
            for row in rows:
                results.append(KeyInstanceRow(row[0], row[1], row[2], DerivationType(row[3]),
                    row[4], ScriptType(row[5]), KeyInstanceFlag(row[6]), row[7]))

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
        size_hint = sum(len(entry[0]) for entry in entries)
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

    def update_script_types(self, entries: Iterable[Tuple[ScriptType, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [(date_updated,) + entry for entry in entries]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_SCRIPT_TYPE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, key_ids: Iterable[int],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = [ (key_id,) for key_id in key_ids ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)


class TransactionOutputRow(NamedTuple):
    tx_hash: bytes
    tx_index: int
    value: int
    keyinstance_id: int
    flags: TransactionOutputFlag


class TransactionOutputTable(BaseWalletStore):
    LOGGER_NAME = "db-table-txoutput"

    CREATE_SQL = ("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, "
        "flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)")
    READ_SQL = "SELECT tx_hash, tx_index, value, keyinstance_id, flags FROM TransactionOutputs"
    UPDATE_FLAGS_SQL = ("UPDATE TransactionOutputs SET date_updated=?, flags=? "
        "WHERE tx_hash=? AND tx_index=?")
    DELETE_SQL = "DELETE FROM TransactionOutputs WHERE tx_hash=? AND tx_index=?"
    DELETE_TRANSACTION_SQL = "DELETE FROM TransactionOutputs WHERE tx_hash=?"

    def create(self, entries: Iterable[TransactionOutputRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = [ (*t, timestamp, timestamp) for t in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

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
            batch_query = self.READ_SQL +" WHERE "+ " OR ".join(conditions)
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


class TransactionDeltaSumRow(NamedTuple):
    account_id: int
    total: int
    match_count: int

class TransactionDeltaRow(NamedTuple):
    tx_hash: bytes
    keyinstance_id: int
    value_delta: int

class TransactionKeyHistoryRow(NamedTuple):
    tx_hash: bytes
    keyinstance_id: int

class TransactionDeltaHistoryRow(NamedTuple):
    tx_hash: bytes
    tx_flags: TxFlags
    value_delta: int

class TransactionDeltaKeySummaryRow(NamedTuple):
    keyinstance_id: int
    masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes
    script_type: ScriptType
    flags: KeyInstanceFlag
    date_updated: int
    total_value: int
    match_count: int


class TransactionDeltaTable(BaseWalletStore):
    LOGGER_NAME = "db-table-txdelta"

    CREATE_SQL_BASE = ("INTO TransactionDeltas "
        "(tx_hash, keyinstance_id, value_delta, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?)")
    CREATE_SQL = "INSERT "+ CREATE_SQL_BASE
    CREATE_OR_IGNORE_SQL = "INSERT OR IGNORE "+ CREATE_SQL_BASE
    READ_SQL = ("SELECT KI.account_id, TOTAL(TD.value_delta), COUNT(TD.value_delta) "
        "FROM TransactionDeltas AS TD "
        "INNER JOIN KeyInstances AS KI ON TD.keyinstance_id = KI.keyinstance_id AND "
            "TD.tx_hash = ? "
        "GROUP BY KI.account_id")
    READ_ACCOUNT_SQL = ("SELECT KI.account_id, TOTAL(TD.value_delta), COUNT(TD.value_delta) "
        "FROM TransactionDeltas AS TD "
        "INNER JOIN KeyInstances AS KI ON TD.keyinstance_id = KI.keyinstance_id AND "
            "KI.account_id = ? AND TD.tx_hash = ? "
        "GROUP BY KI.account_id")
    READ_ACCOUNT_TXFILTERING_SQL_1 = ("SELECT KI.account_id, TOTAL(TD.value_delta), "
            "COUNT(DISTINCT TD.tx_hash) "
        "FROM Transactions AS T "
        "INNER JOIN TransactionDeltas AS TD ON TD.tx_hash = T.tx_hash "
        "INNER JOIN KeyInstances AS KI ON TD.keyinstance_id = KI.keyinstance_id AND "
            "KI.account_id = ? ")
    READ_ACCOUNT_TXFILTERING_SQL_2 = "GROUP BY KI.account_id"
    READ_DESCRIPTIONS_SQL = ("SELECT T.tx_hash, T.description  "
        "FROM TransactionDeltas AS TD "
        "INNER JOIN KeyInstances AS KI ON TD.keyinstance_id = KI.keyinstance_id AND "
            "KI.account_id = ?"
        "INNER JOIN Transactions AS T ON TD.tx_hash = T.tx_hash "
        "WHERE T.description IS NOT NULL "
        "GROUP BY T.tx_hash")
    READ_HISTORY_SQL = ("SELECT T.tx_hash, T.flags, TOTAL(TD.value_delta) "
        "FROM Transactions T "
        "INNER JOIN TransactionDeltas AS TD ON T.tx_hash = TD.tx_hash "
        "INNER JOIN KeyInstances AS KI ON TD.keyinstance_id = KI.keyinstance_id AND "
            "KI.account_id = ? "
        "GROUP BY T.tx_hash")
    READ_HISTORY_DOMAIN_SQL = ("SELECT T.tx_hash, T.flags, TOTAL(TD.value_delta) "
        "FROM Transactions T "
        "INNER JOIN TransactionDeltas AS TD ON T.tx_hash = TD.tx_hash "
        "INNER JOIN KeyInstances AS KI ON TD.keyinstance_id = KI.keyinstance_id AND "
            "KI.account_id = ? AND TD.keyinstance_id IN ({}) "
        "GROUP BY T.tx_hash")
    READ_KEY_SUMMARY_SQL = ("SELECT KI.keyinstance_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.script_type, KI.flags, KI.date_updated, "
            "TOTAL(TD.value_delta), COUNT(TD.value_delta) "
        "FROM KeyInstances AS KI "
        "LEFT JOIN TransactionDeltas TD ON TD.keyinstance_id = KI.keyinstance_id "
        "WHERE KI.account_id = ? "
        "GROUP BY KI.keyinstance_id")
    READ_KEY_SUMMARY_DOMAIN_SQL = ("SELECT KI.keyinstance_id, KI.masterkey_id, KI.derivation_type, "
            "KI.derivation_data, KI.script_type, KI.flags, KI.date_updated, "
            "TOTAL(TD.value_delta), COUNT(TD.value_delta) "
        "FROM KeyInstances AS KI "
        "LEFT JOIN TransactionDeltas TD ON TD.keyinstance_id = KI.keyinstance_id "
        "WHERE KI.account_id = ? AND KI.keyinstance_id IN ({}) "
        "GROUP BY KI.keyinstance_id")
    READ_PAID_KEYS_SQL = ("SELECT TD.keyinstance_id "
        "FROM TransactionDeltas TD "
        "INNER JOIN PaymentRequests AS PR ON TD.keyinstance_id = PR.keyinstance_id "
        "INNER JOIN KeyInstances AS KI ON TD.keyinstance_id = KI.keyinstance_id AND "
            "KI.account_id = ? AND TD.keyinstance_id IN ({}) AND "
            f"(PR.state & {PaymentFlag.UNPAID}) != 0 "
        "GROUP BY TD.keyinstance_id "
        "HAVING PR.value IS NULL OR PR.value <= TOTAL(TD.value_delta)")
    READ_KEY_HISTORY_SQL = ("SELECT TD.tx_hash, TD.keyinstance_id "
        "FROM TransactionDeltas AS TD "
        "INNER JOIN KeyInstances AS KI ON TD.keyinstance_id = KI.keyinstance_id AND "
            "KI.account_id = ?"
        "GROUP BY TD.tx_hash, TD.keyinstance_id")
    READ_CANDIDATE_USED_KEYS = f"""
        WITH active_keys AS (
                SELECT keyinstance_id
                FROM KeyInstances
                WHERE flags & {KeyInstanceFlag.ACTIVE_MASK} = {KeyInstanceFlag.IS_ACTIVE}
                  AND account_id = ?
            ),
            tx_history_table AS (
                SELECT TD.keyinstance_id, tx_hash, value_delta
                FROM TransactionDeltas AS TD
                JOIN active_keys ON TD.keyinstance_id = active_keys.keyinstance_id
            ),
            settled_history AS (
                SELECT tx_history_table.keyinstance_id, tx_history_table.value_delta
                FROM Transactions AS TX
                JOIN tx_history_table ON TX.tx_hash = tx_history_table.tx_hash
                WHERE TX.flags & {TxFlags.StateSettled} = {TxFlags.StateSettled})

            SELECT keyinstance_id
            FROM settled_history
            GROUP BY keyinstance_id HAVING SUM(value_delta) == 0;"""
    DEACTIVATE_KEYINSTANCE_FLAGS = f"""
        UPDATE KeyInstances
        SET date_updated=?, flags=flags&{KeyInstanceFlag.INACTIVE_MASK}
        """ + "WHERE keyinstance_id IN ({0})"
    READ_ALL_SQL = "SELECT tx_hash, keyinstance_id, value_delta FROM TransactionDeltas"
    UPDATE_SQL = ("UPDATE TransactionDeltas SET date_updated=?, value_delta=? "
        "WHERE tx_hash=? AND keyinstance_id=?")
    UPDATE_RELATIVE_SQL = ("UPDATE TransactionDeltas SET date_updated=?, value_delta=value_delta+? "
        "WHERE tx_hash=? AND keyinstance_id=?")
    # self._UPSERT_SQL = (self._CREATE_SQL +" ON CONFLICT(keyinstance_id, tx_hash) DO UPDATE "+
    #     "SET value_delta=excluded.value_delta, date_updated=excluded.date_updated")
    DELETE_SQL = "DELETE FROM TransactionDeltas WHERE tx_hash=? AND keyinstance_id=?"
    DELETE_TRANSACTION_SQL = "DELETE FROM TransactionDeltas WHERE tx_hash=?"

    def _get_many_common(self, query: str, base_params: Optional[List[Any]]=None,
            tx_hashes: Optional[Sequence[bytes]]=None) -> List[Any]:
        params = base_params[:] if base_params is not None else []

        if tx_hashes is None or not len(tx_hashes):
            cursor = self._db.execute(query, params)
            rows = cursor.fetchall()
            cursor.close()
            return rows

        conjunction = "WHERE"
        if " WHERE " in query:
            conjunction = "AND"

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

    def update_used_keys(self, account_id: int,
            completion_callback: Optional[CompletionCallbackType]=None) -> Sequence[Tuple[int]]:
        params = [account_id]
        cursor = self._db.execute(self.READ_CANDIDATE_USED_KEYS, params)  # type: ignore
        key_id_rows = cursor.fetchall()
        cursor.close()

        key_ids = [key_id[0] for key_id in key_id_rows]
        keys = key_ids.copy()

        def _write(db: sqlite3.Connection):
            nonlocal keys
            timestamp = self._get_current_timestamp()
            params = [timestamp]
            batch_size = SQLITE_MAX_VARS - len(params)
            while len(keys):
                batch_keys = keys[:batch_size]
                batch_query = (
                    self.DEACTIVATE_KEYINSTANCE_FLAGS.format(",".join("?" for k in batch_keys)))
                db.execute(batch_query, params + batch_keys) # type: ignore
                keys = keys[batch_size:]
        self._db_context.queue_write(_write, completion_callback)

        return key_ids

    def create(self, entries: Iterable[TransactionDeltaRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = [ (*t, timestamp, timestamp) for t in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.CREATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def create_or_update_relative_values(self, entries: Iterable[TransactionDeltaRow],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        update_datas = [ (timestamp, r.value_delta, r.tx_hash, r.keyinstance_id) for r in entries ]
        insert_datas = [ (*t, timestamp, timestamp) for t in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_RELATIVE_SQL, update_datas)
            db.executemany(self.CREATE_OR_IGNORE_SQL, insert_datas)
        self._db_context.queue_write(_write, completion_callback)

    def read(self) -> List[TransactionDeltaRow]:
        cursor = self._db.execute(self.READ_ALL_SQL)
        rows = cursor.fetchall()
        cursor.close()
        return [ TransactionDeltaRow(*t) for t in rows ]

    def read_key_history(self, account_id: int) -> List[TransactionKeyHistoryRow]:
        results: List[TransactionKeyHistoryRow] = []
        for row in self._get_many_common(self.READ_KEY_HISTORY_SQL, [ account_id ]):
            results.append(TransactionKeyHistoryRow(*row))
        return results

    def read_key_summary(self, account_id: int,
            keyinstance_ids: Optional[Sequence[int]]=None) -> List[TransactionDeltaKeySummaryRow]:
        params = [ account_id ]
        if keyinstance_ids is not None:
            return read_rows_by_id(TransactionDeltaKeySummaryRow, self._db,
                self.READ_KEY_SUMMARY_DOMAIN_SQL, [ account_id ], keyinstance_ids)

        query = self.READ_KEY_SUMMARY_SQL
        cursor = self._db.execute(query, [account_id])
        rows = cursor.fetchall()
        cursor.close()
        return [ TransactionDeltaKeySummaryRow(*t) for t in rows ]

    def read_history(self, account_id: int,
            keyinstance_ids: Optional[Sequence[int]]=None) -> List[TransactionDeltaHistoryRow]:
        params = [ account_id ]
        if keyinstance_ids:
            return read_rows_by_id(TransactionDeltaHistoryRow, self._db,
                self.READ_HISTORY_DOMAIN_SQL, [ account_id ], keyinstance_ids)

        query = self.READ_HISTORY_SQL
        cursor = self._db.execute(query, [account_id])
        rows = cursor.fetchall()
        cursor.close()
        return [ TransactionDeltaHistoryRow(*t) for t in rows ]

    def read_paid_requests(self, account_id: int, keyinstance_ids: Sequence[int]) \
            -> List[int]:
        return read_rows_by_id(int, self._db, self.READ_PAID_KEYS_SQL,
            [ account_id ], keyinstance_ids)

    def read_descriptions(self, account_id: int) -> List[Tuple[bytes, str]]:
        return self._get_many_common(self.READ_DESCRIPTIONS_SQL, [ account_id ])

    def read_balance(self, account_id: int, flags: Optional[int]=None,
            mask: Optional[int]=None) -> TransactionDeltaSumRow:
        query = self.READ_ACCOUNT_TXFILTERING_SQL_1
        params: List[Any] = [ account_id ]
        clause, extra_params = flag_clause("T.flags", flags, mask)
        if clause:
            query += f" WHERE {clause} "
            params.extend(extra_params)
        query += self.READ_ACCOUNT_TXFILTERING_SQL_2
        cursor = self._db.execute(query, params)
        row = cursor.fetchone()
        cursor.close()
        if row is None:
            return TransactionDeltaSumRow(account_id, 0, 0)
        return TransactionDeltaSumRow(*row)

    def read_transaction_value(self, tx_hash: bytes, account_id: Optional[int]=None) \
            -> List[TransactionDeltaSumRow]:
        if account_id is None:
            cursor = self._db.execute(self.READ_SQL, [tx_hash])
        else:
            cursor = self._db.execute(self.READ_ACCOUNT_SQL, [account_id, tx_hash])
        rows = cursor.fetchall()
        cursor.close()
        return [ TransactionDeltaSumRow(*row) for row in rows ]

    def update(self, entries: Iterable[Tuple[int, bytes, int]],
            date_updated: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if date_updated is None:
            date_updated = self._get_current_timestamp()
        datas = [ (date_updated,) + entry for entry in entries ]
        def _write(db: sqlite3.Connection):
            db.executemany(self.UPDATE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)

    def delete(self, entries: Iterable[Tuple[bytes, int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        datas = []
        for key_id, tx_hash in entries:
            datas.append((key_id, tx_hash))
        def _write(db: sqlite3.Connection):
            db.executemany(self.DELETE_SQL, datas)
        self._db_context.queue_write(_write, completion_callback)


class PaymentRequestRow(NamedTuple):
    paymentrequest_id: int
    keyinstance_id: int
    state: PaymentFlag
    value: Optional[int]
    expiration: Optional[int]
    description: Optional[str]
    date_created: int


class PaymentRequestTable(BaseWalletStore):
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
    UPDATE_STATE_SQL = f"""UPDATE PaymentRequests SET date_updated=?,
        state=(state&{~PaymentFlag.STATE_MASK})|? WHERE keyinstance_id=?"""
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


class InvoiceTable(BaseWalletStore):
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


class WalletEventTable(BaseWalletStore):
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

