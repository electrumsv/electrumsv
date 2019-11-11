"""
# Why DateCreated, DateUpdated and DateDeleted?

This was added with the intent that it can be used to serve as a watermark. As most, if not all of
this data is stored in encrypted lumps, we will need to index it and provide cached overviews of it
that can be quickly loaded to provide a responsive user-interface (presumably).

It should be possible using these dates to quickly ascertain whether the indexed/cached preview
is out of date.

"""

from abc import ABC, abstractmethod
from collections import namedtuple
from io import BytesIO
import json
import queue
import random
import sqlite3
import threading
import time
from typing import Optional, Dict, Set, Iterable, List, Tuple, Union, Any, Callable

import bitcoinx

from .constants import DATABASE_EXT, TxFlags
from .logs import logs
from .transaction import Transaction


__all__ = [
    "MissingRowError", "DataPackingError", "TransactionStore", "TransactionInputStore",
    "TransactionOutputStore",
]

def max_sql_variables():
    """Get the maximum number of arguments allowed in a query by the current
    sqlite3 implementation.

    ESV amendment: Report that on CentOS the following error occurs:
       "sqlite3.OperationalError: too many terms in compound SELECT"
    This is another limit, likely lower: SQLITE_LIMIT_COMPOUND_SELECT

    Returns
    -------
    int
        inferred SQLITE_MAX_VARIABLE_NUMBER
    """
    db = sqlite3.connect(':memory:')
    cur = db.cursor()
    cur.execute('CREATE TABLE t (test)')
    low, high = 0, 100000
    while (high - 1) > low:
        guess = (high + low) // 2
        query = 'INSERT INTO t VALUES ' + ','.join(['(?)' for _ in
                                                    range(guess)])
        args = [str(i) for i in range(guess)]
        try:
            cur.execute(query, args)
        except sqlite3.OperationalError as e:
            es = str(e)
            if "too many SQL variables" in es or "too many terms in compound SELECT" in es:
                high = guess
            else:
                raise
        else:
            low = guess
    cur.close()
    db.close()
    return low

# https://stackoverflow.com/a/36788489
MAX_VARS = max_sql_variables()


class DataPackingError(Exception):
    pass


class MissingRowError(Exception):
    pass


class InvalidDataError(Exception):
    pass

class InvalidUpsertError(Exception):
    pass


class MigrationContext(namedtuple("MigrationContextTuple",
        "source_version target_version")):
    pass


TXDATA_VERSION = 1
TXPROOF_VERSION = 1


total_time = 0.0

def tprofiler(func):
    def do_profile(func, args, kw_args):
        global total_time
        n = func.__name__
        logger = logs.get_logger("profiler")
        t0 = time.time()
        o = func(*args, **kw_args)
        t = time.time() - t0
        total_time += t
        logger.debug("%s call=%.4f total=%0.4f", n, t, total_time)
        return o
    return lambda *args, **kw_args: do_profile(func, args, kw_args)


def byte_repr(value):
    if value is None:
        return str(value)
    return f"ByteData({len(value)})"


class WriteDisabledError(Exception):
    pass


WriteCallbackType = Callable[[sqlite3.Connection], None]
CompletionCallbackType = Callable[[], None]

class SqliteWriteDispatcher:
    def __init__(self, db_context: "DatabaseContext") -> None:
        self._db_context = db_context
        self._logger = logs.get_logger(self.__class__.__name__)

        self._writer_queue = queue.Queue()
        self._writer_thread = threading.Thread(target=self._writer_thread_main, daemon=True)
        self._writer_loop_event = threading.Event()
        self._callback_queue = queue.Queue()
        self._callback_thread = threading.Thread(target=self._callback_thread_main, daemon=True)
        self._callback_loop_event = threading.Event()

        self._allow_puts = True
        self._is_alive = True
        self._exit_when_empty = False

        self._writer_thread.start()
        self._callback_thread.start()

    def _writer_thread_main(self) -> None:
        self._db = self._db_context.acquire_connection()

        maximum_batch_size = 10
        write_callbacks: List[WriteCallbackType] = []
        write_callback_backlog: List[WriteCallbackType] = []
        while self._is_alive:
            self._writer_loop_event.set()

            if len(write_callback_backlog):
                assert maximum_batch_size == 1
                write_callbacks = [ write_callback_backlog.pop(0) ]
            else:
                # Block until we have at least one write action. If we already have write
                # actions at this point, it is because we need to retry after a transaction
                # was rolled back.
                try:
                    write_callback: WriteCallbackType = self._writer_queue.get(timeout=0.1)
                except queue.Empty:
                    if self._exit_when_empty:
                        return
                    continue
                write_callbacks = [ write_callback ]

            # Gather the rest of the batch for this transaction.
            while len(write_callbacks) < maximum_batch_size and not self._writer_queue.empty():
                write_callbacks.append(self._writer_queue.get_nowait())

            # Using the connection as a context manager, apply the batch as a transaction.
            completion_callbacks = []
            try:
                with self._db:
                    # We have to force a grouped statement transaction with the explicit 'begin'.
                    self._db.execute('begin')
                    for write_callback in write_callbacks:
                        completion_callback = write_callback(self._db)
                        if completion_callback is not None:
                            completion_callbacks.append(completion_callback)
                # The transaction was successfully committed.
            except sqlite3.IntegrityError as e:
                self._logger.exception("Database write failure", exc_info=e)
                # The transaction was rolled back.
                if maximum_batch_size > 1:
                    self._logger.debug("Retrying with batch size of 1")
                    # We're going to try and reapply the write actions one by one.
                    maximum_batch_size = 1
                    write_callback_backlog = write_callbacks
                # We applied the batch actions one by one. If there was an error with this action
                # then we've logged it, so we can discard it for lack of any other option.
            else:
                if len(write_callbacks) > 1:
                    self._logger.debug("Invoked %d write callbacks", len(write_callbacks))

            for completion_callback in completion_callbacks:
                self._callback_queue.put_nowait(completion_callback)

    def _callback_thread_main(self) -> None:
        while self._is_alive:
            self._callback_loop_event.set()

            # A perpetually blocking get will not get interrupted by CTRL+C.
            try:
                callback: CompletionCallbackType = self._callback_queue.get(timeout=0.1)
            except queue.Empty:
                if self._exit_when_empty:
                    return
                continue

            try:
                callback()
            except Exception as e:
                self._logger.exception("Exception within completion callback", exc_info=e)

    def put(self, write_callback: Optional[WriteCallbackType]=None) -> None:
        # If the writer is closed, then it is expected the caller should have made sure that
        # no more puts will be made, and the error will only be raised if something puts to
        # flag that it is wrong.
        if not self._allow_puts:
            raise WriteDisabledError()

        self._writer_queue.put_nowait(write_callback)

    def stop(self) -> None:
        if self._exit_when_empty:
            return

        self._allow_puts = False
        self._exit_when_empty = True

        # Wait for both threads to exit.
        self._writer_loop_event.wait()
        self._writer_thread.join()
        self._db_context.release_connection(self._db)
        self._db = None
        self._callback_loop_event.wait()
        self._callback_thread.join()

        self._is_alive = False

    def is_stopped(self) -> bool:
        return not self._is_alive


class DatabaseContext:
    def __init__(self, wallet_path: str) -> None:
        if not wallet_path.endswith(DATABASE_EXT):
            wallet_path += DATABASE_EXT
        self._db_path = wallet_path
        self._connections = []

        self._write_dispatcher = SqliteWriteDispatcher(self)

    def acquire_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_path, check_same_thread=False,
            isolation_level=None)
        self._connections.append(connection)
        return connection

    def release_connection(self, connection: sqlite3.Connection) -> None:
        self._connections.remove(connection)
        connection.close()

    def queue_write(self, write_callback: WriteCallbackType) -> None:
        self._write_dispatcher.put(write_callback)

    def close(self) -> None:
        self._write_dispatcher.stop()
        assert self.is_closed()

    def is_closed(self) -> bool:
        return len(self._connections) == 0 and self._write_dispatcher.is_stopped()



class BaseWalletStore:
    _table_name = None

    def __init__(self, table_name: str, db_context: DatabaseContext, aeskey: Optional[bytes],
            group_id: Optional[int]=None,
            migration_context: Optional[MigrationContext]=None) -> None:
        self.set_aeskey(aeskey)

        self._group_id = group_id
        self._db_context = db_context
        self._db = db_context.acquire_connection()

        self._set_table_name(table_name)

        # These are the sole allowed writes outside of the write dispatcher.
        if migration_context is not None:
            self._db_migrate(self._db, migration_context)
        else:
            self._db_create(self._db)
        self._db.commit()

    def close(self):
        if self._aes_key is None:
            del self._decrypt
            del self._encrypt
        self._db_context.release_connection(self._db)
        self._db = None

    def set_aeskey(self, aeskey: Optional[bytes]) -> None:
        if aeskey is None:
            self._aes_key = None
            self._aes_iv = None

            self._encrypt = self._encrypt_nop
            self._decrypt = self._encrypt_nop
        else:
            self._aes_key = aeskey[:16]
            self._aes_iv = aeskey[16:]

    def _set_table_name(self, table_name: str) -> None:
        self._table_name = table_name

    def get_table_name(self) -> str:
        return self._table_name

    def _db_create(self, db: sqlite3.Connection) -> None:
        pass

    def _db_migrate(self, db: sqlite3.Connection, context: MigrationContext) -> None:
        pass

    def _get_column_types(self, db: sqlite3.Connection, table_name: str) -> Dict[str, Any]:
        column_types = {}
        for row in db.execute(f"PRAGMA table_info({table_name});"):
            _discard, column_name, column_type, _discard, _discard, _discard = row
            column_types[column_name] = column_type
        return column_types

    def _get_current_timestamp(self):
        "Get the current timestamp in a form suitable for database column storage."
        return int(time.time())

    def _encrypt_nop(self, value: bytes) -> bytes:
        return value

    def _encrypt(self, value: bytes) -> bytes:
        return bitcoinx.aes.aes_encrypt_with_iv(self._aes_key, self._aes_iv, value)

    def _decrypt(self, value: bytes) -> bytes:
        return bitcoinx.aes.aes_decrypt_with_iv(self._aes_key, self._aes_iv, value)

    def _encrypt_hex(self, value: str) -> bytes:
        return self._encrypt(bytes.fromhex(value))

    def _decrypt_hex(self, value: bytes) -> str:
        return self._decrypt(value).hex()

    def execute_unsafe(self, query: str, *params: Iterable[Any]) -> Any:
        self._db.execute(query, params)
        self._db.commit()


class StringKeyMixin:
    def _encode_key(self, key: str) -> bytes:
        return super()._encode_key(key.encode())

    def _decode_key(self, key_data: bytes) -> str:
        key_bytes = super()._decode_key(key_data)
        return key_bytes.decode('utf-8')


class HexKeyMixin:
    def _encode_key(self, key: str) -> bytes:
        key_bytes = bytes.fromhex(key)
        return super()._encode_key(key_bytes)

    def _decode_key(self, key_data: bytes) -> str:
        key_bytes = super()._decode_key(key_data)
        return key_bytes.hex()


class EncryptedKeyMixin:
    def _encode_key(self, key_bytes: bytes) -> bytes:
        return self._encrypt(key_bytes)

    def _decode_key(self, key_data: bytes) -> bytes:
        return self._decrypt(key_data)


class GenericKeyValueStore(BaseWalletStore):
    def __init__(self, table_name: str, db_context: DatabaseContext, aeskey: Optional[bytes],
            group_id: int, migration_context: Optional[MigrationContext]=None) -> None:
        self._logger = logs.get_logger(f"{table_name}-store")

        super().__init__(table_name, db_context, aeskey, group_id, migration_context)

    def has_unique_keys(self) -> bool:
        return True

    def _set_table_name(self, table_name: str) -> None:
        super()._set_table_name(table_name)

        # NOTE(rt12): The unique constraint is required for the upsert to work.
        self._CREATE_TABLE_SQL = ("CREATE TABLE IF NOT EXISTS "+ table_name +" ("+
                "Key BLOB,"+
                "GroupId INT DEFAULT 0,"+
                "ByteData BLOB,"+
                "DateCreated INTEGER,"+
                "DateUpdated INTEGER,"+
                "DateDeleted INTEGER DEFAULT NULL"+
            ")")
        self._CREATE_INDEX_SQL = ("CREATE UNIQUE INDEX IF NOT EXISTS idx_"+ table_name +"_unique "+
            "ON "+ table_name +"(Key, GroupId)")
        self._CREATE_SQL = ("INSERT INTO "+ table_name +" "+
            "(GroupId, Key, ByteData, DateCreated, DateUpdated) VALUES (?, ?, ?, ?, ?)")
        self._READ_SQL = ("SELECT ByteData FROM "+ table_name +" "+
            "WHERE GroupID=? AND DateDeleted IS NULL AND Key=?")
        self._READ_ALL_SQL = ("SELECT Key, ByteData FROM "+ table_name +" "+
            "WHERE GroupID=? AND DateDeleted IS NULL")
        self._READ_ROW_SQL = ("SELECT ByteData, DateCreated, DateUpdated, DateDeleted "+
            "FROM "+ table_name +" "+
            "WHERE GroupId=? AND Key=?")
        self._UPDATE_SQL = ("UPDATE "+ table_name +" SET ByteData=?, DateUpdated=? "+
            "WHERE GroupId=? AND DateDeleted IS NULL AND Key=?")
        self._UPSERT_SQL = (self._CREATE_SQL +" ON CONFLICT(Key, GroupId) DO UPDATE "+
            "SET ByteData=excluded.ByteData, DateUpdated=excluded.DateUpdated")
        self._DELETE_SQL = ("UPDATE "+ table_name +" SET DateDeleted=? "+
            "WHERE GroupId=? AND DateDeleted IS NULL AND Key=?")
        self._DELETE_VALUE_SQL = ("UPDATE "+ table_name +" SET DateDeleted=? "+
            "WHERE GroupId=? AND DateDeleted IS NULL AND Key=? AND ByteData=?")

    def _db_create(self, db: sqlite3.Connection) -> None:
        db.execute(self._CREATE_TABLE_SQL)
        if self.has_unique_keys():
            db.execute(self._CREATE_INDEX_SQL)

    def _db_migrate(self, db: sqlite3.Connection, context: MigrationContext) -> None:
        if context.source_version == 18 and context.target_version == 19:
            # The creation version is always the latest, so this will be duplicated outside of
            # a migration that starts from 18.
            column_types = self._get_column_types(db, self.get_table_name())
            if "GroupId" not in column_types:
                # Scope of migration is move from single keystore wallet to parent wallet concept.
                db.execute(
                    f"ALTER TABLE {self.get_table_name()} ADD COLUMN GroupId INTEGER DEFAULT 0")
                self._logger.debug(
                    f"_db_migrate: added 'GroupId' column to '{self.get_table_name()}' table")
        elif context.source_version == 20 and context.target_version == 21:
            if self.has_unique_keys():
                db.execute(self._CREATE_INDEX_SQL)
        else:
            raise Exception("Asked to migrate unexpected versions", context)

    @tprofiler
    def add(self, key: str, value: bytes,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        self._add_many([ (key, value) ], completion_callback=completion_callback)

    @tprofiler
    def add_many(self, entries: Iterable[Tuple[str, bytes]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        self._add_many(entries, completion_callback)

    def _add_many(self, entries: Iterable[Tuple[str, bytes]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = []
        for key, value in entries:
            assert type(value) is bytes, f"bad value {value}"
            datas.append([ self._group_id, self._encrypt_key(key), self._encrypt(value),
                timestamp, timestamp])

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("add_many '%s'", list(t[0] for t in entries))
            db.executemany(self._CREATE_SQL, datas)
            return completion_callback

        self._db_context.queue_write(_write)

    @tprofiler
    def get_value(self, key: str) -> Optional[bytes]:
        ekey = self._encrypt_key(key)
        cursor = self._db.execute(self._READ_SQL, [self._group_id, ekey])
        row = cursor.fetchone()
        if row is not None:
            return self._decrypt(row[0])
        return None

    @tprofiler
    def get_many_values(self, keys: Iterable[str]) -> List[Tuple[str, bytes]]:
        query = self._READ_ALL_SQL
        params = [ self._group_id ]

        results = []
        def _collect_results(cursor, results):
            rows = cursor.fetchall()
            cursor.close()
            for row in rows:
                key = self._decrypt_key(row[0])
                bytedata = self._decrypt(row[1])
                results.append((key, bytedata))

        ekeys = [ self._encrypt_key(key) for key in keys ]
        batch_size = MAX_VARS - len(params)
        while len(ekeys):
            batch_ekeys = ekeys[:batch_size]
            batch_query = (query +
                " AND Key IN ({0})".format(",".join("?" for k in batch_ekeys)))
            cursor = self._db.execute(batch_query, params + batch_ekeys)
            _collect_results(cursor, results)
            ekeys = ekeys[batch_size:]

        return results

    @tprofiler
    def get_all(self) -> Optional[bytes]:
        cursor = self._db.execute(self._READ_ALL_SQL, [ self._group_id ])
        return [ (self._decrypt_key(row[0]), self._decrypt(row[1])) for row in cursor.fetchall() ]

    @tprofiler
    def get_values(self, key: str) -> List[bytes]:
        ekey = self._encrypt_key(key)
        cursor = self._db.execute(self._READ_SQL, [self._group_id, ekey])
        return [ self._decrypt(row[0]) for row in cursor.fetchall() ]

    @tprofiler
    def get_row(self, key: str) -> Optional[Tuple[bytes, int, int, int]]:
        ekey = self._encrypt_key(key)
        cursor = self._db.execute(self._READ_ROW_SQL, [self._group_id, ekey])
        row = cursor.fetchone()
        if row is not None:
            return (self._decrypt(row[0]), row[1], row[2], row[3])
        return None

    @tprofiler
    def upsert(self, key: str, value: bytes,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if not self.has_unique_keys():
            raise InvalidUpsertError(key)

        # Some operating systems like Linux effectively lock the sqlite version to something
        # very old, like 3.11.0.
        if sqlite3.sqlite_version_info > (3, 24, 0):
            assert type(value) is bytes
            ekey = self._encrypt_key(key)
            evalue = self._encrypt(value)
            timestamp = self._get_current_timestamp()

            def _write(db: sqlite3.Connection) -> None:
                self._logger.debug("upsert '%s'", key)
                db.execute(self._UPSERT_SQL,
                    [self._group_id, ekey, evalue, timestamp, timestamp])
                return completion_callback

            self._db_context.queue_write(_write)
        else:
            assert self.has_unique_keys()

            # We expect higher-level usageto  prevent overlapping reads and writes.
            if self.get_value(key) is None:
                self._add_many([ (key, value) ], completion_callback=completion_callback)
            else:
                self._update(key, value, completion_callback=completion_callback)

    @tprofiler
    def update(self, key: str, value: bytes,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        self._update(key, value, completion_callback)

    def _update(self, key: str, value: bytes,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        assert type(value) is bytes
        ekey = self._encrypt_key(key)
        evalue = self._encrypt(value)
        timestamp = self._get_current_timestamp()

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("updated '%s'", key)
            db.execute(self._UPDATE_SQL, [evalue, timestamp, self._group_id, ekey])
            return completion_callback

        self._db_context.queue_write(_write)

    @tprofiler
    def update_many(self, entries: Iterable[Tuple[str, bytes]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = []
        for key, value in entries:
            assert type(value) is bytes
            datas.append(
                [ self._encrypt(value), timestamp, self._group_id, self._encrypt_key(key) ])

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("update_many '%s'", list(t[0] for t in entries))
            db.executemany(self._UPDATE_SQL, datas)
            return completion_callback

        self._db_context.queue_write(_write)

    @tprofiler
    def delete(self, key: str,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        ekey = self._encrypt_key(key)
        timestamp = self._get_current_timestamp()

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("deleted '%s'", key)
            db.execute(self._DELETE_SQL, [timestamp, self._group_id, ekey])
            return completion_callback

        self._db_context.queue_write(_write)

    @tprofiler
    def delete_value(self, key: str, value: bytes,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        ekey = self._encrypt_key(key)
        evalue = self._encrypt(value)
        timestamp = self._get_current_timestamp()

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("deleted value for '%s'", key)
            db.execute(self._DELETE_VALUE_SQL, [timestamp, self._group_id, ekey, evalue])
            return completion_callback

        self._db_context.queue_write(_write)

    @tprofiler
    def delete_values(self, entries: Iterable[Tuple[str, bytes]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        datas = []
        for key, value in entries:
            ekey = self._encrypt_key(key)
            evalue = self._encrypt(value)
            datas.append((timestamp, self._group_id, ekey, evalue))

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("deleted values for '%s'", [ v[0] for v in entries ])
            db.executemany(self._DELETE_VALUE_SQL, datas)
            return completion_callback

        self._db_context.queue_write(_write)

    def _delete_duplicates(self) -> None:
        self.execute_unsafe(f"""
        DELETE FROM {self.get_table_name()}
        WHERE rowid NOT IN (
            SELECT MIN(rowid)
            FROM {self.get_table_name()}
            WHERE GroupId=?
            GROUP BY Key, ByteData
        ) AND GroupId=?
        """, self._group_id, self._group_id)

    def _encrypt_key(self, key: str) -> bytes:
        return self._encode_key(key)

    def _decrypt_key(self, key_data: bytes) -> str:
        return self._decode_key(key_data)

    def _encode_key(self, key: Any) -> bytes:
        assert type(key) is bytes
        return key

    def _decode_key(self, key_data: bytes) -> Any:
        return key_data


class JSONKeyValueStore(StringKeyMixin, GenericKeyValueStore):
    def get(self, key: str, value: Any=None) -> Any:
        db_value = self.get_value(key)
        return value if db_value is None else json.loads(db_value)

    def set(self, key: str, value: Any,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        if type(value) is not bytes:
            value = json.dumps(value).encode()

        self.upsert(key, value, completion_callback=completion_callback)


StoreObject = Union[list, dict]

class ObjectKeyValueStore(GenericKeyValueStore):
    def _encrypt_key(self, value: str) -> bytes:
        return self._encrypt(value.encode())

    def _decrypt_key(self, value: bytes) -> str:
        return self._decrypt(value).decode()

    def _pack_value(self, value: StoreObject) -> bytes:
        return json.dumps(value).encode()

    def _unpack_value(self, value: bytes) -> StoreObject:
        return json.loads(value.decode())

    def add(self, key: str, value: StoreObject,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        super().add(key, self._pack_value(value), completion_callback=completion_callback)

    def add_many(self, entries: List[Tuple[str, StoreObject]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        entries = [ (k, self._pack_value(v)) for (k, v) in entries ]
        super().add_many(entries, completion_callback=completion_callback)

    def get_value(self, key: str) -> Optional[StoreObject]:
        byte_value = super().get_value(key)
        return self._unpack_value(byte_value) if byte_value is not None else None

    def get_all(self) -> List[StoreObject]:
        return [ (k, self._unpack_value(v)) for (k, v) in super().get_all() ]

    def get_values(self, key: str) -> List[StoreObject]:
        raise NotImplementedError

    def get_row(self, key: str) -> Optional[Tuple[StoreObject, int, int, int]]:
        row = super().get_row(key)
        if row is not None:
            return self._unpack_value(row[0]), row[1], row[2], row[3]
        return None

    def set(self, key: str, value: StoreObject,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        super().upsert(key, self._pack_value(value), completion_callback=completion_callback)

    def update(self, key: str, value: StoreObject,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        super().update(key, self._pack_value(value), completion_callback=completion_callback)

    def delete_value(self, key: str, value: StoreObject,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        super().delete_value(key, self._pack_value(value), completion_callback=completion_callback)


class AbstractTransactionXput(ABC):
    @abstractmethod
    def add_entries(self, entries: Iterable[Tuple[str, tuple]]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_entries(self, tx_id: str) -> List[tuple]:
        raise NotImplementedError

    @abstractmethod
    def get_all_entries(self) -> Dict[str, List[tuple]]:
        raise NotImplementedError

    @abstractmethod
    def delete_entries(self, entries: Iterable[Tuple[str, tuple]]) -> None:
        raise NotImplementedError


class DBTxInput(namedtuple("DBTxInputTuple", "address_string prevout_tx_hash prev_idx amount")):
    pass


class TransactionInputStore(HexKeyMixin, EncryptedKeyMixin, GenericKeyValueStore,
        AbstractTransactionXput):
    def __init__(self, db_context: DatabaseContext, aeskey: Optional[bytes],
            group_id: int, migration_context: Optional[MigrationContext]=None) -> None:
        super().__init__("TransactionInputs", db_context, aeskey, group_id, migration_context)

    def has_unique_keys(self) -> bool:
        return False

    @staticmethod
    def _pack_value(txin: DBTxInput) -> bytes:
        raw = bitcoinx.pack_varint(1)
        raw += bitcoinx.pack_varbytes(txin.address_string.encode())
        raw += bitcoinx.pack_varbytes(txin.prevout_tx_hash.encode())
        raw += bitcoinx.pack_varint(txin.prev_idx)
        raw += bitcoinx.pack_varint(txin.amount)
        return raw

    @staticmethod
    def _unpack_value(raw: bytes) -> DBTxInput:
        io = BytesIO(raw)
        pack_version = bitcoinx.read_varint(io.read)
        if pack_version == 1:
            address_string = bitcoinx.read_varbytes(io.read).decode()
            prevout_tx_hash = bitcoinx.read_varbytes(io.read).decode()
            prev_idx = bitcoinx.read_varint(io.read)
            amount = bitcoinx.read_varint(io.read)
            return DBTxInput(address_string, prevout_tx_hash, prev_idx, amount)
        raise DataPackingError(f"Unhandled packing format {pack_version}")

    def add_entries(self, entries: Iterable[Tuple[str, DBTxInput]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        super().add_many([ (key, self._pack_value(value)) for (key, value) in entries ],
            completion_callback=completion_callback)

    def get_entries(self, tx_id: str) -> List[DBTxInput]:
        values = super().get_values(tx_id)
        for i, value in enumerate(values):
            values[i] = self._unpack_value(value)
        return values

    def get_all_entries(self) -> Dict[str, List[DBTxInput]]:
        d = {}
        for key, value in super().get_all():
            l = d.setdefault(key, [])
            l.append(self._unpack_value(value))
        return d

    def delete_entries(self, entries: Iterable[Tuple[str, DBTxInput]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        super().delete_values([ (tx_id, self._pack_value(txin)) for (tx_id, txin) in entries ],
            completion_callback=completion_callback)


class DBTxOutput(namedtuple("DBTxOutputTuple", "address_string out_tx_n amount is_coinbase")):
    pass


class TransactionOutputStore(HexKeyMixin, EncryptedKeyMixin, GenericKeyValueStore,
        AbstractTransactionXput):
    def __init__(self, db_context: DatabaseContext, aeskey: Optional[bytes],
            group_id: int, migration_context: Optional[MigrationContext]=None) -> None:
        super().__init__("TransactionOutputs", db_context, aeskey, group_id, migration_context)

    def has_unique_keys(self) -> bool:
        return False

    @staticmethod
    def _pack_value(txout: DBTxOutput) -> bytes:
        raw = bitcoinx.pack_varint(1)
        raw += bitcoinx.pack_varbytes(txout.address_string.encode())
        raw += bitcoinx.pack_varint(txout.out_tx_n)
        raw += bitcoinx.pack_varint(txout.amount)
        raw += bitcoinx.pack_varint(int(txout.is_coinbase))
        return raw

    @staticmethod
    def _unpack_value(raw: bytes) -> DBTxOutput:
        io = BytesIO(raw)
        pack_version = bitcoinx.read_varint(io.read)
        if pack_version == 1:
            address_string = bitcoinx.read_varbytes(io.read).decode()
            out_tx_n = bitcoinx.read_varint(io.read)
            amount = bitcoinx.read_varint(io.read)
            is_coinbase = bool(bitcoinx.read_varint(io.read))
            return DBTxOutput(address_string, out_tx_n, amount, is_coinbase)
        raise DataPackingError(f"Unhandled packing format {pack_version}")

    def add_entries(self, entries: Iterable[Tuple[str, DBTxOutput]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        super().add_many([ (key, self._pack_value(value)) for (key, value) in entries ],
            completion_callback=completion_callback)

    def get_entries(self, tx_hash: str) -> List[DBTxOutput]:
        values = super().get_values(tx_hash)
        for i, value in enumerate(values):
            values[i] = self._unpack_value(value)
        return values

    def get_all_entries(self) -> Dict[str, List[DBTxOutput]]:
        d = {}
        for key, value in super().get_all():
            l = d.setdefault(key, [])
            l.append(self._unpack_value(value))
        return d

    def delete_entries(self, entries: Iterable[Tuple[str, DBTxOutput]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        super().delete_values([ (tx_id, self._pack_value(txout)) for (tx_id, txout) in entries ],
            completion_callback=completion_callback)


class TxData(namedtuple("TxDataTuple", "height timestamp position fee")):
    def __repr__(self):
        return (f"TxData(height={self.height},timestamp={self.timestamp},"+
            f"position={self.position},fee={self.fee})")

# namedtuple defaults do not get added until 3.7, and are not available in 3.6, so we set them
# indirectly to be compatible by both.
TxData.__new__.__defaults__ = (None, None, None, None)


class TxProof(namedtuple("TxProofTuple", "position branch")):
    pass



class TransactionStore(BaseWalletStore):
    """
    We store transactions for two cases currently:
    - Received transactions (IsPending=0) which have come in over the P2P network. These are
      solely those related to the user's inputs, outputs and pruned transactions.
    - Pending transactions (IsPending=1), which have been constructed and designated in play,
      but not broadcast to the P2P network by the user, nor broadcast to the P2P network by anyone
      they might have been given to. The persisted existence of these are considered to freeze the
      coins they have in their inputs.

    These transactions must be the user's own transactions relating to their own inputs and
    outputs.
    """

    def __init__(self, db_context: DatabaseContext, aeskey: Optional[bytes], group_id: int,
            migration_context: Optional[MigrationContext]=None) -> None:
        self._logger = logs.get_logger("tx-store")

        super().__init__("Transactions", db_context, aeskey, group_id, migration_context)

    def _db_create(self, db) -> None:
        db.execute(
            "CREATE TABLE IF NOT EXISTS Transactions ("+
                "GroupId INTEGER DEFAULT 0,"+
                "Key BLOB, "+
                "Flags INTEGER,"
                "MetaData BLOB,"+
                "ByteData BLOB,"+
                "ProofData BLOB,"+
                "DateCreated INTEGER,"+
                "DateUpdated INTEGER,"+
                "DateDeleted INTEGER DEFAULT NULL,"+
                "UNIQUE(Key,DateDeleted))")

    def _db_migrate(self, db: sqlite3.Connection, context: MigrationContext) -> None:
        if context.source_version == 18 and context.target_version == 19:
            # The creation version is always the latest, so this will be duplicated outside of
            # a migration that starts from 18.
            column_types = self._get_column_types(db, "Transactions")
            if "GroupId" not in column_types:
                # Scope of migration is move from single keystore wallet to parent wallet concept.
                db.execute("ALTER TABLE Transactions ADD COLUMN GroupId INTEGER DEFAULT 0")
                self._logger.debug(f"_db_migrate: added 'GroupId' column to 'Transactions' table")
        else:
            raise Exception("Asked to migrate unexpected versions", context)

    # Version 1: Serialised direct values (or dummy random values).
    # Version 2: Serialised direct values (or dummy random values).
    #            Exception is height which ranges from -1 and has to be shifted up.

    @staticmethod
    def _pack_data(data: TxData, flags: int) -> bytes:
        flags &= ~TxFlags.METADATA_FIELD_MASK
        if data.height is not None:
            flags |= TxFlags.HasHeight
        if data.fee is not None:
            flags |= TxFlags.HasFee
        if data.position is not None:
            flags |= TxFlags.HasPosition
        if data.timestamp is not None:
            flags |= TxFlags.HasTimestamp

        # Why put random dummy values in? Why not?
        raw = bitcoinx.pack_varint(2)
        # Height can range from -1 and above, but varints range from 0 and above.
        raw += bitcoinx.pack_varint((data.height + 1) if flags & TxFlags.HasHeight
                                    else random.randint(1000, 100000))
        raw += bitcoinx.pack_varint(data.fee if flags & TxFlags.HasFee
                                    else random.randint(100, 2000))
        raw += bitcoinx.pack_varint(data.position if flags & TxFlags.HasPosition
                                    else random.randint(2, 2000))
        raw += bitcoinx.pack_varint(data.timestamp if flags & TxFlags.HasTimestamp
                                    else random.randint(1554000000, 1556000000))
        return raw, flags

    @staticmethod
    def _unpack_data(raw: bytes, flags: int) -> TxData:
        io = BytesIO(raw)
        pack_version = bitcoinx.read_varint(io.read)
        if pack_version == 1 or pack_version == 2:
            kwargs = {}
            for kw, mask in (
                    ('height', TxFlags.HasHeight),
                    ('fee', TxFlags.HasFee),
                    ('position', TxFlags.HasPosition),
                    ('timestamp', TxFlags.HasTimestamp)):
                value = bitcoinx.read_varint(io.read)
                if pack_version == 2 and mask == TxFlags.HasHeight:
                    value -= 1
                kwargs[kw] = value if (flags & mask) == mask else None
            return TxData(**kwargs)
        raise DataPackingError(f"Unhandled packing format {pack_version}")

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

    @staticmethod
    def _flag_clause(flags: Optional[int], mask: Optional[int]) -> Tuple[str, Tuple]:
        if flags is None:
            if mask is None:
                return "", []
            return "(flags & ?) != 0", [mask]

        if mask is None:
            return "(flags & ?) != 0", [flags]

        return "(flags & ?) == ?", [mask, flags]

    @tprofiler
    def has(self, tx_id: str) -> bool:
        etx_id = self._encrypt_hex(tx_id)
        cursor = self._db.execute("SELECT EXISTS(SELECT 1 FROM Transactions "+
            "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL)", [self._group_id, etx_id])
        row = cursor.fetchone()
        return row[0] == 1

    @tprofiler
    def get_flags(self, tx_id: str) -> Optional[int]:
        etx_id = self._encrypt_hex(tx_id)
        cursor = self._db.execute(
            "SELECT Flags FROM Transactions "+
            "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL", [self._group_id, etx_id])
        row = cursor.fetchone()
        return row[0] if row is not None else None

    @tprofiler
    def get(self, tx_id: str, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[Tuple[TxData, Optional[bytes], int]]:
        etx_id = self._encrypt_hex(tx_id)
        clause, params = self._flag_clause(flags, mask)
        query = ("SELECT MetaData, ByteData, Flags FROM Transactions "+
            "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL")
        if clause:
            query += " AND "+ clause
        cursor = self._db.execute(query, [self._group_id, etx_id] + params)
        row = cursor.fetchone()
        if row is not None:
            bytedata = self._decrypt(row[1]) if row[1] is not None else None
            return self._unpack_data(self._decrypt(row[0]), row[2]), bytedata, row[2]
        return None

    @tprofiler
    def get_many(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_ids: Optional[Iterable[str]]=None) -> List[Tuple[str, TxData, Optional[bytes], int]]:
        query = ("SELECT Key, MetaData, ByteData, Flags FROM Transactions "+
            "WHERE GroupId=? AND DateDeleted IS NULL")
        params = [ self._group_id ]
        clause, extra_params = self._flag_clause(flags, mask)
        if clause:
            query += " AND "+ clause
            params.extend(extra_params)

        results = []
        def _collect_results(cursor, results):
            rows = cursor.fetchall()
            cursor.close()
            for row in rows:
                tx_id = self._decrypt_hex(row[0])
                bytedata = self._decrypt(row[2]) if row[2] is not None else None
                data = self._unpack_data(self._decrypt(row[1]), row[3])
                results.append((tx_id, data, bytedata, row[3]))

        if tx_ids is not None and len(tx_ids):
            etx_ids = [ self._encrypt_hex(tx_id) for tx_id in tx_ids ]

            batch_size = MAX_VARS - len(params)
            while len(etx_ids):
                batch_etx_ids = etx_ids[:batch_size]
                batch_query = (query +
                    " AND Key IN ({0})".format(",".join("?" for k in batch_etx_ids)))
                cursor = self._db.execute(batch_query, params + batch_etx_ids)
                _collect_results(cursor, results)
                etx_ids = etx_ids[batch_size:]
        else:
            cursor = self._db.execute(query, params)
            _collect_results(cursor, results)
        return results

    @tprofiler
    def get_metadata(self, tx_id: str, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[Tuple[TxData, int]]:
        etx_id = self._encrypt_hex(tx_id)
        clause, params = self._flag_clause(flags, mask)
        query = ("SELECT MetaData, Flags FROM Transactions "+
            "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL")
        if clause:
            query += " AND "+ clause
        cursor = self._db.execute(query, [self._group_id, etx_id] + params)
        row = cursor.fetchone()
        if row is not None:
            return self._unpack_data(self._decrypt(row[0]), row[1]), row[1]
        return None

    @tprofiler
    def get_metadata_many(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_ids: Optional[Iterable[str]]=None) -> List[Tuple[str, TxData, int]]:
        query = ("SELECT Key, MetaData, Flags FROM Transactions "+
            "WHERE GroupId=? AND DateDeleted IS NULL")
        params = [ self._group_id ]
        clause, extra_params = self._flag_clause(flags, mask)
        if clause:
            query += " AND "+ clause
            params.extend(extra_params)

        results = []
        def _collect_results(cursor, results):
            rows = cursor.fetchall()
            cursor.close()
            for row in rows:
                tx_id = self._decrypt_hex(row[0])
                data = self._unpack_data(self._decrypt(row[1]), row[2])
                results.append((tx_id, data, row[2]))

        if tx_ids is not None and len(tx_ids):
            etx_ids = [ self._encrypt_hex(tx_id) for tx_id in tx_ids ]

            batch_size = MAX_VARS - len(params)
            while len(etx_ids):
                batch_etx_ids = etx_ids[:batch_size]
                batch_params = params + batch_etx_ids
                batch_query = (query +
                    " AND Key IN ({0})".format(",".join("?" for k in batch_etx_ids)))
                cursor = self._db.execute(batch_query, batch_params)
                _collect_results(cursor, results)
                etx_ids = etx_ids[batch_size:]
        else:
            cursor = self._db.execute(query, params)
            _collect_results(cursor, results)
        return results

    @tprofiler
    def get_proof(self, tx_id: str) -> Optional[TxProof]:
        etx_id = self._encrypt_hex(tx_id)
        cursor = self._db.execute(
            "SELECT ProofData FROM Transactions "+
            "WHERE GroupId=? AND DateDeleted is NULL AND Key=?", [self._group_id, etx_id])
        row = cursor.fetchone()
        if row is None:
            raise MissingRowError(tx_id)
        if row[0] is None:
            return None
        raw = self._decrypt(row[0])
        return self._unpack_proof(raw)

    @tprofiler
    def get_ids(self, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Set[str]:
        query = "SELECT Key FROM Transactions WHERE GroupId=? AND DateDeleted IS NULL"
        clause, params = self._flag_clause(flags, mask)
        if clause:
            query += " AND "+ clause
        results = []
        for t in self._db.execute(query, [ self._group_id ] + params):
            results.append(self._decrypt_hex(t[0]))
        return set(results)

    def add(self, tx_id: str, metadata: TxData, bytedata: Optional[bytes]=None,
            flags: Optional[int]=TxFlags.Unset,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        self.add_many([ (tx_id, metadata, bytedata, flags) ], completion_callback)

    @tprofiler
    def add_many(self, entries: List[Tuple[str, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()

        datas = []
        for tx_id, metadata, bytedata, flags in entries:
            etx_id = self._encrypt_hex(tx_id)
            metadata_bytes, flags = self._pack_data(metadata, flags)
            emetadata = self._encrypt(metadata_bytes)
            flags &= ~TxFlags.HasByteData
            if bytedata is not None:
                flags |= TxFlags.HasByteData
            ebytedata = None if bytedata is None else self._encrypt(bytedata)
            datas.append((self._group_id, etx_id, emetadata, ebytedata, flags, timestamp,
                timestamp))

        def _write(db: sqlite3.Connection) -> None:
            if len(entries) < 20:
                self._logger.debug("add %d transactions: %s", len(entries),
                    [ (a, b, byte_repr(c), TxFlags.to_repr(d)) for (a, b, c, d) in entries ])
            else:
                self._logger.debug("add %d transactions (too many to show)", len(entries))

            db.executemany("INSERT INTO Transactions "+
                "(GroupId, Key, MetaData, ByteData, Flags, DateCreated, DateUpdated) "+
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                datas)
            return completion_callback

        self._db_context.queue_write(_write)

    def update(self, tx_id: str, metadata: TxData, bytedata: Optional[bytes],
            flags: Optional[int]=TxFlags.Unset,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        self.update_many([ (tx_id, metadata, bytedata, flags) ], completion_callback)

    @tprofiler
    def update_many(self, entries: List[Tuple[str, TxData, bytes, int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()

        datas = []
        for tx_id, metadata, bytedata, flags in entries:
            etx_id = self._encrypt_hex(tx_id)
            metadata_bytes, flags = self._pack_data(metadata, flags)
            emetadata = self._encrypt(metadata_bytes)
            ebytedata = None
            flags &= ~TxFlags.HasByteData
            if bytedata is not None:
                flags |= TxFlags.HasByteData
                ebytedata = self._encrypt(bytedata)
            datas.append((emetadata, ebytedata, flags, timestamp, self._group_id, etx_id))

        def _write(db: sqlite3.Connection) -> None:
            if len(entries) < 20:
                self._logger.debug("update %d transactions: %s", len(entries),
                    [ (a, b, byte_repr(c), TxFlags.to_repr(d)) for (a, b, c, d) in entries ])
            else:
                self._logger.debug("update %d transactions (too many to show)", len(entries))

            db.executemany(
                "UPDATE Transactions SET MetaData=?,ByteData=?,Flags=?,DateUpdated=? "+
                "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL",
                datas)
            return completion_callback

        self._db_context.queue_write(_write)

    def update_metadata(self, tx_id: str, data: TxData,
            flags: Optional[int]=TxFlags.Unset) -> None:
        # NOTE: This should only be used if it knows the existing flags column value, it should
        # preserve the state, bytedata and proofdata flags if it does not intend to clear them.
        self.update_metadata_many([ (tx_id, data, flags) ])

    @tprofiler
    def update_metadata_many(self, entries: List[Tuple[str, TxData, int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # NOTE: This should only be used if it knows the existing flags column value, it should
        # preserve the state, bytedata and proofdata flags if it does not intend to clear them.
        timestamp = self._get_current_timestamp()

        datas = []
        for tx_id, data, flags in entries:
            etx_id = self._encrypt_hex(tx_id)
            metadata_bytes, flags = self._pack_data(data, flags)
            emetadata = self._encrypt(metadata_bytes)
            datas.append((emetadata, flags, timestamp, self._group_id, etx_id))

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("update %d tx metadatas: %s", len(entries),
                [ (a, b, TxFlags.to_repr(c)) for (a, b, c) in entries ])

            db.executemany(
                "UPDATE Transactions SET MetaData=?,Flags=?,DateUpdated=? "+
                "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL",
                datas)
            return completion_callback

        self._db_context.queue_write(_write)

    @tprofiler
    def update_flags(self, tx_id: str, flags: int, mask: Optional[int]=TxFlags.Unset,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        etx_id = self._encrypt_hex(tx_id)

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("update_flags '%s'", tx_id)

            db.execute("UPDATE Transactions SET Flags=((Flags&?)|?), DateUpdated=? "+
                "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL",
                [mask, flags, timestamp, self._group_id, etx_id])
            return completion_callback

        self._db_context.queue_write(_write)

    @tprofiler
    def update_proof(self, tx_id: str, proof: TxProof,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        timestamp = self._get_current_timestamp()
        etx_id = self._encrypt_hex(tx_id)
        raw = self._pack_proof(proof)
        eraw = self._encrypt(raw)

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("updating %d transaction proof '%s'", 1, tx_id)
            db.execute(
                "UPDATE Transactions SET ProofData=?, DateUpdated=?, Flags=(Flags|?) "+
                "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL",
                [eraw, timestamp, TxFlags.HasProofData, self._group_id, etx_id])
            return completion_callback

        self._db_context.queue_write(_write)

    def delete(self, tx_id: str,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        self.delete_many([ tx_id ], completion_callback)

    @tprofiler
    def delete_many(self, tx_ids: Iterable[str],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # TODO: Integrate this with delete and look at using executemany.
        timestamp = self._get_current_timestamp()

        datas = []
        for tx_id in tx_ids:
            etx_id = self._encrypt_hex(tx_id)
            datas.append((timestamp, self._group_id, etx_id))

        def _write(db: sqlite3.Connection) -> None:
            self._logger.debug("deleted %d transactions", len(tx_ids))
            db.executemany("UPDATE Transactions SET DateDeleted=? "+
                "WHERE GroupId=? AND Key=? AND DateDeleted IS NULL", datas)
            return completion_callback

        self._db_context.queue_write(_write)


class TxXputCache(AbstractTransactionXput):
    def __init__(self, store, name: str):
        self._store = store
        self._name = name
        self._logger = logs.get_logger(name)

        self._logger.debug("Caching %s entries", name)
        cache_entries = store.get_all_entries()
        self._cache = self._process_cache(cache_entries)
        self._logger.debug("Cached %s entries", name)

    def add_entries(self, entries: Iterable[Tuple[str, tuple]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        new_entries = []
        for i, (tx_id, tx_xput) in enumerate(entries):
            cached_entries = self._cache.setdefault(tx_id, [])
            # We expect to add duplicates and to be responsible for filtering them out.
            if tx_xput not in cached_entries:
                cached_entries.append(tx_xput)
                new_entries.append(entries[i])
        if len(new_entries):
            self._store.add_entries(new_entries, completion_callback=completion_callback)

    def get_entries(self, tx_id: str) -> List[tuple]:
        if tx_id not in self._cache:
            return []
        return self._cache[tx_id].copy()

    def get_all_entries(self) -> Dict[str, List[tuple]]:
        return self._cache.copy()

    def delete_entries(self, entries: Iterable[Tuple[str, tuple]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        for tx_id, tx_xput in entries:
            cached_entries = self._cache[tx_id]
            cached_entries.remove(tx_xput)
        self._store.delete_entries(entries, completion_callback=completion_callback)

    def _process_cache(self, cache: Dict[str, List[tuple]], verbose: Optional[bool]=False) -> None:
        new_cache = {}
        duplicate_count = 0
        for tx_id, entries in list(cache.items()):
            map = {}
            for entry in entries:
                if entry in map:
                    if verbose:
                        self._logger.error(f"LOADED DUPLICATE TxXput {tx_id} entry {entry}")
                        # Clean up later. https://stackoverflow.com/a/25885564
                    else:
                        duplicate_count += 1
                map[entry] = True
            new_cache[tx_id] = list(map.keys())
        if duplicate_count > 0:
            self._logger.error(f"LOADED DUPLICATES store={self._name} count={duplicate_count}")
            # What is a duplicate is a symptom, observing how duplicates added is the diagnosis.
            self._store._delete_duplicates()
        return new_cache


class TxCacheEntry:
    def __init__(self, metadata: TxData, flags: int, bytedata: Optional[bytes]=None,
            time_loaded: Optional[float]=None, is_bytedata_cached: bool=True) -> None:
        self._transaction = None
        self.metadata = metadata
        self.bytedata = bytedata
        self._is_bytedata_cached = is_bytedata_cached
        assert bytedata is None or is_bytedata_cached, \
            f"bytedata consistency check {bytedata} {is_bytedata_cached}"
        self.flags = flags
        self.time_loaded = time.time() if time_loaded is None else time_loaded

    def is_metadata_cached(self):
        # At this time the metadata blob is always loaded, either by itself, or accompanying
        # the bytedata.
        return self.metadata is not None

    def is_bytedata_cached(self):
        # This indicates if we have read the underlying full entry, and not just the metadata.
        # Hence it is set by default, and only clear on explicit reads of the metadata.
        return self._is_bytedata_cached

    @property
    def transaction(self) -> None:
        if self._transaction is None:
            if self.bytedata is None:
                return None
            self._transaction = Transaction.from_bytes(self.bytedata)
        return self._transaction

    def __repr__(self):
        return (f"TxCacheEntry({self.metadata}, {TxFlags.to_repr(self.flags)}, "
            f"{byte_repr(self.bytedata)}, {self._is_bytedata_cached})")


class TxCache:
    _all_metadata_cached = False

    def __init__(self, store: TransactionStore, cache_metadata: bool=True) -> None:
        self.logger = logs.get_logger("tx-cache")
        self._cache = {}
        # self._cache_access = {}
        self._store = store

        self.update_proof = self._store.update_proof

        self._lock = threading.RLock()

        if cache_metadata:
            # Prime the cache with metadata for all transactions.
            self.logger.debug("Caching all existing metadata entries")
            self.get_metadatas()
            self._all_metadata_cached = True
            self.logger.debug("Cached all existing metadata entries")

    def _validate_transaction_bytes(self, tx_id: str, bytedata: Optional[bytes]) -> bool:
        if bytedata is None:
            return True
        hash_bytes = bitcoinx.double_sha256(bytedata)
        return bitcoinx.hash_to_hex_str(hash_bytes) == tx_id

    def _entry_visible(self, entry_flags: int, flags: Optional[int]=None,
            mask: Optional[int]=None) -> bool:
        """
        Filter an entry based on it's flag bits compared to an optional comparison flag and flag
        mask value.
        - No flag and no mask: keep.
        - No flag and mask: keep if any masked bits are set.
        - Flag and no mask: keep if any masked bits are set.
        - Flag and mask: keep if the masked bits are the flags.
        """
        if flags is None:
            if mask is None:
                return True
            return (entry_flags & mask) != 0
        if mask is None:
            return (entry_flags & flags) != 0
        return (entry_flags & mask) == flags

    @staticmethod
    def _adjust_field_flags(data: TxData, flags: TxFlags) -> TxFlags:
        flags &= ~TxFlags.METADATA_FIELD_MASK
        flags |= TxFlags.HasFee if data.fee is not None else 0
        flags |= TxFlags.HasHeight if data.height is not None else 0
        flags |= TxFlags.HasPosition if data.position is not None else 0
        flags |= TxFlags.HasTimestamp if data.timestamp is not None else 0
        return flags

    @staticmethod
    def _validate_new_flags(flags: TxFlags) -> None:
        # All current states are expected to have bytedata.
        if (flags & TxFlags.STATE_MASK) == 0 or (flags & TxFlags.HasByteData) != 0:
            return
        raise InvalidDataError(f"setting uncleared state without bytedata {flags}")

    def add_missing_transaction(self, tx_id: str, height: int, fee: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # TODO: Consider setting state based on height.
        self.add([ (tx_id, TxData(height=height, fee=fee), None, TxFlags.Unset) ],
            completion_callback=completion_callback)

    def add_transaction(self, tx: Transaction, flags: Optional[TxFlags]=TxFlags.Unset,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        tx_id = tx.txid()
        tx_hex = str(tx)
        bytedata = bytes.fromhex(tx_hex)
        self.update_or_add([ (tx_id, TxData(), bytedata, flags | TxFlags.HasByteData) ],
            completion_callback=completion_callback)

    def add(self, inserts: List[Tuple[str, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        with self._lock:
            return self._add(inserts, completion_callback=completion_callback)

    def _add(self, inserts: List[Tuple[str, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        access_time = time.time()
        for tx_id, metadata, bytedata, add_flags in inserts:
            assert tx_id not in self._cache, f"Tx {tx_id} found in cache unexpectedly"
            flags = self._adjust_field_flags(metadata, add_flags)
            if bytedata is not None:
                flags |= TxFlags.HasByteData
            assert ((add_flags & TxFlags.METADATA_FIELD_MASK) == 0 or
                flags == add_flags), f"{TxFlags.to_repr(flags)} != {TxFlags.to_repr(add_flags)}"
            self._validate_new_flags(flags)
            self._cache[tx_id] = TxCacheEntry(metadata, flags, bytedata)
            assert bytedata is None or self._cache[tx_id].is_bytedata_cached(), \
                "bytedata not flagged as cached"
            # self._cache_access[tx_id] = access_time

        self._store.add_many(inserts, completion_callback=completion_callback)

    def update(self, updates: List[Tuple[str, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        with self._lock:
            self._update(updates, completion_callback=completion_callback)

    def _update(self, updates: List[Tuple[str, TxData, Optional[bytes], TxFlags]],
            update_all: bool=True,
            completion_callback: Optional[CompletionCallbackType]=None) -> Set[str]:
        # NOTE: This does not set state flags at this time, from update flags.
        # We would need to pass in a per-row mask for that to work, perhaps.

        update_map = { t[0]: t for t in updates }
        desired_update_ids = set(update_map)
        skipped_update_ids = set([])
        actual_updates = {}
        # self.logger.debug("_update: desired_update_ids=%s", desired_update_ids)
        for tx_id, entry in self._get_entries(tx_ids=desired_update_ids, require_all=update_all):
            _discard, metadata, bytedata, flags = update_map[tx_id]
            # No-one should ever pass in field flags in normal circumstances.
            # In this case we use this to selectively merge the flagged fields in the update
            # to the cache entry data.
            fee = metadata.fee if flags & TxFlags.HasFee else entry.metadata.fee
            height = metadata.height if flags & TxFlags.HasHeight else entry.metadata.height
            position = metadata.position if flags & TxFlags.HasPosition else entry.metadata.position
            timestamp = (metadata.timestamp if flags & TxFlags.HasTimestamp
                else entry.metadata.timestamp)
            new_bytedata = bytedata if flags & TxFlags.HasByteData else entry.bytedata
            new_metadata = TxData(height, timestamp, position, fee)
            # Take the existing entry flags and set the state ones based on metadata present.
            new_flags = self._adjust_field_flags(new_metadata,
                entry.flags & ~TxFlags.STATE_MASK)
            # Take the declared metadata flags that apply and set them.
            if flags & TxFlags.STATE_MASK != 0:
                new_flags |= flags & TxFlags.STATE_MASK
            else:
                new_flags |= entry.flags & TxFlags.STATE_MASK
            if new_bytedata is None:
                new_flags &= ~TxFlags.HasByteData
            else:
                new_flags |= TxFlags.HasByteData
            if (entry.metadata == new_metadata and entry.bytedata == new_bytedata and
                    entry.flags == new_flags):
                # self.logger.debug("_update: skipped %s %r %s %r %s %s", tx_id, metadata,
                #     TxFlags.to_repr(flags), new_metadata, byte_repr(new_bytedata),
                #     entry.is_bytedata_cached())
                skipped_update_ids.add(tx_id)
            else:
                self._validate_new_flags(new_flags)
                is_full_entry = entry.is_bytedata_cached() or new_bytedata is not None
                new_entry = TxCacheEntry(new_metadata, new_flags, new_bytedata,
                    entry.time_loaded, is_full_entry)
                self.logger.debug("_update: %s %r %s %s %r %r HIT %s", tx_id,
                    metadata, TxFlags.to_repr(flags), byte_repr(bytedata),
                    entry, new_entry, new_bytedata is None and (new_flags & TxFlags.HasByteData))
                actual_updates[tx_id] = new_entry

        if len(actual_updates):
            self.set_cache_entries(actual_updates)
            update_entries = [
                (tx_id, entry.metadata, entry.bytedata, entry.flags)
                for tx_id, entry in actual_updates.items()
            ]
            self._store.update_many(update_entries, completion_callback=completion_callback)

        return set(actual_updates) | set(skipped_update_ids)

    def update_or_add(self, upadds: List[Tuple[str, TxData, Optional[bytes], int]],
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # We do not require that all updates are applied, because the subset that do not
        # exist will be inserted.
        with self._lock:
            updated_ids = self._update(upadds, update_all=False,
                completion_callback=completion_callback)
            if len(updated_ids) != len(upadds):
                self._add([ t for t in upadds if t[0] not in updated_ids ],
                    completion_callback=completion_callback)
            return updated_ids

    def update_flags(self, tx_id: str, flags: int, mask: Optional[int]=None,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        # This is an odd function. It logical ors metadata flags, but replaces the other
        # flags losing their values.
        if mask is None:
            mask = TxFlags.METADATA_FIELD_MASK
        else:
            mask |= TxFlags.METADATA_FIELD_MASK

        with self._lock:
            entry = self._get_entry(tx_id)
            entry.flags = (entry.flags & mask) | (flags & ~TxFlags.METADATA_FIELD_MASK)
            self._validate_new_flags(entry.flags)
            self._store.update_flags(tx_id, flags, mask, completion_callback=completion_callback)

    def delete(self, tx_id: str,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        with self._lock:
            self.logger.debug("cache_deletion: %s", tx_id)
            del self._cache[tx_id]
            self._store.delete(tx_id, completion_callback=completion_callback)

    def get_flags(self, tx_id: str) -> Optional[int]:
        # We cache all metadata, so this can avoid touching the database.
        entry = self.get_cached_entry(tx_id)
        if entry is not None:
            return entry.flags

    # def require_store_fetch(self, tx_id: str) -> bool:
    #     if tx_id in self._cache
    #     return False

    def set_cache_entries(self, entries: Dict[str, TxCacheEntry]) -> None:
        for tx_id, new_entry in entries.items():
            if tx_id in self._cache:
                entry = self._cache[tx_id]
                if entry.is_bytedata_cached() and not new_entry.is_bytedata_cached():
                    self.logger.debug(f"set_cache_entries, bytedata conflict v1 {tx_id}")
                    raise RuntimeError(f"bytedata conflict 1 for {tx_id}")
                if entry.bytedata is not None and new_entry.bytedata is None:
                    self.logger.debug(f"set_cache_entries, bytedata conflict v2 {tx_id}")
                    raise RuntimeError(f"bytedata conflict 2 for {tx_id}")
        self._cache.update(entries)

    # NOTE: Only used by unit tests at this time.
    def is_cached(self, tx_id: str) -> bool:
        return tx_id in self._cache

    def get_cached_entry(self, tx_id: str) -> Optional[TxCacheEntry]:
        if tx_id in self._cache:
            return self._cache[tx_id]

    def get_entry(self, tx_id: str, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[TxCacheEntry]:
        with self._lock:
            return self._get_entry(tx_id, flags, mask)

    def _get_entry(self, tx_id: str, flags: Optional[int]=None,
            mask: Optional[int]=None, force_store_fetch: bool=False) -> Optional[TxCacheEntry]:
        # We want to hit the cache, but only if we can give them what they want. Generally if
        # something is cached, then all we may lack is the bytedata.
        if not force_store_fetch and tx_id in self._cache:
            entry = self._cache[tx_id]
            # If they filter the entry they request, we only give them a matched result.
            if not self._entry_visible(entry.flags, flags, mask):
                return None
            # If they don't want bytedata, or they do and we have it cached, give them the entry.
            if mask is not None and (mask & TxFlags.HasByteData) == 0 or entry.is_bytedata_cached():
                # self._cache_access[tx_id] = time.time()
                return entry
            force_store_fetch = True
        if not force_store_fetch and self._all_metadata_cached:
            return None

        result = self._store.get(tx_id, flags, mask)
        if result is not None:
            metadata, bytedata, flags_get = result
            if bytedata is None or self._validate_transaction_bytes(tx_id, bytedata):
                # Overwrite any existing entry for this transaction. Due to the lock, and lack of
                # flushing we can assume that we will not be clobbering any fresh changes.
                entry = TxCacheEntry(metadata, flags_get, bytedata)
                self.set_cache_entries({ tx_id: entry })
                # self._cache_access[tx_id] = time.time()
                self.logger.debug("get_entry/cache_change: %r", (tx_id, entry,
                    TxFlags.to_repr(flags), TxFlags.to_repr(mask)))
                # If they filter the entry they request, we only give them a matched result.
                return entry if self._entry_visible(entry.flags, flags, mask) else None
            raise InvalidDataError(tx_id)

        # TODO: If something is requested that does not exist, it will miss the cache and wait
        # on the store access every time. It should be possible to cache misses and also maintain/
        # update them on other accesses. A complication is the flag/mask filtering, which will
        # not indicate presence of entries for the tx_id.
        return None

    def get_metadata(self, tx_id: str, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[TxCacheEntry]:
        with self._lock:
            return self._get_metadata(tx_id, flags, mask)

    def _get_metadata(self, tx_id: str, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[TxCacheEntry]:
        if tx_id in self._cache:
            entry = self._cache[tx_id]
            # self._cache_access[tx_id] = time.time()
            return entry.metadata if self._entry_visible(entry.flags, flags, mask) else None

        if not self._all_metadata_cached:
            result = self._store.get_metadata(tx_id, flags, mask)
            if result is not None:
                metadata, flags_get = result
                entry = TxCacheEntry(metadata, flags_get, is_bytedata_cached=False)
                self.set_cache_entries({ tx_id: entry })
                # self._cache_access[tx_id] = time.time()
                self.logger.debug("get_metadata/cache_change: %r", (tx_id, entry,
                    TxFlags.to_repr(flags), TxFlags.to_repr(mask)))
                return entry.metadata if self._entry_visible(entry.flags, flags, mask) else None

        # TODO: If something is requested that does not exist, it will miss the cache and wait
        # on the store access every time. It should be possible to cache misses and also maintain/
        # update them on other accesses. A complication is the flag/mask filtering, which will
        # not indicate presence of entries for the tx_id.
        return None

    def have_transaction_data(self, tx_id: str) -> bool:
        entry = self.get_cached_entry(tx_id)
        return entry is not None and (entry.flags & TxFlags.HasByteData) != 0

    def get_transaction(self, tx_id: str, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[Transaction]:
        # Ensure people do not ever use this to effectively request metadata and not require the
        # bytedata, meaning they get a result but it lacks what they expect it to have calling
        # this method.
        assert mask is None or (mask & TxFlags.HasByteData) != 0, "filter excludes transaction"
        entry = self.get_entry(tx_id, flags, mask)
        if entry is not None:
            return entry.transaction

    def get_entries(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_ids: Optional[Iterable[str]]=None,
            require_all: bool=True) -> List[Tuple[str, TxCacheEntry]]:
        with self._lock:
            return self._get_entries(flags, mask, tx_ids, require_all)

    def _get_entries(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_ids: Optional[Iterable[str]]=None,
            require_all: bool=True) -> List[Tuple[str, TxCacheEntry]]:
        # Raises MissingRowError if any transaction id in `tx_ids` is not in the cache afterward,
        # if `require_all` is set.
        store_tx_ids = set()
        cache_tx_ids = set()
        if tx_ids is not None:
            for tx_id in tx_ids:
                # We want to hit the cache, but only if we can give them what they want. Generally
                # if something is cached, then all we may lack is the bytedata.
                if tx_id not in store_tx_ids and tx_id in self._cache:
                    entry = self._cache[tx_id]
                    # If they filter the entry they request, we only give them a matched result.
                    if not self._entry_visible(entry.flags, flags, mask):
                        continue
                    # If they don't want bytedata, or they do and we have it cached, give them the
                    # entry.
                    if mask is not None and (mask & TxFlags.HasByteData) == 0 or \
                            entry.is_bytedata_cached():
                        # self._cache_access[tx_id] = time.time()
                        cache_tx_ids.add(tx_id)
                        continue
                    store_tx_ids.add(tx_id)
                if tx_id not in store_tx_ids:
                    if self._all_metadata_cached:
                        continue
                    store_tx_ids.add(tx_id)
        elif self._all_metadata_cached:
            tx_ids = []
            for tx_id, entry in self._cache.items():
                # We want to hit the cache, but only if we can give them what they want. Generally
                # if something is cached, then all we may lack is the bytedata.
                if tx_id not in store_tx_ids:
                    # If they filter the entry they request, we only give them a matched result.
                    if not self._entry_visible(entry.flags, flags, mask):
                        continue
                    # If they don't want bytedata, or they do and we have it cached, give them the
                    # entry.
                    if mask is not None and (mask & TxFlags.HasByteData) == 0 or \
                            entry.is_bytedata_cached():
                        # self._cache_access[tx_id] = time.time()
                        cache_tx_ids.add(tx_id)
                        continue
                    store_tx_ids.add(tx_id)
            tx_ids.extend(cache_tx_ids)
            tx_ids.extend(store_tx_ids)

        cache_additions = {}
        if tx_ids is None or len(store_tx_ids):
            # self.logger.debug("get_entries specific=%s flags=%s mask=%s", store_tx_ids,
            #     flags and TxFlags.to_repr(flags), mask and TxFlags.to_repr(mask))
            # We either fetch a known set of transactions, indicated by a non-empty set, or we
            # fetch all transactions matching the filter, indicated by an empty set.
            for tx_id, metadata, bytedata, get_flags in self._store.get_many(
                    flags, mask, store_tx_ids):
                # Ensure the bytedata is valid.
                if bytedata is not None and not self._validate_transaction_bytes(tx_id, bytedata):
                    raise InvalidDataError(tx_id)
                # TODO: assert if the entry is there, or it is there and we are not just getting the
                # missing bytedata.
                cache_additions[tx_id] = TxCacheEntry(metadata, get_flags, bytedata)
            self.logger.debug("get_entries/cache_additions: adds=%d", len(cache_additions))
            self.set_cache_entries(cache_additions)

        access_time = time.time()
        results = []
        if tx_ids is not None:
            for tx_id in store_tx_ids | cache_tx_ids:
                entry = self._cache.get(tx_id)
                assert entry is not None
                results.append((tx_id, entry))
        else:
            results = list(cache_additions.items())

        if require_all:
            assert tx_ids is not None
            wanted_ids = set(tx_ids)
            have_ids = set(t[0] for t in results)
            if wanted_ids != have_ids:
                raise MissingRowError(wanted_ids - have_ids)

            # self._cache_access.update([ (t[0], access_time) for t in cache_additions ])
        return results

    def get_metadatas(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_ids: Optional[Iterable[str]]=None,
            require_all: bool=True) -> List[Tuple[str, TxData]]:
        with self._lock:
            return self._get_metadatas(flags, mask, tx_ids, require_all)

    def _get_metadatas(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_ids: Optional[Iterable[str]]=None,
            require_all: bool=True) -> List[Tuple[str, TxData]]:
        if self._all_metadata_cached:
            return [
                t for t in self._cache.items() if self._entry_visible(t[1].flags, flags, mask)
            ]

        store_tx_ids = None
        if tx_ids is not None:
            store_tx_ids = [ tx_id for tx_id in tx_ids if tx_id not in self._cache ]

        cache_additions = {}
        existing_matches = []
        # tx_ids will be None and store_tx_ids will be None.
        # tx_ids will be a list, and store_tx_ids will be a list.
        if tx_ids is None or len(store_tx_ids):
            for tx_id, metadata, flags_get in self._store.get_metadata_many(
                    flags, mask, store_tx_ids):
                # We have no way of knowing if the match already exists, and if it does we should
                # take the possibly full/complete with bytedata cached version, rather than
                # corrupt the cache with the limited metadata version.
                if tx_id in self._cache:
                    existing_matches.append((tx_id, self._cache[tx_id]))
                else:
                    cache_additions[tx_id] = TxCacheEntry(metadata, flags_get,
                        is_bytedata_cached=False)
            self.logger.debug("get_metadatas/cache_additions: adds=%d haves=%d %r...",
                len(cache_additions),
                len(existing_matches), existing_matches[:5])
            self.set_cache_entries(cache_additions)

        results = []
        if store_tx_ids is not None and len(store_tx_ids):
            for tx_id in tx_ids:
                entry = self._cache.get(tx_id)
                if entry is None:
                    if require_all:
                        raise MissingRowError(tx_id)
                elif self._entry_visible(entry.flags, flags, mask):
                    results.append((tx_id, entry))
        else:
            results = list(cache_additions.items()) + existing_matches
        return results

    def get_transactions(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_ids: Optional[Iterable[str]]=None) -> List[Tuple[str, Transaction]]:
        # TODO: This should require that if bytedata is not cached for any entry, that that
        # entry has it's bytedata fetched and cached.
        results = []
        for tx_id, entry in self.get_entries(flags, mask, tx_ids):
            transaction = entry.transaction
            if transaction is not None:
                results.append((tx_id, transaction))
        return results

    def get_height(self, tx_id: str) -> Optional[int]:
        entry = self.get_cached_entry(tx_id)
        if entry is not None and entry.flags & (TxFlags.StateSettled|TxFlags.StateCleared):
            return entry.metadata.height

    def get_unsynced_ids(self) -> List[str]:
        entries = self.get_entries(flags=TxFlags.Unset, mask=TxFlags.HasByteData)
        return [ t[0] for t in entries ]

    def get_unverified_entries(self, watermark_height: int) -> Dict[str, int]:
        results = self.get_metadatas(
            flags=TxFlags.HasByteData | TxFlags.HasHeight,
            mask=TxFlags.HasByteData | TxFlags.HasTimestamp | TxFlags.HasPosition |
                 TxFlags.HasHeight)
        return [ t for t in results if 0 < t[1].metadata.height <= watermark_height ]

    def delete_reorged_entries(self, reorg_height: int,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        fetch_flags = TxFlags.StateSettled
        fetch_mask = TxFlags.StateSettled
        unverify_mask = ~(TxFlags.HasHeight | TxFlags.HasTimestamp | TxFlags.HasPosition |
            TxFlags.HasProofData | TxFlags.STATE_MASK)

        with self._lock:
            # NOTE(rt12): Strictly speaking we should be reading from the database only those
            # rows with relevant height, but all the metadata is cached anyway so not an issue.
            store_updates = []
            for (tx_id, entry) in self.get_metadatas(fetch_flags, fetch_mask):
                if entry.metadata.height > reorg_height:
                    # Update the cached version to match the changes we are going to apply.
                    entry.flags = (entry.flags & unverify_mask) | TxFlags.StateCleared
                    entry.metadata = TxData(0, 0, 0, entry.metadata.fee)
                    store_updates.append((tx_id, entry.metadata, entry.flags))
            if len(store_updates):
                self._store.update_metadata_many(store_updates,
                    completion_callback=completion_callback)
            return len(store_updates)


class WalletData:
    def __init__(self, db_context: DatabaseContext, aeskey: bytes, subwallet_id: int,
            migration_context: Optional[MigrationContext]=None) -> None:
        self.tx_store = TransactionStore(db_context, aeskey, subwallet_id,
            migration_context)
        self.txin_store = TransactionInputStore(db_context, aeskey, subwallet_id,
            migration_context)
        self.txout_store = TransactionOutputStore(db_context, aeskey, subwallet_id,
            migration_context)
        self.misc_store = ObjectKeyValueStore("HotData", db_context, aeskey, subwallet_id,
            migration_context)

        self.tx_cache = TxCache(self.tx_store)
        self.txin_cache = TxXputCache(self.txin_store, "txins")
        self.txout_cache = TxXputCache(self.txout_store, "txouts")

    def close(self) -> None:
        self.tx_store.close()
        self.txin_store.close()
        self.txout_store.close()
        self.misc_store.close()

    @property
    def tx(self) -> TxCache:
        return self.tx_cache

    @property
    def txin(self) -> TxXputCache:
        return self.txin_cache

    @property
    def txout(self) -> TxXputCache:
        return self.txout_cache

    @property
    def misc(self) -> ObjectKeyValueStore:
        return self.misc_store
