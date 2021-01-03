import asyncio
import concurrent.futures
from enum import Enum
import queue
try:
    # Linux expects the latest package version of 3.34.0 (as of pysqlite-binary 0.4.5)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.34.0 (as of 2021-01-13).
    # Windows builds use the official Python 3.9.1 builds and bundled version of 3.33.0.
    import sqlite3 # type: ignore
import threading
import time
import traceback
from typing import Any, Callable, NamedTuple, Optional, Set, Tuple, Union

from ..constants import DATABASE_EXT
from ..logs import logs


class LeakedSQLiteConnectionError(Exception):
    pass


# TODO(rt12): Remove the special case exception for WAL journal mode and see if the in-memory
#     databases work now that there's locking preventing concurrent enabling of the WAL mode,
#     in addition to the backing off of retries at enabling it. I vaguely recall that it perhaps
#     was exacerbated on the Azure Pipelines CI, and had errors there it didn't when running
#     the unit tests locally (the unit tests exercise the in-memory storage).

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

# If the query deals with a list of values, then just batching using `SQLITE_MAX_VARS` should
# be enough. If it deals with expressions, then batch using the least of that and
# `SQLITE_EXPR_TREE_DEPTH`.
# - This shows how to estimate the maximum variables.
#   https://stackoverflow.com/a/36788489
# - This shows that even if you have higher maximum variables you get:
#   "Expression tree is too large (maximum depth 1000)"
#   https://github.com/electrumsv/electrumsv/issues/539
SQLITE_MAX_VARS = max_sql_variables()
SQLITE_EXPR_TREE_DEPTH = 1000


class WriteDisabledError(Exception):
    pass


WriteCallbackType = Union[Callable[[sqlite3.Connection], None], 'ExecutorItem']
CompletionCallbackType = Callable[[Optional[Exception]], None]
CompletionEntryType = Tuple[CompletionCallbackType, Optional[Exception]]

class WriteEntryType(NamedTuple):
    write_callback: WriteCallbackType
    completion_callback: Optional[CompletionCallbackType] = None


class SqliteWriteDispatcher:
    """
    This is a relatively simple write dispatcher for Sqlite that keeps all the writes on one thread,
    in order to avoid conflicts. Any higher level context that invokes a write, can choose to
    get notified on completion. If an exception happens in the course of a writer, the exception
    is passed back to the invoker in the completion notification.

    Completion notifications are done in a thread so as to not block the write dispatcher.
    """

    def __init__(self, db_context: "DatabaseContext") -> None:
        self._db_context = db_context
        self._logger = logs.get_logger("sqlite-writer")

        self._writer_queue: "queue.Queue[WriteEntryType]" = queue.Queue()
        self._writer_thread = threading.Thread(target=self._writer_thread_main, daemon=True)
        self._writer_loop_event = threading.Event()

        self._callback_thread_pool = concurrent.futures.ThreadPoolExecutor()

        self._allow_puts = True
        self._is_alive = True
        self._exit_when_empty = False

        self._writer_thread.start()

    def _writer_thread_main(self) -> None:
        self._db: sqlite3.Connection = self._db_context.acquire_connection()

        while self._is_alive:
            self._writer_loop_event.set()

            # Block until we have at least one write action. If we already have write
            # actions at this point, it is because we need to retry after a transaction
            # was rolled back.
            try:
                write_entry: WriteEntryType = self._writer_queue.get(timeout=0.1)
            except queue.Empty:
                if self._exit_when_empty:
                    return
                continue

            # Using the connection as a context manager, apply the batch as a transaction.
            time_start = time.time()
            if isinstance(write_entry.write_callback, ExecutorItem):
                write_entry.write_callback(self._db)
            else:
                # TODO(nocheckin) remove WriteCompletion stuff.
                self._db.execute("BEGIN")
                try:
                    # `isolation_level=None` means we opt to explicitly start transactions.
                    write_entry.write_callback(self._db)
                    self._db.execute("COMMIT")
                except Exception as e:
                    self._db.execute("ROLLBACK")
                    # The transaction was rolled back.
                    # Exception: This is caught because we need to relay any exception to the
                    # calling context's completion notification callback.
                    self._logger.exception("Database write failure", exc_info=e)
                    # If there was an error with this action then we've logged it, so we can discard
                    # it for lack of any other option.
                    if write_entry.completion_callback is not None:
                        self._callback_thread_pool.submit(self._dispatch_callback,
                            write_entry.completion_callback, e)
                else:
                    # The transaction was successfully committed.
                    if write_entry.completion_callback is not None:
                        _future = self._callback_thread_pool.submit(self._dispatch_callback,
                            write_entry.completion_callback, None)

                    time_ms = int((time.time() - time_start) * 1000)
                    self._logger.debug("Invoked write callback in %d ms", time_ms)

    def _dispatch_callback(self, callback: CompletionCallbackType,
            exc_value: Optional[Exception]) -> None:
        try:
            callback(exc_value)
        except Exception as e:
            traceback.print_exc()
            self._logger.exception("Exception within completion callback", exc_info=e)

    def put(self, write_entry: WriteEntryType) -> None:
        # If the writer is closed, then it is expected the caller should have made sure that
        # no more puts will be made, and the error will only be raised if something puts to
        # flag that it is wrong.
        if not self._allow_puts:
            raise WriteDisabledError()

        self._writer_queue.put_nowait(write_entry)

    def stop(self) -> None:
        if self._exit_when_empty:
            return

        self._allow_puts = False
        self._exit_when_empty = True

        # Wait for both threads to exit.
        self._writer_loop_event.wait()
        self._writer_thread.join()
        self._db_context.release_connection(self._db)
        self._callback_thread_pool.shutdown(wait=True)
        self._is_alive = False

    def is_stopped(self) -> bool:
        return not self._is_alive


class JournalModes(Enum):
    DELETE = "DELETE"
    TRUNCATE = "TRUNCATE"
    PERSIST = "PERSIST"
    MEMORY = "MEMORY"
    WAL = "WAL"
    OFF = "OFF"


class DatabaseContext:
    MEMORY_PATH = ":memory:"
    JOURNAL_MODE = JournalModes.WAL

    SQLITE_CONN_POOL_SIZE = 0

    def __init__(self, wallet_path: str) -> None:
        if not self.is_special_path(wallet_path) and not wallet_path.endswith(DATABASE_EXT):
            wallet_path += DATABASE_EXT
        self._db_path = wallet_path
        self._connection_pool: queue.Queue = queue.Queue()
        self._active_connections: Set = set()

        self._logger = logs.get_logger("sqlite-context")
        self._lock = threading.Lock()
        self._write_dispatcher = SqliteWriteDispatcher(self)
        self._executor = SqliteExecutor(self._write_dispatcher)

    def acquire_connection(self) -> sqlite3.Connection:
        try:
            conn = self._connection_pool.get_nowait()
        except queue.Empty:
            self.increase_connection_pool()
            conn = self._connection_pool.get_nowait()
        self._active_connections.add(conn)
        return conn

    def release_connection(self, connection: sqlite3.Connection) -> None:
        self._active_connections.remove(connection)
        self._connection_pool.put(connection)

    def increase_connection_pool(self) -> None:
        """adds 1 more connection to the pool"""
        self.SQLITE_CONN_POOL_SIZE += 1

        # pylint: disable=line-too-long
        # `isolation_level` is set to `None` in order to disable the automatic transaction
        # management in :mod:`sqlite3`. See the `Python documentation <https://docs.python.org/3/library/sqlite3.html#controlling-transactions>`_
        connection = sqlite3.connect(self._db_path, check_same_thread=False,
            isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000;")
        connection.execute("PRAGMA foreign_keys=ON;")
        # We do not enable journaling for in-memory databases. It resulted in 'database is locked'
        # errors. Perhaps it works now with the locking and backoff retries.
        if not self.is_special_path(self._db_path):
            self._ensure_journal_mode(connection)

        self._connection_pool.put(connection)

    def decrease_connection_pool(self) -> None:
        """release 1 more connection from the pool - raises empty queue error"""
        connection = self._connection_pool.get_nowait()
        connection.close()

    def _ensure_journal_mode(self, connection: sqlite3.Connection) -> None:
        with self._lock:
            cursor = connection.execute(f"PRAGMA journal_mode;")
            journal_mode = cursor.fetchone()[0]
            if journal_mode.upper() == self.JOURNAL_MODE.value:
                return

            self._logger.debug("Switching database from journal mode %s to journal mode %s",
                journal_mode.upper(), self.JOURNAL_MODE.value)

            time_start = time.time()
            attempt = 1
            delay = 0.05
            while True:
                try:
                    cursor = connection.execute(f"PRAGMA journal_mode={self.JOURNAL_MODE.value};")
                except sqlite3.OperationalError:
                    time_delta = time.time() - time_start
                    if time_delta < 10.0:
                        delay = min(delay, max(0.05, 10.0 - time_delta))
                        time.sleep(delay)
                        self._logger.warning("Database %s pragma attempt %d at %ds",
                            self.JOURNAL_MODE.value, attempt, time_delta)
                        delay *= 2
                        attempt += 1
                        continue
                    raise
                else:
                    journal_mode = cursor.fetchone()[0]
                    if journal_mode.upper() != self.JOURNAL_MODE.value:
                        self._logger.error(
                            "Database unable to switch from journal mode %s to journal mode %s",
                            self.JOURNAL_MODE.value, journal_mode.upper())
                        return
                    break

            self._logger.debug("Database now in journal mode %s", self.JOURNAL_MODE.value)

    def get_path(self) -> str:
        return self._db_path

    def queue_write(self, write_callback: WriteCallbackType,
            completion_callback: Optional[CompletionCallbackType]=None) -> None:
        self._write_dispatcher.put(WriteEntryType(write_callback, completion_callback))

    def close(self) -> None:
        self._write_dispatcher.stop()

        # Force close all outstanding connections
        outstanding_connections = list(self._active_connections)
        for conn in outstanding_connections:
            self.release_connection(conn)

        for conn in range(self.SQLITE_CONN_POOL_SIZE):
            self.decrease_connection_pool()

        leak_count = len(outstanding_connections)
        if leak_count:
            raise LeakedSQLiteConnectionError(f"Leaked {leak_count} SQLite connections "
                "when closing DatabaseContext.")
        assert self.is_closed(), f"{self._write_dispatcher.is_stopped()}"

    def is_closed(self) -> bool:
        return self._connection_pool.qsize() == 0 and self._write_dispatcher.is_stopped()

    def is_special_path(self, path: str) -> bool:
        # Each connection has a private database.
        if path == self.MEMORY_PATH:
            return True
        # Shared temporary in-memory database.
        # file:memdb1?mode=memory&cache=shared"
        if path.startswith("file:") and "mode=memory" in path:
            return True
        return False

    def post_to_thread(self, func, *args, **kwargs) -> concurrent.futures.Future:
        return self._executor.submit(func, *args, **kwargs)

    def run_in_thread(self, func, *args, **kwargs) -> Any:
        future = self._executor.submit(func, *args, **kwargs)
        return future.result()

    async def run_in_thread_async(self, func, *args) -> Any:
        """
        Yield the current task until the function has executed in the SQLite write thread.

        This should never be called from outside :mod:`electrumsv.wallet_database`. It is limited
        to positional arguments because that is all :meth:`asyncio.BaseEventLoop.run_in_executor`
        takes.

        The first argument will be the `sqlite3.Connection` instance of the database connection
        that should be used for writing (and reads related to the write). If the caller needs
        positional arguments to precede the database connection, they should use
        :meth:`functools.partial` to achieve that.

        .. code-block:: python

           def _writer(db: sqlite3.Connection) -> Any:
               cursor = db.execute("DELETE FROM Transactions WHERE tx_data IS NULL")
               return cursor.rowcount

           db_context.run_in_thread_async(_writer)
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, func, *args)

    @classmethod
    def shared_memory_uri(cls, unique_name: str) -> str:
        return f"file:{unique_name}?mode=memory&cache=shared"


class _QueryCompleter:
    def __init__(self):
        self._event = threading.Event()

        self._gave_callback = False
        self._have_result = False
        self._result: Any = None

    def get_callback(self) -> CompletionCallbackType:
        assert not self._gave_callback, "Query completer cannot be reused"
        def callback(exc_value: Optional[Exception]) -> None:
            self._have_result = True
            self._result = exc_value
            self._event.set()
        self._gave_callback = True
        return callback

    def succeeded(self) -> bool:
        assert self._gave_callback, "Query completer not active, no callback given out"
        if not self._have_result:
            self._event.wait()
        if self._result is None:
            return True
        exc_value = self._result
        self._result = None
        assert exc_value is not None
        raise exc_value # pylint: disable=raising-bad-type


class SynchronousWriter:
    def __init__(self):
        self._completer = _QueryCompleter()

    def __enter__(self):
        return self._completer

    def __exit__(self, _type, _value, _traceback):
        pass


# Based on `concurrent.futures.thread._ExecutorItem`.
# Relabels `run` to `__call__` and
class ExecutorItem(object):
    def __init__(self, future: concurrent.futures.Future, fn, args, kwargs) -> None:
        self._future = future
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def __call__(self, db: sqlite3.Connection) -> None:
        if not self._future.set_running_or_notify_cancel():
            return

        db.execute("BEGIN")
        try:
            result = self._fn(db, *self._args, **self._kwargs)
        except BaseException as exc:
            db.execute("ROLLBACK")
            self._future.set_exception(exc)
            # Break a reference cycle with the exception 'exc'
            self = None # type: ignore
        else:
            db.execute("COMMIT")
            self._future.set_result(result)


class SqliteExecutor(concurrent.futures.Executor):
    """
    Allow queueing SQLite database writes on the writer thread.

    At this time is is intended that this should only be used through
    :meth:`DatabaseContext.run_in_thread`, and not used directly.
    """
    def __init__(self, dispatcher: SqliteWriteDispatcher) -> None:
        self._dispatcher = dispatcher
        self._shutdown = False
        self._shutdown_lock = threading.Lock()
        self._shutdown_event = threading.Event()
        self._active_items = 0

    def submit(self, fn, *args, **kwargs) -> concurrent.futures.Future:
        with self._shutdown_lock:
            if self._shutdown:
                raise RuntimeError('cannot schedule new futures after shutdown')
            self._active_items += 1
            future: concurrent.futures.Future = concurrent.futures.Future()
            # Used to implement the wait on shutdown.
            future.add_done_callback(self._on_future_done)
            work_item = ExecutorItem(future, fn, args, kwargs)
            self._dispatcher.put(WriteEntryType(work_item))
            # Post the work item somewhere.
            return future

    def shutdown(self, wait: bool=True) -> None:
        with self._shutdown_lock:
            self._shutdown = True
        if wait:
            self._shutdown_event.wait()

    def _on_future_done(self, _future: concurrent.futures.Future) -> None:
        with self._shutdown_lock:
            self._active_items -= 1
            if self._active_items == 0:
                self._shutdown_event.set()


def replace_db_context_with_connection(func):
    def wrapped_call(db_context: DatabaseContext, *args, **kwargs):
        db = db_context.acquire_connection()
        try:
            return func(db, *args, **kwargs)
        finally:
            db_context.release_connection(db)
    return wrapped_call
