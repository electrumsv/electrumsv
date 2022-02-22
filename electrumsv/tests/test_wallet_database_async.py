"""
Test:

* :class:`electrumsv.wallet_database.sqlite_support.SqliteExecutor`.

  * . . .

"""

import os
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore
import tempfile
from typing import Generator

from electrumsv_database.sqlite import DatabaseContext
import pytest


def _db_context():
    wallet_path = os.path.join(tempfile.mkdtemp(), "wallet_create")
    assert not os.path.exists(wallet_path)
    return DatabaseContext(wallet_path)


@pytest.fixture
def db_context() -> Generator[DatabaseContext, None, None]:
    value = _db_context()
    yield value
    value.close()



@pytest.mark.asyncio
async def test_executor_propagates_exception(db_context: DatabaseContext) -> None:
    def _test(db: sqlite3.Connection) -> None:
        1/0 # pylint: disable=pointless-statement
    # NOTE: This should only be called from the :mod:`electrumsv.wallet_database` module. Higher
    # level code should call the exposed API methods that SQL only appears in that module.
    with pytest.raises(ZeroDivisionError):
        await db_context.run_in_thread_async(_test)


@pytest.mark.asyncio
async def test_executor_wraps_database_access(db_context: DatabaseContext) -> None:
    def _test(db: sqlite3.Connection) -> int:
        db.execute("CREATE TABLE FirstTable ("
            "ft_id INTEGER PRIMARY KEY,"
            "ft_name TEXT NOT NULL"
        ")")
        cursor = db.executemany("INSERT INTO FirstTable (ft_name) VALUES (?)",
            [
                ("Alice",), ("Bob",), ("Carol",),
            ])
        return cursor.rowcount
    # NOTE: This should only be called from the :mod:`electrumsv.wallet_database` module. Higher
    # level code should call the exposed API methods that SQL only appears in that module.
    inserts = await db_context.run_in_thread_async(_test)
    assert inserts == 3

