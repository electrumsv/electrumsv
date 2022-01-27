import os
from typing import Generator, NamedTuple

import pytest
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore[no-redef]

from electrumsv.wallet_database import functions as db_functions
from electrumsv.wallet_database.migration import create_database, update_database
from electrumsv.wallet_database.sqlite_support import DatabaseContext, SQLITE_MAX_VARS
from electrumsv.wallet_database.types import WalletDataRow
from electrumsv.wallet_database.util import bulk_insert_returning

from .util import PasswordToken


@pytest.fixture
def db_context() -> Generator[DatabaseContext, None, None]:
    unique_name = os.urandom(8).hex()
    db_filename = DatabaseContext.shared_memory_uri(unique_name)
    db_context = DatabaseContext(db_filename)
    yield db_context
    db_context.close()



class TestWalletDataTable:
    @classmethod
    def setup_class(cls):
        unique_name = os.urandom(8).hex()
        password_token = PasswordToken("123456")
        cls.db_filename = DatabaseContext.shared_memory_uri(unique_name)
        cls.db_context = DatabaseContext(cls.db_filename)
        # We hold onto an open connection to ensure that the database persists for the
        # lifetime of the tests.
        cls.db = cls.db_context.acquire_connection()
        create_database(cls.db)
        update_database(cls.db, password_token)

    @classmethod
    def teardown_class(cls):
        cls.db_context.release_connection(cls.db)
        cls.db_context.close()

    def setup_method(self):
        self.db.execute(f"DELETE FROM WalletData")
        self.db.commit()

    def test_create_and_read(self):
        k = os.urandom(10).hex()
        v = [os.urandom(10).hex()]

        future = db_functions.create_wallet_datas(self.db_context, [ WalletDataRow(k, v) ])
        future.result()

        values = dict(db_functions.read_wallet_datas(self.db_context))
        assert len(values) == 1
        assert values[k] == v

    def test_set(self) -> None:
        values = dict(db_functions.read_wallet_datas(self.db_context))
        assert len(values) == 0

        future = db_functions.set_wallet_datas(self.db_context, [ WalletDataRow("A", "B") ])
        future.result()

        values = dict(db_functions.read_wallet_datas(self.db_context))
        assert len(values) == 1
        assert values["A"] == "B"

        future = db_functions.set_wallet_datas(self.db_context, [ WalletDataRow("A", "C") ])
        future.result()

        values = dict(db_functions.read_wallet_datas(self.db_context))
        assert len(values) == 1
        assert values["A"] == "C"

    def test_delete(self):
        k = os.urandom(10).hex()
        v = [ os.urandom(10).hex() ]

        future = db_functions.set_wallet_datas(self.db_context, [ WalletDataRow(k, v) ])
        future.result()

        values = dict(db_functions.read_wallet_datas(self.db_context))
        assert len(values) == 1
        assert values[k] == v

        future = db_functions.delete_wallet_data(self.db_context, k)
        future.result()

        values = dict(db_functions.read_wallet_datas(self.db_context))
        assert len(values) == 0



def test_bulk_insert_returning(db_context) -> None:
    class OurRow(NamedTuple):
        column1: int
        column2: int
        column3: int

    rows_per_batch = int(SQLITE_MAX_VARS // 2)
    # Overflow into several batches to make sure we get this many rows.
    desired_row_count = int(rows_per_batch * 4.5)
    insert_rows = [ (i + 900000000, i +  800000000) for i in range(desired_row_count) ]

    def writer_function(db: sqlite3.Connection) -> list[OurRow]:
        db.execute("""
        CREATE TABLE table1 (
            column1 INTEGER PRIMARY KEY,
            column2 INTEGER,
            column3 INTEGER
        )""")

        return bulk_insert_returning(OurRow, db,
            "INSERT INTO table1 (column2, column3) VALUES",
            "RETURNING column1, column2, column3", insert_rows)

    returned_rows = db_context.run_in_thread(writer_function)
    expected_rows = set(insert_rows)
    unique_keys = set[int]()
    for returned_row in returned_rows:
        assert returned_row[1:] in expected_rows
        assert returned_row[0] not in unique_keys
        unique_keys.add(returned_row[0])

