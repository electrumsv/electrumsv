import os

from electrumsv.logs import logs
from electrumsv.wallet_database import functions as db_functions
from electrumsv.wallet_database.migration import create_database, update_database
from electrumsv.wallet_database.sqlite_support import DatabaseContext
from electrumsv.wallet_database.types import WalletDataRow

from .util import PasswordToken

logs.set_level("debug")



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


