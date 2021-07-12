import os

from electrumsv.logs import logs
from electrumsv.wallet_database import functions as db_functions
from electrumsv.wallet_database.migration import create_database, update_database
from electrumsv.wallet_database.sqlite_support import DatabaseContext
from electrumsv.wallet_database.types import WalletDataRow

logs.set_level("debug")


tx_hex_1 = ("01000000011a284a701e6a69ba68ac4b1a4509ac04f5c10547e3165fe869d5e910fe91bc4c04000000"+
    "6b483045022100e81ce3382de4d63efad1e2bc4a7ebe70fb03d8451c1bc176b2dfd310f7a636f302200eab4382"+
    "9f9d4c94be41c640f9f6261657dcac6dc345718b89e7a80645dbe27f412102defddf740fa60b0dcdc88578d9de"+
    "a51350db9245e4f1a5072be00e9fb0573fddffffffff02a0860100000000001976a914717b9a7840ef60ef2e2a"+
    "6fca85d55988e070137988acda837e18000000001976a914c0eab5430fd02e18edfc28607eae975001e7560488"+
    "ac00000000")

tx_hex_2 = ("010000000113529b6e34ceebfa3911c569b568ef48b95cc25d4c5c6a5b2435d30c9dbcc8af0000000"+
    "06b483045022100876dfdc3228ff561531c3ba02e2ad9628230f02ef5036599e1c95b747e1731ac02205ed9ff1"+
    "14adc6e7ca58b889272afa695d7f62902bb81286bb46aee7d3a31201e412102642f0cfdb3065d34276c8af2183"+
    "e7d0d8e8e2ce85723eb6fe4942d0db949a225ffffffff027c150000000000001976a91439826f4659bba2a224b"+
    "87b1812206fd4efc9ada388acc0dd3e00000000001976a914337106761eb441a326d4027f6d5aa19eed550c298"+
    "8ac00000000")

tx_hex_3 = ("01000000011953528c5b35f5ec81031738445eab87607214e7206a72b94c74653e1bf962ce00000000"+
    "6a47304402205cbc645cc4fc9e3c303ca1ec25439819482e88c2fd1297ca7d4de60c1cc9971702204a903faebe"+
    "1373d16d832ef1f97043ddd5a4759114017894d57891186277cb1f412103e2a28ed23d71e7747e12b60c425319"+
    "57839e0a07503c4baecf679f73222b63e2ffffffff03000000000000000009006a0648656c6c6f0a68c18e4500"+
    "0000001976a9143037f09afa26dca90a4870fe94e8efdec9992faa88ac1e37744f000000001976a914adcbfd68"+
    "6766d3dadfdd8c438185608cd727441288aceb000000")

tx_hex_4 = ("0100000001ee315ce3d4792c50f3b8a7ea3c4e848dd6fa17bb8da4244166563bb98d1084cb01000000"+
    "6b483045022100a509bb7f733863a2f677e5feae921cfbaa43077bc5567bf05a4d26fcb02d344a02206b0f16dc"+
    "1ff0f540601ca480c7af27241e3c5080ab56a65a28a55f0d5d6315c041210205e928059e9fbfd9a981f5e8f878"+
    "429ede9d69f90d9122b32619f4f225659dd2ffffffff02000000000000000009006a0648656c6c6f0af5030000"+
    "000000001976a914adcbfd686766d3dadfdd8c438185608cd727441288aceb000000")



class TestWalletDataTable:
    @classmethod
    def setup_class(cls):
        unique_name = os.urandom(8).hex()
        cls.db_filename = DatabaseContext.shared_memory_uri(unique_name)
        cls.db_context = DatabaseContext(cls.db_filename)
        # We hold onto an open connection to ensure that the database persists for the
        # lifetime of the tests.
        cls.db = cls.db_context.acquire_connection()
        create_database(cls.db)
        update_database(cls.db)

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


