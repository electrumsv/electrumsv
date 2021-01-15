import os

from electrumsv.logs import logs
from electrumsv import wallet_database
from electrumsv.wallet_database import DatabaseContext 
from electrumsv.wallet_database import functions as db_functions
from electrumsv.wallet_database.migration import create_database, update_database
from electrumsv.wallet_database.types import TxProof, WalletDataRow

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


class MockTransactionStore:
    def update_proof(self, tx_hash: bytes, proof: TxProof) -> None:
        raise NotImplementedError

    # TODO(nocheckin) need replacement tests
    # def test_get_unverified_entries_too_high(self):
    #     cache = TransactionCache(self.db_context, self.store)

    #     tx_1 = Transaction.from_hex(tx_hex_1)
    #     tx_hash_1 = tx_1.hash()
    #     data = TxData(height=11, position=22, date_added=1, date_updated=1)
    #     with SynchronousWriter() as writer:
    #         cache.add([ (tx_hash_1, data, tx_1, TxFlags.STATE_SETTLED, None) ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     results = cache.get_unverified_entries(100)
    #     assert 0 == len(results)

    # def test_get_unverified_entries(self) -> None:
    #     cache = TransactionCache(self.db_context, self.store)

    #     tx_1 = Transaction.from_hex(tx_hex_1)
    #     tx_hash_1 = tx_1.hash()

    #     data = TxData(height=11, date_added=1, date_updated=1)
    #     with SynchronousWriter() as writer:
    #         cache.add([ (tx_hash_1, data, tx_1, TxFlags.STATE_SETTLED, None) ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     results = cache.get_unverified_entries(10)
    #     assert 0 == len(results)

    #     results = cache.get_unverified_entries(11)
    #     assert 1 == len(results)

    # def test_apply_reorg(self) -> None:
    #     common_height = 5
    #     cache = TransactionCache(self.db_context, self.store)

    #     # Add the transaction that should be reset back to settled, with data fields cleared.
    #     tx_y1 = Transaction.from_hex(tx_hex_1)
    #     tx_hash_y1 = tx_y1.hash()

    #     data_y1 = TxData(height=common_height+1, position=33, fee=44, date_added=1, date_updated=1)
    #     with SynchronousWriter() as writer:
    #         cache.add([ (tx_hash_y1, data_y1, tx_y1, TxFlags.STATE_SETTLED, None) ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # Add the transaction that would be reset but is below the common height.
    #     tx_n1 = Transaction.from_hex(tx_hex_2)
    #     tx_hash_n1 = tx_n1.hash()

    #     data_n1 = TxData(height=common_height-1, position=33, fee=44, date_added=1, date_updated=1)
    #     with SynchronousWriter() as writer:
    #         cache.add([ (tx_hash_n1, data_n1, tx_n1, TxFlags.STATE_SETTLED, None) ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # Add the transaction that would be reset but is the common height.
    #     tx_n2 = Transaction.from_hex(tx_hex_3)
    #     tx_hash_n2 = tx_n2.hash()

    #     data_n2 = TxData(height=common_height, position=33, fee=44, date_added=1, date_updated=1)
    #     with SynchronousWriter() as writer:
    #         cache.add([ (tx_hash_n2, data_n2, tx_n2, TxFlags.STATE_SETTLED, None) ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # Add a canary transaction that should remain untouched due to non-cleared state.
    #     tx_n3 = Transaction.from_hex(tx_hex_4)
    #     tx_hash_n3 = tx_n3.hash()

    #     data_n3 = TxData(height=111, position=333, fee=444, date_added=1, date_updated=1)
    #     with SynchronousWriter() as writer:
    #         cache.add([ (tx_hash_n3, data_n3, tx_n3, TxFlags.STATE_DISPATCHED, None) ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # Delete as if a reorg happened above the suitable but excluded canary transaction.
    #     with SynchronousWriter() as writer:
    #         cache.apply_reorg(5, completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     metadata_entries = cache.get_entries()
    #     assert 4 == len(metadata_entries)

    #     # Affected, canary above common height.
    #     y1 = [ m[1] for m in metadata_entries if m[0] == tx_hash_y1 ][0]
    #     assert 0 == y1.metadata.height
    #     assert None is y1.metadata.position
    #     assert data_y1.fee == y1.metadata.fee
    #     assert TxFlags.STATE_CLEARED | TxFlags.HasFee == y1.flags, TxFlags.to_repr(y1.flags)

    #     expected_flags = TxFlags.HasFee | TxFlags.HasHeight | TxFlags.HasPosition

    #     # Skipped, old enough to survive.
    #     n1 = [ m[1] for m in metadata_entries if m[0] == tx_hash_n1 ][0]
    #     assert data_n1.height == n1.metadata.height
    #     assert data_n1.position == n1.metadata.position
    #     assert data_n1.fee == n1.metadata.fee
    #     assert TxFlags.STATE_SETTLED | expected_flags == n1.flags, TxFlags.to_repr(n1.flags)

    #     # Skipped, canary common height.
    #     n2 = [ m[1] for m in metadata_entries if m[0] == tx_hash_n2 ][0]
    #     assert data_n2.height == n2.metadata.height
    #     assert data_n2.position == n2.metadata.position
    #     assert data_n2.fee == n2.metadata.fee
    #     assert TxFlags.STATE_SETTLED | expected_flags == n2.flags, TxFlags.to_repr(n2.flags)

    #     # Skipped, canary non-cleared.
    #     n3 = [ m[1] for m in metadata_entries if m[0] == tx_hash_n3 ][0]
    #     assert data_n3.height == n3.metadata.height
    #     assert data_n3.position == n3.metadata.position
    #     assert data_n3.fee == n3.metadata.fee
    #     assert TxFlags.STATE_DISPATCHED | expected_flags == n3.flags, TxFlags.to_repr(n3.flags)


# TODO(nocheckin) This is no longer valid, but we should really have some tests for it.
# class TestSqliteWriteDispatcher:
#     @classmethod
#     def setup_method(self):
#         self.dispatcher = None
#         self._logger = logs.get_logger("...")
#         class MockSqlite3Connection:
#             def __enter__(self, *args, **kwargs):
#                 pass
#             def __exit__(self, *args, **kwargs):
#                 pass
#             def execute(self, query: str) -> None:
#                 pass
#         class DbContext:
#             def acquire_connection(self):
#                 return MockSqlite3Connection()
#             def release_connection(self, connection):
#                 pass
#         self.db_context = DbContext()

#     @classmethod
#     def teardown_method(self):
#         if self.dispatcher is not None:
#             self.dispatcher.stop()

#     # As we use threading pytest can deadlock if something errors. This will break the deadlock
#     # and display stacktraces.
#     def test_write_dispatcher(self) -> None:
#         self.dispatcher = wallet_database.SqliteWriteDispatcher(self.db_context)
#         self.dispatcher._writer_loop_event.wait()

#         _write_callback_called = False
#         def _write_callback(conn):
#             nonlocal _write_callback_called
#             _write_callback_called = True

#         # NOTE DUD call
#         self.db_context.post_to_thread(_write_callback)
#         self.dispatcher.stop()

#         assert _write_callback_called

