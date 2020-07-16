import os
import pytest
from typing import Tuple, Optional

import bitcoinx

from electrumsv.constants import TxFlags, TRANSACTION_FLAGS
from electrumsv.transaction import Transaction
from electrumsv.logs import logs
from electrumsv import wallet_database
from electrumsv.wallet_database import (DatabaseContext, SynchronousWriter, TxData, TxProof,
    TransactionCache, TransactionCacheEntry)
from electrumsv.wallet_database.migration import create_database, update_database
from electrumsv.wallet_database.sqlite_support import WriteEntryType
from electrumsv.wallet_database.tables import WalletDataRow

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
        cls.store = wallet_database.WalletDataTable(cls.db_context)

    @classmethod
    def teardown_class(cls):
        del cls.store._get_current_timestamp
        cls.store.close()
        cls.db_context.release_connection(cls.db)
        cls.db_context.close()

    def setup_method(self):
        self.store._get_current_timestamp = self._get_timestamp
        self._timestamp = 1
        db = self.store._db
        db.execute(f"DELETE FROM WalletData")
        db.commit()

    def _get_timestamp(self) -> int:
        return self._timestamp

    @pytest.mark.timeout(5)
    def test_add(self):
        k = os.urandom(10).hex()
        v = [os.urandom(10).hex()]

        self.store.timestamp = 1
        with SynchronousWriter() as writer:
            self.store.create([ WalletDataRow(k, v) ], completion_callback=writer.get_callback())
            assert writer.succeeded()

        row = self.store.get_row(k)
        assert row is not None
        assert isinstance(row, WalletDataRow)
        assert row.key == k # key
        assert row.value == v # ByteData

    @pytest.mark.timeout(5)
    def test_create(self):
        kvs = [ WalletDataRow(os.urandom(10).hex(), [os.urandom(10).hex()]) for i in range(10) ]

        self.store.timestamp = 1
        with SynchronousWriter() as writer:
            self.store.create(kvs, completion_callback=writer.get_callback())
            assert writer.succeeded()

        kvs2 = self.store.read([ k for (k, v) in kvs ])
        assert len(kvs) == len(kvs2)
        for t in kvs:
            assert t in kvs2

    @pytest.mark.timeout(5)
    def test_update(self) -> None:
        original_values = {}
        for i in range(10):
            k = os.urandom(10).hex()
            v1 = { "value": os.urandom(10).hex() }
            original_values[k] = v1
        entries = [ WalletDataRow(*t) for t in original_values.items() ]
        with SynchronousWriter() as writer:
            self.store.create(entries, completion_callback=writer.get_callback())
            assert writer.succeeded()

        new_values = original_values.copy()
        for k in original_values.keys():
            new_values[k] = { "value": os.urandom(10).hex() }
        entries = [ WalletDataRow(*t) for t in new_values.items() ]
        with SynchronousWriter() as writer:
            self.store.update(entries, completion_callback=writer.get_callback())
            assert writer.succeeded()

        rows = self.store.read()
        assert len(rows) == len(new_values)
        for row in rows:
            assert row in entries

    def test_get_value_nonexistent(self) -> None:
        assert self.store.get_value("nonexistent") is None

    @pytest.mark.timeout(5)
    def test_upsert(self) -> None:
        with SynchronousWriter() as writer:
            self.store.upsert([ WalletDataRow("A", "B") ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()
        assert self.store.get_value("A") == "B"

        with SynchronousWriter() as writer:
            self.store.upsert([ WalletDataRow("A", "C") ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        assert self.store.get_value("A") == "C"
        values = self.store.read([ "A" ])
        assert len(values) == 1

    @pytest.mark.timeout(5)
    def test_get(self):
        k = os.urandom(10).hex()
        v = os.urandom(10).hex()
        with SynchronousWriter() as writer:
            self.store.create([ WalletDataRow(k, v) ], completion_callback=writer.get_callback())
            assert writer.succeeded()
        byte_data = self.store.get_value(k)
        assert byte_data is not None
        assert byte_data == v

    @pytest.mark.timeout(5)
    def test_delete(self):
        k = os.urandom(10).hex()
        v = [ os.urandom(10).hex() ]

        self.store.timestamp = 1
        with SynchronousWriter() as writer:
            self.store.create([ WalletDataRow(k, v) ], completion_callback=writer.get_callback())
            assert writer.succeeded()

        self.store.timestamp = 2
        with SynchronousWriter() as writer:
            self.store.delete(k, completion_callback=writer.get_callback())
            assert writer.succeeded()

        row = self.store.get_row(k)
        assert row is None


class MockTransactionStore:
    def update_proof(self, tx_hash: bytes, proof: TxProof) -> None:
        raise NotImplementedError


class TestTransactionCache:
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
        cls.store = wallet_database.TransactionTable(cls.db_context)

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.db_context.release_connection(cls.db)
        cls.db_context.close()

    def setup_method(self):
        db = self.store._db
        db.execute(f"DELETE FROM Transactions")
        db.commit()

    def test_entry_visible(self):
        cache = TransactionCache(self.store)

        combos = [
            (TxFlags.Unset, None, None, True),
            (TxFlags.Unset, None, TxFlags.HasHeight, False),
            (TxFlags.HasHeight, None, TxFlags.HasHeight, True),
            (TxFlags.HasHeight, TxFlags.HasHeight, None, True),
            (TxFlags.HasHeight, TxFlags.HasHeight, TxFlags.HasFee, False),
            (TxFlags.HasHeight, TxFlags.HasHeight, TxFlags.HasHeight, True),
            (TxFlags.HasFee, TxFlags.HasHeight, TxFlags.HasHeight, False),
        ]
        for i, (flag_bits, flags, mask, result) in enumerate(combos):
            actual_result = cache._entry_visible(flag_bits, flags, mask)
            assert result == actual_result, str(combos[i])

    @pytest.mark.timeout(5)
    def test_add_transaction(self):
        cache = TransactionCache(self.store)

        tx = Transaction.from_hex(tx_hex_1)
        tx_hash = tx.hash()
        with SynchronousWriter() as writer:
            cache.add_transaction(tx_hash, tx, completion_callback=writer.get_callback())
            assert writer.succeeded()

        assert cache.is_cached(tx_hash)
        entry = cache.get_entry(tx_hash)
        assert TxFlags.HasByteData == entry.flags & TxFlags.HasByteData
        assert cache.have_transaction_data_cached(tx_hash)

    @pytest.mark.timeout(5)
    def test_add_transaction_update(self):
        cache = TransactionCache(self.store)

        tx = Transaction.from_hex(tx_hex_1)
        tx_hash = tx.hash()
        data = [ tx.hash(), TxData(height=1295924,position=4,fee=None, date_added=1,
            date_updated=1), None, TxFlags.Unset, None ]
        with SynchronousWriter() as writer:
            cache.add([ data ], completion_callback=writer.get_callback())
            assert writer.succeeded()

        entry = cache.get_entry(tx_hash)
        assert entry is not None
        assert TxFlags.Unset == entry.flags & TxFlags.STATE_MASK

        with SynchronousWriter() as writer:
            cache.add_transaction(tx_hash, tx, TxFlags.StateCleared,
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        entry = cache.get_entry(tx_hash)
        assert entry is not None
        assert cache.have_transaction_data_cached(tx_hash)
        assert TxFlags.StateCleared == entry.flags & TxFlags.StateCleared

    @pytest.mark.timeout(5)
    def test_add_then_update(self):
        cache = TransactionCache(self.store)

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()
        metadata_1 = TxData(position=11)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, metadata_1, tx_1, TxFlags.StateDispatched, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        assert cache.is_cached(tx_hash_1)
        entry = cache.get_entry(tx_hash_1)
        assert TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.StateDispatched == entry.flags
        assert cache.have_transaction_data_cached(tx_hash_1)

        # NOTE: We are not updating bytedata, and it should remain the same. The flags we pass
        # into update are treated specially to achieve this.
        metadata_2 = TxData(fee=10, height=88)
        propagate_flags = TxFlags.HasFee | TxFlags.HasHeight
        with SynchronousWriter() as writer:
            cache.update([ (tx_hash_1, metadata_2, None, propagate_flags | TxFlags.HasPosition) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Check the cache to see that the flags are correct and that bytedata is cached.
        entry = cache.get_entry(tx_hash_1)
        expected_flags = propagate_flags | TxFlags.StateDispatched | TxFlags.HasByteData
        assert expected_flags == entry.flags, \
            f"{TxFlags.to_repr(expected_flags)} !=  {TxFlags.to_repr(entry.flags)}"
        assert cache.have_transaction_data_cached(tx_hash_1)

        # Check the store to see that the flags are correct and the bytedata is retained.
        rows = self.store.read(tx_hashes=[tx_hash_1])
        assert 1 == len(rows)
        get_tx_hash, bytedata_get, flags_get, metadata_get = rows[0]
        assert tx_1.to_bytes() == bytedata_get
        assert flags_get & TxFlags.HasByteData != 0

    @pytest.mark.timeout(5)
    def test_delete(self):
        cache = TransactionCache(self.store)

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()
        data = TxData(position=11)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, data, tx_1, TxFlags.StateDispatched, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        assert len(self.store.read_metadata(tx_hashes=[ tx_hash_1 ]))
        assert cache.is_cached(tx_hash_1)

        with SynchronousWriter() as writer:
            cache.delete(tx_hash_1, completion_callback=writer.get_callback())
            assert writer.succeeded()

        assert not len(self.store.read_metadata(tx_hashes=[ tx_hash_1 ]))
        assert not cache.is_cached(tx_hash_1)

    @pytest.mark.timeout(5)
    def test_uncleared_bytedata_requirements(self) -> None:
        cache = TransactionCache(self.store)

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()
        data = TxData(position=11)
        for state_flag in TRANSACTION_FLAGS:
            with pytest.raises(wallet_database.InvalidDataError):
                cache.add([ (tx_hash_1, data, None, state_flag, None) ])

        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, data, tx_1, TxFlags.StateSigned, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # We are applying a clearing of the bytedata, this should be invalid given uncleared.
        for state_flag in TRANSACTION_FLAGS:
            with pytest.raises(wallet_database.InvalidDataError):
                cache.update([ (tx_hash_1, data, None, state_flag | TxFlags.HasByteData) ])

    @pytest.mark.timeout(5)
    def test_get_flags(self):
        cache = TransactionCache(self.store)

        assert cache.get_flags(os.urandom(10).hex()) is None

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()
        data = TxData(position=11)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, data, tx_1, TxFlags.StateDispatched, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        assert cache.is_cached(tx_hash_1)
        assert TxFlags.StateDispatched | TxFlags.HasByteData | TxFlags.HasPosition == \
            cache.get_flags(tx_hash_1)

    @pytest.mark.timeout(5)
    def test_get_metadata(self):
        # Full entry caching for non-settled transactions, otherwise only metadata.
        bytedata_set_1 = bytes.fromhex(tx_hex_1)
        tx_hash_1 = bitcoinx.double_sha256(bytedata_set_1)
        metadata_set_1 = TxData(height=None, fee=2, position=None, date_added=1, date_updated=1)
        bytedata_set_2 = bytes.fromhex(tx_hex_2)
        tx_hash_2 = bitcoinx.double_sha256(bytedata_set_2)
        metadata_set_2 = TxData(height=1, fee=2, position=10, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            self.store.create([ (tx_hash_1, metadata_set_1, bytedata_set_1, TxFlags.Unset, None),
                (tx_hash_2, metadata_set_2, bytedata_set_2, TxFlags.StateSettled, None), ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        cache = TransactionCache(self.store)
        metadata_get = cache.get_metadata(tx_hash_1)
        assert metadata_set_1.height == metadata_get.height
        assert metadata_set_1.fee == metadata_get.fee
        assert metadata_set_1.position == metadata_get.position

        metadata_get = cache.get_metadata(tx_hash_2)
        assert metadata_set_2.height == metadata_get.height
        assert metadata_set_2.fee == metadata_get.fee
        assert metadata_set_2.position == metadata_get.position

        entry = cache._cache[tx_hash_1]
        assert cache.have_transaction_data_cached(tx_hash_1)

        entry = cache._cache[tx_hash_2]
        assert not cache.have_transaction_data_cached(tx_hash_2)

    @pytest.mark.timeout(5)
    def test_get_transaction_after_metadata(self):
        # Getting an entry for a settled transaction should update from metadata-only to full.
        bytedata_set = bytes.fromhex(tx_hex_1)
        tx_hash = bitcoinx.double_sha256(bytedata_set)
        metadata_set = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            self.store.create([ (tx_hash, metadata_set, bytedata_set, TxFlags.StateSettled, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        cache = TransactionCache(self.store)
        metadata_get = cache.get_metadata(tx_hash)
        assert metadata_get is not None

        # Initial priming of cache will be only metadata.
        cached_entry_1 = cache._cache[tx_hash]
        assert not cache.have_transaction_data_cached(tx_hash)

        # Entry request will hit the database.
        entry = cache.get_entry(tx_hash)
        assert cache.have_transaction_data_cached(tx_hash)

        cached_entry_2 = cache._cache[tx_hash]
        assert entry.metadata == cached_entry_2.metadata
        assert entry.flags == cached_entry_2.flags

    @pytest.mark.timeout(5)
    def test_get_transaction(self):
        bytedata = bytes.fromhex(tx_hex_1)
        tx_hash = bitcoinx.double_sha256(bytedata)
        metadata = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            self.store.create([ (tx_hash, metadata, bytedata, TxFlags.Unset, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        cache = TransactionCache(self.store)
        tx = cache.get_transaction(tx_hash)
        assert tx is not None
        assert tx_hash == tx.hash()

    @pytest.mark.timeout(5)
    def test_get_transactions(self):
        tx_hashes = []
        for tx_hex in (tx_hex_1, tx_hex_2):
            tx_bytes = bytes.fromhex(tx_hex)
            tx_hash = bitcoinx.double_sha256(tx_bytes)
            data = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
            with SynchronousWriter() as writer:
                self.store.create([ (tx_hash, data, tx_bytes, TxFlags.Unset, None) ],
                    completion_callback=writer.get_callback())
                assert writer.succeeded()
            tx_hashes.append(tx_hash)

        cache = TransactionCache(self.store)
        for (tx_hash, tx) in cache.get_transactions(tx_hashes=tx_hashes):
            assert tx is not None
            assert tx_hash in  tx_hashes

    @pytest.mark.timeout(5)
    def test_get_entry(self):
        cache = TransactionCache(self.store)

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()
        data = TxData(position=11)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, data, tx_1, TxFlags.StateSettled, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        entry = cache.get_entry(tx_hash_1, TxFlags.StateDispatched)
        assert entry is None

        entry = cache.get_entry(tx_hash_1, TxFlags.StateSettled)
        assert entry is not None

    # No complete cache of metadata, tx_hash in cache, store not hit.
    def test_get_entry_cached_already(self) -> None:
        metadata = TxData(position=11, date_added=1, date_updated=1)
        flags = TxFlags.HasPosition
        def _read(*args, **kwargs) -> Tuple[bytes, Optional[bytes], TxFlags, TxData]:
            nonlocal metadata, flags
            return [ (b"tx_hash", None, flags, metadata) ]
        def _read_metadata(*args, **kwargs) -> Tuple[bytes, TxFlags, TxData]:
            nonlocal metadata, flags
            return [ (b"tx_hash", flags, metadata) ]

        mock_store = MockTransactionStore()
        mock_store.read = _read
        mock_store.read_metadata = _read_metadata

        cache = TransactionCache(mock_store, 0)

        # Verify that we do not hit the store for our cached entry.
        our_entry = TransactionCacheEntry(metadata, TxFlags.HasPosition)
        cache._cache[b"tx_hash"] = our_entry

        their_entry = cache.get_entry(b"tx_hash")
        assert our_entry.metadata == their_entry.metadata
        assert our_entry.flags == their_entry.flags

    # No complete cache of metadata, tx_hash not in cache, store hit.
    def test_get_entry_cached_on_demand(self) -> None:
        metadata = TxData(position=11, date_added=1, date_updated=1)
        flags = TxFlags.HasPosition
        def _read(*args, **kwargs) -> Tuple[bytes, Optional[bytes], TxFlags, TxData]:
            nonlocal metadata, flags
            return [ (b"tx_hash", None, flags, metadata) ]
        def _read_metadata(*args, **kwargs) -> Tuple[bytes, TxFlags, TxData]:
            nonlocal metadata, flags
            return [ (b"tx_hash", flags, metadata) ]

        mock_store = MockTransactionStore()
        mock_store.read = _read
        mock_store.read_metadata = _read_metadata

        cache = TransactionCache(mock_store, 0)
        their_entry = cache.get_entry(b"tx_hash")
        assert their_entry.metadata == metadata
        assert their_entry.flags == flags

    @pytest.mark.timeout(5)
    def test_get_height(self):
        cache = TransactionCache(self.store)

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()
        metadata_1 = TxData(height=11)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, metadata_1, tx_1, TxFlags.StateSettled, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        assert 11 == cache.get_height(tx_hash_1)

        cache.update_flags(tx_hash_1, TxFlags.StateCleared, TxFlags.HasByteData)
        assert 11 == cache.get_height(tx_hash_1)

        cache.update_flags(tx_hash_1, TxFlags.StateReceived, TxFlags.HasByteData)
        assert None is cache.get_height(tx_hash_1)

    @pytest.mark.timeout(5)
    def test_get_unsynced_hashes(self):
        cache = TransactionCache(self.store)

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()
        metadata_1 = TxData(height=11)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, metadata_1, None, TxFlags.Unset, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        results = cache.get_unsynced_hashes()
        assert 1 == len(results)

        metadata_2 = TxData()
        with SynchronousWriter() as writer:
            cache.update([ (tx_hash_1, metadata_2, tx_1, TxFlags.HasByteData) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        results = cache.get_unsynced_hashes()
        assert 0 == len(results)

    def test_get_unverified_entries_too_high(self):
        cache = TransactionCache(self.store)

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()
        data = TxData(height=11, position=22, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, data, tx_1, TxFlags.StateSettled, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        results = cache.get_unverified_entries(100)
        assert 0 == len(results)

    def test_get_unverified_entries(self) -> None:
        cache = TransactionCache(self.store)

        tx_1 = Transaction.from_hex(tx_hex_1)
        tx_hash_1 = tx_1.hash()

        data = TxData(height=11, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_1, data, tx_1, TxFlags.StateSettled, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        results = cache.get_unverified_entries(10)
        assert 0 == len(results)

        results = cache.get_unverified_entries(11)
        assert 1 == len(results)

    @pytest.mark.timeout(5)
    def test_apply_reorg(self) -> None:
        common_height = 5
        cache = TransactionCache(self.store)

        # Add the transaction that should be reset back to settled, with data fields cleared.
        tx_y1 = Transaction.from_hex(tx_hex_1)
        tx_hash_y1 = tx_y1.hash()

        data_y1 = TxData(height=common_height+1, position=33, fee=44, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_y1, data_y1, tx_y1, TxFlags.StateSettled, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Add the transaction that would be reset but is below the common height.
        tx_n1 = Transaction.from_hex(tx_hex_2)
        tx_hash_n1 = tx_n1.hash()

        data_n1 = TxData(height=common_height-1, position=33, fee=44, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_n1, data_n1, tx_n1, TxFlags.StateSettled, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Add the transaction that would be reset but is the common height.
        tx_n2 = Transaction.from_hex(tx_hex_3)
        tx_hash_n2 = tx_n2.hash()

        data_n2 = TxData(height=common_height, position=33, fee=44, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_n2, data_n2, tx_n2, TxFlags.StateSettled, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Add a canary transaction that should remain untouched due to non-cleared state.
        tx_n3 = Transaction.from_hex(tx_hex_4)
        tx_hash_n3 = tx_n3.hash()

        data_n3 = TxData(height=111, position=333, fee=444, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            cache.add([ (tx_hash_n3, data_n3, tx_n3, TxFlags.StateDispatched, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Delete as if a reorg happened above the suitable but excluded canary transaction.
        with SynchronousWriter() as writer:
            cache.apply_reorg(5, completion_callback=writer.get_callback())
            assert writer.succeeded()

        metadata_entries = cache.get_entries(TxFlags.HasByteData, TxFlags.HasByteData)
        assert 4 == len(metadata_entries)

        # Affected, canary above common height.
        y1 = [ m[1] for m in metadata_entries if m[0] == tx_hash_y1 ][0]
        assert 0 == y1.metadata.height
        assert None is y1.metadata.position
        assert data_y1.fee == y1.metadata.fee
        assert TxFlags.StateCleared | TxFlags.HasByteData | TxFlags.HasFee == y1.flags, \
            TxFlags.to_repr(y1.flags)

        expected_flags = (TxFlags.HasByteData | TxFlags.HasFee |
            TxFlags.HasHeight | TxFlags.HasPosition)

        # Skipped, old enough to survive.
        n1 = [ m[1] for m in metadata_entries if m[0] == tx_hash_n1 ][0]
        assert data_n1.height == n1.metadata.height
        assert data_n1.position == n1.metadata.position
        assert data_n1.fee == n1.metadata.fee
        assert TxFlags.StateSettled | expected_flags == n1.flags, TxFlags.to_repr(n1.flags)

        # Skipped, canary common height.
        n2 = [ m[1] for m in metadata_entries if m[0] == tx_hash_n2 ][0]
        assert data_n2.height == n2.metadata.height
        assert data_n2.position == n2.metadata.position
        assert data_n2.fee == n2.metadata.fee
        assert TxFlags.StateSettled | expected_flags == n2.flags, TxFlags.to_repr(n2.flags)

        # Skipped, canary non-cleared.
        n3 = [ m[1] for m in metadata_entries if m[0] == tx_hash_n3 ][0]
        assert data_n3.height == n3.metadata.height
        assert data_n3.position == n3.metadata.position
        assert data_n3.fee == n3.metadata.fee
        assert TxFlags.StateDispatched | expected_flags == n3.flags, TxFlags.to_repr(n3.flags)


class TestSqliteWriteDispatcher:
    @classmethod
    def setup_method(self):
        self.dispatcher = None
        self._logger = logs.get_logger("...")
        class MockSqlite3Connection:
            def __enter__(self, *args, **kwargs):
                pass
            def __exit__(self, *args, **kwargs):
                pass
            def execute(self, query: str) -> None:
                pass
        class DbContext:
            def acquire_connection(self):
                return MockSqlite3Connection()
            def release_connection(self, connection):
                pass
        self.db_context = DbContext()

    @classmethod
    def teardown_method(self):
        if self.dispatcher is not None:
            self.dispatcher.stop()

    # As we use threading pytest can deadlock if something errors. This will break the deadlock
    # and display stacktraces.
    @pytest.mark.timeout(5)
    def test_write_dispatcher_to_completion(self) -> None:
        self.dispatcher = wallet_database.SqliteWriteDispatcher(self.db_context)
        self.dispatcher._writer_loop_event.wait()

        _completion_callback_called = False
        def _completion_callback(success: bool):
            nonlocal _completion_callback_called
            _completion_callback_called = True

        _write_callback_called = False
        def _write_callback(conn):
            nonlocal _write_callback_called
            _write_callback_called = True

        self.dispatcher.put(WriteEntryType(_write_callback, _completion_callback, 0))
        self.dispatcher.stop()

        assert _write_callback_called
        assert _completion_callback_called

    # As we use threading pytest can deadlock if something errors. This will break the deadlock
    # and display stacktraces.
    @pytest.mark.timeout(5)
    def test_write_dispatcher_write_only(self) -> None:
        self.dispatcher = wallet_database.SqliteWriteDispatcher(self.db_context)
        self.dispatcher._writer_loop_event.wait()

        _write_callback_called = False
        def _write_callback(conn):
            nonlocal _write_callback_called
            _write_callback_called = True

        self.dispatcher.put(WriteEntryType(_write_callback, None, 0))
        self.dispatcher.stop()

        assert _write_callback_called

