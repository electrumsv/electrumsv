import os
import pytest
import tempfile
from typing import Tuple, Optional, List

import bitcoinx

from electrumsv.constants import TxFlags, TRANSACTION_FLAGS
from electrumsv.transaction import Transaction
from electrumsv.logs import logs
from electrumsv import wallet_database
from electrumsv.wallet_database import (TxData, TxCache, TxCacheEntry, TxProof, DBTxInput,
    DBTxOutput)

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


class TestBaseWalletStore:
    def setup_method(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(self.temp_dir.name, "testbws")
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        self.store = wallet_database.BaseWalletStore(None, db_filename, aeskey, 0)

        self.tx_id = os.urandom(32).hex()

    def teardown_method(self, method):
        self.store.close()
        self.store = None

    def test_encrypt(self):
        data_hex = ("31d4e7921ec6692dd5b155799af530ad58cc9c86663d76356e9cce817f834f73b90e53e"+
            "1ff81620bedb1873b314909b20bf0")
        encrypted_hex = ("e6cb99daeaecc3b187e26bb0aa88461fb2407e865a2038d893cdec61b5558ba245c"+
            "7e42566f7c8bd6ffcf7863bbab7392fa035a97c48dd28f365f71043c9ed92")
        data_bytes = bytes.fromhex(data_hex)
        encrypted_bytes = self.store._encrypt(data_bytes)
        assert encrypted_hex == encrypted_bytes.hex()

    def test_decrypt(self):
        data_hex = ("31d4e7921ec6692dd5b155799af530ad58cc9c86663d76356e9cce817f834f73b90e53e"+
            "1ff81620bedb1873b314909b20bf0")
        encrypted_hex = ("e6cb99daeaecc3b187e26bb0aa88461fb2407e865a2038d893cdec61b5558ba245c"+
            "7e42566f7c8bd6ffcf7863bbab7392fa035a97c48dd28f365f71043c9ed92")
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted_bytes = self.store._decrypt(encrypted_bytes)
        assert decrypted_bytes.hex() == data_hex


class StoreTimestampMixin:
    timestamp = 0

    def _get_current_timestamp(self) -> int:
        return self.timestamp


class _GenericKeyValueStore(StoreTimestampMixin, wallet_database.GenericKeyValueStore):
    pass

class _GenericKeyValueStoreNonUnique(StoreTimestampMixin, wallet_database.GenericKeyValueStore):
    def has_unique_keys(self) -> bool:
        return False

class _ObjectKeyValueStore(StoreTimestampMixin, wallet_database.ObjectKeyValueStore):
    pass


TEST_TABLE_NAME = "test_table"
TEST_AESKEY = bytes.fromhex("6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4")

class TestJSONKeyValueStore:
    @classmethod
    def setup_class(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_path = os.path.join(cls.temp_dir.name, "test")

        cls.db_values = wallet_database.JSONKeyValueStore(TEST_TABLE_NAME, db_path, TEST_AESKEY, 0)

    @classmethod
    def teardown_class(cls) -> None:
        cls.db_values.close()
        del cls.db_values

    def test_get_nonexistent(self) -> None:
        assert self.db_values.get("nonexistent") is None

    def test_upsert(self) -> None:
        self.db_values.set("A", "B")
        assert self.db_values.get("A") == "B"

        self.db_values.set("A", "C")
        assert self.db_values.get("A") == "C"

        values = self.db_values.get_many_values([ "A" ])
        assert len(values) == 1


class TestGenericKeyValueStoreNonUnique:
    @classmethod
    def setup_class(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "testgks")
        cls.store = _GenericKeyValueStoreNonUnique(TEST_TABLE_NAME, db_filename, TEST_AESKEY, 0)

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setup_method(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

        self.store._fetch_write_timestamp()

    @pytest.mark.parametrize("variations,count", ((0, 0), (1, 3), (2, 3)))
    def test__delete_duplicates(self, variations, count) -> None:
        for i in range(variations):
            k = os.urandom(10)
            v = os.urandom(10)
            for i in range(count):
                self.store.add(k, v)
        # 1 other.
        self.store.add(os.urandom(10), os.urandom(10))

        rows = self.store.get_all()
        assert len(rows) == (variations * count) + 1

        self.store._delete_duplicates()

        rows = self.store.get_all()
        assert len(rows) == variations + 1


class TestGenericKeyValueStore:
    @classmethod
    def setup_class(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "testgks")
        cls.store = _GenericKeyValueStore(TEST_TABLE_NAME, db_filename, TEST_AESKEY, 0)

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setup_method(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

        self.store._fetch_write_timestamp()

    def test_add(self):
        k = os.urandom(10)
        v = os.urandom(10)

        assert self.store.get_write_timestamp() == 0

        self.store.timestamp = 1
        self.store.add(k, v)

        assert self.store.get_write_timestamp() == 1

        row = self.store.get_row(k)
        assert row is not None
        assert len(row) == 4
        assert row[0] ==  v # ByteData
        assert row[1] is not None # DateCreated
        assert row[1] == row[2] # DateCreated == DateUpdated
        assert row[3] is None # DateDeleted

    def test_add_many(self):
        kvs = [ (os.urandom(10), os.urandom(10)) for i in range(10) ]

        assert self.store.get_write_timestamp() == 0

        self.store.timestamp = 1
        self.store.add_many(kvs)

        assert self.store.get_write_timestamp() == 1

        kvs2 = self.store.get_many_values([ k for (k, v) in kvs ])
        assert len(kvs) == len(kvs2)
        for t in kvs:
            assert t in kvs2

    def test_update_many(self) -> None:
        original_values = {}
        for i in range(10):
            k = os.urandom(10)
            v1 = os.urandom(10)
            self.store.add(k, v1)
            original_values[k] = v1

        new_values = original_values.copy()
        for k in original_values.keys():
            new_values[k] = os.urandom(10)
        self.store.update_many(new_values.items())

        rows = self.store.get_all()
        assert len(rows) == len(new_values)
        for row in rows:
            assert row[0] in new_values

    def test_update(self):
        k = os.urandom(10)
        v1 = os.urandom(10)

        self.store.timestamp = 1
        self.store.add(k, v1)

        assert self.store.get_write_timestamp() == 1

        v2 = os.urandom(10)
        self.store.timestamp = 2
        self.store.update(k, v2)

        assert self.store.get_write_timestamp() == 2

        row = self.store.get_row(k)
        assert row is not None
        assert len(row) == 4
        assert row[0] == v2 # ByteData
        assert row[1] is not None
        assert row[2] is not None
        assert row[1] != row[2] # DateCreated != DateUpdated
        assert row[3] is  None # DateDeleted

    def test_get(self):
        k = os.urandom(10)
        v = os.urandom(10)
        self.store.add(k, v)
        byte_data = self.store.get_value(k)
        assert byte_data is not None
        assert byte_data == v

    def test_delete(self):
        k = os.urandom(10)
        v = os.urandom(10)

        self.store.timestamp = 1
        self.store.add(k, v)

        assert self.store.get_write_timestamp() == 1

        self.store.timestamp = 2
        self.store.delete(k)

        row = self.store.get_row(k)
        assert row is not None
        assert len(row) == 4
        assert row[0] == v # ByteData
        assert row[1] is not None # DateCreated
        assert row[2] is not None # DateUpdated
        assert row[1] == row[2] # DateCreated == DateUpdated
        assert row[3] is not None # DateDeleted
        assert row[1] != row[3] # DateCreated != DateDeleted

        assert self.store.get_write_timestamp() == 2

    def test_delete_value(self):
        k = os.urandom(10)
        v = os.urandom(10)

        self.store.timestamp = 1
        self.store.add(k, v)

        assert self.store.get_write_timestamp() ==  1

        self.store.timestamp = 2

        # If the value is incorrect, the entry is untouched.
        self.store.delete_value(k, os.urandom(10))
        row = self.store.get_row(k)
        assert row[3] is None # DateDeleted

        # If the value is correct, the entry is deleted.
        self.store.delete_value(k, v)
        row = self.store.get_row(k)
        assert row is not None
        assert len(row) == 4
        assert row[0] == v # ByteData
        assert row[1] is not None # DateCreated
        assert row[2] is not None # DateUpdated
        assert row[1] == row[2] # DateCreated == DateUpdated
        assert row[3] is not None # DateDeleted
        assert row[1] != row[3] # DateCreated != DateDeleted

        assert self.store.get_write_timestamp() == 2


class TestObjectKeyValueStore:
    @classmethod
    def setup_class(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "testokvs")
        cls.store = _ObjectKeyValueStore(TEST_TABLE_NAME, db_filename, TEST_AESKEY,
            0)

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setup_method(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

        self.store._fetch_write_timestamp()

    def test__encrypt_key(self) -> None:
        v = self.store._encrypt_key("my_key")
        assert v == b'\xdaGh\xa5\xe95\x93z\xc3\xc7|\xd1\x904O\xee'

    def test__decrypt_key(self) -> None:
        v = self.store._decrypt_key(b'\xdaGh\xa5\xe95\x93z\xc3\xc7|\xd1\x904O\xee')
        assert v == "my_key"

    def test_get_all(self) -> None:
        added_entries = []
        for i in range(10):
            k = str(i)
            v = [ i ] * i
            self.store.add(k, v)
            added_entries.append((k, v))

        all_entries = self.store.get_all()
        assert all_entries == added_entries

    def test_get_row(self) -> None:
        d = {}
        for i in range(10):
            k = str(i)
            v = [ i ] * i
            self.store.add(k, v)
            d[k] = v

        row = self.store.get_row("5")
        assert row is not None

        value, date_created, date_updated, date_deleted = row
        assert value == d["5"]
        assert date_created is not None
        assert date_created == date_updated
        assert date_deleted is None

    def test_update(self) -> None:
        d = {}
        for i in range(10):
            k = str(i)
            v = [ i ] * i
            self.store.add(k, v)
            d[k] = v

        # Ensure that the update timestamp differs from the create timestamp.
        self.store.timestamp += 1

        new_value = [ 1,2,3,4,5 ]
        self.store.update("5", new_value)

        for i in range(10):
            k = str(i)
            row = self.store.get_row(k)
            assert row is not None

            value, date_created, date_updated, date_deleted = row
            assert date_created is not None
            assert date_updated is not None
            if i == 5:
                # The updated value will be the altered one we need to explicitly check for.
                assert value == new_value
                assert date_created < date_updated
            else:
                assert value == d[k]
                assert date_created == date_updated
            assert date_deleted is None

    def test_delete_value(self) -> None:
        d = {}
        for i in range(10):
            k = str(i)
            v = [ i ] * i
            self.store.add(k, v)
            d[k] = v

        # Ensure that the update timestamp differs from the create timestamp.
        self.store.timestamp += 1

        self.store.delete_value("5", d["5"])

        for i in range(10):
            k = str(i)
            row = self.store.get_row(k)
            assert row is not None

            value, date_created, date_updated, date_deleted = row
            assert date_created is not None
            assert date_updated is not None
            assert date_created == date_updated
            if i == 5:
                # The updated value will be the altered one we need to explicitly check for.
                assert date_deleted is not None
                assert date_deleted > date_created
            else:
                assert value == d[k]
                assert date_deleted is None


class TestTransactionInputStore:
    @classmethod
    def setup_class(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "testtis")
        table_name = "test_table"
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = wallet_database.TransactionInputStore(db_filename, aeskey, 0)

        address_string = "address_string1"
        prevout_tx_hash = "prevout_tx_hash1"
        prev_idx = 20
        amount = 5555
        cls.txin1 = DBTxInput(address_string, prevout_tx_hash, prev_idx, amount)

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setup_method(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

        self.store._fetch_write_timestamp()

    def test_pack_unpack(self):
        packed_raw = self.store._pack_value(self.txin1)
        address_string2, prevout_tx_hash2, prev_idx2, amount2 = self.store._unpack_value(
            packed_raw)
        assert self.txin1.address_string == address_string2
        assert self.txin1.prevout_tx_hash == prevout_tx_hash2
        assert self.txin1.prev_idx == prev_idx2
        assert self.txin1.amount == amount2

    def test_pack_unpack_invalid_version(self):
        # This is a version 0 packed format, which does not exist.
        packed_bytes = b'\x00\x0faddress_string1\x10prevout_tx_hash1\x14\xfd\xb3\x15'
        with pytest.raises(wallet_database.DataPackingError):
            self.store._unpack_value(packed_bytes)

    def test_unpack_version_1(self):
        packed_hex = "010f616464726573735f737472696e673110707265766f75745f74785f686173683114fdb315"
        packed_raw = bytes.fromhex(packed_hex)
        address_string2, prevout_tx_hash2, prev_idx2, amount2 = self.store._unpack_value(
            packed_raw)
        assert "address_string1" == address_string2
        assert "prevout_tx_hash1" == prevout_tx_hash2
        assert 20 == prev_idx2
        assert 5555 == amount2


class TestTransactionOutputStore:
    @classmethod
    def setup_class(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "testtos")
        table_name = "test_table"
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = wallet_database.TransactionOutputStore(db_filename, aeskey, 0)

        address_string1 = "12345"
        out_tx_n1 = 20
        amount1 = 5555
        is_coinbase1 = False
        cls.txout1 = DBTxOutput(address_string1, out_tx_n1, amount1, is_coinbase1)

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setup_method(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

        self.store._fetch_write_timestamp()

    def test_pack_unpack(self):
        packed_raw = self.store._pack_value(self.txout1)
        txout2 = self.store._unpack_value(packed_raw)
        assert self.txout1.address_string == txout2.address_string
        assert self.txout1.out_tx_n == txout2.out_tx_n
        assert self.txout1.amount == txout2.amount
        assert self.txout1.is_coinbase == txout2.is_coinbase

    def test_pack_unpack_invalid_version(self) -> None:
        packed_bytes = b'\x00\x0512345\x14\xfd\xb3\x15\x00'
        with pytest.raises(wallet_database.DataPackingError):
            self.store._unpack_value(packed_bytes)

    def test_unpack_version_1(self):
        packed_hex = "0105313233343514fdb31500"
        packed_raw = bytes.fromhex(packed_hex)
        address_string2, out_tx_n2, amount2, is_coinbase2 = self.store._unpack_value(packed_raw)
        assert "12345" == address_string2
        assert 20 == out_tx_n2
        assert 5555 == amount2
        assert is_coinbase2 is False


class TestTransactionStore:
    @classmethod
    def setup_class(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "testts")
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = wallet_database.TransactionStore(db_filename, aeskey, 0)

        cls.tx_id = os.urandom(32).hex()

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setup_method(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

    def test_create_db_passive(self):
        # This has already run on TransactionStore creation. We test that it does not error being
        # run again, if the database entities already exist.
        self.store._db_create(self.store._get_db())

    def test_has_for_missing_transaction(self):
        assert not self.store.has(self.tx_id)

    def test_has_for_existing_transaction(self):
        metadata = TxData()
        bytedata = os.urandom(100)
        self.store.add(self.tx_id, metadata, bytedata)
        assert self.store.has(self.tx_id)

    def test_data_serialization(self):
        test_cases = [
            TxData(height=None, fee=None, position=None, timestamp=None),
            TxData(height=None, fee=1, position=None, timestamp=None),
            TxData(height=1, fee=None, position=None, timestamp=None),
            TxData(height=None, fee=None, position=1, timestamp=None),
            TxData(height=None, fee=None, position=None, timestamp=100101),
            TxData(height=None, fee=None, position=None, timestamp=None),
            TxData(height=1, fee=2, position=None, timestamp=None),
            TxData(height=1, fee=2, position=100, timestamp=None),
            TxData(height=1, fee=2, position=110, timestamp=1101),
            TxData(height=0, fee=2, position=110, timestamp=1101),
            TxData(height=-1, fee=2, position=110, timestamp=1101),
        ]
        for data1 in test_cases:
            raw, flags = self.store._pack_data(data1, TxFlags.METADATA_FIELD_MASK)
            data2 = self.store._unpack_data(raw, flags)
            assert data1.fee == data2.fee
            assert data1.height == data2.height
            assert data1.position == data2.position
            assert data1.timestamp == data2.timestamp

    def test_unpack_data_version_invalid_version(self):
        with pytest.raises(wallet_database.DataPackingError):
            packed_bytes = bytes.fromhex("0001020000")
            self.store._unpack_data(packed_bytes, TxFlags.HasFee | TxFlags.HasHeight)

    def test_data_unpack_version_1(self):
        for hex, data, flags in [
            [ "0101020000", TxData(height=1, fee=2), TxFlags.HasFee | TxFlags.HasHeight ],
            [ "0200026efd4d04", TxData(height=-1, fee=2, position=110, timestamp=1101),
              TxFlags.HasFee | TxFlags.HasHeight | TxFlags.HasPosition | TxFlags.HasTimestamp ],
        ]:
            raw = bytes.fromhex(hex)
            unpacked_data = self.store._unpack_data(raw, flags)
            assert data.height == unpacked_data.height
            assert data.fee == unpacked_data.fee
            assert data.position == unpacked_data.position
            assert data.timestamp == unpacked_data.timestamp

    def test_proof_serialization(self):
        proof1 = TxProof(position=10, branch=[ os.urandom(32) for i in range(10) ])
        raw = self.store._pack_proof(proof1)
        proof2 = self.store._unpack_proof(raw)
        assert proof1.position == proof2.position
        assert proof1.branch == proof2.branch

    def test_add(self):
        bytedata_1 = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata_1)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata_1 = TxData(height=None, fee=None, position=None, timestamp=None)
        self.store.add(tx_id, metadata_1, bytedata_1, flags=TxFlags.StateDispatched)

        # Check the state is correct, all states should be the same code path.
        flags = self.store.get_flags(tx_id)
        assert TxFlags.StateDispatched == flags & TxFlags.STATE_MASK

        metadata_2, bytedata_2, flags2 = self.store.get(tx_id)
        assert metadata_1 == metadata_2
        assert bytedata_1 == bytedata_2

    def test_add_many(self):
        to_add = []
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            tx_data = TxData(height=1, fee=2, position=None, timestamp=None)
            to_add.append((tx_id, tx_data, tx_bytes, TxFlags.Unset))
        self.store.add_many(to_add)
        existing_tx_ids = self.store.get_ids()
        added_tx_ids = set(t[0] for t in to_add)
        assert added_tx_ids == existing_tx_ids

    def test_update(self):
        bytedata = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata_a = TxData(height=None, fee=None, position=None, timestamp=None)
        self.store.add(tx_id, metadata_a, bytedata)

        metadata_update = TxData(height=None, fee=100, position=None, timestamp=None)
        self.store.update(tx_id, metadata_update, bytedata)

        metadata_get, bytedata_get, flags = self.store.get(tx_id)
        assert metadata_update == metadata_get
        assert bytedata == bytedata_get

    def test_update_many(self):
        to_add = []
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            tx_data = TxData(height=None, fee=2, position=None, timestamp=None)
            to_add.append((tx_id, tx_data, tx_bytes, TxFlags.Unset))
        self.store.add_many(to_add)

        to_update = []
        for tx_id, metadata, tx_bytes, flags in to_add:
            tx_metadata = TxData(height=1, fee=2, position=None, timestamp=None)
            to_update.append((tx_id, tx_metadata, tx_bytes, flags))
        self.store.update_many(to_update)

        for tx_id_get, metadata_get, bytedata_get, flags_get in self.store.get_many():
            for update_tx_id, update_metadata, update_tx_bytes, update_flags in to_update:
                if update_tx_id == tx_id_get:
                    assert metadata_get == update_metadata
                    assert bytedata_get == update_tx_bytes
                    continue

    def test_update_flags(self):
        bytedata = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata, bytedata)

        # Verify the field flags are assigned correctly on the add.
        expected_flags = TxFlags.HasFee | TxFlags.HasHeight | TxFlags.HasByteData
        flags = self.store.get_flags(tx_id)
        assert expected_flags == flags

        flags = TxFlags.StateReceived
        mask = TxFlags.METADATA_FIELD_MASK | TxFlags.HasByteData | TxFlags.HasProofData
        self.store.update_flags(tx_id, flags, mask)

        # Verify the state flag is correctly added via the mask.
        flags_get = self.store.get_flags(tx_id)
        expected_flags |= TxFlags.StateReceived
        assert expected_flags == flags_get, \
            f"{TxFlags.to_repr(expected_flags)} != {TxFlags.to_repr(flags_get)}"

        flags = TxFlags.StateReceived
        mask = TxFlags.Unset
        self.store.update_flags(tx_id, flags, mask)

        # Verify the state flag is correctly set via the mask.
        flags = self.store.get_flags(tx_id)
        assert TxFlags.StateReceived == flags

    def test_delete(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        data = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, data, tx_bytes)
        assert self.store.has(tx_id)
        self.store.delete(tx_id)
        assert not self.store.has(tx_id)

    def test_delete_many(self):
        to_add = []
        for i in range(10):
            bytedata = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(bytedata)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            metadata = TxData(height=1, fee=2, position=None, timestamp=None)
            to_add.append((tx_id, metadata, bytedata, TxFlags.Unset))
        self.store.add_many(to_add)
        add_ids = set(t[0] for t in to_add)
        get_ids = self.store.get_ids()
        assert add_ids == get_ids
        self.store.delete_many(add_ids)
        get_ids = self.store.get_ids()
        assert 0 == len(get_ids)

    def test_get_all_pending(self):
        get_tx_ids = set([])
        for tx_hex in (tx_hex_1, tx_hex_2):
            bytedata = bytes.fromhex(tx_hex)
            tx_hash_bytes = bitcoinx.double_sha256(bytedata)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            metadata = TxData(height=1, fee=2, position=None, timestamp=None)
            self.store.add(tx_id, metadata, bytedata)
            get_tx_ids.add(tx_id)
        result_tx_ids = self.store.get_ids()
        assert get_tx_ids == result_tx_ids

    def test_get(self):
        bytedata = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata, bytedata)

        assert self.store.has(tx_id)
        assert self.store.get(tx_id)[0] is not None
        assert self.store.get(tx_id, TxFlags.HasPosition, TxFlags.HasPosition) is None
        assert self.store.get(tx_id, TxFlags.Unset, TxFlags.HasPosition) is not None
        assert self.store.get(tx_id, TxFlags.HasFee, TxFlags.HasFee) is not None
        assert self.store.get(tx_id, TxFlags.Unset, TxFlags.HasFee) is None

    def test_get_metadata(self) -> None:
        bytedata = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata, bytedata)

        rowdata = self.store.get_metadata(tx_id)
        assert rowdata is not None
        metadata = rowdata[0]
        assert metadata is not None

        assert metadata.height == 1
        assert metadata.fee == 2
        assert metadata.position is None
        assert metadata.timestamp is None

    def test_get_metadata_many(self) -> None:
        # We're going to add five matches and look for two of them, checking that we do not match
        # unwanted rows.
        all_tx_ids = []
        for i in range(5):
            bytedata = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(bytedata)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            metadata = TxData(height=i*100, fee=i*1000, position=None, timestamp=None)
            self.store.add(tx_id, metadata, bytedata)
            all_tx_ids.append(tx_id)

        # We also ask for a dud tx_id that won't get matched.
        select_tx_ids = [ all_tx_ids[0], all_tx_ids[3], "12121212" ]
        rowdatas = self.store.get_metadata_many(tx_ids=select_tx_ids)
        # Check that the two valid matches are there and their values match the projected values.
        assert len(rowdatas) == 2
        for rowdata in rowdatas:
            tx_id = rowdata[0]
            metadata = rowdata[1]
            rowidx = all_tx_ids.index(tx_id)
            assert metadata.height == rowidx * 100
            assert metadata.fee == rowidx * 1000
            assert metadata.position is None
            assert metadata.timestamp is None

    def test_update_metadata_many(self) -> None:
        # We're going to add five matches and look for two of them, checking that we do not match
        # unwanted rows.
        all_tx_ids = []
        for i in range(5):
            bytedata = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(bytedata)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            metadata = TxData(height=i*100, fee=i*1000, position=None, timestamp=None)
            self.store.add(tx_id, metadata, bytedata)
            all_tx_ids.append(tx_id)

        updates = []
        for i in range(5):
            tx_id = all_tx_ids[i]
            metadata = TxData(height=i*200, fee=i*2000, position=None, timestamp=None)
            updates.append((tx_id, metadata, TxFlags.HasHeight | TxFlags.HasFee))
        self.store.update_metadata_many(updates)

        # We also ask for a dud tx_id that won't get matched.
        select_tx_ids = [ all_tx_ids[0], all_tx_ids[3], "12121212" ]
        rowdatas = self.store.get_metadata_many(tx_ids=select_tx_ids)
        # Check that the two valid matches are there and their values match the projected values.
        assert len(rowdatas) == 2
        for rowdata in rowdatas:
            tx_id = rowdata[0]
            metadata = rowdata[1]
            rowidx = all_tx_ids.index(tx_id)
            assert metadata.height == rowidx * 200
            assert metadata.fee == rowidx * 2000
            assert metadata.position is None
            assert metadata.timestamp is None

    def test_get_many(self):
        to_add = []
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            tx_data = TxData(height=None, fee=2, position=None, timestamp=None)
            to_add.append((tx_id, tx_data, tx_bytes, TxFlags.HasFee))
        self.store.add_many(to_add)

        # Test the first "add" id is matched.
        matches = self.store.get_many(tx_ids=[to_add[0][0]])
        assert to_add[0][0] == matches[0][0]

        # Test no id is matched.
        matches = self.store.get_many(tx_ids=["aaaa"])
        assert 0 == len(matches)

        # Test flag and mask combinations.
        matches = self.store.get_many(flags=TxFlags.HasFee)
        assert 10 == len(matches)

        matches = self.store.get_many(flags=TxFlags.Unset, mask=TxFlags.HasHeight)
        assert 10 == len(matches)

        matches = self.store.get_many(flags=TxFlags.HasFee, mask=TxFlags.HasFee)
        assert 10 == len(matches)

        matches = self.store.get_many(flags=TxFlags.Unset, mask=TxFlags.HasFee)
        assert 0 == len(matches)

    def test_proof(self):
        bytedata = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata, bytedata)

        position1 = 10
        merkle_branch1 = [ os.urandom(32) for i in range(10) ]
        proof = TxProof(position1, merkle_branch1)
        self.store.update_proof(tx_id, proof)

        with pytest.raises(wallet_database.MissingRowError):
            self.store.get_proof(self.tx_id)

        position2, merkle_branch2 = self.store.get_proof(tx_id)
        assert position1 == position2
        assert merkle_branch1 == merkle_branch2


class MockTransactionStore:
    def update_proof(self, tx_id: str, proof: TxProof) -> None:
        raise NotImplementedError


class TestTxCache:
    @classmethod
    def setup_class(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "testtxc")
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = wallet_database.TransactionStore(db_filename, aeskey, 0)

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setup_method(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

    def test_entry_visible(self):
        cache = TxCache(self.store)

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

    def test_add_missing_transaction(self):
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)

        cache.add_missing_transaction(tx_id_1, 100, 94)
        assert cache.is_cached(tx_id_1)
        entry = cache.get_entry(tx_id_1)
        assert TxFlags.HasFee | TxFlags.HasHeight, entry.flags & TxFlags.METADATA_FIELD_MASK
        assert entry.bytedata is None

        tx_bytes_2 = bytes.fromhex(tx_hex_2)
        tx_hash_bytes_2 = bitcoinx.double_sha256(tx_bytes_2)
        tx_id_2 = bitcoinx.hash_to_hex_str(tx_hash_bytes_2)

        cache.add_missing_transaction(tx_id_2, 200)
        assert cache.is_cached(tx_id_2)
        entry = cache.get_entry(tx_id_2)
        assert TxFlags.HasHeight == entry.flags & TxFlags.METADATA_FIELD_MASK
        assert entry.bytedata is None

    def test_add_transaction(self):
        cache = TxCache(self.store)

        tx = Transaction.from_hex(tx_hex_1)
        cache.add_transaction(tx)
        assert cache.is_cached(tx.txid())
        entry = cache.get_entry(tx.txid())
        assert TxFlags.HasByteData == entry.flags & TxFlags.HasByteData
        assert entry.bytedata is not None

    def test_add_transaction_update(self):
        cache = TxCache(self.store)

        tx = Transaction.from_hex(tx_hex_1)
        data = [ tx.txid(), TxData(height=1295924,timestamp=1555296290,position=4,fee=None),
            None, TxFlags.Unset ]
        cache.add([ data ])
        entry = cache.get_entry(tx.txid())
        assert entry is not None
        assert TxFlags.Unset == entry.flags & TxFlags.STATE_MASK

        cache.add_transaction(tx, TxFlags.StateCleared)

        entry = cache.get_entry(tx.txid())
        assert entry is not None
        assert entry.bytedata is not None
        assert TxFlags.StateCleared == entry.flags & TxFlags.StateCleared

    def test_add_then_update(self):
        cache = TxCache(self.store)

        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(bitcoinx.double_sha256(bytedata_1))
        metadata_1 = TxData(position=11)
        cache.add([ (tx_id_1, metadata_1, bytedata_1, TxFlags.StateDispatched) ])
        assert cache.is_cached(tx_id_1)
        entry = cache.get_entry(tx_id_1)
        assert TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.StateDispatched == entry.flags
        assert entry.bytedata is not None

        metadata_2 = TxData(fee=10, height=88)
        propagate_flags = TxFlags.HasFee | TxFlags.HasHeight
        cache.update([ (tx_id_1, metadata_2, None, propagate_flags | TxFlags.HasPosition) ])
        entry = cache.get_entry(tx_id_1)
        expected_flags = propagate_flags | TxFlags.StateDispatched | TxFlags.HasByteData
        assert expected_flags == entry.flags, \
            f"{TxFlags.to_repr(expected_flags)} !=  {TxFlags.to_repr(entry.flags)}"
        assert entry.bytedata is not None

    def test_update_or_add(self):
        cache = TxCache(self.store)

        # Add.
        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(bytedata_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        metadata_1 = TxData()
        cache.update_or_add([ (tx_id_1, metadata_1, bytedata_1, TxFlags.StateSettled) ])
        assert cache.is_cached(tx_id_1)
        entry = cache.get_entry(tx_id_1)
        assert TxFlags.HasByteData | TxFlags.StateSettled == entry.flags
        assert entry.bytedata is not None

        # Update.
        metadata_2 = TxData(position=22)
        cache.update_or_add([
            (tx_id_1, metadata_2, None, TxFlags.HasPosition | TxFlags.StateDispatched) ])
        entry = cache.get_entry(tx_id_1)
        store_flags = self.store.get_flags(tx_id_1)
        # State flags if present get set in an update otherwise they remain the same.
        expected_flags = TxFlags.HasPosition | TxFlags.HasByteData | TxFlags.StateDispatched
        assert expected_flags == store_flags, \
            f"{TxFlags.to_repr(expected_flags)} !=  {TxFlags.to_repr(store_flags)}"
        assert expected_flags == entry.flags, \
            f"{TxFlags.to_repr(expected_flags)} !=  {TxFlags.to_repr(entry.flags)}"
        assert bytedata_1 == entry.bytedata
        assert metadata_2.position == entry.metadata.position

    def test_update_flags(self):
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateDispatched) ])
        assert cache.is_cached(tx_id_1)
        entry = cache.get_entry(tx_id_1)
        assert TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.StateDispatched == entry.flags
        assert entry.bytedata is not None

        cache.update_flags(tx_id_1, TxFlags.StateSettled, TxFlags.HasByteData|TxFlags.HasProofData)
        entry = cache.get_entry(tx_id_1)
        store_flags = self.store.get_flags(tx_id_1)
        expected_flags = TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.StateSettled
        assert expected_flags == store_flags, \
            f"{TxFlags.to_repr(expected_flags)} != {TxFlags.to_repr(store_flags)}"
        assert expected_flags == entry.flags, \
            f"{TxFlags.to_repr(expected_flags)} != {TxFlags.to_repr(entry.flags)}"
        assert entry.bytedata is not None

    def test_delete(self):
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateDispatched) ])
        assert self.store.has(tx_id_1)
        assert cache.is_cached(tx_id_1)

        cache.delete(tx_id_1)
        assert not self.store.has(tx_id_1)
        assert not cache.is_cached(tx_id_1)

    def test_uncleared_bytedata_requirements(self) -> None:
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        for state_flag in TRANSACTION_FLAGS:
            with pytest.raises(wallet_database.InvalidDataError):
                cache.add([ (tx_id_1, data, None, state_flag) ])

        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateSigned) ])

        # We are applying a clearing of the bytedata, this should be invalid given uncleared.
        for state_flag in TRANSACTION_FLAGS:
            with pytest.raises(wallet_database.InvalidDataError):
                cache.update([ (tx_id_1, data, None, state_flag | TxFlags.HasByteData) ])

    def test_get_flags(self):
        cache = TxCache(self.store)

        assert cache.get_flags(os.urandom(10).hex()) is None

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateDispatched) ])
        assert cache.is_cached(tx_id_1)

        assert TxFlags.StateDispatched | TxFlags.HasByteData | TxFlags.HasPosition == \
            cache.get_flags(tx_id_1)

    def test_get_metadata(self):
        # Verify that getting a non-cached stored entry's metadata will only load the metadata.
        bytedata_set = os.urandom(10)
        tx_id = bitcoinx.hash_to_hex_str(bitcoinx.double_sha256(bytedata_set))
        metadata_set = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata_set, bytedata_set)

        cache = TxCache(self.store)
        metadata_get = cache.get_metadata(tx_id)
        assert metadata_set.height == metadata_get.height
        assert metadata_set.fee == metadata_get.fee
        assert metadata_set.position == metadata_get.position
        assert metadata_set.timestamp == metadata_get.timestamp

        entry = cache.get_cached_entry(tx_id)
        assert entry.is_metadata_cached()
        assert not entry.is_bytedata_cached()

    def test_get_transaction_after_metadata(self):
        bytedata_set = os.urandom(10)
        tx_id = bitcoinx.hash_to_hex_str(bitcoinx.double_sha256(bytedata_set))
        metadata_set = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata_set, bytedata_set)

        cache = TxCache(self.store)
        metadata_get = cache.get_metadata(tx_id)
        assert metadata_get is not None

        cached_entry_1 = cache.get_cached_entry(tx_id)
        assert cached_entry_1.is_metadata_cached()
        assert not cached_entry_1.is_bytedata_cached()

        entry = cache.get_entry(tx_id)
        assert entry.is_metadata_cached()
        assert entry.is_bytedata_cached()

        cached_entry_2 = cache.get_cached_entry(tx_id)
        assert entry == cached_entry_2

    def test_get_transaction(self):
        bytedata = bytes.fromhex(tx_hex_1)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata, bytedata)

        cache = TxCache(self.store)
        tx = cache.get_transaction(tx_id)
        assert tx is not None
        assert tx_id == tx.txid()

    def test_get_transactions(self):
        tx_ids = []
        for tx_hex in (tx_hex_1, tx_hex_2):
            tx_bytes = bytes.fromhex(tx_hex)
            tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            data = TxData(height=1, fee=2, position=None, timestamp=None)
            self.store.add(tx_id, data, tx_bytes)
            tx_ids.append(tx_id)

        cache = TxCache(self.store)
        for (tx_id, tx) in cache.get_transactions(tx_ids=tx_ids):
            assert tx is not None
            assert tx.txid() in  tx_ids

    def test_get_entry(self):
        cache = TxCache(self.store)

        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(bytedata_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        cache.add([ (tx_id_1, data, bytedata_1, TxFlags.StateSettled) ])

        entry = cache.get_entry(tx_id_1, TxFlags.StateDispatched)
        assert entry is None

        entry = cache.get_entry(tx_id_1, TxFlags.StateSettled)
        assert entry is not None

    # No complete cache of metadata, tx_id in cache, store not hit.
    def test_get_entry_cached_already(self) -> None:
        mock_store = MockTransactionStore()
        cache = TxCache(mock_store, cache_metadata=False)
        assert not cache._all_metadata_cached

        # Verify that we do not hit the store for our cached entry.
        our_entry = TxCacheEntry(TxData(position=11), TxFlags.HasPosition)
        cache.set_cache_entries({ "tx_id": our_entry })
        their_entry = cache.get_entry("tx_id")
        assert our_entry is their_entry

    # No complete cache of metadata, tx_id not in cache, store hit.
    def test_get_entry_cached_on_demand(self) -> None:
        metadata = TxData(position=11)
        flags = TxFlags.HasPosition
        def _get(*args) -> Tuple[TxData, Optional[bytes], TxFlags]:
            nonlocal metadata, flags
            return metadata, None, flags

        mock_store = MockTransactionStore()
        mock_store.get = _get

        cache = TxCache(mock_store, cache_metadata=False)
        assert not cache._all_metadata_cached
        their_entry = cache.get_entry("tx_id")
        assert their_entry.metadata == metadata
        assert their_entry.flags == flags

    # No complete cache of metadata, tx_id in cache, no bytedata cached, store hit for bytedata.
    def test_get_entry_cached_already_have_uncached_bytedata(self) -> None:
        metadata = TxData(position=11)
        flags = TxFlags.HasPosition | TxFlags.HasByteData
        bytedata = b'123456'
        def _get(*args) -> Tuple[TxData, Optional[bytes], TxFlags]:
            nonlocal metadata, bytedata, flags
            return metadata, bytedata, flags
        def _validate_transaction_bytes(*args) -> bool:
            return True

        mock_store = MockTransactionStore()
        mock_store.get = _get
        cache = TxCache(mock_store, cache_metadata=False)
        cache._validate_transaction_bytes = _validate_transaction_bytes
        assert not cache._all_metadata_cached

        our_entry = TxCacheEntry(metadata, flags, is_bytedata_cached=False)
        cache.set_cache_entries({ "tx_id": our_entry })

        # We explicitly filter for non-bytedata fields. This will not trigger the fetching of
        # bytedata from the store into the cache.
        their_entry = cache.get_entry("tx_id", TxFlags.HasPosition, TxFlags.HasPosition)
        assert our_entry is their_entry

        # This explicitly requests the bytedata and will fetch it from the store.
        their_entry = cache.get_entry("tx_id", TxFlags.HasByteData, TxFlags.HasByteData)
        assert their_entry.metadata == metadata
        assert their_entry.bytedata == bytedata
        assert their_entry.flags == flags

        del cache._cache["tx_id"]

        # This explicitly requests unfiltered entries and will fetch bytedata from the store.
        their_entry = cache.get_entry("tx_id")
        assert their_entry.metadata == metadata
        assert their_entry.bytedata == bytedata
        assert their_entry.flags == flags

    # No complete cache of metadata, tx_id in cache, no bytedata cached, store hit for bytedata.
    def test_get_entries_cached_already_have_uncached_bytedata(self) -> None:
        metadata = TxData(position=11)
        flags = TxFlags.HasPosition | TxFlags.HasByteData
        bytedata = b'123456'
        def _get_many(*args) -> List[Tuple[str, Tuple[TxData, Optional[bytes], TxFlags]]]:
            nonlocal metadata, bytedata, flags
            return [ ("tx_id", metadata, bytedata, flags) ]
        def _validate_transaction_bytes(*args) -> bool:
            return True

        mock_store = MockTransactionStore()
        mock_store.get_many = _get_many
        cache = TxCache(mock_store, cache_metadata=False)
        cache._validate_transaction_bytes = _validate_transaction_bytes
        assert not cache._all_metadata_cached

        our_entry = TxCacheEntry(metadata, flags, is_bytedata_cached=False)
        cache.set_cache_entries({ "tx_id": our_entry })

        # We explicitly filter for non-bytedata fields. This will not trigger the fetching of
        # bytedata from the store into the cache.
        their_entries = cache.get_entries(TxFlags.HasPosition, TxFlags.HasPosition, [ "tx_id" ])
        assert our_entry is their_entries[0][1]

        # This explicitly requests the bytedata and will fetch it from the store.
        their_entries = cache.get_entries(TxFlags.HasByteData, TxFlags.HasByteData, [ "tx_id" ])
        their_entry = their_entries[0][1]
        assert their_entry.metadata == metadata
        assert their_entry.bytedata == bytedata
        assert their_entry.flags == flags

        del cache._cache["tx_id"]

        # This explicitly requests unfiltered entries and will fetch bytedata from the store.
        their_entries = cache.get_entries(tx_ids=[ "tx_id" ])
        their_entry = their_entries[0][1]
        assert their_entry.metadata == metadata
        assert their_entry.bytedata == bytedata
        assert their_entry.flags == flags

    # No complete cache of metadata, tx_id in cache, no bytedata cached, store hit for bytedata.
    def test_get_entries_all_metadata_cached_already_have_uncached_bytedata(self) -> None:
        metadata = TxData(position=11)
        flags = TxFlags.HasPosition | TxFlags.HasByteData
        bytedata = b'123456'
        def _get_metadata_many(*args) -> List[Tuple[str, TxData, int]]:
            nonlocal metadata, bytedata, flags
            return [ ("tx_id", metadata, flags) ]
        def _get_many(_flags: TxFlags, _mask: TxFlags,
                _tx_ids: List[str]) -> List[Tuple[str, TxData, Optional[bytes], TxFlags]]:
            nonlocal metadata, bytedata, flags
            assert "tx_id" in _tx_ids
            return [ ("tx_id", metadata, bytedata, flags) ]
        def _validate_transaction_bytes(*args) -> bool:
            return True

        mock_store = MockTransactionStore()
        mock_store.get_metadata_many = _get_metadata_many
        mock_store.get_many = _get_many
        cache = TxCache(mock_store, cache_metadata=True)
        assert cache._all_metadata_cached
        assert "tx_id" in cache._cache
        cache._validate_transaction_bytes = _validate_transaction_bytes

        # We explicitly filter for non-bytedata fields. This will not trigger the fetching of
        # bytedata from the store into the cache.
        their_entries = cache.get_entries(TxFlags.HasPosition, TxFlags.HasPosition, [ "tx_id" ])
        their_entry = their_entries[0][1]
        assert their_entry.metadata == metadata
        assert their_entry.bytedata is None
        assert their_entry.flags == flags
        bytedataless_entry = their_entry

        # This explicitly requests the bytedata and will fetch it from the store.
        their_entries = cache.get_entries(TxFlags.HasByteData, TxFlags.HasByteData, [ "tx_id" ])
        their_entry = their_entries[0][1]
        assert their_entry.metadata == metadata
        assert their_entry.bytedata == bytedata
        assert their_entry.flags == flags

        # Reset the cache entry back to the bytedata-less entry.
        cache._cache["tx_id"] = bytedataless_entry

        # This explicitly requests unfiltered entries and will fetch bytedata from the store.
        their_entries = cache.get_entries(tx_ids=[ "tx_id" ])
        their_entry = their_entries[0][1]
        assert their_entry.metadata == metadata
        assert their_entry.bytedata == bytedata
        assert their_entry.flags == flags

    def test_get_height(self):
        cache = TxCache(self.store)

        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(bytedata_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        metadata_1 = TxData(height=11)
        cache.add([ (tx_id_1, metadata_1, bytedata_1, TxFlags.StateSettled) ])

        assert 11 == cache.get_height(tx_id_1)

        cache.update_flags(tx_id_1, TxFlags.StateCleared, TxFlags.HasByteData)
        assert 11 == cache.get_height(tx_id_1)

        cache.update_flags(tx_id_1, TxFlags.StateReceived, TxFlags.HasByteData)
        assert cache.get_height(tx_id_1) is None

    def test_get_unsynced_ids(self):
        cache = TxCache(self.store)

        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(bytedata_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        metadata_1 = TxData(height=11)
        cache.add([ (tx_id_1, metadata_1, None, TxFlags.Unset) ])

        results = cache.get_unsynced_ids()
        assert 1 == len(results)

        metadata_2 = TxData()
        cache.update([ (tx_id_1, metadata_2, bytedata_1, TxFlags.HasByteData) ])

        results = cache.get_unsynced_ids()
        assert 0 == len(results)

    def test_get_unverified_entries_too_high(self):
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(height=11, position=22)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateSettled) ])

        results = cache.get_unverified_entries(100)
        assert 0 == len(results)

    def test_get_unverified_entries(self) -> None:
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)

        data = TxData(height=11)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateSettled) ])

        results = cache.get_unverified_entries(10)
        assert 0 == len(results)

        results = cache.get_unverified_entries(11)
        assert 1 == len(results)

    def test_delete_reorged_entries(self) -> None:
        common_height = 5
        cache = TxCache(self.store)

        # Add the transaction that should be reset back to settled, with data fields cleared.
        tx_bytes_y1 = bytes.fromhex(tx_hex_1) + b"y1"
        tx_hash_bytes_y1 = bitcoinx.double_sha256(tx_bytes_y1)
        tx_id_y1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_y1)

        data_y1 = TxData(height=common_height+1, timestamp=22, position=33, fee=44)
        cache.add([ (tx_id_y1, data_y1, tx_bytes_y1, TxFlags.StateSettled) ])

        # Add the transaction that would be reset but is below the common height.
        tx_bytes_n1 = bytes.fromhex(tx_hex_1) + b"n1"
        tx_hash_bytes_n1 = bitcoinx.double_sha256(tx_bytes_n1)
        tx_id_n1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_n1)

        data_n1 = TxData(height=common_height-1, timestamp=22, position=33, fee=44)
        cache.add([ (tx_id_n1, data_n1, tx_bytes_n1, TxFlags.StateSettled) ])

        # Add the transaction that would be reset but is the common height.
        tx_bytes_n2 = bytes.fromhex(tx_hex_1) + b"n2"
        tx_hash_bytes_n2 = bitcoinx.double_sha256(tx_bytes_n2)
        tx_id_n2 = bitcoinx.hash_to_hex_str(tx_hash_bytes_n2)

        data_n2 = TxData(height=common_height, timestamp=22, position=33, fee=44)
        cache.add([ (tx_id_n2, data_n2, tx_bytes_n2, TxFlags.StateSettled) ])

        # Add a canary transaction that should remain untouched due to non-cleared state.
        tx_bytes_n3 = bytes.fromhex(tx_hex_2)
        tx_hash_bytes_n3 = bitcoinx.double_sha256(tx_bytes_n3)
        tx_id_n3 = bitcoinx.hash_to_hex_str(tx_hash_bytes_n3)

        data_n3 = TxData(height=111, timestamp=222, position=333, fee=444)
        cache.add([ (tx_id_n3, data_n3, tx_bytes_n3, TxFlags.StateDispatched) ])

        # Delete as if a reorg happened above the suitable but excluded canary transaction.
        cache.delete_reorged_entries(5)

        metadatas = cache.get_metadatas(TxFlags.HasByteData, TxFlags.HasByteData)
        assert 4 == len(metadatas)

        # Affected, canary above common height.
        y1 = [ m[1] for m in metadatas if m[0] == tx_id_y1 ][0]
        assert 0 == y1.metadata.height
        assert 0 == y1.metadata.timestamp
        assert 0 == y1.metadata.position
        assert data_y1.fee == y1.metadata.fee
        assert TxFlags.StateCleared | TxFlags.HasByteData | TxFlags.HasFee == y1.flags, \
            TxFlags.to_repr(y1.flags)

        expected_flags = (TxFlags.HasByteData | TxFlags.HasTimestamp | TxFlags.HasFee |
            TxFlags.HasHeight | TxFlags.HasPosition)

        # Skipped, old enough to survive.
        n1 = [ m[1] for m in metadatas if m[0] == tx_id_n1 ][0]
        assert data_n1.height == n1.metadata.height
        assert data_n1.timestamp == n1.metadata.timestamp
        assert data_n1.position == n1.metadata.position
        assert data_n1.fee == n1.metadata.fee
        assert TxFlags.StateSettled | expected_flags == n1.flags, TxFlags.to_repr(n1.flags)

        # Skipped, canary common height.
        n2 = [ m[1] for m in metadatas if m[0] == tx_id_n2 ][0]
        assert data_n2.height == n2.metadata.height
        assert data_n2.timestamp == n2.metadata.timestamp
        assert data_n2.position == n2.metadata.position
        assert data_n2.fee == n2.metadata.fee
        assert TxFlags.StateSettled | expected_flags == n2.flags, TxFlags.to_repr(n2.flags)

        # Skipped, canary non-cleared.
        n3 = [ m[1] for m in metadatas if m[0] == tx_id_n3 ][0]
        assert data_n3.height == n3.metadata.height
        assert data_n3.timestamp == n3.metadata.timestamp
        assert data_n3.position == n3.metadata.position
        assert data_n3.fee == n3.metadata.fee
        assert TxFlags.StateDispatched | expected_flags == n3.flags, TxFlags.to_repr(n3.flags)


class TestXputCache:
    @classmethod
    def setup_class(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename_txin = os.path.join(cls.temp_dir.name, "test_txin")
        db_filename_txout = os.path.join(cls.temp_dir.name, "test_txout")
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.txin_store = wallet_database.TransactionInputStore(db_filename_txin, aeskey, 0)
        cls.txout_store = wallet_database.TransactionOutputStore(db_filename_txout, aeskey, 0)

    @classmethod
    def teardown_class(cls):
        cls.txin_store.close()
        cls.txin_store = None
        cls.txout_store.close()
        cls.txout_store = None
        cls.temp_dir = None

    def setup_method(self):
        for store in (self.txin_store, self.txout_store):
            db = store._get_db()
            db.execute(f"DELETE FROM {store._table_name}")
            db.commit()

            store._fetch_write_timestamp()

    def test_cache_with_preload(self):
        tx_id = os.urandom(10).hex()
        tx_input = DBTxInput("address_string", "hash", 10, 10)
        tx_output = DBTxOutput("address_string", 10, 10, False)

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            tx_store.add_entries([ (tx_id, tx_xput) ])

            cache = wallet_database.TxXputCache(tx_store, "teststore")
            assert tx_id in cache._cache
            assert 1 == len(cache._cache[tx_id])
            assert tx_xput == cache._cache[tx_id][0]

    def test_cache_get_entries(self):
        tx_id = os.urandom(10).hex()
        tx_input = DBTxInput("address_string", "hash", 10, 10)
        tx_output = DBTxOutput("address_string", 10, 10, False)

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            tx_store.add_entries([ (tx_id, tx_xput) ])
            cache = wallet_database.TxXputCache(tx_store, "teststore")
            entries = cache.get_entries(tx_id)

            assert 1 == len(entries)
            assert tx_xput == entries[0]

        # Look up a tx_id that does not exist.
        entries = cache.get_entries(reversed(tx_id))
        assert 0 == len(entries)

    def test_cache_get_all_entries(self):
        all_tx_ids = []
        for i in range(5):
            tx_id = os.urandom(10).hex()
            all_tx_ids.append(tx_id)
            tx_input = DBTxInput("address_string", "hash", 10, 10)
            tx_output = DBTxOutput("address_string", 10, 10, False)

            for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
                tx_store.add_entries([ (tx_id, tx_xput) ])

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            cache = wallet_database.TxXputCache(tx_store, "teststore")
            entries = cache.get_all_entries()
            assert len(entries) == 5

            expected_tx_ids = all_tx_ids[:]
            for entry_tx_id in entries:
                expected_tx_ids.remove(entry_tx_id)
            assert len(expected_tx_ids) == 0

    def test_cache_add(self):
        tx_id = os.urandom(10).hex()
        tx_input = DBTxInput("address_string", "hash", 10, 10)
        tx_output = DBTxOutput("address_string", 10, 10, False)

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            cache = wallet_database.TxXputCache(tx_store, "teststore")
            cache.add_entries([ (tx_id, tx_xput) ])

            # Check the caching layer has the entry.
            assert tx_id in cache._cache
            assert 1 == len(cache._cache[tx_id])
            assert tx_xput == cache._cache[tx_id][0]

            # Check the store has the entry.
            entries = tx_store.get_entries(tx_id)
            assert 1 == len(entries)
            assert tx_xput == entries[0]

    def test_cache_delete(self):
        tx_id = os.urandom(10).hex()
        tx_input = DBTxInput("address_string", "hash", 10, 10)
        tx_output = DBTxOutput("address_string", 10, 10, False)

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            cache = wallet_database.TxXputCache(tx_store, "teststore")
            cache.add_entries([ (tx_id, tx_xput) ])
            cache.delete_entries([ (tx_id, tx_xput) ])

            # Check the caching layer no longer has the entry.
            assert 0 == len(cache._cache[tx_id])

            # Check the store no longer has the entry.
            entries = tx_store.get_entries(tx_id)
            assert 0 == len(entries)
