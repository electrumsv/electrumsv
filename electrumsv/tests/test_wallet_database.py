import os
import tempfile
import unittest

import bitcoinx

from electrumsv.transaction import Transaction
from electrumsv.logs import logs
from electrumsv import wallet_database
from electrumsv.wallet_database import TxFlags, TxData, TxCache, TxProof, DBTxInput, DBTxOutput

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


class TestBaseWalletStore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(self.temp_dir.name, "test")
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        self.store = wallet_database.BaseWalletStore(None, db_filename, aeskey)

        self.tx_id = os.urandom(32).hex()

    def tearDown(self):
        self.store.close()

    def test_encrypt(self):
        data_hex = ("31d4e7921ec6692dd5b155799af530ad58cc9c86663d76356e9cce817f834f73b90e53e"+
            "1ff81620bedb1873b314909b20bf0")
        encrypted_hex = ("e6cb99daeaecc3b187e26bb0aa88461fb2407e865a2038d893cdec61b5558ba245c"+
            "7e42566f7c8bd6ffcf7863bbab7392fa035a97c48dd28f365f71043c9ed92")
        data_bytes = bytes.fromhex(data_hex)
        encrypted_bytes = self.store._encrypt(data_bytes)
        self.assertEqual(encrypted_hex, encrypted_bytes.hex())

    def test_decrypt(self):
        data_hex = ("31d4e7921ec6692dd5b155799af530ad58cc9c86663d76356e9cce817f834f73b90e53e"+
            "1ff81620bedb1873b314909b20bf0")
        encrypted_hex = ("e6cb99daeaecc3b187e26bb0aa88461fb2407e865a2038d893cdec61b5558ba245c"+
            "7e42566f7c8bd6ffcf7863bbab7392fa035a97c48dd28f365f71043c9ed92")
        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted_bytes = self.store._decrypt(encrypted_bytes)
        self.assertEqual(decrypted_bytes.hex(), data_hex)


class _GKVTestableStore(wallet_database.GenericKeyValueStore):
    timestamp = 0

    def _get_current_timestamp(self) -> int:
        return self.timestamp


class TestGenericKeyValueStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "test")
        table_name = "test_table"
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = _GKVTestableStore(table_name, db_filename, aeskey)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setUp(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

        self.store._fetch_write_timestamp()

    def tearDown(self):
        pass

    def test_add(self):
        k = os.urandom(10).hex()
        v = os.urandom(10)

        self.assertEqual(self.store.get_write_timestamp(), 0)

        self.store.timestamp = 1
        self.store.add(k, v)

        self.assertEqual(self.store.get_write_timestamp(), 1)

        row = self.store.get_row(k)
        self.assertIsNotNone(row)
        self.assertEqual(len(row), 4)
        self.assertEqual(row[0], v) # ByteData
        self.assertIsNotNone(row[1]) # DateCreated
        self.assertEqual(row[1], row[2]) # DateCreated == DateUpdated
        self.assertIsNone(row[3]) # DateDeleted

    def test_get(self):
        k = os.urandom(10).hex()
        v = os.urandom(10)
        self.store.add(k, v)
        byte_data = self.store.get_value(k)
        self.assertIsNotNone(byte_data)
        self.assertEqual(byte_data, v)

    def test_update(self):
        k = os.urandom(10).hex()
        v1 = os.urandom(10)

        self.store.timestamp = 1
        self.store.add(k, v1)

        self.assertEqual(self.store.get_write_timestamp(), 1)

        v2 = os.urandom(10)
        self.store.timestamp = 2
        self.store.update(k, v2)

        self.assertEqual(self.store.get_write_timestamp(), 2)

        row = self.store.get_row(k)
        self.assertIsNotNone(row)
        self.assertEqual(len(row), 4)
        self.assertEqual(row[0], v2) # ByteData
        self.assertIsNotNone(row[1])
        self.assertIsNotNone(row[2])
        self.assertNotEqual(row[1], row[2]) # DateCreated != DateUpdated
        self.assertIsNone(row[3]) # DateDeleted

    def test_delete(self):
        k = os.urandom(10).hex()
        v = os.urandom(10)

        self.store.timestamp = 1
        self.store.add(k, v)

        self.assertEqual(self.store.get_write_timestamp(), 1)

        self.store.timestamp = 2
        self.store.delete(k)

        row = self.store.get_row(k)
        self.assertIsNotNone(row)
        self.assertEqual(len(row), 4)
        self.assertEqual(row[0], v) # ByteData
        self.assertIsNotNone(row[1]) # DateCreated
        self.assertIsNotNone(row[2]) # DateUpdated
        self.assertEqual(row[1], row[2]) # DateCreated == DateUpdated
        self.assertIsNotNone(row[3]) # DateDeleted
        self.assertNotEqual(row[1], row[3]) # DateCreated != DateDeleted

        self.assertEqual(self.store.get_write_timestamp(), 2)


class TestTransactionInputStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "test")
        table_name = "test_table"
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = wallet_database.TransactionInputStore(db_filename, aeskey)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setUp(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

        self.store._fetch_write_timestamp()

    def tearDown(self):
        pass

    def test_pack_unpack(self):
        address_string = "address_string1"
        prevout_tx_hash = "prevout_tx_hash1"
        prevout_n = 20
        amount = 5555
        txin1 = DBTxInput(address_string, prevout_tx_hash, prevout_n, amount)
        packed_raw = self.store._pack_value(txin1)
        address_string2, prevout_tx_hash2, prevout_n2, amount2 = self.store._unpack_value(
            packed_raw)
        self.assertEqual(txin1.address_string, address_string2)
        self.assertEqual(txin1.prevout_tx_hash, prevout_tx_hash2)
        self.assertEqual(txin1.prevout_n, prevout_n2)
        self.assertEqual(txin1.amount, amount2)

    def test_unpack_version_1(self):
        packed_hex = "010f616464726573735f737472696e673110707265766f75745f74785f686173683114fdb315"
        packed_raw = bytes.fromhex(packed_hex)
        address_string2, prevout_tx_hash2, prevout_n2, amount2 = self.store._unpack_value(
            packed_raw)
        self.assertEqual("address_string1", address_string2)
        self.assertEqual("prevout_tx_hash1", prevout_tx_hash2)
        self.assertEqual(20, prevout_n2)
        self.assertEqual(5555, amount2)


class TestTransactionOutputStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "test")
        table_name = "test_table"
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = wallet_database.TransactionOutputStore(db_filename, aeskey)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setUp(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

        self.store._fetch_write_timestamp()

    def tearDown(self):
        pass

    def test_pack_unpack(self):
        address_string1 = "12345"
        out_tx_n1 = 20
        amount1 = 5555
        is_coinbase1 = False
        txout1 = DBTxOutput(address_string1, out_tx_n1, amount1, is_coinbase1)
        packed_raw = self.store._pack_value(txout1)
        txout2 = self.store._unpack_value(packed_raw)
        self.assertEqual(txout1.address_string, txout2.address_string)
        self.assertEqual(txout1.out_tx_n, txout2.out_tx_n)
        self.assertEqual(txout1.amount, txout2.amount)
        self.assertEqual(txout1.is_coinbase, txout2.is_coinbase)

    def test_unpack_version_1(self):
        packed_hex = "0105313233343514fdb31500"
        packed_raw = bytes.fromhex(packed_hex)
        address_string2, out_tx_n2, amount2, is_coinbase2 = self.store._unpack_value(packed_raw)
        self.assertEqual("12345", address_string2)
        self.assertEqual(20, out_tx_n2)
        self.assertEqual(5555, amount2)
        self.assertEqual(False, is_coinbase2)


class TestTransactionStore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "test")
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = wallet_database.TransactionStore(db_filename, aeskey)

        cls.tx_id = os.urandom(32).hex()

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setUp(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

    def tearDown(self):
        pass

    def test_create_db_passive(self):
        # This has already run on TransactionStore creation. We test that it does not error being
        # run again, if the database entities already exist.
        self.store._db_create(self.store._get_db())

    def test_has_for_missing_transaction(self):
        self.assertFalse(self.store.has(self.tx_id))

    def test_has_for_existing_transaction(self):
        metadata = TxData()
        bytedata = os.urandom(100)
        self.store.add(self.tx_id, metadata, bytedata)
        self.assertTrue(self.store.has(self.tx_id))

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
            self.assertEqual(data1.fee, data2.fee)
            self.assertEqual(data1.height, data2.height)
            self.assertEqual(data1.position, data2.position)
            self.assertEqual(data1.timestamp, data2.timestamp)

    def test_data_unpack_version_1(self):
        for hex, data, flags in [
            [ "0101020000", TxData(height=1, fee=2), TxFlags.HasFee | TxFlags.HasHeight ],
            [ "0200026efd4d04", TxData(height=-1, fee=2, position=110, timestamp=1101),
              TxFlags.HasFee | TxFlags.HasHeight | TxFlags.HasPosition | TxFlags.HasTimestamp ],
        ]:
            raw = bytes.fromhex(hex)
            unpacked_data = self.store._unpack_data(raw, flags)
            self.assertEqual(data.height, unpacked_data.height)
            self.assertEqual(data.fee, unpacked_data.fee)
            self.assertEqual(data.position, unpacked_data.position)
            self.assertEqual(data.timestamp, unpacked_data.timestamp)

    def test_proof_serialization(self):
        proof1 = TxProof(position=10, branch=[ os.urandom(32) for i in range(10) ])
        raw = self.store._pack_proof(proof1)
        proof2 = self.store._unpack_proof(raw)
        self.assertEqual(proof1.position, proof2.position)
        self.assertEqual(proof1.branch, proof2.branch)

    def test_add(self):
        bytedata_1 = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata_1)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata_1 = TxData(height=None, fee=None, position=None, timestamp=None)
        self.store.add(tx_id, metadata_1, bytedata_1, flags=TxFlags.StateDispatched)

        # Check the state is correct, all states should be the same code path.
        flags = self.store.get_flags(tx_id)
        self.assertEqual(TxFlags.StateDispatched, flags & TxFlags.STATE_MASK)

        metadata_2, bytedata_2, flags2 = self.store.get(tx_id)
        self.assertEqual(metadata_1, metadata_2)
        self.assertEqual(bytedata_1, bytedata_2)

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
        self.assertEqual(added_tx_ids, existing_tx_ids)

    def test_update(self):
        bytedata = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata_a = TxData(height=None, fee=None, position=None, timestamp=None)
        self.store.add(tx_id, metadata_a, bytedata)

        metadata_update = TxData(height=None, fee=100, position=None, timestamp=None)
        self.store.update(tx_id, metadata_update, bytedata)

        metadata_get, bytedata_get, flags = self.store.get(tx_id)
        self.assertEqual(metadata_update, metadata_get)
        self.assertEqual(bytedata, bytedata_get)

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
                    self.assertEqual(metadata_get, update_metadata)
                    self.assertEqual(bytedata_get, update_tx_bytes)
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
        self.assertEqual(expected_flags, flags)

        flags = TxFlags.StateReceived
        mask = TxFlags.METADATA_FIELD_MASK | TxFlags.HasByteData | TxFlags.HasProofData
        self.store.update_flags(tx_id, flags, mask)

        # Verify the state flag is correctly added via the mask.
        flags_get = self.store.get_flags(tx_id)
        expected_flags |= TxFlags.StateReceived
        self.assertEqual(expected_flags, flags_get,
            f"{TxFlags.to_repr(expected_flags)} != {TxFlags.to_repr(flags_get)}")

        flags = TxFlags.StateReceived
        mask = TxFlags.Unset
        self.store.update_flags(tx_id, flags, mask)

        # Verify the state flag is correctly set via the mask.
        flags = self.store.get_flags(tx_id)
        self.assertEqual(TxFlags.StateReceived, flags)

    def test_delete(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        data = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, data, tx_bytes)
        self.assertTrue(self.store.has(tx_id))
        self.store.delete(tx_id)
        self.assertFalse(self.store.has(tx_id))

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
        self.assertEqual(add_ids, get_ids)
        self.store.delete_many(add_ids)
        get_ids = self.store.get_ids()
        self.assertEqual(0, len(get_ids))

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
        self.assertEqual(get_tx_ids, result_tx_ids)

    def test_get(self):
        bytedata = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata, bytedata)
        self.assertTrue(self.store.has(tx_id))
        self.assertIsNotNone(self.store.get(tx_id)[0])

        self.assertIsNone(self.store.get(tx_id, TxFlags.HasPosition, TxFlags.HasPosition))
        self.assertIsNotNone(self.store.get(tx_id, TxFlags.Unset, TxFlags.HasPosition))

        self.assertIsNotNone(self.store.get(tx_id, TxFlags.HasFee, TxFlags.HasFee))
        self.assertIsNone(self.store.get(tx_id, TxFlags.Unset, TxFlags.HasFee))

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
        self.assertEqual(to_add[0][0], matches[0][0])

        # Test no id is matched.
        matches = self.store.get_many(tx_ids=["aaaa"])
        self.assertEqual(0, len(matches))

        # Test flag and mask combinations.
        matches = self.store.get_many(flags=TxFlags.HasFee)
        self.assertEqual(10, len(matches))

        matches = self.store.get_many(flags=TxFlags.Unset, mask=TxFlags.HasHeight)
        self.assertEqual(10, len(matches))

        matches = self.store.get_many(flags=TxFlags.HasFee, mask=TxFlags.HasFee)
        self.assertEqual(10, len(matches))

        matches = self.store.get_many(flags=TxFlags.Unset, mask=TxFlags.HasFee)
        self.assertEqual(0, len(matches))

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

        with self.assertRaises(wallet_database.MissingRowError):
            self.store.get_proof(self.tx_id)

        position2, merkle_branch2 = self.store.get_proof(tx_id)
        self.assertEqual(position1, position2)
        self.assertEqual(merkle_branch1, merkle_branch2)


class TestTxCache(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename = os.path.join(cls.temp_dir.name, "test")
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.store = wallet_database.TransactionStore(db_filename, aeskey)

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls.store = None
        cls.temp_dir = None

    def setUp(self):
        db = self.store._get_db()
        db.execute(f"DELETE FROM {self.store._table_name}")
        db.commit()

    def tearDown(self):
        pass

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
            self.assertEqual(result, actual_result, str(combos[i]))

    def test_add_missing_transaction(self):
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)

        cache.add_missing_transaction(tx_id_1, 100, 94)
        self.assertTrue(cache.is_cached(tx_id_1))
        entry = cache.get_entry(tx_id_1)
        self.assertEqual(TxFlags.HasFee | TxFlags.HasHeight,
            entry.flags & TxFlags.METADATA_FIELD_MASK)
        self.assertIsNone(entry.bytedata)

        tx_bytes_2 = bytes.fromhex(tx_hex_2)
        tx_hash_bytes_2 = bitcoinx.double_sha256(tx_bytes_2)
        tx_id_2 = bitcoinx.hash_to_hex_str(tx_hash_bytes_2)

        cache.add_missing_transaction(tx_id_2, 200)
        self.assertTrue(cache.is_cached(tx_id_2))
        entry = cache.get_entry(tx_id_2)
        self.assertEqual(TxFlags.HasHeight, entry.flags & TxFlags.METADATA_FIELD_MASK)
        self.assertIsNone(entry.bytedata)

    def test_add_transaction(self):
        cache = TxCache(self.store)

        tx = Transaction(tx_hex_1)
        cache.add_transaction(tx)
        self.assertTrue(cache.is_cached(tx.txid()))
        entry = cache.get_entry(tx.txid())
        self.assertEqual(TxFlags.HasByteData, entry.flags & TxFlags.HasByteData)
        self.assertIsNotNone(entry.bytedata)

    def test_add_transaction_update(self):
        cache = TxCache(self.store)

        tx = Transaction(tx_hex_1)
        data = [ tx.txid(), TxData(height=1295924,timestamp=1555296290,position=4,fee=None),
            None, TxFlags.StateCleared ]
        cache.add([ data ])
        entry = cache.get_entry(tx.txid())
        self.assertIsNotNone(entry)
        self.assertEqual(TxFlags.StateCleared, entry.flags & TxFlags.StateCleared)

        cache.add_transaction(tx, TxFlags.StateSettled)

        entry = cache.get_entry(tx.txid())
        self.assertIsNotNone(entry)
        self.assertIsNotNone(entry.bytedata)
        self.assertEqual(TxFlags.StateSettled, entry.flags & TxFlags.StateSettled)

    def test_add_then_update(self):
        cache = TxCache(self.store)

        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(bitcoinx.double_sha256(bytedata_1))
        metadata_1 = TxData(position=11)
        cache.add([ (tx_id_1, metadata_1, bytedata_1, TxFlags.StateDispatched) ])
        self.assertTrue(cache.is_cached(tx_id_1))
        entry = cache.get_entry(tx_id_1)
        self.assertEqual(TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.StateDispatched,
            entry.flags)
        self.assertIsNotNone(entry.bytedata)

        metadata_2 = TxData(fee=10, height=88)
        propagate_flags = TxFlags.HasFee | TxFlags.HasHeight
        cache.update([ (tx_id_1, metadata_2, None, propagate_flags | TxFlags.HasPosition) ])
        entry = cache.get_entry(tx_id_1)
        expected_flags = propagate_flags | TxFlags.StateDispatched | TxFlags.HasByteData
        self.assertEqual(expected_flags, entry.flags,
            f"{TxFlags.to_repr(expected_flags)} !=  {TxFlags.to_repr(entry.flags)}")
        self.assertIsNotNone(entry.bytedata)

    def test_update_or_add(self):
        cache = TxCache(self.store)

        # Add.
        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(bytedata_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        metadata_1 = TxData()
        cache.update_or_add([ (tx_id_1, metadata_1, bytedata_1, TxFlags.StateCleared) ])
        self.assertTrue(cache.is_cached(tx_id_1))
        entry = cache.get_entry(tx_id_1)
        self.assertEqual(TxFlags.HasByteData | TxFlags.StateCleared, entry.flags)
        self.assertIsNotNone(entry.bytedata)

        # Update.
        metadata_2 = TxData(position=22)
        cache.update_or_add([
            (tx_id_1, metadata_2, None, TxFlags.HasPosition | TxFlags.StateDispatched) ])
        entry = cache.get_entry(tx_id_1)
        store_flags = self.store.get_flags(tx_id_1)
        # State flags if present get set in an update otherwise they remain the same.
        expected_flags = TxFlags.HasPosition | TxFlags.HasByteData | TxFlags.StateDispatched
        self.assertEqual(expected_flags, store_flags,
            f"{TxFlags.to_repr(expected_flags)} !=  {TxFlags.to_repr(store_flags)}")
        self.assertEqual(expected_flags, entry.flags,
            f"{TxFlags.to_repr(expected_flags)} !=  {TxFlags.to_repr(entry.flags)}")
        self.assertEqual(bytedata_1, entry.bytedata)
        self.assertEqual(metadata_2.position, entry.metadata.position)

    def test_update_flags(self):
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateDispatched) ])
        self.assertTrue(cache.is_cached(tx_id_1))
        entry = cache.get_entry(tx_id_1)
        self.assertEqual(TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.StateDispatched,
            entry.flags)
        self.assertIsNotNone(entry.bytedata)

        cache.update_flags(tx_id_1, TxFlags.StateCleared, TxFlags.HasByteData|TxFlags.HasProofData)
        entry = cache.get_entry(tx_id_1)
        store_flags = self.store.get_flags(tx_id_1)
        expected_flags = TxFlags.HasByteData | TxFlags.HasPosition | TxFlags.StateCleared
        self.assertEqual(expected_flags, store_flags,
            f"{TxFlags.to_repr(expected_flags)} != {TxFlags.to_repr(store_flags)}")
        self.assertEqual(expected_flags, entry.flags,
            f"{TxFlags.to_repr(expected_flags)} != {TxFlags.to_repr(entry.flags)}")
        self.assertIsNotNone(entry.bytedata)

    def test_delete(self):
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateDispatched) ])
        self.assertTrue(self.store.has(tx_id_1))
        self.assertTrue(cache.is_cached(tx_id_1))

        cache.delete(tx_id_1)
        self.assertFalse(self.store.has(tx_id_1))
        self.assertFalse(cache.is_cached(tx_id_1))

    def test_get_flags(self):
        cache = TxCache(self.store)

        self.assertIsNone(cache.get_flags(os.urandom(10).hex()))

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateDispatched) ])
        self.assertTrue(cache.is_cached(tx_id_1))

        self.assertEqual(TxFlags.StateDispatched | TxFlags.HasByteData | TxFlags.HasPosition,
            cache.get_flags(tx_id_1))

    def test_get_metadata(self):
        # Verify that getting a non-cached stored entry's metadata will only load the metadata.
        bytedata_set = os.urandom(10)
        tx_id = bitcoinx.hash_to_hex_str(bitcoinx.double_sha256(bytedata_set))
        metadata_set = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata_set, bytedata_set)

        cache = TxCache(self.store)
        metadata_get = cache.get_metadata(tx_id)
        self.assertEqual(metadata_set.height, metadata_get.height)
        self.assertEqual(metadata_set.fee, metadata_get.fee)
        self.assertEqual(metadata_set.position, metadata_get.position)
        self.assertEqual(metadata_set.timestamp, metadata_get.timestamp)

        entry = cache.get_cached_entry(tx_id)
        self.assertTrue(entry.is_metadata_cached())
        self.assertFalse(entry.is_bytedata_cached())

    def test_get_transaction_after_metadata(self):
        bytedata_set = os.urandom(10)
        tx_id = bitcoinx.hash_to_hex_str(bitcoinx.double_sha256(bytedata_set))
        metadata_set = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata_set, bytedata_set)

        cache = TxCache(self.store)
        metadata_get = cache.get_metadata(tx_id)
        self.assertIsNotNone(metadata_get)

        cached_entry_1 = cache.get_cached_entry(tx_id)
        self.assertTrue(cached_entry_1.is_metadata_cached())
        self.assertFalse(cached_entry_1.is_bytedata_cached())

        entry = cache.get_entry(tx_id)
        self.assertTrue(entry.is_metadata_cached())
        self.assertTrue(entry.is_bytedata_cached())

        cached_entry_2 = cache.get_cached_entry(tx_id)
        self.assertEqual(entry, cached_entry_2)

    def test_get_transaction(self):
        bytedata = bytes.fromhex(tx_hex_1)
        tx_hash_bytes = bitcoinx.double_sha256(bytedata)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        metadata = TxData(height=1, fee=2, position=None, timestamp=None)
        self.store.add(tx_id, metadata, bytedata)

        cache = TxCache(self.store)
        tx = cache.get_transaction(tx_id)
        self.assertIsNotNone(tx)
        self.assertEqual(tx_id, tx.txid())

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
            self.assertIsNotNone(tx)
            self.assertIn(tx.txid(), tx_ids)

    def test_get_entry(self):
        cache = TxCache(self.store)

        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(bytedata_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(position=11)
        cache.add([ (tx_id_1, data, bytedata_1, TxFlags.StateCleared) ])

        entry = cache.get_entry(tx_id_1, TxFlags.StateDispatched)
        self.assertIsNone(entry)

        entry = cache.get_entry(tx_id_1, TxFlags.StateCleared)
        self.assertIsNotNone(entry)

    def test_get_height(self):
        cache = TxCache(self.store)

        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(bytedata_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        metadata_1 = TxData(height=11)
        cache.add([ (tx_id_1, metadata_1, bytedata_1, TxFlags.StateCleared) ])

        self.assertEqual(11, cache.get_height(tx_id_1))

        cache.update_flags(tx_id_1, TxFlags.StateSettled)
        self.assertEqual(11, cache.get_height(tx_id_1))

        cache.update_flags(tx_id_1, TxFlags.StateReceived)
        self.assertIsNone(cache.get_height(tx_id_1))

    def test_get_unsynced_ids(self):
        cache = TxCache(self.store)

        bytedata_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(bytedata_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        metadata_1 = TxData(height=11)
        cache.add([ (tx_id_1, metadata_1, None, TxFlags.StateCleared) ])

        results = cache.get_unsynced_ids()
        self.assertEqual(1, len(results))

        metadata_2 = TxData()
        cache.update([ (tx_id_1, metadata_2, bytedata_1, TxFlags.HasByteData) ])

        results = cache.get_unsynced_ids()
        self.assertEqual(0, len(results))

    def test_get_unverified_entries(self):
        cache = TxCache(self.store)

        tx_bytes_1 = bytes.fromhex(tx_hex_1)
        tx_hash_bytes_1 = bitcoinx.double_sha256(tx_bytes_1)
        tx_id_1 = bitcoinx.hash_to_hex_str(tx_hash_bytes_1)
        data = TxData(height=11, position=22)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateCleared) ])

        results = cache.get_unverified_entries(100)
        self.assertEqual(0, len(results))

        cache = TxCache(self.store)

        data = TxData(height=11)
        cache.add([ (tx_id_1, data, tx_bytes_1, TxFlags.StateCleared) ])

        results = cache.get_unverified_entries(10)
        self.assertEqual(0, len(results))

        results = cache.get_unverified_entries(11)
        self.assertEqual(1, len(results))


class TestXputCache(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db_filename_txin = os.path.join(cls.temp_dir.name, "test_txin")
        db_filename_txout = os.path.join(cls.temp_dir.name, "test_txout")
        aeskey_hex = "6fce243e381fe158b5e6497c6deea5db5fbc1c6f5659176b9c794379f97269b4"
        aeskey = bytes.fromhex(aeskey_hex)
        cls.txin_store = wallet_database.TransactionInputStore(db_filename_txin, aeskey)
        cls.txout_store = wallet_database.TransactionOutputStore(db_filename_txout, aeskey)

    @classmethod
    def tearDownClass(cls):
        cls.txin_store.close()
        cls.txin_store = None
        cls.txout_store.close()
        cls.txout_store = None
        cls.temp_dir = None

    def setUp(self):
        for store in (self.txin_store, self.txout_store):
            db = store._get_db()
            db.execute(f"DELETE FROM {store._table_name}")
            db.commit()

            store._fetch_write_timestamp()

    def tearDown(self):
        pass

    def test_cache_with_preload(self):
        tx_id = os.urandom(10).hex()
        tx_input = DBTxInput("address_string", "hash", 10, 10)
        tx_output = DBTxOutput("address_string", 10, 10, False)

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            tx_store.add_entries([ (tx_id, tx_xput) ])

            cache = wallet_database.TxXputCache(tx_store)
            self.assertTrue(tx_id in cache._cache)
            self.assertEqual(1, len(cache._cache[tx_id]))
            self.assertEqual(tx_xput, cache._cache[tx_id][0])

    def test_cache_get_entries(self):
        tx_id = os.urandom(10).hex()
        tx_input = DBTxInput("address_string", "hash", 10, 10)
        tx_output = DBTxOutput("address_string", 10, 10, False)

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            tx_store.add_entries([ (tx_id, tx_xput) ])
            cache = wallet_database.TxXputCache(tx_store)
            entries = cache.get_entries(tx_id)

            self.assertEqual(1, len(entries))
            self.assertEqual(tx_xput, entries[0])

    def test_cache_add(self):
        tx_id = os.urandom(10).hex()
        tx_input = DBTxInput("address_string", "hash", 10, 10)
        tx_output = DBTxOutput("address_string", 10, 10, False)

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            cache = wallet_database.TxXputCache(tx_store)
            cache.add_entries([ (tx_id, tx_xput) ])

            # Check the caching layer has the entry.
            self.assertTrue(tx_id in cache._cache)
            self.assertEqual(1, len(cache._cache[tx_id]))
            self.assertEqual(tx_xput, cache._cache[tx_id][0])

            # Check the store has the entry.
            entries = tx_store.get_entries(tx_id)
            self.assertEqual(1, len(entries))
            self.assertEqual(tx_xput, entries[0])

    def test_cache_delete(self):
        tx_id = os.urandom(10).hex()
        tx_input = DBTxInput("address_string", "hash", 10, 10)
        tx_output = DBTxOutput("address_string", 10, 10, False)

        for tx_xput, tx_store in ((tx_input, self.txin_store), (tx_output, self.txout_store)):
            cache = wallet_database.TxXputCache(tx_store)
            cache.add_entries([ (tx_id, tx_xput) ])
            cache.delete_entries([ (tx_id, tx_xput) ])

            # Check the caching layer no longer has the entry.
            self.assertEqual(0, len(cache._cache[tx_id]))

            # Check the store no longer has the entry.
            entries = tx_store.get_entries(tx_id)
            self.assertEqual(0, len(entries))
