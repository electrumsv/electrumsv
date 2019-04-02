import os
import tempfile
import unittest

import bitcoinx

from electrumsv.transaction import Transaction
from electrumsv import transaction_store

tx_hex_1 = ("01000000011a284a701e6a69ba68ac4b1a4509ac04f5c10547e3165fe869d5e910fe91bc4c04000000"+
    "6b483045022100e81ce3382de4d63efad1e2bc4a7ebe70fb03d8451c1bc176b2dfd310f7a636f302200eab4382"+
    "9f9d4c94be41c640f9f6261657dcac6dc345718b89e7a80645dbe27f412102defddf740fa60b0dcdc88578d9de"+
    "a51350db9245e4f1a5072be00e9fb0573fddffffffff02a0860100000000001976a914717b9a7840ef60ef2e2a"+
    "6fca85d55988e070137988acda837e18000000001976a914c0eab5430fd02e18edfc28607eae975001e7560488"+
    "ac00000000")

class TestTransactionStore(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_filename = os.path.join(self.temp_dir.name, "test")
        self.store = transaction_store.TransactionStore(self.db_filename)

        self.tx_id = os.urandom(32).hex()

    def tearDown(self):
        self.store.close()

    def test_create_db_passive(self):
        # This has already run on TransactionStore creation. We test that it does not error being
        # run again, if the database entities already exist.
        self.store._create(self.store._get_db())

    def test_has_for_missing_transaction(self):
        self.assertFalse(self.store.has(self.tx_id))

    def test_has_for_existing_transaction(self):
        self.store.add(self.tx_id, os.urandom(100))
        self.assertTrue(self.store.has(self.tx_id))

    def test_add_bytes_transaction(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        tx_hex = tx_bytes.hex()
        self.store.add(tx_id, tx_bytes)
        tx = self.store.get(tx_id)
        self.assertEqual(tx_hex, str(tx))

    def test_add_string_transaction(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        tx_hex = tx_bytes.hex()
        self.store.add(tx_id, tx_hex)
        tx = self.store.get(tx_id)
        self.assertEqual(tx_hex, str(tx))

    def test_add_transaction_object(self):
        tx_hex = tx_hex_1
        tx_0 = Transaction(tx_hex)
        tx_id_0 = tx_0.txid()
        self.store.add(tx_id_0, tx_0)
        tx_1 = self.store.get(tx_id_0)
        self.assertEqual(tx_hex, str(tx_1))

    def test_add_bad_transaction(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, bytes(reversed(tx_bytes)))
        tx = self.store.get(tx_id)
        self.assertTrue(tx is None)

    def test_was_received(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes)
        self.assertTrue(self.store.was_received(tx_id))

    def test_was_received_when_pending(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes, is_pending=True)
        self.assertFalse(self.store.was_received(self.tx_id))

    def test_was_received_when_nonexistent(self):
        self.assertFalse(self.store.was_received(self.tx_id))

    def test_add_many_received(self):
        tx_map = {}
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            tx_map[tx_id] = tx_bytes.hex()
        self.store.add_many(tx_map)
        received_tx_ids = self.store.get_received_ids()
        added_tx_ids = set(tx_map)
        self.assertEqual(received_tx_ids, added_tx_ids)

    def test_add_many_pending(self):
        tx_map = {}
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            tx_map[tx_id] = tx_bytes.hex()
        self.store.add_many(tx_map, is_pending=True)
        pending_tx_ids = self.store.get_pending_ids()
        added_tx_ids = set(tx_map)
        self.assertEqual(pending_tx_ids, added_tx_ids)

    def test_delete(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes)
        self.assertTrue(self.store.has(tx_id))
        self.store.delete(tx_id)
        self.assertFalse(self.store.has(tx_id))

    def test_delete_many(self):
        tx_map = {}
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
            tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
            tx_map[tx_id] = tx_bytes.hex()
        self.store.add_many(tx_map)
        for tx_id in tx_map:
            self.assertTrue(self.store.has(tx_id))
        self.store.delete_many(list(tx_map))
        for tx_id in tx_map:
            self.assertFalse(self.store.has(tx_id))

    def test_get_unfiltered_received(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes) # Add as received.
        self.assertTrue(self.store.has(tx_id))
        self.assertIsNotNone(self.store.get(tx_id))

    def test_get_unfiltered_pending(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes, is_pending=True) # Add as pending.
        self.assertTrue(self.store.has(tx_id))
        self.assertIsNotNone(self.store.get(tx_id))

    def test_get_filtered_pending_nonexistent(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes) # Add as received.
        self.assertTrue(self.store.has(tx_id))
        self.assertIsNone(self.store.get(tx_id, is_pending=True))

    def test_get_filtered_pending(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes, is_pending=True) # Add as pending.
        self.assertTrue(self.store.has(tx_id))
        self.assertIsNotNone(self.store.get(tx_id, is_pending=True))

    def test_get_filtered_received(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes) # Add as received.
        self.assertTrue(self.store.has(tx_id))
        self.assertIsNotNone(self.store.get(tx_id, is_pending=False))

    def test_get_filtered_received_nonexistent(self):
        tx_bytes = os.urandom(10)
        tx_hash_bytes = bitcoinx.double_sha256(tx_bytes)
        tx_id = bitcoinx.hash_to_hex_str(tx_hash_bytes)
        self.store.add(tx_id, tx_bytes, is_pending=True) # Add as pending.
        self.assertTrue(self.store.has(tx_id))
        self.assertIsNone(self.store.get(tx_id, is_pending=False))
