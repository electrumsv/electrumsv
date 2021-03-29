import bitcoinx
import os
import pytest
try:
    # Linux expects the latest package version of 3.34.0 (as of pysqlite-binary 0.4.5)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.34.0 (as of 2021-01-13).
    # Windows builds use the official Python 3.9.1 builds and bundled version of 3.33.0.
    import sqlite3 # type: ignore
import tempfile
from typing import List

from electrumsv.constants import (AccountTxFlags, DerivationType, KeyInstanceFlag,
    PaymentFlag, ScriptType, TransactionOutputFlag, TxFlags, WalletEventFlag, WalletEventType)
from electrumsv.logs import logs
from electrumsv.types import TxoKeyType
from electrumsv.wallet_database import functions as db_functions
from electrumsv.wallet_database import migration
from electrumsv.wallet_database.sqlite_support import DatabaseContext, LeakedSQLiteConnectionError
from electrumsv.wallet_database.types import (AccountRow, AccountTransactionRow, InvoiceAccountRow,
    InvoiceRow, KeyInstanceRow, MasterKeyRow, PaymentRequestRow, PaymentRequestUpdateRow,
    TransactionRow, TransactionOutputShortRow, TxProof, WalletEventRow)
from electrumsv.wallet_database.util import pack_proof, unpack_proof

logs.set_level("debug")


tx_hex_1 = ("01000000011a284a701e6a69ba68ac4b1a4509ac04f5c10547e3165fe869d5e910fe91bc4c04000000"
    "6b483045022100e81ce3382de4d63efad1e2bc4a7ebe70fb03d8451c1bc176b2dfd310f7a636f302200eab4382"
    "9f9d4c94be41c640f9f6261657dcac6dc345718b89e7a80645dbe27f412102defddf740fa60b0dcdc88578d9de"
    "a51350db9245e4f1a5072be00e9fb0573fddffffffff02a0860100000000001976a914717b9a7840ef60ef2e2a"
    "6fca85d55988e070137988acda837e18000000001976a914c0eab5430fd02e18edfc28607eae975001e7560488"
    "ac00000000")

tx_hex_2 = ("010000000113529b6e34ceebfa3911c569b568ef48b95cc25d4c5c6a5b2435d30c9dbcc8af0000000"
    "06b483045022100876dfdc3228ff561531c3ba02e2ad9628230f02ef5036599e1c95b747e1731ac02205ed9ff1"
    "14adc6e7ca58b889272afa695d7f62902bb81286bb46aee7d3a31201e412102642f0cfdb3065d34276c8af2183"
    "e7d0d8e8e2ce85723eb6fe4942d0db949a225ffffffff027c150000000000001976a91439826f4659bba2a224b"
    "87b1812206fd4efc9ada388acc0dd3e00000000001976a914337106761eb441a326d4027f6d5aa19eed550c298"
    "8ac00000000")


def _db_context():
    wallet_path = os.path.join(tempfile.mkdtemp(), "wallet_create")
    assert not os.path.exists(wallet_path)
    migration.create_database_file(wallet_path)
    migration.update_database_file(wallet_path)
    return DatabaseContext(wallet_path)

@pytest.fixture
def db_context() -> None:
    value = _db_context()
    yield value
    value.close()


def test_migrations() -> None:
    # Do all the migrations apply cleanly?
    wallet_path = os.path.join(tempfile.mkdtemp(), "wallet_create")
    migration.create_database_file(wallet_path)



def test_database_context() -> None:
    db_context = _db_context()
    # Wait for writer thread to start and acquire 1st connection
    db_context._write_dispatcher._writer_loop_event.wait()

    # initial state
    assert db_context._connection_pool.qsize() == 0
    assert len(db_context._active_connections) == 1  # for writer thread

    # should autoincrement additional connections as needed
    conn = db_context.acquire_connection()
    assert db_context._connection_pool.qsize() == 0
    assert len(db_context._active_connections) == 2

    # return 1 connection to the pool
    db_context.release_connection(conn)
    assert db_context._connection_pool.qsize() == 1
    assert len(db_context._active_connections) == 1

    # an exception is raised immediately on closing due to outstanding connections
    conn = db_context.acquire_connection()
    with pytest.raises(LeakedSQLiteConnectionError):
        db_context.close()

    assert db_context._connection_pool.qsize() == 0
    assert len(db_context._active_connections) == 0

    # any further use of the outstanding connection raises an exception too
    with pytest.raises(sqlite3.ProgrammingError):
        conn.commit()



def test_table_masterkeys_crud(db_context: DatabaseContext) -> None:
    masterkey_rows = db_functions.read_masterkeys(db_context)
    assert len(masterkey_rows) == 0

    line1 = MasterKeyRow(1, None, 2, b'111')
    line2 = MasterKeyRow(2, None, 4, b'222')

    future = db_functions.create_master_keys(db_context, [ line1 ])
    future.result(timeout=5)

    future = db_functions.create_master_keys(db_context, [ line2 ])
    future.result(timeout=5)

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_master_keys(db_context, [ line1 ])
        future.result(timeout=5)

    lines = db_functions.read_masterkeys(db_context)
    assert 2 == len(lines)
    line1_db = [ line for line in lines if line[0] == 1 ][0]
    line2_db = [ line for line in lines if line[0] == 2 ][0]
    assert line1 == line1_db
    assert line2 == line2_db

    future = db_functions.update_masterkey_derivation_datas(db_context, [ (b'234', 1) ])
    future.result()

    masterkey_rows = db_functions.read_masterkeys(db_context)
    masterkey_row1 = [ row for row in masterkey_rows if row.masterkey_id == 1 ][0]
    assert masterkey_row1.derivation_data == b'234'


def test_table_accounts_crud(db_context: DatabaseContext) -> None:
    rows = db_functions.read_accounts(db_context)
    assert len(rows) == 0

    ACCOUNT_ID = 10
    MASTERKEY_ID = 20

    line1 = AccountRow(ACCOUNT_ID+1, MASTERKEY_ID+1, ScriptType.P2PKH, 'name1')
    line2 = AccountRow(ACCOUNT_ID+2, MASTERKEY_ID+1, ScriptType.P2PK, 'name2')

    # No effect: The masterkey foreign key constraint will fail as the masterkey does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_accounts(db_context, [ line1 ])
        future.result()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    mk_row1 = MasterKeyRow(MASTERKEY_ID+1, None, 2, b'111')
    future = db_functions.create_master_keys(db_context, [ mk_row1 ])
    future.result(timeout=5)

    # Create the first and second row.
    # Create the second row.
    future1 = db_functions.create_accounts(db_context, [ line1 ])
    future2 = db_functions.create_accounts(db_context, [ line2 ])
    future1.result()
    future2.result()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_accounts(db_context, [ line1 ])
        future.result()

    db_lines = db_functions.read_accounts(db_context)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0] == line1[0] ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line[0] == line2[0] ][0]
    assert line2 == db_line2

    future1 = db_functions.update_account_names(db_context, [ ('new_name', line2[0]) ])
    future2 = db_functions.update_account_script_types(db_context,
        [ (ScriptType.MULTISIG_BARE, line2[0]) ])
    future1.result()
    future2.result()

    db_lines = db_functions.read_accounts(db_context)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0] == line1.account_id ][0]
    assert ScriptType.P2PKH == db_line1.default_script_type
    db_line2 = [ db_line for db_line in db_lines if db_line[0] == line2.account_id ][0]
    assert ScriptType.MULTISIG_BARE == db_line2.default_script_type
    assert 'new_name' == db_line2[3]



def test_account_transactions(db_context: DatabaseContext) -> None:
    ACCOUNT_ID_1 = 10
    ACCOUNT_ID_2 = 11
    MASTERKEY_ID_1 = 20
    MASTERKEY_ID_2 = 21

    # Create master keys.
    masterkey1 = MasterKeyRow(MASTERKEY_ID_1, None, DerivationType.BIP32, b'111')
    masterkey2 = MasterKeyRow(MASTERKEY_ID_2, None, DerivationType.BIP32, b'222')

    future = db_functions.create_master_keys(db_context, [ masterkey1, masterkey2 ])
    future.result(timeout=5)

    # Create the accounts.
    account1 = AccountRow(ACCOUNT_ID_1, MASTERKEY_ID_1, ScriptType.P2PKH, 'name1')
    account2 = AccountRow(ACCOUNT_ID_2, MASTERKEY_ID_2, ScriptType.P2PK, 'name2')

    future = db_functions.create_accounts(db_context, [ account1, account2 ])
    future.result()

    # Create the key instances.
    KEYINSTANCE_ID_1 = 100
    KEYINSTANCE_ID_2 = 101

    key1 = KeyInstanceRow(KEYINSTANCE_ID_1, ACCOUNT_ID_1, MASTERKEY_ID_1, DerivationType.BIP32,
        b'333', None, KeyInstanceFlag.NONE, None)
    key2 = KeyInstanceRow(KEYINSTANCE_ID_2, ACCOUNT_ID_2, MASTERKEY_ID_2, DerivationType.BIP32,
        b'444', None, KeyInstanceFlag.NONE, None)

    future = db_functions.create_keyinstances(db_context, [ key1, key2 ])
    future.result(timeout=5)

    # Create the transaction.
    TX_BYTES_1 = os.urandom(10)
    TX_HASH_1 = bitcoinx.double_sha256(TX_BYTES_1)
    tx1 = TransactionRow(
        tx_hash=TX_HASH_1,
        tx_bytes=TX_BYTES_1,
        flags=TxFlags.STATE_SETTLED, block_hash=b'11',
        block_height=1, block_position=1, fee_value=250,
        description=None, version=None, locktime=None, date_created=1, date_updated=2)
    TX_BYTES_2 = os.urandom(10)
    TX_HASH_2 = bitcoinx.double_sha256(TX_BYTES_2)
    tx2 = TransactionRow(
        tx_hash=TX_HASH_2,
        tx_bytes=TX_BYTES_2,
        flags=TxFlags.STATE_SETTLED, block_hash=b'11',
        block_height=1, block_position=1, fee_value=250,
        description=None, version=None, locktime=None, date_created=1, date_updated=2)
    future = db_functions.create_transactions(db_context, [ tx1, tx2 ])
    future.result(timeout=5)

    account_transaction_entries = [
        AccountTransactionRow(ACCOUNT_ID_1, TX_HASH_1, AccountTxFlags.NONE, None),
        AccountTransactionRow(ACCOUNT_ID_2, TX_HASH_2, AccountTxFlags.NONE, None),
    ]
    future = db_functions.create_account_transactions(db_context, account_transaction_entries)
    future.result()

    ## Test `read_transaction_hashes`.
    # Both tx should be matched.
    tx_hashes = db_functions.read_transaction_hashes(db_context)
    assert 2 == len(tx_hashes)
    assert { TX_HASH_1, TX_HASH_2 } == set(tx_hashes)

    # Only tx1 which is linked to account1 should be matched.
    tx_hashes_1 = db_functions.read_transaction_hashes(db_context, ACCOUNT_ID_1)
    assert 1 == len(tx_hashes_1)
    assert TX_HASH_1 == tx_hashes_1[0]

    # Only tx2 which is linked to account2 should be matched.
    tx_hashes_2 = db_functions.read_transaction_hashes(db_context, ACCOUNT_ID_2)
    assert 1 == len(tx_hashes_2)
    assert TX_HASH_2 == tx_hashes_2[0]

    # No tx are linked to this non-existent account.
    tx_hashes_3 = db_functions.read_transaction_hashes(db_context, -1)
    assert 0 == len(tx_hashes_3)



def test_table_keyinstances_crud(db_context: DatabaseContext) -> None:
    rows = db_functions.read_keyinstances(db_context)
    assert len(rows) == 0

    KEYINSTANCE_ID = 0
    ACCOUNT_ID = 10
    MASTERKEY_ID = 20
    DERIVATION_DATA1 = b'111'
    DERIVATION_DATA2 = b'222'

    line1 = KeyInstanceRow(KEYINSTANCE_ID+1, ACCOUNT_ID+1, MASTERKEY_ID+1, DerivationType.BIP32,
        DERIVATION_DATA1, None, 0, None)
    line2 = KeyInstanceRow(KEYINSTANCE_ID+2, ACCOUNT_ID+1, MASTERKEY_ID+1, DerivationType.HARDWARE,
        DERIVATION_DATA2, None, 0, None)

    # No effect: The masterkey foreign key constraint will fail as the masterkey does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_keyinstances(db_context, [ line1 ])
        future.result(timeout=5)

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context,
        [ MasterKeyRow(MASTERKEY_ID+1, None, 2, b'111') ])
    future.result(timeout=5)

    # No effect: The account foreign key constraint will fail as the account does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_keyinstances(db_context, [ line1 ])
        future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID+1, MASTERKEY_ID+1, ScriptType.P2PKH, 'name')
    future = db_functions.create_accounts(db_context, [ account_row ])
    future.result()

    # Create the first and second row.
    future = db_functions.create_keyinstances(db_context, [ line1, line2 ])
    future.result(timeout=5)

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_keyinstances(db_context, [ line1 ])
        future.result(timeout=5)

    db_lines = db_functions.read_keyinstances(db_context)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0] == line1[0] ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line[0] == line2[0] ][0]
    assert line2 == db_line2

    future = db_functions.update_keyinstance_derivation_datas(db_context, [ (b'234', line1[0]) ])
    future.result()

    db_lines = db_functions.read_keyinstances(db_context)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0] == line1[0] ][0]
    assert b'234' == db_line1.derivation_data
    db_line2 = [ db_line for db_line in db_lines if db_line[0] == line2[0] ][0]
    assert not db_line2[6]

    # Selective reading of only one record based on it's id.
    db_lines = db_functions.read_keyinstances(db_context, keyinstance_ids=[KEYINSTANCE_ID+1])
    assert 1 == len(db_lines)
    assert KEYINSTANCE_ID+1 == db_lines[0].keyinstance_id

    # Now try out the labels.
    future = db_functions.update_keyinstance_descriptions(db_context,
        [ ("line1", line1.keyinstance_id) ])
    future.result()

    rows = db_functions.read_keyinstances(db_context, keyinstance_ids=[line1.keyinstance_id])
    assert len(rows) == 1
    assert rows[0].keyinstance_id == line1.keyinstance_id
    assert rows[0].description == "line1"


class TestTransactionTable:
    @classmethod
    def setup_class(cls):
        cls.db_context = _db_context()
        cls.db = cls.db_context.acquire_connection()
        cls.tx_hash = os.urandom(32)

    @classmethod
    def teardown_class(cls):
        cls.db_context.release_connection(cls.db)
        cls.db = None
        cls.db_context.close()
        cls.db_context = None

    def setup_method(self):
        db = self.db
        db.execute(f"DELETE FROM Transactions")
        db.commit()

    def _get_store_hashes(self) -> List[bytes]:
        return db_functions.read_transaction_hashes(self.db_context)

    def test_proof_serialization(self):
        proof1 = TxProof(position=10, branch=[ os.urandom(32) for i in range(10) ])
        raw = pack_proof(proof1)
        proof2 = unpack_proof(raw)
        assert proof1.position == proof2.position
        assert proof1.branch == proof2.branch


    def test_create_read_various(self):
        tx_bytes_1 = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(tx_bytes_1)
        tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes_1,
            flags=TxFlags.STATE_DISPATCHED,
            block_hash=b'11', block_height=None, block_position=None, fee_value=None,
            description=None, version=None, locktime=None, date_created=1, date_updated=1)
        future = db_functions.create_transactions(self.db_context, [ tx_row ])
        future.result(timeout=5)

        # Check the state is correct, all states should be the same code path.
        flags = db_functions.read_transaction_flags(self.db_context, tx_hash)
        assert flags is not None
        assert TxFlags.STATE_DISPATCHED == flags & TxFlags.MASK_STATE

        block_height, block_position, fee_value, date_created = \
            db_functions.read_transaction_metadata(self.db_context, tx_hash)
        assert tx_row.block_height == block_height
        assert tx_row.block_position == block_position
        assert tx_row.fee_value == fee_value
        assert tx_row.date_created == date_created

        tx_bytes = db_functions.read_transaction_bytes(self.db_context, tx_hash)
        assert tx_bytes_1 == tx_bytes


    def test_create_multiple(self) -> None:
        to_add = []
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash = bitcoinx.double_sha256(tx_bytes)
            to_add.append(
                TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes, flags=TxFlags.UNSET,
                    block_hash=b'11',
                    block_height=1, block_position=None, fee_value=2, description=None,
                    version=None, locktime=None, date_created=1, date_updated=1))
        future = db_functions.create_transactions(self.db_context, to_add)
        future.result(timeout=5)

        existing_tx_hashes = set(self._get_store_hashes())
        added_tx_hashes = set(t[0] for t in to_add)
        assert added_tx_hashes == existing_tx_hashes

    # TODO(no-merge) no TxData any more
    #
    # def test_update(self):
    #     to_add = []
    #     for i in range(10):
    #         tx_bytes = os.urandom(10)
    #         tx_hash = bitcoinx.double_sha256(tx_bytes)
    #         tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes, flags=TxFlags.UNSET,
    #             block_height=None, block_position=None, fee_value=2, description=None,
    #             version=None, locktime=None, date_created=1, date_updated=1)
    #         to_add.append(tx_row)
    #     with SynchronousWriter() as writer:
    #         db_functions.create_transactions(self.db_context, to_add,
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     to_update = []
    #     for tx_row in to_add:
    #         tx_metadata = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
    #         to_update.append((tx_row.tx_hash, tx_metadata, tx_row.tx_bytes, tx_row.flags))
    #     with SynchronousWriter() as writer:
    #         self.store.update(to_update, completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     for get_tx_hash, bytedata_get, flags_get, metadata_get in self.store.read():
    #         for update_tx_hash, update_metadata, update_tx_bytes, update_flags in to_update:
    #             if update_tx_hash == get_tx_hash:
    #                 assert metadata_get == update_metadata
    #                 assert bytedata_get == update_tx_bytes
    #                 continue

    #
    # def test_update_flags(self):
    #     bytedata = os.urandom(10)
    #     tx_hash = bitcoinx.double_sha256(bytedata)
    #     tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=bytedata, flags=TxFlags.UNSET,
    #         block_height=1, block_position=None, fee_value=2, description=None,
    #         version=None, locktime=None, date_created=1, date_updated=1)
    #     with SynchronousWriter() as writer:
    #         db_functions.create_transactions(self.db_context, [ tx_row ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # Verify the field flags are assigned correctly on the add.
    #     expected_flags = TxFlags.HasFee | TxFlags.HasHeight
    #     _tx_hash, flags, _metadata = self.store.read_metadata(tx_hashes=[tx_hash])[0]
    #     assert expected_flags == flags, f"expected {expected_flags!r}, got {TxFlags.to_repr(flags)}"

    #     flags = TxFlags.STATE_RECEIVED
    #     mask = TxFlags.METADATA_FIELD_MASK
    #     date_updated = 1
    #     with SynchronousWriter() as writer:
    #         self.store.update_flags([ (tx_hash, flags, mask, date_updated) ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # Verify the state flag is correctly added via the mask.
    #     _tx_hash, flags_get, _metadata = self.store.read_metadata(tx_hashes=[tx_hash])[0]
    #     expected_flags |= TxFlags.STATE_RECEIVED
    #     assert expected_flags == flags_get, \
    #         f"{TxFlags.to_repr(expected_flags)} != {TxFlags.to_repr(flags_get)}"

    #     flags = TxFlags.STATE_RECEIVED
    #     mask = TxFlags.UNSET
    #     date_updated = 1
    #     with SynchronousWriter() as writer:
    #         self.store.update_flags([ (tx_hash, flags, mask, date_updated) ],
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # Verify the state flag is correctly set via the mask.
    #     _tx_hash, flags, _metadata = self.store.read_metadata(tx_hashes=[tx_hash])[0]
    #     assert TxFlags.STATE_RECEIVED == flags


    def test_get_all_pending(self):
        get_tx_hashes = set()
        for tx_hex in (tx_hex_1, tx_hex_2):
            tx_bytes = bytes.fromhex(tx_hex)
            tx_hash = bitcoinx.double_sha256(tx_bytes)
            tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes, flags=TxFlags.UNSET,
                block_hash=b'11', block_height=1, block_position=None, fee_value=2,
                description=None, version=None, locktime=None, date_created=1, date_updated=1)
            future = db_functions.create_transactions(self.db_context, [ tx_row ])
            future.result(timeout=5)
            get_tx_hashes.add(tx_hash)

        result_tx_hashes = set(self._get_store_hashes())
        assert get_tx_hashes == result_tx_hashes

    #
    # def test_read(self):
    #     to_add = []
    #     for i in range(10):
    #         tx_bytes = os.urandom(10)
    #         tx_hash = bitcoinx.double_sha256(tx_bytes)
    #         tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes, flags=TxFlags.HasFee,
    #             block_height=None, block_position=None, fee_value=2, description=None,
    #             version=None, locktime=None, date_created=1, date_updated=1)
    #         to_add.append(tx_row)
    #     with SynchronousWriter() as writer:
    #         db_functions.create_transactions(self.db_context,
    #             to_add, completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # Test the first "add" hash is matched.
    #     tx_hash_1 = to_add[0][0]
    #     matches = self.store.read(tx_hashes=[tx_hash_1])
    #     assert tx_hash_1 == matches[0][0]
    #     assert self.store.read(tx_hashes=[tx_hash_1])

    #     # Test no id is matched.
    #     matches = self.store.read(tx_hashes=[b"aaaa"])
    #     assert 0 == len(matches)

    #     # Test flag and mask combinations.
    #     matches = self.store.read(flags=TxFlags.HasFee)
    #     assert 10 == len(matches)

    #     matches = self.store.read(flags=TxFlags.UNSET, mask=TxFlags.HasHeight)
    #     assert 10 == len(matches)

    #     matches = self.store.read(flags=TxFlags.HasFee, mask=TxFlags.HasFee)
    #     assert 10 == len(matches)

    #     matches = self.store.read(flags=TxFlags.UNSET, mask=TxFlags.HasFee)
    #     assert 0 == len(matches)

    #
    # def test_read_metadata(self) -> None:
    #     # We're going to add five matches and look for two of them, checking that we do not match
    #     # unwanted rows.
    #     all_tx_hashes = []
    #     datas = []
    #     for i in range(5):
    #         tx_bytes = os.urandom(10)
    #         tx_hash = bitcoinx.double_sha256(tx_bytes)
    #         tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes, flags=TxFlags.UNSET,
    #             block_height=i*100, block_position=None, fee_value=i*1000, description=None,
    #             version=None, locktime=None, date_created=1, date_updated=1)
    #         datas.append(tx_row)
    #         all_tx_hashes.append(tx_hash)
    #     with SynchronousWriter() as writer:
    #         db_functions.create_transactions(self.db_context, datas,
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # We also ask for a dud tx_hash that won't get matched.
    #     select_tx_hashes = [ all_tx_hashes[0], all_tx_hashes[3], b"12121212" ]
    #     rowdatas = self.store.read_metadata(tx_hashes=select_tx_hashes)
    #     # Check that the two valid matches are there and their values match the projected values.
    #     assert len(rowdatas) == 2
    #     for rowdata in rowdatas:
    #         tx_hash = rowdata[0]
    #         tx_flags = rowdata[1]
    #         metadata = rowdata[2]
    #         rowidx = all_tx_hashes.index(tx_hash)
    #         assert metadata.height == rowidx * 100
    #         assert metadata.fee == rowidx * 1000
    #         assert metadata.position is None

    #
    # def test_update_metadata(self) -> None:
    #     # We're going to add five matches and look for two of them, checking that we do not match
    #     # unwanted rows.
    #     tx_hashes = []
    #     datas = []
    #     for i in range(5):
    #         tx_bytes = os.urandom(10)
    #         tx_hash = bitcoinx.double_sha256(tx_bytes)
    #         tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes, flags=TxFlags.UNSET,
    #             block_height=i*100, block_position=None, fee_value=i*1000, description=None,
    #             version=None, locktime=None, date_created=1, date_updated=1)
    #         datas.append(tx_row)
    #         tx_hashes.append(tx_hash)
    #     with SynchronousWriter() as writer:
    #         db_functions.create_transactions(self.db_context, datas,
    #             completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     updates = []
    #     for i in range(5):
    #         tx_hash = tx_hashes[i]
    #         metadata = TxData(height=i*200, fee=i*2000, position=None, date_added=1, date_updated=1)
    #         updates.append((tx_hash, metadata, TxFlags.HasHeight | TxFlags.HasFee))
    #     with SynchronousWriter() as writer:
    #         self.store.update_metadata(updates, completion_callback=writer.get_callback())
    #         assert writer.succeeded()

    #     # We also ask for a dud tx_hash that won't get matched.
    #     select_tx_hashes = [ tx_hashes[0], tx_hashes[3], b"12121212" ]
    #     rowdatas = self.store.read_metadata(tx_hashes=select_tx_hashes)
    #     # Check that the two valid matches are there and their values match the projected values.
    #     assert len(rowdatas) == 2
    #     for rowdata in rowdatas:
    #         tx_hash = rowdata[0]
    #         tx_flags = rowdata[1]
    #         metadata = rowdata[2]
    #         rowidx = tx_hashes.index(tx_hash)
    #         assert metadata.height == rowidx * 200
    #         assert metadata.fee == rowidx * 2000
    #         assert metadata.position is None

    def test_proof(self):
        tx_bytes = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(tx_bytes)
        tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes, flags=TxFlags.UNSET,
            block_hash=b'11', block_height=1, block_position=None, fee_value=2, description=None,
            version=None, locktime=None, date_created=1, date_updated=1)
        future = db_functions.create_transactions(self.db_context, [ tx_row ])
        future.result(timeout=5)

        position1 = 10
        merkle_branch1 = [ os.urandom(32) for i in range(10) ]
        proof = TxProof(position1, merkle_branch1)
        future = db_functions.update_transaction_proof(self.db_context, tx_hash, 1, 10, proof)
        future.result()

        rows = db_functions.read_transaction_proof(self.db_context, [ self.tx_hash ])
        assert len(rows) == 0

        rows = db_functions.read_transaction_proof(self.db_context, [ tx_hash ])
        assert len(rows) == 1
        assert rows[0].tx_hash == tx_hash
        proof = rows[0].unpack_proof()
        assert proof.position == position1
        assert proof.branch == merkle_branch1


    # TODO(no-merge) descriptions have moved to AccountTransactions
    # def test_labels(self):
    #     bytedata_1 = os.urandom(10)
    #     tx_hash_1 = bitcoinx.double_sha256(bytedata_1)
    #     tx_row_1 = TransactionRow(tx_hash=tx_hash_1, tx_bytes=bytedata_1, flags=TxFlags.UNSET,
    #         block_height=1, block_position=None, fee_value=2, description=None,
    #         version=None, locktime=None, date_created=1, date_updated=1)

    #     bytedata_2 = os.urandom(10)
    #     tx_hash_2 = bitcoinx.double_sha256(bytedata_2)
    #     tx_row_2 = TransactionRow(tx_hash=tx_hash_2, tx_bytes=bytedata_2, flags=TxFlags.UNSET,
    #         block_height=1, block_position=None, fee_value=2, description=None,
    #         version=None, locktime=None, date_created=1, date_updated=1)

    #     future = db_functions.create_transactions(self.db_context, [ tx_row_1, tx_row_2 ])
    #     future.result(timeout=5)

    #     future = db_functions.update_transaction_descriptions(self.db_context,
    #         [ ("tx 1", tx_hash_1) ])
    #     future.result()

    #     rows = self.store.read_descriptions()
    #     assert len(rows) == 1
    #     assert len([r[1] == "tx 1" for r in rows if r[0] == tx_hash_1]) == 1

    #     future = db_functions.update_transaction_descriptions(self.db_context,
    #         [ (None, tx_hash_1), ("tx 2", tx_hash_2) ])
    #     future.result()

    #     rows = self.store.read_descriptions([ tx_hash_2 ])
    #     assert len(rows) == 1
    #     assert rows[0][0] == tx_hash_2 and rows[0][1] == "tx 2"

    #     # Reading entries for a non-existent ...
    #     rows = self.store.read_descriptions([ self.tx_hash ])
    #     assert len(rows) == 0


def test_table_transactionoutputs_crud(db_context: DatabaseContext) -> None:
    TX_BYTES = os.urandom(10)
    TX_HASH = bitcoinx.double_sha256(TX_BYTES)
    TX_INDEX = 1
    TXOUT_FLAGS = TransactionOutputFlag.NONE
    KEYINSTANCE_ID_1 = 1
    KEYINSTANCE_ID_2 = 2
    ACCOUNT_ID = 10
    MASTERKEY_ID = 20
    DERIVATION_DATA1 = b'111'
    DERIVATION_DATA2 = b'222'

    row1 = TransactionOutputShortRow(TX_HASH, TX_INDEX, 100, KEYINSTANCE_ID_1, TXOUT_FLAGS,
        ScriptType.P2PKH, b'')
    row2 = TransactionOutputShortRow(TX_HASH, TX_INDEX+1, 200, KEYINSTANCE_ID_2, TXOUT_FLAGS,
        ScriptType.P2PKH, b'')

    # No effect: The transactionoutput foreign key constraint will fail as the transactionoutput
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_transaction_outputs(db_context, [ row1 ])
        future.result(timeout=5)

    # Satisfy the transaction foreign key constraint by creating the transaction.
    tx_rows = [ TransactionRow(tx_hash=TX_HASH, tx_bytes=TX_BYTES, flags=TxFlags.UNSET,
        block_hash=b'11', block_height=1, block_position=None, fee_value=2, description=None,
        version=None, locktime=None, date_created=1, date_updated=1) ]
    future = db_functions.create_transactions(db_context, tx_rows)
    future.result(timeout=5)

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context, [ (MASTERKEY_ID, None, 2, b'111') ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name')
    future = db_functions.create_accounts(db_context, [ account_row ])
    future.result()

    # Satisfy the keyinstance foreign key constraint by creating the keyinstance.
    key_rows = [
        KeyInstanceRow(KEYINSTANCE_ID_1, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            DERIVATION_DATA1, None, KeyInstanceFlag.NONE, None),
        KeyInstanceRow(KEYINSTANCE_ID_2, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            DERIVATION_DATA2, None, KeyInstanceFlag.NONE, None),
    ]
    future = db_functions.create_keyinstances(db_context, key_rows)
    future.result(timeout=5)

    # Create the first and second row.
    future = db_functions.create_transaction_outputs(db_context, [ row1, row2 ])
    future.result(timeout=5)

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_transaction_outputs(db_context, [ row1 ])
        future.result(timeout=5)

    txo_keys = [
        TxoKeyType(row1.tx_hash, row1.tx_index),
        TxoKeyType(row2.tx_hash, row2.tx_index),
    ]
    db_rows = db_functions.read_transaction_outputs_explicit(db_context, txo_keys)
    assert 2 == len(db_rows)
    db_row1 = db_rows[0]
    assert row1.flags == db_row1.flags
    db_row1 = [ db_line for db_line in db_rows if db_line == row1 ][0]
    assert row1 == db_row1
    db_row2 = [ db_line for db_line in db_rows if db_line == row2 ][0]
    assert row2 == db_row2

    date_updated = 20

    txo_keys = [ TxoKeyType(row2.tx_hash, row2.tx_index) ]
    future = db_functions.update_transaction_output_flags(db_context, txo_keys,
        TransactionOutputFlag.IS_SPENT)
    future.result()

    db_rows = db_functions.read_transaction_outputs_explicit(db_context, txo_keys)
    assert len(db_rows) == 1
    assert db_rows[0].flags == TransactionOutputFlag.IS_SPENT


def test_table_paymentrequests_crud(db_context: DatabaseContext) -> None:
    rows = db_functions.read_payment_requests(db_context)
    assert len(rows) == 0

    TX_BYTES = os.urandom(10)
    TX_HASH = bitcoinx.double_sha256(TX_BYTES)
    TX_INDEX = 1
    TXOUT_FLAGS = 1 << 15
    KEYINSTANCE_ID = 1
    ACCOUNT_ID = 10
    MASTERKEY_ID = 20
    DERIVATION_DATA = b'111'

    TX_BYTES2 = os.urandom(10)
    TX_HASH2 = bitcoinx.double_sha256(TX_BYTES2)

    LINE_COUNT = 3
    line1 = PaymentRequestRow(1, KEYINSTANCE_ID, PaymentFlag.PAID, None, None, "desc")
    line2 = PaymentRequestRow(2, KEYINSTANCE_ID+1, PaymentFlag.UNPAID, 100, 60*60, None)

    # No effect: The transactionoutput foreign key constraint will fail as the key instance
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_payment_requests(db_context, [ line1 ])
        future.result()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context, [ (MASTERKEY_ID, None, 2, b'111') ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name')
    future = db_functions.create_accounts(db_context, [ account_row ])
    future.result()

    # Satisfy the keyinstance foreign key constraint by creating the keyinstance.
    entries = [ (KEYINSTANCE_ID+i, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
        DERIVATION_DATA, ScriptType.P2PKH, True, None) for i in range(LINE_COUNT) ]
    future = db_functions.create_keyinstances(db_context, entries)
    future.result(timeout=5)

    future = db_functions.create_payment_requests(db_context, [ line1, line2 ])
    future.result()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_payment_requests(db_context, [ line1 ])
        future.result()

    def compare_paymentrequest_rows(row1: PaymentRequestRow, row2: PaymentRequestRow) -> None:
        assert row1.keyinstance_id == row2.keyinstance_id
        assert row1.state == row2.state
        assert row1.value == row2.value
        assert row1.expiration == row2.expiration
        assert row1.description == row2.description
        assert -1 != row2.date_created

    # Read all rows in the table.
    db_lines = db_functions.read_payment_requests(db_context)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines
        if db_line.paymentrequest_id == line1.paymentrequest_id ][0]
    compare_paymentrequest_rows(line1, db_line1)
    db_line2 = [ db_line for db_line in db_lines
        if db_line.paymentrequest_id == line2.paymentrequest_id ][0]
    compare_paymentrequest_rows(line2, db_line2)

    # Read all PAID rows in the table.
    db_lines = db_functions.read_payment_requests(db_context, mask=PaymentFlag.PAID)
    assert 1 == len(db_lines)
    assert 1 == db_lines[0].paymentrequest_id
    assert KEYINSTANCE_ID == db_lines[0].keyinstance_id

    # Read all UNPAID rows in the table.
    db_lines = db_functions.read_payment_requests(db_context, mask=PaymentFlag.UNPAID)
    assert 1 == len(db_lines)
    assert 2 == db_lines[0].paymentrequest_id
    assert KEYINSTANCE_ID+1 == db_lines[0].keyinstance_id

    # Require ARCHIVED flag.
    db_lines = db_functions.read_payment_requests(db_context, mask=PaymentFlag.ARCHIVED)
    assert 0 == len(db_lines)

    # Require no ARCHIVED flag.
    db_lines = db_functions.read_payment_requests(db_context, flags=PaymentFlag.NONE,
        mask=PaymentFlag.ARCHIVED)
    assert 2 == len(db_lines)

    row = db_functions.read_payment_request(db_context, request_id=1)
    assert row is not None
    assert 1 == row.paymentrequest_id

    row = db_functions.read_payment_request(db_context, request_id=100101)
    assert row is None

    future = db_functions.update_payment_requests(db_context, [ PaymentRequestUpdateRow(
        PaymentFlag.UNKNOWN, 20, 999, "newdesc", line2.paymentrequest_id) ])
    future.result()

    db_lines = db_functions.read_payment_requests(db_context)
    assert 2 == len(db_lines)
    db_line2 = [ db_line for db_line in db_lines
        if db_line.paymentrequest_id == line2.paymentrequest_id ][0]
    assert db_line2.value == 20
    assert db_line2.state == PaymentFlag.UNKNOWN
    assert db_line2.description == "newdesc"
    assert db_line2.expiration == 999

    # Account does not exist.
    db_lines = db_functions.read_payment_requests(db_context, account_id=1000)
    assert 0 == len(db_lines)

    # This account is matched.
    db_lines = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID)
    assert 2 == len(db_lines)

    future = db_functions.delete_payment_request(db_context, line2.paymentrequest_id,
        line2.keyinstance_id)
    future.result()

    db_lines = db_functions.read_payment_requests(db_context)
    assert 1 == len(db_lines)
    assert db_lines[0].paymentrequest_id == line1.paymentrequest_id


def test_table_walletevents_crud(db_context: DatabaseContext) -> None:
    MASTERKEY_ID = 1
    ACCOUNT_ID = 1

    line1 = WalletEventRow(1, WalletEventType.SEED_BACKUP_REMINDER, ACCOUNT_ID,
        WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, 1)
    line2 = WalletEventRow(2, WalletEventType.SEED_BACKUP_REMINDER, None,
        WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, 1)

    # No effect: The transactionoutput foreign key constraint will fail as the key instance
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_wallet_events(db_context, [ line1 ])
        future.result()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context, [ (MASTERKEY_ID, None, 2, b'111') ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name')
    future = db_functions.create_accounts(db_context, [ account_row ])
    future.result()

    future = db_functions.create_wallet_events(db_context, [ line1, line2 ])
    future.result()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_wallet_events(db_context, [ line1 ])
        future.result()

    db_lines = db_functions.read_wallet_events(db_context)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line == line1 ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line == line2 ][0]
    assert line2 == db_line2

    date_updated = 20

    future = db_functions.update_wallet_event_flags(db_context,
        [ (WalletEventFlag.UNREAD, line2.event_id) ])
    future.result()

    db_lines = db_functions.read_wallet_events(db_context)
    assert 2 == len(db_lines)
    db_line2 = [ db_line for db_line in db_lines
        if db_line.event_id == line2.event_id ][0]
    assert db_line2.event_flags == WalletEventFlag.UNREAD

    # Account does not exist.
    db_lines = db_functions.read_wallet_events(db_context, 1000)
    assert 0 == len(db_lines)

    # This account is matched.
    db_lines = db_functions.read_wallet_events(db_context, ACCOUNT_ID)
    assert 1 == len(db_lines)


# TODO(no-merge) need to remove when we deal with a new deactivated key system
# def test_update_used_keys(db_context: DatabaseContext):
#     """3 main scenarios to test:
#     - 2 x settled txs and zero balance -> used key gets deactivated
#     - 2 x unsettled tx -> not yet used (until settled)
#     - 2 x settled tx BUT user_set_active -> keeps it activated until manually deactivated"""

#     masterkey_table = MasterKeyTable(db_context)
#     accounts_table = AccountTable(db_context)
#     transaction_deltas_table = TransactionDeltaTable(db_context)
#     keyinstance_table = KeyInstanceTable(db_context)
#     tx_table = TransactionTable(db_context)

#     timestamp = tx_table._get_current_timestamp()
#     tx_entries = [
#         # 2 x Settled txs -> Used keyinstance (key_id = 1)
#         TransactionRow(
#             tx_hash=b'1', tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
#                 date_updated=timestamp), tx_bytes=b'tx_bytes1',
#             flags=TxFlags(TxFlags.STATE_SETTLED | TxFlags.HasHeight),
#             description=None, version=None, locktime=None),
#         TransactionRow(tx_hash=b'2',
#             tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
#                 date_updated=timestamp), tx_bytes=b'tx_bytes1',
#             flags=TxFlags(TxFlags.STATE_SETTLED | TxFlags.HasHeight),
#             description=None, version=None, locktime=None),
#         # 2 x Unsettled txs -> Not yet "Used" until settled (key_id = 2)
#         TransactionRow(tx_hash=b'3',
#             tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
#                 date_updated=timestamp), tx_bytes=b'tx_bytes3',
#             flags=TxFlags(TxFlags.STATE_CLEARED | TxFlags.HasHeight),
#             description=None, version=None, locktime=None),
#         TransactionRow(tx_hash=b'4',
#             tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
#                 date_updated=timestamp), tx_bytes=b'tx_bytes4',
#             flags=TxFlags(TxFlags.STATE_CLEARED | TxFlags.HasHeight),
#             description=None, version=None, locktime=None),
#         # 2 x Settled txs BUT keyinstance has flag: USER_SET_ACTIVE manually so not deactivated.
#         TransactionRow(tx_hash=b'5',
#             tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
#                 date_updated=timestamp), tx_bytes=b'tx_bytes5',
#             flags=TxFlags(TxFlags.STATE_SETTLED | TxFlags.HasHeight),
#             description=None, version=None, locktime=None),
#         TransactionRow(tx_hash=b'6',
#             tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
#                 date_updated=timestamp), tx_bytes=b'tx_bytes6',
#             flags=TxFlags(TxFlags.STATE_SETTLED | TxFlags.HasHeight),
#             description=None, version=None, locktime=None),
#     ]
#     tx_delta_entries = [
#         TransactionDeltaRow(tx_hash=b'1',keyinstance_id=1,value_delta=10),
#         TransactionDeltaRow(tx_hash=b'2',keyinstance_id=1,value_delta=-10),
#         TransactionDeltaRow(tx_hash=b'3', keyinstance_id=2, value_delta=10),
#         TransactionDeltaRow(tx_hash=b'4', keyinstance_id=2, value_delta=-10),
#         TransactionDeltaRow(tx_hash=b'5', keyinstance_id=3, value_delta=10),
#         TransactionDeltaRow(tx_hash=b'6', keyinstance_id=3, value_delta=-10)
#     ]

#     keyinstance_entries = [
#         KeyInstanceRow(keyinstance_id=1, account_id=1,masterkey_id=1,
#             derivation_type=DerivationType.BIP32, derivation_data=json.dumps({"subpath": [0, 0]}),
#             script_type=ScriptType.P2PKH, flags=KeyInstanceFlag.IS_ACTIVE, description=""),
#         KeyInstanceRow(keyinstance_id=2,account_id=1,masterkey_id=1,
#             derivation_type=DerivationType.BIP32, derivation_data=json.dumps({"subpath": [0, 1]}),
#             script_type=ScriptType.P2PKH, flags=KeyInstanceFlag.IS_ACTIVE, description=""),
#         KeyInstanceRow(keyinstance_id=3, account_id=1, masterkey_id=1,
#             derivation_type=DerivationType.BIP32, derivation_data=json.dumps({"subpath": [0, 1]}),
#             script_type=ScriptType.P2PKH, flags=KeyInstanceFlag.USER_SET_ACTIVE, description=""),
#     ]

#     with SynchronousWriter() as writer:
#         masterkey_table.create([(1, None, 2, b'1234')],
#             completion_callback=writer.get_callback())
#         assert writer.succeeded()

    # account_row = AccountRow(1, 1, ScriptType.P2PKH, 'name')
    # future = db_functions.create_accounts(db_context, [ account_row ])
    # future.result()

#     with SynchronousWriter() as writer:
#         tx_table.create(tx_entries, completion_callback=writer.get_callback())
#         assert writer.succeeded()

#     with SynchronousWriter() as writer:
#         keyinstance_table.create(keyinstance_entries, completion_callback=writer.get_callback())
#         assert writer.succeeded()

#     with SynchronousWriter() as writer:
#         transaction_deltas_table.create(tx_delta_entries, completion_callback=writer.get_callback())
#         assert writer.succeeded()

#     q = transaction_deltas_table.read()
#     assert len(q) == 6

#     q = tx_table.read()
#     assert len(q) == 6

#     q = keyinstance_table.read()
#     assert len(q) == 3

#     with SynchronousWriter() as writer:
#         used_keys = transaction_deltas_table.update_used_keys(1,
#             completion_callback=writer.get_callback())
#         assert writer.succeeded()

#     assert len(used_keys) == 1
#     assert used_keys == [1]  # 2 x settled txs and zero balance for key

#     rows = keyinstance_table.read(key_ids=[1])
#     assert len(rows) == 1
#     assert rows[0].flags & KeyInstanceFlag.IS_ACTIVE == 0

#     masterkey_table.close()
#     accounts_table.close()
#     transaction_deltas_table.close()
#     keyinstance_table.close()
#     tx_table.close()



def test_table_invoice_crud(db_context: DatabaseContext) -> None:
    db_lines = db_functions.read_invoices_for_account(db_context, 1)
    assert len(db_lines) == 0

    TX_BYTES_1 = os.urandom(10)
    TX_HASH_1 = bitcoinx.double_sha256(TX_BYTES_1)
    TX_INDEX = 1
    TXOUT_FLAGS = 1 << 15
    KEYINSTANCE_ID = 1
    ACCOUNT_ID_1 = 10
    ACCOUNT_ID_2 = 20
    MASTERKEY_ID = 20
    DERIVATION_DATA = b'111'

    TX_BYTES_2 = os.urandom(10)
    TX_HASH_2 = bitcoinx.double_sha256(TX_BYTES_2)

    TX_BYTES_3 = os.urandom(10)
    TX_HASH_3 = bitcoinx.double_sha256(TX_BYTES_3)

    # LINE_COUNT = 3
    line1_1 = InvoiceRow(1, ACCOUNT_ID_1, None, "payment_uri1", "desc", PaymentFlag.UNPAID,
        1, b'{}', None, 111)
    line2_1 = InvoiceRow(2, ACCOUNT_ID_1, TX_HASH_1, "payment_uri2", "desc", PaymentFlag.PAID,
        2, b'{}', 10, 111)
    line3_2 = InvoiceRow(3, ACCOUNT_ID_2, None, "payment_uri3", "desc", PaymentFlag.UNPAID,
        3, b'{}', None, 111)

    # No effect: The transactionoutput foreign key constraint will fail as the account
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_invoices(db_context, [ line1_1 ])
        future.result()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context, [ (MASTERKEY_ID, None, 2, b'111') ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row1 = AccountRow(ACCOUNT_ID_1, MASTERKEY_ID, ScriptType.P2PKH, 'name1')
    account_row2 = AccountRow(ACCOUNT_ID_2, MASTERKEY_ID, ScriptType.P2PKH, 'name2')
    future = db_functions.create_accounts(db_context, [ account_row1, account_row2 ])
    future.result()

    txs = []
    for txh, txb in ((TX_HASH_1, TX_BYTES_1), (TX_HASH_2, TX_BYTES_2), (TX_HASH_3, TX_BYTES_3)):
        tx = TransactionRow(tx_hash=txh, tx_bytes=txb, flags=TxFlags.STATE_SETTLED,
            block_height=1, block_hash=b'11', block_position=1, fee_value=250,
            description=None, version=None, locktime=None, date_created=1, date_updated=2)
        txs.append(tx)
    future = db_functions.create_transactions(db_context, txs)
    future.result(timeout=5)

    future = db_functions.create_invoices(db_context, [ line1_1, line2_1, line3_2 ])
    future.result()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_invoices(db_context, [ line1_1 ])
        future.result()

    def compare_row_to_account_row(src: InvoiceRow, dst: InvoiceAccountRow) -> None:
        assert src.description == dst.description
        assert src.flags == dst.flags
        assert src.value == dst.value
        assert src.date_expires == dst.date_expires
        assert src.date_created == dst.date_created

    # Read all rows in the table for account 1.
    db_lines = db_functions.read_invoices_for_account(db_context, ACCOUNT_ID_1)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line.invoice_id == line1_1.invoice_id ][0]
    compare_row_to_account_row(line1_1, db_line1)
    db_line2 = [ db_line for db_line in db_lines if db_line.invoice_id == line2_1.invoice_id ][0]
    compare_row_to_account_row(line2_1, db_line2)

    # Read all rows in the table for account 2.
    db_lines = db_functions.read_invoices_for_account(db_context, ACCOUNT_ID_2)
    assert 1 == len(db_lines)
    db_line3 = [ db_line for db_line in db_lines if db_line.invoice_id == line3_2.invoice_id ][0]
    compare_row_to_account_row(line3_2, db_line3)

    # Read all PAID rows in the table for the first account.
    db_lines = db_functions.read_invoices_for_account(db_context, ACCOUNT_ID_1,
        mask=PaymentFlag.PAID)
    assert 1 == len(db_lines)
    assert 2 == db_lines[0].invoice_id

    # Read all UNPAID rows in the table for the first account.
    db_lines = db_functions.read_invoices_for_account(db_context, ACCOUNT_ID_1,
        mask=PaymentFlag.UNPAID)
    assert 1 == len(db_lines)
    assert 1 == db_lines[0].invoice_id

    # Require ARCHIVED flag.
    db_lines = db_functions.read_invoices_for_account(db_context, ACCOUNT_ID_1,
        mask=PaymentFlag.ARCHIVED)
    assert 0 == len(db_lines)

    # Require no ARCHIVED flag.
    db_lines = db_functions.read_invoices_for_account(db_context, ACCOUNT_ID_1,
        flags=PaymentFlag.NONE, mask=PaymentFlag.ARCHIVED)
    assert 2 == len(db_lines)

    # Non-existent account.
    db_lines = db_functions.read_invoices_for_account(db_context, 1010101)
    assert 0 == len(db_lines)

    row = db_functions.read_invoice(db_context, invoice_id=line1_1.invoice_id)
    assert row is not None
    assert 1 == row.invoice_id

    row = db_functions.read_invoice(db_context, invoice_id=100101)
    assert row is None

    row = db_functions.read_invoice(db_context, tx_hash=TX_HASH_1)
    assert row is not None
    assert 2 == row.invoice_id

    future = db_functions.update_invoice_transactions(db_context,
        [ (TX_HASH_3, line3_2.invoice_id) ])
    future.result()

    # Verify the invoice is now marked with no associated tx.
    row = db_functions.read_invoice(db_context, invoice_id=line3_2.invoice_id)
    assert row is not None
    assert row.tx_hash == TX_HASH_3

    future = db_functions.update_invoice_transactions(db_context, [ (None, line3_2.invoice_id) ])
    future.result()

    # Verify the invoice is now marked with no associated tx.
    row = db_functions.read_invoice(db_context, invoice_id=line3_2.invoice_id)
    assert row.tx_hash is None

    future = db_functions.update_invoice_descriptions(db_context,
        [ ("newdesc3.2", line3_2.invoice_id) ])
    future.result()

    # Verify the invoice now has the new description.
    row = db_functions.read_invoice(db_context, invoice_id=line3_2.invoice_id)
    assert row.description == "newdesc3.2"

    future = db_functions.update_invoice_flags(db_context,
        [ (~PaymentFlag.ARCHIVED, PaymentFlag.ARCHIVED, line3_2.invoice_id), ])
    future.result()

    # Verify the invoice now has the new description.
    row = db_functions.read_invoice(db_context, invoice_id=line3_2.invoice_id)
    assert row.flags == PaymentFlag.ARCHIVED | PaymentFlag.UNPAID

    duplicate_row1 = db_functions.read_invoice_duplicate(db_context, 111, "ddd")
    assert duplicate_row1 is None
    duplicate_row2 = db_functions.read_invoice_duplicate(db_context, row.value, row.payment_uri)
    assert duplicate_row2 == row

    future = db_functions.delete_invoices(db_context, [ (line2_1.invoice_id,) ])
    future.result()

    db_lines = db_functions.read_invoices_for_account(db_context, ACCOUNT_ID_1)
    assert 1 == len(db_lines)
    assert db_lines[0].invoice_id == line1_1.invoice_id
