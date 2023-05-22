import json
import time
import bitcoinx
import os
import pytest
try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.9.13 builds and version of 3.37.2.
    import sqlite3 # type: ignore
import tempfile
from typing import List

from electrumsv.constants import (TxFlags, ScriptType, DerivationType, TransactionOutputFlag,
    PaymentFlag, KeyInstanceFlag, WalletEventFlag, WalletEventType)
from electrumsv.logs import logs
from electrumsv.types import TxoKeyType
from electrumsv.wallet_database import (migration, KeyInstanceTable, MasterKeyTable,
    PaymentRequestTable, TransactionTable, DatabaseContext, TransactionDeltaTable,
    TransactionOutputTable, SynchronousWriter, TxData, TxProof, AccountTable)
from electrumsv.wallet_database.sqlite_support import LeakedSQLiteConnectionError
from electrumsv.wallet_database.tables import (AccountRow, InvoiceAccountRow, InvoiceRow,
    InvoiceTable, KeyInstanceRow, MAGIC_UNTOUCHED_BYTEDATA, MasterKeyRow, PaymentRequestRow,
    TransactionDeltaRow, TransactionDeltaKeySummaryRow, TransactionRow, TransactionOutputRow,
    WalletEventTable, WalletEventRow)


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


@pytest.mark.timeout(8)
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


@pytest.mark.timeout(8)
def test_table_masterkeys_crud(db_context: DatabaseContext) -> None:
    table = MasterKeyTable(db_context)
    assert [] == table.read()

    table._get_current_timestamp = lambda: 10

    line1 = MasterKeyRow(1, None, 2, b'111')
    line2 = MasterKeyRow(2, None, 4, b'222')

    with SynchronousWriter() as writer:
        table.create([ line1 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        table.create([ line2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    lines = table.read()
    assert 2 == len(lines)

    line1_db = [ line for line in lines if line[0] == 1 ][0]
    assert line1 == line1_db

    line2_db = [ line for line in lines if line[0] == 2 ][0]
    assert line2 == line2_db

    date_updated = 20

    with SynchronousWriter() as writer:
        table.update_derivation_data([ (b'234', 1) ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        table.delete([ 2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    lines = table.read()
    assert 1 == len(lines)
    assert lines[0].masterkey_id == 1
    assert lines[0].derivation_data == b'234'

    table.close()


@pytest.mark.timeout(8)
def test_table_accounts_crud(db_context: DatabaseContext) -> None:
    table = AccountTable(db_context)
    assert [] == table.read()

    table._get_current_timestamp = lambda: 10

    ACCOUNT_ID = 10
    MASTERKEY_ID = 20

    line1 = AccountRow(ACCOUNT_ID+1, MASTERKEY_ID+1, ScriptType.P2PKH, 'name1')
    line2 = AccountRow(ACCOUNT_ID+2, MASTERKEY_ID+1, ScriptType.P2PK, 'name2')

    # No effect: The masterkey foreign key constraint will fail as the masterkey does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    with MasterKeyTable(db_context) as mktable:
        with SynchronousWriter() as writer:
            mktable.create([ MasterKeyRow(MASTERKEY_ID+1, None, 2, b'111') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Create the first row.
    with SynchronousWriter() as writer:
        table.create([ line1 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # Create the second row.
    with SynchronousWriter() as writer:
        table.create([ line2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0] == line1[0] ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line[0] == line2[0] ][0]
    assert line2 == db_line2

    date_updated = 20

    with SynchronousWriter() as writer:
        table.update_masterkey([ (MASTERKEY_ID+1, ScriptType.MULTISIG_BARE, line1[0]) ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        table.update_name([ (line2[0], 'new_name') ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0] == line1[0] ][0]
    assert ScriptType.MULTISIG_BARE == db_line1[2]
    db_line2 = [ db_line for db_line in db_lines if db_line[0] == line2[0] ][0]
    assert 'new_name' == db_line2[3]

    with SynchronousWriter() as writer:
        table.delete([ line2[0] ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 1 == len(db_lines)
    assert db_lines[0][0] == line1[0]

    table.close()


@pytest.mark.timeout(8)
def test_account_transactions(db_context: DatabaseContext) -> None:
    ACCOUNT_ID_1 = 10
    ACCOUNT_ID_2 = 11
    MASTERKEY_ID_1 = 20
    MASTERKEY_ID_2 = 21

    # Create master keys.
    masterkey1 = MasterKeyRow(MASTERKEY_ID_1, None, DerivationType.BIP32, b'111')
    masterkey2 = MasterKeyRow(MASTERKEY_ID_2, None, DerivationType.BIP32, b'222')

    with MasterKeyTable(db_context) as mktable:
        with SynchronousWriter() as writer:
            mktable.create([ masterkey1, masterkey2 ], completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Create the accounts.
    account1 = AccountRow(ACCOUNT_ID_1, MASTERKEY_ID_1, ScriptType.P2PKH, 'name1')
    account2 = AccountRow(ACCOUNT_ID_2, MASTERKEY_ID_2, ScriptType.P2PK, 'name2')

    with AccountTable(db_context) as table:
        with SynchronousWriter() as writer:
            table.create([ account1, account2 ], completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Create the key instances.
    KEYINSTANCE_ID_1 = 100
    KEYINSTANCE_ID_2 = 101

    key1 = KeyInstanceRow(KEYINSTANCE_ID_1, ACCOUNT_ID_1, MASTERKEY_ID_1, DerivationType.BIP32,
        b'333', ScriptType.P2PKH, KeyInstanceFlag.NONE, None)
    key2 = KeyInstanceRow(KEYINSTANCE_ID_2, ACCOUNT_ID_2, MASTERKEY_ID_2, DerivationType.BIP32,
        b'444', ScriptType.P2PKH, KeyInstanceFlag.NONE, None)

    with KeyInstanceTable(db_context) as keyinstance_table:
        with SynchronousWriter() as writer:
            keyinstance_table.create([ key1, key2 ], completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Create the transaction.
    TX_BYTES_1 = os.urandom(10)
    TX_HASH_1 = bitcoinx.double_sha256(TX_BYTES_1)
    tx1 = TransactionRow(
        tx_hash=TX_HASH_1, tx_data=TxData(height=1, position=1, fee=250, date_added=1,
        date_updated=2), tx_bytes=TX_BYTES_1,
        flags=TxFlags(TxFlags.StateSettled | TxFlags.HasByteData | TxFlags.HasHeight),
        description=None)
    TX_BYTES_2 = os.urandom(10)
    TX_HASH_2 = bitcoinx.double_sha256(TX_BYTES_2)
    tx2 = TransactionRow(
        tx_hash=TX_HASH_2, tx_data=TxData(height=1, position=1, fee=250, date_added=1,
        date_updated=2), tx_bytes=TX_BYTES_2,
        flags=TxFlags(TxFlags.StateSettled | TxFlags.HasByteData | TxFlags.HasHeight),
        description=None)
    with TransactionTable(db_context) as transaction_table:
        with SynchronousWriter() as writer:
            transaction_table.create([ tx1, tx2 ], completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Create the transaction deltas.
    txd1 = TransactionDeltaRow(TX_HASH_1, KEYINSTANCE_ID_1, 100)
    txd2 = TransactionDeltaRow(TX_HASH_2, KEYINSTANCE_ID_2, 200)
    with TransactionDeltaTable(db_context) as table:
        with SynchronousWriter() as writer:
            table.create([ txd1, txd2 ], completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Now finally, test the account linkages.
    with TransactionTable(db_context) as table:
        ## Test `TransactionTable.read_metadata`.
        # Both tx should be matched.
        metadatas = table.read_metadata()
        print(metadatas)
        assert 2 == len(metadatas)
        assert { TX_HASH_1, TX_HASH_2 } == { t[0] for t in metadatas }

        # Only tx1 which is linked to account1 should be matched.
        metadatas_1 = table.read_metadata(account_id=ACCOUNT_ID_1)
        assert 1 == len(metadatas_1)
        assert TX_HASH_1 == metadatas_1[0][0]

        # Only tx2 which is linked to account2 should be matched.
        metadatas_2 = table.read_metadata(account_id=ACCOUNT_ID_2)
        assert 1 == len(metadatas_2)
        assert TX_HASH_2 == metadatas_2[0][0]

        # No tx are linked to this non-existent account.
        metadatas_3 = table.read_metadata(account_id=-1)
        assert 0 == len(metadatas_3)

        ## Test `TransactionTable.read`.
        # Both tx should be matched.
        matches = table.read()
        assert 2 == len(matches)
        assert { TX_HASH_1, TX_HASH_2 } == { t[0] for t in matches }

        # Only tx1 which is linked to account1 should be matched.
        matches_1 = table.read(account_id=ACCOUNT_ID_1)
        assert 1 == len(matches_1)
        assert TX_HASH_1 == matches_1[0][0]

        # Only tx2 which is linked to account2 should be matched.
        matches_2 = table.read(account_id=ACCOUNT_ID_2)
        assert 1 == len(matches_2)
        assert TX_HASH_2 == matches_2[0][0]

        # No tx are linked to this non-existent account.
        matches_3 = table.read(account_id=-1)
        assert 0 == len(matches_3)


@pytest.mark.timeout(8)
def test_table_keyinstances_crud(db_context: DatabaseContext) -> None:
    table = KeyInstanceTable(db_context)
    assert [] == table.read()

    table._get_current_timestamp = lambda: 10

    KEYINSTANCE_ID = 0
    ACCOUNT_ID = 10
    MASTERKEY_ID = 20
    DERIVATION_DATA1 = b'111'
    DERIVATION_DATA2 = b'222'

    line1 = KeyInstanceRow(KEYINSTANCE_ID+1, ACCOUNT_ID+1, MASTERKEY_ID+1, DerivationType.BIP32,
        DERIVATION_DATA1, ScriptType.P2PKH, True, None)
    line2 = KeyInstanceRow(KEYINSTANCE_ID+2, ACCOUNT_ID+1, MASTERKEY_ID+1, DerivationType.HARDWARE,
        DERIVATION_DATA2, ScriptType.P2PKH, True, None)

    # No effect: The masterkey foreign key constraint will fail as the masterkey does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    with MasterKeyTable(db_context) as mktable:
        with SynchronousWriter() as writer:
            mktable.create([ MasterKeyRow(MASTERKEY_ID+1, None, 2, b'111') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # No effect: The account foreign key constraint will fail as the account does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Satisfy the account foreign key constraint by creating the account.
    with AccountTable(db_context) as acctable:
        with SynchronousWriter() as writer:
            acctable.create([ AccountRow(ACCOUNT_ID+1, MASTERKEY_ID+1, ScriptType.P2PKH, 'name') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Create the first row.
    with SynchronousWriter() as writer:
        table.create([ line1 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # Create the second row.
    with SynchronousWriter() as writer:
        table.create([ line2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0] == line1[0] ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line[0] == line2[0] ][0]
    assert line2 == db_line2

    date_updated = 20

    with SynchronousWriter() as writer:
        table.update_derivation_data([ (b'234', line1[0]) ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        table.update_flags([ (False, line2[0]) ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0] == line1[0] ][0]
    assert b'234' == db_line1[4]
    db_line2 = [ db_line for db_line in db_lines if db_line[0] == line2[0] ][0]
    assert not db_line2[6]

    # Selective reading of only one record based on it's id.
    db_lines = table.read(key_ids=[KEYINSTANCE_ID+1])
    assert 1 == len(db_lines)
    assert KEYINSTANCE_ID+1 == db_lines[0].keyinstance_id

    with SynchronousWriter() as writer:
        table.delete([ line2[0] ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 1 == len(db_lines)
    assert db_lines[0].keyinstance_id == line1.keyinstance_id
    assert db_lines[0].description is None
    assert db_lines[0].derivation_data == b'234'

    # Now try out the labels.
    with SynchronousWriter() as writer:
        table.update_descriptions([ ("line1", line1.keyinstance_id) ],
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    rows = table.read()
    assert len(rows) == 1
    assert rows[0].keyinstance_id == line1[0]
    assert rows[0].description == "line1"

    table.close()


class TestTransactionTable:
    @classmethod
    def setup_class(cls):
        cls.db_context = _db_context()
        cls.store = TransactionTable(cls.db_context)

        cls.tx_hash = os.urandom(32)

    @classmethod
    def teardown_class(cls):
        cls.store.close()
        cls.db_context.close()

    def setup_method(self):
        db = self.store._db
        db.execute(f"DELETE FROM Transactions")
        db.commit()

    def _get_store_hashes(self) -> List[bytes]:
        return [ row[0] for row in self.store.read_metadata() ]

    def test_proof_serialization(self):
        proof1 = TxProof(position=10, branch=[ os.urandom(32) for i in range(10) ])
        raw = self.store._pack_proof(proof1)
        proof2 = self.store._unpack_proof(raw)
        assert proof1.position == proof2.position
        assert proof1.branch == proof2.branch

    @pytest.mark.timeout(8)
    def test_create1(self):
        bytedata_1 = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(bytedata_1)
        metadata_1 = TxData(height=None, fee=None, position=None, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            self.store.create([ (tx_hash, metadata_1, bytedata_1, TxFlags.StateDispatched, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Check the state is correct, all states should be the same code path.
        _tx_hash, flags, _metadata = self.store.read_metadata(tx_hashes=[tx_hash])[0]
        assert TxFlags.StateDispatched == flags & TxFlags.STATE_MASK

        _tx_hash, bytedata_2, _flags, metadata_2 = self.store.read(tx_hashes=[tx_hash])[0]
        assert metadata_1 == metadata_2
        assert bytedata_1 == bytedata_2

    @pytest.mark.timeout(8)
    def test_create2(self) -> None:
        to_add = []
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash = bitcoinx.double_sha256(tx_bytes)
            tx_data = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
            to_add.append((tx_hash, tx_data, tx_bytes, TxFlags.Unset, None))
        with SynchronousWriter() as writer:
            self.store.create(to_add, completion_callback=writer.get_callback())
            assert writer.succeeded()

        existing_tx_hashes = set(self._get_store_hashes())
        added_tx_hashes = set(t[0] for t in to_add)
        assert added_tx_hashes == existing_tx_hashes

    @pytest.mark.timeout(8)
    def test_update(self):
        to_add = []
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash = bitcoinx.double_sha256(tx_bytes)
            tx_data = TxData(height=None, fee=2, position=None, date_added=1, date_updated=1)
            if i % 2:
                to_add.append((tx_hash, tx_data, tx_bytes, TxFlags.HasByteData, None))
            else:
                to_add.append((tx_hash, tx_data, None, TxFlags.Unset, None))
        with SynchronousWriter() as writer:
            self.store.create(to_add, completion_callback=writer.get_callback())
            assert writer.succeeded()

        to_update = []
        for tx_hash, metadata, tx_bytes, flags, description in to_add:
            tx_metadata = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
            to_update.append((tx_hash, tx_metadata, tx_bytes, flags))
        with SynchronousWriter() as writer:
            self.store.update(to_update, completion_callback=writer.get_callback())
            assert writer.succeeded()

        for get_tx_hash, bytedata_get, flags_get, metadata_get in self.store.read():
            for update_tx_hash, update_metadata, update_tx_bytes, update_flags in to_update:
                if update_tx_hash == get_tx_hash:
                    assert metadata_get == update_metadata
                    assert bytedata_get == update_tx_bytes
                    continue

    @pytest.mark.timeout(8)
    def test_update__entry_with_set_bytedata_flag(self):
        tx_bytes = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(tx_bytes)
        tx_data = TxData(height=None, fee=2, position=None, date_added=1, date_updated=1)
        row = (tx_hash, tx_data, tx_bytes, TxFlags.HasByteData, None)
        with SynchronousWriter() as writer:
            self.store.create([ row ], completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Ensure that a set bytedata flag requires bytedata to be included.
        with pytest.raises(AssertionError):
            self.store.update([(tx_hash, tx_data, None, TxFlags.HasByteData)])

    @pytest.mark.timeout(8)
    def test_update__entry_with_unset_bytedata_flag(self):
        tx_bytes = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(tx_bytes)
        tx_data = TxData(height=None, fee=2, position=None, date_added=1, date_updated=1)
        row = (tx_hash, tx_data, tx_bytes, TxFlags.HasByteData, None)
        with SynchronousWriter() as writer:
            self.store.create([ row ], completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Ensure that a unset bytedata flag requires bytedata to not be included.
        with pytest.raises(AssertionError):
            self.store.update([(tx_hash, tx_data, tx_bytes, TxFlags.Unset)])

    @pytest.mark.timeout(8)
    def test_update__entry_with_magic_bytedata_and_set_flag(self):
        tx_bytes = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(tx_bytes)
        tx_data = TxData(height=None, fee=2, position=None, date_added=1, date_updated=1)
        row = (tx_hash, tx_data, tx_bytes, TxFlags.HasByteData, None)
        with SynchronousWriter() as writer:
            self.store.create([ row ], completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Ensure that the magic bytedata requires a set bytedata flag.
        with pytest.raises(AssertionError):
            self.store.update([(tx_hash, tx_data, MAGIC_UNTOUCHED_BYTEDATA, TxFlags.Unset)])

    @pytest.mark.timeout(8)
    def test_update__with_valid_magic_bytedata(self):
        tx_bytes = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(tx_bytes)
        tx_data = TxData(height=None, fee=2, position=None, date_added=1, date_updated=1)
        row = (tx_hash, tx_data, tx_bytes, TxFlags.HasByteData, None)
        with SynchronousWriter() as writer:
            self.store.create([ row ], completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Ensure that
        with SynchronousWriter() as writer:
            self.store.update([(tx_hash, tx_data, MAGIC_UNTOUCHED_BYTEDATA, TxFlags.HasByteData)],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        rows = self.store.read()
        assert 1 == len(rows)
        get_tx_hash, bytedata_get, flags_get, metadata_get = rows[0]
        assert tx_bytes == bytedata_get
        assert flags_get & TxFlags.HasByteData != 0

    @pytest.mark.timeout(8)
    def test_update_flags(self):
        bytedata = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(bytedata)
        metadata = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            self.store.create([ (tx_hash, metadata, bytedata, TxFlags.Unset, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Verify the field flags are assigned correctly on the add.
        expected_flags = TxFlags.HasByteData | TxFlags.HasFee | TxFlags.HasHeight
        _tx_hash, flags, _metadata = self.store.read_metadata(tx_hashes=[tx_hash])[0]
        assert expected_flags == flags, f"expected {expected_flags!r}, got {TxFlags.to_repr(flags)}"

        flags = TxFlags.StateReceived
        mask = TxFlags.METADATA_FIELD_MASK | TxFlags.HasByteData | TxFlags.HasProofData
        date_updated = 1
        with SynchronousWriter() as writer:
            self.store.update_flags([ (tx_hash, flags, mask, date_updated) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Verify the state flag is correctly added via the mask.
        _tx_hash, flags_get, _metadata = self.store.read_metadata(tx_hashes=[tx_hash])[0]
        expected_flags |= TxFlags.StateReceived
        assert expected_flags == flags_get, \
            f"{TxFlags.to_repr(expected_flags)} != {TxFlags.to_repr(flags_get)}"

        flags = TxFlags.StateReceived
        mask = TxFlags.Unset
        date_updated = 1
        with SynchronousWriter() as writer:
            self.store.update_flags([ (tx_hash, flags, mask, date_updated) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Verify the state flag is correctly set via the mask.
        _tx_hash, flags, _metadata = self.store.read_metadata(tx_hashes=[tx_hash])[0]
        assert TxFlags.StateReceived == flags

    @pytest.mark.timeout(8)
    def test_delete(self) -> None:
        to_add = []
        for i in range(10):
            bytedata = os.urandom(10)
            tx_hash = bitcoinx.double_sha256(bytedata)
            metadata = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
            to_add.append((tx_hash, metadata, bytedata, TxFlags.Unset, None))
        with SynchronousWriter() as writer:
            self.store.create(to_add, completion_callback=writer.get_callback())
            assert writer.succeeded()

        add_hashes = set(t[0] for t in to_add)
        get_hashes = set(self._get_store_hashes())
        assert add_hashes == get_hashes
        with SynchronousWriter() as writer:
            self.store.delete(add_hashes, completion_callback=writer.get_callback())
            assert writer.succeeded()

        get_hashes = self._get_store_hashes()
        assert 0 == len(get_hashes)

    @pytest.mark.timeout(8)
    def test_get_all_pending(self):
        get_tx_hashes = set([])
        for tx_hex in (tx_hex_1, tx_hex_2):
            bytedata = bytes.fromhex(tx_hex)
            tx_hash = bitcoinx.double_sha256(bytedata)
            metadata = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
            with SynchronousWriter() as writer:
                self.store.create([ (tx_hash, metadata, bytedata, TxFlags.Unset, None) ],
                    completion_callback=writer.get_callback())
                assert writer.succeeded()
            get_tx_hashes.add(tx_hash)

        result_tx_hashes = set(self._get_store_hashes())
        assert get_tx_hashes == result_tx_hashes

    @pytest.mark.timeout(8)
    def test_read(self):
        to_add = []
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash = bitcoinx.double_sha256(tx_bytes)
            tx_data = TxData(height=None, fee=2, position=None, date_added=1, date_updated=1)
            to_add.append((tx_hash, tx_data, tx_bytes, TxFlags.HasFee, None))
        with SynchronousWriter() as writer:
            self.store.create(to_add, completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Test the first "add" hash is matched.
        tx_hash_1 = to_add[0][0]
        matches = self.store.read(tx_hashes=[tx_hash_1])
        assert tx_hash_1 == matches[0][0]
        assert self.store.read(TxFlags.HasByteData, TxFlags.HasByteData, [tx_hash_1])

        # Test no id is matched.
        matches = self.store.read(tx_hashes=[b"aaaa"])
        assert 0 == len(matches)

        # Test flag and mask combinations.
        matches = self.store.read(flags=TxFlags.HasFee)
        assert 10 == len(matches)

        matches = self.store.read(flags=TxFlags.Unset, mask=TxFlags.HasHeight)
        assert 10 == len(matches)

        matches = self.store.read(flags=TxFlags.HasFee, mask=TxFlags.HasFee)
        assert 10 == len(matches)

        matches = self.store.read(flags=TxFlags.Unset, mask=TxFlags.HasFee)
        assert 0 == len(matches)

    @pytest.mark.timeout(8)
    def test_read_metadata(self) -> None:
        # We're going to add five matches and look for two of them, checking that we do not match
        # unwanted rows.
        all_tx_hashes = []
        datas = []
        for i in range(5):
            bytedata = os.urandom(10)
            tx_hash = bitcoinx.double_sha256(bytedata)
            metadata = TxData(height=i*100, fee=i*1000, position=None, date_added=1, date_updated=1)
            datas.append((tx_hash, metadata, bytedata, TxFlags.Unset, None))
            all_tx_hashes.append(tx_hash)
        with SynchronousWriter() as writer:
            self.store.create(datas, completion_callback=writer.get_callback())
            assert writer.succeeded()

        # We also ask for a dud tx_hash that won't get matched.
        select_tx_hashes = [ all_tx_hashes[0], all_tx_hashes[3], b"12121212" ]
        rowdatas = self.store.read_metadata(tx_hashes=select_tx_hashes)
        # Check that the two valid matches are there and their values match the projected values.
        assert len(rowdatas) == 2
        for rowdata in rowdatas:
            tx_hash = rowdata[0]
            tx_flags = rowdata[1]
            metadata = rowdata[2]
            rowidx = all_tx_hashes.index(tx_hash)
            assert metadata.height == rowidx * 100
            assert metadata.fee == rowidx * 1000
            assert metadata.position is None

    @pytest.mark.timeout(8)
    def test_update_metadata(self) -> None:
        # We're going to add five matches and look for two of them, checking that we do not match
        # unwanted rows.
        tx_hashes = []
        datas = []
        for i in range(5):
            bytedata = os.urandom(10)
            tx_hash = bitcoinx.double_sha256(bytedata)
            metadata = TxData(height=i*100, fee=i*1000, position=None, date_added=1, date_updated=1)
            datas.append((tx_hash, metadata, bytedata, TxFlags.Unset, None))
            tx_hashes.append(tx_hash)
        with SynchronousWriter() as writer:
            self.store.create(datas, completion_callback=writer.get_callback())
            assert writer.succeeded()

        updates = []
        for i in range(5):
            tx_hash = tx_hashes[i]
            metadata = TxData(height=i*200, fee=i*2000, position=None, date_added=1, date_updated=1)
            updates.append((tx_hash, metadata, TxFlags.HasHeight | TxFlags.HasFee))
        with SynchronousWriter() as writer:
            self.store.update_metadata(updates, completion_callback=writer.get_callback())
            assert writer.succeeded()

        # We also ask for a dud tx_hash that won't get matched.
        select_tx_hashes = [ tx_hashes[0], tx_hashes[3], b"12121212" ]
        rowdatas = self.store.read_metadata(tx_hashes=select_tx_hashes)
        # Check that the two valid matches are there and their values match the projected values.
        assert len(rowdatas) == 2
        for rowdata in rowdatas:
            tx_hash = rowdata[0]
            tx_flags = rowdata[1]
            metadata = rowdata[2]
            rowidx = tx_hashes.index(tx_hash)
            assert metadata.height == rowidx * 200
            assert metadata.fee == rowidx * 2000
            assert metadata.position is None

    @pytest.mark.timeout(8)
    def test_proof(self):
        bytedata = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(bytedata)
        metadata = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)
        with SynchronousWriter() as writer:
            self.store.create([ (tx_hash, metadata, bytedata, 0, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        position1 = 10
        merkle_branch1 = [ os.urandom(32) for i in range(10) ]
        proof = TxProof(position1, merkle_branch1)
        date_updated = 1
        with SynchronousWriter() as writer:
            self.store.update_proof([ (tx_hash, proof, date_updated) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        rows = self.store.read_proof([ self.tx_hash ])
        assert len(rows) == 0

        db_tx_hash, (tx_position2, merkle_branch2) = self.store.read_proof([ tx_hash ])[0]
        assert db_tx_hash == tx_hash
        assert position1 == tx_position2
        assert merkle_branch1 == merkle_branch2

    @pytest.mark.timeout(8)
    def test_labels(self):
        bytedata_1 = os.urandom(10)
        tx_hash_1 = bitcoinx.double_sha256(bytedata_1)
        metadata_1 = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)

        bytedata_2 = os.urandom(10)
        tx_hash_2 = bitcoinx.double_sha256(bytedata_2)
        metadata_2 = TxData(height=1, fee=2, position=None, date_added=1, date_updated=1)

        with SynchronousWriter() as writer:
            self.store.create([ (tx_hash_1, metadata_1, bytedata_1, 0, None),
                    (tx_hash_2, metadata_2, bytedata_2, 0, None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        with SynchronousWriter() as writer:
            self.store.update_descriptions([ ("tx 1", tx_hash_1) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        rows = self.store.read_descriptions()
        assert len(rows) == 1
        assert len([r[1] == "tx 1" for r in rows if r[0] == tx_hash_1]) == 1

        with SynchronousWriter() as writer:
            self.store.update_descriptions([ (None, tx_hash_1), ("tx 2", tx_hash_2) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        rows = self.store.read_descriptions([ tx_hash_2 ])
        assert len(rows) == 1
        assert rows[0][0] == tx_hash_2 and rows[0][1] == "tx 2"

        # Reading entries for a non-existent ...
        rows = self.store.read_descriptions([ self.tx_hash ])
        assert len(rows) == 0


@pytest.mark.timeout(8)
def test_table_transactionoutputs_crud(db_context: DatabaseContext) -> None:
    table = TransactionOutputTable(db_context)
    assert [] == table.read()

    table._get_current_timestamp = lambda: 10

    TX_BYTES = os.urandom(10)
    TX_HASH = bitcoinx.double_sha256(TX_BYTES)
    TX_INDEX = 1
    TXOUT_FLAGS = 1 << 15
    KEYINSTANCE_ID_1 = 1
    KEYINSTANCE_ID_2 = 2
    ACCOUNT_ID = 10
    MASTERKEY_ID = 20
    DERIVATION_DATA1 = b'111'
    DERIVATION_DATA2 = b'222'

    line1 = TransactionOutputRow(TX_HASH, TX_INDEX, 100, KEYINSTANCE_ID_1, TXOUT_FLAGS)
    line2 = TransactionOutputRow(TX_HASH, TX_INDEX+1, 200, KEYINSTANCE_ID_2, TXOUT_FLAGS)

    # No effect: The transactionoutput foreign key constraint will fail as the transactionoutput
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Satisfy the transaction foreign key constraint by creating the transaction.
    with TransactionTable(db_context) as transaction_table:
        with SynchronousWriter() as writer:
            transaction_table.create([ (TX_HASH, TxData(height=1, fee=2, position=None,
                    date_added=1, date_updated=1), TX_BYTES,
                    TxFlags.HasByteData|TxFlags.HasFee|TxFlags.HasHeight,
                    None) ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    with MasterKeyTable(db_context) as masterkey_table:
        with SynchronousWriter() as writer:
            masterkey_table.create([ (MASTERKEY_ID, None, 2, b'111') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the account foreign key constraint by creating the account.
    with AccountTable(db_context) as account_table:
        with SynchronousWriter() as writer:
            account_table.create([ (ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the keyinstance foreign key constraint by creating the keyinstance.
    with KeyInstanceTable(db_context) as keyinstance_table:
        with SynchronousWriter() as writer:
            keyinstance_table.create([
                (KEYINSTANCE_ID_1, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32, DERIVATION_DATA1,
                    ScriptType.P2PKH, True, None),
                (KEYINSTANCE_ID_2, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32, DERIVATION_DATA2,
                    ScriptType.P2PKH, True, None),
                ], completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Create the first row.
    with SynchronousWriter() as writer:
        table.create([ line1 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # Create the second row.
    with SynchronousWriter() as writer:
        table.create([ line2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line == line1 ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line == line2 ][0]
    assert line2 == db_line2

    date_updated = 20

    with SynchronousWriter() as writer:
        table.update_flags([ (TransactionOutputFlag.IS_SPENT, line2.tx_hash, line2.tx_index)],
            date_updated, completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line[0:2] == line1[0:2] ][0]
    db_line2 = [ db_line for db_line in db_lines if db_line[0:2] == line2[0:2] ][0]
    assert db_line2.flags == TransactionOutputFlag.IS_SPENT

    # Read based on mask variations.
    db_lines = table.read(mask=~TransactionOutputFlag.IS_SPENT)
    assert 1 == len(db_lines)
    assert db_lines[0].flags & TransactionOutputFlag.IS_SPENT == 0

    db_lines = table.read(mask=TransactionOutputFlag.IS_SPENT)
    assert 1 == len(db_lines)
    assert db_lines[0].flags & TransactionOutputFlag.IS_SPENT == TransactionOutputFlag.IS_SPENT

    # Read based on different key ids.
    for line in [ line1, line2 ]:
        db_lines = table.read(key_ids=[ line.keyinstance_id ])
        assert 1 == len(db_lines)
        assert line.keyinstance_id == db_lines[0].keyinstance_id

    txo_values = table.read_txokeys([ TxoKeyType(line1.tx_hash, line1.tx_index) ])
    assert len(txo_values) == 1
    assert (txo_values[0].tx_hash, txo_values[0].tx_index, txo_values[0].value) == \
        (line1.tx_hash, line1.tx_index, 100)

    txo_values = table.read_txokeys([ TxoKeyType(line2.tx_hash, line2.tx_index) ])
    assert len(txo_values) == 1
    assert (txo_values[0].tx_hash, txo_values[0].tx_index, txo_values[0].value) == \
        (line2.tx_hash, line2.tx_index, 200)

    txo_values = table.read_txokeys([ TxoKeyType(line1.tx_hash, line1.tx_index),
        TxoKeyType(line2.tx_hash, line2.tx_index) ])
    assert len(txo_values) == 2

    with SynchronousWriter() as writer:
        table.delete([ line2[0:2] ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 1 == len(db_lines)
    assert db_lines[0][0:2] == line1[0:2]

    table.close()


@pytest.mark.timeout(8)
def test_table_transactiondeltas_crud(db_context: DatabaseContext) -> None:
    table = TransactionDeltaTable(db_context)
    assert [] == table.read()

    get_current_timestamp = lambda: 10
    table._get_current_timestamp = get_current_timestamp

    TX_BYTES = os.urandom(10)
    TX_HASH = bitcoinx.double_sha256(TX_BYTES)
    TX_INDEX = 1
    TXOUT_FLAGS = 1 << 15
    KEYINSTANCE_ID = 1
    ACCOUNT_ID = 10
    ACCOUNT_ID_OTHER = 11
    MASTERKEY_ID = 20
    DERIVATION_DATA = b'111'

    TX_BYTES2 = os.urandom(10)
    TX_HASH2 = bitcoinx.double_sha256(TX_BYTES2)

    LINE_COUNT = 3
    line1 = TransactionDeltaRow(TX_HASH, KEYINSTANCE_ID, 100)
    line2 = TransactionDeltaRow(TX_HASH, KEYINSTANCE_ID+1, 100)

    # No effect: The transactionoutput foreign key constraint will fail as the transactionoutput
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Satisfy the transaction foreign key constraint by creating the transaction.
    with TransactionTable(db_context) as transaction_table:
        transaction_table._get_current_timestamp = get_current_timestamp
        with SynchronousWriter() as writer:
            transaction_table.create([
                    (TX_HASH, TxData(height=1, fee=2, position=None, date_added=1,
                    date_updated=1), TX_BYTES,
                    TxFlags.HasByteData|TxFlags.HasFee|TxFlags.HasHeight|TxFlags.PaysInvoice,
                    "tx 1"),
                    (TX_HASH2, TxData(height=1, fee=2, position=None, date_added=1,
                    date_updated=1), TX_BYTES2,
                    TxFlags.HasByteData|TxFlags.HasFee|TxFlags.HasHeight,
                    None)
                ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    with MasterKeyTable(db_context) as masterkey_table:
        masterkey_table._get_current_timestamp = get_current_timestamp
        with SynchronousWriter() as writer:
            masterkey_table.create([ (MASTERKEY_ID, None, 2, b'111') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the account foreign key constraint by creating the account.
    with AccountTable(db_context) as account_table:
        account_table._get_current_timestamp = get_current_timestamp
        with SynchronousWriter() as writer:
            account_table.create([ (ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the keyinstance foreign key constraint by creating the keyinstance.
    with KeyInstanceTable(db_context) as keyinstance_table:
        keyinstance_table._get_current_timestamp = get_current_timestamp
        with SynchronousWriter() as writer:
            entries = [ (KEYINSTANCE_ID+i, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
                DERIVATION_DATA, ScriptType.P2PKH, True, None) for i in range(LINE_COUNT) ]
            keyinstance_table.create(entries, completion_callback=writer.get_callback())
            assert writer.succeeded()

    with SynchronousWriter() as writer:
        table.create([ line1, line2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line == line1 ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line == line2 ][0]
    assert line2 == db_line2

    date_updated = 20

    with SynchronousWriter() as writer:
        table.update([ (20, line2[0], line2[1]) ], date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line2 = [ db_line for db_line in db_lines if db_line[0:2] == line2[0:2] ][0]
    assert db_line2[2] == 20

    line2_delta = TransactionDeltaRow(line2.tx_hash, line2.keyinstance_id, 200)
    line3 = TransactionDeltaRow(TX_HASH, KEYINSTANCE_ID+2, 999)
    with SynchronousWriter() as writer:
        table.create_or_update_relative_values([ line2_delta, line3 ],
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    hrow_sum = line1.value_delta + line2_delta.value_delta + line3.value_delta + 20

    hrows = table.read_history(ACCOUNT_ID, [ KEYINSTANCE_ID, KEYINSTANCE_ID+1, KEYINSTANCE_ID+2 ])
    assert hrows is not None
    assert len(hrows) == 1
    assert hrows[0].tx_hash == TX_HASH
    assert hrows[0].tx_flags != TxFlags.HasByteData | TxFlags.HasHeight | TxFlags.HasFee
    assert hrows[0].value_delta == hrow_sum

    hrows = table.read_history(ACCOUNT_ID)
    assert hrows is not None
    assert len(hrows) == 1
    assert hrows[0].tx_hash == TX_HASH
    assert hrows[0].tx_flags != TxFlags.HasByteData | TxFlags.HasHeight | TxFlags.HasFee
    assert hrows[0].value_delta == hrow_sum

    srows = table.read_key_summary(ACCOUNT_ID)
    assert srows is not None
    assert len(srows) == 3
    srow1 = [ r for r in srows if r.keyinstance_id == KEYINSTANCE_ID ][0]
    assert srow1 == TransactionDeltaKeySummaryRow(keyinstance_id=KEYINSTANCE_ID,
        masterkey_id=MASTERKEY_ID, derivation_type=3, derivation_data=b'111', script_type=2,
        flags=1, date_updated=10, total_value=100.0, match_count=1)
    srow2 = [ r for r in srows if r.keyinstance_id == KEYINSTANCE_ID+1 ][0]
    assert srow2 == TransactionDeltaKeySummaryRow(keyinstance_id=KEYINSTANCE_ID+1,
        masterkey_id=MASTERKEY_ID, derivation_type=3, derivation_data=b'111', script_type=2,
        flags=1, date_updated=10, total_value=220.0, match_count=1)
    srow3 = [ r for r in srows if r.keyinstance_id == KEYINSTANCE_ID+2 ][0]
    assert srow3 == TransactionDeltaKeySummaryRow(keyinstance_id=KEYINSTANCE_ID+2,
        masterkey_id=MASTERKEY_ID, derivation_type=3, derivation_data=b'111', script_type=2,
        flags=1, date_updated=10, total_value=999.0, match_count=1)

    srows = table.read_key_summary(ACCOUNT_ID, [ KEYINSTANCE_ID ])
    assert srows is not None
    assert len(srows) == 1
    srow1 = [ r for r in srows if r.keyinstance_id == KEYINSTANCE_ID ][0]
    assert srow1 == TransactionDeltaKeySummaryRow(keyinstance_id=KEYINSTANCE_ID,
        masterkey_id=MASTERKEY_ID, derivation_type=3, derivation_data=b'111', script_type=2,
        flags=1, date_updated=10, total_value=100.0, match_count=1)

    db_lines = table.read()
    assert 3 == len(db_lines)

    balance_row = table.read_balance(ACCOUNT_ID_OTHER)
    assert balance_row == (ACCOUNT_ID_OTHER, 0, 0)

    balance_row = table.read_balance(ACCOUNT_ID)
    assert balance_row.total == 1319.0
    assert balance_row.match_count == 1

    balance_row = table.read_balance(ACCOUNT_ID, TxFlags.Unset, TxFlags.PaysInvoice)
    assert balance_row.total == 0
    assert balance_row.match_count == 0

    balance_row = table.read_balance(ACCOUNT_ID, TxFlags.PaysInvoice, TxFlags.PaysInvoice)
    assert balance_row.total == 1319.0
    assert balance_row.match_count == 1

    expected_total = 100 + 220 + 999

    ## Test `read_transaction_value`
    # Query all deltas for the given transaction.
    results = table.read_transaction_value(TX_HASH)
    assert len(results) == 1
    assert 3 == results[0].match_count
    assert expected_total == results[0].total

    # Query all deltas for the given transaction for the correct account.
    results = table.read_transaction_value(TX_HASH, ACCOUNT_ID)
    assert len(results) == 1
    assert 3 == results[0].match_count
    assert expected_total == results[0].total

    # Query all deltas for the given transaction for an unrelated account.
    results = table.read_transaction_value(TX_HASH, ACCOUNT_ID_OTHER)
    assert len(results) == 0
    # assert 0 == result.match_count
    # assert 0 == result.total

    db_lines = table.read()
    assert 3 == len(db_lines)
    db_line2 = [ db_line for db_line in db_lines if db_line[0:2] == line2[0:2] ][0]
    assert db_line2[2] == 20 + 200
    db_line3 = [ db_line for db_line in db_lines if db_line[0:2] == line3[0:2] ][0]
    assert db_line3[2] == line3[2]

    # .read_paid_requests()
    pr_line1 = PaymentRequestRow(1, KEYINSTANCE_ID, PaymentFlag.UNPAID, 100, 60*60, None,
        table._get_current_timestamp())
    pr_line2 = PaymentRequestRow(2, KEYINSTANCE_ID+2, PaymentFlag.UNPAID, None, 60*60, None,
        table._get_current_timestamp())

    with PaymentRequestTable(db_context) as pr_table:
        with SynchronousWriter() as writer:
            pr_table.create([ pr_line1, pr_line2 ], completion_callback=writer.get_callback())
            assert writer.succeeded()

        pr_rows = table.read_paid_requests(ACCOUNT_ID, [ KEYINSTANCE_ID ])
        assert len(pr_rows) == 1
        assert pr_rows[0] == KEYINSTANCE_ID

        # Match on null is satisfied with any payment.
        pr_rows = table.read_paid_requests(ACCOUNT_ID, [ KEYINSTANCE_ID+2 ])
        assert len(pr_rows) == 1
        assert pr_rows[0] == KEYINSTANCE_ID+2

        with SynchronousWriter() as writer:
            pr_table.update([ (PaymentFlag.UNPAID, 1000, 700, None,
                pr_line2.paymentrequest_id) ],
                date_updated,
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Match fails on existing value + 1.
        pr_rows = table.read_paid_requests(ACCOUNT_ID, [ KEYINSTANCE_ID+2 ])
        assert len(pr_rows) == 0

        with SynchronousWriter() as writer:
            pr_table.update([ (PaymentFlag.UNPAID, 999, 700, None,
                pr_line2.paymentrequest_id) ],
                date_updated,
                completion_callback=writer.get_callback())
            assert writer.succeeded()

        # Match succeeds on exactly the existing value.
        pr_rows = table.read_paid_requests(ACCOUNT_ID, [ KEYINSTANCE_ID+2 ])
        assert len(pr_rows) == 1
        assert pr_rows[0] == KEYINSTANCE_ID+2

    # .delete
    with SynchronousWriter() as writer:
        table.delete([ line2[0:2], line3[0:2] ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 1 == len(db_lines)
    assert db_lines[0][0:2] == line1[0:2]

    # .read_descriptions()
    drows = table.read_descriptions(ACCOUNT_ID)
    assert len(drows) == 1
    assert drows[0] == (TX_HASH, "tx 1")

    table.close()


@pytest.mark.timeout(8)
def test_table_paymentrequests_crud(db_context: DatabaseContext) -> None:
    table = PaymentRequestTable(db_context)
    assert [] == table.read()

    table._get_current_timestamp = lambda: 10

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
    line1 = PaymentRequestRow(1, KEYINSTANCE_ID, PaymentFlag.PAID, None, None, "desc",
        table._get_current_timestamp())
    line2 = PaymentRequestRow(2, KEYINSTANCE_ID+1, PaymentFlag.UNPAID, 100, 60*60, None,
        table._get_current_timestamp())

    # No effect: The transactionoutput foreign key constraint will fail as the key instance
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    with MasterKeyTable(db_context) as masterkey_table:
        with SynchronousWriter() as writer:
            masterkey_table.create([ (MASTERKEY_ID, None, 2, b'111') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the account foreign key constraint by creating the account.
    with AccountTable(db_context) as account_table:
        with SynchronousWriter() as writer:
            account_table.create([ (ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the keyinstance foreign key constraint by creating the keyinstance.
    with KeyInstanceTable(db_context) as keyinstance_table:
        with SynchronousWriter() as writer:
            entries = [ (KEYINSTANCE_ID+i, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
                DERIVATION_DATA, ScriptType.P2PKH, True, None) for i in range(LINE_COUNT) ]
            keyinstance_table.create(entries, completion_callback=writer.get_callback())
            assert writer.succeeded()

    with SynchronousWriter() as writer:
        table.create([ line1, line2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Read all rows in the table.
    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line == line1 ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line == line2 ][0]
    assert line2 == db_line2

    # Read all PAID rows in the table.
    db_lines = table.read(mask=PaymentFlag.PAID)
    assert 1 == len(db_lines)
    assert 1 == db_lines[0].paymentrequest_id
    assert KEYINSTANCE_ID == db_lines[0].keyinstance_id

    # Read all UNPAID rows in the table.
    db_lines = table.read(mask=PaymentFlag.UNPAID)
    assert 1 == len(db_lines)
    assert 2 == db_lines[0].paymentrequest_id
    assert KEYINSTANCE_ID+1 == db_lines[0].keyinstance_id

    # Require ARCHIVED flag.
    db_lines = table.read(mask=PaymentFlag.ARCHIVED)
    assert 0 == len(db_lines)

    # Require no ARCHIVED flag.
    db_lines = table.read(flags=PaymentFlag.NONE, mask=PaymentFlag.ARCHIVED)
    assert 2 == len(db_lines)

    row = table.read_one(1)
    assert row is not None
    assert 1 == row.paymentrequest_id

    row = table.read_one(100101)
    assert row is None

    date_updated = 20

    with SynchronousWriter() as writer:
        table.update([ (PaymentFlag.UNKNOWN, 20, 999, "newdesc",
            line2.paymentrequest_id) ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line2 = [ db_line for db_line in db_lines
        if db_line.paymentrequest_id == line2.paymentrequest_id ][0]
    assert db_line2.value == 20
    assert db_line2.state == PaymentFlag.UNKNOWN
    assert db_line2.description == "newdesc"
    assert db_line2.expiration == 999

    # Account does not exist.
    db_lines = table.read(1000)
    assert 0 == len(db_lines)

    # This account is matched.
    db_lines = table.read(ACCOUNT_ID)
    assert 2 == len(db_lines)

    with SynchronousWriter() as writer:
        table.delete([ (line2.paymentrequest_id,) ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 1 == len(db_lines)
    assert db_lines[0].paymentrequest_id == line1.paymentrequest_id

    table.close()


@pytest.mark.timeout(8)
def test_table_walletevents_crud(db_context: DatabaseContext) -> None:
    table = WalletEventTable(db_context)

    table._get_current_timestamp = lambda: 10

    MASTERKEY_ID = 1
    ACCOUNT_ID = 1

    line1 = WalletEventRow(1, WalletEventType.SEED_BACKUP_REMINDER, ACCOUNT_ID,
        WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, table._get_current_timestamp())
    line2 = WalletEventRow(2, WalletEventType.SEED_BACKUP_REMINDER, None,
        WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, table._get_current_timestamp())

    # No effect: The transactionoutput foreign key constraint will fail as the key instance
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    with MasterKeyTable(db_context) as masterkey_table:
        with SynchronousWriter() as writer:
            masterkey_table.create([ (MASTERKEY_ID, None, 2, b'111') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the account foreign key constraint by creating the account.
    with AccountTable(db_context) as account_table:
        with SynchronousWriter() as writer:
            account_table.create([ (ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    with SynchronousWriter() as writer:
        table.create([ line1, line2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line == line1 ][0]
    assert line1 == db_line1
    db_line2 = [ db_line for db_line in db_lines if db_line == line2 ][0]
    assert line2 == db_line2

    date_updated = 20

    with SynchronousWriter() as writer:
        table.update_flags([ (WalletEventFlag.UNREAD, line2.event_id) ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 2 == len(db_lines)
    db_line2 = [ db_line for db_line in db_lines
        if db_line.event_id == line2.event_id ][0]
    assert db_line2.event_flags == WalletEventFlag.UNREAD

    # Account does not exist.
    db_lines = table.read(1000)
    assert 0 == len(db_lines)

    # This account is matched.
    db_lines = table.read(ACCOUNT_ID)
    assert 1 == len(db_lines)

    with SynchronousWriter() as writer:
        table.delete([ (line2.event_id,) ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read()
    assert 1 == len(db_lines)
    assert db_lines[0].event_id == line1.event_id

    table.close()


def test_update_used_keys(db_context: DatabaseContext):
    """3 main scenarios to test:
    - 2 x settled txs and zero balance -> used key gets deactivated
    - 2 x unsettled tx -> not yet used (until settled)
    - 2 x settled tx BUT user_set_active -> keeps it activated until manually deactivated"""

    masterkey_table = MasterKeyTable(db_context)
    accounts_table = AccountTable(db_context)
    transaction_deltas_table = TransactionDeltaTable(db_context)
    keyinstance_table = KeyInstanceTable(db_context)
    tx_table = TransactionTable(db_context)

    timestamp = tx_table._get_current_timestamp()
    tx_entries = [
        # 2 x Settled txs -> Used keyinstance (key_id = 1)
        TransactionRow(
            tx_hash=b'1', tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
                date_updated=timestamp), tx_bytes=b'tx_bytes1',
            flags=TxFlags(TxFlags.StateSettled | TxFlags.HasByteData | TxFlags.HasHeight),
            description=None),
        TransactionRow(tx_hash=b'2',
            tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
                date_updated=timestamp), tx_bytes=b'tx_bytes1',
            flags=TxFlags(TxFlags.StateSettled | TxFlags.HasByteData | TxFlags.HasHeight),
            description=None),
        # 2 x Unsettled txs -> Not yet "Used" until settled (key_id = 2)
        TransactionRow(tx_hash=b'3',
            tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
                date_updated=timestamp), tx_bytes=b'tx_bytes3',
            flags=TxFlags(TxFlags.StateCleared | TxFlags.HasByteData | TxFlags.HasHeight),
            description=None),
        TransactionRow(tx_hash=b'4',
            tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
                date_updated=timestamp), tx_bytes=b'tx_bytes4',
            flags=TxFlags(TxFlags.StateCleared | TxFlags.HasByteData | TxFlags.HasHeight),
            description=None),
        # 2 x Settled txs BUT keyinstance has flag: USER_SET_ACTIVE manually so not deactivated.
        TransactionRow(tx_hash=b'5',
            tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
                date_updated=timestamp), tx_bytes=b'tx_bytes5',
            flags=TxFlags(TxFlags.StateSettled | TxFlags.HasByteData | TxFlags.HasHeight),
            description=None),
        TransactionRow(tx_hash=b'6',
            tx_data=TxData(height=1, position=1, fee=250, date_added=timestamp,
                date_updated=timestamp), tx_bytes=b'tx_bytes6',
            flags=TxFlags(TxFlags.StateSettled | TxFlags.HasByteData | TxFlags.HasHeight),
            description=None),
    ]
    tx_delta_entries = [
        TransactionDeltaRow(tx_hash=b'1',keyinstance_id=1,value_delta=10),
        TransactionDeltaRow(tx_hash=b'2',keyinstance_id=1,value_delta=-10),
        TransactionDeltaRow(tx_hash=b'3', keyinstance_id=2, value_delta=10),
        TransactionDeltaRow(tx_hash=b'4', keyinstance_id=2, value_delta=-10),
        TransactionDeltaRow(tx_hash=b'5', keyinstance_id=3, value_delta=10),
        TransactionDeltaRow(tx_hash=b'6', keyinstance_id=3, value_delta=-10)
    ]

    keyinstance_entries = [
        KeyInstanceRow(keyinstance_id=1, account_id=1,masterkey_id=1,
            derivation_type=DerivationType.BIP32, derivation_data=json.dumps({"subpath": [0, 0]}),
            script_type=ScriptType.P2PKH, flags=KeyInstanceFlag.IS_ACTIVE, description=""),
        KeyInstanceRow(keyinstance_id=2,account_id=1,masterkey_id=1,
            derivation_type=DerivationType.BIP32, derivation_data=json.dumps({"subpath": [0, 1]}),
            script_type=ScriptType.P2PKH, flags=KeyInstanceFlag.IS_ACTIVE, description=""),
        KeyInstanceRow(keyinstance_id=3, account_id=1, masterkey_id=1,
            derivation_type=DerivationType.BIP32, derivation_data=json.dumps({"subpath": [0, 1]}),
            script_type=ScriptType.P2PKH, flags=KeyInstanceFlag.USER_SET_ACTIVE, description=""),
    ]

    with SynchronousWriter() as writer:
        masterkey_table.create([(1, None, 2, b'1234')],
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        accounts_table.create([(1, 1, ScriptType.P2PKH, 'name')],
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        tx_table.create(tx_entries, completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        keyinstance_table.create(keyinstance_entries, completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        transaction_deltas_table.create(tx_delta_entries, completion_callback=writer.get_callback())
        assert writer.succeeded()

    q = transaction_deltas_table.read()
    assert len(q) == 6

    q = tx_table.read()
    assert len(q) == 6

    q = keyinstance_table.read()
    assert len(q) == 3

    with SynchronousWriter() as writer:
        used_keys = transaction_deltas_table.update_used_keys(1,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    assert len(used_keys) == 1
    assert used_keys == [1]  # 2 x settled txs and zero balance for key

    rows = keyinstance_table.read(key_ids=[1])
    assert len(rows) == 1
    assert rows[0].flags & KeyInstanceFlag.IS_ACTIVE == 0

    masterkey_table.close()
    accounts_table.close()
    transaction_deltas_table.close()
    keyinstance_table.close()
    tx_table.close()


@pytest.mark.timeout(8)
def test_table_invoice_crud(db_context: DatabaseContext) -> None:
    table = InvoiceTable(db_context)
    assert [] == table.read_account(1)

    table._get_current_timestamp = lambda: 10

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
        1, b'{}', None, table._get_current_timestamp())
    line2_1 = InvoiceRow(2, ACCOUNT_ID_1, TX_HASH_1, "payment_uri2", "desc", PaymentFlag.PAID,
        2, b'{}', table._get_current_timestamp() + 10, table._get_current_timestamp())
    line3_2 = InvoiceRow(3, ACCOUNT_ID_2, None, "payment_uri3", "desc", PaymentFlag.UNPAID,
        3, b'{}', None, table._get_current_timestamp())

    # No effect: The transactionoutput foreign key constraint will fail as the account
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1_1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    with MasterKeyTable(db_context) as masterkey_table:
        with SynchronousWriter() as writer:
            masterkey_table.create([ (MASTERKEY_ID, None, 2, b'111') ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    # Satisfy the account foreign key constraint by creating the account.
    with AccountTable(db_context) as account_table:
        with SynchronousWriter() as writer:
            account_table.create([
                    AccountRow(ACCOUNT_ID_1, MASTERKEY_ID, ScriptType.P2PKH, 'name1'),
                    AccountRow(ACCOUNT_ID_2, MASTERKEY_ID, ScriptType.P2PKH, 'name2'),
                ],
                completion_callback=writer.get_callback())
            assert writer.succeeded()

    txs = []
    for txh, txb in ((TX_HASH_1, TX_BYTES_1), (TX_HASH_2, TX_BYTES_2), (TX_HASH_3, TX_BYTES_3)):
        tx = TransactionRow(
            tx_hash=txh, tx_data=TxData(height=1, position=1, fee=250, date_added=1,
            date_updated=2), tx_bytes=txb,
            flags=TxFlags(TxFlags.StateSettled | TxFlags.HasByteData | TxFlags.HasHeight),
            description=None)
        txs.append(tx)
    transaction_table = TransactionTable(db_context)
    with SynchronousWriter() as writer:
        transaction_table.create(txs, completion_callback=writer.get_callback())
        assert writer.succeeded()

    with SynchronousWriter() as writer:
        table.create([ line1_1, line2_1, line3_2 ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        with SynchronousWriter() as writer:
            table.create([ line1_1 ], completion_callback=writer.get_callback())
            assert not writer.succeeded()

    def compare_row_to_account_row(src: InvoiceRow, dst: InvoiceAccountRow) -> None:
        assert src.description == dst.description
        assert src.flags == dst.flags
        assert src.value == dst.value
        assert src.date_expires == dst.date_expires
        assert src.date_created == dst.date_created

    ## InvoiceTable.read
    # Read all rows in the table for account 1.
    db_lines = table.read_account(ACCOUNT_ID_1)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines if db_line.invoice_id == line1_1.invoice_id ][0]
    compare_row_to_account_row(line1_1, db_line1)
    db_line2 = [ db_line for db_line in db_lines if db_line.invoice_id == line2_1.invoice_id ][0]
    compare_row_to_account_row(line2_1, db_line2)

    # Read all rows in the table for account 2.
    db_lines = table.read_account(ACCOUNT_ID_2)
    assert 1 == len(db_lines)
    db_line3 = [ db_line for db_line in db_lines if db_line.invoice_id == line3_2.invoice_id ][0]
    compare_row_to_account_row(line3_2, db_line3)

    # Read all PAID rows in the table for the first account.
    db_lines = table.read_account(ACCOUNT_ID_1, mask=PaymentFlag.PAID)
    assert 1 == len(db_lines)
    assert 2 == db_lines[0].invoice_id

    # Read all UNPAID rows in the table for the first account.
    db_lines = table.read_account(ACCOUNT_ID_1, mask=PaymentFlag.UNPAID)
    assert 1 == len(db_lines)
    assert 1 == db_lines[0].invoice_id

    # Require ARCHIVED flag.
    db_lines = table.read_account(ACCOUNT_ID_1, mask=PaymentFlag.ARCHIVED)
    assert 0 == len(db_lines)

    # Require no ARCHIVED flag.
    db_lines = table.read_account(ACCOUNT_ID_1, flags=PaymentFlag.NONE, mask=PaymentFlag.ARCHIVED)
    assert 2 == len(db_lines)

    # Non-existent account.
    db_lines = table.read_account(1010101)
    assert 0 == len(db_lines)

    ## InvoiceTable.read_one
    row = table.read_one(line1_1.invoice_id)
    assert row is not None
    assert 1 == row.invoice_id

    row = table.read_one(100101)
    assert row is None

    row = table.read_one(tx_hash=TX_HASH_1)
    assert row is not None
    assert 2 == row.invoice_id

    ## InvoiceTable.update_transaction
    date_updated = 20
    with SynchronousWriter() as writer:
        table.update_transaction([ (TX_HASH_3, line3_2.invoice_id), ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    # Verify the invoice is now marked with no associated tx.
    row = table.read_one(line3_2.invoice_id)
    assert row is not None
    assert row.tx_hash == TX_HASH_3

    ## InvoiceTable.clear_transaction
    date_updated += 1
    with SynchronousWriter() as writer:
        table.clear_transaction([ (TX_HASH_3,), ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    # Verify the invoice is now marked with no associated tx.
    row = table.read_one(line3_2.invoice_id)
    assert row.tx_hash is None

    ## InvoiceTable.update_description
    date_updated += 1
    with SynchronousWriter() as writer:
        table.update_description([ ("newdesc3.2", line3_2.invoice_id), ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    # Verify the invoice now has the new description.
    row = table.read_one(line3_2.invoice_id)
    assert row.description == "newdesc3.2"

    ## InvoiceTable.update_flags
    date_updated += 1
    with SynchronousWriter() as writer:
        table.update_flags([ (~PaymentFlag.ARCHIVED, PaymentFlag.ARCHIVED, line3_2.invoice_id), ],
            date_updated,
            completion_callback=writer.get_callback())
        assert writer.succeeded()

    # Verify the invoice now has the new description.
    row = table.read_one(line3_2.invoice_id)
    assert row.flags == PaymentFlag.ARCHIVED | PaymentFlag.UNPAID

    ## InvoiceTable.read_duplicate
    duplicate_row1 = table.read_duplicate(111, "ddd")
    assert duplicate_row1 is None
    duplicate_row2 = table.read_duplicate(row.value, row.payment_uri)
    assert duplicate_row2 == row

    with SynchronousWriter() as writer:
        table.delete([ (line2_1.invoice_id,) ], completion_callback=writer.get_callback())
        assert writer.succeeded()

    db_lines = table.read_account(ACCOUNT_ID_1)
    assert 1 == len(db_lines)
    assert db_lines[0].invoice_id == line1_1.invoice_id

    transaction_table.close()
    table.close()
