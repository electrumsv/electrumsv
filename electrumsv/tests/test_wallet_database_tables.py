import os
import tempfile
from typing import List
import unittest.mock

import bitcoinx
import pytest
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.9.5 builds and bundled version of 3.35.5.
    import sqlite3
else:
    sqlite3 = pysqlite3

from electrumsv.constants import (AccountTxFlags, DerivationType, KeyInstanceFlag,
    NetworkServerFlag, NetworkServerType,
    PaymentFlag, ScriptType, TransactionOutputFlag, TxFlags, WalletEventFlag, WalletEventType)
from electrumsv.logs import logs
from electrumsv.types import ServerAccountKey, Outpoint
from electrumsv.wallet_database import functions as db_functions
from electrumsv.wallet_database import migration
from electrumsv.wallet_database.sqlite_support import DatabaseContext, LeakedSQLiteConnectionError
from electrumsv.wallet_database.types import (AccountRow, AccountTransactionRow, InvoiceAccountRow,
    InvoiceRow, KeyInstanceRow, MasterKeyRow, NetworkServerRow, NetworkServerAccountRow,
    PaymentRequestReadRow, PaymentRequestRow, PaymentRequestUpdateRow, TransactionBlockRow,
    TransactionRow, TransactionOutputShortRow, TxProof, WalletBalance, WalletEventRow)
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

    line1 = MasterKeyRow(1, None, DerivationType.ELECTRUM_MULTISIG, b'111')
    line2 = MasterKeyRow(2, None, DerivationType.BIP32_SUBPATH, b'222')

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

    # future = db_functions.update_masterkey_derivation_datas(db_context, [ (b'234', 1) ])
    # future.result()

    # masterkey_rows = db_functions.read_masterkeys(db_context)
    # masterkey_row1 = [ row for row in masterkey_rows if row.masterkey_id == 1 ][0]
    # assert masterkey_row1.derivation_data == b'234'


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
    mk_row1 = MasterKeyRow(MASTERKEY_ID+1, None, DerivationType.ELECTRUM_MULTISIG, b'111')
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
        DERIVATION_DATA1, None, KeyInstanceFlag.NONE, None)
    line2 = KeyInstanceRow(KEYINSTANCE_ID+2, ACCOUNT_ID+1, MASTERKEY_ID+1, DerivationType.HARDWARE,
        DERIVATION_DATA2, None, KeyInstanceFlag.NONE, None)

    # No effect: The masterkey foreign key constraint will fail as the masterkey does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_keyinstances(db_context, [ line1 ])
        future.result(timeout=5)

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context,
        [ MasterKeyRow(MASTERKEY_ID+1, None, DerivationType.ELECTRUM_MULTISIG, b'111') ])
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

    future = db_functions.set_keyinstance_flags(db_context, [ line1.keyinstance_id ],
        flags=KeyInstanceFlag.FROZEN)
    update_rows = future.result(5)
    assert len(update_rows) == 1
    assert update_rows[0].keyinstance_id == line1.keyinstance_id
    assert update_rows[0].flags_old == KeyInstanceFlag.NONE
    assert update_rows[0].flags_new == KeyInstanceFlag.FROZEN

    # Set the active flags and ensure they are additive to the `FROZEN` flag.
    active_flags = KeyInstanceFlag.ACTIVE | KeyInstanceFlag.IS_PAYMENT_REQUEST
    future = db_functions.set_keyinstance_flags(db_context, [ line1.keyinstance_id ],
        flags=active_flags)
    update_rows = future.result(5)
    assert len(update_rows) == 1
    assert update_rows[0].keyinstance_id == line1.keyinstance_id
    assert update_rows[0].flags_old == KeyInstanceFlag.FROZEN
    assert update_rows[0].flags_new == active_flags | KeyInstanceFlag.FROZEN

    # Clear the `IS_PAYMENT_REQUEST` flag and ensure it clears `IS_ACTIVE` as there are no other
    # active reason states present to maintain it.
    future = db_functions.set_keyinstance_flags(db_context, [ line1.keyinstance_id ],
        flags=KeyInstanceFlag.NONE, mask=KeyInstanceFlag(~KeyInstanceFlag.IS_PAYMENT_REQUEST))
    update_rows = future.result(5)
    assert len(update_rows) == 1
    assert update_rows[0].keyinstance_id == line1.keyinstance_id
    assert KeyInstanceFlag(update_rows[0].flags_old) == active_flags | KeyInstanceFlag.FROZEN
    assert KeyInstanceFlag(update_rows[0].flags_new) == KeyInstanceFlag.FROZEN

    # Set the multiple active reason flags and ensure they are additive to the `FROZEN` flag.
    active_flags = KeyInstanceFlag.ACTIVE | KeyInstanceFlag.IS_PAYMENT_REQUEST | \
        KeyInstanceFlag.USER_SET_ACTIVE
    future = db_functions.set_keyinstance_flags(db_context, [ line1.keyinstance_id ],
        flags=active_flags)
    update_rows = future.result(5)
    assert len(update_rows) == 1
    assert update_rows[0].keyinstance_id == line1.keyinstance_id
    assert update_rows[0].flags_old == KeyInstanceFlag.FROZEN
    assert update_rows[0].flags_new == active_flags | KeyInstanceFlag.FROZEN

    # Clear the `IS_PAYMENT_REQUEST` flag and ensure it preserves `IS_ACTIVE` as the
    # `USER_SET_ACTIVE` flag maintains the need for it.
    future = db_functions.set_keyinstance_flags(db_context, [ line1.keyinstance_id ],
        flags=KeyInstanceFlag.NONE, mask=KeyInstanceFlag(~KeyInstanceFlag.IS_PAYMENT_REQUEST))
    update_rows = future.result(5)
    assert len(update_rows) == 1
    assert update_rows[0].keyinstance_id == line1.keyinstance_id
    assert KeyInstanceFlag(update_rows[0].flags_old) == active_flags | KeyInstanceFlag.FROZEN
    assert KeyInstanceFlag(update_rows[0].flags_new) == \
        KeyInstanceFlag.ACTIVE| KeyInstanceFlag.USER_SET_ACTIVE| KeyInstanceFlag.FROZEN


class TestTransactionTable:
    @classmethod
    def setup_class(cls):
        cls.db_context: DatabaseContext = _db_context()
        cls.db: sqlite3.Connection = cls.db_context.acquire_connection()
        cls.tx_hash = os.urandom(32)

    @classmethod
    def teardown_class(cls):
        cls.db_context.release_connection(cls.db)
        cls.db = None
        cls.db_context.close()
        del cls.db_context

    def setup_method(self):
        db = self.db
        db.execute(f"DELETE FROM Transactions")
        db.commit()

    def _get_store_hashes(self) -> List[bytes]:
        assert self.db_context is not None
        return db_functions.read_transaction_hashes(self.db_context)

    def test_proof_serialization(self):
        proof1 = TxProof(position=10, branch=[ os.urandom(32) for i in range(10) ])
        raw = pack_proof(proof1)
        proof2 = unpack_proof(raw)
        assert proof1.position == proof2.position
        assert proof1.branch == proof2.branch

    def test_create_read_various(self) -> None:
        assert self.db_context is not None

        tx_bytes_1 = os.urandom(10)
        tx_hash = bitcoinx.double_sha256(tx_bytes_1)
        tx_row = TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes_1,
            flags=TxFlags.STATE_DISPATCHED,
            block_hash=b'11', block_height=222, block_position=None, fee_value=None,
            description=None, version=None, locktime=None, date_created=1, date_updated=1)
        future = db_functions.create_transactions(self.db_context, [ tx_row ])
        future.result(timeout=5)

        # Check the state is correct, all states should be the same code path.
        flags = db_functions.read_transaction_flags(self.db_context, tx_hash)
        assert flags is not None
        assert TxFlags.STATE_DISPATCHED == flags & TxFlags.MASK_STATE

        tx_metadata = db_functions.read_transaction_metadata(self.db_context, tx_hash)
        assert tx_metadata is not None
        block_height, block_position, fee_value, date_created = tx_metadata
        assert tx_row.block_height == block_height
        assert tx_row.block_position == block_position
        assert tx_row.fee_value == fee_value
        assert tx_row.date_created == date_created

        tx_bytes = db_functions.read_transaction_bytes(self.db_context, tx_hash)
        assert tx_bytes_1 == tx_bytes

    def test_create_multiple(self) -> None:
        assert self.db_context is not None

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

    def test_get_all_pending(self) -> None:
        assert self.db_context is not None

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

    def test_proof(self) -> None:
        assert self.db_context is not None

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


def test_table_transactionoutputs_crud(db_context: DatabaseContext) -> None:
    TX_BYTES_COINBASE = os.urandom(10)
    TX_HASH_COINBASE = bitcoinx.double_sha256(TX_BYTES_COINBASE)
    TX_BYTES = os.urandom(10)
    TX_HASH = bitcoinx.double_sha256(TX_BYTES)
    TX_INDEX = 1
    TXOUT_FLAGS = TransactionOutputFlag.NONE
    KEYINSTANCE_ID_1 = 1
    KEYINSTANCE_ID_2 = 2
    KEYINSTANCE_ID_3 = 3
    ACCOUNT_ID = 10
    MASTERKEY_ID = 20
    DERIVATION_DATA1 = b'111'
    DERIVATION_DATA2 = b'222'
    DERIVATION_DATA3 = b'333'

    row1 = TransactionOutputShortRow(TX_HASH_COINBASE, TX_INDEX, 50, KEYINSTANCE_ID_1,
        TXOUT_FLAGS | TransactionOutputFlag.COINBASE, ScriptType.P2PKH, b'')
    row2 = TransactionOutputShortRow(TX_HASH, TX_INDEX, 100, KEYINSTANCE_ID_2, TXOUT_FLAGS,
        ScriptType.P2PKH, b'')
    row3 = TransactionOutputShortRow(TX_HASH, TX_INDEX+1, 200, KEYINSTANCE_ID_3, TXOUT_FLAGS,
        ScriptType.P2PKH, b'')

    # No effect: The transactionoutput foreign key constraint will fail as the transactionoutput
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_transaction_outputs(db_context, [ row2 ])
        future.result(timeout=5)

    # Satisfy the transaction foreign key constraint by creating the transaction.
    tx_rows = [
        TransactionRow(tx_hash=TX_HASH_COINBASE, tx_bytes=TX_BYTES_COINBASE,
            flags=TxFlags.STATE_SETTLED,
            block_hash=b'111', block_height=20, block_position=None, fee_value=2, description=None,
            version=None, locktime=None, date_created=1, date_updated=1),
        TransactionRow(tx_hash=TX_HASH, tx_bytes=TX_BYTES, flags=TxFlags.STATE_CLEARED,
            block_hash=None, block_height=0, block_position=None, fee_value=2, description=None,
            version=None, locktime=None, date_created=1, date_updated=1)
    ]
    future = db_functions.create_transactions(db_context, tx_rows)
    future.result(timeout=5)

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context, [
        MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111') ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name')
    future = db_functions.create_accounts(db_context, [ account_row ])
    future.result()

    future = db_functions.create_account_transactions(db_context, [
        AccountTransactionRow(ACCOUNT_ID, TX_HASH, AccountTxFlags.NONE, None),
        AccountTransactionRow(ACCOUNT_ID, TX_HASH_COINBASE, AccountTxFlags.NONE, None),
    ])
    future.result(timeout=5)

    # Satisfy the keyinstance foreign key constraint by creating the keyinstance.
    key_rows = [
        KeyInstanceRow(KEYINSTANCE_ID_1, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            DERIVATION_DATA1, DERIVATION_DATA1, KeyInstanceFlag.NONE, None),
        KeyInstanceRow(KEYINSTANCE_ID_2, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            DERIVATION_DATA2, DERIVATION_DATA2, KeyInstanceFlag.NONE, None),
        KeyInstanceRow(KEYINSTANCE_ID_3, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            DERIVATION_DATA3, DERIVATION_DATA3, KeyInstanceFlag.NONE, None),
    ]
    future = db_functions.create_keyinstances(db_context, key_rows)
    future.result(timeout=5)

    # Create the first and second row.
    future = db_functions.create_transaction_outputs(db_context, [ row1, row2, row3 ])
    future.result(timeout=5)

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_transaction_outputs(db_context, [ row2 ])
        future.result(timeout=5)

    ## Test `read_transaction_outputs_with_key_data` for the `derivation_data2` path.
    # Test invalid values.
    output_rows = db_functions.read_transaction_outputs_with_key_data(db_context,
        derivation_data2s=[ b'22323232323' ])
    assert len(output_rows) == 0

    # Test valid values with unfiltered search.
    for txo_index, txo_row in enumerate([ row1, row2, row3 ]):
        key_row = key_rows[txo_index]
        output_rows = db_functions.read_transaction_outputs_with_key_data(db_context,
            derivation_data2s=[ key_row.derivation_data2 ])
        assert len(output_rows) == 1
        assert output_rows[0].tx_hash == txo_row.tx_hash
        assert output_rows[0].txo_index == txo_row.txo_index
        assert output_rows[0].keyinstance_id == key_row.keyinstance_id

    # Test an existing match with valid tx_hash filtering.
    output_rows = db_functions.read_transaction_outputs_with_key_data(db_context,
        tx_hash=row1.tx_hash, derivation_data2s=[ key_rows[0].derivation_data2 ])
    assert len(output_rows) == 1

    # Test an existing match with invalid tx_hash filtering.
    output_rows = db_functions.read_transaction_outputs_with_key_data(db_context,
        tx_hash=b'32323232', derivation_data2s=[ key_rows[0].derivation_data2 ])
    assert len(output_rows) == 0

    # Test an existing match with valid `account_id` filtering.
    output_rows = db_functions.read_transaction_outputs_with_key_data(db_context,
        account_id=ACCOUNT_ID, derivation_data2s=[ key_rows[0].derivation_data2 ])
    assert len(output_rows) == 1

    # Test an existing match with invalid `account_id` filtering.
    output_rows = db_functions.read_transaction_outputs_with_key_data(db_context,
        account_id=ACCOUNT_ID+1, derivation_data2s=[ key_rows[0].derivation_data2 ])
    assert len(output_rows) == 0

    ## Test `read_account_transaction_outputs_with_key_data`.
    # Verify that the `mature_height` parameter works for this method.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        mature_height=119)
    assert len(txos_rows) == 2
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX+1
    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        mature_height=120)
    assert len(txos_rows) == 3
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    # Verify that the `mature_height` parameter works for this method.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID, mature_height=119)
    assert len(txos_rows) == 2
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX+1
    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID, mature_height=120)
    assert len(txos_rows) == 3
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    # Verify that the `confirmed_only` parameter works for this method.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        confirmed_only=False)
    assert len(txos_rows) == 3
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1
    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        confirmed_only=True)
    assert len(txos_rows) == 1
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX

    # Verify that the `confirmed_only` parameter works for this method.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID, confirmed_only=False)
    assert len(txos_rows) == 3
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1
    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID, confirmed_only=True)
    assert len(txos_rows) == 1
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX

    # Balances WRT mature_height.
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, 119)
    assert balance == WalletBalance(0, row2.value + row3.value, row1.value, 0)
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, 120)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)

    balance = db_functions.read_wallet_balance(db_context, 119)
    assert balance == WalletBalance(0, row2.value + row3.value, row1.value, 0)
    balance = db_functions.read_wallet_balance(db_context, 120)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)

    ## We are going to freeze the output we do not plan to spend, and verify that it is factored
    ## into account and wallet balances.
    # Balances with no frozen TXO.
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, 1000, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, 1000, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)

    balance = db_functions.read_wallet_balance(db_context, 1000, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_wallet_balance(db_context, 1000, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)

    # Add a key flag. In this case `FROZEN`.
    future = db_functions.set_keyinstance_flags(db_context, [ KEYINSTANCE_ID_2 ],
        KeyInstanceFlag.FROZEN)
    future.result(timeout=5)

    # Balances with a frozen TXO present.
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, 1000, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, 1000, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row3.value, 0, 0)

    balance = db_functions.read_wallet_balance(db_context, 1000, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_wallet_balance(db_context, 1000, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row3.value, 0, 0)

    # `read_account_transaction_outputs_with_key_data`. Spendable TXOs based on `FROZEN` flag.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        exclude_frozen=False)
    assert len(txos_rows) == 3
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        exclude_frozen=True)
    assert len(txos_rows) == 2
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX+1

    # `read_account_transaction_outputs_with_key_and_tx_data`.
    # Spendable TXOs based on `FROZEN` flag.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID, exclude_frozen=False)
    assert len(txos_rows) == 3
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        exclude_frozen=True)
    assert len(txos_rows) == 2
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX+1

    # Remove the key flag, `FROZEN`.
    future = db_functions.set_keyinstance_flags(db_context, [ KEYINSTANCE_ID_2 ],
        KeyInstanceFlag.NONE, KeyInstanceFlag(~KeyInstanceFlag.FROZEN))
    future.result(timeout=5)

    # Add a TXO flag. In this case `FROZEN` to the first TXO.
    future = db_functions.update_transaction_output_flags(db_context,
        [Outpoint(TX_HASH, TX_INDEX)], TransactionOutputFlag.FROZEN)
    future.result(timeout=5)

    # Balances with a frozen TXO present.
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, 1000, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, 1000, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row3.value, 0, 0)

    balance = db_functions.read_wallet_balance(db_context, 1000, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_wallet_balance(db_context, 1000, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row3.value, 0, 0)

    # `read_account_transaction_outputs_with_key_data`. Spendable TXOs based on `FROZEN` flag.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        exclude_frozen=False)
    assert len(txos_rows) == 3
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        exclude_frozen=True)
    assert len(txos_rows) == 2
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX+1

    # `read_account_transaction_outputs_with_key_and_tx_data`.
    # Spendable TXOs based on `FROZEN` flag.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID, exclude_frozen=False)
    assert len(txos_rows) == 3
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        exclude_frozen=True)
    assert len(txos_rows) == 2
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX+1

    # This is the best place to test this function.
    derivation_keyinstances = db_functions.read_keyinstances_for_derivations(db_context,
        ACCOUNT_ID, DerivationType.BIP32, [ DERIVATION_DATA1 ], MASTERKEY_ID)
    assert len(derivation_keyinstances) == 1
    assert derivation_keyinstances[0] == key_rows[0]

    # This is the best place to test this function.
    derivation_keyinstances = db_functions.read_keyinstances_for_derivations(db_context,
        ACCOUNT_ID, DerivationType.BIP32, [ DERIVATION_DATA1, DERIVATION_DATA2 ], MASTERKEY_ID)
    # Sqlite returns the rows in order, but we should not rely on that as it is not a guarantee.
    derivation_keyinstances.sort(key=lambda r: r.keyinstance_id)
    assert len(derivation_keyinstances) == 2
    assert derivation_keyinstances[0] == key_rows[0]
    assert derivation_keyinstances[1] == key_rows[1]

    # Remove a TXO flag. In this case the `FROZEN` flag from the first TXO.
    future = db_functions.update_transaction_output_flags(db_context,
        [Outpoint(TX_HASH, TX_INDEX)], TransactionOutputFlag.NONE,
        TransactionOutputFlag(~TransactionOutputFlag.FROZEN))
    future.result(timeout=5)

    # Verify that the outputs are present and restored to their original state. If the `FROZEN`
    # flag is not removed, then this will fail.
    txo_keys = [
        Outpoint(row2.tx_hash, row2.txo_index),
        Outpoint(row3.tx_hash, row3.txo_index),
    ]
    db_rows = db_functions.read_transaction_outputs_explicit(db_context, txo_keys)
    assert 2 == len(db_rows)
    db_row1 = db_rows[0]
    assert row2.flags == db_row1.flags
    db_row1 = [ db_line for db_line in db_rows if db_line == row2 ][0]
    assert row2 == db_row1
    db_row2 = [ db_line for db_line in db_rows if db_line == row3 ][0]
    assert row3 == db_row2

    txo_keys = [ Outpoint(row3.tx_hash, row3.txo_index) ]
    future = db_functions.update_transaction_output_flags(db_context, txo_keys,
        TransactionOutputFlag.SPENT)
    future.result(5)

    db_rows = db_functions.read_transaction_outputs_explicit(db_context, txo_keys)
    assert len(db_rows) == 1
    assert db_rows[0].flags == TransactionOutputFlag.SPENT

    future = db_functions.update_transaction_block_many(db_context,
        [ TransactionBlockRow(21, b'111', TX_HASH) ])
    update_count = future.result(5)
    assert update_count == 1

    # Edge case, we are looking at a block height less than the transaction height.
    unverified_entries = db_functions.read_unverified_transactions(db_context, 20)
    assert len(unverified_entries) == 0

    # Edge case, we are looking at a block height less than the transaction height.
    unverified_entries = db_functions.read_unverified_transactions(db_context, 21)
    assert len(unverified_entries) == 1
    assert unverified_entries[0][0] == TX_HASH
    assert unverified_entries[0][1] == 21


@pytest.mark.asyncio
async def test_table_paymentrequests_crud(db_context: DatabaseContext) -> None:
    TX_BYTES = os.urandom(10)
    TX_HASH = bitcoinx.double_sha256(TX_BYTES)
    TX_INDEX = 1
    TXOUT_FLAGS = TransactionOutputFlag.NONE
    KEYINSTANCE_ID = 1
    ACCOUNT_ID = 10
    MASTERKEY_ID = 20
    DERIVATION_DATA = b'111'
    TX_DESC1 = "desc1"
    TX_DESC2 = "desc2"
    TX_BYTES2 = os.urandom(10)
    TX_HASH2 = bitcoinx.double_sha256(TX_BYTES2)

    rows = db_functions.read_payment_requests(db_context, ACCOUNT_ID)
    assert len(rows) == 0

    LINE_COUNT = 3
    line1 = PaymentRequestRow(1, KEYINSTANCE_ID, PaymentFlag.PAID, None, None, TX_DESC1)
    line2 = PaymentRequestRow(2, KEYINSTANCE_ID+1, PaymentFlag.UNPAID, 100, 60*60, TX_DESC2)

    # No effect: The transactionoutput foreign key constraint will fail as the key instance
    # does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_payment_requests(db_context, [ line1 ])
        future.result()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context, [
        MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111') ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name')
    future = db_functions.create_accounts(db_context, [ account_row ])
    future.result()

    # Satisfy the keyinstance foreign key constraint by creating the keyinstance.
    # NOTE This is not properly reserving the keys and setting the flags that way, instead it is
    #   adding them manually and setting the expected flags itself. But maybe that is outside the
    #   scope of this unit test.
    entries = [ KeyInstanceRow(KEYINSTANCE_ID+i, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
        DERIVATION_DATA, None,
        KeyInstanceFlag.ACTIVE | KeyInstanceFlag.IS_PAYMENT_REQUEST | KeyInstanceFlag.USED,
        None) for i in range(LINE_COUNT) ]
    future = db_functions.create_keyinstances(db_context, entries)
    future.result(timeout=5)

    future = db_functions.create_payment_requests(db_context, [ line1, line2 ])
    future.result()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_payment_requests(db_context, [ line1 ])
        future.result()

    def compare_paymentrequest_rows(row1: PaymentRequestRow, row2: PaymentRequestReadRow) -> None:
        assert row1.keyinstance_id == row2.keyinstance_id
        assert row1.state == row2.state
        assert row1.requested_value == row2.requested_value
        assert row1.expiration == row2.expiration
        assert row1.description == row2.description
        assert -1 != row2.date_created

    # Read all rows in the table.
    db_lines = db_functions.read_payment_requests(db_context, ACCOUNT_ID)
    assert 2 == len(db_lines)
    db_line1 = [ db_line for db_line in db_lines
        if db_line.paymentrequest_id == line1.paymentrequest_id ][0]
    compare_paymentrequest_rows(line1, db_line1)
    db_line2 = [ db_line for db_line in db_lines
        if db_line.paymentrequest_id == line2.paymentrequest_id ][0]
    compare_paymentrequest_rows(line2, db_line2)

    # Read all PAID rows in the table.
    db_lines = db_functions.read_payment_requests(db_context, ACCOUNT_ID, mask=PaymentFlag.PAID)
    assert 1 == len(db_lines)
    assert 1 == db_lines[0].paymentrequest_id
    assert KEYINSTANCE_ID == db_lines[0].keyinstance_id

    # Read all UNPAID rows in the table.
    db_lines = db_functions.read_payment_requests(db_context, ACCOUNT_ID, mask=PaymentFlag.UNPAID)
    assert 1 == len(db_lines)
    assert 2 == db_lines[0].paymentrequest_id
    assert KEYINSTANCE_ID+1 == db_lines[0].keyinstance_id

    # Require ARCHIVED flag.
    db_lines = db_functions.read_payment_requests(db_context, ACCOUNT_ID, mask=PaymentFlag.ARCHIVED)
    assert 0 == len(db_lines)

    # Require no ARCHIVED flag.
    db_lines = db_functions.read_payment_requests(db_context, ACCOUNT_ID, flags=PaymentFlag.NONE,
        mask=PaymentFlag.ARCHIVED)
    assert 2 == len(db_lines)

    row = db_functions.read_payment_request(db_context, request_id=1)
    assert row is not None
    assert 1 == row.paymentrequest_id

    row = db_functions.read_payment_request(db_context, request_id=100101)
    assert row is None

    ## Pay the payment request.
    # Create the transaction and outputs.
    tx_rows = [ TransactionRow(tx_hash=TX_HASH, tx_bytes=TX_BYTES, flags=TxFlags.UNSET,
        block_hash=b'11', block_height=1, block_position=None, fee_value=2, description=None,
        version=None, locktime=None, date_created=1, date_updated=1) ]
    future = db_functions.create_transactions(db_context, tx_rows)
    future.result(timeout=5)

    txo_row1 = TransactionOutputShortRow(TX_HASH, TX_INDEX, 100, KEYINSTANCE_ID+1, TXOUT_FLAGS,
        ScriptType.P2PKH, b'')

    future = db_functions.create_transaction_outputs(db_context, [ txo_row1 ])
    future.result(timeout=5)

    account_transaction_entries = [
        AccountTransactionRow(ACCOUNT_ID, TX_HASH, AccountTxFlags.NONE, None),
    ]
    future = db_functions.create_account_transactions(db_context, account_transaction_entries)
    future.result()

    db = db_context.acquire_connection()
    try:
        closed_request_ids, updated_key_rows, transaction_description_update_rows = \
            db_functions._close_paid_payment_requests(db)
    finally:
        db_context.release_connection(db)
    assert closed_request_ids == { line2.paymentrequest_id }
    assert updated_key_rows == [ (ACCOUNT_ID, KEYINSTANCE_ID+1, KeyInstanceFlag.USED) ]
    assert transaction_description_update_rows == [ (TX_DESC2, ACCOUNT_ID, TX_HASH) ]

    ## Continue.
    future = db_functions.update_payment_requests(db_context, [ PaymentRequestUpdateRow(
        PaymentFlag.UNKNOWN, 20, 999, "newdesc", line2.paymentrequest_id) ])
    future.result()

    db_lines = db_functions.read_payment_requests(db_context, ACCOUNT_ID)
    assert 2 == len(db_lines)
    db_line2 = [ db_line for db_line in db_lines
        if db_line.paymentrequest_id == line2.paymentrequest_id ][0]
    assert db_line2.requested_value == 20
    assert db_line2.state == PaymentFlag.UNKNOWN
    assert db_line2.description == "newdesc"
    assert db_line2.expiration == 999

    # Account does not exist.
    db_lines = db_functions.read_payment_requests(db_context, 1000)
    assert 0 == len(db_lines)

    # This account is matched.
    db_lines = db_functions.read_payment_requests(db_context, ACCOUNT_ID)
    assert 2 == len(db_lines)

    future = db_functions.delete_payment_request(db_context, line1.paymentrequest_id,
        line1.keyinstance_id)
    future.result()

    db_lines = db_functions.read_payment_requests(db_context, ACCOUNT_ID)
    assert 1 == len(db_lines)
    assert db_lines[0].paymentrequest_id == line2.paymentrequest_id


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
    future = db_functions.create_master_keys(db_context,
        [ MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111') ])
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


@unittest.mock.patch('electrumsv.wallet_database.functions.get_posix_timestamp')
def test_table_invoice_crud(mock_get_posix_timestamp, db_context: DatabaseContext) -> None:
    mock_get_posix_timestamp.side_effect = lambda: 111

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
    future = db_functions.create_master_keys(db_context, [
        MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111') ])
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
        [ (PaymentFlag.NOT_ARCHIVED, PaymentFlag.ARCHIVED, line3_2.invoice_id), ])
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


def test_table_servers_CRUD(db_context: DatabaseContext) -> None:
    ACCOUNT_ID = 1
    SERVER_TYPE = NetworkServerType.ELECTRUMX
    UNUSED_SERVER_TYPE = NetworkServerType.MERCHANT_API
    date_updated = 1
    URL = "..."
    server_rows = [
        NetworkServerRow(URL, SERVER_TYPE, None, NetworkServerFlag.NONE,
            None, 0, 0, date_updated, date_updated),
    ]
    server_account_rows = [
        NetworkServerAccountRow(URL, SERVER_TYPE, ACCOUNT_ID, None, None, 0, 0, date_updated,
            date_updated)
    ]
    server_account_rows_no_server = [
        NetworkServerAccountRow(URL*2, SERVER_TYPE, ACCOUNT_ID, None, None, 0, 0, date_updated,
            date_updated)
    ]

    ## Verify that the NetworkServerRow entry is added.
    future = db_functions.update_network_servers(db_context, added_server_rows=server_rows)
    future.result(timeout=5)

    # Test the Accounts table foreign key.
    future = db_functions.update_network_servers(db_context,
        added_server_account_rows=server_account_rows)
    with pytest.raises(sqlite3.IntegrityError):
        future.result(timeout=5)

    ## Make the account and the masterkey row it requires to exist.
    if True:
        MASTERKEY_ID = 20

        # Satisfy the masterkey foreign key constraint by creating the masterkey.
        mk_row1 = MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111')
        future = db_functions.create_master_keys(db_context, [ mk_row1 ])
        future.result(timeout=5)

        line1 = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name1')
        future = db_functions.create_accounts(db_context, [ line1 ])
        future.result(timeout=5)

    # Test the Servers table foreign key causes an integrity error.
    future = db_functions.update_network_servers(db_context,
        added_server_account_rows=server_account_rows_no_server)
    with pytest.raises(sqlite3.IntegrityError):
        future.result(timeout=5)

    # Verify that the read picks up the added Servers row.
    read_server_rows, read_server_account_rows = db_functions.read_network_servers(db_context)
    assert len(read_server_rows) == 1
    assert len(read_server_account_rows) == 0
    # These columns are not read by the query.
    read_server_rows[0] = read_server_rows[0]._replace(date_created=date_updated,
        date_updated=date_updated)
    assert server_rows == read_server_rows

    # Verify that the NetworkServerAccountRows are added.
    if True:
        future = db_functions.update_network_servers(db_context,
            added_server_account_rows=server_account_rows)
        future.result(timeout=5)

        # Find the server row and account row.
        read_server_rows, read_server_account_rows = db_functions.read_network_servers(db_context)
        assert len(read_server_rows) == 1
        assert len(read_server_account_rows) == 1
        # These columns are not read by the query.
        read_server_account_rows[0] = read_server_account_rows[0]._replace(date_created=date_updated,
            date_updated=date_updated)
        assert server_account_rows == read_server_account_rows

    # Verify that the important NetworkServerRow columns are updated.
    if True:
        update_server_rows = [
            server_rows[0]._replace(flags=NetworkServerFlag.ANY_ACCOUNT, encrypted_api_key="key"),
        ]
        future = db_functions.update_network_servers(db_context,
            updated_server_rows=update_server_rows)
        future.result(timeout=5)

        # Find the server row and account row.
        read_server_rows, read_server_account_rows = db_functions.read_network_servers(db_context)
        assert len(read_server_rows) == 1
        assert len(read_server_account_rows) == 1
        # These columns are not read by the query.
        read_server_rows[0] = read_server_rows[0]._replace(date_created=date_updated,
            date_updated=date_updated)
        assert update_server_rows == read_server_rows
        # These columns are not read by the query.
        read_server_account_rows[0] = read_server_account_rows[0]._replace(
            date_created=date_updated, date_updated=date_updated)
        assert server_account_rows == read_server_account_rows

    # Verify that the important NetworkServerAccountRow columns are updated.
    if True:
        update_server_account_rows = [
            server_account_rows[0]._replace(encrypted_api_key="key"),
        ]
        future = db_functions.update_network_servers(db_context,
            updated_server_account_rows=update_server_account_rows)
        future.result(timeout=5)

        # Find the server row and account row.
        read_server_rows, read_server_account_rows = db_functions.read_network_servers(db_context)
        assert len(read_server_rows) == 1
        assert len(read_server_account_rows) == 1
        # These columns are not read by the query.
        read_server_rows[0] = read_server_rows[0]._replace(date_created=date_updated,
            date_updated=date_updated)
        assert update_server_rows == read_server_rows
        # These columns are not read by the query.
        read_server_account_rows[0] = read_server_account_rows[0]._replace(date_created=date_updated,
            date_updated=date_updated)
        assert update_server_account_rows == read_server_account_rows

    # Delete the Servers row and confirm the related ServerAccounts row is also deleted.
    if True:
        future = db_functions.update_network_servers(db_context,
            deleted_server_keys=[ ServerAccountKey(URL, SERVER_TYPE) ])
        future.result(timeout=5)

        read_server_rows, read_server_account_rows = db_functions.read_network_servers(db_context)
        assert len(read_server_rows) == 0
        assert len(read_server_account_rows) == 0

    # Restore the rows.
    future = db_functions.update_network_servers(db_context, added_server_rows=server_rows,
        added_server_account_rows=server_account_rows)
    future.result(timeout=5)

    # Verify that updating the server state works.
    if True:
        new_server_rows = [ server_rows[0]._replace(mapi_fee_quote_json="fee_quote_json",
            date_last_good=111111, date_last_try=22222) ]
        new_server_account_rows = [ server_account_rows[0]._replace(mapi_fee_quote_json="zzzz",
            date_last_try=555555) ]
        future = db_functions.update_network_server_states(db_context, new_server_rows,
            new_server_account_rows)
        future.result(timeout=5)

        read_server_rows, read_server_account_rows = db_functions.read_network_servers(db_context)
        assert len(read_server_rows) == 1
        assert len(read_server_account_rows) == 1

        # We need to adjust the new update rows for the row update date used by the database.
        new_server_rows = [ new_server_rows[0]._replace(
            date_updated=read_server_rows[0].date_updated) ]
        new_server_account_rows = [ new_server_account_rows[0]._replace(
            date_updated=read_server_account_rows[0].date_updated) ]

        assert read_server_rows == new_server_rows
        assert read_server_account_rows == new_server_account_rows

    # Verify that the deleting just the ServerAccounts row works too.
    if True:
        # Verify that deleting an unmatched Servers row does not delete the existing row.
        future = db_functions.update_network_servers(db_context,
            deleted_server_keys=[ ServerAccountKey(URL, UNUSED_SERVER_TYPE) ])
        future.result(timeout=5)

        # Verify that deleting an unmatched ServerAccounts row does not delete the existing row.
        future = db_functions.update_network_servers(db_context,
            deleted_server_account_keys=[ ServerAccountKey(URL, UNUSED_SERVER_TYPE, 1) ])
        future.result(timeout=5)

        read_server_rows, read_server_account_rows = db_functions.read_network_servers(db_context)
        assert len(read_server_rows) == 1
        assert len(read_server_account_rows) == 1

        # Verify that deleting an matched ServerAccounts row does delete the existing row.
        future = db_functions.update_network_servers(db_context,
            deleted_server_account_keys=[ ServerAccountKey(URL, SERVER_TYPE, 1) ])
        future.result(timeout=5)

        read_server_rows, read_server_account_rows = db_functions.read_network_servers(db_context)
        assert len(read_server_rows) == 1
        assert len(read_server_account_rows) == 0
