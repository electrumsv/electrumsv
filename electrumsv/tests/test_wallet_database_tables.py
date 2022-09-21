import os
import tempfile
from typing import cast, Generator, List, Optional
import unittest.mock

import bitcoinx
from electrumsv_database.sqlite import DatabaseContext, LeakedSQLiteConnectionError
import pytest

from ..util import get_posix_timestamp

try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore[no-redef]

from electrumsv.constants import (AccountFlags, AccountTxFlags, BlockHeight, DerivationType,
    KeyInstanceFlag, MAPIBroadcastFlag, MasterKeyFlags, NetworkServerFlag, NetworkServerType,
    PaymentFlag, PeerChannelMessageFlag, ScriptType, ServerPeerChannelFlag, TransactionOutputFlag,
    TxFlags, WalletEventFlag, WalletEventType)
from electrumsv.types import Outpoint, ServerAccountKey
from electrumsv.wallet_database.exceptions import DatabaseUpdateError
from electrumsv.wallet_database import functions as db_functions
from electrumsv.wallet_database import migration
from electrumsv.wallet_database.types import (AccountRow, AccountTransactionRow, InvoiceAccountRow,
    InvoiceRow, KeyInstanceRow, MAPIBroadcastRow, MasterKeyRow,
    MerkleProofRow, MerkleProofUpdateRow, NetworkServerRow, PaymentRequestOutputRow,
    PaymentRequestRow, PaymentRequestUpdateRow, ServerPeerChannelRow, PeerChannelMessageRow,
    TransactionOutputShortRow, TransactionProofUpdateRow, TransactionRow, WalletBalance,
    WalletEventInsertRow)

from .util import mock_headers, PasswordToken



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
    password_token = PasswordToken("123456")
    wallet_path = os.path.join(tempfile.mkdtemp(), "wallet_create")
    assert not os.path.exists(wallet_path)
    migration.create_database_file(wallet_path)

    with unittest.mock.patch(
        "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state") \
        as migration29_app_state:
            migration29_app_state.headers = mock_headers()
            migration.update_database_file(wallet_path, password_token)

    return DatabaseContext(wallet_path)

@pytest.fixture
def db_context() -> Generator[DatabaseContext, None, None]:
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



def test_table_masterkeys_CRUD(db_context: DatabaseContext) -> None:
    masterkey_rows = db_functions.read_masterkeys(db_context)
    assert len(masterkey_rows) == 2
    wallet_row = [ row for row in masterkey_rows if row.parent_masterkey_id is None ][0]
    petty_cash_row = [ row for row in masterkey_rows if row.parent_masterkey_id is not None ][0]
    assert wallet_row.flags == MasterKeyFlags.WALLET_SEED | MasterKeyFlags.ELECTRUM_SEED
    assert petty_cash_row.flags == MasterKeyFlags.NONE
    assert petty_cash_row.parent_masterkey_id == wallet_row.masterkey_id

    line1 = MasterKeyRow(3, None, DerivationType.ELECTRUM_MULTISIG, b'111',
        MasterKeyFlags.NONE)
    # Ensure that all fields persist.
    line2 = MasterKeyRow(4, None, DerivationType.BIP32_SUBPATH, b'222',
        MasterKeyFlags.ELECTRUM_SEED)

    future = db_functions.create_master_keys(db_context, [ line1 ])
    future.result(timeout=5)

    future = db_functions.create_master_keys(db_context, [ line2 ])
    future.result(timeout=5)

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_master_keys(db_context, [ line1 ])
        future.result(timeout=5)

    lines = db_functions.read_masterkeys(db_context)
    assert 4 == len(lines)
    line1_db = [ line for line in lines if line[0] == 3 ][0]
    line2_db = [ line for line in lines if line[0] == 4 ][0]
    assert line1 == line1_db
    assert line2 == line2_db

    # future = db_functions.update_masterkey_derivation_datas(db_context, [ (b'234', 1) ])
    # future.result()

    # masterkey_rows = db_functions.read_masterkeys(db_context)
    # masterkey_row1 = [ row for row in masterkey_rows if row.masterkey_id == 1 ][0]
    # assert masterkey_row1.derivation_data == b'234'


def test_table_accounts_CRUD(db_context: DatabaseContext) -> None:
    rows = db_functions.read_accounts(db_context)
    assert len(rows) == 1
    assert rows[0].flags == AccountFlags.IS_PETTY_CASH

    ACCOUNT_ID = 10
    MASTERKEY_ID = 20

    line1 = AccountRow(ACCOUNT_ID+1, MASTERKEY_ID+1, ScriptType.P2PKH, 'name1',
        AccountFlags.NONE, None, None)
    line2 = AccountRow(ACCOUNT_ID+2, MASTERKEY_ID+1, ScriptType.P2PK, 'name2',
        AccountFlags(1 << 20), None, None)

    # No effect: The masterkey foreign key constraint will fail as the masterkey does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_accounts(db_context, [ line1 ])
        future.result()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    mk_row1 = MasterKeyRow(MASTERKEY_ID+1, None, DerivationType.ELECTRUM_MULTISIG, b'111',
        MasterKeyFlags.NONE)
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
    assert 3 == len(db_lines)
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
    assert 3 == len(db_lines)
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
    masterkey1 = MasterKeyRow(MASTERKEY_ID_1, None, DerivationType.BIP32, b'111',
        MasterKeyFlags.NONE)
    masterkey2 = MasterKeyRow(MASTERKEY_ID_2, None, DerivationType.BIP32, b'222',
        MasterKeyFlags.NONE)

    future = db_functions.create_master_keys(db_context, [ masterkey1, masterkey2 ])
    future.result(timeout=5)

    # Create the accounts.
    account1 = AccountRow(ACCOUNT_ID_1, MASTERKEY_ID_1, ScriptType.P2PKH, 'name1',
        AccountFlags.NONE, None, None)
    account2 = AccountRow(ACCOUNT_ID_2, MASTERKEY_ID_2, ScriptType.P2PK, 'name2',
        AccountFlags.NONE, None, None)

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
        flags=TxFlags.STATE_SETTLED, block_hash=b'11', block_height=10,
        block_position=1, fee_value=250,
        description=None, version=None, locktime=None, date_created=1, date_updated=2)
    TX_BYTES_2 = os.urandom(10)
    TX_HASH_2 = bitcoinx.double_sha256(TX_BYTES_2)
    tx2 = TransactionRow(
        tx_hash=TX_HASH_2,
        tx_bytes=TX_BYTES_2,
        flags=TxFlags.STATE_SETTLED, block_hash=b'11', block_height=10,
        block_position=1, fee_value=250,
        description=None, version=None, locktime=None, date_created=1, date_updated=2)
    future = db_functions.create_transactions_UNITTEST(db_context, [ tx1, tx2 ])
    future.result(timeout=5)

    account_transaction_entries = [
        AccountTransactionRow(ACCOUNT_ID_1, TX_HASH_1, AccountTxFlags.NONE, None, 1, 1),
        AccountTransactionRow(ACCOUNT_ID_2, TX_HASH_2, AccountTxFlags.NONE, None, 1, 1),
    ]
    future = db_functions.create_account_transactions_UNITTEST(db_context,
        account_transaction_entries)
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

    account_ids = db_functions.read_account_ids_for_transaction(db_context, b"fake hash")
    assert account_ids == []

    account_ids = db_functions.read_account_ids_for_transaction(db_context, TX_HASH_1)
    assert account_ids == [ ACCOUNT_ID_1 ]

    account_ids = db_functions.read_account_ids_for_transaction(db_context, TX_HASH_2)
    assert account_ids == [ ACCOUNT_ID_2 ]


def test_table_keyinstances_CRUD(db_context: DatabaseContext) -> None:
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
        [ MasterKeyRow(MASTERKEY_ID+1, None, DerivationType.ELECTRUM_MULTISIG, b'111',
            MasterKeyFlags.NONE) ])
    future.result(timeout=5)

    # No effect: The account foreign key constraint will fail as the account does not exist.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_functions.create_keyinstances(db_context, [ line1 ])
        future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID+1, MASTERKEY_ID+1, ScriptType.P2PKH, 'name',
        AccountFlags.NONE, None, None)
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

    def test_create_read_various(self) -> None:
        assert self.db_context is not None

        transaction_bytes_1 = os.urandom(10)
        transaction_hash = bitcoinx.double_sha256(transaction_bytes_1)
        transaction_row = TransactionRow(tx_hash=transaction_hash, tx_bytes=transaction_bytes_1,
            flags=TxFlags.STATE_DISPATCHED,
            block_hash=b'11', block_height=BlockHeight.LOCAL, block_position=None, fee_value=None,
            description=None, version=None, locktime=None, date_created=1, date_updated=1)
        future = db_functions.create_transactions_UNITTEST(self.db_context, [ transaction_row ])
        future.result(timeout=5)

        # Check the state is correct, all states should be the same code path.
        read_flags = db_functions.read_transaction_flags(self.db_context, transaction_hash)
        assert read_flags is not None
        assert TxFlags.STATE_DISPATCHED == read_flags & TxFlags.MASK_STATE

        transaction_read_row = db_functions.read_transaction(self.db_context, transaction_hash)
        assert transaction_read_row is not None
        assert transaction_row == transaction_read_row

        transaction_read_bytes = db_functions.read_transaction_bytes(self.db_context,
            transaction_hash)
        assert transaction_bytes_1 == transaction_read_bytes

    def test_create_multiple(self) -> None:
        assert self.db_context is not None

        to_add = []
        for i in range(10):
            tx_bytes = os.urandom(10)
            tx_hash = bitcoinx.double_sha256(tx_bytes)
            to_add.append(
                TransactionRow(tx_hash=tx_hash, tx_bytes=tx_bytes, flags=TxFlags.UNSET,
                    block_hash=b'11', block_height=BlockHeight.LOCAL,
                    block_position=None, fee_value=2, description=None,
                    version=None, locktime=None, date_created=1, date_updated=1))
        future = db_functions.create_transactions_UNITTEST(self.db_context, to_add)
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
                block_hash=b'11', block_position=None, fee_value=2, block_height=BlockHeight.LOCAL,
                description=None, version=None, locktime=None, date_created=1, date_updated=1)
            future = db_functions.create_transactions_UNITTEST(self.db_context, [ tx_row ])
            future.result(timeout=5)
            get_tx_hashes.add(tx_hash)

        result_tx_hashes = set(self._get_store_hashes())
        assert get_tx_hashes == result_tx_hashes


def test_table_transactionproofs_CRUD(db_context: DatabaseContext) -> None:
    tx_bytes_1 = os.urandom(10)
    tx_hash_1 = bitcoinx.double_sha256(tx_bytes_1)
    tx_bytes_2 = os.urandom(10)
    tx_hash_2 = bitcoinx.double_sha256(tx_bytes_2)
    BLOCK_HASH_1 = b'block hash 1'
    BLOCK_HASH_2 = b'block hash 2'
    BLOCK_HASH_3 = b'block hash 3'
    BLOCK_HASH_4 = b'block hash 4'
    PROOF_DATA_1 = b'proof data 1'
    PROOF_DATA_2 = b'proof data 2'
    PROOF_DATA_3 = b'proof data 3'
    PROOF_DATA_4 = b'proof data 4'
    BLOCK_HEIGHT_1 = 1
    BLOCK_HEIGHT_1b = 101
    BLOCK_HEIGHT_2 = 2
    BLOCK_HEIGHT_2b = 102
    BLOCK_HEIGHT_3 = 3
    BLOCK_HEIGHT_4 = 4
    BLOCK_POSITION_1 = 11
    BLOCK_POSITION_2 = 12
    BLOCK_POSITION_3 = 13
    BLOCK_POSITION_4 = 14
    merkle_proof_row_1 = MerkleProofRow(BLOCK_HASH_1, BLOCK_POSITION_1, BLOCK_HEIGHT_1,
        PROOF_DATA_1, tx_hash_1)
    merkle_proof_row_2 = MerkleProofRow(BLOCK_HASH_2, BLOCK_POSITION_2, BLOCK_HEIGHT_2,
        PROOF_DATA_2, tx_hash_1)
    merkle_proof_row_3 = MerkleProofRow(BLOCK_HASH_3, BLOCK_POSITION_3, BLOCK_HEIGHT_3,
        PROOF_DATA_3, tx_hash_2)
    merkle_proof_row_4 = MerkleProofRow(BLOCK_HASH_4, BLOCK_POSITION_4, BLOCK_HEIGHT_4,
        PROOF_DATA_4, tx_hash_2)

    tx_row_1 = TransactionRow(tx_hash=tx_hash_1, tx_bytes=tx_bytes_1,
        flags=TxFlags.STATE_CLEARED, block_height=BlockHeight.MEMPOOL,
        block_hash=BLOCK_HASH_1, block_position=None, fee_value=None,
        description=None, version=None, locktime=None, date_created=1, date_updated=1)
    tx_row_2 = TransactionRow(tx_hash=tx_hash_2, tx_bytes=tx_bytes_2,
        flags=TxFlags.STATE_SIGNED, block_height=BlockHeight.LOCAL,
        block_hash=None, block_position=None, fee_value=None,
        description=None, version=None, locktime=None, date_created=1, date_updated=1)
    future = db_functions.create_transactions_UNITTEST(db_context, [ tx_row_1, tx_row_2 ])
    future.result(timeout=5)

    merkle_proof_rows = [ merkle_proof_row_1 ]
    db_connection = db_context.acquire_connection()
    try:
        # This should create the merkle proofs.
        db_functions.create_merkle_proofs_write(merkle_proof_rows, db_connection)

        # This should create the extra proof but leave the existing one alone.
        merkle_proof_rows.append(merkle_proof_row_2)
        db_functions.create_merkle_proofs_write(merkle_proof_rows, db_connection)

        proofs = db_functions.read_merkle_proofs(db_context, [ b'no match tx hash' ])
        assert len(proofs) == 0

        proofs = db_functions.read_merkle_proofs(db_context, [ tx_hash_1 ])
        assert len(proofs) == 2
        proofs_by_block_hash = { row.block_hash: row for row in proofs }
        assert BLOCK_HASH_1 in proofs_by_block_hash
        assert proofs_by_block_hash[BLOCK_HASH_1] == merkle_proof_row_1
        assert BLOCK_HASH_2 in proofs_by_block_hash
        assert proofs_by_block_hash[BLOCK_HASH_2] == merkle_proof_row_2

        # Update the block height for merkle proof 2.
        db_functions.update_merkle_proofs_write([ MerkleProofUpdateRow(BLOCK_HEIGHT_2b,
            BLOCK_HASH_2, tx_hash_1) ], db_connection)
        proofs = db_functions.read_merkle_proofs(db_context, [ tx_hash_1 ])
        assert len(proofs) == 2
        proofs_by_block_hash = { row.block_hash: row for row in proofs }
        assert proofs_by_block_hash[BLOCK_HASH_1] == merkle_proof_row_1
        assert proofs_by_block_hash[BLOCK_HASH_2] == merkle_proof_row_2._replace(
            block_height=BLOCK_HEIGHT_2b)

        proof_datas = db_functions.UNITTEST_read_transaction_proof_data(db_context, [])
        assert len(proof_datas) == 0
        proof_datas = db_functions.UNITTEST_read_transaction_proof_data(db_context, [ tx_hash_1 ])
        assert len(proof_datas) == 1
        assert proof_datas[0].flags == TxFlags.STATE_CLEARED
        assert proof_datas[0].block_hash == BLOCK_HASH_1
        assert proof_datas[0].proof_bytes == PROOF_DATA_1
        assert proof_datas[0].tx_block_height == BlockHeight.MEMPOOL
        assert proof_datas[0].tx_block_position is None
        assert proof_datas[0].proof_block_height == BLOCK_HEIGHT_1
        assert proof_datas[0].proof_block_position == BLOCK_POSITION_1

        # This is transaction 1, with block hash, no block position, STATE_CLEARED. Ready to
        # check that it gets a block height.
        unconnected_proofs = db_functions.read_unconnected_merkle_proofs(db_context)
        assert len(unconnected_proofs) == 1
        assert unconnected_proofs[0] == merkle_proof_row_1

        # Update transaction 2 to link to proof 3.
        # - Do the transaction block fields get updated?
        # - Does it get linked against the right proof?
        tx_proof_update_row = TransactionProofUpdateRow(merkle_proof_row_3.block_hash,
            merkle_proof_row_3.block_height, merkle_proof_row_3.block_position,
            TxFlags.STATE_SETTLED, 1, merkle_proof_row_3.tx_hash)
        # This updates the block_height on merkle proof 1 (for transaction 1) to BLOCK_HEIGHT_1b.
        proof_update_row = MerkleProofUpdateRow(BLOCK_HEIGHT_1b, BLOCK_HASH_1, tx_hash_1)
        db_functions.update_transaction_proof_write([ tx_proof_update_row ], [ merkle_proof_row_3,
            merkle_proof_row_4 ], [ proof_update_row ], [], db_connection)

        # Confirm the block_height on merkle proof 1 (for transaction 1) is BLOCK_HEIGHT_1b.
        proofs = db_functions.read_merkle_proofs(db_context, [ tx_hash_1 ])
        assert len(proofs) == 2
        proofs_by_block_hash = { row.block_hash: row for row in proofs }
        assert proofs_by_block_hash[BLOCK_HASH_1].block_height == BLOCK_HEIGHT_1b

        # Confirm that proof 3 is associated with tx 2.
        proof_datas = db_functions.UNITTEST_read_transaction_proof_data(db_context, [ tx_hash_2 ])
        assert len(proof_datas) == 1
        assert TxFlags(proof_datas[0].flags) == TxFlags.STATE_SETTLED
        assert proof_datas[0].block_hash == BLOCK_HASH_3
        assert proof_datas[0].proof_bytes == PROOF_DATA_3
        assert proof_datas[0].tx_block_height == BLOCK_HEIGHT_3
        assert proof_datas[0].tx_block_position == BLOCK_POSITION_3
        assert proof_datas[0].proof_block_height == BLOCK_HEIGHT_3
        assert proof_datas[0].proof_block_position == BLOCK_POSITION_3

        # This associates transaction 2 with merkle proof 4.
        # - Does the flag get combined?
        # - Do the transaction block fields get updated?
        # - Does it get linked against the right proof?
        tx_proof_update_row = TransactionProofUpdateRow(merkle_proof_row_4.block_hash,
            merkle_proof_row_4.block_height, merkle_proof_row_4.block_position,
            TxFlags.STATE_SETTLED, 1, tx_hash_2)
        flag_update_entry = (TxFlags(~TxFlags.PAYS_INVOICE), TxFlags.PAYS_INVOICE, tx_hash_2)
        db_functions.update_transaction_proof_and_flag_write([ tx_proof_update_row ],
            [ flag_update_entry ], db_connection)

        # Confirm that proof 4 is associated with tx 3.
        proof_datas = db_functions.UNITTEST_read_transaction_proof_data(db_context, [ tx_hash_2 ])
        assert len(proof_datas) == 1
        assert proof_datas[0].block_hash == BLOCK_HASH_4
        assert proof_datas[0].proof_bytes == PROOF_DATA_4
        assert proof_datas[0].tx_block_height == BLOCK_HEIGHT_4
        assert proof_datas[0].tx_block_position == BLOCK_POSITION_4
        assert proof_datas[0].proof_block_height == BLOCK_HEIGHT_4
        assert proof_datas[0].proof_block_position == BLOCK_POSITION_4
        assert TxFlags(proof_datas[0].flags) == TxFlags.STATE_SETTLED|TxFlags.PAYS_INVOICE
    finally:
        db_context.release_connection(db_connection)


def test_table_transactionoutputs_CRUD(db_context: DatabaseContext) -> None:
    TX_BYTES_COINBASE = os.urandom(100)
    TX_HASH_COINBASE = bitcoinx.double_sha256(TX_BYTES_COINBASE)
    TX_BYTES = os.urandom(100)
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
    BLOCK_HASH=b'bab'

    row1 = TransactionOutputShortRow(TX_HASH_COINBASE, TX_INDEX, 50, KEYINSTANCE_ID_1,
        TXOUT_FLAGS | TransactionOutputFlag.COINBASE | TransactionOutputFlag.COINBASE_IMMATURE,
        ScriptType.P2PKH, b'')
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
            flags=TxFlags.STATE_SETTLED, block_height=10,
            block_hash=BLOCK_HASH, block_position=None, fee_value=2, description=None,
            version=None, locktime=None, date_created=1, date_updated=1),
        TransactionRow(tx_hash=TX_HASH, tx_bytes=TX_BYTES, flags=TxFlags.STATE_CLEARED,
            block_height=BlockHeight.MEMPOOL, block_hash=None, block_position=None, fee_value=2,
            description=None, version=None, locktime=None, date_created=1, date_updated=1)
    ]
    future = db_functions.create_transactions_UNITTEST(db_context, tx_rows)
    future.result(timeout=5)

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context, [
        MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111',
            MasterKeyFlags.NONE) ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name',
        AccountFlags.NONE, None, None)
    future = db_functions.create_accounts(db_context, [ account_row ])
    future.result()

    future = db_functions.create_account_transactions_UNITTEST(db_context, [
        AccountTransactionRow(ACCOUNT_ID, TX_HASH, AccountTxFlags.NONE, None, 1, 1),
        AccountTransactionRow(ACCOUNT_ID, TX_HASH_COINBASE, AccountTxFlags.NONE, None, 1, 1),
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
        exclude_immature=True)
    assert len(txos_rows) == 2
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX+1

    # Manually clear the COINBASE_IMMATURE flag on the transaction output.
    future = db_functions.update_transaction_output_flags(db_context,
        [ Outpoint(TX_HASH_COINBASE, TX_INDEX) ], TransactionOutputFlag.NONE,
        TransactionOutputFlag(~TransactionOutputFlag.COINBASE_IMMATURE))
    future.result()

    txos_rows = db_functions.read_account_transaction_outputs_with_key_data(db_context, ACCOUNT_ID,
        exclude_immature=True)
    assert len(txos_rows) == 3
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    # Manually set the COINBASE_IMMATURE flag on the transaction output again.
    future = db_functions.update_transaction_output_flags(db_context,
        [ Outpoint(TX_HASH_COINBASE, TX_INDEX) ], TransactionOutputFlag.COINBASE_IMMATURE)
    future.result()

    # Verify that the `mature_height` parameter works for this method.
    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID, exclude_immature=True)
    assert len(txos_rows) == 2
    txos_rows.sort(key=lambda r: r.derivation_data2 or b'')
    assert txos_rows[0].tx_hash == TX_HASH and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX+1

    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID)
    assert len(txos_rows) == 3
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    # Manually clear the COINBASE_IMMATURE flag on the transaction output.
    future = db_functions.update_transaction_output_flags(db_context,
        [ Outpoint(TX_HASH_COINBASE, TX_INDEX) ], TransactionOutputFlag.NONE,
        TransactionOutputFlag(~TransactionOutputFlag.COINBASE_IMMATURE))
    future.result()

    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID)
    assert len(txos_rows) == 3
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    txos_rows = db_functions.read_account_transaction_outputs_with_key_and_tx_data(db_context,
        ACCOUNT_ID, exclude_immature=True)
    assert len(txos_rows) == 3
    assert txos_rows[0].tx_hash == TX_HASH_COINBASE and txos_rows[0].txo_index == TX_INDEX
    assert txos_rows[1].tx_hash == TX_HASH and txos_rows[1].txo_index == TX_INDEX
    assert txos_rows[2].tx_hash == TX_HASH and txos_rows[2].txo_index == TX_INDEX+1

    # Manually set the COINBASE_IMMATURE flag on the transaction output again.
    future = db_functions.update_transaction_output_flags(db_context,
        [ Outpoint(TX_HASH_COINBASE, TX_INDEX) ], TransactionOutputFlag.COINBASE_IMMATURE)
    future.result()

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
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID)
    assert balance == WalletBalance(0, row2.value + row3.value, row1.value, 0)
    balance = db_functions.read_wallet_balance(db_context)
    assert balance == WalletBalance(0, row2.value + row3.value, row1.value, 0)

    # Manually clear the COINBASE_IMMATURE flag on the transaction output.
    future = db_functions.update_transaction_output_flags(db_context,
        [ Outpoint(TX_HASH_COINBASE, TX_INDEX) ], TransactionOutputFlag.NONE,
        TransactionOutputFlag(~TransactionOutputFlag.COINBASE_IMMATURE))
    future.result()

    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_wallet_balance(db_context)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)

    ## We are going to freeze the output we do not plan to spend, and verify that it is factored
    ## into account and wallet balances.
    # Balances with no frozen TXO.
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)

    balance = db_functions.read_wallet_balance(db_context, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_wallet_balance(db_context, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)

    # Add a key flag. In this case `FROZEN`.
    future = db_functions.set_keyinstance_flags(db_context, [ KEYINSTANCE_ID_2 ],
        KeyInstanceFlag.FROZEN)
    future.result(timeout=5)

    # Balances with a frozen TXO present.
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row3.value, 0, 0)

    balance = db_functions.read_wallet_balance(db_context, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_wallet_balance(db_context, exclude_frozen=True)
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
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_account_balance(db_context, ACCOUNT_ID, exclude_frozen=True)
    assert balance == WalletBalance(row1.value, row3.value, 0, 0)

    balance = db_functions.read_wallet_balance(db_context, exclude_frozen=False)
    assert balance == WalletBalance(row1.value, row2.value + row3.value, 0, 0)
    balance = db_functions.read_wallet_balance(db_context, exclude_frozen=True)
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


@pytest.mark.asyncio
async def test_table_paymentrequests_CRUD(db_context: DatabaseContext) -> None:
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

    rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID)
    assert len(rows) == 0

    LINE_COUNT = 3
    dpp_invoice_id = "dpp_invoice_id"
    merchant_reference = "merchant_reference"
    dummy_encrypted_secure_key = "KEY"
    server_id = 1
    date_created = int(get_posix_timestamp())
    expiration = date_created + 60*60
    create_request1_row = PaymentRequestRow(1, PaymentFlag.PAID, None, expiration, TX_DESC1,
        server_id, dpp_invoice_id, merchant_reference, dummy_encrypted_secure_key, date_created,
        date_created)
    create_request1_output_row = PaymentRequestOutputRow(1, 0, 0, ScriptType.P2PKH, b"SCRIPT",
        b"PUSHDATAHASH", 111, KEYINSTANCE_ID, date_created, date_created)
    create_request2_row = PaymentRequestRow(2, PaymentFlag.UNPAID, 100, expiration, TX_DESC2,
        server_id, dpp_invoice_id, merchant_reference, dummy_encrypted_secure_key, date_created,
        date_created)
    create_request2_output_row = PaymentRequestOutputRow(2, 0, 0, ScriptType.P2PKH, b"SCRIPT",
        b"PUSHDATAHASH", 100, KEYINSTANCE_ID+1, date_created, date_created)

    # No effect: The transactionoutput foreign key constraint will fail as the key instance
    # does not exist.
    # NOTE(pysqlite3-binary) Different errors on Linux and Windows.
    #     Windows: "sqlite3.IntegrityError: FOREIGN KEY constraint failed"
    #     Linux:   "pysqlite3.dbapi2.OperationalError: FOREIGN KEY constraint failed"
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)):
        future = db_context.post_to_thread(db_functions.create_payment_request_write,
            create_request1_row, [ create_request1_output_row ])
        future.result()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context, [
        MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111',
            MasterKeyFlags.NONE) ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name',
        AccountFlags.NONE, None, None)
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

    future = db_context.post_to_thread(db_functions.create_payment_request_write,
        create_request1_row, [ create_request1_output_row ])
    future.result()

    future = db_context.post_to_thread(db_functions.create_payment_request_write,
        create_request2_row, [ create_request2_output_row ])
    future.result()

    # No effect: The primary key constraint will prevent any conflicting entry from being added.
    with pytest.raises(sqlite3.IntegrityError):
        future = db_context.post_to_thread(db_functions.create_payment_request_write,
            create_request1_row, [ create_request1_output_row ])
        future.result()

    def compare_paymentrequest_rows(row1: PaymentRequestRow, row2: PaymentRequestRow) -> None:
        # assert row1.keyinstance_id == row2.keyinstance_id
        assert row1.state == row2.state
        assert row1.requested_value == row2.requested_value
        assert row1.date_expires == row2.date_expires
        assert row1.description == row2.description
        # assert row1.script_type == row2.script_type
        # assert row1.pushdata_hash == row2.pushdata_hash
        assert -1 != row2.date_created

    # Read all rows in the table.
    db_request_rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID)
    assert 2 == len(db_request_rows)
    db_line1 = [ db_line for db_line in db_request_rows
        if db_line.paymentrequest_id == create_request1_row.paymentrequest_id ][0]
    compare_paymentrequest_rows(create_request1_row, db_line1)
    db_line2 = [ db_line for db_line in db_request_rows
        if db_line.paymentrequest_id == create_request2_row.paymentrequest_id ][0]
    compare_paymentrequest_rows(create_request2_row, db_line2)

    # Read all PAID rows in the table.
    db_request_rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID,
        mask=PaymentFlag.PAID)
    assert 1 == len(db_request_rows)
    assert create_request1_row.paymentrequest_id == db_request_rows[0].paymentrequest_id

    db_request_output_rows = db_functions.read_payment_request_outputs(db_context, [ 1 ])
    assert len(db_request_output_rows) == 1
    assert db_request_output_rows[0].keyinstance_id == KEYINSTANCE_ID

    # Read all UNPAID rows in the table.
    db_request_rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID,
        mask=PaymentFlag.UNPAID)
    assert 1 == len(db_request_rows)
    assert create_request2_row.paymentrequest_id == db_request_rows[0].paymentrequest_id

    db_request_output_rows = db_functions.read_payment_request_outputs(db_context,
        [ create_request2_row.paymentrequest_id ])
    assert len(db_request_output_rows) == 1
    assert db_request_output_rows[0].keyinstance_id == KEYINSTANCE_ID+1

    # Require ARCHIVED flag.
    db_request_rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID,
        mask=PaymentFlag.ARCHIVED)
    assert 0 == len(db_request_rows)

    # Require no ARCHIVED flag.
    db_request_rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID,
        flags=PaymentFlag.NONE, mask=PaymentFlag.ARCHIVED)
    assert 2 == len(db_request_rows)

    request_row, request_output_rows = db_functions.read_payment_request(db_context, request_id=1)
    assert request_row is not None
    assert 1 == request_row.paymentrequest_id

    request_row, request_output_rows = db_functions.read_payment_request(db_context,
        request_id=100101)
    assert request_row is None

    ## Pay the payment request.
    # Create the transaction and outputs.
    tx_rows = [ TransactionRow(tx_hash=TX_HASH, tx_bytes=TX_BYTES, flags=TxFlags.UNSET,
        block_height=BlockHeight.LOCAL,
        block_hash=b'11', block_position=None, fee_value=2, description=None,
        version=None, locktime=None, date_created=1, date_updated=1) ]
    future = db_functions.create_transactions_UNITTEST(db_context, tx_rows)
    future.result(timeout=5)

    txo_row1 = TransactionOutputShortRow(TX_HASH, TX_INDEX, 100, KEYINSTANCE_ID+1, TXOUT_FLAGS,
        ScriptType.P2PKH, b'')

    future = db_functions.create_transaction_outputs(db_context, [ txo_row1 ])
    future.result(timeout=5)

    account_transaction_entries = [
        AccountTransactionRow(ACCOUNT_ID, TX_HASH, AccountTxFlags.NONE, None, 1, 1),
    ]
    future = db_functions.create_account_transactions_UNITTEST(db_context,
        account_transaction_entries)
    future.result()

    assert create_request2_row.paymentrequest_id is not None
    db = db_context.acquire_connection()
    try:
        transaction_description_update_rows = \
            db_functions.close_paid_payment_request(create_request2_row.paymentrequest_id, db)
    finally:
        db_context.release_connection(db)
    assert transaction_description_update_rows == [ (TX_DESC2, ACCOUNT_ID, TX_HASH) ]

    ## Continue.
    assert create_request2_row.paymentrequest_id is not None
    future = db_context.post_to_thread(db_functions.update_payment_requests_write, [
        PaymentRequestUpdateRow(PaymentFlag.UNKNOWN, 20, 999, "newdesc", "newmerchantref",
        create_request2_row.paymentrequest_id) ])
    future.result()

    db_request_rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID)
    assert 2 == len(db_request_rows)
    db_line2 = [ db_line for db_line in db_request_rows
        if db_line.paymentrequest_id == create_request2_row.paymentrequest_id ][0]
    assert db_line2.requested_value == 20
    assert db_line2.state == PaymentFlag.UNKNOWN
    assert db_line2.description == "newdesc"
    assert db_line2.date_expires == 999

    # Account does not exist.
    db_request_rows = db_functions.read_payment_requests(db_context, account_id=1000)
    assert 0 == len(db_request_rows)

    # This account is matched.
    db_request_rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID)
    assert 2 == len(db_request_rows)

    assert create_request1_row.paymentrequest_id is not None
    future3 = db_context.post_to_thread(db_functions.delete_payment_request_write,
        create_request1_row.paymentrequest_id)
    keyinstance_ids_by_account_id = future3.result()
    assert { ACCOUNT_ID: [ KEYINSTANCE_ID ] } == keyinstance_ids_by_account_id

    db_request_rows = db_functions.read_payment_requests(db_context, account_id=ACCOUNT_ID)
    assert 1 == len(db_request_rows)
    assert db_request_rows[0].paymentrequest_id == create_request2_row.paymentrequest_id


def test_table_walletevents_CRUD(db_context: DatabaseContext) -> None:
    MASTERKEY_ID = 10
    ACCOUNT_ID = 10

    line1 = WalletEventInsertRow(WalletEventType.SEED_BACKUP_REMINDER, ACCOUNT_ID,
        WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, 1, 1)
    line2 = WalletEventInsertRow(WalletEventType.SEED_BACKUP_REMINDER, None,
        WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, 1, 1)

    # No effect: The transactionoutput foreign key constraint will fail as the key instance
    # does not exist.
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)):
        future = db_functions.create_wallet_events(db_context, [ line1 ])
        future.result()

    # Satisfy the masterkey foreign key constraint by creating the masterkey.
    future = db_functions.create_master_keys(db_context,
        [ MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111',
            MasterKeyFlags.NONE) ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name',
        AccountFlags.NONE, None, None)
    future = db_functions.create_accounts(db_context, [ account_row ])
    future.result()

    future = db_functions.create_wallet_events(db_context, [ line1, line2 ])
    lines = sorted(future.result(), key=lambda v: v.event_id)

    db_lines = db_functions.read_wallet_events(db_context)
    db_lines = sorted(db_lines, key=lambda v: v.event_id)
    assert lines == db_lines

    future = db_functions.update_wallet_event_flags(db_context,
        [ (WalletEventFlag.UNREAD, lines[1].event_id) ])
    future.result()

    db_lines = db_functions.read_wallet_events(db_context)
    db_lines = sorted(db_lines, key=lambda v: v.event_id)
    assert 2 == len(db_lines)
    assert lines[0] == db_lines[0]
    assert db_lines[1].event_flags == WalletEventFlag.UNREAD

    # Account does not exist.
    db_lines = db_functions.read_wallet_events(db_context, 1000)
    assert 0 == len(db_lines)

    # This account is matched.
    db_lines = db_functions.read_wallet_events(db_context, ACCOUNT_ID)
    assert 1 == len(db_lines)


@pytest.mark.asyncio
@unittest.mock.patch('electrumsv.wallet_database.functions.get_posix_timestamp')
async def test_table_invoice_CRUD(mock_get_posix_timestamp, db_context: DatabaseContext) -> None:
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
        MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111',
            MasterKeyFlags.NONE) ])
    future.result(timeout=5)

    # Satisfy the account foreign key constraint by creating the account.
    account_row1 = AccountRow(ACCOUNT_ID_1, MASTERKEY_ID, ScriptType.P2PKH, 'name1',
        AccountFlags.NONE, None, None)
    account_row2 = AccountRow(ACCOUNT_ID_2, MASTERKEY_ID, ScriptType.P2PKH, 'name2',
        AccountFlags.NONE, None, None)
    future = db_functions.create_accounts(db_context, [ account_row1, account_row2 ])
    future.result()

    txs = []
    for txh, txb in ((TX_HASH_1, TX_BYTES_1), (TX_HASH_2, TX_BYTES_2), (TX_HASH_3, TX_BYTES_3)):
        tx = TransactionRow(tx_hash=txh, tx_bytes=txb, flags=TxFlags.STATE_SETTLED,
            block_height=10, block_hash=b'11', block_position=1, fee_value=250,
            description=None, version=None, locktime=None, date_created=1, date_updated=2)
        txs.append(tx)
    future = db_functions.create_transactions_UNITTEST(db_context, txs)
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
    assert row is not None
    assert row.tx_hash is None

    future = db_functions.update_invoice_descriptions(db_context,
        [ ("newdesc3.2", line3_2.invoice_id) ])
    future.result()

    # Verify the invoice now has the new description.
    row = db_functions.read_invoice(db_context, invoice_id=line3_2.invoice_id)
    assert row is not None
    assert row.description == "newdesc3.2"

    await db_context.run_in_thread_async(db_functions.update_invoice_flags,
        [ (PaymentFlag.NOT_ARCHIVED, PaymentFlag.ARCHIVED, line3_2.invoice_id), ])

    # Verify the invoice now has the new description.
    row = db_functions.read_invoice(db_context, invoice_id=line3_2.invoice_id)
    assert row is not None
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


def test_table_peer_channels_CRUD(db_context: DatabaseContext) -> None:
    date_created = 1

    # Ensure that the foreign key requirement for an existing server is met.
    server_row = NetworkServerRow(None, NetworkServerType.GENERAL, "url", None,
        NetworkServerFlag.NONE, None, None, None, None, None, 0, 0, date_created, date_created)
    future = db_functions.update_network_servers_transaction(db_context, [ server_row ], [], [], [])
    created_server_rows = future.result()
    assert len(created_server_rows) == 1
    server_id = created_server_rows[0].server_id
    assert server_id is not None

    # Check that the foreign key constraint fails on the insert with a non-existing server id.
    create_row = ServerPeerChannelRow(None, 23, None, None, ServerPeerChannelFlag.ALLOCATING,
        date_created, date_created)
    future = db_context.post_to_thread(db_functions.create_server_peer_channel_write,
        create_row)
    # NOTE(pysqlite3-binary) Different errors on Linux and Windows.
    #     Windows: "sqlite3.IntegrityError: FOREIGN KEY constraint failed"
    #     Linux:   "pysqlite3.dbapi2.OperationalError: FOREIGN KEY constraint failed"
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)):
        future.result()

    # Check that a valid insert succeeds.
    create_row = ServerPeerChannelRow(None, server_id, None, None, ServerPeerChannelFlag.ALLOCATING,
        date_created, date_created)
    future = db_context.post_to_thread(db_functions.create_server_peer_channel_write,
        create_row)
    peer_channel_id = future.result()
    assert type(peer_channel_id) is int
    created_row = create_row._replace(peer_channel_id=peer_channel_id)

    # Check that a read produces the same result as the insert.
    read_rows = db_functions.read_server_peer_channels(db_context, server_id)
    assert len(read_rows) == 1
    read_row = read_rows[0]
    assert read_row == created_row


def test_table_peer_channel_messages_CRUD(db_context: DatabaseContext) -> None:
    date_created = 1

    # Ensure that the foreign key requirement for an existing server is met.
    server_row = NetworkServerRow(None, NetworkServerType.GENERAL, "url", None,
        NetworkServerFlag.NONE, None, None, None, None, None, 0, 0, date_created, date_created)
    future = db_functions.update_network_servers_transaction(db_context, [ server_row ], [], [], [])
    created_server_rows = future.result()
    assert len(created_server_rows) == 1
    server_id = created_server_rows[0].server_id
    assert server_id is not None

    # CHANNEL: Check that a valid insert succeeds.
    create_channel_row1 = ServerPeerChannelRow(None, server_id, "remote id", None,
        ServerPeerChannelFlag.TIP_FILTER_DELIVERY, date_created,
        date_created)
    create_channel_future = db_context.post_to_thread(db_functions.create_server_peer_channel_write,
        create_channel_row1, server_id)
    peer_channel_id1 = create_channel_future.result()
    assert type(peer_channel_id1) is int

    # MESSAGE: Create an arbitrary test message.
    sequence = 111
    create_message_row = PeerChannelMessageRow(None, peer_channel_id1, b'abc',
        PeerChannelMessageFlag.NONE, sequence, date_created, date_created, date_created)
    future2 = db_context.post_to_thread(db_functions.create_server_peer_channel_messages_write,
        [ create_message_row ])
    created_message_rows1 = future2.result()
    assert len(created_message_rows1) == 1
    assert created_message_rows1[0].message_id is not None

    # MESSAGE: Verify the created result for the arbitrary test message has the expected contents.
    updated_create_message_row = create_message_row._replace(
        message_id=created_message_rows1[0].message_id)
    assert created_message_rows1[0] == updated_create_message_row

    # CHANNEL: Create a second channel to aid in testing filtering.
    create_channel_row2 = ServerPeerChannelRow(None, server_id, None, None,
        ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK | ServerPeerChannelFlag.ALLOCATING,
        date_created, date_created)
    create_channel_future = db_context.post_to_thread(db_functions.create_server_peer_channel_write,
        create_channel_row2)
    peer_channel_id2 = create_channel_future.result()

    # MESSAGE: Create an arbitrary test message.
    future2 = db_context.post_to_thread(db_functions.create_server_peer_channel_messages_write, [
        PeerChannelMessageRow(None, peer_channel_id2, b'abc',
            PeerChannelMessageFlag.NONE, sequence+1, date_created, date_created, date_created),
        PeerChannelMessageRow(None, peer_channel_id2, b'abc',
            PeerChannelMessageFlag.UNPROCESSED, sequence+2, date_created, date_created,
                date_created),
    ])
    created_message_rows2 = future2.result()
    assert len(created_message_rows2) == 2

    # MESSAGES: No filtering.
    read_rows = db_functions.read_server_peer_channel_messages(db_context, None, None, None, None)
    assert len(read_rows) == 3
    assert { message_row.message_id for message_row in read_rows } == \
        { created_message_rows1[0].message_id, created_message_rows2[0].message_id,
            created_message_rows2[1].message_id }

    # MESSAGES: Filter by server peer channel flag.
    read_rows = db_functions.read_server_peer_channel_messages(db_context,
        PeerChannelMessageFlag.NONE, PeerChannelMessageFlag.NONE,
        ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK, ServerPeerChannelFlag.MASK_PURPOSE)
    assert len(read_rows) == 2
    assert { message_row.message_id for message_row in read_rows } == \
        { created_message_rows2[0].message_id, created_message_rows2[1].message_id }

    # MESSAGES: Filter by server peer channel flag.
    read_rows = db_functions.read_server_peer_channel_messages(db_context,
        PeerChannelMessageFlag.UNPROCESSED, PeerChannelMessageFlag.UNPROCESSED,
        ServerPeerChannelFlag.NONE, ServerPeerChannelFlag.NONE)
    assert len(read_rows) == 1
    assert read_rows[0].message_id == [ message_row for message_row in created_message_rows2
        if message_row.message_flags & PeerChannelMessageFlag.UNPROCESSED ][0].message_id


def test_read_proofless_transactions(db_context: DatabaseContext) -> None:
    """
    This test creates the desired non-matches and all the desired matches and verifies that
    the `read_proofless_transactions` database function only returns the correct matches.
    """
    ACCOUNT1_ID = 10
    ACCOUNT2_ID = 11
    ACCOUNT3_ID = 12
    MASTERKEY1_ID = 20
    MASTERKEY2_ID = 21
    MASTERKEY3_ID = 22

    # Do the preparation so we can create accounts / satisfy the related foreign keys.
    mk_row1 = MasterKeyRow(MASTERKEY1_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111',
        MasterKeyFlags.NONE)
    mk_row2 = MasterKeyRow(MASTERKEY2_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111',
        MasterKeyFlags.NONE)
    mk_row3 = MasterKeyRow(MASTERKEY3_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111',
        MasterKeyFlags.NONE)
    future = db_functions.create_master_keys(db_context, [ mk_row1, mk_row2, mk_row3 ])
    future.result(timeout=5)

    account_row1 = AccountRow(ACCOUNT1_ID, MASTERKEY1_ID, ScriptType.P2PKH, 'name1',
        AccountFlags.NONE, None, None)
    account_row2 = AccountRow(ACCOUNT2_ID, MASTERKEY2_ID, ScriptType.P2PK, 'name2',
        AccountFlags.NONE, None, None)
    account_row3 = AccountRow(ACCOUNT3_ID, MASTERKEY3_ID, ScriptType.P2PK, 'name2',
        AccountFlags.NONE, None, None)
    future = db_functions.create_accounts(db_context, [ account_row1, account_row2, account_row3 ])
    future.result()

    # Create the transactions.
    tx_rows: list[TransactionRow] = []
    TX_BYTES_SETTLED_MATCH1 = os.urandom(10)
    TX_HASH_SETTLED_MATCH1 = bitcoinx.double_sha256(TX_BYTES_SETTLED_MATCH1)
    tx_settled_match1 = TransactionRow(
        tx_hash=TX_HASH_SETTLED_MATCH1,
        tx_bytes=TX_BYTES_SETTLED_MATCH1,
        flags=TxFlags.STATE_SETTLED, block_hash=None, block_height=10,
        block_position=None, fee_value=None,
        description=None, version=None, locktime=None, date_created=1, date_updated=2)
    TX_BYTES_SETTLED_MATCH2 = os.urandom(10)
    TX_HASH_SETTLED_MATCH2 = bitcoinx.double_sha256(TX_BYTES_SETTLED_MATCH2)
    tx_settled_match2 = TransactionRow(
        tx_hash=TX_HASH_SETTLED_MATCH2,
        tx_bytes=TX_BYTES_SETTLED_MATCH2,
        flags=TxFlags.STATE_SETTLED, block_hash=None, block_height=10,
        block_position=None, fee_value=None,
        description=None, version=None, locktime=None, date_created=2, date_updated=2)
    TX_BYTES_SETTLED_IGNORED = os.urandom(10)
    TX_HASH_SETTLED_IGNORED = bitcoinx.double_sha256(TX_BYTES_SETTLED_IGNORED)
    tx_settled_ignored = TransactionRow(
        tx_hash=TX_HASH_SETTLED_IGNORED,
        tx_bytes=TX_BYTES_SETTLED_IGNORED,
        flags=TxFlags.STATE_SETTLED, block_hash=b'ddddd', block_height=10,
        block_position=None, fee_value=None,
        description=None, version=None, locktime=None, date_created=2, date_updated=2)
    TX_BYTES_CLEARED_IGNORED = os.urandom(10)
    TX_HASH_CLEARED_IGNORED = bitcoinx.double_sha256(TX_BYTES_CLEARED_IGNORED)
    tx_cleared_ignored = TransactionRow(
        tx_hash=TX_HASH_CLEARED_IGNORED,
        tx_bytes=TX_BYTES_CLEARED_IGNORED,
        flags=TxFlags.STATE_CLEARED, block_hash=None, block_height=BlockHeight.MEMPOOL,
        block_position=None, fee_value=None,
        description=None, version=None, locktime=None, date_created=2, date_updated=2)
    TX_BYTES_CLEARED_MATCH1 = os.urandom(10)
    TX_HASH_CLEARED_MATCH1 = bitcoinx.double_sha256(TX_BYTES_CLEARED_MATCH1)
    tx_cleared_match1 = TransactionRow(
        tx_hash=TX_HASH_CLEARED_MATCH1,
        tx_bytes=TX_BYTES_CLEARED_MATCH1,
        flags=TxFlags.STATE_CLEARED, block_hash=b'fake block hash',
        block_height=BlockHeight.MEMPOOL,
        block_position=None, fee_value=None,
        description=None, version=None, locktime=None, date_created=2, date_updated=2)

    tx_nonmatches: List[TransactionRow] = []
    tx_nonmatches_orphans: List[TransactionRow] = []
    for tx_state in (TxFlags.UNSET, TxFlags.STATE_CLEARED, TxFlags.STATE_RECEIVED,
            TxFlags.STATE_SETTLED):
        for is_orphan in (True, False):
            TX_BYTES_NONMATCH = f"nonmatch is_orphan={is_orphan} flags={tx_state!r}".encode()
            TX_HASH_NONMATCH = TX_BYTES_NONMATCH
            # proof_data: Optional[bytes] = None
            block_hash: Optional[bytes] = None
            block_position: Optional[int] = None
            block_height = BlockHeight.LOCAL
            if tx_state == TxFlags.STATE_CLEARED:
                block_height = BlockHeight.MEMPOOL
            elif tx_state == TxFlags.STATE_SETTLED:
                block_position = 111
                block_hash = b'ignored block hash'
                block_height = 10
                # proof_data = b'nonmatch settled proof data'
            tx_nonmatch = TransactionRow(
                tx_hash=TX_HASH_NONMATCH,
                tx_bytes=TX_BYTES_NONMATCH,
                flags=tx_state, block_hash=block_hash, block_height=block_height,
                block_position=block_position, fee_value=None,
                description=None, version=None, locktime=None, date_created=2, date_updated=2)
            if is_orphan:
                tx_nonmatches_orphans.append(tx_nonmatch)
            else:
                tx_nonmatches.append(tx_nonmatch)
    tx_rows.extend(tx_nonmatches)
    tx_rows.extend(tx_nonmatches_orphans)
    tx_rows.extend([ tx_settled_match1, tx_settled_match2, tx_settled_ignored,
        tx_cleared_ignored, tx_cleared_match1 ])

    future = db_functions.create_transactions_UNITTEST(db_context, tx_rows)
    future.result(timeout=5)

    # Link the first transaction to both accounts.
    tx1a1 = AccountTransactionRow(ACCOUNT1_ID, TX_HASH_SETTLED_MATCH1, AccountTxFlags.NONE, None,
        20, 20)
    tx1a2 = AccountTransactionRow(ACCOUNT2_ID, TX_HASH_SETTLED_MATCH1, AccountTxFlags.NONE, None,
        10, 10)
    tx1a3 = AccountTransactionRow(ACCOUNT3_ID, TX_HASH_SETTLED_MATCH1, AccountTxFlags.NONE, None,
        30, 30)
    tx2a1 = AccountTransactionRow(ACCOUNT1_ID, TX_HASH_SETTLED_MATCH2, AccountTxFlags.NONE, None,
        5, 5)
    atx_settled_ignored = AccountTransactionRow(ACCOUNT1_ID, TX_HASH_SETTLED_IGNORED,
        AccountTxFlags.NONE, None, 1, 1)
    atx_cleared_ignored = AccountTransactionRow(ACCOUNT1_ID, TX_HASH_CLEARED_IGNORED,
        AccountTxFlags.NONE, None, 1, 1)
    atx_nonmatches: list[AccountTransactionRow]= []
    for tx_nonmatch in tx_nonmatches:
        atx_nonmatch = AccountTransactionRow(ACCOUNT1_ID, tx_nonmatch.tx_hash,
            AccountTxFlags.NONE, None, 1, 1)
        atx_nonmatches.append(atx_nonmatch)
    atx_cleared_match1 = AccountTransactionRow(ACCOUNT1_ID, TX_HASH_CLEARED_MATCH1,
        AccountTxFlags.NONE, None, 1, 1)
    atx_rows: list[AccountTransactionRow] = [ tx1a1, tx1a2, tx1a3,
        tx2a1, atx_settled_ignored, atx_cleared_ignored, atx_cleared_match1 ]
    atx_rows.extend(atx_nonmatches)
    future = db_functions.create_account_transactions_UNITTEST(db_context, atx_rows)
    future.result(timeout=5)

    # tx1 is linked to accounts 2, 3, 1 in that order, so should be associated with 2.
    # tx2 is linked to account 1 only, so should be associated with 1.
    # Others are not linked to any account, so should be not be matched.
    rows = db_functions.read_proofless_transactions(db_context)
    expected_tx_hashes: dict[bytes, int] = {
        TX_HASH_SETTLED_MATCH1: ACCOUNT2_ID,
        TX_HASH_SETTLED_MATCH2: ACCOUNT1_ID,
        TX_HASH_CLEARED_MATCH1: ACCOUNT1_ID,
    }
    remaining_tx_hashes = dict(expected_tx_hashes)
    print(rows)
    for pltx_row in rows:
        assert pltx_row.tx_hash in remaining_tx_hashes
        assert pltx_row.account_id == remaining_tx_hashes[pltx_row.tx_hash]
        del remaining_tx_hashes[pltx_row.tx_hash]
    assert remaining_tx_hashes == {}


def test_table_servers_CRUD(db_context: DatabaseContext) -> None:
    SERVER_ID = 1
    ACCOUNT_ID = 10
    SERVER_TYPE = NetworkServerType.GENERAL
    UNUSED_SERVER_TYPE = NetworkServerType.MERCHANT_API
    date_updated = 1
    URL = "..."
    server_rows = [
        NetworkServerRow(SERVER_ID+1, SERVER_TYPE, URL*1, None, NetworkServerFlag.NONE,
            None, None, None, None, None, 0, 0, date_updated, date_updated),
    ]
    server_account_rows = [
        NetworkServerRow(SERVER_ID+2, SERVER_TYPE, URL*1, ACCOUNT_ID, NetworkServerFlag.NONE,
            None, None, None, None, None, 0, 0, date_updated, date_updated)
    ]

    ## Server row creation.

    # Nothing should prevent creation of the given server row.
    update_future = db_functions.update_network_servers_transaction(db_context, server_rows, [],
        [], [])
    created_server_rows = update_future.result(timeout=5)
    assert len(created_server_rows) == 1
    modified_source_row = server_rows[0]._replace(server_id=created_server_rows[0].server_id)
    assert modified_source_row == created_server_rows[0]

    # Verify that the read picks up the added Servers row.
    read_rows = db_functions.read_network_servers(db_context)
    assert len(read_rows) == 1
    read_server_rows = [ row for row in read_rows if row.account_id is None ]
    assert len(read_server_rows) == 1
    read_server_account_rows = [ row for row in read_rows if row.account_id is not None ]
    assert len(read_server_account_rows) == 0

    # These columns are not read by the query.
    read_server_rows[0] = read_server_rows[0]._replace(date_created=date_updated,
        date_updated=date_updated)
    assert server_rows == read_server_rows

    # Creating the server again should fail as the given url/server type/account is in use now.
    update_future = db_functions.update_network_servers_transaction(db_context, server_rows, [],
        [], [])
    with pytest.raises(sqlite3.IntegrityError):
        update_future.result(timeout=5)

    ## Server account row creation.

    # Creating the server account rows should fail as the referenced account existing with the
    # given id.
    update_future = db_functions.update_network_servers_transaction(db_context,
        server_account_rows, [], [], [])
    # NOTE(pysqlite3-binary) Different errors on Linux and Windows.
    #     Windows: "sqlite3.IntegrityError: FOREIGN KEY constraint failed"
    #     Linux:   "pysqlite3.dbapi2.OperationalError: FOREIGN KEY constraint failed"
    with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)):
        update_future.result(timeout=5)

    # Make the account and the masterkey row `server_account_rows` requires to exist.
    if True:
        MASTERKEY_ID = 20

        # Satisfy the masterkey foreign key constraint by creating the masterkey.
        mk_row1 = MasterKeyRow(MASTERKEY_ID, None, DerivationType.ELECTRUM_MULTISIG, b'111',
            MasterKeyFlags.NONE)
        masterkey_future = db_functions.create_master_keys(db_context, [ mk_row1 ])
        masterkey_future.result(timeout=5)

        line1 = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, 'name1',
            AccountFlags.NONE, None, None)
        account_future = db_functions.create_accounts(db_context, [ line1 ])
        account_future.result(timeout=5)

    # Verify that the server rows with accounts are added correctly.
    update_future = db_functions.update_network_servers_transaction(db_context,
        server_account_rows, [], [], [])
    created_account_rows = update_future.result(timeout=5)
    assert len(created_account_rows) == 1
    modified_source_row = server_account_rows[0]._replace(
        server_id=created_account_rows[0].server_id)
    assert modified_source_row == created_account_rows[0]

    # Find the server row and account row.
    read_rows = db_functions.read_network_servers(db_context)
    assert len(read_rows) == 2
    read_server_rows = [ row for row in read_rows if row.account_id is None ]
    assert len(read_server_rows) == 1
    read_server_account_rows = [ row for row in read_rows if row.account_id is not None ]
    assert len(read_server_account_rows) == 1
    # These columns are not read by the query.
    read_server_account_rows[0] = read_server_account_rows[0]._replace(
        date_created=date_updated, date_updated=date_updated)
    assert server_account_rows == read_server_account_rows

    # Verify that the important NetworkServerRow columns are updated.
    if True:
        update_server_rows = [
            server_rows[0]._replace(server_id=created_server_rows[0].server_id,
                server_flags=NetworkServerFlag.ENABLED, encrypted_api_key="key"),
        ]
        update_future = db_functions.update_network_servers_transaction(db_context, [],
            update_server_rows, [], [])
        update_future.result(timeout=5)

        # Find the server row and account row.
        read_rows = db_functions.read_network_servers(db_context)
        assert len(read_rows) == 2
        read_server_rows = [ row for row in read_rows if row.account_id is None ]
        assert len(read_server_rows) == 1
        read_server_account_rows = [ row for row in read_rows if row.account_id is not None ]
        assert len(read_server_account_rows) == 1
        # These columns are not read by the query.
        read_server_rows[0] = read_server_rows[0]._replace(date_created=date_updated,
            date_updated=date_updated)
        assert update_server_rows == read_server_rows
        # These columns are not read by the query.
        read_server_account_rows[0] = read_server_account_rows[0]._replace(
            date_created=date_updated, date_updated=date_updated)
        assert server_account_rows == read_server_account_rows

    # Verify that the important server rows with account columns are updated.
    if True:
        update_server_account_rows = [
            server_account_rows[0]._replace(encrypted_api_key="key"),
        ]
        update_future = db_functions.update_network_servers_transaction(db_context,
            [], update_server_account_rows, [], [])
        update_future.result(timeout=5)

        # Find the server row and account row.
        read_rows = db_functions.read_network_servers(db_context)
        assert len(read_rows) == 2
        read_server_rows = [ row for row in read_rows if row.account_id is None ]
        assert len(read_server_rows) == 1
        read_server_account_rows = [ row for row in read_rows if row.account_id is not None ]
        assert len(read_server_account_rows) == 1
        # These columns are not read by the query.
        read_server_rows[0] = read_server_rows[0]._replace(date_created=date_updated,
            date_updated=date_updated)
        assert update_server_rows == read_server_rows
        # These columns are not read by the query.
        read_server_account_rows[0] = read_server_account_rows[0]._replace(
            date_created=date_updated, date_updated=date_updated)
        assert update_server_account_rows == read_server_account_rows

    # Delete the both rows by id.
    if True:
        assert created_server_rows[0].server_id is not None
        assert created_account_rows[0].server_id is not None
        update_future = db_functions.update_network_servers_transaction(db_context, [], [],
            [ created_server_rows[0].server_id, created_account_rows[0].server_id ], [])
        update_future.result(timeout=5)

        read_rows = db_functions.read_network_servers(db_context)
        assert len(read_rows) == 0

        # Restore the rows.
        future = db_functions.update_network_servers_transaction(db_context,
            server_rows + server_account_rows, [], [], [])
        future.result(timeout=5)

    # Delete the both rows by key.
    if True:
        delete_key = ServerAccountKey.from_row(created_server_rows[0])
        update_future = db_functions.update_network_servers_transaction(db_context, [], [], [],
            [ delete_key ])
        update_future.result(timeout=5)

        read_rows = db_functions.read_network_servers(db_context)
        assert len(read_rows) == 0

        # Restore the rows.
        future = db_functions.update_network_servers_transaction(db_context,
            server_rows + server_account_rows, [], [], [])
        future.result(timeout=5)

    # Verify that updating the server state works.
    if True:
        new_server_rows = [ server_rows[0]._replace(mapi_fee_quote_json="fee_quote_json",
            date_last_good=111111, date_last_try=22222) ]
        new_server_account_rows = [ server_account_rows[0]._replace(
            mapi_fee_quote_json="fee_quote_zzzz", date_last_good=0, date_last_try=555555) ]
        update_future = db_functions.update_network_servers(db_context, new_server_rows +
            new_server_account_rows)
        update_future.result(timeout=5)

        read_rows = db_functions.read_network_servers(db_context)
        assert len(read_rows) == 2
        read_server_rows = [ row for row in read_rows if row.account_id is None ]
        assert len(read_server_rows) == 1
        read_server_account_rows = [ row for row in read_rows if row.account_id is not None ]
        assert len(read_server_account_rows) == 1

        read_row = read_server_rows[0]
        assert read_row.server_id == server_rows[0].server_id
        assert read_row.mapi_fee_quote_json == "fee_quote_json"
        assert read_row.date_last_good == 111111
        assert read_row.date_last_try == 22222

        read_row = read_server_account_rows[0]
        assert read_row.server_id == server_account_rows[0].server_id
        assert read_row.mapi_fee_quote_json == "fee_quote_zzzz"
        assert read_row.date_last_good == 0
        assert read_row.date_last_try == 555555

    # Verify that deleting an unmatched row does not delete existing rows.
    if True:
        future = db_functions.update_network_servers_transaction(db_context, [], [],
            [ 1343211 ], [])
        with pytest.raises(DatabaseUpdateError):
            future.result(timeout=5)


def test_table_mapi_broadcast_callbacks_CRUD(db_context: DatabaseContext) -> None:
    date_created = 1
    date_updated = 1
    MAPI_STATUS_FLAGS1 = MAPIBroadcastFlag.NONE
    MAPI_STATUS_FLAGS2 = MAPIBroadcastFlag.BROADCAST

    # Create transactions to be the foreign key entries for the broadcast rows.
    if True:
        TX_BYTES_1 = os.urandom(10)
        TX_HASH_1 = bitcoinx.double_sha256(TX_BYTES_1)
        tx1 = TransactionRow(
            tx_hash=TX_HASH_1,
            tx_bytes=TX_BYTES_1,
            flags=TxFlags.STATE_SETTLED, block_hash=b'11', block_height=10,
            block_position=1, fee_value=250,
            description=None, version=None, locktime=None, date_created=1, date_updated=2)

        TX_BYTES_2 = os.urandom(10)
        TX_HASH_2 = bitcoinx.double_sha256(TX_BYTES_2)
        tx2 = TransactionRow(
            tx_hash=TX_HASH_2,
            tx_bytes=TX_BYTES_2,
            flags=TxFlags.STATE_SETTLED, block_hash=b'11', block_height=10,
            block_position=1, fee_value=250,
            description=None, version=None, locktime=None, date_created=1, date_updated=2)

        future = db_functions.create_transactions_UNITTEST(db_context, [ tx1, tx2 ])
        future.result(timeout=5)

    # Create a server to be the foreign key entry for the broadcast rows.
    if True:
        SERVER_ID = 1
        SERVER_TYPE = NetworkServerType.GENERAL
        date_updated = 1
        URL = "..."
        server_rows = [
            NetworkServerRow(SERVER_ID, SERVER_TYPE, URL*1, None, NetworkServerFlag.NONE,
                None, None, None, None, None, 0, 0, date_updated, date_updated),
        ]
        update_future = db_functions.update_network_servers_transaction(db_context, server_rows, [],
            [], [])
        update_future.result(timeout=5)

    # Create a peer channel to be the foreign key entry for the broadcast rows.
    if True:
        # Check that a valid insert succeeds.
        create_row = ServerPeerChannelRow(None, SERVER_ID, None, None,
            ServerPeerChannelFlag.ALLOCATING, date_created, date_created)
        future = db_context.post_to_thread(db_functions.create_server_peer_channel_write,
            create_row)
        peer_channel_id = future.result()

    # These are the rows we will actually create.
    mapi_broadcast_create_rows = [
        MAPIBroadcastRow(None, TX_HASH_1, SERVER_ID, MAPI_STATUS_FLAGS1, peer_channel_id,
            date_created + 1, date_created + 1),
        MAPIBroadcastRow(None, TX_HASH_2, SERVER_ID, MAPI_STATUS_FLAGS2, None,
            date_created + 2, date_updated + 2),
    ]

    # Verify the constraints are enforced.
    if True:
        # Verify that the `tx_hash` foreign key is a required field.
        future = db_context.post_to_thread(db_functions.create_mapi_broadcasts_write, [
            mapi_broadcast_create_rows[0]._replace(tx_hash=None)
        ])
        with pytest.raises(sqlite3.IntegrityError) as integrity_error:
            future.result(timeout=5)
        assert integrity_error.value.args[0] == "NOT NULL constraint failed: MAPIBroadcasts.tx_hash"

        future = db_context.post_to_thread(db_functions.create_mapi_broadcasts_write, [
            mapi_broadcast_create_rows[0]._replace(tx_hash=b"dddd")
        ])
        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as integrity_error:
            future.result(timeout=5)
        assert integrity_error.value.args[0] == "FOREIGN KEY constraint failed"

        # Verify that the `broadcast_server_id` foreign key is a required field.
        future = db_context.post_to_thread(db_functions.create_mapi_broadcasts_write, [
            mapi_broadcast_create_rows[0]._replace(broadcast_server_id=None)
        ])
        with pytest.raises(sqlite3.IntegrityError) as integrity_error:
            future.result(timeout=5)
        assert integrity_error.value.args[0] == \
            "NOT NULL constraint failed: MAPIBroadcasts.broadcast_server_id"

        IMAGINARY_SERVER_ID = 342423423
        future = db_context.post_to_thread(db_functions.create_mapi_broadcasts_write, [
            mapi_broadcast_create_rows[0]._replace(broadcast_server_id=IMAGINARY_SERVER_ID)
        ])
        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as integrity_error:
            future.result(timeout=5)
        assert integrity_error.value.args[0] == "FOREIGN KEY constraint failed"

        # Verify that the `peer_channel_id` foreign key is a required field.
        IMAGINARY_CHANNEL_ID = 342423423
        future = db_context.post_to_thread(db_functions.create_mapi_broadcasts_write, [
            mapi_broadcast_create_rows[0]._replace(peer_channel_id=IMAGINARY_CHANNEL_ID)
        ])
        with pytest.raises((sqlite3.IntegrityError, sqlite3.OperationalError)) as integrity_error:
            future.result(timeout=5)
        assert integrity_error.value.args[0] == "FOREIGN KEY constraint failed"

    ## Now actually create some rows.
    future = db_context.post_to_thread(db_functions.create_mapi_broadcasts_write,
        mapi_broadcast_create_rows)
    mapi_broadcast_rows = future.result(timeout=5)
    assert len(mapi_broadcast_rows) == len(mapi_broadcast_create_rows)
    broadcast_id_by_tx_hash = { mbrow.tx_hash: cast(int, mbrow.broadcast_id)
        for mbrow in mapi_broadcast_rows }

    database_assigned_ids = set[int]()
    for mapi_broadcast_row in mapi_broadcast_rows:
        assert mapi_broadcast_row.broadcast_id is not None
        assert mapi_broadcast_row.broadcast_id not in database_assigned_ids
        database_assigned_ids.add(mapi_broadcast_row.broadcast_id)

    # Populate the SQLite assigned `broadcast_id` in the create rows, so that we can compare them.
    for i, create_row in enumerate(mapi_broadcast_create_rows):
        mapi_broadcast_create_rows[i] = create_row._replace(
            broadcast_id=broadcast_id_by_tx_hash[create_row.tx_hash])

    assert mapi_broadcast_rows == mapi_broadcast_create_rows

    if True:
        rows_after_insert = db_functions.read_mapi_broadcasts(db_context)
        assert rows_after_insert == mapi_broadcast_rows

    if True:
        future = db_functions.delete_mapi_broadcasts(db_context,
            [ broadcast_id_by_tx_hash[TX_HASH_2] ])
        assert future.result(timeout=5) is None

        rows_after_delete = db_functions.read_mapi_broadcasts(db_context)
        assert len(rows_after_delete) == 1
        assert rows_after_delete[0].tx_hash == TX_HASH_1
        assert rows_after_delete[0].mapi_broadcast_flags != MAPIBroadcastFlag.BROADCAST

    if True:
        future = db_functions.update_mapi_broadcasts(db_context,
            entries=[(MAPIBroadcastFlag.BROADCAST, b"response", 1,
                broadcast_id_by_tx_hash[TX_HASH_1])])
        assert future.result(timeout=5) is None

        rows_after_update = db_functions.read_mapi_broadcasts(db_context)
        assert rows_after_update[0].mapi_broadcast_flags == MAPIBroadcastFlag.BROADCAST

