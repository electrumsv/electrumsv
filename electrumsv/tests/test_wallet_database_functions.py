import os
import shutil
import tempfile
import unittest.mock

from bitcoinx import hash_to_hex_str, hex_str_to_hash
import pytest as pytest

from electrumsv.constants import AccountFlags
from electrumsv.networks import Net, SVMainnet, SVRegTestnet
from electrumsv.storage import WalletStorage
from electrumsv.wallet_database import functions as db_functions

from .util import _create_mock_app_state, mock_headers, PasswordToken, read_testdata_for_wallet, \
    TEST_WALLET_PATH


# TODO(techinical-debt) We need to upgrade the test wallet with all the transactions to the current
# database migration. That adds a bit of boilerplate. If we preupgraded all the test wallets and
# stored them somewhere and just copied the files, we'd be able to just open it with SQLite
# directory and without the layers of abstraction and the boilerplate.

@pytest.mark.parametrize("limit_count,skip,expected_count,context_text", [
    (1, 0, 1, "history_1_0"),
    (1, 1, 1, "history_1_1"),
    (1, 10, 1, "history_1_10"),
    (10, 0, 10, "history_10_0"),
    (10, 1, 10, "history_10_1"),
    (10, 10, 10, "history_10_10"),
    (124, 0, 124, "history_124_0"),
    (124, 1, 123, "history_124_1"),
])
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
def test_read_history_for_outputs(mock_wallet_app_state, limit_count, skip, expected_count,
        context_text) -> None:
    """
    Verify that the SQL for the `read_history_for_outputs` database function is correct.
    """
    password = "123456"
    password_token = PasswordToken(password)
    mock_wallet_app_state.credentials.get_wallet_password = lambda wallet_path: password

    # Make sure we do not overwrite the original wallet database.
    wallet_filename = "26_regtest_standard_mining_with_mature_and_immature_coins.sqlite"
    temp_dir = tempfile.mkdtemp()
    source_wallet_path = os.path.join(TEST_WALLET_PATH, wallet_filename)
    wallet_path = os.path.join(temp_dir, wallet_filename)
    shutil.copyfile(source_wallet_path, wallet_path)

    storage = WalletStorage(wallet_path)

    with unittest.mock.patch(
        "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state") \
        as migration29_app_state:
            migration29_app_state.headers = mock_headers()
            storage.upgrade(True, password_token)

    # SECTION: The test preparation.
    db_context = storage.get_db_context()
    assert db_context is not None

    account_id = -1
    for account_row in db_functions.read_accounts(db_context):
         if account_row.flags == AccountFlags.NONE:
              account_id = account_row.account_id
              break
    assert account_id != -1

    Net.set_to(SVRegTestnet)
    try:
        # SECTION: The actual test code.
        testdata_object: list[dict] = []
        for db_row in db_functions.read_history_for_outputs(db_context, account_id,
                limit_count=limit_count, skip_count=skip):
            entry_dict = db_row._asdict()
            # JSON does not support embedded byte data so we convert to hexl; canonical hex
            # byte order in the case of transaction and block hashes.
            entry_dict["tx_id"] = hash_to_hex_str(entry_dict.pop("tx_hash"))
            block_hash = entry_dict.pop("block_hash")
            entry_dict["block_id"] = hash_to_hex_str(block_hash) if block_hash is not None else None
            entry_dict["script_pubkey_hex"] = entry_dict.pop("script_pubkey_bytes").hex()
            testdata_object.append(entry_dict)

        existing_testdata_object = read_testdata_for_wallet(source_wallet_path, context_text)
        assert testdata_object == existing_testdata_object
        assert len(testdata_object) == expected_count
    finally:
        Net.set_to(SVMainnet)

@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
def test_read_history_for_outputs_specified_transaction(mock_wallet_app_state) -> None:
    """
    Verify that the SQL for the `read_history_for_outputs` database function is correct
    """
    password = "123456"
    mock_wallet_app_state.credentials.get_wallet_password = lambda wallet_path: password

    # Make sure we do not overwrite the original wallet database.
    wallet_filename = "29_regtest_standard_spending_wallet_paytomany.sqlite"
    temp_dir = tempfile.mkdtemp()
    # A subdirectory is used to avoid being picked up by the `test_legacy_wallet_loading` test
    source_wallet_path = os.path.join(TEST_WALLET_PATH, wallet_filename)
    wallet_path = os.path.join(temp_dir, wallet_filename)
    shutil.copyfile(source_wallet_path, wallet_path)

    storage = WalletStorage(wallet_path)

    # SECTION: The test preparation.
    db_context = storage.get_db_context()
    assert db_context is not None

    account_id = -1
    for account_row in db_functions.read_accounts(db_context):
         if account_row.flags == AccountFlags.NONE:
              account_id = account_row.account_id
              break
    assert account_id != -1

    Net.set_to(SVRegTestnet)
    try:
        # SECTION: The actual test code.
        # 1) Check that for a specified transaction hash that does not exist no results are returned.
        tx_hash_does_not_exist = hex_str_to_hash(
            "0000000000000000000000000000000000000000000000000000000000000000")
        rows = db_functions.read_history_for_outputs(db_context, account_id,
            transaction_hash=tx_hash_does_not_exist)
        assert isinstance(rows, list)
        assert len(rows) == 0

        # 2) Check that for a specified transaction hash that does exist the correct record is
        #    returned.
        tx_hash_should_exist = hex_str_to_hash(
            "e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063")

        testdata_object: list[dict] = []
        context_text = 'transaction_exists'
        for db_row in db_functions.read_history_for_outputs(db_context, account_id,
                transaction_hash=tx_hash_should_exist):
            entry_dict = db_row._asdict()
            # JSON does not support embedded byte data so we convert to hexl; canonical hex
            # byte order in the case of transaction and block hashes.
            entry_dict["tx_id"] = hash_to_hex_str(entry_dict.pop("tx_hash"))
            block_hash = entry_dict.pop("block_hash")
            entry_dict["block_id"] = hash_to_hex_str(block_hash) if block_hash is not None else None
            entry_dict["script_pubkey_hex"] = entry_dict.pop("script_pubkey_bytes").hex()
            testdata_object.append(entry_dict)

        existing_testdata_object = read_testdata_for_wallet(source_wallet_path, context_text)
        assert testdata_object == existing_testdata_object

        # 3) Find a transaction in the wallet that has multiple (let’s say it has N rows) debits and
        #    credits in the result from `read_history_for_outputs`.
        #    a) Check count=1 returns only the most recent entry.
        #    b) If N > 2, check count=N-1 returns the most recent N-1 entries in correct order but
        #       not the Nth entry.
        #    c) Check count=N returns all N entries in correct order.
        #    d) Check count=N+1 returns all N entries in correct order.
        COUNT_OF_ROWS_FOR_TX = 3
        tx_hash_should_exist = hex_str_to_hash(
            "e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063")

        # (a)
        testdata_object: list[dict] = []
        context_text = 'count_1'
        for db_row in db_functions.read_history_for_outputs(db_context, account_id,
                transaction_hash=tx_hash_should_exist, limit_count=1):
            entry_dict = db_row._asdict()
            entry_dict["tx_id"] = hash_to_hex_str(entry_dict.pop("tx_hash"))
            block_hash = entry_dict.pop("block_hash")
            entry_dict["block_id"] = hash_to_hex_str(block_hash) if block_hash is not None else None
            entry_dict["script_pubkey_hex"] = entry_dict.pop("script_pubkey_bytes").hex()
            testdata_object.append(entry_dict)

        existing_testdata_object = read_testdata_for_wallet(source_wallet_path, context_text)
        assert testdata_object == existing_testdata_object

        # (b)
        testdata_object: list[dict] = []
        context_text = 'count_N_minus_1'
        for db_row in db_functions.read_history_for_outputs(db_context, account_id,
                transaction_hash=tx_hash_should_exist, limit_count=COUNT_OF_ROWS_FOR_TX - 1):
            entry_dict = db_row._asdict()
            entry_dict["tx_id"] = hash_to_hex_str(entry_dict.pop("tx_hash"))
            block_hash = entry_dict.pop("block_hash")
            entry_dict["block_id"] = hash_to_hex_str(block_hash) if block_hash is not None else None
            entry_dict["script_pubkey_hex"] = entry_dict.pop("script_pubkey_bytes").hex()
            testdata_object.append(entry_dict)

        existing_testdata_object = read_testdata_for_wallet(source_wallet_path, context_text)
        assert testdata_object == existing_testdata_object

        # (c)
        testdata_object: list[dict] = []
        context_text = 'count_N'
        for db_row in db_functions.read_history_for_outputs(db_context, account_id,
                transaction_hash=tx_hash_should_exist, limit_count=COUNT_OF_ROWS_FOR_TX):
            entry_dict = db_row._asdict()
            entry_dict["tx_id"] = hash_to_hex_str(entry_dict.pop("tx_hash"))
            block_hash = entry_dict.pop("block_hash")
            entry_dict["block_id"] = hash_to_hex_str(block_hash) if block_hash is not None else None
            entry_dict["script_pubkey_hex"] = entry_dict.pop("script_pubkey_bytes").hex()
            testdata_object.append(entry_dict)

        existing_testdata_object = read_testdata_for_wallet(source_wallet_path, context_text)
        assert testdata_object == existing_testdata_object

        # (d)
        testdata_object: list[dict] = []
        context_text = 'count_N_plus_1'
        for db_row in db_functions.read_history_for_outputs(db_context, account_id,
                transaction_hash=tx_hash_should_exist, limit_count=COUNT_OF_ROWS_FOR_TX + 1):
            entry_dict = db_row._asdict()
            entry_dict["tx_id"] = hash_to_hex_str(entry_dict.pop("tx_hash"))
            block_hash = entry_dict.pop("block_hash")
            entry_dict["block_id"] = hash_to_hex_str(block_hash) if block_hash is not None else None
            entry_dict["script_pubkey_hex"] = entry_dict.pop("script_pubkey_bytes").hex()
            testdata_object.append(entry_dict)

        existing_testdata_object = read_testdata_for_wallet(source_wallet_path, context_text)
        assert testdata_object == existing_testdata_object

    finally:
        Net.set_to(SVMainnet)
