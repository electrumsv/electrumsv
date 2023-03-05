import json
import os
import shutil
import tempfile
import unittest.mock

from bitcoinx import hash_to_hex_str

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

@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
def test_read_history_for_outputs(mock_wallet_app_state) -> None:
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
        for db_row in db_functions.read_history_for_outputs(db_context, account_id):
            entry_dict = db_row._asdict()
            # JSON does not support embedded byte data so we convert to hexl; canonical hex
            # byte order in the case of transaction and block hashes.
            entry_dict["tx_id"] = hash_to_hex_str(entry_dict.pop("tx_hash"))
            block_hash = entry_dict.pop("block_hash")
            entry_dict["block_id"] = hash_to_hex_str(block_hash) if block_hash is not None else None
            entry_dict["script_pubkey_hex"] = entry_dict.pop("script_pubkey_bytes").hex()
            testdata_object.append(entry_dict)

        existing_testdata_object = read_testdata_for_wallet(source_wallet_path, "history_full")
        assert testdata_object == existing_testdata_object
    finally:
        Net.set_to(SVMainnet)
