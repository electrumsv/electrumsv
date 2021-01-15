import pytest

from electrumsv.constants import CHANGE_SUBPATH, RECEIVING_SUBPATH, ScriptType
from electrumsv.keystore import from_seed
from electrumsv.wallet import StandardAccount, Wallet
from electrumsv.wallet_database.types import AccountRow

from .util import MockStorage, setup_async, tear_down_async


def setUpModule():
    setup_async()


def tearDownModule():
    tear_down_async()


@pytest.fixture()
def tmp_storage(tmpdir):
    return MockStorage()


@pytest.mark.asyncio
async def test_key_allocation(tmp_storage) -> None:
    # Boilerplate setting up of a deterministic account. This is copied from above.
    password = 'password'
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = from_seed(seed_words, '')

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)
    wallet.update_password(password)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...')
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    account = StandardAccount(wallet, account_row, [], [])
    wallet.register_account(account.get_id(), account)

    # Create two keys via `derive_new_keys_until`.
    account.derive_new_keys_until(RECEIVING_SUBPATH + (2,))
    assert account.get_next_derivation_index(RECEIVING_SUBPATH) == 3
    assert account.get_next_derivation_index(CHANGE_SUBPATH) == 0

    # Just get the existing created keys.
    account.get_fresh_keys(RECEIVING_SUBPATH, 3)
    assert account.get_next_derivation_index(RECEIVING_SUBPATH) == 3

    keyinstance_rows = account.get_existing_fresh_keys(RECEIVING_SUBPATH, 1)
    assert len(keyinstance_rows) == 1
    keyinstance_rows = account.get_existing_fresh_keys(RECEIVING_SUBPATH, 3)
    assert len(keyinstance_rows) == 3
    keyinstance_rows = account.get_existing_fresh_keys(RECEIVING_SUBPATH, 4)
    assert len(keyinstance_rows) == 3
    # Check if the existing fresh keys are ordered in an ascending fashion.
    assert (keyinstance_rows[0].derivation_data2 < keyinstance_rows[1].derivation_data2
        < keyinstance_rows[2].derivation_data2)

    # Create seven more keys via `derive_new_keys_until`.
    account.derive_new_keys_until(RECEIVING_SUBPATH + (10,))
    assert account.get_next_derivation_index(RECEIVING_SUBPATH) == 11
    assert account.get_next_derivation_index(CHANGE_SUBPATH) == 0

    # Just get the existing created keys.
    account.get_fresh_keys(RECEIVING_SUBPATH, 11)
    assert account.get_next_derivation_index(RECEIVING_SUBPATH) == 11

    # Create one more key via `get_fresh_keys`.
    account.get_fresh_keys(RECEIVING_SUBPATH, 12)
    assert account.get_next_derivation_index(RECEIVING_SUBPATH) == 12

    assert account._count_unused_keys(RECEIVING_SUBPATH) == 12
