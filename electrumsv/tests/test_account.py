from typing import cast
import unittest
import unittest.mock

import pytest

from electrumsv.constants import (CHANGE_SUBPATH, KeyInstanceFlag, KeystoreTextType,
    RECEIVING_SUBPATH, ScriptType)
from electrumsv.keystore import BIP32_KeyStore, instantiate_keystore_from_text
from electrumsv.wallet import StandardAccount, Wallet
from electrumsv.wallet_database.exceptions import KeyInstanceNotFoundError
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
@unittest.mock.patch('electrumsv.wallet.app_state')
async def test_key_creation(mock_app_state, tmp_storage) -> None:
    # Boilerplate setting up of a deterministic account. This is copied from above.
    password = 'password'
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    mock_app_state.credentials = unittest.mock.Mock()
    mock_app_state.credentials.get_wallet_password = lambda wallet_path: password

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...')
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    account = StandardAccount(wallet, account_row, [])
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
    assert keyinstance_rows[0].derivation_data2 is not None
    assert keyinstance_rows[1].derivation_data2 is not None
    assert keyinstance_rows[2].derivation_data2 is not None
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


@pytest.mark.asyncio
@unittest.mock.patch('electrumsv.wallet.app_state')
async def test_key_reservation(mock_app_state, tmp_storage) -> None:
    """
    Verify that the allocate a key on demand database function works as expected for an account.
    """
    # Boilerplate setting up of a deterministic account. This is copied from above.
    password = 'password'
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    mock_app_state.credentials.get_wallet_password = lambda wallet_path: password

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...')
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    account = StandardAccount(wallet, account_row, [])
    wallet.register_account(account.get_id(), account)

    account.derive_new_keys_until(RECEIVING_SUBPATH + (0,))
    account.derive_new_keys_until(CHANGE_SUBPATH + (9,))
    assert account._count_unused_keys(RECEIVING_SUBPATH) == 1
    assert account._count_unused_keys(CHANGE_SUBPATH) == 10

    future = wallet.reserve_keyinstance(account.get_id(), masterkey_row.masterkey_id,
        RECEIVING_SUBPATH)
    keyinstance_id, flags = future.result()
    assert keyinstance_id == 1
    # The flags it thinks were updated as part of this operation.
    assert flags == KeyInstanceFlag.IS_ACTIVE | KeyInstanceFlag.USED

    future = wallet.reserve_keyinstance(account.get_id(), masterkey_row.masterkey_id,
        RECEIVING_SUBPATH)
    with pytest.raises(KeyInstanceNotFoundError):
        _keyinstance_id, _flags = future.result()

    future = wallet.reserve_keyinstance(account.get_id(), masterkey_row.masterkey_id,
        CHANGE_SUBPATH, KeyInstanceFlag.IS_PAYMENT_REQUEST)
    keyinstance_id, flags = future.result()
    assert keyinstance_id == 2
    # The flags it thinks were updated as part of this operation.
    assert flags == (KeyInstanceFlag.IS_ACTIVE | KeyInstanceFlag.USED
        | KeyInstanceFlag.IS_PAYMENT_REQUEST)

    keyinstances = wallet.read_keyinstances(account_id=account.get_id(), keyinstance_ids=[1, 2])
    keyinstance1 = [ ki for ki in keyinstances if ki.keyinstance_id == 1 ][0]
    keyinstance2 = [ ki for ki in keyinstances if ki.keyinstance_id == 2 ][0]
    # That the flags were actually updated in the database.
    assert keyinstance1.flags == KeyInstanceFlag.IS_ACTIVE | KeyInstanceFlag.USED
    assert keyinstance2.flags == (KeyInstanceFlag.IS_ACTIVE | KeyInstanceFlag.USED |
        KeyInstanceFlag.IS_PAYMENT_REQUEST)
