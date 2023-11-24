from typing import cast
import unittest
import unittest.mock

import pytest

from electrumsv.constants import (AccountFlag, CHANGE_SUBPATH, KeyInstanceFlag, KeystoreTextType,
    PaymentRequestFlag, RECEIVING_SUBPATH, ScriptType, ServerConnectionFlag)
from electrumsv.exceptions import NoViableServersError, ServiceUnavailableError
from electrumsv.keystore import BIP32_KeyStore, instantiate_keystore_from_text
from electrumsv.network_support.types import TipFilterRegistrationJob, \
    TipFilterRegistrationJobOutput
from electrumsv.wallet import StandardAccount, Wallet
from electrumsv.wallet_database.exceptions import KeyInstanceNotFoundError
from electrumsv.wallet_database.types import AccountRow
from electrumsv.storage import WalletStorage

from .util import _create_mock_app_state, mock_headers, MockStorage, setup_async, tear_down_async
from ..network_support.types import ServerConnectionState


def setUpModule():
    setup_async()


def tearDownModule():
    tear_down_async()


@pytest.mark.asyncio
@unittest.mock.patch(
    "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state")
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
async def test_key_creation(mock_app_state1, mock_app_state2) -> None:
    password = 'password'
    mock_app_state1.credentials = unittest.mock.Mock()
    mock_app_state1.credentials.get_wallet_password = lambda wallet_path: password
    mock_app_state2.headers = mock_headers()

    tmp_storage = cast(WalletStorage, MockStorage(password))
    # Boilerplate setting up of a deterministic account. This is copied from above.
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
        AccountFlag.NONE, None, None, None, None, 1, 1)
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    account = StandardAccount(wallet, account_row)
    wallet.register_account(account.get_id(), account)

    # Create two keys via `derive_new_keys_until`.
    scripthash_future, keyinstance_rows = account.derive_new_keys_until(RECEIVING_SUBPATH + (2,))
    assert scripthash_future is not None
    scripthash_future.result(5)

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
    derive_future, _keyinstance_rows = account.derive_new_keys_until(RECEIVING_SUBPATH + (10,))
    if derive_future is not None:
        derive_future.result()
    assert account.get_next_derivation_index(RECEIVING_SUBPATH) == 11
    assert account.get_next_derivation_index(CHANGE_SUBPATH) == 0

    # Just get the existing created keys.
    account.get_fresh_keys(RECEIVING_SUBPATH, 11)
    assert account.get_next_derivation_index(RECEIVING_SUBPATH) == 11

    # Create one more key via `get_fresh_keys`.
    account.get_fresh_keys(RECEIVING_SUBPATH, 12)
    assert account.get_next_derivation_index(RECEIVING_SUBPATH) == 12


@pytest.mark.asyncio
@unittest.mock.patch(
    "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state")
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
async def test_key_reservation(mock_app_state1, mock_app_state2) -> None:
    """
    Verify that the allocate a key on demand database function works as expected for an account.
    """
    password = 'password'
    mock_app_state1.credentials.get_wallet_password = lambda wallet_path: password
    mock_app_state2.headers = mock_headers()

    tmp_storage = cast(WalletStorage, MockStorage(password))
    # Boilerplate setting up of a deterministic account. This is copied from above.
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
        AccountFlag.NONE, None, None, None, None, 1, 1)
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    account = StandardAccount(wallet, account_row)
    wallet.register_account(account.get_id(), account)

    account.derive_new_keys_until(RECEIVING_SUBPATH + (0,))
    account.derive_new_keys_until(CHANGE_SUBPATH + (9,))

    future = wallet.data.reserve_keyinstance(account.get_id(), masterkey_row.masterkey_id,
        RECEIVING_SUBPATH)
    keyinstance_id, derivation_type, derivation_data2, flags = future.result()
    assert keyinstance_id == 1
    # The flags it thinks were updated as part of this operation.
    assert flags == KeyInstanceFlag.USED

    future = wallet.data.reserve_keyinstance(account.get_id(), masterkey_row.masterkey_id,
        RECEIVING_SUBPATH)
    with pytest.raises(KeyInstanceNotFoundError):
        _keyinstance_id, derivation_type, derivation_data2, _flags = future.result()

    future = wallet.data.reserve_keyinstance(account.get_id(), masterkey_row.masterkey_id,
        CHANGE_SUBPATH, KeyInstanceFlag.ACTIVE | KeyInstanceFlag.IS_PAYMENT_REQUEST)
    keyinstance_id, derivation_type, derivation_data2, flags = future.result()
    assert keyinstance_id == 2
    # The flags it thinks were updated as part of this operation.
    assert flags == (KeyInstanceFlag.ACTIVE | KeyInstanceFlag.USED
        | KeyInstanceFlag.IS_PAYMENT_REQUEST)

    keyinstances = wallet.data.read_keyinstances(account_id=account.get_id(),
        keyinstance_ids=[1, 2])
    keyinstance1 = [ ki for ki in keyinstances if ki.keyinstance_id == 1 ][0]
    keyinstance2 = [ ki for ki in keyinstances if ki.keyinstance_id == 2 ][0]
    # That the flags were actually updated in the database.
    assert KeyInstanceFlag(keyinstance1.flags) == KeyInstanceFlag.USED
    assert KeyInstanceFlag(keyinstance2.flags) == (KeyInstanceFlag.ACTIVE | KeyInstanceFlag.USED |
        KeyInstanceFlag.IS_PAYMENT_REQUEST)


# TODO(technical-debt) Pre-created test wallets. Have a pre-created wallet with an account.
@pytest.mark.asyncio
@unittest.mock.patch(
    'electrumsv.wallet.create_tip_filter_registration_async')
@unittest.mock.patch(
    "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state")
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
async def test_create_monitored_blockchain_payment_async(mock_app_state1, mock_app_state2,
        create_tip_filter_registration_async) -> None:
    """
    Verify that the allocate a key on demand database function works as expected for an account.
    """
    password = 'password'
    mock_app_state1.credentials.get_wallet_password = lambda wallet_path: password
    mock_app_state2.headers = mock_headers()

    tmp_storage = cast(WalletStorage, MockStorage(password))
    # Boilerplate setting up of a deterministic account. This is copied from above.
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
        AccountFlag.NONE, None, None, None, None, 1, 1)
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    account = StandardAccount(wallet, account_row)
    wallet.register_account(account.get_id(), account)

    # Ensure there is an expiry date passed.
    with pytest.raises(AssertionError):
        await account.create_monitored_blockchain_payment_async(None, None, None, None, None)

    expiry_date = 100
    wallet.get_connection_state_for_usage = lambda *args: None
    with pytest.raises(NoViableServersError):
        await account.create_monitored_blockchain_payment_async(None, None, None, None, expiry_date)

    server_state = unittest.mock.Mock(spec=ServerConnectionState)
    server_state.connection_flags = ServerConnectionFlag.NONE
    wallet.get_connection_state_for_usage = lambda *args: server_state
    with pytest.raises(ServiceUnavailableError):
        await account.create_monitored_blockchain_payment_async(None, None, None, None, expiry_date)

    # We mock out the queued server registration.
    our_job_output = TipFilterRegistrationJobOutput()
    our_job_output.date_registered=11111
    our_job_output.completed_event.set()
    async def fake_create_tip_filter_registration_async(state: ServerConnectionState,
            pushdata_hash: bytes, date_expires: int, keyinstance_id: int,
            script_type: ScriptType) -> TipFilterRegistrationJob:
        nonlocal our_job_output
        return TipFilterRegistrationJob([], our_job_output)

    # TEST: Successful result.
    server_state.connection_flags = ServerConnectionFlag.TIP_FILTER_READY
    create_tip_filter_registration_async.side_effect = fake_create_tip_filter_registration_async
    paymentrequest_row1, paymentrequest_output_rows1, their_job_output = \
        await account.create_monitored_blockchain_payment_async(None, 10000, None, None,
            expiry_date)
    assert their_job_output.date_registered == 11111
    assert their_job_output.failure_reason is None
    assert paymentrequest_row1 is not None
    assert paymentrequest_row1.request_flags & PaymentRequestFlag.MASK_STATE == PaymentRequestFlag.STATE_UNPAID
    assert paymentrequest_row1.request_flags & PaymentRequestFlag.MASK_TYPE == PaymentRequestFlag.TYPE_MONITORED
    assert len(paymentrequest_output_rows1) == 1

    # TEST: Unsuccessful result.
    our_job_output.date_registered = None
    our_job_output.failure_reason = "would be error text"
    create_tip_filter_registration_async.side_effect = fake_create_tip_filter_registration_async
    paymentrequest_row2, paymentrequest_output_rows2, their_job_output = \
        await account.create_monitored_blockchain_payment_async(None, 10000, None, None,
            expiry_date)
    assert their_job_output.date_registered is None
    assert their_job_output.failure_reason == "would be error text"
    assert paymentrequest_row2 is None
    assert len(paymentrequest_output_rows2) == 0

    # The unsuccessful entry should have had it's payment request deleted.
    read_request_rows = sorted(wallet.data.read_payment_requests(),
        key=lambda read_request_row: read_request_row.paymentrequest_id)
    assert len(read_request_rows) == 2
    assert read_request_rows[0].paymentrequest_id == paymentrequest_row1.paymentrequest_id
    assert read_request_rows[0].request_flags & PaymentRequestFlag.MASK_HIDDEN == PaymentRequestFlag.NONE
    assert read_request_rows[1].paymentrequest_id == paymentrequest_row1.paymentrequest_id+1
    assert read_request_rows[1].request_flags & PaymentRequestFlag.MASK_HIDDEN == PaymentRequestFlag.DELETED
