import json
import os
import shutil
import sys
import tempfile
from typing import Any, cast, Dict, Optional, List, Set
import unittest
import unittest.mock

from bitcoinx import Chain, double_sha256, Header, hex_str_to_hash, MissingHeader, Ops, Script
import pytest

from electrumsv.app_state import AppStateProxy
from electrumsv.constants import (AccountFlags, BlockHeight, CHANGE_SUBPATH, DATABASE_EXT,
    DerivationType, DatabaseKeyDerivationType, KeystoreTextType,
    MasterKeyFlags, RECEIVING_SUBPATH, ScriptType, StorageKind, TransactionImportFlag,
    TxFlags, unpack_derivation_path)
from electrumsv.crypto import pw_decode
from electrumsv.exceptions import InvalidPassword, IncompatibleWalletError
from electrumsv.keystore import (BIP32_KeyStore, Hardware_KeyStore,
    Imported_KeyStore, instantiate_keystore_from_text, Old_KeyStore,
    Multisig_KeyStore)
from electrumsv.networks import Net, SVMainnet, SVRegTestnet, SVTestnet
from electrumsv.storage import get_categorised_files, WalletStorage, WalletStorageInfo
from electrumsv.standards.electrum_transaction_extended import transaction_from_electrumsv_dict
from electrumsv.transaction import Transaction, TransactionContext
from electrumsv.types import DatabaseKeyDerivationData, MasterKeyDataBIP32, Outpoint
from electrumsv.wallet import (DeterministicAccount, ImportedPrivkeyAccount,
    ImportedAddressAccount, MissingTransactionEntry, MultisigAccount, Wallet, StandardAccount)
from electrumsv.wallet_database import functions as db_functions
from electrumsv.wallet_database.exceptions import TransactionRemovalError
from electrumsv.wallet_database.types import AccountRow, KeyInstanceRow, TransactionLinkState, \
    MerkleProofRow, WalletBalance

from .util import _create_mock_app_state, mock_headers, MockStorage, PasswordToken, setup_async, \
    tear_down_async, TEST_WALLET_PATH


class _TestableWallet(Wallet):
    def name(self):
        return self.__class__.__name__


def setUpModule():
    setup_async()


def tearDownModule():
    tear_down_async()


def get_categorised_files2(wallet_path: str, exclude_suffix: str="") -> List[WalletStorageInfo]:
    matches = get_categorised_files(wallet_path, exclude_suffix)
    # In order to ensure ordering consistency, we sort the files.
    return sorted(matches, key=lambda v: v.filename)

@pytest.fixture()
def tmp_storage(tmpdir):
    with unittest.mock.patch(
        "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state") \
        as migration29_app_state:
            migration29_app_state.headers = mock_headers()
            return MockStorage("password")

@pytest.fixture(params=[SVMainnet, SVTestnet])
def network(request):
    network = request.param
    Net.set_to(network)
    yield network
    Net.set_to(SVMainnet)


class FakeSynchronizer(object):

    def __init__(self):
        self.store = []

    def add(self, address):
        self.store.append(address)


class WalletTestCase(unittest.TestCase):
    def setUp(self):
        self.user_dir = tempfile.mkdtemp()
        self.wallet_path = os.path.join(self.user_dir,
            f"somewallet-{os.urandom(4).hex()}")

    def tearDown(self):
        shutil.rmtree(self.user_dir)


# A funding transaction.
tx_hex_funding = \
    "01000000014e1653d27b6a00c174cb0e79b327cb2ac2268201533de8f5666e63101a6be46601000000" \
    "6a473044022072c3ca2a6ab271142a70e109474108b11800818acecb192325465e970ad0cccb022011" \
    "6c8c05fad2d5ab2be33ae3fc5362b7137db26d0b7ddd009ee8692daacd57914121037f37bb0d14dc72" \
    "d67f0cfb49f6472163924ba86382fd2490d5c04261386b70b0ffffffff0291ee0f00000000001976a9" \
    "14ea7804a2c266063572cc009a63dc25dcc0e9d9b588ac5883e516000000001976a914ad27edee3653" \
    "50b63b5024a8f8168e7297bdd70b88ac216e1500"

# A spending/depletion transaction for the funding transaction.
tx_hex_spend = \
    "01000000019960eee94aa89f4db93a4bc720dc9b7004127df7c115f121fee5ec7eea1e4ce200000000" \
    "6b483045022100870754d5caf0483501f9ef6b886d42add34a693808310a1199c998e827dca7520220" \
    "31d8a58435ac51fbdc94222d2781c08b2af779925f80ac5e05ed5953ae7d07a24121030b482838721a" \
    "38d94847699fed8818b5c5f56500ef72f13489e365b65e5749cfffffffff01d1ed0f00000000001976" \
    "a914ddec06c1086c07c4b1ddc4299730dacb3b25b24088ac536e1500"


def check_legacy_parent_of_standard_wallet(wallet: Wallet,
        seed_words: Optional[str]=None, is_bip39: bool=False, is_imported_electrum: bool=False,
        password: Optional[str]=None, add_indefinite_credential_mock: Any=None) -> None:
    # The automatically created petty cash account will be there from migration 29.
    assert len(wallet.get_accounts()) == 2
    account = cast(StandardAccount,
        [ entry for entry in wallet.get_accounts() if not entry.is_petty_cash() ][0])

    # There will be three keystores. The one from the automatically created global wallet seed,
    # the one from the automatically created petty cash keystore, and the one from this test.
    wallet_keystores = cast(List[BIP32_KeyStore], wallet.get_keystores())
    assert len(wallet_keystores) == 3

    # Validate the global wallet keystore and the petty cash keystore were created correctly.
    wallet_keystore = [ ks for ks in wallet_keystores
        if ks.get_masterkey_flags() & MasterKeyFlags.WALLET_SEED ][0]
    petty_cash_keystore = [ ks for ks in wallet_keystores
        if ks.get_parent_keystore() is wallet_keystore ][0]
    assert petty_cash_keystore.get_masterkey_flags() == MasterKeyFlags.NONE
    # Check that the petty cash keystore cached it's credential.
    assert petty_cash_keystore._xprv_credential_id is not None
    if add_indefinite_credential_mock is not None and petty_cash_keystore.xprv is not None:
        xprv = pw_decode(petty_cash_keystore.xprv, password)
        add_indefinite_credential_mock.assert_called_once_with(xprv)

    # Validate that the test account keystore was created correctly.
    account_keystores = cast(List[BIP32_KeyStore], account.get_keystores())
    assert len(account_keystores) == 1
    account_keystore = account_keystores[0]
    assert account_keystore in wallet_keystores

    if is_imported_electrum:
        assert account_keystore.get_parent_keystore() is None
        # This account was created for the test and gets the correct flag
        assert account_keystore.get_masterkey_flags() == MasterKeyFlags.ELECTRUM_SEED
    else:
        assert account_keystore.get_parent_keystore() is None
        # These are pre-existing imported accounts and the information was never set and lost.
        assert account_keystore.get_masterkey_flags() == MasterKeyFlags.NONE

    assert password is not None
    assert not account_keystores[0].has_seed() or account_keystores[0].get_seed(password)
    assert type(account_keystores[0].get_passphrase(password)) is str
    assert account_keystores[0].get_master_private_key(password)

    keystore_data = account_keystores[0].to_derivation_data()
    assert len(keystore_data) == 6
    assert 'xpub' in keystore_data
    assert 'derivation' in keystore_data
    assert 'xprv' in keystore_data
    assert 'label' in keystore_data
    assert 'seed' in keystore_data
    assert 'passphrase' in keystore_data

    keystore_encrypted = False
    try:
        account_keystores[0].check_password(None)
    except InvalidPassword:
        keystore_encrypted = True
    assert "encrypted" not in wallet.name() or keystore_encrypted
    if seed_words is not None:
        assert keystore_data['seed'] == seed_words

def check_legacy_parent_of_imported_privkey_wallet(wallet: Wallet, password: str,
        keypairs: Optional[Dict[str, str]]=None) -> None:
    assert len(wallet.get_accounts()) == 2
    account = cast(ImportedPrivkeyAccount,
        [ account for account in wallet.get_accounts()
        if isinstance(account, ImportedPrivkeyAccount) ][0])

    parent_keystores = wallet.get_keystores()
    assert len(parent_keystores) == 2 # Wallet and petty cash.
    child_keystores = cast(List[Imported_KeyStore], account.get_keystores())
    assert len(child_keystores) == 1
    assert child_keystores[0] is not None

    assert not child_keystores[0].has_masterkey()
    with pytest.raises(IncompatibleWalletError):
        child_keystores[0].to_masterkey_row()
    with pytest.raises(IncompatibleWalletError):
        child_keystores[0].to_derivation_data()
    child_keystore = child_keystores[0]
    assert len(child_keystore._keypairs) == 1
    if keypairs:
        for public_key in child_keystore._public_keys.values():
            encrypted_prv =  child_keystore._keypairs[public_key]
            assert pw_decode(encrypted_prv, password) == keypairs[public_key.to_hex()]


def check_legacy_parent_of_imported_address_wallet(wallet: Wallet) -> None:
    assert len(wallet.get_accounts()) == 2
    account = cast(ImportedAddressAccount,
        [ account for account in wallet.get_accounts()
        if isinstance(account, ImportedAddressAccount) ][0])

    assert len(wallet.get_keystores()) == 2
    assert len(account.get_keystores()) == 0


def check_legacy_parent_of_multisig_wallet(wallet: Wallet, password: str,
        seed_phrase: Optional[str]=None) -> None:
    assert len(wallet.get_accounts()) == 2

    account1 = cast(MultisigAccount,
        [ account for account in wallet.get_accounts() if isinstance(account, MultisigAccount) ][0])

    parent_keystores = wallet.get_keystores()
    # Wallet, petty cash and multisig.
    assert len(parent_keystores) == 3
    keystore = cast(Multisig_KeyStore,
        [ keystore for keystore in parent_keystores if isinstance(keystore, Multisig_KeyStore) ][0])
    child_keystores = keystore.get_cosigner_keystores()
    assert len(child_keystores) == account1.n
    parent_data = keystore.to_derivation_data()

    for i in range(account1.n):
        masterkey_row = child_keystores[i].to_masterkey_row()
        assert masterkey_row.derivation_type == DerivationType.BIP32
        keystore_data = cast(MasterKeyDataBIP32, parent_data["cosigner-keys"][i][1])
        encrypted_seed = keystore_data['seed']
        if encrypted_seed is not None:
            if seed_phrase is not None:
                assert pw_decode(encrypted_seed, password) == seed_phrase
            assert keystore_data['xpub'] is not None
            assert keystore_data['xprv'] is not None
        else:
            assert keystore_data['xpub'] is not None
            assert keystore_data['xprv'] is None

def check_parent_of_blank_wallet(wallet: Wallet) -> None:
    # Petty cash account.
    assert len(wallet.get_accounts()) == 1
    parent_keystores = wallet.get_keystores()
    # Wallet and petty cash.
    assert len(parent_keystores) == 2


def check_legacy_parent_of_hardware_wallet(wallet: Wallet) -> None:
    assert len(wallet.get_accounts()) == 2
    child_account = cast(StandardAccount,
        [ entry for entry in wallet.get_accounts() if not entry.is_petty_cash() ][0])

    parent_keystores = cast(List[Hardware_KeyStore], wallet.get_keystores())
    # Wallet, petty cash and the hardware wallet.
    assert len(parent_keystores) == 3
    child_keystores = cast(List[Hardware_KeyStore], child_account.get_keystores())
    assert len(child_keystores) == 1
    assert child_keystores[0] in parent_keystores

    masterkey_row = child_keystores[0].to_masterkey_row()
    assert masterkey_row.derivation_type == DerivationType.HARDWARE
    keystore_data = child_keystores[0].to_derivation_data()
    # General hardware wallet.
    if keystore_data['hw_type'] == "ledger":
        # Ledger wallets extend the keystore.
        assert "cfg" in keystore_data
    assert 'hw_type' in keystore_data
    assert 'label' in keystore_data
    assert "derivation" in keystore_data


def check_create_keys(wallet: Wallet, account: DeterministicAccount) -> None:
    def check_rows(rows: List[KeyInstanceRow], script_type: ScriptType) -> None:
        for row in rows:
            assert isinstance(row.keyinstance_id, int)
            assert account.get_id() == row.account_id
            assert account._row.default_masterkey_id == row.masterkey_id
            assert DerivationType.BIP32_SUBPATH == row.derivation_type
            assert None is row.description

    accounts = wallet.get_accounts()
    assert len(accounts) == 2
    assert account in accounts
    assert [] == account.get_existing_fresh_keys(RECEIVING_SUBPATH, 1000)
    assert [] == account.get_existing_fresh_keys(CHANGE_SUBPATH, 1000)
    assert account._row.default_script_type == account.get_default_script_type()

    keyinstances: List[KeyInstanceRow] = []
    keyinstance_ids: Set[int] = set()

    for count in (0, 1, 5):
        future1, future2, new_keyinstances, new_scripthashes = \
            account.allocate_and_create_keys(count, RECEIVING_SUBPATH)
        assert count == len(new_keyinstances)
        check_rows(new_keyinstances, account._row.default_script_type)
        keyinstance_ids |= set(keyinstance.keyinstance_id for keyinstance in new_keyinstances)
        keyinstances.extend(new_keyinstances)
        assert len(keyinstance_ids) == len(keyinstances)
        # Wait for the creation to complete before we look.
        if count > 0:
            assert future2 is not None
            future2.result()
        else:
            assert future2 is None
        # Both the local list and the database result should be in the order they were created.
        assert keyinstances == \
            account.get_existing_fresh_keys(RECEIVING_SUBPATH, 1000), f"failed for {count}"

    for count in (0, 1, 5):
        local_last_row = keyinstances[-1]
        assert local_last_row.derivation_data2 is not None
        local_last_index = unpack_derivation_path(local_last_row.derivation_data2)[-1]
        next_index = account.get_next_derivation_index(RECEIVING_SUBPATH)
        assert next_index == local_last_index  + 1

        last_allocation_index = next_index + count - 1
        if count == 0:
            future4, new_keyinstances = account.derive_new_keys_until(
                RECEIVING_SUBPATH + (last_allocation_index,))
            assert future4 is None
            assert len(new_keyinstances) == 0
            continue

        future3, new_keyinstances = account.derive_new_keys_until(
            RECEIVING_SUBPATH + (last_allocation_index,))
        assert future3 is not None
        future3.result()
        assert count == len(new_keyinstances)
        check_rows(new_keyinstances, account._row.default_script_type)

        keyinstance_ids |= set(keyinstance.keyinstance_id for keyinstance in new_keyinstances)
        keyinstances.extend(new_keyinstances)
        assert len(keyinstance_ids) == len(keyinstances)
        assert keyinstances == account.get_existing_fresh_keys(RECEIVING_SUBPATH, 1000)

    keyinstance_batches: List[List[KeyInstanceRow]] = []
    for count in (0, 1, 5):
        new_keyinstances = account.get_fresh_keys(RECEIVING_SUBPATH, count)
        assert count == len(new_keyinstances)
        assert new_keyinstances == account.get_existing_fresh_keys(RECEIVING_SUBPATH, count)
        check_rows(new_keyinstances, ScriptType.NONE)
        # Verify each batch includes the last batch and the extra created keys.
        if len(keyinstance_batches) > 0:
            last_keyinstances = keyinstance_batches[-1]
            assert last_keyinstances == new_keyinstances[:len(last_keyinstances)]
        keyinstance_batches.append(new_keyinstances)



# Verify that different legacy wallets are created with correct keystores in both parent
# wallet, and account. And that the underlying data for keystore and wallet persistence
# is also exported correctly.
class TestLegacyWalletCreation:
    @unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
    def test_standard_electrum(self, mock_wallet_app_state, tmp_storage) -> None:
        mock_wallet_app_state.credentials.get_wallet_password = lambda wallet_path: "password"

        password = 'password'
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
            KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

        add_indefinite_credential_mock = unittest.mock.Mock()
        with unittest.mock.patch(
                'electrumsv.keystore.app_state.credentials.add_indefinite_credential',
                add_indefinite_credential_mock):
            wallet = Wallet(tmp_storage)
        masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

        raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
            AccountFlags.NONE, None, None)
        account_row = wallet.add_accounts([ raw_account_row ])[0]
        account = StandardAccount(wallet, account_row)
        wallet.register_account(account.get_id(), account)

        check_legacy_parent_of_standard_wallet(wallet, is_imported_electrum=True,
            password=password, add_indefinite_credential_mock=add_indefinite_credential_mock)
        check_create_keys(wallet, account)

    @unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
    def test_old(self, mock_app_state, tmp_storage) -> None:
        mock_app_state.credentials.get_wallet_password = lambda wallet_path: password

        password = "password"
        seed_words = ('powerful random nobody notice nothing important '+
            'anyway look away hidden message over')
        child_keystore = cast(Old_KeyStore, instantiate_keystore_from_text(
            KeystoreTextType.ELECTRUM_OLD_SEED_WORDS, seed_words, password))
        assert isinstance(child_keystore, Old_KeyStore)

        wallet = Wallet(tmp_storage)
        masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)
        account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
            AccountFlags.NONE, None, None)
        account_row = wallet.add_accounts([ account_row ])[0]
        account = StandardAccount(wallet, account_row)
        wallet.register_account(account.get_id(), account)

        parent_keystores = wallet.get_keystores()
        # Wallet, petty cash and the old keystore.
        assert len(parent_keystores) == 3
        child_keystores = account.get_keystores()
        assert len(child_keystores) == 1
        parent_keystore_index = parent_keystores.index(child_keystores[0])
        assert parent_keystore_index != -1
        parent_keystore = parent_keystores[parent_keystore_index]

        masterkey_row = parent_keystore.to_masterkey_row()
        assert masterkey_row.derivation_type == DerivationType.ELECTRUM_OLD
        keystore_data = parent_keystore.to_derivation_data()
        assert len(keystore_data) == 2
        assert 'mpk' in keystore_data
        assert 'seed' in keystore_data

        check_create_keys(wallet, account)

    @unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
    def test_imported_privkey(self, mock_app_state, tmp_storage) -> None:
        mock_app_state.app = unittest.mock.Mock()
        mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"

        wallet = Wallet(tmp_storage)
        account = wallet.create_account_from_text_entries(KeystoreTextType.PRIVATE_KEYS,
            { "KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6" },
            "password")

        keypairs = {'02c6467b7e621144105ed3e4835b0b4ab7e35266a2ae1c4f8baa19e9ca93452997':
            'KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6'}
        check_legacy_parent_of_imported_privkey_wallet(wallet, keypairs=keypairs,
            password='password')

    @unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
    def test_imported_pubkey(self, mock_app_state, tmp_storage) -> None:
        mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"
        text = """
        15hETetDmcXm1mM4sEf7U2KXC9hDHFMSzz
        1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6
        """
        wallet = Wallet(tmp_storage)
        account = wallet.create_account_from_text_entries(KeystoreTextType.ADDRESSES,
            { "15hETetDmcXm1mM4sEf7U2KXC9hDHFMSzz", "1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6" },
            "password")
        check_legacy_parent_of_imported_address_wallet(wallet)

    @unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
    def test_multisig(self, mock_app_state, tmp_storage) -> None:
        password = "password"
        mock_app_state.credentials.get_wallet_password = lambda wallet_path: password
        wallet = Wallet(tmp_storage)

        seed_words = ('blast uniform dragon fiscal ensure vast young utility dinosaur abandon '+
            'rookie sure')
        ks1 = cast(BIP32_KeyStore, instantiate_keystore_from_text(
            KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))
        assert not ks1.is_watching_only()
        ks2 = cast(BIP32_KeyStore, instantiate_keystore_from_text(
            KeystoreTextType.EXTENDED_PUBLIC_KEY,
            'xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDben'
                'T33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec',
            watch_only=True))

        keystore = Multisig_KeyStore({ 'm': 2, 'n': 2, "cosigner-keys": [] })
        keystore.add_cosigner_keystore(ks1)
        keystore.add_cosigner_keystore(ks2)

        assert not keystore.is_watching_only()
        assert 2 == len(keystore.get_cosigner_keystores())

        masterkey_row = wallet.create_masterkey_from_keystore(keystore)

        account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.MULTISIG_BARE, 'text',
            AccountFlags.NONE, None, None)
        account_row = wallet.add_accounts([ account_row ])[0]
        account = MultisigAccount(wallet, account_row)
        wallet.register_account(account.get_id(), account)

        check_legacy_parent_of_multisig_wallet(wallet, password, seed_words)
        check_create_keys(wallet, account)


@pytest.mark.parametrize("storage_info",
    get_categorised_files2(TEST_WALLET_PATH, exclude_suffix="_testdata.json"))
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
def test_legacy_wallet_loading(mock_wallet_app_state, storage_info: WalletStorageInfo,
        caplog) -> None:
    password = initial_password = "123456"
    password_token = PasswordToken(password)
    mock_wallet_app_state.credentials.get_wallet_password = lambda wallet_path: password

    # When a wallet is composed of multiple files, we need to know which to load.
    wallet_filenames = []
    if storage_info.kind != StorageKind.DATABASE:
        wallet_filenames.append(storage_info.filename)
    if storage_info.kind in (StorageKind.DATABASE, StorageKind.HYBRID):
        wallet_filenames.append(storage_info.filename + DATABASE_EXT)

    temp_dir = tempfile.mkdtemp()
    for _wallet_filename in wallet_filenames:
        source_wallet_path = os.path.join(TEST_WALLET_PATH, _wallet_filename)
        wallet_path = os.path.join(temp_dir, _wallet_filename)
        shutil.copyfile(source_wallet_path, wallet_path)

    wallet_filename = storage_info.filename
    wallet_path = os.path.join(temp_dir, wallet_filename)
    # "<expected version>_<network>_<type>[_<subtype>]"
    (expected_version_text, expected_network, expected_type, *expected_subtypes) \
        = wallet_filename.split("_")
    expected_version = int(expected_version_text)

    if "testnet" == expected_network:
        Net.set_to(SVTestnet)
    elif "regtest" == expected_network:
        Net.set_to(SVRegTestnet)

    if storage_info.kind == StorageKind.HYBRID:
        pytest.fail("old development database not supported yet")

    storage = WalletStorage(wallet_path)

    has_password = True
    if "passworded" in expected_subtypes:
        text_store = storage.get_text_store()
        text_store.load_data(text_store.decrypt(initial_password))
    elif "encrypted" in expected_subtypes:
        pass
    elif expected_version >= 22:
        storage.check_password(initial_password)
    else:
        has_password = False

    with unittest.mock.patch(
        "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state") \
        as migration29_app_state:
            migration29_app_state.headers = mock_headers()
            try:
                storage.upgrade(has_password, password_token)
            except IncompatibleWalletError as exc:
                validate_wallet_migration_failure_message(storage_info, exc.args[0])
                return

    add_indefinite_credential_mock = unittest.mock.Mock()
    with unittest.mock.patch(
            'electrumsv.keystore.app_state.credentials.add_indefinite_credential',
            add_indefinite_credential_mock):
        try:
            wallet = Wallet(storage)
        except FileNotFoundError as e:
            if sys.version_info[:3] >= (3, 8, 0):
                msg = "Could not find module 'libusb-1.0.dll' (or one of its dependencies)."
                if msg in e.args[0]:
                    pytest.xfail("libusb DLL could not be found")
                    return
            raise e
        except OSError as e:
            if sys.version_info[:3] < (3, 8, 0):
                if "The specified module could not be found" in e.args[1]:
                    pytest.xfail("libusb DLL could not be found")
                    return
            raise e

    # Store any pre-password update related data to compare against post-password update data.
    prv_keypairs: Dict[str, str] = {}
    if "imported" == expected_type and "privkey" in wallet_filename:
        assert len(wallet.get_accounts()) == 2
        private_key_account = cast(ImportedPrivkeyAccount,
            [ entry for entry in wallet.get_accounts() if not entry.is_petty_cash() ][0])
        private_key_keystore = cast(Imported_KeyStore, private_key_account.get_keystore())
        # Pre-decrypt the prv for later comparison so the initial password is not needed there.
        for public_key, encrypted_prv in private_key_keystore._keypairs.items():
            prv_keypairs[public_key.to_hex()] = pw_decode(encrypted_prv, initial_password)

    password = "654321"
    future, update_completion_event = wallet.update_password(initial_password, password)
    # Wait for the database update to finish.
    future.result(5)
    # Wait for the done callback to finish.
    update_completion_event.wait()

    if "standard" == expected_type:
        check_legacy_parent_of_standard_wallet(wallet, password=password,
            add_indefinite_credential_mock=add_indefinite_credential_mock)
    elif "imported" == expected_type:
        if "privkey" in wallet_filename:
            check_legacy_parent_of_imported_privkey_wallet(wallet, password, prv_keypairs)
        elif "address" in expected_subtypes:
            check_legacy_parent_of_imported_address_wallet(wallet)
        else:
            raise Exception(f"unrecognised wallet file {wallet_filename}")
    elif "multisig" == expected_type:
        check_legacy_parent_of_multisig_wallet(wallet, password)
    elif "hardware" == expected_type:
        check_legacy_parent_of_hardware_wallet(wallet)
    elif "blank" == expected_type:
        check_parent_of_blank_wallet(wallet)
    else:
        raise Exception(f"unrecognised wallet file {wallet_filename}")

    check_specific_wallets(wallet, password, storage_info)

    if expected_network in { "testnet", "regtest" }:
        Net.set_to(SVMainnet)


def validate_wallet_migration_failure_message(storage_info: WalletStorageInfo, text: str) -> None:
    testdata_filename = storage_info.wallet_filepath +"_testdata.json"
    assert os.path.exists(testdata_filename)

    with open(testdata_filename, "r") as f:
        testdata = json.load(f)

    assert len(testdata) == 1
    assert "failure_message" in testdata
    assert text == testdata["failure_message"]


def check_specific_wallets(wallet: Wallet, password: str, storage_info: WalletStorageInfo) -> None:
    """
    We need to verify that the migrated data in each wallet is correctly migrated for each
    wallet type. A lot of this it would most likely be enough to check one migrated wallet,
    but we'll check them all just to be sure, and should consider varying the stored data
    to ensure more migration cases are checked.
    """
    testdata_filename = storage_info.wallet_filepath +"_testdata.json"
    assert os.path.exists(testdata_filename)

    with open(testdata_filename, "r") as f:
        testdata = json.load(f)

    expected_labels: Dict[bytes, str] = {
        hex_str_to_hash(k): v for (k, v) in testdata["expected_labels"].items()
    }
    settled_tx_hashes: Set[bytes] = {
        hex_str_to_hash(k) for k in testdata["settled_tx_hashes"]
    }
    expected_derivation_datas: Optional[List[Dict[str, Any]]] = testdata["derivation_datas"]

    if len(expected_labels):
        rows1 = wallet.data.read_transaction_descriptions(tx_hashes=list(expected_labels.keys()))
        assert { row1.tx_hash: row1.description  for row1 in rows1 } == expected_labels

    rows2 = wallet.data.read_transactions_exist(list(settled_tx_hashes))
    assert settled_tx_hashes == { row2.tx_hash for row2 in rows2 }

    # Account 1 is the pre-existing account (and predates the petty cash account).
    account = wallet.get_account(1)
    assert account is not None

    if account.is_petty_cash():
        assert not expected_derivation_datas
    elif expected_derivation_datas is not None:
        actual_derivation_datas: List[Dict[str, Any]] = []
        for keystore in account.get_keystores():
            data1 = keystore.to_derivation_data()
            if "seed" in data1:
                data1_typed = cast(MasterKeyDataBIP32, data1)
                if data1_typed["seed"] is not None:
                    data1_typed["seed"] = pw_decode(data1_typed["seed"], password)
                if data1_typed["xprv"] is not None:
                    data1_typed["xprv"] = pw_decode(data1_typed["xprv"], password)
                data1 = cast(Dict[str, Any], data1_typed)
            actual_derivation_datas.append(data1)
        assert expected_derivation_datas == actual_derivation_datas
    else:
        for keystore in account.get_keystores():
            with pytest.raises(IncompatibleWalletError):
                data1 = keystore.to_derivation_data()
                # if "seed" in data1:
                #     data1_typed = cast(MasterKeyDataBIP32, data1)
                #     if data1_typed["seed"] is not None:
                #         data1_typed["seed"] = pw_decode(data1_typed["seed"], password)
                #     if data1_typed["xprv"] is not None:
                #         data1_typed["xprv"] = pw_decode(data1_typed["xprv"], password)
                #     data1 = cast(Dict[str, Any], data1_typed)
                # print("expected_derivation_data", data1)


# class TestImportedPrivkeyAccount:
#     # TODO(rt12) REQUIRED add some unit tests for this account type. The following is obsolete.
#     def test_pubkeys_to_a_ddress(self, tmp_storage, network):
#         coin = network.COIN
#         privkey = PrivateKey.from_random()
#         WIF = privkey.to_WIF(network=coin)
#         wallet = _TestableWallet(tmp_storage)
#         account = ImportedPrivkeyAccount.from_text(wallet, WIF)
#         public_key = privkey.public_key
#         address = public_key.to_address(network=coin).to_string()
#         assert account.pubkeys_to_a_ddress(public_key) == address_from_string(address)


@pytest.mark.asyncio
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
async def test_transaction_script_offsets_and_lengths(mock_app_state, tmp_storage) -> None:
    mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"

    # Boilerplate setting up of a deterministic account. This is copied from above.
    password = 'password'
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
        AccountFlags.NONE, None, None)
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    assert account_row.default_masterkey_id is not None
    account = StandardAccount(wallet, account_row)
    wallet.register_account(account.get_id(), account)

    # Ensure that the keys used by the transaction are present to be linked to.
    account.derive_new_keys_until(RECEIVING_SUBPATH + (2,))

    db_context = tmp_storage.get_db_context()
    db = db_context.acquire_connection()
    try:
        tx_1 = Transaction.from_hex(tx_hex_funding)
        tx_hash_1 = tx_1.hash()
        # Add the funding transaction to the database and link it to key usage.
        link_state = TransactionLinkState()
        await wallet.import_transaction_async(tx_hash_1, tx_1, TxFlags.STATE_SIGNED,
            BlockHeight.LOCAL, link_state=link_state)

        # Verify all the transaction outputs are present and are linked to spending inputs.
        txo_rows = db_functions.read_transaction_outputs_full(db_context)
        assert len(txo_rows) == 2

        tx_data = db_functions.read_transaction_bytes(db_context, tx_hash_1)
        assert tx_data is not None

        assert txo_rows[0].txo_index == 0
        assert txo_rows[0].script_offset == 162
        assert txo_rows[0].script_length == 25
        script = Script(tx_data[txo_rows[0].script_offset:txo_rows[0].script_offset +
            txo_rows[0].script_length])
        assert list(script.ops()) == [Ops.OP_DUP, Ops.OP_HASH160,
            b'\xeax\x04\xa2\xc2f\x065r\xcc\x00\x9ac\xdc%\xdc\xc0\xe9\xd9\xb5',
            Ops.OP_EQUALVERIFY, Ops.OP_CHECKSIG]

        assert txo_rows[1].txo_index == 1
        assert txo_rows[1].script_offset == 196
        assert txo_rows[1].script_length == 25
        script = Script(tx_data[txo_rows[1].script_offset:txo_rows[1].script_offset +
            txo_rows[1].script_length])
        assert list(script.ops()) == [Ops.OP_DUP, Ops.OP_HASH160,
            b"\xad'\xed\xee6SP\xb6;P$\xa8\xf8\x16\x8er\x97\xbd\xd7\x0b",
            Ops.OP_EQUALVERIFY, Ops.OP_CHECKSIG]

        txi_rows = db_functions.read_transaction_inputs_full(db_context)
        assert len(txi_rows) == 1

        assert txi_rows[0].txi_index == 0
        assert txi_rows[0].script_offset == 42
        assert txi_rows[0].script_length == 106
        script = Script(tx_data[txi_rows[0].script_offset:txi_rows[0].script_offset +
            txi_rows[0].script_length])
        # [ Signature, PublicKey ]
        assert list(script.ops()) == [b'0D\x02 r\xc3\xca*j\xb2q\x14*p\xe1\tGA\x08\xb1\x18\x00\x81\x8a\xce\xcb\x19#%F^\x97\n\xd0\xcc\xcb\x02 \x11l\x8c\x05\xfa\xd2\xd5\xab+\xe3:\xe3\xfcSb\xb7\x13}\xb2m\x0b}\xdd\x00\x9e\xe8i-\xaa\xcdW\x91A', b'\x03\x7f7\xbb\r\x14\xdcr\xd6\x7f\x0c\xfbI\xf6G!c\x92K\xa8c\x82\xfd$\x90\xd5\xc0Ba8kp\xb0']
    finally:
        db_context.release_connection(db)


@pytest.mark.asyncio
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
async def test_transaction_import_removal(mock_app_state, tmp_storage) -> None:
    mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"

    # Boilerplate setting up of a deterministic account. This is copied from above.
    password = 'password'
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
        AccountFlags.NONE, None, None)
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    assert account_row.default_masterkey_id is not None
    account = StandardAccount(wallet, account_row)
    wallet.register_account(account.get_id(), account)

    # Ensure that the keys used by the transaction are present to be linked to.
    account.derive_new_keys_until(RECEIVING_SUBPATH + (2,))

    db_context = tmp_storage.get_db_context()
    db = db_context.acquire_connection()
    try:
        tx_1 = Transaction.from_hex(tx_hex_funding)
        tx_hash_1 = tx_1.hash()
        # Add the funding transaction to the database and link it to key usage.
        link_state = TransactionLinkState()
        await wallet.import_transaction_async(tx_hash_1, tx_1, TxFlags.STATE_SIGNED,
            BlockHeight.LOCAL, link_state=link_state)

        # Verify the received funds are present.
        tv_rows1 = db_functions.read_transaction_values(db_context, tx_hash_1)
        assert len(tv_rows1) == 1
        assert tv_rows1[0].account_id == account.get_id()
        assert tv_rows1[0].total == 1044113

        balance = db_functions.read_account_balance(db_context, account.get_id())
        assert balance == WalletBalance(0, 0, 0, 1044113)

        balance = db_functions.read_wallet_balance(db_context)
        assert balance == WalletBalance(0, 0, 0, 1044113)

        tx_2 = Transaction.from_hex(tx_hex_spend)
        tx_hash_2 = tx_2.hash()
        # Add the spending transaction to the database and link it to key usage.
        link_state = TransactionLinkState()
        await wallet.import_transaction_async(tx_hash_2, tx_2, TxFlags.STATE_SIGNED,
            BlockHeight.LOCAL, link_state=link_state)

        # Verify both the received funds are present.
        tv_rows2 = db_functions.read_transaction_values(db_context, tx_hash_2)
        assert len(tv_rows2) == 1
        assert tv_rows2[0].account_id == account.get_id()
        assert tv_rows2[0].total == -1044113

        # Check the transaction balance.
        balance = db_functions.read_account_balance(db_context, account.get_id())
        assert balance == WalletBalance(0, 0, 0, 0)

        balance = db_functions.read_wallet_balance(db_context)
        assert balance == WalletBalance(0, 0, 0, 0)

        # Verify all the transaction outputs are present and are linked to spending inputs.
        txof_rows = db_functions.read_transaction_outputs_full(db_context)
        assert len(txof_rows) == 3
        # tx_1.output0 is linked to the first key.
        assert txof_rows[0].tx_hash == tx_hash_1 and txof_rows[0].txo_index == 0 and \
            txof_rows[0].keyinstance_id == 1 and txof_rows[0].spending_tx_hash == tx_hash_2 and \
            txof_rows[0].spending_txi_index == 0
        # tx_1.output1 is to the payer's change and not linked.
        assert txof_rows[1].tx_hash == tx_hash_1 and txof_rows[1].txo_index == 1 and \
            txof_rows[1].keyinstance_id is None
        # tx_2.output2 is to some other payee.
        assert txof_rows[2].tx_hash == tx_hash_2 and txof_rows[2].txo_index == 0 and \
            txof_rows[2].keyinstance_id is None

        # Verify all the transactions are linked to the account.
        rows = db_functions.read_transaction_hashes(db_context, account.get_id())
        assert len(rows) == 2
        assert set(rows) == { tx_hash_1, tx_hash_2 }

        # Trying to remove the parent transaction when there is a child transaction should fail.
        with pytest.raises(TransactionRemovalError):
            wallet.remove_transaction(tx_hash_1)

        # Remove both transactions (does not delete).
        future_2 = wallet.remove_transaction(tx_hash_2)
        # We need to wait for this to succeed to delete the second. If we really wanted faster
        # removal, we would have a bulk removal function.
        future_2.result()
        future_1 = wallet.remove_transaction(tx_hash_1)
        future_1.result()

        # Verify that the transaction outputs are still linked to key usage (harmless).
        txo_rows = db_functions.read_transaction_outputs_explicit(db_context,
            [ Outpoint(tx_hash_1, 0) ])
        assert len(txo_rows) == 1
        # This value is not cleared. It's not a link to anything that can clash.
        assert txo_rows[0].keyinstance_id == 1

        # Verify that the account transaction link entries have been deleted.
        rows = db_functions.read_transaction_hashes(db_context, account.get_id())
        # Any rows have been deleted.
        assert len(rows) == 0

        # Verify that both transactions have been flagged as removed.
        row1 = db_functions.read_transaction_flags(db_context, tx_hash_1)
        assert row1 is not None
        assert TxFlags(row1) == TxFlags.STATE_SIGNED | TxFlags.REMOVED

        row2 = db_functions.read_transaction_flags(db_context, tx_hash_2)
        assert row2 is not None
        assert TxFlags(row2) == TxFlags.STATE_SIGNED | TxFlags.REMOVED
    finally:
        db_context.release_connection(db)


async def try_get_mapi_proofs_mock(tx_hashes: list[bytes], reorging_chain: Chain) \
        -> tuple[set[bytes], list[MerkleProofRow]]:
    return set(), []


class MockHeadersClient:
    pass


@pytest.mark.asyncio
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
async def test_reorg(mock_app_state, tmp_storage) -> None:
    """
    This test is intended to show that the current subscription mechanism combined with the
    undoing of verifications, should leave the transactions affected in state where their
    remining gets detected and adequately processed.
    """
    mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"

    # Boilerplate setting up of a deterministic account. This is copied from above.
    password = 'password'
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    wallet = Wallet(tmp_storage)
    wallet.try_get_mapi_proofs = try_get_mapi_proofs_mock
    wallet._blockchain_server_state = MockHeadersClient()
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
        AccountFlags.NONE, None, None)
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    assert account_row.default_masterkey_id is not None
    account = StandardAccount(wallet, account_row)
    wallet.register_account(account.get_id(), account)

    # Ensure that the keys used by the transaction are present to be linked to.
    account.derive_new_keys_until(RECEIVING_SUBPATH + (2,))

    db_context = tmp_storage.get_db_context()
    db = db_context.acquire_connection()
    try:
        BLOCK_HASH_REORGED1 = b'HASH_FOR_REORG1'  # which will affect some txs
        BLOCK_POSITION = 3

        BLOCK_HASH_REORGED2 = b'HASH_FOR_REORG2'  # we have no transactions in this block

        ## Add a transaction that is settled.
        tx_1 = Transaction.from_hex(tx_hex_funding)
        tx_hash_1 = tx_1.hash()
        # Add the funding transaction to the database and link it to key usage.
        wallet._missing_transactions[tx_hash_1] = MissingTransactionEntry(
            TransactionImportFlag.UNSET)
        link_state = TransactionLinkState()

        BLOCK_HEIGHT = 232
        proof_row = MerkleProofRow(BLOCK_HASH_REORGED1, BLOCK_POSITION, BLOCK_HEIGHT,
            b'TSC_FAKE_PROOF_BYTES', tx_hash_1)
        await wallet.import_transaction_async(tx_hash_1, tx_1, TxFlags.STATE_SETTLED, BLOCK_HEIGHT,
            link_state=link_state, block_hash=BLOCK_HASH_REORGED1, block_position=BLOCK_POSITION,
            proof_row=proof_row)

        tx_metadata_1 = wallet.data.get_transaction_metadata(tx_hash_1)
        assert tx_metadata_1 is not None
        assert tx_metadata_1.block_hash == BLOCK_HASH_REORGED1
        assert tx_metadata_1.block_position == BLOCK_POSITION
        assert tx_metadata_1.fee_value is None  # == FEE_VALUE

        # Verify that the transaction does not qualify for subscriptions.
        sub_rows = db_functions.read_spent_outputs_to_monitor(db_context)
        assert not len(sub_rows)

        # Reorg that doesn't affect our transactions
        # We have no transactions in this block - there should be no effect
        await wallet.on_reorg([BLOCK_HASH_REORGED2], wallet._current_chain)
        tx_flags1 = db_functions.read_transaction_flags(db_context, tx_hash_1)
        assert tx_flags1 is not None
        assert tx_flags1 == TxFlags.STATE_SETTLED

        # Check the mined metadata is the same as we set.
        tx_metadata_1 = wallet.data.get_transaction_metadata(tx_hash_1)
        assert tx_metadata_1 is not None
        assert tx_metadata_1.block_hash == BLOCK_HASH_REORGED1
        assert tx_metadata_1.block_position == BLOCK_POSITION
        assert tx_metadata_1.fee_value is None # == FEE_VALUE

        # Real reorg.
        await wallet.on_reorg([BLOCK_HASH_REORGED1], wallet._current_chain)

        # Check that the expectation is that the nodes have for now moved it back into the mempool.
        tx_flags1 = db_functions.read_transaction_flags(db_context, tx_hash_1)
        assert tx_flags1 is not None
        assert tx_flags1 == TxFlags.STATE_CLEARED

        # Check that all the mined metadata is reset to mempool state.
        tx_metadata_1 = wallet.data.get_transaction_metadata(tx_hash_1)
        assert tx_metadata_1 is not None
        assert tx_metadata_1.block_hash is None
        assert tx_metadata_1.block_position is None
        assert tx_metadata_1.fee_value is None

        ## Verify that the transaction now qualify for subscriptions, which would mean that
        ## we would listen for re-mining events.
        sub_rows = db_functions.read_spent_outputs_to_monitor(db_context)
        assert len(sub_rows) == 1
        # This is an output that tx_1 spends, we do not actually know what it is to compare,
        # but it will be output 1 in whatever transaction that input spends.
        # assert sub_rows[0].out_tx_hash == tx_hash_1
        assert sub_rows[0].out_index == 1
        assert sub_rows[0].in_tx_hash == tx_hash_1
        assert sub_rows[0].in_index == 0
        assert sub_rows[0].block_hash is None
    finally:
        db_context.release_connection(db)


@pytest.mark.asyncio
@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
async def test_unverified_transactions(mock_app_state, tmp_storage) -> None:
    mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"

    # Boilerplate setting up of a deterministic account. This is copied from above.
    password = 'password'
    seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    wallet = Wallet(tmp_storage)
    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
        AccountFlags.NONE, None, None)
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    assert account_row.default_masterkey_id is not None
    account = StandardAccount(wallet, account_row)
    wallet.register_account(account.get_id(), account)

    # Ensure that the keys used by the transaction are present to be linked to.
    account.derive_new_keys_until(RECEIVING_SUBPATH + (2,))

    db_context = tmp_storage.get_db_context()
    db = db_context.acquire_connection()
    try:
        ## Add a transaction that is settled.
        tx_1 = Transaction.from_hex(tx_hex_funding)
        tx_hash_1 = tx_1.hash()
        # Add the funding transaction to the database and link it to key usage.
        wallet._missing_transactions[tx_hash_1] = MissingTransactionEntry(
            TransactionImportFlag.UNSET)
        link_state = TransactionLinkState()
        await wallet.import_transaction_async(tx_hash_1, tx_1, TxFlags.STATE_CLEARED,
            BlockHeight.MEMPOOL, link_state=link_state)

        pass
    finally:
        db_context.release_connection(db)


@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
def test_transaction_locks(mock_app_state, tmp_storage) -> None:
    mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"

    tx_hash_1 = b'123'
    tx_hash_2 = b'321'

    wallet = Wallet(tmp_storage)

    # Acquire and lock the first transaction.
    lock1a = wallet._obtain_transaction_lock(tx_hash_1)
    assert lock1a is not None
    assert lock1a.acquire(blocking=False)

    # Acquire and lock the second transaction.
    lock2 = wallet._obtain_transaction_lock(tx_hash_2)
    assert lock2 is not None
    assert lock2.acquire(blocking=False)

    # Acquire and try to lock the first transaction again but expect to fail.
    lock1b = wallet._obtain_transaction_lock(tx_hash_1)
    assert lock1b is not None
    assert lock1b is lock1a

    # NOTE There is no point in acquiring a lock twice to prove it blocks as the lock is an
    #   RLock and we can acquire it as many times as we want in this thread.

    lock1a.release()
    lock2.release()

    assert wallet._transaction_locks == { tx_hash_1: (lock1b, 2), tx_hash_2: (lock2, 1) }
    wallet._relinquish_transaction_lock(tx_hash_2)
    assert wallet._transaction_locks == { tx_hash_1: (lock1b, 2) }
    wallet._relinquish_transaction_lock(tx_hash_1) # lock1b
    assert wallet._transaction_locks == { tx_hash_1: (lock1a, 1) }
    wallet._relinquish_transaction_lock(tx_hash_1) # lock1a
    assert len(wallet._transaction_locks) == 0


@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
def test_wallet_migration_database_script_metadata(mock_app_state) -> None:
    password = initial_password = "123456"
    password_token = PasswordToken(password)
    mock_app_state.credentials.get_wallet_password = lambda wallet_path: password

    wallet_filename = "17_testnet_imported_address_2"
    temp_dir = tempfile.mkdtemp()
    source_wallet_path = os.path.join(TEST_WALLET_PATH, wallet_filename)
    wallet_path = os.path.join(temp_dir, wallet_filename)
    shutil.copyfile(source_wallet_path, wallet_path)

    has_password = False
    Net.set_to(SVTestnet)
    try:
        storage = WalletStorage(wallet_path)
        with unittest.mock.patch(
            "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state") \
            as migration29_app_state:
                migration29_app_state.headers = mock_headers()
                storage.upgrade(has_password, password_token)

        wallet = Wallet(storage)
        wallet.start(None)
        try:
            db_context = wallet.get_db_context()

            tx_hash = hex_str_to_hash(
                "2d04beb35232461d9eb27cd7bf2375e86a1e8e396ce6842a09549ed58ceddc93")
            tx_data = db_functions.read_transaction_bytes(db_context, tx_hash)
            assert tx_data is not None

            txi_rows = db_functions.read_transaction_inputs_full(db_context)
            assert len(txi_rows) == 10
            assert txi_rows[0].txi_index == 0
            assert txi_rows[0].script_offset == 42
            assert txi_rows[0].script_length == 106
            script = Script(tx_data[txi_rows[0].script_offset:txi_rows[0].script_offset +
                txi_rows[0].script_length])
            assert list(script.ops()) == [b"0D\x02 ?\x8e^ht\xdd\xd7\xd1s^\x0f)\x18\x0b,\x7fB\x1f\xe7i(\\\xc7\x8f>\x1c\x8eHM\x94\x080\x02 \x07`\x82\xfb\xaf\xdf\xa9\x00'\xb9\xd89RY\xa7\xad\x9f\xcb\x83\xf2\xbe\xabC\x0e\xe7G|\x99*'\x11tA", b'\x02\x1f\x03\xb5\xa2\xf6T+\xaca\x9a\xa3\x82n\xdb\x90\x04k\xb2\x8c\xc8ot\xd3\xf5{\xa9ie\x81\xb5\x95"']

            txo_rows = db_functions.read_transaction_outputs_full(db_context)
            assert len(txo_rows) == 1

            assert txo_rows[0].txo_index == 0
            assert txo_rows[0].script_offset == 1489
            assert txo_rows[0].script_length == 25
            script = Script(tx_data[txo_rows[0].script_offset:txo_rows[0].script_offset +
                txo_rows[0].script_length])
            assert list(script.ops()) == [Ops.OP_DUP, Ops.OP_HASH160,
                b'\xe0\xc1\x90\x14\xa3j\x8f\x94\x91\xcf=\xf2\x14+\xa3b2\xc4\n!',
                Ops.OP_EQUALVERIFY, Ops.OP_CHECKSIG]
        finally:
            wallet.stop()
    finally:
        Net.set_to(SVMainnet)


def test_extend_transaction_complete_hex() -> None:
    tx = Transaction.from_hex(tx_hex_funding)
    tx_context = TransactionContext()

    mock_storage = cast(WalletStorage, MockStorage("password"))

    with unittest.mock.patch("electrumsv.wallet.app_state") as mock_app_state:
        mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"
        wallet = Wallet(mock_storage)

    wallet.extend_transaction(tx, tx_context)

    assert tx_context.invoice_id is None
    assert not len(tx_context.account_descriptions)
    assert len(tx_context.parent_transactions) == 0
    assert tx_context.spent_outpoint_values == {}
    assert tx_context.key_datas_by_spent_outpoint == {}
    assert tx_context.key_datas_by_txo_index == {}


INCOMPLETE_TX_MULTISIG_DICT = {"version": 1, "hex": "01000000018e3efc1708cc072b9ad09ebb32bf0bd7b4681c4db8a15162d3cd8f44e68cd800000000004b00473044022056df5ab9b9294011a11e85b85af87994d386397ee44cd118957fd6e37b513b78022048f6d1fbe705cb10740f45416637915b8726949d2b5bd2fe049645db1b8c84b74101ffffffffff0b40420f00000000001976a914def53ee6c8a15961eea0b07dea23e5404e38a71188ac40ea70000000000047522102e99c5ef6e873396a9f4495dce12457d6fc9307c10b802d0592a43e96ae45cac92103e5a30131ca630fe80d4c1ee435949be822ebae51be7283738d6194c3a0979a6152ae00127a000000000047522102407c4480ce6538af7e6de0117a72699706d08770fb59ada5b626eb2fe16079af2103494d1db5d12adf43a3b97257d18422c164140a3d4db493835ea96dc390c86d4052ae405489000000000047522103797b05207c23dad3c51a4bf48deb25b555f6a17af8abec4a58faffff523b157c2103b7da30209d59445531f6e141837db7bdb27726c503bf34a5ebf1219337f3430252ae08f390000000000047522102103f54f834961d5cb994cc2201751a10672978ab4f9f665ff491323007a94cf0210259def56764098f5a6fea9640035494ac9c604435ec3ff57647be928d4e62080752aea0029400000000004752210258a41c688b97b426130c75093ce590a2581d7837ae11963776af762b1624a7582103d14b8d7005598c1b1944d013957f7db20ea7a1c1e07d1887bef6df5af5dc08f652ae8096980000000000475221023c7b0b01c47b8afcaa0688faf7b2068ef2f0f27c9c24be9eea297f0380b82d212102b55319c1d7aa64f424889df6ed6f42b578d2786d4d6a5aa77a4cef9758c08df752ae809698000000000047522102c67f0584c61f29ee8bd9e851072fb852c5c53c137b13ea661e3de502db74eb2f2103289f9baafdca77a06fb2d1b960e906017d52356416d8766ba31666784ec2fbae52ae00b19e00000000004752210360245a9124311eecb8f0e70904c580040f86e3dea0ada1b442ca78d8af7be57921036052fa7851930559571b4950c872399a03792fe2814319e9b35e56a0b57f2acc52aec0d8a70000000000475221030f71df9dbc747c2b5f6b3df3941bca4f8b390eef3b3768c1c2ace757cedf3237210369b68d182c8892dd8d8e2605fd97c3934ebba9497f61786949363a4227139ea352ae809fd500000000004752210289257e1bca327225f75549a1c3dabe0d854acd74bda4512bbfccb38f3fe8746c2102fe240aa6a9f06b8c15c652ea1f91ec1d0b8d3438f3582e9b96b203cd7c10750052ae71000000", "complete": False, "description": "Pay someone", "inputs": [{"script_type": 5, "threshold": 2, "value": 100000000, "signatures": ["3044022056df5ab9b9294011a11e85b85af87994d386397ee44cd118957fd6e37b513b78022048f6d1fbe705cb10740f45416637915b8726949d2b5bd2fe049645db1b8c84b741", "ff"], "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [0, 0]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [0, 0]}]}], "outputs": [{"script_type": 0, "x_pubkeys": []}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 5]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 5]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 6]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 6]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 1]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 1]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 9]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 9]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 2]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 2]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 7]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 7]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 3]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 3]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 0]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 0]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 4]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 4]}]}, {"script_type": 5, "x_pubkeys": [{"bip32_xpub": "tpubD6NzVbkrYhZ4XshEBN7ots6WCazhf7hz97GEWnyP5DqSfQEXyyPHzaqfGbNsPie25JdxjmBT6GpZhaMdnrZvtdSzepXM2JSrNrRWDUrjvnC", "derivation_path": [1, 8]}, {"bip32_xpub": "tpubD6NzVbkrYhZ4XdQStyZX79qfs5UjGxuJXZk81ukgGKiTq5uSsXtQff51rccS85WUW4ft9fQe3ytfHrViJ1dB1z8tFCzVktD5uxLRUzZ1hD8", "derivation_path": [1, 8]}]}]}

def test_extend_transaction_incomplete_non_database() -> None:
    tx, tx_context = transaction_from_electrumsv_dict(INCOMPLETE_TX_MULTISIG_DICT, [])

    mock_storage = cast(WalletStorage, MockStorage("password"))
    with unittest.mock.patch("electrumsv.wallet.app_state") as mock_app_state:
        mock_app_state.credentials.get_wallet_password = lambda wallet_path: "password"
        wallet = Wallet(mock_storage)

    wallet.extend_transaction(tx, tx_context)

    expected_spent_output_key_data = {
        Outpoint(
            hex_str_to_hash("00d88ce6448fcdd36251a1b84d1c68b4d70bbf32bb9ed09a2b07cc0817fc3e8e"),0):
                DatabaseKeyDerivationData(derivation_path=(0, 0), account_id=None,
                    masterkey_id=None, keyinstance_id=None,
                    source=DatabaseKeyDerivationType.IMPORTED)
    }
    assert tx_context.invoice_id is None
    assert tx_context.account_descriptions == {}
    # assert tx_context.description == "Pay someone"
    assert len(tx_context.parent_transactions) == 0
    assert len(tx_context.spent_outpoint_values) == 0
    assert tx_context.key_datas_by_spent_outpoint == expected_spent_output_key_data

    # Ten change addresses.
    # - There are no database ids, as there are not keys or transactions or anything in the database.
    # - The metadata is classified as being from an imported source, because it is.
    expected_txo_key_datas = {
        1: DatabaseKeyDerivationData(derivation_path=(1, 5), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        2: DatabaseKeyDerivationData(derivation_path=(1, 6), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        3: DatabaseKeyDerivationData(derivation_path=(1, 1), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        4: DatabaseKeyDerivationData(derivation_path=(1, 9), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        5: DatabaseKeyDerivationData(derivation_path=(1, 2), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        6: DatabaseKeyDerivationData(derivation_path=(1, 7), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        7: DatabaseKeyDerivationData(derivation_path=(1, 3), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        8: DatabaseKeyDerivationData(derivation_path=(1, 0), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        9: DatabaseKeyDerivationData(derivation_path=(1, 4), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED),
        10: DatabaseKeyDerivationData(derivation_path=(1, 8), account_id=None, masterkey_id=None, keyinstance_id=None, source=DatabaseKeyDerivationType.IMPORTED)
    }
    assert tx_context.key_datas_by_txo_index == expected_txo_key_datas


SEQUENCE_TX_1_HEX = "01000000018e3efc1708cc072b9ad09ebb32bf0bd7b4681c4db8a15162d3cd8f44e68cd800010000006a47304402202bcbbf0c2f530dc6365397d2788b479b6801a4fefd0c3c445f9527cb156ea12902205f05803062aa550f662e484d1691949c933e7b212b22e848e1022e8d95ba58f64121032a29bd9fb50181164dae4c098e0cd5ed5c1fca0a998628415827c0612708090dffffffff0300e1f505000000001976a914da661cf35fc34999f571319d3e6f425d8783886688ac000e2707000000001976a9141211f3ad5d77afab5513cc72f0a12443294d5b5288ac8ca2bf07000000001976a91453a56c1b8a0da350b08bf06849f359dda8f69ea588ac72000000"
SEQUENCE_TX_2_HEX = "0100000001fe6e0df8db19d66ff62d26ef08acfae3498a80484eb47717ba6e15da84a17098000000006a47304402204503da5da92d0c96b271b2ece053473790e29ccf047332ddcda3c7cd47ea1b06022011a3e94494f95eded70779916ea035c53bcd5e80ba84ff34b3f0c1f74a6ec83d412102a02ccedd7475255197165b0f6825782276697b0bcb392c60ae9b3ae461200ae1ffffffff0b40420f00000000001976a914e20641e8c54f3be047a32b6da573a992d87d164988acc0cf6a00000000001976a914594c73f64e977d209e630e43851d344e5805618488ac00127a00000000001976a914d2368c3efb8d47582d66e780ea82acb7924d793f88ac40548900000000001976a914eada92ab2e26c52d82fd3672d164ce3ce48b527a88ac80618c00000000001976a914655e0716d7de554c0d5e3df0c46be9898ee626d788ac80969800000000001976a9142e7f8a6d66f7e1ff1beacf10dbb41da151f6be7488ac80969800000000001976a9144694d226a87d0921b0f7d615f5475eada6845a6088ac80969800000000001976a91447ddddc2d6ea1a0587117f790dd52a501addf5aa88ac00b19e00000000001976a9144f7ca1a81762c2b177ae359065e1b90b00f26b2988acc0d8a700000000001976a9147d6d128f145fd73be02129e9e800412303c5bd3488acd4b8db00000000001976a914d850f5e18bbe3bd9222321f8502407ea73f1904f88ac73000000"


@pytest.mark.asyncio
async def test_extend_transaction_sequence() -> None:
    # Boilerplate setting up of a deterministic account. This is copied from above.
    password = 'password'
    seed_words = "supply return potato wait seek lamp secret amateur broom club track warrior"
    child_keystore = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_SEED_WORDS, seed_words, password))

    mock_storage = cast(WalletStorage, MockStorage("password"))
    with unittest.mock.patch("electrumsv.wallet.app_state") as mock_app_state:
        mock_app_state.credentials.get_wallet_password = lambda wallet_path: password
        wallet = Wallet(mock_storage)

    masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)
    assert masterkey_row.flags == MasterKeyFlags.ELECTRUM_SEED

    raw_account_row = AccountRow(-1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...',
        AccountFlags.NONE, None, None)
    account_row = wallet.add_accounts([ raw_account_row ])[0]
    assert account_row.default_masterkey_id is not None
    account = StandardAccount(wallet, account_row)
    wallet.register_account(account.get_id(), account)

    db_context = mock_storage.get_db_context()
    assert db_context is not None
    db = db_context.acquire_connection()
    try:
        tx_1 = Transaction.from_hex(SEQUENCE_TX_1_HEX)
        # We know these are the used keys, and we approximate them being active.
        future, keyinstance_rows = account.derive_new_keys_until((0, 0))
        if future is not None:
            future.result()
        assert len(keyinstance_rows) == 1
        keyinstance_row = keyinstance_rows[0]
        assert keyinstance_row.account_id == account_row.account_id
        assert keyinstance_row.masterkey_id == masterkey_row.masterkey_id
        assert keyinstance_row.keyinstance_id == 1

        tx_hash_1 = tx_1.hash()
        # Add the funding transaction to the database and link it to key usage.
        link_state = TransactionLinkState()
        block_height = BlockHeight.LOCAL
        await wallet.import_transaction_async(tx_hash_1, tx_1, TxFlags.STATE_SIGNED, block_height,
            link_state=link_state)

        tx_1_context = TransactionContext()
        wallet.extend_transaction(tx_1, tx_1_context)

        assert tx_1_context.invoice_id is None
        assert tx_1_context.account_descriptions == {}
        assert len(tx_1_context.parent_transactions) == 0
        assert tx_1_context.spent_outpoint_values == {}
        assert tx_1_context.key_datas_by_spent_outpoint == {}

        assert len(tx_1_context.key_datas_by_txo_index) == 1
        assert 0 in tx_1_context.key_datas_by_txo_index
        txo_key_data = tx_1_context.key_datas_by_txo_index[0]
        assert txo_key_data.derivation_path == (0, 0)
        assert txo_key_data.account_id == account_row.account_id
        assert txo_key_data.masterkey_id == masterkey_row.masterkey_id
        assert txo_key_data.keyinstance_id == 1
        assert txo_key_data.source == DatabaseKeyDerivationType.EXTENSION_LINKED

        tx_2 = Transaction.from_hex(SEQUENCE_TX_2_HEX)

        tx_2_context_a = TransactionContext()
        wallet.extend_transaction(tx_2, tx_2_context_a)
        assert tx_2_context_a.invoice_id is None
        assert tx_2_context_a.account_descriptions == {}
        assert len(tx_2_context_a.parent_transactions) == 0
        spent_output_values = {
            Outpoint(tx_1.hash(), 0): 100000000
        }
        assert tx_2_context_a.spent_outpoint_values == spent_output_values
        assert len(tx_2_context_a.key_datas_by_spent_outpoint) == 1
        assert Outpoint(tx_1.hash(), 0) in tx_2_context_a.key_datas_by_spent_outpoint
        txi_key_data = tx_2_context_a.key_datas_by_spent_outpoint[Outpoint(tx_1.hash(), 0)]
        assert txi_key_data.derivation_path == (0, 0)
        assert txi_key_data.account_id == account_row.account_id
        assert txi_key_data.masterkey_id == masterkey_row.masterkey_id
        assert txi_key_data.keyinstance_id == 1
        assert txi_key_data.source == DatabaseKeyDerivationType.EXTENSION_UNLINKED

        assert len(tx_2_context_a.key_datas_by_txo_index) == 10
        expected_derivation_paths = { (1, i) for i in range(10) }
        for txo_index in range(10):
            # We start at output 1 for change. Output 0 is external payment.
            assert txo_index+1 in tx_2_context_a.key_datas_by_txo_index
            txo_key_data = tx_2_context_a.key_datas_by_txo_index[txo_index+1]
            assert txo_key_data.derivation_path in expected_derivation_paths
            assert txo_key_data.account_id == account_row.account_id
            assert txo_key_data.masterkey_id is None
            assert txo_key_data.keyinstance_id is None
            assert txo_key_data.source == DatabaseKeyDerivationType.EXTENSION_EXPLORATION
            expected_derivation_paths.remove(txo_key_data.derivation_path)
        assert len(expected_derivation_paths) == 0

        ## Try again with the transaction not in the database, but change keys created.
        # We know these are the used change keys, and we approximate them being active.
        future, keyinstance_rows = account.derive_new_keys_until((1, 9))
        if future is not None:
            future.result()
        assert len(keyinstance_rows) == 10

        tx_2_context_b = TransactionContext()
        wallet.extend_transaction(tx_2, tx_2_context_b)
        assert tx_2_context_b.invoice_id is None
        assert tx_2_context_b.account_descriptions == {}
        assert len(tx_2_context_b.parent_transactions) == 0
        spent_output_values = {
            Outpoint(tx_1.hash(), 0): 100000000
        }
        assert tx_2_context_b.spent_outpoint_values == spent_output_values
        assert len(tx_2_context_b.key_datas_by_spent_outpoint) == 1
        assert Outpoint(tx_1.hash(), 0) in tx_2_context_b.key_datas_by_spent_outpoint
        txi_key_data = tx_2_context_b.key_datas_by_spent_outpoint[Outpoint(tx_1.hash(), 0)]
        assert txi_key_data.derivation_path == (0, 0)
        assert txi_key_data.account_id == account_row.account_id
        assert txi_key_data.masterkey_id == masterkey_row.masterkey_id
        assert txi_key_data.keyinstance_id == 1
        assert txi_key_data.source == DatabaseKeyDerivationType.EXTENSION_UNLINKED

        assert len(tx_2_context_b.key_datas_by_txo_index) == 10
        expected_derivation_paths = { (1, i) for i in range(10) }
        for txo_index in range(10):
            # We start at output 1 for change. Output 0 is external payment.
            assert txo_index+1 in tx_2_context_b.key_datas_by_txo_index
            txo_key_data = tx_2_context_b.key_datas_by_txo_index[txo_index+1]
            assert txo_key_data.derivation_path in expected_derivation_paths
            assert txo_key_data.account_id == account_row.account_id
            assert txo_key_data.masterkey_id == masterkey_row.masterkey_id
            assert txo_key_data.keyinstance_id is not None
            assert txo_key_data.source == DatabaseKeyDerivationType.EXTENSION_UNLINKED
            expected_derivation_paths.remove(txo_key_data.derivation_path)
        assert len(expected_derivation_paths) == 0

        ## Try again with the transaction in the database.
        tx_hash_2 = tx_2.hash()
        # Add the funding transaction to the database and link it to key usage.
        link_state = TransactionLinkState()
        await wallet.import_transaction_async(tx_hash_2, tx_2, TxFlags.STATE_SIGNED,
            BlockHeight.LOCAL, link_state=link_state)

        tx_2_context_b = TransactionContext()
        wallet.extend_transaction(tx_2, tx_2_context_b)
        assert tx_2_context_b.invoice_id is None
        assert tx_2_context_b.account_descriptions == {}
        assert len(tx_2_context_b.parent_transactions) == 0
        spent_output_values = {
            Outpoint(tx_1.hash(), 0): 100000000
        }
        assert tx_2_context_b.spent_outpoint_values == spent_output_values
        assert len(tx_2_context_b.key_datas_by_spent_outpoint) == 1
        assert Outpoint(tx_1.hash(), 0) in tx_2_context_b.key_datas_by_spent_outpoint
        txi_key_data = tx_2_context_b.key_datas_by_spent_outpoint[Outpoint(tx_1.hash(), 0)]
        assert txi_key_data.derivation_path == (0, 0)
        assert txi_key_data.account_id == account_row.account_id
        assert txi_key_data.masterkey_id == masterkey_row.masterkey_id
        assert txi_key_data.keyinstance_id == 1
        assert txi_key_data.source == DatabaseKeyDerivationType.EXTENSION_LINKED

        assert len(tx_2_context_b.key_datas_by_txo_index) == 10
        expected_derivation_paths = { (1, i) for i in range(10) }
        for txo_index in range(10):
            # We start at output 1 for change. Output 0 is external payment.
            assert txo_index+1 in tx_2_context_b.key_datas_by_txo_index
            txo_key_data = tx_2_context_b.key_datas_by_txo_index[txo_index+1]
            assert txo_key_data.derivation_path in expected_derivation_paths
            assert txo_key_data.account_id == account_row.account_id
            assert txo_key_data.masterkey_id == masterkey_row.masterkey_id
            assert txo_key_data.keyinstance_id is not None
            assert txo_key_data.source == DatabaseKeyDerivationType.EXTENSION_LINKED
            expected_derivation_paths.remove(txo_key_data.derivation_path)
        assert len(expected_derivation_paths) == 0
    finally:
        db_context.release_connection(db)


@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
def test_is_header_within_current_chain(app_state) -> None:
    header_bytes = b"fake header"
    block_hash = double_sha256(header_bytes)

    app_state.raw_header_at_height = lambda chain_arg, height_arg: header_bytes
    app_state.credentials.get_wallet_password = lambda wallet_path: "password"

    mock_storage = cast(WalletStorage, MockStorage("password"))
    wallet = Wallet(mock_storage)

    # No current chain, always returns `False`.
    assert wallet._current_chain is None
    assert not wallet.is_header_within_current_chain(10, b'ignored')

    # header_height > current_tip_header.height -> False (beyond current chain scope)
    wallet._current_chain = unittest.mock.Mock()
    wallet._current_tip_header = unittest.mock.Mock()
    wallet._current_tip_header.height = 5
    assert not wallet.is_header_within_current_chain(10, b'ignored')

    # block hash does not match the header at that height -> False
    wallet._current_chain = unittest.mock.Mock()
    wallet._current_tip_header = unittest.mock.Mock()
    wallet._current_tip_header.height = 10
    assert not wallet.is_header_within_current_chain(5, b'not the block hash')

    # block hash does match the header at that height -> True
    wallet._current_chain = unittest.mock.Mock()
    wallet._current_tip_header = unittest.mock.Mock()
    wallet._current_tip_header.height = 10
    assert wallet.is_header_within_current_chain(5, block_hash)


@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
def test_lookup_header_for_hash(app_state) -> None:
    header_bytes = b"fake header"
    block_hash = double_sha256(header_bytes)
    fake_header1 = unittest.mock.Mock()
    fake_header2 = unittest.mock.Mock()
    fake_chain1 = unittest.mock.Mock()
    fake_chain2 = unittest.mock.Mock()

    def lookup_header_fail(block_hash: bytes) -> tuple[Header, Chain]:
        raise MissingHeader

    def lookup_header_succeed1(lookup_block_hash: bytes) -> tuple[Header, Chain]:
        assert lookup_block_hash == block_hash
        return cast(Header, fake_header1), cast(Chain, fake_chain1)

    def lookup_header_succeed2(lookup_block_hash: bytes) -> tuple[Header, Chain]:
        assert lookup_block_hash == block_hash
        return cast(Header, fake_header2), cast(Chain, fake_chain2)

    def common_chain_and_height_fail(chain_arg: Chain) -> tuple[Optional[Chain], int]:
        return None, -1

    def common_chain_and_height_is_1(chain_arg: Chain) -> tuple[Optional[Chain], int]:
        return fake_chain1, 3

    app_state.credentials.get_wallet_password = lambda wallet_path: "password"

    mock_storage = cast(WalletStorage, MockStorage("password"))
    wallet = Wallet(mock_storage)

    # If we do not know the wallet blockchain state we cannot lookup any header.
    assert wallet._current_chain is None
    assert wallet.lookup_header_for_hash(b'ignored') is None

    # Header not present.
    app_state.lookup_header = lookup_header_fail
    assert wallet.lookup_header_for_hash(b'ignored') is None

    # Case: We are on a fork from the longer chain and the header lies within our fork.
    # Case: We are on the longer chain and the header lies within it.
    app_state.lookup_header = lookup_header_succeed1
    wallet._current_chain = cast(Chain, fake_chain1)
    assert wallet.lookup_header_for_hash(block_hash) == (fake_header1, fake_chain1)

    # Case: We do not even share the Genesis block with the other chain. We could assert but
    #       it does not hurt to generically fail.
    app_state.lookup_header = lookup_header_succeed2
    wallet._current_chain = cast(Chain, fake_chain1)
    fake_chain1.common_chain_and_height = common_chain_and_height_fail
    assert wallet.lookup_header_for_hash(block_hash) is None

    # The header lies on the different fork.
    app_state.lookup_header = lookup_header_succeed2
    fake_header2.height = 10
    wallet._current_chain = cast(Chain, fake_chain1)
    fake_chain1.common_chain_and_height = common_chain_and_height_is_1
    assert wallet.lookup_header_for_hash(block_hash) is None

    # The header is at the common height or below on the common chain.
    app_state.lookup_header = lookup_header_succeed2
    fake_header2.height = 3
    wallet._current_chain = cast(Chain, fake_chain1)
    fake_chain1.common_chain_and_height = common_chain_and_height_is_1
    assert wallet.lookup_header_for_hash(block_hash) == (fake_header2, fake_chain1)


@unittest.mock.patch('electrumsv.wallet.app_state', new_callable=_create_mock_app_state)
async def test_close_paid_payment_requests_async_notifies(app_state: AppStateProxy) -> None:
    app_state.credentials.get_wallet_password = lambda wallet_path: "password"

    mock_storage = cast(WalletStorage, MockStorage("password"))
    wallet = Wallet(mock_storage)
    wallet.data = unittest.mock.Mock()
    async def fake_close_paid_payment_requests_async() -> tuple[set[int], list[Any], list[Any]]:
        return { 1 }, [], []
    wallet.data.close_paid_payment_requests_async.side_effect = \
        fake_close_paid_payment_requests_async

    wallet._event_payment_requests_paid_async = unittest.mock.AsyncMock()
    await wallet._close_paid_payment_requests_async()
    wallet._event_payment_requests_paid_async.assert_called_once_with([ 1 ])
