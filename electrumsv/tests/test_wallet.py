import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
from typing import Dict, Optional, List, Set
import unittest

import pytest

from electrumsv.constants import (DATABASE_EXT, DerivationType, KeystoreTextType, ScriptType,
    StorageKind, CHANGE_SUBPATH, RECEIVING_SUBPATH, KeyInstanceFlag)
from electrumsv.crypto import pw_decode
from electrumsv.exceptions import InvalidPassword, IncompatibleWalletError
from electrumsv.keystore import (from_seed, from_xpub, Old_KeyStore, Multisig_KeyStore)
from electrumsv.networks import Net, SVMainnet, SVTestnet
from electrumsv.storage import get_categorised_files, WalletStorage, WalletStorageInfo
from electrumsv.wallet import (ImportedPrivkeyAccount, ImportedAddressAccount, MultisigAccount,
    Wallet, StandardAccount, AbstractAccount)
from electrumsv.wallet_database import DatabaseContext
from electrumsv.wallet_database.tables import AccountRow, KeyInstanceRow, TransactionDeltaTable

from .util import setup_async, tear_down_async, TEST_WALLET_PATH


class _TestableWallet(Wallet):
    def name(self):
        return self.__class__.__name__

class MockStorage:
    def __init__(self) -> None:
        self.path = tempfile.mktemp()

        from electrumsv.wallet_database.migration import create_database_file, update_database_file
        create_database_file(self.path)
        update_database_file(self.path)

        self._data = {}

    def get(self, attr_name, default=None):
        return self._data.get(attr_name, default)

    def put(self, attr_name, value):
        self._data[attr_name] = value

    def set_password(self, new_password: str) -> None:
        pass

    def get_path(self) -> str:
        return self.path

    def get_db_context(self):
        return DatabaseContext(self.path)


def setUpModule():
    setup_async()


def tearDownModule():
    tear_down_async()


def get_categorised_files2(wallet_path: str) -> List[WalletStorageInfo]:
    matches = get_categorised_files(wallet_path)
    # In order to ensure ordering consistency, we sort the files.
    return sorted(matches, key=lambda v: v.filename)


@pytest.fixture()
def tmp_storage(tmpdir):
    return MockStorage()

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


def check_legacy_parent_of_standard_wallet(wallet: Wallet,
        seed_words: Optional[str]=None, is_bip39: bool=False,
        password: Optional[str]=None) -> None:
    assert len(wallet.get_accounts()) == 1
    account: StandardAccount = wallet.get_accounts()[0]

    parent_keystores = wallet.get_keystores()
    assert len(parent_keystores) == 1
    child_keystores = account.get_keystores()
    assert len(child_keystores) == 1
    assert parent_keystores[0] is child_keystores[0]

    assert password is not None
    assert not child_keystores[0].has_seed() or child_keystores[0].get_seed(password)
    assert type(child_keystores[0].get_passphrase(password)) is str
    assert child_keystores[0].get_master_private_key(password)

    keystore_data = parent_keystores[0].to_derivation_data()
    entry_count = 4
    if is_bip39:
        entry_count = 3
    assert len(keystore_data) == entry_count, keystore_data
    assert 'xpub' in keystore_data
    assert 'xprv' in keystore_data
    keystore_encrypted = False
    try:
        parent_keystores[0].check_password(None)
    except InvalidPassword:
        keystore_encrypted = True
    assert "encrypted" not in wallet.name() or keystore_encrypted
    if is_bip39:
        assert "seed" not in keystore_data
    else:
        if seed_words is None:
            assert "seed" in keystore_data
        else:
            assert keystore_data['seed'] == seed_words

def check_legacy_parent_of_imported_privkey_wallet(wallet: Wallet,
        keypairs: Optional[Dict[str, str]]=None, password: Optional[str]=None) -> None:
    assert len(wallet.get_accounts()) == 1
    account: ImportedPrivkeyAccount = wallet.get_accounts()[0]

    parent_keystores = wallet.get_keystores()
    assert len(parent_keystores) == 0
    child_keystores = account.get_keystores()
    assert len(child_keystores) == 1
    assert child_keystores[0] is not None

    assert not child_keystores[0].has_masterkey()
    with pytest.raises(IncompatibleWalletError):
        child_keystores[0].to_masterkey_row()
    with pytest.raises(IncompatibleWalletError):
        child_keystores[0].to_derivation_data()
    keyinstance_datas = child_keystores[0].get_keyinstance_derivation_data()
    assert len(keyinstance_datas) == 1
    if keypairs is not None:
        for key_id, data in keyinstance_datas:
            assert pw_decode(data['prv'], password) == keypairs[data['pub']]


def check_legacy_parent_of_imported_address_wallet(wallet: Wallet) -> None:
    assert len(wallet.get_accounts()) == 1
    account: ImportedAddressAccount = wallet.get_accounts()[0]

    assert len(wallet.get_keystores()) == 0
    assert len(account.get_keystores()) == 0


def check_legacy_parent_of_multisig_wallet(wallet: Wallet) -> None:
    assert len(wallet.get_accounts()) == 1
    account: MultisigAccount = wallet.get_accounts()[0]

    m = account.m
    n = account.n

    parent_keystores = wallet.get_keystores()
    assert len(parent_keystores) == 1
    keystore = parent_keystores[0]
    child_keystores = keystore.get_cosigner_keystores()
    assert len(child_keystores) == n
    parent_data = keystore.to_derivation_data()

    for i in range(n):
        masterkey_row = child_keystores[i].to_masterkey_row()
        assert masterkey_row.derivation_type == DerivationType.BIP32
        keystore_data = parent_data["cosigner-keys"][i][1]
        if len(keystore_data) == 3:
            assert keystore_data['seed'] is not None # == seed_words
            assert keystore_data['xpub'] is not None
            assert keystore_data['xprv'] is not None
        else:
            assert len(keystore_data) == 2
            assert keystore_data['xpub'] is not None
            assert keystore_data['xprv'] is None

def check_parent_of_blank_wallet(wallet: Wallet) -> None:
    assert len(wallet.get_accounts()) == 0
    parent_keystores = wallet.get_keystores()
    assert len(parent_keystores) == 0


def check_legacy_parent_of_hardware_wallet(wallet: Wallet) -> None:
    assert len(wallet.get_accounts()) == 1
    child_account = wallet.get_accounts()[0]

    parent_keystores = wallet.get_keystores()
    assert len(parent_keystores) == 1
    child_keystores = child_account.get_keystores()
    assert len(child_keystores) == 1
    assert parent_keystores[0] is child_keystores[0]

    masterkey_row = parent_keystores[0].to_masterkey_row()
    assert masterkey_row.derivation_type == DerivationType.HARDWARE
    keystore_data = parent_keystores[0].to_derivation_data()
    # General hardware wallet.
    entry_count = 5
    if keystore_data['hw_type'] == "ledger":
        # Ledger wallets extend the keystore.
        assert "cfg" in keystore_data
        entry_count = 6
    assert len(keystore_data) == entry_count
    assert 'hw_type' in keystore_data
    assert 'label' in keystore_data
    assert "derivation" in keystore_data
    assert "subpaths" in keystore_data


def check_create_keys(wallet: Wallet, account_script_type: ScriptType) -> None:
    def check_rows(rows: List[KeyInstanceRow], script_type: ScriptType) -> None:
        for row in rows:
            assert isinstance(row.keyinstance_id, int)
            assert account.get_id() == row.account_id
            assert 1 == row.masterkey_id
            assert script_type == row.script_type
            assert DerivationType.BIP32_SUBPATH == row.derivation_type
            assert None is row.description

    accounts = wallet.get_accounts()
    assert len(accounts) == 1
    account = accounts[0]
    assert [] == account.get_existing_fresh_keys(RECEIVING_SUBPATH)
    assert [] == account.get_existing_fresh_keys(CHANGE_SUBPATH)
    assert account_script_type == account.get_default_script_type()

    keyinstances: List[KeyInstanceRow] = []
    keyinstance_ids: Set[int] = set()

    for count in (0, 1, 5):
        new_keyinstances = account.create_keys(count, RECEIVING_SUBPATH)
        assert count == len(new_keyinstances)
        check_rows(new_keyinstances, account_script_type)
        keyinstance_ids |= set(keyinstance.keyinstance_id for keyinstance in new_keyinstances)
        keyinstances.extend(new_keyinstances)
        assert len(keyinstance_ids) == len(keyinstances)
        assert [] == account.get_existing_fresh_keys(RECEIVING_SUBPATH)

    for count in (0, 1, 5):
        last_row = keyinstances[-1]
        last_index = account.get_derivation_path(last_row.keyinstance_id)[-1]
        next_index = account.get_next_derivation_index(RECEIVING_SUBPATH)
        assert next_index == last_index  + 1

        try:
            new_keyinstances = account.create_keys_until(
                RECEIVING_SUBPATH + (next_index + count - 1,))
        except AssertionError:
            assert 0 == count
            continue
        assert 0 != count
        assert count == len(new_keyinstances)
        check_rows(new_keyinstances, account_script_type)

        keyinstance_ids |= set(keyinstance.keyinstance_id for keyinstance in new_keyinstances)
        keyinstances.extend(new_keyinstances)
        assert len(keyinstance_ids) == len(keyinstances)
        assert [] == account.get_existing_fresh_keys(RECEIVING_SUBPATH)

    keyinstance_batches: List[List[KeyInstanceRow]] = []
    for count in (0, 1, 5):
        new_keyinstances = account.get_fresh_keys(RECEIVING_SUBPATH, count)
        assert count == len(new_keyinstances)
        assert new_keyinstances == account.get_existing_fresh_keys(RECEIVING_SUBPATH)
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
    def test_standard_electrum(self, tmp_storage) -> None:
        password = 'password'
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        child_keystore = from_seed(seed_words, '')

        wallet = Wallet(tmp_storage)
        masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)
        wallet.update_password(password)

        account_row = AccountRow(1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...')
        account = StandardAccount(wallet, account_row, [], [])
        wallet.register_account(account.get_id(), account)

        check_legacy_parent_of_standard_wallet(wallet, password=password)
        check_create_keys(wallet, account_row.default_script_type)

    def test_old(self, tmp_storage) -> None:
        seed_words = ('powerful random nobody notice nothing important '+
            'anyway look away hidden message over')
        child_keystore = from_seed(seed_words, '')
        assert isinstance(child_keystore, Old_KeyStore)

        wallet = Wallet(tmp_storage)
        masterkey_row = wallet.create_masterkey_from_keystore(child_keystore)
        account_row = AccountRow(1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...')
        account = StandardAccount(wallet, account_row, [], [])
        wallet.register_account(account.get_id(), account)

        parent_keystores = wallet.get_keystores()
        assert len(parent_keystores) == 1
        child_keystores = account.get_keystores()
        assert len(child_keystores) == 1
        assert parent_keystores[0] is child_keystores[0]

        masterkey_row = parent_keystores[0].to_masterkey_row()
        assert masterkey_row.derivation_type == DerivationType.ELECTRUM_OLD
        keystore_data = parent_keystores[0].to_derivation_data()
        assert len(keystore_data) == 3
        assert 'mpk' in keystore_data
        assert 'seed' in keystore_data
        assert 'subpaths' in keystore_data

        check_create_keys(wallet, account_row.default_script_type)

    @unittest.mock.patch('electrumsv.wallet.app_state')
    def test_imported_privkey(self, mock_app_state, tmp_storage) -> None:
        mock_app_state.app = unittest.mock.Mock()
        wallet = Wallet(tmp_storage)
        account = wallet.create_account_from_text_entries(KeystoreTextType.PRIVATE_KEYS,
            ScriptType.P2PKH,
            [ "KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6" ],
            "password")

        keypairs = {'02c6467b7e621144105ed3e4835b0b4ab7e35266a2ae1c4f8baa19e9ca93452997':
            'KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6'}
        mock_app_state.app.on_new_wallet_event.assert_called_once()
        check_legacy_parent_of_imported_privkey_wallet(wallet, keypairs=keypairs,
            password='password')

    @unittest.mock.patch('electrumsv.wallet.app_state')
    def test_imported_pubkey(self, mock_app_state, tmp_storage) -> None:
        text = """
        15hETetDmcXm1mM4sEf7U2KXC9hDHFMSzz
        1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6
        """
        wallet = Wallet(tmp_storage)
        account = wallet.create_account_from_text_entries(KeystoreTextType.ADDRESSES,
            ScriptType.NONE,
            [ "15hETetDmcXm1mM4sEf7U2KXC9hDHFMSzz", "1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6" ],
            "password")
        mock_app_state.app.on_new_wallet_event.assert_called_once()
        check_legacy_parent_of_imported_address_wallet(wallet)

    def test_multisig(self, tmp_storage) -> None:
        wallet = Wallet(tmp_storage)

        seed_words = ('blast uniform dragon fiscal ensure vast young utility dinosaur abandon '+
            'rookie sure')
        ks1 = from_seed(seed_words, '')
        ks2 = from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDben'+
            'T33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec')

        keystore = Multisig_KeyStore({ 'm': 2, 'n': 2, "cosigner-keys": [] })
        keystore.add_cosigner_keystore(ks1)
        keystore.add_cosigner_keystore(ks2)

        assert not keystore.is_watching_only()
        assert 2 == len(keystore.get_cosigner_keystores())

        masterkey_row = wallet.create_masterkey_from_keystore(keystore)

        account_row = AccountRow(1, masterkey_row.masterkey_id, ScriptType.MULTISIG_BARE, 'text')
        account = MultisigAccount(wallet, account_row, [], [])
        wallet.register_account(account.get_id(), account)

        check_legacy_parent_of_multisig_wallet(wallet)
        check_create_keys(wallet, account_row.default_script_type)


@pytest.mark.parametrize("storage_info", get_categorised_files2(TEST_WALLET_PATH))
def test_legacy_wallet_loading(storage_info: WalletStorageInfo) -> None:
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

    if storage_info.kind == StorageKind.HYBRID:
        pytest.xfail("old development database wallets not supported yet")

    password = None
    storage = WalletStorage(wallet_path)
    if "passworded" in expected_subtypes:
        password = "123456"
        text_store = storage.get_text_store()
        text_store.load_data(text_store.decrypt(password))
    if "encrypted" in expected_subtypes:
        password = "123456"
    if expected_version >= 22:
        password = "123456"
        storage.check_password(password)

    storage.upgrade(password is not None, password)

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

    old_password = password
    password = "654321"
    wallet.update_password(password, old_password)

    if "standard" == expected_type:
        is_bip39 = "bip39" in expected_subtypes
        check_legacy_parent_of_standard_wallet(wallet, is_bip39=is_bip39,
            password=password)
    elif "imported" == expected_type:
        if "privkey" in wallet_filename:
            check_legacy_parent_of_imported_privkey_wallet(wallet)
        elif "address" in expected_subtypes:
            check_legacy_parent_of_imported_address_wallet(wallet)
        else:
            raise Exception(f"unrecognised wallet file {wallet_filename}")
    elif "multisig" == expected_type:
        check_legacy_parent_of_multisig_wallet(wallet)
    elif "hardware" == expected_type:
        check_legacy_parent_of_hardware_wallet(wallet)
    elif "blank" == expected_type:
        check_parent_of_blank_wallet(wallet)
    else:
        raise Exception(f"unrecognised wallet file {wallet_filename}")

    if "testnet" == expected_network:
        Net.set_to(SVMainnet)


def test_detect_used_keys(mocker):
    class MockDatabaseContext:
        def acquire_connection(self):
            return
        def release_connection(self, connection):
            return

    class MockWallet:
        def __init__(self):
            self._db_context = MockDatabaseContext()
            self._storage = {'deactivate_used_keys':True}

    class MockAccount(AbstractAccount):
        def __init__(self):
            self._id = 1
            self._wallet = MockWallet()
            self._deactivated_keys_lock = threading.Lock()
            self._deactivated_keys = []
            self._keyinstances = {
                1: KeyInstanceRow(1, 1, 1, DerivationType.BIP32, json.dumps({"subpath": [0, 1]}),
                    ScriptType.P2PKH, KeyInstanceFlag.IS_ACTIVE, ""),
                2: KeyInstanceRow(2, 1, 1, DerivationType.BIP32, json.dumps({"subpath": [0, 2]}),
                    ScriptType.P2PKH, KeyInstanceFlag.USER_SET_ACTIVE, ""),
                3: KeyInstanceRow(3, 1, 1, DerivationType.BIP32, json.dumps({"subpath": [0, 3]}),
                    ScriptType.P2PKH,
                    (KeyInstanceFlag.IS_ACTIVE | KeyInstanceFlag.USER_SET_ACTIVE), "")}
            self._deactivated_keys_event = asyncio.Event()
            self._logger = logging.getLogger("MockAccount")

    def mock_update_used_keys(self, account_id):
        """test coverage of this in 'test_wallet_database_tables.test_update_used_keys'"""
        return [1,2,3]  # keyinstance_ids

    mocker.patch.object(TransactionDeltaTable, 'update_used_keys', mock_update_used_keys)
    account = MockAccount()
    assert account._keyinstances[1].flags == KeyInstanceFlag.IS_ACTIVE
    assert account._keyinstances[2].flags == KeyInstanceFlag.USER_SET_ACTIVE
    assert account._keyinstances[3].flags == KeyInstanceFlag.IS_ACTIVE | \
           KeyInstanceFlag.USER_SET_ACTIVE
    account.detect_used_keys()
    assert account._keyinstances[1].flags == KeyInstanceFlag.NONE
    assert account._keyinstances[2].flags == KeyInstanceFlag.USER_SET_ACTIVE
    assert account._keyinstances[3].flags == KeyInstanceFlag.USER_SET_ACTIVE


# class TestImportedPrivkeyAccount:
#     # TODO(rt12) REQUIRED add some unit tests for this account type. The following is obsolete.
#     def test_pubkeys_to_a_ddress(self, tmp_storage, network):
#         coin = network.COIN
#         privkey = PrivateKey.from_random()
#         WIF = privkey.to_WIF(coin=coin)
#         wallet = _TestableWallet(tmp_storage)
#         account = ImportedPrivkeyAccount.from_text(wallet, WIF)
#         public_key = privkey.public_key
#         address = public_key.to_address(coin=coin).to_string()
#         assert account.pubkeys_to_a_ddress(public_key) == address_from_string(address)
