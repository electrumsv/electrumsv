import json
import os
import shutil
import tempfile
from typing import Dict, Optional
import unittest

import pytest
from bitcoinx import PrivateKey, PublicKey, Script

from electrumsv.bitcoin import address_from_string
from electrumsv.constants import DATABASE_EXT, StorageKind
from electrumsv.keystore import from_seed, from_xpub, Old_KeyStore
from electrumsv.networks import Net, SVMainnet, SVTestnet
from electrumsv.storage import (get_categorised_files, multisig_type,
    WalletStorage, WalletStorageInfo)
from electrumsv.transaction import XPublicKey
from electrumsv.wallet import (sweep_preparations, ImportedPrivkeyWallet, ImportedAddressWallet,
    Multisig_Wallet, ParentWallet, Standard_Wallet, UTXO)
from electrumsv.wallet_database import DatabaseContext

from .util import setup_async, tear_down_async, TEST_WALLET_PATH


class _TestableParentWallet(ParentWallet):
    def name(self):
        return self.__class__.__name__

class MockStorage:
    def __init__(self) -> None:
        self.path = tempfile.mktemp()
        self.tx_store_aeskey_hex = os.urandom(32).hex()

    def get(self, attr_name, default=None):
        if attr_name == "tx_store_aeskey":
            return self.tx_store_aeskey_hex
        return default

    def is_encrypted(self) -> bool:
        return False

    def get_path(self) -> str:
        return self.path

    def get_db_context(self):
        return DatabaseContext(self.path)


def setUpModule():
    setup_async()


def tearDownModule():
    tear_down_async()


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

        self.wallet_path = os.path.join(self.user_dir, "somewallet")

    def tearDown(self):
        shutil.rmtree(self.user_dir)


class TestWalletStorage(WalletTestCase):

    def test_read_dictionary_from_file(self):

        some_dict = {"a":"b", "c":"d"}
        contents = json.dumps(some_dict)
        with open(self.wallet_path, "w") as f:
            contents = f.write(contents)

        storage = WalletStorage(self.wallet_path, manual_upgrades=True)
        self.assertEqual("b", storage.get("a"))
        self.assertEqual("d", storage.get("c"))


def check_legacy_parent_of_standard_wallet(parent_wallet: ParentWallet,
        seed_words: Optional[str]=None, is_bip39: bool=False,
        password: Optional[str]=None) -> None:
    assert len(parent_wallet.get_child_wallets()) == 1
    child_wallet: Standard_Wallet = parent_wallet.get_child_wallets()[0]

    parent_keystores = parent_wallet.get_keystores()
    assert len(parent_keystores) == 1
    child_keystores = child_wallet.get_keystores()
    assert len(child_keystores) == 1
    assert parent_keystores[0] is child_keystores[0]

    keystore_encrypted = parent_wallet.has_password()
    if keystore_encrypted:
        assert password is not None
        assert not child_keystores[0].has_seed() or child_keystores[0].get_seed(password)
        assert type(child_keystores[0].get_passphrase(password)) is str
        assert child_keystores[0].get_master_private_key(password)

    keystore_data = parent_keystores[0].dump()
    entry_count = 4
    if is_bip39:
        entry_count = 3
    assert len(keystore_data) == entry_count
    assert keystore_data['type'] == 'bip32'
    assert 'xpub' in keystore_data
    assert 'xprv' in keystore_data
    assert "encrypted" not in parent_wallet.name() or keystore_encrypted
    if is_bip39:
        assert "seed" not in keystore_data
    else:
        if seed_words is None:
            assert "seed" in keystore_data
        else:
            assert keystore_data['seed'] == seed_words

    child_wallet_data = child_wallet.dump()
    # A newly created wallet.
    expected_count = 3
    if "stored_height" in child_wallet_data:
        # A wallet that has synced after it was created.
        assert "labels" in child_wallet_data
        expected_count = 5
    assert len(child_wallet_data) == expected_count
    assert child_wallet_data['id'] == 0
    assert child_wallet_data['wallet_type'] == 'standard'

    keystore_usage = child_wallet_data['keystore_usage']
    assert len(keystore_usage) == 1
    assert len(keystore_usage[0]) == 1
    assert keystore_usage[0]['index'] == 0

def check_legacy_parent_of_imported_privkey_wallet(parent_wallet: ParentWallet,
        keypairs: Optional[Dict[str, str]]=None) -> None:
    assert len(parent_wallet.get_child_wallets()) == 1
    child_wallet: ImportedPrivkeyWallet = parent_wallet.get_child_wallets()[0]

    parent_keystores = parent_wallet.get_keystores()
    assert len(parent_keystores) == 1
    child_keystores = child_wallet.get_keystores()
    assert len(child_keystores) == 1
    assert parent_keystores[0] is child_keystores[0]

    keystore_data = parent_keystores[0].dump()
    assert 'type' in keystore_data
    assert len(keystore_data) == 2
    assert keystore_data['type'] == 'imported'
    if keypairs is not None:
        assert keystore_data['keypairs'] == keypairs
    else:
        assert "keypairs" in keystore_data

    child_wallet_data = child_wallet.dump()
    # A newly created wallet.
    expected_count = 3
    if "stored_height" in child_wallet_data:
        # A wallet that has synced after it was created.
        expected_count = 4
    assert len(child_wallet_data) == expected_count
    assert child_wallet_data['id'] == 0
    assert child_wallet_data['wallet_type'] == ImportedPrivkeyWallet.wallet_type
    keystore_usage = child_wallet_data['keystore_usage']
    assert len(keystore_usage) == 1
    assert len(keystore_usage[0]) == 1
    assert keystore_usage[0]['index'] == 0


def check_legacy_parent_of_imported_address_wallet(parent_wallet: ParentWallet) -> None:
    assert len(parent_wallet.get_child_wallets()) == 1
    child_wallet: ImportedAddressWallet = parent_wallet.get_child_wallets()[0]

    assert len(parent_wallet.get_keystores()) == 0
    assert len(child_wallet.get_keystores()) == 0
    child_wallet_data = child_wallet.dump()
    # A newly created wallet.
    expected_count = 2
    if "stored_height" in child_wallet_data:
        # A wallet that has synced after it was created.
        expected_count = 3
    assert len(child_wallet_data) == expected_count
    assert child_wallet_data['id'] == 0
    assert child_wallet_data['wallet_type'] == ImportedAddressWallet.wallet_type
    assert "keystore_usage" not in child_wallet_data


def check_legacy_parent_of_multisig_wallet(parent_wallet: ParentWallet) -> None:
    assert len(parent_wallet.get_child_wallets()) == 1
    child_wallet: Multisig_Wallet = parent_wallet.get_child_wallets()[0]

    wallet_type = child_wallet.wallet_type
    m, n = multisig_type(wallet_type)

    parent_keystores = parent_wallet.get_keystores()
    assert len(parent_keystores) == 2
    child_keystores = child_wallet.get_keystores()
    assert len(child_keystores) == n
    for i in range(n):
        assert parent_keystores[i] is child_keystores[i]

    for i in range(n):
        keystore_data = parent_keystores[0].dump()
        if len(keystore_data) == 4:
            assert keystore_data['type'] == 'bip32'
            assert keystore_data['seed'] is not None # == seed_words
            assert keystore_data['xpub'] is not None
            assert keystore_data['xprv'] is not None
        else:
            assert len(keystore_data) == 3
            assert keystore_data['type'] == 'bip32'
            assert keystore_data['xpub'] is not None
            assert keystore_data['xprv'] is None

    child_wallet_data = child_wallet.dump()
    # A newly created wallet.
    entry_count = 3
    if "stored_height" in child_wallet_data:
        assert "labels" in child_wallet_data
        # A wallet that has synced after it was created.
        entry_count = 5
    assert len(child_wallet_data) == entry_count
    assert child_wallet_data['id'] == 0
    assert child_wallet_data['wallet_type'] == wallet_type
    keystore_usage = []
    for i in range(n):
        keystore_usage.append({'index': i, 'name': f'x{i+1}/'})
    assert child_wallet_data['keystore_usage'] == keystore_usage

def check_legacy_parent_of_hardware_wallet(parent_wallet: ParentWallet) -> None:
    assert len(parent_wallet.get_child_wallets()) == 1
    child_wallet = parent_wallet.get_child_wallets()[0]

    parent_keystores = parent_wallet.get_keystores()
    assert len(parent_keystores) == 1
    child_keystores = child_wallet.get_keystores()
    assert len(child_keystores) == 1
    assert parent_keystores[0] is child_keystores[0]

    keystore_data = parent_keystores[0].dump()
    # General hardware wallet.
    entry_count = 5
    if keystore_data['hw_type'] == "ledger":
        # Ledger wallets extend the keystore.
        assert "cfg" in keystore_data
        entry_count = 6
    assert len(keystore_data) == entry_count
    assert keystore_data['type'] == 'hardware'
    assert 'hw_type' in keystore_data
    assert 'label' in keystore_data
    assert "derivation" in keystore_data

    child_wallet_data = child_wallet.dump()
    # A newly created wallet.
    expected_count = 3
    if "stored_height" in child_wallet_data:
        # A wallet that has synced after it was created.
        assert "labels" in child_wallet_data
        expected_count = 5
    assert len(child_wallet_data) == expected_count
    assert child_wallet_data['id'] == 0
    assert child_wallet_data['wallet_type'] == 'standard'

    keystore_usage = child_wallet_data['keystore_usage']
    assert len(keystore_usage) == 1
    assert len(keystore_usage[0]) == 1
    assert keystore_usage[0]['index'] == 0


# Verify that different legacy wallets are created with correct keystores in both parent
# wallet, and child wallet. And that the underlying data for keystore and wallet persistence
# is also exported correctly.
class TestLegacyWalletCreation:
    def test_standard_electrum(self, tmp_storage) -> None:
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        child_keystore = from_seed(seed_words, '', False)

        parent_wallet = ParentWallet.as_legacy_wallet_container(tmp_storage)
        keystore_usage = parent_wallet.add_keystore(child_keystore.dump())
        child_wallet = Standard_Wallet.create_within_parent(parent_wallet,
            keystore_usage=[ keystore_usage ])

        check_legacy_parent_of_standard_wallet(parent_wallet)

    def test_old(self, tmp_storage) -> None:
        seed_words = ('powerful random nobody notice nothing important '+
            'anyway look away hidden message over')
        child_keystore = from_seed(seed_words, '', False)
        assert isinstance(child_keystore, Old_KeyStore)

        parent_wallet = ParentWallet.as_legacy_wallet_container(tmp_storage)
        keystore_usage = parent_wallet.add_keystore(child_keystore.dump())
        child_wallet = Standard_Wallet.create_within_parent(parent_wallet,
            keystore_usage=[ keystore_usage ])

        parent_keystores = parent_wallet.get_keystores()
        assert len(parent_keystores) == 1
        child_keystores = child_wallet.get_keystores()
        assert len(child_keystores) == 1
        assert parent_keystores[0] is child_keystores[0]

        keystore_data = parent_keystores[0].dump()
        assert len(keystore_data) == 3
        assert keystore_data['type'] == 'old'
        assert 'mpk' in keystore_data
        assert 'seed' in keystore_data

        child_wallet_data = child_wallet.dump()
        assert len(child_wallet_data) == 3
        assert child_wallet_data['id'] == 0
        assert child_wallet_data['wallet_type'] == 'standard'
        keystore_usage = child_wallet_data['keystore_usage']
        assert len(keystore_usage) == 1
        assert len(keystore_usage[0]) == 1
        assert keystore_usage[0]['index'] == 0

    def test_imported_privkey(self, tmp_storage) -> None:
        text = """
        KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6
        """
        parent_wallet = ParentWallet.as_legacy_wallet_container(tmp_storage)
        child_wallet = ImportedPrivkeyWallet.from_text(parent_wallet, text)

        keypairs = {'02c6467b7e621144105ed3e4835b0b4ab7e35266a2ae1c4f8baa19e9ca93452997':
            'KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6'}
        check_legacy_parent_of_imported_privkey_wallet(parent_wallet, keypairs=keypairs)

    def test_imported_pubkey(self, tmp_storage) -> None:
        text = """
        15hETetDmcXm1mM4sEf7U2KXC9hDHFMSzz
        1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6
        """
        parent_wallet = ParentWallet.as_legacy_wallet_container(tmp_storage)
        child_wallet = ImportedAddressWallet.from_text(parent_wallet, text)

        check_legacy_parent_of_imported_address_wallet(parent_wallet)

    def test_multisig(self, tmp_storage) -> None:
        parent_wallet = ParentWallet.as_legacy_wallet_container(tmp_storage)
        seed_words = ('blast uniform dragon fiscal ensure vast young utility dinosaur abandon '+
            'rookie sure')
        ks1 = from_seed(seed_words, '', True)
        ks2 = from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDben'+
            'T33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec')
        keystores = [ ks1, ks2 ]
        keystore_usages = []
        for i, k in enumerate(keystores):
            keystore_usage = parent_wallet.add_keystore(k.dump())
            keystore_usage['name'] = f'x{i+1}/'
            keystore_usages.append(keystore_usage)
        child_wallet = Multisig_Wallet.create_within_parent(parent_wallet,
            keystore_usage=keystore_usages, wallet_type="2of2")

        check_legacy_parent_of_multisig_wallet(parent_wallet)


@pytest.mark.parametrize("storage_info", get_categorised_files(TEST_WALLET_PATH))
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

    if "testnet" in wallet_filename:
        Net.set_to(SVTestnet)

    password = "123456"
    storage = WalletStorage(wallet_path)
    if "passworded" in wallet_filename:
        storage.decrypt(password)

    try:
        parent_wallet = ParentWallet(storage)
    except OSError as e:
        if "is not a valid Win32 application" not in e.args[1]:
            raise e
        pytest.xfail("Missing libusb for this architecture")
        return

    if "standard" in wallet_filename:
        is_bip39 = "bip39" in wallet_filename
        check_legacy_parent_of_standard_wallet(parent_wallet, is_bip39=is_bip39,
            password=password)
    elif "imported_privkey" in wallet_filename:
        check_legacy_parent_of_imported_privkey_wallet(parent_wallet)
    elif "imported_address" in wallet_filename:
        check_legacy_parent_of_imported_address_wallet(parent_wallet)
    elif "multisig" in wallet_filename:
        check_legacy_parent_of_multisig_wallet(parent_wallet)
    elif "hardware" in wallet_filename:
        check_legacy_parent_of_hardware_wallet(parent_wallet)
    else:
        raise Exception(f"unrecognised wallet file {wallet_filename}")

    if "testnet" in wallet_filename:
        Net.set_to(SVMainnet)


def test_legacy_wallet_backup_hybrid() -> None:
    # We only need to test for one hybrid wallet, and test permutations of backup cases against it.
    wallet_filename = "19_testnet_standard_electrum"
    source_wallet_path = os.path.join(TEST_WALLET_PATH, wallet_filename)
    temp_dir = tempfile.mkdtemp()
    wallet_path = os.path.join(temp_dir, wallet_filename)
    shutil.copyfile(source_wallet_path, wallet_path)
    shutil.copyfile(source_wallet_path + DATABASE_EXT, wallet_path)

    # We do not care about loading the data, this is purely a test of the renaming.
    storage = WalletStorage(source_wallet_path, manual_upgrades=True)


class TestImportedPrivkeyWallet:

    def test_pubkeys_to_address(self, tmp_storage, network):
        coin = network.COIN
        privkey = PrivateKey.from_random()
        WIF = privkey.to_WIF(coin=coin)
        parent_wallet = _TestableParentWallet.as_legacy_wallet_container(tmp_storage)
        wallet = ImportedPrivkeyWallet.from_text(parent_wallet, WIF)
        public_key = privkey.public_key
        pubkey_hex = public_key.to_hex()
        address = public_key.to_address(coin=coin).to_string()
        assert wallet.pubkeys_to_address(pubkey_hex) == address_from_string(address)



sweep_utxos = {
    # SZEfg4eYxCJoqzumUqP34g uncompressed, address 1KXf5PUHNaV42jE9NbJFPKhGGN1fSSGJNK
    "6dd52f21a1376a67370452d1edfc811bc9d3f344bc7d973616ee27cebfd1940b": [
        {
            "height": 437146,
            "value": 45318048,
            "tx_hash": "9f2c45a12db0144909b5db269415f7319179105982ac70ed80d76ea79d923ebf",
            "tx_pos": 0,
        },
    ],
    # SZEfg4eYxCJoqzumUqP34g compressed, address 14vEZP9zQZGxaKqhRSMVgdPwyjPeDbcRS6
    "c369b25fc68c0697fb20b5790382a7f5946e85b1881b999949c41266bc736647": [
    ],
    # KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 (compressed)
    "e4f6742ca0c2dceef3d055333c7d318aa6d56b4016e5bfaf12a683bc0eee07a3": [
        {
            "height": 500000,
            "value": 18043706,
            "tx_hash": "bcf7ae875b585e00a61055372c1e99046b20f5fbfcd8659959afb6f428326bfa",
            "tx_pos": 1,
        },
    ],
    # KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 (P2PK)
    "b7c7a07e2d02c5686729179b0ec426d813326b54b42efe35214f0e320c81bc0d": [
    ],
    # 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ (uncompressed)
    "2df53273de1b740e6f566eba00d90366e53afd2c6af896a9488515f8ef5abbd8": [
    ],
    # 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ (P2PK)
    "7149d82068249701104cd662bfe8ebc0af131ce6e781b124cc6297f45f7f6de5": [
        {
            "height": 50000,
            "value": 1804376,
            "tx_hash": "3f5a1badfe1beb42b650f325b20935f09f3ab43a3c473c5be18f58308fc7eff1",
            "tx_pos": 3,
        },
    ],
}

result_S = (
    [
        UTXO(value=45318048,
             script_pubkey=Script.from_hex('76a914cb3e86e38ce37d5add87d3da753adc04a04bf60c88ac'),
             tx_hash='9f2c45a12db0144909b5db269415f7319179105982ac70ed80d76ea79d923ebf',
             out_index=0,
             height=437146,
             address=address_from_string('1KXf5PUHNaV42jE9NbJFPKhGGN1fSSGJNK'),
             is_coinbase=False)
    ],
    {
        XPublicKey('04e7dd15b4271f8308ff52ad3d3e472b652e78a2c5bc6ed10250a543d28c0128894ae863d086488e6773c4589be93a1793f685dd3f1e8a1f1b390b23470f7d1095'): (b'\x98\xe3\x15\xc3%j\x97\x17\xd4\xdd\xea0\xeb*\n-V\xa1d\x93yN\xb0SSf\xea"\xd8i\xa3 ', False),
        XPublicKey('03e7dd15b4271f8308ff52ad3d3e472b652e78a2c5bc6ed10250a543d28c012889'): (b'\x98\xe3\x15\xc3%j\x97\x17\xd4\xdd\xea0\xeb*\n-V\xa1d\x93yN\xb0SSf\xea"\xd8i\xa3 ', True),
        XPublicKey('fd76a914cb3e86e38ce37d5add87d3da753adc04a04bf60c88ac'): (b'\x98\xe3\x15\xc3%j\x97\x17\xd4\xdd\xea0\xeb*\n-V\xa1d\x93yN\xb0SSf\xea"\xd8i\xa3 ', False),
        XPublicKey('fd76a9142af9bdc179471526aef15781b00ab6ebd162a45888ac'): (b'\x98\xe3\x15\xc3%j\x97\x17\xd4\xdd\xea0\xeb*\n-V\xa1d\x93yN\xb0SSf\xea"\xd8i\xa3 ', True),
    }
)

result_K = (
    [
        UTXO(value=18043706,
             script_pubkey=Script.from_hex('76a914d9351dcbad5b8f3b8bfa2f2cdc85c28118ca932688ac'),
             tx_hash='bcf7ae875b585e00a61055372c1e99046b20f5fbfcd8659959afb6f428326bfa',
             out_index=1,
             height=500000,
             address=address_from_string('1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK'),
             is_coinbase=False),
        UTXO(value=1804376,
             script_pubkey=Script.from_hex('4104d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0aac'),
             tx_hash='3f5a1badfe1beb42b650f325b20935f09f3ab43a3c473c5be18f58308fc7eff1',
             out_index=3,
             height=50000,
             address=PublicKey.from_hex('04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a'),
             is_coinbase=False)
    ],
    {
        XPublicKey('04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a'): (b"\x0c(\xfc\xa3\x86\xc7\xa2'`\x0b/\xe5\x0b|\xae\x11\xec\x86\xd3\xbf\x1f\xbeG\x1b\xe8\x98'\xe1\x9dr\xaa\x1d", False),
        XPublicKey('02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c'): (b"\x0c(\xfc\xa3\x86\xc7\xa2'`\x0b/\xe5\x0b|\xae\x11\xec\x86\xd3\xbf\x1f\xbeG\x1b\xe8\x98'\xe1\x9dr\xaa\x1d", True),
        XPublicKey('fd76a914d9351dcbad5b8f3b8bfa2f2cdc85c28118ca932688ac'): (b"\x0c(\xfc\xa3\x86\xc7\xa2'`\x0b/\xe5\x0b|\xae\x11\xec\x86\xd3\xbf\x1f\xbeG\x1b\xe8\x98'\xe1\x9dr\xaa\x1d", True),
        XPublicKey('fd76a914a65d1a239d4ec666643d350c7bb8fc44d288112888ac'): (b"\x0c(\xfc\xa3\x86\xc7\xa2'`\x0b/\xe5\x0b|\xae\x11\xec\x86\xd3\xbf\x1f\xbeG\x1b\xe8\x98'\xe1\x9dr\xaa\x1d", False),
    }
)

@pytest.mark.parametrize("privkey,answer", (
    ("SZEfg4eYxCJoqzumUqP34g", result_S),
    ("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", result_K),
))
def test_sweep_preparations(privkey,answer):
    def get_utxos(script_hash):
        return sweep_utxos.get(script_hash, [])

    result = sweep_preparations([privkey], get_utxos)
    assert result == answer
