import json
import os
import pytest
import shutil
import tempfile
import zlib

from bitcoinx import PrivateKey
from unittest.mock import patch

from electrumsv.constants import DATABASE_EXT, StorageKind
from electrumsv.storage import (backup_wallet_files, categorise_file, get_categorised_files,
    BaseStore, DatabaseStore, TextStore, WalletStorageInfo, IncompatibleWalletError, WalletStorage,
    FINAL_SEED_VERSION)

from .util import TEST_WALLET_PATH


FILE_SUFFIXES = [ "", DATABASE_EXT ]

# This tests with a path, and without. With the db suffix, and without. And that the kind, filename
# and wallet_filepath values are correct.
@patch('os.path.exists')
@pytest.mark.parametrize("basepath", ("", os.path.join("a", "b", "c")))
@pytest.mark.parametrize("kind,side_effect,suffixes", (
    (StorageKind.FILE, lambda filename: not filename.endswith(DATABASE_EXT), []),
    (StorageKind.DATABASE, lambda filename: filename.endswith(DATABASE_EXT), FILE_SUFFIXES),
    (StorageKind.HYBRID, lambda filename: True, FILE_SUFFIXES),
    (StorageKind.UNKNOWN, lambda filename: False, []),
))
def test_categorise_file(mock_exists, basepath, kind, side_effect, suffixes) -> None:
    mock_exists.side_effect = side_effect
    for suffix in suffixes:
        fake_filepath = os.path.join(basepath, "walletfile")
        fake_filepath_full = fake_filepath + suffix
        ret = categorise_file(fake_filepath)
        assert ret.filename == "walletfile"
        assert ret.kind == kind
        assert ret.wallet_filepath == fake_filepath


EXPECTED_PATH = os.path.join("...", "file")

@patch('os.listdir')
@pytest.mark.parametrize("pathlist,results", (
    (("file",), [ WalletStorageInfo(StorageKind.FILE, "file", EXPECTED_PATH) ]),
    (("file", "file.sqlite"), [ WalletStorageInfo(StorageKind.HYBRID, "file", EXPECTED_PATH) ]),
    (("file.sqlite",), [ WalletStorageInfo(StorageKind.DATABASE, "file", EXPECTED_PATH) ]),
    ((), []),
))
def test_get_categorised_files(mock_listdir, pathlist, results) -> None:
    mock_listdir.return_value = pathlist
    assert get_categorised_files("...") == results


@pytest.mark.parametrize("kind",
    (StorageKind.FILE, StorageKind.HYBRID, StorageKind.DATABASE))
def test_backup_wallet_json_file(kind) -> None:
    temp_path = tempfile.mkdtemp()

    filename = "18_mainnet_hardware_trezormodelt"

    # A wallet is identified by a primary file, which is the json file if it is present,
    # otherwise it is the database for lack of any other file. The first file/extension is
    # what gets passed to the backup call, it should result in any second file being
    # backed up based on what kind of file it is.
    filenames = []
    extensions = []
    if kind == StorageKind.FILE:
        filenames.append(filename)
        extensions.append("")
    if kind == StorageKind.HYBRID or kind == StorageKind.DATABASE:
        filenames.append(filename)
        extensions.append(DATABASE_EXT)

    for i in range(len(filenames)):
        source_wallet_filepath = os.path.join(TEST_WALLET_PATH, filenames[i] + extensions[i])
        dest_wallet_filepath = os.path.join(temp_path, filenames[i] + extensions[i])
        shutil.copyfile(source_wallet_filepath, dest_wallet_filepath)

    wallet_filepath = os.path.join(temp_path, filenames[0] + extensions[0])

    # Test that a first backup attempt uses the appropriate file name.
    assert backup_wallet_files(wallet_filepath)
    assert len(os.listdir(temp_path)) == len(filenames) * 2
    for i in range(len(filenames)):
        check_filepath = os.path.join(temp_path, filenames[i])
        assert os.path.exists(check_filepath +".backup.1"+ extensions[i])

    # Test that a second backup attempt uses the appropriate sequential file name.
    assert backup_wallet_files(wallet_filepath)
    assert len(os.listdir(temp_path)) == len(filenames) * 3
    for i in range(len(filenames)):
        check_filepath = os.path.join(temp_path, filenames[i])
        assert os.path.exists(check_filepath +".backup.2"+ extensions[i])

    wallet_filepath = os.path.join(temp_path, f"{filenames[0]}.backup.1{extensions[0]}")

    # Test that all kinds work with backing up a backup.
    assert backup_wallet_files(wallet_filepath)
    assert len(os.listdir(temp_path)) == len(filenames) * 4
    for i in range(len(filenames)):
        check_filepath = os.path.join(temp_path, filenames[i] +".backup.1")
        assert os.path.exists(check_filepath +".backup.1"+ extensions[i])



@pytest.mark.parametrize("store_class", (TextStore, DatabaseStore))
def test_store_is_encrypted_no_data(store_class) -> None:
    wallet_path = tempfile.mktemp()
    store = store_class(wallet_path)
    # This is a blank store, so will not have written any data yet.
    with pytest.raises(AssertionError):
        assert not store.is_encrypted()

@pytest.mark.parametrize("store_class", (TextStore, DatabaseStore))
def test_store_is_encrypted_false(store_class) -> None:
    wallet_path = tempfile.mktemp()
    db_store = store_class(wallet_path)
    db_store.write()
    assert not db_store.is_encrypted()

@pytest.mark.parametrize("store_class", (TextStore, DatabaseStore))
def test_store_is_encrypted_true(store_class) -> None:
    privkey = PrivateKey.from_random()
    wallet_path = tempfile.mktemp()
    db_store = store_class(wallet_path, privkey.public_key.to_hex())
    db_store.write()
    assert db_store.is_encrypted()

@pytest.mark.parametrize("store_class,exc_class", ((TextStore, FileNotFoundError),
    (DatabaseStore, AssertionError)))
def test_store_read_raw_data(store_class, exc_class) -> None:
    wallet_path = tempfile.mktemp()
    print(f"wallet_path {wallet_path}")
    store = store_class(wallet_path)
    # No write operation has been done yet on the store.
    with pytest.raises(exc_class):
        store.read_raw_data()
    # Commit the empty JSON lump to disk.
    store.write()
    data = store.read_raw_data()
    assert data == b'{}'
    assert not store.is_encrypted()

@pytest.mark.parametrize("store_class", (TextStore, DatabaseStore))
def test_store_load_data_valid(store_class) -> None:
    wallet_path = tempfile.mktemp()
    store = store_class(wallet_path)
    store.load_data(b"{}")

@pytest.mark.parametrize("store_class,exc_class", ((TextStore, OSError),
    (DatabaseStore, json.JSONDecodeError)))
def test_store_load_data_invalid(store_class, exc_class) -> None:
    wallet_path = tempfile.mktemp()
    store = store_class(wallet_path)
    with pytest.raises(exc_class):
        store.load_data(b"x{}")

@pytest.mark.parametrize("store_class", (TextStore, DatabaseStore))
def test_store__write(store_class) -> None:
    wallet_path = tempfile.mktemp()
    store = store_class(wallet_path)
    assert not store.is_primed()
    store.put("number", 10)
    store._write()
    assert store.is_primed()
    # This will raise an assertion if there is not locatible JSON lump.
    store.read_raw_data()
    assert store.get("number") == 10

    store = store_class(wallet_path)
    assert store.is_primed()
    # We need to do this here because the wallet storage normally does it.
    store.load_data(store.read_raw_data())
    assert store.get("number") == 10

@pytest.mark.parametrize("store_class", (TextStore, DatabaseStore))
def test_store__write_encrypted(store_class) -> None:
    privkey = PrivateKey.from_random()
    wallet_path = tempfile.mktemp()
    store = store_class(wallet_path, privkey.public_key.to_hex())
    assert not store.is_primed()
    store.put("number", 10)
    store._write()
    assert store.is_primed()
    # This will raise an assertion if there is not locatible data for the JSON lump.
    store.read_raw_data()
    assert store.get("number") == 10

    store = store_class(wallet_path, privkey.public_key.to_hex())
    assert store.is_primed()
    store.read_raw_data()
    encrypted_data = store.get_encrypted_data()
    print(encrypted_data)
    raw_data = zlib.decompress(privkey.decrypt_message(encrypted_data))
    store.load_data(raw_data)
    assert store.get("number") == 10



# It should only ever be possible to create a database store from a text store if the text store
# version is the initial database version, representing a continuous migration allowing the
# process to then apply subsequent database store migrations.
@pytest.mark.parametrize("data", (
    {},
    { "seed_version": DatabaseStore.INITIAL_SEED_VERSION-1 },
    { "seed_version": DatabaseStore.INITIAL_SEED_VERSION+1 })
)
def test_database_store_from_text_store_initial_version(data) -> None:
    wallet_path = tempfile.mktemp()
    text_store = TextStore(wallet_path, data=data)
    # Verify that the seed version is rejected (the assertion is hit).
    with pytest.raises(AssertionError):
        DatabaseStore.from_text_store(text_store)

# Shared logic for following version init/set unit tests.
def _check_database_store_version_init_set(db_store, seed_version) -> None:
    # The database file is created when it is opened, not on first write, as is the case with text.
    assert os.path.exists(db_store.get_path())

    # Verify that the seed version is not stored in the JSON lump, but independently.
    assert db_store.get("seed_version") is None, "seed version leaked into JSON lump"
    # Verify that the seed version is really present independently.
    assert db_store._get_seed_version() == seed_version

    db_store._set_seed_version(FINAL_SEED_VERSION + 1)
    assert db_store._get_seed_version() == FINAL_SEED_VERSION + 1
    # Verify that the new seed version is still not stored in the JSON lump, but independently.
    assert db_store.get("seed_version") is None, "seed version leaked into JSON lump"
    # Verify that the new seed version is really present independently.
    assert db_store._get_seed_version() == FINAL_SEED_VERSION + 1

def test_database_store_from_text_store_version_init_set() -> None:
    wallet_path = tempfile.mktemp()
    text_store = TextStore(wallet_path, data={ "seed_version": DatabaseStore.INITIAL_SEED_VERSION })
    # Verify that the seed version is accepted (no assertion hit).
    db_store = DatabaseStore.from_text_store(text_store)
    _check_database_store_version_init_set(db_store, DatabaseStore.INITIAL_SEED_VERSION)

def test_database_store_version_init_set() -> None:
    wallet_path = tempfile.mktemp()
    db_store = DatabaseStore(wallet_path)
    _check_database_store_version_init_set(db_store, FINAL_SEED_VERSION)

def test_database_store_requires_split() -> None:
    wallet_path = tempfile.mktemp()
    db_store = DatabaseStore(wallet_path)
    assert not db_store.requires_split()

def test_database_store_new_never_requires_upgrade() -> None:
    wallet_path = tempfile.mktemp()
    db_store = DatabaseStore(wallet_path)
    # At this time this is not linked to anything as database storage upgrades internally.
    # However, we may need to extend it as the JSON lump contents change.
    assert not db_store.requires_upgrade()

def test_database_store_version_requires_upgrade() -> None:
    wallet_path = tempfile.mktemp()
    db_store = DatabaseStore(wallet_path)
    db_store._set_seed_version(DatabaseStore.INITIAL_SEED_VERSION - 1)
    with pytest.raises(IncompatibleWalletError):
        db_store.requires_upgrade()

# Ensure there's a database store version to upgrade from.
@patch('electrumsv.storage.FINAL_SEED_VERSION', DatabaseStore.INITIAL_SEED_VERSION + 1)
def test_database_store_version_requires_upgrade_not_esv_wallet() -> None:
    wallet_path = tempfile.mktemp()
    db_store = DatabaseStore(wallet_path)
    db_store._set_seed_version(DatabaseStore.INITIAL_SEED_VERSION)
    db_store.write()
    # Missing "ESV" marker.
    with pytest.raises(IncompatibleWalletError):
        db_store.requires_upgrade()

# Ensure there's a database store version to upgrade from.
@patch('electrumsv.storage.FINAL_SEED_VERSION', DatabaseStore.INITIAL_SEED_VERSION + 1)
def test_database_store_version_requires_upgrade_esv_wallet() -> None:
    wallet_path = tempfile.mktemp()
    db_store = DatabaseStore(wallet_path)
    db_store._set_seed_version(DatabaseStore.INITIAL_SEED_VERSION)
    db_store.put("wallet_author", "ESV")
    db_store.write()
    # "ESV" marker present.
    assert db_store.requires_upgrade()


# Test the nuances of BaseStore._modified, whether it gets correctly initialised in the different
# scenarios.
@pytest.mark.parametrize("store_class", (BaseStore, TextStore, DatabaseStore))
def test_store_modified_file_nonexistent(store_class):
    wallet_path = tempfile.mktemp()
    store = store_class(wallet_path)
    assert store._modified is False

# Test the nuances of BaseStore._modified, whether it gets correctly initialised in the different
# scenarios.
@pytest.mark.parametrize("store_class", (BaseStore, TextStore, DatabaseStore))
def test_store_modified_file_nonexistent_with_data(store_class):
    wallet_path = tempfile.mktemp()
    store = store_class(wallet_path, data={"a": 1})
    assert store._modified is True


def test_text_store__write_version_incompatible() -> None:
    wallet_path = tempfile.mktemp()
    store = TextStore(wallet_path)
    store.put("seed_version", TextStore.FINAL_SEED_VERSION+1)
    with pytest.raises(IncompatibleWalletError):
        store.write()

def test_text_store__raise_unsupported_version() -> None:
    wallet_path = tempfile.mktemp()
    store = TextStore(wallet_path)

    with pytest.raises(Exception) as e:
        store._raise_unsupported_version(5)
    assert "To open this wallet" in e.value.args[0]

    with pytest.raises(Exception) as e:
        store._raise_unsupported_version(6)
    assert "It does not contain any keys" in e.value.args[0]

    store.put("master_public_keys", 1)

    with pytest.raises(Exception) as e:
        store._raise_unsupported_version(6)
    assert "Please open this file" in e.value.args[0]



def test_wallet_storage_json_path_nonexistent_errors() -> None:
    base_storage_path = tempfile.mkdtemp()
    nonexistent_storage_path = os.path.join(base_storage_path, "nonexistent", "walletfile")

    with pytest.raises(OSError):
        storage = WalletStorage(nonexistent_storage_path)

def test_wallet_storage_database_nonexistent_creates() -> None:
    base_storage_path = tempfile.mkdtemp()
    wallet_filepath = os.path.join(base_storage_path, "walletfile")
    storage = WalletStorage(wallet_filepath)
    assert type(storage._store) is DatabaseStore
    assert storage.get("wallet_author") == "ESV"
    assert storage.get("seed_version") == FINAL_SEED_VERSION
    key = storage.get("tx_store_aeskey")
    assert type(key) is str

@pytest.mark.parametrize("password,flag", (("pw", True), (None, False)))
def test_wallet_storage_set_password(password, flag) -> None:
    base_storage_path = tempfile.mkdtemp()
    wallet_filepath = os.path.join(base_storage_path, "walletfile")
    storage = WalletStorage(wallet_filepath)
    storage.set_password(password)
    assert storage.get("use_encryption") is flag

