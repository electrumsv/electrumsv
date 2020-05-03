import os
import pytest
import shutil

from unittest.mock import patch

from electrumsv.constants import MIGRATION_CURRENT, MIGRATION_FIRST, DATABASE_EXT, StorageKind
from electrumsv.storage import (backup_wallet_file, categorise_file, get_categorised_files,
    DatabaseStore, TextStore, WalletStorageInfo, IncompatibleWalletError, WalletStorage)

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
def test_backup_wallet_json_file(tmp_path, kind) -> None:
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
        dest_wallet_filepath = os.path.join(tmp_path, filenames[i] + extensions[i])
        shutil.copyfile(source_wallet_filepath, dest_wallet_filepath)

    wallet_filepath = os.path.join(tmp_path, filenames[0] + extensions[0])

    # Test that a first backup attempt uses the appropriate file name.
    assert backup_wallet_file(wallet_filepath) is not None
    assert len(os.listdir(tmp_path)) == len(filenames) * 2
    for i in range(len(filenames)):
        check_filepath = os.path.join(tmp_path, filenames[i])
        assert os.path.exists(check_filepath +".backup.1"+ extensions[i])

    # Test that a second backup attempt uses the appropriate sequential file name.
    assert backup_wallet_file(wallet_filepath) is not None
    assert len(os.listdir(tmp_path)) == len(filenames) * 3
    for i in range(len(filenames)):
        check_filepath = os.path.join(tmp_path, filenames[i])
        assert os.path.exists(check_filepath +".backup.2"+ extensions[i])

    wallet_filepath = os.path.join(tmp_path, f"{filenames[0]}.backup.1{extensions[0]}")

    # Test that all kinds work with backing up a backup.
    assert backup_wallet_file(wallet_filepath) is not None
    assert len(os.listdir(tmp_path)) == len(filenames) * 4
    for i in range(len(filenames)):
        check_filepath = os.path.join(tmp_path, filenames[i] +".backup.1")
        assert os.path.exists(check_filepath +".backup.1"+ extensions[i])


def test_textstore_read_raw_data(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "wallet")
    store = TextStore(wallet_path)
    try:
        # No write operation has been done yet on the store.
        with pytest.raises(FileNotFoundError):
            store._read_raw_data()
        # Commit the empty JSON lump to disk.
        store.write()
        data = store._read_raw_data()
        assert data == b'{}'
        assert not store.is_encrypted()
    finally:
        store.close()

def test_textstore_load_data_valid(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "wallet")
    store = TextStore(wallet_path)
    try:
        store.load_data(b"{}")
    finally:
        store.close()

def test_store_load_data_invalid(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "wallet")
    store = TextStore(wallet_path)
    try:
        with pytest.raises(OSError):
            store.load_data(b"x{}")
    finally:
        store.close()

def test_store__write(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "wallet")
    store = TextStore(wallet_path)
    try:
        assert not store.is_primed()
        store.put("number", 10)
        store._write()
        assert store.is_primed()
        # This will raise an assertion if there is not locatible JSON lump.
        store._read_raw_data()
        assert store.get("number") == 10
    finally:
        store.close()

    store = TextStore(wallet_path)
    try:
        assert store.is_primed()
        # We need to do this here because the wallet storage normally does it.
        store.load_data(store._read_raw_data())
        assert store.get("number") == 10
    finally:
        store.close()


# It should only ever be possible to create a database store from a text store if the text store
# version is the initial database version, representing a continuous migration allowing the
# process to then apply subsequent database store migrations.
@pytest.mark.parametrize("data", (
    {},
    { "seed_version": MIGRATION_FIRST-1 },
    { "seed_version": MIGRATION_FIRST+1 })
)
def test_database_store_from_text_store_initial_version(tmp_path, data) -> None:
    wallet_path = os.path.join(tmp_path, "database")
    text_store = TextStore(wallet_path, data=data)
    try:
        # Verify that the seed version is rejected (the assertion is hit).
        with pytest.raises(AssertionError):
            DatabaseStore.from_text_store(text_store)
    finally:
        text_store.close()

# Shared logic for following version init/set unit tests.
def _check_database_store_version_init_set(db_store, version) -> None:
    # The database file is created when it is opened, not on first write, as is the case with text.
    assert os.path.exists(db_store.get_path())

    # Verify that the seed version is really present independently.
    assert db_store.get("migration") == version

def test_database_store_from_text_store_version_init_set(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "database")
    try:
        text_store = TextStore(wallet_path,
            data={ "seed_version": MIGRATION_FIRST })
        # Verify that the seed version is accepted (no assertion hit).
        db_store = DatabaseStore.from_text_store(text_store)
        _check_database_store_version_init_set(db_store, MIGRATION_CURRENT)
    finally:
        db_store.close()
        text_store.close()

def test_database_store_version_init_set(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "database")
    db_store = DatabaseStore(wallet_path)
    try:
        _check_database_store_version_init_set(db_store, MIGRATION_CURRENT)
    finally:
        db_store.close()

def test_database_store_requires_split(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "database")
    db_store = DatabaseStore(wallet_path)
    try:
        assert not db_store.requires_split()
    finally:
        db_store.close()

def test_database_store_new_never_requires_upgrade(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "database")
    db_store = DatabaseStore(wallet_path)
    try:
        # At this time this is not linked to anything as database storage upgrades internally.
        # However, we may need to extend it as the JSON lump contents change.
        assert not db_store.requires_upgrade()
    finally:
        db_store.close()

def test_database_store_version_requires_upgrade(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "database")
    db_store = DatabaseStore(wallet_path)
    try:
        db_store.put("migration", MIGRATION_FIRST - 1)
        assert db_store.requires_upgrade()
    finally:
        db_store.close()


# Test the nuances of AbstractStore._modified, whether it gets correctly initialised in the different
# scenarios.
@pytest.mark.parametrize("store_class", (TextStore,))
def test_store_modified_file_nonexistent(tmp_path, store_class):
    wallet_path = os.path.join(tmp_path, "database")
    store = store_class(wallet_path)
    try:
        assert store._modified is False
    finally:
        store.close()

# Test the nuances of AbstractStore._modified, whether it gets correctly initialised in the different
# scenarios.
@pytest.mark.parametrize("store_class", (TextStore,))
def test_store_modified_file_nonexistent_with_data(tmp_path, store_class):
    wallet_path = os.path.join(tmp_path, "database")
    store = store_class(wallet_path, data={"a": 1})
    try:
        assert store._modified is True
    finally:
        store.close()


def test_text_store__write_version_incompatible(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "database")
    store = TextStore(wallet_path)
    try:
        store.put("seed_version", TextStore.FINAL_SEED_VERSION+1)
        with pytest.raises(IncompatibleWalletError):
            store.write()
    finally:
        store.close()

def test_text_store__raise_unsupported_version(tmp_path) -> None:
    wallet_path = os.path.join(tmp_path, "database")
    store = TextStore(wallet_path)
    try:
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
    finally:
        store.close()


def test_wallet_storage_json_path_nonexistent_errors(tmp_path) -> None:
    nonexistent_storage_path = os.path.join(tmp_path, "nonexistent", "walletfile")

    with pytest.raises(OSError):
        storage = WalletStorage(nonexistent_storage_path)

def test_wallet_storage_database_nonexistent_creates(tmp_path) -> None:
    wallet_filepath = os.path.join(tmp_path, "walletfile")
    storage = WalletStorage(wallet_filepath)
    try:
        assert type(storage._store) is DatabaseStore
        assert storage.get("migration") == MIGRATION_CURRENT
    finally:
        storage.close()
