import os
import pytest
import shutil
import tempfile

from unittest.mock import patch

from electrumsv.storage import (backup_wallet_files, categorise_file, get_categorised_files,
    StorageKind, WalletStorageInfo, DATABASE_EXT)

from .util import TEST_WALLET_PATH


@patch('os.path.exists')
@pytest.mark.parametrize("kind,side_effect", (
    (StorageKind.FILE, lambda filename: not filename.endswith(".sqlite")),
    (StorageKind.DATABASE, lambda filename: filename.endswith(".sqlite")),
    (StorageKind.HYBRID, lambda filename: True),
    (StorageKind.UNKNOWN, lambda filename: False),
))
def test_categorise_file(mock_exists, kind, side_effect) -> None:
    mock_exists.side_effect = side_effect
    fake_filepath = os.path.join("a", "b", "c", "walletfile")
    ret = categorise_file(fake_filepath)
    assert ret.filename == "walletfile"
    assert ret.kind == kind


@patch('os.listdir')
@pytest.mark.parametrize("pathlist,results", (
    (("file",), [ WalletStorageInfo(StorageKind.FILE, "file") ]),
    (("file", "file.sqlite"), [ WalletStorageInfo(StorageKind.HYBRID, "file") ]),
    (("file.sqlite",), [ WalletStorageInfo(StorageKind.DATABASE, "file") ]),
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
