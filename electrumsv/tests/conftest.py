# Pytest looks here for fixtures
import os
from os.path import dirname
from pathlib import Path
import shutil
import tempfile
from typing import Callable
import unittest.mock

import bitcoinx
import pytest

from electrumsv.networks import Net, SVMainnet, SVRegTestnet, SVTestnet
from electrumsv.simple_config import SimpleConfig
from electrumsv.util.misc import obj_size
from electrumsv.transaction import Transaction, XPublicKey
from electrumsv.wallet import Wallet, WalletStorage

from .util import mock_headers, PasswordToken, TEST_WALLET_PATH


@pytest.fixture(params=(SVMainnet, SVTestnet))
def coin(request):
    network = request.param
    Net.set_to(network)
    try:
        yield network.COIN
    finally:
        Net.set_to(SVMainnet)


@pytest.fixture
def set_to_mainnet_network_on_test_finish():
    try:
        yield
    finally:
        if Net.is_regtest() or Net.is_testnet() or Net.is_scaling_testnet():
            Net.set_to(SVMainnet)

def get_datacarrier_tx() -> Transaction:
    """datacarrier tx with one op_return output >6000 bytes and an xpubkey in the
    input - only for testing obj size calculation"""
    path = Path(dirname(os.path.realpath(__file__))).joinpath("data/transactions/data_carrier.txt")
    with open(path, "r") as f:
        rawtx = f.read()

    tx = Transaction.from_hex(rawtx)
    public_key_bytes = bitcoinx.PrivateKey(bytes.fromhex(
        'a2d9803c912ab380c1491d3bd1aaab34ca06742d7885a224ec8d386182d26ed2')
    ).public_key.to_bytes()
    tx.inputs[0].x_pubkeys[public_key_bytes] = XPublicKey.from_bytes(public_key_bytes)
    return tx

def get_small_tx() -> Transaction:
    path = Path(dirname(os.path.realpath(__file__))).joinpath("data/transactions/hello.txt")
    with open(path, "r") as f:
        rawtx = f.read()
    tx = Transaction.from_hex(rawtx)
    return tx

def get_tx_datacarrier_size() -> int:
    # the sizes vary depending on 32 vs 64 bit and versions of python (maybe linux vs windows too)
    return obj_size(get_datacarrier_tx())

def get_tx_small_size() -> int:
    # the sizes vary depending on 32 vs 64 bit and versions of python (maybe linux vs windows too)
    return obj_size(get_small_tx())

@pytest.fixture
def test_tx_datacarrier()-> Transaction:
    return get_datacarrier_tx()

@pytest.fixture
def test_tx_small()-> Transaction:
    return get_small_tx()

@pytest.fixture
def existing_config():
    electrum_sv_path = tempfile.mkdtemp()
    yield SimpleConfig({'electrum_sv_path': electrum_sv_path})
    shutil.rmtree(electrum_sv_path)


@pytest.fixture
def fresh_wallet_path():
    user_dir = tempfile.mkdtemp()
    yield os.path.join(user_dir, f"somewallet-{os.urandom(4).hex()}")
    shutil.rmtree(user_dir)


@pytest.fixture(scope="session")
def funded_wallet_factory() -> Callable[[], Wallet]:
    """
    This helper method provides a new copy of a stock funded wallet. The wallet in question is
    a sample regtest blockchain imported from the simple indexer file
    "contrib\blockchains\blockchain_115_3677f4" with an extra block on top to
    """
    temp_dir = tempfile.mkdtemp()
    wallet_filename = "26_regtest_standard_mining_with_mature_and_immature_coins.sqlite"
    wallet_password = "123456"
    wallet_password_token = PasswordToken(wallet_password)

    source_wallet_path = os.path.join(TEST_WALLET_PATH, wallet_filename)
    upgrade_wallet_path = os.path.join(temp_dir, wallet_filename)
    shutil.copyfile(source_wallet_path, upgrade_wallet_path)

    # NOTE(rt12) Mocking out the headers is not ideal but we kind of have to do it for now.
    Net.set_to(SVRegTestnet)
    try:
        wallet_storage = WalletStorage(upgrade_wallet_path)
        with unittest.mock.patch(
            "electrumsv.wallet_database.migrations.migration_0029_reference_server.app_state") \
            as migration29_app_state:
                migration29_app_state.headers = mock_headers()
                wallet_storage.upgrade(True, wallet_password_token)
        wallet_storage.close()
    finally:
        Net.set_to(SVMainnet)

    def local_function() -> Wallet:
        nonlocal upgrade_wallet_path, wallet_filename
        # @Python311 This should use `sqlite3.deserialize` to load the upgraded wallet into
        #     memory and use an ephemeral copy.
        copy_path = tempfile.mkdtemp()
        copy_wallet_path = os.path.join(copy_path, wallet_filename)
        shutil.copyfile(upgrade_wallet_path, copy_wallet_path)

        # The caller must have mocked in the wallet password for the wallet to be opened.
        copy_wallet_storage = WalletStorage(copy_wallet_path)
        return Wallet(copy_wallet_storage)

    return local_function

