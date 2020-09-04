"""
Before running these tests you must install the electrumsv-sdk and run:

electrumsv-sdk start node
electrumsv-sdk start electrumx
electrumsv-sdk start --new electrumsv

"""
import pytest
import requests


TEST_WALLET_NAME = "worker1.sqlite"


def test_create_new_wallet():
    expected_json = {'parent_wallet': TEST_WALLET_NAME,
                     'value': {'1':
                                   {'wallet_type': 'Standard account',
                                    'default_script_type': 'P2PKH',
                                    'is_wallet_ready': True}}}
    payload = {"password": "test"}
    result = requests.post(
        f"http://127.0.0.1:9999/v1/regtest/dapp/wallets/{TEST_WALLET_NAME}/create_new_wallet",
        json=payload
    )
    if result.status_code != 200:
        if result.json()['code'] == 40008:
            return pytest.skip("wallet already created")
        raise requests.exceptions.HTTPError(result.text)

    result = requests.get(f"http://127.0.0.1:9999/v1/regtest/dapp/wallets/{TEST_WALLET_NAME}")
    if result.status_code != 200:
        raise requests.exceptions.HTTPError(result.text)
    assert result.json() == expected_json


def test_get_all_wallets():
    expected_json = {"value": [
                        "worker1.sqlite",
                        "worker1.sqlite-shm",
                        "worker1.sqlite-wal"
                      ]
    }
    result = requests.get('http://127.0.0.1:9999/v1/regtest/dapp/wallets/')
    if result.status_code != 200:
        raise requests.exceptions.HTTPError(result.text)

    assert result.json() == expected_json


def test_get_wallet():
    expected_json = {
        "parent_wallet": "worker1.sqlite",
        "value": {
            "1": {
                "wallet_type": "Standard account",
                "default_script_type": "P2PKH",
                "is_wallet_ready": True
            }
        }
    }

    result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/{TEST_WALLET_NAME}')
    if result.status_code != 200:
        raise requests.exceptions.HTTPError(result.text)

    assert result.json() == expected_json
