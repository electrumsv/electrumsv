"""
Before running these tests you must install the electrumsv-sdk and run:

electrumsv-sdk start node
electrumsv-sdk start electrumx
electrumsv-sdk start --new electrumsv

"""
import asyncio
import json
import time

import bitcoinx
import pytest
import requests
import aiohttp
import pytest_asyncio

from electrumsv.networks import Net, SVRegTestnet
from electrumsv.restapi import Fault


class TestRestAPI:

    def setup_class(self):
        self.TEST_WALLET_NAME = "worker1.sqlite"

    def test_create_new_wallet(self):
        expected_json = {'parent_wallet': self.TEST_WALLET_NAME,
                         'value': {'1':
                                       {'wallet_type': 'Standard account',
                                        'default_script_type': 'P2PKH',
                                        'is_wallet_ready': True}}}
        payload = {"password": "test"}
        result = requests.post(
            f"http://127.0.0.1:9999/v1/regtest/dapp/wallets/{self.TEST_WALLET_NAME}/create_new_wallet",
            json=payload
        )
        if result.status_code != 200:
            if result.json()['code'] == 40008:
                return pytest.skip("wallet already created")
            raise requests.exceptions.HTTPError(result.text)

        result = requests.get(f"http://127.0.0.1:9999/v1/regtest/dapp/wallets/{self.TEST_WALLET_NAME}")
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        assert result.json() == expected_json

    def test_get_all_wallets(self):
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

    def test_get_parent_wallet(self):
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
        time.sleep(5)
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/{self.TEST_WALLET_NAME}')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        assert result.json() == expected_json

    def test_load_wallet(self):
        expected_json = {'parent_wallet': 'worker1.sqlite',
                         'value': {'1': {'default_script_type': 'P2PKH',
                                         'is_wallet_ready': True,
                                         'wallet_type': 'Standard account'}}}

        time.sleep(5)  # wait for wallet to be ready
        result = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/load_wallet')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        assert result.json() == expected_json

    def test_get_account(self):
        expected_json = {
            'value': {'1':
                          {'wallet_type': 'Standard account',
                           'default_script_type': 'P2PKH',
                           'is_wallet_ready': True}
                      }
        }
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/1')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        assert result.json() == expected_json

    def test_get_utxos_and_top_up(self):
        """
        1) get coin state before
        2) top up wallet
        3) get coin state after
        4) generate block to confirm coins
        5) get coin state after block confirmation
        """
        result1 = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/1/utxos/coin_state')
        if result1.status_code != 200:
            raise requests.exceptions.HTTPError(result1.text)

        current_cleared_count = result1.json()['value']['cleared_coins']
        current_settled_count = result1.json()['value']['settled_coins']

        result2 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/1/topup_account')
        if result2.status_code != 200:
            raise requests.exceptions.HTTPError(result2.text)

        time.sleep(10)
        result3 = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/1/utxos/coin_state')
        if result3.status_code != 200:
            raise requests.exceptions.HTTPError(result3.text)

        # post-topup (no block mined)
        assert (current_cleared_count + 1) == result3.json()['value']['cleared_coins']
        assert current_settled_count == result3.json()['value']['settled_coins']

        result4 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                               f'{self.TEST_WALLET_NAME}/1/generate_blocks')
        if result4.status_code != 200:
            raise requests.exceptions.HTTPError(result4.text)

        time.sleep(10)
        result5 = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                               f'{self.TEST_WALLET_NAME}/1/utxos/coin_state')
        if result5.status_code != 200:
            raise requests.exceptions.HTTPError(result5.text)

        # post-topup (block mined)
        assert current_settled_count + current_cleared_count + 1 == result5.json()['value'][
            'settled_coins']

    def test_get_balance(self):
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/1/utxos/balance')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

    def test_concurrent_tx_creation_and_broadcast(self, event_loop):
        n_txs = 10

        Net.set_to(SVRegTestnet)
        p2pkh_object = SVRegTestnet.REGTEST_FUNDS_PUBLIC_KEY.to_address()

        P2PKH_OUTPUT = {"value": 10000,
                        "script_pubkey": p2pkh_object.to_script().to_hex()}

        payload = {
            "outputs": [P2PKH_OUTPUT] * n_txs,
            "password": "test"
        }

        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/1/txs/create_and_broadcast'

        # 1) split utxos sufficient for n transactions + confirm
        result = requests.post(url, json=payload)
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        result2 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                               f'{self.TEST_WALLET_NAME}/1/generate_blocks')
        if result2.status_code != 200:
            raise requests.exceptions.HTTPError(result2.text)
        time.sleep(5)

        # 2) test concurrent transaction creation + broadcast

        payload2 = {
            "outputs": [P2PKH_OUTPUT],
            "password": "test"
        }

        async def fetch(session, url):
            async with session.post(url, data=json.dumps(payload2)) as resp:
                if resp != 200:
                    return await resp.json()
                return await resp.json()

        async def main():
            async with aiohttp.ClientSession() as session:
                tasks = [asyncio.create_task(fetch(session, url)) for _ in range(0, n_txs)]
                results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                error_code = result.get('code')
                if error_code:
                    assert False, str(Fault(error_code, result.get('message')))

        event_loop.run_until_complete(main())
