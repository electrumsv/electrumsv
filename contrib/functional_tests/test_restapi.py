"""
Before running these tests you must install the electrumsv-sdk and run:

electrumsv-sdk start node
electrumsv-sdk start electrumx
electrumsv-sdk start --new electrumsv

"""
import asyncio
import json
import time

# NOTE(rt12) We are monkeypatching in our replacement before anything else is imported ideally.
from electrumsv import ripemd # pylint: disable=unused-import

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

    def load_wallet(self):
        result = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                               f'{self.TEST_WALLET_NAME}/load_wallet')
        return result

    async def get_utxos(self, session):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/1/utxos'
        async with session.get(url) as resp:
            if resp != 200:
                return await resp.json()
            return await resp.json()

    async def create_and_send(self, session, payload):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/1/txs/create_and_broadcast'
        async with session.post(url, data=json.dumps(payload)) as resp:
            if resp != 200:
                return await resp.json()
            return await resp.json()

    async def get_tx_history(self, session):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/1/txs/history'
        async with session.get(url) as resp:
            if resp != 200:
                return await resp.json()
            return await resp.json()

    def test_create_new_wallet(self):
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

        assert result.json()['parent_wallet'] == 'worker1.sqlite'
        assert result.json()['accounts']['1']['default_script_type'] == 'P2PKH'
        assert result.json()['accounts']['1']['wallet_type'] == 'Standard account'

    def test_get_all_wallets(self):
        expected_json = {
                "wallets": [
                    "worker1.sqlite",
            ]
        }
        result = requests.get('http://127.0.0.1:9999/v1/regtest/dapp/wallets/')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        assert result.json() == expected_json

    def test_load_wallet(self):
        result = self.load_wallet()
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        assert result.json()['parent_wallet'] == 'worker1.sqlite'
        assert result.json()['accounts']['1']['default_script_type'] == 'P2PKH'
        assert result.json()['accounts']['1']['wallet_type'] == 'Standard account'

    def test_get_parent_wallet(self):
        expected_json = {
            "parent_wallet": "worker1.sqlite",
            "accounts": {
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

    def test_get_account(self):
        expected_json = {
            '1':
                {'wallet_type': 'Standard account',
                 'default_script_type': 'P2PKH',
                 'is_wallet_ready': True}
        }
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/1')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        assert result.json() == expected_json

    """Disabled test until websockets are implemented for waiting on tx processing"""
    # def test_get_utxos_and_top_up(self):
    #     """
    #     1) get coin state before
    #     2) top up wallet
    #     3) get coin state after
    #     4) generate block to confirm coins
    #     5) get coin state after block confirmation
    #     """
    #     result1 = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
    #                           f'{self.TEST_WALLET_NAME}/1/utxos/coin_state')
    #     if result1.status_code != 200:
    #         raise requests.exceptions.HTTPError(result1.text)
    #
    #     current_cleared_count = result1.json()['cleared_coins']
    #     current_settled_count = result1.json()['settled_coins']
    #
    #     result2 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
    #                           f'{self.TEST_WALLET_NAME}/1/topup_account')
    #     if result2.status_code != 200:
    #         raise requests.exceptions.HTTPError(result2.text)
    #
    #     time.sleep(10)
    #     result3 = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
    #                           f'{self.TEST_WALLET_NAME}/1/utxos/coin_state')
    #     if result3.status_code != 200:
    #         raise requests.exceptions.HTTPError(result3.text)
    #
    #     # post-topup (no block mined)
    #     assert (current_cleared_count + 1) == result3.json()['cleared_coins']
    #     assert current_settled_count == result3.json()['settled_coins']
    #
    #     result4 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
    #                            f'{self.TEST_WALLET_NAME}/1/generate_blocks')
    #     if result4.status_code != 200:
    #         raise requests.exceptions.HTTPError(result4.text)
    #
    #     time.sleep(10)
    #     result5 = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
    #                            f'{self.TEST_WALLET_NAME}/1/utxos/coin_state')
    #     if result5.status_code != 200:
    #         raise requests.exceptions.HTTPError(result5.text)
    #
    #     # post-topup (block mined)
    #     assert current_settled_count + current_cleared_count + 1 == result5.json()[
    #         'settled_coins']

    def test_get_balance(self):
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/1/utxos/balance')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

    """Disabled test until websockets are implemented for waiting on tx processing"""
    # def test_concurrent_tx_creation_and_broadcast(self, event_loop):
    #     n_txs = 10
    #
    #     Net.set_to(SVRegTestnet)
    #     p2pkh_object = SVRegTestnet.REGTEST_FUNDS_PUBLIC_KEY.to_address()
    #
    #     P2PKH_OUTPUT = {"value": 10000,
    #                     "script_pubkey": p2pkh_object.to_script().to_hex()}
    #
    #     payload = {
    #         "split_value": 20000,
    #         "split_count": 100,
    #         "password": "test"
    #     }
    #
    #     url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
    #           f'{self.TEST_WALLET_NAME}/1/txs/split_utxos'
    #
    #     # 1) split utxos sufficient for n transactions + confirm
    #     result = requests.post(url, json=payload)
    #     if result.status_code != 200:
    #         raise requests.exceptions.HTTPError(result.text)
    #
    #     result2 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
    #                            f'{self.TEST_WALLET_NAME}/1/generate_blocks')
    #     if result2.status_code != 200:
    #         raise requests.exceptions.HTTPError(result2.text)
    #     time.sleep(10)
    #
    #     # 2) test concurrent transaction creation + broadcast
    #     payload2 = {
    #         "outputs": [P2PKH_OUTPUT],
    #         "password": "test"
    #     }
    #
    #     async def main():
    #         async with aiohttp.ClientSession() as session:
    #             tasks = [asyncio.create_task(self.create_and_send(session, payload2)) for _ in
    #                      range(0, n_txs)]
    #             results = await asyncio.gather(*tasks, return_exceptions=True)
    #
    #         for result in results:
    #             error_code = result.get('code')
    #             if error_code:
    #                 assert False, str(Fault(error_code, result.get('message')))
    #
    #     event_loop.run_until_complete(main())

"""Disabled test until websockets are implemented for waiting on tx processing"""
    # def test_create_and_broadcast_exception_handling(self, event_loop):
    #     Net.set_to(SVRegTestnet)
    #     p2pkh_object = SVRegTestnet.REGTEST_FUNDS_PUBLIC_KEY.to_address()
    #
    #     async def main():
    #         async with aiohttp.ClientSession() as session:
    #             # Todo - use websocket instead of sleeps
    #             time.sleep(6)
    #             # get tx history before tests to compare later
    #             result1 = await self.get_tx_history(session)
    #             error_code = result1.get('code')
    #             if error_code:
    #                 assert False, result1
    #             len_tx_hist_before = len(result1['history'])
    #
    #             # get utxos
    #             result2 = await self.get_utxos(session)
    #             error_code = result2.get('code')
    #             if error_code:
    #                 assert False, result2
    #             utxos = result2['utxos']
    #
    #             # Prepare for two txs that use the same utxo
    #             P2PKH_OUTPUT = {"value": 100,
    #                             "script_pubkey": p2pkh_object.to_script().to_hex()}
    #             # base tx
    #             payload1 = {
    #                 "outputs": [P2PKH_OUTPUT],
    #                 "password": "test",
    #                 "utxos": [utxos[0]]
    #             }
    #             # trigger mempool conflict
    #             payload2 = {
    #                 "outputs": [P2PKH_OUTPUT, P2PKH_OUTPUT],
    #                 "password": "test",
    #                 "utxos": [utxos[0]]
    #             }
    #             # trigger 'duplicate set' internal server error (same exact txid in tx cache)
    #             payload3 = {
    #                 "outputs": [P2PKH_OUTPUT],
    #                 "password": "test",
    #                 "utxos": [utxos[0]]
    #             }
    #             # First tx
    #             result3 = await self.create_and_send(session, payload1)
    #             error_code = result3.get('code')
    #             if error_code:
    #                 assert False, result3
    #
    #             # Trigger "mempool conflict"
    #             result4 = await self.create_and_send(session, payload2)
    #             error_code = result4.get('code')
    #             if not error_code:
    #                 assert False, result4
    #
    #             assert result4['code'] == 40011
    #
    #             # Trigger 'duplicate set' internal server error (same exact txid in tx cache)
    #             result4 = await self.create_and_send(session, payload3)
    #             error_code = result4.get('code')
    #             if not error_code:
    #                 assert False, result4
    #
    #             assert result4['code'] == 50000
    #
    #             # trigger insufficient coins
    #             P2PKH_OUTPUT = {"value": 1_000 * 100_000_000,
    #                             "script_pubkey": p2pkh_object.to_script().to_hex()}
    #             payload2 = {
    #                 "outputs": [P2PKH_OUTPUT],
    #                 "password": "test"
    #             }
    #             result5 = await self.create_and_send(session, payload2)
    #             error_code = result5.get('code')
    #             if not error_code:
    #                 assert False, result5
    #             assert result5 == {'code': 40006,
    #                                'message': 'You have insufficient coins for this transaction'}
    #
    #             # Todo - use websocket instead of sleeps
    #             time.sleep(6)
    #
    #             # check that only 1 new txs was created
    #             result6 = await self.get_tx_history(session)
    #             error_code = result6.get('code')
    #             if error_code:
    #                 assert False, result6
    #             len_tx_hist_after = len(result6['history'])
    #
    #             # only one extra tx should exist (in the other cases, no tx should exist)
    #             assert len_tx_hist_before == (len_tx_hist_after - 1)
    #
    #     event_loop.run_until_complete(main())
