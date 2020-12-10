"""
Before running these tests you must install the electrumsv-sdk and run:

electrumsv-sdk start node
electrumsv-sdk start electrumx
electrumsv-sdk start --new electrumsv

"""
import asyncio
import json
import time

import aiohttp
import pytest
import requests
import pytest_asyncio

from electrumsv.constants import TxFlags
from electrumsv.networks import SVRegTestnet, Net
from electrumsv.restapi import Fault
from .websocket_client import TxStateWSClient


async def wait_for_mempool(txids):
    async with TxStateWSClient() as ws_client:
        await ws_client.block_until_mempool(txids)


async def wait_for_confirmation(txids):
    async with TxStateWSClient() as ws_client:
        await ws_client.block_until_confirmed(txids)


class TestRestAPI:

    def setup_class(self):
        self.TEST_WALLET_NAME = "worker1.sqlite"

    def _load_wallet(self):
        _result1 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                                 f'{self.TEST_WALLET_NAME}/load_wallet')
        if _result1.status_code != 200:
            raise requests.exceptions.HTTPError(_result1.text)
        return _result1

    def _topup_account(self):
        result2 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                                f'worker1.sqlite/1/topup_account')
        if result2.status_code != 200:
            raise requests.exceptions.HTTPError(result2.text)
        return result2

    def _fetch_transaction(self, txid: str):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/fetch'
        payload = {"txid": txid}
        result = requests.post(url, data=json.dumps(payload))
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

    def _generate_blocks(self, nblocks: int):
        payload = {"nblocks": nblocks}
        result4 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                               f'{self.TEST_WALLET_NAME}/1/generate_blocks',
            data=json.dumps(payload))
        if result4.status_code != 200:
            raise requests.exceptions.HTTPError(result4.text)
        return result4

    def _get_coin_state(self):
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                               f'{self.TEST_WALLET_NAME}/1/utxos/coin_state')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

    def _get_utxos(self):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/1/utxos'
        result = requests.get(url)
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

    async def _create_and_send(self, session, payload):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/1/txs/create_and_broadcast'
        async with session.post(url, data=json.dumps(payload)) as resp:
            if resp != 200:
                return await resp.json()
            return await resp.json()

    def _get_tx_history(self):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/1/txs/history'
        result = requests.get(url)
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

    def _split_utxos(self, outut_count: int=100, value: int=20000):
        payload = {
            "split_value": value,
            "split_count": outut_count,
            "password": "test"
        }
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/1/txs/split_utxos'

        result = requests.post(url, json=payload)
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

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
        result1 = self._load_wallet()
        assert result1.json()['parent_wallet'] == 'worker1.sqlite'
        assert result1.json()['accounts']['1']['default_script_type'] == 'P2PKH'
        assert result1.json()['accounts']['1']['wallet_type'] == 'Standard account'

    def test_websocket_wait_for_mempool(self, event_loop):
        self._load_wallet()
        result = self._topup_account()
        txids = [result.json()["txid"]]

        event_loop.run_until_complete(wait_for_mempool(txids))
        for txid in txids:
            result2 = self._fetch_transaction(txid)
            assert result2.json()['tx_flags'] & TxFlags.StateCleared == TxFlags.StateCleared

    def test_websocket_wait_for_confirmation(self, event_loop):
        self._load_wallet()
        result = self._topup_account()
        self._generate_blocks(1)
        txids = [result.json()["txid"]]

        event_loop.run_until_complete(wait_for_confirmation(txids))
        for txid in txids:
            result2 = self._fetch_transaction(txid)
            assert result2.json()['tx_flags'] & TxFlags.StateSettled == TxFlags.StateSettled

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

    def test_get_utxos_and_top_up(self, event_loop):
        """
        1) get coin state before
        2) top up wallet
        3) get coin state after
        4) generate block to confirm coins
        5) get coin state after block confirmation
        """
        async def main():
            self._load_wallet()
            result1 = self._get_coin_state()
            cleared_count_before = result1.json()['cleared_coins']
            settled_count_before = result1.json()['settled_coins']

            result2 = self._topup_account()
            txids = [ result2.json()["txid"] ]
            await wait_for_mempool(txids)

            # post-topup (no block mined)
            result3 = self._get_coin_state()
            assert (cleared_count_before + 1) == result3.json()['cleared_coins']
            assert settled_count_before == result3.json()['settled_coins']

            result4 = self._generate_blocks(1)
            await wait_for_confirmation(txids)

            result4 = self._get_coin_state()
            settled_count_after = result4.json()['settled_coins']
            assert settled_count_before + cleared_count_before + 1 == settled_count_after

        event_loop.run_until_complete(main())

    def test_get_balance(self):
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/1/utxos/balance')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

    def test_concurrent_tx_creation_and_broadcast(self, event_loop):
        async def main():
            n_txs = 10

            # 1) split utxos
            result1 = self._split_utxos(outut_count=100, value=20000)
            txid = result1.json()['txid']
            self._generate_blocks(1)
            await wait_for_confirmation([txid])

            # 2) test concurrent transaction creation + broadcast
            Net.set_to(SVRegTestnet)
            p2pkh_object = SVRegTestnet.REGTEST_FUNDS_PUBLIC_KEY.to_address()
            P2PKH_OUTPUT = {"value": 10000,
                            "script_pubkey": p2pkh_object.to_script().to_hex()}
            payload2 = {
                "outputs": [P2PKH_OUTPUT],
                "password": "test"
            }

            txids = []
            async with aiohttp.ClientSession() as session:
                tasks = [asyncio.create_task(self._create_and_send(session, payload2)) for _ in
                         range(0, n_txs)]
                results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                error_code = result.get('code')
                if error_code:
                    assert False, str(Fault(error_code, result.get('message')))
                txids.append(result['txid'])

            await wait_for_mempool(txids)

        event_loop.run_until_complete(main())

    def test_create_and_broadcast_exception_handling(self, event_loop):
        Net.set_to(SVRegTestnet)
        p2pkh_object = SVRegTestnet.REGTEST_FUNDS_PUBLIC_KEY.to_address()

        async def main():
            async with aiohttp.ClientSession() as session:
                # get tx history before tests to compare later
                result1 = self._get_tx_history()
                len_tx_hist_before = len(result1.json()['history'])

                # get utxos
                result2 = self._get_utxos()
                utxos = result2.json()['utxos']

                # Prepare for two txs that use the same utxo
                P2PKH_OUTPUT = {"value": 100,
                                "script_pubkey": p2pkh_object.to_script().to_hex()}
                # base tx
                payload1 = {
                    "outputs": [P2PKH_OUTPUT],
                    "password": "test",
                    "utxos": [utxos[0]]
                }
                # trigger mempool conflict
                payload2 = {
                    "outputs": [P2PKH_OUTPUT, P2PKH_OUTPUT],
                    "password": "test",
                    "utxos": [utxos[0]]
                }

                txids = []
                # First tx
                result3 = await self._create_and_send(session, payload1)
                error_code = result3.get('code')
                if error_code:
                    assert False, result3
                txids.append(result3['txid'])

                # Trigger "mempool conflict"
                result4 = await self._create_and_send(session, payload2)
                error_code = result4.get('code')
                if not error_code:
                    assert False, result4

                assert result4['code'] == 40011

                # trigger insufficient coins
                P2PKH_OUTPUT = {"value": 1_000 * 100_000_000,
                                "script_pubkey": p2pkh_object.to_script().to_hex()}
                payload2 = {
                    "outputs": [P2PKH_OUTPUT],
                    "password": "test"
                }
                result5 = await self._create_and_send(session, payload2)
                error_code = result5.get('code')
                if not error_code:
                    assert False, result5
                assert result5 == {'code': 40006,
                                   'message': 'You have insufficient coins for this transaction'}

                await wait_for_mempool(txids)

                # check that only 1 new txs was created
                result6 = self._get_tx_history()
                error_code = result6.json().get('code')
                if error_code:
                    assert False, result6
                len_tx_hist_after = len(result6.json()['history'])

                # only one extra tx should exist (in the other cases, no tx should exist)
                assert len_tx_hist_before == (len_tx_hist_after - 1)

        event_loop.run_until_complete(main())
