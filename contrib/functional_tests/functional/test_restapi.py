"""
Before running these tests you must install the electrumsv-sdk and run:

electrumsv-sdk start node
electrumsv-sdk start electrumx
electrumsv-sdk start --new electrumsv

"""
import asyncio
import enum
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

import aiohttp
import pytest
import requests
from async_timeout import timeout

from electrumsv.constants import TxFlags
from electrumsv.networks import SVRegTestnet, Net
from electrumsv.restapi import Fault

from ..websocket_client import TxStateWSClient
from .util import BITCOIN_NODE_URI, REGTEST_FUNDS_PRIVATE_KEY_WIF


MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
ELECTRUMSV_TOP_LEVEL_DIRECTORY = Path(MODULE_DIR).parent.parent.parent
logger = logging.getLogger("test-restapi")


P2PKH_SCRIPT_HEX = "76a914a18ddde6812ea971e6404b633ac403b0cf43f61088ac"

def with_timeout(t):
    def wrapper(corofunc):
        async def run(*args, **kwargs):
            try:
                with timeout(t):
                    return await corofunc(*args, **kwargs)
            except asyncio.TimeoutError:
                pytest.xfail("work in progress alongside refactoring changes...")
        return run
    return wrapper


async def wait_for_mempool(txids: List[str]) -> None:
    async with TxStateWSClient() as ws_client:
        await ws_client.block_until_mempool(txids)


async def wait_for_confirmation(txids):
    async with TxStateWSClient() as ws_client:
        await ws_client.block_until_confirmed(txids)

class WalletInstanceKind(enum.IntEnum):
    TEST_MINING = 1
    TEST_PAYMENT = 2

class TestRestAPI:
    mining_wallet: Dict[str, Any]

    TEST_WALLET_NAME = "worker1.sqlite"

    @classmethod
    def setup_class(cls) -> None:
        cls.TEST_WALLET_NAME = "worker1.sqlite"

        # Assume the node has started. Import the private key.
        payload = json.dumps(
            {"jsonrpc": "2.0", "method": "importprivkey",
            "params": [REGTEST_FUNDS_PRIVATE_KEY_WIF], "id": 0})
        result = requests.post(BITCOIN_NODE_URI, data=payload)
        result.raise_for_status()

        # TODO(REST-API-Refactoring) Re-enable and replace node wallet usage.
        # cls.mining_wallet = cls._load_wallet(WalletInstanceKind.TEST_MINING)
        # cls.payment_wallet = cls._load_wallet(WalletInstanceKind.TEST_PAYMENT)

        # mining_wallet_id = cls.mining_wallet["wallet_id"]
        # for i in range(3):
        #     request = cls._create_payment_request(mining_wallet_id)
        #     regtest_generate_nblocks(1, request["destination"])

        # request = cls._create_payment_request(mining_wallet_id)
        # regtest_generate_nblocks(100, request["destination"])

    @classmethod
    def teardown_class(cls) -> None:
        pass

    # TODO(REST-API-Refactoring) Re-enable and replace node wallet usage.
    # @classmethod
    # def topup_payment_account(cls) -> None:
    #     payment_wallet_id = cls.payment_wallet["wallet_id"]
    #     request = cls._create_payment_request(payment_wallet_id)
    #     destination = request["destination"]

    # @classmethod
    # def _load_wallet(cls, instance_kind: WalletInstanceKind) -> Dict[str, Any]:
    #     payload = {
    #         "password": "123456",
    #         "wallet_instance_id": instance_kind,
    #     }
    #     result = requests.post(
    #         f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/load_instanced',
    #         json=payload)
    #     if result.status_code != 200:
    #         raise requests.exceptions.HTTPError(result.text)
    #     return result.json()

    def _load_wallet(self):
        payload = {
            "password": "test"
        }
        _result1 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                                 f'{self.TEST_WALLET_NAME}/load_wallet', json=payload)
        if _result1.status_code != 200:
            raise requests.exceptions.HTTPError(_result1.text)
        return _result1

    def _topup_account(self):
        result2 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                                f'worker1.sqlite/1/topup_account')
        if result2.status_code != 200:
            raise requests.exceptions.HTTPError(result2.text)
        return result2

    # TODO(REST-API-Refactoring) Re-enable and replace node wallet usage.
    # @classmethod
    # def _create_payment_request(cls, wallet_id: int) -> Dict[str, Any]:
    #     payload = {
    #         "message": "Mining destination",
    #     }
    #     result = requests.post(
    #         f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/{wallet_id}/2/payment_request',
    #         json=payload)
    #     if result.status_code != 200:
    #         raise requests.exceptions.HTTPError(result.text)
    #     return result.json()

    def _fetch_transaction(self, txid: str):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/2/txs/fetch'
        payload = {"txid": txid}
        result = requests.post(url, data=json.dumps(payload))
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

    def _generate_blocks(self, nblocks: int):
        payload = {"nblocks": nblocks}
        result4 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                               f'{self.TEST_WALLET_NAME}/2/generate_blocks',
            data=json.dumps(payload))
        if result4.status_code != 200:
            raise requests.exceptions.HTTPError(result4.text)
        return result4

    def _get_coin_state(self):
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                               f'{self.TEST_WALLET_NAME}/2/utxos/coin_state')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

    def _get_utxos(self):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/2/utxos'
        result = requests.get(url)
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

    async def _create_and_send(self, session, payload):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/2/txs/create_and_broadcast'
        async with session.post(url, data=json.dumps(payload)) as resp:
            if resp != 200:
                return await resp.json()
            return await resp.json()

    def _get_tx_history(self):
        url = f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/' \
              f'{self.TEST_WALLET_NAME}/2/txs/history'
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
              f'{self.TEST_WALLET_NAME}/2/txs/split_utxos'

        result = requests.post(url, json=payload)
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)
        return result

    def test_create_new_wallet(self) -> None:
        payload = {"password": "test"}
        result = requests.post(
            f"http://127.0.0.1:9999/v1/regtest/dapp/wallets/{self.TEST_WALLET_NAME}/create_new_wallet",
            json=payload
        )
        if result.status_code != 200:
            if result.json()['code'] == 40008:
                pytest.skip("wallet already created")
                return
            raise requests.exceptions.HTTPError(result.text)

        result = requests.get(f"http://127.0.0.1:9999/v1/regtest/dapp/wallets/{self.TEST_WALLET_NAME}")
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        assert result.json()['parent_wallet'] == 'worker1.sqlite'
        assert result.json()['accounts']['1']['default_script_type'] == 'P2PKH'
        assert result.json()['accounts']['1']['wallet_type'] == 'Standard account'

    def test_get_all_wallets(self) -> None:
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

    @pytest.mark.asyncio
    @with_timeout(10)
    async def test_websocket_wait_for_mempool(self):
        self._load_wallet()
        result = self._topup_account()
        txids = [result.json()["txid"]]

        await wait_for_mempool(txids)
        for txid in txids:
            result2 = self._fetch_transaction(txid)
            assert result2.json()['tx_flags'] & TxFlags.STATE_CLEARED == TxFlags.STATE_CLEARED

    @pytest.mark.asyncio
    @with_timeout(10)
    async def test_websocket_wait_for_confirmation(self):
        self._load_wallet()
        result = self._topup_account()
        self._generate_blocks(1)
        txids = [result.json()["txid"]]

        await wait_for_confirmation(txids)
        for txid in txids:
            result2 = self._fetch_transaction(txid)
            assert result2.json()['tx_flags'] & TxFlags.STATE_SETTLED == TxFlags.STATE_SETTLED

    @pytest.mark.asyncio
    async def test_get_parent_wallet(self):
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
                              f'{self.TEST_WALLET_NAME}/2')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

        assert result.json() == expected_json

    @pytest.mark.asyncio
    @with_timeout(10)
    async def test_get_utxos_and_top_up(self):
        """
        1) get coin state before
        2) top up wallet
        3) get coin state after
        4) generate block to confirm coins
        5) get coin state after block confirmation
        """
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

    def test_get_balance(self):
        result = requests.get(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                              f'{self.TEST_WALLET_NAME}/2/utxos/balance')
        if result.status_code != 200:
            raise requests.exceptions.HTTPError(result.text)

    @pytest.mark.xfail
    @pytest.mark.asyncio
    @with_timeout(10)
    async def test_concurrent_tx_creation_and_broadcast(self):
        n_txs = 10

        # 1) split utxos
        result1 = self._split_utxos(outut_count=100, value=20000)
        txid = result1.json()['txid']
        self._generate_blocks(1)
        await wait_for_confirmation([txid])

        # 2) test concurrent transaction creation + broadcast
        Net.set_to(SVRegTestnet)
        P2PKH_OUTPUT = {"value": 10000,
                        "script_pubkey": P2PKH_SCRIPT_HEX}
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

    @pytest.mark.xfail
    @pytest.mark.asyncio
    @with_timeout(10)
    async def test_create_and_broadcast_exception_handling(self):
        Net.set_to(SVRegTestnet)

        async with aiohttp.ClientSession() as session:
            self._load_wallet()

            # get tx history before tests to compare later
            result1 = self._get_tx_history()
            len_tx_hist_before = len(result1.json()['history'])

            # get utxos
            result2 = self._get_utxos()
            utxos = result2.json()['utxos']

            # Prepare for two txs that use the same utxo
            P2PKH_OUTPUT = {"value": 100,
                            "script_pubkey": P2PKH_SCRIPT_HEX}
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
                            "script_pubkey": P2PKH_SCRIPT_HEX}
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

