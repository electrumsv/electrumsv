"""
Warning - this will reset all components back to a blank state before running the simulation

Runs node1, indexer1, reference1 and electrumsv1 and loads the default wallet on the daemon
(so that newly submitted blocks will be synchronized by ElectrumSV

reorged txid: 'a1fa9460ca105c1396cd338f7fa202bf79a9d244d730e91e19f6302a05b2f07a'
"""
import asyncio
import os
from pathlib import Path

import pytest
import pytest_asyncio
from electrumsv_node import electrumsv_node
from electrumsv_sdk import utils
import logging
import requests
from contrib.functional_tests.websocket_client import TxStateWSClient

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("simulate-fresh-reorg")


async def wait_for_reorg_transaction_update(reorged_txids, reorg_height):
    MAX_WAIT_TIME = 10  # seconds
    async with TxStateWSClient() as ws_client:
        try:
            await asyncio.wait_for(ws_client.block_until_confirmed_and_height_updated(
                reorged_txids, reorg_height), MAX_WAIT_TIME)
        except asyncio.TimeoutError:
            logger.exception(f"timed out after {MAX_WAIT_TIME} seconds")
            raise


class TestReorg:

    @classmethod
    def setup_class(cls):
        pass

    @classmethod
    def teardown_class(cls):
        pass

    # @pytest.mark.asyncio
    # def test_reorg(self, event_loop):

    #     async def test_reorg():
    #         payload = {
    #             "password": "test"
    #         }
    #         REORGED_TXIDS = "a1fa9460ca105c1396cd338f7fa202bf79a9d244d730e91e19f6302a05b2f07a"

    #         # Load the default wallet on ElectrumSV daemon
    #         url = f"http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/load_wallet"
    #         result = requests.post(url, json=payload)
    #         result.raise_for_status()

    #         # Submit node1 blocks to node
    #         if electrumsv_node.is_node_running():
    #             utils.submit_blocks_from_file(node_id='node1',
    #                 filepath=Path(MODULE_DIR).joinpath('../reorg_blocks/node1_blocks.dat'))
    #         else:
    #             logger.exception("node unavailable")

    #         try:
    #             await wait_for_reorg_transaction_update([REORGED_TXIDS], 201)
    #             # Todo check state of get_balance; get_coin_state; get_transaction_history

    #             # Submit node2 blocks to node
    #             if electrumsv_node.is_node_running():
    #                 utils.submit_blocks_from_file(node_id='node1',
    #                     filepath=Path(MODULE_DIR).joinpath('../reorg_blocks/node2_blocks.dat'))
    #             else:
    #                 logger.exception("node unavailable")

    #             await wait_for_reorg_transaction_update([REORGED_TXIDS], 202)
    #         except asyncio.TimeoutError:
    #             pytest.xfail("work in progress alongside refactoring changes...")

    #         # Todo check state of get_balance; get_coin_state; get_transaction_history

    #     event_loop.run_until_complete(test_reorg())
