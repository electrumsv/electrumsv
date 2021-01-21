"""
Warning - this will reset all components back to a blank state before running the simulation

Runs node1, electrumx1 and electrumsv1 and loads the default wallet on the daemon (so that newly
submitted blocks will be synchronized by ElectrumSV

reorged txid: 'a1fa9460ca105c1396cd338f7fa202bf79a9d244d730e91e19f6302a05b2f07a'
"""
import asyncio
import os
import time
from pathlib import Path

from electrumsv_node import electrumsv_node
from electrumsv_sdk import commands, utils
import logging
import requests
from .websocket_client import TxStateWSClient

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("simulate-fresh-reorg")


async def wait_for_reog_transaction_update(reorged_txids, reorg_height):
    MAX_WAIT_TIME = 30  # seconds
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
        ELECTRUMSV_TOP_LEVEL_DIRECTORY = Path(MODULE_DIR).parent.parent

        commands.stop('node', component_id='node1')
        commands.stop('electrumx', component_id='electrumx1')
        commands.stop('electrumsv', component_id='electrumsv1')
        commands.reset('node', component_id='node1')
        commands.reset('electrumx', component_id='electrumx1')
        commands.reset('electrumsv', component_id='electrumsv1', deterministic_seed=True)

        # Start components
        commands.start("node", component_id='node1')
        commands.start("electrumx", component_id='electrumx1')
        commands.start("electrumsv", component_id='electrumsv1',
            repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY)
        time.sleep(5)

    def teardown_class(cls):
        commands.stop()

    async def test_reorg(self):
        REORGED_TXIDS = "a1fa9460ca105c1396cd338f7fa202bf79a9d244d730e91e19f6302a05b2f07a"

        # Load the default wallet on ElectrumSV daemon
        url = f"http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/load_wallet"
        result = requests.post(url)
        result.raise_for_status()

        # Submit node1 blocks to node
        if electrumsv_node.is_node_running():
            utils.submit_blocks_from_file(node_id='node1',
                filepath=Path(MODULE_DIR).joinpath('reorg_blocks/node1_blocks.dat'))
        else:
            logger.exception("node unavailable")

        await wait_for_reog_transaction_update([REORGED_TXIDS], 201)
        # Todo check state of get_balance; get_coin_state; get_transaction_history

        # Submit node2 blocks to node
        if electrumsv_node.is_node_running():
            utils.submit_blocks_from_file(node_id='node1',
                filepath=Path(MODULE_DIR).joinpath('reorg_blocks/node2_blocks.dat'))
        else:
            logger.exception("node unavailable")

        try:
            await wait_for_reog_transaction_update([REORGED_TXIDS], 202)
        except asyncio.TimeoutError:
            assert False, "timed out"

        # Todo check state of get_balance; get_coin_state; get_transaction_history
