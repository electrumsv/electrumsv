import aiohttp
import asyncio
import json
import logging
import requests
from typing import List, Iterable

from electrumsv.constants import TxFlags

logging.basicConfig(level=logging.DEBUG)


class TxStateWSClient:

    def __init__(self, host="127.0.0.1", port=9999, wallet_name="worker1.sqlite", account=1):
        self.host = host
        self.port = port
        self.url = f'http://{self.host}:{self.port}/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/websocket/text-events'
        self.wallet_name = wallet_name
        self.account = account
        self.session = aiohttp.ClientSession()
        self._ws = None
        self.msg_queue = asyncio.Queue()
        self.logger = logging.getLogger("tx-state-ws-client")

    async def __aenter__(self):
        self._ws = await self.session.ws_connect(self.url)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._ws.close()
        await self.session.close()

    async def send_str(self, msg: str):
        await self._ws.send_str(msg)

    async def _receive_msgs(self):
        try:
            async for msg in self._ws:
                if json.loads(msg.data).get('code'):
                    self.logger.debug(f'Error message received from server: {msg.data}')
                    continue
                self.logger.debug(f'Message received from server: {msg.data}')
                self.msg_queue.put_nowait(msg.data)
                if msg.type in (aiohttp.WSMsgType.CLOSED,
                aiohttp.WSMsgType.ERROR):
                    break
        finally:
            self.msg_queue.put_nowait(None)  # poison pill

    async def block_until_mempool(self, txids: Iterable[str]):
        self._receive_msg_task = asyncio.create_task(self._receive_msgs())
        subs = json.dumps({
            "txids": list(txids)
        })
        txids_set = set(txids)
        await self.send_str(subs)

        while True:
            msg = await self.msg_queue.get()
            if not msg:  # poison pill
                break
            msg = json.loads(msg)
            txid = msg.get("txid")
            if not txid:
                continue
            tx_flags = msg.get("tx_flags")
            if msg.get("txid") in txids_set and \
                    (tx_flags & TxFlags.StateCleared) == TxFlags.StateCleared or \
                    (tx_flags & TxFlags.StateSettled) == TxFlags.StateSettled:
                txids_set.remove(txid)

            if len(txids_set) == 0:
                break

    async def block_until_confirmed(self, txids: List[str]):
        self._receive_msg_task = asyncio.create_task(self._receive_msgs())
        subs = json.dumps({
            "txids": list(txids)
        })
        txids_set = set(txids)
        await self.send_str(subs)

        while True:
            msg = await self.msg_queue.get()
            if not msg:  # poison pill
                break
            msg = json.loads(msg)
            txid = msg.get("txid")
            if not txid:
                continue
            tx_flags = msg.get("tx_flags")
            if msg.get("txid") in txids_set and (tx_flags & TxFlags.StateSettled == TxFlags.StateSettled):
                txids_set.remove(txid)

            if len(txids_set) == 0:
                break


if __name__ == "__main__":

    logger = logging.getLogger("main")
    logger_urllib3 = logging.getLogger("urllib3")
    logger_urllib3.setLevel(logging.WARNING)

    async def wait_for_mempool(txids):
        async with TxStateWSClient() as ws_client:
            await ws_client.block_until_mempool(txids)

    async def wait_for_confirmation(txids):
        async with TxStateWSClient() as ws_client:
            await ws_client.block_until_confirmed(txids)

    result1 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                            f'worker1.sqlite/load_wallet')
    result2 = requests.post(f'http://127.0.0.1:9999/v1/regtest/dapp/wallets/'
                            f'worker1.sqlite/1/topup_account')
    if result2.status_code != 200:
        raise requests.exceptions.HTTPError(result2.text)
    txids = [result2.json()["txid"]]

    logger.info("mine a block to observe the websocket receiving the push notification and "
                "unblocking the thread")
    asyncio.run(wait_for_confirmation(txids))
