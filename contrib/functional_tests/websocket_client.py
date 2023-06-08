import asyncio
import json
import logging
from types import TracebackType
from typing import cast, Iterable, List, Optional, Type

import aiohttp
import requests

from electrumsv.constants import TxFlag

logging.basicConfig(level=logging.DEBUG)


class TxStateWSClient:

    def __init__(self, host: str="127.0.0.1", port: int=9999, wallet_name: str="worker1.sqlite",
            wallet_password: str="test", account: int=1) -> None:
        self.host = host
        self.port = port
        self.url = f'http://{self.host}:{self.port}/v1/regtest/dapp/' \
            f'wallets/{wallet_name}/{account}/txs/websocket/text-events'
        self.wallet_name = wallet_name
        self.wallet_password = wallet_password
        self.account = account
        self.session = aiohttp.ClientSession()
        self._ws: Optional[aiohttp.client.ClientWebSocketResponse] = None
        self.msg_queue = asyncio.Queue()
        self.logger = logging.getLogger("tx-state-ws-client")

    async def __aenter__(self) -> "TxStateWSClient":
        # Normally the RESTAPI pulls the password out of the body, but `ws_connect` cannot be
        # passed a data/json parameter even if it's method is changed to POST.
        self._ws = await self.session.ws_connect(self.url,
            headers={ "X-Wallet-Password": self.wallet_password })
        return self

    async def __aexit__(self, exc_type: Optional[Type[BaseException]],
            exc_value: Optional[BaseException], traceback: Optional[TracebackType]) \
                -> None:
        await cast(aiohttp.client.ClientWebSocketResponse, self._ws).close()
        await self.session.close()

    async def send_str(self, msg: str) -> None:
        await cast(aiohttp.client.ClientWebSocketResponse, self._ws).send_str(msg)

    async def _receive_msgs(self) -> None:
        try:
            async for msg in cast(aiohttp.client.ClientWebSocketResponse, self._ws):
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

    async def block_until_mempool(self, txids: Iterable[str]) -> None:
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
                    (tx_flags & TxFlag.STATE_CLEARED) == TxFlag.STATE_CLEARED or \
                    (tx_flags & TxFlag.STATE_SETTLED) == TxFlag.STATE_SETTLED:
                txids_set.remove(txid)

            if len(txids_set) == 0:
                break

    async def block_until_confirmed(self, txids: List[str]) -> None:
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
                    (tx_flags & TxFlag.STATE_SETTLED == TxFlag.STATE_SETTLED):
                txids_set.remove(txid)

            self.logger.debug(f"count txid_set = {len(txids_set)}")
            if len(txids_set) == 0:
                break

    async def block_until_confirmed_and_height_updated(self, reorg_txids: List[str],
            reorg_height: int) -> None:
        """For waiting on a reorged transaction to have its height updated"""
        self._receive_msg_task = asyncio.create_task(self._receive_msgs())
        subs = json.dumps({
            "txids": list(reorg_txids)
        })
        txids_set = set(reorg_txids)
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
                    (tx_flags & TxFlag.STATE_SETTLED == TxFlag.STATE_SETTLED):
                url = "http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/history"
                payload = {"tx_flags": 2097152}
                result = requests.get(url, data=json.dumps(payload))
                result.raise_for_status()
                for tx in result.json()['history']:
                    if tx['txid'] in txids_set:
                        reorg_tx = tx
                        break
                else:
                    continue  # to wait on queue ^^

                if reorg_tx['height'] == reorg_height:
                    txids_set.remove(txid)
                else:  # keep waiting for the reorg notification...
                    self.logger.info(f"got notification for the stale tx: {tx['txid']} at height: "
                        f"{reorg_tx['height']}")

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
