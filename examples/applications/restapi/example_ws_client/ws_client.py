import asyncio
import json

import aiohttp
import os

HOST = os.getenv('HOST', '127.0.0.1')
PORT = int(os.getenv('PORT', 9999))

URL = f'http://{HOST}:{PORT}/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/ws'


async def main():
    session = aiohttp.ClientSession()
    try:
        async with session.ws_connect(URL) as ws:
            initial_mock_txids = json.dumps({
                "txids": ["0c98872cb9fe74c0693af023310644954ba1f0815d64edc9719adec51e840c79"]
            })
            await ws.send_str(initial_mock_txids)
            async for msg in ws:
                if json.loads(msg.data).get('code'):
                    print('Error message received from server:', msg.data)
                    continue
                print('Message received from server:', msg.data)
                if msg.type in (aiohttp.WSMsgType.CLOSED,
                                aiohttp.WSMsgType.ERROR):
                    break
    finally:
        await session.close()
        print('Disconnected')

if __name__ == '__main__':
    print('Type "exit" to quit')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
