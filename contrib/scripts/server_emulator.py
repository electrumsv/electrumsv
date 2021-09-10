"""
Server emulator for regtest.

This application provides a number of open ports, each of which acts like an independent header
source, and can provide a view of competing tips between them to a connected ElectrumSV wallet.

Notes:
  - ElectrumSV waits 60 seconds for it's lagging main server before switching to the new longest
    chain server as it's main server. This is why the delay between updates is 20 seconds,
    as it gives servers a chance to stay ahead of the current main server for longer than that
    60 seconds (and therefore get switched to as the new main server).

Instructions:

  1. Run this script.
  2. Run ElectrumSV in regtest mode, ensure any existing headers files are deleted.
  3. In ElectrumSV, open the Network dialog.
  4. In the ElectrumSV Network dialog, add an ElectrumX server for tcp://localhost:8888/
  5. In the ElectrumSV Network dialog, add an ElectrumX server for tcp://localhost:8889/
  6. In the ElectrumSV Network dialog, add an ElectrumX server for tcp://localhost:8890/
  7. In the ElectrumSV Network dialog, add an ElectrumX server for tcp://localhost:8891/
  8. Observe two servers on each competing chain (whenever they are not all aligned).

"""

import asyncio
from functools import partial
import logging
import os
import random
import time
import traceback
from typing import Any, List, Tuple, TypedDict

from aiorpcx import handler_invocation, Request, RPCSession, serve_rs
from bitcoinx import BitcoinRegtest, grind_header, merkle_root


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("example-server")


VERSION = 0.1
GENESIS_HEADER_HEX = \
    '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd' \
    '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000'
HEX_HEADER_LENGTH = len(GENESIS_HEADER_HEX)


class HeadersSubscribeResponse(TypedDict):
    hex: str
    height: int


class BlockHeadersResponse(TypedDict):
    count: int
    hex: str
    max: int


class Blockchain:
    def __init__(self) -> None:
        self._header_list: List[str] = [
            GENESIS_HEADER_HEX,
        ]
        self.header_text: str = self._header_list[0]
        self.tips = [
            CompetingTip(1, self),
            CompetingTip(2, self),
            CompetingTip(3, self),
            CompetingTip(4, self),
        ]

    def get_height(self) -> int:
        return len(self._header_list)-1

    def get_header_hex_at_height(self, height: int) -> str:
        assert height >= 0
        header_index = height
        assert header_index < len(self._header_list)
        return self._header_list[header_index]

    def consider_adopting_competing_tip(self, tip: "CompetingTip") -> bool:
        if tip.base_header_hex == self._header_list[-1]:
            self._header_list.extend(tip.local_headers)
            return True
        return False

    async def run(self) -> None:
        try:
            await self._run()
        except Exception:
            traceback.print_exc()

    async def _run(self) -> None:
        # Build up a pre-existing blockchain.
        for i in range(20):
            self.tips[0].advance()
        # Align any other tips with the first tip.
        for tip in self.tips[1:]:
            tip.clear(rewind_amount=random.randint(5, 10))
            for i in range(random.randint(1, 10)):
                tip.advance()

        while True:
            for tip in self.tips:
                if tip.is_branch_too_long():
                    if self.consider_adopting_competing_tip(tip):
                        tip.clear()
                    else:
                        tip.clear(rewind_amount=random.randint(5, 10))
                        for i in range(random.randint(5, 15)):
                            tip.advance()
                        tip.mark_starting_point()
                else:
                    tip.advance()
                await tip.notify_listeners()
                await asyncio.sleep(20.0)


class CompetingTip:
    def __init__(self, tip_id: int, blockchain: Blockchain) -> None:
        self._server_sessions: List["ServerSession"] = []

        self.tip_id = tip_id
        self.blockchain = blockchain
        self.clear()

    def clear(self, rewind_amount: int=0) -> None:
        self.blockchain_height = max(0, self.blockchain.get_height() - rewind_amount)
        print(f"Tip[{self.tip_id}] rewound to height {self.blockchain_height}")
        self.base_header_hex = self.blockchain.get_header_hex_at_height(self.blockchain_height)
        self.local_headers = []
        self._starting_index = 0

    def advance(self) -> None:
        local_height = self.get_height()
        prev_header_hex = self.get_header_hex_at_height(local_height)
        prev_header_bytes = bytes.fromhex(prev_header_hex)
        prev_header = BitcoinRegtest.deserialized_header(prev_header_bytes, local_height)

        version = prev_header.version
        bits = prev_header.bits
        tx_hashes = [os.urandom(32) for _ in range(random.randrange(1, 9))]
        tx_merkle_root = merkle_root(tx_hashes)
        timestamp = int(time.time())

        next_header = grind_header(version, prev_header.hash, tx_merkle_root, timestamp, bits)
        assert next_header is not None
        self.local_headers.append(next_header.hex())
        print(f"Tip[{self.tip_id}] advance, local_height={self.get_height()}")

    def mark_starting_point(self) -> None:
        self._starting_index = self.get_branch_length()

    def is_branch_too_long(self, max_length=5) -> bool:
        return (self.get_branch_length() - self._starting_index) > max_length

    def get_branch_length(self) -> int:
        return len(self.local_headers)

    def get_header_hex_at_height(self, height: int) -> str:
        if height <= self.blockchain_height:
            return self.blockchain.get_header_hex_at_height(height)
        branch_index = (height - self.blockchain_height) - 1
        assert branch_index < self.get_branch_length()
        return self.local_headers[branch_index]

    def get_height(self) -> int:
        return self.blockchain_height + len(self.local_headers)

    def add_listener(self, session: "ServerSession") -> None:
        self._server_sessions.append(session)

    async def notify_listeners(self) -> None:
        for session in self._server_sessions:
            data = await session._handle_blockchain_headers_subscribe()
            await session.send_notification("blockchain.headers.subscribe", (data,))


class ServerSession(RPCSession):
    def __init__(self, server_name: str, competing_tip: CompetingTip, *args, **kwargs):
        self.server_name = server_name
        self.competing_tip = competing_tip

        competing_tip.add_listener(self)

        super().__init__(*args, **kwargs)
        print(f'{self.server_name}: connection from {self.remote_address()}')

    # aiorpcx event
    async def connection_lost(self):
        await super().connection_lost()
        print(f'{self.server_name}: {self.remote_address()} disconnected')

    # aiorpcx event
    async def handle_request(self, request: Request) -> Any:
        print(f"{self.server_name} HANDLE REQUEST {request!r}")
        if request.method == "server.version":
            handler = self._handler_server_version
        elif request.method == "blockchain.headers.subscribe":
            handler = self._handle_blockchain_headers_subscribe
        elif request.method == "blockchain.block.header":
            handler = self._handle_blockchain_block_header
        elif request.method == "blockchain.block.headers":
            handler = self._handle_blockchain_block_headers
        else:
            handler = None
        ret = await handler_invocation(handler, request)()
        print(f"{self.server_name} HANDLE REQUEST {request!r} = {ret}"[:400])
        return ret

    async def _handler_server_version(self, client_string: str, version_range: List[str]) \
            -> Tuple[str, str]:
        # ElectrumSV currently requires version 1.4 <= version >= 1.4, or will reject the server.
        return "FakeServer", "1.4.2"

    async def _handle_blockchain_headers_subscribe(self) -> HeadersSubscribeResponse:
        tip_height = self.competing_tip.get_height()
        return {
            "hex": self.competing_tip.get_header_hex_at_height(tip_height),
            "height": tip_height,
        }

    async def _handle_blockchain_block_header(self, height: int, cp_height: int=0) -> str:
        # We do not handle checkpoints.
        assert cp_height == 0
        return self.competing_tip.get_header_hex_at_height(height)

    async def _handle_blockchain_block_headers(self, start_height: int, header_count: int,
            cp_height: int=0) -> BlockHeadersResponse:
        # We do not handle checkpoints.
        assert cp_height == 0

        max_entries = 2000

        tip_height = self.competing_tip.get_height()
        current_height = start_height
        current_hex = ""
        current_count = 0
        while current_count < min(max_entries, header_count) and current_height <= tip_height:
            current_hex += self.competing_tip.get_header_hex_at_height(current_height)
            current_count += 1
            current_height += 1

        return {
            # The number of headers returned.
            "count": current_count,
            # The in-order concatenated hex of the headers.
            "hex": current_hex,
            # The maximum number of headers the server will return.
            "max": max_entries,
        }


def create_server(loop: asyncio.AbstractEventLoop, server_id: int,
        competing_tip: CompetingTip) -> None:
    """
    This creates a server.
    """
    server_name = f"server[{server_id}]"
    session_factory = partial(ServerSession, server_name, competing_tip)
    host = 'localhost'
    port = 8888 + server_id
    loop.run_until_complete(serve_rs(session_factory, host, port, reuse_address=True))
    print(f"{server_name} listening on {host}:{port}")



def loop_exception_handler(loop: asyncio.AbstractEventLoop, context) -> None:
    logger.debug('Exception handler called')
    logger.debug(context)


async def wakeup() -> None:
    while True:
        await asyncio.sleep(0.2)


loop = asyncio.get_event_loop()
loop.set_exception_handler(loop_exception_handler)
# Create the blockchain.
blockchain = Blockchain()
loop.create_task(blockchain.run())
# Create all the servers.
for i in range(5):
    # Just assign each tip alternately to each server as they are created.
    create_server(loop, i, blockchain.tips[i % len(blockchain.tips)])
# Boilerplate. The wakeup task helps the Ctrl-C handler work IIRC.
loop.create_task(wakeup())
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass
