# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019-2020 The ElectrumSV Developers
# Copyright (c) 2011-2016 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import asyncio
from aiohttp import ClientSession
import bitcoinx
from bitcoinx import Chain, double_sha256, hex_str_to_hash, Header, Headers, MissingHeader
from collections import defaultdict
import dataclasses
import concurrent.futures
import time
from enum import IntEnum
from io import BytesIO
from typing import Any, cast, Iterable, Optional, TYPE_CHECKING

from .app_state import app_state
from .constants import NetworkEventNames, NetworkServerType, ServerCapability
from .exceptions import ServiceUnavailableError
from .logs import logs
from .network_support.api_server import APIServerDefinition
from .network_support.esv_client_types import TipResponse
from .network_support.headers import HeaderServerState, get_batched_headers_by_height_async, \
    get_chain_tips_async, ServerConnectivityMetadata, subscribe_to_headers_async
from .networks import Net
from .types import ServerAccountKey
from .util import TriggeredCallbacks

if TYPE_CHECKING:
    from .wallet import Wallet


logger = logs.get_logger("network")

HEADER_SIZE = 80
ONE_MINUTE = 60
ONE_DAY = 24 * 3600
MAX_CONCEIVABLE_REORG_DEPTH = 500


class SwitchReason(IntEnum):
    '''The reason the main server was changed.'''
    disconnected = 0
    lagging = 1
    user_set = 2


def future_callback(future: concurrent.futures.Future[None]) -> None:
    if future.cancelled():
        return
    future.result()


@dataclasses.dataclass
class MainLoopContext:
    futures: list[concurrent.futures.Future[None]] = dataclasses.field(
        default_factory=list[concurrent.futures.Future[None]])


class Network(TriggeredCallbacks[NetworkEventNames]):
    '''Manages a set of connections to remote ElectrumSV-Reference-Servers. Each loaded Wallet
    instance has a "main server" which only changes if the user manually changes it.

    All operations are asynchronous.
    '''

    def __init__(self) -> None:
        TriggeredCallbacks.__init__(self)

        app_state.read_headers()

        # Events
        self.new_server_connection_event = app_state.async_.event()
        self._shutdown_complete_event = app_state.async_.event()
        self.servers_synced_events: defaultdict[ServerAccountKey, asyncio.Event] = \
            defaultdict(app_state.async_.event)

        # Add an wallet, remove an wallet, or redo all wallet verifications
        self._wallets: set[Wallet] = set()

        self.aiohttp_session = ClientSession(loop=app_state.async_.loop)
        self.connected_header_server_states = dict[ServerAccountKey, HeaderServerState]()

        self._new_server_queue: asyncio.Queue[ServerAccountKey] = asyncio.Queue()
        # The usable set of API servers both globally known by the application and also
        # per-wallet/account servers from each wallet database.
        self._known_header_server_keys = set[ServerAccountKey]()
        self._chosen_servers: set[ServerAccountKey] = set()
        self._server_connectivity_metadata = dict[ServerAccountKey, ServerConnectivityMetadata]()

        self._main_loop_context: Optional[MainLoopContext] = MainLoopContext()
        self._main_loop_future = app_state.async_.spawn(self._main_loop_async,
            self._main_loop_context)
        # Futures swallow exceptions if there are no callbacks to collect the exception.
        self._main_loop_future.add_done_callback(future_callback)

    # TODO(1.4.0) Servers. Call or remove. Just call it directly wherever.
    async def close_aiohttp_session(self) -> None:
        await self.aiohttp_session.close()

    def get_local_height(self) -> int:
        chain = self.chain()
        # This can be called from network_dialog.py when there is no chain
        return cast(int, chain.height) if chain else 0

    def get_local_tip_hash(self) -> bytes:
        chain = self.chain()
        assert chain is not None
        return cast(bytes, chain.tip.hash)

    def is_header_present(self, block_hash: bytes) -> bool:
        """If the mmap headers store is lost/deleted, the orphaned header will be lost with it.
        Therefore, on a wallet restoration, the orphaned header will be missing. The fallback
        is to rescan all transaction history for the new longest chain."""
        try:
            _header, _old_chain = cast(Headers, app_state.headers).lookup(block_hash)
            return True
        except MissingHeader:
            return False

    async def _find_any_common_header_async(self, server_state: HeaderServerState,
            server_tip: Header) -> Header:
        """This steps back through the chain in an exponentially growing interval until it finds a
        common header. This does not return the precise, common parent, it merely returns any header
        that is common to both chains to act as a base for connecting the headers along the server's
        fork.

        If two ESV Reference Servers are on the same chain then this function will only
        be called once per distinct chain (see `_synchronize_initial_headers_async`)"""
        # start with step = 16 to cut down on network round trips for the first initial header sync
        step = 16
        height_to_test = server_tip.height
        while True:
            raw_header = await get_batched_headers_by_height_async(server_state,
                self.aiohttp_session, from_height=max(height_to_test, 0), count=1)
            try:
                self.header_for_hash(double_sha256(raw_header))
                common_header = Net._net.COIN.deserialized_header(raw_header, height_to_test)
                return common_header
            except MissingHeader:
                height_to_test -= step
                step = step * 4  # keep doubling the interval until we hit a common header

    async def _synchronize_initial_headers_async(self, server_state: HeaderServerState) \
            -> tuple[Header, Chain]:
        """
        NOTE: requesting batched headers by height works because the headers at these heights are
        on the longest chain **for that instance of the ElectrumSV-Reference-Server**
        (emphasis added). For example there could be two persisting forks but requesting batched
        headers by height on each instance will give the headers leading to their own respective
        tips.

        Raises `ServiceUnavailableError` via _request_and_connect_headers_at_heights_async
        """
        tip_header = await get_chain_tips_async(server_state, self.aiohttp_session)
        while not self.is_header_present(tip_header.hash):
            any_common_base_header = await self._find_any_common_header_async(server_state,
                server_tip=tip_header)
            heights = [height for height in range(any_common_base_header.height,
                tip_header.height + 1)]
            await self._request_and_connect_headers_at_heights_async(server_state, heights)

        server_tip = tip_header
        header, server_chain = cast(Headers, app_state.headers).lookup(server_tip.hash)
        return server_tip, server_chain

    async def _connect_tip_and_maybe_backfill(self, server_state: HeaderServerState,
            new_tip: TipResponse) -> None:
        try:
            cast(Headers, app_state.headers).connect(new_tip.header)
        except MissingHeader:
            # The headers store uses the genesis block as the base checkpoint but there is
            # no previous header before the genesis header so when attempting to "connect"
            # the genesis block, it will raise MissingHeader. We can only connect subsequent
            # headers to the genesis block.
            if bitcoinx.double_sha256(new_tip.header) == hex_str_to_hash(Net._net.GENESIS):
                return None
            # This should only happen if the new_tip notification skips intervening headers e.g.
            # a) There was a reorg
            # b) The longest chain grows instantly by more than one block e.g. on RegTest sometimes
            #    we mine 100 blocks or more in quick secession.
            heights = [height for height in range(
                new_tip.height-MAX_CONCEIVABLE_REORG_DEPTH, new_tip.height + 1)]
            await self._request_and_connect_headers_at_heights_async(server_state, heights)

        return None

    async def _monitor_chain_tip_task_async(self, server_key: ServerAccountKey) \
            -> None:
        """
        All chosen servers (up to a limit of 10) will run an independent instance this task.
        Only the main server results in mutated wallet state (e.g. only reorgs on the main server
        will affect wallet state).

        raises `ServiceUnavailableError` via:
            - `main_server._synchronize_initial_headers_async` or
            - `main_server.subscribe_to_headers` or
            - `self._connect_tip_and_maybe_backfill`
        """
        # Already obsolete.
        if server_key not in self.connected_header_server_states:
            return

        server_state = self.connected_header_server_states[server_key]

        # Will not proceed past this point until initial headers sync completes
        server_tip, server_chain = \
            await self._synchronize_initial_headers_async(server_state)

        server_state.tip_header = server_tip
        server_state.chain = server_chain
        for wallet in self._wallets:
            if wallet.main_server is not None and \
                    wallet.main_server.server_key.url == server_state.server_key.url:
                wallet.update_main_server_tip_and_chain(server_state.tip_header, server_state.chain)

        self.servers_synced_events[server_key].set()

        server_metadata = self._server_connectivity_metadata[server_key]
        server_metadata.last_try = time.time()

        # This server is ready for wallets to rely on for use as an indexing server (should it
        # be indexing server capable).
        server_state.connection_event.set()

        # TODO(1.4.0) Servers. This establishes a header-only websocket to the server, however if
        #     this is used as an indexing server it will also have a general account websocket to
        #     the server which also sends header events. We should modify this to receive headers
        #     from  the header websocket only if there is not a general websocket connection,
        #     switching back and forwards using some rational heuristic.
        new_tip: TipResponse
        # iterator yields forever
        async for new_tip in subscribe_to_headers_async(server_state, self.aiohttp_session):
            logger.debug("Got new tip: %s for server: %s", new_tip, server_state.server_key.url)

            server_chain_before = server_chain
            await self._connect_tip_and_maybe_backfill(server_state, new_tip)
            header, server_chain = cast(Headers, app_state.headers)\
                .lookup(double_sha256(new_tip.header))
            server_state.tip_header = header
            server_state.chain = server_chain

            for wallet in self._wallets:
                if wallet.main_server is not None and \
                        wallet.main_server.server_key.url == server_state.server_key.url:
                    await wallet.reorg_check_main_chain(server_chain_before, server_chain)
                    wallet.update_main_server_tip_and_chain(server_state.tip_header,
                        server_state.chain)

    # def _available_servers(self) -> List[ServerAccountKey]:
    #     now = time.time()
    #     all_available_server_keys = self._known_header_server_keys - self._chosen_servers
    #     available_server_keys = list[ServerAccountKey]()
    #     for server_key in all_available_server_keys:
    #         server_metadata = self._server_connectivity_metadata[server_key]
    #         if not server_metadata.is_disabled and \
    #                 now > server_metadata.last_blacklisted + ONE_DAY and \
    #                 server_metadata.last_try + server_metadata.retry_delay < now:
    #             available_server_keys.append(server_key)
    #     return available_server_keys

    # def _random_server_nowait(self) -> Optional[ServerAccountKey]:
    #     available_server_keys = self._available_servers()
    #     return random.choice(available_server_keys) if len(available_server_keys) > 0 else None

    # async def _random_server(self, retry_timeout: int=10) -> ServerAccountKey:
    #     while True:
    #         server_key = self._random_server_nowait()
    #         if server_key is not None:
    #             return server_key
    #         await sleep(retry_timeout)

    def register_wallet_server(self, server_key: ServerAccountKey) -> None:
        """
        A wallet is notifying the network of header-capable servers that they know of. There may
        be some overlap, but this is okay. The networking logic filters out known servers.
        """
        self._new_server_queue.put_nowait(server_key)

    async def _main_loop_async(self, context: MainLoopContext) -> None:
        """
        Pre-populate the header servers from the hard-coded configuration.
        When new wallets are loaded they will push new, unique servers to the queue
        """
        try:
            # Make sure this has been created.
            for hardcoded_server_config in cast(list[APIServerDefinition], Net.DEFAULT_SERVERS_API):
                server_type: Optional[NetworkServerType] = getattr(NetworkServerType,
                    hardcoded_server_config['type'], None)
                if server_type is None:
                    logger.error("Misconfigured hard-coded server with url '%s' and type '%s'",
                        hardcoded_server_config['url'], hardcoded_server_config['type'])
                    continue

                # We check the server url is normalised at a superficial level.
                url = hardcoded_server_config['url']
                ideal_url = url.strip().lower()
                assert url == ideal_url, \
                    f"Skipped bad server with strange url '{url}' != '{ideal_url}'"

                server_key = ServerAccountKey(url, server_type, None)
                for capability_name in hardcoded_server_config.get("capabilities", []):
                    capability_value = getattr(ServerCapability, capability_name, None)
                    if capability_value is None:
                        logger.error("Server '%s' has invalid capability '%s'", url,
                            capability_name)
                    elif capability_value == ServerCapability.HEADERS:
                        self._new_server_queue.put_nowait(server_key)

            while self._main_loop_context is context:
                server_key = await self._new_server_queue.get()
                # A wallet loading will notify us of header-capable servers we may already know.
                if server_key in self._known_header_server_keys:
                    continue

                self._known_header_server_keys.add(server_key)
                self._server_connectivity_metadata[server_key] = ServerConnectivityMetadata()

                # TODO(1.4.0) Servers. Need some logic that limits how many servers are
                #     connected to.
                assert self._connect_to_server_async(context, server_key)
        finally:
            logger.debug("Network maintain connections task exiting.")
            for future in context.futures:
                future.cancel()
            self._shutdown_complete_event.set()

    def is_header_server_ready(self, server_key: ServerAccountKey) -> bool:
        if self.servers_synced_events[server_key].is_set():
            return self.connected_header_server_states.get(server_key) is not None
        return False

    async def wait_until_header_server_is_ready_async(self, server_key: ServerAccountKey) -> None:
        """
        The calling wallet is expected to know the network has been notified about the server.
        This will block until the server has connected. It is the responsibility of the wallet
        to timeout the call.
        """
        assert server_key in self._known_header_server_keys
        while server_key not in self.connected_header_server_states:
            await self.new_server_connection_event.wait()

        server_state = self.connected_header_server_states[server_key]
        await server_state.connection_event.wait()

    def _connect_to_server_async(self, context: MainLoopContext, server_key: ServerAccountKey) \
            -> bool:
        """
        The decision has been made that this server must be connected to at this point. Either
        we are already connected or we will have started establishing a connection.
        """
        if server_key not in self.connected_header_server_states:
            future = app_state.async_.spawn(self._maintain_connection, context, server_key)
            # Futures swallow exceptions if there are no callbacks to collect the exception.
            future.add_done_callback(future_callback)
            self.connected_header_server_states[server_key] = HeaderServerState(server_key,
                future)
            self.new_server_connection_event.set()
            self.new_server_connection_event.clear()
            return True
        return False

    async def _maintain_connection(self, context: MainLoopContext, server_key: ServerAccountKey) \
            -> None:
        try:
            while context is self._main_loop_context:
                try:
                    await self._monitor_chain_tip_task_async(server_key)
                except ServiceUnavailableError:
                    logger.error("Server unavailable: %s", server_key)
                # TODO(1.4.0) Servers. Connection retrying should have some logic to it.
                await asyncio.sleep(20)
        finally:
            del self.connected_header_server_states[server_key]

    #
    # External API
    #

    async def shutdown_wait(self) -> None:
        self._main_loop_context = None
        self._main_loop_future.cancel()
        await self._shutdown_complete_event.wait()
        logger.warning('stopped')

    def is_connected(self) -> bool:
        return all([wallet.main_server is not None for wallet in self._wallets])

    # def is_server_disabled(self, url: str, server_type: NetworkServerType) -> bool:
    #     """
    #     Whether the given server is configured to be unusable by anything.
    #     """
    #     return self._known_header_server_keys[ServerAccountKey(url, server_type, None)]\
    #           .is_unusable()

    def add_wallet(self, wallet: "Wallet") -> None:
        """ This wallet has been loaded and is now using this network. """
        self._wallets.add(wallet)

    def remove_wallet(self, wallet: "Wallet") -> None:
        """ This wallet has been unloaded and is no longer using this network. """
        self._wallets.remove(wallet)

    def chain(self) -> Chain:
        return cast(Headers, app_state.headers).longest_chain()

    async def _request_and_connect_headers_at_heights_async(self, server_state: HeaderServerState,
            heights: Iterable[int]) -> None:
        """
        Raises `ServiceUnavailableError` in `get_batched_headers_by_height_async`
        """
        MAX_HEADER_REQUEST_BATCH_SIZE = 2000
        sorted_heights = sorted(heights)
        while len(sorted_heights) != 0:
            batch_heights = sorted_heights[0:MAX_HEADER_REQUEST_BATCH_SIZE]
            sorted_heights = sorted_heights[MAX_HEADER_REQUEST_BATCH_SIZE:]
            min_height = max(batch_heights[0], 1)  # We don't want the genesis block at height 0
            max_height = batch_heights[-1]
            count = max_height - min_height + 1
            logger.debug("Fetching %s headers from start height: %s", count, min_height)
            header_array = await get_batched_headers_by_height_async(server_state,
                self.aiohttp_session, min_height, count)
            print(header_array)
            stream = BytesIO(header_array)

            count_of_raw_headers = len(header_array) // 80
            for i in range(count_of_raw_headers):
                raw_header = stream.read(80)
                cast(Headers, app_state.headers).connect(raw_header)

    def header_at_height(self, height: int) -> Header:
        assert app_state.headers is not None
        return app_state.headers.header_at_height(self.chain(), height)

    def header_for_hash(self, block_hash: bytes) -> Header:
        assert app_state.headers is not None
        header, _chains = app_state.headers.lookup(block_hash)
        return header

    # TODO(1.4.0) Network Dialogue. This needs to be re-connected to the Network Dialogue GUI
    def auto_connect(self) -> bool:
        return app_state.config.get_explicit_type(bool, 'auto_connect', True)

    def status(self) -> dict[str, Any]:
        return {
            # 'server': str(self.main_server.base_url),
            'blockchain_height': self.get_local_height(),
            # 'server_height': self.main_server.tip.height,
            'spv_nodes': len(self._known_header_server_keys),
            'connected': self.is_connected(),
            'auto_connect': self.auto_connect(),
        }
