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

from __future__ import annotations
import asyncio
from aiohttp import ClientSession
import bitcoinx
from bitcoinx import Chain, double_sha256, hex_str_to_hash, Header, MissingHeader
import dataclasses
import concurrent.futures
import time
from io import BytesIO
from typing import cast, Iterable, TYPE_CHECKING

from .app_state import app_state
from .constants import NetworkEventNames, NetworkServerType, ServerCapability
from .exceptions import ServiceUnavailableError
from .logs import logs
from .network_support.api_server import APIServerDefinition
from .network_support.types import TipResponse
from .network_support.headers import filter_tips_for_longest_chain, \
    get_batched_headers_by_height_async, get_chain_tips_async, HeaderServerState, \
    ServerConnectivityMetadata, subscribe_to_headers_async
from .networks import Net
from .types import NetworkStatusDict, ServerAccountKey
from .util import TriggeredCallbacks

if TYPE_CHECKING:
    from .wallet import Wallet


logger = logs.get_logger("network")

HEADER_SIZE = 80
ONE_MINUTE = 60
ONE_DAY = 24 * 3600
MAX_CONCEIVABLE_REORG_DEPTH = 500


async def header_sync_state_middleware(wallet: Wallet) -> bool:
    """This is not implemented as a typical aiohttp middleware, but functionally it acts as a
    middleware as it is called as a check prior to any RPC handlers"""
    assert wallet._network is not None
    if wallet._network.initial_headers_sync_complete():
        return True
    return False


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

        # Events
        self.new_server_ready_event = app_state.async_.event()
        self.new_server_connection_event = app_state.async_.event()
        self.lost_server_connection_event = app_state.async_.event()
        self._shutdown_complete_event = app_state.async_.event()

        # Add an wallet, remove an wallet, or redo all wallet verifications
        self._wallets: set[Wallet] = set()

        self.aiohttp_session = ClientSession(loop=app_state.async_.loop)
        self.connected_header_server_states: dict[ServerAccountKey, HeaderServerState] = {}

        self._new_server_queue: asyncio.Queue[ServerAccountKey] = asyncio.Queue()
        # The usable set of API servers both globally known by the application and also
        # per-wallet/account servers from each wallet database.
        self._known_header_server_keys = set[ServerAccountKey]()
        self._chosen_servers: set[ServerAccountKey] = set()
        self._server_connectivity_metadata: dict[ServerAccountKey, ServerConnectivityMetadata] = {}

        self._main_loop_context: MainLoopContext | None = MainLoopContext()
        self._main_loop_future = app_state.async_.spawn(
            self._main_loop_async(self._main_loop_context))

    def get_local_height(self) -> int:
        assert app_state.headers is not None
        chain = cast(Chain, app_state.headers.longest_chain())
        # This can be called from network_dialog.py when there is no chain
        return cast(int, chain.height) if chain else 0

    async def _find_any_common_header_async(self, server_state: HeaderServerState,
            server_tip: Header) -> Header:
        """This steps back through the chain in an exponentially growing interval until it finds a
        common header. This does not return the precise, common parent, it merely returns any header
        that is common to both chains to act as a base for connecting the headers along the server's
        fork.

        If two ESV Reference Servers are on the same chain then this function will only
        be called once per distinct chain (see `_synchronise_headers_for_server_tip`)"""
        # start with step = 16 to cut down on network round trips for the first initial header sync
        step = 16
        height_to_test = server_tip.height
        while True:
            raw_header = await get_batched_headers_by_height_async(server_state,
                self.aiohttp_session, from_height=max(height_to_test, 0), count=1)
            try:
                app_state.lookup_header(double_sha256(raw_header))
                common_header = Net._net.COIN.deserialized_header(raw_header, height_to_test)
                return common_header
            except MissingHeader:
                height_to_test -= step
                step = step * 4  # keep doubling the interval until we hit a common header

    async def _synchronise_headers_for_server_tip(self, server_state: HeaderServerState) \
            -> tuple[Header, Chain]:
        """
        Identify the chain tip on the remote server, synchronise to that tip and then return
        to the caller.

        NOTE: requesting batched headers by height works because the headers at these heights are
        on the longest chain **for that instance of the ElectrumSV-Reference-Server**
        (emphasis added). For example there could be two persisting forks but requesting batched
        headers by height on each instance will give the headers leading to their own respective
        tips.

        Raises `ServiceUnavailableError` via _request_and_connect_headers_at_heights_async
        """
        assert app_state.headers is not None
        tip_headers = await get_chain_tips_async(server_state, self.aiohttp_session)
        # This get_chain_tips_async call will be the first http request sent to the server.
        # If successful, now is the time to trigger the `new_server_connection_event`
        self.new_server_connection_event.set()
        self.new_server_connection_event.clear()

        tip_header = filter_tips_for_longest_chain(tip_headers)
        server_state.tip_header = tip_header
        while True:
            try:
                app_state.lookup_header(tip_header.hash)
                break
            except MissingHeader:
                pass

            any_common_base_header = await self._find_any_common_header_async(server_state,
                server_tip=tip_header)
            heights = [height for height in range(any_common_base_header.height,
                tip_header.height + 1)]
            if len(heights) > 2000:
                logger.warning("Synchronizing %s headers. Wallet functionality"
                    "will be temporarily limited until complete", len(heights))
            await self._request_and_connect_headers_at_heights_async(server_state, heights)

        return app_state.lookup_header(tip_header.hash)

    async def _connect_tip_and_maybe_backfill(self, server_state: HeaderServerState,
            new_tip: TipResponse) -> None:
        try:
            app_state.connect_header(new_tip.header_bytes)
        except MissingHeader:
            # The headers store uses the genesis block as the base checkpoint but there is
            # no previous header before the genesis header so when attempting to "connect"
            # the genesis block, it will raise MissingHeader. We can only connect subsequent
            # headers to the genesis block.
            if bitcoinx.double_sha256(new_tip.header_bytes) == hex_str_to_hash(Net._net.GENESIS):
                return None
            # This should only happen if the new_tip notification skips intervening headers e.g.
            # a) There was a reorg
            # b) The longest chain grows instantly by more than one block e.g. on RegTest sometimes
            #    we mine 100 blocks or more in quick secession.
            heights = [height for height in range(
                new_tip.height-MAX_CONCEIVABLE_REORG_DEPTH, new_tip.height + 1)]
            await self._request_and_connect_headers_at_heights_async(server_state, heights)
        else:
            # We don't know that we connected a new header, but the "longest chain" task can
            # work out if it is getting redundant notifications.
            app_state.headers_update_event.set()
            app_state.headers_update_event.clear()

        return None

    async def _monitor_chain_tip_task_async(self, server_key: ServerAccountKey) -> None:
        """
        All chosen servers (up to a limit of 10) will run an independent instance this task.
        Only the main server results in mutated wallet state (e.g. only reorgs on the main server
        will affect wallet state).

        raises `ServiceUnavailableError` via:
            - `main_server._synchronise_headers_for_server_tip` or
            - `main_server.subscribe_to_headers` or
            - `self._connect_tip_and_maybe_backfill`
        """
        assert app_state.headers is not None

        # This server is already obsolete.
        if server_key not in self.connected_header_server_states:
            return

        server_metadata = self._server_connectivity_metadata[server_key]
        server_metadata.last_try = time.time()

        # Will not proceed past this point until we have all the headers up to and including
        # the servers tip header.
        server_state = self.connected_header_server_states[server_key]
        current_tip_header, current_chain = await self._synchronise_headers_for_server_tip(
            server_state)

        logger.info("Setting initial header sync event for header server: %s", server_key.url)
        server_state.initial_sync_completed.set()

        server_state.tip_header = current_tip_header
        server_state.chain = current_chain

        # This server is ready for wallets to rely on for use as an indexing server (should it
        # be indexing server capable).
        server_metadata.last_good = time.time()
        server_metadata.consecutive_failed_attempts = 0

        server_state.connection_event.set()

        self.new_server_ready_event.set()
        self.new_server_ready_event.clear()

        new_tip: TipResponse
        # iterator yields forever
        async for new_tip in subscribe_to_headers_async(server_state, self.aiohttp_session):
            logger.debug("Got new tip: %s for server: %s", new_tip, server_state.server_key.url)

            previous_chain = current_chain
            previous_tip_header = current_tip_header
            await self._connect_tip_and_maybe_backfill(server_state, new_tip)
            current_tip_header, current_chain = app_state.lookup_header(
                double_sha256(new_tip.header_bytes))

            # They should not be relied on by the wallet for determining the validity of it's
            # state. The wallet may still be processing previous header updates. They can however
            # be used to identify what alternate servers are available and whether they are
            # synchronised.
            server_state.tip_header = current_tip_header
            server_state.chain = current_chain

            server_metadata.last_good = time.time()

            for wallet in self._wallets:
                wallet.process_header_source_update(server_state, previous_chain,
                    previous_tip_header, current_chain, current_tip_header)

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

    # def _random_server_nowait(self) -> ServerAccountKey | None:
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
        logger.debug("Queueing wallet header server %s", server_key)
        self._new_server_queue.put_nowait(server_key)

    async def _main_loop_async(self, context: MainLoopContext) -> None:
        """
        Pre-populate the header servers from the hard-coded configuration.
        When new wallets are loaded they will push new, unique servers to the queue
        """
        try:
            # Make sure this has been created.
            for hardcoded_server_config in cast(list[APIServerDefinition], Net.DEFAULT_SERVERS_API):
                server_type: NetworkServerType | None = getattr(NetworkServerType,
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
                assert url.endswith("/"), f"All server urls must have trailing slash '{url}'"

                server_key = ServerAccountKey(url, server_type, None)
                for capability_name in hardcoded_server_config.get("capabilities", []):
                    capability_value = getattr(ServerCapability, capability_name, None)
                    if capability_value is None:
                        logger.error("Server '%s' has invalid capability '%s'", url,
                            capability_name)
                    elif capability_value == ServerCapability.HEADERS:
                        logger.debug("Queuing initial header server %s", server_key)
                        self._new_server_queue.put_nowait(server_key)

            while self._main_loop_context is context:
                server_key = await self._new_server_queue.get()
                # A wallet loading will notify us of header-capable servers we may already know.
                if server_key in self._known_header_server_keys:
                    continue

                logger.debug("Connecting to new server %s", server_key)
                self._known_header_server_keys.add(server_key)
                self._server_connectivity_metadata[server_key] = ServerConnectivityMetadata()

                assert self._connect_to_server_async(context, server_key)
        finally:
            logger.debug("Network maintain connections task exiting.")
            for future in context.futures:
                future.cancel()
            self._shutdown_complete_event.set()

    def get_known_header_servers(self) -> set[ServerAccountKey]:
        # These are servers we have been made aware of. We will at the least have metadata related
        # to them, if not an active connection.
        return self._known_header_server_keys

    def get_header_server_metadata(self, server_key: ServerAccountKey) \
            -> ServerConnectivityMetadata:
        return self._server_connectivity_metadata[server_key]

    def get_header_server_state(self, server_key: ServerAccountKey) -> HeaderServerState:
        return self.connected_header_server_states[server_key]

    def initial_headers_sync_complete(self) -> bool:
        """Connecting a large number of headers is a CPU bound process that degrades the user
        experience. Therefore, it is best to inform the user that the initial
        headers sync is ongoing and block NodeAPI RPC requests until initial sync is complete."""
        # It is assumed that these are reliable services and so will always
        # have a tip that is equal to or exceeding any wallet's `persisted_tip_hash`.
        for server_key, state in self.connected_header_server_states.items():
            if state.initial_sync_completed.is_set():
                return True
        return False

    def is_header_server_ready(self, server_key: ServerAccountKey) -> bool:
        server_state = self.connected_header_server_states.get(server_key)
        return server_state is not None and server_state.connection_event.is_set()

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
            future = app_state.async_.spawn(self._maintain_connection(context, server_key))
            self.connected_header_server_states[server_key] = HeaderServerState(server_key,
                future)
            return True
        return False

    async def _maintain_connection(self, context: MainLoopContext, server_key: ServerAccountKey) \
            -> None:
        try:
            while context is self._main_loop_context:
                try:
                    await self._monitor_chain_tip_task_async(server_key)
                except ServiceUnavailableError:
                    server_metadata = self._server_connectivity_metadata.get(server_key, None)
                    if server_metadata is not None:
                        server_metadata.consecutive_failed_attempts += 1
                        # We only log the unavailability for the first failed attempt.
                        if server_metadata.consecutive_failed_attempts == 1:
                           logger.error("Server unavailable: %s", server_key)
                await asyncio.sleep(20)
        finally:
            self.lost_server_connection_event.set()
            self.lost_server_connection_event.clear()
            del self.connected_header_server_states[server_key]

    #
    # External API
    #

    async def shutdown_wait(self) -> None:
        self._main_loop_context = None
        self._main_loop_future.cancel()
        await self._shutdown_complete_event.wait()
        await self.aiohttp_session.close()
        logger.info("Stopped")

    # def is_server_disabled(self, url: str, server_type: NetworkServerType) -> bool:
    #     """
    #     Whether the given server is configured to be unusable by anything.
    #     """
    #     return self._known_header_server_keys[ServerAccountKey(url, server_type, None)]\
    #           .is_unusable()

    def add_wallet(self, wallet: Wallet) -> None:
        """ This wallet has been loaded and is now using this network. """
        self._wallets.add(wallet)

    def remove_wallet(self, wallet: Wallet) -> None:
        """ This wallet has been unloaded and is no longer using this network. """
        self._wallets.remove(wallet)

    async def _request_and_connect_headers_at_heights_async(self, server_state: HeaderServerState,
            heights: Iterable[int]) -> None:
        """
        Raises `ServiceUnavailableError` in `get_batched_headers_by_height_async`
        """
        assert server_state.synchronisation_data is None

        MAX_HEADER_REQUEST_BATCH_SIZE = 2000
        sorted_heights = sorted(heights)
        while len(sorted_heights) != 0:
            batch_heights = sorted_heights[0:MAX_HEADER_REQUEST_BATCH_SIZE]
            sorted_heights = sorted_heights[MAX_HEADER_REQUEST_BATCH_SIZE:]
            min_height = max(batch_heights[0], 1)  # We don't want the genesis block at height 0
            max_height = batch_heights[-1]
            count = max_height - min_height + 1
            logger.debug("Fetching %s headers from start height: %s", count, min_height)

            server_state.synchronisation_data = min_height, count
            server_state.synchronisation_update_event.set()
            server_state.synchronisation_update_event.clear()

            header_array = await get_batched_headers_by_height_async(server_state,
                self.aiohttp_session, min_height, count)
            stream = BytesIO(header_array)
            count_of_raw_headers = len(header_array) // 80
            logger.debug("Fetched %s headers", count_of_raw_headers)

            logger.debug("Connecting %s headers", count_of_raw_headers)
            for i in range(count_of_raw_headers):
                raw_header = stream.read(80)
                # This will acquire a lock for every call, but unless we see that in profiling
                # we are okay with this.
                app_state.connect_header(raw_header)

            logger.debug("Connected %s headers", count_of_raw_headers)
            app_state.headers_update_event.set()
            app_state.headers_update_event.clear()

        server_state.synchronisation_data = None
        server_state.synchronisation_update_event.set()
        server_state.synchronisation_update_event.clear()

    def status(self) -> NetworkStatusDict:
        return {
            "blockchain_height": self.get_local_height(),
        }
