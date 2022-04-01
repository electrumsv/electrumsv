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
from asyncio import sleep
from aiohttp import ClientSession
from aiorpcx import (CancelledError, TaskGroup)
import bitcoinx
from bitcoinx import Chain, double_sha256, hex_str_to_hash, Header, Headers, MissingHeader
from collections import defaultdict
from contextlib import suppress
import random
import time
from enum import IntEnum
from io import BytesIO
from typing import Any, cast, Dict, Iterable, List, Optional, \
    TYPE_CHECKING, Set


from .app_state import app_state, attempt_exception_reporting
from .constants import API_SERVER_TYPES, NetworkEventNames, NetworkServerType, ServerCapability
from .exceptions import ServiceUnavailableError
from .logs import logs
from .network_support.api_server import APIServerDefinition, NewServer, \
    SelectionCandidate, select_servers

from .network_support.esv_client import ESVClient
from .network_support.esv_client_types import TipResponse, ServerConnectionState
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


def _root_from_proof(hash: bytes, branch: List[bytes], index: int) -> bytes:
    '''From ElectrumX.'''
    for elt in branch:
        if index & 1:
            hash = double_sha256(elt + hash)
        else:
            hash = double_sha256(hash + elt)
        index >>= 1
    if index:
        raise ValueError(f'index {index} out of range for proof of length {len(branch)}')
    return hash


class Network(TriggeredCallbacks[NetworkEventNames]):
    '''Manages a set of connections to remote ElectrumSV-Reference-Servers. Each loaded Wallet
    instance has a "main server" which only changes if the user manually changes it.

    All operations are asynchronous.
    '''
    _main_task_active = False

    def __init__(self) -> None:
        TriggeredCallbacks.__init__(self)

        app_state.read_headers()

        # The usable set of API servers both globally known by the application and also
        # per-wallet/account servers from each wallet database.
        self._api_servers: Dict[ServerAccountKey, NewServer] = {}

        # Events
        async_ = app_state.async_
        self.stop_network_event = async_.event()
        self.shutdown_complete_event = async_.event()
        self.servers_synced_events: defaultdict[SelectionCandidate, asyncio.Event] = \
            defaultdict(async_.event)

        # Add an wallet, remove an wallet, or redo all wallet verifications
        self._wallets: Set[Wallet] = set()

        self.aiohttp_session: Optional[ClientSession] = None

        self.chosen_servers: set[SelectionCandidate] = set()
        self.connected_headers_servers: dict[SelectionCandidate, ESVClient] = {}
        self.new_server_queue: asyncio.Queue[SelectionCandidate] = asyncio.Queue()
        self.future = async_.spawn(self._main_task_loop)

    async def instantiate_server(self, selection_candidate: SelectionCandidate) \
            -> ESVClient:
        aiohttp_session = self.get_aiohttp_session()
        assert selection_candidate.api_server is not None

        # NOTE: wallet_data is None because this is in the context of the Network class which
        #   does not require wallet state - it is only using the HeaderSV APIs to track headers.
        server_state = ServerConnectionState(
            wallet_data=None,
            session=aiohttp_session,
            server=selection_candidate.api_server,
            credential_id=selection_candidate.api_server.client_api_keys[None],
            peer_channel_message_queue=asyncio.Queue(),
            output_spend_result_queue=asyncio.Queue(),
            output_spend_registration_queue=asyncio.Queue(),
            tip_filter_new_pushdata_event=asyncio.Event())
        return ESVClient(state=server_state)

    def get_aiohttp_session(self) -> ClientSession:
        """Global client session shared globally for any outbound http requests.
        Benefits from connection pooling if the same instance is re-used"""
        if self.aiohttp_session is not None:
            return self.aiohttp_session
        self.aiohttp_session = ClientSession(loop=app_state.async_.loop)
        return self.aiohttp_session

    async def close_aiohttp_session(self) -> None:
        if self.aiohttp_session is not None:
            await self.aiohttp_session.close()

    async def _main_task_loop(self) -> None:
        self._main_task_active = True
        iterations = 0
        try:
            while self._main_task_active:
                if iterations > 0:
                    logger.debug("Restarting main task, attempt %d", iterations)
                await self._main_task()
                iterations += 1
        finally:
            logger.debug("Network main task loop exiting.")
            self.shutdown_complete_event.set()

    async def _main_task(self) -> None:
        group = TaskGroup()
        try:
            async with group:
                await group.spawn(self._start_network, group)
        finally:
            logger.debug("Network main task exiting")
            # NOTE(exception-reporting) We only try reporting the first exception for now, we do
            # not really expect more than one and it might become spammy if there are many.
            # NOTE(network-exit-bug) We have a problem where the network main task exits because
            # presumably an exception happens in a task, or a task is cancelled by something
            # unknown and this is caught by the `TaskGroup` and causes the cancellation of
            # all the tasks in it (and previously the network main task to exit).
            reported_one_exception = False
            for exc_idx, exc in enumerate(group.exceptions):
                if exc is not None:
                    if not isinstance(exc, CancelledError) and not reported_one_exception:
                        reported_one_exception = True
                        attempt_exception_reporting(type(exc), exc, exc.__traceback__)
                    # Do not log `CancelledError` if we are exiting the network as it is normal.
                    if not self._main_task_active and isinstance(exc, CancelledError):
                        continue
                    # Otherwise log it (in addition to exceptions) because this is possibly an
                    # erroneous cancellation and we want to see where they all came from (this
                    # might not even be good enough and the real problem may be in sub-taskgroups.
                    logger.exception("Exception in task %d", exc_idx,
                        exc_info=(type(exc), exc, exc.__traceback__))

    async def _restart_network(self) -> None:
        self.stop_network_event.set()

    async def _start_network(self, group: TaskGroup) -> None:
        while True:
            logger.debug('starting...')
            connections_task = await group.spawn(self._maintain_connections)
            await self.stop_network_event.wait()
            self.stop_network_event.clear()
            with suppress(CancelledError):
                await connections_task

    def get_local_height(self) -> int:
        chain = self.chain()
        # This can be called from network_dialog.py when there is no chain
        return cast(int, chain.height) if chain else 0

    def get_local_tip_hash(self) -> bytes:
        chain = self.chain()
        assert chain is not None
        return cast(bytes, chain.tip.hash)

    async def get_server_tip_async(self, headers_client: ESVClient) -> Header:
        """raises `ServiceUnavailableError`"""
        assert headers_client is not None
        raw_tip = await headers_client.get_chain_tips()
        raw_header = raw_tip[0:80]
        height = bitcoinx.le_bytes_to_int(raw_tip[80:84])
        return Net._net.COIN.deserialized_header(raw_header, height)

    def is_missing_header(self, block_hash: bytes) -> bool:
        """If the mmap headers store is lost/deleted, the orphaned header will be lost with it.
        Therefore, on a wallet restoration, the orphaned header will be missing. The fallback
        is to rescan all transaction history for the new longest chain."""
        try:
            _header, _old_chain = cast(Headers, app_state.headers).lookup(block_hash)
            return False
        except MissingHeader:
            return True

    async def find_any_common_header(self, headers_client: ESVClient, server_tip: Header) -> Header:
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
            raw_header = await headers_client.get_batched_headers_by_height(
                from_height=max(height_to_test, 0), count=1)
            try:
                self.header_for_hash(double_sha256(raw_header))
                common_header = Net._net.COIN.deserialized_header(raw_header, height_to_test)
                return common_header
            except MissingHeader:
                height_to_test -= step
                step = step * 4  # keep doubling the interval until we hit a common header

    async def _synchronize_initial_headers_async(self, headers_client: ESVClient) \
            -> tuple[Header, Chain]:
        """
        NOTE: requesting batched headers by height works because the headers at these heights are
        on the longest chain **for that instance of the ElectrumSV-Reference-Server**
        (emphasis added). For example there could be two persisting forks but requesting batched
        headers by height on each instance will give the headers leading to their own respective
        tips.

        raises `ServiceUnavailableError` via _request_and_connect_headers_at_heights
        """
        tip_obj: Header = await self.get_server_tip_async(headers_client)
        while self.is_missing_header(tip_obj.hash):
            any_common_base_header = await self.find_any_common_header(headers_client,
                server_tip=tip_obj)
            heights = [height for height in range(any_common_base_header.height,
                tip_obj.height + 1)]
            await self._request_and_connect_headers_at_heights(heights, headers_client)

        server_tip = tip_obj
        header, server_chain = cast(Headers, app_state.headers).lookup(server_tip.hash)
        return server_tip, server_chain

    async def _connect_tip_and_maybe_backfill(self, new_tip: TipResponse,
            headers_client: ESVClient) -> None:
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
            await self._request_and_connect_headers_at_heights(heights, headers_client)

        return None

    async def _monitor_chain_tip_task_async(self, selection_candidate: SelectionCandidate) \
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
        assert selection_candidate.api_server is not None
        headers_client = await self.instantiate_server(selection_candidate)
        self.connected_headers_servers[selection_candidate] = headers_client

        # Will not proceed past this point until initial headers sync completes
        server_tip, server_chain = \
            await self._synchronize_initial_headers_async(headers_client)
        headers_client.update_tip_and_chain(server_tip, server_chain)
        for wallet in self._wallets:
            if wallet.main_server is not None and \
                    wallet.main_server._state.server.url == \
                    headers_client._state.server.url:
                wallet.update_main_server_tip_and_chain(headers_client.tip, headers_client.chain)

        self.servers_synced_events[selection_candidate].set()

        server_state = selection_candidate.api_server \
            .api_key_state[selection_candidate.credential_id]
        server_state.last_try = time.time()

        new_tip: TipResponse
        assert headers_client is not None
        async for new_tip in headers_client.subscribe_to_headers():  # iterator yields forever
            logger.debug("Got new tip: %s for server: %s", new_tip,
                selection_candidate.api_server.url)

            server_chain_before = server_chain
            await self._connect_tip_and_maybe_backfill(new_tip, headers_client)
            header, server_chain = cast(Headers, app_state.headers)\
                .lookup(double_sha256(new_tip.header))
            headers_client.update_tip_and_chain(header, server_chain)

            for wallet in self._wallets:
                if wallet.main_server is not None and \
                        wallet.main_server._state.server.url == \
                        headers_client._state.server.url:
                    await wallet.reorg_check_main_chain(server_chain_before, server_chain)
                    wallet.update_main_server_tip_and_chain(headers_client.tip,
                        headers_client.chain)

    def _api_servers_to_selection_candidates(self) -> Set[SelectionCandidate]:
        selection_candidates = set()
        for server in self._api_servers.values():
            has_credential, credential_id = server.get_credential_id(None)
            assert has_credential
            selection_candidates.add(SelectionCandidate(server.server_type,
                credential_id, server))
        return selection_candidates

    def _available_servers(self) -> List[SelectionCandidate]:
        now = time.time()
        selection_candidates = self._api_servers_to_selection_candidates()
        unchosen = selection_candidates - self.chosen_servers
        servers: List[SelectionCandidate] = []
        for server in unchosen:
            assert server.api_server is not None
            if server.api_server.api_key_state[server.credential_id].can_retry(now):
                servers.append(server)
        return servers

    def _random_server_nowait(self) -> Optional[SelectionCandidate]:
        servers = self._available_servers()
        selection_candidate = random.choice(servers) if servers else None
        # NOTE: Need to add to self.chosen_servers set here because doing it after an
        # `await _random_server()` opens the possibility for duplicate selections
        if selection_candidate:
            self.chosen_servers.add(selection_candidate)
        return selection_candidate

    async def _random_server(self, retry_timeout: int=10) -> SelectionCandidate:
        while True:
            server = self._random_server_nowait()
            if server:
                return server
            await sleep(retry_timeout)

    async def _maintain_connections(self) -> None:
        """When new wallets are loaded they will push new, unique servers to the queue"""
        while True:
            selection_candidate = await self.new_server_queue.get()
            assert selection_candidate.api_server is not None
            key = ServerAccountKey(selection_candidate.api_server.url,
                selection_candidate.server_type, None)
            self._api_servers[key] = selection_candidate.api_server
            if selection_candidate not in self.chosen_servers:
                self.chosen_servers.add(selection_candidate)
                asyncio.create_task(self._maintain_connection(selection_candidate))

    async def _maintain_connection(self, selection_candidate: SelectionCandidate) -> None:
        while True:
            try:
                await self._monitor_chain_tip_task_async(selection_candidate)
            except ServiceUnavailableError as e:
                # assert selection_candidate.api_server is not None
                # logger.debug(f"Server unavailable: %s", selection_candidate.api_server.url)
                pass
            finally:
                self.chosen_servers.remove(selection_candidate)
            await asyncio.sleep(20)
            selection_candidate = await self._random_server()

    #
    # External API
    #

    async def shutdown_wait(self) -> None:
        self._main_task_active = False
        self.future.cancel()
        await self.shutdown_complete_event.wait()
        logger.warning('stopped')

    def is_connected(self) -> bool:
        return all([wallet.main_server is not None for wallet in self._wallets])

    def get_api_servers(self) -> Dict[ServerAccountKey, NewServer]:
        # These are all the available API servers registered within the application.
        return self._api_servers

    # def is_server_disabled(self, url: str, server_type: NetworkServerType) -> bool:
    #     """
    #     Whether the given server is configured to be unusable by anything.
    #     """
    #     return self._api_servers[ServerAccountKey(url, server_type, None)].is_unusable()

    def add_wallet(self, wallet: "Wallet") -> None:
        """ This wallet has been loaded and is now using this network. """
        self._wallets.add(wallet)

    def remove_wallet(self, wallet: "Wallet") -> None:
        """ This wallet has been unloaded and is no longer using this network. """
        self._wallets.remove(wallet)

    def chain(self) -> Chain:
        return cast(Headers, app_state.headers).longest_chain()

    async def _request_and_connect_headers_at_heights(self, heights: Iterable[int],
            headers_client: ESVClient) -> None:
        """raises `ServiceUnavailableError` - via `headers_client.get_batched_headers_by_height`"""
        MAX_HEADER_REQUEST_BATCH_SIZE = 2000
        sorted_heights = sorted(heights)
        while len(sorted_heights) != 0:
            batch_heights = sorted_heights[0:MAX_HEADER_REQUEST_BATCH_SIZE]
            sorted_heights = sorted_heights[MAX_HEADER_REQUEST_BATCH_SIZE:]
            min_height = max(batch_heights[0], 1)  # We don't want the genesis block at height 0
            max_height = batch_heights[-1]
            assert headers_client is not None
            count = max_height - min_height + 1
            logger.debug("Fetching %s headers from start height: %s", count, min_height)
            header_array = await headers_client.get_batched_headers_by_height(min_height, count)
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

    def status(self) -> Dict[str, Any]:
        return {
            # 'server': str(self.main_server.base_url),
            'blockchain_height': self.get_local_height(),
            # 'server_height': self.main_server.tip.height,
            'spv_nodes': len(self._api_servers),
            'connected': self.is_connected(),
            'auto_connect': self.auto_connect(),
        }
