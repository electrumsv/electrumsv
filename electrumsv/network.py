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
import datetime
from concurrent.futures.thread import ThreadPoolExecutor
from io import BytesIO
from typing import Any, cast, Dict, Iterable, List, Optional, Set, TYPE_CHECKING
from aiohttp import ClientSession
from aiorpcx import (RPCError, CancelledError, TaskGroup)
from bitcoinx import Chain, double_sha256, hash_to_hex_str, Header, Headers, MissingHeader
from .app_state import app_state, attempt_exception_reporting
from .constants import API_SERVER_TYPES, NetworkServerType, PendingHeaderWorkKind, ServerCapability
from .exceptions import ServiceUnavailableError
from .i18n import _
from .logs import logs

from .network_support.api_server import APIServerDefinition, NewServer, NewServerAPIContext, \
    SelectionCandidate, select_servers
from .network_support.esv_client import chain_tip_to_header_obj, ESVClient, REGTEST_MASTER_TOKEN
from .network_support.esv_client_types import TipResponse
from .networks import Net
from .subscription import SubscriptionManager
from .types import NetworkServerState, ServerAccountKey
from .util import TriggeredCallbacks
from .util.misc import fmt_hashes_to_hex_str

if TYPE_CHECKING:
    from .wallet import AbstractAccount, Wallet


logger = logs.get_logger("network")

HEADER_SIZE = 80
ONE_MINUTE = 60
ONE_DAY = 24 * 3600
BROADCAST_TX_MSG_LIST = (
    ('dust', _('very small "dust" payments')),
    (('Missing inputs', 'Inputs unavailable', 'bad-txns-inputs-spent'),
     _('missing, already-spent, or otherwise invalid coins')),
    ('insufficient priority', _('insufficient fees or priority')),
    ('bad-txns-premature-spend-of-coinbase', _('attempt to spend an unmatured coinbase')),
    (('txn-already-in-mempool', 'txn-already-known'),
     _("it already exists in the server's mempool")),
    ('txn-mempool-conflict', _("it conflicts with one already in the server's mempool")),
    ('bad-txns-nonstandard-inputs', _('use of non-standard input scripts')),
    ('absurdly-high-fee', _('fee is absurdly high')),
    ('non-mandatory-script-verify-flag', _('the script fails verification')),
    ('tx-size', _('transaction is too large')),
    ('scriptsig-size', _('it contains an oversized script')),
    ('scriptpubkey', _('it contains a non-standard signature')),
    ('bare-multisig', _('it contains a bare multisig input')),
    ('multi-op-return', _('it contains more than 1 OP_RETURN input')),
    ('scriptsig-not-pushonly', _('a scriptsig is not simply data')),
    ('bad-txns-nonfinal', _("transaction is not final"))
)


# TODO(1.4.0) Change RPCError for processing a mAPI broadcast failure error message instead
def broadcast_failure_reason(exception: Exception) -> str:
    if isinstance(exception, RPCError):
        msg = exception.message
        for in_msgs, out_msg in BROADCAST_TX_MSG_LIST:
            if isinstance(in_msgs, str):
                in_msgs = (in_msgs, )
            if any(in_msg in msg for in_msg in in_msgs):
                return out_msg
    return _('reason unknown')


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


class Network(TriggeredCallbacks):
    '''Manages a set of connections to remote ElectrumX servers.  All operations are
    asynchronous.
    '''
    _main_task_active = False

    def __init__(self) -> None:
        TriggeredCallbacks.__init__(self)

        app_state.read_headers()

        self.subscriptions = SubscriptionManager()

        # The usable set of API servers both globally known by the application and also
        # per-wallet/account servers from each wallet database.
        self._api_servers: Dict[ServerAccountKey, NewServer] = {}
        # Track the application API servers from the config and add them to the usable set.
        self._api_servers_config: Dict[NetworkServerType, List[APIServerDefinition]] = {
            server_type: [] for server_type in API_SERVER_TYPES
        }
        self._read_config_api_server_mapi()
        self._read_config_api_server()

        # Events
        async_ = app_state.async_
        self.sessions_changed_event = async_.event()
        self.check_main_chain_event = async_.event()
        self.stop_network_event = async_.event()
        self.shutdown_complete_event = async_.event()

        # Add an wallet, remove an wallet, or redo all wallet verifications
        self._wallets: Set[Wallet] = set()
        self._executor = ThreadPoolExecutor(max_workers=1)

        self.future = async_.spawn(self._main_task_loop)

        self.aiohttp_session: Optional[ClientSession] = None
        self.esv_client: Optional[ESVClient] = None
        self.esv_client_cached_tip: Optional[Header] = None

    # TODO(1.4.0) If a server disconnects or misbehaves we should add it to a temporary ban list
    #  with a timeout so the selection algorithm will select other servers instead
    async def get_esv_headers_client(self) -> Optional[ESVClient]:
        """caches a single dedicated headers client"""
        if self.esv_client is None:
            selection_candidates = self.get_api_servers_for_headers()

            # TODO(1.4.0) Uncomment this extra filtering step when the ESV Ref Server is proxying
            #  merkle proof requests to the indexer

            # There was a discussion in which we decided to remove a lot of client side
            # complexity by keeping the headers state in perfect sync with the indexer's
            # materialized view. Therefore we filter for the ESV-Reference-Servers that have
            # an indexing API. This might change in future.
            # selection_candidates = select_servers(
            #     ServerCapability.MERKLE_PROOF_REQUEST, selection_candidates)

            if len(selection_candidates) == 0:
                return None

            # TODO Prioritise properly. Probably on the basis on the server chain tip among other
            #  things such as fee rate or user preference.
            selection_candidate = selection_candidates[0]
            aiohttp_session = await self.get_aiohttp_session()
            assert selection_candidate.api_server is not None
            self.esv_client = ESVClient(base_url=selection_candidate.api_server.url,
                session=aiohttp_session, master_token=REGTEST_MASTER_TOKEN)
        return self.esv_client

    async def get_aiohttp_session(self) -> ClientSession:
        """Global client session shared globally for any outbound http requests.
        Benefits from connection pooling if the same instance is re-used"""
        if self.aiohttp_session is not None:
            return self.aiohttp_session
        self.aiohttp_session = ClientSession()
        return self.aiohttp_session

    async def close_aiohttp_session(self) -> None:
        if self.aiohttp_session is not None:
            await self.aiohttp_session.close()

    def _read_config_api_server(self) -> None:
        api_servers = cast(List[APIServerDefinition], app_state.config.get("api_servers", []))
        if api_servers:
            logger.info("read %d api servers from config file", len(api_servers))

        servers_by_uri = { api_server['url']: api_server for api_server in api_servers }
        for api_server in Net.DEFAULT_SERVERS_API:
            server = servers_by_uri.get(api_server['url'], None)
            if server is None:
                server = cast(APIServerDefinition, api_server.copy())
                server["modified_date"] = server["static_data_date"]
                api_servers.append(server)
            self._migrate_config_entry(server)

        # Register the API server for visibility and maybe even usage. We pass in the reference
        # to the config entry dictionary, which will be saved via `_api_servers_config`.
        for api_server in api_servers:
            server_type = cast(Optional[NetworkServerType],
                getattr(NetworkServerType, api_server["type"]))
            if server_type is None:
                logger.error("skipping api server '%s' missing server 'type'", api_server["url"])
                continue
            server_key = ServerAccountKey(api_server["url"], server_type)
            self._api_servers[server_key] = self._create_config_api_server(server_key, api_server)
            # This is the collection of application level servers and it is primarily used to group
            # them for persistence.
            self._api_servers_config[server_type].append(api_server)

    def _read_config_api_server_mapi(self) -> None:
        mapi_servers = cast(List[APIServerDefinition], app_state.config.get("mapi_servers", []))
        if mapi_servers:
            logger.info("read %d merchant api servers from config file", len(mapi_servers))

        servers_by_uri = { mapi_server['url']: mapi_server for mapi_server in mapi_servers }
        for mapi_server in Net.DEFAULT_SERVERS_MAPI:
            server = servers_by_uri.get(mapi_server['url'], None)
            if server is None:
                server = cast(APIServerDefinition, mapi_server.copy())
                server["modified_date"] = server["static_data_date"]
                mapi_servers.append(server)
            self._migrate_config_entry(server)

        # Register the MAPI server for visibility and maybe even usage. We pass in the reference
        # to the config entry dictionary, which will be saved via `_api_servers_config`.
        for mapi_server in mapi_servers:
            server_key = ServerAccountKey(mapi_server["url"], NetworkServerType.MERCHANT_API)
            self._api_servers[server_key] = self._create_config_api_server(server_key, mapi_server)

        # This is the collection of application level servers and it is primarily used to group
        # them for persistence.
        self._api_servers_config[NetworkServerType.MERCHANT_API] = mapi_servers

    def _migrate_config_entry(self, server: APIServerDefinition) -> None:
        ## Ensure all the default field values are present if they are not already.
        server.setdefault("api_key", "")
        # Whether the API key is supported for the given server from entry presence.
        server.setdefault("api_key_supported", "api_key_required" in server)
        # All the default MAPI servers are enabled for all wallets out of the box.
        server.setdefault("enabled_for_all_wallets", True)
        # When we were last able to connect, and when we last tried to connect.
        server.setdefault("last_good", 0.0)
        server.setdefault("last_try", 0.0)
        # If we request an anonymous fee quote for this server, keep the last one.
        # server.setdefault("anonymous_fee_quote", None)

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
            app_state.config.set_key('mapi_servers', self.get_config_mapi_servers(), True)

    async def _main_task(self) -> None:
        group = TaskGroup()
        try:
            async with group:
                await group.spawn(self._start_network, group)
                await group.spawn(self._monitor_chain_tip_task)
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
            await self.stop_network_event.wait()
            self.stop_network_event.clear()

    def get_local_height(self) -> int:
        chain = self.chain()
        # This can be called from network_dialog.py when there is no chain
        return cast(int, chain.height) if chain else 0

    def get_local_tip_hash(self) -> bytes:
        chain = self.chain()
        assert chain is not None
        return cast(bytes, chain.tip.hash)

    async def get_esv_server_tip_height(self) -> int:
        """raises `ServiceUnavailableError`"""
        if self.esv_client_cached_tip:
            return cast(int, self.esv_client_cached_tip.height)

        assert self.esv_client is not None
        tip = await self.esv_client.get_chain_tips(longest_chain_only=True)
        self.esv_client_cached_tip = chain_tip_to_header_obj(tip)
        logger.debug(f"Fetched chain tip: {self.esv_client_cached_tip}")
        assert self.esv_client_cached_tip is not None
        return cast(int, self.esv_client_cached_tip.height)


    def get_esv_server_tip_hash(self) -> Optional[bytes]:
        if not self.esv_client_cached_tip:
            return None
        assert self.esv_client_cached_tip is not None
        return cast(bytes, self.esv_client_cached_tip.hash)

    # TODO(post-1.4.0) Need a sound system for banning and selecting a better provider
    async def _initial_headers_sync(self) -> None:
        while True:
            try:
                while self.get_local_height() < await self.get_esv_server_tip_height():
                    missing_heights = [height for height in range(
                        self.get_local_height(), await self.get_esv_server_tip_height() + 1)]
                    await self._fetch_missing_headers_at_heights(missing_heights)

                assert self.esv_client_cached_tip is not None
                if self.get_local_tip_hash() != self.get_esv_server_tip_hash():
                    # Wallet can still operate like this so log error and return from function
                    # TODO(1.4.0) Switch to alternative service providers
                    logger.error("The Headers API tip is either lagging our previously "
                        "stored tip or is an equal height fork. Local tip height: %s, "
                        "Server tip height: %s", self.get_local_height(),
                        self.esv_client_cached_tip.height)
                return None
            except ServiceUnavailableError:
                logger.info("Headers API service is currently unavailable, retrying in 10 seconds")
                await asyncio.sleep(10)

    # TODO: periodically check that selected / prioritised server is still the best
    #  candidate and switch if needed. This ideally should be as simple as polling
    #  get_esv_headers_client() which handles the selection and prioritisation algorithm.
    #  For now, we stick to the same server until it disconnects or misbehaves.
    async def _monitor_chain_tip_task(self) -> None:
        WAIT_TIME = 10
        while True:
            try:
                # Must always clear cached values when switching to a new server
                self.esv_client = None
                self.esv_client_cached_tip = None
                esv_client = await self.get_esv_headers_client()
                if not esv_client:
                    logger.debug("There are no suitable ESV Reference Servers available. "
                                 "Re-checking in %s seconds", WAIT_TIME)
                    await asyncio.sleep(WAIT_TIME)
                    continue

                # Will not proceed past this point until initial headers sync completes
                await self._initial_headers_sync()

                new_tip: TipResponse
                async for new_tip in esv_client.subscribe_to_headers():
                    logger.debug("Got new tip: %s", new_tip)
                    await self._on_new_chain_tip(new_tip)

            # TODO(1.4.0) Add the server to a ban list with a timeout
            except ServiceUnavailableError as e:
                pass

    def notify_wallets_new_tip(self, new_tip: Header, new_chain: Chain) -> None:
        # Some merkle proofs can arrive before the corresponding header. Therefore we need to
        # notify the 'late headers' background worker of any new headers.
        logger.info("Notifying wallets of the new tip hash: %s, height: %s",
            hash_to_hex_str(new_tip.hash), new_tip.height)
        for wallet in self._wallets:
            message = (new_tip, new_chain)
            wallet._late_header_worker_queue.put_nowait((PendingHeaderWorkKind.NEW_HEADER, message))

    async def notify_wallets_reorg(self, orphaned_block_hashes: List[bytes]) -> None:
        logger.info("Notifying wallets of the the reorg")
        loop = asyncio.get_running_loop()
        tasks = [loop.run_in_executor(self._executor, wallet.on_reorg, orphaned_block_hashes)
            for wallet in self._wallets]
        await asyncio.gather(*tasks, return_exceptions=False)  # raises any exceptions

    async def _on_new_chain_tip(self, new_tip: TipResponse) -> None:
        assert app_state.headers is not None
        old_chain: Chain = self.chain()
        await self.force_connect_header(new_tip.header, new_tip.height)
        self.esv_client_cached_tip = new_tip
        new_chain: Chain = self.chain()

        if old_chain != new_chain:
            _chain, common_parent_height = old_chain.common_chain_and_height(new_chain)
            orphaned_block_hashes = [app_state.headers.header_at_height(old_chain, h).hash
                for h in range(common_parent_height + 1, old_chain.tip.height)]
            new_block_hashes = [app_state.headers.header_at_height(new_chain, h).hash for h in
                range(common_parent_height + 1, new_chain.tip.height)]

            logger.info("Reorg detected; undoing wallet verifications for block hashes %s",
                fmt_hashes_to_hex_str(orphaned_block_hashes))

            await self.notify_wallets_reorg(orphaned_block_hashes)
        else:
            new_block_hashes = [app_state.headers.header_at_height(new_chain, h).hash for h in
                range(old_chain.tip.height + 1, new_chain.tip.height)]

        # New tip notifications from HeaderSV can skip multiple headers
        # We need to ensure we notify all wallets of each and every new tip so any backlogged
        # merkle proofs get the required headers for processing.
        for block_hash in new_block_hashes:
            new_tip_header: Header = self.header_for_hash(block_hash)
            self.notify_wallets_new_tip(new_tip_header, new_chain)

        self.trigger_callback('updated')
        # NOTE(AustEcon) What listens for the 'main_chain' event? dapps?
        self.trigger_callback('main_chain', old_chain, new_chain)

    #
    # External API
    #

    async def shutdown_wait(self) -> None:
        self._main_task_active = False
        self.future.cancel()
        await self.shutdown_complete_event.wait()
        self.subscriptions.stop()
        logger.warning('stopped')

    def is_connected(self) -> bool:
        return self.esv_client is not None

    def get_config_mapi_servers(self) -> List[APIServerDefinition]:
        """
        Update the mapi server config entries and return them.

        This will pull in the live server state.
        """
        for config in self._api_servers_config[NetworkServerType.MERCHANT_API]:
            server_key = ServerAccountKey(config["url"], NetworkServerType.MERCHANT_API)
            server = self._api_servers[server_key]
            key_state = server.api_key_state[server.config_credential_id]
            config["last_good"] = key_state.last_good
            config["last_try"] = key_state.last_try
            if server.config_credential_id is None:
                config["anonymous_fee_quote"] = key_state.last_fee_quote_response
            else:
                config["anonymous_fee_quote"] = None
        return self._api_servers_config[NetworkServerType.MERCHANT_API]

    def create_config_api_server(self, server_type: NetworkServerType,
            server_data: APIServerDefinition) -> None:
        """
        Register a new application-level API server entry.

        This will set up the standard default fields, so it is not necessary for any caller to
        provide a 100% complete entry.
        """
        server_url = server_data["url"]
        assert server_url not in [ d["url"] for d in self._api_servers_config[server_type] ]
        if server_type == NetworkServerType.MERCHANT_API:
            self._migrate_config_entry(server_data)
        self._api_servers_config[server_type].append(server_data)

        server_key = ServerAccountKey(server_url, server_type)
        if server_key in self._api_servers:
            return
        self._api_servers[server_key] = self._create_config_api_server(server_key)

    def update_config_api_server(self, server_url: str, server_type: NetworkServerType,
            update_data: APIServerDefinition) -> None:
        """
        Update fields in an existing application-level API server entry.

        This just overwrites existing fields and can only be used for limited updates.
        """
        update_data["modified_date"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for config in self._api_servers_config[server_type]:
            if config["url"] == server_url:
                server_key = ServerAccountKey(server_url, server_type)
                server = self._api_servers[server_key]
                server.on_pending_config_change(update_data)
                # NOTE(typing) This appears to be a mypy bug, where it considers the type of
                #   config to be some raw instance of `TypedDict` and not `APIServerDefinition`.
                config.update(update_data) # type: ignore
                break
        else:
            self.create_config_api_server(server_type, update_data)

    def delete_config_api_server(self, server_url: str, server_type: NetworkServerType) -> None:
        for config_index, config in enumerate(self._api_servers_config[server_type]):
            if config["url"] == server_url:
                del self._api_servers_config[server_type][config_index]
                del self._api_servers[ServerAccountKey(server_url, server_type)]
                break
        else:
            raise KeyError(f"Server '{server_url}' does not exist")

    def get_api_servers(self) -> Dict[ServerAccountKey, NewServer]:
        # These are all the available API servers registered within the application.
        return self._api_servers

    def get_api_servers_for_headers(self) -> List[SelectionCandidate]:
        selection_candidates: List[SelectionCandidate] = []
        for api_server in self.get_api_servers().values():
            selection_candidates.append(
                SelectionCandidate(server_type=api_server.server_type, credential_id=None,
                    api_server=api_server))

        header_capable_servers = select_servers(ServerCapability.HEADERS,
            selection_candidates)
        return header_capable_servers

    def get_api_servers_for_account(self, account: "AbstractAccount",
            server_type: NetworkServerType) -> List[SelectionCandidate]:
        wallet = account.get_wallet()
        client_key = NewServerAPIContext(wallet.get_storage_path(), account.get_id())

        results: List[SelectionCandidate] = []
        for api_server in self._api_servers.values():
            if api_server.server_type == server_type:
                have_credential, credential_id = api_server.get_credential_id(client_key)
                # TODO(API) What about putting the client api context in the result.
                if have_credential:
                    results.append(SelectionCandidate(server_type, credential_id, api_server))
        return results

    def is_server_disabled(self, url: str, server_type: NetworkServerType) -> bool:
        """
        Whether the given server is configured to be unusable by anything.
        """
        return self._api_servers[ServerAccountKey(url, server_type)].is_unusable()

    def _create_config_api_server(self, server_key: ServerAccountKey,
            config: Optional[APIServerDefinition]=None, allow_no_config: bool=False) -> NewServer:
        if config is None:
            # The config entry should exist except when an external wallet database is brought
            # to this installation and loaded, with unknown servers in it.
            for iter_config in self._api_servers_config[server_key.server_type]:
                if iter_config["url"] == server_key.url:
                    config = iter_config
                    break
            else:
                if not allow_no_config:
                    raise KeyError(f"Server config not found {server_key.url}")
        return NewServer(server_key.url, server_key.server_type, config)

    def _register_api_servers_for_wallet(self, wallet: "Wallet") -> None:
        """ For a newly loaded wallet, set up it's API server usage. This will """
        rows = wallet.read_network_servers_with_credentials()

        wallet_path = wallet.get_storage_path()
        for row in rows:
            if row.key.server_type not in API_SERVER_TYPES:
                continue
            # If the server does not exist already it is not one known globally to the application.
            server_key = row.key.to_server_key()
            if server_key not in self._api_servers:
                self._api_servers[server_key] = self._create_config_api_server(server_key,
                    allow_no_config=True)
            server = self._api_servers[server_key]
            server.set_wallet_usage(wallet_path, row)

    def _unregister_all_api_servers_for_wallet(self, wallet: "Wallet") -> List[NetworkServerState]:
        """ Unregister a specific wallet from all API servers. We do this when a wallet has been
            unloaded. """
        wallet_path = wallet.get_storage_path()
        updated_states: List[NetworkServerState] = []
        for server_key, server in list(self._api_servers.items()):
            updated_states.extend(server.unregister_wallet(wallet_path))
            # TODO(rt12) Why are we deleting unused servers from this data structure?
            if server.is_unused():
                del self._api_servers[server_key]
        return updated_states

    def update_api_servers_for_wallet(self,
            wallet: "Wallet", added_keys: List[NetworkServerState],
            updated_keys: List[NetworkServerState], deleted_keys: List[ServerAccountKey]) -> None:
        """
        This is called by the wallet to update the wallet usage of added, updated or removed
        api servers
        """
        wallet_path = wallet.get_storage_path()
        # We know updated servers will not have changed their type or url, so we do not need
        # to do anything with the accounts at this point. But we do need to have observed the flags
        # of servers for enabling/disabling.
        for row in added_keys + updated_keys:
            server = self._api_servers[row.key.to_server_key()]
            server.set_wallet_usage(wallet_path, row)

        for specific_server_key in deleted_keys:
            server = self._api_servers[specific_server_key.to_server_key()]
            server.remove_wallet_usage(wallet_path, specific_server_key)

    def add_wallet(self, wallet: "Wallet") -> None:
        """ This wallet has been loaded and is now using this network. """
        self._wallets.add(wallet)
        self._register_api_servers_for_wallet(wallet)

    def remove_wallet(self, wallet: "Wallet") -> List[NetworkServerState]:
        """ This wallet has been unloaded and is no longer using this network. """
        self._wallets.remove(wallet)
        updated_states = self._unregister_all_api_servers_for_wallet(wallet)
        return updated_states

    def chain(self) -> Optional[Chain]:
        return cast(Headers, app_state.headers).longest_chain()

    async def force_connect_header(self, raw_header: bytes, height: int) -> None:
        try:
            assert app_state.headers is not None
            app_state.headers.connect(raw_header)
        except MissingHeader:
            await self._fetch_missing_headers_at_heights([height])

    async def _fetch_missing_headers_at_heights(self, heights: Iterable[int]) -> Dict[int, Header]:
        MAX_HEADER_REQUEST_BATCH_SIZE = 2000
        MAX_CONCEIVABLE_REORG_DEPTH = 100  # If deeper than this it will recurse until resolved
        sorted_heights = sorted(heights)

        result: Dict[int, Header] = {}
        while len(sorted_heights) != 0:
            batch_heights = sorted_heights[0:MAX_HEADER_REQUEST_BATCH_SIZE]
            sorted_heights = sorted_heights[MAX_HEADER_REQUEST_BATCH_SIZE:]
            min_height = batch_heights[0]
            max_height = batch_heights[-1]
            esv_client = await self.get_esv_headers_client()
            assert esv_client is not None
            count = max_height - min_height + 1
            logger.debug(f"Fetching headers %s from %s", count, min_height)
            header_array = await esv_client.get_headers_by_height(min_height, count)
            stream = BytesIO(header_array)
            for height in batch_heights:
                raw_header = stream.read(80)
                try:
                    cast(Headers, app_state.headers).connect(raw_header)
                except MissingHeader:
                    # NOTE(AustEcon) Recurse back until it reaches our local cache's
                    # common parent header and successfully connects
                    logger.error("Cannot connect missing header. Backfilling %s headers deep",
                        MAX_CONCEIVABLE_REORG_DEPTH)
                    from_height = max(height - MAX_CONCEIVABLE_REORG_DEPTH, 1)

                    to_height = height + 1  # And include the currently missing header

                    await self._fetch_missing_headers_at_heights(
                        [height for height in range(from_height, to_height)])

                assert app_state.headers is not None
                header = app_state.headers.lookup(double_sha256(raw_header))
                result[height] = header
        return result

    def header_at_height(self, height: int) -> Header:
        _header_at_height = cast(Headers, app_state.headers).header_at_height
        return _header_at_height(self.chain(), height)

    def header_for_hash(self, block_hash: bytes) -> Header:
        header, _chains = cast(Headers, app_state.headers).lookup(block_hash)
        return header

    async def headers_at_heights(self, heights: Iterable[int]) -> Dict[int, Header]:
        """This is the top-level API for getting headers and should be used preferentially.
        It checks the local cache first but will 'fail over' to fetching and back-filling any
        missing ones."""
        result = {}
        missing = []
        for height in set(heights):
            try:
                result[height] = self.header_at_height(height)
            except MissingHeader:
                missing.append(height)
        if missing:
            await self._fetch_missing_headers_at_heights(missing)
            for height in missing:
                result[height] = self.header_at_height(height)
        return result

    # TODO(1.4.0) This is no longer actually used in any meaningful way at present -> delete or use
    def auto_connect(self) -> bool:
        return app_state.config.get_explicit_type(bool, 'auto_connect', True)

    def status(self) -> Dict[str, Any]:
        assert self.esv_client is not None
        server_height = 0
        if self.esv_client_cached_tip is not None:
            server_height = self.esv_client_cached_tip.height
        return {
            'server': str(self.esv_client.base_url),
            'blockchain_height': self.get_local_height(),
            'server_height': server_height,
            # 'spv_nodes': len(self.sessions),
            'connected': self.is_connected(),
            'auto_connect': self.auto_connect(),
        }
