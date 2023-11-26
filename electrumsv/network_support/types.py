"""
NOTE(AustEcon) Many of the following types are copied or slightly modified from the
ESVReferenceServer. It might be that at a later date we include a dedicated pypi package
for an ESVReferenceClient and/or use a github submodule in ElectrumSV
(or something along those lines).
"""
from __future__ import annotations
import aiohttp
from aiohttp import ClientWebSocketResponse
import asyncio
import concurrent.futures
import dataclasses
import enum
from typing import Any, NamedTuple, Protocol, Sequence, TYPE_CHECKING, TypedDict

from ..constants import NetworkServerFlag, ScriptType, ServerConnectionFlag, TokenPermissions
from ..types import IndefiniteCredentialId, Outpoint, OutputSpend
from ..wallet_database.types import DPPMessageRow, ExternalPeerChannelRow, ChannelMessageRow
from .constants import ServerProblemKind

if TYPE_CHECKING:
    from ..wallet import Wallet, WalletDataAccess

    from .api_server import NewServer


# ----- HeaderSV types ----- #
class HeaderResponse(TypedDict):
    hash: str
    version: int
    prevBlockHash: str
    merkleRoot: str
    creationTimestamp: int
    difficultyTarget: int
    nonce: int
    transactionCount: int
    work: int


class TipResponse(NamedTuple):
    header_bytes: bytes
    height: int


# ----- Peer Channel Types ----- #

class PeerChannelToken(NamedTuple):
    remote_token_id: int
    permissions: TokenPermissions
    api_key: str


ChannelId = str
GenericJSON = dict[Any, Any]


# ViewModel refers to json response structures
class RetentionViewModel(TypedDict):
    min_age_days: int
    max_age_days: int
    auto_prune: bool


class PeerChannelAPITokenViewModelGet(TypedDict):
    id: int
    token: str
    description: str
    can_read: bool
    can_write: bool


class PeerChannelViewModelGet(TypedDict):
    id: str
    href: str
    public_read: bool
    public_write: bool
    sequenced: bool
    locked: bool
    head_sequence: int
    retention: RetentionViewModel
    access_tokens: list[PeerChannelAPITokenViewModelGet]


class GenericPeerChannelMessage(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: Any


class TipFilterPushDataMatchesData(TypedDict):
    blockId: str|None
    matches: list[TipFilterPushDataMatch]


class TipFilterPushDataMatch(TypedDict):
    pushDataHashHex: str
    transactionId: str
    transactionIndex: int
    flags: int


class PeerChannelBinaryMessage(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: str  # hex


# ----- General Websocket Types ----- #
class ChannelNotification(TypedDict):
    sequence: int
    received: str
    content_type: str
    channel_id: str


class ServerWebsocketNotification(TypedDict):
    message_type: str
    result: ChannelNotification  # Later this will be a Union of multiple message types


class AccountMessageKind(enum.IntEnum):
    PEER_CHANNEL_MESSAGE = 1
    SPENT_OUTPUT_EVENT = 2


class TipFilterRegistrationJobEntry(NamedTuple):
    pushdata_hash: bytes
    duration_seconds: int
    keyinstance_id: int
    script_type: ScriptType


@dataclasses.dataclass
class TipFilterRegistrationJobOutput:
    # Output: This will be set when the processing of this job starts.
    start_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    # Output: This will be set when the processing of this job ends successfully or by error.
    completed_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    # Output: If the registration succeeds this will be the UTC date the request expires.
    date_registered: int | None = None
    # Output: If the registration errors this will be a description to explain why to the user.
    failure_reason: str | None = None


@dataclasses.dataclass
class TipFilterRegistrationJob:
    entries: list[TipFilterRegistrationJobEntry]
    output: TipFilterRegistrationJobOutput


class TipFilterRegistrationResponse(TypedDict):
    dateCreated: str


class IndexerServerSettings(TypedDict):
    tipFilterCallbackUrl: str|None
    tipFilterCallbackToken: str|None


ServerConnectionProblem = tuple[ServerProblemKind, str]
ServerConnectionProblems = dict[ServerProblemKind, list[str]]

@dataclasses.dataclass
class BitcacheProducerState:
    account_id: int
    event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    future: concurrent.futures.Future[None]|None = None


class ServerStateProtocol(Protocol):
    wallet_proxy: Wallet|None
    wallet_data: WalletDataAccess|None
    session: aiohttp.ClientSession
    credential_id: IndefiniteCredentialId|None

    # This should only be used to send problems that occur that should result in the connection
    # being closed and the user informed.
    disconnection_event_queue: asyncio.Queue[tuple[ServerProblemKind, str]]

    # The stage of the connection process it has last reached.
    connection_flags: ServerConnectionFlag
    stage_change_event: asyncio.Event

    # Wallet individual futures (all servers).
    connection_future: concurrent.futures.Future[ServerConnectionProblems]|None

    # Server consuming: Incoming peer channel message notifications from the server.
    peer_channel_message_queue: asyncio.Queue[ChannelNotification]

    # Wallet consuming: Post tip filter matches here to get them registered with the server.
    tip_filter_matches_queue: \
        asyncio.Queue[list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]]
    # Wallet consuming: Post direct connection matches here to get them registered with the server.
    direct_connection_matches_queue: \
        asyncio.Queue[list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]]
    # Wallet consuming: Post bitcache matches here to get them registered with the server.
    bitcache_matches_queue: \
        asyncio.Queue[list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]]

    # Server websocket-related futures.
    websocket_futures: list[concurrent.futures.Future[None]]

    def clear_for_reconnection(self, clear_flags: ServerConnectionFlag=ServerConnectionFlag.NONE) \
            -> None: ...

    @property
    def is_external(self) -> bool: ...
    @property
    def server_url(self) -> str: ...


@dataclasses.dataclass
class PeerChannelServerState(ServerStateProtocol):
    wallet_proxy: Wallet|None
    wallet_data: WalletDataAccess|None
    session: aiohttp.ClientSession
    credential_id: IndefiniteCredentialId|None

    external_channel_row: ExternalPeerChannelRow

    # This should only be used to send problems that occur that should result in the connection
    # being closed and the user informed.
    disconnection_event_queue: asyncio.Queue[tuple[ServerProblemKind, str]] = dataclasses.field(
        default_factory=asyncio.Queue[tuple[ServerProblemKind, str]])

    # The stage of the connection process it has last reached.
    connection_flags: ServerConnectionFlag = ServerConnectionFlag.INITIALISED
    stage_change_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)

    # Wallet individual futures (all servers).
    connection_future: concurrent.futures.Future[ServerConnectionProblems]|None = None

    # Server consuming: Incoming peer channel message notifications from the server.
    peer_channel_message_queue: asyncio.Queue[ChannelNotification] = dataclasses.field(
        default_factory=asyncio.Queue[ChannelNotification])

    # Wallet consuming: Post tip filter matches here to get them registered with the server.
    tip_filter_matches_queue: \
        asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]] = \
        dataclasses.field(default_factory=asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]])
    # Wallet consuming: Post direct connection matches here to get them registered with the server.
    direct_connection_matches_queue: \
        asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]] = \
        dataclasses.field(default_factory=asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]])
    # Wallet consuming: Post bitcache matches here to get them registered with the server.
    bitcache_matches_queue: \
        asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]] = \
        dataclasses.field(default_factory=asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]])

    # Server websocket-related futures.
    websocket_futures: list[concurrent.futures.Future[None]] = dataclasses.field(
        default_factory=list[concurrent.futures.Future[None]])

    def clear_for_reconnection(self, clear_flags: ServerConnectionFlag=ServerConnectionFlag.NONE) \
            -> None:
        self.connection_flags = clear_flags | ServerConnectionFlag.INITIALISED
        self.stage_change_event.set()
        self.stage_change_event.clear()

        # When we establish a new websocket we will register all the outstanding output spend
        # registrations that we need, so whatever is left in the queue at this point is redundant.
        while not self.disconnection_event_queue.empty():
            self.disconnection_event_queue.get_nowait()

    @property
    def is_external(self) -> bool: return True
    @property
    def server_url(self) -> str:
        assert self.external_channel_row.remote_url is not None
        return self.external_channel_row.remote_url


@dataclasses.dataclass
class ServerConnectionState(ServerStateProtocol):
    petty_cash_account_id: int
    usage_flags: NetworkServerFlag
    wallet_proxy: Wallet | None
    wallet_data: WalletDataAccess | None
    session: aiohttp.ClientSession
    server: NewServer

    credential_id: IndefiniteCredentialId | None = None

    # This should only be used to send problems that occur that should result in the connection
    # being closed and the user informed.
    disconnection_event_queue: asyncio.Queue[tuple[ServerProblemKind, str]] = dataclasses.field(
        default_factory=asyncio.Queue[tuple[ServerProblemKind, str]])

    # Incoming peer channel message notifications from the server.
    indexer_settings: IndexerServerSettings | None = None
    # Server consuming: Post outpoints here to get them registered with the server.
    output_spend_registration_queue: asyncio.Queue[Sequence[Outpoint]] = dataclasses.field(
        default_factory=asyncio.Queue[Sequence[Outpoint]])
    # Server consuming: Incoming peer channel message notifications from the server.
    peer_channel_message_queue: asyncio.Queue[ChannelNotification] = dataclasses.field(
        default_factory=asyncio.Queue[ChannelNotification])
    # Server consuming: Set this if there are new pushdata hashes that need to be monitored.
    tip_filter_new_registration_queue: asyncio.Queue[TipFilterRegistrationJob] = \
        dataclasses.field(default_factory=asyncio.Queue[TipFilterRegistrationJob])

    # Wallet consuming: Incoming spend notifications from the server.
    output_spend_result_queue: asyncio.Queue[Sequence[OutputSpend]] = dataclasses.field(
        default_factory=asyncio.Queue[Sequence[OutputSpend]])
    # Wallet consuming: Post tip filter matches here to get them registered with the server.
    tip_filter_matches_queue: \
        asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]] = \
        dataclasses.field(default_factory=asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]])
    # Wallet consuming: Post direct connection matches here to get them registered with the server.
    direct_connection_matches_queue: \
        asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]] = \
        dataclasses.field(default_factory=asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]])
    # Wallet consuming: Post bitcache matches here to get them registered with the server.
    bitcache_matches_queue: \
        asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]] = \
        dataclasses.field(default_factory=asyncio.Queue[
            list[tuple[ChannelMessageRow, GenericPeerChannelMessage]]])
    # Wallet consuming: Direct payment protocol-related messages from the DPP server
    dpp_messages_queue: asyncio.Queue[DPPMessageRow] = dataclasses.field(
        default_factory=asyncio.Queue[DPPMessageRow])
    # dpp_invoice ID -> open websocket. If websocket is None, it means the ws:// is closed
    dpp_websockets: dict[str, ClientWebSocketResponse] = dataclasses.field(
        default_factory=dict[str, ClientWebSocketResponse])
    dpp_websocket_connection_events: dict[str, asyncio.Event] = dataclasses.field(
        default_factory=dict[str, asyncio.Event])

    # The stage of the connection process it has last reached.
    connection_flags: ServerConnectionFlag = ServerConnectionFlag.INITIALISED
    stage_change_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    upgrade_lock: asyncio.Lock = dataclasses.field(default_factory=asyncio.Lock)

    # Wallet individual futures (all servers).
    stage_change_pipeline_future: concurrent.futures.Future[None]|None = None
    connection_future: concurrent.futures.Future[ServerConnectionProblems]|None = None

    # Wallet individual futures (servers used for blockchain services only).
    output_spends_consumer_future: concurrent.futures.Future[None]|None = None
    tip_filter_consumer_future: concurrent.futures.Future[None]|None = None
    contact_message_consumer_future: concurrent.futures.Future[None] | None = None
    bitcache_consumer_future: concurrent.futures.Future[None] | None = None
    bitcache_producer_states: dict[int,BitcacheProducerState] = dataclasses.field(
        default_factory=dict[int,BitcacheProducerState])
    # For each DPP Proxy server there is a manager task to create ws:// connections and
    # a corresponding consumer task associated with the `Wallet` instance (which uses a shared
    # queue)
    manage_dpp_connections_future: concurrent.futures.Future[None]|None = None
    dpp_consumer_future: concurrent.futures.Future[None]|None = None

    # Server websocket-related futures.
    websocket_futures: list[concurrent.futures.Future[None]] = dataclasses.field(
        default_factory=list[concurrent.futures.Future[None]])

    @property
    def is_external(self) -> bool: return False
    @property
    def server_url(self) -> str: return self.server.url

    @property
    def used_with_reference_server_api(self) -> bool:
        return self.usage_flags & NetworkServerFlag.MASK_UTILISATION != 0

    def clear_for_reconnection(self, clear_flags: ServerConnectionFlag=ServerConnectionFlag.NONE) \
            -> None:
        self.connection_flags = clear_flags | ServerConnectionFlag.INITIALISED
        self.stage_change_event.set()
        self.stage_change_event.clear()

        self.indexer_settings = None

        # When we establish a new websocket we will register all the outstanding output spend
        # registrations that we need, so whatever is left in the queue at this point is redundant.
        while not self.output_spend_registration_queue.empty():
            self.output_spend_registration_queue.get_nowait()
        while not self.peer_channel_message_queue.empty():
            self.peer_channel_message_queue.get_nowait()
        while not self.disconnection_event_queue.empty():
            self.disconnection_event_queue.get_nowait()


class VerifiableKeyData(TypedDict):
    public_key_hex: str
    signature_hex: str
    message_hex: str

class AccountRegisteredDict(TypedDict):
    public_key_hex: str
    api_key: str

