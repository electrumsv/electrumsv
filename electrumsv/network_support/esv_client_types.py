"""
NOTE(AustEcon) Many of the following types are copied or slightly modified from the
ESVReferenceServer. It might be that at a later date we include a dedicated pypi package
for an ESVReferenceClient and/or use a github submodule in ElectrumSV
(or something along those lines).
"""
from __future__ import annotations
import asyncio
import concurrent.futures
import dataclasses
import enum
import logging
import struct
from enum import IntFlag
from typing import Any, Callable, NamedTuple, Optional, Sequence, TYPE_CHECKING, TypedDict, Union

import aiohttp
import bitcoinx

from ..bitcoin import TSCMerkleProof
from ..constants import ServerCapability, ServerConnectionFlag
from ..types import IndefiniteCredentialId, Outpoint, OutputSpend

if TYPE_CHECKING:
    from ..wallet import Wallet, WalletDataAccess
    from ..wallet_database.types import ServerPeerChannelRow

    from .api_server import NewServer
    from .esv_client import PeerChannel


# ----- ESVReferenceServer Error types ----- #

class WebsocketUnauthorizedException(Exception):
    pass


class WebsocketError(TypedDict):
    reason: str
    status_code: int


class Error(Exception):

    def __init__(self, reason: str, status: int):
        self.reason = reason
        self.status = status

    def to_websocket_dict(self) -> dict[str, WebsocketError]:
        return {"error": {"reason": self.reason,
                          "status_code": self.status}}

    @classmethod
    def from_websocket_dict(cls, message: dict[str, WebsocketError]) -> 'Error':
        reason = message["error"]["reason"]
        status = message["error"]["status_code"]
        return cls(reason, status)

    def __str__(self) -> str:
        return f"Error(reason={self.reason}, status={self.status})"

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
    header: bytes
    height: int


# ----- Peer Channel Types ----- #
class TokenPermissions(IntFlag):
    NONE            = 0
    READ_ACCESS     = 1 << 1
    WRITE_ACCESS    = 1 << 2


class PeerChannelToken(NamedTuple):
    remote_token_id: int
    permissions: TokenPermissions
    api_key: str


# Todo - we may need to persist a mapping of channel_id -> PeerChannelType
#  Otherwise we cannot know how to parse the received messages.
#  E.g. We need to know that a MAPICallbackResponse type json structure will be received
#  in advance to know how to parse and process it.
class PeerChannelType(IntFlag):
    NONE            = 0
    MERCHANT_API    = 1 << 1
    BACKUP          = 1 << 2


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


class MAPICallbackResponse(TypedDict):
    callbackPayload: str
    apiVersion: str
    timestamp: str
    minerId: str
    blockHash: str
    blockHeight: int
    callbackTxId: str
    callbackReason: str


# These are both for json but they represent an
# underlying json vs binary payload
class MessageViewModelGetJSON(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: MAPICallbackResponse  # Later this will be a Union of multiple message types


class GenericPeerChannelMessage(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: Any


class TipFilterPushDataMatchesData(TypedDict):
    blockId: Optional[str]
    matches: list[TipFilterPushDataMatch]


class TipFilterPushDataMatch(TypedDict):
    pushDataHashHex: str
    transactionId: str
    transactionIndex: int
    flags: int


class MessageViewModelGetBinary(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: str  # hex


# TODO(1.4.0) Peer channels. Get rid of this. Use `GenericPeerChannelMessage`
PeerChannelMessage = Union[MessageViewModelGetJSON, MessageViewModelGetBinary]


# ----- General Websocket Types ----- #
class ChannelNotification(TypedDict):
    id: str
    notification: str


class ServerWebsocketNotification(TypedDict):
    message_type: str
    result: ChannelNotification  # Later this will be a Union of multiple message types


def le_int_to_char(le_int: int) -> bytes:
    return struct.pack('<I', le_int)[0:1]


class TxOrId(enum.IntEnum):
    TRANSACTION_ID = 0
    FULL_TRANSACTION = 1 << 0


class TargetType(enum.IntEnum):
    HASH = 0
    HEADER = 1 << 1
    MERKLE_ROOT = 1 << 2


class ProofType(enum.IntEnum):
    MERKLE_BRANCH = 0
    MERKLE_TREE = 1 << 3


class CompositeProof(enum.IntEnum):
    SINGLE_PROOF = 0
    COMPOSITE_PROOF = 1 << 4


class TSCMerkleProofJson(TypedDict):
    index: int
    txOrId: str  # hex
    targetType: Optional[str]
    target: str  # hex
    nodes: list[str]


def tsc_merkle_proof_json_to_binary(tsc_json: TSCMerkleProofJson, target_type: str) \
        -> TSCMerkleProof:
    """{'index': 0, 'txOrId': txOrId, 'target': target, 'nodes': []}"""
    response = bytearray()

    flags = 0
    include_full_tx = (len(tsc_json['txOrId']) > 32)
    if include_full_tx:
        flags = flags | TxOrId.FULL_TRANSACTION

    if target_type == 'hash':
        flags = flags | TargetType.HASH
    elif target_type == 'header':
        flags = flags | TargetType.HEADER
    elif target_type == 'merkleroot':
        flags = flags | TargetType.MERKLE_ROOT
    else:
        raise NotImplementedError("Caller should have ensured `target_type` is valid.")

    flags = flags | ProofType.MERKLE_BRANCH  # ProofType.MERKLE_TREE not supported
    flags = flags | CompositeProof.SINGLE_PROOF  # CompositeProof.COMPOSITE_PROOF not supported

    response += le_int_to_char(flags)
    response += bitcoinx.pack_varint(tsc_json['index'])

    if include_full_tx:
        txLength = len(tsc_json['txOrId']) // 2
        response += bitcoinx.pack_varint(txLength)
        response += bytes.fromhex(tsc_json['txOrId'])
    else:
        response += bitcoinx.hex_str_to_hash(tsc_json['txOrId'])

    if target_type in {'hash', 'merkleroot'}:
        response += bitcoinx.hex_str_to_hash(tsc_json['target'])
    else:  # header
        response += bytes.fromhex(tsc_json['target'])

    nodeCount = bitcoinx.pack_varint(len(tsc_json['nodes']))
    response += nodeCount
    for node in tsc_json['nodes']:
        if node == "*":
            duplicate_type_node = b'\x01'
            response += duplicate_type_node
        else:
            hash_type_node = b"\x00"
            response += hash_type_node
            response += bitcoinx.hex_str_to_hash(node)
    return TSCMerkleProof.from_bytes(response)


class AccountMessageKind(enum.IntEnum):
    PEER_CHANNEL_MESSAGE = 1
    SPENT_OUTPUT_EVENT = 2


class TipFilterRegistrationJobEntry(NamedTuple):
    pushdata_hash: bytes
    duration_seconds: int
    keyinstance_id: int


@dataclasses.dataclass
class TipFilterRegistrationJob:
    entries: list[TipFilterRegistrationJobEntry]

    # Input: If there is a contextual logger associated with this job it should be set here.
    logger: Optional[logging.Logger] = None
    # Input: If there is a payment request associated with this job this will be the id.
    paymentrequest_id: Optional[int] = None
    # Input: If there is a refresh callback associated with this job. This is not called the
    #    registration process, but if necessary by user logic that has a reference to the job.
    refresh_callback: Optional[Callable[[], None]] = None
    # Input: If there is a completion callback associated with this job. This is not called the
    #    registration process, but if necessary by user logic that has a reference to the job.
    completion_callback: Optional[Callable[[], None]] = None

    # Output: This will be set when the processing of this job starts.
    start_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    # Output: This will be set when the processing of this job ends successfully or by error.
    completed_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    # Output: If the registration succeeds this will be the UTC date the request expires.
    date_registered: Optional[int] = None
    # Output: If the registration errors this will be a description to explain why to the user.
    failure_reason: Optional[str] = None


class TipFilterRegistrationResponse(TypedDict):
    dateCreated: str


class IndexerServerSettings(TypedDict):
    tipFilterCallbackUrl: Optional[str]
    tipFilterCallbackToken: Optional[str]


@dataclasses.dataclass
class ServerConnectionState:
    petty_cash_account_id: int
    utilised_capabilities: set[ServerCapability]
    wallet_proxy: Optional[Wallet]
    wallet_data: Optional[WalletDataAccess]
    session: aiohttp.ClientSession
    server: NewServer

    credential_id: Optional[IndefiniteCredentialId] = None
    cached_peer_channels: Optional[dict[str, PeerChannel]] = None
    cached_peer_channel_rows: Optional[dict[str, ServerPeerChannelRow]] = None

    # Incoming peer channel message notifications from the server.
    indexer_settings: Optional[IndexerServerSettings] = None
    # Server consuming: Post outpoints here to get them registered with the server.
    output_spend_registration_queue: asyncio.Queue[Sequence[Outpoint]] = dataclasses.field(
        default_factory=asyncio.Queue[Sequence[Outpoint]])
    # Server consuming: Incoming peer channel message notifications from the server.
    peer_channel_message_queue: asyncio.Queue[str] = dataclasses.field(
        default_factory=asyncio.Queue[str])
    # Server consuming: Set this if there are new pushdata hashes that need to be monitored.
    tip_filter_new_registration_queue: asyncio.Queue[TipFilterRegistrationJob] = \
        dataclasses.field(default_factory=asyncio.Queue[TipFilterRegistrationJob])

    # Wallet consuming: Post MAPI callback responses here to get them registered with the server.
    mapi_callback_response_queue: asyncio.Queue[MAPICallbackResponse] = dataclasses.field(
        default_factory=asyncio.Queue[MAPICallbackResponse])
    # Wallet consuming: Incoming spend notifications from the server.
    output_spend_result_queue: asyncio.Queue[Sequence[OutputSpend]] = dataclasses.field(
        default_factory=asyncio.Queue[Sequence[OutputSpend]])
    # Wallet consuming: Post tip filter matches here to get them registered with the server.
    tip_filter_new_matches_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)

    # The stage of the connection process it has last reached.
    connection_flags: ServerConnectionFlag = ServerConnectionFlag.INITIALISED
    stage_change_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    # Set this if there is a problem with the connection worthy of abandoning it.
    connection_exit_event: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)

    wallet_futures: list[concurrent.futures.Future[None]] = dataclasses.field(
        default_factory=list[concurrent.futures.Future[None]])

    def clear_for_reconnection(self, clear_flags: ServerConnectionFlag=ServerConnectionFlag.NONE) \
            -> None:
        # TODO(1.4.0) Servers. We should consider what can be cleared and the repercussions of
        #     doing so.
        self.connection_flags = clear_flags | ServerConnectionFlag.INITIALISED
        self.stage_change_event.set()
        self.stage_change_event.clear()

        self.cached_peer_channels = None
        self.cached_peer_channel_rows = None
        self.indexer_settings = None
        # When we establish a new websocket we will register all the outstanding output spend
        # registrations that we need, so whatever is left in the queue at this point is redundant.
        while not self.output_spend_registration_queue.empty():
            self.output_spend_registration_queue.get_nowait()
        while not self.peer_channel_message_queue.empty():
            self.peer_channel_message_queue.get_nowait()


class VerifiableKeyData(TypedDict):
    public_key_hex: str
    signature_hex: str
    message_hex: str
