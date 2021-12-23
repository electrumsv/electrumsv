"""
NOTE(AustEcon) Many of the following types are copied or slightly modified from the
ESVReferenceServer. It might be that at a later date we include a dedicated pypi package
for an ESVReferenceClient and/or use a github submodule in ElectrumSV
(or something along those lines).
"""
from enum import IntFlag
from typing import List, NamedTuple, TypedDict, Dict, Any, Union


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

    def to_websocket_dict(self) -> Dict[str, WebsocketError]:
        return {"error": {"reason": self.reason,
                          "status_code": self.status}}

    @classmethod
    def from_websocket_dict(cls, message: Dict[str, WebsocketError]) -> 'Error':
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


class TipResponse(TypedDict):
    header: HeaderResponse
    state: str
    chainWork: int
    height: int


# ----- Peer Channel Types ----- #
class TokenPermissions(IntFlag):
    NONE            = 0
    READ_ACCESS     = 1 << 1
    WRITE_ACCESS    = 1 << 2


class PeerChannelToken(NamedTuple):
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
GenericJSON = Dict[Any, Any]


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
    access_tokens: List[PeerChannelAPITokenViewModelGet]


class APITokenViewModelGet(TypedDict):
    id: str
    token: str
    description: str
    can_read: bool
    can_write: bool


class MAPICallbackResponse(TypedDict):
    callbackPayload: str
    apiVersion: str
    timestamp: str
    minerId: str
    blockHash: str
    callbackTxId: str
    callbackReason: str


# These are both for json but they represent an
# underlying json vs binary payload
class MessageViewModelGetJSON(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: MAPICallbackResponse  # Later this will be a Union of multiple message types


class MessageViewModelGetBinary(TypedDict):
    sequence: int
    received: str
    content_type: str
    payload: str  # hex


PeerChannelMessage = Union[MessageViewModelGetJSON, MessageViewModelGetBinary]


# ----- General Websocket Types ----- #
class ChannelNotification(TypedDict):
    id: str
    notification: str


class GeneralNotification(TypedDict):
    message_type: str
    result: ChannelNotification  # Later this will be a Union of multiple message types
