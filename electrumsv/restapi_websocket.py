from __future__ import annotations
import dataclasses
from typing import Literal, TYPE_CHECKING
from typing_extensions import NotRequired, TypedDict
import uuid

import aiohttp
from aiohttp import web, web_ws
from bitcoinx import hash_to_hex_str, Header

from .logs import logs
from .restapi import get_wallet_from_request

if TYPE_CHECKING:
    from .standards.tsc_merkle_proof import TSCMerkleProof

logger = logs.get_logger("restapi-endpoints")


BroadcastEventNames = Literal["incoming-payment-expired", "incoming-payment-received",
    "outgoing-payment-delivered", "transaction-mined", "transaction-double-spent" ]
IncomingPaymentJSONStates = Literal["unpaid", "paid", "expired", "archived"]
OutgoingPaymentJSONStates = Literal["delivered", "expired"]

# @RESTAPIStyle: It is assumed that most programmers receiving JSON get their objects with
#      camel case naming, e.g. `lowerUpper`. For this reason we follow this style in our REST
#      API.

# See @RESTAPIStyle note elsewhere.
class IncomingPaymentEventDict(TypedDict):
    incomingPaymentId: int
    state: IncomingPaymentJSONStates
    transactionIds: NotRequired[list[str]]

class OutgoingPaymentEventDict(TypedDict):
    outgoingPaymentId: int
    state: OutgoingPaymentJSONStates

class TransactionMinedEventDict(TypedDict):
    transactionId: str
    blockHeight: int
    blockId: str
    eventSource: Literal["MAPI"]
    eventPayload: str

class TransactionDoubleSpentEventDict(TypedDict):
    transactionId: str
    otherTransactionId: int
    eventSource: Literal["MAPI"]
    eventPayload: str

OutgoingEventTypes = IncomingPaymentEventDict | OutgoingPaymentEventDict | \
    TransactionMinedEventDict | TransactionDoubleSpentEventDict


# See @RESTAPIStyle note elsewhere.
class WebsocketEventDict(TypedDict):
    messageType: BroadcastEventNames
    payload: OutgoingEventTypes


@dataclasses.dataclass
class LocalWebsocketState:
    websocket_id: str
    websocket: web_ws.WebSocketResponse
    accept_type: str


class LocalWebSocket(web.View):
    """
    Each connected client receives account-related notifications on this websocket.

    Protocol versioning is based on the endpoint discovery apiVersion field.
    Requires a master bearer token as this authorizes for notifications from any peer channel
    """

    _logger = logs.get_logger("rest-websocket")

    async def get(self) -> web_ws.WebSocketResponse:
        """The communication for this is one-way for outgoing notifications."""
        # We have to check for the credentials in the query string as javascript clients appear
        # to be broken and do not support `Authorization` headers for web sockets. All other
        # languages can.
        access_token = self.request.query.get('token', None)
        if access_token is None:
            self._logger.warning("Failed connection to wallet '%s' websocket (no access token)",
                self.request.match_info["wallet"])
            raise web.HTTPUnauthorized(reason="No access key")

        wallet = get_wallet_from_request(self.request)
        if wallet is None:
            self._logger.warning("Failed connection to wallet '%s' websocket (wallet not loaded)",
                self.request.match_info["wallet"])
            raise web.HTTPUnauthorized(reason="Invalid access key")

        if access_token != wallet.restapi_websocket_access_token:
            self._logger.warning("Failed connection to wallet '%s' websocket (wrong access token)",
                self.request.match_info["wallet"])
            raise web.HTTPUnauthorized(reason="Invalid access key")

        websocket_id = str(uuid.uuid4())
        accept_type = self.request.headers.get('Accept', 'application/json')
        if accept_type == "*/*":
            accept_type = 'application/json'
        if accept_type != 'application/json':
            raise web.HTTPBadRequest(reason="'application/json' support is required")

        websocket = web.WebSocketResponse()
        await websocket.prepare(self.request)

        websocket_state = LocalWebsocketState(
            websocket_id=websocket_id,
            websocket=websocket,
            accept_type=accept_type)
        if not wallet.setup_restapi_connection(websocket_state):
            raise web.HTTPServiceUnavailable()

        self._logger.debug("Websocket connected, host=%s, accept_type=%s, websocket_id=%s",
            self.request.host, accept_type, websocket_state.websocket_id)
        try:
            await self._websocket_message_loop(websocket_state)
        finally:
            if not websocket.closed:
                await websocket.close()
            self._logger.debug("Websocket disconnecting, websocket_id=%s", websocket_id)
            wallet.teardown_restapi_connection(websocket_id)

        return websocket

    async def _websocket_message_loop(self, websocket_state: LocalWebsocketState) -> None:
        # Loop until the connection is closed. This is a broken usage of the `for` loop by
        # aiohttp, where the number of iterations is not bounded.
        async for message in websocket_state.websocket:
            if message.type in (aiohttp.WSMsgType.text, aiohttp.WSMsgType.binary):
                # We do not accept incoming messages. To ignore them would be to encourage badly
                # implemented clients, is the theory.
                await websocket_state.websocket.close()

            elif message.type == aiohttp.WSMsgType.error:
                self._logger.error("Websocket error, websocket_id=%s", websocket_state.websocket_id,
                    exc_info=websocket_state.websocket.exception())


async def close_restapi_connection_async(websocket_state: LocalWebsocketState) -> None:
    try:
        await websocket_state.websocket.close()
    except Exception:
        logger.exception("Unexpected exception closing REST API websocket")


async def broadcast_restapi_event_async(websocket_state: LocalWebsocketState,
        event_type: BroadcastEventNames,
            paid_request_hashes: list[tuple[int, list[bytes]]] | None,
            invoice_id: int | None, transaction_hash: bytes | None,
            header: Header | None, tsc_proof: TSCMerkleProof | None) -> None:
    payloads: list[OutgoingEventTypes] = []
    if event_type == "incoming-payment-received":
        assert paid_request_hashes is not None
        for paymentrequest_id, transaction_hashes in paid_request_hashes:
            payload1: IncomingPaymentEventDict = {
                "incomingPaymentId": paymentrequest_id,
                "state": "paid",
            }
            assert transaction_hashes is not None and len(transaction_hashes) > 0
            payload1["transactionIds"] = [ hash_to_hex_str(transaction_hash) for transaction_hash
                in transaction_hashes ]
            payloads.append(payload1)
    elif event_type == "outgoing-payment-delivered":
        assert invoice_id is not None
        payload2: OutgoingPaymentEventDict = {
            "outgoingPaymentId": invoice_id,
            "state": "delivered",
        }
        payloads = [ payload2 ]
    elif event_type == "transaction-mined":
        assert transaction_hash is not None
        assert header is not None
        assert tsc_proof is not None

        payload3: TransactionMinedEventDict = {
            "transactionId": hash_to_hex_str(transaction_hash),
            "blockHeight": 1,
            "blockId": hash_to_hex_str(header.hash),
            "eventSource": "MAPI",
            "eventPayload": tsc_proof.to_bytes().hex(),
        }
        payloads = [ payload3 ]
    else:
        raise NotImplementedError(f"Support for event type {event_type} not implemented")

    for event_payload in payloads:
        event_data: WebsocketEventDict = {
            "messageType": event_type,
            "payload": event_payload,
        }
        try:
            await websocket_state.websocket.send_json(event_data)
        except ConnectionResetError:
            # Raised in aiohttp.WebSocketWriter: Ignore writes to closing connections.
            pass
