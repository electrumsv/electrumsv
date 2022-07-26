import json
from typing import Any, cast

import aiohttp
from aiohttp import WSServerHandshakeError
from electrumsv_database.sqlite import DatabaseContext

from .types import ServerConnectionState
from ..app_state import app_state
from ..constants import PaymentFlag
from ..logs import logs
from ..wallet_database.types import DPPMessageRow, PaymentRequestReadRow
from ..wallet_database.util import from_isoformat
from ..wallet_database import functions as db_functions

logger = logs.get_logger("dpp-proxy")

MSG_TYPE_JOIN_SUCCESS = "join.success"
MSG_TYPE_PAYMENT = "payment"
MSG_TYPE_PAYMENT_ACK = "payment.ack"
MSG_TYPE_PAYMENT_ERR = "payment.error"
MSG_TYPE_PAYMENT_REQUEST_CREATE = "paymentrequest.create"
MSG_TYPE_PAYMENT_REQUEST_RESPONSE = "paymentrequest.response"
MSG_TYPE_PAYMENT_REQUEST_ERROR = "paymentrequest.error"

ALL_MSG_TYPES = {MSG_TYPE_JOIN_SUCCESS, MSG_TYPE_PAYMENT, MSG_TYPE_PAYMENT_ACK, MSG_TYPE_PAYMENT_ERR,
    MSG_TYPE_PAYMENT_REQUEST_CREATE, MSG_TYPE_PAYMENT_REQUEST_RESPONSE,
    MSG_TYPE_PAYMENT_REQUEST_ERROR}
DPP_MESSAGE_SEQUENCE = [MSG_TYPE_JOIN_SUCCESS, MSG_TYPE_PAYMENT_REQUEST_CREATE,
    MSG_TYPE_PAYMENT_REQUEST_RESPONSE, MSG_TYPE_PAYMENT, MSG_TYPE_PAYMENT_ACK]


def _is_later_dpp_message_sequence(prior: DPPMessageRow, later: DPPMessageRow) -> bool:
    """Depends upon ascending ordering of these state machine flags when compared as an
    integer"""
    index_prior = DPP_MESSAGE_SEQUENCE.index(prior.type)
    index_later = DPP_MESSAGE_SEQUENCE.index(later.type)
    return index_later > index_prior


class DPPPayeeError(Exception):
    pass

class DPPPayerError(Exception):
    pass


def dpp_msg_type_to_state_flag(msg_type: str) -> PaymentFlag:
    assert msg_type not in {MSG_TYPE_PAYMENT_ERR, MSG_TYPE_PAYMENT_REQUEST_ERROR}, \
        "Caller must check for DPP error states"

    # ----- Payee states ----- #
    if msg_type == MSG_TYPE_PAYMENT_REQUEST_CREATE:
        return PaymentFlag.PAYMENT_REQUEST_REQUESTED

    if msg_type == MSG_TYPE_PAYMENT:
        return PaymentFlag.PAYMENT_RECEIVED

    # ----- Payer states ----- #
    if msg_type == MSG_TYPE_PAYMENT_REQUEST_RESPONSE:
        return PaymentFlag.PAYMENT_REQUEST_RECEIVED

    if msg_type == MSG_TYPE_PAYMENT_ACK:
        return PaymentFlag.PAID


def _validate_dpp_message_json(dpp_message_json: dict[Any, Any]) -> bool:
    """Generic checking of structure - doesn't check the body of the message - that check is
    done elsewhere"""
    assert isinstance(dpp_message_json["correlationId"], str)
    assert isinstance(dpp_message_json["appId"], str)
    assert isinstance(dpp_message_json["clientID"], str)
    assert isinstance(dpp_message_json["userId"], str)
    assert dpp_message_json["expiration"] is None or \
           isinstance(dpp_message_json["expiration"], str)
    if dpp_message_json["body"] is not None:
        assert isinstance(dpp_message_json["body"], dict), f"body={dpp_message_json['body']}"
    else:
        dpp_message_json["body"] = {}
    assert isinstance(dpp_message_json["messageId"], str)
    assert isinstance(dpp_message_json["channelId"], str)
    assert isinstance(dpp_message_json["timestamp"], str)
    assert isinstance(dpp_message_json["type"], str)
    assert dpp_message_json["type"] in ALL_MSG_TYPES, \
        f"Unexpected dpp websocket message type={dpp_message_json['type']}"
    assert isinstance(dpp_message_json["headers"], dict)


async def create_dpp_ws_connection_task_async(state: ServerConnectionState,
        payment_request_row: PaymentRequestReadRow, db_context: DatabaseContext):
    """One async task per ws:// connection - each invoice ID has its own ws:// connection.

    The Wallet in wallet.py can communicate with the open websocket as follows:
    - ServerConnectionState.dpp_websocket is used for sending messages
    - ServerConnectionState.dpp_messages_queue is used for received messages
    """
    try:
        headers = {"Accept": "application/json"}
        BASE_URL = state.server.url.replace("http", "ws")
        logger.debug(f"Opening DPP websocket for payment request: {payment_request_row}")
        websocket_url = f"{BASE_URL.rstrip('/')}/ws/{payment_request_row.dpp_invoice_id}?internal=true"

        async with state.session.ws_connect(websocket_url, headers=headers, timeout=5.0) \
                as server_websocket:
            state.dpp_websockets[payment_request_row.dpp_invoice_id] = server_websocket
            websocket_message: aiohttp.WSMessage
            async for websocket_message in server_websocket:
                if websocket_message.type == aiohttp.WSMsgType.TEXT:
                    message_json = cast(dict, json.loads(websocket_message.data))
                else:
                    raise NotImplementedError("The Direct Payment Protocol does not have a binary "
                                              "format")

                _validate_dpp_message_json(message_json)
                if message_json["expiration"] is not None:
                    expiration = int(from_isoformat(message_json["expiration"]).timestamp())
                else:
                    expiration = None

                dpp_message = DPPMessageRow(
                    message_id=message_json["messageId"],
                    paymentrequest_id=payment_request_row.paymentrequest_id,
                    dpp_invoice_id=message_json["channelId"],
                    correlation_id=message_json["correlationId"],
                    app_id=message_json["appId"],
                    client_id=message_json["clientID"],
                    user_id=message_json["userId"],
                    expiration=expiration,
                    body=json.dumps(message_json["body"]).encode('utf-8'),
                    timestamp=int(from_isoformat(message_json["timestamp"]).timestamp()),
                    type=message_json["type"]
                )
                db_connection = db_context.acquire_connection()
                try:
                    # This is intentionally not async and does not run in a thread
                    # to avoid any chance of thread context switching or another async task
                    # crashing the process and resulting in permanent loss of the message data
                    db_functions.create_dpp_messages([dpp_message], db_connection)
                finally:
                    db_context.release_connection(db_connection)
                if message_json["type"] != MSG_TYPE_JOIN_SUCCESS:
                    state.dpp_messages_queue.put_nowait(dpp_message)
    except aiohttp.ClientConnectorError:
        logger.debug("Unable to connect to server websocket")
    except WSServerHandshakeError as e:
        logger.exception("Websocket connection to %s failed the handshake", state.server.url)
    finally:
        state.dpp_websocket = None


async def manage_dpp_network_connections_async(state: ServerConnectionState,
        db_context: DatabaseContext) -> None:
    """Spawns a new websocket task for each new active invoice pushed to its queue"""
    logger.debug("Entering manage_dpp_connections_async, server_url=%s", state.server.url)
    try:
        while True:
            payment_request_row = await state.active_invoices_queue.get()
            app_state.async_.spawn(create_dpp_ws_connection_task_async(state, payment_request_row,
                db_context))
    except Exception:
        logger.exception("Exception in manage_dpp_connections_async")
    finally:
        logger.debug("Exiting manage_dpp_connections_async, server_url=%s",
            state.server.url)


