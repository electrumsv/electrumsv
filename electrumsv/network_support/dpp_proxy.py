import asyncio
import json
from typing import Any, cast

import aiohttp
from aiohttp import WSServerHandshakeError

from .types import ServerConnectionState
from ..app_state import app_state
from ..constants import PaymentFlag
from ..logs import logs
from ..wallet_database.types import DPPMessageRow, PaymentRequestReadRow

logger = logs.get_logger("dpp-proxy")

MSG_TYPE_JOIN_SUCCESS = "join.success"
MSG_TYPE_PAYMENT = "payment"
MSG_TYPE_PAYMENT_ACK = "payment.ack"
MSG_TYPE_PAYMENT_ERR = "payment.error"
MSG_TYPE_PAYMENT_REQUEST_CREATE = "paymentrequest.create"
MSG_TYPE_PAYMENT_REQUEST_RESPONSE = "paymentrequest.response"
MSG_TYPE_PAYMENT_REQUEST_ERROR = "paymentrequest.error"

ALL_MSG_TYPES = {MSG_TYPE_JOIN_SUCCESS, MSG_TYPE_PAYMENT, MSG_TYPE_PAYMENT_ACK,
    MSG_TYPE_PAYMENT_ERR,
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



async def dpp_websocket_send(state: ServerConnectionState, message_row: DPPMessageRow) -> None:
    websocket = state.dpp_websockets[message_row.dpp_invoice_id]
    if websocket is not None:  # ws:// is still open
        logger.debug("Sending over websocket: %s; message type: %s", message_row.to_json(),
            message_row.type)
        await websocket.send_str(message_row.to_json())
    else:
        logger.error("There is no open websocket for dpp_invoice_id: %s, server url: %s. "
                     "Retrying in 10 seconds...", message_row.dpp_invoice_id, state.server.url)
        await asyncio.sleep(10)
        state.dpp_messages_queue.put_nowait(message_row)



MESSAGE_STATE_BY_TYPE = {
    MSG_TYPE_PAYMENT_REQUEST_CREATE: PaymentFlag.PAYMENT_REQUEST_REQUESTED,
    MSG_TYPE_PAYMENT: PaymentFlag.PAYMENT_RECEIVED,
    MSG_TYPE_PAYMENT_REQUEST_RESPONSE: PaymentFlag.PAYMENT_REQUEST_RECEIVED,
    MSG_TYPE_PAYMENT_ACK: PaymentFlag.PAID
}


def _validate_dpp_message_json(dpp_message_json: dict[Any, Any]) -> None:
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
        payment_request_row: PaymentRequestReadRow) -> None:
    """One async task per ws:// connection - each invoice ID has its own ws:// connection.

    The Wallet in wallet.py can communicate with the open websocket as follows:
    - ServerConnectionState.dpp_websocket is used for sending messages
    - ServerConnectionState.dpp_messages_queue is used for received messages
    """
    assert state.wallet_data is not None
    assert payment_request_row.dpp_invoice_id is not None
    try:
        headers = {"Accept": "application/json"}
        server_url = state.server.url.replace("http", "ws")
        logger.debug("Opening DPP websocket for payment request: %s", payment_request_row)
        # TODO(1.4.0) DPP / AustEcon. Describe what `internal=true` means.
        websocket_url = f"{server_url}ws/{payment_request_row.dpp_invoice_id}?internal=true"

        # TODO(1.4.0) DPP / AustEcon. Rationalise why five seconds timeout.
        async with state.session.ws_connect(websocket_url, headers=headers, timeout=5.0) \
                as server_websocket:
            state.dpp_websockets[payment_request_row.dpp_invoice_id] = server_websocket

            websocket_message: aiohttp.WSMessage
            async for websocket_message in server_websocket:
                if websocket_message.type == aiohttp.WSMsgType.TEXT:
                    message_json = cast(dict[str, Any], json.loads(websocket_message.data))
                else:
                    raise NotImplementedError("The Direct Payment Protocol does not have a binary "
                                              "format")

                _validate_dpp_message_json(message_json)
                expiration_date_text = message_json["expiration"]

                dpp_message = DPPMessageRow(
                    message_id=message_json["messageId"],
                    paymentrequest_id=payment_request_row.paymentrequest_id,
                    dpp_invoice_id=message_json["channelId"],
                    correlation_id=message_json["correlationId"],
                    app_id=message_json["appId"],
                    client_id=message_json["clientID"],
                    user_id=message_json["userId"],
                    expiration=expiration_date_text,
                    body=json.dumps(message_json["body"]).encode('utf-8'),
                    timestamp=message_json["timestamp"],
                    type=message_json["type"]
                )
                await state.wallet_data.create_invoice_proxy_message_async([ dpp_message ])
                if message_json["type"] != MSG_TYPE_JOIN_SUCCESS:
                    state.dpp_messages_queue.put_nowait(dpp_message)
    except aiohttp.ClientConnectorError:
        logger.debug("Unable to connect to server websocket")
    except WSServerHandshakeError as e:
        logger.exception("Websocket connection to %s failed the handshake", state.server.url)
    finally:
        # TODO(1.4.0) DPP. When a DPP server goes down, we need a mechanism to retry every 5 seconds
        #  or so. Otherwise we will no longer have open websocket connections for invoices even
        #  though the DPP proxy server is back online again. Currently the user will have to
        #  restart to wallet to reconnect.
        state.dpp_websockets.pop(payment_request_row.dpp_invoice_id, None)


async def manage_dpp_network_connections_async(state: ServerConnectionState) -> None:
    """Spawns a new websocket task for each new active invoice pushed to its queue"""
    logger.debug("Entering manage_dpp_connections_async, server_url=%s", state.server.url)
    try:
        while True:
            payment_request_row = await state.active_invoices_queue.get()
            app_state.app.run_coro(create_dpp_ws_connection_task_async(state, payment_request_row))
    except Exception:
        logger.exception("Exception in manage_dpp_connections_async")
    finally:
        logger.debug("Exiting manage_dpp_connections_async, server_url=%s",
            state.server.url)


