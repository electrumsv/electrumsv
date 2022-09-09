import asyncio
from concurrent.futures import Future
from http import HTTPStatus
import json
import random
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
MSG_TYPE_PAYMENT_ERROR = "payment.error"
MSG_TYPE_PAYMENT_REQUEST_CREATE = "paymentterms.create"
MSG_TYPE_PAYMENT_REQUEST_RESPONSE = "paymentterms.response"
MSG_TYPE_PAYMENT_REQUEST_ERROR = "paymentterms.error"

ALL_MSG_TYPES = {MSG_TYPE_JOIN_SUCCESS, MSG_TYPE_PAYMENT, MSG_TYPE_PAYMENT_ACK,
    MSG_TYPE_PAYMENT_ERROR,
    MSG_TYPE_PAYMENT_REQUEST_CREATE, MSG_TYPE_PAYMENT_REQUEST_RESPONSE,
    MSG_TYPE_PAYMENT_REQUEST_ERROR}
DPP_MESSAGE_SEQUENCE = [MSG_TYPE_JOIN_SUCCESS, MSG_TYPE_PAYMENT_REQUEST_CREATE,
    MSG_TYPE_PAYMENT_REQUEST_RESPONSE, MSG_TYPE_PAYMENT, MSG_TYPE_PAYMENT_ACK]


def is_later_dpp_message_sequence(prior: DPPMessageRow, later: DPPMessageRow) -> bool:
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


async def manage_dpp_connection_async(state: ServerConnectionState,
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
            state.dpp_websocket_connection_events[payment_request_row.dpp_invoice_id].set()

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
        logger.debug("Closing DPP websocket for payment request: %s", payment_request_row)
        state.dpp_websockets.pop(payment_request_row.dpp_invoice_id, None)


async def create_dpp_server_connection_async(state: ServerConnectionState,
        row: PaymentRequestReadRow, timeout_seconds: float=0.0) \
            -> tuple[Future[None], asyncio.Event]:
    """
    Raises `asyncio.TimeoutError` if the connection is not made within the given timeout.
    """
    assert row.dpp_invoice_id is not None
    assert row.dpp_invoice_id not in state.dpp_websocket_connection_events
    event = state.dpp_websocket_connection_events[row.dpp_invoice_id] = asyncio.Event()
    future = app_state.async_.spawn(manage_dpp_connection_async(state, row))
    if timeout_seconds > 0.0:
        try:
            await asyncio.wait_for(event.wait(), timeout_seconds)
        except asyncio.TimeoutError:
            # TODO(1.4.0) DPP. We need to do error handling here, but it should be unexpected
            #     given our requirement that our server be "connectable".
            future.cancel()
            del state.dpp_websocket_connection_events[row.dpp_invoice_id]
            raise
    return future, event


async def close_dpp_server_connection_async(all_server_states: list[ServerConnectionState],
        payment_request_row: PaymentRequestReadRow) -> None:
    assert payment_request_row.dpp_invoice_id is not None

    for server_state in all_server_states:
        websocket = server_state.dpp_websockets.pop(payment_request_row.dpp_invoice_id, None)
        if websocket is None:
            continue
        break
    else:
        return

    try:
        await websocket.close()
    except Exception:
        # NOTE(exceptions) We have no idea what exceptions this can raise or why! This is the state
        #     of Python as a language across most of the code used with it and it is not good.
        #     Generally it is not recommended to catch `Exception` if you can identify which raise.
        logger.exception("Unexpected exception closing REST API websocket")

    if payment_request_row.dpp_invoice_id in server_state.dpp_websocket_connection_events:
        del server_state.dpp_websocket_connection_events[payment_request_row.dpp_invoice_id]


async def create_dpp_server_connections_async(state: ServerConnectionState,
        payment_request_rows: list[PaymentRequestReadRow]) -> None:
    """Block until all the requested connections are made and report the results."""
    if len(payment_request_rows) == 0:
        return

    active_tasks = list[tuple[PaymentRequestReadRow, Future[None], asyncio.Event]]()
    for row in payment_request_rows:
        assert row.dpp_invoice_id is not None
        future, event = await create_dpp_server_connection_async(state, row)
        active_tasks.append((row, future, event))

    done, pending = await asyncio.wait([ event.wait() for row, future, event in active_tasks ],
        timeout=6.0)
    if len(pending) > 0:
        # TODO(1.4.0) DPP. Handle failure to connect.
        # - It does not matter what the contents of `pending` are, we can look at the task to
        #   see why it exited.
        # - We need some recovery handling or user notification and other things along those lines.
        pass


async def find_connectable_dpp_server(server_states: list[ServerConnectionState]) \
        -> ServerConnectionState | None:
    connected_server_states = [ state for state in server_states if len(state.dpp_websockets) > 0 ]
    if len(connected_server_states) > 0:
        return random.choice(connected_server_states)

    server_states = server_states[:]
    random.shuffle(server_states)
    for state in server_states:
        try:
            async with state.session.options(state.server.url) as response:
                if response.status == HTTPStatus.NO_CONTENT:
                    return state
        except aiohttp.ClientError:
            pass

    return None
