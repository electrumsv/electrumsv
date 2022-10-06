from __future__ import annotations

from typing import TypedDict
from http import HTTPStatus

from bitcoinx import PrivateKey
import uuid
import json
from datetime import datetime, timezone

from .dpp_proxy import MSG_TYPE_PAYMENT_REQUEST_RESPONSE, MSG_TYPE_PAYMENT_ACK, \
    MSG_TYPE_PAYMENT_REQUEST_ERROR, MSG_TYPE_PAYMENT_ERROR
from ..app_state import app_state
from ..dpp_messages import Payment, PaymentACK, PeerChannelDict, HYBRID_PAYMENT_MODE_BRFCID
from ..exceptions import Bip270Exception
from ..logs import logs
from ..networks import Net
from ..standards.json_envelope import pack_json_envelope
from ..types import IndefiniteCredentialId
from ..transaction import Transaction
from ..wallet_database.types import DPPMessageRow, PaymentRequestRow, PaymentRequestOutputRow

logger = logs.get_logger("direct-payments")


class ClientError(TypedDict):
    ID: str
    Code: str
    Title: str
    Message: str


async def send_outgoing_direct_payment_async(payment_url: str,
        transaction_hex: str, their_text: str | None = None) -> PaymentACK:
    """
    Raises `Bip270Exception` if the remote server returned an error. `exception.args[0]` contains
        text describing the error.
    """
    assert app_state.daemon.network is not None
    session = app_state.daemon.network.aiohttp_session

    if their_text is None:
        their_text = "Paid using ElectrumSV"

    logger.debug("Outgoing payment url: %s", payment_url)

    payment = Payment(transaction_hex=transaction_hex, memo=their_text)

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "ElectrumSV",
    }
    json_body = payment.to_json()
    async with session.post(payment_url, headers=headers, data=json_body) as response:
        if response.status not in (200, 201, 202):
            # Propagate 'Bad request' (HTTP 400) messages to the user since they
            # contain valuable information.
            if response.status == HTTPStatus.BAD_REQUEST:
                content_text = await response.text(encoding="UTF-8")
                message = f"{content_text}"  # dpp proxy error message includes response.reason
            elif response.status == HTTPStatus.UNPROCESSABLE_ENTITY:
                content_text = await response.text(encoding="UTF-8")
                message = f"{response.reason}: {content_text}"
            else:
                # Some other errors might display an entire HTML document.
                # Hide those and just display the name of the error code.
                assert response.reason is not None
                message = response.reason
            raise Bip270Exception(message)

        ack_json = await response.text()

    payment_ack = PaymentACK.from_json(ack_json)
    logger.debug("PaymentACK message received: %s", payment_ack.to_json())
    return payment_ack


def dpp_make_payment_request_response(server_url: str, credential_id: IndefiniteCredentialId,
        request_row: PaymentRequestRow,
        request_output_rows: list[PaymentRequestOutputRow],
        message_row_received: DPPMessageRow) -> DPPMessageRow:
    assert request_row.dpp_invoice_id is not None
    payment_url = f"{server_url}api/v1/payment/{request_row.dpp_invoice_id}"

    payment_terms_data = {
        "network": Net.COIN.name,
        "version": "1.0",
        "creationTimestamp": request_row.date_created,
        "paymentUrl": payment_url,
        "memo": request_row.merchant_reference,

        # Hybrid Payment Mode
        'modes': {
            'ef63d9775da5': {
                "choiceID0": {
                    "transactions": [
                        {
                            'outputs': {
                                    'native': [
                                        {
                                            "description": "",
                                            "amount": request_output_row.output_value,
                                            "script": request_output_row.output_script_bytes.hex(),
                                        } for request_output_row in request_output_rows
                                    ]
                            },
                            'policies': {
                                "fees": {
                                    "standard": {"satoshis": 100, "bytes": 200},
                                    "data": {"satoshis": 100, "bytes": 200},
                                },
                            },
                        },
                    ],
                },
            }
        }
    }
    if request_row.date_expires is not None:
        payment_terms_data['expirationTimestamp'] = request_row.date_expires
    payment_terms_json = json.dumps(payment_terms_data)

    secure_private_key = PrivateKey.from_hex(
        app_state.credentials.get_indefinite_credential(credential_id))
    response_json = pack_json_envelope(payment_terms_json, secure_private_key)

    message_row_response = DPPMessageRow(
        message_id=str(uuid.uuid4()),
        paymentrequest_id=message_row_received.paymentrequest_id,
        dpp_invoice_id=message_row_received.dpp_invoice_id,
        correlation_id=message_row_received.correlation_id,
        app_id=message_row_received.app_id,
        client_id=message_row_received.client_id,
        user_id=message_row_received.user_id,
        expiration=message_row_received.expiration,
        body=json.dumps(response_json).encode('utf-8'),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        type=MSG_TYPE_PAYMENT_REQUEST_RESPONSE
    )
    return message_row_response


def dpp_make_ack(tx: Transaction, peer_channel: PeerChannelDict,
        message_row_received: DPPMessageRow) -> DPPMessageRow:

    payment_ack_data = {
        "modeId": HYBRID_PAYMENT_MODE_BRFCID,
        "mode": {
            "transactionIds": [tx.hex_hash()]
        },
        "peerChannel": peer_channel
    }

    message_row_response = DPPMessageRow(
        message_id=str(uuid.uuid4()),
        paymentrequest_id=message_row_received.paymentrequest_id,
        dpp_invoice_id=message_row_received.dpp_invoice_id,
        correlation_id=message_row_received.correlation_id,
        app_id=message_row_received.app_id,
        client_id=message_row_received.client_id,
        user_id=message_row_received.user_id,
        expiration=message_row_received.expiration,
        body=json.dumps(payment_ack_data).encode('utf-8'),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        type=MSG_TYPE_PAYMENT_ACK)
    return message_row_response


def dpp_make_pr_error(message_row_received: DPPMessageRow, error_reason: str) -> DPPMessageRow:
    message_row_response = DPPMessageRow(
        message_id=str(uuid.uuid4()),
        paymentrequest_id=message_row_received.paymentrequest_id,
        dpp_invoice_id=message_row_received.dpp_invoice_id,
        correlation_id=message_row_received.correlation_id,
        app_id=message_row_received.app_id,
        client_id=message_row_received.client_id,
        user_id=message_row_received.user_id,
        expiration=message_row_received.expiration,
        body=error_reason.encode('utf-8'),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        type=MSG_TYPE_PAYMENT_REQUEST_ERROR)
    return message_row_response


def dpp_make_payment_error(message_row_received: DPPMessageRow, error_reason: str) \
        -> DPPMessageRow:
    message_id = str(uuid.uuid4())
    client_error = ClientError(ID=message_id, Code="400", Title="Bad Request", Message=error_reason)
    message_row_response = DPPMessageRow(
        message_id=message_id,
        paymentrequest_id=message_row_received.paymentrequest_id,
        dpp_invoice_id=message_row_received.dpp_invoice_id,
        correlation_id=message_row_received.correlation_id,
        app_id=message_row_received.app_id,
        client_id=message_row_received.client_id,
        user_id=message_row_received.user_id,
        expiration=message_row_received.expiration,
        body=json.dumps(client_error).encode('utf-8'),
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        type=MSG_TYPE_PAYMENT_ERROR)
    return message_row_response

