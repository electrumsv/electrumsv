from __future__ import annotations

from bitcoinx import PrivateKey
from datetime import datetime, timezone
import uuid
from http import HTTPStatus
import json
from typing import TypedDict

from ..app_state import app_state
from ..constants import DPPMessageType
from ..dpp_messages import get_dpp_network_string, HybridModePaymentACKDict, \
    HYBRID_PAYMENT_MODE_BRFCID, Payment, PaymentACK, PaymentACKDict
from ..exceptions import Bip270Exception
from ..logs import logs
from ..standards.json_envelope import pack_json_envelope
from ..types import IndefiniteCredentialId
from ..wallet_database.types import DPPMessageRow, PaymentRequestRow, PaymentRequestOutputRow

logger = logs.get_logger("direct-payments")


# This structure is what the dpp-proxy server expects in the body of the `payment.error` websocket
# message type in order to generate the appropriate http response for the payer SPV wallet
class ClientError(TypedDict):
    id: str
    code: str
    title: str
    message: str


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
            if response.status in {HTTPStatus.BAD_REQUEST, HTTPStatus.UNPROCESSABLE_ENTITY}:
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
        "network": get_dpp_network_string(),
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
        type=DPPMessageType.REQUEST_RESPONSE
    )
    return message_row_response


def dpp_make_ack(txid: str, message_row_received: DPPMessageRow) -> DPPMessageRow:
    mode = HybridModePaymentACKDict(transactionIds=[txid])
    payment_ack_data = PaymentACKDict(modeId=HYBRID_PAYMENT_MODE_BRFCID, mode=mode,
        peerChannel=None, redirectUrl=None)

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
        type=DPPMessageType.PAYMENT_ACK)
    return message_row_response


def dpp_make_payment_request_error(message_row_received: DPPMessageRow, error_reason: str,
        code: int = 400, title: str = "Bad Request") -> DPPMessageRow:
    message_id = str(uuid.uuid4())
    client_error = ClientError(id=message_id, code=str(code), title=title,
        message=error_reason)
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
        type=DPPMessageType.REQUEST_ERROR)
    return message_row_response


def dpp_make_payment_error(message_row_received: DPPMessageRow, error_reason: str,
        code: int = 400, title: str = "Bad Request") -> DPPMessageRow:
    message_id = str(uuid.uuid4())
    client_error = ClientError(id=message_id, code=str(code), title=title,
        message=error_reason)
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
        type=DPPMessageType.PAYMENT_ERROR)
    return message_row_response

