from __future__ import annotations

import typing

from bitcoinx import PrivateKey
import uuid
import json
from datetime import datetime, timezone

from .dpp_proxy import MSG_TYPE_PAYMENT_REQUEST_RESPONSE, MSG_TYPE_PAYMENT_ACK, \
    MSG_TYPE_PAYMENT_ERROR, MSG_TYPE_PAYMENT_REQUEST_ERROR
from .types import ServerConnectionState
from ..app_state import app_state
from ..constants import PeerChannelAccessTokenFlag
from ..dpp_messages import Payment, PaymentACK, PeerChannelDict, HYBRID_PAYMENT_MODE_BRFCID
from ..exceptions import Bip270Exception
from ..logs import logs
from ..standards.json_envelope import pack_json_envelope
from ..transaction import Transaction
from ..wallet_database.types import DPPMessageRow, PaymentRequestReadRow

if typing.TYPE_CHECKING:
    from ..wallet import Wallet

logger = logs.get_logger("direct-payments")


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
            if response.status == 400:
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


def dpp_make_peer_channel_info(wallet: Wallet, tx_hash: bytes,
        peer_channel_server_state: ServerConnectionState) -> PeerChannelDict:
    mapi_rows = wallet.data.read_mapi_broadcasts([tx_hash])
    assert len(mapi_rows) == 1
    mapi_row = mapi_rows[0]

    peer_channel_rows = wallet.data.read_server_peer_channels(
        peer_channel_id=mapi_row.peer_channel_id)
    assert len(peer_channel_rows) == 1, f"number of peer_channel_rows: {len(peer_channel_rows)}"
    peer_channel = peer_channel_rows[0]
    assert peer_channel.remote_channel_id is not None

    assert mapi_row.peer_channel_id is not None
    peer_channel_token_rows = wallet.data.read_server_peer_channel_access_tokens(
        mapi_row.peer_channel_id, flags=PeerChannelAccessTokenFlag.FOR_EXTERNAL_USAGE)
    assert len(peer_channel_token_rows) == 1
    peer_channel_token_row = peer_channel_token_rows[0]

    peer_channel_info = PeerChannelDict(host=peer_channel_server_state.server.url,
        token=peer_channel_token_row.access_token, channel_id=peer_channel.remote_channel_id)
    return peer_channel_info


def dpp_make_payment_request_response(wallet: 'Wallet', pr_row: PaymentRequestReadRow,
        message_row_received: DPPMessageRow) -> DPPMessageRow:
    key_data = wallet.data.read_keyinstance(keyinstance_id=pr_row.keyinstance_id)
    assert key_data is not None
    script_template = wallet._accounts[key_data.account_id].get_script_template_for_derivation(
        pr_row.script_type, key_data.derivation_type, key_data.derivation_data2)
    outputs_object = [
        {
            "description": "",
            "amount": pr_row.requested_value,
            "script": script_template.to_script().to_hex()
        }
    ]

    assert pr_row.date_created != -1
    assert pr_row.server_id is not None
    assert pr_row.dpp_invoice_id is not None
    server_url = wallet.get_dpp_server_url(pr_row.server_id)
    # This the actual payment URL for the payer to send the `Payment`, not the `PaymentTerms`
    # secure url.
    payment_url = f"{server_url}api/v1/payment/{pr_row.dpp_invoice_id}"

    payment_terms_data = {
        "network": "regtest",
        "version": "1.0",
        "creationTimestamp": pr_row.date_created,
        "paymentUrl": payment_url,
        "beneficiary": {"name": "GoldenSocks.com", "paymentReference": "Order-325214",
            "email": "merchant@m.com"},
        "memo": pr_row.merchant_reference,

        # Hybrid Payment Mode
        'modes': {'ef63d9775da5':
            {
                "choiceID0": {
                    "transactions": [
                        {
                            'outputs': {
                                    'native': outputs_object
                                }
                            ,
                            'policies': {
                                "fees": {
                                    "standard": {"satoshis": 100, "bytes": 200},
                                    "data": {"satoshis": 100, "bytes": 200},
                                },
                            },
                        },
                    ],
                },
            }}
    }
    if pr_row.date_expires is not None:
        payment_terms_data['expirationTimestamp'] = pr_row.date_expires
    payment_terms_json = json.dumps(payment_terms_data)

    credential_id, _secure_public_key = wallet._dpp_invoice_credentials[pr_row.dpp_invoice_id]
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
        type=MSG_TYPE_PAYMENT_ERROR)
    return message_row_response

