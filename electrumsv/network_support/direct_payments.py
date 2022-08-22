from __future__ import annotations

from ..app_state import app_state
from ..dpp_messages import Payment, PaymentACK
from ..exceptions import Bip270Exception
from ..logs import logs

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

