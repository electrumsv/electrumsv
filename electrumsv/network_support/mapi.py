# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import annotations
import asyncio
import concurrent.futures
from http import HTTPStatus
import json
from typing import Any, cast, get_type_hints, Optional, TYPE_CHECKING

import aiohttp
from bitcoinx import PublicKey
from aiohttp import ClientConnectorError

from ..app_state import app_state
from ..constants import NetworkServerType
from ..exceptions import BroadcastFailedError, ServiceUnavailableError
from ..logs import logs
from ..wallet_database.types import ServerPeerChannelAccessTokenRow

from .types import BroadcastResponse, FeeQuote, FeeQuoteTypeFee, JSONEnvelope, MAPICallbackResponse

if TYPE_CHECKING:
    from ..types import IndefiniteCredentialId
    from ..network_support.api_server import NewServer
    from ..wallet import AbstractAccount
    from ..types import TransactionSize


logger = logs.get_logger("network-mapi")


# self.mapi_client: Optional[aiohttp.ClientSession] = None
#
# async def _get_mapi_client(self):
#     # aiohttp session needs to be initialised in async function
#     # https://github.com/tiangolo/fastapi/issues/301
#     if self.mapi_client is None:
#         # resolver = AsyncResolver()
#         # conn = aiohttp.TCPConnector(family=socket.AF_INET, resolver=resolver,
#         #      ttl_dns_cache=10,
#         #                             force_close=True, enable_cleanup_closed=True)
#         # self.mapi_client = aiohttp.ClientSession(connector=conn)
#         self.mapi_client = aiohttp.ClientSession()
#     return self.mapi_client
#
# async def _close_mapi_client(self) -> None:
#     logger.debug("closing aiohttp client session.")
#     if self.mapi_client:
#         await self.mapi_client.close()


def get_mapi_servers(account: AbstractAccount) -> \
        list[tuple[NewServer, Optional[IndefiniteCredentialId]]]:
    account_id = account.get_id()
    server_entries: list[tuple[NewServer, Optional[IndefiniteCredentialId]]] = []
    for server, credential_id in account._wallet.get_servers_for_account_id(account_id,
            NetworkServerType.MERCHANT_API):
        if server.should_request_fee_quote(credential_id):
            server_entries.append((server, credential_id))
    return server_entries


def filter_mapi_servers_for_fee_quote(
        selection_candidates: list[tuple[NewServer, Optional[IndefiniteCredentialId]]]) \
            -> list[tuple[NewServer, Optional[IndefiniteCredentialId]]]:
    """raises `ServiceUnavailableError` if there are no merchant APIs with fee quotes"""
    filtered = []

    for server, credential_id in selection_candidates:
        if server.api_key_state[credential_id].last_fee_quote is None:
            logger.error("No fee quote for merchant API at: %s", server.url)
            continue
        filtered.append((server, credential_id))

    if len(filtered) == 0:
        raise ServiceUnavailableError("There are no suitable merchant API servers available")

    return filtered


def poll_servers(account: AbstractAccount) -> Optional[concurrent.futures.Future[None]]:
    """
    Work out if any servers lack fee quotes and poll them.

    If there is work to be done, a `concurrent.futures.Future` instance is returned. Otherwise
    we return `None`.
    """
    server_entries = get_mapi_servers(account)
    if not len(server_entries):
        return None
    return app_state.async_.spawn(poll_servers_async, server_entries)


async def poll_servers_async(
        server_entries: list[tuple[NewServer, Optional[IndefiniteCredentialId]]]) -> None:
    tasks = []
    for server, credential_id in server_entries:
        tasks.append(get_fee_quote(server, credential_id))
    for i, result in enumerate(await asyncio.gather(*tasks, return_exceptions=True)):
        if isinstance(result, Exception):
            logger.error("Failed to get MAPI fee quote from %s", server_entries[i][0].url,
                exc_info=result)


async def get_fee_quote(server: NewServer,
        credential_id: Optional[IndefiniteCredentialId]) -> None:
    """The last_good and last_try timestamps will be used to include/exclude the mAPI for
    selection"""
    server.api_key_state[credential_id].record_attempt()

    url = f"{server.url}feeQuote"
    headers = {'Content-Type': 'application/json'}
    headers.update(server.get_authorization_headers(credential_id))
    is_ssl = url.startswith("https")

    async with aiohttp.ClientSession() as client:
        async with client.get(url, headers=headers, ssl=is_ssl) as response:
            try:
                body = await response.read()
            except (ClientConnectorError, ConnectionError, OSError):
                logger.error("failed connecting to %s", url)
                return
            else:
                if response.status != HTTPStatus.OK:
                    # We hope that this service will become available later. Until then it
                    # should be excluded by prioritisation/server selection algorithms
                    logger.error("feeQuote request to %s failed with: status: %s, reason: %s",
                        url, response.status, response.reason)
                    return

        try:
            json_response = cast(dict[Any, Any], json.loads(body.decode()))
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.error("feeQuote request to %s failed", exc_info=True)
            return

        assert json_response['encoding'].lower() == 'utf-8'

        fee_quote_response = cast(JSONEnvelope, json_response)
        validate_json_envelope(fee_quote_response)
        logger.debug("fee quote received from %s", server.url)

        server.api_key_state[credential_id].update_fee_quote(fee_quote_response)


def validate_json_envelope(json_response: JSONEnvelope) -> None:
    """
    It is not necessary for a fee quote to include a signature, but if there is one we check
    it. What does it mean if there isn't one? No idea, but at this time there is no expectation
    there will be one.

    Raises a `ValueError` to indicate that the signature is invalid.
    """
    message_bytes = json_response["payload"].encode()
    if json_response["signature"] is not None and json_response["publicKey"] is not None:
        signature_bytes = bytes.fromhex(json_response["signature"])
        # TODO This should check the public key is the correct one?
        public_key = PublicKey.from_hex(json_response["publicKey"])
        if not public_key.verify_der_signature(signature_bytes, message_bytes):
            raise ValueError("MAPI signature invalid")


MAPI_CALLBACK_REASONS = {"doubleSpend", "doubleSpendAttempt", "merkleProof"}

# TODO(1.4.0) Unit testing. WRT MAPI callback response validation.
#     Examples: https://github.com/bitcoin-sv-specs/brfc-merchantapi#callback-notifications
def validate_mapi_callback_response(response_data: MAPICallbackResponse) -> None:
    for field_name, field_type in get_type_hints(MAPICallbackResponse).items():
        if field_name not in response_data:
            raise ValueError(f"Missing '{field_name}' field")

        field_value = response_data[field_name] # type: ignore[literal-required]
        # You cannot do a `isinstance(value, Dict[str, Any])`, so you need to extract the
        # `dict` part out and use that as the type. It's close enough.
        if hasattr(field_type, "__origin__"):
            field_type = field_type.__origin__
        if not isinstance(field_value, field_type):
            raise ValueError(f"Invalid '{field_name}' type, expected {field_type}, "
                f"got {type(field_value)}")

    if response_data["callbackReason"] not in MAPI_CALLBACK_REASONS:
        raise ValueError(f"Invalid 'callbackReason' '{response_data['callbackReason']}'")

    block_id = response_data["blockHash"]
    if len(block_id) != 32*2:
        raise ValueError(f"'blockHash' not 64 characters '{response_data['blockHash']}'")

    transaction_id = response_data["callbackTxId"]
    if len(transaction_id) != 32*2:
        raise ValueError(f"'callbackTxId' not 64 characters '{response_data['callbackTxId']}'")


async def broadcast_transaction_mapi_simple(transaction_bytes: bytes, server: NewServer,
        credential_id: Optional[IndefiniteCredentialId], peer_channel_url: str,
        peer_channel_token: ServerPeerChannelAccessTokenRow,
        merkle_proof: bool=False, ds_check: bool=False) -> BroadcastResponse:
    server.api_key_state[credential_id].record_attempt()

    url = f"{server.url}tx"
    params = {
        'merkleProof': 'false' if not merkle_proof else 'true',
        'merkleFormat': "TSC",
        'dsCheck': 'false' if not ds_check else 'true',
        'callbackURL': peer_channel_url,
        'callbackToken': f"Bearer {peer_channel_token.access_token}",
        # 'callbackEncryption': None  # Todo: add libsodium encryption
    }
    headers = {"Content-Type": "application/octet-stream"}
    headers.update(server.get_authorization_headers(credential_id))
    is_ssl = url.startswith("https")
    async with aiohttp.ClientSession() as client:
        async with client.post(url, ssl=is_ssl, headers=headers, params=params,
                data=transaction_bytes) as response:
            try:
                body = await response.read()
            except (ClientConnectorError, ConnectionError, OSError):
                logger.error("failed connecting to %s", url)
                raise BroadcastFailedError(f"Broadcast failed for url: {url}, "
                    f"Unable to connect to the server.")
            else:
                if response.status != HTTPStatus.OK:
                    logger.error("Broadcast request to %s failed with: status: %s, reason: %s",
                        url, response.status, response.reason)
                    raise BroadcastFailedError(f"Broadcast failed for url: {url}. "
                        f"status: {response.status}, reason: {response.reason}")

    try:
        json_response = cast(dict[Any, Any], json.loads(body.decode()))
    except (UnicodeDecodeError, json.JSONDecodeError):
        logger.error("Broadcast request to %s in question (corrupt payload)", exc_info=True)
        raise BroadcastFailedError(f"Broadcast in question for url: {url}. Corrupt payload.")

    assert json_response['encoding'].lower() == 'utf-8'

    broadcast_response_envelope = cast(JSONEnvelope, json_response)
    validate_json_envelope(broadcast_response_envelope)
    logger.debug("transaction broadcast via MAPI server: %s", server.url)

    # TODO(1.4.0) MAPI. Work out if we should be processing the response.
    # TODO(1.4.0) MAPI. Work out if we should be storing the response.
    server.api_key_state[credential_id].record_success()
    broadcast_response: BroadcastResponse = json.loads(broadcast_response_envelope['payload'])

    if broadcast_response['returnResult'] == 'failure':
        raise BroadcastFailedError(broadcast_response['resultDescription'])

    return broadcast_response


class MAPIFeeEstimator:
    standard_fee_satoshis = 0
    standard_fee_bytes = 0
    data_fee_satoshis = 0
    data_fee_bytes = 0

    def __init__(self, fee_quote: FeeQuote) -> None:
        standard_fee: Optional[FeeQuoteTypeFee] = None
        data_fee: Optional[FeeQuoteTypeFee] = None
        for fee in fee_quote["fees"]:
            if fee["feeType"] == "standard":
                standard_fee = fee["miningFee"]
            elif fee["feeType"] == "data":
                data_fee = fee["miningFee"]

        assert standard_fee is not None
        self.standard_fee_satoshis = standard_fee["satoshis"]
        self.standard_fee_bytes = standard_fee["bytes"]
        if data_fee is not None:
            self.data_fee_satoshis = data_fee["satoshis"]
            self.data_fee_bytes = data_fee["bytes"]

    def estimate_fee(self, tx_size: TransactionSize) -> int:
        fee = 0
        standard_size = tx_size.standard_size
        if self.data_fee_bytes:
            standard_size = tx_size.standard_size
            fee += tx_size.data_size * self.data_fee_satoshis // self.data_fee_bytes
        else:
            standard_size += tx_size.data_size
        fee += standard_size * self.standard_fee_satoshis // self.standard_fee_bytes
        return fee

