# Open BSV License version 4
#
# Copyright (c) 2021 Bitcoin Association for BSV ("Bitcoin Association")
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
import concurrent.futures
import json
from typing import Any, cast, Dict, List, Optional, TYPE_CHECKING, Tuple, TypedDict

import aiohttp
from bitcoinx import PublicKey
from aiohttp import ClientConnectorError
from aiorpcx import SOCKSError, TaskGroup

from ..app_state import app_state
from ..constants import NetworkServerType
from ..logs import logs
from ..types import TransactionSize


if TYPE_CHECKING:
    from .api_server import NewServer, SelectionCandidate
    from ..network import Network
    from ..transaction import Transaction
    from ..types import IndefiniteCredentialId
    from ..wallet import AbstractAccount


logger = logs.get_logger("network-mapi")


class FeeQuoteTypeFee(TypedDict):
    satoshis: int
    bytes: int


class FeeQuoteTypeEntry(TypedDict):
    feeType: str
    miningFee: FeeQuoteTypeFee
    relayFee: FeeQuoteTypeFee


# A MAPI fee quote is packaged according to the JSON envelope BRFC.
# https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope
class FeeQuote(TypedDict):
    # https://github.com/bitcoin-sv-specs/brfc-merchantapi#1-get-fee-quote
    apiVersion: str
    timestamp: str
    expiryTime: str
    minerId: str
    currentHighestBlockHash: str
    currentHighestBlockHeight: int
    fees: List[FeeQuoteTypeEntry]


class BroadcastConflict(TypedDict):
    txid: str # Canonical hex transaction id.
    size: int
    hex: str


# A MAPI broadcast response is packaged according to the JSON envelope BRFC.
# https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope
class BroadcastResponse(TypedDict):
    # https://github.com/bitcoin-sv-specs/brfc-merchantapi#2-submit-transaction
    apiVersion: str
    timestamp: str
    txid: str # Canonical hex transaction id.
    returnResult: str # "success" or "failure"
    returnDescription: str # "" or "<error message>"
    minerId: str
    currentHighestBlockHash: str
    currentHighestBlockHeight: int
    txSecondMempoolExpiry: int
    conflictedWith: List[BroadcastConflict]


class JSONEnvelope(TypedDict):
    payload: str
    signature: Optional[str]
    publicKey: Optional[str]
    encoding: str
    mimetype: str


async def decode_response_body(response: aiohttp.ClientResponse) -> Dict[Any, Any]:
    body = await response.read()
    if body == b"" or body == b"{}":
        return {}
    return cast(Dict[Any, Any], json.loads(body.decode()))


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


def poll_servers(network: "Network", account: "AbstractAccount") \
        -> Optional[concurrent.futures.Future[None]]:
    """
    Work out if any servers lack fee quotes and poll them.

    If there is work to be done, a `concurrent.futures.Future` instance is returned. Otherwise
    we return `None`.
    """
    server_entries: List[Tuple["NewServer", Optional["IndefiniteCredentialId"]]] = []
    for candidate in network.get_api_servers_for_account(account, NetworkServerType.MERCHANT_API):
        assert candidate.api_server is not None
        assert candidate.credential_id is not None
        if candidate.api_server.should_request_fee_quote(candidate.credential_id):
            server_entries.append((candidate.api_server, candidate.credential_id))

    if not len(server_entries):
        return None
    return app_state.async_.spawn(_poll_servers_async, server_entries)


async def _poll_servers_async(
        server_entries: List[Tuple["NewServer", Optional["IndefiniteCredentialId"]]]) -> None:
    async with TaskGroup() as group:
        for server, credential_id in server_entries:
            await group.spawn(get_fee_quote, server, credential_id)


async def get_fee_quote(server: "NewServer",
        credential_id: Optional["IndefiniteCredentialId"]) -> None:
    """The last_good and last_try timestamps will be used to include/exclude the mAPI for
    selection"""
    server_state = server.api_key_state[credential_id]
    server_state.record_attempt()

    url = server.url if server.url.endswith("/") else server.url +"/"
    url += "feeQuote"
    headers = { 'Content-Type': 'application/json' }
    headers.update(server.get_authorization_headers(credential_id))
    is_ssl = url.startswith("https")

    async with aiohttp.ClientSession() as client:
        async with client.get(url, headers=headers, ssl=is_ssl) as resp:
            try:
                json_response = await decode_response_body(resp)
            except (ClientConnectorError, ConnectionError, OSError, SOCKSError):
                logger.error("failed connecting to %s", url)
            else:
                if resp.status != 200:
                    logger.error("feeQuote request to %s failed with: status: %s, reason: %s",
                        url, resp.status, resp.reason)
                else:
                    assert json_response['encoding'].lower() == 'utf-8'

                    fee_quote_response = cast(JSONEnvelope, json_response)
                    validate_json_envelope(fee_quote_response)
                    logger.debug("fee quote received from %s", server.url)

                    server_state.update_fee_quote(fee_quote_response)


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


async def broadcast_transaction(tx: "Transaction", server: "NewServer",
        credential_id: Optional["IndefiniteCredentialId"]) -> None:
    server_state = server.api_key_state[credential_id]
    server_state.record_attempt()

    url = server.url if server.url.endswith("/") else server.url +"/"
    url += "tx"
    # It is unclear if we need to pass false values for these, the specification implies that
    # we should but in theory it won't let us broadcast at all.
    params = {
        "merkleProof": "false",
        "dsCheck": "false",
    }
    headers = {}
    headers.update(server.get_authorization_headers(credential_id))
    is_ssl = url.startswith("https")

    async with aiohttp.ClientSession() as client:
        async with client.post(url, ssl=is_ssl, headers=headers, params=params,
                data=tx.to_bytes()) as response:
            try:
                json_response = await decode_response_body(response)
            except (ClientConnectorError, ConnectionError, OSError, SOCKSError):
                logger.error("failed connecting to %s", url)
            else:
                if response.status != 200:
                    logger.error("feeQuote request to %s failed with: status: %s, reason: %s",
                        url, response.status, response.reason)
                else:
                    assert json_response['encoding'].lower() == 'utf-8'

                    broadcast_response = cast(JSONEnvelope, json_response)
                    validate_json_envelope(broadcast_response)
                    logger.debug("transaction broadcast via MAPI server: %s", server.url)

                    # TODO(MAPI) Work out if we should be processing the response.
                    # TODO(MAPI) Work out if we should be storing the response.
                    server_state.record_success()


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

