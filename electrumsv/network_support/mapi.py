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
from dataclasses import dataclass
from http import HTTPStatus
import json
import time
from typing import AsyncIterable, cast, Optional, TYPE_CHECKING

import aiohttp
from aiohttp import ClientConnectorError
from bitcoinx import hash_to_hex_str

from ..exceptions import BadServerError, ServerAuthorizationError, ServerConnectionError, \
    ServerError
from ..constants import MAPIBroadcastFlag, PeerChannelAccessTokenFlag, ServerPeerChannelFlag
from ..logs import logs
from ..standards.mapi import MAPIBroadcastResponse, validate_mapi_broadcast_response
from ..standards.json_envelope import JSONEnvelope, validate_json_envelope
from ..transaction import Transaction
from ..types import ServerAndCredential
from ..wallet_database.types import MAPIBroadcastRow, ServerPeerChannelAccessTokenRow

from .api_server import RequestFeeQuoteResult
from .general_api import create_peer_channel_locally_and_remotely_async

if TYPE_CHECKING:
    from ..types import IndefiniteCredentialId
    from ..network_support.api_server import NewServer
    from ..wallet import WalletDataAccess

    from .types import ServerConnectionState


logger = logs.get_logger("network-mapi")


@dataclass
class PeerChannelCallback:
    callback_url: str
    callback_access_token: ServerPeerChannelAccessTokenRow
    merkle_proof: bool
    double_spend_check: bool

async def update_mapi_fee_quotes_async(servers_with_credentials: list[ServerAndCredential],
        timeout: float=4.0) -> AsyncIterable[ServerAndCredential]:
    """
    Update all fee quotes for the given servers if they have expired.

    All the requests are done concurrently and there is an overall timeout `timeout` after which we
    guarantee we will exit this function. All completed requests have their entry  yielded up to
    the caller as they complete.

    Raises nothing.
    """
    task: asyncio.Task[None]
    local_results: list[ServerAndCredential] = []
    server_tasks = set[asyncio.Task[None]]()
    entry_by_task: dict[asyncio.Task[None], ServerAndCredential] = {}
    for server, credential_id in servers_with_credentials:
        # Do we need a fee quote from this server? Does it require credentials we do not have?
        request_quote_result = server.should_request_fee_quote(credential_id)
        if request_quote_result == RequestFeeQuoteResult.SHOULD:
            task = asyncio.create_task(_get_mapi_fee_quote_async(server, credential_id))
            # We want to match successfully completed tasks to the output data
            entry_by_task[task] = ServerAndCredential(server, credential_id)
            server_tasks.add(task)
        elif request_quote_result == RequestFeeQuoteResult.ALREADY_HAVE:
            fee_quote = server.api_key_state[credential_id].last_fee_quote
            assert fee_quote is not None
            local_results.append(ServerAndCredential(server, credential_id))

    for local_result in local_results:
        yield local_result

    if len(server_tasks) == 0:
        return

    tasks_pending = set[asyncio.Task[None]]()
    current_time = time.time()
    end_time = current_time + timeout
    while len(server_tasks) > 0 and current_time < end_time:
        remaining_seconds = end_time - current_time
        tasks_done, tasks_pending = await asyncio.wait(server_tasks, timeout=remaining_seconds,
            return_when=asyncio.FIRST_COMPLETED)
        for task in tasks_done:
            server_entry = entry_by_task[task]
            exception = task.exception()
            if exception is not None:
                logger.warning("Fee quote request to server %s failed (%s)", server_entry[0].key,
                    str(exception))
                continue
            yield server_entry
        server_tasks = tasks_pending
        current_time = time.time()

    # Cancel any requests that are still in progress.
    for task in tasks_pending:
        task.cancel()

    # Any pending tasks that completed and errored and we did not call `exception` on, will by
    # default log their stack trace to the loop exception handler when they are garbage collected.


async def _get_mapi_fee_quote_async(server: NewServer,
        credential_id: Optional[IndefiniteCredentialId]) -> None:
    """
    Contact the server for a fee quote with the given credential if there is one.

    The last_good and last_try timestamps will be used to include/exclude the mAPI for selection.

    Raises `ServerConnectionError` if we cannot establish a connection to the server.
    Raises `ServerAuthorizationError` if we had no credentials or our credentials are rejected.
    """
    server.api_key_state[credential_id].record_attempt()

    url = f"{server.url}feeQuote"
    headers = {'Content-Type': 'application/json'}
    # This will not add an Authorization header if there are no credentials.
    headers.update(server.get_authorization_headers(credential_id))
    is_ssl = url.startswith("https")

    async with aiohttp.ClientSession() as client:
        async with client.get(url, headers=headers, ssl=is_ssl) as response:
            try:
                body = await response.read()
            except (ClientConnectorError, ConnectionError, OSError):
                raise ServerConnectionError("Unable to establish server connection")

            if response.status == HTTPStatus.OK:
                pass
            elif response.status == HTTPStatus.UNAUTHORIZED:
                if credential_id is None:
                    raise ServerAuthorizationError("Server requires authentication "
                        "(no credentials)")
                raise ServerAuthorizationError("Server requires authentication (key rejected)")
            else:
                # We hope that this service will become available later. Until then it
                # should be excluded by prioritisation/server selection algorithms
                logger.debug("feeQuote request to %s failed with: status: %s, reason: %s",
                    url, response.status, response.reason)
                raise ServerError(f"Response was {response.status}: '{response.reason}'")

        try:
            fee_quote_response = cast(JSONEnvelope, json.loads(body))
        except (TypeError, json.JSONDecodeError):
            logger.error("feeQuote request to %s failed", exc_info=True)
            return

        validate_json_envelope(fee_quote_response)
        logger.debug("fee quote received from %s", server.url)

        server.api_key_state[credential_id].set_fee_quote(fee_quote_response, time.time())


async def mapi_transaction_broadcast_async(wallet_data: WalletDataAccess,
        peer_channel_server_state: ServerConnectionState | None,
        server_and_credential: ServerAndCredential, tx: Transaction, /,
        merkle_proof: bool = False, double_spend_check: bool = False) \
            -> MAPIBroadcastResponse:
    """
    Via `create_peer_channel_locally_and_remotely_async`:
        Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
        Raises `ServerConnectionError` if the remote computer does not accept the connection.
    Via `post_mapi_transaction_broadcast_async`:
        Raises `ServerError` if it connects but there is some other problem with the
            broadcast attempt.
        Raises `ServerConnectionError` if the server could not be connected to.
        Raises `BadServerError` if the response from the server is invalid in some way.
    """
    peer_channel_id: int | None = None
    peer_channel_callback: PeerChannelCallback | None = None
    if peer_channel_server_state is not None:
        third_party_token_flags = PeerChannelAccessTokenFlag.FOR_THIRD_PARTY_USAGE
        peer_channel_row, mapi_write_token, read_only_token = \
            await create_peer_channel_locally_and_remotely_async(
                peer_channel_server_state,
                ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK, third_party_token_flags,
                ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK, third_party_token_flags)
        assert peer_channel_row.remote_channel_id is not None
        assert peer_channel_row.remote_url is not None

        peer_channel_id = peer_channel_row.peer_channel_id
        peer_channel_callback = PeerChannelCallback(peer_channel_row.remote_url,
            mapi_write_token, merkle_proof=merkle_proof,
            double_spend_check=double_spend_check)

    tx_hash = tx.hash()
    date_created = int(time.time())
    mapi_broadcast_rows = await wallet_data.create_mapi_broadcasts_async([
        MAPIBroadcastRow(None, tx_hash, server_and_credential.server.server_id,
        MAPIBroadcastFlag.NONE, peer_channel_id, date_created, date_created) ])
    mapi_broadcast_row = mapi_broadcast_rows[0]
    assert mapi_broadcast_row.broadcast_id is not None

    try:
        mapi_broadcast_result, json_envelope_bytes = await post_mapi_transaction_broadcast_async(
            tx.to_bytes(), server_and_credential, peer_channel_callback)
    except ServerError as server_error:
        wallet_data.delete_mapi_broadcasts(broadcast_ids=[mapi_broadcast_row.broadcast_id])
        logger.error("Error broadcasting to mAPI for tx: %s. Error: %s",
            hash_to_hex_str(tx_hash), str(server_error))
        raise

    # TODO(1.4.0) MAPI. Need to consider downstream consequences of allowing
    #  'Transaction already known' failure state to continue as if it succeeded.
    if mapi_broadcast_result['returnResult'] == 'failure' and \
            mapi_broadcast_result['resultDescription'] != 'Transaction already known':
        logger.debug("Transaction broadcast via MAPI server failed : %s (%s)",
            server_and_credential.server.url, mapi_broadcast_result)
        return mapi_broadcast_result

    if mapi_broadcast_result['resultDescription'] == 'Transaction already known':
        logger.debug("Transaction was already known to the network - treating this as a "
                     "successful broadcast")

    logger.debug("Transaction broadcast via MAPI server succeeded: %s",
        server_and_credential.server.url)

    date_updated = int(time.time())
    updates = [(MAPIBroadcastFlag.BROADCAST, json_envelope_bytes, date_updated,
        mapi_broadcast_row.broadcast_id)]
    wallet_data.update_mapi_broadcasts(updates)

    # Todo - when the merkle proof callback is successfully processed,
    #  delete the MAPIBroadcastRow
    return mapi_broadcast_result


async def post_mapi_transaction_broadcast_async(transaction_bytes: bytes,
        server_and_credential: ServerAndCredential,
        peer_channel_callback: PeerChannelCallback | None = None) \
            -> tuple[MAPIBroadcastResponse, bytes]:
    """
    Do an HTTP POST delivering a transaction to a MAPI endpoint.

    This uses the `server` reference to track successful attempts for a given credential against
    the service.

    Raises `ServerError` if it connects but there is some other problem with the
        broadcast attempt.
    Raises `ServerConnectionError` if the server could not be connected to.
    Raises `BadServerError` if the response from the server is invalid in some way.
    """
    server, credential_id = server_and_credential
    server.api_key_state[credential_id].record_attempt()

    url = f"{server.url}tx"
    params = dict[str, str]()
    if peer_channel_callback is not None:
        params.update({
            'merkleProof': 'true' if peer_channel_callback.merkle_proof else 'false',
            'merkleFormat': "TSC",
            'dsCheck': 'true' if peer_channel_callback.double_spend_check else 'false',
            'callbackURL': peer_channel_callback.callback_url,
            'callbackToken': f"Bearer {peer_channel_callback.callback_access_token.access_token}",
            # 'callbackEncryption': None  # Todo: add libsodium encryption
        })
    headers = { "Content-Type": "application/octet-stream" }
    # This will not add an Authorization header if there are no credentials.
    headers.update(server.get_authorization_headers(credential_id))
    is_ssl = url.startswith("https")
    async with aiohttp.ClientSession() as client:
        async with client.post(url, ssl=is_ssl, headers=headers, params=params,
                data=transaction_bytes) as response:
            try:
                json_envelope_bytes = await response.read()
            except (ClientConnectorError, ConnectionError, OSError):
                logger.error("failed connecting to %s", url)
                raise ServerConnectionError("Unable to connect to the server.")
            else:
                if response.status != HTTPStatus.OK:
                    logger.error("Broadcast request to %s failed with: status: %s, reason: %s",
                        url, response.status, response.reason)
                    raise ServerError(f"Response was {response.status}: '{response.reason}'")

    try:
        broadcast_response_envelope = cast(JSONEnvelope, json.loads(json_envelope_bytes))
    except json.JSONDecodeError as json_error:
        logger.error("Broadcast request to %s has corrupt JSON envelope", url, exc_info=True)
        raise BadServerError("Unable to decode JSON envelope in MAPI response") from json_error

    try:
        validate_json_envelope(broadcast_response_envelope,  { "application/json" })
    except ValueError as value_error:
        raise BadServerError(value_error.args[0]) from value_error

    # This is recording getting a valid response from the server not the success of broadcasting.
    server.api_key_state[credential_id].record_success()

    try:
        broadcast_response = cast(MAPIBroadcastResponse,
            json.loads(broadcast_response_envelope['payload']))
    except json.JSONDecodeError as json_error:
        logger.error("Broadcast request to %s has corrupt broadcast response", url, exc_info=True)
        raise BadServerError("Unable to decode MAPI broadcast response") from json_error

    try:
        validate_mapi_broadcast_response(broadcast_response)
    except ValueError as mapi_error:
        raise BadServerError(f"Unable to validate MAPI response ({mapi_error.args[0]})")

    return broadcast_response, json_envelope_bytes

