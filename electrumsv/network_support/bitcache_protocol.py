# MIT License
#
# Copyright © 2023 rt121212121
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

from __future__ import annotations
import asyncio, base64, binascii, io, json, random
from typing import cast, TYPE_CHECKING

from bitcoinx import hash_to_hex_str

from ..constants import BitcacheTxFlag, NetworkServerFlag, PeerChannelAccessTokenFlag, \
    ChannelMessageFlag, ChannelFlag, TokenPermissions, TxFlag
from ..exceptions import ServerConnectionError
from ..logs import logs
from ..standards.bitcache import BitcacheMessage, BitcacheTxoKeyUsage, \
    read_bitcache_message, write_bitcache_transaction_message
from ..transaction import Transaction
from ..wallet_database.types import PeerChannelAccessTokenRow, PeerChannelMessageRow, \
    ServerPeerChannelRow

from .exceptions import GeneralAPIError
from .general_api import create_peer_channel_locally_and_remotely_async
from .peer_channel import create_peer_channel_message_binary_async, \
    read_peer_channel_metadata_async
from .types import BitcacheProducerState, GenericPeerChannelMessage, PeerChannelServerState, \
    ServerConnectionState, ServerStateProtocol

if TYPE_CHECKING:
    from ..wallet import Wallet

logger = logs.get_logger("bitcache")


async def create_peer_channel_for_bitcache_async(wallet: Wallet, account_id: int) \
        -> tuple[ServerPeerChannelRow, PeerChannelAccessTokenRow]:
    """
    Via `create_peer_channel_locally_and_remotely_async`:
        Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
        Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_state = wallet.get_connection_state_for_usage(NetworkServerFlag.USE_MESSAGE_BOX)
    assert server_state is not None
    account = wallet.get_account(account_id)
    assert account is not None

    # Create a remote peer channel and register it locally. We retain the ALLOCATING flag as we
    # do not consider it as in use until it is fully associated with the contact.
    channel_row, writeonly_access_token, _discard = \
        await create_peer_channel_locally_and_remotely_async(server_state,
            ChannelFlag.ALLOCATING | ChannelFlag.PURPOSE_BITCACHE,
            PeerChannelAccessTokenFlag.FOR_BITCACHE)

    # Associate the peer channel as in use for direct connections with this contact. Removal of
    # the ALLOCATING flag ensures the peer channel is no longer considered unused/discarded.
    await account.set_bitcache_peer_channel_id_async(channel_row=channel_row)
    logger.debug("Local peer channel %d created for account %d", channel_row.peer_channel_id,
        account_id)

    return channel_row, writeonly_access_token


async def add_external_bitcache_connection_async(wallet: Wallet, account_id: int, channel_url: str,
        access_token: str) -> None:
    """
    This verifies that the bitcache exists and can be accessed, and obtains any channel metadata
    whether channel-specific or relating to the access token.

    Via `read_peer_channel_max_sequence_async`:
        Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
        Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    assert wallet._network is not None
    account = wallet.get_account(account_id)
    assert account is not None
    # Verify the server is connectable, the channel exists and is accessible.
    # On failure `GeneralAPIError` and `ServerConnectionError` raise up to the caller.
    metadata = await read_peer_channel_metadata_async(wallet._network.aiohttp_session, channel_url,
        access_token)
    permissions = TokenPermissions.READ_ACCESS | TokenPermissions.WRITE_ACCESS \
        if metadata.flags_text == "rw" else TokenPermissions.READ_ACCESS
    channel_row = await wallet.data.create_external_peer_channel_async(channel_url,
        ChannelFlag.PURPOSE_BITCACHE, access_token, permissions)
    await account.set_bitcache_peer_channel_id_async(external_channel_row=channel_row)


async def consume_bitcache_messages_async(state: ServerStateProtocol) -> None:
    """
    Process messages received from bitcache channels we are set up to monitor.

    @ResilientConsumer: It is safe to cancel this task and resume it safely from where it left off.
    """
    assert state.wallet_data is not None

    message_entries: list[tuple[PeerChannelMessageRow, GenericPeerChannelMessage]] = []
    if state.is_external:
        # This is attached to a per-external peer channel web socket connection.
        e_state = cast(PeerChannelServerState, state)
        message_rows = state.wallet_data.read_external_peer_channel_messages(
            cast(int, e_state.external_channel_row.peer_channel_id),
            ChannelMessageFlag.UNPROCESSED, ChannelMessageFlag.UNPROCESSED,
            ChannelFlag.PURPOSE_BITCACHE, ChannelFlag.PURPOSE_BITCACHE)
    else:
        # Singleton task for all Bitcache-related peer channels for the server.
        s_state = cast(ServerConnectionState, state)
        message_rows = state.wallet_data.read_server_peer_channel_messages(s_state.server.server_id,
            ChannelMessageFlag.UNPROCESSED, ChannelMessageFlag.UNPROCESSED,
            ChannelFlag.PURPOSE_BITCACHE, ChannelFlag.PURPOSE_BITCACHE)
    for message_row in message_rows:
        channel_message = cast(GenericPeerChannelMessage, json.loads(message_row.message_data))
        message_entries.append((message_row, channel_message))

    if len(message_entries) > 0:
        state.bitcache_matches_queue.put_nowait(message_entries)

    assert state.wallet_proxy is not None
    while state.wallet_proxy.is_running():
        processed_message_ids: list[int] = []
        for message_row, channel_message in await state.bitcache_matches_queue.get():
            assert message_row.message_id is not None
            processed_message_ids.append(message_row.message_id)

            if not isinstance(channel_message["payload"], str):
                # TODO(1.4.0) Unreliable server, issue#841. WRT tip filter match, show user.
                logger.error("Peer channel payload not string: '%s'", channel_message)
                continue

            # NOTE(rt) The reference server implementation stores raw data posted to channels
            #     as bytes, and when returning it to a caller encodes it in base64. It doesn't
            #     matter if it was bytes or json.
            try:
                channel_message_bytes = base64.b64decode(channel_message["payload"])
            except binascii.Error:
                logger.error("Channel message %d payload not base64", message_row.message_id)
                continue
            if state.is_external:
                account_id = state.wallet_data.read_account_id_for_bitcache_peer_channel_id(
                    local_id=message_row.peer_channel_id)
            else:
                account_id = state.wallet_data.read_account_id_for_bitcache_peer_channel_id(
                    external_id=message_row.peer_channel_id)
            assert account_id is not None, "Application completely broken, bitcache account unknown"
            account = state.wallet_proxy.get_account(account_id)
            assert account is not None, "Application completely broken, bitcache account missing"

            # TODO(1.4.0) Bitcache. Catch parsing exceptions. Skip this tx or abandon bitcache?
            stream = io.BytesIO(channel_message_bytes)
            message = read_bitcache_message(stream)
            tx = Transaction.from_bytes(message.tx_data)
            tx_hash = tx.hash()
            pass


            if False:
                def transaction_import_callback(message: str) -> None:
                    nonlocal tx
                    # TODO(1.4.0) Bitcache. Do something with the error handling.
                    print(f"Unhandled error importing bitcache transaction {message}")
                state.wallet_proxy.import_transaction_with_error_callback(tx, TxFlag.STATE_RECEIVED,
                    transaction_import_callback)

        logger.debug("Marking %d bitcache messages processed", len(processed_message_ids))
        await state.wallet_data.update_server_peer_channel_message_flags_async(
            processed_message_ids)

async def produce_bitcache_messages_async(server_state: ServerStateProtocol,
        producer_state: BitcacheProducerState) -> None:
    assert server_state.wallet_proxy is not None
    account_id = producer_state.account_id
    logger.debug("Entering bitcache[%d] loop", account_id)
    fail_count = 0
    wallet_data = server_state.wallet_proxy.data
    while server_state.wallet_proxy.is_running():
        match = wallet_data.read_next_unsynced_bitcache_transaction(account_id)
        if match is None: # We are caught up and waiting for newly created transactions.
            logger.debug("Stalling bitcache[%d] loop", account_id)
            await producer_state.event.wait()
            producer_state.event.clear()
            match = wallet_data.read_next_unsynced_bitcache_transaction(account_id)
        assert match is not None

        account = server_state.wallet_proxy.get_account(account_id)
        assert account is not None
        key_fingerprint = account.get_fingerprint()
        account_row = account.get_row()
        access_token: str; channel_url: str
        if account_row.bitcache_peer_channel_id is not None:
            channel_id = account_row.bitcache_peer_channel_id
            channel_rows1 = wallet_data.read_server_peer_channels(channel_id=channel_id,
                flags=ChannelFlag.NONE, mask=ChannelFlag.DEACTIVATED)
            if len(channel_rows1) != 1:
                logger.debug("Bitcache[%d] loop exiting (no server channel)", account_id)
                return
            token_rows = wallet_data.read_server_peer_channel_access_tokens(channel_id,
                PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE,
                PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE)
            if not token_rows:
                logger.debug("Bitcache[%d] loop exiting (no token)", account_id)
                return
            access_token = token_rows[0].access_token
            channel_url = cast(str, channel_rows1[0].remote_url)
        elif account_row.external_bitcache_peer_channel_id is not None:
            channel_id = account_row.external_bitcache_peer_channel_id
            channel_rows2 = wallet_data.read_external_peer_channels(peer_channel_id=channel_id,
                flags=ChannelFlag.NONE, mask=ChannelFlag.DEACTIVATED)
            if len(channel_rows2) != 1:
                logger.debug("Bitcache[%d] loop exiting (no external channel)", account_id)
                return
            access_token = channel_rows2[0].access_token
            channel_url = channel_rows2[0].remote_url
        else:
            logger.error("Bitcache[%d] loop exiting (no valid channel)", account_id)
            return

        stream = io.BytesIO()
        message = BitcacheMessage(match.tx_data, [])
        for key_row in match.key_data:
            assert key_row.masterkey_id == account.get_masterkey_id()
            message.key_data.append(BitcacheTxoKeyUsage(key_row.txo_index, key_row.script_type,
                key_fingerprint, key_row.derivation_type, cast(bytes, key_row.derivation_data2)))
        write_bitcache_transaction_message(stream, message)
        payload_bytes = stream.getbuffer()
        try:
            result = await create_peer_channel_message_binary_async(server_state.session,
                channel_url, access_token, payload_bytes)
        except ServerConnectionError as exc1:   # Connection not accepted.
            fail_count += 1
            logger.error("Bitcache[%d] loop connection not accepted (%s)", account_id, exc1.args[0])
        except GeneralAPIError as exc2:         # Connected but request not successful
            fail_count += 1
            logger.error("Bitcache[%d] loop request not successful (%s)", account_id, exc2.args[0])
        else:
            fail_count = 0
            await wallet_data.create_bitcache_sync_entry_async(account_id,
                match.tx_hash, BitcacheTxFlag.SENT, result["sequence"])
            logger.debug("Bitcache[%d] loop tx sent hash=%s, sequence=%d", account_id,
                hash_to_hex_str(match.tx_hash)[:8], result["sequence"])
            await asyncio.sleep(random.random()) # Avoid hammering the server?
        if fail_count:
            logger.debug("Bitcache[%d] loop sleeping for %d seconds", account_id,
                delay:=min(fail_count,25)**2)
            await asyncio.sleep(delay)
