# Open BSV License version 4
#
# Copyright (c) 2021,2022,2023 Bitcoin Association for BSV ("Bitcoin Association")
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
import base64
import binascii
from http import HTTPStatus
import json
from typing import Any, cast, TYPE_CHECKING, TypedDict
import urllib.parse

import aiohttp
from bitcoinx import base58_decode_check, base58_encode_check, Base58Error, DecryptionError, \
    PrivateKey, PublicKey
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3

from ..app_state import app_state
from ..constants import NetworkServerFlag, PeerChannelAccessTokenFlag, PeerChannelMessageFlag, \
    ServerPeerChannelFlag
from ..exceptions import ServerConnectionError
from ..i18n import _
from ..logs import logs
from ..wallet_database.types import ContactAddRow, ContactRow, PeerChannelAccessTokenRow, \
    PeerChannelMessageRow, ServerPeerChannelRow

from .exceptions import GeneralAPIError
from .general_api import create_peer_channel_locally_and_remotely_async
from .types import GenericPeerChannelMessage, ServerConnectionState

if TYPE_CHECKING:
    from ..wallet import Wallet, WalletDataAccess

logger = logs.get_logger("direct-connect")


class EnvelopeType:
    INVITATION_RESPONSE = "invitation-response"
    DIRECT_MESSAGE = "direct-message"


# The structure used for messages sent and received using direct connection message boxes.
class ConnectionEnvelopeDict(TypedDict):
    type: str
    payload: Any

def validate_connection_envelope(data: Any) -> bool:
    if not isinstance(data, dict) or set(data) != set(ConnectionEnvelopeDict.__annotations__):
        return False

    if not isinstance(data["type"], str):
        return False

    if not 0 < len(data["type"]) <= 30:
        return False

    return True


class ConnectionInvitationDict(TypedDict):
    name: str
    key: str
    url: str
    token: str

def validate_connection_invitation(data: Any) -> bool:
    if not isinstance(data, dict) or set(data) != set(ConnectionInvitationDict.__annotations__):
        return False

    # In the case of this object, all fields are strings.
    if not all(isinstance(field_value, str) for field_value in data.values()):
        return False

    if not 1 <= len(data["name"]) <= 40:
        return False

    if not len(data["key"]) == 33 * 2:
        return False

    if not 10 <= len(data["url"]) <= 200:
        return False

    if not 10 <= len(data["token"]) <= 100:
        return False

    try:
        PublicKey.from_hex(data["key"])
    except (ValueError, TypeError):
        return False

    parsed_url = urllib.parse.urlparse(data["url"])
    if parsed_url.scheme not in { "http", "https" }:
        return False

    return True


def validate_direct_message(data: Any) -> bool:
    if not isinstance(data, str):
        return False

    if not 0 < len(data) < 140:
        return False

    return True


def encode_invitation(name: str, key: str, url: str, token: str) -> str:
    payload_data: ConnectionInvitationDict = {
        "name": name,
        "key": key,
        "url": url,
        "token": token,
    }
    return cast(str, base58_encode_check(json.dumps(payload_data).encode()))

def decode_invitation(invitation_text: str) -> ConnectionInvitationDict | None:
    """
    Raises `TypeError` if the invitation text is not valid JSON.
    """
    # This should be enough for all the encoded fields.
    if len(invitation_text) > 550:
        return None

    try:
        invitation_bytes = cast(bytes, base58_decode_check(invitation_text))
    except (TypeError, Base58Error):
        return None

    try:
        invitation_data = json.loads(invitation_bytes.decode())
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
        return None

    if validate_connection_invitation(invitation_data):
        return cast(ConnectionInvitationDict, invitation_data)
    return None


async def create_peer_channel_for_contact_async(wallet: Wallet, contact_id: int) \
        -> tuple[ServerPeerChannelRow, PeerChannelAccessTokenRow]:
    """
    Via `create_peer_channel_locally_and_remotely_async`:
        Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
        Raises `ServerConnectionError` if the remote computer does not accept the connection.
    """
    server_state = wallet.get_connection_state_for_usage(NetworkServerFlag.USE_MESSAGE_BOX)
    assert server_state is not None

    # Create a remote peer channel and register it locally. We retain the ALLOCATING flag as we
    # do not consider it as in use until it is fully associated with the contact.
    peer_channel_row, writeonly_access_token, _discard = \
        await create_peer_channel_locally_and_remotely_async(server_state,
            ServerPeerChannelFlag.ALLOCATING | ServerPeerChannelFlag.PURPOSE_CONTACT_CONNECTION,
            PeerChannelAccessTokenFlag.FOR_CONTACT_CONNECTION)

    # Associate the peer channel as in use for direct connections with this contact. Removal of
    # the ALLOCATING flag ensures the peer channel is no longer considered unused/discarded.
    assert peer_channel_row.peer_channel_id is not None
    await wallet.data.update_contact_for_local_peer_channel_async(contact_id,
        peer_channel_row.peer_channel_id)

    logger.debug("Local peer channel %d created for contact %d", peer_channel_row.peer_channel_id,
        contact_id)

    return peer_channel_row, writeonly_access_token


async def import_contact_invitation_async(wallet: Wallet, preferred_name: str,
        invite_data: ConnectionInvitationDict) -> tuple[bool, str | None]:
    public_key_bytes = bytes.fromhex(invite_data["key"])
    contact_add_row = ContactAddRow(preferred_name, invite_data["url"], invite_data["token"],
        public_key_bytes)
    try:
        contact_rows = await wallet.data.create_contacts_async([ contact_add_row ])
    except sqlite3.IntegrityError:
        return False, _("This invitation has already been imported.")

    assert len(contact_rows) == 1
    contact_row = contact_rows[0]
    assert contact_row.contact_id is not None

    # At this point we have an unreciprocated invite recorded and we can retry if we fail.
    try:
        peer_channel_row, writeonly_access_token = await create_peer_channel_for_contact_async(
            wallet, contact_row.contact_id)
    except GeneralAPIError as exc:
        # Our message box server is connectable but refusing our requests. The caller can handle it.
        return False, \
            _("Your message box is not working as expected. Reason: {}").format(str(exc))
    except ServerConnectionError as exc:
        # Our message box server is not connectable. The can caller handle it.
        return False, _("Unable to connect to your message box server. Reason: {}").format(str(exc))
    else:
        # Update the cached row for the database update that took place.
        contact_row = contact_row._replace(local_peer_channel_id=peer_channel_row.peer_channel_id)

    # At this point we have a peer channel we have created and are monitoring to use to receive
    # messages from this contact. We want to post our reciprocal invite to the other party.
    assert peer_channel_row.remote_url is not None
    assert writeonly_access_token.access_token is not None
    identity_text = wallet._identity_public_key.to_hex(compressed=True)

    payload_data: ConnectionInvitationDict = {
        "name": "Unknown",
        "key": identity_text,
        "url": peer_channel_row.remote_url,
        "token": writeonly_access_token.access_token,
    }
    envelope_data: ConnectionEnvelopeDict = {
        "type": EnvelopeType.INVITATION_RESPONSE,
        "payload": payload_data,
    }

    contact_public_key = PublicKey.from_bytes(public_key_bytes)
    envelope_bytes = contact_public_key.encrypt_message(json.dumps(envelope_data))

    assert app_state.daemon.network is not None
    session = app_state.daemon.network.aiohttp_session
    server_url = contact_row.remote_peer_channel_url
    assert server_url is not None
    server_token = contact_row.remote_peer_channel_token
    assert server_token is not None
    headers = {
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {server_token}",
    }
    try:
        async with session.post(server_url, data=envelope_bytes, headers=headers) as response:
            if response.status != HTTPStatus.OK:
                # Either their message box does not exist or the access token is not good.
                return False, _("Their message box is not working as expected. "
                    "Code: {}, reason: {}").format(response.status, response.reason)
    except aiohttp.ClientError as exc:
        return False, \
            _("Unable to connect to their message box server. Reason: {}".format(str(exc)))

    return True, None


async def send_direct_message_to_contact_async(wallet_data: WalletDataAccess, contact_id: int,
        message_text: str) -> tuple[bool, str | None]:
    contact_rows = wallet_data.read_contacts([ contact_id ])
    assert len(contact_rows) == 1
    contact_row = contact_rows[0]

    assert contact_row.remote_peer_channel_url is not None
    assert contact_row.remote_peer_channel_token is not None
    assert contact_row.direct_identity_key_bytes is not None

    envelope_data: ConnectionEnvelopeDict = {
        "type": EnvelopeType.DIRECT_MESSAGE,
        "payload": message_text,
    }

    contact_public_key = PublicKey.from_bytes(contact_row.direct_identity_key_bytes)
    envelope_bytes = contact_public_key.encrypt_message(json.dumps(envelope_data))

    headers = {
        "Content-Type": "application/octet-stream",
        "Authorization": f"Bearer {contact_row.remote_peer_channel_token}",
    }
    assert app_state.daemon.network is not None
    session = app_state.daemon.network.aiohttp_session
    try:
        async with session.post(contact_row.remote_peer_channel_url, data=envelope_bytes,
                headers=headers) as response:
            if response.status != HTTPStatus.OK:
                # Either their message box does not exist or the access token is not good.
                return False, _("Their message box is not working as expected. "
                    "Code: {}, reason: {}").format(response.status, response.reason)
    except aiohttp.ClientError as exc:
        return False, \
            _("Unable to connect to their message box server. Reason: {}".format(str(exc)))

    return True, None


async def consume_contact_messages_async(state: ServerConnectionState) -> None:
    """
    Process messages received from contacts who we have a "direct connection" with.

    @ResilientConsumer: It is safe to cancel this task and resume it safely from where it left off.
    """
    assert state.wallet_data is not None

    message_entries: list[tuple[PeerChannelMessageRow, GenericPeerChannelMessage]] = []
    for message_row in await state.wallet_data.read_server_peer_channel_messages_async(
            state.server.server_id,
            PeerChannelMessageFlag.UNPROCESSED, PeerChannelMessageFlag.UNPROCESSED,
            ServerPeerChannelFlag.PURPOSE_CONTACT_CONNECTION,
            ServerPeerChannelFlag.MASK_PURPOSE):
        channel_message = cast(GenericPeerChannelMessage, json.loads(message_row.message_data))
        message_entries.append((message_row, channel_message))

    if len(message_entries) > 0:
        state.direct_connection_matches_queue.put_nowait(message_entries)

    assert state.wallet_proxy is not None
    credential_id = state.wallet_proxy.identity_private_key_credential_id
    while state.wallet_proxy.is_running():
        processed_message_ids: list[int] = []
        for message_row, channel_message in await state.direct_connection_matches_queue.get():
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
                channel_message_bytes_encrypted = base64.b64decode(channel_message["payload"])
            except binascii.Error:
                logger.error("Channel message %d payload not base64", message_row.message_id)
                continue

            try:
                channel_message_bytes = PrivateKey.from_hex(
                    app_state.credentials.get_indefinite_credential(credential_id)).decrypt_message(
                        channel_message_bytes_encrypted)
            except DecryptionError:
                logger.error("Undecryptable channel message %d payload", message_row.message_id)
                continue

            try:
                channel_message_object = json.loads(channel_message_bytes)
            except (json.JSONDecodeError, TypeError):
                logger.error("Channel message %d payload invalid JSON", message_row.message_id)
                continue

            if not validate_connection_envelope(channel_message_object):
                logger.error("Direct connection message %s invalid", message_row.message_id)
                continue

            initial_contact_row = state.wallet_data.read_contact_for_peer_channel(
                message_row.peer_channel_id)
            assert initial_contact_row is not None

            envelope = cast(ConnectionEnvelopeDict, channel_message_object)
            if EnvelopeType.INVITATION_RESPONSE == envelope["type"]:
                # Duplicate messages of this type are handled internally.
                contact_row = await _process_invitation_response_async(state, initial_contact_row,
                    envelope["payload"])
            elif initial_contact_row.direct_identity_key_bytes is None:
                # Do not accept other messages unless we have processed their connection response.
                logger.error("SKIP MESSAGE NO INVITE RESPONSE YET")
                pass
            elif EnvelopeType.DIRECT_MESSAGE == envelope["type"]:
                await _process_direct_message_async(state, initial_contact_row, envelope["payload"])
            else:
                logger.error("SKIP MESSAGE NOT IMPLEMENTED")
                pass

        logger.debug("Marking %d contact messages processed", len(processed_message_ids))
        await state.wallet_data.update_server_peer_channel_message_flags_async(
            processed_message_ids)


async def _process_invitation_response_async(state: ServerConnectionState, contact_row: ContactRow,
        raw_object: Any) -> ContactRow | None:
    assert state.wallet_data is not None
    assert contact_row.contact_id is not None

    if contact_row.direct_identity_key_bytes is not None:
        logger.error("Already had a contact invitation response: %s", raw_object)
        return None

    if not validate_connection_invitation(raw_object):
        logger.error("Invalid contact invitation response: %s", raw_object)
        return None

    invitation = cast(ConnectionInvitationDict, raw_object)
    public_key_bytes = bytes.fromhex(invitation["key"])
    try:
        await state.wallet_data.update_contact_for_invitation_response_async(contact_row.contact_id,
            invitation["name"], invitation["url"], invitation["token"], public_key_bytes)
    except sqlite3.IntegrityError:
        # The unique constraint on the Contacts table indicates the identity public key is in use.
        logger.error("Contact invitation response identity key in use: %s", invitation["key"])
        return None
    logger.debug("Processed invitation response for %d:'%s'", contact_row.contact_id,
        invitation["name"])

    return contact_row._replace(direct_declared_name=invitation["name"],
        remote_peer_channel_url=invitation["url"], remote_peer_channel_token=invitation["token"],
        direct_identity_key_bytes=public_key_bytes)


async def _process_direct_message_async(state: ServerConnectionState, contact_row: ContactRow,
        raw_object: Any) -> ContactRow | None:
    assert state.wallet_proxy is not None

    if not validate_direct_message(raw_object):
        return None

    message_text = cast(str, raw_object)

    try:
        app_state.app_qt
    except AssertionError: # Not the GUI.
        logger.debug("Direct message, %s: %s", contact_row.contact_name, message_text)
        return None

    window = app_state.app_qt.get_wallet_window_by_id(state.wallet_proxy.get_id())
    assert window is not None
    window.direct_message_received_signal.emit(contact_row.contact_id, message_text)

    return None
