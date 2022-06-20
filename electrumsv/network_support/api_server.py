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
import datetime
import json
import dateutil.parser
import dataclasses
import os
from typing import cast, Dict, List, NamedTuple, Optional, TypedDict, TYPE_CHECKING

from ..app_state import app_state
from ..constants import NetworkServerFlag, NetworkServerType, PeerChannelAccessTokenFlag, \
    ServerCapability, ServerPeerChannelFlag
from ..exceptions import BroadcastFailedError
from ..i18n import _
from ..logs import logs
from ..transaction import Transaction
from ..types import IndefiniteCredentialId, ServerAccountKey, TransactionFeeEstimator, \
    TransactionSize
from ..util import get_posix_timestamp
from ..wallet_database.types import MAPIBroadcastCallbackRow, MapiBroadcastStatusFlags, \
    NetworkServerRow

from .types import BroadcastResponse, JSONEnvelope, FeeQuote
from .mapi import broadcast_transaction_mapi_simple, filter_mapi_servers_for_fee_quote, \
    MAPIFeeEstimator, get_mapi_servers, poll_servers_async


if TYPE_CHECKING:
    from ..network import Network
    from ..wallet import AbstractAccount

__all__ = [ "NewServerAccessState", "NewServer" ]


STALE_PERIOD_SECONDS = 60 * 60 * 24
ONE_DAY = 24 * 3600

logger = logs.get_logger("api-server")


class APIServerDefinition(TypedDict):
    id: int
    url: str
    type: str
    api_key: str
    api_key_template: str
    api_key_required: bool
    api_key_supported: bool
    enabled_for_all_accounts: bool
    capabilities: List[str]
    static_data_date: str
    # MAPI
    anonymous_fee_quote: Optional[JSONEnvelope]


@dataclasses.dataclass
class CapabilitySupport:
    name: str
    type: ServerCapability
    is_unsupported: bool=False
    can_disable: bool=False


# TODO(1.4.0) Networking. This kind of overrides the api server configurations, which kind of
#     also should be replaced by the endpoints API results for each server. We should get rid of
#     this, or use it for `MERCHANT_API` and other server types that do not have an 'endpoints'
#     endpoint.
SERVER_CAPABILITIES = {
    NetworkServerType.GENERAL: [
        CapabilitySupport(_("Account restoration"), ServerCapability.RESTORATION),
        CapabilitySupport(_("Arbitrary proof requests"), ServerCapability.MERKLE_PROOF_REQUEST),
        CapabilitySupport(_("Arbitrary transaction requests"),
            ServerCapability.TRANSACTION_REQUEST),
        CapabilitySupport(_("Output spend notifications"), ServerCapability.OUTPUT_SPENDS),
        CapabilitySupport(_("Peer channels"), ServerCapability.PEER_CHANNELS),
        CapabilitySupport(_("Tip filter"), ServerCapability.TIP_FILTER),
    ],
    NetworkServerType.MERCHANT_API: [
        CapabilitySupport(_("Transaction broadcast"), ServerCapability.TRANSACTION_BROADCAST,
            can_disable=True),
        CapabilitySupport(_("Transaction fee quotes"), ServerCapability.FEE_QUOTE),
        CapabilitySupport(_("Transaction proofs"), ServerCapability.MERKLE_PROOF_NOTIFICATION,
            is_unsupported=True),
    ],
}


# TODO(1.4.0) MAPI management, issue#910. Fee quotes should not be done here, they should already
#     have been done in the wallet code and the send view UI should obtain them and factor them
#     into the transaction creation and knowing which MAPI server we are going to use. If there
#     is only one MAPI server, i.e. Gorilla pool, because Mempool and TAAL require API keys.. ???
#     then that makes the decision easy.
# TODO(1.4.0) MAPI management, issue#910. Refactor this to use the `WalletDataAccess` instance for
#     the wallet, and not use private variables on the account.
async def broadcast_transaction(tx: Transaction, network: Network,
        account: "AbstractAccount", merkle_proof: bool = False, ds_check: bool = False) \
            -> BroadcastResponse:
    """This is the top-level broadcasting function and it automates a number of things.
    Polling the mAPI servers (if need be). Prioritisation of mAPI servers; Creating a new peer
    channel using the best available ESVReferenceServer; Ensuring there is a record of attempted
    broadcast & success or failure in MAPIBroadcastCallbacks; And finally, broadcasting via the
    selected merchant API server

    Raises `ServiceUnavailableError` if it cannot connect to the merchant API server
    Raises `BroadcastFailedError` if it connects but there is some other problem with the
        broadcast attempt.
    """
    server_entries = get_mapi_servers(account)
    if len(server_entries) != 0:
        await poll_servers_async(server_entries)

    account_id = account.get_id()
    selection_candidates = account._wallet.get_servers_for_account_id(account_id,
        NetworkServerType.MERCHANT_API)
    candidates_with_fee_quotes = filter_mapi_servers_for_fee_quote(selection_candidates)
    broadcast_servers: list[BroadcastCandidate] = prioritise_broadcast_servers(
        TransactionSize(tx.size()), candidates_with_fee_quotes)

    # Select the best ranked broadcast server
    broadcast_server = broadcast_servers[0]

    state = account._wallet.get_server_state_for_capability(ServerCapability.PEER_CHANNELS)
    assert state is not None
    assert state.wallet_data is not None

    from .general_api import create_peer_channel_locally_and_remotely_async

    peer_channel_row, mapi_callback_access_token = \
        await create_peer_channel_locally_and_remotely_async(
            state, ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK,
            PeerChannelAccessTokenFlag.FOR_MAPI_CALLBACK_USAGE)
    assert peer_channel_row.remote_channel_id is not None
    assert peer_channel_row.remote_url is not None

    mapi_callback_row = MAPIBroadcastCallbackRow(
        tx_hash=tx.hash(),
        peer_channel_id=peer_channel_row.remote_channel_id,
        broadcast_date=datetime.datetime.utcnow().isoformat(),
        encrypted_private_key=os.urandom(64),  # libsodium encryption not implemented yet
        server_id=state.server.server_id,
        status_flags=MapiBroadcastStatusFlags.ATTEMPTING
    )
    await account._wallet.data.create_mapi_broadcast_callbacks_async([mapi_callback_row])

    try:
        result = await broadcast_transaction_mapi_simple(tx.to_bytes(),
            broadcast_server.server, broadcast_server.credential_id, peer_channel_row.remote_url,
            mapi_callback_access_token, merkle_proof, ds_check)
    except BroadcastFailedError as e:
        account._wallet.data.delete_mapi_broadcast_callbacks(tx_hashes=[tx.hash()])
        logger.error("Error broadcasting to mAPI for tx: %s. Error: %s", tx.txid(), str(e))
        raise

    updates = [(MapiBroadcastStatusFlags.SUCCEEDED, tx.hash())]
    account._wallet.data.update_mapi_broadcast_callbacks(updates)
    # Todo - when the merkle proof callback is successfully processed,
    #  delete the MAPIBroadcastCallbackRow
    return result


DEFAULT_API_KEY_TEMPLATE = "Authorization: Bearer {API_KEY}"

class NewServerAccessState:
    """ The state for each URL/api key combination used by the application. """

    def __init__(self) -> None:
        self.last_try = 0.
        self.last_good = 0.

        ## MAPI state.
        # JSON envelope for the actual serialised fee quote JSON.
        self.last_fee_quote_response: Optional[JSONEnvelope] = None
        # The fee quote we locally extracted and deserialised from the fee quote response.
        self.last_fee_quote: Optional[FeeQuote] = None

        # TODO(1.4.0) Servers, issue#905. WRT observing blacklisting and retry delays.
        #     Not currently used.
        self.retry_delay = 0
        self.last_blacklisted = 0.
        self.is_disabled = False

    def __repr__(self) -> str:
        return f"NewServerAccessState(last_try={self.last_try} last_good={self.last_good} " \
               f"last_fee_quote={self.last_fee_quote})"

    def record_attempt(self) -> None:
        self.last_try = datetime.datetime.now(datetime.timezone.utc).timestamp()

    def record_success(self) -> None:
        self.last_good = datetime.datetime.now(datetime.timezone.utc).timestamp()

    def can_retry(self, now: float) -> bool:
        return not self.is_disabled and not self.is_blacklisted(now) and \
            self.last_try + self.retry_delay < now

    def is_blacklisted(self, now: float) -> bool:
        return self.last_blacklisted > now - ONE_DAY

    def update_fee_quote(self, fee_response: JSONEnvelope) -> None:
        """
        Put in place a new fee quote received from just completed server usage.
        """
        timestamp = datetime.datetime.now(datetime.timezone.utc).timestamp()
        self.set_fee_quote(fee_response, timestamp)

    def set_fee_quote(self, fee_response: Optional[JSONEnvelope], timestamp: float) -> None:
        """
        Set the values for any existing (restored from DB) or new fee quote.
        """
        # Remember that we store server state in wallet databases when the server is associated
        # either with that wallet, or with accounts within it, and we may get stale state or
        # later state from a loaded wallet.
        if timestamp < self.last_good:
            return
        self.last_good = timestamp
        self.last_fee_quote_response = fee_response
        self.last_fee_quote = None
        if fee_response:
            self.last_fee_quote = cast(FeeQuote, json.loads(fee_response['payload']))


class NewServer:
    def __init__(self, url: str, server_type: NetworkServerType, row: NetworkServerRow,
            credential_id: Optional[IndefiniteCredentialId]) -> None:
        self.key = ServerAccountKey(url, server_type, None)
        # All code that uses the URL expects a trailing slash.
        assert url.endswith("/")
        self.url = url
        self.server_type = server_type
        assert row.server_id is not None
        self.server_id = row.server_id

        # These are the enabled clients, whether they use an API key and the id if so.
        self.client_api_keys = dict[Optional[int], Optional[IndefiniteCredentialId]]()
        self.database_rows = dict[Optional[int], NetworkServerRow]()
        # We keep per-API key state for a reason. An API key can be considered to be a distinct
        # account with the service, and it makes sense to keep the statistics/metadata for the
        # service separated by API key for this reason. We intentionally leave these in place
        # at least for now as they are kind of relative to the given key value.
        self.api_key_state = dict[Optional[IndefiniteCredentialId], NewServerAccessState]()

        self.set_server_account_usage(row, credential_id)

    def get_account_ids(self) -> list[Optional[int]]:
        return list(self.client_api_keys)

    def set_server_account_usage(self, server_row: NetworkServerRow,
            credential_id: Optional[IndefiniteCredentialId]) -> None:
        """
        Prime the server with the given account-related state.

        This may override the common state for a credential, like when it was last tried,
        when it was last successfully used or the last fee quote received based on what is the
        latest usable state.
        """
        self.client_api_keys[server_row.account_id] = credential_id
        self.database_rows[server_row.account_id] = server_row

        if credential_id not in self.api_key_state:
            self.api_key_state[credential_id] = NewServerAccessState()
        key_state = self.api_key_state[credential_id]

        if server_row.date_last_good > key_state.last_good:
            key_state.last_try = max(key_state.last_try, server_row.date_last_try)
            # Fee quote state is only relevant for MAPI.
            if self.server_type == NetworkServerType.MERCHANT_API:
                fee_response: Optional[JSONEnvelope] = None
                if server_row.mapi_fee_quote_json:
                    fee_response = cast(JSONEnvelope, json.loads(server_row.mapi_fee_quote_json))
                key_state.set_fee_quote(fee_response, server_row.date_last_good)

    def clear_server_account_usage(self, specific_server_key: ServerAccountKey) -> None:
        del self.client_api_keys[specific_server_key.account_id]
        del self.database_rows[specific_server_key.account_id]

    def to_updated_rows(self) -> List[NetworkServerRow]:
        """
        We return the updated state for each registered server/account as of the current time for
        the caller to presumably persist. We only update the metadata, not the fields the user
        edits like the api key related values.
        """
        date_updated = get_posix_timestamp()
        results: List[NetworkServerRow] = []
        for account_id, credential_id in list(self.client_api_keys.items()):
            server_row = self.database_rows[account_id]
            key_state = self.api_key_state[credential_id]

            mapi_fee_quote_json: Optional[str] = None
            if self.server_type == NetworkServerType.MERCHANT_API:
                if key_state.last_fee_quote_response:
                    mapi_fee_quote_json = json.dumps(key_state.last_fee_quote_response)
            else:
                assert key_state.last_fee_quote_response is None

            updated_row = server_row._replace(mapi_fee_quote_json=mapi_fee_quote_json,
                date_last_try=int(key_state.last_try), date_last_good=int(key_state.last_good),
                date_updated=date_updated)
            results.append(updated_row)
        return results

    def is_unusable(self) -> bool:
        """
        Whether the given server is configured to be unusable by anything.
        """
        if len(self.client_api_keys) == 0:
            return True
        return False

    def is_unused(self) -> bool:
        """ An API server is considered unused if it is not a globally stored one (if it were it
            would have a config object) and it no longer has any loaded wallets using it. """
        return len(self.client_api_keys) == 0

    def get_tip_filter_peer_channel_id(self, account_id: int) -> Optional[int]:
        row = self.database_rows.get(account_id)
        if row is None:
            row = self.database_rows[None]
        return row.tip_filter_peer_channel_id

    def set_tip_filter_peer_channel_id(self, account_id: int, peer_channel_id: int) -> None:
        key: Optional[int] = account_id
        if account_id not in self.database_rows:
            key = None
        self.database_rows[key] = self.database_rows[key]._replace(
            tip_filter_peer_channel_id=peer_channel_id)

    def should_request_fee_quote(self, credential_id: Optional[IndefiniteCredentialId]) -> bool:
        """
        Work out if we have a valid fee quote, and if not whether we can get one.
        """
        row = self.database_rows[None]
        if row.server_flags & NetworkServerFlag.API_KEY_REQUIRED and credential_id is None:
            return False

        key_state = self.api_key_state[credential_id]
        if key_state.last_fee_quote is None:
            return True

        now_date = datetime.datetime.now(datetime.timezone.utc)
        # Last I looked I had fee quotes with expiry times of two minutes, we cannot rely on
        # the expiry date being a usable value. So for now we ignore it and assume that it
        # will be enough to just refresh the fee quote around once a day in a haphazard way.
        if False:
            expiry_date = dateutil.parser.isoparse(key_state.last_fee_quote["expiryTime"])
            return now_date > expiry_date

        retrieved_date = dateutil.parser.isoparse(key_state.last_fee_quote["timestamp"])
        return (now_date - retrieved_date).total_seconds() > STALE_PERIOD_SECONDS

    def get_credential_id(self, account_id: Optional[int]) \
            -> tuple[bool, Optional[IndefiniteCredentialId]]:
        """
        Indicate whether the given client can use this server.

        Returns a flag and an optional credential id. The flag indicates whether the client can
        use the given server, and the credential id which can be `None` for no credential.
        """
        # Look up the account.
        if account_id in self.client_api_keys:
            return True, self.client_api_keys[account_id]

        # Look up the account's wallet as the first fallback.
        if None in self.client_api_keys:
            return True, self.client_api_keys[None]

        # This client is not configured to use this server.
        return False, None

    def get_authorization_headers(self, credential_id: Optional[IndefiniteCredentialId]) \
            -> Dict[str, str]:
        if credential_id is None:
            return {}

        decrypted_api_key = app_state.credentials.get_indefinite_credential(credential_id)
        api_key_template = self.database_rows[None].api_key_template
        if api_key_template is not None:
            authorization_header = api_key_template
        else:
            authorization_header = DEFAULT_API_KEY_TEMPLATE
        header_key, _separator, header_value = authorization_header.partition(": ")
        return { header_key: header_value.format(API_KEY=decrypted_api_key) }

    def __repr__(self) -> str:
        return f"NewServer(server_id={self.server_id}, url={self.url} " \
            f"server_type={self.server_type})"


class SelectionCandidate(NamedTuple):
    server_type: NetworkServerType
    credential_id: Optional[IndefiniteCredentialId]
    api_server: Optional[NewServer] = None


class BroadcastCandidate(NamedTuple):
    server: NewServer
    credential_id: Optional[IndefiniteCredentialId]
    estimator: TransactionFeeEstimator
    # Can the calling logic switch servers if they have the same initial fee? Not sure.
    initial_fee: int


def prioritise_broadcast_servers(estimated_tx_size: TransactionSize,
        server_candidates: list[tuple[NewServer, Optional[IndefiniteCredentialId]]]) \
            -> List[BroadcastCandidate]:
    """
    Prioritise the provided servers based on the base fee they would charge for the transaction.

    The transaction at this point might be complete, or it might be incomplete and pending
    server selection and application of the server's fee rate in it's finalisation.

    estimated_tx_size: The incomplete base transaction size or complete transaction size.
    servers: The list of server candidates known to support the transaction broadcast capability.

    Returns the ordered list of server candidates based on lowest to highest estimated fee for
      a transaction of the given size.
    """
    candidates: List[BroadcastCandidate] = []
    fee_estimator: TransactionFeeEstimator
    for server, credential_id in server_candidates:
        if server.server_type == NetworkServerType.MERCHANT_API:
            key_state = server.api_key_state[credential_id]
            assert key_state.last_fee_quote is not None
            estimator = MAPIFeeEstimator(key_state.last_fee_quote)
            fee_estimator = estimator.estimate_fee
        else:
            raise NotImplementedError(f"Unsupported server type {server.server_type}")
        initial_fee = fee_estimator(estimated_tx_size)
        candidates.append(BroadcastCandidate(server, credential_id, fee_estimator, initial_fee))
    candidates.sort(key=lambda entry: entry.initial_fee)
    return candidates
