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
import dataclasses
import datetime
import json
import random
import logging
from typing import cast, Dict, List, NamedTuple, Optional, Tuple, TypedDict, TYPE_CHECKING

import dateutil.parser

from .esv_client import PeerChannel, ESVClient, REGTEST_MASTER_TOKEN
from ..app_state import app_state
from ..constants import NetworkServerType, ServerCapability, TOKEN_PASSWORD
from ..crypto import pw_decode
from ..exceptions import ServiceUnavailableException
from ..i18n import _
from ..types import IndefiniteCredentialId, NetworkServerState, ServerAccountKey, \
    TransactionFeeEstimator, TransactionSize

from .mapi import JSONEnvelope, FeeQuote, MAPIFeeEstimator, BroadcastResponse, get_mapi_servers, \
    poll_servers_async, broadcast_transaction_mapi_simple

if TYPE_CHECKING:
    from ..network import SVServer, Network
    from ..wallet import AbstractAccount
    from ..transaction import Transaction

__all__ = [ "NewServerAPIContext", "NewServerAccessState", "NewServer" ]


STALE_PERIOD_SECONDS = 60 * 60 * 24

logger = logging.getLogger("api-server")


class APIServerDefinition(TypedDict):
    id: int
    url: str
    type: str
    api_key: str
    api_key_required: bool
    api_key_supported: bool
    enabled_for_all_wallets: bool
    last_good: float
    last_try: float
    capabilities: List[str]
    static_data_date: str
    modified_date: str
    # MAPI
    anonymous_fee_quote: Optional[JSONEnvelope]


@dataclasses.dataclass
class CapabilitySupport:
    name: str
    type: ServerCapability
    is_unsupported: bool=False
    can_disable: bool=False


SERVER_CAPABILITIES = {
    NetworkServerType.GENERAL: [
        CapabilitySupport(_("Account restoration"), ServerCapability.RESTORATION),
        CapabilitySupport(_("Arbitrary proof requests"), ServerCapability.MERKLE_PROOF_REQUEST),
        CapabilitySupport(_("Arbitrary transaction requests"),
            ServerCapability.TRANSACTION_REQUEST),
    ],
    NetworkServerType.MERCHANT_API: [
        CapabilitySupport(_("Transaction broadcast"), ServerCapability.TRANSACTION_BROADCAST,
            can_disable=True),
        CapabilitySupport(_("Transaction fee quotes"), ServerCapability.FEE_QUOTE),
        CapabilitySupport(_("Transaction proofs"), ServerCapability.MERKLE_PROOF_NOTIFICATION,
            is_unsupported=True),
    ],
    NetworkServerType.ELECTRUMX: [
        CapabilitySupport(_("Blockchain scanning"), ServerCapability.SCRIPTHASH_HISTORY),
        CapabilitySupport(_("Transaction broadcast"), ServerCapability.TRANSACTION_BROADCAST),
        CapabilitySupport(_("Transaction proofs"), ServerCapability.MERKLE_PROOF_REQUEST),
    ]
}


async def broadcast_transaction(tx: "Transaction", network: "Network",
        account: "AbstractAccount", merkle_proof: bool = False, ds_check: bool = False) \
            -> BroadcastResponse:
    """This is the top-level broadcasting function which automates a number of things:
        - polling the mAPI servers (if need be)
        - prioritisation of mAPI servers
        - creating a new peer channel using the best available ESVReferenceServer
        - ensuring there is a record of attempted broadcast & success or failure in
        MAPIBroadcastCallbacks.
        - finally, broadcasting through mAPI
    """
    server_entries = get_mapi_servers(network, account)
    if len(server_entries) != 0:
        await poll_servers_async(server_entries)

    selection_candidates = network.get_api_servers_for_account(account,
        NetworkServerType.MERCHANT_API)

    broadcast_servers: list[BroadcastCandidate] = prioritise_broadcast_servers(
        TransactionSize(tx.size()), selection_candidates)
    if len(broadcast_servers) == 0:
        raise ServiceUnavailableException("There are no suitable broadcast servers available")

    # Select the best ranked broadcast server
    broadcast_server = broadcast_servers[0]

    peer_channel: Optional[PeerChannel] = None  # Only working on RegTest at present
    if app_state.config.get('regtest'):
        selection_candidates = network.get_api_servers_for_account(account,
            NetworkServerType.GENERAL)

        esv_reference_servers = select_servers(ServerCapability.PEER_CHANNELS, selection_candidates)
        esv_reference_server = esv_reference_servers[0]  # Todo - prioritise properly
        aiohttp_client = await network.get_aiohttp_session()
        assert esv_reference_server.api_server is not None
        url = esv_reference_server.api_server.url
        esv_client = ESVClient(url, aiohttp_client, REGTEST_MASTER_TOKEN)
        peer_channel = await esv_client.create_peer_channel()
    try:
        # Todo create db entry in MAPIBroadcastCallbacks to record attempt
        api_server = broadcast_server.candidate.api_server
        credential_id = broadcast_server.candidate.credential_id
        assert api_server is not None
        assert credential_id is not None
        return await broadcast_transaction_mapi_simple(tx,
            api_server, credential_id, peer_channel, merkle_proof, ds_check)
    except Exception:
        # Todo delete db entry MAPIBroadcastCallbacks on error
        raise
    finally:
        # Todo update db entry in MAPIBroadcastCallbacks after broadcast success
        pass


class NewServerAPIContext(NamedTuple):
    wallet_path: str
    account_id: int


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

    def __repr__(self) -> str:
        return f"<NewServerAccessState last_try={self.last_try} last_good={self.last_good} " \
               f"last_fee_quote={self.last_fee_quote}/>"

    def record_attempt(self) -> None:
        self.last_try = datetime.datetime.now(datetime.timezone.utc).timestamp()

    def record_success(self) -> None:
        self.last_good = datetime.datetime.now(datetime.timezone.utc).timestamp()

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
    def __init__(self, url: str, server_type: NetworkServerType,
            config: Optional[APIServerDefinition]=None) -> None:
        self.url = url
        self.server_type = server_type
        self.config: Optional[APIServerDefinition] = config
        self.config_credential_id: Optional[IndefiniteCredentialId] = None

        # These are the enabled clients, whether they use an API key and the id if so.
        self.client_api_keys: Dict[NewServerAPIContext, Optional[IndefiniteCredentialId]] = {}
        # We keep per-API key state for a reason. An API key can be considered to be a distinct
        # account with the service, and it makes sense to keep the statistics/metadata for the
        # service separated by API key for this reason. We intentionally leave these in place
        # at least for now as they are kind of relative to the given key value.
        self.api_key_state: Dict[Optional[IndefiniteCredentialId], NewServerAccessState] = {}

        # We need to put any config credential in the credential cache. The only time that there
        # will not be an application config entry, is where the server is from an external wallet.
        if config is not None:
            if config.get("api_key"):
                decrypted_api_key = pw_decode(config["api_key"], TOKEN_PASSWORD)
                self.config_credential_id = \
                    app_state.credentials.add_indefinite_credential(decrypted_api_key)
            if self.config_credential_id not in self.api_key_state:
                self.api_key_state[self.config_credential_id] = NewServerAccessState()

    def set_wallet_usage(self, wallet_path: str, server_state: NetworkServerState) -> None:
        """
        Prime the server with the given server state from the given wallet.

        This may override the common state for a credential, like when it was last tried,
        when it was last successfully used or the last fee quote received based on what is the
        latest usable state.
        """
        usage_context = NewServerAPIContext(wallet_path, server_state.key.account_id)
        self.client_api_keys[usage_context] = server_state.credential_id

        if server_state.credential_id not in self.api_key_state:
            self.api_key_state[server_state.credential_id] = NewServerAccessState()
        key_state = self.api_key_state[server_state.credential_id]
        if server_state.date_last_good > key_state.last_good:
            key_state.last_try = max(key_state.last_try, server_state.date_last_try)
            # Fee quote state is only relevant for MAPI.
            if self.server_type == NetworkServerType.MERCHANT_API:
                fee_response: Optional[JSONEnvelope] = None
                if server_state.mapi_fee_quote_json:
                    fee_response = cast(JSONEnvelope, json.loads(server_state.mapi_fee_quote_json))
                key_state.set_fee_quote(fee_response, server_state.date_last_good)

    def remove_wallet_usage(self, wallet_path: str, specific_server_key: ServerAccountKey) -> None:
        usage_context = NewServerAPIContext(wallet_path, specific_server_key.account_id)
        del self.client_api_keys[usage_context]

    def unregister_wallet(self, wallet_path: str) -> List[NetworkServerState]:
        """
        Remove all involvement of a wallet that is being unloaded from this server.

        We return the updated state for each registered server/account as of the time of
        unregistration for the caller to optionally persist.
        """
        # This wallet is being unloaded so remove all it's involvement with the server.
        results: List[NetworkServerState] = []
        for client_key, credential_id in list(self.client_api_keys.items()):
            if client_key.wallet_path != wallet_path:
                continue
            del self.client_api_keys[client_key]

            key_state = self.api_key_state[credential_id]
            specific_server_key = ServerAccountKey(self.url, self.server_type,
                client_key.account_id)
            mapi_fee_quote_json: Optional[str] = None
            if self.server_type == NetworkServerType.MERCHANT_API:
                if key_state.last_fee_quote_response:
                    mapi_fee_quote_json = json.dumps(key_state.last_fee_quote_response)
            else:
                assert key_state.last_fee_quote_response is None
            server_state = NetworkServerState(specific_server_key, credential_id,
                mapi_fee_quote_json, int(key_state.last_try), int(key_state.last_good))
            results.append(server_state)
        return results

    def on_pending_config_change(self, config_update: APIServerDefinition) -> None:
        """
        Process a change to the config entry for this server.

        The instance variable `config` is a reference to the config entry that is tracked by
        the network. We get this event before it is updated, so that we can interpret the changes
        againt it.
        """
        assert self.config is not None
        if self.config_credential_id is not None:
            app_state.credentials.remove_indefinite_credential(self.config_credential_id)
            self.config_credential_id = None

        new_encrypted_api_key = config_update.get("api_key")
        if new_encrypted_api_key:
            decrypted_api_key = pw_decode(new_encrypted_api_key, TOKEN_PASSWORD)
            self.config_credential_id = \
                app_state.credentials.add_indefinite_credential(decrypted_api_key)
            if self.config_credential_id not in self.api_key_state:
                self.api_key_state[self.config_credential_id] = NewServerAccessState()

    def is_unusable(self) -> bool:
        """
        Whether the given server is configured to be unusable by anything.
        """
        if len(self.client_api_keys) == 0:
            if self.config is None:
                return True
            # TODO(rt12) This needs to be documented. How is an enabled server unusable? Wouldn't
            #   it be the other way around?
            return self.config["enabled_for_all_wallets"]
        return False

    def is_unused(self) -> bool:
        """ An API server is considered unused if it is not a globally stored one (if it were it
            would have a config object) and it no longer has any loaded wallets using it. """
        return len(self.client_api_keys) == 0 and self.config is None

    def should_request_fee_quote(self, credential_id: Optional[IndefiniteCredentialId]) -> bool:
        """
        Work out if we have a valid fee quote, and if not whether we can get one.
        """
        if self.config is not None:
            if self.config.get("api_key_required") and credential_id is None:
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

    def get_credential_id(self, client_key: NewServerAPIContext) \
            -> Tuple[bool, Optional[IndefiniteCredentialId]]:
        """
        Indicate whether the given client can use this server.

        Returns a flag and an optional credential id. The flag indicates whether the client can
        use the given server, and the credential id which can be `None` for no credential.
        """
        # Look up the account.
        if client_key in self.client_api_keys:
            return True, self.client_api_keys[client_key]

        # Look up the account's wallet as the first fallback.
        wallet_client_key = NewServerAPIContext(client_key.wallet_path, -1)
        if wallet_client_key in self.client_api_keys:
            return True, self.client_api_keys[wallet_client_key]

        # Finally we look up the application server for this URL, if there is one, and if it
        # is enabled for global use, we use it's api key.
        if self.config is not None and self.config["enabled_for_all_wallets"]:
            return True, self.config_credential_id

        # This client is not configured to use this server.
        return False, None

    def get_authorization_headers(self, credential_id: Optional[IndefiniteCredentialId]) \
            -> Dict[str, str]:
        if credential_id is None:
            return {}

        authorization_header = "Authorization: Bearer {API_KEY}"
        if self.config is not None:
            authorization_header_override = self.config.get("api_key_template")
            if authorization_header_override:
                authorization_header = cast(str, authorization_header_override)

        decrypted_api_key = app_state.credentials.get_indefinite_credential(credential_id)
        header_key, _separator, header_value = authorization_header.partition(": ")
        return { header_key: header_value.format(API_KEY=decrypted_api_key) }

    @property
    def capabilities(self) -> List[ServerCapability]:
        results: List[ServerCapability] = []
        if self.config is not None:
            for capability_name in self.config.get("capabilities", []):
                capability_value = getattr(ServerCapability, capability_name, None)
                if capability_value is not None:
                    results.append(capability_value)
        return results

    def __repr__(self) -> str:
        return f"<NewServer url={self.url} server_type={self.server_type} config={self.config}/>"


class SelectionCandidate(NamedTuple):
    server_type: NetworkServerType
    credential_id: Optional[IndefiniteCredentialId]
    api_server: Optional[NewServer] = None
    electrumx_server: Optional["SVServer"] = None


def select_servers(capability_type: ServerCapability, candidates: List[SelectionCandidate]) \
        -> List[SelectionCandidate]:
    """
    Create a prioritised list of servers to use for the given capability.

    capability_type: The type of capability the calling code wishes to use.
    candidates: A list server candidates, this should not be limited to api servers but all kinds
      of different servers that support capabilities.

    Returns the subset of `candidates` that support the given capability type.
    """
    filtered_servers: List[SelectionCandidate] = []
    for candidate in candidates:
        # TODO There is some clean up and final decisions that need to be made here with respect
        #      to `SERVER_CAPABILITIES`. For now for MAPI servers it is probably good enough to
        #      have this hard-coded selection of services, but it is possible in the longer term
        #      that different MAPI servers will have different endpoints and no-one but ESV
        #      reference server will be supporting our "endpoints" declarations. This might mean
        #      that MAPI servers we offer as defaults might have "capabilities" entries in their
        #      `config`.
        capabilities = [ c.type for c in SERVER_CAPABILITIES[candidate.server_type] ]
        if candidate.api_server is not None:
            config_capabilities = candidate.api_server.capabilities
            if config_capabilities:
                capabilities = config_capabilities
        for server_capability_type in capabilities:
            if server_capability_type == capability_type:
                filtered_servers.append(candidate)
                break
    return filtered_servers


def pick_server_for_account(network: Optional[Network], account: AbstractAccount) -> str:
    assert network is not None
    all_candidates = network.get_api_servers_for_account(
        account, NetworkServerType.GENERAL)
    restoration_candidates = select_servers(ServerCapability.MERKLE_PROOF_REQUEST,
        all_candidates)
    if not len(restoration_candidates):
        # TODO(1.4.0) needs Exception subclass.
        raise Exception(_("No servers available."))

    # TODO(1.4.0) better choice of which server to use, probably some centralised approach.
    candidate = random.choice(restoration_candidates)
    assert candidate.api_server is not None and candidate.api_server.config is not None

    # TODO(1.4.0) better endpoint url resolution rather than this hard-coding.
    url = candidate.api_server.config["url"]
    url = url if url.endswith("/") else url +"/"
    return url


class BroadcastCandidate(NamedTuple):
    candidate: SelectionCandidate
    estimator: TransactionFeeEstimator
    # Can the calling logic switch servers if they have the same initial fee? Not sure.
    initial_fee: int


def prioritise_broadcast_servers(estimated_tx_size: TransactionSize,
        servers: List[SelectionCandidate]) -> List[BroadcastCandidate]:
    """
    Prioritise the provided servers based on the base fee they would charge for the transaction.

    The transaction at this point might be complete, or it might be incomplete and pending
    server selection and application of the server's fee rate in it's finalisation.

    estimated_tx_size: The incomplete base transaction size or complete transaction size.
    servers: The list of server candidates known to support the transaction broadcast capability.

    Returns the ordered list of server candidates based on lowest to highest estimated fee for
      a transaction of the given size.
    """
    electrumx_fee_estimator = app_state.config.estimate_fee
    candidates: List[BroadcastCandidate] = []
    fee_estimator: TransactionFeeEstimator
    for candidate in servers:
        if candidate.server_type == NetworkServerType.MERCHANT_API:
            assert candidate.api_server is not None
            key_state = candidate.api_server.api_key_state[candidate.credential_id]
            if key_state.last_fee_quote is None:
                logger.error(f"No fee quote for {candidate.api_server.url} - server is unavailable")
                continue  # drop from set of servers
            estimator = MAPIFeeEstimator(key_state.last_fee_quote)
            fee_estimator = estimator.estimate_fee
        elif candidate.server_type == NetworkServerType.ELECTRUMX:
            # NOTE At some point if ElectrumX servers stick around maybe they will do their
            #   own fee quotes.
            fee_estimator = electrumx_fee_estimator
        else:
            raise NotImplementedError(f"Unsupported server type {candidate.server_type}")
        initial_fee = fee_estimator(estimated_tx_size)
        candidates.append(BroadcastCandidate(candidate, fee_estimator, initial_fee))
    candidates.sort(key=lambda entry: entry.initial_fee)
    return candidates
