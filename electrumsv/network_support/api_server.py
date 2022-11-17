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
import enum
import json
import dateutil.parser
import dataclasses
import random
from typing import cast, TypedDict, TYPE_CHECKING

from ..app_state import app_state
from ..constants import NetworkServerFlag, NetworkServerType, ServerCapability
from ..i18n import _
from ..logs import logs
from ..standards.json_envelope import JSONEnvelope
from ..standards.mapi import FeeQuote
from ..types import IndefiniteCredentialId, ServerAccountKey
from ..util import get_posix_timestamp
from ..wallet_database.types import NetworkServerRow


if TYPE_CHECKING:
    from ..wallet import Wallet


__all__ = [ "NewServerAccessState", "NewServer" ]


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
    capabilities: list[str]
    static_data_date: str
    # MAPI
    anonymous_fee_quote: JSONEnvelope | None


@dataclasses.dataclass
class CapabilitySupport:
    name: str
    type: ServerCapability
    is_unsupported: bool=False
    can_disable: bool=False


class RequestFeeQuoteResult(enum.IntEnum):
    CANNOT              = 1
    SHOULD              = 2
    ALREADY_HAVE        = 3


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

DEFAULT_API_KEY_TEMPLATE = "Authorization: Bearer {API_KEY}"
OVERRIDE_EXPIRY_DATE = False

def check_fee_quote_expired(fee_quote: FeeQuote, override_expiry_date: bool=False) -> bool:
    expiry_date = dateutil.parser.isoparse(fee_quote["expiryTime"])
    now_date = datetime.datetime.now(datetime.timezone.utc)
    if override_expiry_date:
        issue_date = dateutil.parser.isoparse(fee_quote["timestamp"])
        unofficial_expiry_date = issue_date + datetime.timedelta(days=1)
        # We override the official expiry date if it is higher than our minimum retry span.
        expiry_date = unofficial_expiry_date if expiry_date < unofficial_expiry_date \
            else expiry_date
    return now_date > expiry_date


class NewServerAccessState:
    """ The state for each URL/api key combination used by the application. """

    def __init__(self) -> None:
        self.last_try = 0.
        self.last_good = 0.

        ## MAPI state.
        # JSON envelope for the actual serialised fee quote JSON.
        self.last_fee_quote_response: JSONEnvelope | None = None
        # The fee quote we locally extracted and deserialised from the fee quote response.
        self.last_fee_quote: FeeQuote | None = None

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

    def set_fee_quote(self, fee_response: JSONEnvelope | None, timestamp: float) -> None:
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
            credential_id: IndefiniteCredentialId | None) -> None:
        self.key = ServerAccountKey(url, server_type, None)
        # All code that uses the URL expects a trailing slash.
        assert url.endswith("/")
        self.url = url
        self.server_type = server_type
        assert row.server_id is not None
        self.server_id = row.server_id

        # These are the enabled clients, whether they use an API key and the id if so.
        self.client_api_keys = dict[int | None, IndefiniteCredentialId | None]()
        self.database_rows = dict[int | None, NetworkServerRow]()
        # We keep per-API key state for a reason. An API key can be considered to be a distinct
        # account with the service, and it makes sense to keep the statistics/metadata for the
        # service separated by API key for this reason. We intentionally leave these in place
        # at least for now as they are kind of relative to the given key value.
        self.api_key_state: dict[IndefiniteCredentialId | None, NewServerAccessState] = {
            None: NewServerAccessState()
        }

        self.set_server_account_usage(row, credential_id)

    def get_account_ids(self) -> list[int | None]:
        return list(self.client_api_keys)

    def set_server_account_usage(self, server_row: NetworkServerRow,
            credential_id: IndefiniteCredentialId | None) -> None:
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
                fee_response: JSONEnvelope | None = None
                if server_row.mapi_fee_quote_json:
                    fee_response = cast(JSONEnvelope, json.loads(server_row.mapi_fee_quote_json))
                key_state.set_fee_quote(fee_response, server_row.date_last_good)

    def get_row(self, server_account_id: int | None = None) -> NetworkServerRow:
        return self.database_rows[server_account_id]

    def clear_server_account_usage(self, specific_server_key: ServerAccountKey) -> None:
        del self.client_api_keys[specific_server_key.account_id]
        del self.database_rows[specific_server_key.account_id]

    def to_updated_rows(self) -> list[NetworkServerRow]:
        """
        We return the updated state for each registered server/account as of the current time for
        the caller to presumably persist. We only update the metadata, not the fields the user
        edits like the api key related values.
        """
        date_updated = get_posix_timestamp()
        results: list[NetworkServerRow] = []
        for account_id, credential_id in list(self.client_api_keys.items()):
            server_row = self.database_rows[account_id]
            key_state = self.api_key_state[credential_id]

            mapi_fee_quote_json: str | None = None
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

    def get_tip_filter_peer_channel_id(self, account_id: int) -> int | None:
        row = self.database_rows.get(account_id)
        if row is None or row.tip_filter_peer_channel_id is None:
            row = self.database_rows[None]
        return row.tip_filter_peer_channel_id

    def set_tip_filter_peer_channel_id(self, account_id: int, peer_channel_id: int) -> None:
        key: int | None = account_id
        if account_id not in self.database_rows:
            key = None
        self.database_rows[key] = self.database_rows[key]._replace(
            tip_filter_peer_channel_id=peer_channel_id)

    def get_fee_quote(self, credential_id: IndefiniteCredentialId | None) -> FeeQuote | None:
        access_state = self.api_key_state[credential_id]
        if access_state.last_fee_quote is None or \
                check_fee_quote_expired(access_state.last_fee_quote, OVERRIDE_EXPIRY_DATE):
            return None
        return access_state.last_fee_quote

    def should_request_fee_quote(self, credential_id: IndefiniteCredentialId | None) \
            -> RequestFeeQuoteResult:
        """
        Check the server and any existing fee quote to see if we need to request a new one.
        The recommended approach is to request any needed fee quotes updates at the start of the
        process of constructing a new transaction.

        NOTE(rt12) MAPI servers have low expiry times. We do not want to poll every N minutes.
            This is the reason we do not update them as they expire.

              202?-??-?? Taal:           2 minute expiry times.
              2022-06-22 Gorilla pool:  10 minute expiry times.
        """
        row = self.database_rows[None]
        # If the server requires an API key and we do not have one, we cannot access it.
        if row.server_flags & NetworkServerFlag.API_KEY_REQUIRED and credential_id is None:
            return RequestFeeQuoteResult.CANNOT

        key_state = self.api_key_state[credential_id]
        # If we have no fee quote for this server, we want to request one.
        if key_state.last_fee_quote is None:
            return RequestFeeQuoteResult.SHOULD

        if check_fee_quote_expired(key_state.last_fee_quote, OVERRIDE_EXPIRY_DATE):
            return RequestFeeQuoteResult.SHOULD
        return RequestFeeQuoteResult.ALREADY_HAVE

    def get_credential_id(self, account_id: int | None) \
            -> tuple[bool, IndefiniteCredentialId | None]:
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

    def get_authorization_headers(self, credential_id: IndefiniteCredentialId | None) \
            -> dict[str, str]:
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


def get_viable_servers(servers_by_usage_flag: dict[NetworkServerFlag, set[NewServer]],
        usage_flags: NetworkServerFlag) -> list[tuple[NewServer, NetworkServerFlag]]:
    # For every used service type we need to have viable servers matched.
    usage_flag_by_server: dict[NewServer, NetworkServerFlag] = {}
    for usage_flag in { NetworkServerFlag.USE_BLOCKCHAIN, NetworkServerFlag.USE_MESSAGE_BOX }:
        if usage_flags & usage_flag == 0 or usage_flag not in servers_by_usage_flag:
            continue
        selected_server = random.choice(list(servers_by_usage_flag[usage_flag]))
        if selected_server in usage_flag_by_server:
            usage_flag_by_server[selected_server] |= usage_flag
        else:
            usage_flag_by_server[selected_server] = usage_flag
    return list(usage_flag_by_server.items())
