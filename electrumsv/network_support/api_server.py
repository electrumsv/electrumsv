import datetime
import json
from typing import Any, cast, Dict, List, NamedTuple, Optional, Tuple

import dateutil.parser

from ..app_state import app_state
from ..constants import NetworkServerType, TOKEN_PASSWORD
from ..credentials import CredentialCache
from ..crypto import pw_decode
from ..types import IndefiniteCredentialId, NetworkServerState, ServerAccountKey

from .mapi import JSONEnvelope, FeeQuote


__all__ = [ "NewServerAPIContext", "NewServerAccessState", "NewServer" ]


STALE_PERIOD_SECONDS = 60 * 60 * 24


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
    def __init__(self, url: str, server_type: NetworkServerType, config: Optional[Dict]=None) \
            -> None:
        self.url = url
        self.server_type = server_type
        self.config: Optional[Dict] = config
        self.config_credential_id: Optional[IndefiniteCredentialId] = None

        # These are the enabled clients and which/whether they use an API key.
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
                credentials = cast(CredentialCache, app_state.credentials)
                decrypted_api_key = pw_decode(config["api_key"], TOKEN_PASSWORD)
                self.config_credential_id = credentials.add_indefinite_credential(decrypted_api_key)
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
            fee_response: Optional[JSONEnvelope] = None
            if server_state.fee_quote_json:
                fee_response = cast(JSONEnvelope, json.loads(server_state.fee_quote_json))
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
            specific_server_key = ServerAccountKey(self.url, NetworkServerType.MERCHANT_API,
                client_key.account_id)
            fee_quote_json: Optional[str] = None
            if key_state.last_fee_quote_response:
                fee_quote_json = json.dumps(key_state.last_fee_quote_response)
            server_state = NetworkServerState(specific_server_key, credential_id, fee_quote_json,
                int(key_state.last_try), int(key_state.last_good))
            results.append(server_state)
        return results

    def on_pending_config_change(self, config_update: Dict[str, Any]) -> None:
        """
        Process a change to the config entry for this server.

        The instance variable `config` is a reference to the config entry that is tracked by
        the network. We get this event before it is updated, so that we can interpret the changes
        againt it.
        """
        assert self.config is not None
        credentials = cast(CredentialCache, app_state.credentials)

        if self.config_credential_id is not None:
            credentials.remove_indefinite_credential(self.config_credential_id)
            self.config_credential_id = None

        new_encrypted_api_key = config_update.get("api_key")
        if new_encrypted_api_key:
            decrypted_api_key = pw_decode(new_encrypted_api_key, TOKEN_PASSWORD)
            self.config_credential_id = credentials.add_indefinite_credential(decrypted_api_key)
            if self.config_credential_id not in self.api_key_state:
                self.api_key_state[self.config_credential_id] = NewServerAccessState()

    def is_unusable(self) -> bool:
        if len(self.client_api_keys) == 0:
            if self.config is None:
                return True
            return self.config["enabled_for_all_wallets"]
        return False

    def is_unused(self) -> bool:
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

        credentials = cast(CredentialCache, app_state.credentials)
        decrypted_api_key = credentials.get_indefinite_credential(credential_id)
        header_key, _separator, header_value = authorization_header.partition(": ")
        return { header_key: header_value.format(API_KEY=decrypted_api_key) }

