# The Open BSV license.
#
# Copyright © 2019-2021 Bitcoin Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
#   1. The above copyright notice and this permission notice shall be included
#      in all copies or substantial portions of the Software.
#   2. The Software, and any software that is derived from the Software or parts
#      thereof, can only be used on the Bitcoin SV blockchains. The Bitcoin SV
#      blockchains are defined, for purposes of this license, as the Bitcoin
#      blockchain containing block height #556767 with the hash
#      “000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b” and
#      the test blockchains that are supported by the unmodified Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# TODO(Future directions)
# - Allow users to set long expiry durations so they do not have to re-enter their password.
# - When we have a funding account type where it can be set to pay for expenses for other accounts,
#   it makes more sense if the credentials are cached for the funding account and they are not
#   for the savings account.
# - Indefinite credentials should be reference counted and shared between credential using "owners"
#   so that any data associated with them can be shared between the owners (where applicable),
#   an example of this is server API keys where a server may have a last connection attempt
#   time and a last successful connection attempt time, and even a last fee quote time.
#   Really the credential could be used as an id to centralise common management of a resource.
#   Just hashing a credential value wouldn't be enough, as the user might reuse a password for
#   instance for different contexts, so maybe hashing b"ESV.api.key"+ unencrypted_bytes.

import dataclasses
import threading
import time
from typing import cast, Dict, NamedTuple, Optional, Tuple
import uuid

from bitcoinx import PrivateKey

from .constants import CredentialPolicyFlag, DATABASE_EXT
from .logs import logs
from .types import IndefiniteCredentialId


logger = logs.get_logger("credentials")


@dataclasses.dataclass
class IndefiniteCredential:
    """
    A credential that is cached until it is explicitly removed.
    """
    encrypted_value: bytes


class WalletCredential(NamedTuple):
    """
    A credential tied to the lifetime of a given wallet.
    """
    encrypted_value: bytes
    timestamp: float
    policy: CredentialPolicyFlag = CredentialPolicyFlag.DISCARD_IMMEDIATELY


MAXIMUM_EXPIRATION_SECONDS = 10.0
MAXIMUM_SLEEP_SECONDS = 5.0


class CredentialCache:
    closed = False
    fatal_error = False

    def __init__(self) -> None:
        self._indefinite_credentials: Dict[IndefiniteCredentialId, IndefiniteCredential] = {}
        self._wallet_credentials: Dict[str, WalletCredential] = {}

        self._check_thread: Optional[threading.Thread] = None
        self._credential_lock = threading.RLock()
        self._close_event = threading.Event()

        # This is used to encrypt credentials in-memory so we store no plaintext version. It costs
        # us nothing to do this.
        self._private_key = PrivateKey.from_random()
        self._public_key = self._private_key.public_key

    def close(self) -> None:
        """
        Ensure the credentials are cleared when we are done with this cache.
        """
        self.closed = True
        with self._credential_lock:
            self._close_event.set()
            self._wallet_credentials = {}

    def set_wallet_password(self, wallet_path: str, password: str,
            policy: Optional[CredentialPolicyFlag]=None) -> None:
        if self.fatal_error:
            logger.error("Ignoring request to store credential due to fatal error")
            return
        # We ensure all the wallet paths have database extensions so that legacy wallets
        # passwords are applied to the migrated database paths.
        if not wallet_path.endswith(DATABASE_EXT):
            wallet_path += DATABASE_EXT
        with self._credential_lock:
            assert wallet_path not in self._wallet_credentials
            creation_time = time.time()
            encrypted_value = cast(bytes, self._public_key.encrypt_message(password))
            if policy is None:
                credential = WalletCredential(encrypted_value, creation_time)
            else:
                credential = WalletCredential(encrypted_value, creation_time, policy)
            if credential.policy & CredentialPolicyFlag.DISCARD_IMMEDIATELY:
                return
            assert not self.closed
            self._wallet_credentials[wallet_path] = credential

            if self._check_thread is None:
                self._check_thread = threading.Thread(target=self._check_credentials_thread_main)
                self._check_thread.start()

    def get_wallet_password_and_policy(self, wallet_path: str) \
            -> Tuple[Optional[str], CredentialPolicyFlag]:
        # We ensure all the wallet paths have database extensions so that legacy wallets
        # passwords are applied to the migrated database paths.
        if not wallet_path.endswith(DATABASE_EXT):
            wallet_path += DATABASE_EXT
        with self._credential_lock:
            credential = self._wallet_credentials.get(wallet_path)
            if credential is not None:
                if credential.policy & CredentialPolicyFlag.DISCARD_ON_USE \
                        == CredentialPolicyFlag.DISCARD_ON_USE:
                    del self._wallet_credentials[wallet_path]
                password_bytes = self._private_key.decrypt_message(credential.encrypted_value)
                return password_bytes.decode('utf-8'), credential.policy
        return None, CredentialPolicyFlag.NONE

    def get_wallet_password(self, wallet_path: str) -> Optional[str]:
        password, _policy = self.get_wallet_password_and_policy(wallet_path)
        return password

    def _check_credentials_thread_main(self) -> None:
        logger.debug("Entering thread to check credential expiry")
        try:
            self._check_credentials_thread_body()
        finally:
            logger.debug("Exiting thread to check credential expiry (closed: %s, count: %d)",
                self.closed, len(self._wallet_credentials))

    def add_indefinite_credential(self, credential_value: str) \
            -> IndefiniteCredentialId:
        with self._credential_lock:
            credential_id = uuid.uuid4()
            encrypted_value = cast(bytes, self._public_key.encrypt_message(credential_value))
            credential = IndefiniteCredential(encrypted_value)
            self._indefinite_credentials[credential_id] = credential
        return credential_id

    def update_indefinite_credential(self, credential_id: IndefiniteCredentialId,
            credential_value: str) -> None:
        with self._credential_lock:
            encrypted_value = cast(bytes, self._public_key.encrypt_message(credential_value))
            self._indefinite_credentials[credential_id].encrypted_value = encrypted_value

    def remove_indefinite_credential(self, credential_id: IndefiniteCredentialId) -> None:
        with self._credential_lock:
            self._indefinite_credentials.pop(credential_id)

    def get_indefinite_credential(self, credential_id: IndefiniteCredentialId) -> str:
        """
        This is a credential that is cached as long as it's use is desired.

        There may be multiple things that use this credential, so we keep track of their
        individual ids and their comings and goings.
        """
        with self._credential_lock:
            credential = self._indefinite_credentials[credential_id]
            credential_bytes = cast(bytes,
                self._private_key.decrypt_message(credential.encrypted_value))
            return credential_bytes.decode('utf-8')

    def _check_credentials_thread_body(self) -> None:
        sleep_seconds = MAXIMUM_SLEEP_SECONDS
        while True:
            # We use an event to wait as we can awaken immediately where a sleep will not.
            if self._close_event.wait(min(sleep_seconds, MAXIMUM_SLEEP_SECONDS)):
                self._check_thread = None
                return

            with self._credential_lock:
                if self.closed or not len(self._wallet_credentials):
                    self._check_thread = None
                    return

                current_time = time.time()
                closest_expiration_time = current_time + MAXIMUM_EXPIRATION_SECONDS
                for wallet_path, credential in list(self._wallet_credentials.items()):
                    expiration_time = credential.timestamp
                    if credential.policy & CredentialPolicyFlag.FLUSH_ALMOST_IMMEDIATELY1:
                        expiration_time += 10.0
                    elif credential.policy & CredentialPolicyFlag.FLUSH_ALMOST_IMMEDIATELY2:
                        expiration_time += 20.0
                    elif credential.policy & CredentialPolicyFlag.FLUSH_ALMOST_IMMEDIATELY3:
                        expiration_time += 30.0
                    else:
                        self.fatal_error = True
                        self._check_thread = None
                        logger.error("Disabling credential cache due to fatal error in bad "
                            "credential policy (flags: %x)", credential.policy)
                        return

                    if current_time >= expiration_time:
                        del self._wallet_credentials[wallet_path]
                    else:
                        closest_expiration_time = min(closest_expiration_time, expiration_time)
            sleep_seconds = closest_expiration_time - current_time
