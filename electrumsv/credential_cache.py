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

# Future directions:
# - Allow users to set long expiry durations so they do not have to re-enter their password.
# - When we have a funding account type where it can be set to pay for expenses for other accounts,
#   it makes more sense if the credentials are cached for the funding account and they are not
#   for the savings account.

from collections import defaultdict
import threading
import time
from typing import Any, cast, Dict, NamedTuple, Optional, Set, Tuple

from bitcoinx import PrivateKey

from .constants import CredentialPolicyFlag
from .logs import logs


logger = logs.get_logger("credentials")


LifetimeCredentialId = Any
LifetimeUserId = tuple


class UserLifetimeCredential(NamedTuple):
    """
    A credential that is cached as long as there is an active user for it.
    """
    encrypted_value: bytes
    active_users: Set[LifetimeUserId]


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
        self._lifetime_credential_users: Dict[LifetimeUserId, Set[LifetimeCredentialId]] = \
            defaultdict(set)
        self._user_lifetime_credentials: Dict[LifetimeCredentialId, UserLifetimeCredential] = {}
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
        with self._credential_lock:
            assert not self.closed
            self._wallet_credentials[wallet_path] = credential

            if self._check_thread is None:
                self._check_thread = threading.Thread(target=self._check_credentials_thread_main)
                self._check_thread.start()

    def get_wallet_password_and_policy(self, wallet_path: str) \
            -> Tuple[Optional[str], CredentialPolicyFlag]:
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

    def add_user_lifetime_credential(self, credential_id: LifetimeCredentialId,
            user_id: LifetimeUserId, credential_value: str) -> None:
        with self._credential_lock:
            credential = self._user_lifetime_credentials.get(credential_id)
            encrypted_value = cast(bytes, self._public_key.encrypt_message(credential_value))
            if credential is None:
                credential = UserLifetimeCredential(encrypted_value, { user_id })
                self._user_lifetime_credentials[credential_id] = credential
            else:
                assert user_id not in credential.active_users
                assert encrypted_value == credential.encrypted_value
                credential.active_users.add(user_id)
            self._lifetime_credential_users[user_id].add(credential_id)

    def remove_user_lifetime_credential(self, credential_id: LifetimeCredentialId,
            user_id: LifetimeUserId) -> None:
        with self._credential_lock:
            self._lifetime_credential_users[user_id].remove(credential_id)
            if not self._lifetime_credential_users[user_id]:
                del self._lifetime_credential_users[user_id]

            credential = self._user_lifetime_credentials[credential_id]
            credential.active_users.remove(user_id)
            if not credential.active_users:
                del self._user_lifetime_credentials[credential_id]

    def remove_all_user_credentials(self, user_id: LifetimeUserId) -> None:
        with self._credential_lock:
            for credential_id in list(self._lifetime_credential_users[user_id]):
                self.remove_user_lifetime_credential(credential_id, user_id)

    def get_lifetime_credential(self, credential_id: LifetimeCredentialId) -> str:
        """
        This is a credential that is cached as long as it's use is desired.

        There may be multiple things that use this credential, so we keep track of their
        individual ids and their comings and goings.
        """
        with self._credential_lock:
            credential = self._user_lifetime_credentials[credential_id]
            credential_bytes = self._private_key.decrypt_message(credential.encrypted_value)
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
