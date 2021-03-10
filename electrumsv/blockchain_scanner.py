"""
Blockchain scanning functionality.

Further work
------------

* Potential later advanced setting, where the user can customise the scanned script types. However
  this falls under the umbrella of maybe missing account-related transactions and resulting in
  incorrect state. Better to focus on presumably unavoidably correct state for a start.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable, cast, Dict, List, NamedTuple, Optional, Sequence

from bitcoinx import (bip32_key_from_string, BIP32PublicKey, P2PKH_Address, P2SH_Address,
    PublicKey, sha256)

from .app_state import app_state
from .constants import (ACCOUNT_SCRIPT_TYPES, AccountType, CHANGE_SUBPATH, DerivationType,
    RECEIVING_SUBPATH, ScriptType, SubscriptionOwnerPurpose, SubscriptionType)
from .exceptions import SubscriptionStale, UnsupportedAccountTypeError
from .logs import logs
from .keys import get_single_signer_script_template, get_multi_signer_script_template
from .networks import Net
from .types import (ElectrumXHistoryList, SubscriptionEntry, SubscriptionKey,
    SubscriptionScannerScriptHashOwnerContext, SubscriptionOwner)
from .wallet import AbstractAccount


logger = logs.get_logger("scanner")

# TODO(no-checkin) Network disconnection.

ExtendRangeCallback = Callable[[int], None]


# How many scripts to aim to keep subscribed at a time. This will flow over a little depending on
# how may script types there are for a given key, not that it matters.
MINIMUM_ACTIVE_SCRIPTS = 100

# How far above the last used key to look for more key usage, per derivation subpath.
DEFAULT_GAP_LIMITS = {
    RECEIVING_SUBPATH: 50,
    CHANGE_SUBPATH: 20,
}


@dataclass
class AdvancedSettings:
    gap_limits: Dict[Sequence[int], int] = field(default_factory=dict)

    def __post_init__(self):
        # Ensure that the default gap limits are in place if necessary.
        self.gap_limits = DEFAULT_GAP_LIMITS | self.gap_limits


@dataclass
class BIP32ParentPath:
    # The subpath has already been applied. It is provided solely for context.
    subpath: Sequence[int]
    # The signing threshold.
    threshold: int
    # The pre-derived master public keys.
    master_public_keys: List[BIP32PublicKey]
    # The possible script types that may be used by the children of the parent public keys.
    script_types: Sequence[ScriptType]

    # The pre-derived parent public keys.
    parent_public_keys: List[BIP32PublicKey] = field(default_factory=list)
    # Current index.
    last_index: int = -1
    # How many script hash histories we have obtained.
    result_count: int = 0
    # Highest known index with a non-empty script hash history.
    highest_used_index: int = -1

    def __post_init__(self) -> None:
        self.parent_public_keys = self.master_public_keys[:]
        for i, xpub in enumerate(self.parent_public_keys):
            for n in self.subpath:
                xpub = xpub.child_safe(n)
            self.parent_public_keys[i] = xpub


class ScriptEntryKind(IntEnum):
    NONE = 0
    EXPLICIT = 1
    BIP32 = 2


class ScriptEntry(NamedTuple):
    """
    Mixed state for both fixed scripts and BIP32 derivation paths.

    We are concerned about optimal memory usage.
    """
    kind: ScriptEntryKind = ScriptEntryKind.NONE
    keyinstance_id: Optional[int] = None
    script_type: ScriptType = ScriptType.NONE
    script_hash: bytes = b''
    parent_path: Optional[BIP32ParentPath] = None
    parent_index: int = -1


@dataclass
class ScriptHashHistory:
    """
    The sub-context for the history and the history itself.
    """
    history: ElectrumXHistoryList
    bip32_subpath: Optional[Sequence[int]] = None
    bip32_subpath_index: int = -1



class Scanner:
    """
    NOTE(rt12) At this time, only one `Scanner` instance is supported. The main reason for this
    is that.. I do not remember! Work out why this should be the case or not before using more.
    """
    def __init__(self, wallet_id: int=0, account_id: int=0,
            settings: Optional[AdvancedSettings]=None,
            extend_range_cb: Optional[ExtendRangeCallback]=None) -> None:
        self._started = False
        self._scan_entry_count = 0
        self._extend_range_cb = extend_range_cb

        if settings is None:
            settings = AdvancedSettings()
        self._settings = settings

        self._pending_scripts: List[ScriptEntry] = []
        self._active_scripts: Dict[bytes, ScriptEntry] = {}
        self._script_hash_histories: Dict[bytes, ScriptHashHistory] = {}
        self._bip32_paths: List[BIP32ParentPath] = []

        self._event = app_state.async_.event()
        self._should_exit = False

        self._subscription_owner = SubscriptionOwner(wallet_id, account_id,
            SubscriptionOwnerPurpose.SCANNER)
        app_state.subscriptions.set_owner_callback(self._subscription_owner,
            self._on_script_hash_result)

    def shutdown(self) -> None:
        """
        Required shutdown handling that any external context must invoke.
        """
        if self._should_exit:
            logger.debug("shutdown scanner, duplicate call ignored")
            return
        logger.debug("shutdown scanner")
        self._should_exit = True
        app_state.subscriptions.remove_owner(self._subscription_owner)

    @classmethod
    def from_account(cls, account: AbstractAccount, settings: Optional[AdvancedSettings]=None,
            extend_range_cb: Optional[ExtendRangeCallback]=None) -> 'Scanner':
        """
        Create a scanner that will search for usage of the keys belonging to the account.
        """
        account_type = account.type()
        account_id = account.get_id()
        wallet = account.get_wallet()
        wallet_id = wallet.get_id()
        script_types = ACCOUNT_SCRIPT_TYPES[account_type]
        scanner = cls(wallet_id, account_id, settings, extend_range_cb)

        if account.is_deterministic():
            threshold = account.get_threshold()
            master_public_keys = cast(List[BIP32PublicKey], [ bip32_key_from_string(mpk)
                for mpk in account.get_master_public_keys() ])
            for subpath in (CHANGE_SUBPATH, RECEIVING_SUBPATH):
                scanner.add_bip32_subpath(subpath, master_public_keys, threshold, script_types)
        elif account_type == AccountType.IMPORTED_ADDRESS:
            # The derivation data is the address or hash160 that relates to the script type.
            for key_data in wallet.read_key_list(account_id):
                if key_data.derivation_type == DerivationType.PUBLIC_KEY_HASH:
                    script_template = P2PKH_Address(key_data.derivation_data2, Net.COIN)
                    script_hash = sha256(script_template.to_script_bytes())
                    scanner.add_script(key_data.keyinstance_id, ScriptType.P2PKH, script_hash)
                elif key_data.derivation_type == DerivationType.SCRIPT_HASH:
                    script_template = P2SH_Address(key_data.derivation_data2, Net.COIN)
                    script_hash = sha256(script_template.to_script_bytes())
                    scanner.add_script(key_data.keyinstance_id, ScriptType.MULTISIG_P2SH,
                        script_hash)
        elif account_type == AccountType.IMPORTED_PRIVATE_KEY:
            # The derivation data is the public key for the private key.
            for key_data in wallet.read_key_list(account_id):
                assert key_data.derivation_type == DerivationType.PRIVATE_KEY
                public_key = PublicKey.from_bytes(key_data.derivation_data2)
                for script_type in script_types:
                    script_template = get_single_signer_script_template(public_key, script_type)
                    script_hash = sha256(script_template.to_script_bytes())
                    scanner.add_script(key_data.keyinstance_id, script_type, script_hash)
        else:
            raise UnsupportedAccountTypeError()

        return scanner

    def get_result_count(self) -> int:
        return len(self._script_hash_histories)

    def add_bip32_subpath(self, subpath: Sequence[int], master_public_keys: List[BIP32PublicKey],
            threshold: int, script_types: Sequence[ScriptType]) -> BIP32ParentPath:
        assert not self._started
        data = BIP32ParentPath(subpath, threshold, master_public_keys, script_types)
        self._bip32_paths.append(data)
        return data

    def add_script(self, keyinstance_id: int, script_type: ScriptType, script_hash: bytes) -> None:
        self._pending_scripts.append(ScriptEntry(ScriptEntryKind.EXPLICIT,
            keyinstance_id, script_type, script_hash))

    def start_scanning_for_usage(self, on_done=None) -> None:
        logger.debug("Starting blockchain scan process")
        self._future = app_state.app.run_coro(self.scan_for_usage, on_done=on_done)

    async def scan_for_usage(self) -> None:
        """
        Enumerate and scan keys until all key sources are exhausted.
        """
        logger.debug("Starting blockchain scan")
        while len(self._active_scripts) or len(self._pending_scripts) or len(self._bip32_paths):
            if self._should_exit:
                logger.debug("Blockchain scan exit reason, manual interruption")
                break

            new_entries: List[ScriptEntry] = []
            required_entries = MINIMUM_ACTIVE_SCRIPTS - len(self._active_scripts)

            # Populate any required entries from the pending scripts first.
            if required_entries > 0 and len(self._pending_scripts):
                how_many = min(required_entries, len(self._pending_scripts))
                new_entries.extend(self._pending_scripts[:how_many])
                del self._pending_scripts[:how_many]
                required_entries -= how_many

            # Populate any required entries from any unconsumed dynamic derivation sequences.
            candidates = self._obtain_any_bip32_entries(required_entries)
            if len(candidates):
                required_entries -= len(candidates)
                new_entries.extend(candidates)

            if len(new_entries) > 0:
                subscribe_entries: List[SubscriptionEntry] = []
                for entry in new_entries:
                    # Track the outstanding subscription locally.
                    self._active_scripts[entry.script_hash] = entry
                    # Subscribe to the entry.
                    subscribe_entries.append(SubscriptionEntry(
                        SubscriptionKey(SubscriptionType.SCRIPT_HASH, entry.script_hash),
                        SubscriptionScannerScriptHashOwnerContext(entry)))
                self._extend_range(len(new_entries))
                app_state.subscriptions.create_entries(subscribe_entries, self._subscription_owner)
            elif len(self._active_scripts) == 0 and len(self._pending_scripts) == 0:
                # BIP32 paths do not get removed, but they can be exhausted of candidates.
                if all(self._get_bip32_path_count(pp) == 0 for pp in self._bip32_paths):
                    logger.debug("Blockchain scan exit reason, BIP32 exhaustion")
                    break

            # This should block until a script hash is satisfied, then generate another.
            await self._event.wait()
            self._event.clear()
        logger.debug("Ending blockchain scan")
        self.shutdown()

    def get_scan_results(self) -> Dict[bytes, ScriptHashHistory]:
        return self._script_hash_histories

    def _obtain_any_bip32_entries(self, maximim_candidates: int) -> List[ScriptEntry]:
        """
        Examine each BIP32 path in turn looking for candidates.
        """
        new_entries: List[ScriptEntry] = []
        parent_path_index = 0
        while maximim_candidates > 0 and parent_path_index < len(self._bip32_paths):
            candidates = self._obtain_entries_from_bip32_path(maximim_candidates,
                self._bip32_paths[parent_path_index])
            new_entries.extend(candidates)
            maximim_candidates -= len(candidates)
            parent_path_index += 1
        return new_entries

    def _obtain_entries_from_bip32_path(self, maximum_candidates: int,
            parent_path: BIP32ParentPath) -> List[ScriptEntry]:
        new_entries: List[ScriptEntry] = []
        while maximum_candidates > 0 and self._get_bip32_path_count(parent_path) > 0:
            current_index = parent_path.last_index + 1

            public_keys = [ public_key.child_safe(current_index)
                for public_key in parent_path.parent_public_keys ]
            public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
            for script_type in parent_path.script_types:
                if len(public_keys) == 1:
                    script = get_single_signer_script_template(public_keys[0], script_type)
                else:
                    script = get_multi_signer_script_template(public_keys_hex,
                        parent_path.threshold, script_type)
                script_hash = sha256(script.to_script_bytes())
                new_entries.append(ScriptEntry(ScriptEntryKind.BIP32, None, script_type,
                    script_hash, parent_path, current_index))

            parent_path.last_index = current_index
            maximum_candidates -= len(parent_path.script_types)
        return new_entries

    def _get_bip32_path_count(self, parent_path: BIP32ParentPath) -> int:
        """
        How many keys we can still examine for this BIP32 path given the gap limit.
        """
        gap_limit = self._settings.gap_limits[parent_path.subpath]
        key_count = parent_path.last_index + 1
        # If we have used keys, we aim for the gap limit between highest index and highest used.
        if parent_path.highest_used_index > -1:
            gap_current = parent_path.last_index - parent_path.highest_used_index
            return gap_limit - gap_current

        # # Have we received results for all generated candidates?
        # expected_result_count = (parent_path.last_index + 1) * len(parent_path.script_types)
        # if expected_result_count == parent_path.result_count:
        # Otherwise we are just aiming for the gap limit.
        return gap_limit - key_count

    async def _on_script_hash_result(self, subscription_key: SubscriptionKey,
            context: SubscriptionScannerScriptHashOwnerContext,
            history: ElectrumXHistoryList) -> None:
        """
        Receive an event related to a scanned script hash from the subscription manager.

        `history` is in immediately usable order. Transactions are listed in ascending
        block height (height > 0), followed by the unconfirmed (height == 0) and then
        those with unconfirmed parents (height < 0).

            [
                { "tx_hash": "e232...", "height": 111 },
                { "tx_hash": "df12...", "height": 222 },
                { "tx_hash": "aa12...", "height": 0, "fee": 400 },
                { "tx_hash": "bb12...", "height": -1, "fee": 300 },
            ]

        Receiving this event is interpreted as completing the need to subscribe to the given
        script hash, and having the required information.
        """
        assert subscription_key.value_type == SubscriptionType.SCRIPT_HASH
        script_hash = cast(bytes, subscription_key.value)

        # Signal that we have a result for this script hash and have finished with it.
        history_entry = self._script_hash_histories[script_hash] = ScriptHashHistory(history)
        del self._active_scripts[script_hash]

        entry = cast(ScriptEntry, context.value)
        if entry.kind == ScriptEntryKind.BIP32:
            assert entry.parent_path is not None
            assert entry.parent_index > -1
            entry.parent_path.result_count += 1
            if len(history):
                entry.parent_path.highest_used_index = max(entry.parent_path.highest_used_index,
                    entry.parent_index)

            history_entry.bip32_subpath = entry.parent_path.subpath
            history_entry.bip32_subpath_index = entry.parent_index

        self._event.set()
        # Trigger the unsubscription for this script hash.
        raise SubscriptionStale()

    def _extend_range(self, number: int) -> None:
        """
        Hint for any UI to display how many entries the scanner is waiting for.

        We cannot know ahead of time how many entries there are, because this class is all about
        discovering that.
        """
        assert number > 0
        self._scan_entry_count += number
        if self._extend_range_cb is not None:
            self._extend_range_cb(self._scan_entry_count)
