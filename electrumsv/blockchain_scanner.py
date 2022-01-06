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

"""
Blockchain scanning functionality.

Further work
------------

* Potential later advanced setting, where the user can customise the scanned script types. However
  this falls under the umbrella of maybe missing account-related transactions and resulting in
  incorrect state. Better to focus on presumably unavoidably correct state for a start.
"""

from __future__ import annotations
import concurrent.futures
from dataclasses import dataclass, field
from enum import IntEnum
import random
from typing import Callable, cast, Dict, List, NamedTuple, Optional, Protocol, \
    Sequence, Tuple, TYPE_CHECKING, TypeVar

from bitcoinx import (bip32_key_from_string, BIP32PublicKey, hash160, P2MultiSig_Output,
    P2PKH_Address, P2SH_Address, PublicKey, sha256)

from .app_state import app_state
from .bitcoin import ScriptTemplate
from .constants import (ACCOUNT_SCRIPT_TYPES, AccountType, CHANGE_SUBPATH, DerivationType,
    DerivationPath, NetworkServerType, RECEIVING_SUBPATH, ScriptType, ServerCapability,
    SubscriptionOwnerPurpose, SubscriptionType)
from .exceptions import SubscriptionStale, UnsupportedAccountTypeError
from .i18n import _
from .logs import logs
from .keys import get_single_signer_script_template, get_multi_signer_script_template
from .network_support.api_server import select_servers
from .network_support.general_api import post_restoration_filter_request_binary, \
    RestorationFilterRequest, RestorationFilterResult, unpack_binary_restoration_entry
from .networks import Net
from .types import (ScriptHashHistoryList, SubscriptionEntry,
    ScriptHashResultCallback, SubscriptionKey, SubscriptionScannerScriptHashOwnerContext,
    SubscriptionOwner)
from .wallet import AbstractAccount
from .wallet_database.types import KeyListRow


if TYPE_CHECKING:
    from .network import Network


logger = logs.get_logger("scanner")

# TODO Network disconnection.

ExtendRangeCallback = Callable[[int], None]


class PushDataSearchError(Exception):
    pass


# How far above the last used key to look for more key usage, per derivation subpath.
DEFAULT_GAP_LIMITS = {
    RECEIVING_SUBPATH: 50,
    CHANGE_SUBPATH: 20,
}


@dataclass
class AdvancedSettings:
    gap_limits: Dict[DerivationPath, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Ensure that the default gap limits are in place if necessary.
        self.gap_limits = DEFAULT_GAP_LIMITS | self.gap_limits


@dataclass
class BIP32ParentPath:
    # The subpath has already been applied. It is provided solely for context.
    subpath: DerivationPath
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


class SearchEntryKind(IntEnum):
    NONE = 0
    EXPLICIT = 1
    BIP32 = 2


class SearchEntry(NamedTuple):
    """
    Mixed state for both fixed scripts and BIP32 derivation paths.

    We are concerned about optimal memory usage.
    """
    kind: SearchEntryKind = SearchEntryKind.NONE
    keyinstance_id: Optional[int] = None
    script_type: ScriptType = ScriptType.NONE
    # We currently support only having one hash for looking up this item.
    item_hash: bytes = b''
    parent_path: Optional[BIP32ParentPath] = None
    parent_index: int = -1


@dataclass
class ScriptHashHistory:
    """
    The sub-context for the history and the history itself.
    """
    history: ScriptHashHistoryList
    bip32_subpath: Optional[DerivationPath] = None
    bip32_subpath_index: int = -1


ScanResultType = TypeVar("ScanResultType")
WrappedScanType = TypeVar("WrappedScanType")


# NOTE(rt12) I don't know what the best name for this is yet.
class ScannerHandlerProtocol(Protocol[ScanResultType]):
    _results: ScanResultType

    def setup(self, scanner: BlockchainScanner) -> None:
        raise NotImplementedError

    def shutdown(self) -> None:
        raise NotImplementedError

    async def wait_until_ready(self) -> None:
        """
        Wait until at least one result has been come in.
        """
        raise NotImplementedError

    def get_required_count(self) -> int:
        """
        How many results we can ask for this attempt.
        """
        raise NotImplementedError

    def has_ongoing_activity(self) -> bool:
        raise NotImplementedError

    def get_results(self) -> ScanResultType:
        raise NotImplementedError

    def get_item_hash_for_script(self, script_type: ScriptType, script: ScriptTemplate) -> bytes:
        raise NotImplementedError

    async def search_entries(self, entries: List[SearchEntry]) -> None:
        raise NotImplementedError


class ScriptHashHandler(ScannerHandlerProtocol[Dict[bytes, ScriptHashHistory]]):
    def __init__(self, network: Network, wallet_id: int=0, account_id: int=0) -> None:
        self._network = network
        self._active_subscriptions: Dict[bytes, SearchEntry] = {}
        self._results: Dict[bytes, ScriptHashHistory] = {}

        self._event = app_state.async_.event()
        self._subscription_owner = SubscriptionOwner(wallet_id, account_id,
            SubscriptionOwnerPurpose.SCANNER)
        self._network.subscriptions.set_owner_callback(self._subscription_owner,
            script_hash_callback=cast(ScriptHashResultCallback, self._on_script_hash_result))

    def setup(self, scanner: BlockchainScanner) -> None:
        self._scanner = scanner

    def shutdown(self) -> None:
        self._network.subscriptions.remove_owner(self._subscription_owner)
        del self._scanner
        del self._network

    async def wait_until_ready(self) -> None:
        # This should block until a script hash is satisfied, then generate another.
        await self._event.wait()
        self._event.clear()

    def get_required_count(self) -> int:
        return 100 - len(self._active_subscriptions)

    def has_ongoing_activity(self) -> bool:
        return len(self._active_subscriptions) > 0

    def get_results(self) -> Dict[bytes, ScriptHashHistory]:
        return self._results

    def get_item_hash_for_script(self, script_type: ScriptType, script: ScriptTemplate) -> bytes:
        return cast(bytes, sha256(script.to_script_bytes()))

    async def search_entries(self, search_entries: List[SearchEntry]) -> None:
        # Track the outstanding subscriptions locally.
        subscription_entries: List[SubscriptionEntry] = []
        for search_entry in search_entries:
            subscription_entries.append(SubscriptionEntry(
                SubscriptionKey(SubscriptionType.SCRIPT_HASH, search_entry.item_hash),
                SubscriptionScannerScriptHashOwnerContext(search_entry)))
            self._active_subscriptions[search_entry.item_hash] = search_entry
        # Subscribe to the entries.
        self._network.subscriptions.create_entries(subscription_entries, self._subscription_owner)

    async def _on_script_hash_result(self, subscription_key: SubscriptionKey,
            context: SubscriptionScannerScriptHashOwnerContext,
            history: ScriptHashHistoryList) -> None:
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
        history_entry = self._results[script_hash] = ScriptHashHistory(history)
        entry = cast(SearchEntry, context.value)
        if entry.kind == SearchEntryKind.BIP32:
            assert entry.parent_path is not None
            assert entry.parent_index > -1
            entry.parent_path.result_count += 1
            if len(history):
                entry.parent_path.highest_used_index = max(entry.parent_path.highest_used_index,
                    entry.parent_index)

            history_entry.bip32_subpath = entry.parent_path.subpath
            history_entry.bip32_subpath_index = entry.parent_index

        del self._active_subscriptions[script_hash]
        self._event.set()
        # Trigger the unsubscription for this script hash.
        raise SubscriptionStale()



@dataclass
class PushDataMatchResult:
    filter_result: RestorationFilterResult
    search_entry: SearchEntry


class PushDataHashHandler(ScannerHandlerProtocol[List[PushDataMatchResult]]):
    def __init__(self, network: Network, account: AbstractAccount) -> None:
        self._network = network
        self._account = account
        self._results: List[PushDataMatchResult] = []

    def setup(self, scanner: BlockchainScanner) -> None:
        self._scanner = scanner

    def shutdown(self) -> None:
        del self._scanner
        del self._account
        del self._network

    async def wait_until_ready(self) -> None:
        # There is no background activity to wait for.
        pass

    def get_required_count(self) -> int:
        # Look for 50 push data hashes at a time.
        return 50

    def has_ongoing_activity(self) -> bool:
        # The searching is done within the `search_entries` call, there is no background activity.
        return False

    def get_results(self) -> List[PushDataMatchResult]:
        return self._results

    async def search_entries(self, entries: List[SearchEntry]) -> None:
        """
        This will block and get all the results for the given search entries. If there are any
        exceptions due to connection errors and perhaps incomplete results, these should raise
        up out of the containing future to the managing logic.

        Raises `PushDataSearchError` if there is some problem in this function.
        Raises `FilterResponseInvalidError` if the response content type does not match what we
            accept.
        Raises `FilterResponseIncompleteError` if a response packet is incomplete. This likely
            means that the connection was closed mid-transmission.
        Raises `ServerConnectionError` if the remote computer cannot be connected to.
        """
        all_candidates = self._network.get_api_servers_for_account(
            self._account, NetworkServerType.GENERAL)
        restoration_candidates = select_servers(ServerCapability.RESTORATION, all_candidates)
        if not len(restoration_candidates):
            raise PushDataSearchError(_("No servers available."))

        # TODO better choice of which server to use, probably some centralised approach.
        candidate = random.choice(restoration_candidates)
        assert candidate.api_server is not None and candidate.api_server.config is not None

        # TODO better endpoint url resolution rather than this hard-coding.
        url = candidate.api_server.config["url"]
        url = url if url.endswith("/") else url +"/"
        url = f"{url}api/v1/restoration/search"

        # These are the pushdata hashes that have been passed along.
        entry_mapping: Dict[bytes, SearchEntry] = { entry.item_hash: entry for entry in entries }
        request_data: RestorationFilterRequest = {
            "filterKeys": [
                entry.item_hash.hex() for entry in entries
            ]
        }
        async for payload_bytes in post_restoration_filter_request_binary(url, request_data):
            filter_result = unpack_binary_restoration_entry(payload_bytes)
            search_entry = entry_mapping[filter_result.push_data_hash]
            self._results.append(PushDataMatchResult(filter_result, search_entry))


class BlockchainScanner:
    """
    NOTE(rt12) At this time, only one `Scanner` instance is supported. The main reason for this
    is that.. I do not remember! Work out why this should be the case or not before using more.
    """
    def __init__(self,
            handler: ScannerHandlerProtocol[ScanResultType],
            enumerator: SearchKeyEnumerator,
            extend_range_cb: Optional[ExtendRangeCallback]=None) -> None:
        self._handler = handler
        self._enumerator = enumerator
        self._started = False
        self._scan_entry_count = 0
        self._extend_range_cb = extend_range_cb

        self._should_exit = False

        self._handler.setup(self)

    def shutdown(self) -> None:
        """
        Required shutdown handling that any external context must invoke.
        """
        if self._should_exit:
            logger.debug("shutdown scanner, duplicate call ignored")
            return
        logger.debug("shutdown scanner")
        self._should_exit = True
        self._handler.shutdown()

    def start_scanning_for_usage(self,
            on_done: Optional[Callable[[concurrent.futures.Future[None]], None]]=None) -> None:
        logger.debug("Starting blockchain scan process")
        assert app_state.app is not None
        self._future = app_state.app.run_coro(self.scan_for_usage, on_done=on_done)

    async def scan_for_usage(self) -> None:
        """
        Enumerate and scan all relevant keys.
        """
        logger.debug("Starting blockchain scan")
        while True:
            if self._should_exit:
                logger.debug("Blockchain scan exit reason, manual interruption")
                break

            key_count = self._handler.get_required_count()
            additional_entries: List[SearchEntry] = self._enumerator.create_new_entries(key_count)
            if len(additional_entries) > 0:
                # Search for the additional entries.
                self._extend_range(len(additional_entries))
                await self._handler.search_entries(additional_entries)
            else:
                # Exit if the handler is done and the keys are all enumerated.
                if not self._handler.has_ongoing_activity() and self._enumerator.is_done():
                    logger.debug("Blockchain scan exit reason, BIP32 exhaustion")
                    break

            # If the search process is happening in the background, wait for results.
            await self._handler.wait_until_ready()
        logger.debug("Ending blockchain scan")
        self.shutdown()

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


class ItemHashProtocol(Protocol):
    """
    This provides an interface which can be used for typing of item hashers. There is no need
    to inherit it, the type checker will verify that any passed instances match.
    """

    def get_item_hash_for_public_keys(self, script_type: ScriptType, public_keys: List[PublicKey],
            threshold: int=1) -> bytes:
        """
        At this time, all output scripts are generated based on featured public keys in some
        form used in standard script templates. In the longer run this may not be the case.

        Can cover:
        - P2PK.
        - P2PKH.
        - P2SH multi-signature.
        - Bare multi-signature.
        """
        raise NotImplementedError

    def get_item_hash_for_key_data(self, key_data: KeyListRow) -> Tuple[ScriptType, bytes]:
        """
        This is primarily for imported addresses. The way an address works, and there are two
        types we inherited from Bitcoin Core, is that the hash goes in a standard script opcode
        template. We store the hash in the database for easy matching, and we can use it to
        create the output script without a lot of work.

        Can cover:
        - P2SH.
        - P2PKH.
        """
        raise NotImplementedError


class ScriptHasher:
    """
    The script hash based indexing done by ElectrumX tracks the SHA256 hash of every output
    script that is spendable. This means that you have to know exactly how your key was used
    to find your transactions, which in the world of Bitcoin Core where regular people are
    restricted to standard scripts works fine.
    """

    def get_item_hash_for_public_keys(self, script_type: ScriptType,
            public_keys: List[PublicKey], threshold: int=1) -> bytes:
        if len(public_keys) == 1:
            # P2PK
            # P2PKH
            script_template = get_single_signer_script_template(public_keys[0], script_type)
        else:
            # Bare multi-signature.
            # P2SH multi-signature.
            public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
            script_template = get_multi_signer_script_template(public_keys_hex,
                threshold, script_type)
        return cast(bytes, sha256(script_template.to_script_bytes()))

    def get_item_hash_for_key_data(self, key_data: KeyListRow) -> Tuple[ScriptType, bytes]:
        if key_data.derivation_type == DerivationType.PUBLIC_KEY_HASH:
            script_template = P2PKH_Address(key_data.derivation_data2, Net.COIN)
            item_hash = cast(bytes, sha256(script_template.to_script_bytes()))
            return ScriptType.P2PKH, item_hash
        elif key_data.derivation_type == DerivationType.SCRIPT_HASH:
            script_template = P2SH_Address(key_data.derivation_data2, Net.COIN)
            item_hash = cast(bytes, sha256(script_template.to_script_bytes()))
            return ScriptType.MULTISIG_P2SH, item_hash
        raise NotImplementedError


class PushDataHasher:
    """
    This is currently only used for account restoration. The restoration indexing that ElectrumSV
    hopes to support is currently based on SHA256 pushdata indexing. The wallet provides a list
    of pushdata hashes and asks the indexer if it has any matching data. This will only work for
    capped restoration indexing, it is not reasonable to assume that any indexer will be able
    to provide full blockchain indexes of hashes for arbitrary data (given that future transaction
    outputs are not forced into a limited set of standard script templates).
    """

    def get_item_hash_for_public_keys(self, script_type: ScriptType,
            public_keys: List[PublicKey], threshold: int=1) -> bytes:
        hashable_item: bytes = b''
        if script_type == ScriptType.P2PK:
            # We are looking for this public key.
            assert len(public_keys) == 1
            hashable_item = public_keys[0].to_bytes()
        elif script_type == ScriptType.P2PKH:
            # We are looking for the hash160 of this public key.
            assert len(public_keys) == 1
            hashable_item = public_keys[0].hash160()
        elif script_type == ScriptType.MULTISIG_BARE:
            # We are looking for any one of the featured cosigner public keys used in this.
            hashable_item = public_keys[0].to_bytes()
        elif script_type == ScriptType.MULTISIG_P2SH:
            # We are looking for the hash160 of the redeem script.
            public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
            redeem_script = P2MultiSig_Output(sorted(public_keys_hex), threshold).to_script_bytes()
            hashable_item = hash160(redeem_script)
        assert len(hashable_item)
        return cast(bytes, sha256(hashable_item))

    def get_item_hash_for_key_data(self, key_data: KeyListRow) -> Tuple[ScriptType, bytes]:
        if key_data.derivation_type == DerivationType.PUBLIC_KEY_HASH:
            # We are looking for this hash160 in a P2PKH script output.
            item_hash = cast(bytes, sha256(key_data.derivation_data2))
            return ScriptType.P2PKH, item_hash
        elif key_data.derivation_type == DerivationType.SCRIPT_HASH:
            # We are looking for this hash160 in a P2SH script output.
            item_hash = cast(bytes, sha256(key_data.derivation_data2))
            return ScriptType.MULTISIG_P2SH, item_hash
        raise NotImplementedError


class SearchKeyEnumerator:
    """
    This provides a way to iterate through the possible things we want to match on, or search keys
    to enumerate.
    """
    def __init__(self, item_hasher: ItemHashProtocol,
            settings: Optional[AdvancedSettings]=None) -> None:
        self._item_hasher = item_hasher
        if settings is None:
            settings = AdvancedSettings()
        self._settings = settings

        self._pending_subscriptions: List[SearchEntry] = []
        self._bip32_paths: List[BIP32ParentPath] = []

    def use_account(self, account: AbstractAccount) -> None:
        """
        Create a scanner that will search for usage of the keys belonging to the account.
        """
        wallet = account.get_wallet()
        assert wallet._network is not None

        account_id = account.get_id()
        account_type = account.type()
        script_types = ACCOUNT_SCRIPT_TYPES[account_type]
        if account.is_deterministic():
            threshold = account.get_threshold()
            master_public_keys = cast(List[BIP32PublicKey], [ # type: ignore
                bip32_key_from_string(mpk)
                for mpk in account.get_master_public_keys() ])
            for subpath in (CHANGE_SUBPATH, RECEIVING_SUBPATH):
                self.add_bip32_subpath(subpath, master_public_keys, threshold, script_types)
        elif account_type == AccountType.IMPORTED_ADDRESS:
            # The derivation data is the address or hash160 that relates to the script type.
            for key_data in wallet.read_key_list(account_id):
                script_type, item_hash = self._item_hasher.get_item_hash_for_key_data(key_data)
                self.add_explicit_item(key_data.keyinstance_id, script_type, item_hash)
        elif account_type == AccountType.IMPORTED_PRIVATE_KEY:
            # The derivation data is the public key for the private key.
            for key_data in wallet.read_key_list(account_id):
                assert key_data.derivation_type == DerivationType.PRIVATE_KEY
                public_key = PublicKey.from_bytes(key_data.derivation_data2)
                for script_type in script_types:
                    item_hash = self._item_hasher.get_item_hash_for_public_keys(script_type,
                        [ public_key ])
                    self.add_explicit_item(key_data.keyinstance_id, script_type, item_hash)
        else:
            raise UnsupportedAccountTypeError()

    def add_bip32_subpath(self, subpath: DerivationPath, master_public_keys: List[BIP32PublicKey],
            threshold: int, script_types: Sequence[ScriptType]) -> BIP32ParentPath:
        data = BIP32ParentPath(subpath, threshold, master_public_keys, script_types)
        self._bip32_paths.append(data)
        return data

    def add_explicit_item(self, keyinstance_id: int, script_type: ScriptType,
            item_hash: bytes) -> None:
        self._pending_subscriptions.append(SearchEntry(SearchEntryKind.EXPLICIT,
            keyinstance_id, script_type, item_hash))

    def has_sources(self) -> bool:
        return len(self._bip32_paths) > 0 or len(self._pending_subscriptions) > 0

    def is_done(self) -> bool:
        if len(self._pending_subscriptions) == 0:
            # BIP32 paths do not get removed, but they can be exhausted of candidates.
            if all(self._get_bip32_path_count(pp) == 0 for pp in self._bip32_paths):
                return True
        return False

    def create_new_entries(self, required_entries: int) -> List[SearchEntry]:
        new_entries: List[SearchEntry] = []
        # Populate any required entries from the pending scripts first.
        if required_entries > 0 and len(self._pending_subscriptions):
            how_many = min(required_entries, len(self._pending_subscriptions))
            new_entries.extend(self._pending_subscriptions[:how_many])
            del self._pending_subscriptions[:how_many]
            required_entries -= how_many

        # Populate any required entries from any unconsumed dynamic derivation sequences.
        candidates = self._obtain_any_bip32_entries(required_entries)
        if len(candidates):
            required_entries -= len(candidates)
            new_entries.extend(candidates)
        return new_entries

    def _obtain_any_bip32_entries(self, maximum_candidates: int) -> List[SearchEntry]:
        """
        Examine each BIP32 path in turn looking for candidates.
        """
        new_entries: List[SearchEntry] = []
        parent_path_index = 0
        while maximum_candidates > 0 and parent_path_index < len(self._bip32_paths):
            candidates = self._obtain_entries_from_bip32_path(maximum_candidates,
                self._bip32_paths[parent_path_index])
            new_entries.extend(candidates)
            maximum_candidates -= len(candidates)
            parent_path_index += 1
        return new_entries

    def _obtain_entries_from_bip32_path(self, maximum_candidates: int,
            parent_path: BIP32ParentPath) -> List[SearchEntry]:
        new_entries: List[SearchEntry] = []
        while maximum_candidates > 0 and self._get_bip32_path_count(parent_path) > 0:
            current_index = parent_path.last_index + 1

            public_keys: List[PublicKey] = [ public_key.child_safe(current_index)
                for public_key in parent_path.parent_public_keys ]
            for script_type in parent_path.script_types:
                item_hash = self._item_hasher.get_item_hash_for_public_keys(script_type,
                    public_keys)
                new_entries.append(SearchEntry(SearchEntryKind.BIP32, None, script_type,
                    item_hash, parent_path, current_index))

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
