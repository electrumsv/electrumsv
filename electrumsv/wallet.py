# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Wallet classes:
#   - ImportedAddressAccount: imported address, no keystore
#   - ImportedPrivkeyAccount: imported private keys, keystore
#   - StandardAccount: one keystore, P2PKH
#   - MultisigAccount: several keystores, P2SH

from collections import defaultdict
import concurrent
from dataclasses import dataclass
from datetime import datetime
import json
import os
import random
import threading
import time
from typing import (Any, cast, Dict, Iterable, List, NamedTuple, Optional, Sequence,
    Set, Tuple, TypeVar, TYPE_CHECKING, Union)
import weakref

import aiorpcx
from bitcoinx import (double_sha256, hash_to_hex_str, hex_str_to_hash, P2PKH_Address,
    P2SH_Address, PrivateKey, PublicKey, MissingHeader, Ops, pack_byte, push_item, Script)

from . import coinchooser
from .app_state import app_state
from .bitcoin import scripthash_bytes, ScriptTemplate
from .constants import (ACCOUNT_SCRIPT_TYPES, AccountType, CHANGE_SUBPATH,
    DEFAULT_TXDATA_CACHE_SIZE_MB, DerivationType, KeyInstanceFlag, KeystoreTextType,
    MAXIMUM_TXDATA_CACHE_SIZE_MB, MINIMUM_TXDATA_CACHE_SIZE_MB, pack_derivation_path, PaymentFlag,
    SubscriptionOwnerPurpose, SubscriptionType, ScriptType, TransactionInputFlag,
    TransactionOutputFlag, TxFlags, unpack_derivation_path, WalletEventFlag, WalletEventType,
    WalletSettings)
from .contacts import Contacts
from .crypto import pw_encode, sha256
from .exceptions import (ExcessiveFee, NotEnoughFunds, PreviousTransactionsMissingException,
    UserCancelled, WalletLoadError)
from .i18n import _
from .keys import get_multi_signer_script_template, get_single_signer_script_template
from .keystore import (Deterministic_KeyStore, Hardware_KeyStore, Imported_KeyStore,
    instantiate_keystore, KeyStore, Multisig_KeyStore, SinglesigKeyStoreTypes,
    SignableKeystoreTypes, StandardKeystoreTypes, Xpub)
from .logs import logs
from .networks import Net
from .storage import WalletStorage
from .transaction import (Transaction, TransactionContext, TxSerialisationFormat, NO_SIGNATURE,
    tx_dict_from_text, XPublicKey, XPublicKeyType, XTxInput, XTxOutput)
from .types import (SubscriptionEntry, SubscriptionKey, SubscriptionOwner,
    SubscriptionScriptHashOwnerContext, TxoKeyType, WaitingUpdateCallback)
from .util import (format_satoshis, get_wallet_name_from_path, timestamp_to_datetime,
    TriggeredCallbacks)
from .util.cache import LRUCache
from .wallet_database import functions as db_functions
from .wallet_database.util import create_derivation_data2, TxProof
from .wallet_database.sqlite_support import DatabaseContext
from .wallet_database.types import (AccountRow, AccountTransactionDescriptionRow,
    HistoryListRow, InvoiceAccountRow, InvoiceRow, KeyDataType, KeyDataTypes,
    KeyInstanceRow, KeyListRow, KeyInstanceScriptHashRow, MasterKeyRow,
    PaymentRequestRow, PaymentRequestUpdateRow,
    TransactionDeltaSumRow, TransactionLinkState, TransactionMetadata,
    TransactionOutputShortRow, TransactionOutputSpendableRow2, TransactionOutputSpendableRow,
    TransactionOutputSpendableTypes, TransactionValueRow,
    TransactionInputAddRow, TransactionOutputAddRow,
    TransactionRow, WalletBalance, WalletEventRow)

if TYPE_CHECKING:
    from .network import Network
    from electrumsv.gui.qt.main_window import ElectrumWindow
    from electrumsv.devices.hw_wallet.qt import QtPluginBase

logger = logs.get_logger("wallet")


class DeterministicKeyAllocation(NamedTuple):
    masterkey_id: int
    derivation_type: DerivationType
    derivation_path: Sequence[int]


@dataclass
class HistoryListEntry:
    sort_key: Tuple[int, int]
    row: HistoryListRow
    balance: int


def dust_threshold(network):
    return 546 # hard-coded Bitcoin SV dust threshold. Was changed to this as of Sept. 2018

T = TypeVar('T', bound='AbstractAccount')

class AbstractAccount:
    """
    Account classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    _default_keystore: Optional[KeyStore] = None
    _stopped: bool = False

    max_change_outputs = 10

    def __init__(self, wallet: 'Wallet', row: AccountRow, keyinstance_rows: List[KeyInstanceRow],
            transaction_descriptions: List[AccountTransactionDescriptionRow]) -> None:
        # Prevent circular reference keeping parent and accounts alive.
        self._wallet = weakref.proxy(wallet)
        self._row = row
        self._id = row.account_id
        self._subscription_owner_keys = SubscriptionOwner(self._wallet._id, self._id,
            SubscriptionOwnerPurpose.ACTIVE_KEYS)

        self._logger = logs.get_logger("account[{}]".format(self.name()))
        self._network = None

        self.request_count = 0
        self.response_count = 0
        self.last_poll_time: Optional[float] = None

        self._masterkey_ids: Set[int] = set(row.masterkey_id for row in keyinstance_rows
            if row.masterkey_id is not None)
        self._transaction_descriptions: Dict[bytes, str] = { r.tx_hash: cast(str, r.description)
            for r in transaction_descriptions }

        self._load_keys(keyinstance_rows)

        # locks: if you need to take several, acquire them in the order they are defined here!
        self.lock = threading.RLock()

    def scriptpubkey_to_scripthash(self, script):
        script_bytes = bytes(script)
        return sha256(script_bytes)

    def get_id(self) -> int:
        return self._id

    def get_wallet(self) -> 'Wallet':
        return self._wallet

    def requires_input_transactions(self) -> bool:
        return any(k.requires_input_transactions() for k in self.get_keystores())

    def get_next_derivation_index(self, derivation_path: Sequence[int]) -> int:
        raise NotImplementedError

    def allocate_keys(self, count: int,
            derivation_path: Sequence[int]) -> Sequence[DeterministicKeyAllocation]:
        """
        Produce an annotated sequence of each key that should be created.

        This should include the derivation type and the derivation context of each individual key.
        """
        raise NotImplementedError

    def get_fresh_keys(self, derivation_parent: Sequence[int], count: int) -> List[KeyInstanceRow]:
        raise NotImplementedError

    def derive_new_keys_until(self, derivation_path: Sequence[int]) -> Sequence[KeyInstanceRow]:
        """
        Ensure that keys are created up to and including the given derivation path.

        This will look at the existing keys and create any further keys if necessary
        """
        derivation_subpath = derivation_path[:-1]
        final_index = derivation_path[-1]
        with self.lock:
            next_index = self.get_next_derivation_index(derivation_subpath)
            required_count = (final_index - next_index) + 1
            assert required_count > 0, f"final={final_index}, current={next_index-1}"
            self._logger.debug("derive_new_keys_until path=%s index=%d count=%d",
                derivation_subpath, final_index, required_count)
            future, rows = self.create_keys(derivation_subpath, required_count)
            # TODO(nocheckin) Reconcile the need for waiting for the future here.
            if future is not None:
                future.result()
            return rows

    def create_keys(self, derivation_subpath: Sequence[int], count: int) \
            -> Tuple[Optional[concurrent.futures.Future], List[KeyInstanceRow]]:
        # Identify the metadata for each key that is to be created.
        key_allocations = self.allocate_keys(count, derivation_subpath)
        if not key_allocations:
            return None, []

        keyinstances: List[KeyInstanceRow] = []
        for ka in key_allocations:
            derivation_data_dict = self.create_derivation_data_dict(ka)
            derivation_data = json.dumps(derivation_data_dict).encode()
            derivation_data2 = create_derivation_data2(ka.derivation_type, derivation_data_dict)
            keyinstances.append(KeyInstanceRow(-1, self.get_id(), ka.masterkey_id,
                ka.derivation_type, derivation_data, derivation_data2, KeyInstanceFlag.IS_ACTIVE,
                None))
        keyinstance_future, rows = self._wallet.create_keyinstances(self._id, keyinstances)

        keyinstance_scripthashes: List[KeyInstanceScriptHashRow] = []
        for row in rows:
            for script_type, script in self.get_possible_scripts_for_key_data(row):
                script_hash = scripthash_bytes(script.to_bytes())
                keyinstance_scripthashes.append(KeyInstanceScriptHashRow(row.keyinstance_id,
                    script_type, script_hash))
        future_ = self._wallet.create_keyinstance_scripts(keyinstance_scripthashes)
        # TODO(nocheckin) The concept of activated keys will change with the new model.
        # self._add_activated_keys(rows)
        return keyinstance_future, rows

    def create_derivation_data_dict(self, key_allocation: DeterministicKeyAllocation) \
            -> Dict[str, Any]:
        assert key_allocation.derivation_type == DerivationType.BIP32_SUBPATH
        return { "subpath": key_allocation.derivation_path }

    def _get_subscription_entries_for_keyinstance_ids(self, keyinstance_ids: List[int]) \
            -> List[SubscriptionEntry]:
        entries: List[SubscriptionEntry] = []
        for row in self._wallet.read_keyinstance_scripts(keyinstance_ids):
            entries.append(
                SubscriptionEntry(
                    SubscriptionKey(SubscriptionType.SCRIPT_HASH, row.script_hash),
                    SubscriptionScriptHashOwnerContext(row.keyinstance_id, row.script_type)))
        return entries

    def set_keyinstance_flags(self, keyinstance_ids: List[int], flags: KeyInstanceFlag,
            mask: Optional[KeyInstanceFlag]=None) -> concurrent.futures.Future:
        """
        Encapsulate updating the flags for keyinstances belonging to this account.

        This will subscribe or unsubscribe from script hash notifications from any indexer
        automatically as any flags relating to activeness of the key are set or unset.
        """
        # We need the current flags in order to reconcile keys becoming/losing active status.
        keyinstances = self._wallet.read_keyinstances(account_id=self._id,
            keyinstance_ids=keyinstance_ids)
        assert len(keyinstances) == len(keyinstance_ids)

        subscription_keyinstance_ids: List[int] = []
        unsubscription_keyinstance_ids: List[int] = []
        for keyinstance in keyinstances:
            if flags & KeyInstanceFlag.MASK_ACTIVE:
                if not keyinstance.flags & KeyInstanceFlag.MASK_ACTIVE:
                    # Inactive -> active.
                    subscription_keyinstance_ids.append(keyinstance.keyinstance_id)
            else:
                if keyinstance.flags & KeyInstanceFlag.MASK_ACTIVE:
                    # Active -> inactive.
                    unsubscription_keyinstance_ids.append(keyinstance.keyinstance_id)

        if len(subscription_keyinstance_ids):
            app_state.subscriptions.create(
                self._get_subscription_entries_for_keyinstance_ids(subscription_keyinstance_ids),
                self._subscription_owner_keys)

        if len(unsubscription_keyinstance_ids):
            app_state.subscriptions.delete(
                self._get_subscription_entries_for_keyinstance_ids(unsubscription_keyinstance_ids),
                self._subscription_owner_keys)

        return self._wallet.set_keyinstance_flags(keyinstance_ids, flags, mask)

    def get_script_template_for_key_data(self, keydata: KeyDataTypes,
            script_type: ScriptType) -> ScriptTemplate:
        raise NotImplementedError

    def get_enabled_script_types(self) -> Sequence[ScriptType]:
        "The allowed set of script types that this account can make use of."
        raise NotImplementedError

    def get_supported_script_types(self) -> Sequence[ScriptType]:
        "The complete set of script types that this account type can make use of."
        return self.get_enabled_script_types()

    def get_possible_scripts_for_id(self, keyinstance_id: int) -> List[Tuple[ScriptType, Script]]:
        raise NotImplementedError

    def get_script_for_key_data(self, keydata: KeyDataTypes, script_type: ScriptType) \
            -> Script:
        script_template = self.get_script_template_for_key_data(keydata, script_type)
        return script_template.to_script()

    def is_synchronized(self) -> bool:
        # TODO(nocheckin) Need to reimplement to deal with scanning/pending state?
        return True

    def get_keystore(self) -> Optional[KeyStore]:
        if self._row.default_masterkey_id is not None:
            return self._wallet.get_keystore(self._row.default_masterkey_id)
        return self._default_keystore

    def get_keystores(self) -> Sequence[KeyStore]:
        keystore = self.get_keystore()
        return [ keystore ] if keystore is not None else []

    def get_keyinstances(self) -> List[KeyInstanceRow]:
        return self._wallet.read_keyinstances(account_id=self._id)

    def get_master_public_key(self):
        return None

    # TODO(nocheckin) This is not compatible with multi-account usage of the same transaction
    # unless we repackage the outer transaction. The problem here is that we would be overwriting
    # the description on the cached transaction for the last requested account.
    def get_transaction(self, tx_hash: bytes) -> Optional[Transaction]:
        """
        Get the transaction with account-specific metadata like the description.
        """
        tx = self._wallet.get_transaction(tx_hash)
        if tx is not None:
            # Populate the description.
            desc = self.get_transaction_label(tx_hash)
            if desc:
                tx.context.description = desc
            return tx
        return None

    def set_transaction_label(self, tx_hash: bytes, text: Optional[str]) -> None:
        self.set_transaction_labels([ (tx_hash, text) ])

    def set_transaction_labels(self, entries: List[Tuple[bytes, Optional[str]]]) -> None:
        update_entries = []
        for tx_hash, value in entries:
            text = None if value is None or value.strip() == "" else value.strip()
            label = self._transaction_descriptions.get(tx_hash)
            if label != text:
                if label is not None and value is None:
                    del self._transaction_descriptions[tx_hash]
                update_entries.append((text, self._id, tx_hash))

        future_ = self._wallet.update_account_transaction_descriptions(update_entries)

        for text, _account_id, tx_hash in update_entries:
            app_state.app.on_transaction_label_change(self, tx_hash, text)

    def get_transaction_label(self, tx_hash: bytes) -> str:
        label = self._transaction_descriptions.get(tx_hash)
        return "" if label is None else label

    def __str__(self) -> str:
        return self.name()

    def get_name(self) -> str:
        return self._row.account_name

    def set_name(self, name: str) -> None:
        self._wallet.update_account_names([ (name, self._row.account_id) ])

        self._row = AccountRow(self._row.account_id, self._row.default_masterkey_id,
            self._row.default_script_type, name)

        self._wallet.trigger_callback('on_account_renamed', self._id, name)

    # Displayed in the regular user UI.
    def display_name(self) -> str:
        return self._row.account_name if self._row.account_name else _("unnamed account")

    # Displayed in the advanced user UI/logs.
    def name(self) -> str:
        parent_name = self._wallet.name()
        return f"{parent_name}/{self._id}"

    # Used for exception reporting account class instance classification.
    def type(self) -> AccountType:
        return AccountType.UNSPECIFIED

    # Used for exception reporting overall account classification.
    def debug_name(self) -> str:
        k = self.get_keystore()
        if k is None:
            return self.type().value
        return f"{self.type().value}/{k.debug_name()}"

    def _load_keys(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        pass

    def is_deterministic(self) -> bool:
        # Not all wallets have a keystore, like imported address for instance.
        keystore = self.get_keystore()
        return keystore is not None and keystore.is_deterministic()

    def involves_hardware_wallet(self) -> bool:
        return any([ k for k in self.get_keystores() if isinstance(k, Hardware_KeyStore) ])

    def get_label_data(self) -> Dict[str, Any]:
        # Create exported data structure for account labels/descriptions.
        # TODO(nocheckin) Are key labels still supported?
        # NOTE(typing) Ignore when `derivation_data2` is None.
        label_entries = [
            (unpack_derivation_path(key.derivation_data2),  key.description) # type: ignore
            for key in self.get_keyinstances() if key.description is not None
        ]
        rows = self._wallet.read_account_transaction_descriptions(self._id)
        transaction_entries = [
            (hash_to_hex_str(tx_hash), description) for tx_hash, description in rows
        ]

        data: Dict[str, Any] = {}
        if len(transaction_entries):
            data["transactions"] = transaction_entries
        if len(label_entries):
            data["keys"] = {
                "account_fingerprint": self.get_fingerprint().hex(),
                "entries": label_entries,
            }
        return data

    def get_keyinstance_label(self, key_id: int) -> str:
        keyinstance = self._wallet.get_keyinstance(key_id)
        return keyinstance.description or ""

    def set_keyinstance_label(self, keyinstance_id: int, text: Optional[str]) -> None:
        text = None if text is None or text.strip() == "" else text.strip()
        keyinstance = self._wallet.get_keyinstance(keyinstance_id)
        if keyinstance.description == text:
            return
        self._wallet.update_keyinstance_descriptions([ (text, keyinstance_id) ])
        app_state.app.on_keyinstance_label_change(self, keyinstance_id, text)

    def get_dummy_script_template(self, script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        public_key = PrivateKey(os.urandom(32)).public_key
        return self.get_script_template(public_key, script_type)

    def get_script_template(self, public_key: PublicKey,
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        if script_type is None:
            script_type = self.get_default_script_type()
        return get_single_signer_script_template(public_key, script_type)

    def get_default_script_type(self) -> ScriptType:
        return ScriptType(self._row.default_script_type)

    def set_default_script_type(self, script_type: ScriptType) -> None:
        if script_type == self._row.default_script_type:
            return
        self._wallet.update_account_script_types([ (script_type, self._row.account_id) ])
        self._row = self._row._replace(default_script_type=script_type)

    def get_threshold(self, script_type: ScriptType) -> int:
        assert script_type in (ScriptType.P2PKH, ScriptType.P2PK), \
            f"get_threshold got bad script type {script_type}"
        return 1

    def export_private_key(self, keydata: KeyDataTypes, password: str) -> Optional[str]:
        """ extended WIF format """
        if self.is_watching_only():
            return None
        keystore = self._wallet.get_keystore(keydata.masterkey_id)
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        secret, compressed = keystore.get_private_key(derivation_path, password)
        return PrivateKey(secret).to_WIF(compressed=compressed, coin=Net.COIN)

    def get_frozen_balance(self) -> Tuple[int, int, int]:
        return self._wallet.read_account_balance(self._id, self._wallet.get_local_height(),
            TransactionOutputFlag.IS_FROZEN)

    def get_balance(self) -> Tuple[int, int, int]:
        return self._wallet.read_account_balance(self._id, self._wallet.get_local_height())

    def maybe_set_transaction_dispatched(self, tx_hash: bytes) -> bool:
        """
        We should only ever mark a transaction as dispatched if it hasn't already been broadcast.
        raises UnknownTransactionException
        """
        if self._wallet.set_transaction_dispatched(tx_hash):
            self._wallet.trigger_callback('transaction_state_change', self._id, tx_hash,
                TxFlags.STATE_DISPATCHED)
            return True
        return False

    def get_paid_requests(self, keyinstance_ids: Sequence[int]) -> List[int]:
        return self._wallet.read_paid_requests(self._id, keyinstance_ids)

    def get_raw_balance(self, flags: Optional[int]=None, mask: Optional[int]=None) \
            -> TransactionDeltaSumRow:
        return self._wallet.read_account_balance_raw(self._id, flags, mask)

    def get_key_list(self, keyinstance_ids: Optional[List[int]]=None) -> List[KeyListRow]:
        return self._wallet.read_key_list(self._id, keyinstance_ids)

    def get_local_transaction_entries(self, tx_hashes: Optional[List[bytes]]=None) \
            -> List[TransactionValueRow]:
        return self._wallet.read_transaction_value_entries(self._id, tx_hashes=tx_hashes,
            mask=TxFlags.MASK_STATE_UNCLEARED)

    def get_transaction_value_entries(self, mask: Optional[TxFlags]=None) \
            -> List[TransactionValueRow]:
        return self._wallet.read_transaction_value_entries(self._id, mask=mask)

    def get_transaction_outputs(self, flags: TransactionOutputFlag, mask: TransactionOutputFlag,
            require_key_usage: bool=False, tx_hash: Optional[bytes]=None) \
                -> List[TransactionOutputSpendableRow2]:
        return self._wallet.read_account_transaction_outputs(self._id, flags, mask,
            require_key_usage, tx_hash)

    def get_spendable_transaction_outputs(self, exclude_frozen: bool=True, mature: bool=True,
            confirmed_only: Optional[bool]=None, keyinstance_ids: Optional[List[int]]=None) \
                -> List[TransactionOutputSpendableRow]:
        if confirmed_only is None:
            confirmed_only = app_state.config.get('confirmed_only', False)
        mature_height = self._wallet.get_local_height() if mature else None
        return self._wallet.read_account_transaction_outputs_spendable(self._id,
            confirmed_only=confirmed_only, mature_height=mature_height,
            exclude_frozen=exclude_frozen)

    def get_spendable_transaction_outputs_extended(self, exclude_frozen: bool=True,
            mature: bool=True, confirmed_only: Optional[bool]=None,
            keyinstance_ids: Optional[List[int]]=None) -> List[TransactionOutputSpendableRow2]:
        if confirmed_only is None:
            confirmed_only = app_state.config.get('confirmed_only', False)
        mature_height = self._wallet.get_local_height() if mature else None
        return self._wallet.read_account_transaction_outputs_spendable_extended(self._id,
            confirmed_only=confirmed_only, mature_height=mature_height,
            exclude_frozen=exclude_frozen)

    def get_extended_input_for_spendable_output(self, row: TransactionOutputSpendableTypes) \
            -> XTxInput:
        assert row.account_id == self._id
        assert row.keyinstance_id is not None
        assert row.derivation_type is not None
        x_pubkeys = self.get_xpubkeys_for_key_data(row)
        # NOTE(typing) The first four arguments for `TxInput` cause mypy to choke because `attrs`..
        return XTxInput( # type: ignore
            prev_hash          = row.tx_hash,
            prev_idx           = row.txo_index,
            script_sig         = Script(),
            sequence           = 0xffffffff,
            threshold          = self.get_threshold(row.script_type),
            script_type        = row.script_type,
            signatures         = [NO_SIGNATURE] * len(x_pubkeys),
            x_pubkeys          = x_pubkeys,
            value              = row.value,
            key_data           = KeyDataType(row.keyinstance_id, row.account_id, row.masterkey_id,
                                    row.derivation_type, row.derivation_data2)
        )

    def get_history(self, domain: Optional[Set[int]]=None) -> List[HistoryListEntry]:
        """
        Return the list of transactions in the account kind of sorted from newest to oldest.

        Sorting is nuanced, in that transactions that are in a block are sorted by both block
        height and position. Transactions that are not in a block are ordered according to when
        they were added to the account.

        This is called for three uses:
        - The transaction list in the history tab.
        - The transaction list in the key usage window.
        - Exporting the account history.
        """
        history_raw: List[HistoryListEntry] = []

        for row in self._wallet.read_history_list(self._id, domain):
            if row.block_position is not None:
                sort_key = row.block_height, row.block_position
            else:
                sort_key = (1e9, row.date_created)
            history_raw.append(HistoryListEntry(sort_key, row, 0))

        history_raw.sort(key=lambda t: t.sort_key)

        balance = 0
        for entry in history_raw:
            balance += entry.row.value_delta
            entry.balance = balance
        history_raw.reverse()
        return history_raw

    def export_history(self, from_timestamp=None, to_timestamp=None,
                       show_addresses=False):
        h = self.get_history()
        fx = app_state.fx
        out = []

        network = app_state.daemon.network
        chain = app_state.headers.longest_chain()
        backfill_headers = network.backfill_headers_at_heights
        header_at_height = app_state.headers.header_at_height
        server_height = network.get_server_height() if network else 0
        for history_line, balance in h:
            try:
                timestamp = timestamp_to_datetime(header_at_height(chain,
                                history_line.height).timestamp)
            except MissingHeader:
                if history_line.height > 0:
                    self._logger.debug("fetching missing headers at height: %s",
                                       history_line.height)
                    assert history_line.height <= server_height, "inconsistent blockchain data"
                    backfill_headers([history_line.height])
                    timestamp = timestamp_to_datetime(header_at_height(chain,
                                    history_line.height).timestamp)
                else:
                    timestamp = datetime.now()
            if from_timestamp and timestamp < from_timestamp:
                continue
            if to_timestamp and timestamp >= to_timestamp:
                continue
            item = {
                'txid': hash_to_hex_str(history_line.tx_hash),
                'height': history_line.height,
                'timestamp': timestamp.isoformat(),
                'value': format_satoshis(history_line.value_delta,
                            is_diff=True) if history_line.value_delta is not None else '--',
                'balance': format_satoshis(balance),
                'label': self.get_transaction_label(history_line.tx_hash)
            }
            if fx:
                date = timestamp
                item['fiat_value'] = fx.historical_value_str(history_line.value_delta, date)
                item['fiat_balance'] = fx.historical_value_str(balance, date)
            out.append(item)
        return out

    def create_extra_outputs(self, coins: List[TransactionOutputSpendableTypes],
            outputs: List[XTxOutput], force: bool=False) -> List[XTxOutput]:
        # Hardware wallets can only sign a limited range of output types (not OP_FALSE OP_RETURN).
        if self.involves_hardware_wallet() or len(coins) == 0:
            return []

        ## Extra: Add an output that is not compatible with Bitcoin Cash.
        if not force and not self._wallet.get_boolean_setting(WalletSettings.ADD_SV_OUTPUT):
            return []

        # We use the first signing public key from the first of the ordered UTXOs, for most coin
        # script types there will only be one signing public key, with the exception of
        # multi-signature accounts.
        ordered_coins = sorted(coins, key=lambda v: cast(int, v.keyinstance_id))
        for public_key in self.get_public_keys_for_key_data(ordered_coins[0]):
            raw_payload_bytes = push_item(os.urandom(random.randrange(32)))
            payload_bytes = public_key.encrypt_message(raw_payload_bytes)
            script_bytes = pack_byte(Ops.OP_0) + pack_byte(Ops.OP_RETURN) + push_item(payload_bytes)
            script = Script(script_bytes)
            # NOTE(rt12) This seems to be some attrs/mypy clash, the base class attrs should come
            # before the XTxOutput attrs, but typing expects these to be the XTxOutput attrs.
            return [XTxOutput(0, script)] # type: ignore

        return []

    def dust_threshold(self):
        return dust_threshold(self._network)

    def make_unsigned_transaction(self, unspent_outputs: List[TransactionOutputSpendableTypes],
            outputs: List[XTxOutput], fixed_fee: Optional[int]=None) -> Transaction:
        # check outputs
        all_index = None
        for n, output in enumerate(outputs):
            if output.value is all:
                if all_index is not None:
                    raise ValueError("More than one output set to spend max")
                all_index = n

        # Avoid index-out-of-range with inputs[0] below
        if not unspent_outputs:
            raise NotEnoughFunds()

        if fixed_fee is None and app_state.config.fee_per_kb() is None:
            raise Exception('Dynamic fee estimates not available')

        fee_estimator = app_state.config.estimate_fee if fixed_fee is None \
            else lambda size: fixed_fee
        inputs = [ self.get_extended_input_for_spendable_output(utxo) for utxo in unspent_outputs ]
        if all_index is None:
            # Let the coin chooser select the coins to spend
            # TODO(rt12) BACKLOG Hardware wallets should use 1 change at most. Make sure the
            # corner case of the active multisig cosigning wallet being hardware is covered.
            max_change = self.max_change_outputs \
                if self._wallet.get_boolean_setting(WalletSettings.MULTIPLE_CHANGE, True) else 1
            if self._wallet.get_boolean_setting(WalletSettings.USE_CHANGE, True) and \
                    self.is_deterministic():
                script_type = self.get_default_script_type()
                change_keyinstances = self.get_fresh_keys(CHANGE_SUBPATH, max_change)
                change_outs = []
                for keyinstance in change_keyinstances:
                    # NOTE(typing) `attrs` and `mypy` are not compatible, `TxOutput` vars unseen.
                    change_outs.append(XTxOutput( # type: ignore
                        value       = 0,
                        script      = self.get_script_for_key_data(keyinstance, script_type),
                        script_type = script_type,
                        x_pubkeys   = self.get_xpubkeys_for_key_data(keyinstance)))
            else:
                # NOTE(typing) `attrs` and `mypy` are not compatible, `TxOutput` vars unseen.
                change_outs = [ XTxOutput( # type: ignore
                    value         = 0,
                    script        = self.get_script_for_key_data(unspent_outputs[0],
                                        unspent_outputs[0].script_type),
                    script_type   = inputs[0].script_type,
                    x_pubkeys     = inputs[0].x_pubkeys) ]
            coin_chooser = coinchooser.CoinChooserPrivacy()
            tx = coin_chooser.make_tx(inputs, outputs, change_outs, fee_estimator,
                self.dust_threshold())
        else:
            assert all(txin.value is not None for txin in inputs)
            sendable = cast(int, sum(txin.value for txin in inputs))
            outputs[all_index].value = 0
            tx = Transaction.from_io(inputs, outputs)
            fee = cast(int, fee_estimator(tx.estimated_size()))
            outputs[all_index].value = max(0, sendable - tx.output_value() - fee)
            tx = Transaction.from_io(inputs, outputs)

        # If user tries to send too big of a fee (more than 50
        # sat/byte), stop them from shooting themselves in the foot
        tx_in_bytes=tx.estimated_size()
        fee_in_satoshis=tx.get_fee()
        sats_per_byte=fee_in_satoshis/tx_in_bytes
        if sats_per_byte > 50:
           raise ExcessiveFee()

        # Sort the inputs and outputs deterministically
        tx.BIP_LI01_sort()
        # Timelock tx to current height.
        locktime = self._wallet.get_local_height()
        if locktime == -1: # We have no local height data (no headers synced).
            locktime = 0
        tx.locktime = locktime
        return tx

    def start(self, network) -> None:
        self._network = network
        if network:
            app_state.subscriptions.set_owner_callback(self._subscription_owner_keys,
                self._on_network_key_script_hash_result)
            # TODO(nocheckin). Register the owners for this account.

    def stop(self) -> None:
        assert not self._stopped
        self._stopped = True

        self._logger.debug("stopping account %s", self)
        if self._network:
            # Unsubscribe from the account's existing subscriptions.
            app_state.subscriptions.remove_owner(self._subscription_owner_keys)
            self._network = None

    def _on_network_key_script_hash_result(self, subscription_type: SubscriptionType,
            script_hash: bytes, history: Dict[str, Any]) -> None:
        """
        Receive an event related to this account and it's active keys.
        """
        pass
        # TODO(nocheckin) There is a problem here in that we have no context for the script
        # hash. Can we add user data/a context to the subscription?

    def can_export(self) -> bool:
        if self.is_watching_only():
            return False
        keystore = self.get_keystore()
        if keystore is not None:
            return cast(KeyStore, keystore).can_export()
        return False

    def cpfp(self, tx: Transaction, fee: int) -> Optional[Transaction]:
        """
        Construct a "child pays for parent" transaction for `tx`.
        """
        # TODO(nocheckin) get any output for this transaction that belongs to this account.
        # Get all outputs for this transaction with keyinstances
        # TODO(nocheckin) we need to get the script and the xpubkeys for the child
        tx_hash = tx.hash()
        # These are required to have attached keys, so will be account coins received in the
        # given transaction.
        db_outputs = self._wallet.get_transaction_outputs_spendable_explicit(account_id=self._id,
            tx_hash=tx_hash, require_spends=True)
        if not db_outputs:
            return None

        db_outputs = sorted(db_outputs, key=lambda db_output: -db_output.value)
        output = db_outputs[0]
        inputs = [ self.get_extended_input_for_spendable_output(output) ]
        # TODO(rt12) This should get a change output key from the account (if applicable).
        outputs = [
            XTxOutput(
                # TxOutput
                output.value - fee,
                self.get_script_for_key_data(output, output.script_type),
                # XTxOutput
                output.script_type,
                self.get_xpubkeys_for_key_data(output)) # type: ignore
        ]
        locktime = self._wallet.get_local_height()
        # note: no need to call tx.BIP_LI01_sort() here - single input/output
        return Transaction.from_io(inputs, outputs, locktime=locktime)

    def can_sign(self, tx: Transaction) -> bool:
        if tx.is_complete():
            return False
        for k in self.get_keystores():
            if k.can_sign(tx):
                return True
        return False

    def get_xpubkeys_for_key_data(self, row: KeyDataTypes) -> List[XPublicKey]:
        raise NotImplementedError

    def get_master_public_keys(self):
        raise NotImplementedError

    def get_public_keys_for_key_data(self, keydata: KeyDataTypes) -> List[PublicKey]:
        raise NotImplementedError

    def sign_transaction(self, tx: Transaction, password: str,
            tx_context: Optional[TransactionContext]=None) -> None:
        if self.is_watching_only():
            return

        if tx_context is None:
            tx_context = TransactionContext()

        # This is primarily required by hardware wallets in order for them to sign transactions.
        # But it should be extended to bundle SPV proofs, and other general uses at a later time.
        self.obtain_supporting_data(tx, tx_context)

        # sign
        for k in self.get_keystores():
            try:
                if k.can_sign(tx):
                    k.sign_transaction(tx, password, tx_context)
            except UserCancelled:
                continue

        # Incomplete transactions are multi-signature transactions that have not passed the
        # required signature threshold. We do not store these until they are fully signed.
        if tx.is_complete():
            tx_hash = tx.hash()
            tx_flags = TxFlags.STATE_SIGNED
            if tx_context.invoice_id:
                tx_flags |= TxFlags.PAYS_INVOICE

            app_state.async_.spawn_and_wait(self._wallet.add_local_transaction,
                tx_hash, tx, tx_flags)

            # The transaction has to be in the database before we can refer to it in the invoice.
            if tx_flags & TxFlags.PAYS_INVOICE:
                future = self._wallet.update_invoice_transactions(
                    [ (tx_hash, cast(int, tx_context.invoice_id)) ])
                future.result()
            if tx_context.description:
                self.set_transaction_label(tx_hash, tx_context.description)

    def obtain_supporting_data(self, tx: Transaction, tx_context: TransactionContext) -> None:
        # Called by the signing logic to ensure all the required data is present.
        # Should be called by the logic that serialises incomplete transactions to gather the
        # context for the next party.
        if self.requires_input_transactions():
            self.obtain_previous_transactions(tx, tx_context)

        # Annotate the outputs to the account's own keys for hardware wallets.
        # - Digitalbitbox makes use of all available output annotations.
        # - Keepkey and Trezor use this to annotate one arbitrary change address.
        # - Ledger kind of ignores it?
        # Hardware wallets cannot send to internal outputs for multi-signature, only have P2SH!
        if any([isinstance(k,Hardware_KeyStore) and k.can_sign(tx) for k in self.get_keystores()]):
            self._add_hardware_derivation_context(tx)

    def obtain_previous_transactions(self, tx: Transaction, tx_context: TransactionContext,
            update_cb: Optional[WaitingUpdateCallback]=None) -> None:
        # Called by the signing logic to ensure all the required data is present.
        # Should be called by the logic that serialises incomplete transactions to gather the
        # context for the next party.
        # Raises PreviousTransactionsMissingException
        need_tx_hashes: Set[bytes] = set()
        for txin in tx.inputs:
            txid = hash_to_hex_str(txin.prev_hash)
            prev_tx: Optional[Transaction] = tx_context.prev_txs.get(txin.prev_hash)
            if prev_tx is None:
                # If the input is a coin we are spending, then it should be in the database.
                # Otherwise we'll try to get it from the network - as long as we are not offline.
                # In the longer term, the other party whose coin is being spent should have
                # provided the source transaction. The only way we should lack it is because of
                # bad wallet management.
                if self._wallet.have_transaction(txin.prev_hash):
                    self._logger.debug("fetching input transaction %s from cache", txid)
                    if update_cb is not None:
                        update_cb(False, _("Retrieving local transaction.."))
                    prev_tx = self._wallet.get_transaction(txin.prev_hash)
                else:
                    if update_cb is not None:
                        update_cb(False, _("Requesting transaction from external service.."))
                    prev_tx = self._external_transaction_request(txin.prev_hash)
            if prev_tx is None:
                need_tx_hashes.add(txin.prev_hash)
            else:
                tx_context.prev_txs[txin.prev_hash] = prev_tx
                if update_cb is not None:
                    update_cb(True)
        if need_tx_hashes:
            have_tx_hashes = set(tx_context.prev_txs)
            raise PreviousTransactionsMissingException(have_tx_hashes, need_tx_hashes)

    def _external_transaction_request(self, tx_hash: bytes) -> Optional[Transaction]:
        txid = hash_to_hex_str(tx_hash)
        if self._network is None:
            self._logger.debug("unable to fetch input transaction %s from network (offline)", txid)
            return None

        self._logger.debug("fetching input transaction %s from network", txid)
        try:
            tx_hex = self._network.request_and_wait('blockchain.transaction.get', [ txid ])
        except aiorpcx.jsonrpc.RPCError:
            self._logger.exception("failed retrieving transaction")
            return None
        else:
            # TODO(possibly) Once we've moved away from indexer state being authoritative
            # over the contents of a wallet, we should be able to add this to the
            # database as an non-owned input transaction. This isn't necessarily what we want
            # so we may want to make it an opt-in user option.
            return Transaction.from_hex(tx_hex)

    def _add_hardware_derivation_context(self, tx: Transaction) -> None:
        # add output info for hw wallets
        # the hw keystore at the time of signing does not have access to either the threshold
        # or the larger set of xpubs it's own mpk is included in. So we collect these in the
        # wallet at this point before proceeding to sign.
        info = []
        xpubs = self.get_master_public_keys()
        for tx_output in tx.outputs:
            output_items = {}
            # NOTE(rt12) this will need to exclude all script types hardware wallets dont use
            if tx_output.script_type != ScriptType.MULTISIG_BARE:
                for x_public_key in tx_output.x_pubkeys:
                    candidate_keystores = [ k for k in self.get_keystores()
                        if k.is_signature_candidate(x_public_key) ]
                    if len(candidate_keystores) == 0:
                        continue
                    # TODO(checkin)
                    pubkeys = self.get_public_keys_for_key_data(tx_output)
                    pubkeys = [pubkey.to_hex() for pubkey in pubkeys]
                    sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
                    item = (x_public_key.derivation_path(), sorted_xpubs,
                        self.get_threshold(self.get_default_script_type()))
                    output_items[candidate_keystores[0].get_fingerprint()] = item
            info.append(output_items)
        tx.output_info = info

    def estimate_extend_serialised_transaction_steps(self, format: TxSerialisationFormat,
            tx: Transaction, data: Dict[str, Any]) -> int:
        """
        Calculate how many steps are involved in extending the serialised transaction.

        This is intended to be used by the progress dialog so that it can show some approximation
        of the amount of work involved in doing this, with which the user can visualise progress.
        This represents the work done in `extend_serialised_transaction`, and should be updated
        as that function is changed.
        """
        if format == TxSerialisationFormat.JSON_WITH_PROOFS:
            return len(tx.inputs)
        return 0

    def extend_serialised_transaction(self, format: TxSerialisationFormat, tx: Transaction,
            data: Dict[str, Any], update_cb: Optional[WaitingUpdateCallback]=None) \
            -> Optional[Dict[str, Any]]:
        """
        Worker function that gathers the data required for serialised transactions.

        `update_cb` if provided is given as the last argument by `WaitingDialog` and `TxDialog`.
        """
        if format == TxSerialisationFormat.JSON_WITH_PROOFS:
            try:
                self.obtain_previous_transactions(tx, tx.context, update_cb)
            except RuntimeError:
                if update_cb is None:
                    self._logger.exception("unexpected runtime error")
                else:
                    # Sometimes we will get a Qt error depending on when things are interrupted.
                    # This cannot be avoided, and it can be ignored safely.
                    #
                    #   RuntimeError: wrapped C/C++ object of type WaitingDialog has been deleted
                    self._logger.debug("extend_serialised_transaction interrupted")
                return None
            else:
                data["prev_txs"] = [ ptx.to_hex() for ptx in tx.context.prev_txs.values() ]
        return data

    def get_fingerprint(self) -> bytes:
        raise NotImplementedError()

    def can_import_privkey(self):
        return False

    def can_import_address(self):
        return False

    def can_delete_key(self):
        return False

    # TODO(nocheckin) This whole concept needs to be rewritten
    # def _add_activated_keys(self, keys: Sequence[KeyInstanceRow]) -> None:
    #     # There is no unique id for the account, so we just pass the wallet for now.
    #     self._wallet.trigger_callback('on_keys_created', self._id, keyinstance_ids)

    # TODO(nocheckin) need to remove when we deal with a new deactivated key system
    # def poll_used_key_detection(self, every_n_seconds: int) -> None:
    #     if self.last_poll_time is None or time.time() - self.last_poll_time > every_n_seconds:
    #         self.last_poll_time = time.time()
    #         self.detect_used_keys()

    # TODO(nocheckin) need to remove when we deal with a new deactivated key system
    # def detect_used_keys(self) -> None:
    #     """Note: re-activation of keys is dealt with via:
    #       a) reorg detection time - see self.reactivate_reorged_keys()
    #       b) manual re-activation by the user

    #     Therefore, this function only needs to deal with deactivation"""

    #     if not self._wallet._storage.get('deactivate_used_keys', False):
    #         return

    #     # Get all used keys with zero balance (of the ones that are currently active)
    #     self._logger.debug("detect-used-keys: checking active keys for deactivation criteria")
    #     with TransactionDeltaTable(self._wallet._db_context) as table:
    #         used_keyinstance_ids = table.update_used_keys(self._id)

    #     if len(used_keyinstance_ids) == 0:
    #         return

    #     used_keyinstances = []
    #     with self._deactivated_keys_lock:
    #         for keyinstance_id in used_keyinstance_ids:
    #             self._deactivated_keys.append(keyinstance_id)
    #             key: KeyInstanceRow = self._keyinstances[keyinstance_id]
    #             used_keyinstances.append(key)
    #         self._deactivated_keys_event.set()

    #     self.update_key_activation_state_cache(used_keyinstances, False)
    #     self._logger.debug("deactivated %s used keys", len(used_keyinstance_ids))

    # def update_key_activation_state(self, keyinstances: List[KeyInstanceRow], activate: bool) \
    #         -> None:
    #     db_updates = self.update_key_activation_state_cache(keyinstances, activate)
    #     self._wallet.update_keyinstance_flags(db_updates)

    # def update_key_activation_state_cache(self, keyinstances: List[KeyInstanceRow],
    #         activate: bool) -> List[Tuple[KeyInstanceFlag, int]]:
    #     db_updates = []
    #     for key in keyinstances:
    #         old_flags = KeyInstanceFlag(key.flags)
    #         if activate:
    #             new_flags = old_flags | KeyInstanceFlag.IS_ACTIVE
    #         else:
    #             # if USER_SET_ACTIVE flag is set - this flag will remain
    #             new_flags = old_flags & (KeyInstanceFlag.MASK_INACTIVE |
    #                 KeyInstanceFlag.USER_SET_ACTIVE)
    #         self._keyinstances[key.keyinstance_id] = key._replace(flags=new_flags)
    #         db_updates.append((new_flags, key.keyinstance_id))
    #     return db_updates

    def reactivate_reorged_keys(self, reorged_tx_hashes: List[bytes]) -> None:
        """re-activate all of the reorged keys and allow deactivation to occur via the usual
        mechanisms."""
        pass
        # with self.lock:
        #     key_ids: List[int] = []
            # TODO(nocheckin) needs to be unatchive keys for the reorged transactions?
            # Need to work out the larger model.
            # for tx_hash in reorged_tx_hashes:
            #     tx_key_ids.append((tx_hash, self._sync_state.get_transaction_key_ids(
            #         hash_to_hex_str(tx_hash))))
            # self.unarchive_keys(key_ids)

    def sign_message(self, key_data: KeyDataTypes, message, password: str):
        assert key_data.derivation_data2 is not None
        derivation_path = unpack_derivation_path(key_data.derivation_data2)
        keystore = cast(SignableKeystoreTypes, self.get_keystore())
        return keystore.sign_message(derivation_path, message, password)

    def decrypt_message(self, key_data: KeyDataTypes, message, password: str):
        assert key_data.derivation_data2 is not None
        derivation_path = unpack_derivation_path(key_data.derivation_data2)
        keystore = cast(SignableKeystoreTypes, self.get_keystore())
        return keystore.decrypt_message(derivation_path, message, password)

    def is_watching_only(self) -> bool:
        raise NotImplementedError

    def can_change_password(self) -> bool:
        raise NotImplementedError

    def can_spend(self) -> bool:
        # All accounts can at least construct unsigned transactions except for imported address
        # accounts.
        return True


class SimpleAccount(AbstractAccount):
    # wallet with a single keystore

    def is_watching_only(self) -> bool:
        return cast(KeyStore, self.get_keystore()).is_watching_only()

    def can_change_password(self) -> bool:
        return cast(KeyStore, self.get_keystore()).can_change_password()


class ImportedAccountBase(SimpleAccount):
    def can_delete_key(self) -> bool:
        return True

    def has_seed(self) -> bool:
        return False

    def get_master_public_keys(self):
        return []

    def get_fingerprint(self) -> bytes:
        return b''


class ImportedAddressAccount(ImportedAccountBase):
    # Watch-only wallet of imported addresses

    # def __init__(self, wallet: 'Wallet', row: AccountRow,
    #         keyinstance_rows: List[KeyInstanceRow],
    #         description_rows: List[AccountTransactionDescriptionRow]) -> None:
    #     super().__init__(wallet, row, keyinstance_rows, description_rows)

    def type(self) -> AccountType:
        return AccountType.IMPORTED_ADDRESS

    def is_watching_only(self) -> bool:
        return True

    def can_spend(self) -> bool:
        return False

    def can_import_privkey(self):
        return False

    def can_change_password(self) -> bool:
        return False

    def can_import_address(self) -> bool:
        return True

    # TODO(nocheckin,test) verify this still works.
    def import_address(self, address: P2PKH_Address) -> bool:
        assert isinstance(address, P2PKH_Address)

        # TODO(nocheckin,test) verify that this does indeed find any existing keys.
        existing_key = self._wallet.read_keyinstance_for_derivation(self._id,
            DerivationType.PUBLIC_KEY_HASH, address.hash160())
        if existing_key is None:
            return False

        derivation_data_dict = { "hash": address.to_string() }
        derivation_data = json.dumps(derivation_data_dict).encode()
        derivation_data2 = create_derivation_data2(DerivationType.PUBLIC_KEY_HASH,
            derivation_data_dict)
        raw_keyinstance = KeyInstanceRow(-1, -1,
            None, DerivationType.PUBLIC_KEY_HASH, derivation_data, derivation_data2,
            KeyInstanceFlag.IS_ACTIVE, None)
        keyinstance_future, rows = self._wallet.create_keyinstances(self._id, [ raw_keyinstance ])

        # TODO(nocheckin) The concept of activated keys is going to change to a different model.
        # self._add_activated_keys(rows)
        return True

    def get_public_keys_for_key_data(self, keydata: KeyDataTypes) -> List[PublicKey]:
        return [ ]

    def get_script_template_for_key_data(self, keydata: KeyDataTypes,
            script_type: ScriptType) -> ScriptTemplate:
        if keydata.derivation_type == DerivationType.PUBLIC_KEY_HASH:
            assert script_type == ScriptType.P2PKH
            return P2PKH_Address(keydata.derivation_data2, Net.COIN)
        elif keydata.derivation_type == DerivationType.SCRIPT_HASH:
            assert script_type == ScriptType.MULTISIG_P2SH
            return P2SH_Address(keydata.derivation_data2, Net.COIN)
        else:
            raise NotImplementedError(f"derivation_type {keydata.derivation_type}")


class ImportedPrivkeyAccount(ImportedAccountBase):
    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            description_rows: List[AccountTransactionDescriptionRow]) -> None:
        assert all(row.derivation_type == DerivationType.PRIVATE_KEY for row in keyinstance_rows)
        self._default_keystore = Imported_KeyStore()
        AbstractAccount.__init__(self, wallet, row, keyinstance_rows, description_rows)

    def type(self) -> AccountType:
        return AccountType.IMPORTED_PRIVATE_KEY

    def is_watching_only(self) -> bool:
        return False

    def can_import_privkey(self):
        return True

    # TODO(obsolete?)
    def _load_keys(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        cast(Imported_KeyStore, self._default_keystore).load_state(keyinstance_rows)

    # TODO(nocheckin) what should this account type do here?
    # def _unload_keys(self, key_ids: Set[int]) -> None:
    #     for key_id in key_ids:
    #         cast(Imported_KeyStore, self._default_keystore).remove_key(key_id)
    #     super()._unload_keys(key_ids)

    def can_change_password(self) -> bool:
        return True

    def can_import_address(self) -> bool:
        return False

    def import_private_key(self, private_key_text: str, password: str) -> str:
        public_key = PrivateKey.from_text(private_key_text).public_key
        keystore = cast(Imported_KeyStore, self.get_keystore())

        # Prevent re-importing existing entries.
        existing_key = self._wallet.read_keyinstance_for_derivation(self._id,
            DerivationType.PRIVATE_KEY, public_key.to_bytes(compressed=True))
        if existing_key is not None:
            return private_key_text

        enc_private_key_text = pw_encode(private_key_text, password)
        derivation_data_dict = {
            "pub": public_key.to_hex(),
            "prv": enc_private_key_text,
        }
        derivation_data = json.dumps(derivation_data_dict).encode()
        derivation_data2 = create_derivation_data2(DerivationType.PRIVATE_KEY, derivation_data_dict)
        raw_keyinstance = KeyInstanceRow(-1, -1, None, DerivationType.PRIVATE_KEY, derivation_data,
            derivation_data2, KeyInstanceFlag.IS_ACTIVE, None)
        keyinstance_future, rows = self._wallet.create_keyinstances(self._id, [ raw_keyinstance ])
        # TODO(nocheckin) imported private keystores need the key instances.
        keystore.import_private_key(rows[0].keyinstance_id, public_key, enc_private_key_text)
        # TODO(nocheckin) The concept of activated keys is going away as we change models.
        # self._add_activated_keys(rows)
        return private_key_text

    def export_private_key(self, keydata: KeyDataTypes, password: str) -> str:
        '''Returned in WIF format.'''
        keystore = cast(Imported_KeyStore, self.get_keystore())
        public_key = PublicKey.from_bytes(keydata.derivation_data2)
        return keystore.export_private_key(public_key, password)

    def get_public_keys_for_key_data(self, keydata: KeyDataTypes) -> List[PublicKey]:
        return [ PublicKey.from_bytes(keydata.derivation_data2) ]

    def get_xpubkeys_for_key_data(self, row: KeyDataTypes) -> List[XPublicKey]:
        return [ self._get_xpubkey_for_key_data(row) ]

    def _get_xpubkey_for_key_data(self, row: KeyDataTypes) -> XPublicKey:
        return XPublicKey(pubkey_bytes=row.derivation_data2)

    def get_script_template_for_key_data(self, keydata: KeyDataTypes,
            script_type: ScriptType) -> ScriptTemplate:
        public_key = self.get_public_keys_for_key_data(keydata)[0]
        return self.get_script_template(public_key, script_type)


class DeterministicAccount(AbstractAccount):
    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            description_rows: List[AccountTransactionDescriptionRow]) -> None:
        AbstractAccount.__init__(self, wallet, row, keyinstance_rows, description_rows)

    def has_seed(self) -> bool:
        return cast(Deterministic_KeyStore, self.get_keystore()).has_seed()

    def get_seed(self, password: Optional[str]) -> str:
        return cast(Deterministic_KeyStore, self.get_keystore()).get_seed(password)

    def get_next_derivation_index(self, derivation_path: Sequence[int]) -> int:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        return self._wallet.get_next_derivation_index(self._id, keystore.get_id(),
            derivation_path)

    def allocate_keys(self, count: int,
            parent_derivation_path: Sequence[int]) -> Sequence[DeterministicKeyAllocation]:
        """
        Produce an annotated sequence of each key that should be created.

        This should include the derivation type and the derivation context of each individual key.
        """
        if count <= 0:
            return []

        self._logger.info(f'creating {count} new keys within {parent_derivation_path}')
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        masterkey_id = keystore.get_id()
        next_index = self.get_next_derivation_index(parent_derivation_path)
        return tuple(DeterministicKeyAllocation(masterkey_id, DerivationType.BIP32_SUBPATH,
            tuple(parent_derivation_path) + (i,)) for i in range(next_index, next_index + count))

    # Returns ordered from use first to use last.
    def get_fresh_keys(self, derivation_parent: Sequence[int], count: int) -> List[KeyInstanceRow]:
        fresh_keys = self.get_existing_fresh_keys(derivation_parent, count)
        if len(fresh_keys) < count:
            required_count = count - len(fresh_keys)
            future, new_keys = self.create_keys(derivation_parent, required_count)
            # TODO(nocheckin) Reconcile whether we need to wait on the future here.
            if future is not None:
                future.result()
            # Preserve oldest to newest ordering.
            fresh_keys += new_keys
            assert len(fresh_keys) == count
        return fresh_keys

    # Returns ordered from use first to use last.
    def get_existing_fresh_keys(self, derivation_parent: Sequence[int], limit: int) \
            -> List[KeyInstanceRow]:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        masterkey_id = keystore.get_id()
        return self._wallet.read_bip32_keys_unused(self._id, masterkey_id, derivation_parent,
            limit)
        # def _is_fresh_key(keyinstance: KeyInstanceRow) -> bool:
        #     return (keyinstance.script_type == ScriptType.NONE and
        #         (keyinstance.flags & KeyInstanceFlag.MASK_ALLOCATED) == 0)
        # parent_depth = len(derivation_parent)
        # candidates = [ key for key in self._keyinstances.values()
        #     if len(self._keypath[key.keyinstance_id]) == parent_depth+1
        #     and self._keypath[key.keyinstance_id][:parent_depth] == derivation_parent ]
        # # Order keys from newest to oldest and work out how many in front are unused/fresh.
        # keys = sorted(candidates, key=lambda v: -v.keyinstance_id)
        # newest_to_oldest = list(itertools.takewhile(_is_fresh_key, keys))
        # # Provide them in the more usable oldest to newest form.
        # return list(reversed(newest_to_oldest))

    def _count_unused_keys(self, derivation_parent: Sequence[int]) -> int:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        masterkey_id = keystore.get_id()
        return self._wallet.count_unused_bip32_keys(self._id, masterkey_id, derivation_parent)

    def get_master_public_keys(self) -> List[str]:
        return [self.get_master_public_key()]

    def get_fingerprint(self) -> bytes:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        return keystore.get_fingerprint()


class SimpleDeterministicAccount(SimpleAccount, DeterministicAccount):
    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            description_rows: List[AccountTransactionDescriptionRow]) -> None:
        DeterministicAccount.__init__(self, wallet, row, keyinstance_rows, description_rows)

    def get_master_public_key(self) -> str:
        keystore = cast(StandardKeystoreTypes, self.get_keystore())
        return cast(str, keystore.get_master_public_key())

    def _get_public_key_for_key_data(self, keydata: KeyDataTypes) -> PublicKey:
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        # TODO(nocheckin) is this ever not the account's keystore?
        keystore = self._wallet.get_keystore(keydata.masterkey_id)
        return keystore.derive_pubkey(derivation_path)

    def get_public_keys_for_key_data(self, keydata: KeyDataTypes) -> List[PublicKey]:
        return [ self._get_public_key_for_key_data(keydata) ]

    def get_script_template_for_key_data(self, keydata: KeyDataTypes,
            script_type: ScriptType) -> ScriptTemplate:
        public_key = self._get_public_key_for_key_data(keydata)
        return self.get_script_template(public_key, script_type)

    def get_xpubkeys_for_key_data(self, keydata: KeyDataTypes) -> List[XPublicKey]:
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        # TODO(nocheckin) is this ever not the account's keystore?
        keystore = self._wallet.get_keystore(keydata.masterkey_id)
        return [ keystore.get_xpubkey(derivation_path) ]

    def derive_pubkeys(self, derivation_path: Sequence[int]) -> PublicKey:
        keystore = cast(Xpub, self.get_keystore())
        return keystore.derive_pubkey(derivation_path)

    def derive_script_template(self, derivation_path: Sequence[int]) -> ScriptTemplate:
        return self.get_script_template(self.derive_pubkeys(derivation_path))



class StandardAccount(SimpleDeterministicAccount):
    def type(self) -> AccountType:
        return AccountType.STANDARD


class MultisigAccount(DeterministicAccount):
    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            description_rows: List[AccountTransactionDescriptionRow]) -> None:
        self._multisig_keystore = cast(Multisig_KeyStore,
            wallet.get_keystore(cast(int, row.default_masterkey_id)))
        self.m = self._multisig_keystore.m
        self.n = self._multisig_keystore.n

        DeterministicAccount.__init__(self, wallet, row, keyinstance_rows, description_rows)

    def type(self) -> AccountType:
        return AccountType.MULTISIG

    def get_threshold(self, script_type: ScriptType) -> int:
        assert script_type in ACCOUNT_SCRIPT_TYPES[AccountType.MULTISIG], \
            f"get_threshold got bad script_type {script_type}"
        return self.m

    def get_public_keys_for_key_data(self, keydata: KeyDataTypes) -> List[PublicKey]:
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        return [ keystore.derive_pubkey(derivation_path) for keystore in self.get_keystores() ]

    def get_possible_scripts_for_key_data(self, keydata: KeyDataTypes) \
            -> List[Tuple[ScriptType, Script]]:
        public_keys = self.get_public_keys_for_key_data(keydata)
        public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
        return [
            (script_type, self.get_script_template(public_keys_hex, script_type).to_script())
            for script_type in ACCOUNT_SCRIPT_TYPES[AccountType.MULTISIG]
        ]

    def get_script_template_for_key_data(self, keydata: KeyDataTypes,
            script_type: ScriptType) -> ScriptTemplate:
        public_keys = self.get_public_keys_for_key_data(keydata)
        public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
        return self.get_script_template(public_keys_hex, script_type)

    def get_dummy_script_template(self, script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        public_keys_hex = []
        for i in range(self.m):
            public_keys_hex.append(PrivateKey(os.urandom(32)).public_key.to_hex())
        return self.get_script_template(public_keys_hex, script_type)

    def get_script_template(self, public_keys_hex: List[str],
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        if script_type is None:
            script_type = self.get_default_script_type()
        return get_multi_signer_script_template(public_keys_hex, self.m, script_type)

    def derive_pubkeys(self, derivation_path: Sequence[int]) -> List[PublicKey]:
        return [ k.derive_pubkey(derivation_path) for k in self.get_keystores() ]

    def derive_script_template(self, derivation_path: Sequence[int]) -> ScriptTemplate:
        public_keys_hex = [pubkey.to_hex() for pubkey in self.derive_pubkeys(derivation_path)]
        return self.get_script_template(public_keys_hex)

    def get_keystore(self) -> Multisig_KeyStore:
        return self._multisig_keystore

    def get_keystores(self) -> Sequence[SinglesigKeyStoreTypes]:
        return self._multisig_keystore.get_cosigner_keystores()

    def has_seed(self) -> bool:
        return self.get_keystore().has_seed()

    def can_change_password(self) -> bool:
        return self.get_keystore().can_change_password()

    def is_watching_only(self) -> bool:
        return self._multisig_keystore.is_watching_only()

    def get_master_public_key(self) -> str:
        raise NotImplementedError
        # return cast(str, self.get_keystore().get_master_public_key())

    def get_master_public_keys(self) -> List[str]:
        return [cast(str, k.get_master_public_key()) for k in self.get_keystores()]

    def get_fingerprint(self) -> bytes:
        # Sort the fingerprints in the same order as their master public keys.
        mpks = self.get_master_public_keys()
        fingerprints = [ k.get_fingerprint() for k in self.get_keystores() ]
        sorted_mpks, sorted_fingerprints = zip(*sorted(zip(mpks, fingerprints)))
        return b''.join(sorted_fingerprints)

    def get_xpubkeys_for_key_data(self, row: KeyDataTypes) -> List[XPublicKey]:
        assert row.derivation_data2 is not None
        derivation_path = unpack_derivation_path(row.derivation_data2)
        return self.get_xpubkeys_for_derivation_path(derivation_path)

    def get_xpubkeys_for_derivation_path(self, derivation_path: Sequence[int]) -> List[XPublicKey]:
        x_pubkeys = [ k.get_xpubkey(derivation_path) for k in self.get_keystores() ]
        # Sort them using the order of the realized pubkeys
        sorted_pairs = sorted((x_pubkey.to_public_key().to_hex(), x_pubkey)
            for x_pubkey in x_pubkeys)
        return [x_pubkey for _hex, x_pubkey in sorted_pairs]


class Wallet(TriggeredCallbacks):
    _network: Optional['Network'] = None
    _stopped: bool = False

    def __init__(self, storage: WalletStorage) -> None:
        TriggeredCallbacks.__init__(self)

        self._id = random.randint(0, (1<<32)-1)

        self._storage = storage
        self._logger = logs.get_logger(f"wallet[{self.name()}]")

        # NOTE The wallet abstracts all database access. The database context should not be
        # used outside of the `Wallet` object.
        self._db_context = storage.get_db_context()
        assert self._db_context is not None

        self.db_functions_async = db_functions.AsynchronousFunctions(self._db_context)

        txdata_cache_size = self.get_cache_size_for_tx_bytedata() * (1024 * 1024)
        self._transaction_cache2 = LRUCache(max_size=txdata_cache_size)

        self._masterkey_rows: Dict[int, MasterKeyRow] = {}
        self._account_rows: Dict[int, AccountRow] = {}

        self._accounts: Dict[int, AbstractAccount] = {}
        self._keystores: Dict[int, KeyStore] = {}

        # Guards `transaction_locks`.
        self._transaction_lock = threading.RLock()
        # Guards per-transaction locks to limit blocking to per-transaction activity.
        self._transaction_locks: Dict[bytes, Tuple[threading.RLock, int]] = {}

        self.load_state()

        self.contacts = Contacts(self._storage)

        self.txs_changed_event = app_state.async_.event()
        self.progress_event = app_state.async_.event()
        self.request_count = 0
        self.response_count = 0

    def __str__(self) -> str:
        return f"wallet(path='{self._storage.get_path()}')"

    def get_db_context(self) -> DatabaseContext:
        assert self._db_context is not None, "This wallet does not have a database context"
        return self._db_context

    def move_to(self, new_path: str) -> None:
        self._db_context = None
        self._storage.move_to(new_path)
        self._db_context = cast(DatabaseContext, self._storage.get_db_context())

    def load_state(self) -> None:
        if self._db_context is None:
            return

        self._last_load_height = self._storage.get('stored_height', 0)
        last_load_hash = self._storage.get('last_tip_hash')
        if last_load_hash is not None:
            last_load_hash = hex_str_to_hash(last_load_hash)
        self._last_load_hash = last_load_hash
        self._logger.debug("chain %d:%s", self._last_load_height,
            hash_to_hex_str(last_load_hash) if last_load_hash is not None else None)

        self._keystores.clear()
        self._accounts.clear()

        all_account_tx_descriptions: Dict[int, List[AccountTransactionDescriptionRow]] = {}
        for atd_row in self.read_account_transaction_descriptions():
            atd_rows = all_account_tx_descriptions.setdefault(atd_row.account_id, [])
            atd_rows.append(atd_row)

        masterkey_rows = db_functions.read_masterkeys(self.get_db_context())
        # Create the keystores for masterkeys without parent masterkeys first.
        for mk_row in sorted(masterkey_rows,
                key=lambda t: 0 if t.parent_masterkey_id is None else t.parent_masterkey_id):
            self._realize_keystore(mk_row)

        # TODO(nocheckin) for deterministic accounts we need to load the unused keys
        # TODO(nocheckin) for non-deterministic accounts we need to load all keys active.
        all_account_keys: Dict[int, List[KeyInstanceRow]] = defaultdict(list)
        keyinstances = {}
        for ki_row in self.read_keyinstances():
            keyinstances[ki_row.keyinstance_id] = ki_row
            all_account_keys[ki_row.account_id].append(ki_row)

        for row in db_functions.read_accounts(self.get_db_context()):
            account_keys = all_account_keys.get(row.account_id, [])
            account_descriptions = all_account_tx_descriptions.get(row.account_id, [])
            if row.default_masterkey_id is not None:
                account = self._realize_account(row, account_keys, account_descriptions)
            else:
                found_types = set(key.derivation_type for key in account_keys)
                prvkey_types = set([ DerivationType.PRIVATE_KEY ])
                address_types = set([ DerivationType.PUBLIC_KEY_HASH,
                    DerivationType.SCRIPT_HASH ])
                if found_types & prvkey_types:
                    account = ImportedPrivkeyAccount(self, row, account_keys,
                        account_descriptions)
                elif found_types & address_types:
                    account = ImportedAddressAccount(self, row, account_keys,
                        account_descriptions)
                else:
                    raise WalletLoadError(_("Account corrupt, types: %s"), found_types)
            self.register_account(row.account_id, account)

    def register_account(self, account_id: int, account: AbstractAccount) -> None:
        self._accounts[account_id] = account

    def name(self) -> str:
        return get_wallet_name_from_path(self.get_storage_path())

    def get_storage_path(self) -> str:
        return self._storage.get_path()

    def get_storage(self) -> WalletStorage:
        return self._storage

    def get_keystore(self, keystore_id: int) -> KeyStore:
        return self._keystores[keystore_id]

    def get_keystores(self) -> Sequence[KeyStore]:
        return list(self._keystores.values())

    def check_password(self, password: str) -> None:
        self._storage.check_password(password)

    def update_password(self, new_password: str, old_password: Optional[str]=None) -> None:
        assert new_password, "calling code must provide an new password"
        self._storage.put("password-token", pw_encode(os.urandom(32).hex(), new_password))

        for keystore in self._keystores.values():
            if keystore.can_change_password():
                keystore.update_password(new_password, old_password)
                if keystore.has_masterkey():
                    self.update_masterkey_derivation_data(keystore.get_id())
                else:
                    assert isinstance(keystore, Imported_KeyStore)
                    # TODO(nocheckin) read from the database
                    updates = []
                    for key_id, derivation_data in keystore.get_keyinstance_derivation_data():
                        derivation_bytes = json.dumps(derivation_data).encode()
                        updates.append((derivation_bytes, key_id))
                    db_functions.update_keyinstance_derivation_datas(self.get_db_context(),
                        updates)

    def get_account(self, account_id: int) -> Optional[AbstractAccount]:
        return self._accounts.get(account_id)

    def get_accounts_for_keystore(self, keystore: KeyStore) -> List[AbstractAccount]:
        accounts = []
        for account in self.get_accounts():
            account_keystore = account.get_keystore()
            if keystore is account_keystore:
                accounts.append(account)
        return accounts

    def get_account_ids(self) -> Set[int]:
        return set(self._accounts)

    def get_accounts(self) -> Sequence[AbstractAccount]:
        return list(self._accounts.values())

    def get_default_account(self) -> Optional[AbstractAccount]:
        if len(self._accounts):
            return list(self._accounts.values())[0]
        return None

    def _realize_keystore(self, row: MasterKeyRow) -> None:
        data: Dict[str, Any] = json.loads(row.derivation_data)
        parent_keystore: Optional[KeyStore] = None
        if row.parent_masterkey_id is not None:
            parent_keystore = self._keystores[row.parent_masterkey_id]
        keystore = instantiate_keystore(row.derivation_type, data, parent_keystore, row)
        self._keystores[row.masterkey_id] = keystore
        self._masterkey_rows[row.masterkey_id] = row

    def _realize_account(self, account_row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            transaction_descriptions: List[AccountTransactionDescriptionRow]) \
                -> AbstractAccount:
        account_constructors = {
            DerivationType.BIP32: StandardAccount,
            DerivationType.BIP32_SUBPATH: StandardAccount,
            DerivationType.ELECTRUM_OLD: StandardAccount,
            DerivationType.ELECTRUM_MULTISIG: MultisigAccount,
            DerivationType.HARDWARE: StandardAccount,
        }
        if account_row.default_masterkey_id is None:
            if keyinstance_rows[0].derivation_type == DerivationType.PUBLIC_KEY_HASH:
                return ImportedAddressAccount(self, account_row, keyinstance_rows,
                    transaction_descriptions)
            elif keyinstance_rows[0].derivation_type == DerivationType.PRIVATE_KEY:
                return ImportedPrivkeyAccount(self, account_row, keyinstance_rows,
                    transaction_descriptions)
        else:
            masterkey_row = self._masterkey_rows[account_row.default_masterkey_id]
            klass = account_constructors.get(masterkey_row.derivation_type, None)
            if klass is not None:
                return klass(self, account_row, keyinstance_rows, transaction_descriptions)
        raise WalletLoadError(_("unknown account type %d"), masterkey_row.derivation_type)

    def _realize_account_from_row(self, account_row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            transaction_descriptions: List[AccountTransactionDescriptionRow]) -> AbstractAccount:
        account = self._realize_account(account_row, keyinstance_rows, transaction_descriptions)
        self.register_account(account_row.account_id, account)
        self.trigger_callback("on_account_created", account_row.account_id)

        self.create_wallet_events([
            WalletEventRow(0, WalletEventType.SEED_BACKUP_REMINDER, account_row.account_id,
                WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, int(time.time()))
        ])

        if self._network is not None:
            account.start(self._network)
        return account

    def read_history_list(self, account_id: int, keyinstance_ids: Optional[Sequence[int]]=None) \
            -> List[HistoryListRow]:
        return db_functions.read_history_list(self.get_db_context(), account_id, keyinstance_ids)

    def read_bip32_keys_unused(self, account_id: int, masterkey_id: int,
            derivation_path: Sequence[int], limit: int) -> List[KeyInstanceRow]:
        return db_functions.read_bip32_keys_unused(self.get_db_context(), account_id, masterkey_id,
            derivation_path, limit)

    def count_unused_bip32_keys(self, account_id: int, masterkey_id: int,
            derivation_path: Sequence[int]) -> int:
        return db_functions.count_unused_bip32_keys(self.get_db_context(), account_id,
            masterkey_id, derivation_path)

    # Accounts.

    def add_accounts(self, entries: List[AccountRow]) -> List[AccountRow]:
        account_id = self._storage.get("next_account_id", 1)
        rows = entries[:]
        for i, row in enumerate(rows):
            rows[i] = row._replace(account_id=account_id)
            account_id += 1

        self._storage.put("next_account_id", account_id)
        future = db_functions.create_accounts(self.get_db_context(), rows)
        future.result()
        return rows

    def create_account_from_keystore(self, keystore) -> AbstractAccount:
        masterkey_row = self.create_masterkey_from_keystore(keystore)
        if masterkey_row.derivation_type == DerivationType.ELECTRUM_OLD:
            account_name = "Outdated Electrum account"
            script_type = ScriptType.P2PKH
        elif masterkey_row.derivation_type == DerivationType.BIP32:
            account_name = "Standard account"
            script_type = ScriptType.P2PKH
        elif masterkey_row.derivation_type == DerivationType.ELECTRUM_MULTISIG:
            account_name = "Multi-signature account"
            script_type = ScriptType.MULTISIG_BARE
        elif masterkey_row.derivation_type == DerivationType.HARDWARE:
            account_name = keystore.label or "Hardware wallet"
            script_type = ScriptType.P2PKH
        else:
            raise WalletLoadError(f"Unhandled derivation type {masterkey_row.derivation_type}")

        basic_row = AccountRow(-1, masterkey_row.masterkey_id, script_type, account_name)
        rows = self.add_accounts([ basic_row ])
        return self._realize_account_from_row(rows[0], [], [])

    def create_account_from_text_entries(self, text_type: KeystoreTextType, script_type: ScriptType,
            entries: List[str], password: str) -> AbstractAccount:
        account_name: Optional[str] = None
        if text_type == KeystoreTextType.ADDRESSES:
            account_name = "Imported addresses"
        elif text_type == KeystoreTextType.PRIVATE_KEYS:
            account_name = "Imported private keys"
        else:
            raise WalletLoadError(f"Unhandled text type {text_type}")

        raw_keyinstance_rows = []
        if text_type == KeystoreTextType.ADDRESSES:
            # NOTE(P2SHNotImportable) see the account wizard for why this does not get P2SH ones.
            for address_string in entries:
                derivation_data_dict = { "hash": address_string }
                derivation_data = json.dumps(derivation_data_dict).encode()
                raw_keyinstance_rows.append(KeyInstanceRow(-1, -1,
                    None, DerivationType.PUBLIC_KEY_HASH, derivation_data,
                    create_derivation_data2(DerivationType.PUBLIC_KEY_HASH, derivation_data_dict),
                    KeyInstanceFlag.IS_ACTIVE, None))
        elif text_type == KeystoreTextType.PRIVATE_KEYS:
            for private_key_text in entries:
                private_key = PrivateKey.from_text(private_key_text)
                pubkey_hex = private_key.public_key.to_hex()
                derivation_data_dict = {
                    "pub": pubkey_hex,
                    "prv": pw_encode(private_key_text, password),
                }
                derivation_data = json.dumps(derivation_data_dict).encode()
                raw_keyinstance_rows.append(KeyInstanceRow(-1, -1,
                    None, DerivationType.PRIVATE_KEY, derivation_data,
                    create_derivation_data2(DerivationType.PRIVATE_KEY, derivation_data_dict),
                    KeyInstanceFlag.IS_ACTIVE, None))

        basic_account_row = AccountRow(-1, None, script_type, account_name)
        account_row = self.add_accounts([ basic_account_row ])[0]
        keyinstance_future, keyinstance_rows = self.create_keyinstances(account_row.account_id,
            raw_keyinstance_rows)
        return self._realize_account_from_row(account_row, keyinstance_rows, [])

    def read_account_balance(self, account_id: int, local_height: int,
            filter_bits: Optional[TransactionOutputFlag]=None,
            filter_mask: Optional[TransactionOutputFlag]=None) -> WalletBalance:
        return db_functions.read_account_balance(self.get_db_context(),
            account_id, local_height, filter_bits, filter_mask)

    def read_account_balance_raw(self, account_id: int, flags: Optional[int]=None,
            mask: Optional[int]=None) -> TransactionDeltaSumRow:
        return db_functions.read_account_balance_raw(self.get_db_context(), account_id, flags, mask)

    def update_account_names(self, entries: Iterable[Tuple[str, int]]) -> concurrent.futures.Future:
        return db_functions.update_account_names(self.get_db_context(), entries)

    def update_account_script_types(self, entries: Iterable[Tuple[ScriptType, int]]) \
            -> concurrent.futures.Future:
        return db_functions.update_account_script_types(self.get_db_context(), entries)

    # Account transactions.

    def read_account_transaction_descriptions(self, account_id: Optional[int]=None) \
            -> List[AccountTransactionDescriptionRow]:
        return db_functions.read_account_transaction_descriptions(self.get_db_context(), account_id)

    def update_account_transaction_descriptions(self,
            entries: Iterable[Tuple[Optional[str], int, bytes]]) -> concurrent.futures.Future:
        return db_functions.update_account_transaction_descriptions(self.get_db_context(),
            entries)

    # Invoices.

    def create_invoices(self, entries: Iterable[InvoiceRow]) -> concurrent.futures.Future:
        return db_functions.create_invoices(self.get_db_context(), entries)

    def read_invoice(self, *, invoice_id: Optional[int]=None, tx_hash: Optional[bytes]=None,
            payment_uri: Optional[str]=None) -> Optional[InvoiceRow]:
        return db_functions.read_invoice(self.get_db_context(), invoice_id=invoice_id,
            tx_hash=tx_hash, payment_uri=payment_uri)

    def read_invoice_duplicate(self, value: int, payment_uri: str) -> Optional[InvoiceRow]:
        return db_functions.read_invoice_duplicate(self.get_db_context(), value, payment_uri)

    def read_invoices_for_account(self, account_id: int, flags: Optional[int]=None,
            mask: Optional[int]=None) -> List[InvoiceAccountRow]:
        return db_functions.read_invoices_for_account(self.get_db_context(), account_id, flags,
            mask)

    def update_invoice_transactions(self, entries: Iterable[Tuple[Optional[bytes], int]]) \
            -> concurrent.futures.Future:
        return db_functions.update_invoice_transactions(self.get_db_context(), entries)

    def update_invoice_descriptions(self, entries: Iterable[Tuple[Optional[str], int]]) \
            -> concurrent.futures.Future:
        return db_functions.update_invoice_descriptions(self.get_db_context(), entries)

    def update_invoice_flags(self, entries: Iterable[Tuple[PaymentFlag, PaymentFlag, int]]) \
            -> concurrent.futures.Future:
        return db_functions.update_invoice_flags(self.get_db_context(), entries)

    def delete_invoices(self, entries: Iterable[Tuple[int]]) -> concurrent.futures.Future:
        return db_functions.delete_invoices(self.get_db_context(), entries)

    # Key instances.

    def create_keyinstances(self, account_id: int, entries: List[KeyInstanceRow]) \
            -> Tuple[concurrent.futures.Future, List[KeyInstanceRow]]:
        keyinstance_id = self._storage.get("next_keyinstance_id", 1)
        rows = entries[:]
        for i, row in enumerate(rows):
            rows[i] = row._replace(keyinstance_id=keyinstance_id, account_id=account_id)
            keyinstance_id += 1
        self._storage.put("next_keyinstance_id", keyinstance_id)
        future = db_functions.create_keyinstances(self.get_db_context(), rows)
        return future, rows

    def read_key_list(self, account_id, keyinstance_ids: Optional[List[int]]=None) \
            -> List[KeyListRow]:
        return db_functions.read_key_list(self.get_db_context(), account_id, keyinstance_ids)

    def read_keyinstance_for_derivation(self, account_id: int,
            derivation_type: DerivationType, derivation_data2: bytes,
            masterkey_id: Optional[int]=None) -> Optional[KeyInstanceRow]:
        return db_functions.read_keyinstance_for_derivation(account_id, derivation_type,
            derivation_data2, masterkey_id)

    def read_keyinstances(self, *, account_id: Optional[int]=None,
        keyinstance_ids: Optional[Sequence[int]]=None) -> List[KeyInstanceRow]:
        return db_functions.read_keyinstances(self.get_db_context(), account_id=account_id,
            keyinstance_ids=keyinstance_ids)

    def set_keyinstance_flags(self, key_ids: List[int], flags: KeyInstanceFlag,
            mask: Optional[KeyInstanceFlag]=None) -> concurrent.futures.Future:
        return db_functions.set_keyinstance_flags(self.get_db_context(), key_ids, flags, mask)

    def get_keyinstance(self, keyinstance_id: int) -> KeyInstanceRow:
        return db_functions.read_keyinstances(self.get_db_context(), account_id=self._id,
            keyinstance_ids=[ keyinstance_id ])

    def get_next_derivation_index(self, account_id, masterkey_id: int,
            derivation_path: Sequence[int]) -> int:
        last_index = db_functions.read_keyinstance_derivation_index_last(
            self.get_db_context(), account_id, masterkey_id, derivation_path)
        if last_index is None:
            return 0
        return last_index + 1

    def update_keyinstance_descriptions(self, entries: Iterable[Tuple[Optional[str], int]]) \
            -> concurrent.futures.Future:
        return db_functions.update_keyinstance_descriptions(self.get_db_context(), entries)

    # Master keys.

    def add_masterkeys(self, entries: List[MasterKeyRow]) -> List[MasterKeyRow]:
        masterkey_id = self._storage.get("next_masterkey_id", 1)
        rows = entries[:]
        for i, row in enumerate(rows):
            rows[i] = row._replace(masterkey_id=masterkey_id)
            self._masterkey_rows[masterkey_id] = row
            masterkey_id += 1

        self._storage.put("next_masterkey_id", masterkey_id)
        future = db_functions.create_master_keys(self.get_db_context(), rows)
        future.result()
        return rows

    def create_masterkey_from_keystore(self, keystore: KeyStore) -> MasterKeyRow:
        basic_row = keystore.to_masterkey_row()
        rows = self.add_masterkeys([ basic_row ])
        keystore.set_row(rows[0])
        self._keystores[rows[0].masterkey_id] = keystore
        self._masterkey_rows[rows[0].masterkey_id] = rows[0]
        return rows[0]

    def update_masterkey_derivation_data(self, masterkey_id: int) -> None:
        keystore = self.get_keystore(masterkey_id)
        derivation_data = json.dumps(keystore.to_derivation_data()).encode()
        db_functions.update_masterkey_derivation_datas(self.get_db_context(),
            [ (derivation_data, masterkey_id) ])

    # Payment requests.

    def create_payment_requests(self, account_id: int, requests: List[PaymentRequestRow]) \
            -> concurrent.futures.Future:
        def callback(callback_future: concurrent.futures.Future) -> None:
            nonlocal account_id, requests
            if callback_future.cancelled():
                return
            callback_future.result()

            updated_keyinstance_ids = [ row.keyinstance_id for row in requests ]
            self.trigger_callback('on_keys_updated', account_id, updated_keyinstance_ids)

        request_id = self._storage.get("next_paymentrequest_id", 1)
        rows = []
        for request in requests:
            rows.append(request._replace(paymentrequest_id=request_id))
            request_id += 1
        self._storage.put("next_paymentrequest_id", request_id)
        future = db_functions.create_payment_requests(self.get_db_context(), rows)
        future.add_done_callback(callback)
        return future

    def read_paid_requests(self, account_id: int, keyinstance_ids: Sequence[int]) -> List[int]:
        return db_functions.read_paid_requests(self.get_db_context(), account_id, keyinstance_ids)

    def read_payment_request(self, request_id: Optional[int]=None,
            keyinstance_id: Optional[int]=None) -> Optional[PaymentRequestRow]:
        return db_functions.read_payment_request(self.get_db_context(), request_id, keyinstance_id)

    def read_payment_requests(self, account_id: Optional[int]=None, flags: Optional[int]=None,
            mask: Optional[int]=None) -> List[PaymentRequestRow]:
        return db_functions.read_payment_requests(self.get_db_context(), account_id, flags,
            mask)

    def update_payment_request_states(self, entries: Iterable[Tuple[Optional[PaymentFlag], int]]) \
            -> concurrent.futures.Future:
        return db_functions.update_payment_request_states(self.get_db_context(), entries)

    def update_payment_requests(self, entries: Iterable[PaymentRequestUpdateRow]) \
            -> concurrent.futures.Future:
        return db_functions.update_payment_requests(self.get_db_context(), entries)

    def delete_payment_request(self, account_id: int, request_id: int, keyinstance_id: int) \
            -> concurrent.futures.Future:
        def callback(callback_future: concurrent.futures.Future) -> None:
            nonlocal account_id, keyinstance_id
            if callback_future.cancelled():
                return
            callback_future.result()
            self.trigger_callback('on_keys_updated', account_id, [ keyinstance_id ])

        future = db_functions.delete_payment_request(self.get_db_context(), request_id,
            keyinstance_id)
        future.add_done_callback(callback)
        return future

    # Script hashes.

    def create_keyinstance_scripts(self, entries: Iterable[KeyInstanceScriptHashRow]) \
            -> concurrent.futures.Future:
        return db_functions.create_keyinstance_scripts(self.get_db_context(), entries)

    def read_keyinstance_scripts(self, keyinstance_ids: List[int]) \
            -> List[KeyInstanceScriptHashRow]:
        return db_functions.read_keyinstance_scripts(self.get_db_context(), keyinstance_ids)

    # Transaction outputs.

    def create_transaction_outputs(self, account_id: int,
            entries: List[TransactionOutputShortRow]) -> List[TransactionOutputShortRow]:
        db_functions.create_transaction_outputs(self.get_db_context(), entries)
        return entries

    def read_account_transaction_outputs(self, account_id: int,
            flags: TransactionOutputFlag, mask: TransactionOutputFlag,
            require_key_usage: bool=False, tx_hash: Optional[bytes]=None,
            keyinstance_ids: Optional[List[int]]=None) -> List[TransactionOutputSpendableRow2]:
        return db_functions.read_account_transaction_outputs(self.get_db_context(), account_id,
            flags, mask, require_key_usage, tx_hash, keyinstance_ids)

    def read_account_transaction_outputs_spendable(self, account_id: int,
            confirmed_only: bool=False, mature_height: Optional[int]=None,
            exclude_frozen: bool=False, keyinstance_ids: Optional[List[int]]=None) \
                -> List[TransactionOutputSpendableRow]:
        return db_functions.read_account_transaction_outputs_spendable(self.get_db_context(),
            account_id, confirmed_only, mature_height, exclude_frozen, keyinstance_ids)

    def read_account_transaction_outputs_spendable_extended(self, account_id: int,
            confirmed_only: bool=False, mature_height: Optional[int]=None,
            exclude_frozen: bool=False, keyinstance_ids: Optional[List[int]]=None) \
                -> List[TransactionOutputSpendableRow2]:
        return db_functions.read_account_transaction_outputs_spendable_extended(
            self.get_db_context(), account_id, confirmed_only, mature_height, exclude_frozen,
                keyinstance_ids)

    def get_parent_transaction_outputs(self, tx_hash: bytes) -> List[TransactionOutputShortRow]:
        """ When the child transaction is in the database. """
        return db_functions.read_parent_transaction_outputs(self.get_db_context(), tx_hash)

    def get_transaction_outputs_spendable_explicit(self,
            *,
            account_id: Optional[int]=None,
            tx_hash: Optional[bytes]=None,
            txo_keys: Optional[List[TxoKeyType]]=None,
            require_spends: bool=False) -> List[TransactionOutputSpendableRow]:
        return db_functions.read_transaction_outputs_spendable_explicit(self.get_db_context(),
            account_id=account_id, tx_hash=tx_hash, txo_keys=txo_keys)

    def get_transaction_outputs_short(self, l: List[TxoKeyType]) \
            -> List[TransactionOutputShortRow]:
        return db_functions.read_transaction_outputs_explicit(self.get_db_context(), l)

    def update_transaction_output_flags(self, txo_keys: List[TxoKeyType],
            flags: TransactionOutputFlag, mask: Optional[TransactionOutputFlag]=None) \
                -> concurrent.futures.Future:
        return db_functions.update_transaction_output_flags(self.get_db_context(),
            txo_keys, flags, mask)

    # Wallet events.

    def create_wallet_events(self,  entries: List[WalletEventRow]) -> List[WalletEventRow]:
        next_id = self._storage.get("next_wallet_event_id", 1)
        rows = []
        for entry in entries:
            rows.append(entry._replace(event_id=next_id))
            next_id += 1
        db_functions.create_wallet_events(self.get_db_context(), rows)
        self._storage.put("next_wallet_event_id", next_id)
        for row in rows:
            app_state.app.on_new_wallet_event(self.get_storage_path(), row)
        return rows

    def read_wallet_events(self, mask: WalletEventFlag=WalletEventFlag.NONE) \
            -> List[WalletEventRow]:
        return db_functions.read_wallet_events(self.get_db_context(), mask=mask)

    def update_wallet_event_flags(self,
            entries: Iterable[Tuple[WalletEventFlag, int]]) -> concurrent.futures.Future:
        return db_functions.update_wallet_event_flags(self.get_db_context(), entries)

    # Transactions.

    def get_transaction_deltas(self, tx_hash: bytes, account_id: Optional[int]=None) \
            -> List[TransactionDeltaSumRow]:
        return db_functions.read_transaction_values(self.get_db_context(), tx_hash, account_id)

    def get_transaction_flags(self, tx_hash: bytes) -> Optional[TxFlags]:
        return db_functions.read_transaction_flags(self.get_db_context(), tx_hash)

    def set_transaction_dispatched(self, tx_hash: bytes) -> bool:
        future = db_functions.set_transaction_dispatched(self.get_db_context(), tx_hash)
        return future.result()

    def get_transaction_metadata(self, tx_hash: bytes) -> Optional[TransactionMetadata]:
        return db_functions.read_transaction_metadata(self.get_db_context(), tx_hash)

    def get_tx_height(self, tx_hash: bytes) -> Tuple[int, int, int, Union[int, bool]]:
        """ return the height and timestamp of a verified transaction. """
        block_height, block_position = db_functions.read_transaction_block_info(
            self.get_db_context(), tx_hash)
        assert block_height is not None, f"tx {hash_to_hex_str(tx_hash)} has no height"
        assert block_position is not None, f"tx {hash_to_hex_str(tx_hash)} has no position"
        timestamp = None
        if block_height > 0:
            chain = app_state.headers.longest_chain()
            try:
                header = app_state.headers.header_at_height(chain, block_height)
                timestamp = header.timestamp
            except MissingHeader:
                pass
        if timestamp is not None:
            conf = max(self.get_local_height() - block_height + 1, 0)
            return block_height, block_position, conf, timestamp
        else:
            return block_height, block_position, 0, False

    def read_transaction_value_entries(self, account_id: int, *,
            tx_hashes: Optional[List[bytes]]=None, mask: Optional[TxFlags]=None) \
                -> List[TransactionValueRow]:
        return db_functions.read_transaction_value_entries(self.get_db_context(), account_id,
            tx_hashes=tx_hashes, mask=mask)

    def missing_transactions(self) -> List[bytes]:
        '''Returns a set of tx_hashes.'''
        raise NotImplementedError()

    def unverified_transactions(self) -> Dict[bytes, int]:
        '''Returns a map of tx_hash to tx_height.'''
        results = db_functions.read_unverified_transactions(self.get_db_context(),
            self.get_local_height())
        self._logger.debug("unverified_transactions: %s", [hash_to_hex_str(r[0]) for r in results])
        return { t[0]: cast(int, t[1].metadata.height) for t in results }

    # TODO(nocheckin) unit test
    def _acquire_transaction_lock(self, tx_hash: bytes) -> threading.RLock:
        """
        Acquire a lock for working with a given transaction.

        The caller should use a finally clause to ensure that they are releasing the lock.
        """
        with self._transaction_lock:
            lock_data = self._transaction_locks.get(tx_hash)
            if lock_data is None:
                lock = threading.RLock()
                self._transaction_locks[tx_hash] = (lock, 1)
            else:
                lock, reference_count = lock_data
                self._transaction_locks[tx_hash] = (lock, reference_count + 1)
        return lock

    # TODO(nocheckin) unit test
    def _release_transaction_lock(self, tx_hash: bytes) -> None:
        """
        Release a lock acquired for working with a given transaction.
        """
        with self._transaction_lock:
            lock, reference_count = self._transaction_locks[tx_hash]
            if reference_count == 1:
                del self._transaction_locks[tx_hash]
            else:
                assert reference_count > 1
                self._transaction_locks[tx_hash] = (lock, reference_count - 1)

    # TODO(nocheckin) unused
    # def _extend_transaction_output(self, output: XTxOutput, key_data: KeyDataTypes) -> None:
    #     output.account_id = key_data.account_id
    #     output.keyinstance_id = key_data.keyinstance_id
    #     output.masterkey_id = key_data.masterkey_id
    #     output.derivation_type = key_data.derivation_type
    #     output.derivation_data2 = key_data.derivation_data2

    def _extend_database_transaction(self, tx: Transaction, force: bool=False) -> None:
        """
        Add external extended data to a transaction object.

        A transaction is composed of extended inputs and outputs that can contain additional
        information, and most of that can be populated from an extended serialisation
        format that contains more data than standard transactions do.

        This method aims to populate the extended data of a transaction object, and if there
        is already information present there, to validate that it is correct. If there is an
        inconsistency, an `InvalidTransactionError` exception will be raised. The caller can
        opt to ignore all inconsistencies and just overwrite the values using the `force`
        argument (NOT DONE).
        """
        tx_id = hash_to_hex_str(tx.hash())

        input_map: Dict[TxoKeyType, Tuple[int, XTxInput]] = {}
        for tx_input in tx.inputs:
            outpoint = TxoKeyType(tx_input.prev_hash, tx_input.prev_idx)
            input_map[outpoint] = tx_input
        # TODO(nocheckin) require_spends=True?
        previous_outputs = self.get_transaction_outputs_spendable_explicit(txo_keys=list(input_map))

        for db_output in previous_outputs:
            outpoint = TxoKeyType(db_output.tx_hash, db_output.txo_index)
            txi_index, tx_input = input_map[outpoint]

            if tx_input.value is not None and tx_input.value != db_output.value:
                # TODO(nocheckin) this should report back to the caller
                logger.error("extend_transaction: input %s:%d got value %d, expected %d",
                    tx_id, txi_index, tx_input.value, db_output.value)
            tx_input.value = db_output.value

            tx_input.script_type = db_output.script_type
            assert db_output.keyinstance_id is not None
            assert db_output.account_id is not None
            assert db_output.derivation_type is not None
            tx_input.key_data = KeyDataType(db_output.keyinstance_id, db_output.account_id,
                db_output.masterkey_id, db_output.derivation_type, db_output.derivation_data2)
        # TODO(nocheckin) unfinished

    def _extend_ephemeral_transaction(self, tx_hash: bytes, tx: Transaction) -> None:
        """
        Add extended data to this transaction based on it not being in the database.

        As the wallet should know about all transactions associated with any of it's accounts and
        the keys they use, this is expected to be a transaction not directly related to the
        wallet.

        It is also possible that the user constructed this transaction locally, exported it without
        sharing it externally, and is reloading it into the wallet. At this point it may or may not
        clash with other wallet contents. However, as we are loading it ephemerally we need to
        detect that ourselves. In this case, the transaction should be marked up exactly like a
        transaction that was in the database and was fully processed would be.
        """
        assert tx.is_complete()

        spend_keys = [ TxoKeyType(txin.prev_hash, txin.prev_idx) for txin in tx.inputs ]
        spent_output_map = {
            TxoKeyType(txo.tx_hash, txo.txo_index):
                txo for txo in self.get_transaction_outputs_spendable_explicit(txo_keys=spend_keys)
        }

        for txi_index, tx_input in enumerate(tx.inputs):
            spent_output = spent_output_map.get(spend_keys[txi_index])
            if spent_output is None:
                continue

            # Provide output-related values.
            tx_input.value = spent_output.value
            tx_input.script_type = spent_output.script_type

            # Provide key data values.
            tx_input.keyinstance_id = spent_output.keyinstance_id
            tx_input.account_id = spent_output.account_id
            tx_input.masterkey_id = spent_output.masterkey_id
            tx_input.derivation_type = spent_output.derivation_type
            tx_input_derivation_data2 = spent_output.derivation_data2
            # NOTE we do not populate the x_pubkeys as the transaction is fully signed.
            # There is some overlap with the key data values, and this can be worked out
            # later anyway.

        receive_output_map = {
            TxoKeyType(txo.tx_hash, txo.txo_index):
                txo for txo in self.get_transaction_outputs_spendable_explicit(tx_hash=tx_hash)
        }
        # TODO(nocheckin) need to work out what we actually want to store here. Good idea would
        # be to look at transaction dialog.

    def extend_transaction(self, tx: Transaction) -> None:
        """
        Add all the extended metadata to the transaction to aid wallet logic.

        All loaded transactions should be extended, as this will add signing/key metadata that
        relates to inputs and outputs, and allow logic to operate on the transaction without
        having to do trivial database lookups.

        Edge cases (this text might be better placed somewhere else):
        * We support loading conflicting transactions, flagging them and setting them aside.
          * A user may have constructed a local transaction, saved a copy, removed it from the
            wallet and then spent coins in another transaction. Then loaded the previously removed
            local transaction which also spends those coins.
          * A user may be using their seed words in different wallets, and have used coins in
            a local transaction in one wallet and also used them in a dispatched transaction
            in the other wallet.
        """
        tx_hash = tx.hash()
        is_complete = tx.is_complete()

        # First gather up what the database knows about this transaction.
        # - The inputs are spends of existing coins. They implicitly must be from complete
        #   transactions at this time. And if they conflict, the transaction is not integrated.
        # - The outputs are usage of keys, or potential usage of keys.
        # - The outputs may also already be spent in the case of out of order transactions, which
        #   are imported either via indexer results or manually.

        db_output_map: Dict[TxoKeyType, TransactionOutputSpendableRow] = {}
        # TODO(nocheckin) Either . . .
        db_output_map.update({
            TxoKeyType(row.tx_hash, row.txo_index): row
            for row in db_functions.read_parent_transaction_outputs_spendable(
                self.get_db_context(), tx_hash)
        })
        db_output_map.update({
            TxoKeyType(row.tx_hash, row.txo_index): row
            for row in db_functions.read_transaction_outputs_spendable_explicit(
                self.get_db_context(), tx_hash=tx_hash)
        })

        for txi_index, tx_input in enumerate(tx.inputs):
            db_output_key = TxoKeyType(tx_input.prev_hash, tx_input.prev_idx)
            db_output = db_output_map.get(db_output_key)
            if db_output is None:
                continue
            tx_input.value = db_output.value
            if db_output.keyinstance_id is None:
                continue
            assert db_output.account_id is not None and db_output.derivation_type is not None
            tx_input.key_data = KeyDataType(db_output.keyinstance_id, db_output.account_id,
                db_output.masterkey_id, db_output.derivation_type, db_output.derivation_data2)

        # TODO read the spends
        # TODO read the key usage of the receipts
        # TODO read the known spends of the receipts
        #   what does this give us? is it more useful for the add to database step?

        spent_values: Dict[TxoKeyType, int] = {}
        # An imported transaction may optionally come with parent transactions. This is used by
        # Trezor (as far as it can be given their incompatibility with Bitcoin SV) for analysing
        # spent outputs of the transaction being signed, and also as SPV proofs for the signer.
        for parent_tx_hash, parent_tx in tx.context.prev_txs.items():
            for txo_index, tx_output in parent_tx.outputs:
                # NOTE parent transactions are not extended and if they are it is an accident.
                spent_values[TxoKeyType(parent_tx_hash, txo_index)] = tx_output.value
        # TODO(nocheckin) do we have any other use for the information in the parent transactions
        #    at this time?

        # Do all the input information gathering.
        signer_key_data: Dict[XPublicKeyType, Tuple[List[int], List[bytes]]] = {
            XPublicKeyType.BIP32:       ([], []),
            XPublicKeyType.PRIVATE_KEY: ([], []),
            XPublicKeyType.OLD:         ([], []),
        }
        for txi_index, tx_input in enumerate(tx.inputs):
            # Extended public keys are only present for incomplete transactions and represent the
            # remaining potential signers of this unsigned input.
            if tx_input.x_pubkeys:
                for x_public_key in tx_input.x_pubkeys:
                    xpk_kind = x_public_key.kind()
                    signer_key_entry = signer_key_data[xpk_kind]
                    signer_key_entry[0].append(txi_index)
                    if xpk_kind == XPublicKeyType.PRIVATE_KEY:
                        signer_key_entry[1].append(x_public_key.to_public_key_bytes())
                    elif xpk_kind in (XPublicKeyType.BIP32, XPublicKeyType.OLD):
                        # TODO(nocheckin) Find the masterkey for the mpk/oldkey and include it in
                        # the lookup data.
                        derivation_path_bytes = pack_derivation_path(x_public_key.derivation_path())
                        signer_key_entry[1].append(derivation_path_bytes)

        # Do all the output information gathering.
        for tx_output in tx.outputs:
            # Extended public keys are only present for incomplete transactions and are expected
            # to only represent the change transactions in this payment.
            pass


        # TODO(nocheckin) all cases should add spent output values to transaction inputs.
        # TODO(nocheckin) there may be parent data that is in memory that we do not have in the
        #     database. This should also be processed.
        # TODO(nocheckin) incomplete transactions may have extended public key data that maps
        #     to key usage we do not know about. They may also be partially signed and have
        #     removed public key data for those signed inputs, so we also need to scan here.
        # TODO(nocheckin) complete transactions may have key usage we do not know about also,
        #     so we need to scan here.

        pass

    # TODO(nocheckin) rewritten and needs to be tested
    def load_transaction_from_text(self, text: str) -> Optional[Transaction]:
        """
        Takes user-provided text and attempts to extract a transaction from it.

        Returns the loaded transaction if the text contains a valid one. The transaction is not
        guaranteed to be in the database, and if it is not may even conflict with existing coin
        spends known to the wallet. Returns `None` if the text does not contain a valid
        transaction.

        Raises `ValueError` if the text is not found to contain viable transaction data.
        """
        if not text:
            return None

        txdict = tx_dict_from_text(text)
        tx = Transaction.from_dict(txdict)
        self.extend_transaction(tx)
        return tx

    def load_transaction_from_bytes(self, data: bytes) -> Transaction:
        """
        Loads a transaction using given transaction data.

        If the transaction is already in the cache, it will return that transaction.
        If the transaction is in the database, this will load it in extended form and cache it.
        Otherwise the transaction data will be parsed, loaded in extended form and cached.
        """
        tx_hash = double_sha256(data)
        lock = self._acquire_transaction_lock(tx_hash)
        with lock:
            try:
                # Get it if cached in memory / load from database if present.
                tx = self._get_cached_transaction(tx_hash)
                if tx is not None:
                    return tx

                # Parse the transaction data.
                tx = Transaction.from_bytes(data)
                self._extend_ephemeral_transaction(tx_hash, tx)
                self._transaction_cache2.set(tx_hash, tx)
            finally:
                self._release_transaction_lock(tx_hash)

        return tx

        # Otherwise:
        #   Load the transaction.
        #   Amend it with signing metadata.
        #   Put it in the cache.

    async def add_local_transaction(self, tx_hash: bytes, tx: Transaction, flags: TxFlags) -> None:
        link_state = TransactionLinkState()
        link_state.rollback_on_spend_conflict = True
        await self._import_transaction(tx_hash, tx, flags, link_state)

    async def import_transaction_async(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            block_height: Optional[int]=None, block_position: Optional[int]=None,
            fee_hint: Optional[int]=None, external: bool=False) -> None:
        link_state = TransactionLinkState()
        link_state.acquire_related_account_ids = True
        await self._import_transaction(tx_hash, tx, flags, link_state, block_height,
            block_position, fee_hint, external)

    async def _import_transaction(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            link_state: TransactionLinkState, block_height: Optional[int]=None,
            block_position: Optional[int]=None, fee_hint: Optional[int]=None,
            external: bool=False) -> None:
        """
        Add an external complete transaction to the database.

        We do not know whether the transaction uses any wallet keys, and is related to any
        accounts related to those keys. We will work this out as part of the importing process.
        """
        assert tx.is_complete()
        timestamp = int(time.time())

        # The database layer should be decoupled from core wallet logic so we need to
        # break down the transaction and related data for it to consume.
        tx_row = TransactionRow(tx_hash, tx.to_bytes(), flags, block_height, block_position,
            fee_hint, None, tx.version, tx.locktime, timestamp, timestamp)

        # TODO(nocheckin) Verify that the input flags used here are correct.
        # TODO(nocheckin) Unit test that the input script offset and lengths are correct. Also
        #     do it for migrated wallets in the unit tests.
        txi_rows: List[TransactionInputAddRow] = []
        for txi_index, input in enumerate(tx.inputs):
            txi_row = TransactionInputAddRow(tx_hash, txi_index,
                input.prev_hash, input.prev_idx, input.sequence,
                TransactionInputFlag.NONE,
                input.script_offset, input.script_length,
                timestamp, timestamp)
            txi_rows.append(txi_row)

        # TODO(nocheckin) Unit test that the output script offset and lengths are correct.
        txo_rows: List[TransactionOutputAddRow] = []
        for txo_index, txo in enumerate(tx.outputs):
            txo_row = TransactionOutputAddRow(tx_hash, txo_index, txo.value,
                None,                           # Raw transaction means no idea of key usage.
                ScriptType.NONE,                # Raw transaction means no idea of script type.
                TransactionOutputFlag.NONE,     # TODO(nocheckin) work out if different
                scripthash_bytes(txo.script_pubkey),
                txo.script_offset, txo.script_length,
                timestamp, timestamp)
            txo_rows.append(txo_row)

        ret = await self.db_functions_async.import_transaction_async(tx_row, txi_rows, txo_rows,
            link_state)

        self.trigger_callback('transaction_added', tx_hash, tx, link_state, external)

    # Called by network.
    async def add_transaction_proof(self, tx_hash: bytes, height: int, timestamp: int,
            position: int, proof_position: int, proof_branch: Sequence[bytes]) -> None:
        tx_id = hash_to_hex_str(tx_hash)
        if self._stopped:
            self._logger.debug("add_transaction_proof on stopped wallet: %s", tx_id)
            return

        proof = TxProof(proof_position, proof_branch)
        await self.db_functions_async.update_transaction_proof_async(tx_hash, height, position,
            proof)

        height, position, conf, _timestamp = self.get_tx_height(tx_hash)
        self._logger.debug("add_transaction_proof %d %d %d", height, conf, timestamp)
        self.trigger_callback('verified', tx_hash, height, position, conf, timestamp)

    def remove_transaction(self, tx_hash: bytes) -> concurrent.futures.Future:
        """
        Unlink the transaction from accounts and their associated data.

        This will not delete the transaction from the database. It will however remove any
        links to the transaction including:
        - Invoice assocations with the transaction.
        """
        tx_id = hash_to_hex_str(tx_hash)
        self._logger.debug("removing tx from history %s", tx_id)

        def on_db_call_done(future: concurrent.futures.Future) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()
            self.trigger_callback('transaction_deleted', self._id, tx_hash)

        future = db_functions.remove_transaction(self.get_db_context(), tx_hash)
        future.add_done_callback(on_db_call_done)
        return future

    # TODO(nocheckin) unit test
    def ensure_incomplete_transaction_keys_exist(self, tx: Transaction) -> None:
        """
        Ensure that the keys the incomplete transaction uses exist.

        An incomplete transaction will have come from an external source that has shared it with
        us as we are either the offline signer, or multi-signature cosigner, and we need to make
        sure we have formally created the records for the key derivations it uses (which we
        probably haven't as we're likely a recipient).
        """
        if tx.is_complete():
            return

        self._logger.debug("ensure_incomplete_transaction_keys_exist")

        # Make sure we have created the keys that the transaction inputs use.
        for txin in tx.inputs:
            # These will be present for the signers who have not yet signed.
            for extended_public_key in txin.unused_x_pubkeys():
                account = self.find_account_for_extended_public_key(extended_public_key)
                if account is not None:
                    account.derive_new_keys_until(extended_public_key.derivation_path())

        # Make sure we have created the keys that the transaction outputs use.
        # - At the time of writing, this is change addresses.
        # - If the transaction creator added any of their own receiving addresses as destinations
        #   then there is no guarantee that they have the extended public key metadata.
        for txout in tx.outputs:
            if not len(txout.x_pubkeys):
                continue
            for extended_public_key in txout.x_pubkeys:
                account = self.find_account_for_extended_public_key(extended_public_key)
                if account is not None:
                    account.derive_new_keys_until(extended_public_key.derivation_path())

    def find_account_for_extended_public_key(self, extended_public_key: XPublicKey) \
            -> Optional[AbstractAccount]:
        """
        Find the account that can sign transactions that spend coins secured by the given
        extended public key.
        """
        for account in self._accounts.values():
            for keystore in account.get_keystores():
                if keystore.is_signature_candidate(extended_public_key):
                    return account
        return None

    def undo_verifications(self, above_height: int) -> None:
        '''Called by network when a reorg has happened'''
        if self._stopped:
            self._logger.debug("undo_verifications on stopped wallet: %d", above_height)
            return

        tx_hashes = db_functions.read_reorged_transactions(self.get_db_context(), above_height)
        self._logger.info('removing verification of %d transactions above %d',
            len(tx_hashes), above_height)
        future = db_functions.set_transactions_reorged(self.get_db_context(), tx_hashes)
        future.result()

        if self._storage.get('deactivate_used_keys', False):
            for account in self._accounts.values():
                # TODO(nocheckin) Verify this does what it should.
                account.reactivate_reorged_keys(tx_hashes)

    def have_transaction(self, tx_hash: bytes) -> bool:
        return self.get_transaction_flags(tx_hash) is not None

    def get_transaction(self, tx_hash: bytes) -> Optional[Transaction]:
        lock = self._acquire_transaction_lock(tx_hash)
        with lock:
            try:
                return self._get_cached_transaction(tx_hash)
            finally:
                self._release_transaction_lock(tx_hash)

    def _get_cached_transaction(self, tx_hash: bytes) -> Optional[Transaction]:
        tx = self._transaction_cache2.get(tx_hash)
        if tx is None:
            tx_bytes = db_functions.read_transaction_bytes(self.get_db_context(), tx_hash)
            if tx_bytes is not None:
                tx = Transaction.from_bytes(tx_bytes)
                self._transaction_cache2.set(tx_hash, tx)
        return tx

    def get_transaction_bytes(self, tx_hash: bytes) -> Optional[bytes]:
        """
        Get the byte data for the transaction directly from the database if it is present.
        """
        return db_functions.read_transaction_bytes(self.get_db_context(), tx_hash)

    # def set_deactivate_used_keys(self, enabled: bool) -> None:
    #     current_setting = self._storage.get('deactivate_used_keys', None)
    #     if not enabled and current_setting is True:
    #         # ensure all keys are re-activated
    #         for account in self.get_accounts():
    #             account.update_key_activation_state(list(account._keyinstances.values()), True)

    #     return self._storage.put('deactivate_used_keys', enabled)

    def get_boolean_setting(self, setting_name: str, default_value: bool=False) -> bool:
        """
        Get the value of a wallet-global config variable that is known to be boolean type.

        For the sake of simplicity, callers are expected to know the default value of their
        given variable and pass it in. Known cases are:
          WalletSettings.USE_CHANGE: True
          WalletSettings.MULTIPLE_CHANGE: True
        """
        return self._storage.get(str(setting_name), default_value)

    def is_synchronized(self) -> bool:
        "If all the accounts are synchronized"
        return all(w.is_synchronized() for w in self.get_accounts())

    def set_boolean_setting(self, setting_name: str, enabled: bool) -> None:
        self._storage.put(setting_name, enabled)
        self.trigger_callback('on_setting_changed', setting_name, enabled)

    def get_cache_size_for_tx_bytedata(self) -> int:
        """
        This returns the number of megabytes of cache. The caller should convert it to bytes for
        the cache.
        """
        return self._storage.get('tx_bytedata_cache_size', DEFAULT_TXDATA_CACHE_SIZE_MB)

    def set_cache_size_for_tx_bytedata(self, maximum_size: int, force_resize: bool=False) -> None:
        assert MINIMUM_TXDATA_CACHE_SIZE_MB <= maximum_size <= MAXIMUM_TXDATA_CACHE_SIZE_MB, \
            f"invalid cache size {maximum_size}"
        self._storage.put('tx_bytedata_cache_size', maximum_size)
        maximum_size_bytes = maximum_size * (1024 * 1024)
        self._transaction_cache2.set_maximum_size(maximum_size, force_resize)

    def get_local_height(self) -> int:
        """ return last known height if we are offline """
        return (self._network.get_local_height() if self._network else
            self._storage.get('stored_height', 0))

    def get_request_response_counts(self) -> Tuple[int, int]:
        request_count = self.request_count
        response_count = self.response_count
        for account in self.get_accounts():
            if account.request_count > account.response_count:
                request_count += account.request_count
                response_count += account.response_count
            else:
                account.request_count = 0
                account.response_count = 0
        return request_count, response_count

    def start(self, network: Optional['Network']) -> None:
        self._network = network
        if network is not None:
            network.add_wallet(self)
        for account in self.get_accounts():
            account.start(network)
        self._stopped = False

    def stop(self) -> None:
        assert not self._stopped
        local_height = self._last_load_height
        chain_tip_hash = self._last_load_hash
        if self._network is not None and self._network.chain():
            chain_tip = self._network.chain().tip
            local_height = chain_tip.height
            chain_tip_hash = chain_tip.hash
        self._storage.put('stored_height', local_height)
        self._storage.put('last_tip_hash', chain_tip_hash.hex() if chain_tip_hash else None)

        for account in self.get_accounts():
            account.stop()
        if self._network is not None:
            self._network.remove_wallet(self)
        self.db_functions_async.close()
        self._storage.close()
        self._network = None
        self._stopped = True

    def create_gui_handler(self, window: 'ElectrumWindow', account: AbstractAccount) -> None:
        for keystore in account.get_keystores():
            if isinstance(keystore, Hardware_KeyStore):
                plugin = cast('QtPluginBase', keystore.plugin)
                plugin.replace_gui_handler(window, keystore)
