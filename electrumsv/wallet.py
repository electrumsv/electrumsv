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
import concurrent.futures
import dataclasses
from datetime import datetime
from enum import IntFlag
import itertools
import json
import os
import random
import threading
from typing import (Any, cast, Dict, Iterable, List, Optional, Sequence, Set, Tuple, TypedDict,
    TypeVar, TYPE_CHECKING, Union)
import weakref

import aiorpcx
from bitcoinx import (Address, bip32_build_chain_string,
    double_sha256, hash_to_hex_str, Header, hex_str_to_hash,
    MissingHeader, P2PKH_Address, P2SH_Address, PrivateKey, PublicKey, Ops, pack_byte, push_item,
    Script)

from . import coinchooser
from .app_state import app_state
from .bitcoin import scripthash_bytes, ScriptTemplate
from .constants import (ACCOUNT_SCRIPT_TYPES, AccountCreationType, AccountType, BlockHeight,
    CHANGE_SUBPATH, DatabaseKeyDerivationType,
    DEFAULT_TXDATA_CACHE_SIZE_MB, DerivationType, DerivationPath, TransactionImportFlag,
    KeyInstanceFlag, KeystoreTextType, KeystoreType,
    MAXIMUM_TXDATA_CACHE_SIZE_MB, MINIMUM_TXDATA_CACHE_SIZE_MB, NetworkServerType,
    pack_derivation_path, PaymentFlag, RECEIVING_SUBPATH,
    SubscriptionOwnerPurpose, SubscriptionType, ScriptType, TransactionInputFlag,
    TransactionOutputFlag, TxFlags, unpack_derivation_path, WalletEventFlag, WalletEventType,
    WalletSettings)
from .contacts import Contacts
from .crypto import pw_decode, pw_encode
from .exceptions import (ExcessiveFee, NotEnoughFunds, PreviousTransactionsMissingException,
    SubscriptionStale, UnsupportedAccountTypeError, UnsupportedScriptTypeError, UserCancelled,
    WalletLoadError)
from .i18n import _
from .keys import get_multi_signer_script_template, get_single_signer_script_template
from .keystore import (BIP32_KeyStore, Deterministic_KeyStore, Hardware_KeyStore, Imported_KeyStore,
    instantiate_keystore, KeyStore, Multisig_KeyStore, Old_KeyStore, SinglesigKeyStoreTypes,
    SignableKeystoreTypes, StandardKeystoreTypes, Xpub)
from .logs import logs
from .networks import Net
from .storage import WalletStorage
from .transaction import (HardwareSigningMetadata, Transaction, TransactionContext,
    TxSerialisationFormat, NO_SIGNATURE, tx_dict_from_text, XPublicKey, XTxInput, XTxOutput)
from .types import (SubscriptionDerivationData, ElectrumXHistoryList,
    IndefiniteCredentialId,
    KeyInstanceDataBIP32SubPath,
    KeyInstanceDataHash, KeyInstanceDataPrivateKey, MasterKeyDataTypes,
    MasterKeyDataBIP32, MasterKeyDataElectrumOld, MasterKeyDataMultiSignature,
    NetworkServerState, ServerAccountKey, SubscriptionEntry,
    SubscriptionKey, SubscriptionDerivationScriptHashOwnerContext,
    SubscriptionOwner, SubscriptionKeyScriptHashOwnerContext,
    SubscriptionTransactionScriptHashOwnerContext, Outpoint, WaitingUpdateCallback,
    DatabaseKeyDerivationData)
from .util import (format_satoshis, get_posix_timestamp, get_wallet_name_from_path,
    posix_timestamp_to_datetime, TriggeredCallbacks, ValueLocks)
from .util.cache import LRUCache
from .wallet_database.exceptions import KeyInstanceNotFoundError
from .wallet_database import functions as db_functions
from .wallet_database.sqlite_support import DatabaseContext
from .wallet_database.types import (AccountRow, AccountTransactionDescriptionRow,
    HistoryListRow, InvoiceAccountRow, InvoiceRow, KeyDataTypes, KeyInstanceFlagChangeRow,
    KeyInstanceRow, KeyListRow, KeyInstanceScriptHashRow, MasterKeyRow,
    NetworkServerRow, NetworkServerAccountRow, PasswordUpdateResult, PaymentRequestReadRow,
    PaymentRequestRow, PaymentRequestUpdateRow, TransactionBlockRow,
    TransactionDeltaSumRow, TransactionExistsRow, TransactionLinkState, TransactionMetadata,
    TransactionSubscriptionRow,
    TransactionOutputShortRow, TransactionOutputSpendableRow2, TransactionOutputSpendableRow,
    TransactionOutputSpendableTypes, TransactionValueRow,
    TransactionInputAddRow, TransactionOutputAddRow,
    TransactionRow, TxProof, WalletBalance, WalletEventRow)
from .wallet_database.util import create_derivation_data2

if TYPE_CHECKING:
    from .network import Network
    from electrumsv.gui.qt.main_window import ElectrumWindow
    from electrumsv.devices.hw_wallet.qt import QtPluginBase

logger = logs.get_logger("wallet")


class AccountInstantiationFlags(IntFlag):
    NONE = 0
    IMPORTED_PRIVATE_KEYS = 1 << 0
    IMPORTED_ADDRESSES = 1 << 1
    NEW = 1 << 2


class AccountExportEntry(TypedDict):
    txid: str
    height: int
    timestamp: str
    value: str
    balance: str
    label: str
    fiat_value: Optional[str]
    fiat_balance: Optional[str]


@dataclasses.dataclass(frozen=True)
class KeyAllocation:
    masterkey_id: int
    derivation_type: DerivationType

    ## Optional fields with required data for different derivation types.
    # Only used for BIP32 key allocations.
    derivation_path: DerivationPath = ()


@dataclasses.dataclass
class HistoryListEntry:
    sort_key: Tuple[int, int]
    row: HistoryListRow
    balance: int


@dataclasses.dataclass
class MissingTransactionEntry:
    block_hash: Optional[bytes]
    block_height: int
    fee_hint: Optional[int]
    import_flags: TransactionImportFlag


ADDRESS_TYPES = { DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH }


def dust_threshold(network: Optional["Network"]) -> int:
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

    def __init__(self, wallet: 'Wallet', row: AccountRow) -> None:
        # Prevent circular reference keeping parent and accounts alive.
        self._wallet: 'Wallet' = cast('Wallet', weakref.proxy(wallet))
        self._row = row
        self._id = row.account_id

        # Monitor active keys for transaction detection.
        self._subscription_owner_for_keys = SubscriptionOwner(self._wallet._id, self._id,
            SubscriptionOwnerPurpose.ACTIVE_KEYS)
        # Monitor a key per transaction for mining detection.
        self._subscription_owner_for_transactions = SubscriptionOwner(self._wallet._id, self._id,
            SubscriptionOwnerPurpose.TRANSACTION_STATE)

        self._logger = logs.get_logger("account[{}]".format(self.name()))
        self._network: Optional["Network"] = None

        self.request_count = 0
        self.response_count = 0
        self.last_poll_time: Optional[float] = None

        self._gap_limit_observer_event_async = app_state.async_.event()

        # locks: if you need to take several, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self._value_locks = ValueLocks()

    def get_id(self) -> int:
        return self._id

    def get_wallet(self) -> 'Wallet':
        return self._wallet

    def requires_input_transactions(self) -> bool:
        return any(k.requires_input_transactions() for k in self.get_keystores())

    def get_next_derivation_index(self, derivation_subpath: DerivationPath) -> int:
        raise NotImplementedError

    def allocate_keys(self, count: int, derivation_subpath: DerivationPath) \
            -> Sequence[KeyAllocation]:
        """
        Produce an annotated sequence of each key that should be created.

        This should include the derivation type and the derivation context of each individual key.
        """
        raise NotImplementedError

    def get_fresh_keys(self, derivation_parent: DerivationPath, count: int) -> List[KeyInstanceRow]:
        raise NotImplementedError

    def reserve_unassigned_key(self, derivation_parent: DerivationPath, flags: KeyInstanceFlag) \
            -> int:
        raise NotImplementedError

    def derive_new_keys_until(self, derivation_path: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> Tuple[Optional[concurrent.futures.Future[None]], List[KeyInstanceRow]]:
        raise NotImplementedError

    def derive_script_template(self, derivation_path: DerivationPath,
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        raise NotImplementedError

    def allocate_and_create_keys(self, count: int, derivation_subpath: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> Tuple[Optional[concurrent.futures.Future[None]],
                        Optional[concurrent.futures.Future[None]],
                        List[KeyInstanceRow], List[KeyInstanceScriptHashRow]]:
        raise NotImplementedError

    def create_preallocated_keys(self, key_allocations: Sequence[KeyAllocation],
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> Tuple[concurrent.futures.Future[None], concurrent.futures.Future[None],
                        List[KeyInstanceRow], List[KeyInstanceScriptHashRow]]:
        """
        Take a list of key allocations and create keyinstances and scripts in the database for them.

        Key allocations are expected to be created in a safe context that prevents multiple
        allocations of the same key allocation parameters from being assigned to multiple callers.
        """
        keyinstance_rows: List[KeyInstanceRow] = []
        for ka in key_allocations:
            derivation_data_dict = self._create_derivation_data_dict(ka)
            derivation_data = json.dumps(derivation_data_dict).encode()
            derivation_data2 = create_derivation_data2(ka.derivation_type, derivation_data_dict)
            keyinstance_rows.append(KeyInstanceRow(-1, self.get_id(), ka.masterkey_id,
                ka.derivation_type, derivation_data, derivation_data2,
                keyinstance_flags, None))
        keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
            self.create_provided_keyinstances(keyinstance_rows)
        return keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows

    def create_provided_keyinstances(self, keyinstance_rows: List[KeyInstanceRow]) -> \
            Tuple[concurrent.futures.Future[None], concurrent.futures.Future[None],
                List[KeyInstanceRow], List[KeyInstanceScriptHashRow]]:
        """
        Take a list of pre-created keyinstances and create them and their scripts in the database.

        The `keyinstances` are not considered to have a valid `keyinstance_id` field, and an
        id will be allocated for each row before they are written to the database. The returned
        `keyinstances` will be the final rows, including the allocated id.
        """
        # This will set the allocated keyinstance id for the given row and start a database
        # operation to formally create them there.
        keyinstance_future, keyinstance_rows = \
            self._wallet.create_keyinstances(self._id, keyinstance_rows)
        # The script hashes are used to match incoming transactions to usage of keyinstances
        # and must be added for all expected script types, for the given key.
        scripthash_rows: List[KeyInstanceScriptHashRow] = []
        for keyinstance_row in keyinstance_rows:
            for script_type, script in self.get_possible_scripts_for_derivation(
                    keyinstance_row.derivation_type, keyinstance_row.derivation_data2):
                script_hash = scripthash_bytes(script)
                scripthash_rows.append(KeyInstanceScriptHashRow(keyinstance_row.keyinstance_id,
                    script_type, script_hash))
        scripthash_future = self._wallet.create_keyinstance_scripts(scripthash_rows)
        # The caller only needs to wait on the second future, as the database writes are executed
        # sequentially and the second will complete after the first.
        return keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows

    def _create_derivation_data_dict(self, key_allocation: KeyAllocation) \
            -> KeyInstanceDataBIP32SubPath:
        assert key_allocation.derivation_type == DerivationType.BIP32_SUBPATH
        assert len(key_allocation.derivation_path)
        return { "subpath": key_allocation.derivation_path }

    def _get_subscription_entries_for_keyinstance_ids(self, keyinstance_ids: List[int]) \
            -> List[SubscriptionEntry]:
        entries: List[SubscriptionEntry] = []
        for row in self._wallet.read_keyinstance_scripts_by_id(keyinstance_ids):
            entries.append(
                SubscriptionEntry(
                    SubscriptionKey(SubscriptionType.SCRIPT_HASH, row.script_hash),
                    SubscriptionKeyScriptHashOwnerContext(row.keyinstance_id, row.script_type)))
        return entries

    def set_keyinstance_flags(self, keyinstance_ids: Sequence[int], flags: KeyInstanceFlag,
            mask: Optional[KeyInstanceFlag]=None) \
                -> concurrent.futures.Future[List[KeyInstanceFlagChangeRow]]:
        """
        Encapsulate updating the flags for keyinstances belonging to this account.

        This will subscribe or unsubscribe from script hash notifications from any indexer
        automatically as any flags relating to activeness of the key are set or unset.
        """
        # There is no situation where keys should be marked active, as this is meaningless.
        # Keys should only be activated with supplementary reasons so we can know if we can
        # deactivate it fully.
        assert flags & KeyInstanceFlag.ACTIVE == 0, "do not set directly"

        # Setting any `MASK_ACTIVE_REASON` flag is additive to the base `ACTIVE` flag.
        if flags & KeyInstanceFlag.MASK_ACTIVE_REASON:
            flags |= KeyInstanceFlag.ACTIVE

        def callback(future: concurrent.futures.Future[List[KeyInstanceFlagChangeRow]]) -> None:
            # Ensure we abort if it is cancelled.
            if future.cancelled():
                return
            # Ensure we abort if there is an error.
            results = future.result()

            # NOTE(ActivitySubscription) If a key becomes active here through one of the specialised
            #   activity flags, then we will want to subscribe to it. But if it has one of those
            #   flags removed this does not mean we will want to unsubscribe. We may still want to
            #   get notifications to detect whether a transaction has been mined, so that we know
            #   to request a merkle proof.
            if self._network is not None:
                subscription_keyinstance_ids: List[int] = []
                unsubscription_keyinstance_ids: List[int] = []
                for keyinstance_id, flags, final_flags in results:
                    if flags & KeyInstanceFlag.ACTIVE:
                        if final_flags & KeyInstanceFlag.ACTIVE == 0:
                            unsubscription_keyinstance_ids.append(keyinstance_id)
                    else:
                        if final_flags & KeyInstanceFlag.ACTIVE:
                            subscription_keyinstance_ids.append(keyinstance_id)

                if len(subscription_keyinstance_ids):
                    self._network.subscriptions.create_entries(
                        self._get_subscription_entries_for_keyinstance_ids(
                            subscription_keyinstance_ids), self._subscription_owner_for_keys)

                if len(unsubscription_keyinstance_ids):
                    self._network.subscriptions.delete_entries(
                        self._get_subscription_entries_for_keyinstance_ids(
                            unsubscription_keyinstance_ids), self._subscription_owner_for_keys)

            self._wallet.trigger_callback('keys_updated', self._id, keyinstance_ids)

        future = self._wallet.set_keyinstance_flags(keyinstance_ids, flags, mask)
        future.add_done_callback(callback)
        return future

    def delete_key_subscriptions(self, keyinstance_ids: List[int]) -> None:
        assert self._network is not None
        self._network.subscriptions.delete_entries(
            self._get_subscription_entries_for_keyinstance_ids(
                keyinstance_ids), self._subscription_owner_for_keys)

    def is_synchronized(self) -> bool:
        # TODO(no-merge) Need to reimplement to deal with scanning/pending state?
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

    # TODO(multi-account) This is not compatible with multi-account usage of the same transaction
    # unless we repackage the outer transaction. We kind of need per-account transaction context.
    def get_transaction(self, tx_hash: bytes) -> Optional[Tuple[Transaction, TransactionContext]]:
        """
        Get the transaction with account-specific metadata like the description.
        """
        tx = self._wallet.get_transaction(tx_hash)
        context: Optional[TransactionContext] = None
        if tx is None:
            return None
        # Populate the description.
        context = TransactionContext()
        desc = self.get_transaction_label(tx_hash)
        if desc:
            context.description = desc
        return tx, context

    def set_transaction_label(self, tx_hash: bytes, text: Optional[str]) \
            -> concurrent.futures.Future[None]:
        return self.set_transaction_labels([ (tx_hash, text) ])

    def set_transaction_labels(self, entries: Iterable[Tuple[bytes, Optional[str]]]) \
            -> concurrent.futures.Future[None]:
        def callback(future: concurrent.futures.Future[None]) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()

            self._wallet.trigger_callback('transaction_labels_updated', update_entries)

            for tx_hash, text in entries:
                app_state.app_qt.on_transaction_label_change(self, tx_hash, text or "")

        update_entries: List[Tuple[Optional[str], int, bytes]] = []
        for tx_hash, description in entries:
            update_entries.append((description, self._id, tx_hash))
        future = self._wallet.update_account_transaction_descriptions(update_entries)
        future.add_done_callback(callback)
        return future

    def get_transaction_label(self, tx_hash: bytes) -> str:
        rows = self._wallet.read_transaction_descriptions(self._id, tx_hashes=[ tx_hash ])
        if len(rows) and rows[0].description:
            return rows[0].description
        return ""

    def get_transaction_labels(self, tx_hashes: Sequence[bytes]) \
            -> List[AccountTransactionDescriptionRow]:
        return self._wallet.read_transaction_descriptions(self._id, tx_hashes=tx_hashes)

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

    def is_deterministic(self) -> bool:
        # Not all wallets have a keystore, like imported address for instance.
        keystore = self.get_keystore()
        return keystore is not None and keystore.is_deterministic()

    def involves_hardware_wallet(self) -> bool:
        return any([ k for k in self.get_keystores() if isinstance(k, Hardware_KeyStore) ])

    def get_label_data(self) -> Dict[str, Any]:
        # Create exported data structure for account labels/descriptions.
        label_entries = [
            (bip32_build_chain_string(unpack_derivation_path(cast(bytes, key.derivation_data2))),
                key.description)
            for key in self.get_keyinstances() if key.description is not None
        ]
        rows = self._wallet.read_transaction_descriptions(self._id)
        transaction_entries = [
            (hash_to_hex_str(tx_hash), description) for account_id, tx_hash, description in rows
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
        keyinstance = self._wallet.read_keyinstance(keyinstance_id=key_id)
        assert keyinstance is not None
        return keyinstance.description or ""

    def set_keyinstance_label(self, keyinstance_id: int, text: Optional[str]) \
            -> Optional[concurrent.futures.Future[None]]:
        text = None if text is None or text.strip() == "" else text.strip()
        keyinstance = self._wallet.read_keyinstance(keyinstance_id=keyinstance_id)
        assert keyinstance is not None
        if keyinstance.description == text:
            return None
        future = self._wallet.update_keyinstance_descriptions([ (text, keyinstance_id) ])
        app_state.app_qt.on_keyinstance_label_change(self, keyinstance_id, text or "")
        return future

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

    def get_threshold(self) -> int:
        return 1

    def export_private_key(self, keydata: KeyDataTypes, password: str) -> Optional[str]:
        """ extended WIF format """
        if self.is_watching_only():
            return None
        assert keydata.masterkey_id is not None
        keystore = self._wallet.get_keystore(keydata.masterkey_id)
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        secret, compressed = keystore.get_private_key(derivation_path, password)
        return cast(str, PrivateKey(secret).to_WIF(compressed=compressed, coin=Net.COIN))

    def get_frozen_balance(self) -> WalletBalance:
        return self._wallet.read_account_balance(self._id, self._wallet.get_local_height(),
            TransactionOutputFlag.FROZEN)

    def get_balance(self) -> WalletBalance:
        return self._wallet.read_account_balance(self._id, self._wallet.get_local_height())

    def maybe_set_transaction_state(self, tx_hash: bytes, flags: TxFlags,
            ignore_mask: Optional[TxFlags]=None) -> bool:
        """
        We should only ever mark a transaction as a state if it it isn't already in a related
        state.
        """
        future = self._wallet.set_transaction_state(tx_hash, flags, ignore_mask)
        if future.result():
            self._wallet.trigger_callback('transaction_state_change', self._id, tx_hash, flags)
            return True
        return False

    def get_key_list(self, keyinstance_ids: Optional[List[int]]=None) -> List[KeyListRow]:
        return self._wallet.read_key_list(self._id, keyinstance_ids)

    def get_local_transaction_entries(self, tx_hashes: Optional[List[bytes]]=None) \
            -> List[TransactionValueRow]:
        return self._wallet.read_transaction_value_entries(self._id, tx_hashes=tx_hashes,
            mask=TxFlags.MASK_STATE_UNCLEARED)

    def get_transaction_value_entries(self, mask: Optional[TxFlags]=None) \
            -> List[TransactionValueRow]:
        return self._wallet.read_transaction_value_entries(self._id, mask=mask)

    def get_transaction_outputs_with_key_data(self, exclude_frozen: bool=True, mature: bool=True,
            confirmed_only: Optional[bool]=None, keyinstance_ids: Optional[List[int]]=None) \
                -> List[TransactionOutputSpendableRow]:
        if confirmed_only is None:
            confirmed_only = cast(bool, app_state.config.get('confirmed_only', False))
        mature_height = self._wallet.get_local_height() if mature else None
        return self._wallet.read_account_transaction_outputs_with_key_data(self._id,
            confirmed_only=confirmed_only, mature_height=mature_height,
            exclude_frozen=exclude_frozen, keyinstance_ids=keyinstance_ids)

    def get_transaction_outputs_with_key_and_tx_data(self, exclude_frozen: bool=True,
            mature: bool=True, confirmed_only: Optional[bool]=None,
            keyinstance_ids: Optional[List[int]]=None) -> List[TransactionOutputSpendableRow2]:
        if confirmed_only is None:
            confirmed_only = cast(bool, app_state.config.get('confirmed_only', False))
        mature_height = self._wallet.get_local_height() if mature else None
        return self._wallet.read_account_transaction_outputs_with_key_and_tx_data(self._id,
            confirmed_only=confirmed_only, mature_height=mature_height,
            exclude_frozen=exclude_frozen, keyinstance_ids=keyinstance_ids)

    def get_extended_input_for_spendable_output(self, row: TransactionOutputSpendableTypes) \
            -> XTxInput:
        assert row.account_id is not None
        assert row.account_id == self._id
        assert row.keyinstance_id is not None
        assert row.derivation_type is not None
        x_pubkeys = self.get_xpubkeys_for_key_data(row)
        # NOTE(typing) The first four arguments for `TxInput` cause mypy to choke because `attrs`..
        return XTxInput(
            prev_hash          = row.tx_hash, # type: ignore
            prev_idx           = row.txo_index,
            script_sig         = Script(),
            sequence           = 0xffffffff,
            threshold          = self.get_threshold(),
            script_type        = row.script_type,
            signatures         = [NO_SIGNATURE] * len(x_pubkeys),
            x_pubkeys          = x_pubkeys,
            value              = row.value,
        )

    def get_history(self, domain: Optional[Sequence[int]]=None) -> List[HistoryListEntry]:
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
                assert row.block_height is not None
                sort_key = row.block_height, row.block_position
            else:
                sort_key = (1000000000, row.date_created)
            history_raw.append(HistoryListEntry(sort_key, row, 0))

        history_raw.sort(key=lambda t: t.sort_key)

        balance = 0
        for entry in history_raw:
            balance += entry.row.value_delta
            entry.balance = balance
        history_raw.reverse()
        return history_raw

    def export_history(self, from_datetime: Optional[datetime]=None,
            to_datetime: Optional[datetime]=None) -> List[AccountExportEntry]:
        # TODO If the history is exported and we do not have headers for entries, we try and
        #   populate the header for a given line as we go. However, if we are offline then there
        #   will be no network and no way to backfill a header.
        fx = app_state.fx
        assert app_state.headers is not None
        chain = app_state.headers.longest_chain()
        header_at_height = app_state.headers.header_at_height
        server_height = self._network.get_server_height() if self._network else 0

        out: List[AccountExportEntry] = []
        for entry in self.get_history():
            history_line = entry.row
            assert history_line.block_height is not None
            try:
                timestamp = posix_timestamp_to_datetime(header_at_height(chain,
                                history_line.block_height).timestamp)
            except MissingHeader:
                if history_line.block_height > BlockHeight.MEMPOOL:
                    assert self._network is not None, "missing headers and offline"
                    self._logger.debug("fetching missing headers at height: %s",
                                       history_line.block_height)
                    assert history_line.block_height <= server_height, \
                        "inconsistent blockchain data"
                    self._network.backfill_headers_at_heights([ history_line.block_height ])
                    timestamp = posix_timestamp_to_datetime(header_at_height(chain,
                                    history_line.block_height).timestamp)
                else:
                    timestamp = datetime.now()
            assert timestamp is not None
            if from_datetime and timestamp < from_datetime:
                continue
            if to_datetime and timestamp >= to_datetime:
                continue
            export_entry = AccountExportEntry(
                txid=hash_to_hex_str(history_line.tx_hash),
                height=history_line.block_height,
                timestamp=timestamp.isoformat(),
                value=format_satoshis(history_line.value_delta,
                    is_diff=True) if history_line.value_delta is not None else '--',
                balance=format_satoshis(entry.balance),
                label=history_line.description or "",
                fiat_value=None,
                fiat_balance=None)
            if fx:
                date = timestamp
                export_entry['fiat_value'] = fx.historical_value_str(history_line.value_delta, date)
                export_entry['fiat_balance'] = fx.historical_value_str(entry.balance, date)
            out.append(export_entry)
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
        assert ordered_coins[0].derivation_data2 is not None
        public_keys = self.get_public_keys_for_derivation(
            cast(DerivationType, ordered_coins[0].derivation_type),
            ordered_coins[0].derivation_data2)
        for public_key in public_keys:
            raw_payload_bytes = push_item(os.urandom(random.randrange(32)))
            payload_bytes = public_key.encrypt_message(raw_payload_bytes)
            script_bytes = pack_byte(Ops.OP_0) + pack_byte(Ops.OP_RETURN) + push_item(payload_bytes)
            script = Script(script_bytes)
            # NOTE(rt12) This seems to be some attrs/mypy clash, the base class attrs should come
            # before the XTxOutput attrs, but typing expects these to be the XTxOutput attrs.
            return [XTxOutput(0, script)] # type: ignore

        return []

    def dust_threshold(self) -> int:
        return dust_threshold(self._network)

    def make_unsigned_transaction(self, unspent_outputs: List[TransactionOutputSpendableTypes],
            outputs: List[XTxOutput]) -> Tuple[Transaction, TransactionContext]:
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

        if app_state.config.fee_per_kb() is None:
            raise Exception('Dynamic fee estimates not available')

        # TODO(MAPI) This needs to be replaced with a fee estimator based on whether the server
        #   is an ElectrumX server, or a MAPI server. If it is a MAPI server, then we need to
        #   use a per-server fee quote. Really, we might change `estimate_fee` to instead return
        #   a fee quote.
        fee_estimator = app_state.config.estimate_fee

        tx_context = TransactionContext()
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
                    change_outs.append(XTxOutput(
                        value         = 0, # type: ignore
                        script_pubkey = self.get_script_for_derivation(script_type,
                            keyinstance.derivation_type, keyinstance.derivation_data2),
                        script_type   = script_type,
                        x_pubkeys     = self.get_xpubkeys_for_key_data(keyinstance)))
            else:
                # NOTE(typing) `attrs` and `mypy` are not compatible, `TxOutput` vars unseen.
                change_outs = [ XTxOutput( # type: ignore
                    value         = 0,
                    script_pubkey = self.get_script_for_derivation(unspent_outputs[0].script_type,
                        cast(DerivationType, unspent_outputs[0].derivation_type),
                        unspent_outputs[0].derivation_data2),
                    script_type   = inputs[0].script_type,
                    x_pubkeys     = inputs[0].x_pubkeys) ]
            coin_chooser = coinchooser.CoinChooserPrivacy()
            tx = coin_chooser.make_tx(inputs, outputs, change_outs,
                fee_estimator, self.dust_threshold())
        else:
            assert all(txin.value is not None for txin in inputs)
            sendable = cast(int, sum(txin.value for txin in inputs))
            outputs[all_index].value = 0
            tx = Transaction.from_io(inputs, outputs)
            fee = fee_estimator(tx.estimated_size())
            outputs[all_index].value = max(0, sendable - tx.output_value() - fee)
            tx = Transaction.from_io(inputs, outputs)

        # If user tries to send too big of a fee (more than 50
        # sat/byte), stop them from shooting themselves in the foot
        tx_in_bytes=sum(tx.estimated_size())
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
        return tx, tx_context

    def start(self, network: Optional["Network"]) -> None:
        self._network = network
        if network is not None:
            # Set up the key monitoring for the account.
            network.subscriptions.set_owner_callback(self._subscription_owner_for_keys,
                # NOTE(typing) The union of callback types does not recognise this case ??
                self._on_network_key_script_hash_result) # type: ignore
            # TODO(deferred) This only needs to read keyinstance ids and could be combined with
            #   the second call in `_get_subscription_entries_for_keyinstance_ids`
            keyinstances = self._wallet.read_keyinstances(account_id=self._id,
                mask=KeyInstanceFlag.ACTIVE)
            self.register_for_keyinstance_events(keyinstances)

            # Set up the transaction monitoring for the account.
            network.subscriptions.set_owner_callback(self._subscription_owner_for_transactions,
                # NOTE(typing) The union of callback types does not recognise this case ??
                self._on_network_transaction_script_hash_result) # type: ignore
            self.register_for_transaction_proofs()

    def stop(self) -> None:
        assert not self._stopped
        self._stopped = True

        self._logger.debug("stopping account %s", self)
        if self._network:
            # Unsubscribe from the account's existing subscriptions.
            future = self._network.subscriptions.remove_owner(self._subscription_owner_for_keys)
            if future is not None:
                future.result()
            self._network = None

    def register_for_keyinstance_events(self, keyinstances: List[KeyInstanceRow]) -> None:
        assert self._network is not None
        if len(keyinstances):
            self._logger.debug("Creating %d active key subscriptions: %s",
                len(keyinstances), [ row.keyinstance_id for row in keyinstances ])
            subscription_keyinstance_ids = [ row.keyinstance_id for row in keyinstances ]
            self._network.subscriptions.create_entries(
                self._get_subscription_entries_for_keyinstance_ids(
                    subscription_keyinstance_ids), self._subscription_owner_for_keys)

    def register_for_transaction_proofs(self, tx_hash: Optional[bytes]=None) -> None:
        """
        Observe our mempool and local transactions though one registered script hash.

        This accomplishes two things, it notifies the wallet when our transactions are mined
        so we can display the status change and it allows us to grab the merkle proof for
        the transaction so that we can provide as necessary with the outputs in order to spend
        them.

        At this time we grab the merkle proof for all transactions and not just those with
        UTXOs, but this will be the minority of cases. We can revisit the whole merkle proof
        model when there is an SPV server-based system that can provide all the merkle proofs
        in a standard way.
        """
        assert self._network is not None
        # At this point, this is used to get a script hash per transaction that does not have
        # a proof. In theory, we could just grab the script hash of the first output of any
        # unproven transaction, but it is not a given that all transactions have outputs let
        # alone outputs that can be used for this. If there is one, we use the script hash for
        # it but if there isn't we will use the script hash of a spent output and associate
        # it with the unproven spending transaction.
        tx_seen: Set[bytes] = set()
        tx_rows_by_script_hash: Dict[bytes, List[TransactionSubscriptionRow]] = {}
        tx_subscription_entries: List[SubscriptionEntry] = []
        for tx_row in self._wallet.read_keys_for_transaction_subscriptions(self._id, tx_hash):
            # It is possible we will get multiple entries for a transaction. Does it happen?
            if tx_row.tx_hash in tx_seen:
                continue
            tx_seen.add(tx_row.tx_hash)
            if tx_row.script_hash in tx_rows_by_script_hash:
                # The subscription entry has a reference to this, so appending will add
                # to that subscription.
                tx_rows_by_script_hash[tx_row.script_hash].append(tx_row)
            else:
                tx_entry_rows = tx_rows_by_script_hash[tx_row.script_hash] = [ tx_row ]
                tx_entry = SubscriptionEntry(
                    SubscriptionKey(SubscriptionType.SCRIPT_HASH, tx_row.script_hash),
                    SubscriptionTransactionScriptHashOwnerContext(tx_entry_rows))
                tx_subscription_entries.append(tx_entry)

        if len(tx_subscription_entries):
            self._logger.debug("Creating %d transaction subscriptions (tx_hash=%s)",
                len(tx_subscription_entries),
                hash_to_hex_str(tx_hash) if tx_hash is not None else None)
            self._network.subscriptions.create_entries(tx_subscription_entries,
                self._subscription_owner_for_transactions)

        # This will awaken the loop that pulls in proofs for transactions we know are mined
        # but have not yet fetched the proof for.
        self._wallet.txs_changed_event.set()

    async def _on_network_key_script_hash_result(self, subscription_key: SubscriptionKey,
            context: SubscriptionKeyScriptHashOwnerContext,
            history: ElectrumXHistoryList) -> None:
        """
        Receive an event related to this account and it's active keys.

        `history` is in immediately usable order. Transactions are listed in ascending
        block height (height > 0), followed by the unconfirmed (height == 0) and then
        those with unconfirmed parents (height < 0).

            [
                { "tx_hash": "e232...", "height": 111 },
                { "tx_hash": "df12...", "height": 222 },
                { "tx_hash": "aa12...", "height": 0, "fee": 400 },
                { "tx_hash": "bb12...", "height": -1, "fee": 300 },
            ]

        Use cases handled:
        * Process the information about transactions that use this key.
          - The user has manually marked a key as being actively watched.
          - The user has created a payment request (receiving to a dispensed payment destination).
            o Transactions are only processed as long as the payment request is in UNPAID state.
              There is a good argument we should log an error otherwise.
        """
        if not history:
            return

        tx_hashes: List[bytes] = []
        tx_heights: Dict[bytes, int] = {}
        tx_fee_hints: Dict[bytes, Optional[int]] = {}
        for entry in history:
            tx_hash = hex_str_to_hash(entry["tx_hash"])
            tx_hashes.append(tx_hash)
            # NOTE(typing) The storage of mixed type values in the history gives false positives.
            tx_heights[tx_hash] = entry["height"] # type: ignore
            tx_fee_hints[tx_hash] = entry.get("fee") # type: ignore

        keyinstance = self._wallet.read_keyinstance(account_id=self._id,
            keyinstance_id=context.keyinstance_id)
        assert keyinstance is not None

        obtain_missing_transactions = False
        if keyinstance.flags & KeyInstanceFlag.USER_SET_ACTIVE:
            # If a user has told the wallet to fetch all transactions related to a given key by
            # marking it as forced active by the user, then we do as they tell us.
            obtain_missing_transactions = True
        elif keyinstance.flags & KeyInstanceFlag.IS_PAYMENT_REQUEST:
            # We subscribe for events for keys used in unpaid payment requests. So we need to
            # ensure that we fetch the transactins when we receive these events as the model no
            # longer monitors all key usage any more.
            request = self._wallet.read_payment_request(keyinstance_id=context.keyinstance_id)
            assert request is not None, f"no payment request for key {context.keyinstance_id}"
            if (request.state & (PaymentFlag.UNPAID | PaymentFlag.ARCHIVED)) == PaymentFlag.UNPAID:
                obtain_missing_transactions = True
        else:
            self._logger.error("received unexpected key subscriptions for id: %d row: %r",
                context.keyinstance_id, keyinstance)

        if obtain_missing_transactions:
            await self._wallet.maybe_obtain_transactions_async(tx_hashes,
                tx_heights, tx_fee_hints)

    # TODO unit test malleation replacement of a transaction
    # TODO unit test spam transaction presence
    async def _on_network_transaction_script_hash_result(self, subscription_key: SubscriptionKey,
            context: SubscriptionTransactionScriptHashOwnerContext,
            history: ElectrumXHistoryList) -> None:
        """
        Receive an event related to this account and it's published account-related transactions.

        `history` is in immediately usable order. Transactions are listed in ascending
        block height (height > 0), followed by the unconfirmed (height == 0) and then
        those with unconfirmed parents (height < 0).

            [
                { "tx_hash": "e232...", "height": 111 },
                { "tx_hash": "df12...", "height": 222 },
                { "tx_hash": "aa12...", "height": 0, "fee": 400 },
                { "tx_hash": "bb12...", "height": -1, "fee": 300 },
            ]

        Use cases handled:
        * Ignore all information about unknown transactions that use this key, and solely
          observe whether the given transaction is mined in order to know when we can obtain a
          merkle proof.
          - The user creates a local transaction and gives it to another party.
          - The user creates and broadcasts a payment (pays to a payment destination).
          - The user is paying an invoice.
          - The user makes a payment to via Paymail.
          - The user receives a payment via Paymail.

        Note that we are called synchronously from the network.
        """
        if not history:
            return

        tx_heights: Dict[bytes, int] = {}
        for entry in history:
            tx_hash = hex_str_to_hash(entry["tx_hash"])
            # NOTE(typing) The storage of mixed type values in the history gives false positives.
            tx_heights[tx_hash] = entry["height"] # type: ignore

        async with self._wallet._obtain_proofs_async_lock:
            entries: List[TransactionBlockRow] = []
            pending_rows: List[TransactionSubscriptionRow] = []
            for row in context.tx_rows[:]:
                if row.tx_hash in tx_heights:
                    # The transaction is either present in the mempool or in a block. We can
                    # update the height and clear the proof.
                    block_height = tx_heights[row.tx_hash]
                    block_hash = self._wallet._get_header_hash_for_height(block_height)
                    entries.append(TransactionBlockRow(block_height, block_hash, row.tx_hash))
                    # If the transaction is in a block, it will be in a state in the database
                    # where we do not need to monitor it any more. If it is in the mempool we
                    # need to wait for it to be included in a block, and will continue to monitor
                    # it.
                    if block_height > BlockHeight.MEMPOOL:
                        context.tx_rows.remove(row)
                else:
                    pending_rows.append(row)

            # Process any subscription transactions we did not locate if we can.
            if len(pending_rows) and len(entries) < len(tx_heights):
                # There are several possibilities here.
                #
                # 1. The transaction has been malleated and is present with another hash.
                # 2. The transaction is not present but others are perhaps in the form of spam
                #    transactions that we do not want to have.
                #
                # We need to fetch each transaction and analyse them. This should be the exception
                # rather than the rule, so should not be that common. As the chance of users seeing
                # spam transactions goes away, especially with ElectrumSV no longer showing them
                # by default, the benefits of making them should no longer be present.
                #
                # However we are not going to do that at this point. It will be a todo item and a
                # second pass.
                # TODO(tx-malleation) Catch malleated transactions by fetching and processing
                #   them as described.
                pass

            future = self._wallet.update_transaction_block_many(entries)
            update_count = future.result()
            self._logger.debug("maybe_obtain_proofs_async: updated %d of %d entries",
                update_count, len(entries))
            if update_count:
                # Notify the network loop that if it has blocked waiting for more work to do
                # requesting proofs and transactions, otherwise it will block indefinitely waiting
                # to be told.
                self._wallet.txs_changed_event.set()
                # Updating the height needs to happen in related UI.
                self._wallet.trigger_callback('transaction_heights_updated', self._id, entries)

            # Ensure that all subscriptions to this script hash for our transaction needs are
            # removed and cleaned up.
            if len(context.tx_rows) == 0:
                raise SubscriptionStale()

    def can_export(self) -> bool:
        if self.is_watching_only():
            return False
        keystore = self.get_keystore()
        if keystore is not None:
            return keystore.can_export()
        return False

    def cpfp(self, tx: Transaction, fee: int=0) -> Optional[Transaction]:
        """
        Construct a "child pays for parent" transaction for `tx`.

        if `fee` is 0, we should not allocate a fresh key and will reuse the existing output.
        This is used by the caller to get a size estimate of the cpfp funding transaction.

        Note that in an ideal world the `fee` we pay should be the total fee for the underfunded
        transaction and the cpfp funding transaction. This would be the total size of both, at
        the wallet's standard fee rate. However, it is more than likely we will just repay a whole
        fee for the underfunded transaction in addition to the required fee for the cpfp funding
        transaction and ignore whatever fee the underfunded transaction already paid.

        For transactions spending coins in this wallet, it is almost guaranteed we should have
        the parent transactions and be able to calculate the fee. But Bitcoin SV is cheap enough
        and it is unlikely users use this very often, so for now.. we'll just overpay. Electrum
        for Bitcoin Core refuses to do a CPFP in this situation because BTC is of course broken
        and the expense of overpaying becomes prohibitive.
        """
        tx_hash = tx.hash()
        # These are required to have attached keys, so will be account coins received in the
        # given transaction.
        db_outputs = self._wallet.read_transaction_outputs_with_key_data(account_id=self._id,
            tx_hash=tx_hash, require_keys=True)
        if not db_outputs:
            return None

        db_outputs = sorted(db_outputs, key=lambda db_output: -db_output.value)
        output = db_outputs[0]
        inputs = [ self.get_extended_input_for_spendable_output(output) ]
        # TODO(rt12) This should get a change output key from the account (if applicable).
        # NOTE(typing) mypy struggles with attrs inheritance, so we need to disable it.
        outputs = [
            XTxOutput(
                # TxOutput
                output.value - fee, # type:ignore
                self.get_script_for_derivation(output.script_type,
                    cast(DerivationType, output.derivation_type), output.derivation_data2),
                # XTxOutput
                output.script_type,
                self.get_xpubkeys_for_key_data(output)) # type:ignore
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

    def get_master_public_key(self) -> Optional[str]:
        raise NotImplementedError

    def get_master_public_keys(self) -> List[str]:
        raise NotImplementedError

    def get_public_keys_for_derivation(self, derivation_type: DerivationType,
            derivation_data2: Optional[bytes]) -> List[PublicKey]:
        assert derivation_data2 is not None
        if derivation_type == DerivationType.BIP32_SUBPATH:
            derivation_path = unpack_derivation_path(derivation_data2)
            return self.get_public_keys_for_derivation_path(derivation_path)
        elif derivation_type == DerivationType.PRIVATE_KEY:
            return [ PublicKey.from_bytes(derivation_data2) ]
        elif derivation_type in (DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH):
            # This is all the data we have. The hash of the key usage is the key instance. We
            # should never reach here.
            return []
        else:
            # We do not pack `derivation_data` blobs for any other derivation type.
            return []

    def get_public_keys_for_derivation_path(self, derivation_path: DerivationPath) \
            -> List[PublicKey]:
        raise NotImplementedError

    def get_script_template_for_derivation(self, script_type: ScriptType,
            derivation_type: DerivationType, derivation_data2: Optional[bytes]) -> ScriptTemplate:
        raise NotImplementedError

    def get_possible_scripts_for_derivation(self, derivation_type: DerivationType,
            derivation_data2: Optional[bytes]) -> List[Tuple[ScriptType, Script]]:
        script_types = ACCOUNT_SCRIPT_TYPES.get(self.type())
        if script_types is None:
            raise UnsupportedAccountTypeError
        # NOTE(typing) Pylance does not know how to deal with abstract methods.
        return [
            (script_type,
                self.get_script_template_for_derivation(script_type, derivation_type,
                    derivation_data2).to_script())
            for script_type in script_types ]

    def get_script_for_derivation(self, script_type: ScriptType, derivation_type: DerivationType,
            derivation_data2: Optional[bytes]) -> Script:
        script_template = self.get_script_template_for_derivation(script_type, derivation_type,
            derivation_data2)
        # NOTE(typing) Pylance does not know how to deal with abstract methods.
        return script_template.to_script()

    def sign_transaction(self, tx: Transaction, password: str,
            context: Optional[TransactionContext]=None) \
                -> Optional[concurrent.futures.Future[None]]:
        if self.is_watching_only():
            return None

        tx_context = TransactionContext() if context is None else context

        # For hardware wallets annotate the outputs to the account's own keys for hardware wallets.
        # - Digitalbitbox makes use of all available output annotations.
        # - Keepkey and Trezor use this to annotate one arbitrary change address.
        # - Ledger kind of ignores it?
        signing_keystores = [ k for k in self.get_keystores() if k.can_sign(tx) ]
        if any([ k.type() == KeystoreType.HARDWARE for k in signing_keystores ]):
            tx_context.hardware_signing_metadata \
                = self._create_hardware_signing_metadata(tx, tx_context)

        # Called by the signing logic to ensure all the required data is present.
        # Should be called by the logic that serialises incomplete transactions to gather the
        # context for the next party.
        if self.requires_input_transactions():
            self.obtain_previous_transactions(tx, tx_context)

        for k in signing_keystores:
            try:
                k.sign_transaction(tx, password, tx_context)
            except UserCancelled:
                continue

        # Incomplete transactions are multi-signature transactions that have not passed the
        # required signature threshold. We do not currently store these until they are fully signed.
        if not tx.is_complete():
            return None

        tx_hash = tx.hash()
        tx_flags = TxFlags.STATE_SIGNED
        if tx_context.invoice_id:
            tx_flags |= TxFlags.PAYS_INVOICE

        def callback(callback_future: concurrent.futures.Future[None]) -> None:
            if callback_future.cancelled():
                return
            callback_future.result()

            # The transaction has to be in the database before we can refer to it in the
            # invoice.
            if tx_context.invoice_id:
                self._wallet.update_invoice_transactions(
                    [ (tx_hash, tx_context.invoice_id) ])

            if tx_context.description:
                self.set_transaction_label(tx_hash, tx_context.description)

        transaction_future = app_state.async_.spawn(self._wallet.add_local_transaction,
            tx_hash, tx, tx_flags)
        transaction_future.add_done_callback(callback)
        return transaction_future

    def _create_hardware_signing_metadata(self, tx: Transaction, context: TransactionContext) \
            -> List[HardwareSigningMetadata]:
        # add output info for hw wallets
        # the hw keystore at the time of signing does not have access to either the threshold
        # or the larger set of xpubs it's own mpk is included in. So we collect these in the
        # wallet at this point before proceeding to sign.
        tx_output: XTxOutput
        x_public_key: XPublicKey
        hardware_output_info: List[HardwareSigningMetadata] = []
        xpubs = self.get_master_public_keys()
        for tx_output in tx.outputs:
            output_items: Dict[bytes, Tuple[DerivationPath, Tuple[str], int]] = {}
            # NOTE(rt12) This should exclude all script types hardware wallets dont use.
            if tx_output.script_type == ScriptType.MULTISIG_BARE:
                context.hardware_signing_metadata.append(output_items)
                continue
            for x_public_key in tx_output.x_pubkeys:
                candidate_keystores = [ k for k in self.get_keystores()
                    if k.is_signature_candidate(x_public_key) ]
                if len(candidate_keystores) == 0:
                    continue
                pubkeys = self.get_public_keys_for_derivation_path(x_public_key.derivation_path)
                pubkeys_hex = [pubkey.to_hex() for pubkey in pubkeys]
                sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys_hex, xpubs)))
                item = (x_public_key.derivation_path, sorted_xpubs, self.get_threshold())
                output_items[candidate_keystores[0].get_fingerprint()] = item
            hardware_output_info.append(output_items)
        assert len(hardware_output_info) == len(tx.outputs)
        return hardware_output_info

    def obtain_previous_transactions(self, tx: Transaction, context: TransactionContext,
            update_cb: Optional[WaitingUpdateCallback]=None) -> None:
        # Called by the signing logic to ensure all the required data is present.
        # Should be called by the logic that serialises incomplete transactions to gather the
        # context for the next party.
        # Raises PreviousTransactionsMissingException
        need_tx_hashes: Set[bytes] = set()
        for txin in tx.inputs:
            txid = hash_to_hex_str(txin.prev_hash)
            prev_tx: Optional[Transaction] = context.parent_transactions.get(txin.prev_hash)
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
                context.parent_transactions[txin.prev_hash] = prev_tx
                if update_cb is not None:
                    update_cb(True, None)
        if need_tx_hashes:
            have_tx_hashes = set(context.parent_transactions)
            raise PreviousTransactionsMissingException(have_tx_hashes, need_tx_hashes)

    def _external_transaction_request(self, tx_hash: bytes) -> Optional[Transaction]:
        txid = hash_to_hex_str(tx_hash)
        if self._network is None:
            self._logger.debug("unable to fetch input transaction %s from network (offline)", txid)
            return None

        self._logger.debug("fetching input transaction %s from network", txid)
        try:
            tx_hex = cast(str,
                self._network.request_and_wait('blockchain.transaction.get', [ txid ]))
        except aiorpcx.jsonrpc.RPCError:
            self._logger.exception("failed retrieving transaction")
            return None
        else:
            # TODO(possibly) Once we've moved away from indexer state being authoritative
            # over the contents of a wallet, we should be able to add this to the
            # database as an non-owned input transaction. This isn't necessarily what we want
            # so we may want to make it an opt-in user option.
            return cast(Transaction, Transaction.from_hex(tx_hex))

    def extend_serialised_transaction(self, format: TxSerialisationFormat, tx: Transaction,
            context: TransactionContext, data: Dict[str, Any],
            update_cb: Optional[WaitingUpdateCallback]=None) -> Optional[Dict[str, Any]]:
        """
        Worker function that gathers the data required for serialised transactions.

        `update_cb` if provided is given as the last argument by `WaitingDialog` and `TxDialog`.
        """
        if format == TxSerialisationFormat.JSON_WITH_PROOFS:
            try:
                self.obtain_previous_transactions(tx, context, update_cb)
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
                data["prev_txs"] = [ ptx.to_hex() for ptx in context.parent_transactions.values() ]
        return data

    def get_fingerprint(self) -> bytes:
        raise NotImplementedError()

    def can_import_privkey(self) -> bool:
        return False

    def can_import_address(self) -> bool:
        return False

    def can_delete_key(self) -> bool:
        return False

    def sign_message(self, key_data: KeyDataTypes, message: bytes, password: str) -> bytes:
        raise NotImplementedError

    def decrypt_message(self, key_data: KeyDataTypes, message: bytes, password: str) -> bytes:
        raise NotImplementedError

    def is_watching_only(self) -> bool:
        raise NotImplementedError

    def is_gap_limit_observer(self) -> bool:
        return False

    def can_change_password(self) -> bool:
        raise NotImplementedError

    def can_spend(self) -> bool:
        # All accounts can at least construct unsigned transactions except for imported address
        # accounts.
        return True

    def get_masterkey_id(self) -> Optional[int]:
        raise NotImplementedError


class SimpleAccount(AbstractAccount):
    # wallet with a single keystore

    def is_watching_only(self) -> bool:
        return cast(KeyStore, self.get_keystore()).is_watching_only()

    def can_change_password(self) -> bool:
        return cast(KeyStore, self.get_keystore()).can_change_password()


class ImportedAccountBase(SimpleAccount):
    def get_masterkey_id(self) -> Optional[int]:
        return None

    def can_delete_key(self) -> bool:
        return True

    def has_seed(self) -> bool:
        return False

    def get_master_public_keys(self) -> List[str]:
        return []

    def get_fingerprint(self) -> bytes:
        return b''


class ImportedAddressAccount(ImportedAccountBase):
    # Watch-only wallet of imported addresses

    def type(self) -> AccountType:
        return AccountType.IMPORTED_ADDRESS

    def is_watching_only(self) -> bool:
        return True

    def can_spend(self) -> bool:
        return False

    def can_import_privkey(self) -> bool:
        return False

    def can_change_password(self) -> bool:
        return False

    def can_import_address(self) -> bool:
        return True

    def import_address(self, address: Address) -> bool:
        if isinstance(address, P2PKH_Address):
            derivation_type = DerivationType.PUBLIC_KEY_HASH
        elif isinstance(address, P2SH_Address):
            derivation_type = DerivationType.SCRIPT_HASH
        else:
            raise UnsupportedScriptTypeError()

        existing_keys = self._wallet.read_keyinstances_for_derivations(self._id, derivation_type,
            [ address.hash160() ])
        if len(existing_keys) == 0:
            return False

        def callback(future: concurrent.futures.Future[None]) -> None:
            if future.cancelled():
                return
            future.result()
            self.register_for_keyinstance_events(keyinstance_rows)

        derivation_data_dict: KeyInstanceDataHash = { "hash": address.to_string() }
        derivation_data = json.dumps(derivation_data_dict).encode()
        derivation_data2 = create_derivation_data2(derivation_type, derivation_data_dict)
        raw_keyinstance = KeyInstanceRow(-1, -1, None, derivation_type, derivation_data,
            derivation_data2, KeyInstanceFlag.ACTIVE | KeyInstanceFlag.USER_SET_ACTIVE, None)
        keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
            self.create_provided_keyinstances([ raw_keyinstance ])
        scripthash_future.add_done_callback(callback)
        return True

    def get_public_keys_for_derivation_path(self, derivation_path: DerivationPath) \
            -> List[PublicKey]:
        return [ ]

    def get_script_template_for_derivation(self, script_type: ScriptType,
            derivation_type: DerivationType, derivation_data2: Optional[bytes]) -> ScriptTemplate:
        if derivation_type == DerivationType.PUBLIC_KEY_HASH:
            assert script_type == ScriptType.P2PKH
            assert derivation_data2 is not None
            return P2PKH_Address(derivation_data2, Net.COIN)
        elif derivation_type == DerivationType.SCRIPT_HASH:
            assert script_type == ScriptType.MULTISIG_P2SH
            assert derivation_data2 is not None
            return P2SH_Address(derivation_data2, Net.COIN)
        else:
            raise NotImplementedError(f"derivation_type {derivation_type}")


class ImportedPrivkeyAccount(ImportedAccountBase):
    def __init__(self, wallet: 'Wallet', row: AccountRow) -> None:
        self._default_keystore = Imported_KeyStore()
        AbstractAccount.__init__(self, wallet, row)

    def type(self) -> AccountType:
        return AccountType.IMPORTED_PRIVATE_KEY

    def is_watching_only(self) -> bool:
        return False

    def can_import_privkey(self) -> bool:
        return True

    def can_change_password(self) -> bool:
        return True

    def can_import_address(self) -> bool:
        return False

    def set_initial_state(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        keystore = cast(Imported_KeyStore, self.get_keystore())
        keystore.set_state(keyinstance_rows)

    def import_private_key(self, private_key_text: str, password: str) -> str:
        public_key = PrivateKey.from_text(private_key_text).public_key
        keystore = cast(Imported_KeyStore, self.get_keystore())

        # Prevent re-importing existing entries.
        existing_keys = self._wallet.read_keyinstances_for_derivations(self._id,
            DerivationType.PRIVATE_KEY, [ public_key.to_bytes(compressed=True) ])
        if len(existing_keys) > 0:
            return private_key_text

        def callback(future: concurrent.futures.Future[None]) -> None:
            if future.cancelled():
                return
            future.result()
            self.register_for_keyinstance_events(keyinstance_rows)

        enc_private_key_text = pw_encode(private_key_text, password)
        derivation_data_dict: KeyInstanceDataPrivateKey = {
            "pub": public_key.to_hex(),
            "prv": enc_private_key_text,
        }
        derivation_data = json.dumps(derivation_data_dict).encode()
        derivation_data2 = create_derivation_data2(DerivationType.PRIVATE_KEY, derivation_data_dict)
        raw_keyinstance = KeyInstanceRow(-1, -1, None, DerivationType.PRIVATE_KEY, derivation_data,
            derivation_data2, KeyInstanceFlag.ACTIVE | KeyInstanceFlag.USER_SET_ACTIVE, None)
        keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
            self.create_provided_keyinstances([ raw_keyinstance ])
        scripthash_future.add_done_callback(callback)
        keystore.import_private_key(keyinstance_rows[0].keyinstance_id, public_key,
            enc_private_key_text)
        return private_key_text

    def export_private_key(self, keydata: KeyDataTypes, password: str) -> str:
        '''Returned in WIF format.'''
        keystore = cast(Imported_KeyStore, self.get_keystore())
        public_key = PublicKey.from_bytes(keydata.derivation_data2)
        return keystore.export_private_key(public_key, password)

    def sign_message(self, key_data: KeyDataTypes, message: bytes, password: str) -> bytes:
        assert key_data.derivation_data2 is not None
        public_key = PublicKey.from_bytes(key_data.derivation_data2)
        keystore = cast(Imported_KeyStore, self.get_keystore())
        return keystore.sign_message(public_key, message, password)

    def decrypt_message(self, key_data: KeyDataTypes, message: bytes, password: str) -> bytes:
        assert key_data.derivation_data2 is not None
        public_key = PublicKey.from_bytes(key_data.derivation_data2)
        keystore = cast(Imported_KeyStore, self.get_keystore())
        return keystore.decrypt_message(public_key, message, password)

    def get_xpubkeys_for_key_data(self, row: KeyDataTypes) -> List[XPublicKey]:
        data = DatabaseKeyDerivationData.from_key_data(row, DatabaseKeyDerivationType.SIGNING)
        return [ XPublicKey(pubkey_bytes=row.derivation_data2, derivation_data=data) ]

    def get_script_template_for_derivation(self, script_type: ScriptType,
            derivation_type: DerivationType, derivation_data2: Optional[bytes]) -> ScriptTemplate:
        public_key = self.get_public_keys_for_derivation(derivation_type, derivation_data2)[0]
        return self.get_script_template(public_key, script_type)


class DeterministicAccount(AbstractAccount):
    _subscription_owner_for_gap_limit: Optional[SubscriptionOwner] = None

    def __init__(self, wallet: 'Wallet', row: AccountRow) -> None:
        AbstractAccount.__init__(self, wallet, row)

        # TODO This should check if the gap limit observer functionality is active.
        #   This might be a column on the account row, not sure yet. If we decide not to go with
        #   the gap limit observer, then all this code should be removed.
        self._gap_limit_observer_enabled = False
        self._gap_limit_observer_future: Optional[concurrent.futures.Future[None]] = None

        # We do not just keep the last used derivation index for each derived path for gap limit
        # observation, we also keep them in order to make extending a sequence less race conditiony
        # with the database. This is because otherwise we need to both query the database for the
        # last derivation path in a sequence, and then write the new keys that use the extended
        # sequence before we can do more keys.
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        masterkey_id = keystore.get_id()
        # The gap limit observer needs to know what subpaths it needs to generate scripts along,
        # and if they were not otherwise in the database because there were no keys yet using them
        # then we need to have the defaults.
        self._derivation_sub_paths: Dict[int, List[Tuple[DerivationPath, int]]] = {
            masterkey_id: [
                (CHANGE_SUBPATH, -1),
                (RECEIVING_SUBPATH, -1),
            ]
        }

        for derivation_entry in wallet.read_keyinstance_derivation_indexes_last(self._id):
            masterkey_id, derivation_subpath_bytes, derivation_index_bytes = derivation_entry
            if masterkey_id not in self._derivation_sub_paths:
                self._derivation_sub_paths[masterkey_id] = []
            derivation_subpath = unpack_derivation_path(derivation_subpath_bytes)
            derivation_index = unpack_derivation_path(derivation_index_bytes)[0]
            new_entry = (derivation_subpath, derivation_index)
            for i, (entry_subpath, entry_index) in \
                    enumerate(self._derivation_sub_paths[masterkey_id]):
                if entry_subpath == derivation_subpath:
                    self._derivation_sub_paths[masterkey_id][i] = new_entry
                    break
            else:
                self._derivation_sub_paths[masterkey_id].append(new_entry)

    def is_gap_limit_observer(self) -> bool:
        return True

    def get_masterkey_id(self) -> Optional[int]:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        return keystore.get_id()

    def has_seed(self) -> bool:
        return cast(Deterministic_KeyStore, self.get_keystore()).has_seed()

    def start(self, network: Optional["Network"]) -> None:
        super().start(network)
        if self._network is not None and self._gap_limit_observer_enabled:
            self._subscription_owner_for_gap_limit = SubscriptionOwner(self._wallet._id, self._id,
                SubscriptionOwnerPurpose.GAP_LIMIT_OBSERVER)
            self._gap_limit_observer_future = app_state.async_.spawn(
                self._bip32_gap_limit_observer_async)

    def stop(self) -> None:
        network = self._network
        super().stop()
        if network is not None and self._gap_limit_observer_future is not None:
            self._gap_limit_observer_future.cancel()
            assert self._subscription_owner_for_gap_limit is not None
            # Unsubscribe from the account's existing subscriptions.
            future = network.subscriptions.remove_owner(self._subscription_owner_for_gap_limit)
            if future is not None:
                future.result()

    def sign_message(self, key_data: KeyDataTypes, message: bytes, password: str) -> bytes:
        assert key_data.derivation_data2 is not None
        derivation_path = unpack_derivation_path(key_data.derivation_data2)
        keystore = cast(SignableKeystoreTypes, self.get_keystore())
        return keystore.sign_message(derivation_path, message, password)

    def decrypt_message(self, key_data: KeyDataTypes, message: bytes, password: str) -> bytes:
        assert key_data.derivation_data2 is not None
        derivation_path = unpack_derivation_path(key_data.derivation_data2)
        keystore = cast(BIP32_KeyStore, self.get_keystore())
        return keystore.decrypt_message(derivation_path, message, password)

    def notify_key_allocation_creation_or_something(self) -> None:
        # asyncio Event objects are not thread-safe. This is the recommended way of calling their
        # methods in a thread-safe way.
        app_state.async_.loop.call_soon_threadsafe(self._gap_limit_observer_event_async.set)

    async def _bip32_gap_limit_observer_async(self) -> None:
        """
        This worker task is notified of changing key sequences and extends their "gap limit".

        No keys are created for this, rather registrations are made for the expected key uses
        in the derivation sequence. We monitor all possible key usage for the account, not just
        unused keys primarily because we do not want to handle creation of keys out of order.

        TODO:
        1. DONE Write a database function that returns all the existing derivation subpaths for
           the account and their latest sequence.
        2. DONE Update AbstractAccount to read them in when it is loaded.
        3. DONE Deterministic key creation should use the latest sequence entry to pick new
           sequences to allocate.
        4. Any time there is an allocation the `gap_limit_observer_event_async` event should
           be set.
            - Do we want it to be the allocation, or the full creation of a key so that we are
              not getting events before the key is created in the most extreme interpretation of
              correctness.
        5. DONE This would go through all the derivation subpaths and work out what
           scripts to subscribe to. For a start it would need to subscribe to all keys.
            a) Have a local cache of which derivation paths are currently monitored.
            b) Each loop look at the gap size of each derivation path.
            c) Extend the registrations.
        6. DONE It should be possible to start up and shut down the gap limit observer.
        7. The notifications need to be processed.
            - It might be that we have to disable the key and transaction subscriptions if the
              gap limit observer is active, and have it do full management.
            - Otherwise we have to map out the model and make sure all subscription mechanics
              work well together.
        """
        assert self._network is not None
        assert self._subscription_owner_for_gap_limit is not None

        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        masterkey_id = keystore.get_id()

        # Create the registrations for the existing keys.
        derivation_type_datas: List[SubscriptionDerivationData] = []
        for masterkey_id, derivation_entries in self._derivation_sub_paths.items():
            for derivation_subpath, last_derivation_index in derivation_entries:
                derivation_type_datas.extend(self._get_derivation_type_datas(masterkey_id,
                    derivation_subpath, 0, last_derivation_index+1))

        self._network.subscriptions.create_entries(
            self._get_subscription_entries_for_derivations(derivation_type_datas),
            self._subscription_owner_for_gap_limit)

        self._gap_limit_observer_event_async.set()
        while True:
            await self._gap_limit_observer_event_async.wait()
            self._gap_limit_observer_event_async.clear()

            batched_derivation_type_datas: List[SubscriptionDerivationData] = []
            for masterkey_id, derivation_entries in self._derivation_sub_paths.items():
                for derivation_subpath, last_derivation_index in derivation_entries:
                    # Race conditions may make this inaccurate, but any event that may move the
                    # gap should also set the event and cause reprocessing.
                    path_prefix = pack_derivation_path(derivation_subpath)
                    gap_size = self._wallet.read_bip32_keys_gap_size(self._id, masterkey_id,
                        path_prefix)
                    if derivation_subpath == RECEIVING_SUBPATH:
                        desired_gap_size = 20
                    else:
                        desired_gap_size = 10
                    required_gap_size = desired_gap_size - gap_size
                    if required_gap_size <= 0:
                        self._logger.debug(
                            "gap limit observer, nothing to do account_id=%d derivation_subpath=%s",
                            self._id, derivation_subpath)
                        continue

                    derivation_type_datas = self._get_derivation_type_datas(masterkey_id,
                        derivation_subpath, last_derivation_index + 1,
                        last_derivation_index + required_gap_size)
                    batched_derivation_type_datas.extend(derivation_type_datas)
                    self._logger.debug("gap limit observer  account_id=%d derivation_subpath=%s, "
                        "extension_size=%d",
                        self._id, derivation_subpath, required_gap_size)

            self._network.subscriptions.create_entries(
                self._get_subscription_entries_for_derivations(batched_derivation_type_datas),
                self._subscription_owner_for_gap_limit)

    def _get_derivation_type_datas(self, masterkey_id: Optional[int],
            derivation_subpath: DerivationPath, first_derivation_index: int,
            last_derivation_index: int) \
                -> List[SubscriptionDerivationData]:
        """
        First step in gathering subscription entries for gap limit subscriptions.
        """
        derivation_type_datas: List[SubscriptionDerivationData] = []
        for i in range(first_derivation_index, last_derivation_index+1):
            derivation_data2 = pack_derivation_path(derivation_subpath + (i,))
            derivation_type_data = SubscriptionDerivationData(masterkey_id,
                DerivationType.BIP32_SUBPATH, derivation_data2)
            derivation_type_datas.append(derivation_type_data)
        return derivation_type_datas

    def _get_subscription_entries_for_derivations(self,
            derivation_type_datas: List[SubscriptionDerivationData]) -> List[SubscriptionEntry]:
        """
        Second step in gathering subscription entries for gap limit subscriptions.
        """
        entries: List[SubscriptionEntry] = []
        for derivation_type_data in derivation_type_datas:
            for script_type, script in self.get_possible_scripts_for_derivation(
                    derivation_type_data.derivation_type, derivation_type_data.derivation_data2):
                script_hash = scripthash_bytes(script)
                entries.append(
                    SubscriptionEntry(
                        SubscriptionKey(SubscriptionType.SCRIPT_HASH, script_hash),
                        SubscriptionDerivationScriptHashOwnerContext(derivation_type_data,
                            script_type)))
        return entries

    def get_next_derivation_index(self, derivation_subpath: DerivationPath) -> int:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        derivation_entries = self._derivation_sub_paths.get(keystore.get_id(), [])
        for this_derivation_subpath, last_derivation_index in derivation_entries:
            if derivation_subpath == this_derivation_subpath:
                next_index = last_derivation_index + 1
                break
        else:
            next_index = 0
        return next_index

    def allocate_keys(self, count: int, derivation_subpath: DerivationPath,
            expected_next_index: int=-1) -> Sequence[KeyAllocation]:
        """
        Produce an annotated sequence of each key that should be created.

        This should include the derivation type and the derivation context of each individual key.
        """
        if count <= 0:
            return []

        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        derivation_entries = self._derivation_sub_paths.setdefault(keystore.get_id(), [])
        for i, (this_derivation_subpath, last_derivation_index) in enumerate(derivation_entries):
            if derivation_subpath == this_derivation_subpath:
                next_index = last_derivation_index + 1
                assert expected_next_index == -1 or next_index == expected_next_index
                derivation_entries[i] = (derivation_subpath, last_derivation_index + count)
                break
        else:
            next_index = 0
            derivation_entries.append((derivation_subpath, count-1))
            assert expected_next_index == -1 or expected_next_index == next_index
        self._logger.info(f"creating {count} new keys within {derivation_subpath} "
            f"next_index={next_index}")
        masterkey_id = keystore.get_id()
        return tuple(KeyAllocation(masterkey_id, DerivationType.BIP32_SUBPATH,
            tuple(derivation_subpath) + (i,)) for i in range(next_index, next_index + count))

    def reserve_unassigned_key(self, derivation_subpath: DerivationPath, flags: KeyInstanceFlag) \
            -> int:
        """
        Reserve the first available unused key from the given derivation path.

        If there are no existing keys available, then it creates new keys and uses one of those.

        Callers should not set `ACTIVE` unless there is a reason we should be watching for
        transactions using this key via an indexer. And the calling system should be responsible
        for ensuring that the `ACTIVE` flag is removed, when the user no longer wants to
        monitor the key (directly or indirectly).
        """
        # It is expected that a caller will have a flag that is sufficient to indicate the reasons
        # it is in use/reserved. The calling system is expected at this stage to clear this flag
        # when they are done using the key.
        assert flags & KeyInstanceFlag.MASK_RESERVATION != 0

        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        masterkey_id = keystore.get_id()
        future: Optional[concurrent.futures.Future[Tuple[int, KeyInstanceFlag]]] \
            = self._wallet.reserve_keyinstance(self._id, masterkey_id, derivation_subpath, flags)
        assert future is not None
        try:
            keyinstance_id, final_flags = future.result()
        except KeyInstanceNotFoundError:
            keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
                self.allocate_and_create_keys(1, derivation_subpath, flags | KeyInstanceFlag.USED)
            assert scripthash_future is not None
            keyinstance_id = keyinstance_rows[0].keyinstance_id
            final_flags = keyinstance_rows[0].flags
            scripthash_future.result()

        self._wallet.trigger_callback('keys_updated', self._id, [ keyinstance_id ])

        if final_flags & KeyInstanceFlag.ACTIVE and self._network is not None:
            # NOTE(ActivitySubscription) This represents a key that was not previously active
            #   becoming active and requiring a subscription for events.
            self._network.subscriptions.create_entries(
                self._get_subscription_entries_for_keyinstance_ids([ keyinstance_id ]),
                    self._subscription_owner_for_keys)
        return keyinstance_id

    def derive_new_keys_until(self, derivation_path: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> Tuple[Optional[concurrent.futures.Future[None]], List[KeyInstanceRow]]:
        """
        Ensure that keys are created up to and including the given derivation path.

        This will look at the existing keys and create any further keys if necessary. It only
        returns the newly created keys, which is probably useless and only used in the unit
        tests.
        """
        derivation_subpath = derivation_path[:-1]
        final_index = derivation_path[-1]
        self._value_locks.acquire_lock(derivation_subpath)
        try:
            next_index = self.get_next_derivation_index(derivation_subpath)
            required_count = (final_index - next_index) + 1
            if required_count < 1:
                return None, []

            self._logger.debug("derive_new_keys_until path=%s index=%d count=%d",
                derivation_subpath, final_index, required_count)

            # Identify the metadata for each key that is to be created.
            key_allocations = self.allocate_keys(required_count, derivation_subpath)
            if not key_allocations:
                return None, []
        finally:
            self._value_locks.release_lock(derivation_subpath)

        keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
            self.create_preallocated_keys(key_allocations, keyinstance_flags)
        return scripthash_future, keyinstance_rows

    def allocate_and_create_keys(self, count: int, derivation_subpath: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> Tuple[Optional[concurrent.futures.Future[None]],
                        Optional[concurrent.futures.Future[None]],
                        List[KeyInstanceRow], List[KeyInstanceScriptHashRow]]:
        self._value_locks.acquire_lock(derivation_subpath)
        try:
            # Identify the metadata for each key that is to be created.
            key_allocations = self.allocate_keys(count, derivation_subpath)
            if not key_allocations:
                return None, None, [], []
        finally:
            self._value_locks.release_lock(derivation_subpath)

        keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
            self.create_preallocated_keys(key_allocations, keyinstance_flags)
        scripthash_future.result()
        return keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows

    # Returns ordered from use first to use last.
    def get_fresh_keys(self, derivation_parent: DerivationPath, count: int) -> List[KeyInstanceRow]:
        fresh_keys = self.get_existing_fresh_keys(derivation_parent, count)
        if len(fresh_keys) < count:
            required_count = count - len(fresh_keys)
            keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
                self.allocate_and_create_keys(required_count, derivation_parent)
            # TODO Reconcile whether we can return the future instead of blocking here.
            if scripthash_future is not None:
                scripthash_future.result()
            # Preserve oldest to newest ordering.
            fresh_keys += keyinstance_rows
            assert len(fresh_keys) == count
        return fresh_keys

    # Returns ordered from use first to use last.
    def get_existing_fresh_keys(self, derivation_parent: DerivationPath, limit: int) \
            -> List[KeyInstanceRow]:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        masterkey_id = keystore.get_id()
        return self._wallet.read_bip32_keys_unused(self._id, masterkey_id, derivation_parent,
            limit)

    def get_master_public_keys(self) -> List[str]:
        mpk = self.get_master_public_key()
        assert mpk is not None
        return [ mpk ]

    def get_fingerprint(self) -> bytes:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        return keystore.get_fingerprint()


class SimpleDeterministicAccount(SimpleAccount, DeterministicAccount):
    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, wallet: 'Wallet', row: AccountRow) -> None:
        DeterministicAccount.__init__(self, wallet, row)

    def get_master_public_key(self) -> str:
        keystore = cast(StandardKeystoreTypes, self.get_keystore())
        return cast(str, keystore.get_master_public_key())

    def get_public_keys_for_derivation_path(self, derivation_path: DerivationPath) \
            -> List[PublicKey]:
        xpub_keystore = cast(Xpub, self.get_keystore())
        return [ xpub_keystore.derive_pubkey(derivation_path) ]

    def get_script_template_for_derivation(self, script_type: ScriptType,
            derivation_type: DerivationType, derivation_data2: Optional[bytes]) -> ScriptTemplate:
        assert derivation_type == DerivationType.BIP32_SUBPATH
        assert derivation_data2 is not None
        derivation_path = unpack_derivation_path(derivation_data2)
        xpub_keystore = cast(Xpub, self.get_keystore())
        public_key = xpub_keystore.derive_pubkey(derivation_path)
        return self.get_script_template(public_key, script_type)

    def get_xpubkeys_for_key_data(self, row: KeyDataTypes) -> List[XPublicKey]:
        data = DatabaseKeyDerivationData.from_key_data(row, DatabaseKeyDerivationType.SIGNING)
        keystore = cast(KeyStore, self.get_keystore())
        if keystore.type() == KeystoreType.OLD:
            return [ cast(Old_KeyStore, keystore).get_xpubkey(data) ]
        return [ cast(Xpub, keystore).get_xpubkey(data) ]

    def derive_pubkeys(self, derivation_path: DerivationPath) -> PublicKey:
        keystore = cast(KeyStore, self.get_keystore())
        if keystore.type() == KeystoreType.OLD:
            return cast(Old_KeyStore, keystore).derive_pubkey(derivation_path)
        return cast(Xpub, keystore).derive_pubkey(derivation_path)

    def derive_script_template(self, derivation_path: DerivationPath,
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        return self.get_script_template(self.derive_pubkeys(derivation_path), script_type)



class StandardAccount(SimpleDeterministicAccount):
    def type(self) -> AccountType:
        return AccountType.STANDARD


class MultisigAccount(DeterministicAccount):
    def __init__(self, wallet: 'Wallet', row: AccountRow) -> None:
        self._multisig_keystore = cast(Multisig_KeyStore,
            wallet.get_keystore(cast(int, row.default_masterkey_id)))
        self.m = self._multisig_keystore.m
        self.n = self._multisig_keystore.n

        DeterministicAccount.__init__(self, wallet, row)

    def type(self) -> AccountType:
        return AccountType.MULTISIG

    def get_threshold(self) -> int:
        return self.m

    def get_public_keys_for_derivation_path(self, derivation_path: DerivationPath) \
            -> List[PublicKey]:
        return [ keystore.derive_pubkey(derivation_path) for keystore in self.get_keystores() ]

    def get_possible_scripts_for_key_data(self, keydata: KeyDataTypes) \
            -> List[Tuple[ScriptType, Script]]:
        public_keys = self.get_public_keys_for_derivation(
            cast(DerivationType, keydata.derivation_type), keydata.derivation_data2)
        public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
        return [
            (script_type, self.get_script_template(public_keys_hex, script_type).to_script())
            for script_type in ACCOUNT_SCRIPT_TYPES[AccountType.MULTISIG]
        ]

    def get_script_template_for_derivation(self, script_type: ScriptType,
            derivation_type: DerivationType, derivation_data2: Optional[bytes]) -> ScriptTemplate:
        public_keys = self.get_public_keys_for_derivation(derivation_type, derivation_data2)
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

    def derive_pubkeys(self, derivation_path: DerivationPath) -> List[PublicKey]:
        return [ k.derive_pubkey(derivation_path) for k in self.get_keystores() ]

    def derive_script_template(self, derivation_path: DerivationPath,
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        public_keys_hex = [pubkey.to_hex() for pubkey in self.derive_pubkeys(derivation_path)]
        return self.get_script_template(public_keys_hex, script_type)

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

    def get_master_public_keys(self) -> List[str]:
        return cast(List[str], [ k.get_master_public_key() for k in self.get_keystores()])

    def get_fingerprint(self) -> bytes:
        # Sort the fingerprints in the same order as their master public keys.
        mpks = self.get_master_public_keys()
        fingerprints = [ k.get_fingerprint() for k in self.get_keystores() ]
        _sorted_mpks, sorted_fingerprints = zip(*sorted(zip(mpks, fingerprints)))
        return b''.join(cast(Sequence[bytes], sorted_fingerprints))

    def get_xpubkeys_for_key_data(self, row: KeyDataTypes) -> List[XPublicKey]:
        data = DatabaseKeyDerivationData.from_key_data(row, DatabaseKeyDerivationType.SIGNING)
        x_pubkeys = [ k.get_xpubkey(data) for k in self.get_keystores() ]
        # Sort them using the order of the realized pubkeys
        sorted_pairs = sorted((x_pubkey.to_public_key().to_hex(), x_pubkey)
            for x_pubkey in x_pubkeys)
        return [x_pubkey for _hex, x_pubkey in sorted_pairs]


class Wallet(TriggeredCallbacks):
    _network: Optional['Network'] = None
    _stopped: bool = False

    def __init__(self, storage: WalletStorage, password: Optional[str]=None) -> None:
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
        self._missing_transactions: Dict[bytes, MissingTransactionEntry] = {}

        # Guards `transaction_locks`.
        self._transaction_lock = threading.RLock()
        # Guards per-transaction locks to limit blocking to per-transaction activity.
        self._transaction_locks: Dict[bytes, Tuple[threading.RLock, int]] = {}

        # Guards the obtaining and processing of missing transactions from race conditions.
        self._obtain_transactions_async_lock = app_state.async_.lock()
        self._obtain_proofs_async_lock = app_state.async_.lock()

        self.load_state()

        self.contacts = Contacts(self._storage)

        self.txs_changed_event = app_state.async_.event()
        self.progress_event = app_state.async_.event()
        self.request_count = 0
        self.response_count = 0

        # When ElectrumSV is asked to open a wallet it first requests the password and verifies
        # it is correct for the wallet. Then it does the separate open operation and did not
        # require the password. However, we have since added encrypted wallet data that needs
        # to be read and cached. We expect the password to still be in the credential cache
        # given we just did that verification.
        if password is None:
            password = app_state.credentials.get_wallet_password(self._storage.get_path())
            assert password is not None, "Expected cached wallet password"

        # Cache the stuff that is needed unencrypted but is encrypted.
        self._registered_api_keys: Dict[ServerAccountKey, IndefiniteCredentialId] = {}
        server_rows, server_account_rows = self.read_network_servers()
        for server_row in server_rows:
            if server_row.encrypted_api_key is not None:
                server_key = ServerAccountKey(server_row.url, server_row.server_type, -1)
                self._registered_api_keys[server_key] = \
                    app_state.credentials.add_indefinite_credential(
                        pw_decode(server_row.encrypted_api_key, password))

        for account_row in server_account_rows:
            if account_row.encrypted_api_key is not None:
                server_key = ServerAccountKey(account_row.url, account_row.server_type,
                    account_row.account_id)
                self._registered_api_keys[server_key] = \
                    app_state.credentials.add_indefinite_credential(
                        pw_decode(account_row.encrypted_api_key, password))

    def __str__(self) -> str:
        return f"wallet(path='{self._storage.get_path()}')"

    def get_id(self) -> int:
        return self._id

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

        masterkey_rows = db_functions.read_masterkeys(self.get_db_context())
        # Create the keystores for masterkeys without parent masterkeys first.
        for mk_row in sorted(masterkey_rows,
                key=lambda t: 0 if t.parent_masterkey_id is None else t.parent_masterkey_id):
            self._realize_keystore(mk_row)

        account_flags: Dict[int, AccountInstantiationFlags] = \
            defaultdict(lambda: AccountInstantiationFlags.NONE)
        keyinstances_by_account_id: Dict[int, List[KeyInstanceRow]] = {}
        # TODO Avoid reading in all the keyinstances we are not interested in.
        for keyinstance_row in self.read_keyinstances():
            if keyinstance_row.derivation_type == DerivationType.PRIVATE_KEY:
                if keyinstance_row.account_id not in keyinstances_by_account_id:
                    account_flags[keyinstance_row.account_id] |= \
                        AccountInstantiationFlags.IMPORTED_PRIVATE_KEYS
                    keyinstances_by_account_id[keyinstance_row.account_id] = []
                keyinstances_by_account_id[keyinstance_row.account_id].append(keyinstance_row)
            elif keyinstance_row.derivation_type in ADDRESS_TYPES:
                account_flags[keyinstance_row.account_id] |= \
                    AccountInstantiationFlags.IMPORTED_ADDRESSES

        for account_row in db_functions.read_accounts(self.get_db_context()):
            account = self._instantiate_account(account_row, account_flags[account_row.account_id])
            if account.type() == AccountType.IMPORTED_PRIVATE_KEY:
                keyinstance_rows = keyinstances_by_account_id[account_row.account_id]
                assert keyinstance_rows
                cast(ImportedPrivkeyAccount, account).set_initial_state(keyinstance_rows)

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

    def update_password(self, old_password: str, new_password: str) \
            -> concurrent.futures.Future[PasswordUpdateResult]:
        """
        Update the wallet password and use it to re-encrypt all the values encrypted with the old.

        Before all the re-encryptions happened to unknown data in different places. Now they
        almost all happpen here. The one exception is the tracked encrypted API keys in the
        network.

        NOTE The whole network API key thing is awkward and tied to the encrypted values, if we
        decoupled it from that and instead used a deterministic key for each piece of data, we
        would not need to ...
        """
        assert old_password, "wallet migration should have added a password"
        assert new_password, "calling code must provide the new password"

        def update_cached_values(callback_future: concurrent.futures.Future[PasswordUpdateResult]) \
                -> None:
            if callback_future.cancelled():
                return
            result = callback_future.result()
            # Update the cached wallet setting without doing the usual db write.
            self._storage.put("password-token", result.password_token, already_persisted=True)

            # Update the encrypted private keys for the new password. Remember that the private
            # key keystore is not known to the wallet, as it is not a masterkey in the database and
            # is created by the account.
            for account_id, new_encrypted_keys in result.account_private_key_updates.items():
                account = cast(ImportedPrivkeyAccount, self._accounts[account_id])
                imported_keystore = cast(Imported_KeyStore, account.get_keystore())
                for keyinstance_id, encrypted_prv in new_encrypted_keys:
                    imported_keystore.set_encrypted_prv(keyinstance_id, encrypted_prv)

            # Update all the keystore encrypted derivation data fields.
            keystore_by_masterkey_id = { keystore_id: keystore for keystore_id, keystore
                in self._keystores.items() if keystore.can_change_password() }

            def set_encrypted_values(derivation_type: DerivationType,
                    derivation_data: MasterKeyDataTypes, keystore: KeyStore) -> None:
                if derivation_type == DerivationType.BIP32:
                    bip32_data = cast(MasterKeyDataBIP32, derivation_data)
                    bip32_keystore = cast(BIP32_KeyStore, keystore)
                    if bip32_data["seed"] is not None:
                        bip32_keystore.set_encrypted_seed(bip32_data["seed"])
                    if bip32_data["passphrase"] is not None:
                        bip32_keystore.set_encrypted_passphrase(bip32_data["passphrase"])
                    if bip32_data["xprv"] is not None:
                        bip32_keystore.set_encrypted_xprv(bip32_data["xprv"])
                elif derivation_type == DerivationType.ELECTRUM_OLD:
                    old_data = cast(MasterKeyDataElectrumOld, derivation_data)
                    old_keystore = cast(Old_KeyStore, keystore)
                    if old_data["seed"] is not None:
                        old_keystore.set_encrypted_seed(old_data["seed"])

            for masterkey_id, derivation_type, derivation_data in result.masterkey_updates:
                keystore = keystore_by_masterkey_id[masterkey_id]
                if derivation_type == DerivationType.ELECTRUM_MULTISIG:
                    multisig_data = cast(MasterKeyDataMultiSignature, derivation_data)
                    multisig_keystore = cast(Multisig_KeyStore, keystore)
                    cosigner_keystores = multisig_keystore.get_cosigner_keystores()
                    assert len(cosigner_keystores) == len(multisig_data["cosigner-keys"])
                    for i, (cosigner_derivation_type, cosigner_data) in \
                            enumerate(multisig_data["cosigner-keys"]):
                        cosigner_keystore = cosigner_keystores[i]
                        set_encrypted_values(cosigner_derivation_type, cosigner_data,
                            cosigner_keystore)
                else:
                    set_encrypted_values(derivation_type, derivation_data, keystore)

        future = db_functions.update_password(self.get_db_context(), old_password, new_password)
        future.add_done_callback(update_cached_values)
        return future

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
        data = cast(MasterKeyDataTypes, json.loads(row.derivation_data))
        parent_keystore: Optional[KeyStore] = None
        if row.parent_masterkey_id is not None:
            parent_keystore = self._keystores[row.parent_masterkey_id]
        keystore = instantiate_keystore(row.derivation_type, data, parent_keystore, row)
        self._keystores[row.masterkey_id] = keystore
        self._masterkey_rows[row.masterkey_id] = row

    def _instantiate_account(self, account_row: AccountRow, flags: AccountInstantiationFlags) \
            -> AbstractAccount:
        """
        Create the correct account type instance and register it for the given account id.
        """
        account: Optional[AbstractAccount] = None
        if account_row.default_masterkey_id is None:
            if flags & AccountInstantiationFlags.IMPORTED_ADDRESSES:
                account = ImportedAddressAccount(self, account_row)
            elif flags & AccountInstantiationFlags.IMPORTED_PRIVATE_KEYS:
                account = ImportedPrivkeyAccount(self, account_row)
            else:
                raise WalletLoadError(_("unknown imported account type"))
        else:
            masterkey_row = self._masterkey_rows[account_row.default_masterkey_id]
            if masterkey_row.derivation_type == DerivationType.BIP32:
                account = StandardAccount(self, account_row)
            elif masterkey_row.derivation_type == DerivationType.BIP32_SUBPATH:
                account = StandardAccount(self, account_row)
            elif masterkey_row.derivation_type == DerivationType.ELECTRUM_OLD:
                account = StandardAccount(self, account_row)
            elif masterkey_row.derivation_type == DerivationType.ELECTRUM_MULTISIG:
                account = MultisigAccount(self, account_row)
            elif masterkey_row.derivation_type == DerivationType.HARDWARE:
                account = StandardAccount(self, account_row)
            else:
                raise WalletLoadError(_("unknown account type %d"), masterkey_row.derivation_type)
        assert account is not None
        self.register_account(account_row.account_id, account)
        return account

    def _create_account_from_data(self, account_row: AccountRow, flags: AccountInstantiationFlags) \
            -> AbstractAccount:
        account = self._instantiate_account(account_row, flags)

        # NOTE(wallet-event-race-condition) For now we block creating this as we want the
        #   main window to be able to find it present, to display on new account creation.
        future = self.create_wallet_events([
            WalletEventRow(0, WalletEventType.SEED_BACKUP_REMINDER, account_row.account_id,
                WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, get_posix_timestamp())
        ])
        future.result()

        self.trigger_callback("account_created", account_row.account_id, flags)
        if self._network is not None:
            account.start(self._network)
        return account

    def read_history_list(self, account_id: int, keyinstance_ids: Optional[Sequence[int]]=None) \
            -> List[HistoryListRow]:
        return db_functions.read_history_list(self.get_db_context(), account_id, keyinstance_ids)

    def read_bip32_keys_unused(self, account_id: int, masterkey_id: int,
            derivation_path: DerivationPath, limit: int) -> List[KeyInstanceRow]:
        return db_functions.read_bip32_keys_unused(self.get_db_context(), account_id, masterkey_id,
            derivation_path, limit)

    def read_keyinstance_derivation_indexes_last(self, account_id: int) \
            -> List[Tuple[int, bytes, bytes]]:
        return db_functions.read_keyinstance_derivation_indexes_last(self.get_db_context(),
            account_id)

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

    def create_account_from_keystore(self, creation_type: AccountCreationType, keystore: KeyStore) \
            -> AbstractAccount:
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

        creation_flags = AccountInstantiationFlags.NONE
        if creation_type == AccountCreationType.NEW:
            creation_flags |= AccountInstantiationFlags.NEW

        basic_row = AccountRow(-1, masterkey_row.masterkey_id, script_type, account_name)
        rows = self.add_accounts([ basic_row ])
        return self._create_account_from_data(rows[0], creation_flags)

    def create_account_from_text_entries(self, text_type: KeystoreTextType,
            entries: Set[str], password: str) -> AbstractAccount:
        raw_keyinstance_rows: List[KeyInstanceRow] = []

        account_name: Optional[str] = None
        account_flags: AccountInstantiationFlags
        if text_type == KeystoreTextType.ADDRESSES:
            account_name = "Imported addresses"
            account_flags = AccountInstantiationFlags.IMPORTED_ADDRESSES
        elif text_type == KeystoreTextType.PRIVATE_KEYS:
            account_name = "Imported private keys"
            account_flags = AccountInstantiationFlags.IMPORTED_PRIVATE_KEYS
        else:
            raise WalletLoadError(f"Unhandled text type {text_type}")

        script_type = ScriptType.P2PKH
        if text_type == KeystoreTextType.ADDRESSES:
            # NOTE(P2SHNotImportable) see the account wizard for why this does not get P2SH ones.
            #   If we do support it, which would require the ability to mint those transactions on
            #   regtest, we would set the script_type here to `ScriptType.P2SH`.
            for address_string in entries:
                derivation_data_hash: KeyInstanceDataHash = { "hash": address_string }
                derivation_data = json.dumps(derivation_data_hash).encode()
                raw_keyinstance_rows.append(KeyInstanceRow(-1, -1,
                    None, DerivationType.PUBLIC_KEY_HASH, derivation_data,
                    create_derivation_data2(DerivationType.PUBLIC_KEY_HASH, derivation_data_hash),
                    KeyInstanceFlag.ACTIVE | KeyInstanceFlag.USER_SET_ACTIVE, None))
        elif text_type == KeystoreTextType.PRIVATE_KEYS:
            for private_key_text in entries:
                private_key = PrivateKey.from_text(private_key_text)
                pubkey_hex = private_key.public_key.to_hex()
                derivation_data_dict: KeyInstanceDataPrivateKey = {
                    "pub": pubkey_hex,
                    "prv": pw_encode(private_key_text, password),
                }
                derivation_data = json.dumps(derivation_data_dict).encode()
                raw_keyinstance_rows.append(KeyInstanceRow(-1, -1,
                    None, DerivationType.PRIVATE_KEY, derivation_data,
                    create_derivation_data2(DerivationType.PRIVATE_KEY, derivation_data_dict),
                    KeyInstanceFlag.ACTIVE | KeyInstanceFlag.USER_SET_ACTIVE, None))

        basic_account_row = AccountRow(-1, None, script_type, account_name)
        account_row = self.add_accounts([ basic_account_row ])[0]
        account = self._create_account_from_data(account_row, account_flags)

        def callback(future: concurrent.futures.Future[None]) -> None:
            if future.cancelled():
                return
            future.result()
            account.register_for_keyinstance_events(keyinstance_rows)

        keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
            account.create_provided_keyinstances(raw_keyinstance_rows)
        scripthash_future.add_done_callback(callback)

        if account.type() == AccountType.IMPORTED_PRIVATE_KEY:
            cast(ImportedPrivkeyAccount, account).set_initial_state(keyinstance_rows)

        return account

    def read_account_balance(self, account_id: int, local_height: int,
            txo_flags: TransactionOutputFlag=TransactionOutputFlag.NONE,
            txo_mask: TransactionOutputFlag=TransactionOutputFlag.SPENT,
            exclude_frozen: bool=True) -> WalletBalance:
        return db_functions.read_account_balance(self.get_db_context(),
            account_id, local_height, txo_flags, txo_mask)

    def update_account_names(self, entries: Iterable[Tuple[str, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_account_names(self.get_db_context(), entries)

    def update_account_script_types(self, entries: Iterable[Tuple[ScriptType, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_account_script_types(self.get_db_context(), entries)

    # Account transactions.

    def read_transaction_descriptions(self, account_id: Optional[int]=None,
            tx_hashes: Optional[Sequence[bytes]]=None) -> List[AccountTransactionDescriptionRow]:
        return db_functions.read_transaction_descriptions(self.get_db_context(),
            account_id, tx_hashes)

    def update_account_transaction_descriptions(self,
            entries: Iterable[Tuple[Optional[str], int, bytes]]) -> concurrent.futures.Future[None]:
        return db_functions.update_account_transaction_descriptions(self.get_db_context(),
            entries)

    # Invoices.

    def create_invoices(self, entries: Iterable[InvoiceRow]) -> concurrent.futures.Future[None]:
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
            -> concurrent.futures.Future[None]:
        return db_functions.update_invoice_transactions(self.get_db_context(), entries)

    def update_invoice_descriptions(self, entries: Iterable[Tuple[Optional[str], int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_invoice_descriptions(self.get_db_context(), entries)

    def update_invoice_flags(self, entries: Iterable[Tuple[PaymentFlag, PaymentFlag, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_invoice_flags(self.get_db_context(), entries)

    def delete_invoices(self, entries: Iterable[Tuple[int]]) -> concurrent.futures.Future[None]:
        return db_functions.delete_invoices(self.get_db_context(), entries)

    # Key instances.

    def create_keyinstances(self, account_id: int, entries: List[KeyInstanceRow]) \
            -> Tuple[concurrent.futures.Future[None], List[KeyInstanceRow]]:
        keyinstance_id = self._storage.get("next_keyinstance_id", 1)
        rows = entries[:]
        for i, row in enumerate(rows):
            rows[i] = row._replace(keyinstance_id=keyinstance_id, account_id=account_id)
            keyinstance_id += 1
        self._storage.put("next_keyinstance_id", keyinstance_id)
        future = db_functions.create_keyinstances(self.get_db_context(), rows)
        def callback(callback_future: concurrent.futures.Future[None]) -> None:
            if callback_future.cancelled():
                return
            callback_future.result()
            keyinstance_ids = [ row.keyinstance_id for row in rows ]
            self.trigger_callback('on_keys_created', account_id, keyinstance_ids)
        future.add_done_callback(callback)
        return future, rows

    def read_key_list(self, account_id: int, keyinstance_ids: Optional[List[int]]=None) \
            -> List[KeyListRow]:
        return db_functions.read_key_list(self.get_db_context(), account_id, keyinstance_ids)

    def read_keys_for_transaction_subscriptions(self, account_id: int,
            tx_hash: Optional[bytes]=None) -> List[TransactionSubscriptionRow]:
        return db_functions.read_keys_for_transaction_subscriptions(self.get_db_context(),
            account_id, tx_hash)

    def read_keyinstances_for_derivations(self, account_id: int,
            derivation_type: DerivationType, derivation_data2s: List[bytes],
            masterkey_id: Optional[int]=None) -> List[KeyInstanceRow]:
        return db_functions.read_keyinstances_for_derivations(self.get_db_context(), account_id,
            derivation_type, derivation_data2s, masterkey_id)

    def read_keyinstance(self, *, account_id: Optional[int]=None, keyinstance_id: int) \
            -> Optional[KeyInstanceRow]:
        return db_functions.read_keyinstance(self.get_db_context(), account_id=account_id,
            keyinstance_id=keyinstance_id)

    def read_keyinstances(self, *, account_id: Optional[int]=None,
            keyinstance_ids: Optional[Sequence[int]]=None, flags: Optional[KeyInstanceFlag]=None,
            mask: Optional[KeyInstanceFlag]=None) -> List[KeyInstanceRow]:
        return db_functions.read_keyinstances(self.get_db_context(), account_id=account_id,
            keyinstance_ids=keyinstance_ids, flags=flags, mask=mask)

    def reserve_keyinstance(self, account_id: int, masterkey_id: int,
            derivation_path: DerivationPath,
            allocation_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> concurrent.futures.Future[Tuple[int, KeyInstanceFlag]]:
        """
        Allocate one keyinstance for the caller's usage.

        See the account `reserve_keyinstance` docstring for more detail about how to use this.

        Returns a future.
        The result of the future is the allocated `keyinstance_id` if successful.
        Raises `KeyInstanceNotFoundError` if there are no available key instances.
        Raises `DatabaseUpdateError` if something else allocated the selected keyinstance first.
        """
        return db_functions.reserve_keyinstance(self.get_db_context(), account_id, masterkey_id,
            derivation_path, allocation_flags)

    def set_keyinstance_flags(self, key_ids: Sequence[int], flags: KeyInstanceFlag,
            mask: Optional[KeyInstanceFlag]=None) \
                -> concurrent.futures.Future[List[KeyInstanceFlagChangeRow]]:
        return db_functions.set_keyinstance_flags(self.get_db_context(), key_ids, flags, mask)

    def get_next_derivation_index(self, account_id: int, masterkey_id: int,
            derivation_subpath: DerivationPath) -> int:
        last_index = db_functions.read_keyinstance_derivation_index_last(
            self.get_db_context(), account_id, masterkey_id, derivation_subpath)
        if last_index is None:
            return 0
        return last_index + 1

    def update_keyinstance_descriptions(self, entries: Iterable[Tuple[Optional[str], int]]) \
            -> concurrent.futures.Future[None]:
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

    # Payment requests.

    def create_payment_requests(self, account_id: int, requests: List[PaymentRequestRow]) \
            -> concurrent.futures.Future[List[PaymentRequestRow]]:
        def callback(callback_future: concurrent.futures.Future[List[PaymentRequestRow]]) -> None:
            if callback_future.cancelled():
                return
            callback_future.result()
            updated_keyinstance_ids = [ row.keyinstance_id for row in requests ]
            self.trigger_callback('keys_updated', account_id, updated_keyinstance_ids)

        request_id = self._storage.get("next_paymentrequest_id", 1)
        rows: List[PaymentRequestRow] = []
        for request in requests:
            rows.append(request._replace(paymentrequest_id=request_id))
            request_id += 1
        self._storage.put("next_paymentrequest_id", request_id)

        future = db_functions.create_payment_requests(self.get_db_context(), rows)
        future.add_done_callback(callback)
        return future

    def read_payment_request(self, *, request_id: Optional[int]=None,
            keyinstance_id: Optional[int]=None) -> Optional[PaymentRequestReadRow]:
        return db_functions.read_payment_request(self.get_db_context(), request_id=request_id,
            keyinstance_id=keyinstance_id)

    def read_payment_requests(self, account_id: int, flags: Optional[PaymentFlag]=None,
            mask: Optional[PaymentFlag]=None) -> List[PaymentRequestReadRow]:
        return db_functions.read_payment_requests(self.get_db_context(), account_id, flags,
            mask)

    def update_payment_requests(self, entries: Iterable[PaymentRequestUpdateRow]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_payment_requests(self.get_db_context(), entries)

    def delete_payment_request(self, account_id: int, request_id: int, keyinstance_id: int) \
            -> concurrent.futures.Future[KeyInstanceFlag]:
        """
        Deletes a payment request and clears any flags on the key as appropriate.

        Returns the `KeyInstanceFlag` values that are cleared from the key that was allocated for
        the payment request.
        """
        def callback(callback_future: concurrent.futures.Future[KeyInstanceFlag]) -> None:
            if callback_future.cancelled():
                return
            cleared_flags = callback_future.result()
            if self._network is not None and cleared_flags & KeyInstanceFlag.ACTIVE:
                # This payment request was the only reason the key was active and being monitored
                # on the indexing server for new transactions. We can now delete the subscription.
                account = self._accounts[account_id]
                account.delete_key_subscriptions([ keyinstance_id ])

            self.trigger_callback('keys_updated', account_id, [ keyinstance_id ])

        future = db_functions.delete_payment_request(self.get_db_context(), request_id,
            keyinstance_id)
        future.add_done_callback(callback)
        return future

    # Script hashes.

    def create_keyinstance_scripts(self, entries: Iterable[KeyInstanceScriptHashRow]) \
            -> concurrent.futures.Future[None]:
        return db_functions.create_keyinstance_scripts(self.get_db_context(), entries)

    def read_keyinstance_scripts_by_id(self, keyinstance_ids: List[int]) \
            -> List[KeyInstanceScriptHashRow]:
        return db_functions.read_keyinstance_scripts_by_id(self.get_db_context(), keyinstance_ids)

    # Transaction outputs.

    def create_transaction_outputs(self, account_id: int,
            entries: List[TransactionOutputShortRow]) -> List[TransactionOutputShortRow]:
        db_functions.create_transaction_outputs(self.get_db_context(), entries)
        return entries

    def read_account_transaction_outputs_with_key_data(self, account_id: int,
            confirmed_only: bool=False, mature_height: Optional[int]=None,
            exclude_frozen: bool=False, keyinstance_ids: Optional[List[int]]=None) \
                -> List[TransactionOutputSpendableRow]:
        return db_functions.read_account_transaction_outputs_with_key_data(self.get_db_context(),
            account_id, confirmed_only, mature_height, exclude_frozen, keyinstance_ids)

    def read_account_transaction_outputs_with_key_and_tx_data(self, account_id: int,
            confirmed_only: bool=False, mature_height: Optional[int]=None,
            exclude_frozen: bool=False, keyinstance_ids: Optional[List[int]]=None) \
                -> List[TransactionOutputSpendableRow2]:
        return db_functions.read_account_transaction_outputs_with_key_and_tx_data(
            self.get_db_context(), account_id, confirmed_only, mature_height, exclude_frozen,
                keyinstance_ids)

    # def get_parent_transaction_outputs(self, tx_hash: bytes) -> List[TransactionOutputShortRow]:
    #     """ When the child transaction is in the database. """
    #     return db_functions.read_parent_transaction_outputs(self.get_db_context(), tx_hash)

    def read_transaction_outputs_with_key_data(self, *, account_id: Optional[int]=None,
            tx_hash: Optional[bytes]=None, txo_keys: Optional[List[Outpoint]]=None,
            derivation_data2s: Optional[List[bytes]]=None, require_keys: bool=False) \
                -> List[TransactionOutputSpendableRow]:
        return db_functions.read_transaction_outputs_with_key_data(self.get_db_context(),
            account_id=account_id, tx_hash=tx_hash, txo_keys=txo_keys,
            derivation_data2s=derivation_data2s, require_keys=require_keys)

    def get_transaction_outputs_short(self, l: List[Outpoint]) \
            -> List[TransactionOutputShortRow]:
        return db_functions.read_transaction_outputs_explicit(self.get_db_context(), l)

    def update_transaction_output_flags(self, txo_keys: List[Outpoint],
            flags: TransactionOutputFlag, mask: Optional[TransactionOutputFlag]=None) \
                -> concurrent.futures.Future[bool]:
        return db_functions.update_transaction_output_flags(self.get_db_context(),
            txo_keys, flags, mask)

    # Wallet events.

    def create_wallet_events(self,  entries: List[WalletEventRow]) \
            -> concurrent.futures.Future[None]:
        next_id = self._storage.get("next_wallet_event_id", 1)
        rows = []
        for entry in entries:
            rows.append(entry._replace(event_id=next_id))
            next_id += 1
        future = db_functions.create_wallet_events(self.get_db_context(), rows)
        self._storage.put("next_wallet_event_id", next_id)
        self.trigger_callback('notifications_created', self.get_storage_path(), rows)
        return future

    def read_wallet_events(self, account_id: Optional[int]=None,
            mask: WalletEventFlag=WalletEventFlag.NONE) -> List[WalletEventRow]:
        return db_functions.read_wallet_events(self.get_db_context(), account_id=account_id,
            mask=mask)

    def update_wallet_event_flags(self,
            entries: Iterable[Tuple[WalletEventFlag, int]]) -> concurrent.futures.Future[None]:
        return db_functions.update_wallet_event_flags(self.get_db_context(), entries)

    # Transactions.

    def get_transaction_deltas(self, tx_hash: bytes, account_id: Optional[int]=None) \
            -> List[TransactionDeltaSumRow]:
        return db_functions.read_transaction_values(self.get_db_context(), tx_hash, account_id)

    def get_transaction_flags(self, tx_hash: bytes) -> Optional[TxFlags]:
        return db_functions.read_transaction_flags(self.get_db_context(), tx_hash)

    def set_transaction_state(self, tx_hash: bytes, flag: TxFlags,
            ignore_mask: Optional[TxFlags]=None) -> concurrent.futures.Future[bool]:
        return db_functions.set_transaction_state(self.get_db_context(), tx_hash, flag,
            ignore_mask)

    def get_transaction_metadata(self, tx_hash: bytes) -> Optional[TransactionMetadata]:
        return db_functions.read_transaction_metadata(self.get_db_context(), tx_hash)

    def get_transaction_height(self, tx_hash: bytes) -> int:
        """
        Return the height we have for a transaction.

        Remember that the only valid height values we should find are:

            -2: Most likely a local transaction.
            -1: In the mempool with unconfirmed parents.
             0: In the mempool with confirmed parents.
            1+: Confirmed in a block with the given value as the height.

        If someone is calling this, they should know that the transaction is in the database.
        """
        block_height, _block_position = db_functions.read_transaction_block_info(
            self.get_db_context(), tx_hash)
        assert block_height is not None, f"tx {hash_to_hex_str(tx_hash)} has no height"
        return block_height

    def read_transaction_value_entries(self, account_id: int, *,
            tx_hashes: Optional[List[bytes]]=None, mask: Optional[TxFlags]=None) \
                -> List[TransactionValueRow]:
        return db_functions.read_transaction_value_entries(self.get_db_context(), account_id,
            tx_hashes=tx_hashes, mask=mask)

    def read_transactions_exist(self, tx_hashes: Sequence[bytes], account_id: Optional[int]=None) \
            -> List[TransactionExistsRow]:
        return db_functions.read_transactions_exist(self.get_db_context(), tx_hashes, account_id)

    def update_transaction_block_many(self, entries: Iterable[TransactionBlockRow]) \
            -> concurrent.futures.Future[int]:
        return db_functions.update_transaction_block_many(self.get_db_context(), entries)

    # Data acquisition.

    async def maybe_obtain_transactions_async(self, tx_hashes: List[bytes],
            tx_heights: Dict[bytes, int], tx_fee_hints: Dict[bytes, Optional[int]],
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) -> Set[bytes]:
        """
        Update the registry of transactions we do not have or are in the process of getting.

        For now we attempt to preserve the ordering the caller gives. This is assisted by
        Python 3.7+ dictionary key ordering being in order of insertion. In theory we could
        keep a height ordered list if it were really important, but for now we do not bother.

        Return the hashes out of `tx_hashes` that do not already exist.
        """
        async with self._obtain_transactions_async_lock:
            missing_tx_hashes: Set[bytes] = set()
            existing_tx_rows = self.read_transactions_exist(tx_hashes)
            existing_tx_hashes = set(r.tx_hash for r in existing_tx_rows)
            for tx_hash in tx_hashes:
                if tx_hash in existing_tx_hashes:
                    continue
                block_height = tx_heights[tx_hash]
                block_hash = self._get_header_hash_for_height(block_height)
                fee_hint = tx_fee_hints[tx_hash]
                if tx_hash in self._missing_transactions:
                    # These transactions are not in the database, metadata is tracked in the entry
                    # and we should update it.
                    self._missing_transactions[tx_hash].block_hash = block_hash
                    self._missing_transactions[tx_hash].block_height = block_height
                    self._missing_transactions[tx_hash].fee_hint = fee_hint
                    self._missing_transactions[tx_hash].import_flags |= import_flags
                else:
                    self._missing_transactions[tx_hash] = MissingTransactionEntry(block_hash,
                        block_height, fee_hint, import_flags)
                    missing_tx_hashes.add(tx_hash)
            self._logger.debug("Registering %d missing transactions", len(missing_tx_hashes))
            if len(missing_tx_hashes):
                self.txs_changed_event.set()
            return missing_tx_hashes

    async def get_missing_transactions_async(self, n: int=50) -> List[bytes]:
        """
        Return the kind of ordered list of missing transactions.

        Given that dictionary keys are iterated in order of insertion, if any keyinstance has
        height ordered transactions that need to be acquired, those should be fetched in that
        order. However, if any other keyinstance already referred to any of those transactions
        this will break that ordering. So.. who cares?

        Returns a list of transaction hashes that the wallet wants the byte data for.
        """
        async with self._obtain_transactions_async_lock:
            return list(itertools.islice(self._missing_transactions, n))

    async def get_unverified_transactions_async(self) -> Dict[bytes, int]:
        """
        Identify transactions that are associated with a block but lack the merkle proof.

        Returns any transactions that are in need of a merkle proof in the form of:
            [ (tx_hash_1: bytes, tx_height_1: int), ... ]
        """
        async with self._obtain_proofs_async_lock:
            results = db_functions.read_unverified_transactions(self.get_db_context(),
                self.get_local_height())
            self._logger.debug("unverified_transactions: %s",
                [ hash_to_hex_str(r[0])[:8] for r in results ])
            return dict(results)

    def read_network_servers(self, server_key: Optional[Tuple[NetworkServerType, str]]=None) \
            -> Tuple[List[NetworkServerRow], List[NetworkServerAccountRow]]:
        return db_functions.read_network_servers(self.get_db_context(), server_key)

    def read_network_servers_with_credentials(self) -> List[NetworkServerState]:
        results: List[NetworkServerState] = []
        server_rows, account_rows = self.read_network_servers()
        for server_row in server_rows:
            server_key = ServerAccountKey.for_server_row(server_row)
            results.append(NetworkServerState(server_key, self._registered_api_keys.get(server_key),
                server_row.fee_quote_json, server_row.date_last_try, server_row.date_last_good))
        for account_row in account_rows:
            server_key = ServerAccountKey.for_account_row(account_row)
            results.append(NetworkServerState(server_key, self._registered_api_keys.get(server_key),
                account_row.fee_quote_json, account_row.date_last_try, account_row.date_last_good))
        return results

    def get_credential_id_for_server_key(self, key: ServerAccountKey) \
            -> Optional[IndefiniteCredentialId]:
        return self._registered_api_keys.get(key)

    def update_network_servers(self,
            added_server_rows: List[NetworkServerRow],
            added_server_account_rows: List[NetworkServerAccountRow],
            updated_server_rows: List[NetworkServerRow],
            updated_server_account_rows: List[NetworkServerAccountRow],
            deleted_server_keys: List[ServerAccountKey],
            deleted_server_account_keys: List[ServerAccountKey],
            updated_api_keys: Dict[ServerAccountKey,
                Tuple[Optional[str], Optional[Tuple[str, str]]]]) \
                    -> concurrent.futures.Future[None]:
        """
        Update the database, wallet and network for the given set of network server changes.

        These benefit from being packaged together because they can be updated in a database
        transaction, and then the network and wallet usage of this information can be updated
        on a successful database update. If the database update fails, then no changes should
        be applied.
        """
        def update_cached_values(future: concurrent.futures.Future[None]) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()

            # Need to delete, add and update cached credentials. This should happen regardless of
            # whether the network is activated.
            for server_key, (encrypted_api_key, new_key_state) in updated_api_keys.items():
                if encrypted_api_key is not None:
                    credential_id = self._registered_api_keys[server_key]
                    if new_key_state is None:
                        app_state.credentials.remove_indefinite_credential(credential_id)
                        del self._registered_api_keys[server_key]
                    else:
                        unencrypted_value, _encrypted_value = new_key_state
                        app_state.credentials.update_indefinite_credential(
                            credential_id, unencrypted_value)
                else:
                    assert new_key_state is not None
                    unencrypted_value, _encrypted_value = new_key_state
                    self._registered_api_keys[server_key] = \
                        app_state.credentials.add_indefinite_credential(unencrypted_value)

            if self._network is not None:
                added_keys: List[NetworkServerState] = []
                updated_keys: List[NetworkServerState] = []
                deleted_keys: List[ServerAccountKey] = []

                for server_row in added_server_rows:
                    server_key = ServerAccountKey.for_server_row(server_row)
                    added_keys.append(NetworkServerState(server_key,
                        self._registered_api_keys.get(server_key)))

                for account_row in added_server_account_rows:
                    server_key = ServerAccountKey.for_account_row(account_row)
                    added_keys.append(NetworkServerState(server_key,
                        self._registered_api_keys.get(server_key)))

                for server_row in updated_server_rows:
                    server_key = ServerAccountKey.for_server_row(server_row)
                    if server_key in updated_api_keys:
                        updated_keys.append(NetworkServerState(server_key,
                            self._registered_api_keys.get(server_key)))

                for account_row in updated_server_account_rows:
                    server_key = ServerAccountKey.for_account_row(account_row)
                    if server_key in updated_api_keys:
                        updated_keys.append(NetworkServerState(server_key,
                            self._registered_api_keys.get(server_key)))

                deleted_keys.extend(deleted_server_keys)
                deleted_keys.extend(deleted_server_account_keys)

                self._network.update_api_servers_for_wallet(self, added_keys, updated_keys,
                    deleted_keys)

        future = db_functions.update_network_servers(self.get_db_context(), added_server_rows,
            added_server_account_rows, updated_server_rows, updated_server_account_rows,
            deleted_server_keys, deleted_server_account_keys)
        # We do not update the data used by the wallet and network unless the database update
        # successfully applies. There is likely no reason it won't, outside of programmer error.
        future.add_done_callback(update_cached_values)
        return future

    def update_network_server_states(self, updated_states: List[NetworkServerState]) \
            -> concurrent.futures.Future[None]:
        """
        Update this wallet's network servers for the latest state changes.

        This is the statistics and data sourced from the server, not the definition of the server
        itself.
        """
        server_rows: List[NetworkServerRow] = []
        server_account_rows: List[NetworkServerAccountRow] = []
        for state in updated_states:
            if state.key.account_id == -1:
                server_rows.append(NetworkServerRow(state.key.url, state.key.server_type,
                    fee_quote_json=state.fee_quote_json, date_last_good=state.date_last_good,
                    date_last_try=state.date_last_try))
            else:
                server_account_rows.append(NetworkServerAccountRow(state.key.url,
                    state.key.server_type, state.key.account_id,
                    fee_quote_json=state.fee_quote_json, date_last_good=state.date_last_good,
                    date_last_try=state.date_last_try))
        future = db_functions.update_network_server_states(self.get_db_context(),
            server_rows, server_account_rows)
        return future

    def _get_header_hash_for_height(self, height: int) -> Optional[bytes]:
        assert app_state.headers is not None
        chain = app_state.headers.longest_chain()
        try:
            header_bytes = app_state.headers.raw_header_at_height(chain, height)
        except MissingHeader:
            # It is possible we could get notified of key usage in a block before we actually
            # get the header. Does it happen? Probably not. We can remove this case later.
            return None
        else:
            return cast(bytes, double_sha256(header_bytes))

    def _obtain_transaction_lock(self, tx_hash: bytes) -> threading.RLock:
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

    def _relinquish_transaction_lock(self, tx_hash: bytes) -> None:
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

    # # TODO(no-merge) unit test
    def extend_transaction(self, tx: Transaction, tx_context: TransactionContext) -> None:
        """
        If this information is kept long term, there is the possibility it might become stale:
        - If created before all related keys are created, then the metadata will become out-dated.
        - If created before parent transactions are found, the metadata will be incomplete.
        """
        input: XTxInput
        output: XTxOutput

        # Index the signing metadata. This may come from several places. One is where the user is
        # creating the transaction themselves, and the other is where they have imported an
        # externally created incomplete transaction perhaps from an online watch only wallet to
        # this offline signing version of that wallet (or some multi-signature variation of that).
        for input in tx.inputs:
            outpoint = Outpoint(input.prev_hash, input.prev_idx)

            if len(input.x_pubkeys):
                data = input.x_pubkeys[0].get_derivation_data()
                if data is not None:
                    tx_context.key_datas_by_spent_outpoint[outpoint] = data

            parent_tx = tx_context.parent_transactions.get(input.prev_hash)
            if parent_tx:
                tx_context.spent_outpoint_values[outpoint] = parent_tx.outputs[input.prev_idx].value

        for txo_index, output in enumerate(tx.outputs):
            if len(output.x_pubkeys):
                data = output.x_pubkeys[0].get_derivation_data()
                if data is not None:
                    tx_context.key_datas_by_txo_index[txo_index] = data

        self.populate_transaction_context_key_data_from_database(tx, tx_context)
        self.populate_transaction_context_key_data_from_database_keys(tx, tx_context)
        self.populate_transaction_context_key_data_from_search(tx, tx_context)

    @staticmethod
    def sanity_check_derivation_key_data(data1: Optional[DatabaseKeyDerivationData],
            data2: DatabaseKeyDerivationData) -> None:
        if data1 is not None:
            if data1.derivation_path is not None:
                assert data1.derivation_path == data2.derivation_path
            if data1.account_id is not None:
                assert data1.account_id == data2.account_id
            if data1.masterkey_id is not None:
                assert data1.masterkey_id == data2.masterkey_id
            if data1.keyinstance_id is not None:
                assert data1.keyinstance_id == data2.keyinstance_id

    def populate_transaction_context_key_data_from_database(self, tx: Transaction,
            tx_context: TransactionContext) -> None:
        """
        Get metadata about which keys are used for transaction inputs and outputs based on
        transactions in the database already, potentially including the given transaction.
        """
        # At this point we probably know if the inputs and outputs have signing metadata
        # associated with them. If that information is there, we will validate it's correctness.
        found_in_database: bool = False
        if tx.is_complete():
            # If the transaction is in the database we map in it's data as authoritative.
            tx_hash = tx.hash()

            for txo_row in db_functions.read_parent_transaction_outputs_with_key_data(
                    self.get_db_context(), tx_hash):
                found_in_database = True
                database_data = DatabaseKeyDerivationData.from_key_data(txo_row,
                    DatabaseKeyDerivationType.EXTENSION_LINKED)
                outpoint = Outpoint(txo_row.tx_hash, txo_row.txo_index)
                self.sanity_check_derivation_key_data(
                    tx_context.key_datas_by_spent_outpoint.get(outpoint), database_data)
                tx_context.key_datas_by_spent_outpoint[outpoint] = database_data
                tx_context.spent_outpoint_values[outpoint] = txo_row.value

            for txo_row in db_functions.read_transaction_outputs_with_key_data(
                    self.get_db_context(), tx_hash=tx_hash, require_keys=True):
                found_in_database = True
                database_data = DatabaseKeyDerivationData.from_key_data(txo_row,
                    DatabaseKeyDerivationType.EXTENSION_LINKED)
                self.sanity_check_derivation_key_data(
                    tx_context.key_datas_by_txo_index.get(txo_row.txo_index), database_data)
                tx_context.key_datas_by_txo_index[txo_row.txo_index] = database_data

        if not found_in_database:
            # Whether the transaction is incomplete or complete and not in the database, we may
            # have the parent transactions in the database that the transaction is spending coins
            # from. In the post-SPV world, we should have them as part of the merkle proof data
            # if they are not our spends. But keep in mind that this is used for arbitrary
            # transactions, not just SPV-related transactions.
            all_outpoints = [ Outpoint(input.prev_hash, input.prev_idx)
                for input in cast(List[XTxInput], tx.inputs) ]
            for txo_row in db_functions.read_transaction_outputs_with_key_data(
                    self.get_db_context(), txo_keys=all_outpoints):
                database_data = DatabaseKeyDerivationData.from_key_data(txo_row,
                    DatabaseKeyDerivationType.EXTENSION_UNLINKED)
                outpoint = Outpoint(txo_row.tx_hash, txo_row.txo_index)
                existing_data = tx_context.key_datas_by_spent_outpoint.get(outpoint)
                self.sanity_check_derivation_key_data(existing_data, database_data)
                tx_context.key_datas_by_spent_outpoint[outpoint] = database_data
                tx_context.spent_outpoint_values[outpoint] = txo_row.value

    def populate_transaction_context_key_data_from_database_keys(self, tx: Transaction,
            tx_context: TransactionContext, skip_existing: bool=False) -> None:
        """
        Get metadata about which keys are used for transaction inputs and outputs based on
        matches with known script hashes.

        Calling this if `populate_transaction_context_key_data_from_database` has already been
        called and the transaction is in the database seems pointless, but it will be useful if
        the transaction is not in the database.
        """
        txo_indexes_by_script_hash: Dict[bytes, List[int]] = defaultdict(list)
        script_hashes_by_keyinstance_id: Dict[int, Set[bytes]] = defaultdict(set)

        output: XTxOutput
        for txo_index, output in enumerate(tx.outputs):
            database_data = tx_context.key_datas_by_txo_index.get(txo_index)
            if database_data and database_data.source >= DatabaseKeyDerivationType.EXTENSION_LINKED:
                continue
            if txo_index in tx_context.key_datas_by_txo_index and not skip_existing:
                continue
            script_hash = scripthash_bytes(output.script_pubkey)
            txo_indexes_by_script_hash[script_hash].append(txo_index)

        script_hashes = list(txo_indexes_by_script_hash)
        for script_row in db_functions.read_keyinstance_scripts_by_hash(self.get_db_context(),
                script_hashes):
            script_hashes_by_keyinstance_id[script_row.keyinstance_id].add(
                script_row.script_hash)

        if not script_hashes_by_keyinstance_id:
            return

        for keyinstance_row in db_functions.read_keyinstances(self.get_db_context(),
                keyinstance_ids=list(script_hashes_by_keyinstance_id)):
            database_data = DatabaseKeyDerivationData.from_key_data(keyinstance_row,
                DatabaseKeyDerivationType.EXTENSION_UNLINKED)
            for script_hash in script_hashes_by_keyinstance_id[keyinstance_row.keyinstance_id]:
                for txo_index in txo_indexes_by_script_hash[script_hash]:
                    self.sanity_check_derivation_key_data(
                        tx_context.key_datas_by_txo_index.get(txo_index), database_data)
                    tx_context.key_datas_by_txo_index[txo_index] = database_data

    def populate_transaction_context_key_data_from_search(self, tx: Transaction,
            tx_context: TransactionContext) -> None:
        """
        Get metadata about which keys are used for transaction inputs and outputs based on
        exploring the derivation paths beyond how far we've already created database keys
        for.
        """
        input_data_by_script_hash: Dict[bytes, Outpoint] = {}
        output_data_by_script_hash: Dict[bytes, int] = {}

        # Work out if there are any things we still need to look for.
        input: XTxInput
        output: XTxOutput
        for input in tx.inputs:
            outpoint = Outpoint(input.prev_hash, input.prev_idx)
            # Skip the input if we already have key data for it.
            database_data = tx_context.key_datas_by_spent_outpoint.get(outpoint)
            if database_data and database_data.source >= DatabaseKeyDerivationType.EXTENSION_LINKED:
                continue
            # Skip the input if we do not have the parent transaction.
            parent_tx = tx_context.parent_transactions.get(input.prev_hash)
            if parent_tx is None:
                continue
            script_hash = scripthash_bytes(parent_tx.outputs[input.prev_idx].script_pubkey)
            input_data_by_script_hash[script_hash] = outpoint

        for output_idx, output in enumerate(tx.outputs):
            # Skip the output if we already have key data for it.
            database_data = tx_context.key_datas_by_txo_index.get(output_idx)
            if database_data and database_data.source >= DatabaseKeyDerivationType.EXTENSION_LINKED:
                continue
            output_data_by_script_hash[scripthash_bytes(output.script_pubkey)] = output_idx

        script_hashes = set(input_data_by_script_hash) | set(output_data_by_script_hash)
        if not script_hashes:
            return

        # Search all the deterministic accounts for key usage.
        for account in self._accounts.values():
            if not account.is_deterministic():
                continue
            account_id = account.get_id()
            for derivation_subpath in (CHANGE_SUBPATH, RECEIVING_SUBPATH):
                next_derivation_index = account.get_next_derivation_index(derivation_subpath)
                for i in range(300):
                    derivation_path = derivation_subpath + (next_derivation_index + i,)
                    for script_type in ACCOUNT_SCRIPT_TYPES[account.type()]:
                        script_bytes = account.derive_script_template(derivation_path,
                            script_type).to_script_bytes()
                        script_hash = scripthash_bytes(script_bytes)
                        if script_hash in input_data_by_script_hash:
                            outpoint = input_data_by_script_hash[script_hash]
                            database_data = DatabaseKeyDerivationData(derivation_path,
                                account_id=account_id,
                                source=DatabaseKeyDerivationType.EXTENSION_EXPLORATION)
                            self.sanity_check_derivation_key_data(
                                tx_context.key_datas_by_spent_outpoint.get(outpoint), database_data)
                            tx_context.key_datas_by_spent_outpoint[outpoint] = database_data
                        elif script_hash in output_data_by_script_hash:
                            txo_index = output_data_by_script_hash[script_hash]
                            database_data = DatabaseKeyDerivationData(derivation_path,
                                account_id=account_id,
                                source=DatabaseKeyDerivationType.EXTENSION_EXPLORATION)
                            self.sanity_check_derivation_key_data(
                                tx_context.key_datas_by_txo_index.get(txo_index), database_data)
                            tx_context.key_datas_by_txo_index[txo_index] = database_data
                        else:
                            continue
                        script_hashes.remove(script_hash)
                        if not script_hashes:
                            return

    def load_transaction_from_text(self, text: str) \
            -> Tuple[Optional[Transaction], Optional[TransactionContext]]:
        """
        Takes user-provided text and attempts to extract a transaction from it.

        Returns the loaded transaction if the text contains a valid one. The transaction is not
        guaranteed to be in the database, and if it is not may even conflict with existing coin
        spends known to the wallet. Returns `None` if the text does not contain a valid
        transaction.

        Raises `ValueError` if the text is not found to contain viable transaction data.
        """
        if not text:
            return None, None

        txdict = tx_dict_from_text(text)
        tx, context = Transaction.from_dict(txdict)

        # Incomplete transactions should not be cached.
        if not tx.is_complete():
            return tx, context

        tx_hash = tx.hash()
        # Update the cached transaction for the given hash.
        lock = self._obtain_transaction_lock(tx_hash)
        with lock:
            try:
                self._transaction_cache2.set(tx_hash, tx)
            finally:
                self._relinquish_transaction_lock(tx_hash)

        return tx, context

    def load_transaction_from_bytes(self, data: bytes) -> Transaction:
        """
        Loads a transaction using given transaction data.

        If the transaction is already in the cache, it will return that transaction.
        If the transaction is in the database, this will load it in extended form and cache it.
        Otherwise the transaction data will be parsed, loaded in extended form and cached.
        """
        tx_hash = double_sha256(data)
        lock = self._obtain_transaction_lock(tx_hash)
        with lock:
            try:
                # Get it if cached in memory / load from database if present.
                tx = self._get_cached_transaction(tx_hash)
                if tx is not None:
                    return tx

                # Parse the transaction data.
                tx = Transaction.from_bytes(data)
                self._transaction_cache2.set(tx_hash, tx)
            finally:
                self._relinquish_transaction_lock(tx_hash)

        return tx

    async def add_local_transaction(self, tx_hash: bytes, tx: Transaction, flags: TxFlags) -> None:
        """
        This is currently only called when an account constructs and signs a transaction
        """
        link_state = TransactionLinkState()
        link_state.rollback_on_spend_conflict = True
        await self._import_transaction(tx_hash, tx, flags, link_state, block_hash=None,
            block_height=BlockHeight.LOCAL, block_position=None, fee_hint=None)

    async def import_transaction_async(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            link_state: Optional[TransactionLinkState]=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) \
                -> None:
        """
        This is currently only called when a missing transaction arrives.

        Note that a new transaction is imported as state cleared even if we know it has been
        mined through the `block_height` and `block_hash` values. It is not changed to state
        settled until we have obtained the merkle proof.
        """
        block_hash: Optional[bytes] = None
        block_height: int = BlockHeight.LOCAL
        fee_hint: Optional[int] = None

        # If there is a missing transaction entry it is almost certain that the indexer monitoring
        # detected, obtained and is importing the transaction.
        missing_entry = self._missing_transactions.get(tx_hash)
        if missing_entry is not None:
            block_hash = missing_entry.block_hash
            block_height = missing_entry.block_height
            fee_hint = missing_entry.fee_hint
            import_flags |= missing_entry.import_flags

        if link_state is None:
            link_state = TransactionLinkState()
        await self._import_transaction(tx_hash, tx, flags, link_state, block_hash=block_hash,
            block_height=block_height, fee_hint=fee_hint, import_flags=import_flags)

    async def _import_transaction(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            link_state: TransactionLinkState, block_hash: Optional[bytes]=None,
            block_height: Union[int, BlockHeight]=BlockHeight.LOCAL,
            block_position: Optional[int]=None, fee_hint: Optional[int]=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) -> None:
        """
        Add an external complete transaction to the database.

        We do not know whether the transaction uses any wallet keys, and is related to any
        accounts related to those keys. We will work this out as part of the importing process.

        We do not attempt to correct the block height for the transaction state. It is assumed
        that the caller is passing in legitimate data
        """
        assert tx.is_complete()
        timestamp = get_posix_timestamp()
        txo_flags = TransactionOutputFlag.COINBASE if tx.is_coinbase() else \
            TransactionOutputFlag.NONE

        # The database layer should be decoupled from core wallet logic so we need to
        # break down the transaction and related data for it to consume.
        tx_row = TransactionRow(tx_hash, tx.to_bytes(), flags, block_hash, int(block_height),
            block_position, fee_hint, None, tx.version, tx.locktime, timestamp, timestamp)

        txi_rows: List[TransactionInputAddRow] = []
        for txi_index, input in enumerate(tx.inputs):
            txi_row = TransactionInputAddRow(tx_hash, txi_index,
                input.prev_hash, input.prev_idx, input.sequence,
                TransactionInputFlag.NONE,
                input.script_offset, input.script_length,
                timestamp, timestamp)
            txi_rows.append(txi_row)

        txo_rows: List[TransactionOutputAddRow] = []
        for txo_index, raw_txo in enumerate(tx.outputs):
            txo = cast(XTxOutput, raw_txo)
            txo_row = TransactionOutputAddRow(tx_hash, txo_index, txo.value,
                None,                           # Raw transaction means no idea of key usage.
                ScriptType.NONE,                # Raw transaction means no idea of script type.
                txo_flags,
                scripthash_bytes(txo.script_pubkey),
                txo.script_offset, txo.script_length,
                timestamp, timestamp)
            txo_rows.append(txo_row)

        await self.db_functions_async.import_transaction_async(tx_row, txi_rows, txo_rows,
            link_state)

        # TODO(rt12) later on we would have some way of asking servers whether a
        # transaction has been mined, or to get notified if they get mined.
        if self._network is not None:
            if block_height < BlockHeight.BLOCK1:
                if link_state.account_ids is not None:
                    for account_id in link_state.account_ids:
                        account = self._accounts[account_id]
                        account.register_for_transaction_proofs(tx_hash)
            else:
                # This will awaken the loop that pulls in proofs for transactions we know are mined
                # but have not yet fetched the proof for.
                self.txs_changed_event.set()

        async with self._obtain_transactions_async_lock:
            if tx_hash in self._missing_transactions:
                del self._missing_transactions[tx_hash]
                self._logger.debug("Removed missing transaction %s", hash_to_hex_str(tx_hash)[:8])
                self.trigger_callback('missing_transaction_obtained', tx_hash, tx, link_state)

        # This primarily routes a notification to the user interface, for it to update for this
        # specific change.
        self.trigger_callback('transaction_added', tx_hash, tx, link_state, import_flags)

        # NOTE It is kind of arbitrary that this returns a future, let alone the one for closed
        #   payment requests. In the future, perhaps this will return a grouped set of futures
        #   for all the related dependent updates?
        app_state.async_.spawn(self._close_paid_payment_requests_async)

    async def link_transaction_async(self, tx_hash: bytes, link_state: TransactionLinkState) \
            -> None:
        """
        Link an existing transaction to any applicable accounts.

        We do not know whether the transaction uses any wallet keys, and is related to any
        accounts related to those keys. We will work this out as part of the importing process.
        This should not be done for any pre-existing transactions.
        """
        await self.db_functions_async.link_transaction_async(tx_hash, link_state)

        self.trigger_callback('transaction_link_result', tx_hash, link_state)

    async def _close_paid_payment_requests_async(self) \
            -> Tuple[Set[int], List[Tuple[int, int, int]]]:
        """
        Apply paid status to any payment requests and keys satisfied by this transaction.

        This will identify the payment requests that are `UNPAID` and whose value is satisfied
        by the outputs in the given transaction that receive value into the payment requests
        keys. It will mark those as `PAID` and it will remove the flag on the keys that
        identifies them as used in a payment request.
        """
        paymentrequest_ids, key_update_rows = await db_functions.close_paid_payment_requests_async(
            self.get_db_context())

        # Notify any dependent systems including the GUI that payment requests have updated.
        if len(paymentrequest_ids):
            self.trigger_callback("payment_requests_paid")

        # Unsubscribe from any deactivated keys.
        account_keyinstance_ids: Dict[int, Set[int]] = defaultdict(set)
        for account_id, keyinstance_id, flags in key_update_rows:
            account_keyinstance_ids[account_id].add(keyinstance_id)
        for account_id, keyinstance_ids in account_keyinstance_ids.items():
            self._accounts[account_id].delete_key_subscriptions(list(keyinstance_ids))

        return paymentrequest_ids, key_update_rows

    def read_bip32_keys_gap_size(self, account_id: int, masterkey_id: int, prefix_bytes: bytes) \
            -> int:
        return db_functions.read_bip32_keys_gap_size(self.get_db_context(), account_id,
            masterkey_id, prefix_bytes)

    # Called by network.
    async def add_transaction_proof(self, tx_hash: bytes, block_height: int, header: Header,
            block_position: int, proof_position: int, proof_branch: Sequence[bytes]) -> None:
        tx_id = hash_to_hex_str(tx_hash)
        if self._stopped:
            self._logger.debug("add_transaction_proof on stopped wallet: %s", tx_id)
            return

        proof = TxProof(proof_position, proof_branch)
        await self.db_functions_async.update_transaction_proof_async(tx_hash, block_height,
            block_position, proof)

        confirmations = max(self.get_local_height() - block_height + 1, 0)
        self._logger.debug("add_transaction_proof %d %d %d", block_height, confirmations,
            header.timestamp)
        self.trigger_callback('transaction_verified', tx_hash, block_height, block_position,
            confirmations, header.timestamp)

    def remove_transaction(self, tx_hash: bytes) -> concurrent.futures.Future[bool]:
        """
        Unlink the transaction from accounts and their associated data.

        This will not delete the transaction from the database. It will however remove any
        links to the transaction including:
        - Invoice assocations with the transaction.
        """
        tx_id = hash_to_hex_str(tx_hash)
        self._logger.debug("removing tx from history %s", tx_id)

        def on_db_call_done(future: concurrent.futures.Future[bool]) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()
            self.trigger_callback('transaction_deleted', self._id, tx_hash)

        future = db_functions.remove_transaction(self.get_db_context(), tx_hash)
        future.add_done_callback(on_db_call_done)
        return future

    # TODO(no-merge) Manually test with a multi-signature account/transaction.
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
                    account.derive_new_keys_until(extended_public_key.derivation_path)

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
                    account.derive_new_keys_until(extended_public_key.derivation_path)

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

    def have_transaction(self, tx_hash: bytes) -> bool:
        return self.get_transaction_flags(tx_hash) is not None

    def get_transaction(self, tx_hash: bytes) -> Optional[Transaction]:
        lock = self._obtain_transaction_lock(tx_hash)
        with lock:
            try:
                return self._get_cached_transaction(tx_hash)
            finally:
                self._relinquish_transaction_lock(tx_hash)

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

    def get_boolean_setting(self, setting_name: str, default_value: bool=False) -> bool:
        """
        Get the value of a wallet-global config variable that is known to be boolean type.

        For the sake of simplicity, callers are expected to know the default value of their
        given variable and pass it in. Known cases are:
          WalletSettings.USE_CHANGE: True
          WalletSettings.MULTIPLE_CHANGE: True
        """
        return self._storage.get_explicit_type(bool, str(setting_name), default_value)

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
        return self._storage.get_explicit_type(int, 'tx_bytedata_cache_size',
            DEFAULT_TXDATA_CACHE_SIZE_MB)

    def set_cache_size_for_tx_bytedata(self, maximum_size: int, force_resize: bool=False) -> None:
        assert MINIMUM_TXDATA_CACHE_SIZE_MB <= maximum_size <= MAXIMUM_TXDATA_CACHE_SIZE_MB, \
            f"invalid cache size {maximum_size}"
        self._storage.put('tx_bytedata_cache_size', maximum_size)
        maximum_size_bytes = maximum_size * (1024 * 1024)
        self._transaction_cache2.set_maximum_size(maximum_size_bytes, force_resize)

    def get_local_height(self) -> int:
        """ return last known height if we are offline """
        return (self._network.get_local_height() if self._network else
            self._storage.get_explicit_type(int, 'stored_height', 0))

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
        if self._network is not None:
            chain = self._network.chain()
            if chain is not None:
                chain_tip = chain.tip
                local_height = chain_tip.height
                chain_tip_hash = chain_tip.hash
        self._storage.put('stored_height', local_height)
        self._storage.put('last_tip_hash', chain_tip_hash.hex() if chain_tip_hash else None)

        for credential_id in self._registered_api_keys.values():
            app_state.credentials.remove_indefinite_credential(credential_id)

        for account in self.get_accounts():
            account.stop()
        if self._network is not None:
            updated_states = self._network.remove_wallet(self)
            if len(updated_states):
                # We do not need to wait for the future to complete, as closing the storage below
                # should close out all database pending writes.
                self.update_network_server_states(updated_states)

        self.db_functions_async.close()
        self._storage.close()
        self._network = None
        self._stopped = True

    def create_gui_handler(self, window: 'ElectrumWindow', account: AbstractAccount) -> None:
        for keystore in account.get_keystores():
            if isinstance(keystore, Hardware_KeyStore):
                plugin = cast('QtPluginBase', keystore.plugin)
                plugin.replace_gui_handler(window, keystore)
