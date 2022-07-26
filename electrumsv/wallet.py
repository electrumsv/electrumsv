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
#   - StandardAccount: one keystore, P2PKH (default) / P2PK
#   - MultisigAccount: several keystores, bare multisig (default) / P2SH (pre-genesis)

from __future__ import annotations
import asyncio
import concurrent.futures
import dataclasses
from datetime import datetime, timezone
from enum import IntFlag
from functools import partial
import json
import os
import random
import threading
from typing import Any, AsyncIterable, Awaitable, Callable, cast, Coroutine, Iterable, Optional, \
    Sequence, TypedDict, TypeVar, TYPE_CHECKING, Union
import uuid
import weakref

from bitcoinx import (Address, bip32_build_chain_string, bip32_decompose_chain_string,
    BIP32PrivateKey, Chain, double_sha256, Header, hash_to_hex_str, hex_str_to_hash,
    MissingHeader, P2PKH_Address, P2SH_Address, PrivateKey, PublicKey, Script)
from electrumsv_database.sqlite import DatabaseContext

from . import coinchooser
from .app_state import app_state
from .bitcoin import  scripthash_bytes, ScriptTemplate
from .constants import (ACCOUNT_SCRIPT_TYPES, AccountCreationType, AccountFlags, AccountType,
    API_SERVER_TYPES, BlockHeight, ChainManagementKind, ChainWorkerToken, CHANGE_SUBPATH,
    DatabaseKeyDerivationType, DEFAULT_TXDATA_CACHE_SIZE_MB, DerivationType,
    DerivationPath, KeyInstanceFlag, KeystoreTextType, KeystoreType, MAPIBroadcastFlag,
    MasterKeyFlags, MAX_VALUE, MAXIMUM_TXDATA_CACHE_SIZE_MB, MINIMUM_TXDATA_CACHE_SIZE_MB,
    NetworkEventNames, NetworkServerFlag, NetworkServerType, PaymentFlag,
    PeerChannelAccessTokenFlag,
    PeerChannelMessageFlag, PushDataHashRegistrationFlag, PushDataMatchFlag, RECEIVING_SUBPATH,
    SERVER_USES, ServerCapability, ServerPeerChannelFlag, ServerProgress, ScriptType,
    TransactionImportFlag,
    TransactionInputFlag, TransactionOutputFlag, TxFlags, unpack_derivation_path,
    WALLET_ACCOUNT_PATH_TEXT, WALLET_IDENTITY_PATH_TEXT, WalletEvent, WalletEventFlag,
    WalletEventType, WalletSettings)
from .contacts import Contacts
from .crypto import pw_decode, pw_encode
from .exceptions import (BroadcastError, ExcessiveFee, InvalidPassword, NotEnoughFunds,
    PreviousTransactionsMissingException, ServerConnectionError, UnsupportedAccountTypeError,
    UnsupportedScriptTypeError, UserCancelled, WalletLoadError)
from .i18n import _
from .keys import get_multi_signer_script_template, get_single_signer_script_template
from .keystore import BIP32_KeyStore, Deterministic_KeyStore, Hardware_KeyStore, \
    Imported_KeyStore, instantiate_keystore, KeyStore, Multisig_KeyStore, Old_KeyStore, \
    SinglesigKeyStoreTypes, SignableKeystoreTypes, StandardKeystoreTypes, Xpub
from .logs import logs
from .network_support.api_server import APIServerDefinition, NewServer
from .network_support.dpp_proxy import dpp_msg_type_to_state_flag, _is_later_dpp_message_sequence, \
    manage_dpp_network_connections_async, MSG_TYPE_JOIN_SUCCESS, MSG_TYPE_PAYMENT_REQUEST_RESPONSE
from .network_support.exceptions import GeneralAPIError, FilterResponseInvalidError, \
    IndexerResponseMissingError, TransactionNotFoundError
from .network_support.general_api import create_reference_server_account_async, \
    maintain_server_connection_async, request_binary_merkle_proof_async, \
    request_transaction_data_async, upgrade_server_connection_async
from .network_support.headers import get_longest_valid_chain
from .network_support.mapi import mapi_transaction_broadcast_async, update_mapi_fee_quotes_async
from .network_support.types import GenericPeerChannelMessage, ServerConnectionProblems, \
    ServerConnectionState, TipFilterPushDataMatchesData
from .networks import Net
from .standards.electrum_transaction_extended import transaction_from_electrumsv_dict
from .standards.json_envelope import JSONEnvelope, validate_json_envelope
from .standards.mapi import MAPICallbackResponse, validate_mapi_callback_response
from .standards.tsc_merkle_proof import separate_proof_and_embedded_transaction, TSCMerkleProof, \
    TSCMerkleProofError, TSCMerkleProofJson, verify_proof
from .storage import WalletStorage
from .transaction import (HardwareSigningMetadata, Transaction, TransactionContext,
    TransactionFeeEstimator, tx_dict_from_text, TxSerialisationFormat, XPublicKey, XTxInput,
    XTxOutput)
from .types import (ConnectHeaderlessProofWorkerState, DatabaseKeyDerivationData,
    IndefiniteCredentialId, FeeEstimatorProtocol, FeeQuoteCommon,
    KeyInstanceDataBIP32SubPath, KeyInstanceDataHash, KeyInstanceDataPrivateKey, KeyStoreResult,
    MasterKeyDataTypes, MasterKeyDataBIP32, MasterKeyDataElectrumOld, MasterKeyDataMultiSignature,
    Outpoint, OutputSpend, ServerAccountKey, ServerAndCredential, TransactionFeeContext, \
    WaitingUpdateCallback)
from .util import format_satoshis, get_posix_timestamp, get_wallet_name_from_path, \
    TriggeredCallbacks, ValueLocks
from .util.cache import LRUCache
from .wallet_database.exceptions import DatabaseUpdateError, KeyInstanceNotFoundError, \
    TransactionAlreadyExistsError
from .wallet_database import functions as db_functions
from .wallet_database.types import (AccountRow, AccountTransactionDescriptionRow,
    AccountTransactionOutputSpendableRow, AccountTransactionOutputSpendableRowExtended,
    HistoryListRow, InvoiceAccountRow, InvoiceRow, KeyDataProtocol, KeyData,
    KeyInstanceFlagChangeRow, KeyInstanceRow, KeyListRow, KeyInstanceScriptHashRow,
    MAPIBroadcastRow, MasterKeyRow, NetworkServerRow,
    PasswordUpdateResult, PaymentRequestReadRow, PaymentRequestRow, PaymentRequestUpdateRow,
    MerkleProofUpdateRow, PushDataHashRegistrationRow, PushDataMatchRow, PushDataMatchMetadataRow,
    ServerPeerChannelRow, ServerPeerChannelAccessTokenRow, ServerPeerChannelMessageRow,
    SpentOutputRow, TransactionDeltaSumRow, TransactionExistsRow, TransactionLinkState,
    TransactionMetadata, TransactionOutputShortRow, TransactionOutputSpendableRow,
    TransactionOutputSpendableProtocol, TransactionInputAddRow, TransactionOutputAddRow,
    MerkleProofRow, TransactionProofUpdateRow, TransactionRow, TransactionValueRow, WalletBalance,
    WalletEventInsertRow, WalletEventRow, DPPMessageRow)
from .wallet_database.util import create_derivation_data2
from .wallet_support.keys import get_pushdata_hash_for_account_key_data
from .web import create_DPP_URL

if TYPE_CHECKING:
    from .network import Network
    from .network_support.headers import HeaderServerState
    from electrumsv.gui.qt.util import WindowProtocol
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
    sort_key: tuple[int, int]
    row: HistoryListRow
    balance: int


@dataclasses.dataclass
class MissingTransactionEntry:
    import_flags: TransactionImportFlag
    with_proof: bool = False
    account_ids: list[int] = dataclasses.field(default_factory=list)


ADDRESS_TYPES = { DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH }


T = TypeVar('T', bound='AbstractAccount')

class AbstractAccount:
    """
    Account classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    _default_keystore: Optional[KeyStore] = None
    _stopped: bool = False

    MAX_SOFTWARE_CHANGE_OUTPUTS = 10
    MAX_HARDWARE_CHANGE_OUTPUTS = 1

    def __init__(self, wallet: Wallet, row: AccountRow) -> None:
        # Prevent circular reference keeping parent and accounts alive.
        self._wallet: Wallet = cast(Wallet, weakref.proxy(wallet))
        self._row = row
        self._id = row.account_id

        self._logger = logs.get_logger("account[{}]".format(self.name()))
        self._network: Optional[Network] = None

        # locks: if you need to take several, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self._value_locks = ValueLocks()

    def get_id(self) -> int:
        return self._id

    def get_row(self) -> AccountRow:
        return self._row

    def get_wallet(self) -> Wallet:
        return self._wallet

    def is_petty_cash(self) -> bool:
        return self._row.flags & AccountFlags.IS_PETTY_CASH != 0

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

    def get_fresh_keys(self, derivation_parent: DerivationPath, count: int) -> list[KeyInstanceRow]:
        raise NotImplementedError

    def reserve_unassigned_key(self, derivation_parent: DerivationPath, flags: KeyInstanceFlag) \
            -> KeyData:
        raise NotImplementedError

    def derive_new_keys_until(self, derivation_path: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> tuple[Optional[concurrent.futures.Future[None]], list[KeyInstanceRow]]:
        raise NotImplementedError

    def derive_script_template(self, derivation_path: DerivationPath,
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        raise NotImplementedError

    def allocate_and_create_keys(self, count: int, derivation_subpath: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> tuple[Optional[concurrent.futures.Future[None]],
                        Optional[concurrent.futures.Future[None]],
                        list[KeyInstanceRow], list[KeyInstanceScriptHashRow]]:
        raise NotImplementedError

    def create_preallocated_keys(self, key_allocations: Sequence[KeyAllocation],
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> tuple[concurrent.futures.Future[None], concurrent.futures.Future[None],
                        list[KeyInstanceRow], list[KeyInstanceScriptHashRow]]:
        """
        Take a list of key allocations and create keyinstances and scripts in the database for them.

        Key allocations are expected to be created in a safe context that prevents multiple
        allocations of the same key allocation parameters from being assigned to multiple callers.
        """
        keyinstance_rows: list[KeyInstanceRow] = []
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

    def create_provided_keyinstances(self, keyinstance_rows: list[KeyInstanceRow]) -> \
            tuple[concurrent.futures.Future[None], concurrent.futures.Future[None],
                list[KeyInstanceRow], list[KeyInstanceScriptHashRow]]:
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
        scripthash_rows: list[KeyInstanceScriptHashRow] = []
        for keyinstance_row in keyinstance_rows:
            for script_type, script in self.get_possible_scripts_for_derivation(
                    keyinstance_row.derivation_type, keyinstance_row.derivation_data2):
                script_hash = scripthash_bytes(script)
                scripthash_rows.append(KeyInstanceScriptHashRow(keyinstance_row.keyinstance_id,
                    script_type, script_hash))
        scripthash_future = self._wallet.data.create_keyinstance_scripts(scripthash_rows)
        # The caller only needs to wait on the second future, as the database writes are executed
        # sequentially and the second will complete after the first.
        return keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows

    def _create_derivation_data_dict(self, key_allocation: KeyAllocation) \
            -> KeyInstanceDataBIP32SubPath:
        assert key_allocation.derivation_type == DerivationType.BIP32_SUBPATH
        assert len(key_allocation.derivation_path)
        return { "subpath": key_allocation.derivation_path }

    def set_keyinstance_flags(self, keyinstance_ids: Sequence[int], flags: KeyInstanceFlag,
            mask: Optional[KeyInstanceFlag]=None) \
                -> concurrent.futures.Future[list[KeyInstanceFlagChangeRow]]:
        """
        Encapsulate updating the flags for keyinstances belonging to this account.

        This used to subscribe and unsubscribe key usage with the indexer and ...
        """
        # There is no situation where keys should be marked active, as this is meaningless.
        # Keys should only be activated with supplementary reasons so we can know if we can
        # deactivate it fully.
        assert flags & KeyInstanceFlag.ACTIVE == 0, "do not set directly"

        # Setting any `MASK_ACTIVE_REASON` flag is additive to the base `ACTIVE` flag.
        if flags & KeyInstanceFlag.MASK_ACTIVE_REASON:
            flags |= KeyInstanceFlag.ACTIVE

        def callback(future: concurrent.futures.Future[list[KeyInstanceFlagChangeRow]]) -> None:
            # Ensure we abort if it is cancelled.
            if future.cancelled():
                return
            # Ensure we abort if there is an error.
            future.result()

            self._wallet.events.trigger_callback(WalletEvent.KEYS_UPDATE, self._id, keyinstance_ids)

        future = self._wallet.data.set_keyinstance_flags(keyinstance_ids, flags, mask)
        future.add_done_callback(callback)
        return future

    def get_keystore(self) -> Optional[KeyStore]:
        if self._row.default_masterkey_id is not None:
            return self._wallet.get_keystore(self._row.default_masterkey_id)
        return self._default_keystore

    def get_keystores(self) -> Sequence[KeyStore]:
        keystore = self.get_keystore()
        return [ keystore ] if keystore is not None else []

    def get_keyinstances(self) -> list[KeyInstanceRow]:
        return self._wallet.data.read_keyinstances(account_id=self._id)

    # TODO(multi-account) This is not compatible with multi-account usage of the same transaction
    # unless we repackage the outer transaction. We kind of need per-account transaction context.
    def get_transaction(self, tx_hash: bytes) -> Optional[tuple[Transaction, TransactionContext]]:
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
            context.account_descriptions[self._id] = desc
        return tx, context

    def set_transaction_label(self, tx_hash: bytes, text: Optional[str]) \
            -> concurrent.futures.Future[None]:
        return self._wallet.set_transaction_labels([ (text, self._id, tx_hash) ])

    def get_transaction_label(self, tx_hash: bytes) -> str:
        rows = self._wallet.data.read_transaction_descriptions(self._id, tx_hashes=[ tx_hash ])
        if len(rows) and rows[0].description:
            return rows[0].description
        return ""

    def get_transaction_labels(self, tx_hashes: Sequence[bytes]) \
            -> list[AccountTransactionDescriptionRow]:
        return self._wallet.data.read_transaction_descriptions(self._id, tx_hashes=tx_hashes)

    def __str__(self) -> str:
        return self.name()

    def get_name(self) -> str:
        return self._row.account_name

    def set_name(self, name: str) -> None:
        self._wallet.data.update_account_names([ (name, self._row.account_id) ])
        self._row = self._row._replace(account_name=name)
        self._wallet.events.trigger_callback(WalletEvent.ACCOUNT_RENAME, self._id, name)

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

    def get_label_data(self) -> dict[str, Any]:
        # Create exported data structure for account labels/descriptions.
        label_entries = [
            (bip32_build_chain_string(unpack_derivation_path(cast(bytes, key.derivation_data2))),
                key.description)
            for key in self.get_keyinstances() if key.description is not None
        ]
        rows = self._wallet.data.read_transaction_descriptions(self._id)
        transaction_entries = [
            (hash_to_hex_str(tx_hash), description) for account_id, tx_hash, description in rows
        ]

        data: dict[str, Any] = {}
        if len(transaction_entries):
            data["transactions"] = transaction_entries
        if len(label_entries):
            data["keys"] = {
                "account_fingerprint": self.get_fingerprint().hex(),
                "entries": label_entries,
            }
        return data

    def get_keyinstance_label(self, key_id: int) -> str:
        keyinstance = self._wallet.data.read_keyinstance(keyinstance_id=key_id)
        assert keyinstance is not None
        return keyinstance.description or ""

    def set_keyinstance_label(self, keyinstance_id: int, text: Optional[str]) \
            -> Optional[concurrent.futures.Future[None]]:
        text = None if text is None or text.strip() == "" else text.strip()
        keyinstance = self._wallet.data.read_keyinstance(keyinstance_id=keyinstance_id)
        assert keyinstance is not None
        if keyinstance.description == text:
            return None
        future = self._wallet.data.update_keyinstance_descriptions([ (text, keyinstance_id) ])
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

    def set_default_script_type(self, script_type: ScriptType) \
            -> concurrent.futures.Future[None] | None:
        if script_type == self._row.default_script_type:
            return None
        self._row = self._row._replace(default_script_type=script_type)
        return self._wallet.data.update_account_script_types([
            (script_type, self._row.account_id) ])

    def set_server_ids(self, blockchain_server_id: int | None, peer_channel_server_id: int | None) \
            -> concurrent.futures.Future[None]:
        """
        Update the servers used by this account.

        NOTE: This should only be done for the currently automatically created and hidden petty
              cash account. That is the only place it is used.
        """
        self._row = self._row._replace(peer_channel_server_id=peer_channel_server_id,
            blockchain_server_id=blockchain_server_id)
        return self._wallet.data.update_account_server_ids(blockchain_server_id,
            peer_channel_server_id, self._row.account_id)

    def get_threshold(self) -> int:
        return 1

    def export_private_key(self, keydata: KeyDataProtocol, password: str) -> Optional[str]:
        """ extended WIF format """
        if self.is_watching_only():
            return None
        assert keydata.masterkey_id is not None
        keystore = self._wallet.get_keystore(keydata.masterkey_id)
        assert keydata.derivation_data2 is not None
        derivation_path = unpack_derivation_path(keydata.derivation_data2)
        private_key = keystore.get_private_key(derivation_path, password)
        return cast(str, private_key.to_WIF())

    def get_frozen_balance(self) -> WalletBalance:
        return self._wallet.data.read_account_balance(self._id, TransactionOutputFlag.FROZEN)

    def get_balance(self) -> WalletBalance:
        return self._wallet.data.read_account_balance(self._id)

    def get_key_list(self, keyinstance_ids: Optional[list[int]]=None) -> list[KeyListRow]:
        return self._wallet.data.read_key_list(self._id, keyinstance_ids)

    def get_local_transaction_entries(self, tx_hashes: Optional[list[bytes]]=None) \
            -> list[TransactionValueRow]:
        return self._wallet.data.read_transaction_value_entries(self._id, tx_hashes=tx_hashes,
            mask=TxFlags.MASK_STATE_LOCAL)

    def get_transaction_value_entries(self, mask: Optional[TxFlags]=None) \
            -> list[TransactionValueRow]:
        return self._wallet.data.read_transaction_value_entries(self._id, mask=mask)

    def get_transaction_outputs_with_key_data(self, exclude_frozen: bool=True, mature: bool=True,
            confirmed_only: Optional[bool]=None, keyinstance_ids: Optional[list[int]]=None) \
                -> Sequence[AccountTransactionOutputSpendableRow]:
        if confirmed_only is None:
            confirmed_only = cast(bool, app_state.config.get('confirmed_only', False))
        return self._wallet.data.read_account_transaction_outputs_with_key_data(self._id,
            confirmed_only=confirmed_only, exclude_immature=mature,
            exclude_frozen=exclude_frozen, keyinstance_ids=keyinstance_ids)

    def get_transaction_outputs_with_key_and_tx_data(self, exclude_frozen: bool=True,
            mature: bool=True, confirmed_only: Optional[bool]=None,
            keyinstance_ids: Optional[list[int]]=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        if confirmed_only is None:
            confirmed_only = cast(bool, app_state.config.get('confirmed_only', False))
        mature_height = self._wallet.get_local_height() if mature else None
        return self._wallet.data.read_account_transaction_outputs_with_key_and_tx_data(self._id,
            confirmed_only=confirmed_only, mature_height=mature_height,
            exclude_frozen=exclude_frozen, keyinstance_ids=keyinstance_ids)

    def get_extended_input_for_spendable_output(self, row: TransactionOutputSpendableProtocol) \
            -> XTxInput:
        assert row.account_id is not None
        assert row.account_id == self._id
        assert row.keyinstance_id is not None
        assert row.derivation_type is not None
        x_pubkeys = self.get_xpubkeys_for_key_data(cast(KeyDataProtocol, row))
        # NOTE(typing) The first four arguments for `TxInput` cause mypy to choke because `attrs`..
        return XTxInput(
            prev_hash          = row.tx_hash, # type: ignore
            prev_idx           = row.txo_index,
            script_sig         = Script(),
            sequence           = 0xffffffff,
            threshold          = self.get_threshold(),
            script_type        = row.script_type,
            x_pubkeys          = x_pubkeys,
            value              = row.value,
        )

    def get_history(self, domain: Optional[Sequence[int]]=None) -> list[HistoryListEntry]:
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
        assert app_state.headers is not None

        history_raw: list[HistoryListEntry] = []
        rows = db_functions.read_history_list(self._wallet.get_db_context(), self._id, domain)
        for row in rows:
            block_height = row.block_height
            if block_height <= BlockHeight.MEMPOOL:
                # This will list local transactions then unconfirmed then confirmed.
                sort_key = (-block_height + 100000000000, row.date_created)
            else:
                assert row.block_position is not None
                sort_key = (row.block_height, row.block_position)
            history_raw.append(HistoryListEntry(sort_key, row, 0))
        history_raw.sort(key=lambda t: t.sort_key)

        balance = 0
        for entry in history_raw:
            balance += entry.row.value_delta
            entry.balance = balance
        history_raw.reverse()
        return history_raw

    def export_history(self, from_datetime: Optional[datetime]=None,
            to_datetime: Optional[datetime]=None) -> list[AccountExportEntry]:
        fx = app_state.fx
        assert app_state.headers is not None

        out: list[AccountExportEntry] = []
        for entry in self.get_history():
            history_line = entry.row

            entry_utc_date = datetime.now(tz=timezone.utc)
            block_height = -0
            if history_line.block_hash is not None:
                header_data = self._wallet.lookup_header_for_hash(history_line.block_hash)
                if header_data is None:
                    # Most likely a transaction with a merkle proof that is waiting on the header
                    logger.warning("Wallet has not processed header for %s in export_history",
                        hash_to_hex_str(history_line.block_hash))
                else:
                    header = header_data[0]
                    block_height = header.height
                    entry_utc_date = datetime.fromtimestamp(header.timestamp, tz=timezone.utc)

            if from_datetime and entry_utc_date < from_datetime:
                continue
            if to_datetime and entry_utc_date >= to_datetime:
                continue
            export_entry = AccountExportEntry(
                txid=hash_to_hex_str(history_line.tx_hash),
                height=block_height,
                timestamp=entry_utc_date.isoformat(),
                value=format_satoshis(history_line.value_delta,
                    is_diff=True) if history_line.value_delta is not None else '--',
                balance=format_satoshis(entry.balance),
                label=history_line.description or "",
                fiat_value=None,
                fiat_balance=None)
            if fx:
                export_entry['fiat_value'] = fx.historical_value_str(history_line.value_delta,
                    entry_utc_date)
                export_entry['fiat_balance'] = fx.historical_value_str(entry.balance,
                    entry_utc_date)
            out.append(export_entry)
        return out

    def dust_threshold(self) -> int:
        """
        Return the number of satoshis that is the current dust threshold.

        History:
        - The hard-coded Bitcoin SV dust threshold as of Sep 2018 was 546 satoshis.
        - The hard-coded Bitcoin SV dust threshold as of the v1.0.11 node release is 1 satoshi.
        """
        return 1

    def get_max_change_outputs(self) -> int:
        # The full set of software change outputs is too much for hardware wallet users. This
        # currently defaults hardware wallets to using one change output because generally that
        # is all the hardware wallets can handle identifying as belonging to the wallet.
        # - Ledger source code claims only one change output.
        if self.involves_hardware_wallet() and self.type() != AccountType.MULTISIG:
            return self.MAX_HARDWARE_CHANGE_OUTPUTS
        return self.MAX_SOFTWARE_CHANGE_OUTPUTS

    def make_unsigned_transaction(self,
            unspent_outputs: Sequence[TransactionOutputSpendableProtocol], outputs: list[XTxOutput],
            fee_estimator: FeeEstimatorProtocol | None=None) \
                -> tuple[Transaction, TransactionContext]:
        """
        Raises `NotEnoughFunds` if there are no selected coins to be spent.
        Raises `NotEnoughFunds` if the value of the outputs cannot be satisfied by the coin chooser
            from the selected coins.
        Raises `ValueError` if more than one output is set to spend the maximum amount.
        """
        # check outputs
        all_index = None
        for n, output in enumerate(outputs):
            if output.value == MAX_VALUE:
                if all_index is not None:
                    raise ValueError("More than one output set to spend max")
                all_index = n

        # Avoid index-out-of-range with inputs[0] below
        if not unspent_outputs:
            raise NotEnoughFunds()

        # Default to using the wallet configured fee-per-kb rate.
        if fee_estimator is None:
            if app_state.config.fee_per_kb() is None:
                raise Exception('Dynamic fee estimates not available')
            fee_estimator = app_state.config.get_fee_estimator()

        tx_context = TransactionContext()
        tx_context.mapi_server_hint = fee_estimator.get_mapi_server_hint()
        inputs = [ self.get_extended_input_for_spendable_output(utxo) for utxo in unspent_outputs ]
        if all_index is None:
            # Let the coin chooser select the coins to spend.
            max_change = self.get_max_change_outputs() \
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
                        x_pubkeys     = self.get_xpubkeys_for_key_data(
                            cast(KeyDataProtocol, keyinstance))))
            else:
                # NOTE(typing) `attrs` and `mypy` are not compatible, `TxOutput` vars unseen.
                change_outs = [ XTxOutput( # type: ignore
                    value         = 0,
                    script_pubkey = self.get_script_for_derivation(unspent_outputs[0].script_type,
                        unspent_outputs[0].derivation_type,
                        unspent_outputs[0].derivation_data2),
                    script_type   = inputs[0].script_type,
                    x_pubkeys     = inputs[0].x_pubkeys) ]
            coin_chooser = coinchooser.CoinChooserPrivacy()
            tx = coin_chooser.make_tx(inputs, outputs, change_outs,
                fee_estimator, self.dust_threshold())
        else:
            # All of the selected coins are being spent.
            assert all(txin.value is not None for txin in inputs)
            sendable = cast(int, sum(txin.value for txin in inputs))
            outputs[all_index].value = 0
            tx = Transaction.from_io(inputs, outputs)
            fee = fee_estimator.estimate_fee(tx.estimated_size())
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
        return tx, tx_context

    def start(self, network: Optional[Network]) -> None:
        self._network = network

    def stop(self) -> None:
        assert not self._stopped
        self._stopped = True

        self._logger.debug("stopping account %s", self)

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
        db_outputs = self._wallet.data.read_transaction_outputs_with_key_data(account_id=self._id,
            tx_hash=tx_hash, require_keys=True)
        if not db_outputs:
            return None

        db_outputs = sorted(db_outputs, key=lambda db_output: -db_output.value)
        output = cast(TransactionOutputSpendableProtocol, db_outputs[0])
        inputs = [ self.get_extended_input_for_spendable_output(output) ]
        # TODO(rt12) This should get a change output key from the account (if applicable).
        # NOTE(typing) mypy struggles with attrs inheritance, so we need to disable it.
        outputs = [
            XTxOutput(
                # TxOutput
                output.value - fee, # type:ignore
                self.get_script_for_derivation(output.script_type,
                    output.derivation_type, output.derivation_data2),
                # XTxOutput
                output.script_type,
                self.get_xpubkeys_for_key_data(output)) # type:ignore
        ]
        # note: no need to call tx.BIP_LI01_sort() here - single input/output
        return Transaction.from_io(inputs, outputs)

    def can_sign(self, tx: Transaction) -> bool:
        if tx.is_complete():
            return False
        for k in self.get_keystores():
            if k.can_sign(tx):
                return True
        return False

    def get_xpubkeys_for_key_data(self, row: KeyDataProtocol) -> dict[bytes, XPublicKey]:
        raise NotImplementedError

    def get_master_public_key(self) -> Optional[str]:
        raise NotImplementedError

    def get_master_public_keys(self) -> list[str]:
        raise NotImplementedError

    def get_public_keys_for_derivation(self, derivation_type: DerivationType,
            derivation_data2: Optional[bytes]) -> list[PublicKey]:
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
            -> list[PublicKey]:
        raise NotImplementedError

    def get_script_template_for_derivation(self, script_type: ScriptType,
            derivation_type: DerivationType, derivation_data2: Optional[bytes]) -> ScriptTemplate:
        raise NotImplementedError

    def get_possible_scripts_for_derivation(self, derivation_type: DerivationType,
            derivation_data2: Optional[bytes]) -> list[tuple[ScriptType, Script]]:
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
            context: Optional[TransactionContext]=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) \
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
            if self.is_petty_cash():
                bip32_keystore = cast(BIP32_KeyStore, k)
                bip32_keystore.sign_transaction_with_credentials(tx, tx_context)
            else:
                try:
                    k.sign_transaction(tx, password, tx_context)
                except UserCancelled: # Hardware wallets.
                    continue

        # Incomplete transactions are multi-signature transactions that have not passed the
        # required signature threshold. We do not currently store these until they are fully signed.
        if not tx.is_complete():
            return None

        tx.update_script_offsets()

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
                self._wallet.data.update_invoice_transactions(
                    [ (tx_hash, tx_context.invoice_id) ])

            if len(tx_context.account_descriptions) > 0:
                update_entries: list[tuple[str | None, int, bytes]] = [
                    (description, account_id, tx_hash) for (account_id, description)
                    in tx_context.account_descriptions.items() ]
                self._wallet.set_transaction_labels(update_entries)

        transaction_future = app_state.async_.spawn(self._wallet.add_local_transaction(tx_hash,
            tx, tx_flags, BlockHeight.LOCAL, None, None, import_flags))
        transaction_future.add_done_callback(callback)
        return transaction_future

    def _create_hardware_signing_metadata(self, tx: Transaction, context: TransactionContext) \
            -> list[HardwareSigningMetadata]:
        # add output info for hw wallets
        # the hw keystore at the time of signing does not have access to either the threshold
        # or the larger set of xpubs it's own mpk is included in. So we collect these in the
        # wallet at this point before proceeding to sign.
        tx_output: XTxOutput
        x_public_key: XPublicKey
        hardware_output_info: list[HardwareSigningMetadata] = []
        xpubs = self.get_master_public_keys()
        for tx_output in tx.outputs:
            output_items: dict[bytes, tuple[DerivationPath, tuple[str], int]] = {}
            # NOTE(rt12) This should exclude all script types hardware wallets dont use.
            if tx_output.script_type == ScriptType.MULTISIG_BARE:
                context.hardware_signing_metadata.append(output_items)
                continue
            for x_public_key in tx_output.x_pubkeys.values():
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
            update_cb: Optional[WaitingUpdateCallback]=None, *,
            # NOTE(rt12) This is disabled by default as we do not want unexpected network access,
            #     post-electrumx.
            allow_remote_access: bool=False) -> None:
        # Called by the signing logic to ensure all the required data is present.
        # Should be called by the logic that serialises incomplete transactions to gather the
        # context for the next party.
        # Raises PreviousTransactionsMissingException
        need_tx_hashes: set[bytes] = set()
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
                elif allow_remote_access:
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
            rawtx = app_state.async_.spawn_and_wait(self._wallet.fetch_raw_transaction_async(
                tx_hash, self), timeout=10)
        except (GeneralAPIError, ServerConnectionError, TransactionNotFoundError):
            self._logger.exception("failed retrieving transaction")
            return None
        else:
            # TODO(possibly) Once we've moved away from indexer state being authoritative
            # over the contents of a wallet, we should be able to add this to the
            # database as an non-owned input transaction. This isn't necessarily what we want
            # so we may want to make it an opt-in user option.
            return Transaction.from_bytes(rawtx)

    def extend_serialised_transaction(self, format: TxSerialisationFormat, tx: Transaction,
            context: TransactionContext, data: dict[str, Any],
            update_cb: Optional[WaitingUpdateCallback]=None) -> Optional[dict[str, Any]]:
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

    def sign_message(self, key_data: KeyDataProtocol, message: bytes, password: str) -> bytes:
        raise NotImplementedError

    def decrypt_message(self, key_data: KeyDataProtocol, message: bytes, password: str) -> bytes:
        raise NotImplementedError

    def is_watching_only(self) -> bool:
        raise NotImplementedError

    def can_change_password(self) -> bool:
        raise NotImplementedError

    def can_spend(self) -> bool:
        # All accounts can at least construct unsigned transactions except for imported address
        # accounts.
        return True

    def get_masterkey_id(self) -> Optional[int]:
        raise NotImplementedError

    def create_payment_request(self, message: str, dpp_invoice_id: str, server_id: int,
            amount: Optional[int]=None, expiration_seconds: Optional[int]=None,
            flags: PaymentFlag=PaymentFlag.NONE) \
                -> tuple[concurrent.futures.Future[list[PaymentRequestRow]], KeyDataProtocol]:
        # The payment request flags that are allowed to be set are just the supplementary flags,
        # not the state flags.
        assert flags & PaymentFlag.MASK_STATE == 0
        # We set `KeyInstanceFlag.ACTIVE` here with the understanding that we are responsible for
        # removing it when the payment request is deleted, expires or whatever.
        key_data = self.reserve_unassigned_key(RECEIVING_SUBPATH,
            KeyInstanceFlag.IS_PAYMENT_REQUEST | KeyInstanceFlag.ACTIVE)
        script_type = self.get_default_script_type()
        pushdata_hash = get_pushdata_hash_for_account_key_data(self, key_data, script_type)
        row = PaymentRequestRow(-1, key_data.keyinstance_id, dpp_invoice_id,
            flags | PaymentFlag.UNPAID, amount, expiration_seconds, message, script_type,
            pushdata_hash, server_id, get_posix_timestamp())
        future = self._wallet.create_payment_requests(self._id, [ row ])
        return future, key_data


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

    def get_master_public_keys(self) -> list[str]:
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

        existing_keys = self._wallet.data.read_keyinstances_for_derivations(self._id,
            derivation_type, [ address.hash160() ])
        if len(existing_keys):
            return False

        # TODO(key-monitoring) We used to scan for usage of this key and restore the
        #     transactions/history, however this will not work moving forward as we will not
        #     have a way to scan beyond the capped height of the restoration index up to the
        #     tip. It would if we supported it, only be able to catch restorable transactions
        #     or newly broadcast/mined transactions.

        derivation_data_dict: KeyInstanceDataHash = { "hash": address.to_string() }
        derivation_data = json.dumps(derivation_data_dict).encode()
        derivation_data2 = create_derivation_data2(derivation_type, derivation_data_dict)
        raw_keyinstance = KeyInstanceRow(-1, -1, None, derivation_type, derivation_data,
            derivation_data2, KeyInstanceFlag.ACTIVE | KeyInstanceFlag.USER_SET_ACTIVE, None)
        keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
            self.create_provided_keyinstances([ raw_keyinstance ])
        return True

    def get_public_keys_for_derivation_path(self, derivation_path: DerivationPath) \
            -> list[PublicKey]:
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
    def __init__(self, wallet: Wallet, row: AccountRow) -> None:
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

    def set_initial_state(self, keyinstance_rows: list[KeyInstanceRow]) -> None:
        keystore = cast(Imported_KeyStore, self.get_keystore())
        keystore.set_state(keyinstance_rows)

    def import_private_key(self, private_key_text: str, password: str) -> str:
        public_key = PrivateKey.from_text(private_key_text).public_key
        keystore = cast(Imported_KeyStore, self.get_keystore())

        # Prevent re-importing existing entries.
        existing_keys = self._wallet.data.read_keyinstances_for_derivations(self._id,
            DerivationType.PRIVATE_KEY, [ public_key.to_bytes(compressed=True) ])
        if len(existing_keys) > 0:
            return private_key_text

        # TODO(key-monitoring) We used to scan for usage of this key and restore the
        #     transactions/history, however this will not work moving forward as we will not
        #     have a way to scan beyond the capped height of the restoration index up to the
        #     tip. It would if we supported it, only be able to catch restorable transactions
        #     or newly broadcast/mined transactions.

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
        keystore.import_private_key(keyinstance_rows[0].keyinstance_id, public_key,
            enc_private_key_text)
        return private_key_text

    def export_private_key(self, keydata: KeyDataProtocol, password: str) -> str:
        '''Returned in WIF format.'''
        keystore = cast(Imported_KeyStore, self.get_keystore())
        public_key = PublicKey.from_bytes(keydata.derivation_data2)
        return keystore.export_private_key(public_key, password)

    def sign_message(self, key_data: KeyDataProtocol, message: bytes, password: str) -> bytes:
        assert key_data.derivation_data2 is not None
        public_key = PublicKey.from_bytes(key_data.derivation_data2)
        keystore = cast(Imported_KeyStore, self.get_keystore())
        return keystore.sign_message(public_key, message, password)

    def decrypt_message(self, key_data: KeyDataProtocol, message: bytes, password: str) -> bytes:
        assert key_data.derivation_data2 is not None
        public_key = PublicKey.from_bytes(key_data.derivation_data2)
        keystore = cast(Imported_KeyStore, self.get_keystore())
        return keystore.decrypt_message(public_key, message, password)

    def get_xpubkeys_for_key_data(self, row: KeyDataProtocol) -> dict[bytes, XPublicKey]:
        data = DatabaseKeyDerivationData.from_key_data(row, DatabaseKeyDerivationType.SIGNING)
        x_pubkey = XPublicKey(pubkey_bytes=row.derivation_data2, derivation_data=data)
        return { x_pubkey.to_bytes(): x_pubkey }

    def get_script_template_for_derivation(self, script_type: ScriptType,
            derivation_type: DerivationType, derivation_data2: Optional[bytes]) -> ScriptTemplate:
        public_key = self.get_public_keys_for_derivation(derivation_type, derivation_data2)[0]
        return self.get_script_template(public_key, script_type)


class DeterministicAccount(AbstractAccount):
    def __init__(self, wallet: Wallet, row: AccountRow) -> None:
        AbstractAccount.__init__(self, wallet, row)

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
        self._derivation_sub_paths: dict[int, list[tuple[DerivationPath, int]]] = {
            masterkey_id: [
                (CHANGE_SUBPATH, -1),
                (RECEIVING_SUBPATH, -1),
            ]
        }

        for derivation_entry in wallet.data.read_keyinstance_derivation_indexes_last(self._id):
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

    def get_masterkey_id(self) -> Optional[int]:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        return keystore.get_id()

    def has_seed(self) -> bool:
        return cast(Deterministic_KeyStore, self.get_keystore()).has_seed()

    def sign_message(self, key_data: KeyDataProtocol, message: bytes, password: str) -> bytes:
        assert key_data.derivation_data2 is not None
        derivation_path = unpack_derivation_path(key_data.derivation_data2)
        keystore = cast(SignableKeystoreTypes, self.get_keystore())
        return keystore.sign_message(derivation_path, message, password)

    def decrypt_message(self, key_data: KeyDataProtocol, message: bytes, password: str) -> bytes:
        assert key_data.derivation_data2 is not None
        derivation_path = unpack_derivation_path(key_data.derivation_data2)
        keystore = cast(BIP32_KeyStore, self.get_keystore())
        return keystore.decrypt_message(derivation_path, message, password)

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
            -> KeyData:
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
        future: Optional[concurrent.futures.Future[tuple[int, DerivationType, bytes,
            KeyInstanceFlag]]] = self._wallet.data.reserve_keyinstance(self._id, masterkey_id,
            derivation_subpath, flags)
        assert future is not None
        try:
            keyinstance_id, derivation_type, derivation_data2, final_flags = future.result()
        except KeyInstanceNotFoundError:
            keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
                self.allocate_and_create_keys(1, derivation_subpath, flags | KeyInstanceFlag.USED)
            assert scripthash_future is not None
            keyinstance_id = keyinstance_rows[0].keyinstance_id
            derivation_type = keyinstance_rows[0].derivation_type
            derivation_data2 = cast(bytes, keyinstance_rows[0].derivation_data2)
            final_flags = keyinstance_rows[0].flags
            scripthash_future.result()

        self._wallet.events.trigger_callback(WalletEvent.KEYS_UPDATE, self._id, [ keyinstance_id ])

        return KeyData(keyinstance_id, self._id, masterkey_id, derivation_type,
            derivation_data2)

    def derive_new_keys_until(self, derivation_path: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> tuple[Optional[concurrent.futures.Future[None]], list[KeyInstanceRow]]:
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
                -> tuple[Optional[concurrent.futures.Future[None]],
                        Optional[concurrent.futures.Future[None]],
                        list[KeyInstanceRow], list[KeyInstanceScriptHashRow]]:
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
    def get_fresh_keys(self, derivation_parent: DerivationPath, count: int) -> list[KeyInstanceRow]:
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
            -> list[KeyInstanceRow]:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        masterkey_id = keystore.get_id()
        return self._wallet.data.read_bip32_keys_unused(self._id, masterkey_id, derivation_parent,
            limit)

    def get_master_public_keys(self) -> list[str]:
        mpk = self.get_master_public_key()
        assert mpk is not None
        return [ mpk ]

    def get_fingerprint(self) -> bytes:
        keystore = cast(Deterministic_KeyStore, self.get_keystore())
        return keystore.get_fingerprint()


class SimpleDeterministicAccount(SimpleAccount, DeterministicAccount):
    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, wallet: Wallet, row: AccountRow) -> None:
        DeterministicAccount.__init__(self, wallet, row)

    def get_master_public_key(self) -> str:
        keystore = cast(StandardKeystoreTypes, self.get_keystore())
        return cast(str, keystore.get_master_public_key())

    def get_public_keys_for_derivation_path(self, derivation_path: DerivationPath) \
            -> list[PublicKey]:
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

    def get_xpubkeys_for_key_data(self, row: KeyDataProtocol) -> dict[bytes, XPublicKey]:
        data = DatabaseKeyDerivationData.from_key_data(row, DatabaseKeyDerivationType.SIGNING)
        keystore = cast(KeyStore, self.get_keystore())
        if keystore.type() == KeystoreType.OLD:
            x_pubkey = cast(Old_KeyStore, keystore).get_xpubkey(data)
        else:
            x_pubkey = cast(Xpub, keystore).get_xpubkey(data)
        return { x_pubkey.to_bytes(): x_pubkey }

    def derive_pubkeys(self, derivation_path: DerivationPath) -> PublicKey:
        keystore = cast(KeyStore, self.get_keystore())
        if keystore.type() == KeystoreType.OLD:
            return cast(Old_KeyStore, keystore).derive_pubkey(derivation_path)
        return cast(Xpub, keystore).derive_pubkey(derivation_path)

    def derive_script_template(self, derivation_path: DerivationPath,
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        return self.get_script_template(self.derive_pubkeys(derivation_path), script_type)



class StandardAccount(SimpleDeterministicAccount):
    def __init__(self, wallet: Wallet, row: AccountRow) -> None:
        super().__init__(wallet, row)

        if self.is_petty_cash():
            # We cache the xprv for the petty cash account as an indefinitely stored credential
            # encrypted in the credential manager. It can be decrypted for use on demand.
            password = app_state.credentials.get_wallet_password(wallet.get_storage_path())
            assert password is not None
            bip32_keystore = cast(BIP32_KeyStore, self.get_keystore())
            bip32_keystore.cache_xprv_as_indefinite_credential(password)

    def type(self) -> AccountType:
        return AccountType.STANDARD

    def stop(self) -> None:
        super().stop()

        if self.is_petty_cash():
            bip32_keystore = cast(BIP32_KeyStore, self.get_keystore())
            bip32_keystore.clear_credentials()


class MultisigAccount(DeterministicAccount):
    def __init__(self, wallet: Wallet, row: AccountRow) -> None:
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
            -> list[PublicKey]:
        return [ keystore.derive_pubkey(derivation_path) for keystore in self.get_keystores() ]

    def get_possible_scripts_for_key_data(self, keydata: KeyDataProtocol) \
            -> list[tuple[ScriptType, Script]]:
        public_keys = self.get_public_keys_for_derivation(keydata.derivation_type,
            keydata.derivation_data2)
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

    def get_script_template(self, public_keys_hex: list[str],
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        if script_type is None:
            script_type = self.get_default_script_type()
        return get_multi_signer_script_template(public_keys_hex, self.m, script_type)

    def derive_pubkeys(self, derivation_path: DerivationPath) -> list[PublicKey]:
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

    def get_master_public_keys(self) -> list[str]:
        return cast(list[str], [ k.get_master_public_key() for k in self.get_keystores()])

    def get_fingerprint(self) -> bytes:
        # Sort the fingerprints in the same order as their master public keys.
        mpks = self.get_master_public_keys()
        fingerprints = [ k.get_fingerprint() for k in self.get_keystores() ]
        _sorted_mpks, sorted_fingerprints = zip(*sorted(zip(mpks, fingerprints)))
        return b''.join(cast(Sequence[bytes], sorted_fingerprints))

    def get_xpubkeys_for_key_data(self, row: KeyDataProtocol) -> dict[bytes, XPublicKey]:
        data = DatabaseKeyDerivationData.from_key_data(row, DatabaseKeyDerivationType.SIGNING)
        unordered_x_pubkeys = [ k.get_xpubkey(data) for k in self.get_keystores() ]
        return { x_pubkey.to_bytes(): x_pubkey  for x_pubkey in unordered_x_pubkeys }


class WalletDataAccess:
    """
    This is an abstraction for the database access for a given wallet. All database functions
    that are called by application code should be wrapped here, so that the wallet code does not
    need access to the database context object. And so that the application code does not need
    to hold a reference to the wallet.
    """
    def __init__(self, db_context: DatabaseContext, events: TriggeredCallbacks[WalletEvent]) \
            -> None:
        # Private.
        self._db_context = db_context

        # Public.
        self.events = events

    def teardown(self) -> None:
        del self._db_context

    # Accounts.

    def read_account_balance(self, account_id: int,
            txo_flags: TransactionOutputFlag=TransactionOutputFlag.NONE,
            txo_mask: TransactionOutputFlag=TransactionOutputFlag.SPENT,
            exclude_frozen: bool=True) -> WalletBalance:
        return db_functions.read_account_balance(self._db_context,
            account_id, txo_flags, txo_mask, exclude_frozen)

    def update_account_names(self, entries: Iterable[tuple[str, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_account_names(self._db_context, entries)

    def update_account_script_types(self, entries: Iterable[tuple[ScriptType, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_account_script_types(self._db_context, entries)

    def update_account_server_ids(self, indexing_server_id: Optional[int],
            peer_channel_server_id: Optional[int], account_id: int) \
                -> concurrent.futures.Future[None]:
        return self._db_context.post_to_thread(db_functions.update_account_server_ids_write,
            indexing_server_id, peer_channel_server_id, account_id)

    # Account transactions.

    def read_account_ids_for_transaction(self, tx_hash: bytes) -> list[int]:
        return db_functions.read_account_ids_for_transaction(self._db_context, tx_hash)

    def read_transaction_descriptions(self, account_id: Optional[int]=None,
            tx_hashes: Optional[Sequence[bytes]]=None) -> list[AccountTransactionDescriptionRow]:
        return db_functions.read_transaction_descriptions(self._db_context,
            account_id, tx_hashes)

    def update_account_transaction_descriptions(self,
            entries: Iterable[tuple[Optional[str], int, bytes]]) -> concurrent.futures.Future[None]:
        return db_functions.update_account_transaction_descriptions(self._db_context,
            entries)

    # Invoices.

    def create_invoices(self, entries: Iterable[InvoiceRow]) -> concurrent.futures.Future[None]:
        return db_functions.create_invoices(self._db_context, entries)

    def read_invoice(self, *, invoice_id: Optional[int]=None, tx_hash: Optional[bytes]=None,
            payment_uri: Optional[str]=None) -> Optional[InvoiceRow]:
        return db_functions.read_invoice(self._db_context, invoice_id=invoice_id,
            tx_hash=tx_hash, payment_uri=payment_uri)

    def read_invoice_duplicate(self, value: int, payment_uri: str) -> Optional[InvoiceRow]:
        return db_functions.read_invoice_duplicate(self._db_context, value, payment_uri)

    def read_invoices_for_account(self, account_id: int, flags: Optional[int]=None,
            mask: Optional[int]=None) -> list[InvoiceAccountRow]:
        return db_functions.read_invoices_for_account(self._db_context, account_id, flags,
            mask)

    def update_invoice_transactions(self, entries: Iterable[tuple[Optional[bytes], int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_invoice_transactions(self._db_context, entries)

    def update_invoice_descriptions(self, entries: Iterable[tuple[Optional[str], int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_invoice_descriptions(self._db_context, entries)

    def update_invoice_flags(self, entries: Iterable[tuple[PaymentFlag, PaymentFlag, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_invoice_flags(self._db_context, entries)

    def delete_invoices(self, entries: Iterable[tuple[int]]) -> concurrent.futures.Future[None]:
        return db_functions.delete_invoices(self._db_context, entries)

    # Key instances.

    def reserve_keyinstance(self, account_id: int, masterkey_id: int,
            derivation_path: DerivationPath,
            allocation_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> concurrent.futures.Future[tuple[int, DerivationType, bytes, KeyInstanceFlag]]:
        """
        Allocate one keyinstance for the caller's usage.

        See the account `reserve_keyinstance` docstring for more detail about how to use this.

        Returns a future.
        The result of the future is the allocated `keyinstance_id` if successful.
        Raises `KeyInstanceNotFoundError` if there are no available key instances.
        Raises `DatabaseUpdateError` if something else allocated the selected keyinstance first.
        """
        return db_functions.reserve_keyinstance(self._db_context, account_id,
            masterkey_id, derivation_path, allocation_flags)

    def read_key_list(self, account_id: int, keyinstance_ids: Optional[list[int]]=None) \
            -> list[KeyListRow]:
        return db_functions.read_key_list(self._db_context, account_id,
            keyinstance_ids)

    def read_keyinstances_for_derivations(self, account_id: int,
            derivation_type: DerivationType, derivation_data2s: list[bytes],
            masterkey_id: Optional[int]=None) -> list[KeyInstanceRow]:
        return db_functions.read_keyinstances_for_derivations(self._db_context,
            account_id, derivation_type, derivation_data2s, masterkey_id)

    def read_keyinstance(self, *, account_id: Optional[int]=None, keyinstance_id: int) \
            -> Optional[KeyInstanceRow]:
        return db_functions.read_keyinstance(self._db_context, account_id=account_id,
            keyinstance_id=keyinstance_id)

    def read_keyinstances(self, *, account_id: Optional[int]=None,
            keyinstance_ids: Optional[Sequence[int]]=None, flags: Optional[KeyInstanceFlag]=None,
            mask: Optional[KeyInstanceFlag]=None) -> list[KeyInstanceRow]:
        return db_functions.read_keyinstances(self._db_context,
            account_id=account_id, keyinstance_ids=keyinstance_ids, flags=flags, mask=mask)

    def set_keyinstance_flags(self, key_ids: Sequence[int], flags: KeyInstanceFlag,
            mask: Optional[KeyInstanceFlag]=None) \
                -> concurrent.futures.Future[list[KeyInstanceFlagChangeRow]]:
        return db_functions.set_keyinstance_flags(self._db_context, key_ids, flags, mask)

    def update_keyinstance_descriptions(self, entries: Iterable[tuple[Optional[str], int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_keyinstance_descriptions(self._db_context, entries)

    def read_bip32_keys_unused(self, account_id: int, masterkey_id: int,
            derivation_path: DerivationPath, limit: int) -> list[KeyInstanceRow]:
        return db_functions.read_bip32_keys_unused(self._db_context, account_id,
            masterkey_id, derivation_path, limit)

    def read_keyinstance_derivation_indexes_last(self, account_id: int) \
            -> list[tuple[int, bytes, bytes]]:
        return db_functions.read_keyinstance_derivation_indexes_last(self._db_context,
            account_id)

    # mAPI broadcast callbacks

    async def create_mapi_broadcasts_async(self, rows: list[MAPIBroadcastRow]) \
            -> list[MAPIBroadcastRow]:
        return await self._db_context.run_in_thread_async(
            db_functions.create_mapi_broadcasts_write, rows)

    def read_mapi_broadcasts(self, tx_hashes: Optional[list[bytes]]=None) \
            -> list[MAPIBroadcastRow]:
        return db_functions.read_mapi_broadcasts(self._db_context, tx_hashes)

    def update_mapi_broadcasts(self,
            entries: Iterable[tuple[MAPIBroadcastFlag, bytes, int, int]]) -> \
                concurrent.futures.Future[None]:
        return db_functions.update_mapi_broadcasts(self._db_context, entries)

    def delete_mapi_broadcasts(self, broadcast_ids: Iterable[int]) \
            -> concurrent.futures.Future[None]:
        return db_functions.delete_mapi_broadcasts(self._db_context, broadcast_ids)

    # Merkle proofs.

    async def create_merkle_proofs_async(self, creation_rows: list[MerkleProofRow]) -> None:
        await self._db_context.run_in_thread_async(db_functions.create_merkle_proofs_write,
            creation_rows)

    async def update_merkle_proofs_async(self, update_rows: list[MerkleProofUpdateRow]) -> None:
        return await self._db_context.run_in_thread_async(
            db_functions.update_merkle_proofs_write, update_rows)

    # Network.

    def read_network_servers(self, server_key: Optional[ServerAccountKey]=None) \
            -> list[NetworkServerRow]:
        return db_functions.read_network_servers(self._db_context, server_key)

    def update_network_servers(self, rows: list[NetworkServerRow]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_network_servers(self._db_context, rows)

    async def update_network_server_credentials_async(self, server_id: int,
            encrypted_api_key: Optional[str], payment_key_bytes: Optional[bytes],
            updated_flags: NetworkServerFlag, updated_flags_mask: NetworkServerFlag) -> None:
        await self._db_context.run_in_thread_async(
            db_functions.update_network_server_credentials_write, server_id, encrypted_api_key,
                payment_key_bytes, updated_flags, updated_flags_mask)

    def update_network_server_peer_channel_id(self, server_id: int, server_peer_channel_id: int) \
            -> None:
        self._db_context.run_in_thread(db_functions.update_network_server_peer_channel_id_write,
            server_id, server_peer_channel_id)

    async def update_network_server_flags_async(self, server_id: int,
            server_flags: NetworkServerFlag, server_flags_mask: NetworkServerFlag) \
                -> None:
        await self._db_context.run_in_thread_async(db_functions.update_network_server_flags_write,
            server_id, server_flags, server_flags_mask)

    def update_network_servers_transaction(self, create_rows: list[NetworkServerRow],
        update_rows: list[NetworkServerRow], deleted_server_ids: list[int],
        deleted_server_keys: list[ServerAccountKey]) \
            -> concurrent.futures.Future[list[NetworkServerRow]]:
        return db_functions.update_network_servers_transaction(self._db_context,
            create_rows, update_rows, deleted_server_ids, deleted_server_keys)

    # Payment requests.

    def read_payment_request(self, *, request_id: Optional[int]=None,
            keyinstance_id: Optional[int]=None) -> Optional[PaymentRequestReadRow]:
        return db_functions.read_payment_request(self._db_context, request_id=request_id,
            keyinstance_id=keyinstance_id)

    def read_payment_requests(self, account_id: int, flags: Optional[PaymentFlag]=None,
            mask: Optional[PaymentFlag]=None) -> list[PaymentRequestReadRow]:
        return db_functions.read_payment_requests(self._db_context, account_id, flags,
            mask)

    def read_registered_tip_filter_pushdata_for_request(self, request_id: int) \
            -> Optional[PushDataHashRegistrationRow]:
        return db_functions.read_registered_tip_filter_pushdata_for_request(self._db_context,
            request_id)

    def update_payment_requests(self, entries: Iterable[PaymentRequestUpdateRow]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_payment_requests(self._db_context, entries)

    # Peer channels.

    async def create_server_peer_channel_async(self, row: ServerPeerChannelRow,
            tip_filter_server_id: Optional[int]=None) -> int:
        return await self._db_context.run_in_thread_async(
            db_functions.create_server_peer_channel_write, row, tip_filter_server_id)

    def read_server_peer_channels(self, server_id: int) -> list[ServerPeerChannelRow]:
        return db_functions.read_server_peer_channels(self._db_context, server_id)

    def read_server_peer_channel_access_tokens(self, peer_channel_id: int,
            mask: Optional[PeerChannelAccessTokenFlag]=None,
            flags: Optional[PeerChannelAccessTokenFlag]=None) \
                -> list[ServerPeerChannelAccessTokenRow]:
        return db_functions.read_server_peer_channel_access_tokens(self._db_context,
            peer_channel_id, mask, flags)

    async def update_server_peer_channel_async(self, remote_channel_id: Optional[str],
            remote_url: Optional[str], peer_channel_flags: ServerPeerChannelFlag,
            peer_channel_id: int,
            addable_access_tokens: list[ServerPeerChannelAccessTokenRow]) -> ServerPeerChannelRow:
        return await self._db_context.run_in_thread_async(
            db_functions.update_server_peer_channel_write, remote_channel_id, remote_url,
                peer_channel_flags, peer_channel_id, addable_access_tokens)

    async def create_server_peer_channel_messages_async(self,
            rows: list[ServerPeerChannelMessageRow]) -> list[ServerPeerChannelMessageRow]:
        return await self._db_context.run_in_thread_async(
            db_functions.create_server_peer_channel_messages_write, rows)

    async def read_server_peer_channel_messages_async(self,
            message_flags: Optional[PeerChannelMessageFlag]=None,
            message_mask: Optional[PeerChannelMessageFlag]=None,
            channel_flags: Optional[ServerPeerChannelFlag]=None,
            channel_mask: Optional[ServerPeerChannelFlag]=None) \
                -> list[ServerPeerChannelMessageRow]:
        return db_functions.read_server_peer_channel_messages(self._db_context, message_flags,
            message_mask, channel_flags, channel_mask)

    # Pushdata hashes.

    async def create_pushdata_matches_async(self, rows: list[PushDataMatchRow],
            processed_message_ids: list[int]) -> None:
        await self._db_context.run_in_thread_async(
            db_functions.create_pushdata_matches_write, rows, processed_message_ids)

    def read_pushdata_match_metadata(self, for_missing_transactions: bool=False) \
            -> list[PushDataMatchMetadataRow]:
        return db_functions.read_pushdata_match_metadata(self._db_context, for_missing_transactions)

    # Script hashes.

    def create_keyinstance_scripts(self, entries: Iterable[KeyInstanceScriptHashRow]) \
            -> concurrent.futures.Future[None]:
        return db_functions.create_keyinstance_scripts(self._db_context, entries)

    def read_keyinstance_scripts_by_id(self, keyinstance_ids: list[int]) \
            -> list[KeyInstanceScriptHashRow]:
        return db_functions.read_keyinstance_scripts_by_id(self._db_context,
            keyinstance_ids)

    # Tip filters.

    async def create_tip_filter_pushdata_registrations_async(self,
            rows: list[PushDataHashRegistrationRow], upsert: bool=False) -> None:
        return await self._db_context.run_in_thread_async(
            db_functions.create_tip_filter_pushdata_registrations_write, rows, upsert)

    async def delete_registered_tip_filter_pushdatas_async(self,
            rows: list[tuple[int, int]]) -> None:
        return await self._db_context.run_in_thread_async(
            db_functions.delete_registered_tip_filter_pushdatas_write, rows)

    def read_tip_filter_pushdata_registrations(self, server_id: int,
            expiry_timestamp: Optional[int]=None,
            flags: Optional[PushDataHashRegistrationFlag]=None,
            mask: Optional[PushDataHashRegistrationFlag]=None) -> list[PushDataHashRegistrationRow]:
        return db_functions.read_tip_filter_pushdata_registrations(self._db_context, server_id,
            expiry_timestamp, flags, mask)

    def read_unregistered_tip_filter_pushdatas(self) -> list[tuple[bytes, int, int]]:
        """
        Returns [ (pushdata_hash, duration_seconds, keyinstance_id), ... ]
        """
        return db_functions.read_unregistered_tip_filter_pushdatas(self._db_context)

    async def update_registered_tip_filter_pushdatas_async(self,
            rows: list[tuple[int, int, int, int, int, int]]) -> None:
        """
        rows = [ (date_registered, date_updated, flags_mask, flags_flag, server_id,
            keyinstance_id), ... ]
        """
        return await self._db_context.run_in_thread_async(
            db_functions.update_registered_tip_filter_pushdatas_write, rows)

    async def update_registered_tip_filter_pushdatas_flags_async(self,
            rows: list[tuple[int, int, int, int]]) -> None:
        """
        rows = [ (pushdata_flags, date_updated, server_id, keyinstance_id), ... ]
        """
        return await self._db_context.run_in_thread_async(
            db_functions.update_registered_tip_filter_pushdatas_flags_write, rows)

    # Transactions.

    def get_transaction_deltas(self, tx_hash: bytes, account_id: Optional[int]=None) \
            -> list[TransactionDeltaSumRow]:
        return db_functions.read_transaction_values(self._db_context, tx_hash, account_id)

    def get_transaction_flags(self, tx_hash: bytes) -> Optional[TxFlags]:
        return db_functions.read_transaction_flags(self._db_context, tx_hash)

    def get_transaction_metadata(self, tx_hash: bytes) -> Optional[TransactionMetadata]:
        return db_functions.read_transaction_metadata(self._db_context, tx_hash)

    def read_unconnected_merkle_proofs(self) -> list[MerkleProofRow]:
        return db_functions.read_unconnected_merkle_proofs(self._db_context)

    def read_transaction_value_entries(self, account_id: int, *,
            tx_hashes: Optional[list[bytes]]=None, mask: Optional[TxFlags]=None) \
                -> list[TransactionValueRow]:
        return db_functions.read_transaction_value_entries(self._db_context, account_id,
            tx_hashes=tx_hashes, mask=mask)

    def read_transactions_exist(self, tx_hashes: Sequence[bytes], account_id: Optional[int]=None) \
            -> list[TransactionExistsRow]:
        return db_functions.read_transactions_exist(self._db_context, tx_hashes, account_id)

    async def set_transaction_state_async(self, tx_hash: bytes, flag: TxFlags,
            ignore_mask: Optional[TxFlags]=None) -> bool:
        return await self._db_context.run_in_thread_async(
            db_functions.set_transaction_state_write, tx_hash, flag, ignore_mask)

    async def update_reorged_transactions_async(self, orphaned_block_hashes: list[bytes]) \
            -> list[bytes]:
        return await self._db_context.run_in_thread_async(
            db_functions.update_reorged_transactions_write, orphaned_block_hashes)

    async def update_transaction_flags_async(self, entries: list[tuple[TxFlags, TxFlags, bytes]]) \
            -> int:
        return await self._db_context.run_in_thread_async(
            db_functions.update_transaction_flags_write, entries)

    async def update_transaction_proof_async(self, tx_update_rows: list[TransactionProofUpdateRow],
            proof_rows: list[MerkleProofRow], proof_update_rows: list[MerkleProofUpdateRow],
            processed_message_ids: list[int]) -> None:
        return await self._db_context.run_in_thread_async(
            db_functions.update_transaction_proof_write, tx_update_rows, proof_rows,
                proof_update_rows, processed_message_ids)

    async def update_transaction_proofs_and_flags(self,
            tx_update_rows: list[TransactionProofUpdateRow],
            flag_entries: list[tuple[TxFlags, TxFlags, bytes]]) -> None:
        await self._db_context.run_in_thread_async(
            db_functions.update_transaction_proof_and_flag_write, tx_update_rows, flag_entries)

    # Transaction outputs.

    def read_account_transaction_outputs_with_key_data(self, account_id: int,
            confirmed_only: bool=False, exclude_immature: bool=False,
            exclude_frozen: bool=False, keyinstance_ids: Optional[list[int]]=None) \
                -> list[AccountTransactionOutputSpendableRow]:
        return db_functions.read_account_transaction_outputs_with_key_data(
            self._db_context, account_id, confirmed_only, exclude_immature,
            exclude_frozen, keyinstance_ids)

    def read_account_transaction_outputs_with_key_and_tx_data(self, account_id: int,
            confirmed_only: bool=False, mature_height: Optional[int]=None,
            exclude_frozen: bool=False, keyinstance_ids: Optional[list[int]]=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        return db_functions.read_account_transaction_outputs_with_key_and_tx_data(
            self._db_context, account_id, confirmed_only, mature_height,
                exclude_frozen, keyinstance_ids)

    def read_spent_outputs_to_monitor(self) -> list[OutputSpend]:
        return db_functions.read_spent_outputs_to_monitor(self._db_context)

    def read_existing_output_spends(self, outpoints: list[Outpoint]) -> list[SpentOutputRow]:
        return db_functions.read_existing_output_spends(self._db_context, outpoints)

    def read_transaction_outputs_with_key_data(self, *, account_id: Optional[int]=None,
            tx_hash: Optional[bytes]=None, txo_keys: Optional[list[Outpoint]]=None,
            derivation_data2s: Optional[list[bytes]]=None, require_keys: bool=False) \
                -> list[TransactionOutputSpendableRow]:
        return db_functions.read_transaction_outputs_with_key_data(self._db_context,
            account_id=account_id, tx_hash=tx_hash, txo_keys=txo_keys,
            derivation_data2s=derivation_data2s, require_keys=require_keys)

    def get_transaction_outputs_short(self, l: list[Outpoint]) \
            -> list[TransactionOutputShortRow]:
        return db_functions.read_transaction_outputs_explicit(self._db_context, l)

    def update_transaction_output_flags(self, txo_keys: list[Outpoint],
            flags: TransactionOutputFlag, mask: Optional[TransactionOutputFlag]=None) \
                -> concurrent.futures.Future[bool]:
        return db_functions.update_transaction_output_flags(self._db_context,
            txo_keys, flags, mask)

    # Wallet events.

    def create_wallet_events(self,  rows: list[WalletEventInsertRow]) \
            -> concurrent.futures.Future[list[WalletEventRow]]:
        def callback(future: concurrent.futures.Future[list[WalletEventRow]]) -> None:
            if future.cancelled():
                return
            rows = future.result()
            self.events.trigger_callback(WalletEvent.NOTIFICATIONS_CREATE, rows)

        future = db_functions.create_wallet_events(self._db_context, rows)
        future.add_done_callback(callback)
        return future

    def read_wallet_events(self, account_id: Optional[int]=None,
            mask: WalletEventFlag=WalletEventFlag.NONE) -> list[WalletEventRow]:
        return db_functions.read_wallet_events(self._db_context, account_id=account_id,
            mask=mask)

    def update_wallet_event_flags(self, entries: Iterable[tuple[WalletEventFlag, int]]) \
            -> concurrent.futures.Future[None]:
        def callback(future: concurrent.futures.Future[None]) -> None:
            if future.cancelled():
                return
            future.result()
            self.events.trigger_callback(WalletEvent.NOTIFICATIONS_UPDATE, entries)

        future = db_functions.update_wallet_event_flags(self._db_context, entries)
        future.add_done_callback(callback)
        return future


class Wallet:
    """
    This represents a loaded wallet and manages both data and network access for it.
    """

    _network: Optional[Network] = None
    _stopped = False
    _stopping = False

    _persisted_tip_hash: Optional[bytes] = None
    _current_chain: Optional[Chain] = None
    _current_tip_header: Optional[Header] = None
    _blockchain_server_state: Optional[HeaderServerState] = None
    _blockchain_server_state_ready: bool = False

    def __init__(self, storage: WalletStorage, password: Optional[str]=None) -> None:
        self._id = random.randint(0, (1<<32)-1)

        self._storage = storage
        self._logger = logs.get_logger(f"wallet[{self.name()}]")

        # NOTE The wallet abstracts all database access. The database context should not be
        # used outside of the `Wallet` object.
        self._db_context = storage.get_db_context()
        assert self._db_context is not None

        self.events = TriggeredCallbacks[WalletEvent]()
        self.data = WalletDataAccess(self._db_context, self.events)
        self._servers = dict[ServerAccountKey, NewServer]()
        self._server_progress = dict[int, ServerProgress]()

        self.db_functions_async = db_functions.AsynchronousFunctions(self._db_context)

        txdata_cache_size = self.get_cache_size_for_tx_bytedata() * (1024 * 1024)
        self._transaction_cache2 = LRUCache(max_size=txdata_cache_size)

        self._masterkey_rows: dict[int, MasterKeyRow] = {}
        self._account_rows: dict[int, AccountRow] = {}

        self._accounts: dict[int, AbstractAccount] = {}
        self._keystores: dict[int, KeyStore] = {}
        self._wallet_master_keystore: Optional[BIP32_KeyStore] = None

        self._missing_transactions: dict[bytes, MissingTransactionEntry] = {}

        self._fee_quote_lock = asyncio.Lock()

        ## State related to the wallet processing headers from it's header source.
        self._header_source_synchronised_event = asyncio.Event()
        self._start_chain_management_event = asyncio.Event()

        # It is possible that the wallet receives merkle proofs that it cannot process because
        # they are either not within the wallet's view of the blockchain (or in the more extreme
        # case are for a disconnected header).
        self._connect_headerless_proof_worker_state = ConnectHeaderlessProofWorkerState(
            asyncio.Event(), asyncio.Event(), asyncio.Queue(), asyncio.Queue(), {})

        # Guards the obtaining and processing of missing transactions from race conditions.
        self._obtain_transactions_async_lock = app_state.async_.lock()
        self._worker_startup_reorg_check: concurrent.futures.Future[None] | None = None
        self._worker_task_initialise_headers: concurrent.futures.Future[None] | None = None
        self._worker_task_manage_server_connections: concurrent.futures.Future[None] | None = None
        self._worker_task_manage_dpp_connections: Optional[concurrent.futures.Future[None]] = None
        self._worker_tasks_maintain_server_connection = dict[int, list[ServerConnectionState]]()
        self._worker_task_chain_management: concurrent.futures.Future[None] | None = None
        self._worker_task_obtain_transactions: concurrent.futures.Future[None] | None = None
        self._worker_task_obtain_merkle_proofs: concurrent.futures.Future[None] | None = None
        self._worker_task_connect_headerless_proofs: concurrent.futures.Future[None] | None = None

        self.dpp_proxy_server_states: list[ServerConnectionState] = []  # for task cancellation

        ## ...
        # Guards `transaction_locks`.
        self._transaction_lock = threading.RLock()
        # Guards per-transaction locks to limit blocking to per-transaction activity.
        self._transaction_locks: dict[bytes, tuple[threading.RLock, int]] = {}

        self.load_state()

        self.contacts = Contacts(self._storage)

        # These are transactions the wallet has decided it needs that we will fetch and process in
        # the background.
        self._check_missing_transactions_event = asyncio.Event()
        # This locates transactions that we have, expect proofs to be available for, but do not
        # have the proof.
        self._check_missing_proofs_event = asyncio.Event()
        self._new_server_connection_event = asyncio.Event()
        self.progress_event = asyncio.Event()

        # When ElectrumSV is asked to open a wallet it first requests the password and verifies
        # it is correct for the wallet. Then it does the separate open operation and did not
        # require the password. However, we have since added encrypted wallet data that needs
        # to be read and cached. We expect the password to still be in the credential cache
        # given we just did that verification.
        if password is None:
            password = app_state.credentials.get_wallet_password(self._storage.get_path())
            assert password is not None, "Expected cached wallet password"

        self._cache_identity_keys(password)
        self._load_servers(password)

    def __str__(self) -> str:
        return f"wallet(path='{self._storage.get_path()}')"

    def get_id(self) -> int:
        return self._id

    def get_db_context(self) -> DatabaseContext:
        assert self._db_context is not None, "This wallet does not have a database context"
        return self._db_context

    def get_db_context_ref(self) -> weakref.WeakMethod[Callable[[], DatabaseContext]]:
        """
        In order to avoid passing around either a database context or proxying database calls
        through the wallet, we pass this `weakref.ref` to wallet function that returns it's
        database context. This requires the recipient to do a `f = callback(); db_context = f()`
        to try and get the database context. We can revisit it later if we have better ideas.
        This is not a reference to the context itself, but to the function that returns it.
        """
        return weakref.WeakMethod(self.get_db_context)

    def move_to(self, new_path: str) -> None:
        self._db_context = None
        self._storage.move_to(new_path)
        self._db_context = cast(DatabaseContext, self._storage.get_db_context())

    def load_state(self) -> None:
        if self._db_context is None:
            return

        assert app_state.headers is not None

        # NOTE: This used to be stored but not used as `last_tip_hash` but the logic was broken and
        #     used reversed hashes for persistence and non-reversed hashes for loading. This means
        #     that all the historically saved values are useless.
        last_known_tip_id = self._storage.get_explicit_type(str, "current_tip_hash",
            None)
        if last_known_tip_id is not None:
            last_known_tip_hash = hex_str_to_hash(last_known_tip_id)
        else:
            last_known_tip_hash = None
        self._persisted_tip_hash = last_known_tip_hash

        self._logger.debug("Existing persisted chain is %s",
            hash_to_hex_str(last_known_tip_hash) if last_known_tip_hash is not None else None)

        self._keystores.clear()
        self._accounts.clear()
        self._wallet_master_keystore = None

        masterkey_rows = db_functions.read_masterkeys(self.get_db_context())
        # Create the keystores for masterkeys without parent masterkeys first.
        for mk_row in sorted(masterkey_rows,
                key=lambda t: 0 if t.parent_masterkey_id is None else t.parent_masterkey_id):
            keystore = self._realize_keystore(mk_row)
            if mk_row.flags & MasterKeyFlags.WALLET_SEED:
                self._wallet_master_keystore = cast(BIP32_KeyStore, keystore)
        assert self._wallet_master_keystore is not None, "migration 29 master keystore missing"

        account_flags = dict[int, AccountInstantiationFlags]()
        keyinstances_by_account_id = dict[int, list[KeyInstanceRow]]()
        # TODO Avoid reading in all the keyinstances we are not interested in.
        for keyinstance_row in self.data.read_keyinstances():
            if keyinstance_row.derivation_type == DerivationType.PRIVATE_KEY:
                if keyinstance_row.account_id not in keyinstances_by_account_id:
                    if keyinstance_row.account_id not in account_flags:
                        account_flags[keyinstance_row.account_id] \
                            = AccountInstantiationFlags.IMPORTED_PRIVATE_KEYS
                    else:
                        account_flags[keyinstance_row.account_id] |= \
                            AccountInstantiationFlags.IMPORTED_PRIVATE_KEYS
                    keyinstances_by_account_id[keyinstance_row.account_id] = []
                keyinstances_by_account_id[keyinstance_row.account_id].append(keyinstance_row)
            elif keyinstance_row.derivation_type in ADDRESS_TYPES:
                if keyinstance_row.account_id not in account_flags:
                    account_flags[keyinstance_row.account_id] \
                        = AccountInstantiationFlags.IMPORTED_ADDRESSES
                else:
                    account_flags[keyinstance_row.account_id] |= \
                        AccountInstantiationFlags.IMPORTED_ADDRESSES

        for account_row in db_functions.read_accounts(self.get_db_context()):
            account = self._instantiate_account(account_row,
                account_flags.get(account_row.account_id, AccountInstantiationFlags.NONE))
            if account.type() == AccountType.IMPORTED_PRIVATE_KEY:
                keyinstance_rows = keyinstances_by_account_id[account_row.account_id]
                assert keyinstance_rows
                cast(ImportedPrivkeyAccount, account).set_initial_state(keyinstance_rows)
            if account.is_petty_cash():
                self._petty_cash_account = account

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
            -> tuple[concurrent.futures.Future[PasswordUpdateResult], threading.Event]:
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

        # There is no way to say "let me know when this future is complete and all the done
        # events are also complete." So we use this event for that purpose.
        completion_event = threading.Event()

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

            completion_event.set()

        future = db_functions.update_password(self.get_db_context(), old_password, new_password)
        future.add_done_callback(update_cached_values)
        return future, completion_event

    def get_account(self, account_id: int) -> Optional[AbstractAccount]:
        return self._accounts.get(account_id)

    def get_accounts_for_keystore(self, keystore: KeyStore) -> list[AbstractAccount]:
        accounts = []
        for account in self.get_accounts():
            account_keystore = account.get_keystore()
            if keystore is account_keystore:
                accounts.append(account)
        return accounts

    def get_account_ids(self) -> set[int]:
        return set(self._accounts)

    def get_accounts(self) -> list[AbstractAccount]:
        return list(self._accounts.values())

    # NOTE(petty-cash) We do not show the petty cash account for now. We do not have
    #     micro-payment support in the servers or the wallet itself yet.
    def get_visible_accounts(self) -> list[AbstractAccount]:
        return [ account for account in self._accounts.values() if not account.is_petty_cash() ]

    def get_xpubs_by_fingerprint(self) -> dict[bytes, str]:
        bip32_keystores: list[BIP32_KeyStore] = []
        for account in self._accounts.values():
            if account.type() == AccountType.STANDARD:
                standard_account = cast(StandardAccount, account)
                keystore = standard_account.get_keystore()
                if isinstance(keystore, BIP32_KeyStore):
                    bip32_keystores.append(keystore)
            elif account.type() == AccountType.MULTISIG:
                multisig_account = cast(MultisigAccount, account)
                for keystore in multisig_account.get_keystores():
                    if isinstance(keystore, BIP32_KeyStore):
                        bip32_keystores.append(keystore)

        xpub_by_fingerprint: dict[bytes, str] = {}
        for bip32_keystore in bip32_keystores:
            xpub = bip32_keystore.get_master_public_key()
            assert xpub is not None
            xpub_by_fingerprint[bip32_keystore.get_fingerprint()] = xpub
        return xpub_by_fingerprint

    def get_default_account(self) -> Optional[AbstractAccount]:
        if len(self._accounts):
            return list(self._accounts.values())[0]
        return None

    def _realize_keystore(self, row: MasterKeyRow) -> KeyStore:
        data = cast(MasterKeyDataTypes, json.loads(row.derivation_data))
        parent_keystore: Optional[KeyStore] = None
        if row.parent_masterkey_id is not None:
            parent_keystore = self._keystores[row.parent_masterkey_id]
        keystore = instantiate_keystore(row.derivation_type, data, parent_keystore, row)
        self._keystores[row.masterkey_id] = keystore
        self._masterkey_rows[row.masterkey_id] = row
        return keystore

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

        date_created = get_posix_timestamp()
        future = self.data.create_wallet_events([
            WalletEventInsertRow(WalletEventType.SEED_BACKUP_REMINDER, account_row.account_id,
                WalletEventFlag.FEATURED | WalletEventFlag.UNREAD, date_created, date_created)
        ])
        # The wallet UI needs to find this in the database after the account is created, but
        # was actually proceeding before the database operation completed. This is why we
        # originally blocked here waiting for the account creation/notification insert. There
        # may be other reasons now that rely on this, and all calling contexts would need to be
        # explored to remove it.
        future.result()

        self.events.trigger_callback(WalletEvent.ACCOUNT_CREATE, account_row.account_id, flags)
        if self._network is not None:
            account.start(self._network)
        return account

    # Accounts.

    def _preallocate_account_id(self) -> int:
        """
        Sometimes we need an account id to refer to before we create the account.
        `add_accounts` will respect this being pre-provided and not allocate a new one as it does
        otherwise.
        """
        account_id = cast(int, self._storage.get("next_account_id", 1))
        self._storage.put("next_account_id", account_id + 1)
        return account_id

    def add_accounts(self, entries: list[AccountRow]) -> list[AccountRow]:
        account_id = initial_account_id = self._storage.get("next_account_id", 1)
        rows = entries[:]
        for i, row in enumerate(rows):
            if row.account_id < 1:
                rows[i] = row._replace(account_id=account_id)
                account_id += 1
        if account_id != initial_account_id:
            self._storage.put("next_account_id", account_id)

        future = db_functions.create_accounts(self.get_db_context(), rows)
        future.result()
        return rows

    # Called by `account_wizard.py:AddAccountWizardPage._create_new_account` to create new
    # standard accounts which are now derived from the wallet seed.
    def derive_child_keystore(self, for_account: bool=False,
            password: Optional[str]=None) -> KeyStoreResult:
        if for_account:
            assert password is not None, "this code path should always have a password"
            assert self._wallet_master_keystore is not None
            preallocated_account_id = self._preallocate_account_id()
            derivation_text = f"{WALLET_ACCOUNT_PATH_TEXT}/{preallocated_account_id}'"
            derivation_path: DerivationPath = tuple(bip32_decompose_chain_string(derivation_text))
            private_key = cast(BIP32PrivateKey,
                self._wallet_master_keystore.get_private_key(derivation_path, password))
            encrypted_xprv = pw_encode(private_key.to_extended_key_string(), password)
            derivation_data: MasterKeyDataBIP32 = {
                "seed": None,
                "label": None,
                "passphrase": None,
                "xpub": private_key.public_key.to_extended_key_string(),
                "derivation": derivation_text,
                "xprv": encrypted_xprv,
            }
            keystore = BIP32_KeyStore(derivation_data,
                parent_keystore=self._wallet_master_keystore)
            return KeyStoreResult(AccountCreationType.NEW, keystore, preallocated_account_id)
        raise NotImplementedError

    def create_account_from_keystore(self, keystore_result: KeyStoreResult) -> AbstractAccount:
        assert keystore_result.keystore is not None
        masterkey_row = self.create_masterkey_from_keystore(keystore_result.keystore)
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
            account_name = keystore_result.keystore.label or "Hardware wallet"
            script_type = ScriptType.P2PKH
        else:
            raise WalletLoadError(f"Unhandled derivation type {masterkey_row.derivation_type}")

        creation_flags = AccountInstantiationFlags.NONE
        if keystore_result.account_creation_type == AccountCreationType.NEW:
            creation_flags |= AccountInstantiationFlags.NEW

        basic_row = AccountRow(keystore_result.account_id, masterkey_row.masterkey_id, script_type,
            account_name, AccountFlags.NONE, None, None)
        rows = self.add_accounts([ basic_row ])
        return self._create_account_from_data(rows[0], creation_flags)

    def create_account_from_text_entries(self, text_type: KeystoreTextType,
            entries: set[str], password: str) -> AbstractAccount:
        raw_keyinstance_rows: list[KeyInstanceRow] = []

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

        basic_account_row = AccountRow(-1, None, script_type, account_name, AccountFlags.NONE,
            None, None)
        account_row = self.add_accounts([ basic_account_row ])[0]
        account = self._create_account_from_data(account_row, account_flags)

        keyinstance_future, scripthash_future, keyinstance_rows, scripthash_rows = \
            account.create_provided_keyinstances(raw_keyinstance_rows)

        if account.type() == AccountType.IMPORTED_PRIVATE_KEY:
            cast(ImportedPrivkeyAccount, account).set_initial_state(keyinstance_rows)

        return account

    # Key instances.

    def create_keyinstances(self, account_id: int, entries: list[KeyInstanceRow]) \
            -> tuple[concurrent.futures.Future[None], list[KeyInstanceRow]]:
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
            self.events.trigger_callback(WalletEvent.KEYS_CREATE, account_id, keyinstance_ids)
        future.add_done_callback(callback)
        return future, rows

    def get_next_derivation_index(self, account_id: int, masterkey_id: int,
            derivation_subpath: DerivationPath) -> int:
        last_index = db_functions.read_keyinstance_derivation_index_last(
            self.get_db_context(), account_id, masterkey_id, derivation_subpath)
        if last_index is None:
            return 0
        return last_index + 1

    # Master keys.

    def add_masterkeys(self, entries: list[MasterKeyRow]) -> list[MasterKeyRow]:
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

    def create_payment_requests(self, account_id: int, requests: list[PaymentRequestRow]) \
            -> concurrent.futures.Future[list[PaymentRequestRow]]:
        def callback(callback_future: concurrent.futures.Future[list[PaymentRequestRow]]) -> None:
            """
            After the payment requests have been successfully written to the database.
            """
            if callback_future.cancelled():
                return
            created_rows = callback_future.result()
            updated_keyinstance_ids = [ row.keyinstance_id for row in created_rows ]
            self.events.trigger_callback(WalletEvent.KEYS_UPDATE, account_id,
                updated_keyinstance_ids)

        request_id = self._storage.get("next_paymentrequest_id", 1)
        rows: list[PaymentRequestRow] = []
        for request in requests:
            rows.append(request._replace(paymentrequest_id=request_id))
            request_id += 1
        self._storage.put("next_paymentrequest_id", request_id)

        future = db_functions.create_payment_requests(self.get_db_context(), rows)
        future.add_done_callback(callback)
        return future

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
                pass
                # This payment request was the only reason the key was active and being monitored
                # on the blockchain server for new transactions. We can now delete the subscription.
                # TODO(1.4.0) Payment requests, issue#911. When the user closes/deletes a payment
                #     request we need to clean up all resources allocated when the request was
                #     created. This would include the tip filter.
                pass

            self.events.trigger_callback(WalletEvent.KEYS_UPDATE, account_id, [ keyinstance_id ])

        future = db_functions.delete_payment_request(self.get_db_context(), request_id,
            keyinstance_id)
        future.add_done_callback(callback)
        return future

    async def fetch_raw_transaction_async(self, tx_hash: bytes, account: AbstractAccount) -> bytes:
        """Selects a suitable server and requests the raw transaction.

        Raises `ServerConnectionError` if the remote server is not online (and other networking
            problems).
        Raises `GeneralAPIError` if a connection was established but the request errored.
        """
        # TODO(petty-cash). We intercept this call because the wallet will be funding it
        #     via the petty cash account. Therefore we need to wrap the call to apply the checks
        #     and handling
        state = self.get_connection_state_for_usage(NetworkServerFlag.USE_BLOCKCHAIN)
        assert state is not None
        return await request_transaction_data_async(state, tx_hash)

    def get_credential_id_for_server_key(self, key: ServerAccountKey) \
            -> Optional[IndefiniteCredentialId]:
        return self._registered_api_keys.get(key)

    def update_network_servers(self, added_server_rows: list[NetworkServerRow],
            updated_server_rows: list[NetworkServerRow],
            deleted_server_keys: list[ServerAccountKey], updated_api_keys: dict[ServerAccountKey,
                tuple[Optional[str], Optional[tuple[str, str]]]]) \
                    -> concurrent.futures.Future[list[NetworkServerRow]]:
        """
        Update the database, wallet and network for the given set of network server changes.

        These benefit from being packaged together because they can be updated in a database
        transaction, and then the network and wallet usage of this information can be updated
        on a successful database update. If the database update fails, then no changes should
        be applied.
        """
        def update_cached_values(future: concurrent.futures.Future[list[NetworkServerRow]]) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            created_rows = future.result()

            credential_id: Optional[IndefiniteCredentialId] = None
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

            updated_states: list[tuple[NetworkServerRow, Optional[IndefiniteCredentialId]]] = []

            for server_row in created_rows:
                assert server_row.server_id is not None
                server_key = ServerAccountKey.from_row(server_row)
                credential_id = self._registered_api_keys.get(server_key)
                updated_states.append((server_row, credential_id))

                # Create the base server for the wallet.
                if server_row.account_id is None:
                    assert server_key not in self._servers
                    self._servers[server_key] = NewServer(server_key.url, server_key.server_type,
                        server_row, credential_id)

            for server_row in updated_server_rows:
                assert server_row.server_id is not None
                server_key = ServerAccountKey.from_row(server_row)
                updated_states.append((server_row, self._registered_api_keys.get(server_key)))

            for server_row, credential_id in updated_states:
                base_server_key = ServerAccountKey(server_row.url, server_row.server_type, None)
                self._servers[base_server_key].set_server_account_usage(server_row, credential_id)

            for specific_server_key in deleted_server_keys:
                server = self._servers[specific_server_key.to_base_key()]
                server.clear_server_account_usage(specific_server_key)

        # The `added_server_rows` do not yet have an assigned primary key value, and are not
        # representative of the actual added rows.
        future = self.data.update_network_servers_transaction(added_server_rows,
            updated_server_rows, [], deleted_server_keys)
        # We do not update the data used by the wallet and network unless the database update
        # successfully applies. There is likely no reason it won't, outside of programmer error.
        future.add_done_callback(update_cached_values)
        return future

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

            if len(input.x_pubkeys) > 0:
                x_pubkey = list(input.x_pubkeys.values())[0]
                data = x_pubkey.get_derivation_data()
                if data is not None:
                    tx_context.key_datas_by_spent_outpoint[outpoint] = data

            parent_tx = tx_context.parent_transactions.get(input.prev_hash)
            if parent_tx:
                tx_context.spent_outpoint_values[outpoint] = parent_tx.outputs[input.prev_idx].value

        for txo_index, output in enumerate(tx.outputs):
            if len(output.x_pubkeys):
                data = list(output.x_pubkeys.values())[0].get_derivation_data()
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
                assert data1.derivation_path == data2.derivation_path, (data1.derivation_path,
                    data2.derivation_path)
            if data1.account_id is not None:
                assert data1.account_id == data2.account_id, (data1.account_id, data2.account_id)
            if data1.masterkey_id is not None:
                assert data1.masterkey_id == data2.masterkey_id, (data1.masterkey_id,
                    data2.masterkey_id)
            if data1.keyinstance_id is not None:
                assert data1.keyinstance_id == data2.keyinstance_id, (data1.keyinstance_id,
                    data2.keyinstance_id)

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
                database_data = DatabaseKeyDerivationData.from_key_data(
                    cast(KeyDataProtocol, txo_row),
                    DatabaseKeyDerivationType.EXTENSION_LINKED)
                outpoint = Outpoint(txo_row.tx_hash, txo_row.txo_index)
                self.sanity_check_derivation_key_data(
                    tx_context.key_datas_by_spent_outpoint.get(outpoint), database_data)
                tx_context.key_datas_by_spent_outpoint[outpoint] = database_data
                tx_context.spent_outpoint_values[outpoint] = txo_row.value

            for txo_row in db_functions.read_transaction_outputs_with_key_data(
                    self.get_db_context(), tx_hash=tx_hash, require_keys=True):
                found_in_database = True
                database_data = DatabaseKeyDerivationData.from_key_data(
                    cast(KeyDataProtocol, txo_row),
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
            all_outpoints = [ Outpoint(input.prev_hash, input.prev_idx) for input in tx.inputs ]
            for txo_row in db_functions.read_transaction_outputs_with_key_data(
                    self.get_db_context(), txo_keys=all_outpoints):
                database_data = DatabaseKeyDerivationData.from_key_data(
                    cast(KeyDataProtocol, txo_row),
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
        txo_indexes_by_script_hash = dict[bytes, list[int]]()
        script_hashes_by_keyinstance_id = dict[int, set[bytes]]()

        output: XTxOutput
        for txo_index, output in enumerate(tx.outputs):
            database_data = tx_context.key_datas_by_txo_index.get(txo_index)
            if database_data and database_data.source >= DatabaseKeyDerivationType.EXTENSION_LINKED:
                continue
            if txo_index in tx_context.key_datas_by_txo_index and not skip_existing:
                continue
            script_hash = scripthash_bytes(output.script_pubkey)
            if script_hash in txo_indexes_by_script_hash:
                txo_indexes_by_script_hash[script_hash].append(txo_index)
            else:
                txo_indexes_by_script_hash[script_hash] = [ txo_index ]

        script_hashes = list(txo_indexes_by_script_hash)
        for script_row in db_functions.read_keyinstance_scripts_by_hash(self.get_db_context(),
                script_hashes):
            if script_row.keyinstance_id in script_hashes_by_keyinstance_id:
                script_hashes_by_keyinstance_id[script_row.keyinstance_id].add(
                    script_row.script_hash)
            else:
                script_hashes_by_keyinstance_id[script_row.keyinstance_id] \
                    = { script_row.script_hash }

        if not script_hashes_by_keyinstance_id:
            return

        for keyinstance_row in db_functions.read_keyinstances(self.get_db_context(),
                keyinstance_ids=list(script_hashes_by_keyinstance_id)):
            database_data = DatabaseKeyDerivationData.from_key_data(
                cast(KeyDataProtocol, keyinstance_row),
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
        input_data_by_script_hash: dict[bytes, Outpoint] = {}
        output_data_by_script_hash: dict[bytes, int] = {}

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

    def load_transaction_from_bytes(self, data: bytes) \
            -> tuple[Transaction | None, TransactionContext | None]:
        """
        Loads a transaction using given transaction data.

        If the transaction is already in the cache, it will return that transaction.
        If the transaction is in the database, this will load it in extended form and cache it.
        Otherwise the transaction data will be parsed, loaded in extended form and cached.

        Raises `ValueError` if the text is not found to contain viable transaction data.
        """
        if not data:
            return None, None

        context: TransactionContext | None = None
        if data.startswith(b"psbt\xff"):
            # Bitcoin Core compatible partial transactions.
            from .standards.psbt import parse_psbt_bytes
            psbt_data = parse_psbt_bytes(data, self.get_xpubs_by_fingerprint())
            tx = psbt_data.transaction
            if tx is None or not tx.is_complete():
                return tx, context

            tx_hash = tx.hash()
        elif data.startswith(b"{"):
            # Legacy ElectrumSV partial transactions.
            txdict = tx_dict_from_text(data.decode())
            tx, context = transaction_from_electrumsv_dict(txdict, self.get_accounts())
            if not tx.is_complete():
                return tx, context

            tx_hash = tx.hash()
        else:
            tx_hash = double_sha256(data)

        lock = self._obtain_transaction_lock(tx_hash)
        with lock:
            try:
                # Get it if cached in memory / load from database if present.
                tx = self._get_cached_transaction(tx_hash)
                if tx is not None:
                    return tx, context

                # Parse the transaction data.
                tx = Transaction.from_bytes(data)
                self._transaction_cache2.set(tx_hash, tx)
            finally:
                self._relinquish_transaction_lock(tx_hash)

        return tx, context

    async def add_local_transaction(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            block_height: int, block_hash: Optional[bytes]=None, block_position: Optional[int]=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) -> None:
        """
        This is currently only called when an account constructs and signs a transaction

        Raises:
        - `TransactionAlreadyExistsError` if the transaction is already in the wallet database.
        - `DatabaseUpdateError` if there are spend conflicts and the transaction was rolled back.
        """
        link_state = TransactionLinkState()
        link_state.rollback_on_spend_conflict = True
        await self._import_transaction(tx_hash, tx, flags, block_height, block_hash, block_position,
            link_state, import_flags=import_flags)

    async def import_transaction_async(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            block_height: int, block_hash: Optional[bytes]=None, block_position: Optional[int]=None,
            link_state: Optional[TransactionLinkState]=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET,
            proof_row: Optional[MerkleProofRow]=None) -> None:
        """
        This is currently only called when a missing transaction arrives.

        Note that a new transaction is imported as state cleared even if we know it has been
        mined through the `block_height` and `block_hash` values. It is not changed to state
        settled until we have obtained the merkle proof.

        Raises:
        - `TransactionAlreadyExistsError` if the transaction is already in the wallet database.
        - `DatabaseUpdateError` if the link state indicated that there should be a rollback if
            there were spend conflicts and this has happened.
        """
        # If there is a missing transaction entry it is almost certain that the indexer monitoring
        # detected, obtained and is importing the transaction.
        missing_entry = self._missing_transactions.get(tx_hash)
        if missing_entry is not None:
            import_flags |= missing_entry.import_flags

        if link_state is None:
            link_state = TransactionLinkState()
        await self._import_transaction(tx_hash, tx, flags, block_height, block_hash,
            block_position, link_state, import_flags=import_flags, proof_row=proof_row)

    async def _import_transaction(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            block_height: int, block_hash: Optional[bytes], block_position: Optional[int],
            link_state: TransactionLinkState,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET,
            proof_row: Optional[MerkleProofRow]=None) -> None:
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
        tx_row = TransactionRow(tx_hash, tx.to_bytes(), flags, block_hash, block_height,
            block_position, fee_value=None, description=None, version=tx.version,
            locktime=tx.locktime, date_created=timestamp, date_updated=timestamp)

        txi_rows: list[TransactionInputAddRow] = []
        for txi_index, input in enumerate(tx.inputs):
            txi_row = TransactionInputAddRow(tx_hash, txi_index,
                input.prev_hash, input.prev_idx, input.sequence,
                TransactionInputFlag.NONE,
                input.script_offset, input.script_length,
                timestamp, timestamp)
            txi_rows.append(txi_row)

        txo_rows: list[TransactionOutputAddRow] = []
        for txo_index, txo in enumerate(tx.outputs):
            txo_row = TransactionOutputAddRow(tx_hash, txo_index, txo.value,
                None,                           # Raw transaction means no idea of key usage.
                ScriptType.NONE,                # Raw transaction means no idea of script type.
                txo_flags,
                scripthash_bytes(txo.script_pubkey),
                txo.script_offset, txo.script_length,
                timestamp, timestamp)
            txo_rows.append(txo_row)

        await self.db_functions_async.import_transaction_async(tx_row, txi_rows, txo_rows,
            proof_row, link_state)

        async with self._obtain_transactions_async_lock:
            if tx_hash in self._missing_transactions:
                del self._missing_transactions[tx_hash]
                self._logger.debug("Removed missing transaction %s", hash_to_hex_str(tx_hash)[:8])
                self.events.trigger_callback(WalletEvent.TRANSACTION_OBTAINED, tx_row, tx,
                    link_state)

        # TODO(1.4.0) MAPI management, issue#910. Allow user to correct lost STATE_SIGNED or
        #     STATE_CLEARED transactions. This would likely be some UI option that used spent
        #     outputs to deal with either unexpected MAPI non-involvement or loss of mined/double
        #     spent callback.

        # We monitor local and mempool transactions to see if they have been mined.
        # TODO(1.4.0) Transaction import, issue#913. Think through all the edge cases.
        if self._network is not None and flags & (TxFlags.MASK_STATE_LOCAL | TxFlags.STATE_CLEARED):
            # We do not monitor local transactions that are being MAPI broadcast.
            # We do not monitor transactions that have proof and are pending verification.
            monitor_spent_outputs = True
            if flags & TxFlags.STATE_SIGNED:
                if import_flags & TransactionImportFlag.EXPLICIT_BROADCAST:
                    # The user has used the "Send" UI button which covers signing and broadcasting.
                    broadcast_type = import_flags & TransactionImportFlag.MASK_BROADCAST_TYPE
                    if broadcast_type == TransactionImportFlag.BROADCAST_MAPI:
                        # We do not need to monitor MAPI broadcasts as we use the callback instead.
                        monitor_spent_outputs = False
            elif flags & TxFlags.STATE_CLEARED:
                if proof_row is not None:
                    # We do not need to monitor this broadcast as we already have the proof for
                    # this transaction but were not able to verify it due to the lack of the
                    # header for the block that the transaction is in.
                    monitor_spent_outputs = False
                # TODO(1.4.0) Output spends, issue#913. We need to recover from all failure cases.
                #     - Maybe the header never arrives (unlikely but should handle).
                #     - Maybe the header does not verify correctly.
                #     - Other failure cases?

            if monitor_spent_outputs:
                # TODO(1.4.0) Output spends, issue#913. This can do more intelligent selection of
                #     spent outputs to monitor. We really only care about UTXOs that affect us,
                #     but it is likely that in most cases it is simpler to care about them all.
                #     - List the higher level code that triggers this so we know we are clear on
                #       when this is being triggered.
                self._register_spent_outputs_to_monitor(
                    [ Outpoint(input.prev_hash, input.prev_idx) for input in tx.inputs ])

        # This primarily routes a notification to the user interface, for it to update for this
        # specific change.
        self.events.trigger_callback(WalletEvent.TRANSACTION_ADD, tx_hash, tx, link_state,
            import_flags)
        app_state.async_.spawn(self._close_paid_payment_requests_async())

    def import_transaction_with_error_callback(self, tx: Transaction, tx_state: TxFlags,
            error_callback: Callable[[str], None]) -> None:
        def callback(callback_future: concurrent.futures.Future[None]) -> None:
            if callback_future.cancelled():
                return
            try:
                callback_future.result()
            except DatabaseUpdateError as update_exception:
                error_callback(update_exception.args[0])
            except TransactionAlreadyExistsError:
                error_callback(_("That transaction has already been imported"))

        future = app_state.async_.spawn(self.add_local_transaction(tx.hash(), tx,
            tx_state, BlockHeight.LOCAL, None, TransactionImportFlag.MANUAL_IMPORT))
        future.add_done_callback(callback)

    async def link_transaction_async(self, tx_hash: bytes, link_state: TransactionLinkState) \
            -> TransactionRow:
        """
        Link an existing transaction to any applicable accounts.

        We do not know whether the transaction uses any wallet keys, and is related to any
        accounts related to those keys. We will work this out as part of the importing process.
        This should not be done for any pre-existing transactions.
        """
        return await self.db_functions_async.link_transaction_async(tx_hash, link_state)

    async def _close_paid_payment_requests_async(self) \
            -> tuple[set[int], list[tuple[int, int, int]], list[tuple[str, int, bytes]]]:
        """
        Apply paid status to any payment requests and keys satisfied by this transaction.

        This will identify the payment requests that are `UNPAID` and whose value is satisfied
        by the outputs in the given transaction that receive value into the payment requests
        keys. It will mark those as `PAID` and it will remove the flag on the keys that
        identifies them as used in a payment request.
        """
        paymentrequest_ids, key_update_rows, transaction_description_update_rows = \
            await db_functions.close_paid_payment_requests_async(self.get_db_context())

        # Notify any dependent systems including the GUI that payment requests have updated.
        if len(paymentrequest_ids):
            self.events.trigger_callback(WalletEvent.PAYMENT_REQUEST_PAID, list(paymentrequest_ids))

        # Unsubscribe from any deactivated keys.
        account_keyinstance_ids = dict[int, set[int]]()
        for account_id, keyinstance_id, flags in key_update_rows:
            if account_id in account_keyinstance_ids:
                account_keyinstance_ids[account_id].add(keyinstance_id)
            else:
                account_keyinstance_ids[account_id] = { keyinstance_id }

        # TODO(1.4.0) Tip filters, issue#911. Remove this registration, save money.
        #     This is also linked to the delete payment requests function.

        if len(transaction_description_update_rows):
            self.events.trigger_callback(WalletEvent.TRANSACTION_LABELS_UPDATE,
                transaction_description_update_rows)

        return paymentrequest_ids, key_update_rows, transaction_description_update_rows

    def read_bip32_keys_gap_size(self, account_id: int, masterkey_id: int, prefix_bytes: bytes) \
            -> int:
        return db_functions.read_bip32_keys_gap_size(self.get_db_context(), account_id,
            masterkey_id, prefix_bytes)

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
            self.events.trigger_callback(WalletEvent.TRANSACTION_DELETE, self._id, tx_hash)

        future = db_functions.remove_transaction(self.get_db_context(), tx_hash)
        future.add_done_callback(on_db_call_done)
        return future

    def ensure_incomplete_transaction_keys_exist(self, tx: Transaction) \
            -> tuple[Optional[concurrent.futures.Future[None]], list[KeyInstanceRow]]:
        """
        Ensure that the keys the incomplete transaction uses exist.

        An incomplete transaction will have come from an external source that has shared it with
        us as we are either the offline signer, or multi-signature cosigner, and we need to make
        sure we have formally created the records for the key derivations it uses (which we
        probably haven't as we're likely a recipient).
        """
        if tx.is_complete():
            return None, []

        self._logger.debug("ensure_incomplete_transaction_keys_exist")

        last_future: Optional[concurrent.futures.Future[None]] = None
        keyinstance_rows: list[KeyInstanceRow] = []
        # Make sure we have created the keys that the transaction inputs use.
        for txin in tx.inputs:
            # These will be present for the signers who have not yet signed.
            for extended_public_key in txin.unused_x_pubkeys():
                account = self.find_account_for_extended_public_key(extended_public_key)
                if account is not None:
                    last_future, new_keyinstance_rows = account.derive_new_keys_until(
                        extended_public_key.derivation_path)
                    keyinstance_rows.extend(new_keyinstance_rows)

        # Make sure we have created the keys that the transaction outputs use.
        # - At the time of writing, this is change addresses.
        # - If the transaction creator added any of their own receiving addresses as destinations
        #   then there is no guarantee that they have the extended public key metadata.
        for txout in tx.outputs:
            if len(txout.x_pubkeys) == 0:
                continue
            for extended_public_key in txout.x_pubkeys.values():
                account = self.find_account_for_extended_public_key(extended_public_key)
                if account is not None:
                    last_future, new_keyinstance_rows = account.derive_new_keys_until(
                        extended_public_key.derivation_path)
                    keyinstance_rows.extend(new_keyinstance_rows)

        return last_future, keyinstance_rows

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

    def set_transaction_labels(self, entries: list[tuple[Optional[str], int, bytes]]) \
            -> concurrent.futures.Future[None]:
        def callback(future: concurrent.futures.Future[None]) -> None:
            # Skip if the operation was cancelled.
            if future.cancelled():
                return
            # Raise any exception if it errored or get the result if completed successfully.
            future.result()

            self.events.trigger_callback(WalletEvent.TRANSACTION_LABELS_UPDATE, entries)

            for text, account_id, tx_hash in entries:
                account = self._accounts[account_id]
                app_state.app_qt.on_transaction_label_change(account, tx_hash, text or "")

        future = self.data.update_account_transaction_descriptions(entries)
        future.add_done_callback(callback)
        return future

    async def set_transaction_state_async(self, tx_hash: bytes, flags: TxFlags,
            ignore_mask: TxFlags | None=None) -> bool:
        """
        Change the state of a transaction but only if it is in an expected state.

        Returns `True` if the state was changed.
        Returns `False` if the transaction does not exist or was not in an expected state.
        """
        if not await self.data.set_transaction_state_async(tx_hash, flags, ignore_mask):
            return False

        for account_id in self.data.read_account_ids_for_transaction(tx_hash):
            self.events.trigger_callback(WalletEvent.TRANSACTION_STATE_CHANGE, account_id, tx_hash,
                flags)
        return True

    async def broadcast_transaction_async(self, transaction: Transaction,
            transaction_context: TransactionContext | None) -> bool:
        """
        Broadcast a transaction. This transaction does not even have to be known to the wallet.

        For now this is limited to broadcasting via MAPI.
        """
        broadcast_hash = transaction.hash()
        successful = False
        if transaction_context is not None and transaction_context.mapi_server_hint is not None:
            # For now we expect to be connected to a peer channel server.
            peer_channel_server_state = self.get_connection_state_for_usage(
                NetworkServerFlag.USE_MESSAGE_BOX)
            assert peer_channel_server_state is not None

            broadcast_response = await mapi_transaction_broadcast_async(self.data,
                peer_channel_server_state, transaction_context.mapi_server_hint, transaction, True,
                True)
            successful = broadcast_response["returnResult"] == "success"
        else:
            raise BroadcastError("P2P broadcast is not currently supported")

        if successful:
            await self.set_transaction_state_async(broadcast_hash, TxFlags.STATE_CLEARED,
                TxFlags.MASK_STATE_BROADCAST)
            return True

        return False

    async def update_mapi_fee_quotes_async(self, account_id: int, timeout: float=4.0) \
            -> AsyncIterable[tuple[NewServer, IndefiniteCredentialId | None]]:
        """
        Ask the wallet to coordinate ensuring it has updated fee quotes.

        Raises nothing.
        """
        # In most cases overlapping updates will be fetching the same things. Any blocked calls
        # will pick up matches from the blocking call.
        async with self._fee_quote_lock:
            servers_with_credentials = self.get_servers_for_account_id(account_id,
                NetworkServerType.MERCHANT_API)
            async for server, credential_id in update_mapi_fee_quotes_async(
                    servers_with_credentials, timeout):
                yield server, credential_id

    def get_mapi_broadcast_context(self, account_id: int, tx: Transaction) \
            -> ServerAndCredential | None:
        try:
            transaction_fee = tx.get_fee()
        except ValueError:
            transaction_fee = None

        transaction_size = tx.estimated_size()
        servers_with_credentials: list[ServerAndCredential] = []
        for server_and_credential in self.get_servers_for_account_id(account_id,
                NetworkServerType.MERCHANT_API):
            server, credential_id = server_and_credential
            if transaction_fee is None:
                servers_with_credentials.append(server_and_credential)
            else:
                fee_quote = server.get_fee_quote(credential_id)
                if fee_quote is not None:
                    server_fee_estimator = TransactionFeeEstimator(fee_quote, server_and_credential)
                    server_fee = server_fee_estimator.estimate_fee(transaction_size)
                    if server_fee >= transaction_fee:
                        servers_with_credentials.append(server_and_credential)
        if len(servers_with_credentials) > 0:
            return random.choice(servers_with_credentials)
        return None

    async def try_get_mapi_proofs(self, tx_hashes: list[bytes], reorging_chain: Chain) \
            -> tuple[set[bytes], list[MerkleProofRow]]:
        # Try to get the appropriate merkle proof for the main chain from TransactionProofs table
        # i.e. we may already have received the mAPI callback for the 'correct chain'
        assert self._db_context is not None
        assert self._blockchain_server_state is not None
        proofs_on_main_chain: list[MerkleProofRow] = []
        remaining_tx_hashes = set(tx_hashes)
        tx_proofs_rows = db_functions.read_merkle_proofs(self._db_context, tx_hashes)
        for proof_row in tx_proofs_rows:
            header_data = self.lookup_header_for_hash(proof_row.block_hash, reorging_chain)
            if header_data is not None:
                proofs_on_main_chain.append(proof_row)
                remaining_tx_hashes.remove(proof_row.tx_hash)
        return remaining_tx_hashes, tx_proofs_rows

    async def on_reorg(self, orphaned_block_hashes: list[bytes], reorging_chain: Chain) -> None:
        '''Called by network when a reorg has happened'''
        assert self._db_context is not None
        loggable_block_ids = [ hash_to_hex_str(h) for h in orphaned_block_hashes ]

        if self._stopping or self._stopped:
            self._logger.debug("Cannot undo verifications on a stopped wallet. "
                "Orphaned block hashes: %s", loggable_block_ids)
            return

        reorged_tx_hashes = await self.data.update_reorged_transactions_async(orphaned_block_hashes)

        self._logger.info('Removing verification of %d transactions. Orphaned block hashes: %s',
            len(reorged_tx_hashes), loggable_block_ids)

        # We want to get all the proofs we already have for the reorged transactions on the
        # chain we are reorging to.
        remaining_tx_hashes, proofs_on_main_chain = await self.try_get_mapi_proofs(
            reorged_tx_hashes, reorging_chain)
        # TODO(1.4.0) Reorgs, issue#914. What triggers the processing of existing proofs?

        # TODO(malleation) Merkle Proofs. Consider how malleated tx_hashes would be handled. The
        #     problem would be if the reorged-to block had malleated transactions and not the
        #     exact transaction we knew to be in the reorged-from block.

        # Are we expecting a mAPI merkle proof callback for any of these?
        for mapi_row in self.data.read_mapi_broadcasts(list(remaining_tx_hashes)):
            remaining_tx_hashes.remove(mapi_row.tx_hash)

        if self._blockchain_server_state is not None:
            # TODO(1.4.0) Reorgs, issue#914. Are these registered on startup? They may not be
            # registerablehere. Otherwise, register for utxo spend notifications for these
            # transactionsto getproofdata when the transaction is included into a block (on the
            # new chain)
            for tx_hash in remaining_tx_hashes:
                tx = self.get_transaction(tx_hash)
                assert tx is not None
                self._register_spent_outputs_to_monitor(
                    [Outpoint(input.prev_hash, input.prev_idx) for input in tx.inputs])

    def _cache_identity_keys(self, password: str) -> None:
        assert self._wallet_master_keystore is not None
        derivation_text = f"{WALLET_IDENTITY_PATH_TEXT}/0'"
        derivation_path: DerivationPath = tuple(bip32_decompose_chain_string(derivation_text))
        # TODO(1.4.0) Identity private key, issue#907. Is this what we plan to do in the long term?
        identity_private_key = cast(BIP32PrivateKey,
            self._wallet_master_keystore.get_private_key(derivation_path, password))
        self.identity_private_key_credential_id = app_state.credentials.add_indefinite_credential(
            identity_private_key.to_hex())
        self._identity_public_key = identity_private_key.public_key

    def get_servers_for_account_id(self, account_id: int, server_type: NetworkServerType) \
            -> list[ServerAndCredential]:
        """
        Get the servers with the credentials to be used with each for any activity performed
        by the given account.
        """
        results: list[ServerAndCredential] = []
        for server in self._servers.values():
            if server.server_type == server_type:
                _have_credential, credential_id = server.get_credential_id(account_id)
                results.append(ServerAndCredential(server, credential_id))
        return results

    def get_unused_reference_servers(self, usage_flags: NetworkServerFlag,
            excluded_servers: dict[NetworkServerFlag, set[NewServer]] | None=None) \
                -> dict[NetworkServerFlag, set[NewServer]]:
        if excluded_servers is None:
            excluded_servers = {}
        capability_by_usage_flag = {
            NetworkServerFlag.USE_BLOCKCHAIN: NetworkServerFlag.CAPABILITY_TIP_FILTER,
            NetworkServerFlag.USE_MESSAGE_BOX: NetworkServerFlag.CAPABILITY_PEER_CHANNELS,
        }
        available_servers: dict[NetworkServerFlag, set[NewServer]] = {}
        for server in self.get_servers():
            # We can only register with servers that support our registration protocol.
            if server.key.server_type != NetworkServerType.GENERAL:
                continue
            server_row = server.database_rows[None]
            for usage_flag, capability_flag in capability_by_usage_flag.items():
                # The caller is not interested in servers with this capability.
                # The caller is not interested in servers that do not have this capability.
                # The caller is not interested in servers that are already in use.
                if usage_flags & usage_flag == 0 or \
                        server_row.server_flags & capability_flag == 0 or \
                        server_row.server_flags & usage_flag != 0:
                    continue
                # The caller is not interested in servers they explicitly do not want.
                relevant_excluded_servers = excluded_servers.get(usage_flag, set())
                if server in relevant_excluded_servers:
                    continue

                if usage_flag in available_servers:
                    available_servers[usage_flag].add(server)
                else:
                    available_servers[usage_flag] = { server }
        return available_servers

    def have_wallet_servers(self, usage_flags: NetworkServerFlag) -> bool:
        """
        This works out if the wallet has signed up to servers that satisfy the usage needs.
        """
        # Collect all the existing server uses that are covered by existing servers.
        satisfied_usage_flags = NetworkServerFlag.NONE
        for _server, server_flags in self.get_wallet_servers():
            satisfied_usage_flags |= server_flags
        for usage_flag in SERVER_USES:
            if usage_flags & usage_flag == 0:
                continue
            # If we are interested in this server use check if it is not covered already.
            if satisfied_usage_flags & usage_flag == 0:
                return False
        return True

    def get_wallet_servers(self) -> list[tuple[NewServer, NetworkServerFlag]]:
        """
        Get the designated servers to use for the different type of usage.
        """
        account_row = self._petty_cash_account.get_row()

        server_id_usages: list[tuple[int, NetworkServerFlag]] = []
        if account_row.blockchain_server_id is not None:
            if account_row.peer_channel_server_id == account_row.blockchain_server_id:
                server_id_usages.append((account_row.blockchain_server_id,
                    NetworkServerFlag.USE_BLOCKCHAIN | NetworkServerFlag.USE_MESSAGE_BOX))
            else:
                server_id_usages.append((account_row.blockchain_server_id,
                    NetworkServerFlag.USE_BLOCKCHAIN))
        elif account_row.peer_channel_server_id is not None:
            server_id_usages.append((account_row.peer_channel_server_id,
                NetworkServerFlag.USE_MESSAGE_BOX))

        server_usages: list[tuple[NewServer, NetworkServerFlag]] = []
        for server_id, usage_flags in server_id_usages:
            for server in self._servers.values():
                if server.server_id == server_id:
                    server_usages.append((server, usage_flags))
                    break
            else:
                # TODO(1.4.0) Unreliable application, issue#906. Broken database state?
                raise NotImplementedError("Existing server not found for given "
                    f"id={server_id}, flags={usage_flags}")
        return server_usages

    def get_servers(self) -> list[NewServer]:
        return list(self._servers.values())

    def get_server(self, server_key: ServerAccountKey) -> Optional[NewServer]:
        assert server_key.account_id is None
        return self._servers.get(server_key)

    def _load_servers(self, password: str) -> None:
        """
        Load into the wallet all the known servers.

        This will include both the servers known in the wallet database, and it will also import
        the servers that are not known in the wallet database but are hardcoded into ElectrumSV.
        """
        self._registered_api_keys: dict[ServerAccountKey, IndefiniteCredentialId] = {}
        credential_id: Optional[IndefiniteCredentialId] = None

        base_row_by_server_key = dict[ServerAccountKey, NetworkServerRow]()
        account_rows_by_server_key = dict[ServerAccountKey, list[NetworkServerRow]]()
        for row in self.data.read_network_servers():
            assert row.server_id is not None
            assert row.server_type in API_SERVER_TYPES
            server_account_key = ServerAccountKey.from_row(row)
            server_base_key = server_account_key.to_base_key()

            if row.account_id is None:
                base_row_by_server_key[server_base_key] = row
            else:
                if server_base_key not in account_rows_by_server_key:
                    account_rows_by_server_key[server_base_key] = []
                account_rows_by_server_key[server_base_key].append(row)

            # Cache the stuff that is needed unencrypted but is encrypted.
            if row.encrypted_api_key is not None:
                server_key = ServerAccountKey(row.url, row.server_type, row.account_id)
                self._registered_api_keys[server_key] = \
                    app_state.credentials.add_indefinite_credential(
                        pw_decode(row.encrypted_api_key, password))

        # Verify that any account row for a server has a base row present.
        for server_base_key in account_rows_by_server_key:
            assert server_base_key in base_row_by_server_key

        for server_base_key, row in base_row_by_server_key.items():
            credential_id = self._registered_api_keys.get(server_base_key)
            server = self._servers[server_base_key] = NewServer(server_base_key.url,
                server_base_key.server_type, row, credential_id)

            for account_row in account_rows_by_server_key.get(server_base_key, []):
                server_key = ServerAccountKey.from_row(account_row)
                credential_id = self._registered_api_keys.get(server_key)
                server.set_server_account_usage(account_row, credential_id)

        # Add any of the hard-coded servers that do not exist in this wallet's database.
        for hardcoded_server_config in cast(list[APIServerDefinition], Net.DEFAULT_SERVERS_API):
            server_type: Optional[NetworkServerType] = getattr(NetworkServerType,
                hardcoded_server_config['type'], None)
            if server_type is None:
                self._logger.error("Misconfigured hard-coded server with url '%s' and type '%s'",
                    hardcoded_server_config['url'], hardcoded_server_config['type'])
                continue

            # We check the server url is normalised at a superficial level.
            url = hardcoded_server_config['url']
            ideal_url = url.strip().lower()
            assert url == ideal_url, f"Skipped bad server with strange url '{url}' != '{ideal_url}'"
            assert url.endswith("/"), f"All server urls must have trailing slash '{url}'"

            server_key = ServerAccountKey(url, server_type, None)

            server_config = hardcoded_server_config.copy()
            server_flags = NetworkServerFlag.FROM_CONFIG
            if server_config.get("enabled_for_all_accounts", True):
                server_flags |= NetworkServerFlag.ENABLED
            api_key_required = server_config.get("api_key_required", False)
            if api_key_required:
                server_flags |= NetworkServerFlag.API_KEY_REQUIRED
            if server_config.get("api_key_supported", True):
                server_flags |= NetworkServerFlag.API_KEY_SUPPORTED
            else:
                assert not api_key_required, \
                    f"Server {url} requires api key, but does not support it"

            for capability_name in server_config.get("capabilities", []):
                capability_value = getattr(ServerCapability, capability_name, None)
                if capability_value is None:
                    self._logger.error("Server '%s' has invalid capability '%s'", url,
                        capability_name)
                elif capability_value == ServerCapability.MERKLE_PROOF_REQUEST:
                    server_flags |= NetworkServerFlag.CAPABILITY_MERKLE_PROOF_REQUEST
                elif capability_value == ServerCapability.RESTORATION:
                    server_flags |= NetworkServerFlag.CAPABILITY_RESTORATION
                elif capability_value == ServerCapability.TRANSACTION_REQUEST:
                    server_flags |= NetworkServerFlag.CAPABILITY_TRANSACTION_REQUEST
                elif capability_value == ServerCapability.HEADERS:
                    server_flags |= NetworkServerFlag.CAPABILITY_HEADERS
                elif capability_value == ServerCapability.PEER_CHANNELS:
                    server_flags |= NetworkServerFlag.CAPABILITY_PEER_CHANNELS
                elif capability_value == ServerCapability.OUTPUT_SPENDS:
                    server_flags |= NetworkServerFlag.CAPABILITY_OUTPUT_SPENDS
                elif capability_value == ServerCapability.TIP_FILTER:
                    server_flags |= NetworkServerFlag.CAPABILITY_TIP_FILTER

            # We do not support hard-coded api keys (this used to be supported for regtest).

            date_now_utc = get_posix_timestamp()
            hardcoded_api_key_template = server_config.get("api_key_template")
            if server_key in self._servers:
                server = self._servers[server_key]
                row = server.database_rows[None]
                # We do not propagate changes from the config to the database unless the user
                # has not edited it.
                if row.server_flags & NetworkServerFlag.API_KEY_MANUALLY_UPDATED != 0:
                    continue
                retained_server_flags = row.server_flags & NetworkServerFlag.MASK_RETAINED
                updated_row = row._replace(server_flags=server_flags | retained_server_flags,
                    api_key_template=hardcoded_api_key_template)
                if row != updated_row:
                    future = self.data.update_network_servers_transaction([], [ row ], [], [])
                    created_rows = future.result()
                    assert len(created_rows) == 0
                    # Make sure we do not overwrite the credential.
                    credential_id = server.client_api_keys[row.account_id]
                    server.set_server_account_usage(updated_row, credential_id)
            else:
                # This server is hardcoded into ElectrumSV and this wallet does not know about it.
                # We add it to the wallet database, as an option. This may be flawed in that if
                # the wallet user has managed to delete it, we are adding it back in. However,
                # that is not in the scope of preventing in the original design and we likely do
                # not allow users to delete servers yet.
                encrypted_api_key: Optional[str] = None
                credential_id = None
                row = NetworkServerRow(None, server_key.server_type, server_key.url, None,
                    server_flags, hardcoded_api_key_template, encrypted_api_key, None, None, None,
                    0, 0, date_now_utc, date_now_utc)
                future = self.data.update_network_servers_transaction([ row ], [], [], [])
                created_rows = future.result()
                assert len(created_rows) == 1
                row = created_rows[0]
                self._servers[server_key] = NewServer(server_key.url, server_key.server_type,
                    row, credential_id)

    def is_blockchain_server_active(self) -> bool:
        """
        Determine if the wallet has a configured and in use blockchain server.
        """
        for account in self._accounts.values():
            if account.is_petty_cash():
                account_row = account.get_row()
                return account_row.blockchain_server_id is not None
        return False

    async def _initialise_headers_from_header_store(self) -> None:
        """
        On startup if the wallet does not have an active blockchain server it will initialise
        it's knowledge of the blockchain from the header store.

        This ensures that wallets that are not able to connect, whether offline or with a
        bad internet connection, start with knowledge of at least the distributed set of headers.
        """
        logger.debug("Initialising headers from header store")
        current_chain = get_longest_valid_chain()
        current_tip_header = cast(Header, current_chain.tip)
        await self._reconcile_wallet_with_header_source(None, current_chain, current_tip_header)

        if self._network is not None:
            self._worker_task_manage_server_connections = app_state.async_.spawn(
                self._start_existing_server_connections())

    async def _start_existing_server_connections(self) -> None:
        """
        Start managed connections to all the servers that the wallet makes use of.
        """
        assert self._network is not None
        logger.debug("Starting server connection process")

        # TODO(petty-cash) In theory each petty cash account maintains a connection. At the
        #     time of writing, we only have one petty cash account per wallet, but there are loose
        #     plans that sets of accounts may hierarchically share different petty cash accounts.
        # TODO(1.4.0) Networking, issue#841. These worker tasks should be restarted if they
        #     prematurely exit?

        self._server_progress.clear()

        # These are the servers the user has opted to use primarily whether through manual or
        # automatic choice.
        for server, usage_flags in self.get_wallet_servers():
            await self.start_server_connection_async(server, usage_flags)

        # self._update_server_progress(account_id, ServerProgress.CONNECTION_PROCESS_STARTED)

        # chosen_servers: list[tuple[NewServer, set[ServerCapability]]] = []
        # new_indexing_server_id: Optional[int] = None
        # new_peer_channel_server_id: Optional[int] = None
        # if account_row.blockchain_server_id is None:
        #     # We need to select an blockchain server for the wallet/user. First work out
        #     # which ones have some form of vetting (they either come from the hard-coded
        #     # configuration or user-entry).
        #     blockchain_server_candidates = list[tuple[ServerAccountKey, NewServer]]()
        #     for server_key, server in self._servers.items():
        #         server_row = server.database_rows[None]
        #         if server_row.server_flags & NetworkServerFlag.CAPABILITY_TIP_FILTER:
        #             blockchain_server_candidates.append((server_key, server))

        #     assert len(blockchain_server_candidates) > 0

        #     # In `Wallet.start()` the wallet notifies the network object of it's internal
        #     # header servers before starting this task. We want to pick one that has fully
        #     # synchronised headers and that we are connected to, as the selected indexing
        #     # server.

        #     self._update_server_progress(account_id,
        #         ServerProgress.WAITING_FOR_VALID_CANDIDATES)

        #     self._logger.debug("Picking an blockchain server, candidates: %s",
        #         blockchain_server_candidates)
        #     while True:
        #         server_candidates = list[tuple[ServerAccountKey, NewServer]]()
        #         for server_key, server in blockchain_server_candidates:
        #             if self._network.is_header_server_ready(server_key):
        #                 server_candidates.append((server_key, server))
        #         if len(server_candidates) > 0:
        #             server_key, server = random.choice(server_candidates)
        #             break
        #         self._logger.debug("Waiting for valid blockchain server, candidates: %s",
        #             blockchain_server_candidates)
        #         await self._network.new_server_ready_event.wait()

        #     chosen_servers.append((server, { ServerCapability.TIP_FILTER }))
        #     new_indexing_server_id = server.server_id
        # else:
        #     for server in self._servers.values():
        #         if server.server_id == account_row.blockchain_server_id:
        #             chosen_servers.append((server, { ServerCapability.TIP_FILTER }))
        #             break
        #     else:
        #         # TODO(1.4.0) Unreliable application, issue#906. Broken database state?
        #         raise NotImplementedError("Existing blockchain server not found for given "
        #             f"id={account_row.blockchain_server_id}")

        # self._update_server_progress(account_id,
        #     ServerProgress.WAITING_UNTIL_CANDIDATE_IS_READY)

        # blockchain_server_key = ServerAccountKey(server.url, server.server_type, None)
        # logger.info("Setting blockchain service to: '%s'", blockchain_server_key)

        # # When making the initial choice above about what blockchain server to use, we
        # # stall until we know the server is ready so this should not block in that case.
        # # If the wallet was loaded with an existing blockchain server, we may block
        # # here.
        # await self._network.wait_until_header_server_is_ready_async(blockchain_server_key)

        # blockchain_server_state = self._network.get_header_server_state(
        #     blockchain_server_key)
        # # This is obviously incorrect when we properly support server switching..
        # assert self._blockchain_server_state is None
        # # This will set the blockchain server state as our header source.
        # assert blockchain_server_state.chain is not None
        # assert blockchain_server_state.tip_header is not None
        # await self._reconcile_wallet_with_header_source(blockchain_server_state,
        #     blockchain_server_state.chain, blockchain_server_state.tip_header)

        # self._network.trigger_callback(NetworkEventNames.GENERIC_STATUS)

        # if account_row.peer_channel_server_id is not None:
        #     if account_row.peer_channel_server_id == account_row.blockchain_server_id:
        #         # Both servers are used for indexing and peer channels.
        #         chosen_servers[0][1].add(ServerCapability.PEER_CHANNELS)
        #     else:
        #         for server in self._servers.values():
        #             if server.server_id == account_row.peer_channel_server_id:
        #                 chosen_servers.append((server, { ServerCapability.PEER_CHANNELS }))
        #                 break
        #         else:
        #             # TODO(1.4.0) Unreliable application, issue#906. Broken database state.
        #             raise NotImplementedError("Existing peer channel server not found for "
        #                 f"given id={account_row.peer_channel_server_id}")
        # else:
        #     peer_channel_server_candidates = list[NewServer]()
        #     for server_key, server in self._servers.items():
        #         server_row = server.database_rows[None]
        #         # TODO(1.4.0) Servers, issue#???. Peer channel selection. We need to know
        #         #     that the selected peer channel server is working/available. For now
        #         #     we tie it to the header server.
        #         if server_row.server_flags & NetworkServerFlag.CAPABILITY_PEER_CHANNELS \
        #                 and self._network.is_header_server_ready(server_key):
        #             peer_channel_server_candidates.append(server)
        #     server = random.choice(peer_channel_server_candidates)
        #     if chosen_servers[0][0].server_id == server.server_id:
        #         # Both servers are used for indexing and peer channels.
        #         chosen_servers[0][1].add(ServerCapability.PEER_CHANNELS)
        #     else:
        #         chosen_servers.append((server, { ServerCapability.PEER_CHANNELS }))
        #     new_peer_channel_server_id = server.server_id

        # # If we had to pick servers because the petty cash account did not have them,
        # # we record them for next time.
        # if new_indexing_server_id is not None or new_peer_channel_server_id is not None:
        #     if new_indexing_server_id is None:
        #         new_indexing_server_id = account_row.blockchain_server_id
        #     if new_peer_channel_server_id is None:
        #         new_peer_channel_server_id = account_row.peer_channel_server_id
        #     self._logger.debug("Stored new servers for account %d, indexing=%d, "
        #         "peer_channels=%d", account_id, new_indexing_server_id,
        #         new_peer_channel_server_id)
        #     self.data.update_account_server_ids(new_indexing_server_id,
        #         new_peer_channel_server_id, account_id)

        # # Further connection state is tracked via `_monitor_connection_stage_changes_async`
        # self._update_server_progress(account_id, ServerProgress.CONNECTION_PROCESS_ACTIVE)

        # self._worker_tasks_maintain_server_connection[account_id] = []
        # covered_capabilities = set[ServerCapability]()
        # for api_server, utilised_capabilities in chosen_servers:
        #     self.start_server_connection(api_server)
        # assert covered_capabilities == { ServerCapability.PEER_CHANNELS,
        #     ServerCapability.TIP_FILTER }

    def _maintain_server_connection_done(self, state: ServerConnectionState,
            future: concurrent.futures.Future[ServerConnectionProblems]) -> None:
        """
        The task that establishes the connection and manages it has exited.
        """
        if future.cancelled():
            return

        # ...
        problems = future.result()
        # TODO(1.4.0) User experience. Work out

    async def create_server_account_async(self, server: NewServer, usage_flags: NetworkServerFlag) \
            -> None:
        """
        Raises `InvalidPassword` if wallet password is not provided by the user.
        From `create_reference_server_account_async`:
            Raises `AuthenticationError` if response does not give valid payment keys or api keys.
            Raises `GeneralAPIError` if non-successful response encountered.
            Raises `ServerConnectionError` if the server could not be reliably connected to.
        """
        assert self._network is not None
        assert usage_flags & ~NetworkServerFlag.MASK_UTILISATION == 0

        account_row = self._petty_cash_account.get_row()
        # TODO(peer-channels) If a wallet can have access to multiple message box servers then we
        #     need to make sure that this account row field is only used for the server that
        #     should be used over all others.
        if usage_flags & NetworkServerFlag.USE_BLOCKCHAIN:
            assert account_row.blockchain_server_id is None
        if usage_flags & NetworkServerFlag.USE_MESSAGE_BOX:
            assert account_row.peer_channel_server_id is None

        existing_server_row = server.get_row()
        if existing_server_row.server_flags & NetworkServerFlag.REGISTERED_WITH == 0:
            # We lookup the password here before we do anything that will change server-side state.
            # If the user is asked to enter it, should it not be in the cache, then we may abort
            # the connection if they refuse.
            wallet_path = self.get_storage_path()
            password = app_state.credentials.get_wallet_password(wallet_path)
            if password is None:
                password = await app_state.credentials.get_or_request_wallet_password_async(
                    wallet_path, _("In order to encrypt server access keys for '{}', it is "
                    "necessary for you to provide your password.").format(server.url))
                if password is None:
                    raise InvalidPassword("Unable to access password to connect")

            # Side effect: Remotely creates an account on the given server or raises an exception.
            api_key, payment_key_bytes = await create_reference_server_account_async(server.url,
                self._network.aiohttp_session, self._identity_public_key,
                self.identity_private_key_credential_id)

            credential_id = app_state.credentials.add_indefinite_credential(api_key)

            encrypted_api_key = pw_encode(api_key, password)
            # NOTE(typing) Mypy thinks this returns an int, but console experimentation says not.
            updated_flags_mask = cast(NetworkServerFlag, ~NetworkServerFlag.MASK_UTILISATION)
            updated_flags = usage_flags | NetworkServerFlag.REGISTERED_WITH
            server_flags = (existing_server_row.server_flags & updated_flags_mask) | updated_flags
            # This gets persisted on wallet exit so we need to update the cached row.
            existing_server_row = existing_server_row._replace(
                encrypted_api_key=encrypted_api_key, payment_key_bytes=payment_key_bytes,
                server_flags=server_flags)
            server.set_server_account_usage(existing_server_row, credential_id)

            await self.data.update_network_server_credentials_async(server.server_id,
                encrypted_api_key, payment_key_bytes, updated_flags, updated_flags_mask)
            logger.debug("Obtained new credentials for server %s", server.server_id)
        else:
            server_flags = existing_server_row.server_flags | usage_flags
            # This gets persisted on wallet exit so we need to update the cached row.
            existing_server_row = existing_server_row._replace(server_flags=server_flags)
            server.set_server_account_usage(existing_server_row,
                server.client_api_keys[existing_server_row.account_id])
            # NOTE(typing) ~ operator on an enum value claims to produce an int, but it doesn't
            #     when done in an interpreter.
            await self.data.update_network_server_flags_async(server.server_id,
                usage_flags, cast(NetworkServerFlag, ~usage_flags))
            logger.debug("Extended registered server %s for %s", server.server_id, usage_flags)

        # TODO(peer-channels) If a wallet can have access to multiple message box servers then we
        #     need to make sure that this account row field is only used for the server that
        #     should be used over all others.
        # Preserve the existing server settings already in use. We know we're not overwriting
        # anything as there are asserts above to prevent the function executing if we were.
        new_blockchain_server_id: int | None = account_row.blockchain_server_id
        new_peer_channel_server_id: int | None = account_row.peer_channel_server_id
        if usage_flags & NetworkServerFlag.USE_MESSAGE_BOX != 0:
            new_peer_channel_server_id = existing_server_row.server_id
        if usage_flags & NetworkServerFlag.USE_BLOCKCHAIN != 0:
            new_blockchain_server_id = existing_server_row.server_id
        self._petty_cash_account.set_server_ids(new_blockchain_server_id,
            new_peer_channel_server_id)

    async def start_server_connection_async(self, server: NewServer,
            usage_flags: NetworkServerFlag) -> ServerConnectionState:
        assert self._network is not None, "use of network in offline mode"

        if usage_flags & NetworkServerFlag.USE_BLOCKCHAIN != 0:
            blockchain_server_key = ServerAccountKey(server.url, server.server_type, None)
            logger.info("Setting blockchain service to: '%s'", blockchain_server_key)

            await self._network.wait_until_header_server_is_ready_async(blockchain_server_key)

            blockchain_server_state = self._network.get_header_server_state(
                blockchain_server_key)
            # This is obviously incorrect when we properly support server switching..
            assert self._blockchain_server_state is None
            # This will set the blockchain server state as our header source.
            assert blockchain_server_state.chain is not None
            assert blockchain_server_state.tip_header is not None
            await self._reconcile_wallet_with_header_source(blockchain_server_state,
                blockchain_server_state.chain, blockchain_server_state.tip_header)

            self._network.trigger_callback(NetworkEventNames.GENERIC_STATUS)

        account_id = self._petty_cash_account.get_id()
        existing_server_state: ServerConnectionState | None = None
        if account_id not in self._worker_tasks_maintain_server_connection:
            self._worker_tasks_maintain_server_connection[account_id] = []
        else:
            # Ensure that the caller knows that this server is not already running.
            for account_server_state in self._worker_tasks_maintain_server_connection[account_id]:
                if account_server_state.server is server:
                    existing_server_state = account_server_state

        def start_use_case_specific_worker_tasks(server_state: ServerConnectionState,
                usage_flags: NetworkServerFlag) -> None:
            if usage_flags & NetworkServerFlag.USE_BLOCKCHAIN:
                server_state.mapi_callback_consumer_future = app_state.async_.spawn(
                    self._consume_mapi_callback_messages_async(server_state))
                server_state.output_spends_consumer_future = app_state.async_.spawn(
                    self._consume_output_spend_notifications_async(
                        server_state.output_spend_result_queue))
                server_state.tip_filter_consumer_future = app_state.async_.spawn(
                    self._consume_tip_filter_matches_async(server_state))

        server_row = server.get_row()
        assert server_row.server_flags & NetworkServerFlag.REGISTERED_WITH != 0, \
            "attempting to connect to a server we have not completed registration with"
        assert server_row.encrypted_api_key is not None, \
            "attempting to connect to a server that unexpectedly has no authentication key"

        new_server_state: ServerConnectionState | None = None
        if existing_server_state is None:
            new_server_state = ServerConnectionState(
                petty_cash_account_id=account_id,
                usage_flags=usage_flags,
                wallet_proxy=weakref.proxy(self),
                wallet_data=self.data,
                session=self._network.aiohttp_session,
                server=server,
                credential_id=server.client_api_keys[None])

            new_server_state.stage_change_pipeline_future = app_state.async_.spawn(
                self._monitor_connection_stage_changes_async(new_server_state))

            # This is the task that establishes the connection and manages it.
            new_server_state.connection_future = app_state.async_.spawn(
                maintain_server_connection_async(new_server_state))
            new_server_state.connection_future.add_done_callback(
                partial(self._maintain_server_connection_done, new_server_state))
            start_use_case_specific_worker_tasks(new_server_state, usage_flags)
            self._worker_tasks_maintain_server_connection[account_id].append(new_server_state)
            server_state = new_server_state
        else:
            # Find the newly enabled use cases flags that we want to additionally enable.
            usage_flags &= ~existing_server_state.usage_flags
            assert usage_flags, "No new use cases to enable on the existing server connection"
            existing_server_state.usage_flags |= usage_flags
            start_use_case_specific_worker_tasks(existing_server_state, usage_flags)
            app_state.app.run_coro(
                upgrade_server_connection_async(existing_server_state, usage_flags))
            server_state = existing_server_state

        self._new_server_connection_event.set()
        self._new_server_connection_event.clear()

        return server_state

    async def _monitor_connection_stage_changes_async(self, state: ServerConnectionState) -> None:
        """
        Map events where the connection flags are changed (different connection stages) to the
        wallet event that the UI listens to.
        """
        while True:
            await state.stage_change_event.wait()
            self.progress_event.set()
            self.progress_event.clear()

    def _update_server_progress(self, petty_cash_account_id: int, value: ServerProgress) -> None:
        """
        Process server pre-connection progress and trigger the wallet event the UI listens to.
        """
        self._server_progress[petty_cash_account_id] = value
        self.progress_event.set()
        self.progress_event.clear()

    def get_server_progress(self, petty_cash_account_id: Optional[int]=None) -> ServerProgress:
        if petty_cash_account_id is None:
            # TODO(petty-cash) In theory later on we may have multiple petty cash accounts
            #     but for now that is just too complicated.
            petty_cash_account_id = self._petty_cash_account.get_id()
        return self._server_progress.get(petty_cash_account_id, ServerProgress.NONE)

    def get_connection_state_for_usage(self, usage_flags: NetworkServerFlag) \
            -> Optional[ServerConnectionState]:
        # TODO(future) In the longer term a wallet will be able to have multiple petty cash
        #     accounts and whatever calls this should provide the relevant `petty_cash_account_id`.
        assert usage_flags & NetworkServerFlag.MASK_UTILISATION != 0
        assert usage_flags & ~NetworkServerFlag.MASK_UTILISATION == 0

        petty_cash_account_id = self._petty_cash_account.get_id()
        if petty_cash_account_id in self._worker_tasks_maintain_server_connection:
            for state in self._worker_tasks_maintain_server_connection[petty_cash_account_id]:
                if state.usage_flags & usage_flags != 0:
                    return state
        return None

    async def wait_for_connection_state_for_usage(self, usage_flags: NetworkServerFlag) \
            -> ServerConnectionState:
        """
        Block tasks until a connection is availabile to a server that offers the requested usage.

        Returns a `ServerConnectionState` matching the given usage flags.
        Raises nothing.
        """
        server_state = self.get_connection_state_for_usage(usage_flags)
        while server_state is None:
            await self._new_server_connection_event.wait()
            server_state = self.get_connection_state_for_usage(usage_flags)
        return server_state

    async def _consume_mapi_callback_messages_async(self, state: ServerConnectionState) -> None:
        """
        Process MAPI callback messages received from a server.

        This will either receive messages directly from the server message loop, or it will
        process backlogged unprocessed messages on startup.
        """
        message_entries = list[tuple[ServerPeerChannelMessageRow, GenericPeerChannelMessage]]()
        for message_row in await self.data.read_server_peer_channel_messages_async(
                PeerChannelMessageFlag.UNPROCESSED, PeerChannelMessageFlag.UNPROCESSED,
                ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK, ServerPeerChannelFlag.MASK_PURPOSE):
            message = cast(GenericPeerChannelMessage, json.loads(message_row.message_data))
            message_entries.append((message_row, message))
        state.mapi_callback_response_queue.put_nowait(message_entries)
        state.mapi_callback_response_event.set()

        while not (self._stopping or self._stopped):
            # This blocks until there is pending work and it is safe to perform it.
            self._logger.debug("Waiting for more MAPI callback messages")
            await self._wait_for_chain_related_work_async(
                ChainWorkerToken.MAPI_MESSAGE_CONSUMER, [ state.mapi_callback_response_event.wait ])
            if self._stopping or self._stopped:
                return

            # We can now process the next batch of messages.
            message_entries = state.mapi_callback_response_queue.get_nowait()
            if state.mapi_callback_response_queue.qsize() == 0:
                state.mapi_callback_response_event.clear()

            tx_update_rows :list[TransactionProofUpdateRow] = []
            proof_rows: list[MerkleProofRow] = []
            processed_message_ids: list[int] = []
            headerless_proofs = list[tuple[TSCMerkleProof, MerkleProofRow]]()
            verified_entries = list[tuple[bytes, Header, TSCMerkleProof]]()
            date_updated = get_posix_timestamp()

            for message_row, message in message_entries:
                assert message_row.message_id is not None
                processed_message_ids.append(message_row.message_id)

                if not isinstance(message["payload"], dict):
                    # TODO(1.4.0) Unreliable server, issue#841. WRT peer channel message, show user.
                    self._logger.error("Peer channel MAPI callback payload invalid: '%s'", message)
                    continue

                envelope = cast(JSONEnvelope, message["payload"])
                try:
                    validate_json_envelope(envelope)
                except ValueError as e:
                    # TODO(1.4.0) Unreliable server, issue#841. WRT peer channel message, show user.
                    self._logger.error("Peer channel MAPI callback envelope invalid: %s '%s'",
                        e.args[0], message)
                    continue

                response = cast(MAPICallbackResponse, json.loads(envelope["payload"]))
                try:
                    validate_mapi_callback_response(response)
                except ValueError as e:
                    # TODO(1.4.0) Unreliable server, issue#841. WRT peer channel message, show user.
                    self._logger.exception("Peer channel MAPI callback response invalid: %s '%s'",
                        e.args[0], message)
                    continue

                if response["callbackReason"] != "merkleProof":
                    self._logger.error("Peer channel MAPI message not yet supported %s '%s'",
                        response["callbackReason"], message)
                    continue

                proof_json = cast(TSCMerkleProofJson, response["callbackPayload"])
                # TODO(1.4.0) Unreliable server, issue#841. Validate the response 'targetType'. We
                #     should verify it in `validate_mapi_callback_response` or we should handle all
                #     target types.
                assert proof_json["targetType"] == "header"
                proof = TSCMerkleProof.from_json(proof_json)

                # TODO(mapi) The MAPI server may send updates if the transaction is reorged,
                #     this means the lifetime of the channel has to be long enough to catch these.

                if not verify_proof(proof):
                    # TODO(1.4.0) Unreliable server, issue#841. The MAPI proof is standalone with
                    #     embedded header, no failure! If we do get a dud proof then we throw it
                    #     away.
                    self._logger.error("Peer channel MAPI proof invalid: '%s'", message)
                    continue

                assert proof.block_header_bytes is not None
                assert proof.transaction_hash is not None

                block_hash = double_sha256(proof.block_header_bytes)
                header_match = self.lookup_header_for_hash(block_hash)
                if header_match is None:
                    # Reasons why we are here:
                    # - This header is on the wallet's current chain but it is on the unprocessed
                    #   tip. This falls to the headerless proof worker to resolve when the tip is
                    #   connected.
                    # - This header is for a different chain/fork which the MAPI server is
                    #   apparently following and we are not (yet?). It will be present if we
                    #   reorg to the MAPI server's fork.

                    # Connecting out of band headers (or trying to) does not necessarily help this
                    # wallet as the wallet follows a specific header source and not necessarily
                    # the longest chain.
                    header, _chain = app_state.connect_out_of_band_header(proof.block_header_bytes)

                    block_height: int = BlockHeight.MEMPOOL
                    if header is not None:
                        block_height = cast(int, header.height)

                    tx_update_rows.append(TransactionProofUpdateRow(block_hash, BlockHeight.MEMPOOL,
                        proof.transaction_index, TxFlags.STATE_CLEARED, date_updated,
                        proof.transaction_hash))
                    proof_row = MerkleProofRow(block_hash, proof.transaction_index,
                        block_height, proof.to_bytes(), proof.transaction_hash)
                    proof_rows.append(proof_row)
                    headerless_proofs.append((proof, proof_row))
                else:
                    header, _common_chain = header_match
                    block_height = cast(int, header.height)
                    tx_update_rows.append(TransactionProofUpdateRow(block_hash, block_height,
                        proof.transaction_index, TxFlags.STATE_SETTLED, date_updated,
                        proof.transaction_hash))
                    proof_rows.append(MerkleProofRow(block_hash, proof.transaction_index,
                        block_height, proof.to_bytes(), proof.transaction_hash))

                    verified_entries.append((proof.transaction_hash, header, proof))
                    logger.debug("MCB Storing verified merkle proof for transaction %s",
                        hash_to_hex_str(proof.transaction_hash))

            # Set the given merkle proof as the one for the active chain on the given transaction
            # also creating it in the merkle proof table if it is not already there.
            if len(tx_update_rows) > 0 or len(proof_rows) > 0:
                await self.data.update_transaction_proof_async(tx_update_rows, proof_rows, [],
                    processed_message_ids)

            # These are detached proofs, which we do not have a header or chain for. We register
            # Them so that when the header comes in, they can be considered for use.
            for headerless_proof in headerless_proofs:
                self._connect_headerless_proof_worker_state.proof_queue.put_nowait(headerless_proof)
            self._connect_headerless_proof_worker_state.proof_event.set()

            # We set these proofs on transactions which makes the transactions verified.
            for verified_entry in verified_entries:
                self.events.trigger_callback(WalletEvent.TRANSACTION_VERIFIED, *verified_entry)

    def _filter_out_earlier_dpp_message_states(self, dpp_messages: list[DPPMessageRow]) -> \
            list[DPPMessageRow]:
        latest_dpp_messages: dict[str, DPPMessageRow] = {}  # dpp_invoice_id: DPPMessageRow
        for dpp_message in dpp_messages:
            if latest_dpp_messages.get(dpp_message.dpp_invoice_id) is None:
                latest_dpp_messages[dpp_message.dpp_invoice_id] = dpp_message
            else:
                msg_prior = latest_dpp_messages[dpp_message.dpp_invoice_id]
                msg_later = dpp_message
                if _is_later_dpp_message_sequence(msg_prior, msg_later):
                    latest_dpp_messages[dpp_message.dpp_invoice_id] = msg_later
        return [msg for msg in latest_dpp_messages.values()]

    # ----- DPP Message Creators ----- #
    def dpp_make_payment_request_response(self, pr_row: PaymentRequestReadRow,
            message_row_received: DPPMessageRow) -> DPPMessageRow:
        key_data = self.data.read_keyinstance(keyinstance_id=pr_row.keyinstance_id)
        script_template = self.get_default_account().get_script_template_for_derivation(
            pr_row.script_type, key_data.derivation_type, key_data.derivation_data2)
        outputs_object = [
            {
                "description": pr_row.description,
                "amount": pr_row.requested_value,
                "script": script_template.to_string()
            }
        ]

        paymentRequestData = {
            "network": "regtest",
            "version": "1.0",
            "creationTimestamp": int(datetime.now(tz=timezone.utc).timestamp()),
            "expirationTimestamp": pr_row.expiration,
            "paymentUrl": create_DPP_URL(self.dpp_proxy_server_states, pr_row),
            # "beneficiary": {"name": "GoldenSocks.com", "paymentReference": "Order-325214"},
            "memo": pr_row.description,

            # Hybrid Payment Mode
            'modes': {'ef63d9775da5':
                {
                    "choiceID0": {
                        "transactions": [
                            {
                                'outputs': {
                                    'native': outputs_object
                                },
                                'policies': {
                                    'fees': {
                                        'standard': {"satoshis": 100, "bytes": 200},
                                        'data': {'satoshis': 100, 'bytes': 200}},
                                    'SPVRequired': False}
                            },
                        ],
                    },
                }}
        }

        message_row_response = DPPMessageRow(
            message_id=str(uuid.uuid4()),
            paymentrequest_id=message_row_received.paymentrequest_id,
            dpp_invoice_id=message_row_received.dpp_invoice_id,
            correlation_id=message_row_received.correlation_id,
            app_id=message_row_received.app_id,
            client_id=message_row_received.client_id,
            user_id=message_row_received.user_id,
            expiration=message_row_received.expiration,
            body=json.dumps(paymentRequestData).encode('utf-8'),
            timestamp=int(datetime.now(tz=timezone.utc).timestamp()),
            type=MSG_TYPE_PAYMENT_REQUEST_RESPONSE
        )
        return message_row_response

    def dpp_make_payment_message(self, pr_row: PaymentRequestRow,
            message_row: DPPMessageRow) -> DPPMessageRow:
        pass

    def dpp_make_ack(self, pr_row: PaymentRequestRow, message_row: DPPMessageRow) \
            -> DPPMessageRow:
        pass

    def dpp_make_pr_error(self, pr_row: PaymentRequestRow, message_row: DPPMessageRow) \
            -> DPPMessageRow:
        pass

    def dpp_make_payment_error(self, pr_row: PaymentRequestRow, message_row: DPPMessageRow) \
            -> DPPMessageRow:
        pass

    # ----- DPP Message Validators ----- #

    def dpp_payment_is_valid(self, pr_row: PaymentRequestRow, message_row: DPPMessageRow) \
            -> bool:
        # TODO: Do validation
        return True

    def dpp_payment_request_is_valid(self, pr_row: PaymentRequestRow, message_row: DPPMessageRow) \
            -> bool:
        # TODO: Do validation
        return True

    async def dpp_websocket_send(self, state: ServerConnectionState, message_row: DPPMessageRow):
        try:
            websocket = state.dpp_websockets[message_row.dpp_invoice_id]
        except KeyError:
            # TODO(1.4.0) DPP. This was happening because it takes a second before the
            #  websockets are actually opened and the state.dpp_websockets cache is filled.
            #  therefore this likely needs some kind of synchronization to wait until the initial
            #  opening of all active invoices in database is completed. Currently this is being
            #  avoided with an `await asyncio.sleep(1)` to yield the event loop. - AustEcon
            self._logger.exception(f"Key Error looking up cached dpp websocket: "
                                   f"state.dpp_websockets={state.dpp_websockets}")
            return

        if websocket is not None:  # ws:// is still open
            await websocket.send_str(message_row.to_json())
        else:
            self._logger.error("There is no open websocket for dpp_invoice_id: %s, "
                               "server url: %s. Retrying in 10 seconds...",
                message_row.dpp_invoice_id, state.server.url)
            await asyncio.sleep(10)
            state.dpp_messages_queue.put_nowait(message_row)

    async def update_pr_flags_in_db_async(self, pr_row: PaymentRequestRow,
            new_flags: PaymentFlag) -> None:
        entries = [PaymentRequestUpdateRow(new_flags, pr_row.requested_value, pr_row.expiration,
            pr_row.description, pr_row.paymentrequest_id)]
        await self._db_context.run_in_thread_async(db_functions.update_payment_requests_no_wait,
            entries)

    async def _consume_dpp_messages_async(self, state: ServerConnectionState,
            pr_rows_for_server: list[PaymentRequestReadRow]) -> None:
        """Consumes and processes all invoice messages for a single DPP Proxy server

        A core principle here is that both Payer and Payee should be able to retry any message type
        in the exchange and it should never result in double invoicing or payment.
        This is achieved by recording the DPPMessage in the database before sending over the
        websocket for retrying after a sudden crash or power failure i.e. there is an
        "at-least-once-delivery" garauntee.

        The `payment.ack`, `payment.error` and `paymentrequest.error` message types do not have a
        corresponding ws:// response message. As there is no feedback that the message was
        successfully delivered, it should be possible for the payer to retry paying the invoice
        from any state in the sequence if needed.
        """
        # Initialize ws:// connections for pre-existing active invoice records from the database
        for pr_row in pr_rows_for_server:
            state.active_invoices_queue.put_nowait(pr_row)

        await asyncio.sleep(1)  # yield event loop so that websocket connections open

        # Initialize the state machine message queue for pre-existing active invoice records
        paymentrequest_ids = [pr_row.paymentrequest_id for pr_row in pr_rows_for_server]
        dpp_messages = db_functions.read_dpp_messages_by_pr_id(self._db_context, paymentrequest_ids)
        for dpp_message in self._filter_out_earlier_dpp_message_states(dpp_messages):
            state.dpp_messages_queue.put_nowait(dpp_message)

        # State machine
        while not (self._stopping or self._stopped):
            message_row: DPPMessageRow
            message_row = await state.dpp_messages_queue.get()
            if message_row.type == MSG_TYPE_JOIN_SUCCESS:
                continue

            pr_rows = db_functions.read_payment_requests(self._db_context,
                paymentrequest_ids=[message_row.paymentrequest_id])
            if len(pr_rows) != 1:
                self._logger.error(f"Failed to read payment request with id: "
                                   f"{message_row.paymentrequest_id} from the database. "
                                   f"DPPMessageRow data: {message_row}")
                continue

            pr_row = pr_rows[0]
            assert pr_row.state & PaymentFlag.INVOICE == PaymentFlag.INVOICE
            assert pr_row.state & PaymentFlag.UNPAID == PaymentFlag.UNPAID

            # Update flag to new state & write to database
            new_state_flag = dpp_msg_type_to_state_flag(message_row.type)
            if pr_row.state & new_state_flag != new_state_flag:
                new_state = pr_row.state & ~PaymentFlag.MASK_DPP_STATE_MACHINE | new_state_flag
                await self.update_pr_flags_in_db_async(pr_row, new_state)

            self._logger.debug("State machine processing DPPMessageRow: %s for state: %s",
                message_row, pr_row.state)

            # ----- States for when we are the Payee ----- #
            if pr_row.state & PaymentFlag.PAYMENT_REQUEST_REQUESTED == \
                    PaymentFlag.PAYMENT_REQUEST_REQUESTED:
                dpp_response_message = self.dpp_make_payment_request_response(pr_row,
                    message_row)
                _future = app_state.async_.spawn(self.dpp_websocket_send(state,
                    dpp_response_message))

            elif pr_row.state & PaymentFlag.PAYMENT_RECEIVED == \
                    PaymentFlag.PAYMENT_RECEIVED:
                if self.dpp_payment_is_valid(pr_row, message_row):
                    dpp_ack_message = self.dpp_make_ack(pr_row, message_row)
                    _future = app_state.async_.spawn(self.dpp_websocket_send(state,
                        dpp_ack_message))
                else:
                    dpp_err_message = self.dpp_make_pr_error(pr_row, message_row)
                    _future = app_state.async_.spawn(self.dpp_websocket_send(state,
                        dpp_err_message))

            elif pr_row.state & PaymentFlag.PAYMENT_RECEIVED == PaymentFlag.PAYMENT_RECEIVED:
                # TODO(1.4.0) DPP. Validate Payment struct
                # TODO(1.4.0) DPP. Create Peer Channel
                # TODO(1.4.0) DPP. Broadcast to mAPI
                # TODO(1.4.0) DPP. On Success. Update invoice to PaymentFlag.PAID

                # Send PaymentACK to payer
                dpp_payment_ack_message = self.dpp_make_ack(pr_row, message_row)
                _future = app_state.async_.spawn(self.dpp_websocket_send(state,
                    dpp_payment_ack_message))

            # ----- States for when we are the Payer ----- #
            # NOTE: Not included because when we are the ** Payer **, we use the simplified
            # http request/response REST API endpoints of the DPP server (i.e. BIP272 URI)


    async def _consume_tip_filter_matches_async(self, state: ServerConnectionState) -> None:
        """
        Process tip filter messages received from a server.

        This will either receive messages directly from the server message loop, or it will
        process backlogged unprocessed messages on startup.

        * It is safe to cancel this task rather than tell it to exit.
          * It queues all outstanding messages as an initial batch on startup.
          * It will do a first loop which may or may not process any messages, but will start the
            process of obtaining all message-related missing transactions.
          * The update is atomic so:
            * If the batch is processed then it is no longer valid.
            * If the batch is processed (task cancelled) then it will be picked up next restart.
        """
        # TODO(1.4.0) Should this db read be filtering for state.server.server_id? - AustEcon
        message_entries = list[tuple[ServerPeerChannelMessageRow, GenericPeerChannelMessage]]()
        for message_row in await self.data.read_server_peer_channel_messages_async(
                PeerChannelMessageFlag.UNPROCESSED, PeerChannelMessageFlag.UNPROCESSED,
                ServerPeerChannelFlag.TIP_FILTER_DELIVERY, ServerPeerChannelFlag.MASK_PURPOSE):
            message = cast(GenericPeerChannelMessage, json.loads(message_row.message_data))
            message_entries.append((message_row, message))
        state.tip_filter_matches_queue.put_nowait(message_entries)

        while not (self._stopping or self._stopped):
            rows_by_account_id = dict[int, list[PushDataMatchMetadataRow]]()
            creation_pushdata_match_rows = list[PushDataMatchRow]()
            processed_message_ids = list[int]()
            for message_row, message in await state.tip_filter_matches_queue.get():
                assert message_row.message_id is not None
                processed_message_ids.append(message_row.message_id)

                if not isinstance(message["payload"], dict):
                    # TODO(1.4.0) Unreliable server, issue#841. WRT tip filter match, show user.
                    self._logger.error("Peer channel message payload invalid: '%s'", message)
                    continue

                pushdata_matches = cast(TipFilterPushDataMatchesData, message["payload"])
                if "blockId" not in pushdata_matches or "matches" not in pushdata_matches:
                    # TODO(1.4.0) Unreliable server, issue#841. WRT tip filter match, show user.
                    self._logger.error("Peer channel message payload invalid: '%s'", message)
                    continue

                date_created = get_posix_timestamp()
                block_hash: Optional[bytes] = None
                if pushdata_matches["blockId"] is not None:
                    block_hash = hex_str_to_hash(pushdata_matches["blockId"])
                for tip_filter_match in pushdata_matches["matches"]:
                    pushdata_hash = bytes.fromhex(tip_filter_match["pushDataHashHex"])
                    transaction_hash = hex_str_to_hash(tip_filter_match["transactionId"])
                    transaction_index = tip_filter_match["transactionIndex"]
                    match_flags = PushDataMatchFlag(tip_filter_match["flags"])
                    # TODO(1.4.0) Tip filters, issue#904. See `read_pushdata_match_metadata`
                    match_flags |= PushDataMatchFlag.UNPROCESSED
                    creation_pushdata_match_row = PushDataMatchRow(state.server.server_id,
                        pushdata_hash, transaction_hash, transaction_index, block_hash, match_flags,
                        date_created)
                    creation_pushdata_match_rows.append(creation_pushdata_match_row)

            self._logger.debug("Writing %d pushdata matches to the database",
                len(creation_pushdata_match_rows))
            # The processed messages will have their `UNPROCESSED` flag removed here as part of an
            # atomic update, that also inserts their extracted pushdata matches.
            await self.data.create_pushdata_matches_async(creation_pushdata_match_rows,
                processed_message_ids)

            # At the moment we read the matches out of the database to associate them with
            # individual accounts. It should be possible to say we only create pushdata matches
            # when we want to do this and return that there. Unless we have in-memory state that
            # allows us to do that mapping, we have to go to the database for it in some way
            # and this will do for now.
            # TODO(technical-debt) Double-dipping in the database?
            metadata_rows = self.data.read_pushdata_match_metadata(for_missing_transactions=True)
            for metadata_row in metadata_rows:
                if metadata_row.account_id in rows_by_account_id:
                    rows_by_account_id[metadata_row.account_id].append(metadata_row)
                else:
                    rows_by_account_id[metadata_row.account_id] = [ metadata_row ]

            self._logger.debug("Wallet processing %d tip filter matches", len(metadata_rows))

            for account_id, metadata_rows in rows_by_account_id.items():
                obtain_transaction_keys = list[tuple[bytes, bool]]()
                for metadata_row in metadata_rows:
                    obtain_transaction_keys.append((metadata_row.transaction_hash,
                        metadata_row.block_hash is not None))
                self._logger.debug("Obtaining %d transactions for account %d, %s",
                    len(obtain_transaction_keys), account_id, obtain_transaction_keys)
                await self.obtain_transactions_async(account_id, obtain_transaction_keys)

    def _register_spent_outputs_to_monitor(self, spent_outpoints: list[Outpoint]) -> None:
        """
        Call this to start monitoring outpoints when the wallet needs to know if they are mined.
        """
        if self._network is None:
            return

        state = self.get_connection_state_for_usage(NetworkServerFlag.USE_BLOCKCHAIN)
        if state is None:
            # The server has not started yet.
            self._logger.debug("Skipping premature output spend registrations")
            return
        state.output_spend_registration_queue.put_nowait(spent_outpoints)

    # TODO(malleation) Spent outputs. Unit test malleation replacement of a transaction
    async def _consume_output_spend_notifications_async(self,
            queue: asyncio.Queue[Sequence[OutputSpend]]) -> None:
        """
        Process spent output results received from a server.

        * It is safe to cancel this task rather than tell it to exit.
          * It only receives events from the network requests or events.
          * The update is atomic so:
            * If the network data is processed then it is not requested again -> `STATE_CLEARED`.
            * If the network data is not processed it is requested again.
        """
        while not (self._stopping or self._stopped):
            spent_outputs = await queue.get()

            # Match the received state to the current database state.
            rows_by_outpoint: dict[Outpoint, list[SpentOutputRow]] = {}
            spent_outpoints = { Outpoint(spent_output.out_tx_hash, spent_output.out_index)
                for spent_output in spent_outputs }
            for spent_output_row in self.data.read_existing_output_spends(list(spent_outpoints)):
                spent_outpoint = Outpoint(spent_output_row.spent_tx_hash,
                    spent_output_row.spent_txo_index)
                if spent_outpoint not in rows_by_outpoint:
                    rows_by_outpoint[spent_outpoint] = []
                rows_by_outpoint[spent_outpoint].append(spent_output_row)

            # Reconcile the received server state against the database state.
            mined_transactions = set[tuple[bytes, bytes]]()
            mempool_transactions = dict[bytes, TxFlags]()
            for spent_output in spent_outputs:
                spent_outpoint = Outpoint(spent_output.out_tx_hash, spent_output.out_index)
                if spent_outpoint not in rows_by_outpoint:
                    # TODO(server-reliability) Spent outputs. The user would have had to delete the
                    #     transaction from the database if that is even possible? Is that correct?
                    #     Should we do something here?
                    self._logger.error("No database entries for spent output notification %r",
                        spent_output)
                    continue

                # TODO(output-spends) Finalise handling of all the different cases when
                #     processing notifications from a blockchain server.
                for row in rows_by_outpoint[spent_outpoint]:
                    if row.spending_tx_hash != spent_output.in_tx_hash:
                        # We have this outpoint being spent by a different transaction than the
                        # blockchain server is telling us it has been spent by. These are the
                        # suspected causes:
                        #
                        # - Double spend.
                        # - Malleation (we ignore this problem for now as unlikely).
                        # - Bad testing environment where an old wallet was loaded against a
                        #   reset blockchain? (developer needs to reset wallets).
                        # - Non-final transaction has been finalised without notice by another
                        #   involved party by broadcasting before we received any communication.
                        #   (we do not support non-final transactions yet)
                        #
                        # Note that this may be a notification related to a transaction we
                        # considered already broadcast, or about a transaction that we (and maybe
                        # other involved parties) have locally.

                        # TODO(malleation) We would want to compare both transactions, the old and
                        #     the new, and identify if it is a malleation or something else. This
                        #     will have to be done elsewhere and started here, as it will involve
                        #     synchronous time consuming work like fetching the malleating
                        #     transaction.

                        self._logger.error("Ignored output spend notification. This may be a "
                            "double spend, malleation, a developer not resetting their test "
                            "wallet or a non-final transaction being finalised by broadcast. "
                            "Details: %r ~ %r", spent_output, row)
                    elif row.block_hash != spent_output.block_hash:
                        if spent_output.block_hash is None:
                            # The blockchain server has informed us that the transaction is back
                            # in the mempool. The wallet believes that the transaction is in a
                            # block. We should never apply this change here, it should be
                            # applied by the processing of updates from our header source.

                            # TODO(reorgs) Consider using this output spend to check consistency.
                            self._logger.debug("Unspent output event, transaction is back in "
                                "mempool %r ~ %r", spent_output, row)
                        elif row.block_hash is None:
                            # The blockchain server has informed us that the transaction is in
                            # a block. The wallet believes the transaction was either in the
                            # mempool already or is watching to see if someone else broadcasts it.
                            if row.flags & TxFlags.MASK_STATE_LOCAL:
                                # Process someone else broadcasting this transaction.
                                # TODO(1.4.0) User experience, issue#909. Notify the user that
                                #     this local transaction has been broadcast unexpectedly.
                                pass

                            self._logger.debug("Unspent output event, transaction has been mined "
                                " %r ~ %r", spent_output, row)
                            mined_transactions.add((row.spending_tx_hash, spent_output.block_hash))
                        else:
                            # The blockchain server has informed us that the transaction is in a
                            # block. The wallet believes that the transaction is in a different
                            # block. We should never apply this change here, it should be
                            # applied by the processing of updates from our header source.

                            # TODO(reorgs) Consider using this output spend to check consistency.
                            self._logger.debug("Unspent output event, transaction reorged %r ~ %r",
                                spent_output, row)
                    elif row.block_hash is None and row.flags & TxFlags.MASK_STATE_LOCAL:
                        # The blockchain server has informed us that a transaction we do not
                        # know to be broadcast, has been broadcast and is in the mempool.

                        # TODO(1.4.0) User experience, issue#909. Notify the user that this local
                        #     transaction has been broadcast unexpectedly.

                        if row.mapi_broadcast_flags is None:
                            self._logger.debug("Unspent output event, local transaction has been "
                                "broadcast %r ~ %r", spent_output, row)
                            mempool_transactions[spent_output.in_tx_hash] = row.flags
                        else:
                            self._logger.warning("Unspent output event, local transaction has "
                                "been broadcast with unwanted output spend notification "
                                "%r ~ %r", spent_output, row)
                    else:
                        # Nothing is different than what we already have. Ignore the result. It
                        # probably came in during the registration as the initial state.
                        pass

            tx_update_rows = list[TransactionProofUpdateRow]()
            for tx_hash, block_hash in mined_transactions:
                # We indicate that we need to obtain the proof by setting the known block hash and
                # the state to cleared.
                date_updated = get_posix_timestamp()
                tx_update_row = TransactionProofUpdateRow(block_hash, BlockHeight.MEMPOOL, None,
                    TxFlags.STATE_CLEARED, date_updated, tx_hash)
                tx_update_rows.append(tx_update_row)

            flag_update_rows = [ (TxFlags.MASK_STATELESS, TxFlags.STATE_CLEARED, tx_hash)
                for tx_hash in mempool_transactions ]

            # This is an atomic update. If it succeeds then the missing proofs will get triggered
            # below. If it does not succeed (maybe the task is cancelled) then the next time
            # this task starts the data will be reprocessed again.
            if len(tx_update_rows) > 0 or len(flag_update_rows) > 0:
                await self.data.update_transaction_proofs_and_flags(tx_update_rows,
                    flag_update_rows)

            if len(tx_update_rows) > 0:
                self._check_missing_proofs_event.set()
                self.events.trigger_callback(WalletEvent.TRANSACTION_HEIGHTS_UPDATED, 1, 1)

            for tx_hash, tx_flags in mempool_transactions.items():
                self.events.trigger_callback(WalletEvent.TRANSACTION_STATE_CHANGE, -1,
                    tx_hash, (tx_flags & TxFlags.MASK_STATE) | TxFlags.STATE_CLEARED)

    def have_transaction(self, tx_hash: bytes) -> bool:
        return self.data.get_transaction_flags(tx_hash) is not None

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

    def is_connected_to_blockchain_server(self) -> bool:
        return self._blockchain_server_state is not None

    def is_synchronized(self) -> bool:
        "If all the accounts are synchronized"
        return not (self._network and self._missing_transactions)

    def set_boolean_setting(self, setting_name: str, enabled: bool) -> None:
        self._storage.put(setting_name, enabled)
        self.events.trigger_callback(WalletEvent.WALLET_SETTING_CHANGE, setting_name, enabled)

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

    async def _manage_dpp_connections_async(self):
        # Petty cash account_id is for ServerConnectionState in case payment is required in future
        petty_cash_account_id = None
        for account in self._accounts.values():
            if account.is_petty_cash():
                petty_cash_account_id = account.get_id()
        assert petty_cash_account_id is not None

        # Scan through all accounts for all active payment requests and get the DPP proxy servers
        # associated with each invoice ID.
        unique_dpp_servers: set[NewServer] = { server for server in self._servers.values()
                if server.server_type == NetworkServerType.DPP_PROXY }

        server_to_pr_map: dict[NewServer, list[PaymentRequestReadRow]] = {}
        for server in unique_dpp_servers:
            server_to_pr_map[server] = []

        for account in self._accounts.values():
            # We are only processing PaymentFlag.INVOICE type invoices (not legacy invoices)
            flags = PaymentFlag.INVOICE | PaymentFlag.UNPAID
            active_pr_rows: list[PaymentRequestReadRow] = \
                self.data.read_payment_requests(account.get_id(), flags=flags)

            # software join on server_id to obtain NewServer info (for the ws:// connection)
            for active_pr_row in active_pr_rows:
                for server in unique_dpp_servers:
                    if active_pr_row.server_id == server.server_id:
                        server_to_pr_map[server].append(active_pr_row)

        for server in unique_dpp_servers:
            usage_flags = NetworkServerFlag.CAPABILITY_DPP
            state = ServerConnectionState(
                petty_cash_account_id=petty_cash_account_id,
                usage_flags=usage_flags,
                wallet_proxy=weakref.proxy(self),
                wallet_data=self.data,
                session=self._network.aiohttp_session,
                server=server,
                credential_id=server.client_api_keys[None])

            self.dpp_proxy_server_states.append(state)
            state.manage_dpp_connections_future = \
                app_state.async_.spawn(manage_dpp_network_connections_async(state,
                    self._db_context))

            pr_rows_for_server = server_to_pr_map[server]
            state.dpp_consumer_future = app_state.async_.spawn(
                self._consume_dpp_messages_async(state, pr_rows_for_server))

    def start(self, network: Optional[Network]) -> None:
        assert app_state.headers is not None

        self._network = network
        self._chain_management_queue = asyncio.Queue[tuple[ChainManagementKind,
            Union[tuple[Chain, list[bytes], list[Header]], tuple[Chain, list[Header]]]]]()
        self._chain_management_interrupt_event = asyncio.Event()
        self._chain_worker_queue = asyncio.Queue[ChainWorkerToken]()
        self._is_chain_management_pending = False

        is_blockchain_server_active = self.is_blockchain_server_active()

        if network is not None:
            # Online mode.
            network.add_wallet(self)

            # Add all servers with HEADERS capability to the network layer for header tracking
            for server_key, server in self._servers.items():
                server_row = server.database_rows[None]
                if server_row.server_flags & NetworkServerFlag.CAPABILITY_HEADERS:
                    network.register_wallet_server(server_key)

            for account in self.get_accounts():
                account.start(network)

            # We can start trying to connect to any servers we are already using.
            self._worker_task_manage_server_connections = app_state.async_.spawn(
                self._start_existing_server_connections())

            self._worker_task_manage_dpp_connections = app_state.async_.spawn(
                self._manage_dpp_connections_async())

        else:
            # Offline mode.
            pass

        # Online or offline, if the wallet is not already using a blockchain server, we first
        # synchronise to the longest valid chain from the header store.
        if not is_blockchain_server_active:
            # Wallets start off following the longest valid chain.
            self._worker_task_initialise_headers = app_state.async_.spawn(
                self._initialise_headers_from_header_store())

        self._worker_task_obtain_transactions = app_state.async_.spawn(
            self._obtain_transactions_worker_async())
        self._worker_task_obtain_merkle_proofs = app_state.async_.spawn(
            self._obtain_merkle_proofs_worker_async())
        self._worker_task_connect_headerless_proofs = app_state.async_.spawn(
            self._connect_headerless_proofs_worker_async())
        self._worker_task_chain_management = app_state.async_.spawn(self._chain_management_task())

        self._stopped = False

    def stop(self) -> None:
        assert not (self._stopping or self._stopped)
        self._stopping = True

        for account in self.get_accounts():
            account.stop()

        if self._network is not None:
            self._shutdown_network_related_tasks()

        if self._worker_task_chain_management is not None:
            self._worker_task_chain_management.cancel()
            self._worker_task_chain_management = None

        for credential_id in self._registered_api_keys.values():
            app_state.credentials.remove_indefinite_credential(credential_id)
        app_state.credentials.remove_indefinite_credential(self.identity_private_key_credential_id)

        # This will be a metadata save on exit. Anything else has been updated as it was changed.
        updated_states = list[NetworkServerRow]()
        for server in self._servers.values():
            updated_states.extend(server.to_updated_rows())
        if len(updated_states):
            # We do not need to wait for the future to complete, as closing the storage below
            # should close out all database pending writes.
            self.update_network_servers([], updated_states, [], {})

        if self._network is not None:
            self._network.remove_wallet(self)

        self.data.teardown()
        self.db_functions_async.close()
        self._storage.close()

        self._network = None
        self._stopped = True

    def _shutdown_network_related_tasks(self) -> None:
        # Collect the futures we are waiting to complete.
        pending_futures = set[concurrent.futures.Future[Any]]()

        # The following tasks can be cancelled directly and do not need to shutdown cleanly.
        if self._worker_task_initialise_headers is not None:
            self._worker_task_initialise_headers.cancel()
            pending_futures.add(self._worker_task_initialise_headers)
            self._worker_task_initialise_headers = None
        if self._worker_task_manage_server_connections is not None:
            self._worker_task_manage_server_connections.cancel()
            pending_futures.add(self._worker_task_manage_server_connections)
            self._worker_task_manage_server_connections = None
        if self._worker_task_manage_dpp_connections is not None:
            self._worker_task_manage_dpp_connections.cancel()
            pending_futures.add(self._worker_task_manage_dpp_connections)
            self._worker_task_manage_dpp_connections = None

        async def trigger_chain_management_interrupt_event() -> None:
            # `Event.set` is not thread-safe, needs to be executed in the async thread.
            self._chain_management_interrupt_event.set()
            await asyncio.sleep(0)

        # This blocks the current thread, but we are exiting and it is not expected that
        # anything should take a noticeable amount of time to exit.
        app_state.async_.spawn_and_wait(trigger_chain_management_interrupt_event())

        # Only kill if not signalled to exit by the chain management interrupt event.
        kill_worker_tasks = not self._header_source_synchronised_event.is_set()
        if self._worker_task_obtain_transactions is not None:
            if kill_worker_tasks:
                self._worker_task_obtain_transactions.cancel()
            pending_futures.add(self._worker_task_obtain_transactions)
            self._worker_task_obtain_transactions = None
        if self._worker_task_obtain_merkle_proofs is not None:
            if kill_worker_tasks:
                self._worker_task_obtain_merkle_proofs.cancel()
            pending_futures.add(self._worker_task_obtain_merkle_proofs)
            self._worker_task_obtain_merkle_proofs = None
        if self._worker_task_connect_headerless_proofs is not None:
            if kill_worker_tasks:
                self._worker_task_connect_headerless_proofs.cancel()
            pending_futures.add(self._worker_task_connect_headerless_proofs)
            self._worker_task_connect_headerless_proofs = None

        for petty_cash_account_id in list(self._worker_tasks_maintain_server_connection):
            for state in self._worker_tasks_maintain_server_connection.pop(petty_cash_account_id):
                # This was signalled to exit by the chain management interrupt event.
                if state.mapi_callback_consumer_future is not None:
                    pending_futures.add(state.mapi_callback_consumer_future)
                # These are manually cancelled and it should be safe to do so.
                if state.connection_future is not None:
                    state.connection_future.cancel()
                    pending_futures.add(state.connection_future)
                if state.output_spends_consumer_future is not None:
                    state.output_spends_consumer_future.cancel()
                    pending_futures.add(state.output_spends_consumer_future)
                if state.tip_filter_consumer_future is not None:
                    state.tip_filter_consumer_future.cancel()
                    pending_futures.add(state.tip_filter_consumer_future)
        del self._worker_tasks_maintain_server_connection

        total_wait = 0.0
        while len(pending_futures) > 0 and total_wait < 5.0:
            self._logger.debug("Shutdown waiting for %d tasks to exit: %s", len(pending_futures),
                pending_futures)
            # Cancelled tasks clean up when they get a chance to run next. Python will complain
            # on exit about tasks that are not cleaned up.
            app_state.async_.spawn_and_wait(asyncio.sleep(0))
            done, not_done = concurrent.futures.wait(pending_futures, 1.0)
            pending_futures = not_done
            total_wait += 1.0

        for state in self.dpp_proxy_server_states:
            if state.dpp_consumer_future is not None:
                state.dpp_consumer_future.cancel()
                pending_futures.add(state.dpp_consumer_future)
            if state.manage_dpp_connections_future is not None:
                state.manage_dpp_connections_future.cancel()
                pending_futures.add(state.manage_dpp_connections_future)

        if len(pending_futures) > 0:
            # This should never happen outside of in development errors. We include it both for
            # that reason and also in case it unexpectedly happens, the user does not have a
            # zombie wallet process.
            for lagging_future in pending_futures:
                lagging_future.cancel()
            self._logger.error("Network related tasks shutdown uncleanly (cancelled %d)",
                len(pending_futures))
        else:
            self._logger.debug("Network related tasks shutdown cleanly")

    def create_gui_handler(self, window: WindowProtocol, account: AbstractAccount) -> None:
        for keystore in account.get_keystores():
            if isinstance(keystore, Hardware_KeyStore):
                plugin = cast('QtPluginBase', keystore.plugin)
                plugin.replace_gui_handler(window, keystore)

    async def _wait_for_chain_related_work_async(self, token: ChainWorkerToken,
            coroutine_callables: Optional[Sequence[Callable[[], Coroutine[Any, Any, Any]]]]=None) \
                -> None:
        """
        This should be called by a worker task to get permission to do another batch of work.
        Any worker task using this should be doing work that would otherwise engage in race
        conditions with the reorg task (should a reorg be in process).
        """
        while not self._stopped and not self._stopping:
            # We can proceed unless the chain management task requesting that we block and let it
            # work.
            if not self._is_chain_management_pending:
                if coroutine_callables is None:
                    return
                if len(coroutine_callables) == 0:
                    return

                # We don't just want to wait for work for the caller, we also want to exit and do
                # the appropriate thing if the chain management becomes pending. We use a task
                # because that is what `asyncio.wait` returns.
                chain_task = asyncio.create_task(self._chain_management_interrupt_event.wait(),
                    name="chain management interrupt")
                extended_awaitables: list[Awaitable[Any]] = \
                    [ entry() for entry in coroutine_callables ]
                extended_awaitables.append(chain_task)

                awaitables_done, _awaitables_pending = await asyncio.wait(extended_awaitables,
                    return_when=asyncio.FIRST_COMPLETED)

                # If there is a network shutdown event
                # If chain management is pending we stay here. Otherwise we exit to the caller.
                # If it is not set, one of the caller awaitables must have completed and we exit.
                if self._stopping or chain_task not in awaitables_done:
                    return
                assert self._is_chain_management_pending

            # Signal that we are waiting using the worker queue, then block on the chain management
            # queue until the chain management task completes it's work.
            self._chain_worker_queue.put_nowait(token)
            await self._chain_worker_queue.join()

    async def _chain_management_task(self) -> None:
        """
        Decoupled processing of blockchain header updates for the wallet's header source.

        Due to the wait on `_header_source_synchronised_event` this will not process updates until
        the blockchain server connection process has:

          1. Verified that the network object has finished synchronising the headers from the
             header source.
          2. Reconciled the wallet's last persisted blockchain state with the header source's
             current blockchain state in `_reconcile_wallet_with_header_source`.

        WARNING: We do not want to lose blockchain header updates so we expect certain guarantees.
            These are based on the asynchronous thread not yielding and the `self._current_chain`
            variable being used as a flag.

          1. The `process_header_source_update` function sends us updates as long as
             `self._current_chain` is set.
          2. The blockchain state reconciliation function `_reconcile_wallet_with_header_source`
             takes care not to block between getting the current header source blockchain state,
             processing it and setting `self._current_chain`.
        """
        # NOTE(technical-debt) This event is currently only set when a server is reconciled as a
        # header source. In the longer term we would want this to respond to updates to the
        # longest valid chain (if we are not following a server).
        self._logger.debug("Waiting to start chain management task")
        await self._start_chain_management_event.wait()
        assert self._current_chain is not None

        # These are the chain-related worker tasks this management task needs to coordinate with.
        expected_worker_tokens = {
            ChainWorkerToken.CONNECT_PROOF_CONSUMER, ChainWorkerToken.MAPI_MESSAGE_CONSUMER,
            ChainWorkerToken.OBTAIN_PROOF_WORKER, ChainWorkerToken.OBTAIN_TRANSACTION_WORKER,
        }

        self._logger.debug("Entered chain management task")
        while True:
            item_kind, item_data = await self._chain_management_queue.get()
            self._logger.debug("Acquired chain management work %s", item_kind)
            if item_kind == ChainManagementKind.BLOCKCHAIN_EXTENSION:
                extension_chain, new_headers = cast(tuple[Chain, list[Header]], item_data)
                assert self._current_chain is extension_chain
                self._current_tip_header = new_headers[-1]

                self._storage.put("current_tip_hash",
                    hash_to_hex_str(self._current_tip_header.hash))

                for header in new_headers:
                    logger.info("New tip hash: %s, height: %s", hash_to_hex_str(header.hash),
                        header.height)
                    self._connect_headerless_proof_worker_state.header_queue.put_nowait(
                        (header, extension_chain))
                self._connect_headerless_proof_worker_state.header_event.set()

                if self._network is not None:
                    self._network.trigger_callback(NetworkEventNames.GENERIC_UPDATE)
                continue
            elif item_kind == ChainManagementKind.BLOCKCHAIN_REORGANISATION:
                new_chain, orphaned_block_hashes, new_headers = cast(
                    tuple[Chain, list[bytes], list[Header]], item_data)
            else:
                raise NotImplementedError(f"Unexpected item kind={item_kind}, data={item_data}")

            # Signal the chain-related workers to complete their current batch and block.
            self._is_chain_management_pending = True
            self._chain_management_interrupt_event.set()
            # Wait for all the worker tasks to compete their current batches and block.
            signalled_worker_tokens = set[ChainWorkerToken]()
            while signalled_worker_tokens != expected_worker_tokens:
                self._logger.debug("Awaiting chain management workers %s",
                    expected_worker_tokens-signalled_worker_tokens)
                try:
                    worker_token = await asyncio.wait_for(self._chain_worker_queue.get(), 10.0)
                except asyncio.TimeoutError:
                    self._logger.exception("Timed out waiting for a worker to block, have %s",
                        signalled_worker_tokens)
                    # It is assumed that if this happens, the code is broken and the reliability
                    # of the application cannot be guaranteed.
                    # TODO(1.4.0) Unreliable application, issue#906. Clean shutdown failure.
                    return

                assert worker_token in expected_worker_tokens
                signalled_worker_tokens.add(worker_token)

            # This blocks the current task so we need to be sure there are not race conditions.
            # The problem would be with header source updates. However, that does delta changes
            # relative to the header source's fork, and those are queued for this task to process
            # so they still happen in order.
            await self.on_reorg(orphaned_block_hashes, new_chain)
            self._update_current_chain(new_chain, new_headers[-1])

            self._logger.debug("Post reorg wallet chain %d->%d:%s",
                new_chain.first_height, new_headers[-1].height,
                hash_to_hex_str(new_headers[-1].hash))

            # This task consumes data produced by the wallet header processing we need to ensure
            # it flushes stale data and starts from the current (post-reorg) database state.
            self._connect_headerless_proof_worker_state.requires_reload = True

            # Reawaken all the worker tasks
            self._is_chain_management_pending = False
            self._chain_management_interrupt_event.clear()
            for worker_token in signalled_worker_tokens:
                self._chain_worker_queue.task_done()

    async def _reconcile_wallet_with_header_source(self,
            server_state: Optional[HeaderServerState], header_source_chain: Chain,
            header_source_tip_header: Header) -> None:
        """
        Before the wallet starts modifying blockchain related data, it needs to reconcile it's
        last position (what fork and what height) on the blockchain against the current state
        of it's header source.

        CorrectHeaderSequence: We require a set of guarantees from different places in order to
        ensure that blockchain state transitions for the wallet are in order.
            1. `_reconcile_wallet_with_header_source` is called in the application state async loop.
            2. `process_header_source_update` is only called from tasks running in the application
               state async loop.
        This means that there is no chance that updates will come in while this function is
        executing unless we block, and we only block in the explicit reorg call.

        Caveats (must be true or the wallet chain state can corrupt it's blockchain data):
        1. The caller must be providing the chain and header for the header source, and
           they should be the current values for that header source when we are called.
        """
        self._blockchain_server_state = server_state
        self._blockchain_server_state_ready = False

        if self._current_chain is None:
            # Adopt the given header source as the initial chain state of the wallet.
            if self._persisted_tip_hash is not None:
                assert self._current_tip_header is None

                # Ensure the header store has the current chain tip header for this wallet.
                try:
                    header, chain = app_state.lookup_header(self._persisted_tip_hash)
                except MissingHeader:
                    # Either the header store has been deleted, or the wallet database has been
                    # moved to another computer with a different header store. As the headers are
                    # known to be synchronised, it should be assumed that the fork the wallet has
                    # been following up to now was reorged and is no longer relevant.
                    detached_wallet_tip = True
                else:
                    detached_wallet_tip = False

                    # Guarantees relating to these calls: Search for CorrectHeaderSequence.
                    self._update_current_chain(chain, header)
                    self._logger.debug("Continuing existing wallet chain %d->%d:%s",
                        chain.first_height, header.height, hash_to_hex_str(header.hash))
                    assert self.process_header_source_update(server_state, chain, header,
                        header_source_chain, header_source_tip_header, force=True)
            else:
                detached_wallet_tip = True

            if detached_wallet_tip:
                # Either this is a new wallet or it is an old wallet that predates storage of this
                # record. We have to do a full table scan to rectify this situation, but none of
                # these wallets should have that many transactions.
                orphaned_block_hashes = list[bytes]()
                for block_hash in db_functions.read_transaction_block_hashes(self._db_context):
                    try:
                        transaction_header, transaction_chain = app_state.lookup_header(block_hash)
                    except MissingHeader:
                        orphaned_block_hashes.append(block_hash)
                    else:
                        if transaction_chain is header_source_chain:
                            continue

                        common_chain, common_height = cast(tuple[Optional[Chain], int],
                            transaction_chain.common_chain_and_height(header_source_chain))
                        if common_height == -1:
                            # TODO(1.4.0) Unreliable application, issue#906. Different blockchain.
                            raise Exception("Broken header source; claims to have different "
                                "blockchain")

                        # This block is on a different fork from the wallet's header source.
                        if common_height < transaction_header.height:
                            orphaned_block_hashes.append(block_hash)

                # Reorging blocks this task while the database writes happen and allows the chance
                # that the header source may have updates in the meantime that get ignored because
                # `_blockchain_server_state_ready` is `False`. These would be lost and result in
                # possible corruption so we get the current chain and header of the header source,
                # and check for changes and process them before proceeding.

                if len(orphaned_block_hashes) > 0:
                    await self.on_reorg(orphaned_block_hashes, header_source_chain)

                # Guarantees relating to these calls: Search for CorrectHeaderSequence.
                updated_header_source_chain, updated_header_source_tip_header = \
                    self.get_header_source_state(server_state)
                if header_source_tip_header != updated_header_source_tip_header:
                    assert self.process_header_source_update(server_state, header_source_chain,
                        header_source_tip_header, updated_header_source_chain,
                        updated_header_source_tip_header, force=True)
                self._update_current_chain(header_source_chain, header_source_tip_header)
                self._logger.debug("Processed detached wallet chain %d->%d:%s",
                    header_source_chain.first_height,
                    header_source_tip_header.height, hash_to_hex_str(header_source_tip_header.hash))
        else:
            # Switch header sources for an already initialised wallet with a current chain.
            assert self._current_tip_header is not None
            # Guarantees relating to these calls: Search for CorrectHeaderSequence.
            self._update_current_chain(header_source_chain, header_source_tip_header)
            self._logger.debug("Switched wallet chain %d->%d:%s", header_source_chain.first_height,
                header_source_tip_header.height, hash_to_hex_str(header_source_tip_header.hash))
            assert self.process_header_source_update(server_state, self._current_chain,
                self._current_tip_header, header_source_chain,
                header_source_tip_header, force=True)

        self._blockchain_server_state_ready = True
        self._start_chain_management_event.set()
        if server_state is not None:
            self._header_source_synchronised_event.set()

    def _update_current_chain(self, chain: Chain, header: Header) -> None:
        """
        Update the chain and tip header for the wallet's header source.

        We might be setting this for the first time or updating it for several potential reasons.

        Guarantees:
        * This is non-blocking. Both to any asynchronous thread loop and to any thread.
          Database writes are posted to the writer thread, and no blocking is done to wait for
          their completion.
        """
        # The header store includes our current tip header.
        self._current_chain = chain
        self._current_tip_header = header

        self._storage.put("current_tip_hash", hash_to_hex_str(self._current_tip_header.hash))

    def process_header_source_update(self, server_state: Optional[HeaderServerState],
            previous_chain: Chain, previous_tip_header: Header, current_chain: Chain,
            current_tip_header: Header, force: bool=False) -> bool:
        """
        Process a change to the headers on one of our header sources. This may be the P2P network
        or one selected blockchain server the wallet knows of.

        Processing changes and race conditions
        --------------------------------------

        In the normal case, this task processes delta changes for the header source. However these
        still need to be linked to the wallet's initial last processed header which was loaded
        from the database. This happens in `_reconcile_wallet_with_header_source` and it is the
        one initial case where this is called directly by the wallet, rather than by the network
        object with updates. It also sets the `current_chain` which will not have been set until
        then causing all header source updates that were received before then to be discarded.

        Why the central header store is not directly usable
        ---------------------------------------------------

        A given wallet instance cannot rely on the central bitcoinx header store as an indicator of
        what block notifications the wallet instance has processed. It must instead follow a
        specific header source and the choice of followed fork for that header source. The central
        header store is a superset of any header source ElectrumSV is obtaining headers through,
        which means a wallet must know how to map it's header source and what state it has
        processed to the headers in the central header store.

        How we tell when there is a reorg
        ---------------------------------

        It does not necessarily mean anything that the chain object changed. This does not
        indicate a reorg, it just indicates that the centralised header store received the
        header at the given height for this header source after another header at the given
        height. The first header at that height extends that chain, and any additional headers
        at that height each become the first header in new "bitcoinx chains".

        The key question is whether we need to look back at previously processed heights and
        reorg the transactions that have merkle proofs on a different fork. We do not care if
        the chain object has changed unless this shows that we have forked off at a lower height
        than we have already processed.

        NOTE The P2P network is not currently supported.
        """
        assert app_state.headers is not None

        if self._is_wallet_header_source(server_state):
            # `_reconcile_wallet_with_header_source` sets this before we make use of these updates.
            if not (force or self._blockchain_server_state_ready):
                return False

            # This update is relevant for the wallet as this is our header source.
            fork_height = -1
            last_processed_height = previous_tip_header.height
            if current_chain is previous_chain:
                is_reorg = False
            else:
                _chain, fork_height = cast(tuple[Optional[Chain], int],
                    previous_chain.common_chain_and_height(current_chain))
                if fork_height == -1:
                    # TODO(1.4.0) Unreliable application, issue#906. On different blockchain.
                    raise Exception("Broken header source; claims to have different blockchain")
                elif fork_height > last_processed_height:
                    # The fork happens after the last block header we have processed. When these
                    # headers are processed, we will switch the current chain to this fork chain.
                    is_reorg = False
                else:
                    # The fork happens on a block header we have already processed.
                    is_reorg = True

            if is_reorg:
                assert fork_height > -1
                orphaned_block_hashes = [app_state.header_at_height(previous_chain, h).hash
                    for h in range(fork_height + 1, last_processed_height + 1)]
                new_block_headers = [app_state.header_at_height(current_chain, h) for h in
                    range(fork_height + 1, current_tip_header.height + 1)]

                block_hashes_as_str = [hash_to_hex_str(h) for h in orphaned_block_hashes]
                logger.info("Reorg detected; undoing wallet verifications for block hashes %s",
                    block_hashes_as_str)

                self._chain_management_queue.put_nowait(
                    (ChainManagementKind.BLOCKCHAIN_REORGANISATION,
                        (current_chain, orphaned_block_hashes, new_block_headers)))
            elif last_processed_height != current_tip_header.height:
                new_block_headers = [app_state.header_at_height(current_chain, h) for h in
                    range(last_processed_height + 1, current_tip_header.height + 1)]

                self._chain_management_queue.put_nowait(
                    (ChainManagementKind.BLOCKCHAIN_EXTENSION, (current_chain, new_block_headers)))
            return True
        else:
            # If anything is forcing an update and does not know the correct header source then
            # we have problems we should flag.
            assert not force
            # TODO(1.4.0) Headers, issue#915. This is not our header source, does it have
            #     repercussions for us? We can detect a stall. We can detect a longer chain and
            #     warn the user if relevant?
            return False

    def _is_wallet_header_source(self, server_state: Optional[HeaderServerState]) -> bool:
        if self._blockchain_server_state is not None:
            # Header source: The explicitly or implicitly user selected blockchain server.
            # We have to follow them as a header source because they will be providing results
            # from their blockchain APIs based on their choice of preferred chain (this may be
            # automatically the longest or a manual override if perhaps there is an attack on the
            # chain).
            return server_state == self._blockchain_server_state
        elif server_state is not None:
            # Header source: A server's header API.
            # TODO(1.4.0) Headers, issue#915. If no blockchain server wanted / no P2P access.
            #     Follow headers from the most acceptable chain seen on the <= 5 header API servers
            #     we should be connecting to.
            return False
        else:
            # Header source: P2P.
            # TODO(1.4.0) Headers, issue#915. If no blockchain server wanted, but we have P2P
            #     access. Follow headers from the most acceptable chain seen through P2P (we
            #     should not use header API servers in this case at all).
            return True

    async def obtain_transactions_async(self, account_id: int, keys: list[tuple[bytes, bool]],
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) -> set[bytes]:
        """
        Update the registry of transactions we do not have or are in the process of getting.

        It is optional whether the caller wants

        Return the hashes out of `tx_hashes` that do not already exist and will attempt to be
        acquired.
        """
        async with self._obtain_transactions_async_lock:
            missing_tx_hashes: set[bytes] = set()
            existing_tx_hashes = set(r.tx_hash for r in self.data.read_transactions_exist(
                [ key[0] for key in keys ]))
            for tx_hash, with_proof in keys:
                if tx_hash in existing_tx_hashes:
                    continue
                if tx_hash in self._missing_transactions:
                    # These transactions are not in the database, metadata is tracked in the entry
                    # and we should update it.
                    self._missing_transactions[tx_hash].import_flags |= import_flags
                    self._missing_transactions[tx_hash].with_proof |= with_proof
                    if account_id not in self._missing_transactions[tx_hash].account_ids:
                        self._missing_transactions[tx_hash].account_ids.append(account_id)
                else:
                    self._missing_transactions[tx_hash] = MissingTransactionEntry(import_flags,
                        with_proof, [ account_id ])
                    missing_tx_hashes.add(tx_hash)

            self._logger.debug("Registering %d missing transactions", len(missing_tx_hashes))
            # Prompt the missing transaction logic to try again if the user is re-registering
            # already missing transactions (the `TransactionImportFlag.PROMPTED` check).
            if len(missing_tx_hashes) or import_flags & TransactionImportFlag.PROMPTED:
                self._check_missing_transactions_event.set()
            return missing_tx_hashes

    async def _obtain_transactions_worker_async(self) -> None:
        assert app_state.headers is not None
        self._logger.debug("_obtain_transactions_worker_async entered")

        # We need the header source to be fully synchronised before we start.
        await self._header_source_synchronised_event.wait()
        self._logger.debug("_obtain_transactions_worker_async started")

        # To get here there must not have been any further missing transactions.
        self._check_missing_transactions_event.set()
        while not (self._stopping or self._stopped):
            # This blocks until there is pending work and it is safe to perform it.
            self._logger.debug("Waiting for more missing transactions")
            await self._wait_for_chain_related_work_async(
                ChainWorkerToken.OBTAIN_TRANSACTION_WORKER,
                [ self._check_missing_transactions_event.wait ])
            if self._stopping or self._stopped:
                return

            state = self.get_connection_state_for_usage(NetworkServerFlag.USE_BLOCKCHAIN)
            assert state is not None

            self._check_missing_transactions_event.clear()

            while len(self._missing_transactions):
                tx_hash: bytes
                entry: MissingTransactionEntry
                async with self._obtain_transactions_async_lock:
                    if not len(self._missing_transactions):
                        break
                    # In theory this should pick missing transactions in order of insertion.
                    tx_hash = next(iter(self._missing_transactions))
                    self._logger.debug("Picked missing transaction %s", hash_to_hex_str(tx_hash))
                    entry = self._missing_transactions[tx_hash]

                # The request gets billed to the first account to request a transaction.
                account_id = entry.account_ids[0]
                account = self._accounts[account_id]

                if entry.with_proof:
                    try:
                        tsc_full_proof_bytes = await request_binary_merkle_proof_async(state,
                            tx_hash, include_transaction=True)
                    except ServerConnectionError:
                        # TODO(1.4.0) Unreliable server, issue#841. Server error for proof request.
                        #     No reliable server should cause this, we should stand off the server
                        #     or something similar.
                        logger.error("Still need to implement handling for inability to connect"
                            "to a server to get arbitrary merkle proofs, sleeping 60 seconds")
                        await asyncio.sleep(60)
                        continue
                    except IndexerResponseMissingError:
                        # There is no proof for this transaction. Just get the transaction.
                        entry.with_proof = False
                        continue
                    except FilterResponseInvalidError as response_exception:
                        # TODO(1.4.0) Unreliable server, issue#841. Tip filter response invalid.
                        #     No reliable server should cause this, we should stand off the server
                        #     or something similar. For now we exit the loop and let the user cause
                        #     other events that allow retry by setting the event.
                        logger.error("Server responded to proof request with error %s",
                            str(response_exception))
                        break

                    try:
                        tsc_full_proof = TSCMerkleProof.from_bytes(tsc_full_proof_bytes)
                    except TSCMerkleProofError:
                        # TODO(1.4.0) Unreliable server, issue#841. Provided merkle proof invalid.
                        #     No trustable server should cause this, we should disable the server or
                        #     something similar.
                        self._logger.error("Still need to implement handling for inability to "
                            "connect to a server to get arbitrary merkle proofs")
                        return

                    assert tsc_full_proof.block_hash is not None
                    try:
                        header, chain = app_state.lookup_header(tsc_full_proof.block_hash)
                    except MissingHeader:
                        # Missing header therefore add the transaction as TxFlags.STATE_CLEARED with
                        # proof data until the late_header_worker_async gets the required header.
                        tx_bytes, tsc_proof = separate_proof_and_embedded_transaction(
                            tsc_full_proof, tx_hash)
                        assert tsc_proof.block_hash is not None

                        tx = Transaction.from_bytes(tx_bytes)
                        await self.import_transaction_async(tx_hash, tx, TxFlags.STATE_CLEARED,
                            BlockHeight.MEMPOOL)

                        proof_row = MerkleProofRow(tsc_proof.block_hash,
                            tsc_proof.transaction_index, -1, tsc_proof.to_bytes(), tx_hash)
                        await self.data.create_merkle_proofs_async([ proof_row ])

                        # The late header worker task can verify this proof.
                        self._connect_headerless_proof_worker_state.proof_queue.put_nowait(
                            (tsc_proof, proof_row))
                        self._connect_headerless_proof_worker_state.proof_event.set()

                        assert tx_hash not in self._missing_transactions
                        continue

                    try:
                        if not verify_proof(tsc_full_proof, header.merkle_root):
                            # TODO(1.4.0) Unreliable server, issue#841. Merkle proof verify fails.
                            self._logger.error("Still need to implement handling for receiving "
                                "invalid merkle proofs")
                            return
                    except TSCMerkleProofError:
                        # TODO(1.4.0) Unreliable server, issue#841. Merkle proof verify invalid.
                        self._logger.error("Still need to implement handling for receiving "
                            "invalid merkle proofs")
                        return

                    # Separate the transaction data and the proof data for storage.
                    tx_bytes, tsc_proof = separate_proof_and_embedded_transaction(tsc_full_proof,
                        tx_hash)
                    assert tsc_proof.block_hash is not None
                    tx = Transaction.from_bytes(tx_bytes)

                    proof_row = MerkleProofRow(tsc_proof.block_hash,
                        tsc_proof.transaction_index, header.height, tsc_proof.to_bytes(), tx_hash)

                    block_height = cast(int, header.height)
                    if self.is_header_within_current_chain(header.height, tsc_proof.block_hash):
                        await self.import_transaction_async(tx_hash, tx, TxFlags.STATE_SETTLED,
                            block_height, tsc_proof.block_hash, tsc_proof.transaction_index,
                            proof_row=proof_row)
                    else:
                        await self.import_transaction_async(tx_hash, tx, TxFlags.STATE_CLEARED,
                            block_height)
                        await self.data.create_merkle_proofs_async([ proof_row ])

                    assert tx_hash not in self._missing_transactions
                else:
                    tx_bytes = await self.fetch_raw_transaction_async(tx_hash, account)
                    tx = Transaction.from_bytes(tx_bytes)
                    await self.import_transaction_async(tx_hash, tx, TxFlags.STATE_CLEARED,
                        BlockHeight.MEMPOOL)
                    assert tx_hash not in self._missing_transactions

    async def _obtain_merkle_proofs_worker_async(self) -> None:
        """
        Obtain TSC merkle proofs for transactions we know are mined.

        This is currently only used to obtain merkle proofs for the following cases:

        - We delete the older non-TSC proof from `STATE_SETTLED` transactions in migration 29.
          Those transactions need a new TSC proof, and that should happen in the first iteration
          given ability to access and use a server successfully.

        It is planned that this would also handle the following cases:

        - If we have transactions we did not obtain through either restoration scanning (which
          provides merkle proofs) or through some mechanism where MAPI delivers the proof (either
          to our channel or another party's channel where they deliver it to us) then we need to
          manually obtain the proof ourselves. This would need some other external event source
          where we find out whether transactions have been mined, like output spend notifications.
        """
        assert app_state.headers is not None

        # We need the header source to be fully synchronised before we start.
        await self._header_source_synchronised_event.wait()

        # TODO(1.4.0) Networking, issue#916. If the user does not have their internet connection
        #     enabled when the wallet is first opened, then this will maybe error and exit or block.
        #     We should be able to detect problems like this and highlight it to the user, and retry
        #     periodically or when they manually indicate they want to retry.
        self._check_missing_proofs_event.set()
        while not (self._stopping or self._stopped):
            # This blocks until there is pending proof connection work and it is safe to perform it.
            await self._wait_for_chain_related_work_async(ChainWorkerToken.OBTAIN_PROOF_WORKER, [
                self._check_missing_proofs_event.wait ])
            if self._stopping or self._stopped:
                return

            state = self.get_connection_state_for_usage(NetworkServerFlag.USE_BLOCKCHAIN)
            assert state is not None

            self._check_missing_proofs_event.clear()

            # We just take the first returned transaction for now (and ignore the rest).
            rows = db_functions.read_proofless_transactions(self.get_db_context())
            tx_hash = rows[0].tx_hash if len(rows) else None
            if len(rows) > 0:
                # We want to make sure we read any other transactions other than the first.
                if len(rows) > 1:
                    self._check_missing_proofs_event.set()

                row = rows[0]
                tx_hash = row.tx_hash
                self._logger.debug("Requesting merkle proof from server for transaction %s",
                    hash_to_hex_str(row.tx_hash))
                try:
                    tsc_full_proof_bytes = await request_binary_merkle_proof_async(state, tx_hash,
                        include_transaction=False)
                except ServerConnectionError:
                    # TODO(1.4.0) Unreliable server, issue#841. Error connecting to server.
                    #     No reliable server should cause this, we should stand off the server or
                    #     something similar.
                    self._logger.error("Still need to implement handling for inability to connect"
                        "to a server to get arbitrary merkle proofs")
                    await asyncio.sleep(60)
                    continue

                try:
                    tsc_proof = TSCMerkleProof.from_bytes(tsc_full_proof_bytes)
                except TSCMerkleProofError:
                    # TODO(1.4.0) Unreliable server, issue#841. Non-parseable merkle proof.
                    #     No trustable server should cause this, we should disable the server or
                    #     something similar.
                    self._logger.error("Still need to implement handling for inability to connect"
                        "to a server to get arbitrary merkle proofs")
                    return

                assert tsc_proof.block_hash is not None
                try:
                    header, chain = app_state.lookup_header(tsc_proof.block_hash)
                except MissingHeader:
                    # We store the proof in a way where we know we obtained it recently, but
                    # that it is still in need of processing. The late header worker can
                    # read these in on startup and will get it via the queue at runtime.
                    # date_updated = get_posix_timestamp()
                    proof_row = MerkleProofRow(tsc_proof.block_hash,
                        tsc_proof.transaction_index, -1, tsc_proof.to_bytes(), tx_hash)
                    await self.data.create_merkle_proofs_async([ proof_row  ])

                    self._connect_headerless_proof_worker_state.proof_queue.put_nowait(
                        (tsc_proof, proof_row))
                    self._connect_headerless_proof_worker_state.proof_event.set()
                    continue

                try:
                    if not verify_proof(tsc_proof, header.merkle_root):
                        # TODO(1.4.0) Unreliable server, issue#841. Merkle proof verify fails.
                        self._logger.error("Still need to implement handling for inability to "
                            "connect to a server to get arbitrary merkle proofs")
                        return
                except TSCMerkleProofError:
                    # TODO(1.4.0) Unreliable server, issue#841. Merkle proof invalid on verify.
                    self._logger.error("Still need to implement handling for receiving "
                        "invalid merkle proofs")
                    return

                block_height = cast(int, header.height)
                if self.is_header_within_current_chain(header.height, tsc_proof.block_hash):
                    self._logger.debug("OMP Storing verified merkle proof for transaction %s",
                        hash_to_hex_str(row.tx_hash))

                    # This proof is valid for the wallet's view of the blockchain.
                    date_updated = get_posix_timestamp()
                    tx_update_row = TransactionProofUpdateRow(tsc_proof.block_hash, block_height,
                        tsc_proof.transaction_index, TxFlags.STATE_SETTLED, date_updated,
                        row.tx_hash)
                    proof_row = MerkleProofRow(tsc_proof.block_hash,
                        tsc_proof.transaction_index, header.height, tsc_proof.to_bytes(),
                        row.tx_hash)
                    await self.data.update_transaction_proof_async([ tx_update_row ],
                        [ proof_row ], [], [])

                    self.events.trigger_callback(WalletEvent.TRANSACTION_VERIFIED, tx_hash, header,
                        tsc_proof)
                else:
                    proof_row = MerkleProofRow(tsc_proof.block_hash,
                        tsc_proof.transaction_index, block_height, tsc_proof.to_bytes(), tx_hash)
                    await self.data.create_merkle_proofs_async([ proof_row  ])

                    self._connect_headerless_proof_worker_state.proof_queue.put_nowait(
                        (tsc_proof, proof_row))
                    self._connect_headerless_proof_worker_state.proof_event.set()

    async def _connect_headerless_proofs_worker_async(self) -> None:
        # We need the header source to be fully synchronised before we start.
        await self._header_source_synchronised_event.wait()

        assert self._connect_headerless_proof_worker_state is not None

        state = self._connect_headerless_proof_worker_state
        state.requires_reload = True

        while not (self._stopping or self._stopped):
            if state.requires_reload:
                state.requires_reload = False

                # Any state that is there is there with the understanding that it is already in
                # the database or would be reconciled when this task first runs.
                state.reset()

                # Gather the existing unconnected proofs from the database.
                for proof_row in self.data.read_unconnected_merkle_proofs():
                    proof = TSCMerkleProof.from_bytes(proof_row.proof_data)
                    state.proof_queue.put_nowait((proof, proof_row))
                # If there is data to process ensure we start right away.
                if state.proof_queue.qsize() > 0:
                    state.proof_event.set()

            # This blocks until there is pending proof connection work and it is safe to perform it.
            await self._wait_for_chain_related_work_async(ChainWorkerToken.CONNECT_PROOF_CONSUMER, [
                    state.header_event.wait,      # Set when there are pending headers.
                    state.proof_event.wait,       # Set when there are pending proofs.
                ])
            if self._stopping or self._stopped:
                return

            process_entries = list[tuple[Header, tuple[TSCMerkleProof, MerkleProofRow]]]()

            # This is non-blocking. We know it empties all the pending proofs.
            if state.proof_event.is_set():
                pending_proof_entries = list[tuple[TSCMerkleProof, MerkleProofRow]]()
                while state.proof_queue.qsize() > 0:
                    pending_proof_entries.append(state.proof_queue.get_nowait())
                state.proof_event.clear()

                for proof_entry in pending_proof_entries:
                    proof = proof_entry[0]
                    assert proof.transaction_hash is not None
                    block_hash = proof.block_hash
                    if block_hash is None:
                        assert proof.block_header_bytes is not None
                        block_hash = double_sha256(proof.block_header_bytes)
                    lookup_result = self.lookup_header_for_hash(block_hash)
                    if lookup_result is None:
                        logger.debug("Backlogged transaction %s verification waiting for missing "
                            "header", hash_to_hex_str(proof.transaction_hash))
                        if state.block_transactions.get(block_hash) is None:
                            state.block_transactions[block_hash] = []
                        state.block_transactions[block_hash].append(proof_entry)
                    else:
                        header, _common_chain = lookup_result
                        process_entries.append((header, proof_entry))

            # This is non-blocking. We know it empties all the pending headers.
            if state.header_event.is_set():
                pending_headers = list[tuple[Header, Chain]]()
                while state.header_queue.qsize() > 0:
                    pending_headers.append(state.header_queue.get_nowait())
                state.header_event.clear()

                for header, chain in pending_headers:
                    assert chain == self._current_chain
                    block_hash = header.hash
                    if block_hash in state.block_transactions:
                        for proof_entry in state.block_transactions[block_hash]:
                            process_entries.append((header, proof_entry))
                        del state.block_transactions[block_hash]

            date_updated = get_posix_timestamp()
            transaction_proof_updates = list[TransactionProofUpdateRow]()
            proof_updates = list[MerkleProofUpdateRow]()
            verified_proof_entries = list[tuple[Header, tuple[TSCMerkleProof, MerkleProofRow]]]()

            for process_entry in process_entries:
                header, (proof, proof_row) = process_entry
                assert proof.transaction_hash is not None
                # Proofs come in different formats. Some embed the header.
                if proof.block_header_bytes is not None:
                    proof_block_hash = double_sha256(proof.block_header_bytes)
                    verified = proof_block_hash == header.hash and verify_proof(proof)
                else:
                    proof_block_hash = proof.block_hash
                    assert proof_block_hash is not None
                    verified = verify_proof(proof, header.merkle_root)

                if verified:
                    block_height = cast(int, header.height)
                    transaction_proof_updates.append(TransactionProofUpdateRow(proof_block_hash,
                        block_height, proof.transaction_index, TxFlags.STATE_SETTLED, date_updated,
                        proof.transaction_hash))
                    verified_proof_entries.append(process_entry)
                    proof_updates.append(MerkleProofUpdateRow(block_height, proof_block_hash,
                        proof_row.tx_hash))
                else:
                    # TODO(1.4.0) Unreliable server#issue841. Invalid proof when connecting to hdr.
                    #     We probably want to know what server this came from so we can treat it as
                    #     a bad server. And we would want to retry with a good server.
                    logger.error("Deferred verification transaction %s failed verifying proof",
                        hash_to_hex_str(proof.transaction_hash))
                    # Remove the "pending verification" proof and block data from the transaction,
                    # it should not be necessary to update the UI as the transaction should not have
                    # changed state and we do not display "pending verification" proofs.
                    transaction_proof_updates.append(TransactionProofUpdateRow(None,
                        BlockHeight.MEMPOOL, None, TxFlags.STATE_CLEARED, date_updated,
                        proof.transaction_hash))

            await self.data.update_transaction_proof_async(transaction_proof_updates, [],
                proof_updates, [])

            for header, (proof, _proof_row) in verified_proof_entries:
                self.data.events.trigger_callback(WalletEvent.TRANSACTION_VERIFIED,
                    proof.transaction_hash, header, proof)

    # Helper methods to access blockchain data that can be seen through the wallet's view of the it.

    def get_header_source_state(self, server_state: Optional[HeaderServerState]) \
            -> tuple[Chain, Header]:
        if server_state is None:
            chain = get_longest_valid_chain()
            tip_header = cast(Header, chain.tip)
            return chain, tip_header

        assert server_state.chain is not None
        assert server_state.tip_header is not None
        return server_state.chain, server_state.tip_header

    def get_local_height(self) -> int:
        """
        Gets the height of the latest header that the wallet has processed.

        This will return `0` if the wallet has no discernable latest header.
        """
        # If we do not know the wallet blockchain state we cannot know the height it is at.
        if self._current_chain is None:
            return 0

        assert self._current_tip_header is not None
        return cast(int, self._current_tip_header.height)

    def is_header_within_current_chain(self, height: int, block_hash: bytes) -> bool:
        """
        Identify if the block at the given height on the current chain has the given hash.

        Raises no exceptions.
        """
        # If we do not know the wallet blockchain state we cannot lookup any header.
        if self._current_chain is None:
            return False

        assert self._current_tip_header is not None
        if height > self._current_tip_header.height:
            return False
        try:
            header_bytes = app_state.raw_header_at_height(self._current_chain, height)
        except MissingHeader:
            return False
        return cast(bytes, double_sha256(header_bytes)) == block_hash

    def lookup_header_for_height(self, block_height: int) -> Optional[Header]:
        """
        """
        if self._current_chain is None:
            return None
        try:
            return app_state.header_at_height(self._current_chain, block_height)
        except MissingHeader:
            return None

    def lookup_header_for_hash(self, block_hash: bytes, force_chain: Chain | None=None) \
            -> Optional[tuple[Header, Chain]]:
        """
        Lookup the header based on the wallet's current chain state.

        The wallet cannot allow access to the header store as a way of asserting what the wallet
        does or does not know about the blockchain. What the wallet knows about the blockchain
        is dependent on it's header source, which in the case of a blockchain service provider
        will have to follow the chain state of that provider.

        All chain state access relative to a given wallet should happen through the `Wallet`
        instance, using helper methods like this.
        """
        lookup_chain = force_chain
        if lookup_chain is None:
            lookup_chain = self._current_chain

        # If we do not know the wallet blockchain state we cannot lookup any header.
        if lookup_chain is None:
            return None

        try:
            header, chain = app_state.lookup_header(block_hash)
        except MissingHeader:
            return None

        # Case: We are on a fork from the longer chain and the header lies within our fork.
        # Case: We are on the longer chain and the header lies within it.
        if chain is lookup_chain:
            return header, chain

        # Case: We are on a fork and the header lies on the longer chain we are attached to
        #       but at or below the common height (above that would be a different fork).
        common_chain: Optional[Chain]
        common_height: int
        common_chain, common_height = lookup_chain.common_chain_and_height(chain)
        # Case: We do not even share the Genesis block with the other chain. We could assert but
        #       it does not hurt to generically fail.
        if common_chain is None:
            return None

        # The header lies on the different fork.
        if header.height > common_height:
            return None

        # The header is at the common height or below on the common chain.
        return header, common_chain

    def reference(self) -> Wallet:
        return self


# NOTE(rt12) Is this the right level of abstraction? I do not know.
class TransactionCreationContext:
    unspent_outputs: Sequence[TransactionOutputSpendableProtocol] | None = None
    outputs: list[XTxOutput] | None = None
    selected_fee_quote: FeeQuoteCommon | None = None
    mapi_broadcast_hint: ServerAndCredential | None = None
    account: AbstractAccount | None = None

    def __init__(self) -> None:
        self._fee_quotes = list[TransactionFeeContext]()
        self._fee_quote_future: concurrent.futures.Future[list[TransactionFeeContext]] | None = None
        self.callbacks = list[Callable[[list[TransactionFeeContext]], None]]()

    def clean_up(self) -> None:
        if self._fee_quote_future is not None:
            self._fee_quote_future.cancel()
        self.account = None

    def set_account(self, account: AbstractAccount | None) -> None:
        self.account = account

    def set_unspent_outputs(self, unspent_outputs: Sequence[TransactionOutputSpendableProtocol]) \
            -> None:
        self.unspent_outputs = unspent_outputs

    def set_outputs(self, outputs: list[XTxOutput]) -> None:
        self.outputs = outputs

    def set_fee_quote(self, fee_quote: FeeQuoteCommon) -> None:
        self.selected_fee_quote = fee_quote

    def set_mapi_broadcast_hint(self, mapi_broadcast_hint: ServerAndCredential) -> None:
        self.mapi_broadcast_hint = mapi_broadcast_hint

    def create_transaction(self) -> tuple[Transaction, TransactionContext]:
        """
        Raises `ValueError` if no unspent outputs or outputs have been provided.
        """
        if self.account is None:
            raise ValueError("No account set")

        if self.unspent_outputs is None:
            raise ValueError("No unspent outputs set")

        if self.outputs is None:
            raise ValueError("No outputs set")

        mapi_fee_estimator: TransactionFeeEstimator | None = None
        if self.selected_fee_quote is not None:
            mapi_fee_estimator = TransactionFeeEstimator(self.selected_fee_quote,
                self.mapi_broadcast_hint)
        # If no fee context is specified it will use the wallet default.
        return self.account.make_unsigned_transaction(self.unspent_outputs, self.outputs,
            mapi_fee_estimator)

    def obtain_fee_quotes(self) -> None:
        # We cannot obtain fee quotes if we are offline.
        if self.account is None or self.account._wallet._network is None:
            return

        self._fee_quotes = []
        self._fee_quote_future = app_state.async_.spawn(self._obtain_fee_quotes_async(
            self._fee_quotes))
        self._fee_quote_future.add_done_callback(self._on_future_fee_quotes_done)

    async def _obtain_fee_quotes_async(self, fee_quotes: list[TransactionFeeContext]) \
            -> list[TransactionFeeContext]:
        """
        Map fee quote updates to a non-async context.

        Raises nothing.
        """
        assert self.account is not None
        account_id = self.account.get_id()
        async for server, credential_id in self.account._wallet.update_mapi_fee_quotes_async(
                account_id):
            server_state = server.api_key_state[credential_id]
            assert server_state.last_fee_quote is not None
            fee_context = TransactionFeeContext(server_state.last_fee_quote,
                ServerAndCredential(server, credential_id))
            fee_quotes.append(fee_context)

        return fee_quotes

    def _on_future_fee_quotes_done(self,
            future: concurrent.futures.Future[list[TransactionFeeContext]]) -> None:
        if future.cancelled():
            return

        # Skip handling if we were replaced by a new fee quote lookup before this attempt.
        fee_quotes = future.result()
        if fee_quotes is not self._fee_quotes:
            return

        # Select a fee quote and notify listeners.
        for callback in self.callbacks:
            callback(fee_quotes)
