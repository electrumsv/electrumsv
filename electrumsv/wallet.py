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
import base64
import binascii
import concurrent.futures
import dataclasses
from datetime import datetime, timezone
from enum import IntFlag
from functools import partial
import json
import os
import random
import threading
import time
from typing import Any, Callable, cast, Coroutine, Iterable, Literal, Sequence, TypedDict, \
    TypeVar, TYPE_CHECKING
import weakref

from bitcoinx import (Address, bip32_build_chain_string, bip32_decompose_chain_string,
    BIP32PrivateKey, Chain, double_sha256, Header, hash_to_hex_str, hex_str_to_hash, MissingHeader,
    P2PKH_Address, P2SH_Address, PrivateKey, PublicKey, Script)
from electrumsv_database.sqlite import DatabaseContext

from . import coinchooser
from .app_state import app_state
from .bitcoin import  scripthash_bytes, ScriptTemplate
from .constants import (ACCOUNT_SCRIPT_TYPES, AccountCreationType, AccountFlags, AccountType,
    API_SERVER_TYPES, BlockHeight, ChainManagementKind, ChainWorkerToken, CHANGE_SUBPATH,
    DatabaseKeyDerivationType, DEFAULT_TXDATA_CACHE_SIZE_MB, DerivationType, DerivationPath,
    DPPMessageType, KeyInstanceFlag, KeystoreTextType, KeystoreType, MAPIBroadcastFlag,
    MasterKeyFlags, MAX_VALUE,
    MAXIMUM_TXDATA_CACHE_SIZE_MB, MINIMUM_TXDATA_CACHE_SIZE_MB, NetworkEventNames,
    NetworkServerFlag, NetworkServerType, PaymentFlag, PeerChannelAccessTokenFlag,
    PeerChannelMessageFlag, PushDataHashRegistrationFlag, PushDataMatchFlag,
    PEER_CHANNEL_EXPIRY_SECONDS, RECEIVING_SUBPATH, SERVER_USES,
    ServerCapability, ServerConnectionFlag, ServerPeerChannelFlag, ScriptType,
    TransactionImportFlag, TransactionInputFlag, TransactionOutputFlag, TxFlags,
    unpack_derivation_path, WALLET_ACCOUNT_PATH_TEXT, WALLET_IDENTITY_PATH_TEXT, WalletEvent,
    WalletEventFlag, WalletEventType, WalletSettings)
from .contacts import Contacts
from .crypto import pw_decode, pw_encode
from .dpp_messages import Payment, PaymentACK, PaymentACKDict
from .exceptions import (BadServerError, Bip270Exception, BroadcastError, ExcessiveFee,
    InvalidPassword, NotEnoughFunds, NoViableServersError, PreviousTransactionsMissingException,
    ServerConnectionError, ServerError, ServiceUnavailableError, UnsupportedAccountTypeError,
    UnsupportedScriptTypeError, UserCancelled, WalletLoadError)
from .i18n import _
from .keystore import BIP32_KeyStore, Deterministic_KeyStore, Hardware_KeyStore, \
    Imported_KeyStore, instantiate_keystore, KeyStore, Multisig_KeyStore, Old_KeyStore, \
    SinglesigKeyStoreTypes, SignableKeystoreTypes, StandardKeystoreTypes, Xpub
from .logs import logs
from .network_support.api_server import APIServerDefinition, NewServer
from .network_support.direct_payments import dpp_make_ack, dpp_make_payment_error, \
    dpp_make_payment_request_response, send_outgoing_direct_payment_async, \
    dpp_make_payment_request_error
from .network_support.dpp_proxy import is_later_dpp_message_sequence, \
    close_dpp_server_connection_async, create_dpp_server_connection_async, \
    create_dpp_server_connections_async, dpp_websocket_send, find_connectable_dpp_server, \
    MESSAGE_STATE_BY_TYPE
from .network_support.exceptions import GeneralAPIError, FilterResponseInvalidError, \
    IndexerResponseMissingError, TransactionNotFoundError
from .network_support.general_api import create_reference_server_account_async, \
    create_tip_filter_registration_async, delete_tip_filter_registration_async, \
    maintain_server_connection_async, request_binary_merkle_proof_async, \
    request_transaction_data_async, upgrade_server_connection_async
from .network_support.peer_channel import maintain_external_peer_channel_connection_async
from .network_support.headers import get_longest_valid_chain
from .network_support.mapi import mapi_transaction_broadcast_async, update_mapi_fee_quotes_async
from .network_support.types import GenericPeerChannelMessage, PeerChannelServerState, \
    ServerConnectionProblems, ServerConnectionState, ServerStateProtocol, \
    TipFilterPushDataMatchesData, TipFilterRegistrationJobOutput, TokenPermissions
from .networks import Net
from .restapi_websocket import broadcast_restapi_event_async, BroadcastEventNames, \
    BroadcastEventPayloadNames, close_restapi_connection_async
from .standards.electrum_transaction_extended import transaction_from_electrumsv_dict
from .standards.json_envelope import JSONEnvelope, validate_json_envelope
from .standards.mapi import MAPICallbackResponse, validate_mapi_callback_response
from .standards.tsc_merkle_proof import separate_proof_and_embedded_transaction, TSCMerkleProof, \
    TSCMerkleProofError, TSCMerkleProofJson, verify_proof
from .storage import WalletStorage
from .transaction import (HardwareSigningMetadata, Transaction,
    TransactionContext, TransactionFeeEstimator, tx_dict_from_text, TxSerialisationFormat,
    XPublicKey, XTxInput, XTxOutput)
from .types import (BroadcastResult, ConnectHeaderlessProofWorkerState, DatabaseKeyDerivationData,
    FeeEstimatorProtocol, FeeQuoteCommon, IndefiniteCredentialId,
    KeyInstanceDataBIP32SubPath, KeyInstanceDataHash, KeyInstanceDataPrivateKey, KeyStoreResult,
    MAPIBroadcastResult, MasterKeyDataTypes, MasterKeyDataBIP32, MasterKeyDataElectrumOld,
    MasterKeyDataMultiSignature, MissingTransactionMetadata, Outpoint, OutputSpend,
    ServerAccountKey, ServerAndCredential, TransactionFeeContext, TransactionKeyUsageMetadata,
    WaitingUpdateCallback, WalletStatusDict)
from .util import format_satoshis, get_posix_timestamp, get_wallet_name_from_path, \
    TriggeredCallbacks, ValueLocks
from .util.cache import LRUCache
from .wallet_database.exceptions import DatabaseUpdateError, KeyInstanceNotFoundError, \
    TransactionAlreadyExistsError
from .wallet_database import functions as db_functions
from .wallet_database.types import (AccountRow, AccountTransactionDescriptionRow,
    AccountTransactionOutputSpendableRow, AccountTransactionOutputSpendableRowExtended,
    DPPMessageRow, ExternalPeerChannelRow, HistoryListRow, InvoiceAccountRow, InvoiceRow,
    KeyDataProtocol, KeyData, KeyInstanceFlagChangeRow, KeyInstanceRow, KeyListRow,
    MAPIBroadcastRow, MasterKeyRow, MerkleProofRow, NetworkServerRow, PasswordUpdateResult,
    PaymentRequestRow, PaymentRequestOutputRow, PaymentRequestUpdateRow, MerkleProofUpdateRow,
    PushDataHashRegistrationRow, PushDataMatchRow, PushDataMatchMetadataRow,
    ServerPeerChannelRow, PeerChannelAccessTokenRow, PeerChannelMessageRow, SpentOutputRow,
    TransactionDeltaSumRow, TransactionExistsRow, TransactionInputAddRow, TransactionLinkState,
    TransactionOutputAddRow, TransactionOutputSpendRow,
    TransactionOutputSpendableProtocol, TransactionOutputSpendableRow, TransactionProofUpdateRow,
    TransactionRow, TransactionValueRow, WalletBalance, WalletEventInsertRow, WalletEventRow)
from .wallet_database.util import create_derivation_data2
from .wallet_support.keys import get_multi_signer_script_template, \
    get_pushdata_hash_for_derivation, get_pushdata_hash_for_public_keys, \
    get_single_signer_script_template, map_transaction_output_key_usage


if TYPE_CHECKING:
    from .devices.hw_wallet.qt import QtPluginBase
    from .gui.qt.util import WindowProtocol
    from .network import Network
    from .network_support.headers import HeaderServerState
    from .restapi_websocket import LocalWebsocketState


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
    fiat_value: str|None
    fiat_balance: str|None


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
    match_metadatas: set[TransactionKeyUsageMetadata]
    with_proof: bool = False
    account_ids: list[int] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class HostedInvoiceCreationResult:
    request_row: PaymentRequestRow
    request_output_rows: list[PaymentRequestOutputRow]
    payment_url: str
    secure_public_key: PublicKey


ADDRESS_TYPES = { DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH }


T = TypeVar('T', bound='AbstractAccount')

class AbstractAccount:
    """
    Account classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    _default_keystore: KeyStore|None = None
    _stopped: bool = False

    MAX_SOFTWARE_CHANGE_OUTPUTS = 10
    MAX_HARDWARE_CHANGE_OUTPUTS = 1

    def __init__(self, wallet: Wallet, row: AccountRow) -> None:
        # Prevent circular reference keeping parent and accounts alive.
        self._wallet: Wallet = cast(Wallet, weakref.proxy(wallet))
        self._row = row
        self._id = row.account_id

        self._logger = logs.get_logger("account[{}]".format(self.name()))
        self._network: Network|None = None

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
                -> tuple[concurrent.futures.Future[None] | None, list[KeyInstanceRow]]:
        raise NotImplementedError

    def derive_script_template(self, derivation_path: DerivationPath,
            script_type: ScriptType | None=None) -> ScriptTemplate:
        raise NotImplementedError

    def allocate_and_create_keys(self, count: int, derivation_subpath: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> tuple[concurrent.futures.Future[None] | None, list[KeyInstanceRow]]:
        raise NotImplementedError

    def create_preallocated_keys(self, key_allocations: Sequence[KeyAllocation],
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> tuple[concurrent.futures.Future[None], list[KeyInstanceRow]]:
        """
        Take a list of key allocations and create keyinstances and scripts in the database for them.

        Key allocations are expected to be created in a safe context that prevents multiple
        allocations of the same key allocation parameters from being assigned to multiple callers.
        """
        account_id = self.get_id()
        keyinstance_rows: list[KeyInstanceRow] = []
        for ka in key_allocations:
            derivation_data_dict = self._create_derivation_data_dict(ka)
            derivation_data = json.dumps(derivation_data_dict).encode()
            derivation_data2 = create_derivation_data2(ka.derivation_type, derivation_data_dict)
            keyinstance_rows.append(KeyInstanceRow(-1, account_id, ka.masterkey_id,
                ka.derivation_type, derivation_data, derivation_data2,
                keyinstance_flags, None))
        return self._wallet.create_keyinstances(self._id, keyinstance_rows)

    def _create_derivation_data_dict(self, key_allocation: KeyAllocation) \
            -> KeyInstanceDataBIP32SubPath:
        assert key_allocation.derivation_type == DerivationType.BIP32_SUBPATH
        assert len(key_allocation.derivation_path)
        return { "subpath": key_allocation.derivation_path }

    def set_keyinstance_flags(self, keyinstance_ids: Sequence[int], flags: KeyInstanceFlag,
            mask: KeyInstanceFlag|None=None) \
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

    def get_keystore(self) -> KeyStore|None:
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
    def get_transaction(self, tx_hash: bytes) -> tuple[Transaction, TransactionContext]|None:
        """
        Get the transaction with account-specific metadata like the description.
        """
        tx = self._wallet.get_transaction(tx_hash)
        context: TransactionContext|None = None
        if tx is None:
            return None
        # Populate the description.
        context = TransactionContext()
        desc = self.get_transaction_label(tx_hash)
        if desc:
            context.account_descriptions[self._id] = desc
        return tx, context

    def set_transaction_label(self, tx_hash: bytes, text: str|None) \
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

    def set_keyinstance_label(self, keyinstance_id: int, text: str | None) \
            -> concurrent.futures.Future[None] | None:
        text = None if text is None or text.strip() == "" else text.strip()
        keyinstance = self._wallet.data.read_keyinstance(keyinstance_id=keyinstance_id)
        assert keyinstance is not None
        if keyinstance.description == text:
            return None
        future = self._wallet.data.update_keyinstance_descriptions([ (text, keyinstance_id) ])
        app_state.app_qt.on_keyinstance_label_change(self, keyinstance_id, text or "")
        return future

    def get_dummy_script_template(self, script_type: ScriptType | None=None) -> ScriptTemplate:
        public_key = PrivateKey(os.urandom(32)).public_key
        return self.get_script_template(public_key, script_type)

    def get_script_template(self, public_key: PublicKey, script_type: ScriptType | None=None) \
            -> ScriptTemplate:
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

    def export_private_key(self, keydata: KeyDataProtocol, password: str) -> str|None:
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
        maturity_height = self._wallet.get_local_height() - 100
        return self._wallet.data.read_account_balance(self._id, maturity_height,
            TransactionOutputFlag.FROZEN)

    def get_balance(self) -> WalletBalance:
        maturity_height = self._wallet.get_local_height() - 100
        return self._wallet.data.read_account_balance(self._id, maturity_height)

    def get_key_list(self, keyinstance_ids: list[int]|None=None) -> list[KeyListRow]:
        return self._wallet.data.read_key_list(self._id, keyinstance_ids)

    def get_local_transaction_entries(self, tx_hashes: list[bytes]|None=None) \
            -> list[TransactionValueRow]:
        return self._wallet.data.read_transaction_value_entries(self._id, tx_hashes=tx_hashes,
            mask=TxFlags.MASK_STATE_LOCAL)

    def get_transaction_value_entries(self, mask: TxFlags|None=None) -> list[TransactionValueRow]:
        return self._wallet.data.read_transaction_value_entries(self._id, mask=mask)

    def get_transaction_outputs_with_key_data(self, exclude_frozen: bool=True, mature: bool=True,
            confirmed_only: bool|None=None, keyinstance_ids: list[int]|None=None) \
                -> Sequence[AccountTransactionOutputSpendableRow]:
        if confirmed_only is None:
            confirmed_only = cast(bool, app_state.config.get('confirmed_only', False))
        maturity_height = self._wallet.get_local_height() - 100 if mature else None
        return self._wallet.data.read_account_transaction_outputs_with_key_data(self._id,
            confirmed_only=confirmed_only, maturity_height=maturity_height,
            exclude_frozen=exclude_frozen, keyinstance_ids=keyinstance_ids)

    def get_transaction_outputs_with_key_and_tx_data(self, exclude_frozen: bool=True,
            confirmed_only: bool|None=None, keyinstance_ids: list[int]|None=None,
            outpoints: list[Outpoint]|None=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        if confirmed_only is None:
            confirmed_only = cast(bool, app_state.config.get('confirmed_only', False))
        return self._wallet.data.read_account_transaction_outputs_with_key_and_tx_data(self._id,
            confirmed_only=confirmed_only, exclude_frozen=exclude_frozen,
            keyinstance_ids=keyinstance_ids, outpoints=outpoints)

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

    def get_history(self, domain: Sequence[int]|None=None) -> list[HistoryListEntry]:
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

    def export_history(self, from_datetime: datetime|None=None, to_datetime: datetime|None=None) \
            -> list[AccountExportEntry]:
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

    def start(self, network: Network|None) -> None:
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

    def cpfp(self, tx: Transaction, fee: int=0) -> Transaction|None:
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

    def get_master_public_key(self) -> str|None:
        raise NotImplementedError

    def get_master_public_keys(self) -> list[str]:
        raise NotImplementedError

    def get_public_keys_for_derivation(self, derivation_type: DerivationType,
            derivation_data2: bytes|None) -> list[PublicKey]:
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
            derivation_type: DerivationType, derivation_data2: bytes | None) -> ScriptTemplate:
        raise NotImplementedError

    def get_possible_scripts_for_derivation(self, derivation_type: DerivationType,
            derivation_data2: bytes | None) -> list[tuple[ScriptType, Script]]:
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
            derivation_data2: bytes|None) -> Script:
        script_template = self.get_script_template_for_derivation(script_type, derivation_type,
            derivation_data2)
        # NOTE(typing) Pylance does not know how to deal with abstract methods.
        return script_template.to_script()

    def sign_transaction(self, tx: Transaction, password: str,
            context: TransactionContext|None=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) \
                -> concurrent.futures.Future[TransactionLinkState] | None:
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

        def callback(callback_future: concurrent.futures.Future[TransactionLinkState]) -> None:
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

        # These need to be explicitly passed into the import transaction logic.
        transaction_output_key_usage: dict[int, tuple[int, ScriptType]] = {}
        for output_index, transaction_output in enumerate(tx.outputs):
            key_usages: list[tuple[int, ScriptType]] = []
            # If there are extended public keys they should either be single signature or
            # multi-signature and only one key instance that is shared in the multi case.
            for x_pubkey in transaction_output.x_pubkeys.values():
                assert x_pubkey.derivation_data.keyinstance_id is not None
                key_usage = (x_pubkey.derivation_data.keyinstance_id,
                    transaction_output.script_type)
                if key_usage not in key_usages:
                    key_usages.append(key_usage)
            # These will either be a receiving/change output
            assert len(key_usages) <= 1
            if len(key_usages) == 1:
                transaction_output_key_usage[output_index] = key_usages[0]

        transaction_future = app_state.async_.spawn(self._wallet.add_local_transaction_async(
            tx_hash, tx, tx_flags, BlockHeight.LOCAL, None, None, import_flags,
            transaction_output_key_usage=transaction_output_key_usage))
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
            update_cb: WaitingUpdateCallback|None=None, *,
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
            prev_tx: Transaction|None = context.parent_transactions.get(txin.prev_hash)
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

    def _external_transaction_request(self, tx_hash: bytes) -> Transaction|None:
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
            update_cb: WaitingUpdateCallback|None=None) -> dict[str, Any]|None:
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

    def get_masterkey_id(self) -> int|None:
        raise NotImplementedError

    async def create_payment_request_async(self, amount: int | None,
            internal_description: str | None,
            merchant_reference: str | None, date_expires: int | None = None,
            server_id: int | None = None, dpp_invoice_id: str | None=None,
            dpp_ack_json: str | None=None, encrypted_key_text: str | None=None,
            flags: PaymentFlag=PaymentFlag.NONE) \
                -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow]]:
        payment_type = flags & PaymentFlag.MASK_TYPE

        # We do not allow setting the state flags.
        assert flags & PaymentFlag.MASK_STATE == PaymentFlag.NONE
        # The request and output amount can only be blank for @BlindPaymentRequests.
        assert isinstance(amount, int) or payment_type == PaymentFlag.TYPE_MONITORED

        # We set `KeyInstanceFlag.ACTIVE` here with the understanding that we are responsible for
        # removing it when the payment request is deleted, expires or whatever.
        key_data = self.reserve_unassigned_key(RECEIVING_SUBPATH,
            KeyInstanceFlag.IS_PAYMENT_REQUEST | KeyInstanceFlag.ACTIVE)
        assert key_data.derivation_data2 is not None
        script_type = self.get_default_script_type()
        script_template = self.get_script_template_for_derivation(script_type,
            key_data.derivation_type, key_data.derivation_data2)
        if key_data.derivation_type in (DerivationType.BIP32_SUBPATH, DerivationType.PRIVATE_KEY):
            public_keys = self.get_public_keys_for_derivation(key_data.derivation_type,
                key_data.derivation_data2)
            pushdata_hash = get_pushdata_hash_for_public_keys(script_type, public_keys)
        else:
            key_script_type, pushdata_hash = get_pushdata_hash_for_derivation(
                key_data.derivation_type, key_data.derivation_data2)
            assert key_script_type == script_type

        if payment_type == PaymentFlag.TYPE_MONITORED:
            # This will transition to `STATE_UNPAID` when known to be remotely registered.
            flags |= PaymentFlag.STATE_PREPARING
        else:
            flags |= PaymentFlag.STATE_UNPAID

        date_created = int(time.time())
        # This will get the payment request id assigned on insert.
        request_row = PaymentRequestRow(None, flags, amount, date_expires, internal_description,
            server_id, dpp_invoice_id, dpp_ack_json, merchant_reference, encrypted_key_text,
            date_created, date_created)
        request_output_rows: list[PaymentRequestOutputRow] = [
            PaymentRequestOutputRow(None, 0, 0, script_type, script_template.to_script_bytes(),
                pushdata_hash, amount, key_data.keyinstance_id, date_created, date_created),
        ]
        request_row, request_output_rows = await self._wallet.data.create_payment_request_async(
            request_row, request_output_rows)
        self._wallet.events.trigger_callback(WalletEvent.KEYS_UPDATE, self._id,
            [ key_data.keyinstance_id ])

        return request_row, request_output_rows

    async def create_hosted_invoice_async(self, amount_satoshis: int, date_expires: int,
            description: str | None, merchant_reference: str | None) \
                -> HostedInvoiceCreationResult:
        """
        Raises `UserCancelled` if the user cancels a dialog they need to use correctly in order
            to complete this process (like the password input dialog).
        Raises `NoViableServersError` if there are no servers available to use.
        """
        server_state = await find_connectable_dpp_server(self._wallet.dpp_proxy_server_states)
        if server_state is None:
            raise NoViableServersError()

        password = await app_state.credentials.get_or_request_wallet_password_async(
            self._wallet.get_storage_path(), _("We need your password to encrypt the key that "
                "will be used to ensure the payer knows they are paying you."))
        if password is None:
            raise UserCancelled()

        secure_private_key = PrivateKey.from_random()
        secure_public_key = cast(PublicKey, secure_private_key.public_key)
        encrypted_key_text = pw_encode(secure_private_key.to_hex(), password)
        dpp_invoice_id = secure_public_key.to_address(compressed=True, network=Net.COIN).to_string()
        request_row, request_output_rows = await self.create_payment_request_async(amount_satoshis,
            description, merchant_reference, server_id=server_state.server.server_id,
            date_expires=date_expires, dpp_invoice_id=dpp_invoice_id,
            encrypted_key_text=encrypted_key_text, flags=PaymentFlag.TYPE_INVOICE)
        # We need to convert it to a "read row" to pass to the web socket.
        assert request_row.paymentrequest_id is not None
        self._wallet.register_outstanding_invoice(request_row, password)
        await self.connect_to_hosted_invoice_proxy_server_async(request_row.paymentrequest_id)

        payment_url = f"{server_state.server.url}api/v1/payment/{request_row.dpp_invoice_id}"
        return HostedInvoiceCreationResult(request_row=request_row,
            request_output_rows=request_output_rows, payment_url=payment_url,
            secure_public_key=secure_public_key)

    async def connect_to_hosted_invoice_proxy_server_async(self, request_id: int) -> None:
        """
        Raises `ValueError` if the wallet has lost this server!
        Raises `ServerConnectionError` if the connection to the server cannot be established.
        """
        request_row, request_output_rows = self._wallet.data.read_payment_request(
            request_id=request_id)
        assert request_row is not None
        assert request_row.server_id is not None
        for server_state in self._wallet.dpp_proxy_server_states:
            if server_state.server.server_id == request_row.server_id:
                break
        else:
            raise ValueError("The server for this payment request is unknown")

        try:
            await create_dpp_server_connection_async(server_state, request_row, timeout_seconds=5.5)
        except asyncio.TimeoutError:
            raise ServerConnectionError("Timed out connecting to server")

    async def delete_hosted_invoice_async(self, request_id: int) -> None:
        request_row, request_output_rows = self._wallet.data.read_payment_request(
            request_id=request_id)
        assert request_row is not None
        await close_dpp_server_connection_async(self._wallet.dpp_proxy_server_states, request_row)
        await self._wallet.data.delete_payment_requests_async([request_id], PaymentFlag.ARCHIVED)

    async def create_monitored_blockchain_payment_async(self, amount_satoshis: int | None,
            internal_description: str | None, merchant_reference: str | None,
            date_expires: int | None = None) -> tuple[PaymentRequestRow|None,
                list[PaymentRequestOutputRow], TipFilterRegistrationJobOutput]:
        """
        Raises `NoViableServersError` if there is no blockchain server available to use.
        Raises `ServiceUnavailableError` if there is a blockchain server and it is not ready
            to take our tip filter registrations.
        """
        assert date_expires is not None

        server_state = self._wallet.get_connection_state_for_usage(NetworkServerFlag.USE_BLOCKCHAIN)
        if server_state is None:
            raise NoViableServersError()
        if server_state.connection_flags & ServerConnectionFlag.TIP_FILTER_READY == 0:
            raise ServiceUnavailableError()

        request_row, request_output_rows = await self.create_payment_request_async(amount_satoshis,
            internal_description, merchant_reference, date_expires=date_expires,
            flags=PaymentFlag.TYPE_MONITORED)
        assert request_row.paymentrequest_id is not None
        assert request_row.date_expires is not None

        # We only accept one output row for monitored blockchain payments at this time.
        assert len(request_output_rows) == 1
        job = await create_tip_filter_registration_async(server_state,
            request_output_rows[0].pushdata_hash, request_row.date_expires,
            request_output_rows[0].keyinstance_id, request_output_rows[0].output_script_type)

        # We need to do some post-processing when the queued registration completes.
        await job.output.completed_event.wait()

        if job.output.date_registered is None:
            # A failed monitoring registration is a failed creation. Delete the request.
            await self._wallet.data.delete_payment_requests_async([ request_row.paymentrequest_id ],
                PaymentFlag.DELETED)
            return None, [], job.output

        # Formally promote the payment request from temporary to pending payment.
        await self._wallet.data.update_payment_request_state_async(
            request_row.paymentrequest_id, PaymentFlag.STATE_UNPAID,
            PaymentFlag.CLEARED_MASK_STATE)
        new_flags = (request_row.request_flags & PaymentFlag.CLEARED_MASK_STATE) | \
            PaymentFlag.STATE_UNPAID
        request_row = request_row._replace(request_flags=new_flags)
        return request_row, request_output_rows, job.output

    async def stop_monitoring_blockchain_payment_async(self, request_id: int) -> bool:
        """
        Returns `True` if the registrations for this payment request were deleted.
        Returns `False` if there is no server or if the tip filter is not ready for that server.

        From `general_api.py:delete_tip_filter_registrations_async`:
        - Raises `GeneralAPIError` if a connection was established but the request was unsuccessful.
        - Raises `ServerConnectionError` if the remote computer does not accept the connection.
        """
        request_row, request_output_rows = self._wallet.data.read_payment_request(
            request_id=request_id)
        assert request_row is not None
        assert request_row.date_expires is not None

        server_state = self._wallet.get_tip_filter_server_state()
        if server_state is None:
            return False

        for request_output_row in request_output_rows:
            await delete_tip_filter_registration_async(server_state, [
                (request_output_row.pushdata_hash, request_output_row.keyinstance_id) ])
        return True

    async def pay_hosted_invoice_async(self, pay_url: str) -> None:
        # TODO Fetch the payment terms.
        # TODO Check the payment terms are ...
        pass



class SimpleAccount(AbstractAccount):
    # wallet with a single keystore

    def is_watching_only(self) -> bool:
        return cast(KeyStore, self.get_keystore()).is_watching_only()

    def can_change_password(self) -> bool:
        return cast(KeyStore, self.get_keystore()).can_change_password()


class ImportedAccountBase(SimpleAccount):
    def get_masterkey_id(self) -> int|None:
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
        self._wallet.create_keyinstances(self._id, [ raw_keyinstance ])
        return True

    def get_public_keys_for_derivation_path(self, derivation_path: DerivationPath) \
            -> list[PublicKey]:
        return [ ]

    def get_script_template_for_derivation(self, script_type: ScriptType,
            derivation_type: DerivationType, derivation_data2: bytes | None) -> ScriptTemplate:
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
        keyinstance_future, keyinstance_rows = self._wallet.create_keyinstances(self._id,
            [ raw_keyinstance ])
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
            derivation_type: DerivationType, derivation_data2: bytes | None) -> ScriptTemplate:
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

    def get_masterkey_id(self) -> int|None:
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
        self._logger.debug(f"creating {count} new keys within {derivation_subpath} "
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
        future: concurrent.futures.Future[tuple[int, DerivationType, bytes,
            KeyInstanceFlag]]|None = self._wallet.data.reserve_keyinstance(self._id, masterkey_id,
            derivation_subpath, flags)
        assert future is not None
        try:
            keyinstance_id, derivation_type, derivation_data2, final_flags = future.result()
        except KeyInstanceNotFoundError:
            keyinstance_future, keyinstance_rows = \
                self.allocate_and_create_keys(1, derivation_subpath, flags | KeyInstanceFlag.USED)
            assert keyinstance_future is not None
            keyinstance_id = keyinstance_rows[0].keyinstance_id
            derivation_type = keyinstance_rows[0].derivation_type
            derivation_data2 = cast(bytes, keyinstance_rows[0].derivation_data2)
            final_flags = keyinstance_rows[0].flags
            keyinstance_future.result()

        self._wallet.events.trigger_callback(WalletEvent.KEYS_UPDATE, self._id, [ keyinstance_id ])

        return KeyData(keyinstance_id, self._id, masterkey_id, derivation_type,
            derivation_data2)

    def derive_new_keys_until(self, derivation_path: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> tuple[concurrent.futures.Future[None] | None, list[KeyInstanceRow]]:
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

        return self.create_preallocated_keys(key_allocations, keyinstance_flags)

    def allocate_and_create_keys(self, count: int, derivation_subpath: DerivationPath,
            keyinstance_flags: KeyInstanceFlag=KeyInstanceFlag.NONE) \
                -> tuple[concurrent.futures.Future[None] | None, list[KeyInstanceRow]]:
        self._value_locks.acquire_lock(derivation_subpath)
        try:
            # Identify the metadata for each key that is to be created.
            key_allocations = self.allocate_keys(count, derivation_subpath)
            if not key_allocations:
                return None, []
        finally:
            self._value_locks.release_lock(derivation_subpath)

        keyinstance_future, keyinstance_rows = \
            self.create_preallocated_keys(key_allocations, keyinstance_flags)
        keyinstance_future.result()
        return keyinstance_future, keyinstance_rows

    # Returns ordered from use first to use last.
    def get_fresh_keys(self, derivation_parent: DerivationPath, count: int) -> list[KeyInstanceRow]:
        fresh_keys = self.get_existing_fresh_keys(derivation_parent, count)
        if len(fresh_keys) < count:
            required_count = count - len(fresh_keys)
            keyinstance_future, keyinstance_rows = \
                self.allocate_and_create_keys(required_count, derivation_parent)
            # TODO Reconcile whether we can return the future instead of blocking here.
            if keyinstance_future is not None:
                keyinstance_future.result()
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
            derivation_type: DerivationType, derivation_data2: bytes | None) -> ScriptTemplate:
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
            script_type: ScriptType|None=None) -> ScriptTemplate:
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
            derivation_type: DerivationType, derivation_data2: bytes | None) -> ScriptTemplate:
        public_keys = self.get_public_keys_for_derivation(derivation_type, derivation_data2)
        public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
        return self.get_script_template(public_keys_hex, script_type)

    def get_dummy_script_template(self, script_type: ScriptType | None=None) -> ScriptTemplate:
        public_keys_hex = []
        for i in range(self.m):
            public_keys_hex.append(PrivateKey(os.urandom(32)).public_key.to_hex())
        return self.get_script_template(public_keys_hex, script_type)

    def get_script_template(self, public_keys_hex: list[str],
            script_type: ScriptType | None=None) -> ScriptTemplate:
        if script_type is None:
            script_type = self.get_default_script_type()
        return get_multi_signer_script_template(public_keys_hex, self.m, script_type)

    def derive_pubkeys(self, derivation_path: DerivationPath) -> list[PublicKey]:
        return [ k.derive_pubkey(derivation_path) for k in self.get_keystores() ]

    def derive_script_template(self, derivation_path: DerivationPath,
            script_type: ScriptType | None=None) -> ScriptTemplate:
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

    def read_account_balance(self, account_id: int, maturity_height: int,
            txo_flags: TransactionOutputFlag=TransactionOutputFlag.NONE,
            txo_mask: TransactionOutputFlag=TransactionOutputFlag.SPENT,
            exclude_frozen: bool=True) -> WalletBalance:
        return db_functions.read_account_balance(self._db_context,
            account_id, maturity_height, txo_flags, txo_mask, exclude_frozen)

    def update_account_names(self, entries: Iterable[tuple[str, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_account_names(self._db_context, entries)

    def update_account_script_types(self, entries: Iterable[tuple[ScriptType, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_account_script_types(self._db_context, entries)

    def update_account_server_ids(self, indexing_server_id: int|None,
            peer_channel_server_id: int|None, account_id: int) \
                -> concurrent.futures.Future[None]:
        return self._db_context.post_to_thread(db_functions.update_account_server_ids_write,
            indexing_server_id, peer_channel_server_id, account_id)

    # Account transactions.

    def read_account_ids_for_transaction(self, tx_hash: bytes) -> list[int]:
        return db_functions.read_account_ids_for_transaction(self._db_context, tx_hash)

    def read_transaction_descriptions(self, account_id: int|None=None,
            tx_hashes: Sequence[bytes]|None=None) -> list[AccountTransactionDescriptionRow]:
        return db_functions.read_transaction_descriptions(self._db_context,
            account_id, tx_hashes)

    def update_account_transaction_descriptions(self,
            entries: Iterable[tuple[str|None, int, bytes]]) -> concurrent.futures.Future[None]:
        return db_functions.update_account_transaction_descriptions(self._db_context,
            entries)

    # Invoices.

    def create_invoices(self, entries: Iterable[InvoiceRow]) -> concurrent.futures.Future[None]:
        return db_functions.create_invoices(self._db_context, entries)

    def read_invoice(self, *, invoice_id: int|None=None, tx_hash: bytes|None=None,
            payment_uri: str|None=None) -> InvoiceRow|None:
        return db_functions.read_invoice(self._db_context, invoice_id=invoice_id,
            tx_hash=tx_hash, payment_uri=payment_uri)

    def read_invoice_duplicate(self, value: int, payment_uri: str) -> InvoiceRow|None:
        return db_functions.read_invoice_duplicate(self._db_context, value, payment_uri)

    def read_invoices_for_account(self, account_id: int, flags: int|None=None,
            mask: int|None=None) -> list[InvoiceAccountRow]:
        return db_functions.read_invoices_for_account(self._db_context, account_id, flags,
            mask)

    def update_invoice_transactions(self, entries: Iterable[tuple[bytes|None, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_invoice_transactions(self._db_context, entries)

    def update_invoice_descriptions(self, entries: Iterable[tuple[str|None, int]]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_invoice_descriptions(self._db_context, entries)

    async def update_invoice_flags_async(self,
            entries: Iterable[tuple[PaymentFlag, PaymentFlag, int]]) -> None:
        await self._db_context.run_in_thread_async(db_functions.update_invoice_flags, entries)

    def delete_invoices(self, invoice_ids: list[int]) -> concurrent.futures.Future[None]:
        return db_functions.delete_invoices(self._db_context, invoice_ids)

    async def create_invoice_proxy_message_async(self, dpp_messages: list[DPPMessageRow]) -> None:
        await self._db_context.run_in_thread_async(db_functions.create_dpp_messages, dpp_messages)

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
        Raises `DatabaseUpdateError` should only happen if the sqlite or python bindings are broken.
        """
        return db_functions.reserve_keyinstance(self._db_context, account_id,
            masterkey_id, derivation_path, allocation_flags)

    def read_key_list(self, account_id: int, keyinstance_ids: list[int]|None=None) \
            -> list[KeyListRow]:
        return db_functions.read_key_list(self._db_context, account_id,
            keyinstance_ids)

    def read_keyinstances_for_derivations(self, account_id: int,
            derivation_type: DerivationType, derivation_data2s: list[bytes],
            masterkey_id: int|None=None) -> list[KeyInstanceRow]:
        return db_functions.read_keyinstances_for_derivations(self._db_context,
            account_id, derivation_type, derivation_data2s, masterkey_id)

    def read_keyinstance(self, *, account_id: int | None=None, keyinstance_id: int) \
            -> KeyInstanceRow|None:
        return db_functions.read_keyinstance(self._db_context, account_id=account_id,
            keyinstance_id=keyinstance_id)

    def read_keyinstances(self, *, account_id: int | None=None,
            keyinstance_ids: Sequence[int] | None=None, flags: KeyInstanceFlag | None=None,
            mask: KeyInstanceFlag | None=None) -> list[KeyInstanceRow]:
        return db_functions.read_keyinstances(self._db_context,
            account_id=account_id, keyinstance_ids=keyinstance_ids, flags=flags, mask=mask)

    def set_keyinstance_flags(self, key_ids: Sequence[int], flags: KeyInstanceFlag,
            mask: KeyInstanceFlag|None=None) \
                -> concurrent.futures.Future[list[KeyInstanceFlagChangeRow]]:
        return db_functions.set_keyinstance_flags(self._db_context, key_ids, flags, mask)

    def update_keyinstance_descriptions(self, entries: Iterable[tuple[str|None, int]]) \
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

    def read_mapi_broadcasts(self, tx_hashes: list[bytes]|None=None) \
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

    def read_network_servers(self, server_key: ServerAccountKey|None=None) \
            -> list[NetworkServerRow]:
        return db_functions.read_network_servers(self._db_context, server_key)

    def update_network_servers(self, rows: list[NetworkServerRow]) \
            -> concurrent.futures.Future[None]:
        return db_functions.update_network_servers(self._db_context, rows)

    async def update_network_server_credentials_async(self, server_id: int,
            encrypted_api_key: str|None, payment_key_bytes: bytes|None,
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

    async def create_payment_request_async(self, request_entry: PaymentRequestRow,
            request_output_entries: list[PaymentRequestOutputRow]) \
            -> tuple[PaymentRequestRow, list[PaymentRequestOutputRow]]:
        return await self._db_context.run_in_thread_async(
            db_functions.create_payment_request_write, request_entry, request_output_entries)

    def read_payment_request(self, request_id: int) \
            -> tuple[PaymentRequestRow | None, list[PaymentRequestOutputRow]]:
        return db_functions.read_payment_request(self._db_context, request_id)

    def read_payment_requests(self, *, account_id: int | None=None, flags: PaymentFlag | None=None,
            mask: PaymentFlag | None=None, server_id: int | None=None) \
                -> list[PaymentRequestRow]:
        """
        Warning: This database function does not filter out deleted or archived payment requests
            unless the caller specifies `PaymentFlag.MASK_HIDDEN` in the `mask` parameter.
        """
        return db_functions.read_payment_requests(self._db_context, account_id=account_id,
            flags=flags, mask=mask, server_id=server_id)

    def read_payment_request_ids_for_transaction(self, transaction_hash: bytes) -> list[int]:
        return db_functions.read_payment_request_ids_for_transaction(self._db_context,
            transaction_hash)

    async def read_payment_request_outputs_async(self, paymentrequest_ids: list[int]) \
            -> list[PaymentRequestOutputRow]:
        return await self._db_context.run_in_thread_async(
            db_functions.read_payment_request_outputs, paymentrequest_ids)

    async def read_payment_request_transactions_hashes_async(self, paymentrequest_ids: list[int]) \
            -> dict[int, list[bytes]]:
        return await self._db_context.run_in_thread_async(
            db_functions.read_payment_request_transactions_hashes, paymentrequest_ids)

    def read_registered_tip_filter_pushdata_for_request(self, request_id: int) \
            -> PushDataHashRegistrationRow | None:
        return db_functions.read_registered_tip_filter_pushdata_for_request(self._db_context,
            request_id)

    def update_payment_requests(self, entries: Iterable[PaymentRequestUpdateRow]) \
            -> concurrent.futures.Future[None]:
        return self._db_context.post_to_thread(db_functions.update_payment_requests_write, entries)

    async def update_payment_requests_async(self, entries: Iterable[PaymentRequestUpdateRow]) \
            -> None:
        await self._db_context.run_in_thread_async(
            db_functions.update_payment_requests_write, entries)

    async def update_payment_request_state_async(self, request_id: int, flags: PaymentFlag,
            mask: PaymentFlag) -> None:
        await self._db_context.run_in_thread_async(
            db_functions.update_payment_request_flags_write, request_id, flags, mask)

    async def close_paid_payment_request_async(self, request_id: int) \
            -> list[tuple[str, int, bytes]]:
        """
        Wrap the database operations required to link a transaction so the processing is
        offloaded to the SQLite writer thread while this task is blocked.

        Raises `DatabaseUpdateError` if the attempt to close the payment request fails.
        """
        return await self._db_context.run_in_thread_async(db_functions.close_paid_payment_request,
            request_id)

    async def delete_payment_requests_async(self, paymentrequest_ids: list[int],
            update_flag: PaymentFlag) -> None:
        for _paymentrequest_id, keyinstance_ids_by_account_id in \
                await self._db_context.run_in_thread_async(
                    db_functions.delete_payment_requests_write, paymentrequest_ids, update_flag):
            for account_id, keyinstance_ids in keyinstance_ids_by_account_id.items():
                self.events.trigger_callback(WalletEvent.KEYS_UPDATE, account_id, keyinstance_ids)

    # Peer channels.

    async def create_external_peer_channel_async(self,
            remote_channel_id: str, remote_url: str, token: str, invoice_id: int) \
                -> tuple[ExternalPeerChannelRow, PeerChannelAccessTokenRow]:
        """
        This is similar in function to the `create_peer_channel_locally_and_remotely_async` except
        that we are not the creator of the remote peer channel (the payee already created it)
        """
        date_created = get_posix_timestamp()
        remote_peer_channel_id = remote_channel_id
        peer_channel_flags = ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK
        peer_channel_row = ExternalPeerChannelRow(None, invoice_id, remote_peer_channel_id,
            remote_url, peer_channel_flags, date_created, date_created)
        peer_channel_id = await self._db_context.run_in_thread_async(
            db_functions.create_external_peer_channel_write, peer_channel_row)
        peer_channel_row = peer_channel_row._replace(peer_channel_id=peer_channel_id)
        logger.debug("Added peer channel %s with flags: %s", remote_peer_channel_id,
            peer_channel_row.peer_channel_flags)

        # Record peer channel token in the database if it doesn't exist there already
        assert peer_channel_row.peer_channel_id is not None
        read_only_access_token_flag = PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE | \
                                      PeerChannelAccessTokenFlag.FOR_MAPI_CALLBACK_USAGE
        read_only_access_token = PeerChannelAccessTokenRow(peer_channel_row.peer_channel_id,
            read_only_access_token_flag, TokenPermissions.READ_ACCESS, token)

        # Add the read_only token
        peer_channel_row = await self.update_external_peer_channel_async(
            remote_peer_channel_id, remote_url, peer_channel_flags, peer_channel_id,
            addable_access_tokens=[read_only_access_token])

        return peer_channel_row, read_only_access_token

    async def create_server_peer_channel_async(self, row: ServerPeerChannelRow,
            tip_filter_server_id: int|None=None) -> int:
        return await self._db_context.run_in_thread_async(
            db_functions.create_server_peer_channel_write, row, tip_filter_server_id)

    def read_server_peer_channels(self, server_id: int | None=None,
            peer_channel_id: int | None = None) -> list[ServerPeerChannelRow]:
        return db_functions.read_server_peer_channels(self._db_context, server_id, peer_channel_id)

    def read_external_peer_channels(self, remote_channel_id: str | None = None,
            flags: ServerPeerChannelFlag | None = None, mask: ServerPeerChannelFlag | None = None) \
            -> list[ExternalPeerChannelRow]:
        return db_functions.read_external_peer_channels(self._db_context, remote_channel_id, flags,
            mask)

    def read_external_peer_channel_messages_by_id(self, peer_channel_id: int,
            most_recent_only: bool=False) -> list[PeerChannelMessageRow]:
        return db_functions.read_external_peer_channel_messages_by_id(self._db_context,
            peer_channel_id, most_recent_only)

    def read_server_peer_channel_access_tokens(self, peer_channel_id: int,
            mask: PeerChannelAccessTokenFlag|None=None,
            flags: PeerChannelAccessTokenFlag|None=None) \
                -> list[PeerChannelAccessTokenRow]:
        return db_functions.read_server_peer_channel_access_tokens(self._db_context,
            peer_channel_id, mask, flags)

    def read_external_peer_channel_access_tokens(self, peer_channel_id: int,
            mask: PeerChannelAccessTokenFlag|None=None,
            flags: PeerChannelAccessTokenFlag|None=None) \
                -> list[PeerChannelAccessTokenRow]:
        return db_functions.read_external_peer_channel_access_tokens(self._db_context,
            peer_channel_id, mask, flags)

    async def update_server_peer_channel_async(self, remote_channel_id: str | None,
                remote_url: str | None, peer_channel_flags: ServerPeerChannelFlag,
                peer_channel_id: int,
            addable_access_tokens: list[PeerChannelAccessTokenRow]) -> ServerPeerChannelRow:
        return await self._db_context.run_in_thread_async(
            db_functions.update_server_peer_channel_write, remote_channel_id, remote_url,
                peer_channel_flags, peer_channel_id, addable_access_tokens)

    async def update_external_peer_channel_async(self, remote_channel_id: str|None,
            remote_url: str|None, peer_channel_flags: ServerPeerChannelFlag,
            peer_channel_id: int, addable_access_tokens: list[
                PeerChannelAccessTokenRow]) -> ExternalPeerChannelRow:
        return await self._db_context.run_in_thread_async(
            db_functions.update_external_peer_channel_write, remote_channel_id, remote_url,
                peer_channel_flags, peer_channel_id, addable_access_tokens)

    async def create_server_peer_channel_messages_async(self,
            rows: list[PeerChannelMessageRow]) -> list[PeerChannelMessageRow]:
        return await self._db_context.run_in_thread_async(
            db_functions.create_server_peer_channel_messages_write, rows)

    async def create_external_peer_channel_messages_async(self,
            rows: list[PeerChannelMessageRow]) -> list[PeerChannelMessageRow]:
        return await self._db_context.run_in_thread_async(
            db_functions.create_external_peer_channel_messages_write, rows)

    async def read_server_peer_channel_messages_async(self, server_id: int,
            message_flags: PeerChannelMessageFlag|None=None,
            message_mask: PeerChannelMessageFlag|None=None,
            channel_flags: ServerPeerChannelFlag|None=None,
            channel_mask: ServerPeerChannelFlag|None=None) \
                -> list[PeerChannelMessageRow]:
        return db_functions.read_server_peer_channel_messages(self._db_context, server_id,
            message_flags, message_mask, channel_flags, channel_mask)

    async def read_external_peer_channel_messages_async(self,
            message_flags: PeerChannelMessageFlag|None=None,
            message_mask: PeerChannelMessageFlag|None=None,
            channel_flags: ServerPeerChannelFlag|None=None,
            channel_mask: ServerPeerChannelFlag|None=None) \
                -> list[PeerChannelMessageRow]:
        return db_functions.read_external_peer_channel_messages(self._db_context, message_flags,
            message_mask, channel_flags, channel_mask)

    # Pushdata hashes.

    async def create_pushdata_matches_async(self, rows: list[PushDataMatchRow],
            processed_message_ids: list[int]) -> None:
        await self._db_context.run_in_thread_async(
            db_functions.create_pushdata_matches_write, rows, processed_message_ids)

    def read_pushdata_match_metadata(self) -> list[PushDataMatchMetadataRow]:
        return db_functions.read_pushdata_match_metadata(self._db_context)

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
            expiry_timestamp: int | None=None,
            flags: PushDataHashRegistrationFlag | None=None,
            mask: PushDataHashRegistrationFlag | None=None) -> list[PushDataHashRegistrationRow]:
        return db_functions.read_tip_filter_pushdata_registrations(self._db_context, server_id,
            expiry_timestamp, flags, mask)

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

    def get_transaction_deltas(self, tx_hash: bytes, account_id: int | None=None) \
            -> list[TransactionDeltaSumRow]:
        return db_functions.read_transaction_values(self._db_context, tx_hash, account_id)

    def get_transaction_flags(self, tx_hash: bytes) -> TxFlags | None:
        return db_functions.read_transaction_flags(self._db_context, tx_hash)

    async def import_transaction_async(self, tx_row: TransactionRow,
            txi_rows: list[TransactionInputAddRow], txo_rows: list[TransactionOutputAddRow],
            proof_row: MerkleProofRow | None, *, rollback_on_spend_conflict: bool=False) \
                -> TransactionLinkState:
        """
        Wrap the database operations required to import a transaction so the processing is
        offloaded to the SQLite writer thread while this task is blocked.

        Raises:
        - `TransactionAlreadyExistsError` if the transaction is already in the wallet database.
        - `DatabaseUpdateError` if there are spend conflicts and it was requested that the
              transaction was rolled back.
        """
        return await self._db_context.run_in_thread_async(db_functions.import_transaction, tx_row,
            txi_rows, txo_rows, proof_row, rollback_on_spend_conflict=rollback_on_spend_conflict)

    async def link_transaction_async(self, tx_hash: bytes, *,
            rollback_on_spend_conflict: bool=False) -> TransactionLinkState:
        """
        Link an existing transaction to any applicable accounts.

        We do not know whether the transaction uses any wallet keys, and is related to any
        accounts related to those keys. We will work this out as part of the importing process.
        This should not be done for any pre-existing transactions.
        """
        return await self._db_context.run_in_thread_async(db_functions.link_transaction, tx_hash,
            rollback_on_spend_conflict=rollback_on_spend_conflict)

    def read_transaction(self, transaction_hash: bytes) -> TransactionRow | None:
        return db_functions.read_transaction(self._db_context, transaction_hash)

    def read_transaction_block_hashes(self) -> list[bytes]:
        return db_functions.read_transaction_block_hashes(self._db_context)

    def read_unconnected_merkle_proofs(self) -> list[MerkleProofRow]:
        return db_functions.read_unconnected_merkle_proofs(self._db_context)

    def read_transaction_value_entries(self, account_id: int, *,
            tx_hashes: list[bytes]|None=None, mask: TxFlags|None=None) \
                -> list[TransactionValueRow]:
        return db_functions.read_transaction_value_entries(self._db_context, account_id,
            tx_hashes=tx_hashes, mask=mask)

    def read_transactions_exist(self, tx_hashes: Sequence[bytes], account_id: int | None=None) \
            -> list[TransactionExistsRow]:
        return db_functions.read_transactions_exist(self._db_context, tx_hashes, account_id)

    async def set_transaction_state_async(self, transaction_hash: bytes, flag: TxFlags,
            ignore_mask: TxFlags | None=None) -> bool:
        """
        Change the state of a transaction but only if it is in an expected state.

        Returns `True` if the state was changed.
        Returns `False` if the transaction does not exist or was not in an expected state.
        """
        succeeded = await self._db_context.run_in_thread_async(
            db_functions.set_transaction_state_write, transaction_hash, flag, ignore_mask)
        # @TransactionStateChange: This tag is used to mark all the locations that we trigger
        # the transaction state change event. The locations were chosen because they are the lower
        # level calls that were previously made in the higher level wallet code where we used to
        # trigger it. In theory, we would benefit by batching the calls although in the other
        # locations not `set_transaction_state_async`.
        if succeeded:
            self.events.trigger_callback(WalletEvent.TRANSACTION_STATE_CHANGE, transaction_hash,
                flag & TxFlags.MASK_STATE)
            if app_state.daemon.nodeapi_server is not None:
                app_state.daemon.nodeapi_server.event_transaction_change(transaction_hash)
        return succeeded

    async def update_reorged_transactions_async(self, orphaned_block_hashes: list[bytes]) \
            -> list[bytes]:
        transaction_hashes = await self._db_context.run_in_thread_async(
            db_functions.update_reorged_transactions_write, orphaned_block_hashes)
        # @TransactionStateChange
        for transaction_hash in transaction_hashes:
            self.events.trigger_callback(WalletEvent.TRANSACTION_STATE_CHANGE, transaction_hash,
                TxFlags.STATE_CLEARED)
            if app_state.daemon.nodeapi_server is not None:
                app_state.daemon.nodeapi_server.event_transaction_change(transaction_hash)
        return transaction_hashes

    async def update_transaction_flags_async(self, entries: list[tuple[TxFlags, TxFlags, bytes]]) \
            -> int:
        return await self._db_context.run_in_thread_async(
            db_functions.update_transaction_flags_write, entries)

    async def update_transaction_proof_async(self, tx_update_rows: list[TransactionProofUpdateRow],
            proof_rows: list[MerkleProofRow], proof_update_rows: list[MerkleProofUpdateRow],
            processed_message_ids: list[int], processed_message_ids_externally_owned: list[int],
            event_relevant_flags: set[TxFlags]) -> None:
        await self._db_context.run_in_thread_async(
            db_functions.update_transaction_proof_write, tx_update_rows, proof_rows,
                proof_update_rows, processed_message_ids, processed_message_ids_externally_owned)
        # @TransactionStateChange
        for update_row in tx_update_rows:
            state_flags = update_row.tx_flags & TxFlags.MASK_STATE
            if state_flags not in event_relevant_flags:
                continue
            self.events.trigger_callback(WalletEvent.TRANSACTION_STATE_CHANGE, update_row.tx_hash,
                state_flags)
            if app_state.daemon.nodeapi_server is not None:
                app_state.daemon.nodeapi_server.event_transaction_change(update_row.tx_hash)

    async def update_transaction_proofs_and_flags(self,
            tx_update_rows: list[TransactionProofUpdateRow],
            flag_entries: list[tuple[TxFlags, TxFlags, bytes]]) -> None:
        await self._db_context.run_in_thread_async(
            db_functions.update_transaction_proof_and_flag_write, tx_update_rows, flag_entries)

        # @TransactionStateChange
        updated_entries: set[tuple[bytes, TxFlags]] = set()
        for update_row in tx_update_rows:
            updated_entries.add((update_row.tx_hash, update_row.tx_flags))
        for _flag_mask_bits, flag_set_bits, transaction_hash in flag_entries:
            updated_entries.add((transaction_hash, flag_set_bits))
        for transaction_hash, transaction_flags in updated_entries:
            self.events.trigger_callback(WalletEvent.TRANSACTION_STATE_CHANGE, transaction_hash,
                transaction_flags & TxFlags.MASK_STATE)
            if app_state.daemon.nodeapi_server is not None:
                app_state.daemon.nodeapi_server.event_transaction_change(transaction_hash)

    # Transaction outputs.

    def read_account_transaction_outputs_with_key_data(self, account_id: int,
            confirmed_only: bool=False, maturity_height: int|None=None,
            exclude_frozen: bool=False, keyinstance_ids: list[int]|None=None) \
                -> list[AccountTransactionOutputSpendableRow]:
        return db_functions.read_account_transaction_outputs_with_key_data(
            self._db_context, account_id, confirmed_only, maturity_height,
            exclude_frozen, keyinstance_ids)

    def read_account_transaction_outputs_with_key_and_tx_data(self, account_id: int,
            confirmed_only: bool=False, exclude_frozen: bool=False,
            keyinstance_ids: list[int]|None=None, outpoints: list[Outpoint]|None=None) \
                -> list[AccountTransactionOutputSpendableRowExtended]:
        return db_functions.read_account_transaction_outputs_with_key_and_tx_data(
            self._db_context, account_id, confirmed_only, exclude_frozen, keyinstance_ids,
            outpoints)

    def read_parent_transaction_outputs_with_key_data(self, transaction_hash: bytes, *,
            include_absent: bool) -> list[TransactionOutputSpendRow]:
        return db_functions.read_parent_transaction_outputs_with_key_data(self._db_context,
            transaction_hash, include_absent)

    def read_spent_outputs_to_monitor(self) -> list[OutputSpend]:
        return db_functions.read_spent_outputs_to_monitor(self._db_context)

    def read_existing_output_spends(self, outpoints: list[Outpoint]) -> list[SpentOutputRow]:
        return db_functions.read_existing_output_spends(self._db_context, outpoints)

    def read_transaction_outputs_with_key_data(self, *, account_id: int | None=None,
            tx_hash: bytes | None=None, txo_keys: list[Outpoint] | None=None,
            derivation_data2s: list[bytes] | None=None, require_keys: bool=False) \
                -> list[TransactionOutputSpendableRow]:
        return db_functions.read_transaction_outputs_with_key_data(self._db_context,
            account_id=account_id, tx_hash=tx_hash, txo_keys=txo_keys,
            derivation_data2s=derivation_data2s, require_keys=require_keys)

    def read_transaction_outputs(self, l: list[Outpoint]) -> list[TransactionOutputAddRow]:
        return db_functions.read_transaction_outputs(self._db_context, l)

    def update_transaction_output_flags(self, txo_keys: list[Outpoint],
            flags: TransactionOutputFlag, mask: TransactionOutputFlag|None=None) \
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

    def read_wallet_events(self, account_id: int|None=None,
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

    _network: Network|None = None
    _stopped = False
    _stopping = False

    _persisted_tip_hash: bytes|None = None
    _current_chain: Chain|None = None
    _current_tip_header: Header|None = None
    _blockchain_server_state: HeaderServerState|None = None
    _blockchain_server_state_ready: bool = False

    def __init__(self, storage: WalletStorage, password: str|None=None) -> None:
        self._id = random.randint(0, (1<<32)-1)

        self._storage = storage
        self.logger = logs.get_logger(f"wallet[{self.name()}]")

        # NOTE The wallet abstracts all database access. The database context should not be
        # used outside of the `Wallet` object.
        self._db_context = storage.get_db_context()
        assert self._db_context is not None

        self.events = TriggeredCallbacks[WalletEvent]()
        self.data = WalletDataAccess(self._db_context, self.events)
        self._servers: dict[ServerAccountKey, NewServer] = {}

        txdata_cache_size = self.get_cache_size_for_tx_bytedata() * (1024 * 1024)
        self._transaction_cache2 = LRUCache(max_size=txdata_cache_size)

        self._masterkey_rows: dict[int, MasterKeyRow] = {}
        self._account_rows: dict[int, AccountRow] = {}

        self._accounts: dict[int, AbstractAccount] = {}
        self._keystores: dict[int, KeyStore] = {}
        self._wallet_master_keystore: BIP32_KeyStore|None = None

        self._missing_transactions: dict[bytes, MissingTransactionEntry] = {}

        self._fee_quote_lock = asyncio.Lock()

        ## State related to the wallet processing headers from it's header source.
        self._header_source_chain_reconciled_event = asyncio.Event()
        self._blockchain_server_chain_reconciled_event = asyncio.Event()

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
        self._worker_task_manage_dpp_connections: concurrent.futures.Future[None]|None = None
        self._worker_tasks_maintain_server_connection: dict[int, list[ServerConnectionState]] = {}
        self._worker_tasks_external_peer_channel_connections = \
            dict[int, list[PeerChannelServerState]]()
        self._worker_task_peer_channel_garbage_collection: \
            concurrent.futures.Future[None] | None = None
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

        self.events.register_callback(self._event_payment_requests_paid,
            [ WalletEvent.PAYMENT_REQUEST_PAID ])
        self.events.register_callback(self._event_transaction_verified,
            [ WalletEvent.TRANSACTION_VERIFIED ])

        self.load_state()

        self.contacts = Contacts(self._storage)

        # These are transactions the wallet has decided it needs that we will fetch and process in
        # the background.
        self._check_missing_transactions_event = asyncio.Event()
        # This locates transactions that we have, expect proofs to be available for, but do not
        # have the proof.
        self._check_missing_proofs_event = asyncio.Event()
        self._new_server_connection_event = asyncio.Event()
        self.local_chain_update_event = asyncio.Event()
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
        self._process_payment_requests(password)

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

        self.logger.debug("Existing persisted chain is %s",
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

        account_flags: dict[int, AccountInstantiationFlags] = {}
        keyinstances_by_account_id: dict[int, list[KeyInstanceRow]] = {}
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

    def get_master_keystore(self) -> BIP32_KeyStore:
        assert self._wallet_master_keystore is not None
        return self._wallet_master_keystore

    def get_keystore(self, keystore_id: int) -> KeyStore:
        return self._keystores[keystore_id]

    def get_keystores(self) -> Sequence[KeyStore]:
        return list(self._keystores.values())

    def check_password(self, password: str) -> None:
        """
        Raises `InvalidPassword` if the given password is not the wallet password.
        """
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

    def get_account(self, account_id: int) -> AbstractAccount|None:
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

    def _realize_keystore(self, row: MasterKeyRow) -> KeyStore:
        data = cast(MasterKeyDataTypes, json.loads(row.derivation_data))
        parent_keystore: KeyStore|None = None
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
        account: AbstractAccount|None = None
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
            password: str|None=None) -> KeyStoreResult:
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

        account_name: str|None = None
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

        keyinstance_future, keyinstance_rows = self.create_keyinstances(account.get_id(),
            raw_keyinstance_rows)

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
            -> IndefiniteCredentialId|None:
        return self._registered_api_keys.get(key)

    def update_network_servers(self, added_server_rows: list[NetworkServerRow],
            updated_server_rows: list[NetworkServerRow],
            deleted_server_keys: list[ServerAccountKey], updated_api_keys: dict[ServerAccountKey,
                tuple[str|None, tuple[str, str]|None]]) \
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

            credential_id: IndefiniteCredentialId|None = None
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

            updated_states: list[tuple[NetworkServerRow, IndefiniteCredentialId|None]] = []

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
        self.populate_transaction_context_key_data_from_search(tx, tx_context)

    @staticmethod
    def sanity_check_derivation_key_data(data1: DatabaseKeyDerivationData|None,
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

            for txo_row1 in self.data.read_parent_transaction_outputs_with_key_data(tx_hash,
                    include_absent=False):
                found_in_database = True
                database_data = DatabaseKeyDerivationData.from_key_data(
                    cast(KeyDataProtocol, txo_row1),
                    DatabaseKeyDerivationType.EXTENSION_LINKED)
                outpoint = Outpoint(txo_row1.tx_hash, txo_row1.txo_index)
                self.sanity_check_derivation_key_data(
                    tx_context.key_datas_by_spent_outpoint.get(outpoint), database_data)
                tx_context.key_datas_by_spent_outpoint[outpoint] = database_data
                tx_context.spent_outpoint_values[outpoint] = txo_row1.value

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
            -> tuple[Transaction, TransactionContext | None]:
        """
        Loads a transaction using given transaction data.

        If the transaction is already in the cache, it will return that transaction.
        If the transaction is in the database, this will load it in extended form and cache it.
        Otherwise the transaction data will be parsed, loaded in extended form and cached.

        Raises `ValueError` if the text is not found to contain viable transaction data.
        """
        if not data:
            raise ValueError("Empty transaction data")

        context: TransactionContext | None = None
        if data.startswith(b"psbt\xff"):
            # Bitcoin Core compatible partial transactions.
            from .standards.psbt import parse_psbt_bytes
            psbt_data = parse_psbt_bytes(data, self.get_xpubs_by_fingerprint())
            tx = psbt_data.transaction
            if tx is None:
                raise ValueError(_("PSBT transaction not valid"))
            if not tx.is_complete():
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

    async def add_local_transaction_async(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            block_height: int, block_hash: bytes | None=None, block_position: int | None=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET,
            transaction_output_key_usage: dict[int, tuple[int, ScriptType]] | None = None) \
                -> TransactionLinkState:
        """
        This is currently only called when an account constructs and signs a transaction

        Raises:
        - `TransactionAlreadyExistsError` if the transaction is already in the wallet database.
        - `DatabaseUpdateError` if there are spend conflicts and the transaction was rolled back.
        """
        return await self._import_transaction_async(tx_hash, tx, flags, block_height, block_hash,
            block_position, import_flags=import_flags, rollback_on_spend_conflict=True,
            transaction_output_key_usage=transaction_output_key_usage)

    async def import_transaction_async(self, tx_hash: bytes, tx: Transaction, flags: TxFlags,
            block_height: int, block_hash: bytes | None=None, block_position: int | None=None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET,
            proof_row: MerkleProofRow | None=None, *,
            transaction_output_key_usage: dict[int, tuple[int, ScriptType]] | None = None,
            key_usage_metadatas: set[TransactionKeyUsageMetadata] | None = None,
            rollback_on_spend_conflict: bool=False) \
                -> TransactionLinkState:
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

        if key_usage_metadatas is not None:
            assert transaction_output_key_usage is None
            transaction_output_key_usage = map_transaction_output_key_usage(tx,
                key_usage_metadatas)

        return await self._import_transaction_async(tx_hash, tx, flags, block_height, block_hash,
            block_position, import_flags=import_flags, proof_row=proof_row,
            transaction_output_key_usage=transaction_output_key_usage,
            rollback_on_spend_conflict=rollback_on_spend_conflict)

    async def _import_transaction_async(self, transaction_hash: bytes, transaction: Transaction,
            flags: TxFlags, block_height: int, block_hash: bytes | None, block_position: int | None,
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET,
            proof_row: MerkleProofRow | None=None, *,
            transaction_output_key_usage: dict[int, tuple[int, ScriptType]] | None = None,
            rollback_on_spend_conflict: bool=False) \
                -> TransactionLinkState:
        """
        Add an external complete transaction to the database.

        We do not know whether the transaction uses any wallet keys, and is related to any
        accounts related to those keys. We will work this out as part of the importing process.

        We do not attempt to correct the block height for the transaction state. It is assumed
        that the caller is passing in legitimate data
        """
        assert transaction.is_complete()

        timestamp = int(time.time())
        transaction_output_flags = TransactionOutputFlag.COINBASE if transaction.is_coinbase() \
            else TransactionOutputFlag.NONE
        if transaction_output_key_usage is None:
            transaction_output_key_usage = {}

        # The database layer should be decoupled from core wallet logic so we need to
        # break down the transaction and related data for it to consume.
        transaction_row = TransactionRow(transaction_hash, transaction.to_bytes(), flags,
            block_hash, block_height, block_position, fee_value=None, description=None,
            version=transaction.version, locktime=transaction.locktime, date_created=timestamp,
            date_updated=timestamp)

        transaction_input_rows: list[TransactionInputAddRow] = []
        for input_index, transaction_input in enumerate(transaction.inputs):
            transaction_input_row = TransactionInputAddRow(transaction_hash, input_index,
                transaction_input.prev_hash, transaction_input.prev_idx, transaction_input.sequence,
                TransactionInputFlag.NONE,
                transaction_input.script_offset, transaction_input.script_length,
                timestamp, timestamp)
            transaction_input_rows.append(transaction_input_row)

        transaction_output_rows: list[TransactionOutputAddRow] = []
        for output_index, transaction_output in enumerate(transaction.outputs):
            keyinstance_id, script_type = transaction_output_key_usage.get(output_index,
                (None, ScriptType.NONE))
            transaction_output_row = TransactionOutputAddRow(transaction_hash, output_index,
                transaction_output.value,
                keyinstance_id,
                script_type,
                transaction_output_flags,
                scripthash_bytes(transaction_output.script_pubkey),
                transaction_output.script_offset, transaction_output.script_length,
                timestamp, timestamp)
            transaction_output_rows.append(transaction_output_row)

        link_state = await self.data.import_transaction_async(transaction_row,
            transaction_input_rows, transaction_output_rows, proof_row,
            rollback_on_spend_conflict=rollback_on_spend_conflict)

        async with self._obtain_transactions_async_lock:
            if transaction_hash in self._missing_transactions:
                del self._missing_transactions[transaction_hash]
                self.logger.debug("Removed missing transaction %s",
                    hash_to_hex_str(transaction_hash)[:8])
                self.events.trigger_callback(WalletEvent.TRANSACTION_OBTAINED, transaction_row,
                    transaction, link_state)

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
                    [ Outpoint(input.prev_hash, input.prev_idx) for input in transaction.inputs ])

        # This primarily routes a notification to the user interface, for it to update for this
        # specific change.
        self.events.trigger_callback(WalletEvent.TRANSACTION_ADD, transaction_hash, transaction,
            link_state, import_flags)

        if app_state.daemon.nodeapi_server is not None:
            app_state.daemon.nodeapi_server.event_transaction_change(transaction_hash)

        return link_state

    def import_transaction_with_error_callback(self, tx: Transaction, tx_state: TxFlags,
            error_callback: Callable[[str], None]) -> None:
        def callback(callback_future: concurrent.futures.Future[TransactionLinkState]) -> None:
            if callback_future.cancelled():
                return
            try:
                callback_future.result()
            except DatabaseUpdateError as update_exception:
                error_callback(update_exception.args[0])
            except TransactionAlreadyExistsError:
                error_callback(_("That transaction has already been imported"))

        future = app_state.async_.spawn(self.add_local_transaction_async(tx.hash(), tx,
            tx_state, BlockHeight.LOCAL, None, TransactionImportFlag.MANUAL_IMPORT))
        future.add_done_callback(callback)

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
        self.logger.debug("removing tx from history %s", tx_id)

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
            -> tuple[concurrent.futures.Future[None]|None, list[KeyInstanceRow]]:
        """
        Ensure that the keys the incomplete transaction uses exist.

        An incomplete transaction will have come from an external source that has shared it with
        us as we are either the offline signer, or multi-signature cosigner, and we need to make
        sure we have formally created the records for the key derivations it uses (which we
        probably haven't as we're likely a recipient).
        """
        if tx.is_complete():
            return None, []

        self.logger.debug("ensure_incomplete_transaction_keys_exist")

        last_future: concurrent.futures.Future[None]|None = None
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
            -> AbstractAccount|None:
        """
        Find the account that can sign transactions that spend coins secured by the given
        extended public key.
        """
        for account in self._accounts.values():
            for keystore in account.get_keystores():
                if keystore.is_signature_candidate(extended_public_key):
                    return account
        return None

    def set_transaction_labels(self, entries: list[tuple[str|None, int, bytes]]) \
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

    async def broadcast_transaction_async(self, transaction: Transaction,
            transaction_context: TransactionContext | None) -> BroadcastResult:
        """
        Broadcast a transaction. This transaction does not even have to be known to the wallet.

        For now this is limited to broadcasting via MAPI.
        """
        broadcast_hash = transaction.hash()
        result: BroadcastResult | None = None

        if transaction_context is not None and transaction_context.mapi_server_hint is not None:
            # For now we expect to be connected to a peer channel server.
            peer_channel_server_state = self.get_connection_state_for_usage(
                NetworkServerFlag.USE_MESSAGE_BOX)
            assert peer_channel_server_state is not None

            broadcast_response, peer_channel_info = await mapi_transaction_broadcast_async(
                self.data, peer_channel_server_state, transaction_context.mapi_server_hint,
                transaction, True, True)
            result = BroadcastResult(
                broadcast_response["returnResult"] == "success",
                MAPIBroadcastResult(broadcast_response, peer_channel_info,
                    peer_channel_server_state))

        if result is None:
            raise BroadcastError("P2P broadcast is not currently supported")

        if result.success:
            await self.data.set_transaction_state_async(broadcast_hash, TxFlags.STATE_CLEARED,
                TxFlags.MASK_STATE_BROADCAST)

        return result

    async def update_mapi_fee_quotes_async(self, account_id: int, timeout: float=4.0) \
            -> list[TransactionFeeContext]:
        """
        Ask the wallet to coordinate ensuring it has updated fee quotes.

        Raises nothing.
        """
        # In most cases overlapping updates will be fetching the same things. Any blocked calls
        # will pick up matches from the blocking call.
        fee_quotes: list[TransactionFeeContext] = []
        async with self._fee_quote_lock:
            servers_with_credentials = self.get_servers_for_account_id(account_id,
                NetworkServerType.MERCHANT_API)
            async for server, credential_id in update_mapi_fee_quotes_async(
                    servers_with_credentials, timeout):
                server_state = server.api_key_state[credential_id]
                assert server_state.last_fee_quote is not None
                fee_context = TransactionFeeContext(server_state.last_fee_quote,
                    ServerAndCredential(server, credential_id))
                fee_quotes.append(fee_context)
        return fee_quotes

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
                    if server_fee <= transaction_fee:
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
            self.logger.debug("Cannot undo verifications on a stopped wallet. "
                "Orphaned block hashes: %s", loggable_block_ids)
            return

        reorged_tx_hashes = await self.data.update_reorged_transactions_async(orphaned_block_hashes)

        self.logger.debug('Removing verification of %d transactions. Orphaned block hashes: %s',
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

    def get_server(self, server_key: ServerAccountKey) -> NewServer|None:
        assert server_key.account_id is None
        return self._servers.get(server_key)

    def _load_servers(self, password: str) -> None:
        """
        Load into the wallet all the known servers.

        This will include both the servers known in the wallet database, and it will also import
        the servers that are not known in the wallet database but are hardcoded into ElectrumSV.
        """
        self._registered_api_keys: dict[ServerAccountKey, IndefiniteCredentialId] = {}
        base_row_by_server_key: dict[ServerAccountKey, NetworkServerRow] = {}
        account_rows_by_server_key: dict[ServerAccountKey, list[NetworkServerRow]] = {}
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

        credential_id: IndefiniteCredentialId | None
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
            server_type: NetworkServerType | None = getattr(NetworkServerType,
                hardcoded_server_config['type'], None)
            if server_type is None:
                self.logger.error("Misconfigured hard-coded server with url '%s' and type '%s'",
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
                    self.logger.error("Server '%s' has invalid capability '%s'", url,
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
                encrypted_api_key: str|None = None
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

        # REST API: Tracked on the wallet and not the network because it works in offline mode too.
        # We can likely come up with a better approach to an access token for the websocket later.
        self.restapi_websocket_access_token = double_sha256(os.urandom(256)).hex()
        self._restapi_connections: dict[str, LocalWebsocketState] = {}

    def setup_restapi_connection(self, websocket_state: LocalWebsocketState) -> bool:
        "Register a new external REST API websocket connection for this wallet."
        if self._stopping or self._stopped:
            return False
        self._restapi_connections[websocket_state.websocket_id] = websocket_state
        return True

    def teardown_restapi_connection(self, websocket_id: str) -> None:
        "Unregister an existing external REST API websocket connection for this wallet."
        del self._restapi_connections[websocket_id]

    async def _close_restapi_connections_async(self) -> None:
        "Shutdown all external REST API websocket connections for this wallet."
        for websocket_state1 in list(self._restapi_connections.values()):
            # We only close the connection if it is still open (this loop blocks).
            websocket_state2 = self._restapi_connections.pop(websocket_state1.websocket_id)
            if websocket_state2 is not None:
                await close_restapi_connection_async(websocket_state1)

    async def subscribe_to_external_peer_channel(self, remote_url: str,
            remote_channel_id: str, token: str, invoice_id: int,
            pre_existing_channel: bool=False) -> None:
        """Calling this must be idempotent - i.e. it will only perform database writes if
        there is not already an entry, otherwise it only updates in-memory caches and re-establishes
        websocket connectivity"""
        credential_id = app_state.credentials.add_indefinite_credential(
            token)
        assert self._network is not None
        # Add Peer Channel information to the database if it has not already been added
        if not pre_existing_channel:
            peer_channel_row, read_token = await self.data.create_external_peer_channel_async(
                remote_channel_id, remote_url, token, invoice_id=invoice_id)
        else:
            channel_rows = self.data.read_external_peer_channels(
                remote_channel_id=remote_channel_id)
            assert len(channel_rows) == 1
            peer_channel_row = channel_rows[0]

        peer_channel_server_state = PeerChannelServerState(
            wallet_proxy=weakref.proxy(self),
            wallet_data=self.data,
            session=self._network.aiohttp_session,
            credential_id=credential_id,
            remote_channel_id=remote_channel_id,
            external_channel_row=peer_channel_row
        )

        assert peer_channel_row.remote_channel_id is not None
        peer_channel_server_state.mapi_callback_consumer_future = app_state.async_.spawn(
            self._consume_mapi_callback_messages_async(peer_channel_server_state))

        # Connect to the peer channel and actively listen on the websocket for messages
        peer_channel_server_state.connection_future = app_state.async_.spawn(
            maintain_external_peer_channel_connection_async(peer_channel_server_state))
        peer_channel_server_state.connection_future.add_done_callback(
            partial(self._maintain_server_connection_done, peer_channel_server_state))

        account_id = self._petty_cash_account.get_id()
        if self._worker_tasks_external_peer_channel_connections.get(account_id) is not None:
            self._worker_tasks_external_peer_channel_connections[account_id]\
                .append(peer_channel_server_state)
        else:
            self._worker_tasks_external_peer_channel_connections[account_id] = \
                [(peer_channel_server_state)]


    async def send_outgoing_direct_payment_async(self, invoice_id: int,
            transaction: Transaction) -> PaymentACK:
        """
        Raises `Bip270Exception` if the remote server returned an error. `exception.args[0]`
            contains text describing the error.
        """
        assert self._network is not None
        invoice_row = self.data.read_invoice(invoice_id=invoice_id)
        assert invoice_row is not None
        # Calling logic should have detected this and warned/confirmed with the user.
        transaction_hash = transaction.hash()
        assert transaction_hash == invoice_row.tx_hash

        payment_ack = await send_outgoing_direct_payment_async(
            invoice_row.payment_uri, transaction.to_hex())
        await self.data.set_transaction_state_async(transaction_hash, TxFlags.STATE_DISPATCHED,
            TxFlags.MASK_STATE_BROADCAST)
        assert payment_ack.peer_channel_info is not None
        remote_url = payment_ack.peer_channel_info['host']
        remote_channel_id = payment_ack.peer_channel_info['channel_id']
        token = payment_ack.peer_channel_info['token']
        await self.subscribe_to_external_peer_channel(remote_url=remote_url,
            remote_channel_id=remote_channel_id, token=token, invoice_id=invoice_id,
            pre_existing_channel=False)

        await self.data.update_invoice_flags_async(
            [ (PaymentFlag.CLEARED_MASK_STATE, PaymentFlag.STATE_PAID, invoice_id) ])
        await self.notify_external_listeners_async("outgoing-payment-delivered",
            invoice_id=invoice_id)
        return payment_ack

    def _event_transaction_verified(self, event_name: str, transaction_hash: bytes, header: Header,
            tsc_proof: TSCMerkleProof) -> None:
        # NOTE(rt12) The `TriggeredEvents` mechanic has no async capabilities so we do this for now.
        app_state.async_.spawn(self._event_transaction_verified_async(transaction_hash, header,
            tsc_proof))

    async def _event_transaction_verified_async(self, transaction_hash: bytes, header: Header,
            tsc_proof: TSCMerkleProof) -> None:
        await self.notify_external_listeners_async("transaction-mined",
            transaction_hash=transaction_hash, header=header, tsc_proof=tsc_proof)

    def _event_payment_requests_paid(self, event_name: str, paymentrequest_ids: list[int]) -> None:
        # NOTE(rt12) The `TriggeredEvents` mechanic has no async capabilities so we do this for now.
        app_state.async_.spawn(self._event_payment_requests_paid_async(paymentrequest_ids))

    async def _event_payment_requests_paid_async(self, paymentrequest_ids: list[int]) -> None:
        transaction_ids_by_request_id = \
            await self.data.read_payment_request_transactions_hashes_async(paymentrequest_ids)
        await self.notify_external_listeners_async("incoming-payment-received",
            request_payment_hashes=list(transaction_ids_by_request_id.items()))

    async def notify_external_listeners_async(self, event_name: BroadcastEventNames, *,
            request_payment_hashes: list[tuple[int, list[bytes]]] | None = None,
            invoice_id: int | None = None, transaction_hash: bytes | None = None,
            header: Header | None = None, tsc_proof: TSCMerkleProof | None = None,
            mapi_callback_response: MAPICallbackResponse | None = None,
            event_source: BroadcastEventPayloadNames | None = None,
            event_payload: str | None = None) -> None:
        """
        This is used for broadcasts to any external connections for this wallet. The responsibility
        is on the external connection type to transform the raw wallet data into the outgoing data
        structures it sends to connected parties.
        """
        for websocket_state in list(self._restapi_connections.values()):
            await broadcast_restapi_event_async(websocket_state, event_name,
                paid_request_hashes=request_payment_hashes,
                invoice_id=invoice_id, transaction_hash=transaction_hash, header=header,
                tsc_proof=tsc_proof, mapi_callback_response=mapi_callback_response,
                event_source=event_source, event_payload=event_payload)

    def _process_payment_requests(self, password: str) -> None:
        """
        Read in any outstanding payment requests and reconcile them or cache any runtime state.

        Raises nothing.
        """
        # Legacy payments. Delete interrupted requests.
        # The user will not have been given any way to give out the payment details for this
        # payment request. We should abandon everything related to it, including any peer channels
        # that were mid-creation.
        # TODO(1.4.0) Peer channels. Make sure we delete any peer channels that were created for
        #     this on reconnection to the server, and drop any messages.
        paymentrequest_ids: list[int] = []
        for paymentrequest_row in self.data.read_payment_requests(
                flags=PaymentFlag.STATE_PREPARING | PaymentFlag.TYPE_MONITORED,
                mask=PaymentFlag.MASK_STATE | PaymentFlag.MASK_TYPE | PaymentFlag.MASK_HIDDEN):
            assert paymentrequest_row.paymentrequest_id is not None
            if paymentrequest_row.date_created + 2 * 24 * 60 * 60 < time.time():
                paymentrequest_ids.append(paymentrequest_row.paymentrequest_id)
        if len(paymentrequest_ids) > 0:
            app_state.async_.spawn(
                self.data.delete_payment_requests_async(paymentrequest_ids, PaymentFlag.DELETED))

        # DPP invoices. Cache runtime state.
        self._dpp_invoice_credentials: dict[str, tuple[IndefiniteCredentialId, PublicKey]] = {}
        for paymentrequest_row in self.data.read_payment_requests(
                flags=PaymentFlag.STATE_UNPAID | PaymentFlag.TYPE_INVOICE,
                mask=PaymentFlag.MASK_STATE | PaymentFlag.MASK_TYPE | PaymentFlag.MASK_HIDDEN):
            self.register_outstanding_invoice(paymentrequest_row, password)

    def register_outstanding_invoice(self, payment_request_row: PaymentRequestRow,
            password: str) -> None:
        """
        Cache the credential and public key for an outstanding DPP invoice the wallet has hosted
        externally.

        Raises nothing.
        """
        assert payment_request_row.dpp_invoice_id is not None
        assert payment_request_row.encrypted_key_text is not None
        secure_key_text = pw_decode(payment_request_row.encrypted_key_text, password)
        credential_id = app_state.credentials.add_indefinite_credential(secure_key_text)
        secure_public_key = PrivateKey.from_hex(secure_key_text).public_key
        self._dpp_invoice_credentials[payment_request_row.dpp_invoice_id] = \
            credential_id, secure_public_key

    def get_outstanding_invoice_data(self, invoice_id: str) \
            -> tuple[IndefiniteCredentialId, PublicKey]:
        return self._dpp_invoice_credentials[invoice_id]

    def unregister_outstanding_invoice(self, payment_request_row: PaymentRequestRow) -> None:
        assert payment_request_row.dpp_invoice_id is not None
        del self._dpp_invoice_credentials[payment_request_row.dpp_invoice_id]

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

        # These are the servers the user has opted to use primarily whether through manual or
        # automatic choice.
        for server, usage_flags in self.get_wallet_servers():
            await self.start_reference_server_connection_async(server, usage_flags)

        # Read in all non-deactivated peer channels for externally owned peer channels
        for external_peer_channel_row in self.data.read_external_peer_channels(
                flags=ServerPeerChannelFlag.NONE,
                mask=ServerPeerChannelFlag.DEACTIVATED):
            peer_channel_id = external_peer_channel_row.peer_channel_id
            assert peer_channel_id is not None
            access_tokens = self.data.read_external_peer_channel_access_tokens(peer_channel_id,
                None, PeerChannelAccessTokenFlag.FOR_LOCAL_USAGE)
            assert len(access_tokens) == 1, "There should only be one access token " \
                "designated for local use"

            assert external_peer_channel_row.remote_url is not None
            assert external_peer_channel_row.remote_channel_id is not None
            remote_url = external_peer_channel_row.remote_url
            remote_channel_id = external_peer_channel_row.remote_channel_id
            token = access_tokens[0].access_token
            await self.subscribe_to_external_peer_channel(remote_url=remote_url,
                remote_channel_id=remote_channel_id, token=token,
                invoice_id=external_peer_channel_row.invoice_id, pre_existing_channel=True)

    def _maintain_server_connection_done(self, state: ServerStateProtocol,
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

    async def start_reference_server_connection_async(self, server: NewServer,
            usage_flags: NetworkServerFlag) -> ServerConnectionState:
        assert self._network is not None, "use of network in offline mode"

        if usage_flags & NetworkServerFlag.USE_BLOCKCHAIN != 0:
            blockchain_server_key = ServerAccountKey(server.url, server.server_type, None)
            logger.debug("Setting blockchain service to: '%s'", blockchain_server_key)

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
                added_usage_flags: NetworkServerFlag) -> None:

            # In theory this consumer could be started only for servers that actually will
            # be receiving mapi callbacks but this is a future problem. We should aim to only
            # run code where it is relevant.
            if added_usage_flags & NetworkServerFlag.USE_MESSAGE_BOX:
                server_state.mapi_callback_consumer_future = app_state.async_.spawn(
                    self._consume_mapi_callback_messages_async(server_state))

            # If the server was created only for "message box" usage, then we still need to
            # start the mapi callback consumer task
            if added_usage_flags & NetworkServerFlag.USE_BLOCKCHAIN:
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
            # Ensure that everything is fully upgraded and ready to use by doing this blocking
            # logic here. The caller can then proceed to use the server without race conditions.
            # An example of what blocks is creating a peer channel locally and remotely to
            # receive tip filter notifications through.
            await upgrade_server_connection_async(existing_server_state, usage_flags)
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

    def get_tip_filter_server_state(self) -> ServerConnectionState | None:
        server_state = self.get_connection_state_for_usage(NetworkServerFlag.USE_BLOCKCHAIN)
        if server_state is None or \
                server_state.connection_flags & ServerConnectionFlag.TIP_FILTER_READY == 0:
            return None
        return server_state

    def get_connection_state_for_usage(self, usage_flags: NetworkServerFlag) \
            -> ServerConnectionState | None:
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

    async def _consume_mapi_callback_messages_async(self, state: ServerStateProtocol) -> None:
        """
        Process MAPI callback messages received from a server.

        This will either receive messages directly from the server message loop, or it will
        process backlogged unprocessed messages on startup.
        """
        message_entries = list[tuple[PeerChannelMessageRow, GenericPeerChannelMessage]]()
        if isinstance(state, ServerConnectionState):
            for message_row in await self.data.read_server_peer_channel_messages_async(
                    state.server.server_id,
                    PeerChannelMessageFlag.UNPROCESSED, PeerChannelMessageFlag.UNPROCESSED,
                    ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK,
                    ServerPeerChannelFlag.MASK_PURPOSE):
                message = cast(GenericPeerChannelMessage, json.loads(message_row.message_data))
                message_entries.append((message_row, message))
        elif isinstance(state, PeerChannelServerState):
            for message_row in await self.data.read_external_peer_channel_messages_async(
                    PeerChannelMessageFlag.UNPROCESSED, PeerChannelMessageFlag.UNPROCESSED,
                    ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK,
                    ServerPeerChannelFlag.MASK_PURPOSE):
                message = cast(GenericPeerChannelMessage, json.loads(message_row.message_data))
                message_entries.append((message_row, message))
        else:
            raise NotImplementedError("Server connection state type not recognized")

        # Iterate loop and get from queue
        state.mapi_callback_response_queue.put_nowait(message_entries)
        state.mapi_callback_response_event.set()

        while not (self._stopping or self._stopped):
            # This blocks until there is pending work and it is safe to perform it.
            self.logger.debug("Waiting for more MAPI callback messages")
            await self._wait_for_chain_related_work_async(
                ChainWorkerToken.MAPI_MESSAGE_CONSUMER, [ state.mapi_callback_response_event.wait ])
            if self._stopping or self._stopped:
                return

            if state.mapi_callback_response_queue.qsize() == 0:
                state.mapi_callback_response_event.clear()
                continue

            # We can now process the next batch of messages.
            message_entries = state.mapi_callback_response_queue.get_nowait()

            tx_update_rows :list[TransactionProofUpdateRow] = []
            proof_rows: list[MerkleProofRow] = []
            processed_message_ids: list[int] = []
            processed_message_ids_externally_owned: list[int] = []
            headerless_proofs = list[tuple[TSCMerkleProof, MerkleProofRow]]()
            verified_entries = list[tuple[bytes, Header, TSCMerkleProof]]()
            date_updated = get_posix_timestamp()

            for message_row, message in message_entries:
                self.logger.debug("Got mAPI callback message: %s", message)
                assert message_row.message_id is not None
                if isinstance(state, ServerConnectionState):
                    processed_message_ids.append(message_row.message_id)
                elif isinstance(state, PeerChannelServerState):
                    processed_message_ids_externally_owned.append(message_row.message_id)

                if not isinstance(message["payload"], str):
                    # TODO(1.4.0) Unreliable server, issue#841. WRT peer channel message, show user.
                    self.logger.error("Peer channel message (MAPI) payload invalid: '%s'",
                        message)
                    continue

                try:
                    payload_bytes = base64.b64decode(message["payload"])
                except binascii.Error:
                    self.logger.error("Peer channel message (MAPI) payload invalid base64: '%s'",
                        message)
                    continue

                try:
                    payload_object = json.loads(payload_bytes)
                except json.JSONDecodeError:
                    self.logger.error("Peer channel message (MAPI) payload invalid JSON: '%s'",
                        message)
                    continue

                envelope = cast(JSONEnvelope, payload_object)
                try:
                    validate_json_envelope(envelope)
                except ValueError as e:
                    # TODO(1.4.0) Unreliable server, issue#841. WRT peer channel message, show user.
                    self.logger.error("Peer channel MAPI callback envelope invalid: %s '%s'",
                        e.args[0], message)
                    continue

                response = cast(MAPICallbackResponse, json.loads(envelope["payload"]))
                try:
                    validate_mapi_callback_response(response)
                except ValueError as e:
                    # TODO(1.4.0) Unreliable server, issue#841. WRT peer channel message, show user.
                    self.logger.exception("Peer channel MAPI callback response invalid: %s '%s'",
                        e.args[0], message)
                    continue

                if response["callbackReason"] == "merkleProof":
                    proof_json = cast(TSCMerkleProofJson, response["callbackPayload"])
                    # TODO(1.4.0) Unreliable server, issue#841. Validate the response 'targetType'.
                    #     We should verify it in `validate_mapi_callback_response` or we should
                    #     handle all target types.
                    assert proof_json["targetType"] == "header"
                    proof = TSCMerkleProof.from_json(proof_json)

                    # TODO(mapi) The MAPI server may send updates if the transaction is reorged,
                    #      this means the lifetime of the channel has to be long enough to catch
                    #      these.

                    if not verify_proof(proof):
                        # TODO(1.4.0) Unreliable server, issue#841. The MAPI proof is standalone
                        #     with embedded header, no failure! If we do get a dud proof then we
                        #     throw it away.
                        self.logger.error("Peer channel MAPI proof invalid: '%s'", message)
                        continue

                    assert proof.block_header_bytes is not None
                    assert proof.transaction_hash is not None

                    block_hash = double_sha256(proof.block_header_bytes)
                    header_match = self.lookup_header_for_hash(block_hash)
                    if header_match is None:
                        self.logger.debug("Missing header for merkle proof with block hash: '%s'.",
                            hash_to_hex_str(block_hash))
                        # Reasons why we are here:
                        # - This header is on the wallet's current chain but it is on the
                        #   unprocessed tip. This falls to the headerless proof worker to resolve
                        #   when the tip is connected.
                        # - This header is for a different chain/fork which the MAPI server is
                        #   apparently following and we are not (yet?). It will be present if we
                        #   reorg to the MAPI server's fork.

                        # Connecting out of band headers (or trying to) does not necessarily help
                        # this wallet as the wallet follows a specific header source and not
                        # necessarily the longest chain.
                        header, _chain = app_state.connect_out_of_band_header(
                            proof.block_header_bytes)

                        block_height: int = BlockHeight.MEMPOOL
                        if header is not None:
                            block_height = cast(int, header.height)

                        tx_update_rows.append(TransactionProofUpdateRow(block_hash,
                            BlockHeight.MEMPOOL, proof.transaction_index, TxFlags.STATE_CLEARED,
                            date_updated, proof.transaction_hash))
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
                elif response["callbackReason"] in ("doubleSpend", "doubleSpendAttempt"):
                    event_name: BroadcastEventNames = "transaction-double-spend"
                    # Double spend detected in a new block or an attempt arrived in the mempool.
                    app_state.async_.spawn(
                        self.notify_external_listeners_async(event_name,
                            mapi_callback_response=response, event_source="MAPI",
                            event_payload=envelope["payload"]))
                else:
                    self.logger.error("Peer channel MAPI message not yet supported %s '%s'",
                        response["callbackReason"], message)
                    continue

            # Set the given merkle proof as the one for the active chain on the given transaction
            # also creating it in the merkle proof table if it is not already there.
            if len(tx_update_rows) > 0 or len(proof_rows) > 0:
                await self.data.update_transaction_proof_async(tx_update_rows, proof_rows, [],
                    processed_message_ids, processed_message_ids_externally_owned,
                    { TxFlags.STATE_SETTLED })

            # These are detached proofs, which we do not have a header or chain for. We register
            # them so that when the header comes in, they can be considered for use.
            for headerless_proof in headerless_proofs:
                self._connect_headerless_proof_worker_state.proof_queue.put_nowait(headerless_proof)
            if headerless_proofs:
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
                if is_later_dpp_message_sequence(msg_prior, msg_later):
                    latest_dpp_messages[dpp_message.dpp_invoice_id] = msg_later
        return [msg for msg in latest_dpp_messages.values()]

    def get_dpp_server_url(self, server_id: int) -> str:
        server_url: str | None = None
        for dpp_server_state in self.dpp_proxy_server_states:
            if dpp_server_state.server.server_id == server_id:
                server_url = dpp_server_state.server.url
                break
        assert server_url is not None
        return server_url

    async def _consume_dpp_messages_async(self, state: ServerConnectionState) -> None:
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
        payment_request_rows = self.data.read_payment_requests(
            flags=PaymentFlag.TYPE_INVOICE | PaymentFlag.STATE_UNPAID,
            mask=PaymentFlag.MASK_TYPE | PaymentFlag.MASK_STATE | PaymentFlag.MASK_HIDDEN,
            server_id=state.server.server_id)

        # Initialize ws:// connections for pre-existing active invoice records from the database
        assert len(state.dpp_websockets) == 0
        await create_dpp_server_connections_async(state, payment_request_rows)

        # Initialize the state machine message queue for pre-existing active invoice records
        paymentrequest_ids = [pr_row.paymentrequest_id for pr_row in payment_request_rows]
        dpp_messages = db_functions.read_dpp_messages_by_pr_id(self._db_context, paymentrequest_ids)
        for dpp_message in self._filter_out_earlier_dpp_message_states(dpp_messages):
            state.dpp_messages_queue.put_nowait(dpp_message)

        # State machine
        while not (self._stopping or self._stopped):
            message_row: DPPMessageRow
            message_row = await state.dpp_messages_queue.get()
            if message_row.type == DPPMessageType.JOIN_SUCCESS:
                continue

            request_row, request_output_rows = self.data.read_payment_request(
                request_id=message_row.paymentrequest_id)
            if request_row is None:
                self.logger.error("Failed to read payment request with id: %s from the database. "
                    "DPPMessageRow data: %s", message_row.paymentrequest_id, message_row)
                continue

            if request_row.request_flags & PaymentFlag.MASK_STATE == PaymentFlag.STATE_PAID:
                if message_row.type == DPPMessageType.PAYMENT:
                    # Defensive code in the case that the payer tries to pay an invoice that is
                    # already paid.
                    assert request_row.dpp_ack_json is not None
                    self.logger.warning("Peer attempted to pay for an already paid invoice")
                    dpp_ack_dict = cast(PaymentACKDict, json.loads(request_row.dpp_ack_json))
                    dpp_ack_message = dpp_make_ack(txid=dpp_ack_dict["mode"]["transactionIds"][0],
                        peer_channel=dpp_ack_dict["peerChannel"], message_row_received=message_row)
                    app_state.async_.spawn(dpp_websocket_send(state, dpp_ack_message))
                    continue
                elif message_row.type == DPPMessageType.REQUEST_CREATE:
                    error_reason = "Requested payment terms for an already paid invoice. " \
                        f"Invoice id: {request_row.dpp_invoice_id}"
                    self.logger.warning(error_reason)
                    dpp_err_message = dpp_make_payment_request_error(message_row, error_reason)
                    app_state.async_.spawn(dpp_websocket_send(state, dpp_err_message))
                    continue
                raise NotImplementedError("Unexpected message type")

            assert request_row.paymentrequest_id is not None
            assert request_row.request_flags & PaymentFlag.MASK_TYPE == PaymentFlag.TYPE_INVOICE, \
                request_row.request_flags

            # Update flag to new state & write to database
            assert message_row.type in MESSAGE_STATE_BY_TYPE, message_row.type
            new_state = MESSAGE_STATE_BY_TYPE[message_row.type]
            if request_row.request_flags & PaymentFlag.MASK_DPP_STATE != new_state:
                new_flags = request_row.request_flags & ~PaymentFlag.MASK_DPP_STATE | new_state
                request_row = request_row._replace(request_flags=new_flags)
                assert request_row.paymentrequest_id is not None
                update_row = PaymentRequestUpdateRow(new_flags, request_row.requested_value,
                    request_row.date_expires, request_row.description,
                    request_row.merchant_reference, request_row.dpp_ack_json,
                    request_row.paymentrequest_id)
                await self.data.update_payment_requests_async([ update_row ])

            self.logger.debug("State machine processing DPPMessageRow: %s for state: %s",
                message_row, request_row.request_flags)

            # ----- States for when we are the Payee ----- #
            if request_row.request_flags & PaymentFlag.MASK_DPP_STATE == \
                    PaymentFlag.DPP_TERMS_REQUESTED:
                assert request_row.server_id is not None
                assert request_row.dpp_invoice_id is not None
                server_url = self.get_dpp_server_url(request_row.server_id)
                credential_id, _secure_public_key = self.get_outstanding_invoice_data(
                    request_row.dpp_invoice_id)
                dpp_response_message = dpp_make_payment_request_response(server_url, credential_id,
                    request_row, request_output_rows, message_row)
                app_state.async_.spawn(dpp_websocket_send(state, dpp_response_message))

            elif request_row.request_flags & PaymentFlag.MASK_DPP_STATE == \
                    PaymentFlag.DPP_PAYMENT_RECEIVED:
                # This parsing step also validates the received `Payment` message
                try:
                    payment_obj = Payment.from_json(message_row.body.decode('utf-8'))
                except Bip270Exception:
                    self.logger.exception("Received direct-payment-protocol `Payment` was invalid")
                    continue

                # As the *Payee*, we broadcast the transaction
                tx = Transaction.from_hex(payment_obj.transaction_hex)
                assert request_row.paymentrequest_id is not None
                try:
                    await self.validate_payment_request_async(request_row.paymentrequest_id,
                        [ (tx, None) ])
                except Bip270Exception as e:
                    self.logger.exception("Bip270Exception validating payment request: %s, "
                        "txid: %s", request_row.paymentrequest_id, tx.txid())
                    error_reason = str(e)
                    dpp_err_message = dpp_make_payment_error(message_row, error_reason)
                    app_state.async_.spawn(dpp_websocket_send(state, dpp_err_message))
                    continue
                except Exception:
                    self.logger.exception("Unexpected exception validating the payment request: "
                        "%s, txid: %s", request_row.paymentrequest_id, tx.txid())
                    error_reason = "The Payee wallet encountered an unexpected exception " \
                        f"validating payment request: {request_row.paymentrequest_id}, " \
                        f"txid: {tx.txid()}."
                    dpp_err_message = dpp_make_payment_error(message_row, error_reason, 500,
                        "Internal Server Error")
                    app_state.async_.spawn(dpp_websocket_send(state, dpp_err_message))
                    continue

                # @pettycash @accountkeys ??
                # The petty cash account is supposed to fund general wallet background maintenance
                # without requiring the user to enter their password to approve spending. Is it the
                # right choice to use here? Is there any other option?
                mapi_server_hint = \
                    self.get_mapi_broadcast_context(state.petty_cash_account_id, tx)
                assert mapi_server_hint is not None
                tx_context = TransactionContext(mapi_server_hint=mapi_server_hint)
                try:
                    broadcast_result = await self.broadcast_transaction_async(tx, tx_context)
                except (GeneralAPIError, ServerConnectionError, ServerError, BadServerError):
                    self.logger.exception("Unexpected exception broadcasting to mAPI")
                    continue
                mapi_result = broadcast_result.mapi
                assert mapi_result is not None

                if broadcast_result.success:
                    try:
                        # NOTE: This will update the payment request with PaymentFlag.PAID
                        await self.close_payment_request_async(request_row.paymentrequest_id,
                            [(tx, None)])
                    except Bip270Exception as e:
                        error_reason = str(e)
                        dpp_err_message = dpp_make_payment_error(message_row, error_reason)
                        app_state.async_.spawn(dpp_websocket_send(state, dpp_err_message))
                        self.logger.exception("Unexpected exception processing the transaction")
                        continue
                    except Exception:
                        self.logger.exception("Unexpected exception processing the transaction")
                        error_reason = "The Payee wallet encountered an unexpected exception " \
                            "processing this transaction."
                        dpp_err_message = dpp_make_payment_error(message_row, error_reason, 500,
                            "Internal Server Error")
                        app_state.async_.spawn(dpp_websocket_send(state, dpp_err_message))
                        continue

                    # Re-read from the db because `close_payment_request_async` applied updates
                    request_row, request_output_rows = self.data.read_payment_request(
                        request_id=message_row.paymentrequest_id)
                    assert request_row is not None
                    assert request_row.paymentrequest_id is not None
                    assert mapi_result.peer_channel_data is not None

                    # Add dpp_ack_json to payment_request_row in case the Payer tries to
                    # re-attempt payment for the same invoice.
                    dpp_ack_message = dpp_make_ack(tx.txid(), mapi_result.peer_channel_data,
                        message_row)
                    update_row = PaymentRequestUpdateRow(request_row.request_flags,
                        request_row.requested_value, request_row.date_expires,
                        request_row.description, request_row.merchant_reference,
                        dpp_ack_message.body.decode('utf-8'),
                        request_row.paymentrequest_id)
                    await self.data.update_payment_requests_async([update_row])

                    # Send PaymentACK to payer
                    app_state.async_.spawn(dpp_websocket_send(state, dpp_ack_message))
                else:
                    self.logger.error("mAPI broadcast for txid: %s failed with reason: %s",
                        tx.txid(), mapi_result.response['resultDescription'])

                    # Inform the *Payer* of the reason we rejected their `Payment`
                    error_reason = mapi_result.response['resultDescription']
                    dpp_err_message = dpp_make_payment_error(message_row, error_reason)
                    app_state.async_.spawn(dpp_websocket_send(state, dpp_err_message))

                    # Mark the now unused peer channel with deactivated state
                    # NOTE: This is an "Owned" peer channel type (not externally owned)
                    if mapi_result.server_state is not None:
                        assert mapi_result.peer_channel_data is not None
                        assert mapi_result.server_state.cached_peer_channel_rows is not None
                        remote_channel_id = mapi_result.peer_channel_data['channel_id']
                        peer_channel_row = mapi_result.server_state.\
                            cached_peer_channel_rows[remote_channel_id]
                        new_channel_flags = peer_channel_row.peer_channel_flags | \
                            ServerPeerChannelFlag.DEACTIVATED
                        assert peer_channel_row.peer_channel_id is not None
                        await self.data.update_server_peer_channel_async(
                            peer_channel_row.remote_channel_id,
                            peer_channel_row.remote_url, new_channel_flags,
                            peer_channel_row.peer_channel_id,
                            addable_access_tokens=[])

            # ----- States for when we are the Payer ----- #
            # NOTE: Not included because when we are the ** Payer **, we use the simplified
            # http request/response REST API endpoints of the DPP server (i.e. BIP272 URI)

    async def garbage_collect_externally_owned_peer_channels_async(self) -> None:
        """Cleanup peer channels that have mAPI callback messages with timestamp past the
        expiry window and set the peer channel to the DEACTIVATED state."""
        def have_active_connection(remote_channel_id: str) -> bool:
            for account_id in list(self._worker_tasks_external_peer_channel_connections):
                for externally_owned_state in \
                        self._worker_tasks_external_peer_channel_connections[account_id]:

                    # The peer_channel_message_queue.qsize() check is to ensure that the initial
                    # check for missed messages has completed after websocket connection.
                    # The `processing_message_event` is an additional precaution to ensure that
                    # processing of the last message in the queue actually completes before
                    # deactivation.
                    if externally_owned_state.remote_channel_id == remote_channel_id\
                            and externally_owned_state.peer_channel_message_queue.qsize() == 0 \
                            and not externally_owned_state.processing_message_event.is_set():
                        return True
            return False

        async def deactivate_channel_if_appropriate(
                external_peer_channel_row: ExternalPeerChannelRow) -> None:
            assert external_peer_channel_row.peer_channel_id is not None
            messages = self.data.read_external_peer_channel_messages_by_id(
                external_peer_channel_row.peer_channel_id, most_recent_only=True)
            if len(messages) == 1:
                peer_channel_past_expiry = \
                    int(time.time()) - messages[0].date_received > PEER_CHANNEL_EXPIRY_SECONDS
                if messages[0].message_flags & PeerChannelMessageFlag.UNPROCESSED == 0 and \
                        peer_channel_past_expiry:
                    self.logger.debug("Deactivating external peer channel row: %s ",
                        external_peer_channel_row)
                    new_flags = external_peer_channel_row.peer_channel_flags | \
                        ServerPeerChannelFlag.DEACTIVATED
                    await self.data.update_external_peer_channel_async(
                        external_peer_channel_row.remote_channel_id,
                        external_peer_channel_row.remote_url, new_flags,
                        external_peer_channel_row.peer_channel_id, []
                    )

        while not (self._stopping or self._stopped):
            await asyncio.sleep(60)
            # Get all externally owned peer channels that are NOT in the deactivated state
            for external_peer_channel_row in self.data.read_external_peer_channels(
                    flags=ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK,
                    mask=ServerPeerChannelFlag.MAPI_BROADCAST_CALLBACK |
                         ServerPeerChannelFlag.DEACTIVATED):
                # If we do not yet have an established connection, there might still be more
                # messages to come
                assert external_peer_channel_row.remote_channel_id is not None
                if have_active_connection(external_peer_channel_row.remote_channel_id):
                    await deactivate_channel_if_appropriate(external_peer_channel_row)

    async def _consume_tip_filter_matches_async(self, state: ServerConnectionState) -> None:
        """
        Process tip filter messages received from a server.

        NOTE: We ignore tip filter events for the same pushdata/tx in the database function.

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
        message_entries: list[tuple[PeerChannelMessageRow, GenericPeerChannelMessage]] = []
        for message_row in await self.data.read_server_peer_channel_messages_async(
                state.server.server_id,
                PeerChannelMessageFlag.UNPROCESSED, PeerChannelMessageFlag.UNPROCESSED,
                ServerPeerChannelFlag.TIP_FILTER_DELIVERY, ServerPeerChannelFlag.MASK_PURPOSE):
            message = cast(GenericPeerChannelMessage, json.loads(message_row.message_data))
            message_entries.append((message_row, message))
        state.tip_filter_matches_queue.put_nowait(message_entries)

        while not (self._stopping or self._stopped):
            rows_by_account_id: dict[int, list[PushDataMatchMetadataRow]] = {}
            creation_pushdata_match_rows: list[PushDataMatchRow] = []
            processed_message_ids: list[int] = []
            for message_row, message in await state.tip_filter_matches_queue.get():
                assert message_row.message_id is not None
                processed_message_ids.append(message_row.message_id)

                # We are getting JSON peer channel notifications. These are encoded as base64.
                if not isinstance(message["payload"], str):
                    # TODO(1.4.0) Unreliable server, issue#841. WRT tip filter match, show user.
                    self.logger.error("Peer channel message (filter) payload invalid: '%s'",
                        message)
                    continue

                try:
                    payload_bytes = base64.b64decode(message["payload"])
                except binascii.Error:
                    self.logger.error("Peer channel message (filter) payload invalid base64: '%s'",
                        message)
                    continue

                try:
                    payload_object = json.loads(payload_bytes)
                except json.JSONDecodeError:
                    self.logger.error("Peer channel message (filter) payload invalid JSON: '%s'",
                        message)
                    continue

                pushdata_matches = cast(TipFilterPushDataMatchesData, payload_object)
                if "blockId" not in pushdata_matches or "matches" not in pushdata_matches:
                    # TODO(1.4.0) Unreliable server, issue#841. WRT tip filter match, show user.
                    self.logger.error("Peer channel message payload invalid: '%s'", message)
                    continue

                date_created = int(time.time())
                block_hash: bytes|None = None
                if pushdata_matches["blockId"] is not None:
                    block_hash = hex_str_to_hash(pushdata_matches["blockId"])
                for tip_filter_match in pushdata_matches["matches"]:
                    pushdata_hash = bytes.fromhex(tip_filter_match["pushDataHashHex"])
                    transaction_hash = hex_str_to_hash(tip_filter_match["transactionId"])
                    transaction_index = tip_filter_match["transactionIndex"]
                    match_flags = PushDataMatchFlag(tip_filter_match["flags"])
                    creation_pushdata_match_row = PushDataMatchRow(state.server.server_id,
                        pushdata_hash, transaction_hash, transaction_index, block_hash, match_flags,
                        date_created)
                    creation_pushdata_match_rows.append(creation_pushdata_match_row)

            self.logger.debug("Writing %d pushdata matches to the database",
                len(creation_pushdata_match_rows))
            # The processed messages will have their `PeerChannelMessageFlag.UNPROCESSED` flag
            # removed here as part of an atomic update, that also inserts their extracted
            # pushdata matches.
            # Subsequent pushdata events for the same pushdata/tx combination are ignored by this
            # function as they are redundant for achieving an initial import of the transaction.
            await self.data.create_pushdata_matches_async(creation_pushdata_match_rows,
                processed_message_ids)

            # We have to go to the database to find out:
            # - What account a push data match is associated with.
            # - Which matches do not already have the associated transaction imported.
            # We could do this in the `create_pushdata_matches_async` call and return it, but
            # this double-dipping in the database is good enough for now.
            match_metadata_rows = self.data.read_pushdata_match_metadata()
            for metadata_row in match_metadata_rows:
                if metadata_row.account_id in rows_by_account_id:
                    rows_by_account_id[metadata_row.account_id].append(metadata_row)
                else:
                    rows_by_account_id[metadata_row.account_id] = [ metadata_row ]

            self.logger.debug("Wallet processing %d tip filter matches", len(match_metadata_rows))

            for account_id, match_metadata_rows in rows_by_account_id.items():
                obtain_transaction_keys: list[MissingTransactionMetadata] = []
                for metadata_row in match_metadata_rows:
                    obtain_transaction_keys.append(MissingTransactionMetadata(
                        metadata_row.transaction_hash,
                        { TransactionKeyUsageMetadata(metadata_row.pushdata_hash,
                            metadata_row.keyinstance_id, metadata_row.script_type) },
                        metadata_row.block_hash is not None))
                self.logger.debug("Obtaining %d transactions for account %d, %s",
                    len(obtain_transaction_keys), account_id, obtain_transaction_keys)
                await self.obtain_transactions_async(account_id, obtain_transaction_keys,
                    TransactionImportFlag.TIP_FILTER_MATCH)

    def _register_spent_outputs_to_monitor(self, spent_outpoints: list[Outpoint]) -> None:
        """
        Call this to start monitoring outpoints when the wallet needs to know if they are mined.
        """
        if self._network is None:
            return

        state = self.get_connection_state_for_usage(NetworkServerFlag.USE_BLOCKCHAIN)
        if state is None:
            # The server has not started yet.
            self.logger.debug("Skipping premature output spend registrations")
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
            mined_transactions: set[tuple[bytes, bytes]] = set()
            mempool_transactions: dict[bytes, TxFlags] = {}
            for spent_output in spent_outputs:
                spent_outpoint = Outpoint(spent_output.out_tx_hash, spent_output.out_index)
                if spent_outpoint not in rows_by_outpoint:
                    # TODO(server-reliability) Spent outputs. The user would have had to delete the
                    #     transaction from the database if that is even possible? Is that correct?
                    #     Should we do something here?
                    self.logger.error("No database entries for spent output notification %r",
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

                        self.logger.error("Ignored output spend notification. This may be a "
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
                            self.logger.debug("Unspent output event, transaction is back in "
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

                            self.logger.debug("Unspent output event, transaction has been mined "
                                " %r ~ %r", spent_output, row)
                            mined_transactions.add((row.spending_tx_hash, spent_output.block_hash))
                        else:
                            # The blockchain server has informed us that the transaction is in a
                            # block. The wallet believes that the transaction is in a different
                            # block. We should never apply this change here, it should be
                            # applied by the processing of updates from our header source.

                            # TODO(reorgs) Consider using this output spend to check consistency.
                            self.logger.debug("Unspent output event, transaction reorged %r ~ %r",
                                spent_output, row)
                    elif row.block_hash is None and row.flags & TxFlags.MASK_STATE_LOCAL:
                        # The blockchain server has informed us that a transaction we do not
                        # know to be broadcast, has been broadcast and is in the mempool.

                        # TODO(1.4.0) User experience, issue#909. Notify the user that this local
                        #     transaction has been broadcast unexpectedly.

                        if row.mapi_broadcast_flags is None:
                            self.logger.debug("Unspent output event, local transaction has been "
                                "broadcast %r ~ %r", spent_output, row)
                            mempool_transactions[spent_output.in_tx_hash] = row.flags
                        else:
                            self.logger.warning("Unspent output event, local transaction has "
                                "been broadcast with unwanted output spend notification "
                                "%r ~ %r", spent_output, row)
                    else:
                        # Nothing is different than what we already have. Ignore the result. It
                        # probably came in during the registration as the initial state.
                        pass

            tx_update_rows: list[TransactionProofUpdateRow] = []
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

    async def validate_payment_request_async(self, request_id: int,
            candidates: list[tuple[Transaction, TransactionContext | None]],
            error_callback: Callable[[str], None] | None=None) -> None:
        """
        Raises `Bip270Exception` if the candidate transactions do not fully and correctly pay for
            the payment request.
        """
        request_row, request_output_rows = self.data.read_payment_request(request_id)
        assert request_row is not None
        assert len(request_output_rows) > 0

        if not all(transaction.is_complete() for transaction, transaction_context in candidates):
            raise Bip270Exception(_("One or more of the transactions provided are not final."))

        request_output_row_by_script_bytes = {
            request_output_row.output_script_bytes: request_output_row
            for request_output_row in request_output_rows }

        received_value = 0
        transaction_hashes: list[bytes] = []
        transaction_output_key_usages: list[dict[int, tuple[int, ScriptType]]] = []
        for transaction, transaction_context in candidates:
            transaction_hash = transaction.hash()
            transaction_hashes.append(transaction_hash)
            transaction_output_key_usage: dict[int, tuple[int, ScriptType]] = {}
            transaction_output_key_usages.append(transaction_output_key_usage)

            for output_index, transaction_output in enumerate(transaction.outputs):
                script_bytes = transaction_output.script_pubkey.to_bytes()
                request_output_row = request_output_row_by_script_bytes.get(script_bytes, None)
                if request_output_row is None:
                    continue
                if request_output_row.output_value != transaction_output.value:
                    self.logger.debug("Transaction '%s' output %d has value %d, "
                        "expected value %d", hash_to_hex_str(transaction_hash), output_index,
                        transaction_output.value, request_output_row.output_value)
                    raise Bip270Exception(_("The transactions do not provide the correct values."))
                transaction_output_key_usage[output_index] = (request_output_row.keyinstance_id,
                    request_output_row.output_script_type)

                received_value += transaction_output.value

        if received_value != request_row.requested_value:
            self.logger.debug("The transactions are incorrect and provided value %d but "
                "expected value %d satoshis.", received_value, request_row.requested_value)
            raise Bip270Exception(_("The transactions do not provide the correct values."))

        # NOTE(output-spends) This will trigger registration for output spend events to monitor
        #     if this transaction gets broadcast externally.
        for transaction_index, (transaction, transaction_context) in enumerate(candidates):
            transaction_hash = transaction_hashes[transaction_index]
            transaction_output_key_usage = transaction_output_key_usages[transaction_index]
            try:
                await self.add_local_transaction_async(transaction.hash(), transaction,
                    TxFlags.STATE_RECEIVED, BlockHeight.LOCAL, None,
                    TransactionImportFlag.MANUAL_IMPORT,
                    transaction_output_key_usage=transaction_output_key_usage)
            except DatabaseUpdateError as update_exception:
                # TODO Abort/bail.
                pass
            except TransactionAlreadyExistsError:
                # TODO Check if the keys are mapped correctly.
                pass

    async def close_payment_request_async(self, request_id: int,
            candidates: list[tuple[Transaction, TransactionContext | None]],
            error_callback: Callable[[str], None] | None=None) -> None:
        """
        Raises `ValueError` if the candidate transactions do not fully and correctly pay for
            the payment request.
        """
        await self.validate_payment_request_async(request_id, candidates, error_callback)

        transaction_description_update_rows = await self.data.close_paid_payment_request_async(
            request_id)

        # Notify any dependent systems including the GUI that the payment request has been updated.
        self.events.trigger_callback(WalletEvent.PAYMENT_REQUEST_PAID, [ request_id ])
        if len(transaction_description_update_rows):
            self.events.trigger_callback(WalletEvent.TRANSACTION_LABELS_UPDATE,
                transaction_description_update_rows)

    async def _close_payment_request_for_transaction_async(self, transaction_hash: bytes) -> None:
        """
        This transaction is expected to be related to an outstanding payment request and we need
        to locate that payment request, and see if it closes out that payment request as paid.

        At the time of writing this is related to the tip filter and blockchain monitored ones.
        """
        payment_request_ids = self.data.read_payment_request_ids_for_transaction(transaction_hash)
        # The caller should only call this in circumstances where they expect there to be a payment
        # request associated with this transaction. Our policy is to error in problem situations.
        assert len(payment_request_ids) > 0, "_close_payment_request_for_transaction_async given " \
            "a transaction hash that is not linked to keys associated with outstanding payment " \
            f"requests {hash_to_hex_str(transaction_hash)}"

        closed_payment_request_ids: list[int] = []
        all_transaction_description_update_rows: list[tuple[str, int, bytes]] = []
        for payment_request_id in payment_request_ids:
            request_row, request_output_rows = self.data.read_payment_request(payment_request_id)
            assert request_row is not None
            assert len(request_output_rows) > 0

            # @BlindPaymentRequests
            # This is to support the node wallet comparible JSON-RPC API. The GUI does not use it.
            # The idea is that these payment requests relate to an existing externally registered
            # tip filter registration and the external party should be notified about all payment
            # transactions to this key.
            if request_row.requested_value is None:
                continue

            try:
                transaction_description_update_rows = \
                    await self.data.close_paid_payment_request_async(payment_request_id)
            except DatabaseUpdateError:
                self.logger.exception("Transaction did not close payment request %s",
                    payment_request_id)
            else:
                all_transaction_description_update_rows.extend(transaction_description_update_rows)

        # Notify dependent systems including the GUI that these payment requests have been updated.
        self.events.trigger_callback(WalletEvent.PAYMENT_REQUEST_PAID, closed_payment_request_ids)
        if len(all_transaction_description_update_rows):
            self.events.trigger_callback(WalletEvent.TRANSACTION_LABELS_UPDATE,
                all_transaction_description_update_rows)

    def have_transaction(self, transaction_hash: bytes) -> bool:
        return self.data.get_transaction_flags(transaction_hash) is not None

    def get_transaction(self, transaction_hash: bytes) -> Transaction|None:
        lock = self._obtain_transaction_lock(transaction_hash)
        with lock:
            try:
                return self._get_cached_transaction(transaction_hash)
            finally:
                self._relinquish_transaction_lock(transaction_hash)

    def _get_cached_transaction(self, transaction_hash: bytes) -> Transaction|None:
        tx = self._transaction_cache2.get(transaction_hash)
        if tx is None:
            tx_bytes = db_functions.read_transaction_bytes(self.get_db_context(), transaction_hash)
            if tx_bytes is not None:
                tx = Transaction.from_bytes(tx_bytes)
                self._transaction_cache2.set(transaction_hash, tx)
        return tx

    def get_transaction_bytes(self, transaction_hash: bytes) -> bytes|None:
        """
        Get the byte data for the transaction directly from the database if it is present.
        """
        return db_functions.read_transaction_bytes(self.get_db_context(), transaction_hash)

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

    def get_blockchain_server_state(self) -> HeaderServerState | None:
        return self._blockchain_server_state

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

    async def _manage_dpp_connections_async(self) -> None:
        assert self._network is not None

        for server in self._servers.values():
            if server.server_type == NetworkServerType.DPP_PROXY:
                state = ServerConnectionState(
                    # TODO(petty-cash) Which petty cash account to bill against when/if we do that.
                    petty_cash_account_id=self._petty_cash_account.get_id(),
                    usage_flags=NetworkServerFlag.NONE,
                    wallet_proxy=weakref.proxy(self),
                    wallet_data=self.data,
                    session=self._network.aiohttp_session,
                    server=server,
                    credential_id=server.client_api_keys[None])
                self.dpp_proxy_server_states.append(state)
                state.dpp_consumer_future = app_state.async_.spawn(
                    self._consume_dpp_messages_async(state))

    def start(self, network: Network | None) -> None:
        assert app_state.headers is not None

        self._network = network
        self._chain_management_queue = asyncio.Queue[tuple[ChainManagementKind,
            tuple[Chain, list[bytes], list[Header]] | tuple[Chain, list[Header]]]]()
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

            self._worker_task_peer_channel_garbage_collection = app_state.async_.spawn(
                self.garbage_collect_externally_owned_peer_channels_async())

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

        # REST API websockets are available online and offline. We do not want to do no-op async
        # here as it locks up the direct command-line options `create_wallet` / `create_account`.
        if len(self._restapi_connections) > 0:
            app_state.async_.spawn_and_wait(self._close_restapi_connections_async())
        if self._network is not None:
            self._shutdown_network_related_tasks()

        if self._worker_task_chain_management is not None:
            self._worker_task_chain_management.cancel()
            self._worker_task_chain_management = None

        for credential_id in self._registered_api_keys.values():
            app_state.credentials.remove_indefinite_credential(credential_id)
        app_state.credentials.remove_indefinite_credential(self.identity_private_key_credential_id)

        # This will be a metadata save on exit. Anything else has been updated as it was changed.
        updated_states: list[NetworkServerRow] = []
        for server in self._servers.values():
            updated_states.extend(server.to_updated_rows())
        if len(updated_states):
            # We do not need to wait for the future to complete, as closing the storage below
            # should close out all database pending writes.
            self.update_network_servers([], updated_states, [], {})

        if self._network is not None:
            self._network.remove_wallet(self)

        self.data.teardown()
        self._storage.close()

        self._network = None
        self._stopped = True

    def _shutdown_network_related_tasks(self) -> None:
        # Collect the futures we are waiting to complete.
        pending_futures: set[concurrent.futures.Future[Any]] = set()

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
        if self._worker_task_peer_channel_garbage_collection is not None:
            self._worker_task_peer_channel_garbage_collection.cancel()
            pending_futures.add(self._worker_task_peer_channel_garbage_collection)

        async def trigger_chain_management_interrupt_event() -> None:
            # `Event.set` is not thread-safe, needs to be executed in the async thread.
            self._chain_management_interrupt_event.set()
            await asyncio.sleep(0)

        # This blocks the current thread, but we are exiting and it is not expected that
        # anything should take a noticeable amount of time to exit.
        app_state.async_.spawn_and_wait(trigger_chain_management_interrupt_event())

        # Only kill if not signalled to exit by the chain management interrupt event.
        kill_blockchain_server_dependent_workers = \
            not self._blockchain_server_chain_reconciled_event.is_set()
        if self._worker_task_obtain_transactions is not None:
            if kill_blockchain_server_dependent_workers:
                self._worker_task_obtain_transactions.cancel()
            pending_futures.add(self._worker_task_obtain_transactions)
            self._worker_task_obtain_transactions = None
        if self._worker_task_obtain_merkle_proofs is not None:
            if kill_blockchain_server_dependent_workers:
                self._worker_task_obtain_merkle_proofs.cancel()
            pending_futures.add(self._worker_task_obtain_merkle_proofs)
            self._worker_task_obtain_merkle_proofs = None

        kill_headerless_proofs_worker = not self._header_source_chain_reconciled_event.is_set()
        if self._worker_task_connect_headerless_proofs is not None:
            if kill_headerless_proofs_worker:
                self._worker_task_connect_headerless_proofs.cancel()
            pending_futures.add(self._worker_task_connect_headerless_proofs)
            self._worker_task_connect_headerless_proofs = None

        for petty_cash_account_id in list(self._worker_tasks_maintain_server_connection):
            for state in self._worker_tasks_maintain_server_connection.pop(petty_cash_account_id):
                # This was signalled to exit by the chain management interrupt event.
                if state.mapi_callback_consumer_future is not None:
                    pending_futures.add(state.mapi_callback_consumer_future)
                # These are manually cancelled and it should be safe to do so.
                if state.stage_change_pipeline_future is not None:
                    state.stage_change_pipeline_future.cancel()
                    pending_futures.add(state.stage_change_pipeline_future)
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

        for account_id in list(self._worker_tasks_external_peer_channel_connections):
            for externally_owned_state in \
                    self._worker_tasks_external_peer_channel_connections.pop(account_id):
                if externally_owned_state.mapi_callback_consumer_future is not None:
                    pending_futures.add(externally_owned_state.mapi_callback_consumer_future)
                if externally_owned_state.connection_future is not None:
                    externally_owned_state.connection_future.cancel()
                    pending_futures.add(externally_owned_state.connection_future)

        for state in self.dpp_proxy_server_states:
            if state.dpp_consumer_future is not None:
                state.dpp_consumer_future.cancel()
                pending_futures.add(state.dpp_consumer_future)

        total_wait = 0.0
        while len(pending_futures) > 0 and total_wait < 5.0:
            self.logger.debug("Shutdown waiting for %d tasks to exit: %s", len(pending_futures),
                pending_futures)
            # Cancelled tasks clean up when they get a chance to run next. Python will complain
            # on exit about tasks that are not cleaned up.
            app_state.async_.spawn_and_wait(asyncio.sleep(0))
            done, not_done = concurrent.futures.wait(pending_futures, 1.0)
            pending_futures = not_done
            total_wait += 1.0

        if len(pending_futures) > 0:
            # This should never happen outside of in development errors. We include it both for
            # that reason and also in case it unexpectedly happens, the user does not have a
            # zombie wallet process.
            for lagging_future in pending_futures:
                lagging_future.cancel()
            self.logger.error("Network related tasks shutdown uncleanly (cancelled %d)",
                len(pending_futures))
        else:
            self.logger.debug("Network related tasks shutdown cleanly")

    def create_gui_handler(self, window: WindowProtocol, account: AbstractAccount) -> None:
        for keystore in account.get_keystores():
            if isinstance(keystore, Hardware_KeyStore):
                plugin = cast('QtPluginBase', keystore.plugin)
                plugin.replace_gui_handler(window, keystore)

    async def _wait_for_chain_related_work_async(self, token: ChainWorkerToken,
            coroutine_callables: \
                Sequence[Callable[[], Coroutine[Any, Any, Literal[True]]]]|None=None) -> None:
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
                extended_awaitables: list[asyncio.Task[Literal[True]]] = \
                    [ asyncio.create_task(entry(), name=token.name)
                        for entry in coroutine_callables ]
                extended_awaitables.append(chain_task)

                try:
                    awaitables_done, _awaitables_pending = await asyncio.wait(extended_awaitables,
                        return_when=asyncio.FIRST_COMPLETED)
                finally:
                    for task in extended_awaitables:
                        task.cancel()

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
        self.logger.debug("Waiting to start chain management task")
        await self._start_chain_management_event.wait()
        assert self._current_chain is not None

        # These are the chain-related worker tasks this management task needs to coordinate with.
        expected_worker_tokens = {
            ChainWorkerToken.CONNECT_PROOF_CONSUMER, ChainWorkerToken.MAPI_MESSAGE_CONSUMER,
            ChainWorkerToken.OBTAIN_PROOF_WORKER, ChainWorkerToken.OBTAIN_TRANSACTION_WORKER,
        }

        self.logger.debug("Entered chain management task")
        while True:
            item_kind, item_data = await self._chain_management_queue.get()
            self.logger.debug("Acquired chain management work %s", item_kind)
            if item_kind == ChainManagementKind.BLOCKCHAIN_EXTENSION:
                extension_chain, new_headers = cast(tuple[Chain, list[Header]], item_data)
                assert self._current_chain is extension_chain
                self._current_tip_header = new_headers[-1]

                self._storage.put("current_tip_hash",
                    hash_to_hex_str(self._current_tip_header.hash))

                self.local_chain_update_event.set()
                self.local_chain_update_event.clear()

                for header in new_headers:
                    logger.debug("New tip hash: %s, height: %s", hash_to_hex_str(header.hash),
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
                self.logger.debug("Awaiting chain management workers %s",
                    expected_worker_tokens-signalled_worker_tokens)
                try:
                    worker_token = await asyncio.wait_for(self._chain_worker_queue.get(), 10.0)
                except asyncio.TimeoutError:
                    self.logger.exception("Timed out waiting for a worker to block, have %s",
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

            self.logger.debug("Post reorg wallet chain %d->%d:%s",
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
            server_state: HeaderServerState|None, header_source_chain: Chain,
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
                    self.logger.debug("Continuing existing wallet chain %d->%d:%s",
                        chain.first_height, header.height, hash_to_hex_str(header.hash))
                    assert self.process_header_source_update(server_state, chain, header,
                        header_source_chain, header_source_tip_header, force=True)
            else:
                detached_wallet_tip = True

            if detached_wallet_tip:
                # Either this is a new wallet or it is an old wallet that predates storage of this
                # record. We have to do a full table scan to rectify this situation, but none of
                # these wallets should have that many transactions.
                orphaned_block_hashes: list[bytes] = []
                for block_hash in self.data.read_transaction_block_hashes():
                    try:
                        transaction_header, transaction_chain = app_state.lookup_header(block_hash)
                    except MissingHeader:
                        orphaned_block_hashes.append(block_hash)
                    else:
                        if transaction_chain is header_source_chain:
                            continue

                        common_chain, common_height = cast(tuple[Chain|None, int],
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
                self.logger.debug("Processed detached wallet chain %d->%d:%s",
                    header_source_chain.first_height,
                    header_source_tip_header.height, hash_to_hex_str(header_source_tip_header.hash))
        else:
            # Switch header sources for an already initialised wallet with a current chain.
            assert self._current_tip_header is not None
            # Guarantees relating to these calls: Search for CorrectHeaderSequence.
            self._update_current_chain(header_source_chain, header_source_tip_header)
            self.logger.debug("Switched wallet chain %d->%d:%s", header_source_chain.first_height,
                header_source_tip_header.height, hash_to_hex_str(header_source_tip_header.hash))
            assert self.process_header_source_update(server_state, self._current_chain,
                self._current_tip_header, header_source_chain,
                header_source_tip_header, force=True)

        self._blockchain_server_state_ready = True
        self._start_chain_management_event.set()
        if server_state is not None:
            self._blockchain_server_chain_reconciled_event.set()
        self._header_source_chain_reconciled_event.set()

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

        self.local_chain_update_event.set()
        self.local_chain_update_event.clear()

    def process_header_source_update(self, server_state: HeaderServerState|None,
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
                _chain, fork_height = cast(tuple[Chain|None, int],
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
                logger.debug("Reorg detected; undoing wallet verifications for block hashes %s",
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

    def _is_wallet_header_source(self, server_state: HeaderServerState|None) -> bool:
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

    async def obtain_transactions_async(self, account_id: int,
            missing_transaction_entries: list[MissingTransactionMetadata],
            import_flags: TransactionImportFlag=TransactionImportFlag.UNSET) -> set[bytes]:
        """
        Update the registry of transactions we do not have or are in the process of getting.

        Return the hashes out of `tx_hashes` that do not already exist and will attempt to be
        acquired.
        """
        async with self._obtain_transactions_async_lock:
            missing_transaction_hashes: set[bytes] = set()
            existing_tx_hashes = set(r.tx_hash for r in self.data.read_transactions_exist(
                [ key.transaction_hash for key in missing_transaction_entries ]))
            for transaction_hash, match_metadatas, with_proof in missing_transaction_entries:
                if transaction_hash in existing_tx_hashes:
                    continue
                if transaction_hash in self._missing_transactions:
                    # These transactions are not in the database, metadata is tracked in the entry
                    # and we should update it.
                    self._missing_transactions[transaction_hash].import_flags |= import_flags
                    self._missing_transactions[transaction_hash].with_proof |= with_proof
                    self._missing_transactions[transaction_hash].match_metadatas |= match_metadatas
                    if account_id not in self._missing_transactions[transaction_hash].account_ids:
                        self._missing_transactions[transaction_hash].account_ids.append(account_id)
                else:
                    self._missing_transactions[transaction_hash] = MissingTransactionEntry(
                        import_flags, match_metadatas, with_proof, [ account_id ])
                    missing_transaction_hashes.add(transaction_hash)

            self.logger.debug("Registering %d missing transactions",
                len(missing_transaction_hashes))
            # Prompt the missing transaction logic to try again if the user is re-registering
            # already missing transactions (the `TransactionImportFlag.PROMPTED` check).
            if len(missing_transaction_hashes) or import_flags & TransactionImportFlag.PROMPTED:
                self._check_missing_transactions_event.set()
            return missing_transaction_hashes

    async def _obtain_transactions_worker_async(self) -> None:
        assert app_state.headers is not None
        self.logger.debug("_obtain_transactions_worker_async entered")

        # We need the header source to be fully synchronised before we start.
        await self._blockchain_server_chain_reconciled_event.wait()
        self.logger.debug("_obtain_transactions_worker_async started")

        # To get here there must not have been any further missing transactions.
        self._check_missing_transactions_event.set()
        while not (self._stopping or self._stopped):
            # This blocks until there is pending work and it is safe to perform it.
            self.logger.debug("Waiting for more missing transactions")
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
                    self.logger.debug("Picked missing transaction %s", hash_to_hex_str(tx_hash))
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
                        self.logger.error("Still need to implement handling for inability to "
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
                            BlockHeight.MEMPOOL, key_usage_metadatas=entry.match_metadatas)

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
                            self.logger.error("Still need to implement handling for receiving "
                                "invalid merkle proofs")
                            return
                    except TSCMerkleProofError:
                        # TODO(1.4.0) Unreliable server, issue#841. Merkle proof verify invalid.
                        self.logger.error("Still need to implement handling for receiving "
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
                            proof_row=proof_row, key_usage_metadatas=entry.match_metadatas)
                    else:
                        await self.import_transaction_async(tx_hash, tx, TxFlags.STATE_CLEARED,
                            block_height, key_usage_metadatas=entry.match_metadatas)
                        await self.data.create_merkle_proofs_async([ proof_row ])

                    assert tx_hash not in self._missing_transactions
                else:
                    tx_bytes = await self.fetch_raw_transaction_async(tx_hash, account)
                    tx = Transaction.from_bytes(tx_bytes)
                    await self.import_transaction_async(tx_hash, tx, TxFlags.STATE_CLEARED,
                        BlockHeight.MEMPOOL, key_usage_metadatas=entry.match_metadatas)
                    assert tx_hash not in self._missing_transactions

                if entry.import_flags & TransactionImportFlag.TIP_FILTER_MATCH:
                    await self._close_payment_request_for_transaction_async(tx_hash)

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
        await self._blockchain_server_chain_reconciled_event.wait()

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
                self.logger.debug("Requesting merkle proof from server for transaction %s",
                    hash_to_hex_str(tx_hash))
                try:
                    tsc_full_proof_bytes = await request_binary_merkle_proof_async(state, tx_hash,
                        include_transaction=False)
                except ServerConnectionError:
                    # TODO(1.4.0) Unreliable server, issue#841. Error connecting to server.
                    #     No reliable server should cause this, we should stand off the server or
                    #     something similar.
                    self.logger.error("Still need to implement handling for inability to connect"
                        "to a server to get arbitrary merkle proofs")
                    await asyncio.sleep(60)
                    continue

                try:
                    tsc_proof = TSCMerkleProof.from_bytes(tsc_full_proof_bytes)
                except TSCMerkleProofError:
                    # TODO(1.4.0) Unreliable server, issue#841. Non-parseable merkle proof.
                    #     No trustable server should cause this, we should disable the server or
                    #     something similar.
                    self.logger.error("Still need to implement handling for inability to connect"
                        "to a server to get arbitrary merkle proofs")
                    return

                assert tsc_proof.block_hash is not None
                try:
                    header, chain = app_state.lookup_header(tsc_proof.block_hash)
                except MissingHeader:
                    # We store the proof in a way where we know we obtained it recently, but
                    # that it is still in need of processing. The late header worker can
                    # read these in on startup and will get it via the queue at runtime.
                    # date_updated = int(time.time())
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
                        self.logger.error("Still need to implement handling for inability to "
                            "connect to a server to get arbitrary merkle proofs")
                        return
                except TSCMerkleProofError:
                    # TODO(1.4.0) Unreliable server, issue#841. Merkle proof invalid on verify.
                    self.logger.error("Still need to implement handling for receiving "
                        "invalid merkle proofs")
                    return

                block_height = cast(int, header.height)
                if self.is_header_within_current_chain(header.height, tsc_proof.block_hash):
                    self.logger.debug("OMP Storing verified merkle proof for transaction %s",
                        hash_to_hex_str(tx_hash))

                    # This proof is valid for the wallet's view of the blockchain.
                    date_updated = int(time.time())
                    tx_update_row = TransactionProofUpdateRow(tsc_proof.block_hash, block_height,
                        tsc_proof.transaction_index, TxFlags.STATE_SETTLED, date_updated,
                        tx_hash)
                    proof_row = MerkleProofRow(tsc_proof.block_hash,
                        tsc_proof.transaction_index, header.height, tsc_proof.to_bytes(),
                        tx_hash)
                    await self.data.update_transaction_proof_async([ tx_update_row ],
                        [ proof_row ], [], [], [], { TxFlags.STATE_SETTLED })

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
        await self._header_source_chain_reconciled_event.wait()
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

            process_entries: list[tuple[Header, tuple[TSCMerkleProof, MerkleProofRow]]] = []

            # This is non-blocking. We know it empties all the pending proofs.
            if state.proof_event.is_set():
                pending_proof_entries: list[tuple[TSCMerkleProof, MerkleProofRow]] = []
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
                pending_headers: list[tuple[Header, Chain]] = []
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
            transaction_proof_updates: list[TransactionProofUpdateRow] = []
            proof_updates: list[MerkleProofUpdateRow] = []
            verified_proof_entries: list[tuple[Header, tuple[TSCMerkleProof, MerkleProofRow]]] = []

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

            self.logger.debug("Updating %s headerless proofs after receipt of new block header(s)",
                len(transaction_proof_updates))
            await self.data.update_transaction_proof_async(transaction_proof_updates, [],
                proof_updates, [], [], { TxFlags.STATE_CLEARED, TxFlags.STATE_SETTLED })

            for header, (proof, _proof_row) in verified_proof_entries:
                assert proof.transaction_hash is not None
                self.data.events.trigger_callback(WalletEvent.TRANSACTION_VERIFIED,
                    proof.transaction_hash, header, proof)

    # Helper methods to access blockchain data that can be seen through the wallet's view of the it.

    def get_current_chain(self) -> Chain | None:
        return self._current_chain

    def get_header_source_state(self, server_state: HeaderServerState|None) \
            -> tuple[Chain, Header]:
        if server_state is None:
            chain = get_longest_valid_chain()
            tip_header = cast(Header, chain.tip)
            return chain, tip_header

        assert server_state.chain is not None
        assert server_state.tip_header is not None
        return server_state.chain, server_state.tip_header

    def get_local_tip_header(self) -> Header | None:
        return self._current_tip_header

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

    def lookup_header_for_height(self, block_height: int) -> Header|None:
        """
        """
        if self._current_chain is None:
            return None
        try:
            return app_state.header_at_height(self._current_chain, block_height)
        except MissingHeader:
            return None

    def lookup_header_for_hash(self, block_hash: bytes, force_chain: Chain | None=None) \
            -> tuple[Header, Chain]|None:
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
        common_chain: Chain|None
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

    def status(self) -> WalletStatusDict:
        servers_state: dict[str, list[str]] = {}
        for usage_flag in SERVER_USES:
            server_state = self.get_connection_state_for_usage(usage_flag)
            if server_state is not None:
                if server_state.server.url not in servers_state:
                    servers_state[server_state.server.url] = []
                servers_state[server_state.server.url].append(cast(str, usage_flag.name))
        return { "servers": servers_state }

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
        self._fee_quotes: list[TransactionFeeContext] = []
        self._fee_quote_future: concurrent.futures.Future[list[TransactionFeeContext]] | None = None
        self.callbacks: list[Callable[[list[TransactionFeeContext]], None]] = []

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
        fee_quotes.extend(await self.account._wallet.update_mapi_fee_quotes_async(account_id))
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
