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
import attr
import itertools
import json
import os
import random
import threading
import time
from typing import (Any, Dict, Iterable, List, NamedTuple, Optional, Sequence, Set,
    Tuple, Type, TypeVar, Union)
import weakref

from bitcoinx import (
    Address, PrivateKey, PublicKey, P2MultiSig_Output, hash160, P2SH_Address,
    P2PK_Output, Script,
    hex_str_to_hash, hash_to_hex_str, MissingHeader
)

from . import coinchooser
from .app_state import app_state
from .bitcoin import compose_chain_string, COINBASE_MATURITY, ScriptTemplate
from .constants import (CHANGE_SUBPATH, DerivationType, KeyInstanceFlag, TxFlags,
    RECEIVING_SUBPATH, ScriptType, TransactionOutputFlag, PaymentState)
from .contacts import Contacts
from .crypto import pw_encode, pw_decode
from .exceptions import (NotEnoughFunds, ExcessiveFee, UserCancelled, UnknownTransactionException,
    WalletLoadError)
from .i18n import _
from .keystore import (Hardware_KeyStore, Imported_KeyStore, instantiate_keystore, KeyStore)
from .logs import logs
from .networks import Net
from .paymentrequest import InvoiceStore
from .simple_config import SimpleConfig
from .storage import WalletStorage
from .transaction import (Transaction, XPublicKey, NO_SIGNATURE,
    XTxInput, XTxOutput, XPublicKeyType)
from .util import (format_satoshis, format_time, timestamp_to_datetime,
    get_wallet_name_from_path)
from .wallet_database import TxData, TxProof, TransactionCacheEntry, TransactionCache
from .wallet_database.tables import (AccountRow, AccountTable, KeyInstanceRow, KeyInstanceTable,
    MasterKeyRow, MasterKeyTable, TransactionTable, TransactionOutputTable,
    TransactionOutputRow, TransactionDeltaTable, TransactionDeltaRow, PaymentRequestTable,
    PaymentRequestRow)

logger = logs.get_logger("wallet")



@attr.s(auto_attribs=True)
class DeterministicKeyAllocation:
    masterkey_id: int
    derivation_type: DerivationType
    derivation_path: Sequence[int]

@attr.s(auto_attribs=True)
class BIP32KeyData:
    masterkey_id: int
    derivation_path: Sequence[int]
    script_type: ScriptType
    script_pubkey: bytes


class HistoryLine(NamedTuple):
    sort_key: Tuple[int, int]
    tx_hash: bytes
    height: Optional[int]
    value_delta: int


@attr.s(slots=True, cmp=False, hash=False)
class UTXO:
    value = attr.ib()
    script_pubkey = attr.ib()
    script_type = attr.ib()
    tx_hash = attr.ib()
    out_index = attr.ib()
    height = attr.ib()
    keyinstance_id = attr.ib()
    address = attr.ib()
    # To determine if matured and spendable
    is_coinbase = attr.ib()
    flags: TransactionOutputFlag = attr.ib()

    def __eq__(self, other):
        return isinstance(other, UTXO) and self.key() == other.key()

    def __hash__(self):
        return hash(self.key())

    def key(self) -> Tuple[bytes, int]:
        return (self.tx_hash, self.out_index)

    def key_str(self) -> str:
        return f"{hash_to_hex_str(self.tx_hash)}:{self.out_index}"

    def to_tx_input(self, account: 'AbstractAccount') -> XTxInput:
        threshold = account.get_threshold(self.script_type)
        return XTxInput(
            prev_hash=self.tx_hash,
            prev_idx=self.out_index,
            script_sig=Script(),
            sequence=0xffffffff,
            threshold=threshold,
            script_type=self.script_type,
            signatures=[NO_SIGNATURE] * threshold,
            x_pubkeys=account.get_xpubkeys_for_id(self.keyinstance_id),
            value=self.value,
            keyinstance_id=self.keyinstance_id
        )


class SyncState:
    def __init__(self) -> None:
        self._key_history: Dict[int, List[Tuple[str, int]]] = {}
        self._tx_keys: Dict[str, Set[int]] = {}

    def get_key_history(self, key_id: int) -> List[Tuple[str, int]]:
        return self._key_history.get(key_id, [])

    def set_key_history(self, key_id: int,
            history: List[Tuple[str, int]]) -> Tuple[Set[str], Set[str]]:
        old_history = self._key_history.get(key_id, [])
        self._key_history[key_id] = history

        old_tx_ids = set(t[0] for t in old_history)
        new_tx_ids = set(t[0] for t in history)

        removed_tx_ids = old_tx_ids - new_tx_ids
        added_tx_ids = new_tx_ids - old_tx_ids

        for tx_id in removed_tx_ids:
            self._tx_keys[tx_id].remove(key_id)

        for tx_id in added_tx_ids:
            if tx_id not in self._tx_keys:
                 self._tx_keys[tx_id] = set()
            self._tx_keys[tx_id].add(key_id)

        return removed_tx_ids, added_tx_ids

    def get_transaction_key_ids(self, tx_id: str) -> Set[int]:
        tx_keys = self._tx_keys.get(tx_id)
        if tx_keys is None:
            return set()
        return tx_keys


def dust_threshold(network):
    return 546 # hard-coded Bitcoin SV dust threshold. Was changed to this as of Sept. 2018


T = TypeVar('T', bound='AbstractAccount')

class AbstractAccount:
    """
    Account classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    _default_keystore: KeyStore = None

    max_change_outputs = 10

    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            output_rows: List[TransactionOutputRow]) -> None:
        # Prevent circular reference keeping parent and accounts alive.
        self._wallet = weakref.proxy(wallet)
        self._row = row
        self._id = row.account_id

        self._logger = logs.get_logger("account[{}]".format(self.name()))
        self._network = None

        # For synchronization.
        self._activated_keys: List[int] = []
        self._activated_keys_lock = threading.Lock()
        self._activated_keys_event = app_state.async_.event()
        self._deactivated_keys: List[int] = []
        self._deactivated_keys_lock = threading.Lock()
        self._deactivated_keys_event = app_state.async_.event()
        self._synchronize_event = app_state.async_.event()
        self._synchronized_event = app_state.async_.event()
        self.txs_changed_event = app_state.async_.event()
        self.request_count = 0
        self.response_count = 0
        self.progress_event = app_state.async_.event()

        self._load_sync_state()
        self._utxos: Dict[Tuple[bytes, int], UTXO] = {}
        self._stxos: Dict[Tuple[bytes, int], int] = {}
        self._keypath: Dict[int, Sequence[int]] = {}
        self._keyinstances: Dict[int, KeyInstanceRow] = { r.keyinstance_id: r for r
            in keyinstance_rows }
        self._masterkey_ids: Set[int] = set(row.masterkey_id for row in keyinstance_rows
            if row.masterkey_id is not None)
        self._payment_requests: Dict[int, PaymentRequestRow] = {}

        self._load_keys(keyinstance_rows)
        self._load_txos(output_rows)
        self._load_payment_requests()

        # locks: if you need to take several, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()

        # invoices and contacts
        # TODO(rt12) BACKLOG formalise porting/storage of invoice data extracted from storage data
        self.invoices = InvoiceStore({})

    def get_id(self) -> int:
        return self._id

    def get_wallet(self) -> 'Wallet':
        return self._wallet

    # Displayable short-hand for intra-wallet usage.
    def get_key_text(self, key_id: int) -> str:
        keyinstance = self._keyinstances[key_id]
        text = f"{key_id}:{keyinstance.masterkey_id}"
        derivation = self._keypath.get(key_id)
        text += ":"+ ("None" if derivation is None else compose_chain_string(derivation))
        return text

    def get_keyinstance(self, key_id: int) -> KeyInstanceRow:
        return self._keyinstances[key_id]

    def get_keyinstance_ids(self) -> Sequence[int]:
        return tuple(self._keyinstances.keys())

    def get_next_derivation_index(self, derivation_path: Sequence[int]) -> int:
        raise NotImplementedError

    def allocate_keys(self, count: int,
            derivation_path: Sequence[int]) -> List[DeterministicKeyAllocation]:
        return []

    def create_keys_until(self, derivation: Sequence[int],
            script_type: Optional[ScriptType]=None) -> List[KeyInstanceRow]:
        with self.lock:
            derivation_path = derivation[:-1]
            next_index = self.get_next_derivation_index(derivation_path)
            desired_index = derivation[-1]
            required_count = (desired_index - next_index) + 1
            assert required_count > 0, f"desired={desired_index}, current={next_index-1}"
            self._logger.debug("create_keys_until path=%s index=%d count=%d",
                derivation_path, desired_index, required_count)
            return self.create_keys(required_count, derivation_path, script_type)

    def create_keys(self, count: int, derivation_path: Sequence[int],
            script_type: Optional[ScriptType]=None) -> List[KeyInstanceRow]:
        key_allocations = self.allocate_keys(count, derivation_path)
        return self.create_allocated_keys(key_allocations, script_type)

    def create_allocated_keys(self, key_allocations: List[DeterministicKeyAllocation],
            script_type: Optional[ScriptType]=None) -> List[KeyInstanceRow]:
        if not len(key_allocations):
            return []
        if script_type is None:
            script_type = self.get_default_script_type()

        keyinstances = [ KeyInstanceRow(-1, self.get_id(), ka.masterkey_id,
            ka.derivation_type, self.create_derivation_data(ka), script_type,
            KeyInstanceFlag.IS_ACTIVE, None) for ka in key_allocations ]
        rows = self._wallet.create_keyinstances(self._id, keyinstances)
        for i, row in enumerate(rows):
            self._keyinstances[row.keyinstance_id] = row
            self._keypath[row.keyinstance_id] = key_allocations[i].derivation_path
        self._add_activated_keys(rows)
        return rows

    def create_derivation_data(self, key_allocation: DeterministicKeyAllocation) -> str:
        assert key_allocation.derivation_type == DerivationType.BIP32_SUBPATH
        return json.dumps({ "subpath": key_allocation.derivation_path }).encode()

    def set_key_active(self, key_id: int, is_active: bool) -> bool:
        if is_active:
            raise NotImplementedError("TODO(rt12) BACKLOG")
            # TODO(rt12) BACKLOG If the key is already active, then flag it as user active.

        if key_id not in self._keyinstances:
            return False
        # Persist the removal of the active state from the key.
        self._wallet.update_keyinstance_flags([
            (self._keyinstances[key_id].flags & ~KeyInstanceFlag.ACTIVE_MASK, key_id) ])
        # Flush the associated UTXO state and account state from memory.
        for utxo in self.get_key_utxos(key_id):
            del self._utxos[utxo.key()]
        self._unload_keys([ key_id ])
        return True

    def _unload_keys(self, key_ids: List[int]) -> None:
        for key_id in key_ids:
            del self._keyinstances[key_id]

    def get_key_utxos(self, key_id: int) -> List[UTXO]:
        return [ u for u in self._utxos if u.keyinstance_id == key_id ]

    def get_script_type_for_id(self, key_id: int) -> ScriptType:
        keyinstance = self._keyinstances[key_id]
        return (keyinstance.script_type if keyinstance.script_type != ScriptType.NONE else
            self.get_default_script_type())

    def get_script_template_for_id(self, keyinstance_id: int,
            script_type: Optional[ScriptType]=None) -> Any:
        raise NotImplementedError

    def get_valid_script_types(self) -> Sequence[ScriptType]:
        raise NotImplementedError

    def get_possible_scripts_for_id(self, keyinstance_id: int) -> List[Script]:
        raise NotImplementedError

    def get_script_for_id(self, keyinstance_id: int,
            script_type: Optional[ScriptType]=None) -> Script:
        script_template = self.get_script_template_for_id(keyinstance_id, script_type)
        return script_template.to_script()

    def missing_transactions(self) -> List[bytes]:
        '''Returns a set of tx_hashes.'''
        return self._wallet._transaction_cache.get_unsynced_hashes()

    def unverified_transactions(self):
        '''Returns a map of tx_hash to tx_height.'''
        results = self._wallet._transaction_cache.get_unverified_entries(
            self._wallet.get_local_height())
        self._logger.debug("unverified_transactions: %s",
            [(hash_to_hex_str(r[0]), r[1]) for r in results])
        return { t[0]: t[1].metadata.height for t in results }

    async def synchronize_loop(self):
        while True:
            await self._synchronize()
            await self._synchronize_event.wait()

    async def _trigger_synchronization(self):
        if self._network:
            self._synchronize_event.set()
        else:
            await self._synchronize()

    async def _synchronize_wallet(self) -> None:
        '''Class-specific synchronization (generation of missing addresses).'''
        pass

    async def _synchronize(self):
        self._logger.debug('synchronizing...')
        self._synchronize_event.clear()
        self._synchronized_event.clear()
        await self._synchronize_wallet()
        self._synchronized_event.set()
        self._logger.debug('synchronized.')
        if self._network:
            self._network.trigger_callback('updated')

    def synchronize(self):
        app_state.async_.spawn_and_wait(self._trigger_synchronization)
        app_state.async_.spawn_and_wait(self._synchronized_event.wait)

    def is_synchronized(self):
        return (self._synchronized_event.is_set() and
                not (self._network and self.missing_transactions()))

    def __str__(self):
        return self.name()

    def get_keystore(self) -> Optional[KeyStore]:
        if self._row.default_masterkey_id is not None:
            return self._wallet.get_keystore(self._row.default_masterkey_id)
        return self._default_keystore

    def get_keystores(self) -> List[KeyStore]:
        keystore = self.get_keystore()
        return [ keystore ] if keystore is not None else []

    def get_master_public_key(self):
        return None

    def have_transaction_data(self, tx_hash: bytes) -> bool:
        return self._wallet._transaction_cache.have_transaction_data(tx_hash)

    def get_transaction(self, tx_hash: bytes, flags: Optional[int]=None) -> Optional[Transaction]:
        return self._wallet._transaction_cache.get_transaction(tx_hash, flags)

    def get_transaction_entry(self, tx_hash: bytes, flags: Optional[int]=None,
            mask: Optional[int]=None) -> Optional[TransactionCacheEntry]:
        return self._wallet._transaction_cache.get_entry(tx_hash, flags, mask)

    def get_transaction_metadata(self, tx_hash: bytes) -> Optional[TxData]:
        return self._wallet._transaction_cache.get_metadata(tx_hash)

    def get_transaction_metadatas(self, flags: Optional[int]=None, mask: Optional[int]=None,
            tx_hashes: Optional[Iterable[bytes]]=None,
            require_all: bool=True) -> List[Tuple[str, TxData]]:
        return self._wallet._transaction_cache.get_metadatas(flags, mask, tx_hashes, require_all)

    def has_received_transaction(self, tx_hash: bytes) -> bool:
        # At this time, this means received over the P2P network.
        flags = self._wallet._transaction_cache.get_flags(tx_hash)
        return flags is not None and (flags & (TxFlags.StateCleared | TxFlags.StateSettled)) != 0

    def display_name(self) -> str:
        return self._row.account_name if self._row.account_name else _("unnamed account")

    def name(self) -> str:
        parent_name = self._wallet.name()
        return f"{parent_name}/{self._id}"

    def _load_sync_state(self) -> None:
        self._sync_state = SyncState()

        with TransactionDeltaTable(self._wallet._db_context) as table:
            rows = table.read_history(self._id)

        key_history: Dict[int, List[Tuple[str, int]]] = {}
        positions: Dict[Tuple[str, int], int] = {}
        for tx_hash, _value_delta, keyinstance_id in rows:
            metadata = self.get_transaction_metadata(tx_hash)
            if metadata.height is not None:
                tx_id = hash_to_hex_str(tx_hash)
                positions[(tx_id, keyinstance_id)] = metadata.position
                entries = key_history.setdefault(keyinstance_id, [])
                entries.append((tx_id, metadata.height))

        for keyinstance_id, entries in key_history.items():
            entries.sort(key=lambda v: (v[1], positions.get((v[0], keyinstance_id))))
            self._sync_state.set_key_history(keyinstance_id, entries)

    def _load_keys(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        pass

    def _load_txos(self, output_rows: List[TransactionOutputRow]) -> None:
        self._stxos.clear()
        self._utxos.clear()
        self._frozen_coins = set([])

        for row in output_rows:
            txo_key = row.tx_hash, row.tx_index
            if row.flags & TransactionOutputFlag.IS_SPENT:
                self._stxos[txo_key] = row.keyinstance_id
            else:
                keyinstance = self._keyinstances[row.keyinstance_id]
                script_template = self.get_script_template_for_id(row.keyinstance_id)
                metadata = self._wallet._transaction_cache.get_metadata(row.tx_hash)
                flags = row.flags
                if metadata.position==0:
                    flags |= TransactionOutputFlag.IS_COINBASE
                self.register_utxo(row.tx_hash, row.tx_index, row.value, metadata.height, flags,
                    keyinstance, script_template)

    def register_utxo(self, tx_hash: bytes, output_index: int, value: int, height: int,
            flags: TransactionOutputFlag, keyinstance: KeyInstanceRow,
            script_template: ScriptTemplate) -> None:
        is_coinbase = (flags & TransactionOutputFlag.IS_COINBASE) != 0
        utxo_key = (tx_hash, output_index)
        self._utxos[utxo_key] = UTXO(
            value=value,
            script_pubkey=script_template.to_script(),
            script_type=keyinstance.script_type,
            tx_hash=tx_hash,
            out_index=output_index,
            height=height,
            keyinstance_id=keyinstance.keyinstance_id,
            flags=flags,
            address=script_template if isinstance(script_template, Address) else None,
            is_coinbase=is_coinbase)
        if flags & TransactionOutputFlag.IS_FROZEN:
            self._frozen_coins.add(utxo_key)

    # Should be called with the transaction lock.
    def create_transaction_output(self, tx_hash: bytes, output_index: int, value: int,
            flags: TransactionOutputFlag, keyinstance: KeyInstanceRow,
            script_template: ScriptTemplate):
        metadata = self._wallet._transaction_cache.get_metadata(tx_hash)
        if metadata.position == 0:
            flags |= TransactionOutputFlag.IS_COINBASE
        if flags & TransactionOutputFlag.IS_SPENT:
            self._stxos[(tx_hash, output_index)] = keyinstance.keyinstance_id
        else:
            self.register_utxo(tx_hash, output_index, value, metadata.height, flags, keyinstance,
                script_template)

        self._wallet.create_transactionoutputs(self._id, [ TransactionOutputRow(tx_hash,
            output_index, value, keyinstance.keyinstance_id, flags) ])

    def _load_payment_requests(self) -> None:
        self._payment_requests.clear()

        with PaymentRequestTable(self._wallet._db_context) as table:
            rows = table.read(self._id)
        for row in rows:
            self._payment_requests[row.paymentrequest_id] = row

    def get_payment_request_for_keyinstance_id(self,
            keyinstance_id: int) -> Optional[PaymentRequestRow]:
        for row in self._payment_requests.values():
            if row.keyinstance_id == keyinstance_id:
                return row
        return None

    def create_payment_request(self, keyinstance_id: int, state: PaymentState, value: Optional[int],
            expiration: Optional[int], description: Optional[str]) -> PaymentRequestRow:
        row = self._wallet.create_payment_requests([ PaymentRequestRow(-1,
            keyinstance_id, state, value, expiration, description, int(time.time())) ])[0]
        key = self._keyinstances[keyinstance_id]
        self._keyinstances[keyinstance_id] = KeyInstanceRow(keyinstance_id, key.account_id,
            key.masterkey_id, key.derivation_type, key.derivation_data, key.script_type,
            key.flags | KeyInstanceFlag.IS_PAYMENT_REQUEST, key.description)
        new_key = self._keyinstances[keyinstance_id]
        self._wallet.update_keyinstance_flags([ (new_key.flags, keyinstance_id) ])
        self._payment_requests[row.paymentrequest_id] = row
        self._network.trigger_callback('on_keys_updated', self._wallet.get_storage_path(),
            self._id, [ new_key ])
        return row

    def update_payment_request(self, paymentrequest_id: int, state: PaymentState,
            value: Optional[int], expiration: Optional[int],
            description: Optional[str]) -> PaymentRequestRow:
        req = self._payment_requests[paymentrequest_id]
        new_req = PaymentRequestRow(paymentrequest_id, req.keyinstance_id, state,
            value, expiration, description, req.date_created)
        self._wallet.update_payment_requests([ new_req ])
        self._payment_requests[paymentrequest_id] = new_req
        return new_req

    def delete_payment_request(self, pr_id: int):
        if pr_id in self._payment_requests:
            pr = self._payment_requests.pop(pr_id)
            with PaymentRequestTable(self._wallet._db_context) as table:
                table.delete([ (pr_id,) ])
            key = self._keyinstances[pr.keyinstance_id]
            self._keyinstances[pr.keyinstance_id] = KeyInstanceRow(key.keyinstance_id,
                key.account_id, key.masterkey_id, key.derivation_type, key.derivation_data,
                key.script_type, key.flags & ~KeyInstanceFlag.IS_PAYMENT_REQUEST, key.description)
            new_key = self._keyinstances[pr.keyinstance_id]
            self._wallet.update_keyinstance_flags([ (new_key.flags, pr.keyinstance_id) ])
            self._network.trigger_callback('on_keys_updated', self._wallet.get_storage_path(),
                self._id, [ new_key ])
            return True
        return False

    def get_payment_request(self, pr_id: int) -> Optional[PaymentRequestRow]:
        return self._payment_requests.get(pr_id)

    def is_deterministic(self):
        # Not all wallets have a keystore, like imported address for instance.
        keystore = self.get_keystore()
        return keystore and keystore.is_deterministic()

    def is_hardware_wallet(self) -> bool:
        return any([ isinstance(k, Hardware_KeyStore) for k in self.get_keystores() ])

    def get_label_data(self) -> Any:
        # Create exported data structure for account labels/descriptions.
        def _derivation_path(key_id: int) -> str:
            derivation = self._keypath.get(key_id)
            return None if derivation is None else compose_chain_string(derivation)
        label_entries = [ [ _derivation_path(key.keyinstance_id),  key.description ]
            for key in self._keyinstances.values() if key.description is not None ]

        with TransactionDeltaTable(self._wallet._db_context) as table:
            rows = table.read_descriptions(self._id)
        transaction_entries = [ [ hash_to_hex_str(tx_hash), description ]
            for tx_hash, description in rows ]

        data = {}
        if len(transaction_entries):
            data["transactions"] = transaction_entries
        if len(label_entries):
            data["keys"] = {
                "account_fingerprint": self.get_fingerprint().hex(),
                "entries": label_entries,
            }
        return data

    def get_transaction_label(self, tx_hash: bytes) -> str:
        label = self._wallet._transaction_descriptions.get(tx_hash)
        return "" if label is None else label

    def set_transaction_label(self, tx_hash: bytes, text: Optional[str]) -> None:
        text = None if text is None or text.strip() == "" else text.strip()
        label = self._wallet._transaction_descriptions.get(tx_hash)
        if label == text:
            return
        self._wallet.update_transaction_descriptions([ (text, tx_hash) ])
        app_state.app.on_transaction_label_change(self, tx_hash, text)

    def get_keyinstance_label(self, key_id: int) -> str:
        return self._keyinstances[key_id].description or ""

    def set_keyinstance_label(self, key_id: int, text: Optional[str]) -> None:
        text = None if text is None or text.strip() == "" else text.strip()
        key = self._keyinstances[key_id]
        if key.description == text:
            return
        self._keyinstances[key_id] = KeyInstanceRow(key.keyinstance_id, key.account_id,
            key.masterkey_id, key.derivation_type, key.derivation_data, key.script_type,
            key.flags, text)
        self._wallet.update_keyinstance_descriptions([ (text, key_id) ])
        app_state.app.on_keyinstance_label_change(self, key_id, text)

    def get_default_script_type(self) -> ScriptType:
        return ScriptType(self._row.default_script_type)

    def set_default_script_type(self, script_type: ScriptType) -> None:
        if script_type == self._row.default_script_type:
            return
        self._wallet.update_account_script_types([ (script_type, self._row.account_id) ])
        self._row = AccountRow(self._row.account_id, self._row.default_masterkey_id,
            script_type, self._row.account_name)

    def get_derivation_path(self, keyinstance_id: int) -> Optional[Sequence[int]]:
        return self._keypath.get(keyinstance_id)

    def get_keyinstance_id_for_derivation(self, derivation: Sequence[int]) -> Optional[int]:
        for keyinstance_id, keypath in self._keypath.items():
            if keypath == derivation:
                return keyinstance_id

    def get_threshold(self, script_type: ScriptType) -> int:
        assert script_type in (ScriptType.P2PKH, ScriptType.P2PK), \
            f"get_threshold got bad script type {script_type}"
        return 1

    def export_private_key(self, keyinstance_id: int, password: str) -> Optional[str]:
        """ extended WIF format """
        if self.is_watching_only():
            return None
        keyinstance = self._keyinstances[keyinstance_id]
        keystore = self._wallet.get_keystore(keyinstance.masterkey_id)
        derivation_path = self.get_derivation_path(keyinstance_id)
        secret, compressed = keystore.get_private_key(derivation_path, password)
        return PrivateKey(secret).to_WIF(compressed=compressed, coin=Net.COIN)

    def add_verified_tx(self, tx_hash: bytes, height: int, timestamp: int, position: int,
            proof_position: int, proof_branch: Sequence[bytes]) -> None:
        tx_id = hash_to_hex_str(tx_hash)
        entry = self._wallet._transaction_cache.get_entry(tx_hash, TxFlags.StateCleared) # HasHeight

        # Ensure we are not verifying transactions multiple times.
        if entry is None:
            # We have proof now so regardless what TxState is, we can 'upgrade' it to StateSettled.
            # This rests on the commitment that any of the following four tx States *will*
            # Have tx bytedata i.e. "HasByteData" flag is set.
            entry = self._wallet._transaction_cache.get_entry(tx_hash,
                flags=TxFlags.STATE_UNCLEARED_MASK)
            if entry.flags & TxFlags.HasByteData != 0:
                self._logger.debug("Fast_tracking entry to StateSettled: %r", entry)
            else:
                self._logger.error("Transaction bytedata absent for %s %r", tx_id, entry)
                return

        # We only update a subset.
        flags = TxFlags.HasHeight | TxFlags.HasPosition
        data = TxData(height=height, position=position)
        self._wallet._transaction_cache.update(
            [ (tx_hash, data, None, flags | TxFlags.StateSettled) ])

        proof = TxProof(proof_position, proof_branch)
        self._wallet._transaction_cache.update_proof(tx_hash, proof)

        height, conf, _timestamp = self.get_tx_height(tx_hash)
        self._logger.debug("add_verified_tx %d %d %d", height, conf, timestamp)
        self._network.trigger_callback('verified', self._wallet.get_storage_path(),
            tx_hash, height, conf, timestamp)

    def undo_verifications(self, above_height):
        '''Used by the verifier when a reorg has happened'''
        with self.lock:
            reorg_count = self._wallet._transaction_cache.apply_reorg(above_height)
            self._logger.info(f'removing verification of {reorg_count} transactions')

    def get_tx_height(self, tx_hash: bytes) -> Tuple[int, int, Union[int, bool]]:
        """ return the height and timestamp of a verified transaction. """
        with self.lock:
            metadata = self._wallet._transaction_cache.get_metadata(tx_hash)
            assert metadata.height is not None, f"tx {tx_hash} has no height"
            timestamp = None
            if metadata.height > 0:
                chain = app_state.headers.longest_chain()
                try:
                    header = app_state.headers.header_at_height(chain, metadata.height)
                    timestamp = header.timestamp
                except MissingHeader:
                    pass
            if timestamp is not None:
                conf = max(self._wallet.get_local_height() - metadata.height + 1, 0)
                return metadata.height, conf, timestamp
            else:
                return metadata.height, 0, False

    def get_transaction_delta(self, tx_hash: bytes) -> Optional[int]:
        assert type(tx_hash) is bytes, f"tx_hash is {type(tx_hash)}, expected bytes"
        with TransactionDeltaTable(self._wallet._db_context) as table:
            return table.read_transaction_value(tx_hash)

    # Should be called with the transaction lock.
    def set_utxo_spent(self, tx_hash: bytes, output_index: int) -> None:
        txo_key = (tx_hash, output_index)
        utxo = self._utxos.pop(txo_key)
        retained_flags = utxo.flags & TransactionOutputFlag.IS_COINBASE
        self._wallet.update_transactionoutput_flags(
            [ (retained_flags | TransactionOutputFlag.IS_SPENT, tx_hash, output_index)  ])
        self._stxos[txo_key] = utxo.keyinstance_id

    def is_frozen_utxo(self, utxo):
        return utxo.key() in self._frozen_coins

    def get_stxo(self, tx_hash: bytes, output_index: int) -> Optional[int]:
        return self._stxos.get((tx_hash, output_index), None)

    def get_utxo(self, tx_hash: bytes, output_index: int) -> Optional[TransactionOutputRow]:
        return self._utxos.get((tx_hash, output_index), None)

    def get_spendable_coins(self, domain: Optional[List[int]], config, isInvoice = False):
        confirmed_only = config.get('confirmed_only', False)
        if isInvoice:
            confirmed_only = True
        utxos = self.get_utxos(exclude_frozen=True, mature=True, confirmed_only=confirmed_only)
        if domain is not None:
            return [ utxo for utxo in utxos if utxo.keyinstance_id in domain ]
        return utxos

    def get_utxos(self, exclude_frozen=False, mature=False, confirmed_only=False):
        '''Note exclude_frozen=True checks for coin-level frozen status. '''
        mempool_height = self._wallet.get_local_height() + 1
        def is_spendable_utxo(utxo):
            if exclude_frozen and self.is_frozen_utxo(utxo):
                return False
            if confirmed_only and utxo.height <= 0:
                return False
            # A coin is spendable at height (utxo.height + COINBASE_MATURITY)
            if mature and utxo.is_coinbase and mempool_height < utxo.height + COINBASE_MATURITY:
                return False
            return True

        return [ utxo for utxo in self._utxos.values() if is_spendable_utxo(utxo)]

    def existing_active_keys(self) -> List[int]:
        with self._activated_keys_lock:
            self._activated_keys = []
            return [ key_id for (key_id, key) in self._keyinstances.items()
                if key.flags & KeyInstanceFlag.IS_ACTIVE ]

    def get_frozen_balance(self) -> Tuple[int, int, int]:
        return self.get_balance(self._frozen_coins)

    def get_balance(self, domain=None, exclude_frozen_coins: bool=False) -> Tuple[int, int, int]:
        if domain is None:
            domain = set(self._utxos.keys())
        c = u = x = 0
        for k in domain:
            if exclude_frozen_coins and k in self._frozen_coins:
                continue
            o = self._utxos[k]
            if o.is_coinbase and o.height + COINBASE_MATURITY > self._wallet.get_local_height():
                x += o.value
            elif o.height > 0:
                c += o.value
            else:
                u += o.value
        return c, u, x

    def add_transaction(self, tx_hash: bytes, tx: Transaction, flag: TxFlags) -> None:
        def _completion_callback(exc_value: Any) -> None:
            if exc_value is not None:
                raise exc_value # pylint: disable=raising-bad-type

            self._network.trigger_callback('transaction_added', self._wallet.get_storage_path(),
                self._id, tx_hash)

        with self.transaction_lock:
            self._logger.debug("adding tx data %s (flags: %s)", hash_to_hex_str(tx_hash),
                TxFlags.to_repr(flag))
            self._wallet._transaction_cache.add_transaction(tx, flag, _completion_callback)
            self._process_key_usage(tx_hash, tx)

    def set_transaction_state(self, tx_hash: bytes, flags: TxFlags) -> bool:
        """ raises UnknownTransactionException """
        with self.transaction_lock:
            if not self._wallet._transaction_cache.is_cached(tx_hash):
                raise UnknownTransactionException(f"tx {tx_hash} unknown")
            existing_flags = self._wallet._transaction_cache.get_cached_entry(tx_hash).flags
            updated_flags = self._wallet._transaction_cache.update_flags(tx_hash, flags)
        self._network.trigger_callback('transaction_state_change',
            self._wallet.get_storage_path(), self._id, tx_hash, existing_flags, updated_flags)

    def process_key_usage(self, tx_hash: bytes, tx: Transaction) -> None:
        with self.transaction_lock:
            self._process_key_usage(tx_hash, tx)

    def _process_key_usage(self, tx_hash: bytes, tx: Transaction) -> Set[int]:
        tx_id = hash_to_hex_str(tx_hash)
        key_ids = self._sync_state.get_transaction_key_ids(tx_id)
        key_matches = [(self.get_keyinstance(key_id),
            self.get_script_template_for_id(key_id)) for key_id in key_ids]

        tx_deltas: Dict[Tuple[bytes, int], int] = defaultdict(int)
        new_txos: List[Tuple[bytes, int, int, TransactionOutputFlag, KeyInstanceRow,
            ScriptTemplate]] = []
        for output_index, output in enumerate(tx.outputs):
            utxo = self.get_utxo(tx_hash, output_index)
            if utxo is not None:
                continue
            keyinstance_id = self.get_stxo(tx_hash, output_index)
            if keyinstance_id is not None:
                continue

            for keyinstance, script_template in key_matches:
                if script_template.to_script() == output.script_pubkey:
                    break
            else:
                continue

            # Search the known candidates to see if we already have this txo's spending input.
            txo_flags = TransactionOutputFlag.NONE
            for spend_tx_id, _height in self._sync_state.get_key_history(
                    keyinstance.keyinstance_id):
                if spend_tx_id == tx_id:
                    continue
                spend_tx_hash = hex_str_to_hash(spend_tx_id)
                spend_tx = self._wallet._transaction_cache.get_transaction(spend_tx_hash)
                if spend_tx is None:
                    continue
                for spend_txin in spend_tx.inputs:
                    if spend_txin.prev_hash == tx_hash and spend_txin.prev_idx == output_index:
                        break
                else:
                    continue

                tx_deltas[(spend_tx_hash, keyinstance.keyinstance_id)] -= output.value
                txo_flags = TransactionOutputFlag.IS_SPENT
                break

            # TODO(rt12) BACKLOG batch create the outputs.
            self.create_transaction_output(tx_hash, output_index, output.value,
                txo_flags, keyinstance, script_template)
            tx_deltas[(tx_hash, keyinstance.keyinstance_id)] += output.value

        for input_index, input in enumerate(tx.inputs):
            keyinstance_id = self.get_stxo(input.prev_hash, input.prev_idx)
            if keyinstance_id is not None:
                continue
            utxo = self.get_utxo(input.prev_hash, input.prev_idx)
            if utxo is None:
                continue

            self.set_utxo_spent(input.prev_hash, input.prev_idx)
            tx_deltas[(tx_hash, utxo.keyinstance_id)] -= utxo.value

        if len(tx_deltas):
            self._wallet.create_or_update_transactiondelta_relative(
                [ TransactionDeltaRow(k[0], k[1], v) for k, v in tx_deltas.items() ])

        if len(tx_deltas):
            affected_keys = [self._keyinstances[k] for (_x, k) in tx_deltas.keys()]
            self._network.trigger_callback('on_keys_updated', self._wallet.get_storage_path(),
                self._id, affected_keys)

    def delete_transaction(self, tx_hash: bytes) -> None:
        def _completion_callback(exc_value: Any) -> None:
            if exc_value is not None:
                raise exc_value # pylint: disable=raising-bad-type

            self._network.trigger_callback('transaction_deleted', self._wallet.get_storage_path(),
                self._id, tx_hash)

        tx_id = hash_to_hex_str(tx_hash)
        with self.transaction_lock:
            self._logger.debug("removing tx from history %s", tx_id)
            self._remove_transaction(tx_hash)
            self._logger.debug("deleting tx from cache and datastore: %s", tx_id)
            self._wallet._transaction_cache.delete(tx_hash, _completion_callback)

    def _remove_transaction(self, tx_hash: bytes) -> None:
        with self.transaction_lock:
            self._logger.debug("removing transaction %s", hash_to_hex_str(tx_hash))

            tx = self._wallet._transaction_cache.get_transaction(tx_hash)
            # tx_deltas: Dict[Tuple[bytes, int], int] = defaultdict(int)
            txout_flags: List[Tuple[TransactionOutputFlag, bytes, int]] = []

            utxos: List[UTXO] = []
            for output_index, txout in enumerate(tx.outputs):
                txo_key = tx_hash, output_index
                # Check if any outputs of this transaction have been spent already.
                if txo_key in self._stxos:
                    raise Exception("Cannot remove as spent by child")
                if txo_key in self._utxos:
                    utxo = self._utxos[txo_key]
                    utxos.append(utxo)

            # TODO(rt12) BACKLOG only read the outputs we are recreating.
            with TransactionOutputTable(self._wallet._db_context) as table:
                output_rows = table.read()

            for input_index, txin in enumerate(tx.inputs):
                txo_key = (txin.prev_hash, txin.prev_idx)
                if txo_key in self._stxos:
                    spent_keyinstance_id = self._stxos.pop(txo_key)
                    # This may incur database read latency, but deletion should be uncommon.
                    spent_metadata = self._wallet._transaction_cache.get_metadata(txin.prev_hash)
                    spent_tx = self._wallet._transaction_cache.get_transaction(txin.prev_hash)
                    spent_value = spent_tx.outputs[txin.prev_idx].value
                    # Need to set the TXO to non-spent.s
                    # tx_deltas[(txin.prev_hash, spent_keyinstance_id)] = spent_value

                    # TODO(rt12) BACKLOG lookup the existing flags less painfully.
                    txo_flags = [ row for row in output_rows if row.tx_hash == txin.prev_hash
                        and row.tx_index == txin.prev_idx ][0].flags
                    txo_flags &= ~TransactionOutputFlag.IS_SPENT
                    spent_keyinstance = self._keyinstances[spent_keyinstance_id]
                    script_template = self.get_script_template_for_id(spent_keyinstance_id,
                        spent_keyinstance.script_type)
                    self.register_utxo(txin.prev_hash, txin.prev_idx, spent_value,
                        spent_metadata.height, txo_flags, spent_keyinstance, script_template)
                    txout_flags.append((txo_flags, *txo_key))

            key_script_types: List[Tuple[ScriptType, int]] = []
            for utxo in utxos:
                key_script_types.append((ScriptType.NONE, utxo.keyinstance_id))
                # Update the cached key to be unused.
                key = self._keyinstances[utxo.keyinstance_id]
                key = KeyInstanceRow(key.keyinstance_id, key.account_id, key.masterkey_id,
                    key.derivation_type, key.derivation_data, ScriptType.NONE, key.flags,
                    key.description)
                self._keyinstances[utxo.keyinstance_id] = key
                # Expunge the UTXO.
                del self._utxos[(utxo.tx_hash, utxo.out_index)]

            if len(txout_flags):
                self._wallet.update_transactionoutput_flags(txout_flags)

            if len(key_script_types):
                self._wallet.update_keyinstance_script_types(key_script_types)

            # if len(tx_deltas):
            #     self._wallet.create_or_update_transactiondelta_relative(
            #         [ TransactionDeltaRow(k[0], k[1], v) for k, v in tx_deltas.items() ])

    def get_key_history(self, keyinstance_id: int,
            script_type: ScriptType) -> List[Tuple[str, int]]:
        keyinstance = self._keyinstances[keyinstance_id]
        if keyinstance.script_type in (ScriptType.NONE, script_type):
            return self._sync_state.get_key_history(keyinstance_id)
        # This is normal for multi-script monitoring key registrations (fresh keys).
        # self._logger.warning("Received key history request from server for key that already "
        #     f"has script type {keyinstance.script_type}, where server history relates "
        #     f"to script type {script_type}. ElectrumSV has never handled this in the "
        #     f"past, and will ignore it for now. Please report it.")
        return []

    async def set_key_history(self, keyinstance_id: int, script_type: ScriptType,
            hist: List[Tuple[str, int]], tx_fees: Dict[str, int]) -> None:
        with self.lock:
            self._logger.debug("set_key_history %s %s", keyinstance_id, tx_fees)
            key = self._keyinstances[keyinstance_id]
            if key.script_type == ScriptType.NONE:
                # This is the first use of the allocated key and we update the key to reflect it.
                key = KeyInstanceRow(key.keyinstance_id, key.account_id, key.masterkey_id,
                    key.derivation_type, key.derivation_data, script_type, key.flags,
                    key.description)
                self._keyinstances[keyinstance_id] = key
                self._wallet.update_keyinstance_script_types([ (script_type, keyinstance_id) ])
            elif key.script_type != script_type:
                self._logger.error("Received key history from server for key that already "
                    f"has script type {key.script_type}, where server history relates "
                    f"to script type {script_type}. ElectrumSV has never handled this in the "
                    f"past, and will ignore it for now. Please report it. History={hist}")
                return

            # The history is in immediately usable order. Transactions are listed in ascending
            # block height (height > 0), followed by the unconfirmed (height == 0) and then
            # those with unconfirmed parents (height < 0). [ (tx_hash, tx_height), ... ]
            self._sync_state.set_key_history(keyinstance_id, hist)

            updates = []
            unique_tx_hashes: Set[bytes] = set([])
            for tx_id, tx_height in hist:
                tx_fee = tx_fees.get(tx_id, None)
                data = TxData(height=tx_height, fee=tx_fee)
                # The metadata flags indicate to the update call which TxData fields should
                # be updated. Fields that are not flagged in the existing cache record, should
                # remain as they are.
                flags = TxFlags.HasHeight
                if tx_fee is not None:
                    flags |= TxFlags.HasFee
                tx_hash = hex_str_to_hash(tx_id)
                updates.append((tx_hash, data, None, flags))
                unique_tx_hashes.add(tx_hash)
            self._wallet._transaction_cache.update_or_add(updates)

            # If a transaction has bytedata at this point, but no state, then it is likely that
            # we added it locally and broadcast it ourselves. Transactions without bytedata cannot
            # have a state.
            for tx_hash in unique_tx_hashes:
                entry = self._wallet._transaction_cache.get_cached_entry(tx_hash)
                if entry.flags & (TxFlags.HasByteData|TxFlags.StateCleared|TxFlags.StateSettled) \
                        == TxFlags.HasByteData:
                    self.set_transaction_state(tx_hash, TxFlags.StateCleared | TxFlags.HasByteData)

            for tx_id, tx_height in hist:
                tx_hash = hex_str_to_hash(tx_id)
                entry = self._wallet._transaction_cache.get_cached_entry(tx_hash)
                if entry.flags & TxFlags.HasByteData == TxFlags.HasByteData:
                    tx = self._wallet._transaction_cache.get_transaction(tx_hash)
                    self.process_key_usage(tx_hash, tx)

        self.txs_changed_event.set()
        await self._trigger_synchronization()

    def get_history(self, domain: Optional[Set[int]]=None) -> List[Tuple[HistoryLine, int]]:
        history_raw: List[HistoryLine] = []
        with TransactionDeltaTable(self._wallet._db_context) as table:
            rows = table.read_history(self._id)
        if domain is not None:
            rows = [ r for r in rows if r[2] in domain ]
        tx_sums: Dict[bytes, int] = defaultdict(int)
        for row in rows:
            tx_sums[row[0]] += row[1]

        for tx_hash, value_delta in tx_sums.items():
            metadata = self._wallet._transaction_cache.get_metadata(tx_hash)
            # Signed but not cleared.
            if metadata.height is None:
                continue
            height, position = metadata.height, metadata.position
            if position is not None:
                sort_key = height, position
            elif height is not None:
                sort_key = (height, 0) if height > 0 else ((1e9 - height), 0)
            else:
                sort_key = (1e9+1, 0)
            history_raw.append(HistoryLine(sort_key, tx_hash, height, value_delta))

        history_raw.sort(key = lambda v: v.sort_key)

        history: List[Tuple[HistoryLine, int]] = []
        balance = 0
        for history_line in history_raw:
            balance += history_line.value_delta
            history.append((history_line, balance))

        history.reverse()

        return history

    def export_history(self, from_timestamp=None, to_timestamp=None,
                       show_addresses=False):
        h = self.get_history()
        fx = app_state.fx
        out = []
        for tx_hash, height, conf, timestamp, value, balance in h:
            if from_timestamp and timestamp < from_timestamp:
                continue
            if to_timestamp and timestamp >= to_timestamp:
                continue
            item = {
                'txid':tx_hash,
                'height':height,
                'confirmations':conf,
                'timestamp':timestamp,
                'value': format_satoshis(value, is_diff=True) if value is not None else '--',
                'balance': format_satoshis(balance)
            }
            if item['height']>0:
                if timestamp is not None:
                    date_str = format_time(timestamp, _("unknown"))
                else:
                    date_str = _("unverified")
            else:
                date_str = _("unconfirmed")
            item['date'] = date_str
            item['label'] = self.get_transaction_label(tx_hash)
            # if show_addresses:
            #     tx = self.get_transaction(tx_hash)
            #     input_addresses = []
            #     output_addresses = []
            #     for txin in tx.inputs:
            #         if txin.is_coinbase():
            #             continue
            #         addr = txin.address
            #         if addr is None:
            #             continue
            #         input_addresses.append(addr.to_string())
            #     for tx_output in tx.outputs:
            #         text, kind = tx_output_to_display_text(tx_output)
            #         output_addresses.append(text)
            #     item['input_addresses'] = input_addresses
            #     item['output_addresses'] = output_addresses
            if fx:
                date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                item['fiat_value'] = fx.historical_value_str(value, date)
                item['fiat_balance'] = fx.historical_value_str(balance, date)
            out.append(item)
        return out

    def dust_threshold(self):
        return dust_threshold(self._network)

    def make_unsigned_transaction(self, utxos: List[UTXO], outputs: List[XTxOutput],
            config: SimpleConfig, fixed_fee: Optional[int]=None) -> Transaction:
        # check outputs
        all_index = None
        for n, output in enumerate(outputs):
            if output.value is all:
                if all_index is not None:
                    raise ValueError("More than one output set to spend max")
                all_index = n

        # Avoid index-out-of-range with inputs[0] below
        if not utxos:
            raise NotEnoughFunds()

        if fixed_fee is None and config.fee_per_kb() is None:
            raise Exception('Dynamic fee estimates not available')

        fee_estimator = config.estimate_fee if fixed_fee is None else lambda size: fixed_fee
        inputs = [utxo.to_tx_input(self) for utxo in utxos]
        if all_index is None:
            # Let the coin chooser select the coins to spend
            # TODO(rt12) BACKLOG Hardware wallets should use 1 change at most. Make sure the
            # corner case of the active multisig cosigning wallet being hardware is covered.
            max_change = self.max_change_outputs if self._wallet.get_multiple_change() else 1
            if self._wallet.get_use_change() and self.is_deterministic():
                change_keyinstances = self.get_fresh_keys(CHANGE_SUBPATH, max_change)
                change_outs = []
                for keyinstance in change_keyinstances:
                    script_type = self.get_script_type_for_id(keyinstance.keyinstance_id)
                    change_outs.append(XTxOutput(None,
                        self.get_script_for_id(keyinstance.keyinstance_id, script_type),
                        script_type,
                        self.get_xpubkeys_for_id(keyinstance.keyinstance_id)))
            else:
                change_outs = [ XTxOutput(None, utxos[0].script_pubkey, inputs[0].script_type,
                    inputs[0].x_pubkeys) ]
            coin_chooser = coinchooser.CoinChooserPrivacy()
            tx = coin_chooser.make_tx(inputs, outputs, change_outs, fee_estimator,
                self.dust_threshold())
        else:
            sendable = sum(txin.value for txin in inputs)
            outputs[all_index].value = 0
            tx = Transaction.from_io(inputs, outputs)
            fee = fee_estimator(tx.estimated_size())
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

    def set_frozen_coin_state(self, utxos: List[UTXO], freeze: bool) -> None:
        '''Set frozen state of the COINS to FREEZE, True or False.  Note that coin-level freezing
        is set/unset independent of address-level freezing, however both must be satisfied for
        a coin to be defined as spendable.'''
        update_entries = []
        if freeze:
            self._frozen_coins.update(utxo.key() for utxo in utxos)
            update_entries.extend(
                (utxo.flags | TransactionOutputFlag.FROZEN_MASK, utxo.tx_hash, utxo.out_index)
                for utxo in utxos if (utxo.flags & TransactionOutputFlag.FROZEN_MASK !=
                    TransactionOutputFlag.FROZEN_MASK))
        else:
            self._frozen_coins.difference_update(utxo.key() for utxo in utxos)
            update_entries.extend(
                (utxo.flags & ~TransactionOutputFlag.FROZEN_MASK, utxo.tx_hash, utxo.out_index)
                for utxo in utxos if utxo.flags & TransactionOutputFlag.FROZEN_MASK != 0)
        if update_entries:
            self._wallet.update_transactionoutput_flags(update_entries)

    def start(self, network) -> None:
        self._network = network
        if network:
            network.add_account(self)

    def stop(self) -> None:
        self._logger.debug(f'stopping account {self}')
        if self._network:
            self._network.remove_account(self)
            self._network = None

    def can_export(self) -> bool:
        return not self.is_watching_only() and hasattr(self.get_keystore(), 'get_private_key')

    def cpfp(self, tx: Transaction, fee: int) -> Transaction:
        tx_hash = tx.hash()
        for output_index, tx_output in enumerate(tx.outputs):
            utxo = self.get_utxo(tx_hash, output_index)
            if utxo is not None:
                break
        else:
            return

        inputs = [utxo.to_tx_input(self)]
        # TODO(rt12) BACKLOG does CPFP need to pay to the parent's output script? If not fix.
        outputs = [XTxOutput(tx_output.value - fee, utxo.script_pubkey,
            utxo.script_type, self.get_xpubkeys_for_id(utxo.keyinstance_id))]
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

    def _add_hw_info(self, tx: Transaction) -> None:
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
                for xpubkey in tx_output.x_pubkeys:
                    candidate_keystores = [ k for k in self.get_keystores()
                        if k.is_signature_candidate(xpubkey) ]
                    if len(candidate_keystores) == 0:
                        continue
                    keyinstance_id = self.get_keyinstance_id_for_derivation(
                        xpubkey.derivation_path())
                    keyinstance = self._keyinstances[keyinstance_id]
                    pubkeys = self.get_public_keys_for_id(keyinstance_id)
                    pubkeys = [pubkey.to_hex() for pubkey in pubkeys]
                    sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
                    item = (xpubkey.derivation_path(), sorted_xpubs,
                        self.get_threshold(self.get_default_script_type()))
                    output_items[candidate_keystores[0].get_fingerprint()] = item
            info.append(output_items)
        tx.output_info = info

    def sign_transaction(self, tx: Transaction, password: str) -> None:
        if self.is_watching_only():
            return

        # Annotate the outputs to the account's own keys for hardware wallets.
        # - Digitalbitbox makes use of all available output annotations.
        # - Keepkey and Trezor use this to annotate one arbitrary change address.
        # - Ledger kind of ignores it.
        # Hardware wallets cannot send to internal outputs for multi-signature, only have P2SH!
        if any([(isinstance(k, Hardware_KeyStore) and k.can_sign(tx))
                for k in self.get_keystores()]):
            self._add_hw_info(tx)

        # sign
        for k in self.get_keystores():
            try:
                if k.can_sign(tx):
                    k.sign_transaction(tx, password)
            except UserCancelled:
                continue

        # Incomplete transactions are multi-signature transactions that have not passed the
        # require signature threshold. We do not store these until they are fully signed.
        if tx.is_complete():
            tx_hash = tx.hash()
            self.add_transaction(tx_hash, tx, TxFlags.StateSigned)

    def get_payment_status(self, req: PaymentRequestRow) -> Tuple[bool, int]:
        local_height = self._wallet.get_local_height()
        related_utxos = [ u for u in self._utxos.values()
            if u.keyinstance_id == req.keyinstance_id ]
        l = []
        for utxo in related_utxos:
            tx_height = self._wallet._transaction_cache.get_height(utxo.tx_hash)
            if tx_height is not None:
                confirmations = local_height - tx_height
            else:
                confirmations = 0
            l.append((confirmations, req.value))

        vsum = 0
        for conf, v in reversed(sorted(l)):
            vsum += v
            if vsum >= req.value:
                return True, conf
        return False, None

    # NOTE(rt12) no matches for this
    # def get_request_status(self, pr_id: int) -> Tuple[PaymentState, Optional[int]]:
    #     pr = self._payment_requests.get(pr_id)
    #     if pr is None:
    #         return PaymentState.UNKNOWN

    #     conf = None
    #     if pr.value:
    #         if self.is_synchronized():
    #             paid, conf = self.get_payment_status(pr)
    #             status = PaymentState.PAID if paid else PaymentState.UNPAID
    #             if (status == PaymentState.UNPAID and pr.expiration is not None and
    #                     time.time() > pr.date_created + pr.expiration):
    #                 status = PaymentState.EXPIRED
    #         else:
    #             status = PaymentState.UNKNOWN
    #     else:
    #         status = PaymentState.UNKNOWN
    #     return status, conf

    def get_sorted_requests(self) -> List[PaymentRequestRow]:
        return (self.get_payment_request(pr_id) for pr_id in self._payment_requests)

    def get_fingerprint(self) -> bytes:
        raise NotImplementedError()

    def can_import_privkey(self):
        return False

    def can_import_address(self):
        return False

    def can_delete_key(self):
        return False

    def _add_activated_keys(self, keys: Sequence[KeyInstanceRow]) -> None:
        if not len(keys):
            return

        # self._logger.debug("_add_activated_keys: %s", keys)
        with self._activated_keys_lock:
            self._activated_keys.extend(k.keyinstance_id for k in keys)
        self._activated_keys_event.set()

        # Ensures keys show in key list
        if self._network:
            # There is no unique id for the account, so we just pass the wallet for now.
            self._network.trigger_callback('on_keys_created', self._wallet.get_storage_path(),
                self._id, keys)

    async def new_activated_keys(self) -> List[int]:
        await self._activated_keys_event.wait()
        self._activated_keys_event.clear()
        with self._activated_keys_lock:
            result = self._activated_keys
            self._activated_keys = []
        return result

    async def new_deactivated_keys(self) -> List[int]:
        await self._deactivated_keys_event.wait()
        self._deactivated_keys_event.clear()
        with self._deactivated_keys_lock:
            result = self._deactivated_keys
            self._deactivated_keys = []
        return result

    def sign_message(self, keyinstance_id, message, password: str):
        derivation_path = self._keypath[keyinstance_id]
        keystore = self.get_keystore()
        return keystore.sign_message(derivation_path, message, password)

    def decrypt_message(self, keyinstance_id: int, message, password: str):
        derivation_path = self._keypath[keyinstance_id]
        keystore = self.get_keystore()
        return keystore.decrypt_message(derivation_path, message, password)

    def is_watching_only(self) -> bool:
        raise NotImplementedError

    def can_change_password(self):
        raise NotImplementedError


class SimpleAccount(AbstractAccount):
    # wallet with a single keystore

    def is_watching_only(self) -> bool:
        return self.get_keystore().is_watching_only()

    def can_change_password(self):
        return self.get_keystore().can_change_password()


class ImportedAccountBase(SimpleAccount):
    def can_delete_key(self):
        return True

    def has_seed(self):
        return False

    def get_master_public_keys(self):
        return []

    def get_fingerprint(self) -> bytes:
        return b''


class ImportedAddressAccount(ImportedAccountBase):
    # Watch-only wallet of imported addresses

    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            output_rows: List[TransactionOutputRow]) -> None:
        self._hashes: Dict[int, str] = {}
        super().__init__(wallet, row, keyinstance_rows, output_rows)

    @classmethod
    def from_text(cls: Type[T], wallet: 'Wallet', account_id: Optional[int], text: str) -> T:
        if account_id is None:
            account_rows = wallet.add_accounts([ AccountRow(-1, None, ScriptType.NONE,
                "watch only") ])
            account_id = account_rows[0].account_id
            wallet.register_account(account_id,
                ImportedAddressAccount(wallet, account_rows[0], [], []))
        account = wallet.get_account(account_id)

        keyinstance_creation_rows = []
        for address_text in text.split():
            address = Address.from_string(address_text, Net.COIN)
            if isinstance(address, P2SH_Address):
                derivation_type = DerivationType.SCRIPT_HASH
            else:
                derivation_type = DerivationType.PUBLIC_KEY_HASH
            derivation_json = json.dumps({ "hash": address_text })
            keyinstance_creation_rows.append(KeyInstanceRow(-1, None, None,
                derivation_type, derivation_json, ScriptType.NONE, KeyInstanceFlag.NONE, None))

        keyinstances = wallet.create_keyinstances(account_id, keyinstance_creation_rows)
        account._load_keys(keyinstances)
        return account

    def is_watching_only(self) -> bool:
        return True

    def can_import_privkey(self):
        return False

    def _load_keys(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        self._hashes.clear()

        for row in keyinstance_rows:
            derivation_data = json.loads(row.derivation_data)
            assert row.derivation_type == DerivationType.PUBLIC_KEY_HASH
            self._hashes[row.keyinstance_id] = derivation_data['hash']

    def _unload_keys(self, key_ids: List[int]) -> None:
        for key_id in key_ids:
            del self._hashes[key_id]
        super()._unload_keys(key_ids)

    def can_change_password(self):
        return False

    def can_import_address(self):
        return True

    def import_address(self, address):
        assert isinstance(address, Address)
        if address in self.addresses:
            return False
        self.addresses.append(address)
        self._add_activated_keys([address])
        return True

    def get_xpubkeys_for_id(self, keyinstance_id: int) -> List[XPublicKey]:
        raise NotImplementedError


class ImportedPrivkeyAccount(ImportedAccountBase):
    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            output_rows: List[TransactionOutputRow]) -> None:
        assert all(row.derivation_type == DerivationType.PRIVATE_KEY for row in keyinstance_rows)
        self._default_keystore = Imported_KeyStore()
        AbstractAccount.__init__(self, wallet, row, keyinstance_rows, output_rows)

    @classmethod
    def from_text(cls: Type[T], wallet: 'Wallet', account_id: Optional[int],
            script_type: ScriptType, password: str, text: str) -> T:
        if account_id is None:
            account_rows = wallet.add_accounts(
                [ AccountRow(-1, None, script_type, "private keys") ])
            account_id = account_rows[0].account_id
            wallet.register_account(account_id,
                ImportedPrivkeyAccount(wallet, account_rows[0], [], []))
        account = wallet.get_account(account_id)

        keyinstance_creation_rows = []
        for prvkey_text in text.split():
            pubkey_text = PrivateKey.from_text(prvkey_text).public_key.to_hex()
            prvkeyenc_text = pw_encode(prvkey_text, password)
            derivation_json = json.dumps({ "pub": pubkey_text, "prv": prvkeyenc_text })
            keyinstance_creation_rows.append(KeyInstanceRow(-1, None, None,
                DerivationType.PRIVATE_KEY, derivation_json, ScriptType.P2PKH,
                KeyInstanceFlag.NONE, None))

        keyinstances = wallet.create_keyinstances(account_id, keyinstance_creation_rows)
        account._load_keys(keyinstances)
        return account

    def is_watching_only(self) -> bool:
        return False

    def can_import_privkey(self):
        return True

    def _load_keys(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        self._default_keystore.load_state(keyinstance_rows)

    def _unload_keys(self, key_ids: List[int]) -> None:
        for key_id in key_ids:
            self._default_keystore.remove_key(key_id)
        super()._unload_keys(key_ids)

    def can_change_password(self):
        return True

    def can_import_address(self):
        return False

    def get_public_keys_for_id(self, keyinstance_id: int) -> List[PublicKey]:
        return [ self.get_keystore().get_public_key_for_id(keyinstance_id) ]

    def import_private_key(self, sec, pw):
        pubkey = self.get_keystore().import_privkey(sec, pw)
        # TODO(rt12) REQUIRED ensure this addition is written to the database immediately
        address = pubkey.to_address(coin=Net.COIN)
        self._add_activated_keys([ address ])
        return address

    def export_private_key(self, keyinstance_id: int, password: str) -> str:
        '''Returned in WIF format.'''
        keystore = self.get_keystore()
        pubkey = keystore.get_public_key_for_id(keyinstance_id)
        return keystore.export_private_key(pubkey, password)

    def get_xpubkeys_for_id(self, keyinstance_id: int) -> List[XPublicKey]:
        public_key = self.get_keystore().get_public_key_for_id(keyinstance_id)
        return [XPublicKey(pubkey_bytes=public_key.to_bytes())]


class DeterministicAccount(AbstractAccount):
    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            output_rows: List[TransactionOutputRow]) -> None:
        AbstractAccount.__init__(self, wallet, row, keyinstance_rows, output_rows)

    def has_seed(self) -> bool:
        return self.get_keystore().has_seed()

    def get_seed(self, password: Optional[str]) -> str:
        return self.get_keystore().get_seed(password)

    def _load_keys(self, keyinstance_rows: List[KeyInstanceRow]) -> None:
        for row in keyinstance_rows:
            derivation_data = json.loads(row.derivation_data)
            assert row.derivation_type == DerivationType.BIP32_SUBPATH
            self._keypath[row.keyinstance_id] = tuple(derivation_data["subpath"])

    def _unload_keys(self, key_ids: List[int]) -> None:
        for key_id in key_ids:
            if key_id in self._keypath:
                del self._keypath[key_id]
        super()._unload_keys(key_ids)

    def get_next_derivation_index(self, derivation_path: Sequence[int]) -> int:
        with self.lock:
            keystore = self.get_keystore()
            return keystore.get_next_index(derivation_path)

    def allocate_keys(self, count: int,
            derivation_path: Sequence[int]) -> Sequence[DeterministicKeyAllocation]:
        if count <= 0:
            return []
        self._logger.info(f'creating {count} new keys within {derivation_path}')
        with self.lock:
            keystore = self.get_keystore()
            next_id = keystore.allocate_indexes(derivation_path, count)
            masterkey_id = keystore.get_id()
            self._wallet.update_masterkey_derivation_data(masterkey_id)
        return tuple(DeterministicKeyAllocation(masterkey_id, DerivationType.BIP32_SUBPATH,
            derivation_path + (i,)) for i in range(next_id, next_id + count))

    # Returns ordered from use first to use last.
    def get_fresh_keys(self, derivation_parent: Sequence[int], count: int) -> List[KeyInstanceRow]:
        fresh_keys = self.get_existing_fresh_keys(derivation_parent)
        fresh_keys = fresh_keys[:count]
        if len(fresh_keys) < count:
            required_count = count - len(fresh_keys)
            new_keys = self.create_keys(required_count, derivation_parent, ScriptType.NONE)
            # Preserve oldest to newest ordering.
            fresh_keys += new_keys
            assert len(fresh_keys) == count
        return fresh_keys

    # Returns ordered from use first to use last.
    def get_existing_fresh_keys(self, derivation_parent: Sequence[int]) -> List[KeyInstanceRow]:
        def _is_fresh_key(keyinstance: KeyInstanceRow) -> bool:
            return (keyinstance.script_type == ScriptType.NONE and
                (keyinstance.flags & KeyInstanceFlag.ALLOCATED_MASK) == 0)
        parent_depth = len(derivation_parent)
        candidates = [ key for key in self._keyinstances.values()
            if len(self._keypath[key.keyinstance_id]) == parent_depth+1
            and self._keypath[key.keyinstance_id][:parent_depth] == derivation_parent ]
        # Order keys from newest to oldest and work out how many in front are unused/fresh.
        keys = sorted(candidates, key=lambda v: -v.keyinstance_id)
        newest_to_oldest = list(itertools.takewhile(_is_fresh_key, keys))
        # Provide them in the more usable oldest to newest form.
        return list(reversed(newest_to_oldest))

    async def _synchronize_chain(self, derivation_parent: Sequence[int], wanted: int) -> None:
        existing_count = self.get_keystore().get_next_index(derivation_parent)
        fresh_count = len(self.get_existing_fresh_keys(derivation_parent))
        self.get_fresh_keys(derivation_parent, wanted)
        self._logger.info(
            f'derivation {derivation_parent} has {existing_count:,d} keys, {fresh_count:,d} fresh')

    async def _synchronize_wallet(self) -> None:
        '''Class-specific synchronization (generation of missing addresses).'''
        # TODO(rt12) BACKLOG This should have a per path gap limit configurable somewhere,
        # perhaps the account settings.
        await self._synchronize_chain(RECEIVING_SUBPATH, 20)
        await self._synchronize_chain(CHANGE_SUBPATH, 20)

    def get_master_public_keys(self) -> List[str]:
        return [self.get_master_public_key()]

    def get_fingerprint(self) -> bytes:
        return self.get_keystore().get_fingerprint()


class SimpleDeterministicAccount(SimpleAccount, DeterministicAccount):
    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            output_rows: List[TransactionOutputRow]) -> None:
        DeterministicAccount.__init__(self, wallet, row, keyinstance_rows, output_rows)

    def get_xpubkeys_for_id(self, keyinstance_id: int) -> List[XPublicKey]:
        keyinstance = self._keyinstances[keyinstance_id]
        derivation_path = self._keypath[keyinstance_id]
        return [self._wallet.get_keystore(keyinstance.masterkey_id).get_xpubkey(derivation_path)]

    def get_master_public_key(self) -> str:
        return self.get_keystore().get_master_public_key()

    def _get_public_key_for_id(self, keyinstance_id: int) -> PublicKey:
        derivation_path = self._keypath[keyinstance_id]
        keyinstance = self._keyinstances[keyinstance_id]
        keystore = self._wallet.get_keystore(keyinstance.masterkey_id)
        return keystore.derive_pubkey(derivation_path)

    def get_public_keys_for_id(self, keyinstance_id: int) -> List[PublicKey]:
        return [ self._get_public_key_for_id(keyinstance_id) ]

    def get_valid_script_types(self) -> Sequence[ScriptType]:
        return (ScriptType.P2PKH,)

    def get_possible_scripts_for_id(self, keyinstance_id: int) -> List[Tuple[ScriptType, Script]]:
        public_key = self._get_public_key_for_id(keyinstance_id)
        keyinstance = self._keyinstances[keyinstance_id]
        return [ (script_type, self.get_script_template(public_key, script_type).to_script())
            for script_type in self.get_valid_script_types() ]

    def get_script_template_for_id(self, keyinstance_id: int,
            script_type: Optional[ScriptType]=None) -> Any:
        public_key = self._get_public_key_for_id(keyinstance_id)
        keyinstance = self._keyinstances[keyinstance_id]
        script_type = (script_type if script_type is not None or
            keyinstance.script_type == ScriptType.NONE else keyinstance.script_type)
        return self.get_script_template(public_key, script_type)

    def get_dummy_script_template(self, script_type: Optional[ScriptType]=None) -> Any:
        public_key = PrivateKey(os.urandom(32)).public_key
        return self.get_script_template(public_key, script_type)

    def get_script_template(self, public_key: PublicKey,
            script_type: Optional[ScriptType]=None) -> Any:
        if script_type is None:
            script_type = self.get_default_script_type()
        if script_type == ScriptType.P2PK:
            return P2PK_Output(public_key)
        elif script_type == ScriptType.P2PKH:
            return public_key.to_address()
        else:
            raise Exception("unsupported script type", script_type)

    def derive_pubkeys(self, derivation_path: Sequence[int]) -> PublicKey:
        return self.get_keystore().derive_pubkey(derivation_path)

    def derive_script_template(self, derivation_path: Sequence[int]) -> ScriptTemplate:
        return self.get_script_template(self.derive_pubkeys(derivation_path))



class StandardAccount(SimpleDeterministicAccount):
    pass


class MultisigAccount(DeterministicAccount):
    def __init__(self, wallet: 'Wallet', row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            output_rows: List[TransactionOutputRow]) -> None:
        self._multisig_keystore = wallet.get_keystore(row.default_masterkey_id)
        self.m = self._multisig_keystore.m
        self.n = self._multisig_keystore.n

        DeterministicAccount.__init__(self, wallet, row, keyinstance_rows, output_rows)

    def get_threshold(self, script_type: ScriptType) -> int:
        assert script_type in self.get_valid_script_types(), \
            f"get_threshold got bad script_type {script_type}"
        return self.m

    def get_public_keys_for_id(self, keyinstance_id: int) -> List[PublicKey]:
        derivation_path = self._keypath[keyinstance_id]
        return [ k.derive_pubkey(derivation_path) for k in self.get_keystores() ]

    def get_valid_script_types(self) -> Sequence[ScriptType]:
        return (ScriptType.MULTISIG_P2SH, ScriptType.MULTISIG_BARE)

    def get_possible_scripts_for_id(self, keyinstance_id: int) -> List[Script]:
        public_keys = self.get_public_keys_for_id(keyinstance_id)
        public_keys_hex = [pubkey.to_hex() for pubkey in public_keys]
        return [ (script_type, self.get_script_template(public_keys_hex, script_type).to_script())
            for script_type in self.get_valid_script_types() ]

    def get_script_template_for_id(self, keyinstance_id: int,
            script_type: Optional[ScriptType]=None) -> Any:
        keyinstance = self._keyinstances[keyinstance_id]
        public_keys = self.get_public_keys_for_id(keyinstance_id)
        public_keys_hex = [pubkey.to_hex() for pubkey in public_keys]
        script_type = (script_type if script_type is not None or
            keyinstance.script_type == ScriptType.NONE else keyinstance.script_type)
        return self.get_script_template(public_keys_hex, script_type)

    def get_dummy_script_template(self, script_type: Optional[ScriptType]=None) -> Any:
        public_keys_hex = []
        for i in range(self.m):
            public_keys_hex.append(PrivateKey(os.urandom(32)).public_key.to_hex())
        return self.get_script_template(public_keys_hex, script_type)

    def get_script_template(self, public_keys_hex: List[str],
            script_type: Optional[ScriptType]=None) -> Any:
        if script_type is None:
            script_type = self.get_default_script_type()
        if script_type == ScriptType.MULTISIG_BARE:
            return P2MultiSig_Output(sorted(public_keys_hex), self.m)
        elif script_type == ScriptType.MULTISIG_P2SH:
            redeem_script = P2MultiSig_Output(sorted(public_keys_hex), self.m).to_script_bytes()
            return P2SH_Address(hash160(redeem_script), Net.COIN)
        else:
            raise Exception("unsupported script type", script_type)

    def derive_pubkeys(self, derivation_path: Sequence[int]) -> List[PublicKey]:
        return [ k.derive_pubkey(derivation_path) for k in self.get_keystores() ]

    def derive_script_template(self, derivation_path: Sequence[int]) -> ScriptTemplate:
        public_keys_hex = [pubkey.to_hex() for pubkey in self.derive_pubkeys(derivation_path)]
        return self.get_script_template(public_keys_hex)

    def get_keystore(self):
        return self._multisig_keystore

    def get_keystores(self) -> List[KeyStore]:
        return self._multisig_keystore.get_cosigner_keystores()

    def has_seed(self) -> bool:
        return self.get_keystore().has_seed()

    def can_change_password(self) -> bool:
        return self.get_keystore().can_change_password()

    def is_watching_only(self) -> bool:
        return self._multisig_keystore.is_watching_only()

    def get_master_public_key(self) -> str:
        return self.get_keystore().get_master_public_key()

    def get_master_public_keys(self) -> List[str]:
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self) -> bytes:
        # Sort the fingerprints in the same order as their master public keys.
        mpks = self.get_master_public_keys()
        fingerprints = [ k.get_fingerprint() for k in self.get_keystores() ]
        sorted_mpks, sorted_fingerprints = zip(*sorted(zip(mpks, fingerprints)))
        return b''.join(sorted_fingerprints)

    def get_xpubkeys_for_id(self, keyinstance_id: int) -> List[XPublicKey]:
        derivation_path = self._keypath[keyinstance_id]
        x_pubkeys = [k.get_xpubkey(derivation_path) for k in self.get_keystores()]
        # Sort them using the order of the realized pubkeys
        sorted_pairs = sorted((x_pubkey.to_public_key().to_hex(), x_pubkey)
            for x_pubkey in x_pubkeys)
        return [x_pubkey for _hex, x_pubkey in sorted_pairs]


class Wallet:
    _network: 'Network' = None
    _transaction_table: Optional[TransactionTable] = None
    _transaction_cache: Optional[TransactionCache] = None

    def __init__(self, storage: WalletStorage) -> None:
        self._id = random.randint(0, (1<<32)-1)

        self._storage = storage
        self._logger = logs.get_logger(f"wallet[{self.name()}]")
        self._db_context = storage.get_db_context()

        if self._db_context is not None:
            self._transaction_table = TransactionTable(self._db_context)
            self._transaction_cache = TransactionCache(self._transaction_table)
        self._transaction_descriptions: Dict[bytes, str] = {}

        self._masterkey_rows: Dict[int, MasterKeyRow] = {}
        self._account_rows: Dict[int, AccountRow] = {}

        self._accounts: Dict[int, AbstractAccount] = {}
        self._keystores: Dict[int, KeyStore] = {}

        self.load_state()

        self.contacts = Contacts(self._storage)

    def move_to(self, new_path: str) -> None:
        self._transaction_table.close()
        self._db_context = None

        self._storage.move_to(new_path)

        self._db_context = self._storage.get_db_context()
        self._transaction_table = TransactionTable(self._db_context)
        self._transaction_cache.set_store(self._transaction_table)

    def load_state(self) -> None:
        if self._db_context is None:
            return

        self._keystores.clear()
        self._accounts.clear()
        self._transaction_descriptions.clear()

        with TransactionTable(self._db_context) as table:
            # NOTE(rt12) BACKLOG These are actually read in the transaction cache but perhaps
            # shouldn't be, if they are managed separately.
            self._transaction_descriptions = dict(table.read_descriptions())

        with MasterKeyTable(self._db_context) as table:
            for row in sorted(table.read(), key=lambda t: 0 if t[1] is None else t[1]):
                self._realize_keystore(row)

        with KeyInstanceTable(self._db_context) as table:
            all_account_keys = defaultdict(list)
            keyinstances = {}
            for row in table.read(mask=KeyInstanceFlag.IS_ACTIVE):
                keyinstances[row.keyinstance_id] = row
                all_account_keys[row.account_id].append(row)

        with TransactionOutputTable(self._db_context) as table:
            all_account_outputs = defaultdict(list)
            for row in table.read():
                keyinstance = keyinstances[row.keyinstance_id]
                all_account_outputs[keyinstance.account_id].append(row)

        with AccountTable(self._db_context) as table:
            for row in table.read():
                account_keys = all_account_keys.get(row.account_id, [])
                account_outputs = all_account_outputs.get(row.account_id, [])
                if row.default_masterkey_id is not None:
                    account = self._realize_account(row, account_keys, account_outputs)
                else:
                    found_types = set(key.derivation_type for key in account_keys)
                    prvkey_types = set([ DerivationType.PRIVATE_KEY ])
                    address_types = set([ DerivationType.PUBLIC_KEY_HASH,
                        DerivationType.SCRIPT_HASH ])
                    if found_types & prvkey_types:
                        account = ImportedPrivkeyAccount(self, row, account_keys, account_outputs)
                    elif found_types & address_types:
                        account = ImportedAddressAccount(self, row, account_keys, account_outputs)
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

    def get_keystores(self) -> List[KeyStore]:
        return list(self._keystores.values())

    def check_password(self, password: str) -> None:
        # raises InvalidPassword on failure.
        password_token: Optional[str] = self._storage.get("password-token")
        assert password_token is not None
        pw_decode(password_token, password)

    def update_password(self, new_password: str, old_password: Optional[str]=None) -> None:
        assert new_password, "calling code must provide an new password"
        self._storage.put("password-token", pw_encode(os.urandom(32).hex(), new_password))
        for keystore in self._keystores.values():
            if keystore.can_change_password():
                keystore.update_password(new_password, old_password)
                if keystore.has_masterkey():
                    self.update_masterkey_derivation_data(keystore.get_id())
                else:
                    updates = []
                    for key_id, derivation_data in keystore.get_keyinstance_derivation_data():
                        derivation_bytes = json.dumps(derivation_data).encode()
                        updates.append((derivation_bytes, key_id))
                    self.update_keyinstance_derivation_data(updates)

    def get_account(self, account_id: int) -> AbstractAccount:
        return self._accounts[account_id]

    def get_accounts_for_keystore(self, keystore: KeyStore) -> List[AbstractAccount]:
        accounts = []
        for account in self.get_accounts():
            account_keystore = account.get_keystore()
            if keystore is account_keystore:
                accounts.append(account)
        return accounts

    def get_accounts(self) -> Iterable[AbstractAccount]:
        return list(self._accounts.values())

    def get_default_account(self) -> Optional[AbstractAccount]:
        if len(self._accounts):
            return list(self._accounts.values())[0]

    def _realize_keystore(self, row: MasterKeyRow) -> None:
        data: Dict[str, Any] = json.loads(row.derivation_data)
        parent_keystore: Optional[KeyStore] = None
        if row.parent_masterkey_id is not None:
            parent_keystore = self._masterkeys[row.parent_masterkey_id]
        keystore = instantiate_keystore(row.derivation_type, data, parent_keystore, row)
        self._keystores[row.masterkey_id] = keystore
        self._masterkey_rows[row.masterkey_id] = row

    def _realize_account(self, account_row: AccountRow,
            keyinstance_rows: List[KeyInstanceRow],
            output_rows: List[TransactionOutputRow]) -> None:
        account_constructors = {
            DerivationType.BIP32: StandardAccount,
            DerivationType.BIP32_SUBPATH: StandardAccount,
            DerivationType.ELECTRUM_OLD: StandardAccount,
            DerivationType.ELECTRUM_MULTISIG: MultisigAccount,
            DerivationType.HARDWARE: StandardAccount,
        }
        masterkey_row = self._masterkey_rows[account_row.default_masterkey_id]
        klass = account_constructors.get(masterkey_row.derivation_type, None)
        if klass is not None:
            return klass(self, account_row, keyinstance_rows, output_rows)
        raise WalletLoadError(_("unknown account type %d"), masterkey_row.derivation_type)

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
            script_type = ScriptType.MULTISIG_P2SH
        elif masterkey_row.derivation_type == DerivationType.HARDWARE:
            account_name = keystore.label or "Hardware wallet"
            script_type = ScriptType.P2PKH
        else:
            raise WalletLoadError(f"Unhandled derivation type {masterkey_row.derivation_type}")
        basic_row = AccountRow(-1, masterkey_row.masterkey_id, script_type, account_name)
        rows = self.add_accounts([ basic_row ])
        account = self._realize_account(rows[0], [], [])
        self.register_account(rows[0].account_id, account)
        if self._network is not None:
            account.start(self._network)
        self._network.trigger_callback("on_account_created", rows[0].account_id)
        return account

    def create_masterkey_from_keystore(self, keystore: KeyStore) -> MasterKeyRow:
        basic_row = keystore.to_masterkey_row()
        rows = self.add_masterkeys([ basic_row ])
        keystore.set_row(rows[0])
        self._keystores[rows[0].masterkey_id] = keystore
        self._masterkey_rows[rows[0].masterkey_id] = rows[0]
        return rows[0]

    def add_masterkeys(self, entries: Iterable[MasterKeyRow]) -> Iterable[MasterKeyRow]:
        masterkey_id = self._storage.get("next_masterkey_id", 1)
        rows = []
        for entry in entries:
            row = MasterKeyRow(masterkey_id, entry.parent_masterkey_id, entry.derivation_type,
                entry.derivation_data)
            rows.append(row)
            self._masterkey_rows[masterkey_id] = row
            masterkey_id += 1
        self._storage.put("next_masterkey_id", masterkey_id)
        with MasterKeyTable(self._db_context) as table:
            table.create(rows)
        return rows

    def add_accounts(self, accounts: List[AccountRow]) -> List[AccountRow]:
        account_id = self._storage.get("next_account_id", 1)
        rows = []
        for account in accounts:
            row = AccountRow(account_id, account.default_masterkey_id, account.default_script_type,
                account.account_name)
            rows.append(row)
            account_id += 1

        self._storage.put("next_account_id", account_id)
        with AccountTable(self._db_context) as table:
            table.create(rows)

        return rows

    def create_keyinstances(self, account_id: int,
            keyinstances: List[KeyInstanceRow]) -> List[KeyInstanceRow]:
        keyinstance_id = self._storage.get("next_keyinstance_id", 1)

        rows = []
        for keyinstance in keyinstances:
            rows.append(KeyInstanceRow(keyinstance_id, account_id, keyinstance.masterkey_id,
                keyinstance.derivation_type, keyinstance.derivation_data, keyinstance.script_type,
                keyinstance.flags, keyinstance.description))
            keyinstance_id += 1
        self._storage.put("next_keyinstance_id", keyinstance_id)

        with KeyInstanceTable(self._db_context) as table:
            table.create(rows)

        return rows

    def create_transactionoutputs(self, account_id: int,
            entries: List[TransactionOutputRow]) -> List[TransactionOutputRow]:
        with TransactionOutputTable(self._db_context) as table:
            table.create(entries)
        return entries

    def create_payment_requests(self, requests: List[PaymentRequestRow]) -> List[PaymentRequestRow]:
        request_id = self._storage.get("next_paymentrequest_id", 1)
        rows = []
        for request in requests:
            rows.append(PaymentRequestRow(request_id, request.keyinstance_id, request.state,
                request.value, request.expiration, request.description, request.date_created))
            request_id += 1
        self._storage.put("next_paymentrequest_id", request_id)
        with PaymentRequestTable(self._db_context) as table:
            table.create(rows)
        return rows

    def update_payment_requests(self, requests: List[PaymentRequestRow]) -> List[PaymentRequestRow]:
        entries = []
        for request in requests:
            entries.append((request.state, request.value, request.expiration, request.description,
                request.paymentrequest_id))
        with PaymentRequestTable(self._db_context) as table:
            table.update(entries)
        return requests

    def update_transaction_descriptions(self,
            entries: Iterable[Tuple[Optional[str], bytes]]) -> None:
        for text, tx_hash in entries:
            if text is None:
                del self._transaction_descriptions[tx_hash]
            else:
                self._transaction_descriptions[tx_hash] = text

        with TransactionTable(self._db_context) as table:
            table.update_descriptions(entries)

    def update_account_script_types(self, entries: Iterable[Tuple[ScriptType, int]]) -> None:
        with AccountTable(self._db_context) as table:
            table.update_script_type(entries)

    def update_masterkey_derivation_data(self, masterkey_id: int) -> None:
        keystore = self.get_keystore(masterkey_id)
        derivation_data = json.dumps(keystore.to_derivation_data()).encode()
        with MasterKeyTable(self._db_context) as table:
            table.update_derivation_data([ (masterkey_id, derivation_data) ])

    def update_keyinstance_derivation_data(self, entries: Iterable[Tuple[bytes, int]]) -> None:
        with KeyInstanceTable(self._db_context) as table:
            table.update_derivation_data(entries)

    def update_keyinstance_descriptions(self, entries: Iterable[Tuple[Optional[str], int]]) -> None:
        with KeyInstanceTable(self._db_context) as table:
            table.update_descriptions(entries)

    def update_keyinstance_flags(self, entries: Iterable[Tuple[KeyInstanceFlag, int]]) -> None:
        with KeyInstanceTable(self._db_context) as table:
            table.update_flags(entries)

    def update_keyinstance_script_types(self, entries: Iterable[Tuple[ScriptType, int]]) -> None:
        with KeyInstanceTable(self._db_context) as table:
            table.update_script_types(entries)

    def update_transactionoutput_flags(self,
            entries: Iterable[Tuple[TransactionOutputFlag, bytes, int]]) -> None:
        with TransactionOutputTable(self._db_context) as table:
            table.update_flags(entries)

    # This should only be called by an account that holds it's own transaction lock.
    def create_or_update_transactiondelta_relative(self,
            entries: Iterable[TransactionDeltaRow]) -> None:
        # Because we do not cache transaction delta entries in an account, the database needs
        # to do extra work to both insert any new record, and adjust the existing record
        # with the relative `value_delta`.
        with TransactionDeltaTable(self._db_context) as table:
            table.create_or_update_relative_values(entries)

    def is_synchronized(self) -> bool:
        "If all the accounts are synchronized"
        return all(w.is_synchronized() for w in self.get_accounts())

    def synchronize_incomplete_transaction(self, tx: Transaction) -> None:
        if tx.is_complete():
            self._logger.debug("synchronize_incomplete_transaction complete")
            return

        for txin in tx.inputs:
            for xpubkey in txin.unused_x_pubkeys():
                result = self.resolve_xpubkey(xpubkey)
                if result is None:
                    continue
                account, keyinstance_id = result
                if keyinstance_id is None:
                    account.create_keys_until(xpubkey.derivation_path(), txin.script_type)

        for txout in tx.outputs:
            if not len(txout.x_pubkeys):
                continue
            for xpubkey in txout.x_pubkeys:
                result = self.resolve_xpubkey(xpubkey)
                if result is None:
                    continue
                account, keyinstance_id = result
                if keyinstance_id is None:
                    account.create_keys_until(xpubkey.derivation_path(), txout.script_type)

    def resolve_xpubkey(self,
            x_pubkey: XPublicKey) -> Optional[Tuple[AbstractAccount, Optional[int]]]:
        for account in self._accounts.values():
            for keystore in account.get_keystores():
                if keystore.is_signature_candidate(x_pubkey):
                    if x_pubkey.kind() == XPublicKeyType.PRIVATE_KEY:
                        keyinstance_id = keystore.get_keyinstance_id_for_public_key(
                            x_pubkey.to_public_key())
                    else:
                        keyinstance_id = account.get_keyinstance_id_for_derivation(
                            x_pubkey.derivation_path())
                    return account, keyinstance_id

    def get_local_height(self) -> int:
        """ return last known height if we are offline """
        return (self._network.get_local_height() if self._network else
            self._storage.get('stored_height', 0))

    def get_use_change(self) -> bool:
        return self._storage.get('use_change', True)

    def set_use_change(self, enabled: bool) -> None:
        return self._storage.put('use_change', enabled)

    def get_multiple_change(self) -> bool:
        return self._storage.get('multiple_change', False)

    def set_multiple_change(self, enabled: bool) -> None:
        return self._storage.put('multiple_change', enabled)

    def start(self, network: 'Network') -> None:
        self._network = network
        for account in self.get_accounts():
            account.start(network)

    def stop(self) -> None:
        self._storage.put('stored_height', self.get_local_height())

        for account in self.get_accounts():
            account.stop()
        if self._transaction_table is not None:
            self._transaction_table.close()
        self._storage.close()
        self._network = None

    def create_gui_handler(self, window: 'ElectrumWindow', account: AbstractAccount) -> None:
        for keystore in account.get_keystores():
            if isinstance(keystore, Hardware_KeyStore):
                keystore.plugin.replace_gui_handler(window, keystore)
