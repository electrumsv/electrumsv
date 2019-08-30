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
#   - ImportedAddressWallet: imported address, no keystore
#   - ImportedPrivkeyWallet: imported private keys, keystore
#   - Standard_Wallet: one keystore, P2PKH
#   - Multisig_Wallet: several keystores, P2SH

from collections import defaultdict, namedtuple
import attr
import copy
import errno
import itertools
import json
import os
import random
import threading
import time
from typing import Optional, Union, Tuple, List, Any, Iterable, Dict, Type, TypeVar
import weakref

from aiorpcx import run_in_thread
from bitcoinx import (
    PrivateKey, PublicKey, P2MultiSig_Output, Address, hash160, P2SH_Address,
    TxOutput, classify_output_script, P2PKH_Address, P2PK_Output, Script,
    hex_str_to_hash, hash_to_hex_str, sha256,
)

from . import coinchooser
from . import paymentrequest
from .app_state import app_state
from .bitcoin import COINBASE_MATURITY
from .contacts import Contacts
from .crypto import sha256d
from .exceptions import NotEnoughFunds, ExcessiveFee, UserCancelled, InvalidPassword
from .i18n import _
from .keystore import (load_keystore, Hardware_KeyStore, Imported_KeyStore, BIP32_KeyStore,
    KeyStore)
from .logs import logs
from .networks import Net
from .paymentrequest import InvoiceStore
from .paymentrequest import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED
from .storage import multisig_type, WalletStorage, ParentWalletKinds
from .transaction import (
    Transaction, classify_tx_output, tx_output_to_display_text, XPublicKey, NO_SIGNATURE,
    XTxInput
)
from .wallet_database import WalletData, DBTxInput, DBTxOutput, TxFlags, TxData, TxProof
from .util import profiler, format_satoshis, bh2u, format_time, timestamp_to_datetime
from .web import create_URI

logger = logs.get_logger("wallet")


class WalletTypes:
    STANDARD = "standard"
    MULTISIG = "multisig"
    IMPORTED = "imported"


TxInfo = namedtuple('TxInfo', 'hash status label can_broadcast amount '
                    'fee height conf timestamp')


@attr.s(slots=True, cmp=False, hash=False)
class UTXO:
    value = attr.ib()
    script_pubkey = attr.ib()
    # This is currently a hex string
    tx_hash = attr.ib()
    out_index = attr.ib()
    height = attr.ib()
    address = attr.ib()
    # To determine if matured and spendable
    is_coinbase = attr.ib()

    def __eq__(self, other):
        return isinstance(other, UTXO) and self.key() == other.key()

    def __hash__(self):
        return hash(self.key())

    def key(self):
        return (self.tx_hash, self.out_index)

    def key_str(self):
        return ':'.join((self.tx_hash, str(self.out_index)))

    def to_tx_input(self):
        kind = classify_output_script(self.script_pubkey)
        if isinstance(kind, P2PKH_Address):
            threshold = 1
            # _add_input_sig_info() will replace with public key
            x_pubkeys = [XPublicKey('fd' + self.script_pubkey.to_hex())]
        elif isinstance(kind, P2SH_Address):
            # _add_input_sig_info() will replace with public key
            threshold = 0
            x_pubkeys = []
        elif isinstance(kind, P2PK_Output):
            threshold = 1
            x_pubkeys = [XPublicKey(kind.public_key.to_bytes())]
        else:
            raise RuntimeError(f'cannot spend {self}')

        return XTxInput(
            prev_hash=hex_str_to_hash(self.tx_hash),
            prev_idx=self.out_index,
            script_sig=Script(),
            sequence=0xffffffff,
            value=self.value,
            x_pubkeys=x_pubkeys,
            address=self.address,
            threshold=threshold,
            signatures=[NO_SIGNATURE] * len(x_pubkeys),
        )


def dust_threshold(network):
    return 546 # hard-coded Bitcoin SV dust threshold. Was changed to this as of Sept. 2018


def sweep_preparations(privkeys, get_utxos, imax=100):

    def find_coins(address, script_pubkey):
        script_hash_hex = hash_to_hex_str(sha256(bytes(script_pubkey)))
        return [UTXO(value=item['value'],
                     script_pubkey=script_pubkey,
                     tx_hash=item['tx_hash'],
                     out_index=item['tx_pos'],
                     height=item['height'],
                     address=address,
                     is_coinbase=False)  # Guess
                for item in get_utxos(script_hash_hex)]

    coins = []
    keypairs = {}
    for sec in privkeys:
        privkey = PrivateKey.from_text(sec)
        # Search compressed and uncompressed keys, P2PKH and P2PK
        for public_key in (privkey.public_key, privkey.public_key.complement()):
            address = public_key.to_address(coin=Net.COIN)
            coins.extend(find_coins(address, address.to_script()))
            output = P2PK_Output(public_key)
            coins.extend(find_coins(public_key, output.to_script()))
            for x_pubkey in [XPublicKey(b'\xfd' + address.to_script().to_bytes()),
                             XPublicKey(public_key.to_bytes())]:
                keypairs[x_pubkey] = privkey.to_bytes(), public_key.is_compressed()

    if not coins:
        raise Exception(_('No inputs found. (Note that inputs need to be confirmed)'))
    return coins[:imax], keypairs


def sweep(privkeys, network, config, recipient, fee=None, imax=100):
    pay_to_script = recipient.to_script()
    inputs, keypairs = sweep_preparations(privkeys, network.get_utxos, imax)
    total = sum(i.get('value') for i in inputs)
    if fee is None:
        outputs = [TxOutput(total, pay_to_script)]
        tx = Transaction.from_io(inputs, outputs)
        fee = config.estimate_fee(tx.estimated_size())
    if total - fee < 0:
        raise Exception(_('Not enough funds on address.') +
                        '\nTotal: %d satoshis\nFee: %d'%(total, fee))
    if total - fee < dust_threshold(network):
        raise Exception(_('Not enough funds on address.') +
                        '\nTotal: %d satoshis\nFee: %d\nDust Threshold: %d' %
                        (total, fee, dust_threshold(network)))

    outputs = [TxOutput(total - fee, pay_to_script)]
    locktime = network.get_local_height()

    tx = Transaction.from_io(inputs, outputs, locktime=locktime)
    tx.BIP_LI01_sort()
    tx.sign(keypairs)
    return tx


T = TypeVar('T', bound='Abstract_Wallet')

class Abstract_Wallet:
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    max_change_outputs = 3
    _filter_observed_addresses = False

    def __init__(self, parent_wallet: 'ParentWallet', wallet_data: Dict[str, Any]) -> None:
        # Prevent circular reference keeping parent and child wallets alive.
        self._parent_wallet = weakref.proxy(parent_wallet)
        self._wallet_data = wallet_data

        # Database Id for this child wallet.
        self._id = wallet_data["id"]
        self._datastore = parent_wallet.get_wallet_datastore(self._id)

        self.logger = logs.get_logger("wallet[{}]".format(self.name()))
        self.network = None

        # For synchronization.
        self._new_addresses = []
        self._new_addresses_lock = threading.Lock()
        self._new_addresses_event = app_state.async_.event()
        self._used_addresses = []
        self._used_addresses_lock = threading.Lock()
        self._used_addresses_event = app_state.async_.event()
        self._synchronize_event = app_state.async_.event()
        self._synchronized_event = app_state.async_.event()
        self.txs_changed_event = app_state.async_.event()
        self.request_count = 0
        self.response_count = 0
        self.progress_event = app_state.async_.event()

        self.gap_limit_for_change = 6  # constant
        # saved fields
        self.use_change = wallet_data.get('use_change', True)
        self.multiple_change = wallet_data.get('multiple_change', False)
        self.labels = wallet_data.get('labels', {})

        self.load_external_data()

        # load requests
        requests = wallet_data.get('payment_requests', {})
        for key, req in requests.items():
            req['address'] = Address.from_string(key)
        self.receive_requests = {req['address']: req
                                 for req in requests.values()}

        # locks: if you need to take several, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()

        # save wallet type the first time
        if wallet_data.get('wallet_type') is None:
            wallet_data['wallet_type'] = self.wallet_type

        # invoices and contacts
        self.invoices = InvoiceStore(wallet_data)

    @classmethod
    def create_within_parent(klass: Type[T], parent_wallet: 'ParentWallet',
            **wallet_data: Any) -> T:
        wallet_data['id'] = parent_wallet.get_next_child_wallet_id()
        instance = klass(parent_wallet, wallet_data)
        parent_wallet.add_child_wallet(instance)
        return instance

    def is_wrapped_legacy_wallet(self):
        return True

    def get_id(self) -> int:
        return self._id

    def dump(self) -> Dict[str, Any]:
        return self._wallet_data

    def get(self, key: str, default: Optional[Any]=None):
        return self._wallet_data.get(key, default)

    def put(self, key: str, value: Any):
        self._wallet_data[key] = value

    def missing_transactions(self):
        '''Returns a set of tx_hashes.'''
        return self._datastore.tx.get_unsynced_ids()

    def unverified_transactions(self):
        '''Returns a map of tx_hash to tx_height.'''
        results = self._datastore.tx.get_unverified_entries(self.get_local_height())
        self.logger.debug("unverified_transactions: %r", results)
        return { t[0]: t[1].metadata.height for t in results }

    async def synchronize_loop(self):
        while True:
            await self._synchronize()
            await self._synchronize_event.wait()

    async def _trigger_synchronization(self):
        if self.network:
            self._synchronize_event.set()
        else:
            await self._synchronize()

    async def _synchronize_wallet(self):
        '''Class-specific synchronization (generation of missing addresses).'''
        pass

    async def _synchronize(self):
        self.logger.debug('synchronizing...')
        self._synchronize_event.clear()
        self._synchronized_event.clear()
        await self._synchronize_wallet()
        self._synchronized_event.set()
        self.logger.debug('synchronized.')
        if self.network:
            self.network.trigger_callback('updated')

    def synchronize(self):
        app_state.async_.spawn_and_wait(self._trigger_synchronization)
        app_state.async_.spawn_and_wait(self._synchronized_event.wait)

    def is_synchronized(self):
        return (self._synchronized_event.is_set() and
                not (self.network and self.missing_transactions()))

    @classmethod
    def to_Address_dict(cls, d):
        '''Convert a dict of strings to a dict of Adddress objects.'''
        return {Address.from_string(text): value for text, value in d.items()}

    @classmethod
    def from_Address_dict(cls, d):
        '''Convert a dict of Address objects to a dict of strings.'''
        return {addr.to_string(): value for addr, value in d.items()}

    def __str__(self):
        return self.name()

    def _get_keystore_usage(self) -> List[Dict[str, Any]]:
        """
        Get the list of keystore references. The actual keystore data is located in the parent
        wallet, and the reference may not be to a atomic master private key (assuming there even
        is one) of the keystore.
        """
        return self._wallet_data.get('keystore_usage', [])

    def get_keystore(self, name: Optional[str]=None) -> Optional[KeyStore]:
        """
        Get a specific keystore that is used by this wallet. Generally, this should be the first
        one, and would be called with the expectation that there is only one for this kind of
        wallet. If `name` is given, it should only be the one with the matching name. If there is
        no match or no keystores to match, then None is returned.
        """
        for keystore_data in self._get_keystore_usage():
            if keystore_data.get('name', None) == name:
                return self._parent_wallet.get_keystore(keystore_data)
        return None

    def get_keystores(self) -> List[KeyStore]:
        """
        Get all the keystores that are used by this wallet.
        """
        return [ self._parent_wallet.get_keystore(keystore_data)
            for keystore_data in self._get_keystore_usage() ]

    def get_master_public_key(self):
        return None

    @profiler
    def load_external_data(self):
        # TODO: ACCOUNTS: This is a per-account database on the same file under the multi-account
        # paradigm. It needs to share access in that case. It is possible the parent wallet needs
        # to be the place where it is obtained. Each child wallet can hold a reference.

        self.pending_txs = self._datastore.tx.get_transactions(TxFlags.StateSigned,
            TxFlags.STATE_MASK)

        # address -> list(txid, height)
        addr_history = self._datastore.misc.get_value('addr_history')
        self._history = self.to_Address_dict(addr_history) if addr_history is not None else {}

        pruned_txo = self._datastore.misc.get_value('pruned_txo')
        if pruned_txo is None:
            self.pruned_txo = {}
        else:
            self.pruned_txo = { tuple(k): v for (k, v) in pruned_txo }

        # Frozen addresses
        self._frozen_addresses = set([])
        frozen_addresses = self._datastore.misc.get_value('frozen_addresses')
        if frozen_addresses is not None:
            self._frozen_addresses = set(Address.from_string(addr) for addr in frozen_addresses)

        # Frozen coins (UTXOs) -- note that we have 2 independent
        # levels of "freezing": address-level and coin-level.  The two
        # types of freezing are flagged independently of each other
        # and 'spendable' is defined as a coin that satisfies BOTH
        # levels of freezing.
        frozen_coins = self._datastore.misc.get_value('frozen_coins')
        self.logger.debug("frozen_coins %r", frozen_coins)
        self._frozen_coins = (set(tuple(v) for v in frozen_coins)
            if frozen_coins is not None else set([]))

        # What is persisted here differs depending on the wallet type.
        self.load_addresses(self._datastore.misc.get_value('addresses'))

        # If there was no address history entry we can take this as representative that there
        # are no other entries because the wallet has not been saved yet. This is not the case
        # with addresses, but otherwise so.
        self._insert = addr_history is None
        self.logger.debug("load_external_data insert=%r", self._insert)

    @profiler
    def save_external_data(self):
        with self.transaction_lock:
            if self._insert:
                save_func = self._datastore.misc.add
            else:
                save_func = self._datastore.misc.update

            save_func('pruned_txo', [ [ list(k), v ] for (k, v) in self.pruned_txo.items() ])
            save_func('frozen_addresses',
                list(addr.to_string() for addr in self._frozen_addresses))
            save_func('frozen_coins', list(self._frozen_coins))
            save_func('addr_history', self.from_Address_dict(self._history))
            # What is persisted here differs depending on the wallet type.
            address_data = self.save_addresses()
            if address_data is not None:
                save_func('addresses', address_data)

    def get_tx_ids_for_address(self, address: Address) -> List[str]:
        address_string = address.to_string()
        tx_ids = set([])
        for tx_id, entries in self._datastore.txin.get_all_entries().items():
            for entry in entries:
                if entry.address_string == address_string:
                    tx_ids.add(tx_id)
        for tx_id, entries in self._datastore.txout.get_all_entries().items():
            for entry in entries:
                if entry.address_string == address_string:
                    tx_ids.add(tx_id)
        return tx_ids

    def get_txins(self, tx_id: str, address: Optional[Address]=None) -> List[DBTxInput]:
        entries = self._datastore.txin.get_entries(tx_id)
        if address is None:
            return entries
        address_string = address.to_string()
        return [ v for v in entries if v.address_string == address_string ]

    def get_txouts(self, tx_id: str, address: Optional[str]=None) -> List[DBTxOutput]:
        entries = self._datastore.txout.get_entries(tx_id)
        if address is None:
            return entries
        address_string = address.to_string()
        return [ v for v in entries if v.address_string == address_string ]

    def get_transaction(self, tx_id: str, flags: Optional[int]=None) -> Optional[Transaction]:
        return self._datastore.tx.get_transaction(tx_id, flags)

    def has_received_transaction(self, tx_id: str) -> bool:
        # At this time, this means received over the P2P network.
        flags = self._datastore.tx.get_flags(tx_id)
        return flags is not None and (flags & (TxFlags.StateSettled | TxFlags.StateCleared)) != 0

    def display_name(self) -> str:
        # TODO: ACCOUNTS: Allow user to change this.
        if self._id == 0:
            return f"main wallet ({self.wallet_type})"
        return f"wallet {self._id} ({self.wallet_type})"

    def name(self) -> str:
        parent_name = self._parent_wallet.name()
        return f"{parent_name}/{self._id}"

    def save_addresses(self) -> dict:
        return {
            'receiving': [addr.to_string() for addr in self.receiving_addresses],
            'change': [addr.to_string() for addr in self.change_addresses],
        }

    def load_addresses(self, data: dict) -> None:
        if data is None:
            data = {}
        self.receiving_addresses = [Address.from_string(addr)
                                    for addr in data.get('receiving', [])]
        self.change_addresses = [Address.from_string(addr)
                                 for addr in data.get('change', [])]

    def is_deterministic(self):
        # Not all wallets have a keystore, like imported address for instance.
        keystore = self.get_keystore()
        return keystore and keystore.is_deterministic()

    def is_hardware_wallet(self) -> bool:
        return any([ isinstance(k, Hardware_KeyStore) for k in self.get_keystores() ])

    def set_label(self, name: Union[str, Address], text: Optional[str] = None) -> bool:
        if isinstance(name, Address):
            name = name.to_string()
        changed = False
        old_text = self.labels.get(name)
        if text:
            text = text.replace("\n", " ")
            if old_text != text:
                self.labels[name] = text
                changed = True
        else:
            if old_text:
                self.labels.pop(name)
                changed = True

        if changed:
            app_state.app.on_label_change(self, name, text)
            self._wallet_data['labels'] = self.labels

        return changed

    def is_mine(self, address: Address) -> bool:
        assert not isinstance(address, str)
        return address in self.get_addresses()

    def is_change(self, address: Address) -> bool:
        assert not isinstance(address, str)
        return address in self.change_addresses

    def get_address_index(self, address: Address) -> Tuple[bool, int]:
        try:
            return False, self.receiving_addresses.index(address)
        except ValueError:
            pass
        try:
            return True, self.change_addresses.index(address)
        except ValueError:
            pass
        assert not isinstance(address, str)
        raise Exception("Address {} not found".format(address))

    def export_private_key(self, address: Address, password: str):
        """ extended WIF format """
        if self.is_watching_only():
            return []
        index = self.get_address_index(address)
        keystore = self.get_keystore()
        secret, compressed = keystore.get_private_key(index, password)
        return PrivateKey(secret).to_WIF(compressed=compressed, coin=Net.COIN)

    def get_public_keys(self, address: Address):
        sequence = self.get_address_index(address)
        return self.get_pubkeys(*sequence)

    def add_verified_tx(self, tx_hash, height, timestamp, position, proof_position, proof_branch):
        entry = self._datastore.tx.get_entry(tx_hash, TxFlags.StateSettled)
        # Ensure we are not verifying transactions multiple times.
        if entry is None:
            entry = self._datastore.tx.get_entry(tx_hash)
            self.logger.debug("Attempting to clear unsettled tx %s %r",
                tx_hash, entry)
            return

        # We only update a subset.
        flags = TxFlags.HasHeight | TxFlags.HasTimestamp | TxFlags.HasPosition
        data = TxData(height=height, timestamp=timestamp, position=position)
        self._datastore.tx.update([ (tx_hash, data, None, flags | TxFlags.StateCleared) ])

        proof = TxProof(proof_position, proof_branch)
        self._datastore.tx.update_proof(tx_hash, proof)

        height, conf, timestamp = self.get_tx_height(tx_hash)
        self.logger.debug("add_verified_tx %d %d %d", height, conf, timestamp)
        self.network.trigger_callback('verified', tx_hash, height, conf, timestamp)

        addresses = [ Address.from_string(entry.address_string)
            for entry in self.get_txins(tx_hash) ]
        self._check_used_addresses(addresses)

    def undo_verifications(self, above_height):
        '''Used by the verifier when a reorg has happened'''
        with self.lock:
            reorg_count = self._datastore.tx.delete_reorged_entries(above_height)
            self.logger.info(f'removing verification of {reorg_count} transactions')

    def get_local_height(self):
        """ return last known height if we are offline """
        return (self.network.get_local_height() if self.network else
                self._wallet_data.get('stored_height', 0))

    def get_tx_height(self, tx_hash):
        """ return the height and timestamp of a verified transaction. """
        with self.lock:
            metadata = self._datastore.tx.get_metadata(tx_hash)
            assert metadata.height is not None, f"tx {tx_hash} has no height"
            if metadata.timestamp is not None:
                conf = max(self.get_local_height() - metadata.height + 1, 0)
                return metadata.height, conf, metadata.timestamp
            else:
                return metadata.height, 0, False

    def get_txpos(self, tx_hash):
        "return position, even if the tx is unverified"
        with self.lock:
            metadata = self._datastore.tx.get_metadata(tx_hash)
            if metadata.timestamp is not None:
                return metadata.height, metadata.position
            elif metadata.height is not None:
                # TODO: Look into whether entry.height is ever < 0
                return ((metadata.height, 0)
                    if metadata.height > 0 else ((1e9 - metadata.height), 0))
            else:
                return (1e9+1, 0)

    def has_usage(self):
        return len(self._history)

    def get_num_tx(self, address):
        """ return number of transactions where address is involved """
        return len(self.get_address_history(address))

    def get_tx_delta(self, tx_hash, address):
        "effect of tx on address"
        assert isinstance(address, Address)
        # pruned
        if tx_hash in self.pruned_txo.values():
            return None
        delta = 0
        # substract the value of coins sent from address
        for txin in self.get_txins(tx_hash, address):
            delta -= txin.amount
        # add the value of the coins received at address
        for txout in self.get_txouts(tx_hash, address):
            delta += txout.amount
        return delta

    def get_wallet_delta(self, tx):
        """ effect of tx on wallet """
        addresses = self.get_addresses()
        is_relevant = False
        is_mine = False
        is_pruned = False
        is_partial = False
        v_in = v_out = v_out_mine = 0
        for txin in tx.inputs:
            addr = txin.address
            if addr in addresses:
                is_mine = True
                is_relevant = True
                for txout in self.get_txouts(hash_to_hex_str(txin.prev_hash), addr):
                    if txout.out_tx_n == txin.prev_idx:
                        value = txout.amount
                        break
                else:
                    value = None
                if value is None:
                    is_pruned = True
                else:
                    v_in += value
            else:
                is_partial = True
        if not is_mine:
            is_partial = False
        for tx_output in tx.outputs:
            v_out += tx_output.value
            addr = classify_tx_output(tx_output)   # Needn't be an address
            if addr in addresses:
                v_out_mine += tx_output.value
                is_relevant = True
        if is_pruned:
            # some inputs are mine:
            fee = None
            if is_mine:
                v = v_out_mine - v_out
            else:
                # no input is mine
                v = v_out_mine
        else:
            v = v_out_mine - v_in
            if is_partial:
                # some inputs are mine, but not all
                fee = None
            else:
                # all inputs are mine
                fee = v_in - v_out
        if not is_mine:
            fee = None
        return is_relevant, is_mine, v, fee

    # Only called from the history ui dialog.
    def get_tx_info(self, tx):
        is_relevant, is_mine, v, fee = self.get_wallet_delta(tx)
        can_broadcast = False
        label = ''
        height = conf = timestamp = None
        tx_hash = tx.txid()
        if tx.is_complete():
            if self.has_received_transaction(tx_hash):
                label = self.get_label(tx_hash)
                height, conf, timestamp = self.get_tx_height(tx_hash)
                if height > 0:
                    if conf:
                        status = _("{:,d} confirmations (in block {:,d})"
                            ).format(conf, height)
                    else:
                        status = _('Not verified')
                else:
                    status = _('Unconfirmed')
                    if fee is None:
                        # We know this should be here as the transaction has been received.
                        fee = self._datastore.tx.get_metadata(tx_hash).fee
            else:
                status = _("Signed")
                can_broadcast = self.network is not None
        else:
            s, r = tx.signature_count()
            status = _("Unsigned") if s == 0 else _('Partially signed') + ' (%d/%d)'%(s,r)

        if is_relevant:
            if is_mine:
                if fee is not None:
                    amount = v + fee
                else:
                    amount = v
            else:
                amount = v
        else:
            amount = None

        return TxInfo(tx_hash, status, label, can_broadcast, amount, fee,
                      height, conf, timestamp)

    def _get_addr_io(self, address):
        h = self.get_address_history(address)
        received = {}
        for tx_hash, height in h:
            for txout in self.get_txouts(tx_hash, address):
                received[(tx_hash, txout.out_tx_n)] = (height, txout.amount, txout.is_coinbase)
        sent = {}
        for tx_hash, height in h:
            for txin in self.get_txins(tx_hash, address):
                sent[(txin.prevout_tx_hash, txin.prev_idx)] = height
        return received, sent

    def is_frozen_utxo(self, utxo):
        return utxo.key() in self._frozen_coins

    def _get_addr_utxos(self, address):
        coins, spent = self._get_addr_io(address)
        for input_key in spent:
            coins.pop(input_key)
            # cleanup/detect if the 'frozen coin' was spent and
            # remove it from the frozen coin set
            self._frozen_coins.discard(input_key)

        return [UTXO(value=value,
                     script_pubkey=address.to_script(),
                     tx_hash=tx_hash,
                     out_index=out_index,
                     height=height,
                     address=address,
                     is_coinbase=is_coinbase)
                for (tx_hash, out_index), (height, value, is_coinbase) in coins.items()
        ]

    # return the total amount ever received by an address
    def get_addr_received(self, address):
        received_amount = 0
        for tx_hash, height in self.get_address_history(address):
            received_amount += sum(txout.amount for txout in self.get_txouts(tx_hash, address))
        return received_amount

    # return the balance of a bitcoin address: confirmed and matured,
    # unconfirmed, unmatured Note that 'exclude_frozen_coins = True'
    # only checks for coin-level freezing, not address-level.
    def get_addr_balance(self, address, exclude_frozen_coins = False):
        assert isinstance(address, Address)
        received, sent = self._get_addr_io(address)
        c = u = x = 0
        for output_key, (tx_height, amount, is_coinbase) in received.items():
            if exclude_frozen_coins and output_key in self._frozen_coins:
                continue
            if is_coinbase and tx_height + COINBASE_MATURITY > self.get_local_height():
                x += amount
            elif tx_height > 0:
                c += amount
            else:
                u += amount
            if output_key in sent:
                if sent[output_key] > 0:
                    c -= amount
                else:
                    u -= amount
        return c, u, x

    def get_spendable_coins(self, domain, config, isInvoice = False):
        confirmed_only = config.get('confirmed_only', False)
        if isInvoice:
            confirmed_only = True
        return self.get_utxos(domain, exclude_frozen=True, mature=True,
                              confirmed_only=confirmed_only)

    def get_utxos(self, domain=None, exclude_frozen=False, mature=False, confirmed_only=False):
        '''Note exclude_frozen=True checks for BOTH address-level and coin-level frozen status. '''
        if domain is None:
            domain = self.get_addresses()
        if exclude_frozen:
            domain = set(domain) - self._frozen_addresses

        mempool_height = self.get_local_height() + 1
        def is_spendable_utxo(utxo):
            if exclude_frozen and self.is_frozen_utxo(utxo):
                return False
            if confirmed_only and utxo.height <= 0:
                return False
            # A coin is spendable at height (utxo.height + COINBASE_MATURITY)
            if mature and utxo.is_coinbase and mempool_height < utxo.height + COINBASE_MATURITY:
                return False
            return True

        return [utxo for addr in domain for utxo in self._get_addr_utxos(addr)
                if is_spendable_utxo(utxo)]

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_addresses(self):
        return self.get_receiving_addresses() + self.get_change_addresses()

    def get_observed_addresses(self):
        """
        Get the unused addresses and used ones with unspent balances.
        """
        if self._filter_observed_addresses:
            address_list = [
                self.get_receiving_addresses(),
                self.get_change_addresses()
            ]
            observed = []
            for addresses in address_list:
                empty_idx = None
                for i, address in enumerate(addresses):
                    if not self.is_archived_address(address):
                        observed.append(address)

            return observed
        return self.get_addresses()

    def get_frozen_balance(self) -> Tuple[int, int, int]:
        if not self._frozen_coins:
            # performance short-cut -- get the balance of the frozen
            # address set only IFF we don't have any frozen coins
            return self.get_balance(self._frozen_addresses)
        # otherwise, do this more costly calculation...
        cc_no_f, uu_no_f, xx_no_f = self.get_balance(None, exclude_frozen_coins=True,
                                                     exclude_frozen_addresses=True)
        cc_all, uu_all, xx_all = self.get_balance(None, exclude_frozen_coins=False,
                                                  exclude_frozen_addresses=False)
        return (cc_all-cc_no_f), (uu_all-uu_no_f), (xx_all-xx_no_f)

    def get_balance(self, domain=None, exclude_frozen_coins: bool=False,
                    exclude_frozen_addresses: bool=False) -> Tuple[int, int, int]:
        if domain is None:
            domain = self.get_addresses()
        if exclude_frozen_addresses:
            domain = set(domain) - self._frozen_addresses
        cc = uu = xx = 0
        for addr in domain:
            c, u, x = self.get_addr_balance(addr, exclude_frozen_coins)
            cc += c
            uu += u
            xx += x
        return cc, uu, xx

    def get_address_history(self, address: Address):
        assert isinstance(address, Address)
        return self._history.get(address, [])

    def add_pending_transaction(self, tx_hash: str, tx: Transaction) -> None:
        with self.transaction_lock:
            # freeze the inputs.
            pass

    def add_transaction(self, tx_hash: str, tx: Transaction) -> None:
        with self.transaction_lock:
            self._update_transaction_xputs(tx_hash, tx)
            self.logger.debug("adding tx data %s", tx_hash)
            self._datastore.tx.add_transaction(tx, TxFlags.StateSettled)

    def apply_transactions_xputs(self, tx_hash: str, tx: Transaction) -> None:
        with self.transaction_lock:
            self._update_transaction_xputs(tx_hash, tx)

    def _update_transaction_xputs(self, tx_hash: str, tx: Transaction) -> None:
        is_coinbase = tx.is_coinbase()
        # We batch the adding of inputs and outputs as it is a thousand times faster.
        txins = []
        txouts = []
        addresses = set([])

        # add inputs
        for tx_input in tx.inputs:
            address = tx_input.address
            if self.is_mine(address):
                prev_hash_hex = hash_to_hex_str(tx_input.prev_hash)
                prev_idx = tx_input.prev_idx
                # find value from prev output
                match = next((row for row in self.get_txouts(prev_hash_hex, address)
                    if row.out_tx_n == prev_idx), None)
                if match is not None:
                    txin = DBTxInput(address.to_string(), prev_hash_hex, prev_idx, match.amount)
                    txins.append((tx_hash, txin))
                else:
                    self.pruned_txo[(prev_hash_hex, prev_idx)] = tx_hash
                addresses.add(address)

        # add outputs
        for n, tx_output in enumerate(tx.outputs):
            address = classify_tx_output(tx_output)
            if isinstance(address, Address) and self.is_mine(address):
                txout = DBTxOutput(address.to_string(coin=Net.COIN), n,
                                   tx_output.value, is_coinbase)
                txouts.append((tx_hash, txout))
                addresses.add(address)

            # give the value to txi that spends me
            next_tx_hash = self.pruned_txo.get((tx_hash, n))
            if next_tx_hash is not None:
                self.pruned_txo.pop((tx_hash, n))

                txin = DBTxInput(address.to_string(), tx_hash, n, tx_output.value)
                txins.append((next_tx_hash, txin))

        # We expect to be passing in existing entries as this gets recalled for a transaction
        # by the history code, and we do not filter them out above.
        if txins:
            self._datastore.txin.add_entries(txins)
        if txouts:
            self._datastore.txout.add_entries(txouts)

    # Used by ImportedWalletBase
    def _remove_transaction(self, tx_hash: str) -> None:
        with self.transaction_lock:
            self.logger.debug("removing tx from history %s", tx_hash)

            for out_key, next_tx_hash in list(self.pruned_txo.items()):
                if next_tx_hash == tx_hash:
                    self.pruned_txo.pop(out_key)

            # add tx to pruned_txo, and undo the txi addition
            removal_txins = []
            for txin_hash, txin in self._datastore.txin.get_all_entries().items():
                if txin.prevout_tx_hash == tx_hash:
                    removal_txins.append((tx_hash, txin))
                    self.pruned_txo[(txin.prevout_tx_hash, txin.prev_idx)] = txin_hash

            removal_txins.extend(self.get_txins(tx_hash))
            if len(removal_txins):
                self._datastore.txin.delete_entries(removal_txins)

            removal_txouts = self.get_txouts(tx_hash)
            if len(removal_txouts):
                self._datastore.txout.delete_entries(removal_txouts)

    async def set_address_history(self, addr, hist, tx_fees):
        with self.lock:
            self._history[addr] = hist # { address: (tx_hash, tx_height) }

            updates = []
            for tx_hash, tx_height in hist:
                tx_fee = tx_fees.get(tx_hash, None)
                data = TxData(height=tx_height, fee=tx_fee)
                flags = TxFlags.HasHeight
                if tx_fee is not None:
                    flags |= TxFlags.HasFee
                updates.append((tx_hash, data, None, flags))
            self._datastore.tx.update_or_add(updates)

            for tx_id in set(t[0] for t in hist):
                # if addr is new, we have to recompute txi and txo
                tx = self.get_transaction(tx_id)
                if (tx is not None and not len(self.get_txins(tx_id, addr)) and
                        not len(self.get_txouts(tx_id, addr))):
                    self.apply_transactions_xputs(tx_id, tx)

        self.txs_changed_event.set()
        await self._trigger_synchronization()

    # Called by wallet.py:export_history()
    # Called by history_list.py:on_update()
    def get_history(self, domain=None):
        # get domain
        if domain is None:
            domain = self.get_addresses()
        # 1. Get the history of each address in the domain, maintain the
        #    delta of a tx as the sum of its deltas on domain addresses
        tx_deltas = defaultdict(int)
        for addr in domain:
            h = self.get_address_history(addr)
            for tx_hash, height in h:
                delta = self.get_tx_delta(tx_hash, addr)
                if delta is None or tx_deltas[tx_hash] is None:
                    tx_deltas[tx_hash] = None
                else:
                    tx_deltas[tx_hash] += delta

        # 2. create sorted history
        history = []
        for tx_hash in tx_deltas:
            delta = tx_deltas[tx_hash]
            height, conf, timestamp = self.get_tx_height(tx_hash)
            history.append((tx_hash, height, conf, timestamp, delta))
        history.sort(key = lambda x: self.get_txpos(x[0]), reverse=True)

        # 3. add balance
        c, u, x = self.get_balance(domain)
        balance = c + u + x
        h2 = []
        for tx_hash, height, conf, timestamp, delta in history:
            h2.append((tx_hash, height, conf, timestamp, delta, balance))
            if balance is None or delta is None:
                balance = None
            else:
                balance -= delta
        h2.reverse()

        return h2

    def export_history(self, domain=None, from_timestamp=None, to_timestamp=None,
                       show_addresses=False):
        h = self.get_history(domain)
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
            item['label'] = self.get_label(tx_hash)
            if show_addresses:
                tx = self.get_transaction(tx_hash)
                input_addresses = []
                output_addresses = []
                for txin in tx.inputs:
                    if txin.is_coinbase():
                        continue
                    addr = tx.address
                    if addr is None:
                        continue
                    input_addresses.append(addr.to_string())
                for tx_output in tx.outputs:
                    text, kind = tx_output_to_display_text(tx_output)
                    output_addresses.append(text)
                item['input_addresses'] = input_addresses
                item['output_addresses'] = output_addresses
            if fx:
                date = timestamp_to_datetime(time.time() if conf <= 0 else timestamp)
                item['fiat_value'] = fx.historical_value_str(value, date)
                item['fiat_balance'] = fx.historical_value_str(balance, date)
            out.append(item)
        return out

    def get_label(self, tx_hash):
        label = self.labels.get(tx_hash, '')
        if label == '':
            label = self.get_default_label(tx_hash)
        return label

    def get_default_label(self, tx_hash):
        if not len(self.get_txins(tx_hash)):
            labels = []
            for txout in self.get_txouts(tx_hash):
                label = self.labels.get(txout.address_string)
                if label:
                    labels.append(label)
            return ', '.join(labels)
        return ''

    def dust_threshold(self):
        return dust_threshold(self.network)

    def make_unsigned_transaction(self, utxos, outputs, config, fixed_fee: Optional[int]=None,
                                  change_addr: Optional[Address]=None) -> Transaction:
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

        inputs = [utxo.to_tx_input() for utxo in utxos]
        for txin in inputs:
            self._add_input_sig_info(txin)

        # change address
        if change_addr:
            change_addrs = [change_addr]
        else:
            addrs = self.get_change_addresses()[-self.gap_limit_for_change:]
            if self.use_change and addrs:
                # New change addresses are created only after a few
                # confirmations.  Select the unused addresses within the
                # gap limit; if none take one at random
                change_addrs = [addr for addr in addrs if
                                self.get_num_tx(addr) == 0]
                if not change_addrs:
                    change_addrs = [random.choice(addrs)]
            else:
                change_addrs = [inputs[0]['address']]

        assert all(isinstance(addr, Address) for addr in change_addrs)

        # Fee estimator
        if fixed_fee is None:
            fee_estimator = config.estimate_fee
        else:
            fee_estimator = lambda size: fixed_fee

        if all_index is None:
            # Let the coin chooser select the coins to spend
            max_change = self.max_change_outputs if self.multiple_change else 1
            coin_chooser = coinchooser.CoinChooserPrivacy()
            tx = coin_chooser.make_tx(inputs, outputs, change_addrs[:max_change],
                                      fee_estimator, self.dust_threshold())
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
        locktime = self.get_local_height()
        if locktime == -1: # We have no local height data (no headers synced).
            locktime = 0
        tx.locktime = locktime
        return tx

    def mktx(self, outputs, password, config, fee=None, change_addr=None, domain=None):
        coins = self.get_spendable_coins(domain, config)
        tx = self.make_unsigned_transaction(coins, outputs, config, fee, change_addr)
        self.sign_transaction(tx, password)
        return tx

    def is_frozen_address(self, addr):
        '''Address-level frozen query. Note: this is set/unset independent of
        'coin' level freezing.'''
        assert isinstance(addr, Address)
        return addr in self._frozen_addresses

    def set_frozen_state(self, addrs: Iterable[Address], freeze: bool) -> bool:
        '''Set frozen state of the addresses to FREEZE, True or False.  Note that address-level
        freezing is set/unset independent of coin-level freezing, however both must be
        satisfied for a coin to be defined as spendable.
        '''
        if all(self.is_mine(addr) for addr in addrs):
            if freeze:
                self._frozen_addresses |= set(addrs)
            else:
                self._frozen_addresses -= set(addrs)
            return True
        return False

    def set_frozen_coin_state(self, utxos, freeze) -> None:
        '''Set frozen state of the COINS to FREEZE, True or False.  Note that coin-level freezing
        is set/unset independent of address-level freezing, however both must be satisfied for
        a coin to be defined as spendable.
        '''
        if freeze:
            self._frozen_coins.update(utxo.key() for utxo in utxos)
        else:
            self._frozen_coins.difference_update(utxo.key() for utxo in utxos)

    def start(self, network):
        self.network = network
        if network:
            network.add_wallet(self)

    def stop(self):
        self.logger.debug(f'stopping wallet {self}')
        if self.network:
            self.network.remove_wallet(self)
            self._wallet_data['stored_height'] = self.get_local_height()
            self.network = None
        self.save_external_data()

    def can_export(self) -> bool:
        return not self.is_watching_only() and hasattr(self.get_keystore(), 'get_private_key')

    def is_archived_address(self, address: Address) -> bool:
        # The address was used, all known usage is finalised, and it has a balance of 0.
        return (len(self.get_address_history(address)) and self.is_empty_address(address) and
            self.is_confirmed_address(address))

    def is_empty_address(self, address: Address) -> bool:
        # No confirmed, unconfirmed or unmatured balance on the address.
        assert isinstance(address, Address)
        return not any(self.get_addr_balance(address))

    def is_confirmed_address(self, address: Address) -> bool:
        # Knowing this address has been used, is all usage finalised?
        for tx_id in self.get_tx_ids_for_address(address):
            metadata = self._datastore.tx.get_cached_entry(tx_id).metadata
            if metadata.height is not None and metadata.height >= 0:
                return True
        return False

    def cpfp(self, tx, fee):
        txid = tx.txid()
        for output_index, tx_output in enumerate(tx.outputs):
            address = classify_tx_output(tx_output)
            if isinstance(address, Address) and self.is_mine(address):
                break
        else:
            return
        key = (txid, output_index)
        for utxo in self._get_addr_utxos(address):
            if utxo.key() == key:
                break
        else:
            return
        txin = utxo.to_tx_input()
        self._add_input_sig_info(txin)
        inputs = [txin]
        outputs = [TxOutput(tx_output.value - fee, address.to_script())]
        locktime = self.get_local_height()
        # note: no need to call tx.BIP_LI01_sort() here - single input/output
        return Transaction.from_io(inputs, outputs, locktime=locktime)

    def can_sign(self, tx):
        if tx.is_complete():
            return False
        for k in self.get_keystores():
            # setup "wallet advice" so Xpub wallets know how to sign 'fd' type tx inputs
            # by giving them the sequence number ahead of time
            if isinstance(k, BIP32_KeyStore):
                for txin in tx.inputs:
                    for x_pubkey in txin.x_pubkeys:
                        addr = x_pubkey.to_address()
                        try:
                            c, index = self.get_address_index(addr)
                        except:
                            continue
                        if index is not None:
                            k.set_wallet_advice(addr, [c,index])
            if k.can_sign(tx):
                return True
        return False

    def get_input_tx(self, tx_hash):
        # First look up an input transaction in the wallet where it
        # will likely be.  If co-signing a transaction it may not have
        # all the input txs, in which case we ask the network.
        tx = self.get_transaction(tx_hash)
        if not tx and self.network:
            tx_hex = self.network.request_and_wait('blockchain.transaction.get', [tx_hash])
            tx = Transaction.from_hex(tx_hex)
        return tx

    def add_hw_info(self, tx):
        # add output info for hw wallets
        info = []
        xpubs = self.get_master_public_keys()
        for tx_output in tx.outputs:
            addr = classify_tx_output(tx_output)
            if isinstance(addr, Address) and self.is_mine(addr):
                index = self.get_address_index(addr)
                pubkeys = self.get_public_keys(addr)
                # sort xpubs using the order of pubkeys
                sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
                item = (index, sorted_xpubs, self.m if isinstance(self, Multisig_Wallet) else None)
            else:
                item = None
            info.append(item)
        logger.debug(f'add_hw_info: {info}')
        tx.output_info = info

    def sign_transaction(self, tx: Transaction, password: str) -> None:
        if self.is_watching_only():
            return
        # hardware wallets require extra info
        if any([(isinstance(k, Hardware_KeyStore) and k.can_sign(tx))
                for k in self.get_keystores()]):
            self.add_hw_info(tx)
        # sign
        for k in self.get_keystores():
            try:
                if k.can_sign(tx):
                    k.sign_transaction(tx, password)
            except UserCancelled:
                continue

    def get_unused_addresses(self):
        # fixme: use slots from expired requests
        domain = self.get_receiving_addresses()
        return [
            addr for addr in domain
            if not self.get_address_history(addr)
            and addr not in self.receive_requests
            and not self.is_frozen_address(addr)
        ]

    def get_unused_address(self):
        addrs = self.get_unused_addresses()
        if addrs:
            return addrs[0]

    def get_receiving_address(self):
        '''Returns a receiving address or None.'''
        domain = self.get_unused_addresses() or self.get_receiving_addresses()
        if domain:
            return domain[0]

    def get_payment_status(self, address, amount):
        local_height = self.get_local_height()
        received, _sent = self._get_addr_io(address)
        l = []
        for (tx_id, _n), (_h, amount, _is_cb) in received.items():
            tx_height = self._datastore.tx.get_height(tx_id)
            if tx_height is not None:
                confirmations = local_height - tx_height
            else:
                confirmations = 0
            l.append((confirmations, amount))

        vsum = 0
        for conf, v in reversed(sorted(l)):
            vsum += v
            if vsum >= amount:
                return True, conf
        return False, None

    def get_payment_request(self, addr, config):
        assert isinstance(addr, Address)
        r = self.receive_requests.get(addr)
        if not r:
            return
        out = copy.copy(r)
        out['URI'] = create_URI(addr, r['amount'], None)
        status, conf = self.get_request_status(addr)
        out['status'] = status
        if conf is not None:
            out['confirmations'] = conf
        # check if bip270 file exists
        rdir = config.get('requests_dir')
        if rdir:
            key = out.get('id', addr.to_string())
            path = os.path.join(rdir, 'req', key[0], key[1], key)
            if os.path.exists(path):
                baseurl = 'file://' + rdir
                rewrite = config.get('url_rewrite')
                if rewrite:
                    baseurl = baseurl.replace(*rewrite)
                out['request_url'] = os.path.join(baseurl, 'req', key[0], key[1], key, key)
                out['URI'] += '&r=' + out['request_url']
                out['index_url'] = os.path.join(baseurl, 'index.html') + '?id=' + key
                websocket_server_announce = config.get('websocket_server_announce')
                if websocket_server_announce:
                    out['websocket_server'] = websocket_server_announce
                else:
                    out['websocket_server'] = config.get('websocket_server', 'localhost')
                websocket_port_announce = config.get('websocket_port_announce')
                if websocket_port_announce:
                    out['websocket_port'] = websocket_port_announce
                else:
                    out['websocket_port'] = config.get('websocket_port', 9999)
        return out

    def get_request_status(self, key):
        r = self.receive_requests.get(key)
        if r is None:
            return PR_UNKNOWN
        address = r['address']
        amount = r.get('amount')
        timestamp = r.get('time', 0)
        if timestamp and type(timestamp) != int:
            timestamp = 0
        expiration = r.get('exp')
        if expiration and type(expiration) != int:
            expiration = 0
        conf = None
        if amount:
            if self.is_synchronized():
                paid, conf = self.get_payment_status(address, amount)
                status = PR_PAID if paid else PR_UNPAID
                if (status == PR_UNPAID and expiration is not None and
                       time.time() > timestamp + expiration):
                    status = PR_EXPIRED
            else:
                status = PR_UNKNOWN
        else:
            status = PR_UNKNOWN
        return status, conf

    def make_payment_request(self, addr, amount, message, expiration=None):
        assert isinstance(addr, Address)
        timestamp = int(time.time())
        _id = bh2u(sha256d(addr.to_string() + "%d" % timestamp))[0:10]
        return {
            'time': timestamp,
            'amount': amount,
            'exp': expiration,
            'address': addr,
            'memo': message,
            'id': _id
        }

    def serialize_request(self, r):
        result = r.copy()
        result['address'] = r['address'].to_string()
        return result

    def save_payment_requests(self):
        def _delete_transient_state(value):
            del value['address']
            return value

        requests = {
            address_.to_string(): _delete_transient_state(value.copy())
            for address_, value in self.receive_requests.items()
        }
        self._wallet_data['payment_requests'] = requests
        self._parent_wallet.save_storage()

    def add_payment_request(self, req, config, set_address_label=True):
        address_ = req['address']
        address_text = address_.to_string()
        amount = req['amount']
        message = req['memo']
        self.receive_requests[address_] = req
        self.save_payment_requests()

        if set_address_label:
            self.set_label(address_text, message) # should be a default label

        requests_path = config.get('requests_dir')
        if requests_path and amount is not None:
            key = req.get('id', address_text)
            pr = paymentrequest.make_unsigned_request(req)
            path = os.path.join(requests_path, 'req', key[0], key[1], key)
            if not os.path.exists(path):
                try:
                    os.makedirs(path)
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
            with open(os.path.join(path, key), 'wb') as f:
                f.write(pr.SerializeToString())
            # reload
            req = self.get_payment_request(address_, config)
            req['address'] = req['address'].to_string()
            with open(os.path.join(path, key + '.json'), 'w', encoding='utf-8') as f:
                f.write(json.dumps(req))

    def remove_payment_request(self, addr, config):
        if isinstance(addr, str):
            addr = Address.from_string(addr)
        if addr not in self.receive_requests:
            return False
        r = self.receive_requests.pop(addr)
        rdir = config.get('requests_dir')
        if rdir:
            key = r.get('id', addr.to_string())
            for s in ['.json', '']:
                n = os.path.join(rdir, 'req', key[0], key[1], key, key + s)
                if os.path.exists(n):
                    os.unlink(n)
        self.save_payment_requests()
        return True

    def get_sorted_requests(self, config):
        def f(x):
            try:
                addr = x['address']
                return self.get_address_index(addr) or str(addr)
            except:
                return str(addr)
        return sorted((self.get_payment_request(x, config) for x in self.receive_requests), key=f)

    def get_fingerprint(self):
        raise NotImplementedError()

    def can_import_privkey(self):
        return False

    def can_import_address(self):
        return False

    def can_delete_address(self):
        return False

    def _add_new_addresses(self, addresses: Iterable[Address], *, save: bool=True):
        assert all(isinstance(address, Address) for address in addresses)
        if addresses:
            with self._new_addresses_lock:
                self._new_addresses.extend(addresses)
            self._new_addresses_event.set()
            if save:
                self.save_addresses()
            # Ensures addresses show in address list
            if self.network:
                self.network.trigger_callback('updated')

    async def new_addresses(self) -> List[Address]:
        await self._new_addresses_event.wait()
        self._new_addresses_event.clear()
        with self._new_addresses_lock:
            result = self._new_addresses
            self._new_addresses = []
        return result

    def _check_used_addresses(self, addresses: Iterable[Address]) -> None:
        if not self._filter_observed_addresses:
            return
        assert all(isinstance(address, Address) for address in addresses)
        addresses = [ a for a in addresses if self.is_archived_address(a) ]
        if addresses:
            address_strings = [a.to_string() for a in addresses]
            self.logger.debug("_check_used_addresses: %s", address_strings)
            with self._used_addresses_lock:
                self._used_addresses.extend(addresses)
            self._used_addresses_event.set()

    async def used_addresses(self) -> List[Address]:
        await self._used_addresses_event.wait()
        self._used_addresses_event.clear()
        with self._used_addresses_lock:
            result = self._used_addresses
            self._used_addresses = []
        return result

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        keystore = self.get_keystore()
        return keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey, message, password):
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        keystore = self.get_keystore()
        return keystore.decrypt_message(index, message, password)


class Simple_Wallet(Abstract_Wallet):
    # wallet with a single keystore

    def is_watching_only(self):
        return self.get_keystore().is_watching_only()

    def can_change_password(self):
        return self.get_keystore().can_change_password()


class ImportedWalletBase(Simple_Wallet):
    txin_type = 'p2pkh'

    def get_txin_type(self, address):
        return self.txin_type

    def can_delete_address(self):
        return True

    def has_seed(self):
        return False

    def is_change(self, address):
        return False

    def get_master_public_keys(self):
        return []

    def get_fingerprint(self):
        return ''

    def get_receiving_addresses(self):
        return self.get_addresses()

    def get_change_addresses(self):
        return []

    def delete_address(self, address):
        assert isinstance(address, Address)
        if address not in self.get_addresses():
            return

        transactions_to_remove = set()  # only referred to by this address
        transactions_new = set()  # txs that are not only referred to by address
        with self.lock:
            for addr, details in self._history.items():
                if addr == address:
                    for tx_hash, height in details:
                        transactions_to_remove.add(tx_hash)
                else:
                    for tx_hash, height in details:
                        transactions_new.add(tx_hash)
            transactions_to_remove -= transactions_new
            self._history.pop(address, None)

            for tx_hash in transactions_to_remove:
                self._remove_transaction(tx_hash)

        self.save_external_data()

        self.set_label(address.to_string(), None)
        self.remove_payment_request(address, {})
        self.set_frozen_state([address], False)

        self.delete_address_derived(address)
        self.save_addresses()


class ImportedAddressWallet(ImportedWalletBase):
    # Watch-only wallet of imported addresses

    wallet_type = 'imported_addr'

    def __init__(self, parent_wallet: 'ParentWallet', wallet_data: Dict[str, Any]) -> None:
        self._sorted = None
        super().__init__(parent_wallet, wallet_data)

    @classmethod
    def from_text(cls: Type[T], parent_wallet: 'ParentWallet', text: str) -> T:
        wallet = cls.create_within_parent(parent_wallet)
        for address in text.split():
            wallet.import_address(Address.from_string(address))
        # Avoid adding addresses twice in network.py
        wallet._new_addresses.clear()
        return wallet

    def is_watching_only(self):
        return True

    def can_import_privkey(self):
        return False

    def load_addresses(self, data: list) -> None:
        assert type(data) is list or data is None, str(data)
        if data is None:
            data = []
        self.addresses = [Address.from_string(addr) for addr in data]

    def save_addresses(self) -> list:
        return [addr.to_string() for addr in self.addresses]

    def can_change_password(self):
        return False

    def can_import_address(self):
        return True

    def get_addresses(self, include_change=False):
        if not self._sorted:
            self._sorted = sorted(self.addresses, key=lambda addr: addr.to_string())
        return self._sorted

    def import_address(self, address):
        assert isinstance(address, Address)
        if address in self.addresses:
            return False
        self.addresses.append(address)
        self._add_new_addresses([address])
        self._sorted = None
        return True

    def delete_address_derived(self, address):
        self.addresses.remove(address)
        self._sorted = None

    def _add_input_sig_info(self, txin):
        pass


class ImportedPrivkeyWallet(ImportedWalletBase):
    # wallet made of imported private keys
    wallet_type = 'imported_privkey'

    def __init__(self, parent_wallet: 'ParentWallet', wallet_data: Dict[str, Any]):
        Abstract_Wallet.__init__(self, parent_wallet, wallet_data)

    @classmethod
    def from_text(cls: Type[T], parent_wallet: 'ParentWallet', text: str) -> T:
        keystore = Imported_KeyStore({})
        for privkey in text.split():
            # Passwords are set on the parent wallet.
            keystore.import_privkey(privkey, None)
        keystore_usage = parent_wallet.add_keystore(keystore.dump())

        wallet = cls.create_within_parent(parent_wallet, keystore_usage=[ keystore_usage ])

        # Avoid adding addresses twice in network.py
        wallet._new_addresses.clear()
        return wallet

    def is_watching_only(self):
        return False

    def can_import_privkey(self):
        return True

    def load_addresses(self, data: Any) -> None:
        pass

    def save_addresses(self) -> None:
        return None

    def can_change_password(self):
        return True

    def can_import_address(self):
        return False

    def get_addresses(self, include_change=False):
        return self.get_keystore().get_addresses()

    def delete_address_derived(self, address):
        self.get_keystore().remove_address(address)

    def get_address_index(self, address):
        return self.get_public_key(address)

    def get_public_key(self, address):
        return self.get_keystore().address_to_pubkey(address)

    def import_private_key(self, sec, pw):
        pubkey = self.get_keystore().import_privkey(sec, pw)
        self._parent_wallet.save_storage()
        address_str = pubkey.to_address(coin=Net.COIN).to_string()
        self._add_new_addresses([Address.from_string(address_str)])
        return address_str

    def export_private_key(self, address, password):
        '''Returned in WIF format.'''
        keystore = self.get_keystore()
        pubkey = keystore.address_to_pubkey(address)
        return keystore.export_private_key(pubkey, password)

    def _add_input_sig_info(self, txin):
        address = txin.address
        if self.is_mine(address):
            pubkey = self.get_keystore().address_to_pubkey(address)
            txin.x_pubkeys = [XPublicKey(pubkey.to_bytes())]

    def pubkeys_to_address(self, pubkey):
        pubkey = PublicKey.from_hex(pubkey)
        if pubkey in self.get_keystore().keypairs:
            return Address.from_string(pubkey.to_address(coin=Net.COIN).to_string())


class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, parent_wallet: 'ParentWallet', wallet_data: Dict[str, Any]) -> None:
        Abstract_Wallet.__init__(self, parent_wallet, wallet_data)
        self.gap_limit = wallet_data.get('gap_limit', 20)

    def has_seed(self) -> bool:
        return self.get_keystore().has_seed()

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_seed(self, password: Optional[str]) -> str:
        return self.get_keystore().get_seed(password)

    def change_gap_limit(self, value: int) -> bool:
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.gap_limit:
            self.gap_limit = value
            self._wallet_data['gap_limit'] = self.gap_limit
            return True
        elif value >= self.min_acceptable_gap():
            addresses = self.get_receiving_addresses()
            k = self.num_unused_trailing_addresses(addresses)
            n = len(addresses) - k + value
            self.receiving_addresses = self.receiving_addresses[0:n]
            self.gap_limit = value
            self._wallet_data['gap_limit'] = self.gap_limit
            self.save_addresses()
            return True
        else:
            return False

    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for addr in reversed(addresses):
            if addr in self._history:
                break
            k = k + 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0
        addresses = self.get_receiving_addresses()
        k = self.num_unused_trailing_addresses(addresses)
        for a in addresses[0:-k]:
            if a in self._history:
                n = 0
            else:
                n += 1
                if n > nmax: nmax = n
        return nmax + 1

    def create_new_address(self, for_change=False):
        address, = app_state.async_.spawn_and_wait(self._create_new_addresses, for_change, 1)
        return address

    def create_new_addresses(self, for_change=False, count=1):
        return app_state.async_.spawn_and_wait(self._create_new_addresses, for_change, count)

    async def _create_new_addresses(self, for_change, count):
        if count <= 0:
            return []
        self.logger.info(f'creating {count} new addresses')

        def derive_addresses(index_range):
            return [self.pubkeys_to_address(self.derive_pubkeys(for_change, index))
                    for index in index_range]
        with self.lock:
            chain = self.change_addresses if for_change else self.receiving_addresses
            first = len(chain)
            addresses = await run_in_thread(derive_addresses, range(first, first + count))
            chain.extend(addresses)
        self._add_new_addresses(addresses)
        return addresses

    def _is_fresh_address(self, address):
        heights = [height for _, height in self.get_address_history(address) if height > 0]
        conf_count = self.get_local_height() - max(heights) + 1 if heights else 0
        return conf_count <= 0

    async def _synchronize_chain(self, for_change):
        wanted = self.gap_limit_for_change if for_change else self.gap_limit
        chain = self.change_addresses if for_change else self.receiving_addresses
        count = len(list(itertools.takewhile(self._is_fresh_address, reversed(chain))))
        name = 'change' if for_change else 'receiving'
        self.logger.info(f'chain {name} has {len(chain):,d} addresses, {count:,d} fresh')
        return await self._create_new_addresses(for_change, wanted - count)

    async def _synchronize_wallet(self):
        '''Class-specific synchronization (generation of missing addresses).'''
        await self._synchronize_chain(False)
        await self._synchronize_chain(True)

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()

    def get_txin_type(self, address):
        return self.txin_type


class Simple_Deterministic_Wallet(Simple_Wallet, Deterministic_Wallet):

    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, parent_wallet: 'ParentWallet', wallet_data: Dict[str, Any]) -> None:
        Deterministic_Wallet.__init__(self, parent_wallet, wallet_data)
        self.txin_type = 'p2pkh'

    def get_public_key(self, address):
        sequence = self.get_address_index(address)
        pubkey = self.get_pubkey(*sequence)
        return pubkey

    def get_pubkey(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_public_keys(self, address):
        return [self.get_public_key(address)]

    def _add_input_sig_info(self, txin):
        address = txin.address
        if self.is_mine(address):
            derivation = self.get_address_index(address)
            x_pubkey = self.get_keystore().get_xpubkey(*derivation)
            txin.x_pubkeys = [x_pubkey]

    def get_master_public_key(self):
        return self.get_keystore().get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.get_keystore().derive_pubkey(c, i)


class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_address(self, pubkey):
        return PublicKey.from_hex(pubkey).to_address(coin=Net.COIN)


class Multisig_Wallet(Deterministic_Wallet):
    # generic m of n
    gap_limit = 20

    def __init__(self, parent_wallet: 'ParentWallet', wallet_data: Dict[str, Any]) -> None:
        self.wallet_type = wallet_data.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, parent_wallet, wallet_data)
        self.txin_type = 'p2sh'

    def get_pubkeys(self, c, i):
        return self.derive_pubkeys(c, i)

    def pubkeys_to_address(self, pubkeys):
        redeem_script = self.pubkeys_to_redeem_script(pubkeys)
        return P2SH_Address(hash160(redeem_script))

    def pubkeys_to_redeem_script(self, pubkeys):
        assert all(isinstance(pubkey, str) for pubkey in pubkeys)
        return P2MultiSig_Output(sorted(pubkeys), self.m).to_script_bytes()

    def derive_pubkeys(self, c, i):
        return [k.derive_pubkey(c, i) for k in self.get_keystores()]

    def _get_keystore_usage(self) -> List[Dict[str, Any]]:
        # Ensure that `get_keystores` returns a list sorted by name.
        # Note that this does not actually sort the keystores by numerical order, as 'x100/'
        # will come before 'x20/'...
        keystore_usage = super()._get_keystore_usage()
        return sorted(keystore_usage, key=lambda d: d['name'])

    def get_keystore(self):
        return super().get_keystore('x1/')

    def has_seed(self):
        return self.get_keystore().has_seed()

    def can_change_password(self):
        return self.get_keystore().can_change_password()

    def is_watching_only(self):
        return not any([not k.is_watching_only() for k in self.get_keystores()])

    def get_master_public_key(self):
        return self.get_keystore().get_master_public_key()

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))

    def _add_input_sig_info(self, txin):
        address = txin.address
        if self.is_mine(address):
            derivation = self.get_address_index(address)
            x_pubkeys = [k.get_xpubkey(*derivation) for k in self.get_keystores()]
            # Sort them using the order of the realized pubkeys
            sorted_pairs = sorted((x_pubkey.to_public_key_hex(), x_pubkey)
                                  for x_pubkey in x_pubkeys)
            txin.x_pubkeys = [x_pubkey for _hex, x_pubkey in sorted_pairs]
            txin.signatures = [NO_SIGNATURE] * len(x_pubkeys)
            txin.threshold = self.m


class LegacyWalletExpectedError(Exception):
    pass


class ParentWallet:
    _type: Optional[str] = None

    def __init__(self, storage: WalletStorage,
            creation_type: Optional[ParentWalletKinds]=None) -> None:
        self._storage = storage
        self._logger = logs.get_logger(f"wallet[{self.name()}]")

        self.tx_store_aeskey_bytes = bytes.fromhex(self._storage.get('tx_store_aeskey'))
        self.load_state(creation_type)

        self.contacts = Contacts(self._storage)

    @classmethod
    def as_legacy_wallet_container(klass, storage: WalletStorage) -> 'ParentWallet':
        return klass(storage, ParentWalletKinds.LEGACY)

    def load_state(self, creation_type: Optional[ParentWalletKinds]=None) -> None:
        self._type = self._storage.get("type", creation_type)
        assert creation_type is None or self._type == creation_type, \
            f"Parent wallet type conflict, got: {self._type}, expected: {creation_type}"

        keystore_datas = self._storage.get("keystores", [])
        self._keystores = [ None ] * len(keystore_datas)
        for i, keystore_data in enumerate(keystore_datas):
            self._keystores[i] = load_keystore(keystore_data)

        subwallet_datas = self._storage.get("subwallets", [])
        self._child_wallets = [ None ] * len(subwallet_datas)
        # This data is modified by reference at the moment.
        for subwallet_data in subwallet_datas:
            subwallet_id = subwallet_data["id"]
            self._child_wallets[subwallet_id] = self._create_child_wallet(subwallet_data)

    def name(self) -> str:
        return os.path.basename(self._storage.get_path())

    def get_storage_path(self) -> str:
        return self._storage.get_path()

    def get_storage(self) -> WalletStorage:
        return self._storage

    def save_storage(self) -> bool:
        self._storage.put("type", self._type)
        self._storage.put("keystores", [ ks.dump() for ks in self._keystores ])
        self._storage.put("subwallets", [ sw.dump() for sw in self._child_wallets ])
        self._storage.write()

    def get_wallet_datastore(self, wallet_id: int) -> WalletData:
        store = WalletData(self.get_storage_path(), self.tx_store_aeskey_bytes, wallet_id)
        return store

    def get_next_child_wallet_id(self) -> int:
        return len(self._child_wallets)

    def get_keystore(self, keystore_usage: Dict[str, Any]) -> KeyStore:
        keystore_index = keystore_usage['index']
        assert 'derivation_path' not in keystore_usage, 'Keystore derivations not supported yet'
        return self._keystores[keystore_index]

    def get_keystores(self) -> List[KeyStore]:
        return self._keystores[:]

    def is_encrypted(self) -> bool:
        return self._storage.is_encrypted()

    def has_password(self) -> bool:
        return self._storage.get('use_encryption', False)

    def check_password(self, password) -> None:
        self._keystores[0].check_password(password)

    def set_initial_password(self, new_pw: str) -> None:
        for keystore in self._keystores:
            if keystore.may_have_password():
                keystore.update_password(None, new_pw)
        self._storage.set_password(new_pw)

    def update_password(self, old_pw: Optional[str], new_pw: Optional[str], encrypt=False) -> None:
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        for keystore in self._keystores:
            if keystore.can_change_password():
                keystore.update_password(old_pw, new_pw)
        self._storage.set_password(new_pw)
        self._storage.write()

    def is_wrapped_legacy_wallet(self) -> bool:
        return self._type == ParentWalletKinds.LEGACY

    def contains_wallet(self, wallet: Abstract_Wallet) -> bool:
        return wallet in self.get_child_wallets()

    def get_wallet_for_account(self, account_id: int) -> Abstract_Wallet:
        return self._child_wallets[account_id]

    def get_wallet_for_address(self, address: Address) -> Abstract_Wallet:
        for wallet in self.get_child_wallets():
            if address in wallet.get_addresses():
                return wallet

    def get_wallets_for_keystore(self, keystore: KeyStore) -> List[Abstract_Wallet]:
        child_wallets = []
        for child_wallet in self.get_child_wallets():
            wallet_keystore = child_wallet.get_keystore()
            if keystore is wallet_keystore:
                child_wallets.append(child_wallet)
        return child_wallets

    def get_child_wallets(self) -> Iterable[Abstract_Wallet]:
        return self._child_wallets[:]

    def get_default_wallet(self) -> Abstract_Wallet:
        return self._child_wallets[0]

    def _create_child_wallet(self, wallet_data: Dict[str, Any]) -> Abstract_Wallet:
        wallet_constructors = {
            'standard': Standard_Wallet,
            'old': Standard_Wallet,
            'xpub': Standard_Wallet,
            'imported_privkey': ImportedPrivkeyWallet,
            'imported_addr': ImportedAddressWallet,
        }

        wallet_type = wallet_data.get('wallet_type')
        if multisig_type(wallet_type):
            return Multisig_Wallet(self, wallet_data)
        if wallet_type in wallet_constructors:
            return wallet_constructors[wallet_type](self, wallet_data)

        raise RuntimeError("Unknown wallet type: " + str(wallet_type))

    def add_child_wallet(self, child_wallet: Abstract_Wallet) -> None:
        self._child_wallets.append(child_wallet)

    def add_keystore(self, keystore_data: Dict[str, Any]) -> Dict[str, Any]:
        keystore = load_keystore(keystore_data)
        self._keystores.append(keystore)
        return {
            'index': len(self._keystores) - 1,
        }

    def has_usage(self) -> bool:
        "If there is any known usage of any child wallet."
        return any(w.has_usage() for w in self.get_child_wallets())

    def is_synchronized(self) -> bool:
        "If all the child wallets are synchronized"
        return all(w.is_synchronized() for w in self.get_child_wallets())

    def start(self, network: 'Network') -> None:
        for wallet in self.get_child_wallets():
            wallet.start(network)

    def stop(self) -> None:
        for wallet in self.get_child_wallets():
            wallet.stop()
        self._storage.write()

    def create_gui_handlers(self, window: 'ElectrumWindow') -> None:
        for wallet in self.get_child_wallets():
            for keystore in wallet.get_keystores():
                if isinstance(keystore, Hardware_KeyStore):
                    keystore.plugin.replace_gui_handler(window, keystore)
