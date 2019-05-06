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
from typing import Optional, Union, Tuple, List, Any

from aiorpcx import run_in_thread
from bitcoinx import PrivateKey, PublicKey, is_minikey

from . import coinchooser
from . import paymentrequest
from .address import Address, Script
from .app_state import app_state
from .bitcoin import COINBASE_MATURITY, TYPE_ADDRESS, scripthash_hex
from .contacts import Contacts
from .crypto import sha256d
from .exceptions import NotEnoughFunds, ExcessiveFee, UserCancelled, InvalidPassword
from .i18n import _
from .keystore import (
    load_keystore, Hardware_KeyStore, Imported_KeyStore, BIP32_KeyStore, xpubkey_to_address
)
from .logs import logs
from .networks import Net
from .paymentrequest import InvoiceStore
from .paymentrequest import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED
from .storage import multisig_type
from .transaction import Transaction
from .wallet_database import WalletData, TxInput, TxOutput, TxFlags, TxData, TxProof
from .util import profiler, format_satoshis, bh2u, format_time, timestamp_to_datetime
from .version import PACKAGE_VERSION
from .web import create_URI

logger = logs.get_logger("wallet")


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
        return {
            'address': self.address,
            'value': self.value,
            'prevout_n': self.out_index,
            'prevout_hash': self.tx_hash,
        }


def dust_threshold(network):
    return 546 # hard-coded Bitcoin SV dust threshold. Was changed to this as of Sept. 2018


def _append_utxos_to_inputs(inputs, get_utxos, pubkey, txin_type, imax):
    if txin_type == 'p2pkh':
        address = Address.from_pubkey(pubkey)
        sh = address.to_scripthash_hex()
    else:
        address = PublicKey.from_hex(pubkey)
        sh = scripthash_hex(address.P2PK_script())
    for item in get_utxos(sh):
        if len(inputs) >= imax:
            break
        item['address'] = address
        item['type'] = txin_type
        item['prevout_hash'] = item['tx_hash']
        item['prevout_n'] = item['tx_pos']
        item['pubkeys'] = [pubkey]
        item['x_pubkeys'] = [pubkey]
        item['signatures'] = [None]
        item['num_sig'] = 1
        inputs.append(item)

def sweep_preparations(privkeys, get_utxos, imax=100):

    def find_utxos_for_privkey(txin_type, privkey, compressed):
        pubkey = PrivateKey(privkey).public_key.to_hex(compressed=compressed)
        _append_utxos_to_inputs(inputs, get_utxos, pubkey, txin_type, imax)
        keypairs[pubkey] = privkey, compressed

    inputs = []
    keypairs = {}
    for sec in privkeys:
        privkey = PrivateKey.from_text(sec)
        privkey, compressed = privkey.to_bytes(), privkey.is_compressed()
        find_utxos_for_privkey('p2pkh', privkey, compressed)
        # do other lookups to increase support coverage
        if is_minikey(sec):
            # minikeys don't have a compressed byte
            # we lookup both compressed and uncompressed pubkeys
            find_utxos_for_privkey('p2pkh', privkey, not compressed)
        else:
            # WIF serialization does not distinguish p2pkh and p2pk
            # we also search for pay-to-pubkey outputs
            find_utxos_for_privkey('p2pk', privkey, compressed)
    if not inputs:
        raise Exception(_('No inputs found. (Note that inputs need to be confirmed)'))
    return inputs, keypairs


def sweep(privkeys, network, config, recipient, fee=None, imax=100):
    inputs, keypairs = sweep_preparations(privkeys, network.get_utxos, imax)
    total = sum(i.get('value') for i in inputs)
    if fee is None:
        outputs = [(TYPE_ADDRESS, recipient, total)]
        tx = Transaction.from_io(inputs, outputs)
        fee = config.estimate_fee(tx.estimated_size())
    if total - fee < 0:
        raise Exception(_('Not enough funds on address.') +
                        '\nTotal: %d satoshis\nFee: %d'%(total, fee))
    if total - fee < dust_threshold(network):
        raise Exception(_('Not enough funds on address.') +
                        '\nTotal: %d satoshis\nFee: %d\nDust Threshold: %d' %
                        (total, fee, dust_threshold(network)))

    outputs = [(TYPE_ADDRESS, recipient, total - fee)]
    locktime = network.get_local_height()

    tx = Transaction.from_io(inputs, outputs, locktime=locktime)
    tx.BIP_LI01_sort()
    tx.sign(keypairs)
    return tx


class Abstract_Wallet:
    """
    Wallet classes are created to handle various address generation methods.
    Completion states (watching-only, single account, no seed, etc) are handled inside classes.
    """

    max_change_outputs = 3

    def __init__(self, storage):
        self.storage = storage
        self.logger = logs.get_logger("wallet[{}]".format(self.basename()))
        self.electrum_version = PACKAGE_VERSION
        self.network = None

        # For synchronization.
        self._new_addresses = []
        self._new_addresses_lock = threading.Lock()
        self._new_addresses_event = app_state.async_.event()
        self._synchronize_event = app_state.async_.event()
        self._synchronized_event = app_state.async_.event()
        self.txs_changed_event = app_state.async_.event()

        self.gap_limit_for_change = 6  # constant
        # saved fields
        self.use_change            = storage.get('use_change', True)
        self.multiple_change       = storage.get('multiple_change', False)
        self.labels                = storage.get('labels', {})

        self.load_keystore()
        self.load_external_data()

        # load requests
        requests = self.storage.get('payment_requests', {})
        for key, req in requests.items():
            req['address'] = Address.from_string(key)
        self.receive_requests = {req['address']: req
                                 for req in requests.values()}

        # locks: if you need to take several, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()

        # save wallet type the first time
        if self.storage.get('wallet_type') is None:
            self.storage.put('wallet_type', self.wallet_type)

        # invoices and contacts
        self.invoices = InvoiceStore(self.storage)
        self.contacts = Contacts(self.storage)

        self._analyze_history()

    def save_storage(self):
        self.storage.write()

    def missing_transactions(self):
        '''Returns a set of tx_hashes.'''
        return self.db.tx.get_unsynced_ids()

    def unverified_transactions(self):
        '''Returns a map of tx_hash to tx_height.'''
        results = self.db.tx.get_unverified_entries(self.get_local_height())
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
        return self.basename()

    def get_master_public_key(self):
        return None

    def create_gui_handlers(self, window):
        for keystore in self.get_keystores():
            if isinstance(keystore, Hardware_KeyStore):
                keystore.plugin.replace_gui_handler(window, keystore)

    @profiler
    def load_external_data(self):
        tx_store_aeskey_bytes = bytes.fromhex(self.storage.get('tx_store_aeskey'))
        self.db = WalletData(self.storage.path, tx_store_aeskey_bytes)

        self.pending_txs = self.db.tx.get_transactions(TxFlags.StateSigned, TxFlags.STATE_MASK)

        # address -> list(txid, height)
        addr_history = self.db.misc.get_value('addr_history')
        self._history = self.to_Address_dict(addr_history) if addr_history is not None else {}

        pruned_txo = self.db.misc.get_value('pruned_txo')
        self.pruned_txo = {} if pruned_txo is None else pruned_txo

        # Frozen addresses
        self._frozen_addresses = set([])
        frozen_addresses = self.db.misc.get_value('frozen_addresses')
        if frozen_addresses is not None:
            self._frozen_addresses = set(Address.from_string(addr) for addr in frozen_addresses)

        # Frozen coins (UTXOs) -- note that we have 2 independent
        # levels of "freezing": address-level and coin-level.  The two
        # types of freezing are flagged independently of each other
        # and 'spendable' is defined as a coin that satisfies BOTH
        # levels of freezing.
        frozen_coins = self.db.misc.get_value('frozen_coins')
        self.logger.debug("frozen_coins %r", frozen_coins)
        self._frozen_coins = (set(tuple(v) for v in frozen_coins)
            if frozen_coins is not None else set([]))

        # What is persisted here differs depending on the wallet type.
        self.load_addresses(self.db.misc.get_value('addresses'))

        # If there was no address history entry we can take this as representative that there
        # are no other entries because the wallet has not been saved yet. This is not the case
        # with addresses, but otherwise so.
        self._insert = addr_history is None
        self.logger.debug("load_external_data insert=%r", self._insert)

    @profiler
    def save_external_data(self):
        with self.transaction_lock:
            if self._insert:
                save_func = self.db.misc.add
            else:
                save_func = self.db.misc.update

            save_func('pruned_txo', self.pruned_txo)
            save_func('frozen_addresses',
                list(addr.to_string() for addr in self._frozen_addresses))
            save_func('frozen_coins', list(self._frozen_coins))
            save_func('addr_history', self.from_Address_dict(self._history))
            # What is persisted here differs depending on the wallet type.
            address_data = self.save_addresses()
            if address_data is not None:
                save_func('addresses', address_data)

    def get_txins(self, tx_id: str, address: Optional[Address]=None) -> List[TxInput]:
        entries = self.db.txin.get_entries(tx_id)
        if address is None:
            return entries
        address_string = address.to_string()
        return [ v for v in entries if v.address_string == address_string ]

    def get_txouts(self, tx_id: str, address: Optional[str]=None) -> List[TxOutput]:
        entries = self.db.txout.get_entries(tx_id)
        if address is None:
            return entries
        address_string = address.to_string()
        return [ v for v in entries if v.address_string == address_string ]

    @profiler
    def get_transaction(self, tx_id: str, flags: Optional[int]=None) -> Optional[Transaction]:
        return self.db.tx.get_transaction(tx_id, flags)

    def has_received_transaction(self, tx_id: str) -> bool:
        flags = self.db.tx.get_flags(tx_id)
        return flags is not None and (flags & TxFlags.StateSettled) != 0

    def basename(self) -> str:
        return os.path.basename(self.storage.path)

    def save_addresses(self) -> dict:
        return {
            'receiving': [addr.to_string() for addr in self.receiving_addresses],
            'change': [addr.to_string() for addr in self.change_addresses],
        }

    def load_addresses(self, data: dict) -> None:
        if data is None:
            data = {}
        self.receiving_addresses = Address.from_strings(data.get('receiving', []))
        self.change_addresses = Address.from_strings(data.get('change', []))

    def is_deterministic(self):
        return self.keystore.is_deterministic()

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
            self.storage.put('labels', self.labels)

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
        secret, compressed = self.keystore.get_private_key(index, password)
        return PrivateKey(secret).to_WIF(compressed=compressed, coin=Net.COIN)

    def get_public_keys(self, address: Address):
        sequence = self.get_address_index(address)
        return self.get_pubkeys(*sequence)

    def add_verified_tx(self, tx_hash, height, timestamp, position, proof_position, proof_branch):
        entry = self.db.tx.get_entry(tx_hash, TxFlags.StateSettled)
        if entry is None:
            self.logger.debug("Attempting to clear unsettled tx %s", tx_hash)
            return
        # We only update a subset.
        flags = TxFlags.HasHeight | TxFlags.HasTimestamp | TxFlags.HasPosition
        data = TxData(height=height, timestamp=timestamp, position=position)
        self.db.tx.update([ (tx_hash, data, None, flags | TxFlags.StateCleared) ])

        proof = TxProof(proof_position, proof_branch)
        self.db.tx.update_proof(tx_hash, proof)

        height, conf, timestamp = self.get_tx_height(tx_hash)
        self.logger.debug("add_verified_tx %d %d %d", height, conf, timestamp)
        self.network.trigger_callback('verified', tx_hash, height, conf, timestamp)

    def undo_verifications(self, above_height):
        '''Used by the verifier when a reorg has happened'''
        with self.lock:
            reorg_count = self.db.tx.delete_reorged_entries(above_height)
            self.logger.info(f'removing verification of {reorg_count} transactions')

    def get_local_height(self):
        """ return last known height if we are offline """
        return (self.network.get_local_height() if self.network else
                self.storage.get('stored_height', 0))

    def get_tx_height(self, tx_hash):
        """ return the height and timestamp of a verified transaction. """
        with self.lock:
            metadata = self.db.tx.get_metadata(tx_hash)
            assert metadata.height is not None
            if metadata.timestamp is not None:
                conf = max(self.get_local_height() - metadata.height + 1, 0)
                return metadata.height, conf, metadata.timestamp
            else:
                return metadata.height, 0, False

    def get_txpos(self, tx_hash):
        "return position, even if the tx is unverified"
        with self.lock:
            metadata = self.db.tx.get_metadata(tx_hash)
            if metadata.timestamp is not None:
                return metadata.height, metadata.position
            elif metadata.height is not None:
                # TODO: Look into whether entry.height is ever < 0
                return ((metadata.height, 0)
                    if metadata.height > 0 else ((1e9 - metadata.height), 0))
            else:
                return (1e9+1, 0)

    def is_found(self):
        return any(value for value in self._history.values())

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
        for item in tx.inputs():
            addr = item['address']
            if addr in addresses:
                is_mine = True
                is_relevant = True
                for txout in self.get_txouts(item['prevout_hash'], addr):
                    if txout.out_tx_n == item['prevout_n']:
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
        for addr, value in tx.get_outputs():
            v_out += value
            if addr in addresses:
                v_out_mine += value
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
                        fee = self.db.tx.get_metadata(tx_hash).fee
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
                sent[(txin.prevout_tx_hash, txin.prevout_n)] = height
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

        address_script = address.to_script()
        return [UTXO(value=value,
                     script_pubkey=address_script,
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
        self._process_transaction(tx_hash, tx, add=True)

    def update_transaction(self, tx_hash: str, tx: Transaction) -> None:
        self._process_transaction(tx_hash, tx)

    def _process_transaction(self, tx_hash: str, tx: Transaction,
            add: Optional[bool]=False) -> None:
        is_coinbase = tx.inputs()[0]['type'] == 'coinbase'
        with self.transaction_lock:
            # We batch the adding of inputs and outputs as it is a thousand times faster.
            txins = []
            txouts = []

            # add inputs
            for tx_input in tx.inputs():
                address = tx_input.get('address')
                if not self.is_mine(address):
                    continue
                if tx_input['type'] != 'coinbase':
                    prevout_hash = tx_input['prevout_hash']
                    prevout_n = tx_input['prevout_n']
                # find value from prev output
                match = next((row for row in self.get_txouts(prevout_hash, address)
                     if row.out_tx_n == prevout_n), None)
                if match is not None:
                    txin = TxInput(address.to_string(), prevout_hash, prevout_n, match.amount)
                    txins.append((tx_hash, txin))
                else:
                    self.pruned_txo[(prevout_hash, prevout_n)] = tx_hash

            # add outputs
            for n, txo in enumerate(tx.outputs()):
                _type, address, value = txo
                if self.is_mine(address):
                    txout = TxOutput(address.to_string(), n, value, is_coinbase)
                    txouts.append((tx_hash, txout))

                # give the value to txi that spends me
                next_tx_hash = self.pruned_txo.get((tx_hash, n))
                if next_tx_hash is not None:
                    self.pruned_txo.pop((tx_hash, n))

                    txin = TxInput(address.to_string(), tx_hash, n, value)
                    txins.append((next_tx_hash, txin))

            if len(txins):
                self.db.txin.add_entries(txins)
            if len(txouts):
                self.db.txout.add_entries(txouts)

            # Save the underlying transaction if we know it should be new and not present.
            # It is possible we may need to update even in the update cases, but that implies
            # knowing that uses intend it, and we do not know that at this time.
            if add:
                self.logger.debug("updating tx data %s", tx_hash)
                self.db.tx.add_transaction(tx, TxFlags.StateSettled)

    # Used by ImportedWalletBase
    def _remove_transaction(self, tx_hash: str) -> None:
        with self.transaction_lock:
            self.logger.debug("removing tx from history %s", tx_hash)

            for out_key, next_tx_hash in list(self.pruned_txo.items()):
                if next_tx_hash == tx_hash:
                    self.pruned_txo.pop(out_key)

            # add tx to pruned_txo, and undo the txi addition
            removal_txins = []
            for txin_hash, txin in self.db.txin.get_all_entries().items():
                if txin.prevout_tx_hash == tx_hash:
                    removal_txins.append((tx_hash, txin))
                    self.pruned_txo[(txin.prevout_tx_hash, txin.prevout_n)] = txin_hash

            removal_txins.extend(self.get_txins(tx_hash))
            if len(removal_txins):
                self.db.txin.delete_entries(removal_txins)

            removal_txouts = self.get_txouts(tx_hash)
            if len(removal_txouts):
                self.db.txout.delete_entries(removal_txouts)

    async def set_address_history(self, addr, hist, tx_fees):
        with self.lock:
            self._history[addr] = hist # { address: (tx_hash, tx_height) }

            tx_ids = set(t[0] for t in hist)
            updates = []
            for tx_hash, tx_height in hist:
                tx_fee = tx_fees.get(tx_hash, None)
                data = TxData(height=tx_height, fee=tx_fee)
                flags = TxFlags.HasHeight
                if tx_fee is not None:
                    flags |= TxFlags.HasFee
                updates.append((tx_hash, data, None, flags))
            self.db.tx.update_or_add(updates)

            for tx_id in tx_ids:
                # if addr is new, we have to recompute txi and txo
                tx = self.get_transaction(tx_hash)
                if (tx is not None and not len(self.get_txins(tx_hash, addr)) and
                        not len(self.get_txouts(tx_hash, addr))):
                    self.update_transaction(tx_hash, tx)

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
                tx.deserialize()
                input_addresses = []
                output_addresses = []
                for x in tx.inputs():
                    if x['type'] == 'coinbase': continue
                    addr = x.get('address')
                    if addr is None: continue
                    input_addresses.append(addr.to_string())
                for addr, v in tx.get_outputs():
                    output_addresses.append(addr.to_string())
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

    def make_unsigned_transaction(self, inputs, outputs, config, fixed_fee: Optional[int]=None,
                                  change_addr: Optional[Address]=None) -> Transaction:
        # check outputs
        i_max = None
        for i, o in enumerate(outputs):
            _type, data, value = o
            if value == '!':
                if i_max is not None:
                    raise Exception("More than one output set to spend max")
                i_max = i

        # Avoid index-out-of-range with inputs[0] below
        if not inputs:
            raise NotEnoughFunds()

        if fixed_fee is None and config.fee_per_kb() is None:
            raise Exception('Dynamic fee estimates not available')

        inputs = [item.to_tx_input() if isinstance(item, UTXO) else item for item in inputs]
        for item in inputs:
            self._add_input_info(item)

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

        if i_max is None:
            # Let the coin chooser select the coins to spend
            max_change = self.max_change_outputs if self.multiple_change else 1
            coin_chooser = coinchooser.CoinChooserPrivacy()
            tx = coin_chooser.make_tx(inputs, outputs, change_addrs[:max_change],
                                      fee_estimator, self.dust_threshold())
        else:
            sendable = sum(x['value'] for x in inputs)
            _type, data, value = outputs[i_max]
            outputs[i_max] = (_type, data, 0)
            tx = Transaction.from_io(inputs, outputs)
            fee = fee_estimator(tx.estimated_size())
            amount = max(0, sendable - tx.output_value() - fee)
            outputs[i_max] = (_type, data, amount)
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

    def set_frozen_state(self, addrs, freeze) -> bool:
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

    def _analyze_history(self):
        bad_addrs = [addr for addr in self._history if not self.is_mine(addr)]
        for addr in bad_addrs:
            self._history.pop(addr)

        for hist in self._history.values():
            for tx_hash, tx_height in hist:
                if (len(self.get_txouts(tx_hash)) or len(self.get_txins(tx_hash)) or
                        tx_hash in self.pruned_txo.values()):
                    continue
                tx = self.get_transaction(tx_hash)
                if tx is not None:
                    self.add_transaction(tx_hash, tx)

    def start(self, network):
        self.network = network
        if network:
            network.add_wallet(self)

    def stop(self):
        self.logger.debug(f'stopping wallet {self}')
        if self.network:
            self.network.remove_wallet(self)
            self.storage.put('stored_height', self.get_local_height())
            self.network = None
        self.save_external_data()
        self.storage.write()

    def can_export(self):
        return not self.is_watching_only() and hasattr(self.keystore, 'get_private_key')

    def is_used(self, address):
        return self.get_address_history(address) and not self.is_empty(address)

    def is_empty(self, address):
        assert isinstance(address, Address)
        return any(self.get_addr_balance(address))

    def cpfp(self, tx, fee):
        txid = tx.txid()
        for output_index, txout in enumerate(tx.outputs()):
            otype, address, value = txout
            if otype == TYPE_ADDRESS and self.is_mine(address):
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
        self._add_input_info(txin)
        inputs = [txin]
        outputs = [(TYPE_ADDRESS, address, value - fee)]
        locktime = self.get_local_height()
        # note: no need to call tx.BIP_LI01_sort() here - single input/output
        return Transaction.from_io(inputs, outputs, locktime=locktime)

    def _add_input_info(self, txin):
        address = txin['address']
        if self.is_mine(address):
            txin['type'] = self.get_txin_type(address)
            if 'value' not in txin:
                # Bitcoin SV needs value to sign
                received_amount = 0
                received, _spent = self._get_addr_io(address)
                item = received.get((txin['prevout_hash'], txin['prevout_n']))
                txin['value'] = item[1]
            self._add_input_sig_info(txin, address)

    def can_sign(self, tx):
        if tx.is_complete():
            return False
        for k in self.get_keystores():
            # setup "wallet advice" so Xpub wallets know how to sign 'fd' type tx inputs
            # by giving them the sequence number ahead of time
            if isinstance(k, BIP32_KeyStore):
                for txin in tx.inputs():
                    for x_pubkey in txin['x_pubkeys']:
                        _, addr = xpubkey_to_address(x_pubkey)
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
            tx = Transaction(tx_hex)
        return tx

    def add_input_values_to_tx(self, tx):
        """ add input values to the tx, for signing"""
        for txin in tx.inputs():
            if 'value' not in txin:
                inputtx = self.get_input_tx(txin['prevout_hash'])
                if inputtx is not None:
                    out_zero, out_addr, out_val = inputtx.outputs()[txin['prevout_n']]
                    txin['value'] = out_val
                    txin['prev_tx'] = inputtx   # may be needed by hardware wallets

    def add_hw_info(self, tx):
        for txin in tx.inputs():
            if 'prev_tx' not in txin:
                txin['prev_tx'] = self.get_input_tx(txin['prevout_hash'])
        # add output info for hw wallets
        info = {}
        xpubs = self.get_master_public_keys()
        for txout in tx.outputs():
            _type, addr, amount = txout
            if self.is_mine(addr):
                index = self.get_address_index(addr)
                pubkeys = self.get_public_keys(addr)
                # sort xpubs using the order of pubkeys
                sorted_pubkeys, sorted_xpubs = zip(*sorted(zip(pubkeys, xpubs)))
                info[addr] = (index, sorted_xpubs, self.m if isinstance(self, Multisig_Wallet)
                              else None)
        logger.debug(f'add_hw_info: {info}')
        tx.output_info = info

    def sign_transaction(self, tx: Transaction, password: str) -> None:
        if self.is_watching_only():
            return
        # add input values for signing
        self.add_input_values_to_tx(tx)
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
        return [addr for addr in domain
                if not self.get_address_history(addr)
                and addr not in self.receive_requests]

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
            tx_height = self.db.tx.get_height(tx_id)
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
        self.storage.put('payment_requests', requests)
        self.storage.write()

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
                return self.get_address_index(addr) or addr
            except:
                return addr
        return sorted((self.get_payment_request(x, config) for x in self.receive_requests), key=f)

    def get_fingerprint(self):
        raise NotImplementedError()

    def can_import_privkey(self):
        return False

    def can_import_address(self):
        return False

    def can_delete_address(self):
        return False

    def _add_new_addresses(self, addresses, *, save=True):
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

    async def new_addresses(self):
        await self._new_addresses_event.wait()
        self._new_addresses_event.clear()
        with self._new_addresses_lock:
            result = self._new_addresses
            self._new_addresses = []
        return result

    def has_password(self):
        return self.storage.get('use_encryption', False)

    def check_password(self, password):
        self.keystore.check_password(password)

    def sign_message(self, address, message, password):
        index = self.get_address_index(address)
        return self.keystore.sign_message(index, message, password)

    def decrypt_message(self, pubkey, message, password):
        addr = self.pubkeys_to_address(pubkey)
        index = self.get_address_index(addr)
        return self.keystore.decrypt_message(index, message, password)


class Simple_Wallet(Abstract_Wallet):
    # wallet with a single keystore

    def get_keystore(self):
        return self.keystore

    def get_keystores(self):
        return [self.keystore]

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        # Watching only wallets are the non-keystore case.
        if self.keystore is not None:
            self.keystore.update_password(old_pw, new_pw)
            self.save_keystore()
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())


class ImportedWalletBase(Simple_Wallet):

    txin_type = 'p2pkh'

    def get_txin_type(self, address):
        return self.txin_type

    def can_delete_address(self):
        return True

    def has_seed(self):
        return False

    def is_deterministic(self):
        return False

    def is_change(self, address):
        return False

    def get_master_public_keys(self):
        return []

    def is_beyond_limit(self, address, is_change):
        return False

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

    def __init__(self, storage):
        self._sorted = None
        super().__init__(storage)

    @classmethod
    def from_text(cls, storage, text):
        wallet = cls(storage)
        for address in text.split():
            wallet.import_address(Address.from_string(address))
        # Avoid adding addresses twice in network.py
        wallet._new_addresses.clear()
        return wallet

    def is_watching_only(self):
        return True

    def get_keystores(self):
        return []

    def can_import_privkey(self):
        return False

    def load_keystore(self):
        self.keystore = None

    def save_keystore(self):
        pass

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
            self._sorted = sorted(self.addresses, key=Address.to_string)
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

    def _add_input_sig_info(self, txin, address):
        x_pubkey = 'fd' + address.to_script_hex()
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]


class ImportedPrivkeyWallet(ImportedWalletBase):
    # wallet made of imported private keys

    wallet_type = 'imported_privkey'

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)

    @classmethod
    def from_text(cls, storage, text, password=None):
        wallet = cls(storage)
        storage.put('use_encryption', bool(password))
        for privkey in text.split():
            wallet.import_private_key(privkey, password)
        # Avoid adding addresses twice in network.py
        wallet._new_addresses.clear()
        return wallet

    def is_watching_only(self):
        return False

    def get_keystores(self):
        return [self.keystore]

    def can_import_privkey(self):
        return True

    def load_keystore(self):
        if self.storage.get('keystore'):
            self.keystore = load_keystore(self.storage, 'keystore')
        else:
            self.keystore = Imported_KeyStore({})

    def save_keystore(self):
        self.storage.put('keystore', self.keystore.dump())

    def load_addresses(self, data: Any) -> None:
        pass

    def save_addresses(self) -> None:
        return None

    def can_change_password(self):
        return True

    def can_import_address(self):
        return False

    def get_addresses(self, include_change=False):
        return self.keystore.get_addresses()

    def delete_address_derived(self, address):
        self.keystore.remove_address(address)
        self.save_keystore()

    def get_address_index(self, address):
        return self.get_public_key(address)

    def get_public_key(self, address):
        return self.keystore.address_to_pubkey(address)

    def import_private_key(self, sec, pw):
        pubkey = self.keystore.import_privkey(sec, pw)
        self.save_keystore()
        self.storage.write()
        address_str = pubkey.to_address(coin=Net.COIN).to_string()
        self._add_new_addresses([Address.from_string(address_str)])
        return address_str

    def export_private_key(self, address, password):
        '''Returned in WIF format.'''
        pubkey = self.keystore.address_to_pubkey(address)
        return self.keystore.export_private_key(pubkey, password)

    def _add_input_sig_info(self, txin, address):
        assert txin['type'] == 'p2pkh'
        pubkey = self.keystore.address_to_pubkey(address)
        txin['num_sig'] = 1
        txin['x_pubkeys'] = [pubkey.to_hex()]
        txin['signatures'] = [None]

    def pubkeys_to_address(self, pubkey):
        pubkey = PublicKey.from_hex(pubkey)
        if pubkey in self.keystore.keypairs:
            return Address.from_string(pubkey.to_address(coin=Net.COIN).to_string())


class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)
        self.gap_limit = storage.get('gap_limit', 20)

    def has_seed(self):
        return self.keystore.has_seed()

    def get_receiving_addresses(self):
        return self.receiving_addresses

    def get_change_addresses(self):
        return self.change_addresses

    def get_seed(self, password):
        return self.keystore.get_seed(password)

    def change_gap_limit(self, value):
        '''This method is not called in the code, it is kept for console use'''
        if value >= self.gap_limit:
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
            return True
        elif value >= self.min_acceptable_gap():
            addresses = self.get_receiving_addresses()
            k = self.num_unused_trailing_addresses(addresses)
            n = len(addresses) - k + value
            self.receiving_addresses = self.receiving_addresses[0:n]
            self.gap_limit = value
            self.storage.put('gap_limit', self.gap_limit)
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

    def is_beyond_limit(self, address, is_change):
        if is_change:
            addr_list = self.get_change_addresses()
            limit = self.gap_limit_for_change
        else:
            addr_list = self.get_receiving_addresses()
            limit = self.gap_limit
        idx = addr_list.index(address)
        ref_idx = idx - limit
        if ref_idx < 0:
            return False
        addresses = addr_list[ref_idx: idx]
        # This isn't really right but it's good enough for now and not entirely broken...
        return all(not self._history.get(addr) for addr in addresses)

    def get_master_public_keys(self):
        return [self.get_master_public_key()]

    def get_fingerprint(self):
        return self.get_master_public_key()

    def get_txin_type(self, address):
        return self.txin_type


class Simple_Deterministic_Wallet(Simple_Wallet, Deterministic_Wallet):

    """ Deterministic Wallet with a single pubkey per address """

    def __init__(self, storage):
        Deterministic_Wallet.__init__(self, storage)

    def get_public_key(self, address):
        sequence = self.get_address_index(address)
        pubkey = self.get_pubkey(*sequence)
        return pubkey

    def load_keystore(self):
        self.keystore = load_keystore(self.storage, 'keystore')
        self.txin_type = 'p2pkh'

    def get_pubkey(self, c, i):
        return self.derive_pubkeys(c, i)

    def get_public_keys(self, address):
        return [self.get_public_key(address)]

    def _add_input_sig_info(self, txin, address):
        derivation = self.get_address_index(address)
        x_pubkey = self.keystore.get_xpubkey(*derivation)
        txin['x_pubkeys'] = [x_pubkey]
        txin['signatures'] = [None]
        txin['num_sig'] = 1

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def derive_pubkeys(self, c, i):
        return self.keystore.derive_pubkey(c, i)






class Standard_Wallet(Simple_Deterministic_Wallet):
    wallet_type = 'standard'

    def pubkeys_to_address(self, pubkey):
        return Address.from_pubkey(pubkey)


class Multisig_Wallet(Deterministic_Wallet):
    # generic m of n
    gap_limit = 20

    def __init__(self, storage):
        self.wallet_type = storage.get('wallet_type')
        self.m, self.n = multisig_type(self.wallet_type)
        Deterministic_Wallet.__init__(self, storage)

    def get_pubkeys(self, c, i):
        return self.derive_pubkeys(c, i)

    def pubkeys_to_address(self, pubkeys):
        pubkeys = [bytes.fromhex(pubkey) for pubkey in pubkeys]
        redeem_script = self.pubkeys_to_redeem_script(pubkeys)
        return Address.from_multisig_script(redeem_script)

    def pubkeys_to_redeem_script(self, pubkeys):
        return Script.multisig_script(self.m, sorted(pubkeys))

    def derive_pubkeys(self, c, i):
        return [k.derive_pubkey(c, i) for k in self.get_keystores()]

    def load_keystore(self):
        self.keystores = {}
        for i in range(self.n):
            name = 'x%d/'%(i+1)
            self.keystores[name] = load_keystore(self.storage, name)
        self.keystore = self.keystores['x1/']
        self.txin_type = 'p2sh'

    def save_keystore(self):
        for name, k in self.keystores.items():
            self.storage.put(name, k.dump())

    def get_keystore(self):
        return self.keystores.get('x1/')

    def get_keystores(self):
        return [self.keystores[i] for i in sorted(self.keystores.keys())]

    def update_password(self, old_pw, new_pw, encrypt=False):
        if old_pw is None and self.has_password():
            raise InvalidPassword()
        for name, keystore in self.keystores.items():
            if keystore.can_change_password():
                keystore.update_password(old_pw, new_pw)
                self.storage.put(name, keystore.dump())
        self.storage.set_password(new_pw, encrypt)
        self.storage.write()

    def has_seed(self):
        return self.keystore.has_seed()

    def can_change_password(self):
        return self.keystore.can_change_password()

    def is_watching_only(self):
        return not any([not k.is_watching_only() for k in self.get_keystores()])

    def get_master_public_key(self):
        return self.keystore.get_master_public_key()

    def get_master_public_keys(self):
        return [k.get_master_public_key() for k in self.get_keystores()]

    def get_fingerprint(self):
        return ''.join(sorted(self.get_master_public_keys()))

    def _add_input_sig_info(self, txin, address):
        # x_pubkeys are not sorted here because it would be too slow
        # they are sorted in transaction.get_sorted_pubkeys
        derivation = self.get_address_index(address)
        txin['x_pubkeys'] = [k.get_xpubkey(*derivation) for k in self.get_keystores()]
        txin['pubkeys'] = None
        # we need n place holders
        txin['signatures'] = [None] * self.n
        txin['num_sig'] = self.m


wallet_types = ['standard', 'multisig', 'imported']

wallet_constructors = {
    'standard': Standard_Wallet,
    'old': Standard_Wallet,
    'xpub': Standard_Wallet,
    'imported_privkey': ImportedPrivkeyWallet,
    'imported_addr': ImportedAddressWallet,
}

def register_constructor(wallet_type, constructor):
    wallet_constructors[wallet_type] = constructor

# former WalletFactory
class Wallet(object):
    """The main wallet "entry point".
    This class is actually a factory that will return a wallet of the correct
    type when passed a WalletStorage instance."""

    def __new__(self, storage):
        wallet_type = storage.get('wallet_type')
        WalletClass = Wallet.wallet_class(wallet_type)
        return WalletClass(storage)

    @staticmethod
    def wallet_class(wallet_type):
        if multisig_type(wallet_type):
            return Multisig_Wallet
        if wallet_type in wallet_constructors:
            return wallet_constructors[wallet_type]
        raise RuntimeError("Unknown wallet type: " + str(wallet_type))
