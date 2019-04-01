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
import copy
import errno
import itertools
import json
import os
import random
import threading
import time
from typing import Optional, Union, Tuple

from aiorpcx import run_in_thread
from bitcoinx import PrivateKey

from . import bitcoin
from . import coinchooser
from . import paymentrequest
from .address import Address, Script, PublicKey
from .app_state import app_state
from .bitcoin import COINBASE_MATURITY, TYPE_ADDRESS, is_minikey
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
from .transaction_store import TransactionStore
from .util import profiler, format_satoshis, bh2u, format_time, timestamp_to_datetime
from .version import PACKAGE_VERSION
from .web import create_URI

logger = logs.get_logger("wallet")

TX_STATUS = [
    _('Unconfirmed parent'),
    _('Unconfirmed'),
    _('Not Verified'),
]


TxInfo = namedtuple('TxInfo', 'hash status label can_broadcast amount '
                    'fee height conf timestamp')


def dust_threshold(network):
    return 546 # hard-coded Bitcoin SV dust threshold. Was changed to this as of Sept. 2018


def _append_utxos_to_inputs(inputs, get_utxos, pubkey, txin_type, imax):
    if txin_type == 'p2pkh':
        address = Address.from_pubkey(pubkey)
    else:
        address = PublicKey.from_pubkey(pubkey)
    sh = address.to_scripthash_hex()
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
        txin_type, privkey, compressed = bitcoin.deserialize_privkey(sec)
        find_utxos_for_privkey(txin_type, privkey, compressed)
        # do other lookups to increase support coverage
        if is_minikey(sec):
            # minikeys don't have a compressed byte
            # we lookup both compressed and uncompressed pubkeys
            find_utxos_for_privkey(txin_type, privkey, not compressed)
        elif txin_type == 'p2pkh':
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
        # Frozen addresses
        frozen_addresses = storage.get('frozen_addresses',[])
        self.frozen_addresses = set(Address.from_string(addr)
                                    for addr in frozen_addresses)
        # Frozen coins (UTXOs) -- note that we have 2 independent
        # levels of "freezing": address-level and coin-level.  The two
        # types of freezing are flagged independently of each other
        # and 'spendable' is defined as a coin that satisfies BOTH
        # levels of freezing.
        self.frozen_coins = set(storage.get('frozen_coins', []))
        # address -> list(txid, height)
        self._history = self.to_Address_dict(storage.get('addr_history',{}))

        self.load_keystore()
        self.load_addresses()
        self.load_transactions()

        # load requests
        requests = self.storage.get('payment_requests', {})
        for key, req in requests.items():
            req['address'] = Address.from_string(key)
        self.receive_requests = {req['address']: req
                                 for req in requests.values()}

        # In-memory tx_hash -> tx_height map.  Use self.lock
        self.hh_map = {}

        # Verified transactions.  Each value is a (height, timestamp, block_pos) tuple.
        # Access with self.lock.
        self.verified_tx = storage.get('verified_tx3', {})

        # locks: if you need to take several, acquire them in the order they are defined here!
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()

        # save wallet type the first time
        if self.storage.get('wallet_type') is None:
            self.storage.put('wallet_type', self.wallet_type)

        # invoices and contacts
        self.invoices = InvoiceStore(self.storage)
        self.contacts = Contacts(self.storage)

        self.analyze_history()

    def missing_transactions(self):
        '''Returns a set of tx_hashes.'''
        with self.lock:
            return set(self.hh_map).difference(self.transactions)

    def unverified_transactions(self):
        '''Returns a map of tx_hash to tx_height.'''
        hh_map = self.hh_map
        local_height = self.get_local_height()
        with self.lock:
            return {tx_hash: hh_map[tx_hash]
                    for tx_hash in set(hh_map).difference(self.verified_tx)
                    if 0 < hh_map[tx_hash] <= local_height}

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
    def load_transactions(self):
        txi = self.storage.get('txi', {})
        self.txi = {tx_hash: self.to_Address_dict(value)
                    for tx_hash, value in txi.items()}
        txo = self.storage.get('txo', {})
        self.txo = {tx_hash: self.to_Address_dict(value)
                    for tx_hash, value in txo.items()}
        self.tx_fees = self.storage.get('tx_fees', {})
        self.pruned_txo = self.storage.get('pruned_txo', {})
        tx_list = self.storage.get('transactions', {})
        from .transaction_store import TransactionStore
        wallet_tx_ids = set(self.txi) | set(self.txo) | set(self.pruned_txo.values())
        self.transactions = TransactionStore(wallet_tx_ids)
        for tx_hash, raw in tx_list.items():
            tx = Transaction(raw)
            self.transactions[tx_hash] = tx
            if not any((tx_hash in self.txi, tx_hash in self.txo, tx_hash
                        in self.pruned_txo.values())):
                self.logger.debug("removing unreferenced tx %s", tx_hash)
                self.transactions.pop(tx_hash)
        self.storage.put('transactions', {})

    @profiler
    def save_transactions(self, write=False):
        with self.transaction_lock:
            if not isinstance(self.transactions, TransactionStore):
                tx = {}
                for k,v in self.transactions.items():
                    tx[k] = str(v)
                self.storage.put('transactions', tx)
            txi = {tx_hash: self.from_Address_dict(value)
                   for tx_hash, value in self.txi.items()}
            txo = {tx_hash: self.from_Address_dict(value)
                   for tx_hash, value in self.txo.items()}
            self.storage.put('txi', txi)
            self.storage.put('txo', txo)
            self.storage.put('tx_fees', self.tx_fees)
            self.storage.put('pruned_txo', self.pruned_txo)
            history = self.from_Address_dict(self._history)
            self.storage.put('addr_history', history)
            if write:
                self.storage.write()

    def save_verified_tx(self, write=False):
        with self.lock:
            self.storage.put('verified_tx3', self.verified_tx)
            if write:
                self.storage.write()

    def basename(self) -> str:
        return os.path.basename(self.storage.path)

    def save_addresses(self) -> None:
        addr_dict = {
            'receiving': [addr.to_string() for addr in self.receiving_addresses],
            'change': [addr.to_string() for addr in self.change_addresses],
        }
        self.storage.put('addresses', addr_dict)

    def load_addresses(self) -> None:
        d = self.storage.get('addresses', {})
        if not isinstance(d, dict):
            d = {}
        self.receiving_addresses = Address.from_strings(d.get('receiving', []))
        self.change_addresses = Address.from_strings(d.get('change', []))

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

    def is_mine(self, address) -> bool:
        assert not isinstance(address, str)
        return address in self.get_addresses()

    def is_change(self, address) -> bool:
        assert not isinstance(address, str)
        return address in self.change_addresses

    def get_address_index(self, address) -> Tuple[bool, int]:
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

    def export_private_key(self, address, password):
        """ extended WIF format """
        if self.is_watching_only():
            return []
        index = self.get_address_index(address)
        secret, compressed = self.keystore.get_private_key(index, password)
        return PrivateKey(secret).to_WIF(compressed=compressed, coin=Net.COIN)

    def get_public_keys(self, address):
        sequence = self.get_address_index(address)
        return self.get_pubkeys(*sequence)

    def add_verified_tx(self, tx_hash, info):
        # Remove from the unverified map and add to the verified map and
        with self.lock:
            self.verified_tx[tx_hash] = info  # (tx_height, timestamp, pos)
        height, conf, timestamp = self.get_tx_height(tx_hash)
        self.network.trigger_callback('verified', tx_hash, height, conf, timestamp)

    def undo_verifications(self, above_height):
        '''Used by the verifier when a reorg has happened'''
        with self.lock:
            for tx_hash, item in self.verified_tx.items():
                tx_height, timestamp, pos = item
                if tx_height > above_height:
                    self.logger.info(f'removing verification of {tx_hash}')
                    self.verified_tx.pop(tx_hash)

    def get_local_height(self):
        """ return last known height if we are offline """
        return (self.network.get_local_height() if self.network else
                self.storage.get('stored_height', 0))

    def get_tx_height(self, tx_hash):
        """ return the height and timestamp of a verified transaction. """
        with self.lock:
            if tx_hash in self.verified_tx:
                height, timestamp, pos = self.verified_tx[tx_hash]
                conf = max(self.get_local_height() - height + 1, 0)
                return height, conf, timestamp
            else:
                return self.hh_map[tx_hash], 0, False

    def get_txpos(self, tx_hash):
        "return position, even if the tx is unverified"
        with self.lock:
            if tx_hash in self.verified_tx:
                height, timestamp, pos = self.verified_tx[tx_hash]
                return height, pos
            elif tx_hash in self.hh_map:
                height = self.hh_map[tx_hash]
                return (height, 0) if height > 0 else ((1e9 - height), 0)
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
        d = self.txi.get(tx_hash, {}).get(address, [])
        for n, v in d:
            delta -= v
        # add the value of the coins received at address
        d = self.txo.get(tx_hash, {}).get(address, [])
        for n, v, cb in d:
            delta += v
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
                d = self.txo.get(item['prevout_hash'], {}).get(addr, [])
                for n, v, cb in d:
                    if n == item['prevout_n']:
                        value = v
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

    def get_tx_info(self, tx):
        is_relevant, is_mine, v, fee = self.get_wallet_delta(tx)
        can_broadcast = False
        label = ''
        height = conf = timestamp = None
        tx_hash = tx.txid()
        if tx.is_complete():
            if tx_hash in self.transactions:
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
                        fee = self.tx_fees.get(tx_hash)
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

    def get_addr_io(self, address):
        h = self.get_address_history(address)
        received = {}
        sent = {}
        for tx_hash, height in h:
            l = self.txo.get(tx_hash, {}).get(address, [])
            for n, v, is_cb in l:
                received[tx_hash + ':%d'%n] = (height, v, is_cb)
        for tx_hash, height in h:
            l = self.txi.get(tx_hash, {}).get(address, [])
            for txi, v in l:
                sent[txi] = height
        return received, sent

    def get_addr_utxo(self, address):
        coins, spent = self.get_addr_io(address)
        for txi in spent:
            coins.pop(txi)
            if txi in self.frozen_coins:
                # cleanup/detect if the 'frozen coin' was spent and
                # remove it from the frozen coin set
                self.frozen_coins.remove(txi)
        out = {}
        for txo, v in coins.items():
            tx_height, value, is_cb = v
            prevout_hash, prevout_n = txo.split(':')
            x = {
                'address':address,
                'value':value,
                'prevout_n':int(prevout_n),
                'prevout_hash':prevout_hash,
                'height':tx_height,
                'coinbase':is_cb,
                'is_frozen_coin':txo in self.frozen_coins
            }
            out[txo] = x
        return out

    # return the total amount ever received by an address
    def get_addr_received(self, address):
        received, sent = self.get_addr_io(address)
        return sum([v for height, v, is_cb in received.values()])

    # return the balance of a bitcoin address: confirmed and matured,
    # unconfirmed, unmatured Note that 'exclude_frozen_coins = True'
    # only checks for coin-level freezing, not address-level.
    def get_addr_balance(self, address, exclude_frozen_coins = False):
        assert isinstance(address, Address)
        received, sent = self.get_addr_io(address)
        c = u = x = 0
        for txo, (tx_height, v, is_cb) in received.items():
            if exclude_frozen_coins and txo in self.frozen_coins:
                continue
            if is_cb and tx_height + COINBASE_MATURITY > self.get_local_height():
                x += v
            elif tx_height > 0:
                c += v
            else:
                u += v
            if txo in sent:
                if sent[txo] > 0:
                    c -= v
                else:
                    u -= v
        return c, u, x

    def get_spendable_coins(self, domain, config, isInvoice = False):
        confirmed_only = config.get('confirmed_only', False)
        if isInvoice:
            confirmed_only = True
        return self.get_utxos(domain, exclude_frozen=True, mature=True,
                              confirmed_only=confirmed_only)

    def get_utxos(self, domain=None, exclude_frozen=False, mature=False, confirmed_only=False):
        '''Note exclude_frozen=True checks for BOTH address-level and coin-level frozen status. '''
        coins = []
        if domain is None:
            domain = self.get_addresses()
        if exclude_frozen:
            domain = set(domain) - self.frozen_addresses
        for addr in domain:
            utxos = self.get_addr_utxo(addr)
            for x in utxos.values():
                if exclude_frozen and x['is_frozen_coin']:
                    continue
                if confirmed_only and x['height'] <= 0:
                    continue
                if (mature and x['coinbase'] and
                        x['height'] + COINBASE_MATURITY > self.get_local_height()):
                    continue
                coins.append(x)
                continue
        return coins

    def dummy_address(self):
        return self.get_receiving_addresses()[0]

    def get_addresses(self):
        return self.get_receiving_addresses() + self.get_change_addresses()

    def get_frozen_balance(self) -> Tuple[int, int, int]:
        if not self.frozen_coins:
            # performance short-cut -- get the balance of the frozen
            # address set only IFF we don't have any frozen coins
            return self.get_balance(self.frozen_addresses)
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
            domain = set(domain) - self.frozen_addresses
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

    def add_transaction(self, tx_hash: str, tx: Transaction) -> None:
        '''Return True if tx_hash is verified.'''
        is_coinbase = tx.inputs()[0]['type'] == 'coinbase'
        with self.transaction_lock:
            # add inputs
            self.txi[tx_hash] = d = {}
            for txi in tx.inputs():
                addr = txi.get('address')
                if txi['type'] != 'coinbase':
                    prevout_hash = txi['prevout_hash']
                    prevout_n = txi['prevout_n']
                    ser = prevout_hash + ':%d'%prevout_n
                # find value from prev output
                if self.is_mine(addr):
                    dd = self.txo.get(prevout_hash, {})
                    for n, v, is_cb in dd.get(addr, []):
                        if n == prevout_n:
                            if d.get(addr) is None:
                                d[addr] = []
                            d[addr].append((ser, v))
                            break
                    else:
                        self.pruned_txo[ser] = tx_hash

            # add outputs
            self.txo[tx_hash] = d = {}
            for n, txo in enumerate(tx.outputs()):
                ser = tx_hash + ':%d'%n
                _type, addr, v = txo
                if self.is_mine(addr):
                    if not addr in d:
                        d[addr] = []
                    d[addr].append((n, v, is_coinbase))
                # give v to txi that spends me
                next_tx = self.pruned_txo.get(ser)
                if next_tx is not None:
                    self.pruned_txo.pop(ser)
                    dd = self.txi.get(next_tx, {})
                    if dd.get(addr) is None:
                        dd[addr] = []
                    dd[addr].append((ser, v))
            # save
            self.transactions[tx_hash] = tx

    def remove_transaction(self, tx_hash: str) -> None:
        with self.transaction_lock:
            self.logger.debug("removing tx from history %s", tx_hash)
            for ser, hh in list(self.pruned_txo.items()):
                if hh == tx_hash:
                    self.pruned_txo.pop(ser)
            # add tx to pruned_txo, and undo the txi addition
            for next_tx, dd in self.txi.items():
                for addr, l in list(dd.items()):
                    ll = l[:]
                    for item in ll:
                        ser, v = item
                        prev_hash, prev_n = ser.split(':')
                        if prev_hash == tx_hash:
                            l.remove(item)
                            self.pruned_txo[ser] = next_tx
                    if l == []:
                        dd.pop(addr)
                    else:
                        dd[addr] = l
            try:
                self.txi.pop(tx_hash)
                self.txo.pop(tx_hash)
            except KeyError:
                self.logger.error("tx was not in history %s", tx_hash)

    async def set_address_history(self, addr, hist, tx_fees):
        with self.lock:
            self._history[addr] = hist
            for tx_hash, tx_height in hist:
                self.hh_map[tx_hash] = tx_height

                # If unconfirmed it is not verified
                if tx_height <= 0:
                    self.verified_tx.pop(tx_hash, None)
                # if addr is new, we have to recompute txi and txo
                tx = self.transactions.get(tx_hash)
                if (tx is not None and
                        self.txi.get(tx_hash, {}).get(addr) is None and
                        self.txo.get(tx_hash, {}).get(addr) is None):
                    self.add_transaction(tx_hash, tx)

            # Store fees
            self.tx_fees.update(tx_fees)
        self.txs_changed_event.set()
        await self._trigger_synchronization()

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
                tx = self.transactions.get(tx_hash)
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
        if self.txi.get(tx_hash) == {}:
            d = self.txo.get(tx_hash, {})
            labels = []
            for addr in d.keys():
                label = self.labels.get(addr.to_string())
                if label:
                    labels.append(label)
            return ', '.join(labels)
        return ''

    def get_tx_status(self, tx_hash, height, conf, timestamp):
        if conf == 0:
            tx = self.transactions.get(tx_hash)
            if not tx:
                return 3, 'unknown'
            fee = self.tx_fees.get(tx_hash)
            if height < 0:
                status = 0
            elif height == 0:
                status = 1
            else:
                status = 2
        else:
            status = 3 + min(conf, 6)
        time_str = format_time(timestamp, _("unknown")) if timestamp else _("unknown")
        status_str = TX_STATUS[status] if status < len(TX_STATUS) else time_str
        return status, status_str

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

        for item in inputs:
            self.add_input_info(item)

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

    def is_frozen(self, addr):
        '''Address-level frozen query. Note: this is set/unset independent of
        'coin' level freezing.'''
        assert isinstance(addr, Address)
        return addr in self.frozen_addresses

    def is_frozen_coin(self, utxo):
        ''''coin' level frozen query. `utxo' is a prevout:n string, or a dict
            as returned from get_utxos().  Note: this is set/unset
            independent of 'address' level freezing.
        '''
        assert isinstance(utxo, (str, dict))
        if isinstance(utxo, dict):
            ret = ("{}:{}".format(utxo['prevout_hash'], utxo['prevout_n'])) in self.frozen_coins
            if ret != utxo['is_frozen_coin']:
                self.logger.warning("utxo has stale is_frozen_coin flag")
                utxo['is_frozen_coin'] = ret # update stale flag
            return ret
        return utxo in self.frozen_coins

    def set_frozen_state(self, addrs, freeze):
        '''Set frozen state of the addresses to FREEZE, True or False.  Note that address-level
        freezing is set/unset independent of coin-level freezing, however both must be
        satisfied for a coin to be defined as spendable.
        '''
        if all(self.is_mine(addr) for addr in addrs):
            if freeze:
                self.frozen_addresses |= set(addrs)
            else:
                self.frozen_addresses -= set(addrs)
            frozen_addresses = [addr.to_string() for addr in self.frozen_addresses]
            self.storage.put('frozen_addresses', frozen_addresses)
            return True
        return False

    def set_frozen_coin_state(self, utxos, freeze):
        '''Set frozen state of the COINS to FREEZE, True or False.  utxos is a (possibly mixed)
        list of either "prevout:n" strings and/or coin-dicts as returned from get_utxos().
        Note that if passing prevout:n strings as input, 'is_mine()' status is not checked
        for the specified coin.  Also note that coin-level freezing is set/unset
        independent of address-level freezing, however both must be satisfied for a coin
        to be defined as spendable.
        '''
        ok = 0
        for utxo in utxos:
            if isinstance(utxo, str):
                if freeze:
                    self.frozen_coins |= { utxo }
                else:
                    self.frozen_coins -= { utxo }
                ok += 1
            elif isinstance(utxo, dict) and self.is_mine(utxo['address']):
                txo = "{}:{}".format(utxo['prevout_hash'], utxo['prevout_n'])
                if freeze:
                    self.frozen_coins |= { txo }
                else:
                    self.frozen_coins -= { txo }
                utxo['is_frozen_coin'] = bool(freeze)
                ok += 1
        if ok:
            self.storage.put('frozen_coins', list(self.frozen_coins))
        return ok

    def analyze_history(self):
        bad_addrs = [addr for addr in self._history if not self.is_mine(addr)]
        for addr in bad_addrs:
            self._history.pop(addr)

        # FIXME: the wallet format sucks - why is history a list of pairs?
        self.hh_map = {tx_hash: tx_height
                       for addr_history in self._history.values()
                       for tx_hash, tx_height in addr_history}

        for hist in self._history.values():
            for tx_hash, tx_height in hist:
                if (tx_hash in self.txi or tx_hash in self.txo or
                        tx_hash in self.pruned_txo.values()):
                    continue
                tx = self.transactions.get(tx_hash)
                if tx is not None:
                    self.add_transaction(tx_hash, tx)

        for tx_hash, tx_height in self.hh_map.items():
            # If unconfirmed it is not verified
            if tx_height <= 0 and self.verified_tx.pop(tx_hash, None):
                self.logger.debug(f'unverifying {tx_hash}')

        for tx_hash in set(self.transactions).difference(self.hh_map):
            self.logger.debug(f'removing transaction {tx_hash}')
            self.transactions.pop(tx_hash)

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
        self.save_transactions()
        self.save_verified_tx()
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
        for i, o in enumerate(tx.outputs()):
            otype, address, value = o
            if otype == TYPE_ADDRESS and self.is_mine(address):
                break
        else:
            return
        coins = self.get_addr_utxo(address)
        item = coins.get(txid+':%d'%i)
        if not item:
            return
        self.add_input_info(item)
        inputs = [item]
        outputs = [(TYPE_ADDRESS, address, value - fee)]
        locktime = self.get_local_height()
        # note: no need to call tx.BIP_LI01_sort() here - single input/output
        return Transaction.from_io(inputs, outputs, locktime=locktime)

    def add_input_info(self, txin):
        address = txin['address']
        if self.is_mine(address):
            txin['type'] = self.get_txin_type(address)
            # Bitcoin SV needs value to sign
            received, spent = self.get_addr_io(address)
            item = received.get(txin['prevout_hash']+':%d'%txin['prevout_n'])
            tx_height, value, is_cb = item
            txin['value'] = value
            self.add_input_sig_info(txin, address)

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
        tx = self.transactions.get(tx_hash)
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
        received, sent = self.get_addr_io(address)
        l = []
        for txo, x in received.items():
            h, v, is_cb = x
            txid, n = txo.split(':')
            info = self.verified_tx.get(txid)
            if info:
                tx_height, timestamp, pos = info
                conf = local_height - tx_height
            else:
                conf = 0
            l.append((conf, v))
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
                self.remove_transaction(tx_hash)
                self.tx_fees.pop(tx_hash, None)
                self.verified_tx.pop(tx_hash, None)
                self.transactions.pop(tx_hash, None)

            self.storage.put('verified_tx3', self.verified_tx)

        self.save_transactions()

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

    def load_addresses(self):
        addresses = self.storage.get('addresses', [])
        self.addresses = [Address.from_string(addr) for addr in addresses]

    def save_addresses(self):
        self.storage.put('addresses', [addr.to_string() for addr in self.addresses])
        self.storage.write()

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

    def add_input_sig_info(self, txin, address):
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

    def load_addresses(self):
        pass

    def save_addresses(self):
        pass

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
        self._add_new_addresses([pubkey.address])
        return pubkey.address.to_string()

    def export_private_key(self, address, password):
        '''Returned in WIF format.'''
        pubkey = self.keystore.address_to_pubkey(address)
        return self.keystore.export_private_key(pubkey, password)

    def add_input_sig_info(self, txin, address):
        assert txin['type'] == 'p2pkh'
        pubkey = self.keystore.address_to_pubkey(address)
        txin['num_sig'] = 1
        txin['x_pubkeys'] = [pubkey.to_string()]
        txin['signatures'] = [None]

    def pubkeys_to_address(self, pubkey):
        pubkey = PublicKey.from_string(pubkey)
        if pubkey in self.keystore.keypairs:
            return pubkey.address


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

    def add_input_sig_info(self, txin, address):
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

    def add_input_sig_info(self, txin, address):
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
