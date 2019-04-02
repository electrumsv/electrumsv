#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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

import argparse
import ast
import base64
import datetime
from decimal import Decimal
from functools import wraps
import json
import sys

from bitcoinx import PrivateKey, PublicKey

from . import bitcoin
from .address import Address
from .app_state import app_state
from .bitcoin import COIN, TYPE_ADDRESS
from .crypto import hash_160
from .exchange_rate import FxTask
from .i18n import _
from .logs import logs
from .paymentrequest import PR_PAID, PR_UNPAID, PR_UNKNOWN, PR_EXPIRED
from .transaction import Transaction, multisig_script
from .util import bfh, bh2u, format_satoshis, json_decode, to_bytes


logger = logs.get_logger("commands")

known_commands = {}


def satoshis(amount):
    # satoshi conversion must not be performed by the parser
    return int(COIN*Decimal(amount)) if amount not in ['!', None] else amount


class Command:
    def __init__(self, func, s):
        self.name = func.__name__
        self.requires_network = 'n' in s
        self.requires_wallet = 'w' in s
        self.requires_password = 'p' in s
        self.description = func.__doc__
        self.help = self.description.split('.')[0] if self.description else None
        varnames = func.__code__.co_varnames[1:func.__code__.co_argcount]
        self.defaults = func.__defaults__
        if self.defaults:
            n = len(self.defaults)
            self.params = list(varnames[:-n])
            self.options = list(varnames[-n:])
        else:
            self.params = list(varnames)
            self.options = []
            self.defaults = []

    def __repr__(self):
        return "<Command {}>".format(self)

    def __str__(self):
        return "{}({})".format(
            self.name,
            ", ".join(self.params + ["{}={!r}".format(name, self.defaults[i])
                                     for i, name in enumerate(self.options)]))


def command(s):
    def decorator(func):
        global known_commands
        name = func.__name__
        known_commands[name] = Command(func, s)
        @wraps(func)
        def func_wrapper(*args, **kwargs):
            c = known_commands[func.__name__]
            wallet = args[0].wallet
            network = args[0].network
            password = kwargs.get('password')
            if c.requires_network and network is None:
                raise Exception("Daemon offline")  # Same wording as in daemon.py.
            if c.requires_wallet and wallet is None:
                raise Exception("Wallet not loaded. Use 'electrum-sv daemon load_wallet'")
            if c.requires_password and password is None and wallet.storage.get('use_encryption') \
               and not kwargs.get("unsigned"):
                return {'error': 'Password required' }
            return func(*args, **kwargs)
        return func_wrapper
    return decorator


class Commands:

    def __init__(self, config, wallet, network, callback = None):
        self.config = config
        self.wallet = wallet
        self.network = network
        self._callback = callback

    def _run(self, method, *args, password_getter=None, **kwargs):
        # this wrapper is called from the python console
        cmd = known_commands[method]
        if cmd.requires_password and self.wallet.has_password():
            password = password_getter()
            if password is None:
                return
        else:
            password = None

        f = getattr(self, method)
        if cmd.requires_password:
            kwargs.update(password=password)
        result = f(*args, **kwargs)

        if self._callback:
            self._callback()
        return result

    @staticmethod
    def _EnsureDictNamedTuplesAreJSONSafe(d):
        """Address, ScriptOutput and other objects contain bytes.  They cannot be serialized
            using JSON. This makes sure they get serialized properly by calling
            .to_string() on them.  See issue #638
        """
        def DoChk(v):
            def ChkList(l):
                for i in range(0,len(l)): l[i] = DoChk(l[i]) # recurse
                return l
            def EncodeNamedTupleObject(nt):
                if hasattr(nt, 'to_string'): return nt.to_string()
                return nt

            if isinstance(v, tuple): v = EncodeNamedTupleObject(v)
            elif isinstance(v, list): v = ChkList(v) # may recurse
            elif isinstance(v, dict): v = Commands._EnsureDictNamedTuplesAreJSONSafe(v) # recurse
            return v

        for k in d.keys():
            d[k] = DoChk(d[k])
        return d

    @command('')
    def commands(self):
        """List of commands"""
        return ' '.join(sorted(known_commands.keys()))

    @command('')
    def create(self):
        """Create a new wallet"""
        raise Exception('Not a JSON-RPC command')

    @command('wn')
    def restore(self, text):
        """Restore a wallet from text. Text can be a seed phrase, a master
        public key, a master private key, a list of bitcoin cash addresses
        or bitcoin cash private keys. If you want to be prompted for your
        seed, type '?' or ':' (concealed) """
        raise Exception('Not a JSON-RPC command')

    @command('wp')
    def password(self, password=None, new_password=None):
        """Change wallet password. """
        b = self.wallet.storage.is_encrypted()
        self.wallet.update_password(password, new_password, b)
        self.wallet.storage.write()
        return {'password':self.wallet.has_password()}

    @command('')
    def getconfig(self, key):
        """Return a configuration variable. """
        return self.config.get(key)

    @classmethod
    def _setconfig_normalize_value(cls, key, value):
        if key not in ('rpcuser', 'rpcpassword'):
            value = json_decode(value)
            try:
                value = ast.literal_eval(value)
            except:
                pass
        return value

    @command('')
    def setconfig(self, key, value):
        """Set a configuration variable. 'value' may be a string or a Python expression."""
        value = self._setconfig_normalize_value(key, value)
        self.config.set_key(key, value)
        return True

    @command('')
    def make_seed(self, nbits=132, language=None):
        """Create a seed"""
        from .mnemonic import Mnemonic
        t = 'standard'
        s = Mnemonic(language).make_seed(t, nbits)
        return s

    @command('n')
    def getaddresshistory(self, address):
        """Return the transaction history of any address. Note: This is a
        walletless server query, results are not checked by SPV.
        """
        sh = Address.from_string(address).to_scripthash_hex()
        return self.network.request_and_wait('blockchain.scripthash.get_history', [sh])

    @command('w')
    def listunspent(self):
        """List unspent outputs. Returns the list of unspent transaction
        outputs in your wallet."""
        l = self.wallet.get_utxos(exclude_frozen=False)
        for i in l:
            v = i["value"]
            i["value"] = str(Decimal(v)/COIN) if v is not None else None
            i["address"] = i["address"].to_string()
        return l

    @command('n')
    def getaddressunspent(self, address):
        """Returns the UTXO list of any address. Note: This
        is a walletless server query, results are not checked by SPV.
        """
        sh = Address.from_string(address).to_scripthash_hex()
        return self.network.request_and_wait('blockchain.scripthash.listunspent', [sh])

    @command('')
    def serialize(self, jsontx):
        """Create a transaction from json inputs.
        Inputs must have a redeemPubkey.
        Outputs must be a list of {'address':address, 'value':satoshi_amount}.
        """
        keypairs = {}
        inputs = jsontx.get('inputs')
        outputs = jsontx.get('outputs')
        locktime = jsontx.get('locktime', 0)
        for txin in inputs:
            if txin.get('output'):
                prevout_hash, prevout_n = txin['output'].split(':')
                txin['prevout_n'] = int(prevout_n)
                txin['prevout_hash'] = prevout_hash
            sec = txin.get('privkey')
            if sec:
                privkey = PrivateKey.from_text(sec)
                txin_type, privkey, compressed = (
                    'p2pkh', privkey.to_bytes(), privkey.is_compressed()
                )
                pubkey = privkey.public_key.to_hex()
                keypairs[pubkey] = privkey, compressed
                txin['type'] = txin_type
                txin['x_pubkeys'] = [pubkey]
                txin['signatures'] = [None]
                txin['num_sig'] = 1

        outputs = [(TYPE_ADDRESS, Address.from_string(x['address']), int(x['value']))
                   for x in outputs]
        tx = Transaction.from_io(inputs, outputs, locktime=locktime)
        tx.sign(keypairs)
        return tx.as_dict()

    @command('wp')
    def signtransaction(self, tx, privkey=None, password=None):
        """Sign a transaction. The wallet keys will be used unless a private key is provided."""
        tx = Transaction(tx)
        if privkey:
            privkey2 = PrivateKey.from_text(privkey)
            txin_type, privkey2, compressed = (
                'p2pkh', privkey2.to_bytes(), privkey2.is_compressed()
            )
            h160 = hash_160(privkey2.public_key.to_bytes())
            x_pubkey = 'fd' + bh2u(b'\x00' + h160)
            tx.sign({x_pubkey:(privkey2, compressed)})
        else:
            self.wallet.sign_transaction(tx, password)
        return tx.as_dict()

    @command('')
    def deserialize(self, tx):
        """Deserialize a serialized transaction"""
        tx = Transaction(tx)
        return self._EnsureDictNamedTuplesAreJSONSafe(tx.deserialize().copy())

    @command('n')
    def broadcast(self, tx):
        """Broadcast a transaction to the network. """
        tx = Transaction(tx)
        return self.network.broadcast_transaction_and_wait(tx)

    @command('')
    def createmultisig(self, num, pubkeys):
        """Create multisig address"""
        assert isinstance(pubkeys, list), (type(num), type(pubkeys))
        redeem_script = multisig_script(pubkeys, num)
        address = bitcoin.hash160_to_p2sh(hash_160(bfh(redeem_script)))
        return {'address':address, 'redeemScript':redeem_script}

    @command('w')
    def freeze(self, address):
        """Freeze address. Freeze the funds at one of your wallet\'s addresses"""
        address = Address.from_string(address)
        return self.wallet.set_frozen_state([address], True)

    @command('w')
    def unfreeze(self, address):
        """Unfreeze address. Unfreeze the funds at one of your wallet\'s address"""
        address = Address.from_string(address)
        return self.wallet.set_frozen_state([address], False)

    @command('wp')
    def getprivatekeys(self, address, password=None):
        """Get private keys of addresses. You may pass a single wallet address, or a list of
        wallet addresses."""
        def get_pk(address):
            address = Address.from_string(address)
            return self.wallet.export_private_key(address, password)

        if isinstance(address, str):
            return get_pk(address)
        else:
            return [get_pk(addr) for addr in address]

    @command('w')
    def ismine(self, address):
        """Check if address is in wallet. Return true if and only address is in wallet"""
        address = Address.from_string(address)
        return self.wallet.is_mine(address)

    @command('')
    def dumpprivkeys(self):
        """Deprecated."""
        return ("This command is deprecated. Use a pipe instead: "
                "'electrum-sv listaddresses | electrum-sv getprivatekeys - '")

    @command('')
    def validateaddress(self, address):
        """Check that an address is valid. """
        return Address.is_valid(address)

    @command('w')
    def getpubkeys(self, address):
        """Return the public keys for a wallet address. """
        address = Address.from_string(address)
        return self.wallet.get_public_keys(address)

    @command('w')
    def getbalance(self):
        """Return the balance of your wallet. """
        c, u, x = self.wallet.get_balance()
        out = {"confirmed": str(Decimal(c)/COIN)}
        if u:
            out["unconfirmed"] = str(Decimal(u)/COIN)
        if x:
            out["unmatured"] = str(Decimal(x)/COIN)
        return out

    @command('n')
    def getaddressbalance(self, address):
        """Return the balance of any address. Note: This is a walletless
        server query, results are not checked by SPV.
        """
        sh = Address.from_string(address).to_scripthash_hex()
        out = self.network.request_and_wait('blockchain.scripthash.get_balance', [sh])
        out["confirmed"] =  str(Decimal(out["confirmed"])/COIN)
        out["unconfirmed"] =  str(Decimal(out["unconfirmed"])/COIN)
        return out

    @command('n')
    def getmerkle(self, txid, height):
        """Get Merkle branch of a transaction included in a block. Electrum
        uses this to verify transactions (Simple Payment Verification)."""
        return self.network.request_and_wait('blockchain.transaction.get_merkle',
                                             [txid, int(height)])

    @command('n')
    def getservers(self):
        """Return the list of available servers"""
        return self.network.get_servers()

    @command('')
    def version(self):
        """Return the version of electrum-sv."""
        from .version import PACKAGE_VERSION
        return PACKAGE_VERSION

    @command('w')
    def getmpk(self):
        """Get master public key. Return your wallet\'s master public key"""
        return self.wallet.get_master_public_key()

    @command('wp')
    def getmasterprivate(self, password=None):
        """Get master private key. Return your wallet\'s master private key"""
        return str(self.wallet.keystore.get_master_private_key(password))

    @command('wp')
    def getseed(self, password=None):
        """Get seed phrase. Print the generation seed of your wallet."""
        s = self.wallet.get_seed(password)
        return s

    @command('wp')
    def importprivkey(self, privkey, password=None):
        """Import a private key."""
        if not self.wallet.can_import_privkey():
            return ("Error: This type of wallet cannot import private keys. "
                    "Try to create a new wallet with that key.")
        try:
            addr = self.wallet.import_private_key(privkey, password)
            out = "Keypair imported: " + addr
        except Exception as e:
            out = "Error: " + str(e)
        return out

    def _resolver(self, x):
        if x is None:
            return None
        out = self.wallet.contacts.resolve(x)
        return out['address']

    @command('n')
    def sweep(self, privkey, destination, fee=None, nocheck=False, imax=100):
        """Sweep private keys. Returns a transaction that spends UTXOs from
        privkey to a destination address. The transaction is not
        broadcasted."""
        from .wallet import sweep
        tx_fee = satoshis(fee)
        privkeys = privkey.split()
        self.nocheck = nocheck
        addr = Address.from_string(destination)
        tx = sweep(privkeys, self.network, self.config, addr, tx_fee, imax)
        return tx.as_dict() if tx else None

    @command('wp')
    def signmessage(self, address, message, password=None):
        """Sign a message with a key. Use quotes if your message contains
        whitespaces"""
        address = Address.from_string(address)
        sig = self.wallet.sign_message(address, message, password)
        return base64.b64encode(sig).decode('ascii')

    @command('')
    def verifymessage(self, address, signature, message):
        """Verify a signature."""
        return bitcoin.verify_message_and_address(signature, message, address)

    def _mktx(self, outputs, fee=None, change_addr=None, domain=None, nocheck=False,
              unsigned=False, password=None, locktime=None):
        self.nocheck = nocheck
        change_addr = self._resolver(change_addr)
        domain = None if domain is None else [self._resolver(x) for x in domain]
        final_outputs = []
        for address, amount in outputs:
            address = self._resolver(address)
            amount = satoshis(amount)
            final_outputs.append((TYPE_ADDRESS, address, amount))

        coins = self.wallet.get_spendable_coins(domain, self.config)
        tx = self.wallet.make_unsigned_transaction(coins, final_outputs, self.config,
                                                   fee, change_addr)
        if locktime is not None:
            tx.locktime = locktime
        if not unsigned:
            self.wallet.sign_transaction(tx, password)
        return tx

    @command('wp')
    def payto(self, destination, amount, fee=None, from_addr=None, change_addr=None,
              nocheck=False, unsigned=False, password=None, locktime=None):
        """Create a transaction. """
        tx_fee = satoshis(fee)
        domain = from_addr.split(',') if from_addr else None
        tx = self._mktx([(destination, amount)], tx_fee, change_addr, domain,
                        nocheck, unsigned, password, locktime)
        return tx.as_dict()

    @command('wp')
    def paytomany(self, outputs, fee=None, from_addr=None, change_addr=None, nocheck=False,
                  unsigned=False, password=None, locktime=None):
        """Create a multi-output transaction. """
        tx_fee = satoshis(fee)
        domain = from_addr.split(',') if from_addr else None
        tx = self._mktx(outputs, tx_fee, change_addr, domain, nocheck, unsigned,
                        password, locktime)
        return tx.as_dict()

    @command('w')
    def history(self, year=None, show_addresses=False, show_fiat=False):
        """Wallet history. Returns the transaction history of your wallet."""
        kwargs = {'show_addresses': show_addresses}
        if year:
            import time
            start_date = datetime.datetime(year, 1, 1)
            end_date = datetime.datetime(year+1, 1, 1)
            kwargs['from_timestamp'] = time.mktime(start_date.timetuple())
            kwargs['to_timestamp'] = time.mktime(end_date.timetuple())
        if show_fiat:
            app_state.fx = FxTask(app_state.config, None)
        return self.wallet.export_history(**kwargs)

    @command('w')
    def setlabel(self, key, label):
        """Assign a label to an item. Item may be a bitcoin address address or a
        transaction ID"""
        self.wallet.set_label(key, label)

    @command('w')
    def listcontacts(self):
        """Show your list of contacts"""
        return self.wallet.contacts

    @command('w')
    def getalias(self, key):
        """Retrieve alias. Lookup in your list of contacts."""
        return self.wallet.contacts.resolve(key)

    @command('w')
    def searchcontacts(self, query):
        """Search through contacts, return matching entries. """
        results = {}
        for key, value in self.wallet.contacts.items():
            if query.lower() in key.lower():
                results[key] = value
        return results

    @command('w')
    def listaddresses(self, receiving=False, change=False, labels=False, frozen=False,
                      unused=False, funded=False, balance=False):
        """List wallet addresses. Returns the list of all addresses in your wallet. Use optional
        arguments to filter the results.
        """
        out = []
        for addr in self.wallet.get_addresses():
            if frozen and not self.wallet.is_frozen(addr):
                continue
            if receiving and self.wallet.is_change(addr):
                continue
            if change and not self.wallet.is_change(addr):
                continue
            if unused and self.wallet.is_used(addr):
                continue
            if funded and self.wallet.is_empty(addr):
                continue
            item = addr.to_string()
            if labels or balance:
                item = (item,)
            if balance:
                item += (format_satoshis(sum(self.wallet.get_addr_balance(addr))),)
            if labels:
                item += (repr(self.wallet.labels.get(addr.to_string(), '')),)
            out.append(item)
        return out

    @command('n')
    def gettransaction(self, txid):
        """Retrieve a transaction. """
        if self.wallet and txid in self.wallet.transactions:
            tx = self.wallet.transactions[txid]
        else:
            raw = self.network.request_and_wait('blockchain.transaction.get', [txid])
            if raw:
                tx = Transaction(raw)
            else:
                raise Exception("Unknown transaction")
        return tx.as_dict()

    @command('')
    def encrypt(self, pubkey, message):
        """Encrypt a message with a public key. Use quotes if the message contains whitespaces."""
        public_key = PublicKey.from_hex(pubkey)
        encrypted = public_key.encrypt_message_to_base64(message)
        return encrypted

    @command('wp')
    def decrypt(self, pubkey, encrypted, password=None):
        """Decrypt a message encrypted with a public key."""
        return self.wallet.decrypt_message(pubkey, encrypted, password)

    def _format_request(self, out):
        pr_str = {
            PR_UNKNOWN: 'Unknown',
            PR_UNPAID: 'Pending',
            PR_PAID: 'Paid',
            PR_EXPIRED: 'Expired',
        }
        out['address'] = out.get('address').to_string()
        out['amount (BTC)'] = format_satoshis(out.get('amount'))
        out['status'] = pr_str[out.get('status', PR_UNKNOWN)]
        return out

    @command('w')
    def getrequest(self, key):
        """Return a payment request"""
        r = self.wallet.get_payment_request(Address.from_string(key), self.config)
        if not r:
            raise Exception("Request not found")
        return self._format_request(r)

    @command('w')
    def listrequests(self, pending=False, expired=False, paid=False):
        """List the payment requests you made."""
        out = self.wallet.get_sorted_requests(self.config)
        if pending:
            f = PR_UNPAID
        elif expired:
            f = PR_EXPIRED
        elif paid:
            f = PR_PAID
        else:
            f = None
        if f is not None:
            out = [x for x in out if x.get('status')==f]
        return [self._format_request(x) for x in out]

    @command('w')
    def createnewaddress(self):
        """Create a new receiving address, beyond the gap limit of the wallet"""
        return self.wallet.create_new_address(False).to_string()

    @command('w')
    def getunusedaddress(self):
        """Returns the first unused address of the wallet, or None if all addresses are used.  An
        address is considered as used if it has received a transaction, or if it is used
        in a payment request.
        """
        return self.wallet.get_unused_address().to_string()

    @command('w')
    def addrequest(self, amount, memo='', expiration=None, force=False):
        """Create a payment request, using the first unused address of the wallet.  The address
        will be condidered as used after this operation.  If no payment is received, the
        address will be considered as unused if the payment request is deleted from the
        wallet.
        """
        addr = self.wallet.get_unused_address()
        if addr is None:
            if force:
                addr = self.wallet.create_new_address(False)
            else:
                return False
        amount = satoshis(amount)
        expiration = int(expiration) if expiration else None
        req = self.wallet.make_payment_request(addr, amount, memo, expiration)
        self.wallet.add_payment_request(req, self.config)
        out = self.wallet.get_payment_request(addr, self.config)
        return self._format_request(out)

    @command('wp')
    def signrequest(self, address, password=None):
        raise Exception("Not applicable as no openalias")

    @command('w')
    def rmrequest(self, address):
        """Remove a payment request"""
        return self.wallet.remove_payment_request(address, self.config)

    @command('w')
    def clearrequests(self):
        """Remove all payment requests"""
        for k in list(self.wallet.receive_requests.keys()):
            self.wallet.remove_payment_request(k, self.config)

    @command('n')
    def notify(self, address, URL):
        """Watch an address. Everytime the address changes, a http POST is sent to the URL."""
        def callback(x):
            import urllib.request
            headers = {'content-type':'application/json'}
            data = {'address':address, 'status':x.get('result')}
            serialized_data = to_bytes(json.dumps(data))
            try:
                req = urllib.request.Request(URL, serialized_data, headers)
                response_stream = urllib.request.urlopen(req, timeout=5)
                logger.debug('Got Response for %s', address)
            except Exception as e:
                logger.error("exception processing response %s", e)
        h = Address.from_string(address).to_scripthash_hex()
        self.network.send([('blockchain.scripthash.subscribe', [h])], callback)
        return True

    @command('wn')
    def is_synchronized(self):
        """ return wallet synchronization status """
        return self.wallet.is_synchronized()

    @command('n')
    def getfeerate(self):
        """Return current optimal fee rate per kilobyte, according
        to config settings (static/dynamic)"""
        return self.config.fee_per_kb()

    @command('')
    def help(self):
        # for the python console
        return sorted(known_commands.keys())

param_descriptions = {
    'privkey': 'Private key. Type \'?\' to get a prompt.',
    'destination': 'Bitcoin SV address, contact or alias',
    'address': 'Bitcoin SV address',
    'seed': 'Seed phrase',
    'txid': 'Transaction ID',
    'pos': 'Position',
    'height': 'Block height',
    'tx': 'Serialized transaction (hexadecimal)',
    'key': 'Variable name',
    'pubkey': 'Public key',
    'message': 'Clear text message. Use quotes if it contains spaces.',
    'encrypted': 'Encrypted message',
    'amount': 'Amount to be sent (in BTC). Type \'!\' to send the maximum available.',
    'requested_amount': 'Requested amount (in BTC).',
    'outputs': 'list of ["address", amount]',
    'redeem_script': 'redeem script (hexadecimal)',
}

command_options = {
    'password':    ("-W", "Password"),
    'new_password':(None, "New Password"),
    'receiving':   (None, "Show only receiving addresses"),
    'change':      (None, "Show only change addresses"),
    'frozen':      (None, "Show only frozen addresses"),
    'unused':      (None, "Show only unused addresses"),
    'funded':      (None, "Show only funded addresses"),
    'balance':     ("-b", "Show the balances of listed addresses"),
    'labels':      ("-l", "Show the labels of listed addresses"),
    'nocheck':     (None, "Do not verify aliases"),
    'imax':        (None, "Maximum number of inputs"),
    'fee':         ("-f", "Transaction fee (in BTC)"),
    'from_addr':   ("-F", "Source address (must be a wallet address; "
                    "use sweep to spend from non-wallet address)."),
    'change_addr': ("-c", "Change address. Default is a spare address, or the source "
                    "address if it's not in the wallet"),
    'nbits':       (None, "Number of bits of entropy"),
    'language':    ("-L", "Default language for wordlist"),
    'privkey':     (None, "Private key. Set to '?' to get a prompt."),
    'unsigned':    ("-u", "Do not sign transaction"),
    'locktime':    (None, "Set locktime block number"),
    'domain':      ("-D", "List of addresses"),
    'memo':        ("-m", "Description of the request"),
    'expiration':  (None, "Time in seconds"),
    'timeout':     (None, "Timeout in seconds"),
    'force':       (None, "Create new address beyond gap limit, if no more addresses "
                    "are available."),
    'pending':     (None, "Show only pending requests."),
    'expired':     (None, "Show only expired requests."),
    'paid':        (None, "Show only paid requests."),
    'show_addresses': (None, "Show input and output addresses"),
    'show_fiat':   (None, "Show fiat value of transactions"),
    'year':        (None, "Show history for a given year"),
}


# don't use floats because of rounding errors
from .transaction import tx_from_str
json_loads = lambda x: json.loads(x, parse_float=lambda x: str(Decimal(x)))
arg_types = {
    'num': int,
    'nbits': int,
    'imax': int,
    'year': int,
    'tx': tx_from_str,
    'pubkeys': json_loads,
    'jsontx': json_loads,
    'inputs': json_loads,
    'outputs': json_loads,
    'fee': lambda x: str(Decimal(x)) if x is not None else None,
    'amount': lambda x: str(Decimal(x)) if x != '!' else '!',
    'locktime': int,
}

config_variables = {

    'addrequest': {
        'requests_dir': 'directory where a bip270 file will be written.',
        'url_rewrite': ('Parameters passed to str.replace(), in order to create the r= part '
                        'of bitcoin: URIs. Example: '
                        '\"(\'file:///var/www/\',\'https://electrum.org/\')\"'),
    },
    'listrequests':{
        'url_rewrite': ('Parameters passed to str.replace(), in order to create the r= part '
                        'of bitcoin: URIs. Example: '
                        '\"(\'file:///var/www/\',\'https://electrum.org/\')\"'),
    }
}

def set_default_subparser(self, name, args=None):
    """see http://stackoverflow.com/questions/5176691"""
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help']:  # global help if no subparser
            break
    else:
        for x in self._subparsers._actions:
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            # insert default in first position, this implies no
            # global options without a sub_parsers specified
            if args is None:
                sys.argv.insert(1, name)
            else:
                args.insert(0, name)

argparse.ArgumentParser.set_default_subparser = set_default_subparser


# workaround https://bugs.python.org/issue23058
# see https://github.com/nickstenning/honcho/pull/121

def subparser_call(self, parser, namespace, values, option_string=None):
    from argparse import ArgumentError, SUPPRESS, _UNRECOGNIZED_ARGS_ATTR
    parser_name = values[0]
    arg_strings = values[1:]
    # set the parser name if requested
    if self.dest is not SUPPRESS:
        setattr(namespace, self.dest, parser_name)
    # select the parser
    try:
        parser = self._name_parser_map[parser_name]
    except KeyError:
        tup = parser_name, ', '.join(self._name_parser_map)
        msg = _('unknown parser {!r} (choices: {})').format(*tup)
        raise ArgumentError(self, msg)
    # parse all the remaining options into the namespace
    # store any unrecognized options on the object, so that the top
    # level parser can decide what to do with them
    namespace, arg_strings = parser.parse_known_args(arg_strings, namespace)
    if arg_strings:
        vars(namespace).setdefault(_UNRECOGNIZED_ARGS_ATTR, [])
        getattr(namespace, _UNRECOGNIZED_ARGS_ATTR).extend(arg_strings)

argparse._SubParsersAction.__call__ = subparser_call


def add_network_options(parser):
    parser.add_argument("-1", "--oneserver", action="store_true", dest="oneserver",
                        default=False, help="connect to one server only")
    parser.add_argument("-s", "--server", dest="server", default=None,
                        help="set server host:port:protocol, where protocol is either "
                        "t (tcp) or s (ssl)")
    parser.add_argument("-p", "--proxy", dest="proxy", default=None,
                        help="set proxy [type:]host[:port], where type is socks4 or socks5")

def add_global_options(parser):
    group = parser.add_argument_group('global options')
    group.add_argument("-v", "--verbose", action="store", dest="verbose",
                       const='info', default='warning', nargs='?',
                       choices = ('debug', 'info', 'warning', 'error'),
                       help="Set logging verbosity")
    group.add_argument("-D", "--dir", dest="electrum_sv_path", help="ElectrumSV directory")
    group.add_argument("-P", "--portable", action="store_true", dest="portable", default=False,
                       help="Use local 'electrum_data' directory")
    group.add_argument("-w", "--wallet", dest="wallet_path", help="wallet path")
    group.add_argument("-wp", "--walletpassword", dest="wallet_password", default=None,
                       help="Supply wallet password")
    group.add_argument("--testnet", action="store_true", dest="testnet", default=False,
                       help="Use Testnet")
    group.add_argument("--file-logging", action="store_true", dest="file_logging", default=False,
                       help="Redirect logging to log file")

def get_parser():
    # create main parser
    parser = argparse.ArgumentParser(
        epilog="Run 'electrum-sv help <command>' to see the help for a command")
    add_global_options(parser)
    subparsers = parser.add_subparsers(dest='cmd', metavar='<command>')
    # gui
    parser_gui = subparsers.add_parser('gui',
                                       description="Run Electrum's Graphical User Interface.",
                                       help="Run GUI (default)")
    parser_gui.add_argument("url", nargs='?', default=None, help="bitcoin URI (or bip270 file)")
    parser_gui.add_argument("-g", "--gui", dest="gui", help="select graphical user interface",
                            choices=['qt'])
    parser_gui.add_argument("-o", "--offline", action="store_true", dest="offline", default=False,
                            help="Run offline")
    parser_gui.add_argument("-m", action="store_true", dest="hide_gui", default=False,
                            help="hide GUI on startup")
    parser_gui.add_argument("-L", "--lang", dest="language", default=None,
                            help="default language used in GUI")
    add_network_options(parser_gui)
    add_global_options(parser_gui)
    # daemon
    parser_daemon = subparsers.add_parser('daemon', help="Run Daemon")
    parser_daemon.add_argument("subcommand", choices=['start', 'status', 'stop',
                                                      'load_wallet', 'close_wallet'], nargs='?')
    parser_daemon.add_argument("-dapp", "--daemon-app-module", dest="daemon_app_module",
        help="Run the daemon control app from the given module")
    #parser_daemon.set_defaults(func=run_daemon)
    add_network_options(parser_daemon)
    add_global_options(parser_daemon)
    # commands
    for cmdname in sorted(known_commands.keys()):
        cmd = known_commands[cmdname]
        p = subparsers.add_parser(cmdname, help=cmd.help, description=cmd.description)
        add_global_options(p)
        if cmdname == 'restore':
            p.add_argument("-o", "--offline", action="store_true", dest="offline", default=False,
                           help="Run offline")
        for optname, default in zip(cmd.options, cmd.defaults):
            a, help = command_options[optname]
            b = '--' + optname
            action = "store_true" if type(default) is bool else 'store'
            args = (a, b) if a else (b,)
            if action == 'store':
                _type = arg_types.get(optname, str)
                p.add_argument(*args, dest=optname, action=action, default=default,
                               help=help, type=_type)
            else:
                p.add_argument(*args, dest=optname, action=action, default=default, help=help)

        for param in cmd.params:
            h = param_descriptions.get(param, '')
            _type = arg_types.get(param, str)
            p.add_argument(param, help=h, type=_type)

        cvh = config_variables.get(cmdname)
        if cvh:
            group = p.add_argument_group('configuration variables',
                                         '(set with setconfig/getconfig)')
            for k, v in cvh.items():
                group.add_argument(k, nargs='?', help=v)

    # 'gui' is the default command
    parser.set_default_subparser('gui')
    return parser
