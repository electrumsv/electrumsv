#!/usr/bin/env python
#
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

# TODO(rt12): Look at how the public key is stored for encryption, currently it is passed into
#     the stores as hex. Is this the best way?


import ast
import base64
from collections import namedtuple
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import threading
from typing import Any, Dict, List, Optional, Type, TypeVar
import zlib

from bitcoinx import PrivateKey, PublicKey

from .bitcoin import is_address_valid
from .constants import StorageKind, DATABASE_EXT, TxFlags, ParentWalletKinds
from .exceptions import IncompatibleWalletError
from .keystore import bip44_derivation
from .logs import logs
from .networks import Net
from .wallet_database import (DBTxInput, DBTxOutput, JSONKeyValueStore, MigrationContext,
    TxData, WalletData)


logger = logs.get_logger("storage")



def multisig_type(wallet_type):
    '''If wallet_type is mofn multi-sig, return [m, n],
    otherwise return None.'''
    if not wallet_type:
        return None
    match = re.match(r'(\d+)of(\d+)', wallet_type)
    if match:
        match = [int(x) for x in match.group(1, 2)]
    return match

FINAL_SEED_VERSION = 21

WalletStorageInfo = namedtuple('WalletStorageInfo', ['kind', 'filename', 'wallet_filepath'])


def get_categorised_files(wallet_path: str) -> List[WalletStorageInfo]:
    """
    This categorises files based on the three different ways in which we have stored wallets.

    FILE - Just the JSON file (version <= 17).
      thiswalletfile
    HYBRID - Partial transition from JSON file to database (version = 18 or 19).
      thiswalletfile / thiswalletfile.sqlite
    DATABASE - Just the database (version >= 20).
      thiswalletfile.sqlite
    """
    filenames = set(s for s in os.listdir(wallet_path))
    database_filenames = set([ s for s in filenames if s.endswith(DATABASE_EXT) ])
    matches = []
    for database_filename in database_filenames:
        filename, _ext = os.path.splitext(database_filename)
        wallet_filepath = os.path.join(wallet_path, filename)
        if filename in filenames:
            filenames.remove(filename)
            matches.append(WalletStorageInfo(StorageKind.HYBRID, filename, wallet_filepath))
        else:
            matches.append(WalletStorageInfo(StorageKind.DATABASE, filename, wallet_filepath))
    filenames -= database_filenames
    for filename in filenames:
        wallet_filepath = os.path.join(wallet_path, filename)
        matches.append(WalletStorageInfo(StorageKind.FILE, filename, wallet_filepath))
    return matches


def categorise_file(wallet_filepath: str) -> WalletStorageInfo:
    database_filepath = wallet_filepath
    if database_filepath.endswith(DATABASE_EXT):
        wallet_filepath = database_filepath[:-len(DATABASE_EXT)]
    else:
        database_filepath = wallet_filepath + DATABASE_EXT

    kind = StorageKind.UNKNOWN
    if os.path.exists(wallet_filepath):
        kind = StorageKind.FILE
    if os.path.exists(database_filepath):
        if kind == StorageKind.FILE:
            kind = StorageKind.HYBRID
        else:
            kind = StorageKind.DATABASE

    _path, filename = os.path.split(wallet_filepath)
    return WalletStorageInfo(kind, filename, wallet_filepath)


def backup_wallet_files(wallet_filepath: str) -> bool:
    info = categorise_file(wallet_filepath)
    if info.kind == StorageKind.UNKNOWN:
        return False

    base_wallet_filepath = os.path.join(os.path.dirname(wallet_filepath), info.filename)
    attempt = 0
    while True:
        attempt += 1
        attempted_wallet_filepath = f"{base_wallet_filepath}.backup.{attempt}"

        # Check if a file of the same name as the attempted database backup exists.
        if info.kind == StorageKind.HYBRID or info.kind == StorageKind.DATABASE:
            if os.path.exists(attempted_wallet_filepath + DATABASE_EXT):
                continue
        # Check if a file of the same name as the attempted file backup exists.
        if info.kind == StorageKind.FILE or info.kind == StorageKind.HYBRID:
            if os.path.exists(attempted_wallet_filepath):
                continue

        # No objection, the attempted backup path is acceptable.
        break

    if info.kind == StorageKind.HYBRID or info.kind == StorageKind.DATABASE:
        shutil.copyfile(
            base_wallet_filepath + DATABASE_EXT, attempted_wallet_filepath + DATABASE_EXT)
    if info.kind == StorageKind.FILE or info.kind == StorageKind.HYBRID:
        shutil.copyfile(base_wallet_filepath,  attempted_wallet_filepath)

    return True

StoreType = TypeVar('StoreType', bound='BaseStore')

class BaseStore:
    _raw: Optional[bytes] = None

    def __init__(self, path: str, pubkey: Optional[str]=None,
            data: Optional[Dict[str, Any]]=None) -> None:
        self._path = path
        assert pubkey is None or type(pubkey) is str, "must be hex representation of pubkey"
        self._pubkey = pubkey

        self._data = {} if data is None else data
        self._modified = bool(data)

        self._lock = threading.RLock()

    def move_to(self, new_path: str) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def get_path(self) -> str:
        return self._path

    def is_primed(self) -> bool:
        # Represents whether the data has been written at least once.
        raise NotImplementedError

    def is_encrypted(self) -> bool:
        raise NotImplementedError

    def load_data(self, s: bytes) -> None:
        raise NotImplementedError

    def read_raw_data(self) -> bytes:
        raise NotImplementedError

    def get_raw_data(self) -> Optional[bytes]:
        return self._raw

    def get_encrypted_data(self) -> Optional[bytes]:
        return self._raw

    def _set_seed_version(self, seed_version: Optional[int]) -> None:
        raise NotImplementedError

    def set_pubkey(self, pubkey: Optional[str]=None) -> None:
        self._pubkey = pubkey

    def get(self, key: str, default: Optional[Any]=None) -> Any:
        with self._lock:
            v = self._data.get(key)
            if v is None:
                v = default
            else:
                v = copy.deepcopy(v)
        return v

    def put(self, key: str, value: Any) -> None:
        # Both key and value should be JSON serialisable.
        json.dumps([ key, value ])

        with self._lock:
            if value is not None:
                if self._data.get(key) != value:
                    self._modified = True
                    self._data[key] = copy.deepcopy(value)
            elif key in self._data:
                self._modified = True
                self._data.pop(key)

    def write(self) -> None:
        if threading.currentThread().isDaemon():
            logger.error('daemon thread cannot write wallet')
            return

        with self._lock:
            if self._modified or not self.is_primed():
                self._raw = self._write()
                self._modified = False

        logger.debug("saved '%s'", self._path)

    def _write(self) -> bytes:
        raise NotImplementedError

    def requires_split(self) -> bool:
        raise NotImplementedError

    def split_accounts(self) -> Optional[List[str]]:
        raise NotImplementedError

    def requires_upgrade(self) -> bool:
        raise NotImplementedError

    def upgrade(self) -> Optional['BaseStore']:
        raise NotImplementedError

    def _is_upgrade_method_needed(self, min_version, max_version):
        cur_version = self._get_seed_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise Exception(
                ('storage upgrade: unexpected version %d (should be %d-%d)'
                 % (cur_version, min_version, max_version)))
        else:
            return True

    def _get_seed_version(self) -> int:
        raise NotImplementedError

    def _raise_unsupported_version(self, seed_version):
        msg = "Your wallet has an unsupported seed version."
        msg += '\n\nWallet file: %s' % os.path.abspath(self._path)
        raise Exception(msg)



class DatabaseStore(BaseStore):
    _primed: bool = False
    _db_values: JSONKeyValueStore

    INITIAL_SEED_VERSION = 20

    def __init__(self, path: str, pubkey: Optional[str]=None,
            data: Optional[Dict[str, Any]]=None) -> None:
        # Start from any seed version remaining in the data lump that we inherit from the upgrade
        # from the `TextStore`. Otherwise we should default to the latest seed version for new
        # database stores, or whatever is currently persisted for existing database stores.
        seed_version = 0
        if data is not None and "seed_version" in data:
            seed_version = data.pop("seed_version")

        super().__init__(path, pubkey=pubkey, data=data)

        self._open_database()

        version_data = self._db_values.get("seed_version")
        if version_data is None:
            # A new database store, either for a freshly created wallet, or updated from a
            # text store.
            self._set_seed_version(seed_version or FINAL_SEED_VERSION)
        else:
            # An existing database store we are loading.
            self._primed = True
            self._set_seed_version(version_data)

    def move_to(self, new_path: str) -> None:
        assert os.path.exists(new_path + DATABASE_EXT)

        self._path = new_path
        self._open_database(close_existing=True)

    def close(self) -> None:
        # NOTE(rt12): Strictly speaking this just ensures that things are released and deallocated
        # for now. This ensures that the object gets garbage collected in a deterministic manner
        # which means that for instance the unit tests can rely on the database being closed
        # given knowledge of the resources in use, and their lifetime.
        # See: WalletStorage.close
        self._db_values.close()

    def _open_database(self, close_existing=False) -> None:
        if close_existing:
            self._db_values.close()

        # This table is unencrypted. If anything is to be encrypted in it, it is encrypted
        # manually before storage.
        initial_aeskey = None
        storage_group_id = -1
        self._db_values = JSONKeyValueStore("Storage", self._path, initial_aeskey,
            storage_group_id)

    def _get_seed_version(self) -> int:
        seed_version = self._db_values.get("seed_version")
        assert seed_version is not None
        return seed_version

    def _set_seed_version(self, seed_version: Optional[int]) -> None:
        assert seed_version is not None
        self._db_values.set("seed_version", seed_version)

    @classmethod
    def from_text_store(cls: Type[StoreType], store: 'TextStore') -> StoreType:
        data = copy.deepcopy(store._data)
        # Only fully updated text stores can upgrade to a database store.
        assert data.get("seed_version") == DatabaseStore.INITIAL_SEED_VERSION
        new_store = cls(store._path, store._pubkey, data)
        # We could defer writing to the caller, as an upgrade call should be followed by
        # a write, but the database file gets created regardless and should be created with
        # written initial state (which comes from the data).
        new_store.write()
        return new_store

    def read_raw_data(self) -> bytes:
        self._raw = self._db_values.get_value("jsondata")
        assert self._raw is not None
        return self._raw

    def get_path(self) -> str:
        return self._path + DATABASE_EXT

    def is_primed(self) -> bool:
        "Whether data has been written to the storage yet."
        return self._primed

    def is_encrypted(self) -> bool:
        assert self._raw is not None
        try:
            return self._raw[0:4] == b'BIE1'
        except:
            return False

    def load_data(self, s: bytes) -> None:
        self._data = json.loads(s)

    def _write(self) -> bytes:
        # We pack as JSON before encrypting, so can't just put in the generic key value store,
        # as that is unencrypted and would just be JSON values in the DB.

        s = json.dumps(self._data, indent=4, sort_keys=True)
        if self._pubkey:
            c = zlib.compress(s.encode())
            raw = PublicKey.from_hex(self._pubkey).encrypt_message(c)
        else:
            raw = s.encode()

        self._db_values.set("jsondata", raw)
        self._primed = True

        return raw

    def requires_split(self) -> bool:
        return False

    def requires_upgrade(self) -> bool:
        seed_version = self._get_seed_version()
        # Detect if we were given a file that should have been given to TextStore.
        if seed_version <= TextStore.FINAL_SEED_VERSION:
            raise IncompatibleWalletError(
                "This wallet should have been loaded as TEXT or HYBRID")
        # Detect if the wallet is a not yet upgraded DATABASE wallet.
        if seed_version < FINAL_SEED_VERSION:
            # Check if ESV was forked, or EC(BCH) or E(BTC) adopted our database changes.
            if self.get('wallet_author') == 'ESV':
                return True
            raise IncompatibleWalletError("This wallet was not created in ElectrumSV")
        return False

    def upgrade(self: StoreType) -> Optional[StoreType]:
        # NOTE(rt12): Loading the database migrates the table structure automatically. However
        # we will likely want to extend this to adjust table column contents, like the JSON
        # lump structure.
        seed_version = self._get_seed_version()
        if seed_version < 21:
            print("UPGRADE", seed_version)
            self._set_seed_version(FINAL_SEED_VERSION)
        return None


class TextStore(BaseStore):
    # seed_version is used for the version of the wallet file
    OLD_SEED_VERSION = 4        # electrum versions < 2.0
    NEW_SEED_VERSION = 11       # electrum versions >= 2.0
    FINAL_SEED_VERSION = 19     # electrum >= 2.7 will set this to prevent
                                # old versions from overwriting new format

    def read_raw_data(self) -> bytes:
        try:
            with open(self._path, "rb") as f:
                self._raw = f.read()
            # Ensure it can be decoded.
            self._raw.decode('utf8')
        except UnicodeDecodeError as e:
            raise IOError("Error reading file: "+ str(e))
        return self._raw

    def is_primed(self) -> bool:
        "Whether any data has ever been written to the storage."
        # We should only inherit existing text stores, not create new ones.
        return os.path.exists(self._path)

    def is_encrypted(self) -> bool:
        assert self._raw is not None
        try:
            return base64.b64decode(self._raw)[0:4] == b'BIE1'
        except:
            return False

    def get_encrypted_data(self) -> Optional[bytes]:
        data = self.get_raw_data()
        if data is not None:
            data = base64.b64decode(data)
        return data

    def load_data(self, s: bytes) -> None:
        try:
            self._data = json.loads(s)
        except:
            try:
                d = ast.literal_eval(s.decode('utf8'))
                labels = d.get('labels', {})
            except Exception as e:
                raise IOError("Cannot read wallet file '%s'" % self._path)
            self._data = {}
            for key, value in d.items():
                try:
                    json.dumps(key)
                    json.dumps(value)
                except:
                    logger.error('Failed to convert label to json format %s', key)
                    continue
                self._data[key] = value

    def _write(self) -> bytes:
        seed_version = self._get_seed_version()
        raw = json.dumps(self._data, indent=4, sort_keys=True)
        if self._pubkey:
            c = zlib.compress(raw.encode())
            raw = PublicKey.from_hex(self._pubkey).encrypt_message_to_base64(c)

        temp_path = "%s.tmp.%s" % (self._path, os.getpid())
        with open(temp_path, "w", encoding='utf-8') as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())

        file_exists = os.path.exists(self._path)
        mode = os.stat(self._path).st_mode if file_exists else stat.S_IREAD | stat.S_IWRITE
        os.replace(temp_path, self._path)
        os.chmod(self._path, mode)

        return raw.encode()

    def requires_split(self) -> bool:
        d = self.get('accounts', {})
        return len(d) > 1

    def split_accounts(self) -> Optional[List[str]]:
        result: List[str] = []
        # backward compatibility with old wallets
        d = self.get('accounts', {})
        if len(d) < 2:
            return None
        wallet_type = self.get('wallet_type')
        if wallet_type == 'old':
            assert len(d) == 2
            data1 = copy.deepcopy(self._data)
            storage1 = WalletStorage(self._path + '.deterministic', data=data1,
                storage_kind=StorageKind.FILE)
            storage1.put('accounts', {'0': d['0']})
            storage1.upgrade()
            storage1.write()
            storage1.close()

            data2 = copy.deepcopy(self._data)
            storage2 = WalletStorage(self._path + '.imported', data=data2,
                storage_kind=StorageKind.FILE)
            storage2.put('accounts', {'/x': d['/x']})
            storage2.put('seed', None)
            storage2.put('seed_version', None)
            storage2.put('master_public_key', None)
            storage2.put('wallet_type', 'imported')
            storage2.write()
            storage2.upgrade()
            storage2.write()
            storage2.close()

            result = [storage1.get_path(), storage2.get_path()]
        elif wallet_type in ['bip44', 'trezor', 'keepkey', 'ledger', 'btchip', 'digitalbitbox']:
            mpk = self.get('master_public_keys')
            for k in d.keys():
                i = int(k)
                x = d[k]
                if x.get("pending"):
                    continue
                xpub = mpk["x/%d'"%i]
                new_path = self._path + '.' + k
                data2 = copy.deepcopy(self._data)
                storage2 = WalletStorage(new_path, data=data2, storage_kind=StorageKind.FILE)
                # save account, derivation and xpub at index 0
                storage2.put('accounts', {'0': x})
                storage2.put('master_public_keys', {"x/0'": xpub})
                storage2.put('derivation', bip44_derivation(k))
                storage2.write()
                storage2.upgrade()
                storage2.write()
                storage2.close()

                result.append(new_path)
        else:
            raise Exception("This wallet has multiple accounts and must be split")
        return result

    def requires_upgrade(self) -> bool:
        seed_version = self._get_seed_version()
        # The version at which we should retain compatibility with Electrum and Electron Cash
        # if they upgrade their wallets using this versioning system correctly.
        if seed_version <= 17:
            return True
        # Versions above the compatible seed version, which may conflict with versions those
        # other wallets use.
        if seed_version < TextStore.FINAL_SEED_VERSION + 1:
            # We flag our upgraded wallets past seed version 17 with 'wallet_author' = 'ESV'.
            if self.get('wallet_author') == 'ESV':
                return True
            raise IncompatibleWalletError
        return False

    def upgrade(self) -> Optional[BaseStore]:
        self._convert_imported()
        self._convert_wallet_type()
        self._convert_account()
        self._convert_version_13_b()
        self._convert_version_14()
        self._convert_version_15()
        self._convert_version_16()
        self._convert_version_17()
        self._convert_version_18()
        self._convert_version_19()
        self._convert_version_20()

        database_wallet_path = self._path + DATABASE_EXT
        assert os.path.exists(database_wallet_path)
        assert not os.path.exists(self._path)

        return DatabaseStore.from_text_store(self)

    def _convert_imported(self) -> None:
        if not self._is_upgrade_method_needed(0, 13):
            return

        # '/x' is the internal ID for imported accounts
        d = self.get('accounts', {}).get('/x', {}).get('imported',{})
        if not d:
            return # False
        addresses = []
        keypairs = {}
        for addr, v in d.items():
            pubkey, privkey = v
            if privkey:
                keypairs[pubkey] = privkey
            else:
                addresses.append(addr)
        if addresses and keypairs:
            raise Exception('mixed addresses and privkeys')
        elif addresses:
            self.put('addresses', addresses)
            self.put('accounts', None)
        elif keypairs:
            self.put('wallet_type', 'standard')
            self.put('key_type', 'imported')
            self.put('keypairs', keypairs)
            self.put('accounts', None)
        else:
            raise Exception('no addresses or privkeys')

    def _convert_wallet_type(self) -> None:
        if not self._is_upgrade_method_needed(0, 13):
            return

        wallet_type = self.get('wallet_type')
        if wallet_type == 'btchip': wallet_type = 'ledger'
        if self.get('keystore') or self.get('x1/') or wallet_type=='imported':
            return # False
        assert not self.requires_split()
        seed_version = self._get_seed_version()
        seed = self.get('seed')
        xpubs = self.get('master_public_keys')
        xprvs = self.get('master_private_keys', {})
        mpk = self.get('master_public_key')
        keypairs = self.get('keypairs')
        key_type = self.get('key_type')
        if seed_version == self.OLD_SEED_VERSION or wallet_type == 'old':
            d = {
                'type': 'old',
                'seed': seed,
                'mpk': mpk,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif key_type == 'imported':
            d = {
                'type': 'imported',
                'keypairs': keypairs,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['xpub', 'standard']:
            xpub = xpubs["x/"]
            xprv = xprvs.get("x/")
            d = {
                'type': 'bip32',
                'xpub': xpub,
                'xprv': xprv,
                'seed': seed,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['bip44']:
            xpub = xpubs["x/0'"]
            xprv = xprvs.get("x/0'")
            d = {
                'type': 'bip32',
                'xpub': xpub,
                'xprv': xprv,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif wallet_type in ['trezor', 'keepkey', 'ledger', 'digitalbitbox']:
            xpub = xpubs["x/0'"]
            derivation = self.get('derivation', bip44_derivation(0))
            d = {
                'type': 'hardware',
                'hw_type': wallet_type,
                'xpub': xpub,
                'derivation': derivation,
            }
            self.put('wallet_type', 'standard')
            self.put('keystore', d)

        elif multisig_type(wallet_type):
            for key in xpubs.keys():
                d = {
                    'type': 'bip32',
                    'xpub': xpubs[key],
                    'xprv': xprvs.get(key),
                }
                if key == 'x1/' and seed:
                    d['seed'] = seed
                self.put(key, d)
        else:
            raise Exception(
                f'Unable to tell wallet type "{wallet_type}". Is this even a wallet file?')
        # remove junk
        self.put('master_public_key', None)
        self.put('master_public_keys', None)
        self.put('master_private_keys', None)
        self.put('derivation', None)
        self.put('seed', None)
        self.put('keypairs', None)
        self.put('key_type', None)

    def _convert_account(self) -> None:
        if not self._is_upgrade_method_needed(0, 13):
            return

        self.put('accounts', None)

    def _convert_version_13_b(self) -> None:
        # version 13 is ambiguous, and has an earlier and a later structure
        if not self._is_upgrade_method_needed(0, 13):
            return

        if self.get('wallet_type') == 'standard':
            if self.get('keystore').get('type') == 'imported':
                pubkeys = self.get('keystore').get('keypairs').keys()
                d: Dict[str, List[str]] = {'change': []}
                receiving_addresses = []
                for pubkey in pubkeys:
                    addr = PublicKey.from_hex(pubkey).to_address(coin=Net.COIN).to_string()
                    receiving_addresses.append(addr)
                d['receiving'] = receiving_addresses
                self.put('addresses', d)
                self.put('pubkeys', None)

        self.put('seed_version', 13)

    def _convert_version_14(self) -> None:
        # convert imported wallets for 3.0
        if not self._is_upgrade_method_needed(13, 13):
            return

        if self.get('wallet_type') =='imported':
            addresses = self.get('addresses')
            if type(addresses) is list:
                addresses = dict([(x, None) for x in addresses])
                self.put('addresses', addresses)
        elif self.get('wallet_type') == 'standard':
            if self.get('keystore').get('type')=='imported':
                addresses = set(self.get('addresses').get('receiving'))
                pubkeys = self.get('keystore').get('keypairs').keys()
                assert len(addresses) == len(pubkeys)
                d = {}
                for pubkey in pubkeys:
                    addr = PublicKey.from_hex(pubkey).to_address(coin=Net.COIN).to_string()
                    assert addr in addresses
                    d[addr] = {
                        'pubkey': pubkey,
                        'redeem_script': None,
                        'type': 'p2pkh'
                    }
                self.put('addresses', d)
                self.put('pubkeys', None)
                self.put('wallet_type', 'imported')
        self.put('seed_version', 14)

    def _convert_version_15(self) -> None:
        if not self._is_upgrade_method_needed(14, 14):
            return
        self.put('seed_version', 15)

    def _convert_version_16(self) -> None:
        # fixes issue #3193 for imported address wallets
        # also, previous versions allowed importing any garbage as an address
        #       which we now try to remove, see pr #3191
        if not self._is_upgrade_method_needed(15, 15):
            return

        def remove_address(addr):
            def remove_from_dict(dict_name):
                d = self.get(dict_name, None)
                if d is not None:
                    d.pop(addr, None)
                    self.put(dict_name, d)

            def remove_from_list(list_name):
                lst = self.get(list_name, None)
                if lst is not None:
                    s = set(lst)
                    s -= {addr}
                    self.put(list_name, list(s))

            # note: we don't remove 'addr' from self.get('addresses')
            remove_from_dict('addr_history')
            remove_from_dict('labels')
            remove_from_dict('payment_requests')
            remove_from_list('frozen_addresses')

        if self.get('wallet_type') == 'imported':
            addresses: Dict[str, Any] = self.get('addresses')
            assert isinstance(addresses, dict)
            addresses_new: Dict[str, Any] = {}
            for address, details in addresses.items():
                if not is_address_valid(address):
                    remove_address(address)
                    continue
                if details is None:
                    addresses_new[address] = {}
                else:
                    addresses_new[address] = details
            self.put('addresses', addresses_new)

        self.put('seed_version', 16)

    def _convert_version_17(self) -> None:
        if not self._is_upgrade_method_needed(16, 16):
            return
        if self.get('wallet_type') == 'imported':
            addrs = self.get('addresses')
            if all(v for v in addrs.values()):
                self.put('wallet_type', 'imported_privkey')
            else:
                self.put('wallet_type', 'imported_addr')

        self.put('seed_version', 17)

    def _convert_version_18(self) -> None:
        if not self._is_upgrade_method_needed(17, 17):
            return

        # The scope of this change is to move the bulk of the data stored in the encrypted JSON
        # wallet file, into encrypted external storage.  At the time of the change, this
        # storage is based on an Sqlite database.

        wallet_type = self.get('wallet_type')

        tx_store_aeskey_hex = self.get('tx_store_aeskey')
        if tx_store_aeskey_hex is None:
            tx_store_aeskey_hex = os.urandom(32).hex()
            self.put('tx_store_aeskey', tx_store_aeskey_hex)
        tx_store_aeskey = bytes.fromhex(tx_store_aeskey_hex)

        db = WalletData(self._path, tx_store_aeskey, 0)

        # Transaction-related data.
        tx_map_in = self.get('transactions', {})
        tx_fees = self.get('fees', {})
        tx_verified = self.get('verified_tx3', {})

        _history = self.get('addr_history',{})
        hh_map = {tx_hash: tx_height
                  for addr_history in _history.values()
                  for tx_hash, tx_height in addr_history}

        to_add1 = []
        for tx_id, tx in tx_map_in.items():
            payload = bytes.fromhex(str(tx))
            fee = tx_fees.get(tx_id, None)
            if tx_id in tx_verified:
                flags = TxFlags.StateSettled
                height, timestamp, position = tx_verified[tx_id]
            else:
                flags = TxFlags.StateCleared
                timestamp = position = None
                height = hh_map.get(tx_id)
            tx_data = TxData(height=height, fee=fee, position=position, timestamp=timestamp)
            to_add1.append((tx_id, tx_data, payload, flags))
        if len(to_add1):
            db.tx_store.add_many(to_add1)

        # Address/utxo related data.
        txi = self.get('txi', {})
        to_add2 = []
        for tx_hash, address_entry in txi.items():
            for address_string, output_values in address_entry.items():
                for prevout_key, amount in output_values:
                    prevout_tx_hash, prev_idx = prevout_key.split(":")
                    txin = DBTxInput(address_string, prevout_tx_hash, int(prev_idx), amount)
                    to_add2.append((tx_hash, txin))
        if len(to_add2):
            db.txin_store.add_entries(to_add2)

        txo = self.get('txo', {})
        to_add = []
        for tx_hash, address_entry in txo.items():
            for address_string, input_values in address_entry.items():
                for txout_n, amount, is_coinbase in input_values:
                    txout = DBTxOutput(address_string, txout_n, amount, is_coinbase)
                    to_add.append((tx_hash, txout))
        if len(to_add):
            db.txout_store.add_entries(to_add)

        addresses = self.get('addresses')
        if addresses is not None:
            # Bug in the wallet storage upgrade tests, it turns this into a dict.
            if wallet_type == "imported_addr" and type(addresses) is dict:
                addresses = list(addresses.keys())
            db.misc_store.add('addresses', addresses)
        db.misc_store.add('addr_history', self.get('addr_history'))
        db.misc_store.add('frozen_addresses', self.get('frozen_addresses'))

        # Convert from "hash:n" to (hash, n).
        frozen_coins = self.get('frozen_coins', [])
        for i, s in enumerate(frozen_coins):
            hash, n = s.split(":")
            n = int(n)
            frozen_coins[i] = (hash, n)
        db.misc_store.add('frozen_coins', frozen_coins)

        pruned_txo = self.get('pruned_txo', {})
        new_pruned_txo = {}
        for k, v in pruned_txo.items():
            hash, n = k.split(":")
            n = int(n)
            new_pruned_txo[(hash, n)] = v
        db.misc_store.add('pruned_txo', new_pruned_txo)

        self.put('addresses', None)
        self.put('addr_history', None)
        self.put('frozen_addresses', None)
        self.put('frozen_coins', None)
        self.put('pruned_txo', None)
        self.put('transactions', None)
        self.put('txi', None)
        self.put('txo', None)
        self.put('tx_fees', None)
        self.put('verified_tx3', None)

        self.put('wallet_author', 'ESV')
        self.put('seed_version', 18)

    def _convert_version_19(self) -> None:
        if not self._is_upgrade_method_needed(18, 18):
            return

        # The scope of this upgrade is the move towards a wallet no longer being a keystore,
        # but being a container for one or more child wallets. The goal of this change was to
        # prepare for a move towards an account-oriented interface.

        wallet_type = self.get('wallet_type')
        assert wallet_type is not None, "Wallet has no type"

        # Some of these fields are specific to the wallet type, and others are common.
        possible_wallet_fields = [ "gap_limit", "invoices", "labels",
            "multiple_change", "payment_requests", "stored_height", "use_change" ]

        # 2. Move the local contents of this wallet into the first account / legacy wallet.
        subwallet_data = {}
        subwallet_data['wallet_type'] = wallet_type
        for field_name in possible_wallet_fields:
            field_value = self.get(field_name)
            if field_value is not None:
                # Move this field to the subwallet data, and remove from the parent wallet.
                subwallet_data[field_name] = field_value
                self.put(field_name, None)

        # 3. Move the keystore out of the subwallet, and put a reference to it instead.
        keystores = []
        keystore = self.get('keystore')
        if keystore is not None:
            keystores.append(keystore)
            subwallet_data['keystore_usage'] = [ { 'index': 0, }, ]

        # Special case for the multiple keystores for the multisig wallets.
        multsig_mn = multisig_type(wallet_type)
        if multsig_mn is not None:
            keystore_usage = []
            m, n = multsig_mn
            for i in range(n):
                keystore_name = f'x{i+1:d}/'
                keystore = self.get(keystore_name)
                keystores.append(keystore)
                self.put(field_name, None)
                keystore_usage.append({ 'index': i, 'name': keystore_name })
            subwallet_data['keystore_usage'] = keystore_usage

        # Linked to the wallet database GroupId column.
        subwallet_id = 0
        subwallet_data["id"] = subwallet_id

        self.put('keystores', keystores)
        self.put('subwallets', [ subwallet_data ])
        self.put('wallet_type', ParentWalletKinds.LEGACY)

        # Convert the database to designate child wallets.
        tx_store_aeskey = bytes.fromhex(self.get('tx_store_aeskey'))
        WalletData(self._path, tx_store_aeskey, subwallet_id, MigrationContext(18, 19))

        self.put('seed_version', 19)

    def _convert_version_20(self) -> None:
        if not self._is_upgrade_method_needed(19, 19):
            return

        # Remove the TEXT file, as the store is now database-only.
        assert os.path.exists(self._path + DATABASE_EXT)
        # The only case where the file will not exist is where we upgraded from split accounts,
        os.remove(self._path)

        # Setting this will ensure this store cannot write the TEXT file again.
        self.put('seed_version', 20)

    def _get_seed_version(self) -> int:
        seed_version = self.get('seed_version')
        if not seed_version:
            seed_version = (self.OLD_SEED_VERSION if len(self.get('master_public_key','')) == 128
                else self.NEW_SEED_VERSION)
        if seed_version > self.FINAL_SEED_VERSION:
            raise IncompatibleWalletError("TEXT store has DATABASE store version")
        if seed_version >= 12:
            return seed_version
        if seed_version not in (self.OLD_SEED_VERSION, self.NEW_SEED_VERSION):
            self._raise_unsupported_version(seed_version)
        return seed_version

    def _raise_unsupported_version(self, seed_version: int) -> None:
        msg = "Your wallet has an unsupported seed version."
        msg += '\n\nWallet file: %s' % os.path.abspath(self._path)
        if seed_version in [5, 7, 8, 9, 10, 14]:
            msg += "\n\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
        if seed_version == 6:
            # version 1.9.8 created v6 wallets when an incorrect seed
            # was entered in the restore dialog
            msg += '\n\nThis file was created because of a bug in version 1.9.8.'
            if (self.get('master_public_keys') is None and
                self.get('master_private_keys') is None and
                self.get('imported_keys') is None):
                # pbkdf2 (at that time an additional dependency) was not included
                # with the binaries, and wallet creation aborted.
                msg += "\nIt does not contain any keys, and can safely be removed."
            else:
                # creation was complete if electrum was run from source
                msg += ("\nPlease open this file with Electrum 1.9.8, and move "
                        "your coins to a new wallet.")
        raise Exception(msg)


class WalletStorage:
    _store: BaseStore

    def __init__(self, path: str, manual_upgrades: bool=False,
            data: Optional[Dict[str, Any]]=None,
            storage_kind: StorageKind=StorageKind.UNKNOWN) -> None:
        logger.debug("wallet path '%s'", path)
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            raise IOError(f'directory {dirname} does not exist')

        storage_info = categorise_file(path)
        if storage_kind == StorageKind.UNKNOWN:
            storage_kind = storage_info.kind
        # Take the chance to normalise the wallet filename (remove any extension).
        if storage_info.kind == StorageKind.DATABASE:
            path = storage_info.wallet_filepath

        self._manual_upgrades = manual_upgrades
        self._path = path

        store: Optional[BaseStore] = None
        if storage_kind == StorageKind.UNKNOWN:
            store = DatabaseStore(path, data=data)
            self._set_store(store)

            # Initialise anything that needs to be in the wallet storage and immediately persisted.
            # In the case of the aeskey, this is because the wallet saving is not guaranteed and
            # the writes to the database are not synchronised with it.
            tx_store_aeskey_hex = os.urandom(32).hex()
            self.put('tx_store_aeskey', tx_store_aeskey_hex)

            self.put('wallet_author', 'ESV')
            self.put('seed_version', FINAL_SEED_VERSION)
        else:
            is_unsaved_file = (storage_kind == StorageKind.FILE and not os.path.exists(path) and \
                data is not None)
            assert data is None or is_unsaved_file
            if storage_kind == StorageKind.FILE or storage_kind == StorageKind.HYBRID:
                store = TextStore(path, data=data)
            else:
                store = DatabaseStore(path)
            self._set_store(store)

            # Unsaved files already have explicit unpersisted data. Note that no upgrade will be
            # performed on them, regardless of the value of `manual_upgrades`.
            if not is_unsaved_file:
                raw = self._store.read_raw_data()
                if not self._store.is_encrypted():
                    self.load_data(raw)

    def move_to(self, new_path: str) -> None:
        # This does not remove the original database file. The move refers to the switch over
        # to the copy as the underlying store.
        if new_path.lower().endswith(DATABASE_EXT):
            new_path = new_path[:-len(DATABASE_EXT)]

        shutil.copyfile(self.get_path(), new_path + DATABASE_EXT)

        # NOTE(rt12): Everything keeps the extensionless path. Need to consider if it makes it
        # easier to keep the full path, and refactor accordingly.
        self._path = new_path
        self._store.move_to(new_path)

    def close(self) -> None:
        # NOTE(rt12): Strictly speaking this just ensures that things are released and deallocated
        # for now. This ensures that the object gets garbage collected in a deterministic manner
        # which means that for instance the unit tests can rely on the database being closed
        # given knowledge of the resources in use, and their lifetime.
        # See: DatabaseStore.close
        self._store.close()

        del self.get
        del self.put
        del self.write
        del self.requires_split
        del self.split_accounts
        del self.requires_upgrade
        del self.is_encrypted

    def get_path(self) -> str:
        return self._store.get_path()

    def load_data(self, raw: bytes) -> None:
        self._store.load_data(raw)
        self._load_data()

    def _load_data(self) -> None:
        if not self._manual_upgrades:
            if self.requires_split():
                raise Exception("This wallet has multiple accounts and must be split")
            if self.requires_upgrade():
                self.upgrade()

    @staticmethod
    def get_eckey_from_password(password: str) -> PrivateKey:
        secret = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=1024)
        return PrivateKey.from_arbitrary_bytes(secret)

    def decrypt(self, password: str) -> None:
        ec_key = self.get_eckey_from_password(password)
        encrypted_data = self._store.get_encrypted_data()
        assert type(encrypted_data) is bytes
        raw = zlib.decompress(ec_key.decrypt_message(encrypted_data))

        pubkey = ec_key.public_key.to_hex()
        self._store.set_pubkey(pubkey)

        self.load_data(raw)

    def set_password(self, password: Optional[str]) -> None:
        self.put('use_encryption', bool(password))
        if password:
            ec_key = self.get_eckey_from_password(password)
            pubkey = ec_key.public_key.to_hex()
        else:
            pubkey = None
        self._store.set_pubkey(pubkey)

    def _set_store(self, store: StoreType) -> None:
        self._store = store

        self.get = store.get
        self.put = store.put
        self.write = store.write
        self.requires_split = store.requires_split
        self.split_accounts = store.split_accounts
        self.requires_upgrade = store.requires_upgrade
        self.is_encrypted = store.is_encrypted

    def upgrade(self) -> None:
        logger.debug('upgrading wallet format')
        backup_wallet_files(self._path)

        # The store can change if the old kind of store was obsoleted. We upgrade through
        # obsoleted kinds of stores to the final in-use kind of store.
        while True:
            print(f"upgrade {self._store}")
            new_store = self._store.upgrade()
            if new_store is not None:
                self._set_store(new_store)
                print(f"new_store.requires_upgrade {new_store.requires_upgrade()}")
                if new_store.requires_upgrade():
                    continue
            break

    @classmethod
    def files_are_matched_by_path(klass, path: str) -> StorageKind:
        return categorise_file(path).kind != StorageKind.UNKNOWN

    @classmethod
    def canonical_path(klass, database_filepath: str) -> str:
        if not database_filepath.lower().endswith(DATABASE_EXT):
            database_filepath += "."+ DATABASE_EXT
        return database_filepath
