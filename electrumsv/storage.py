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

from __future__ import annotations
import ast
import base64
import binascii
import concurrent.futures
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import threading
from typing import Any, cast, Iterable, NamedTuple, Sequence, Type, TYPE_CHECKING, TypeVar
import zlib

from bitcoinx import DecryptionError, hash_to_hex_str, hex_str_to_hash, PrivateKey, PublicKey
from bitcoinx.address import P2PKH_Address, P2SH_Address
from electrumsv_database.sqlite import DatabaseContext

from .bitcoin import is_address_valid, address_from_string
from .constants import (CHANGE_SUBPATH, DATABASE_EXT, DerivationType,
    DerivationPath, MIGRATION_CURRENT, MIGRATION_FIRST, RECEIVING_SUBPATH, ScriptType, StorageKind,
    KeyInstanceFlag)
from .crypto import pw_encode, pw_decode
from .exceptions import IncompatibleWalletError, InvalidPassword
from .i18n import _
from .keystore import bip44_derivation
from .logs import logs
from .networks import Net
from .standards.script_templates import classify_transaction_output_script, parse_script_sig
from .transaction import Transaction, XPublicKey
from .util import get_posix_timestamp
from .util.misc import ProgressCallbacks
from .wallet_database import migration
from .wallet_database import functions as db_functions
from .wallet_database.storage_migration import (create_accounts1, create_keys1,
    create_master_keys1, create_payment_requests1, create_transaction_deltas_22, \
    create_transaction_outputs1,
    create_transactions1, create_wallet_datas1, AccountRow1, KeyInstanceRow_22, MasterKeyRow_22,
    PaymentRequestRow_22, TransactionDeltaRow_22, TransactionOutputFlag1, TransactionOutputRow_22,
    TransactionRow1, TxData1,
    TxFlags_22, read_wallet_data1, update_wallet_datas1, WalletDataRow1)
from .wallet_database.types import WalletDataRow


if TYPE_CHECKING:
    from .credentials import PasswordTokenProtocol


T1 = TypeVar("T1")
T2 = TypeVar("T2")

logger = logs.get_logger("storage")



def multisig_type(wallet_type: str) -> tuple[int, int] | None:
    '''If wallet_type is mofn multi-sig, return [m, n],
    otherwise return None.'''
    if wallet_type:
        match = re.match(r'(\d+)of(\d+)', wallet_type)
        if match:
            result = tuple(int(x) for x in match.group(1, 2))
            return cast(tuple[int, int], result)
    return None

FINAL_SEED_VERSION = 22


class WalletStorageInfo(NamedTuple):
    kind: StorageKind
    filename: str
    wallet_filepath: str

    def exists(self) -> bool:
        if self.kind == StorageKind.FILE:
            return os.path.exists(self.wallet_filepath)
        elif self.kind != StorageKind.HYBRID:
            return os.path.exists(self.wallet_filepath + DATABASE_EXT)
        raise ValueError(f"Kind {self.kind} should not reach here")


def get_categorised_files(wallet_path: str, exclude_suffix: str='') -> list[WalletStorageInfo]:
    """
    This categorises files based on the three different ways in which we have stored wallets.

    FILE - Just the JSON file (version <= 17).
      thiswalletfile
    HYBRID - Partial transition from JSON file to database (version = 18 or 19).
      thiswalletfile / thiswalletfile.sqlite. We do not support these. They were an interim
      development branch step. These will be dropped entirely after some transition period
      has passed.
    DATABASE - Just the database (version >= 22).
      thiswalletfile.sqlite
    """
    filenames = {
        s for s in os.listdir(wallet_path)
        if not (exclude_suffix and s.endswith(exclude_suffix))
    }
    database_filenames = { s for s in filenames if s.endswith(DATABASE_EXT) }
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


def backup_wallet_file(wallet_filepath: str) -> tuple[str, str] | None:
    info = categorise_file(wallet_filepath)
    if info.kind not in (StorageKind.FILE, StorageKind.DATABASE):
        return None

    base_wallet_filepath = os.path.join(os.path.dirname(wallet_filepath), info.filename)
    attempt = 0
    while True:
        attempt += 1
        attempted_wallet_filepath = f"{base_wallet_filepath}.backup.{attempt}"

        # Check if a file of the same name as the attempted database backup exists.
        if info.kind == StorageKind.DATABASE:
            if os.path.exists(attempted_wallet_filepath + DATABASE_EXT):
                continue
        # Check if a file of the same name as the attempted file backup exists.
        if info.kind == StorageKind.FILE:
            if os.path.exists(attempted_wallet_filepath):
                continue

        # No objection, the attempted backup path is acceptable.
        break

    if info.kind == StorageKind.DATABASE:
        shutil.copyfile(
            base_wallet_filepath + DATABASE_EXT, attempted_wallet_filepath + DATABASE_EXT)
        return base_wallet_filepath + DATABASE_EXT, attempted_wallet_filepath + DATABASE_EXT
    if info.kind == StorageKind.FILE:
        shutil.copyfile(base_wallet_filepath,  attempted_wallet_filepath)
        return base_wallet_filepath, attempted_wallet_filepath

    return None


StoreType = TypeVar('StoreType', bound='AbstractStore')

class AbstractStore:
    def __init__(self, path: str, data: dict[str, Any] | None=None) -> None:
        assert not path.endswith(DATABASE_EXT)
        self._path = path

        self._data = {} if data is None else data

        self._lock = threading.RLock()

    def close(self) -> None:
        pass

    def set_path(self, new_path: str) -> None:
        self._path = new_path

    def get_path(self) -> str:
        return self._path

    def check_password(self, password: str) -> None:
        raise NotImplementedError

    def attempt_load_data(self) -> bool:
        raise NotImplementedError

    def get(self, key: str, default: Any=None) -> Any:
        with self._lock:
            v = self._data.get(key)
            if v is None:
                v = default
            else:
                v = copy.deepcopy(v)
        return v

    def get_explicit_type(self, return_type: Type[T1], key: str, default: T1) -> T1:
        with self._lock:
            v = self._data.get(key)
            if v is None:
                return default
            ret = cast(T1, copy.deepcopy(v))
        assert isinstance(ret, return_type)
        return ret

    def put(self, key: str, value: Any, already_persisted: bool=False) -> None:
        """
        This caches the update in `self._data` and also posts a database operation to the
        writer thread to update the wallet database. This function should therefore be
        non-blocking except when there is lock contention. However for the asynchronous thread
        this will block the scheduler and will not yield to other tasks, allowing race conditions.
        """
        # Both key and value should be JSON serialisable.
        json.dumps([ key, value ])

        with self._lock:
            if value is not None:
                if self._data.get(key) != value:
                    self._data[key] = copy.deepcopy(value)
                    self._on_value_modified(key, self._data[key], already_persisted)
            elif key in self._data:
                self._data.pop(key)
                self._on_value_deleted(key, already_persisted)

    def _on_value_modified(self, key: str, value: Any, already_persisted: bool=False) -> None:
        raise NotImplementedError

    def _on_value_deleted(self, key: str, already_persisted: bool=False) -> None:
        raise NotImplementedError

    def write(self) -> None:
        if threading.current_thread().daemon:
            logger.error('daemon thread cannot write wallet')
            return

        with self._lock:
            self._write()

        logger.debug("saved '%s'", self._path)

    def _write(self) -> None:
        raise NotImplementedError

    def requires_split(self) -> bool:
        raise NotImplementedError

    def split_accounts(self, has_password: bool,
            new_password_token: PasswordTokenProtocol) -> list[str] | None:
        raise NotImplementedError

    def requires_upgrade(self) -> bool:
        raise NotImplementedError

    def upgrade(self, has_password: bool, new_password_token: PasswordTokenProtocol,
            callbacks: ProgressCallbacks | None=None) -> AbstractStore | None:
        raise NotImplementedError

    def _get_version(self) -> int:
        raise NotImplementedError


class DatabaseStore(AbstractStore):
    _db_context: DatabaseContext

    def __init__(self, path: str, password_token: PasswordTokenProtocol | None=None) -> None:
        super().__init__(path)

        database_already_exists = os.path.exists(self.get_path())
        if not database_already_exists:
            assert password_token is not None
            # The database does not exist. Create it with the latest schema.
            # Note that the migration process will have pre-created it through in
            # `_convert_to_database`.
            from .wallet_database.migration import create_database_file, update_database_file
            create_database_file(path)
            update_database_file(path, password_token)
        self.open_database()
        self.attempt_load_data()

    def close(self) -> None:
        self.close_database()

    def set_path(self, new_path: str) -> None:
        assert os.path.exists(new_path + DATABASE_EXT)
        super().set_path(new_path)

    def open_database(self) -> None:
        # This table is unencrypted. If anything is to be encrypted in it, it is encrypted
        # manually before storage.
        self._db_context = DatabaseContext(self._path)

    def close_database(self) -> None:
        # Wait for the database to finish writing, and verify that the context has been fully
        # released by all stores that make use of it.
        self._db_context.close()

    @classmethod
    def from_text_store(cls: Type[DatabaseStore], text_store: TextStore,
            password_token: PasswordTokenProtocol) -> DatabaseStore:
        # Only fully updated text stores can upgrade to a database store.
        data = text_store._data.copy()
        assert text_store._data.pop("seed_version", -1) == MIGRATION_FIRST
        return cls(text_store._path, password_token=password_token)

    def get_path(self) -> str:
        return self._path + DATABASE_EXT

    def check_password(self, password: str) -> None:
        password_token: str | None = self.get("password-token")
        assert password_token is not None
        pw_decode(password_token, password)

    def attempt_load_data(self) -> bool:
        self._data = {}
        for row in db_functions.read_wallet_datas(self._db_context):
            self._data[row[0]] = row[1]
        return True

    def _on_value_modified(self, key: str, value: Any, already_persisted: bool=False) -> None:
        # Queued write, we do not wait for it to complete. Closing the DB context will wait.
        if not already_persisted:
            db_functions.post_update_wallet_datas(self._db_context, [ WalletDataRow(key, value) ])

    def _on_value_deleted(self, key: str, already_persisted: bool=False) -> None:
        # Queued write, we do not wait for it to complete. Closing the DB context will wait.
        if not already_persisted:
            db_functions.post_delete_wallet_data(self._db_context, key)

    def _write(self) -> None:
        pass

    def requires_split(self) -> bool:
        return False

    def requires_upgrade(self) -> bool:
        return self.get_explicit_type(int, "migration", 0) < MIGRATION_CURRENT

    def upgrade(self: DatabaseStore, has_password: bool,
            new_password_token: PasswordTokenProtocol,
            callbacks: ProgressCallbacks | None=None) -> DatabaseStore | None:
        from .wallet_database.migration import update_database
        connection = self._db_context.acquire_connection()
        try:
            update_database(connection, new_password_token, callbacks)
        finally:
            self._db_context.release_connection(connection)
        # Refresh the cached data.
        self.attempt_load_data()
        assert MIGRATION_CURRENT == self.get("migration")
        return None


class TextStore(AbstractStore):
    _raw: bytes | None = None

    # seed_version is used for the version of the wallet file
    OLD_SEED_VERSION = 4        # electrum versions < 2.0
    NEW_SEED_VERSION = 11       # electrum versions >= 2.0
    FINAL_SEED_VERSION = 17     # electrum >= 2.7 will set this to prevent
                                # old versions from overwriting new format

    def __init__(self, path: str, data: dict[str, Any] | None=None) -> None:
        super().__init__(path, data)
        self._modified = bool(data)

    def _read_raw_data(self) -> Any:
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
        except Exception:
            return False

    def check_password(self, password: str) -> None:
        self._read_raw_data()
        try:
            self.decrypt(password)
        except DecryptionError:
            raise InvalidPassword
        except binascii.Error:
            # Someone opens something that isn't a wallet and gets asked for a password.
            # Decryption can't happen because base64 decoding fails.
            raise IncompatibleWalletError

    def decrypt(self, password: str) -> bytes:
        assert self._raw is not None
        ec_key = WalletStorage.get_eckey_from_password(password)
        encrypted_data = base64.b64decode(self._raw)
        return zlib.decompress(ec_key.decrypt_message(encrypted_data))

    def attempt_load_data(self) -> bool:
        data = self._read_raw_data()
        assert type(data) is bytes
        if not self.is_encrypted():
            self.load_data(data)
            return True
        return False

    def _set_data(self, data: dict[str, Any]) -> None:
        self._data = data

    def load_data(self, data: Any) -> None:
        try:
            self._data = json.loads(data)
        except Exception:
            try:
                d = ast.literal_eval(data.decode('utf8'))
                labels = d.get('labels', {})
            except Exception as e:
                raise IOError("Cannot read wallet file '%s'" % self._path)
            self._data = {}
            for key, value in d.items():
                try:
                    json.dumps(key)
                    json.dumps(value)
                except Exception:
                    logger.error('Failed to convert label to json format %s', key)
                    continue
                self._data[key] = value

    def _on_value_modified(self, key: str, value: Any, already_persisted: bool=False) -> None:
        if not already_persisted:
            self._modified = True

    def _on_value_deleted(self, key: str, already_persisted: bool=False) -> None:
        if not already_persisted:
            self._modified = True

    def _write(self) -> None:
        if self._modified or not self.is_primed():
            seed_version = self._get_version()
            raw = json.dumps(self._data, indent=4, sort_keys=True)
            temp_path = "%s.tmp.%s" % (self._path, os.getpid())
            with open(temp_path, "w", encoding='utf-8') as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())

            file_exists = os.path.exists(self._path)
            mode = os.stat(self._path).st_mode if file_exists else stat.S_IREAD | stat.S_IWRITE
            os.replace(temp_path, self._path)
            os.chmod(self._path, mode)

            self._modified = False

    def requires_split(self) -> bool:
        d = self.get('accounts', {})
        return len(d) > 1

    def split_accounts(self, has_password: bool,
            new_password_token: PasswordTokenProtocol) -> list[str] | None:
        result: list[str] = []
        # backward compatibility with old wallets
        d = self.get('accounts', {})
        if len(d) < 2:
            return None
        wallet_type = self.get('wallet_type')
        if wallet_type == 'old':
            assert len(d) == 2
            data1 = copy.deepcopy(self._data)
            storage1 = WalletStorage.from_file_data(self._path + '.deterministic', data1)
            storage1.put('accounts', {'0': d['0']})
            storage1.upgrade(has_password, new_password_token)
            storage1.write()
            storage1.close()

            data2 = copy.deepcopy(self._data)
            storage2 = WalletStorage.from_file_data(self._path + '.imported', data2)
            storage2.put('accounts', {'/x': d['/x']})
            storage2.put('seed', None)
            storage2.put('seed_version', None)
            storage2.put('master_public_key', None)
            storage2.put('wallet_type', 'imported')
            storage2.write()
            storage2.upgrade(has_password, new_password_token)
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
                storage2 = WalletStorage.from_file_data(new_path, data2)
                # save account, derivation and xpub at index 0
                storage2.put('accounts', {'0': x})
                storage2.put('master_public_keys', {"x/0'": xpub})
                storage2.put('derivation', bip44_derivation(k))
                storage2.write()
                storage2.upgrade(has_password, new_password_token)
                storage2.write()
                storage2.close()

                result.append(new_path)
        else:
            raise Exception("This wallet has multiple accounts and must be split")
        return result

    def requires_upgrade(self) -> bool:
        seed_version = self._get_version()
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
            raise IncompatibleWalletError("Not an ElectrumSV wallet")
        return False

    def upgrade(self, has_password: bool, new_password_token: PasswordTokenProtocol,
            callbacks: ProgressCallbacks | None=None) -> AbstractStore | None:
        self._convert_imported()
        self._convert_wallet_type()
        self._convert_account()
        self._convert_version_13_b()
        self._convert_version_14()
        self._convert_version_15()
        self._convert_version_16()
        self._convert_version_17()
        self._convert_to_database(has_password, new_password_token)
        assert self.get("seed_version") == MIGRATION_FIRST, ("expected "
            f"{MIGRATION_FIRST}, got {self.get('seed_version')}")

        database_wallet_path = self._path + DATABASE_EXT
        assert os.path.exists(database_wallet_path)
        assert not os.path.exists(self._path)

        return DatabaseStore.from_text_store(self, new_password_token)

    def _is_upgrade_method_needed(self, min_version: int, max_version: int) -> bool:
        cur_version = self._get_version()
        if cur_version > max_version:
            return False
        elif cur_version < min_version:
            raise Exception(
                ('storage upgrade: unexpected version %d (should be %d-%d)'
                 % (cur_version, min_version, max_version)))
        else:
            return True

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

        wallet_type = self.get_explicit_type(str, 'wallet_type', "")
        if wallet_type == 'btchip': wallet_type = 'ledger'
        if self.get('keystore') or self.get('x1/') or wallet_type=='imported':
            return # False
        assert not self.requires_split()
        seed_version = self._get_version()
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
                d: dict[str, list[str]] = {'change': []}
                receiving_addresses = []
                for pubkey in pubkeys:
                    addr = PublicKey.from_hex(pubkey).to_address(network=Net.COIN).to_string()
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
                    addr = PublicKey.from_hex(pubkey).to_address(network=Net.COIN).to_string()
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

        def remove_address(addr: str) -> None:
            def remove_from_dict(dict_name: str) -> None:
                d = self.get(dict_name, None)
                if d is not None:
                    d.pop(addr, None)
                    self.put(dict_name, d)

            def remove_from_list(list_name: str) -> None:
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
            addresses: dict[str, Any] = self.get('addresses')
            assert isinstance(addresses, dict)
            addresses_new: dict[str, Any] = {}
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

    def _convert_to_database(self, has_password: bool,
            new_password_token: PasswordTokenProtocol) -> None:
        if not self._is_upgrade_method_needed(17, 17):
            return

        wallet_type = self.get('wallet_type')
        assert wallet_type is not None, "Wallet has no type"

        # Create the latest database structure with only initial populated data.
        migration.create_database_file(self._path)

        new_password = new_password_token.password

        # Take the old style JSON data and add it to the latest database structure.
        # This code should be updated as the structure and wallet workings changes to ensure
        # older wallets can always be migrated as long as we support them.
        db_context = DatabaseContext(self._path)
        try:
            next_masterkey_id = cast(int, read_wallet_data1(db_context, "next_masterkey_id"))
            next_account_id = cast(int, read_wallet_data1(db_context, "next_account_id"))
            next_keyinstance_id = cast(int, read_wallet_data1(db_context, "next_keyinstance_id"))
            next_paymentrequest_id = cast(int, read_wallet_data1(db_context,
                "next_paymentrequest_id"))

            masterkey_id = next_masterkey_id
            next_masterkey_id += 1
            account_id = next_account_id
            next_account_id += 1

            masterkey_rows: list[MasterKeyRow_22] = []
            account_rows: list[AccountRow1] = []
            keyinstance_rows: list[KeyInstanceRow_22] = []
            txdelta_rows: list[TransactionDeltaRow_22] = []
            transaction_rows: list[TransactionRow1] = []
            txoutput_rows: list[TransactionOutputRow_22] = []
            paymentrequest_rows: list[PaymentRequestRow_22] = []

            class _TxState(NamedTuple):
                tx: Transaction
                tx_hash: bytes
                bytedata: bytes
                verified: bool
                height: int
                known_addresses: set[str]
                encountered_addresses: set[str]

            class _TxOutputState(NamedTuple):
                value: int
                row_index: int

            class _AddressState(NamedTuple):
                keyinstance_id: int
                row_index: int
                script_type: ScriptType

            address_usage: dict[str, Iterable[tuple[str, int]]] = self.get('addr_history', {})
            frozen_addresses: set[str] = set(self.get('frozen_addresses', []))
            frozen_coins: list[str] = self.get('frozen_coins', [])
            tx_map_in: dict[str, str] = self.get('transactions', {})
            tx_fees: dict[str, int] = self.get('tx_fees', {})
            tx_verified: dict[str, Any] = self.get('verified_tx3', {})
            labels: dict[str, str] = self.get('labels', {})

            # height > 0: confirmed
            # height = 0: unconfirmed
            # height < 0: unconfirmed with unconfirmed parents
            # { address_string: { tx_id: tx_height } }
            tx_heights = {tx_id: tx_height
                    for addr_history in address_usage.values()
                    for tx_id, tx_height in addr_history}

            txouts_frozen = set()
            for txo_id in frozen_coins:
                tx_id, n = txo_id.split(":")
                txouts_frozen.add((tx_id, int(n)))

            address_states: dict[str, _AddressState] = {}
            tx_states: dict[str, _TxState] = {}

            date_added = get_posix_timestamp()
            for tx_id, tx_hex in tx_map_in.items():
                tx_hash = hex_str_to_hash(tx_id)
                tx_bytedata = bytes.fromhex(tx_hex)
                tx = Transaction.from_bytes(tx_bytedata)
                fee = tx_fees.get(tx_id)
                description = labels.pop(tx_id, None)
                if tx_id in tx_verified:
                    flags = TxFlags_22.STATE_SETTLED
                    height, _timestamp, position = tx_verified[tx_id]
                    tx_states[tx_id] = _TxState(tx=tx, tx_hash=tx_hash, bytedata=tx_bytedata,
                        verified=True, height=height, known_addresses=set(),
                        encountered_addresses=set())
                else:
                    height = tx_heights.get(tx_id)
                    flags = TxFlags_22.STATE_CLEARED
                    position = None
                    tx_states[tx_id] = _TxState(tx=tx, tx_hash=tx_hash, bytedata=tx_bytedata,
                        verified=False, height=height, known_addresses=set(),
                        encountered_addresses=set())
                tx_metadata = TxData1(height=height, fee=fee, position=position,
                    date_added=date_added, date_updated=date_added)
                transaction_rows.append(TransactionRow1(tx_hash, tx_metadata, tx_bytedata, flags,
                    description))

            # Index all the address usage via the ElectrumX server scripthash state.
            for address_string, usage_list in address_usage.items():
                for tx_id, tx_height in usage_list:
                    if tx_id not in tx_states:
                        raise IncompatibleWalletError(_("Wallets that are mid-synchronization "
                            "cannot be migrated."))
                    tx_states[tx_id].known_addresses.add(address_string)
                    assert tx_height <= tx_states[tx_id].height, \
                        (f"bad height {tx_height} > {tx_states[tx_id].height}" +
                        f"verified {tx_verified.get(tx_id)}" +
                        f"heights {tx_heights.get(tx_id)}")

            _addresses = self.get("addresses")
            if not isinstance(_addresses, dict):
                _addresses = {}
            _receiving_address_strings = _addresses.get('receiving', [])
            _change_address_strings = _addresses.get('change', [])

            # Network check. Error if the user started up with a wallet on a different network.
            if len(_receiving_address_strings):
                sample_address_string = _receiving_address_strings[0]
                # This will raise a ValueError if the address is incompatible with the network.
                address_from_string(sample_address_string)

            def update_private_data(data: str) -> str:
                # We can assume that the new password is the old password.
                if has_password:
                    # We do this for several reasons.
                    # 1. A legacy wallet that has encrypted secured data, but not the file itself.
                    # 2. Any passworded wallet that has data, to ensure it is correctly encrypted.
                    pw_decode(data, new_password)
                    return data
                return pw_encode(data, new_password)

            def get_keystore_data(data: dict[str, Any]) -> tuple[DerivationType, dict[str, Any]]:
                derivation_type: DerivationType
                keystore_type: str = data.pop("type")
                if keystore_type == "hardware":
                    derivation_type = DerivationType.HARDWARE
                elif keystore_type == "bip32":
                    derivation_type = DerivationType.BIP32
                    if data.get("passphrase"):
                        data["passphrase"] = update_private_data(data["passphrase"])
                    if data.get("seed"):
                        data["seed"] = update_private_data(data["seed"])
                    if data.get("xprv"):
                        data["xprv"] = update_private_data(data["xprv"])
                elif keystore_type == "old":
                    derivation_type = DerivationType.ELECTRUM_OLD
                    if data.get("seed"):
                        data["seed"] = update_private_data(data["seed"])
                else:
                    raise IncompatibleWalletError("unknown keystore type", keystore_type)
                return derivation_type, data

            def convert_keystore(data: dict[str, Any],
                    subpaths: Sequence[tuple[DerivationPath, int]] | None=None) -> tuple[
                        DerivationType, bytes]:
                derivation_type, data = get_keystore_data(data)
                if subpaths is not None:
                    data["subpaths"] = subpaths
                derivation_data = json.dumps(data).encode()
                return (derivation_type, derivation_data)

            def process_keyinstances_receiving_change(script_type: ScriptType) -> None:
                nonlocal masterkey_id, account_id
                nonlocal _receiving_address_strings, _change_address_strings
                nonlocal keyinstance_rows, address_states, next_keyinstance_id

                for type_idx, address_strings in enumerate((_receiving_address_strings,
                        _change_address_strings)):
                    for address_idx, address_string in enumerate(address_strings):
                        address_states[address_string] = _AddressState(next_keyinstance_id,
                            len(keyinstance_rows), script_type)
                        description = labels.pop(address_string, None)
                        flags = KeyInstanceFlag.ACTIVE
                        derivation_info = {
                            "subpath": (type_idx, address_idx),
                        }
                        derivation_data = json.dumps(derivation_info).encode()
                        keyinstance_rows.append(KeyInstanceRow_22(next_keyinstance_id, account_id,
                            masterkey_id, DerivationType.BIP32_SUBPATH, derivation_data,
                            ScriptType.NONE, flags, description))
                        next_keyinstance_id += 1

            def process_transactions(*script_classes: Any) -> None:
                nonlocal _receiving_address_strings, _change_address_strings
                nonlocal keyinstance_rows, txoutput_rows, txdelta_rows
                nonlocal address_states, tx_states

                key_deltas: dict[int, int] = {}
                tx_deltas: dict[tuple[bytes, int], int] = {}
                txout_states: dict[tuple[bytes, int], _TxOutputState] = {}

                # Locate all the outputs.
                for tx_id, tx_state in tx_states.items():
                    for n, tx_output in enumerate(tx_state.tx.outputs):
                        _script_type, _threshold, output = classify_transaction_output_script(
                            tx_output.script_pubkey)
                        if not isinstance(output, script_classes):
                            continue

                        address_string = output.to_string()
                        if address_string in address_states:
                            address_state = address_states[address_string]
                            delta_key = (tx_state.tx_hash, address_state.keyinstance_id)
                            tx_deltas[delta_key] = tx_deltas.get(delta_key, 0) + tx_output.value
                            key_deltas[address_state.keyinstance_id] = \
                                key_deltas.get(address_state.keyinstance_id, 0) + tx_output.value

                            txout_states[(tx_state.tx_hash, n)] = _TxOutputState(tx_output.value,
                                len(txoutput_rows))
                            # Handled later: flags are changed if spent.
                            txo_flags = (TransactionOutputFlag1.IS_FROZEN
                                if (address_string in frozen_addresses or
                                    (tx_id, n) in txouts_frozen)
                                else TransactionOutputFlag1.NONE)
                            txoutput_rows.append(TransactionOutputRow_22(tx_state.tx_hash, n,
                                tx_output.value, address_state.keyinstance_id, txo_flags))
                            tx_state.encountered_addresses.add(address_string)

                            # We now update the key to reflect the existence of the output.
                            key = keyinstance_rows[address_state.row_index]
                            keyinstance_rows[address_state.row_index] = \
                                key._replace(script_type=address_state.script_type)

                # Reconcile spending of outputs.
                for tx_id, tx_state in tx_states.items():
                    for n, tx_input in enumerate(tx_state.tx.inputs):
                        if tx_input.is_coinbase():
                            continue

                        # We do not store partial transactions so we know that any public key
                        # embedded in the `script_sig` will be standard bitcoin ones and not
                        # Electrum extended forms.
                        script_data = parse_script_sig(tx_input.script_sig.to_bytes(),
                            XPublicKey.from_bytes)
                        assert script_data.address is not None
                        address_string = script_data.address.to_string()

                        if address_string in address_states:
                            address_state = address_states[address_string]
                            txout_key = (tx_input.prev_hash, tx_input.prev_idx)
                            if txout_key not in txout_states:
                                logger.debug("migration has orphaned spend, input=%s:%d, "
                                    "address %s, output=%s:%d", tx_id, n, address_string,
                                    hash_to_hex_str(tx_input.prev_hash), tx_input.prev_idx)
                                continue

                            txout_state = txout_states[txout_key]
                            delta_key = (tx_state.tx_hash, address_state.keyinstance_id)
                            tx_deltas[delta_key] = tx_deltas.get(delta_key, 0) - txout_state.value
                            key_deltas[address_state.keyinstance_id] = \
                                key_deltas.get(address_state.keyinstance_id, 0) - txout_state.value

                            # Go back to the rows produced from outputs and adjust spent flag.
                            orow = txoutput_rows[txout_state.row_index]
                            txoutput_rows[txout_state.row_index] = TransactionOutputRow_22(
                                orow.tx_hash, orow.tx_index, orow.value, orow.keyinstance_id,
                                TransactionOutputFlag1.IS_SPENT)
                            tx_state.encountered_addresses.add(address_string)

                # Record all the balance deltas.
                for (tx_hash, keyinstance_id), delta_value in tx_deltas.items():
                    txdelta_rows.append(TransactionDeltaRow_22(tx_hash, keyinstance_id,
                        delta_value))

            multsig_mn = multisig_type(wallet_type)
            if multsig_mn is not None:
                multsig_m, multsig_n = multsig_mn
                cosigner_keys: list[tuple[DerivationType, dict[str, Any]]] = []
                # We bake the cosigner key data into the multi-signature masterkey.
                for i in range(multsig_n):
                    keystore_name = f'x{i+1:d}/'
                    keystore = self.get(keystore_name)
                    cosigner_keys.append(get_keystore_data(keystore))
                mk_data = {
                    "m": multsig_m,
                    "n": multsig_n,
                    "subpaths": [
                        (RECEIVING_SUBPATH, len(_receiving_address_strings)),
                        (CHANGE_SUBPATH, len(_change_address_strings)),
                    ],
                    "cosigner-keys": cosigner_keys,
                }

                derivation_data = json.dumps(mk_data).encode()
                masterkey_rows.append(MasterKeyRow_22(masterkey_id, None,
                    DerivationType.ELECTRUM_MULTISIG, derivation_data))
                account_rows.append(AccountRow1(account_id, masterkey_id, ScriptType.MULTISIG_BARE,
                    "Multisig account"))
                process_keyinstances_receiving_change(ScriptType.MULTISIG_P2SH)
                process_transactions(P2SH_Address)
            elif wallet_type == "imported_addr":
                imported_address_strings = self.get("addresses")

                if not imported_address_strings:
                    # An imported account's type is defined by the type of keys within it. This
                    # means that we have no idea what an account of this kind is, if it has no keys.
                    # This is a structural problem in early migrations and cannot be fixed without
                    # complicating things given distribution of wallets of later versions out there.
                    raise IncompatibleWalletError("This imported address wallet has no entries and "
                        "cannot be imported due to technical limitations of the import process. "
                        "If there is information you want to access, it is suggested you do so "
                        "using ElectrumSV 1.2.5.")

                for address_string in imported_address_strings:
                    ia_data = { "hash": address_string }
                    derivation_data = json.dumps(ia_data).encode()
                    description = labels.pop(address_string, None)
                    address = address_from_string(address_string)
                    if isinstance(address, P2PKH_Address):
                        address_states[address_string] = _AddressState(next_keyinstance_id,
                            len(keyinstance_rows), ScriptType.P2PKH)
                        keyinstance_rows.append(KeyInstanceRow_22(next_keyinstance_id, account_id,
                            None, DerivationType.PUBLIC_KEY_HASH, derivation_data,
                            ScriptType.P2PKH, KeyInstanceFlag.ACTIVE, description))
                    elif isinstance(address, P2SH_Address):
                        address_states[address_string] = _AddressState(next_keyinstance_id,
                            len(keyinstance_rows), ScriptType.MULTISIG_P2SH)
                        keyinstance_rows.append(KeyInstanceRow_22(next_keyinstance_id, account_id,
                            None, DerivationType.SCRIPT_HASH, derivation_data,
                            ScriptType.MULTISIG_P2SH, KeyInstanceFlag.ACTIVE, description))
                    else:
                        raise IncompatibleWalletError("This imported address wallet has invalid "
                            "non-address entries which the migration process has no idea how "
                            "to handle.")
                    next_keyinstance_id += 1

                account_rows.append(AccountRow1(account_id, None, ScriptType.NONE,
                    "Imported addresses"))
                process_transactions(P2PKH_Address, P2SH_Address)
            elif wallet_type == "imported_privkey":
                keystore = self.get("keystore")
                assert "imported" == keystore.pop("type")
                keypairs = keystore.get("keypairs")

                if not keypairs:
                    # An imported account's type is defined by the type of keys within it. This
                    # means that we have no idea what an account of this kind is, if it has no keys.
                    # This is a structural problem in early migrations and cannot be fixed without
                    # complicating things given distribution of wallets of later versions out there.
                    raise IncompatibleWalletError("This imported private key wallet has no "
                        "entries and cannot be imported due to technical limitations of the "
                        "import process. If there is information you want to access, it is "
                        "suggested you do so using ElectrumSV 1.2.5.")

                for pubkey_hex, enc_prvkey in keypairs.items():
                    pubkey = PublicKey.from_hex(pubkey_hex)
                    address_string = pubkey.to_address(network=Net.COIN).to_string()
                    description = labels.pop(address_string, None)
                    address_states[address_string] = _AddressState(next_keyinstance_id,
                        len(keyinstance_rows), ScriptType.P2PKH)
                    ik_data = {
                        "pub": pubkey_hex,
                        "prv": update_private_data(enc_prvkey),
                    }
                    derivation_data = json.dumps(ik_data).encode()
                    keyinstance_rows.append(KeyInstanceRow_22(next_keyinstance_id, account_id,
                        None, DerivationType.PRIVATE_KEY, derivation_data,
                        ScriptType.P2PKH, KeyInstanceFlag.ACTIVE, description))
                    next_keyinstance_id += 1

                account_rows.append(AccountRow1(account_id, None, ScriptType.P2PKH,
                    "Imported private keys"))
                process_transactions(P2PKH_Address)
            elif wallet_type in ("standard", "old"):
                subpaths = [
                    (RECEIVING_SUBPATH, len(_receiving_address_strings)),
                    (CHANGE_SUBPATH, len(_change_address_strings)),
                ]
                keystore = self.get("keystore")
                masterkey_row = MasterKeyRow_22(*(masterkey_id, None),
                    *convert_keystore(keystore, subpaths))
                masterkey_rows.append(masterkey_row)
                account_rows.append(AccountRow1(account_id, masterkey_id, ScriptType.P2PKH,
                    "Standard account"))
                process_keyinstances_receiving_change(ScriptType.P2PKH)
                process_transactions(P2PKH_Address)
            else:
                raise IncompatibleWalletError("unknown wallet type", wallet_type)

            payment_requests: dict[str, dict[str, Any]] = self.get("payment_requests", {})
            for address_string, request_data in payment_requests.items():
                if address_string not in address_states:
                    continue

                address_state = address_states[address_string]
                paymentrequest_rows.append(PaymentRequestRow_22(next_paymentrequest_id,
                    address_state.keyinstance_id,
                    request_data.get("status", 2), # PaymentFlag.UNKNOWN = 2
                    request_data.get('amount', None), request_data.get('exp', None),
                    request_data.get('memo', None),
                        request_data.get('time', get_posix_timestamp())))
                next_paymentrequest_id += 1

            # Reconcile what addresses we found for transactions with the addresses that were in
            # the ElectrumX address usage state.
            for tx_id, tx_state in tx_states.items():
                missing_addresses = tx_state.known_addresses - tx_state.encountered_addresses
                if missing_addresses:
                    logger.debug("db-migration, tx %s missing addresses %s", tx_id,
                        missing_addresses)
                extra_addresses = tx_state.encountered_addresses - tx_state.known_addresses
                if extra_addresses:
                    logger.debug("db-migration, tx %s extra addresses %s", tx_id,
                        extra_addresses)

            # Commit all the changes to the database. This is ordered to respect FK constraints.
            # Note that database write calls are done sequentially. By waiting for the final one
            # to complete we know the others have already completed.
            futures: list[concurrent.futures.Future[None]] = []
            if len(transaction_rows):
                futures.append(create_transactions1(db_context, transaction_rows))
            if len(masterkey_rows):
                futures.append(create_master_keys1(db_context, masterkey_rows))
            if len(account_rows):
                futures.append(create_accounts1(db_context, account_rows))
            if len(keyinstance_rows):
                futures.append(create_keys1(db_context, keyinstance_rows))
            if len(txdelta_rows):
                futures.append(create_transaction_deltas_22(db_context, txdelta_rows))
            if len(txoutput_rows):
                futures.append(create_transaction_outputs1(db_context, txoutput_rows))
            if len(paymentrequest_rows):
                futures.append(create_payment_requests1(db_context, paymentrequest_rows))

            # The database creation should create these rows.
            creation_rows = []
            creation_rows.append(WalletDataRow1("password-token",
                pw_encode(os.urandom(32).hex(), new_password)))
            if len(labels):
                creation_rows.append(WalletDataRow1("lost-labels", labels))
            for key in [
                    "contacts2", # contacts.py
                    "wallet_nonce", "labels", # labels.py (A, B), wallet.py (B)
                    "winpos-qt", # main_window.py
                    "use_change", "multiple_change", # preferences.py
                    "invoices", "stored_height", "gap_limit" ]: # wallet.py
                value = self.get(key)
                if value is not None:
                    creation_rows.append(WalletDataRow1(key, value))
            futures.append(create_wallet_datas1(db_context, creation_rows))

            # These are inserted when the table is created, so we know the update will have an
            # existing row to effect and won't be a NOP.
            update_rows = [
                WalletDataRow1("next_masterkey_id", next_masterkey_id),
                WalletDataRow1("next_account_id", next_account_id),
                WalletDataRow1("next_keyinstance_id", next_keyinstance_id),
                WalletDataRow1("next_paymentrequest_id", next_paymentrequest_id),
            ]
            futures.append(update_wallet_datas1(db_context, update_rows))

            for future in futures:
                future.result()
        finally:
            db_context.close()

        # We hand across the data to the database store, so correct it.
        self.put('addresses', None)
        self.put('addr_history', None)
        self.put('frozen_addresses', None)
        self.put('frozen_coins', None)
        self.put('keystore', None)
        self.put('labels', None)
        self.put('payment_requests', None)
        self.put('pruned_txo', None)
        self.put('transactions', None)
        self.put('txi', None)
        self.put('txo', None)
        self.put('tx_fees', None)
        self.put('wallet_type', None)

        # Remove the TEXT file, as the store is now database-only.
        assert os.path.exists(db_context.get_path())
        # The only case where the file will not exist is where we upgraded from split accounts,
        os.remove(self._path)

        # Setting this will ensure this store cannot write the TEXT file again.
        self.put('seed_version', MIGRATION_FIRST)

    def _get_version(self) -> int:
        seed_version = self.get_explicit_type(int, 'seed_version', 0)
        if not seed_version:
            seed_version = (self.OLD_SEED_VERSION if len(self.get('master_public_key','')) == 128
                else self.NEW_SEED_VERSION)
        if seed_version > self.FINAL_SEED_VERSION:
            raise IncompatibleWalletError("TEXT store has DATABASE store version"
                f" {seed_version} > {self.FINAL_SEED_VERSION}")
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
    _store: AbstractStore
    _is_closed: bool = False
    _backup_filepaths: tuple[str, str] | None = None

    def __init__(self, path: str, storage_kind: StorageKind=StorageKind.UNKNOWN,
            password_token: PasswordTokenProtocol | None=None) -> None:
        logger.debug("wallet path '%s'", path)
        dirname = os.path.dirname(path)
        if not os.path.exists(dirname):
            raise IOError(f'directory {dirname} does not exist')

        storage_info = categorise_file(path)
        if storage_kind == StorageKind.UNKNOWN:
            storage_kind = storage_info.kind
        if storage_kind == StorageKind.HYBRID:
            raise IncompatibleWalletError("Migration of development wallet format unsupported")

        # Take the chance to normalise the wallet filename (remove any extension).
        if storage_info.kind in (StorageKind.DATABASE, StorageKind.UNKNOWN):
            path = storage_info.wallet_filepath

        self._path = path

        store: AbstractStore | None = None
        if storage_kind == StorageKind.UNKNOWN:
            self._set_store(DatabaseStore(path, password_token))
        else:
            if storage_kind == StorageKind.FILE:
                store = TextStore(path)
                if os.path.exists(path):
                    store.attempt_load_data()
            else:
                store = DatabaseStore(path, password_token)
            self._set_store(store)

    @classmethod
    def create(cls, wallet_path: str, password_token: PasswordTokenProtocol) -> WalletStorage:
        storage = cls(wallet_path, password_token=password_token)
        # This is a random value that we are using to record what the password is.
        storage.put("password-token", pw_encode(os.urandom(32).hex(), password_token.password))
        return storage

    @classmethod
    def from_file_data(cls, path: str, data: dict[str, Any]) -> WalletStorage:
        storage = cls(path=path, storage_kind=StorageKind.FILE)
        text_store = storage.get_text_store()
        text_store._set_data(data)
        return storage

    def move_to(self, new_path: str) -> None:
        db_store = cast(DatabaseStore, self._store)

        # At this point, anything that shares the database context, or database file, should
        # have relinquished it. This should be the final action in closing the database.
        db_store.close_database()

        # This does not remove the original database file. The move refers to the switch over
        # to the copy as the underlying store.
        if new_path.lower().endswith(DATABASE_EXT):
            new_path = new_path[:-len(DATABASE_EXT)]

        shutil.copyfile(self.get_path(), new_path + DATABASE_EXT)

        # Everything keeps the extensionless path.
        self._path = new_path

        db_store.set_path(new_path)
        db_store.open_database()

    def is_closed(self) -> bool:
        return self._is_closed

    def close(self) -> None:
        if self._is_closed:
            return

        # NOTE(rt12): Strictly speaking this just ensures that things are released and deallocated
        # for now. This ensures that the object gets garbage collected in a deterministic manner
        # which means that for instance the unit tests can rely on the database being closed
        # given knowledge of the resources in use, and their lifetime.
        # See: DatabaseStore.close
        self._store.close()

        del self.check_password
        del self.get
        del self.get_explicit_type
        del self.put
        del self.write
        del self.requires_split
        del self.split_accounts
        del self.requires_upgrade

        self._is_closed = True

    def get_path(self) -> str:
        return self._store.get_path()

    @staticmethod
    def get_eckey_from_password(password: str) -> PrivateKey:
        secret = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), b'', iterations=1024)
        return PrivateKey.from_arbitrary_bytes(secret)

    def is_password_valid(self, password: str) -> bool:
        try:
            self.check_password(password)
        except InvalidPassword:
            pass
        else:
            return True
        return False

    def _set_store(self, store: StoreType) -> None:
        # This should only be called on `WalletStorage` creation or during the upgrade process
        # as one type of store transitions to another type. This will ensure that any object
        # using this object, will post-creation/post-upgrade have a static store to work with.
        self._store = store

        self.check_password = store.check_password
        self.get = store.get
        self.get_explicit_type = store.get_explicit_type
        self.put = store.put
        self.write = store.write
        self.requires_split = store.requires_split
        self.split_accounts = store.split_accounts
        self.requires_upgrade = store.requires_upgrade

    def get_text_store(self) -> TextStore:
        assert isinstance(self._store, TextStore)
        return self._store

    def get_database_store(self) -> DatabaseStore:
        assert isinstance(self._store, DatabaseStore)
        return self._store

    def is_legacy_format(self) -> bool:
        return not isinstance(self._store, DatabaseStore)

    def get_storage_path(self) -> str:
        return self._path

    def get_backup_filepaths(self) -> tuple[str, str] | None:
        return self._backup_filepaths

    def upgrade(self, has_password: bool, new_password_token: PasswordTokenProtocol,
            callbacks: ProgressCallbacks | None=None) -> None:
        logger.debug('upgrading wallet format')
        self._backup_filepaths = backup_wallet_file(self._path)

        # The store can change if the old kind of store was obsoleted. We upgrade through
        # obsoleted kinds of stores to the final in-use kind of store.
        while True:
            new_store = self._store.upgrade(has_password, new_password_token, callbacks)
            if new_store is not None:
                self._set_store(new_store)
                if new_store.requires_upgrade():
                    continue
            break

    def get_db_context(self) -> DatabaseContext | None:
        if isinstance(self._store, DatabaseStore):
            return self._store._db_context
        return None

    @classmethod
    def files_are_matched_by_path(cls, path: str | None) -> bool:
        if path is None:
            return False
        return categorise_file(path).kind != StorageKind.UNKNOWN

    @classmethod
    def canonical_path(cls, database_filepath: str) -> str:
        if not database_filepath.lower().endswith(DATABASE_EXT):
            database_filepath += DATABASE_EXT
        return database_filepath
