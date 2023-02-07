"""
Keeps backwards compatible logic for storage migration.

Every structure in here should be versioned according to the first migration that the structure
was introduced for, e.g. "SomeStruct_22", where 22 was the first database migration.

TODO Currently this contains structures named "SomeStruct1" instead of "SomeStruct_22". This should
     be rectified at some point, but is not being rectified yet in order to reduce merge burden.

TODO There are aliases for some structures, mostly "SomeStruct_27" at the moment, where we
     refer to the current version in the code. When these change they should be formalised
     into a full structure.

"""
import concurrent.futures
from enum import IntFlag
import json
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3
from typing import Any, cast, Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple, \
    TypedDict, Union

from bitcoinx import bip32_build_chain_string
from electrumsv_database.sqlite import DatabaseContext, replace_db_context_with_connection
from ..constants import DerivationPath, DerivationType, KeyInstanceFlag, MasterKeyFlags, \
    PaymentFlag, ScriptType
from ..types import MasterKeyDataBIP32, \
    MasterKeyDataHardware, MasterKeyDataMultiSignature, MultiSignatureMasterKeyDataTypes, \
    MasterKeyDataTypes
from ..util import get_posix_timestamp

from .types import KeyInstanceRow, MasterKeyRow, PaymentRequestRow


class KeyInstanceFlag_22(IntFlag):
    NONE = 0

    # This key should be loaded and managed appropriately.
    IS_ACTIVE = 1 << 0

    # The user explicitly set this key to be active. It is not intended that the management
    # mark it inactive without good reason.
    USER_SET_ACTIVE = 1 << 8
    IS_PAYMENT_REQUEST = 1 << 9
    IS_INVOICE = 1 << 10

    # The mask used to load the subset of keys that are actively cached by accounts.
    CACHE_MASK = IS_ACTIVE
    ACTIVE_MASK = IS_ACTIVE | USER_SET_ACTIVE
    INACTIVE_MASK = ~IS_ACTIVE
    ALLOCATED_MASK = IS_PAYMENT_REQUEST | IS_INVOICE

KeyInstanceFlag_27 = KeyInstanceFlag


class TransactionOutputFlag1(IntFlag):
    NONE = 0

    # If the UTXO is in a local or otherwise unconfirmed transaction.
    IS_ALLOCATED = 1 << 1
    # If the UTXO is in a confirmed transaction.
    IS_SPENT = 1 << 2
    # If the UTXO is marked as not to be used. It should not be allocated if unallocated, and
    # if allocated then ideally we might extend this to prevent further dispatch in any form.
    IS_FROZEN = 1 << 3
    IS_COINBASE = 1 << 4

    USER_SET_FROZEN = 1 << 8

    FROZEN_MASK = IS_FROZEN | USER_SET_FROZEN


class TxFlags_22(IntFlag):
    HasFee = 1 << 4
    HasHeight = 1 << 5
    HasPosition = 1 << 6
    HasByteData = 1 << 12
    HasProofData = 1 << 13 # Deprecated.

    # A transaction received over the p2p network which is unconfirmed and in the mempool.
    STATE_CLEARED = 1 << 20
    # A transaction received over the p2p network which is confirmed and known to be in a block.
    STATE_SETTLED = 1 << 21

    METADATA_FIELD_MASK = HasFee | HasHeight | HasPosition


class AccountRow1(NamedTuple):
    account_id: int
    default_masterkey_id: Optional[int]
    default_script_type: ScriptType
    account_name: str


class KeyInstanceRow_22(NamedTuple):
    keyinstance_id: int
    account_id: int
    masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes
    script_type: ScriptType
    flags: KeyInstanceFlag
    description: Optional[str]

KeyInstanceRow_27 = KeyInstanceRow

class MasterKeyRow_22(NamedTuple):
    masterkey_id: int
    parent_masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes


class PaymentRequestRow_22(NamedTuple):
    paymentrequest_id: int
    keyinstance_id: int
    state: PaymentFlag
    value: Optional[int]
    expiration: Optional[int]
    description: Optional[str]
    date_created: int

PaymentRequestRow_27 = PaymentRequestRow

class TransactionDeltaRow_22(NamedTuple):
    tx_hash: bytes
    keyinstance_id: int
    value_delta: int


class TransactionOutputRow_22(NamedTuple):
    tx_hash: bytes
    tx_index: int
    value: int
    keyinstance_id: Optional[int]
    flags: TransactionOutputFlag1


class TxData1(NamedTuple):
    height: Optional[int] = None
    position: Optional[int] = None
    fee: Optional[int] = None
    date_added: Optional[int] = None
    date_updated: Optional[int] = None

    def __repr__(self) -> str:
        return (f"TxData1(height={self.height},position={self.position},fee={self.fee},"
            f"date_added={self.date_added},date_updated={self.date_updated})")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TxData1):
            return NotImplemented
        return (self.height == other.height and self.position == other.position
            and self.fee == other.fee)


class TxProof1(NamedTuple):
    position: int
    branch: Sequence[bytes]


class TransactionRow1(NamedTuple):
    tx_hash: bytes
    tx_data: TxData1
    tx_bytes: Optional[bytes]
    flags: TxFlags_22
    description: Optional[str]


class WalletDataRow1(NamedTuple):
    key: str
    value: Any


# TODO(database) We do not actually know what revision this originated in, but before 27.
class MasterKeyDataBIP32_26(TypedDict):
    xpub: str
    seed: Optional[str]
    passphrase: Optional[str]
    label: Optional[str]
    xprv: Optional[str]
    subpaths: List[Tuple[DerivationPath, int]]

# # The current definition of `electrumsv.types.MasterKeyDataBIP32` at the 27th migration.
# class MasterKeyDataBIP32_27(TypedDict):
#     xpub: str
#     seed: Optional[str]
#     # If there is a seed / no parent masterkey, the xpub/xprv are derived from the seed using it.
#     # - For master keys with Electrum seeds this will always be 'm'
#     # If there is no seed, the xpub/xprv are derived from the parent masterkey using this.
#     derivation: Optional[str]
#     passphrase: Optional[str]
#     label: Optional[str]
#     xprv: Optional[str]
MasterKeyDataBIP32_27 = MasterKeyDataBIP32

class MasterKeyDataElectrumOld1(TypedDict):
    seed: Optional[str]
    mpk: str


class MasterKeyDataHardwareCfg1(TypedDict):
    mode: int


class MasterKeyDataHardware1(TypedDict):
    hw_type: str
    xpub: str
    # A regression in a previous version stored the sequence and not the str, we now replace
    # the sequence on account load.
    derivation: Union[str, DerivationPath]
    label: Optional[str]
    cfg: Optional[MasterKeyDataHardwareCfg1]
    subpaths: List[Tuple[DerivationPath, int]]


# class MasterKeyDataHardware_27(TypedDict):
#     hw_type: str
#     xpub: str
#     derivation: str
#     label: Optional[str]
#     cfg: Optional[MasterKeyDataHardwareCfg1]
MasterKeyDataHardware_27 = MasterKeyDataHardware

MultiSignatureMasterKeyDataTypes1 = Union[MasterKeyDataBIP32_26, MasterKeyDataElectrumOld1,
    MasterKeyDataHardware1]

# MultiSignatureMasterKeyDataTypes_27 = Union[MasterKeyDataBIP32_27, MasterKeyDataElectrumOld1,
#     MasterKeyDataHardware_27]
MultiSignatureMasterKeyDataTypes_27 = MultiSignatureMasterKeyDataTypes


CosignerListType1 = List[Tuple[DerivationType, MultiSignatureMasterKeyDataTypes1]]

_MasterKeyDataMultiSignature1 = TypedDict(
    '_MasterKeyDataMultiSignature1',
    { 'cosigner-keys': CosignerListType1 },
    total=True,
)

class MasterKeyDataMultiSignature1(_MasterKeyDataMultiSignature1):
    m: int
    n: int

MasterKeyDataTypes1 = Union[MasterKeyDataBIP32_26, MasterKeyDataElectrumOld1,
    MasterKeyDataHardware1, MasterKeyDataMultiSignature1]


# CosignerListType_27 = List[Tuple[DerivationType, MultiSignatureMasterKeyDataTypes_27]]

# _MasterKeyDataMultiSignature_27 = TypedDict(
#     '_MasterKeyDataMultiSignature_27',
#     { 'cosigner-keys': CosignerListType_27 },
#     total=True,
# )

# class MasterKeyDataMultiSignature_27(_MasterKeyDataMultiSignature_27):
#     m: int
#     n: int
MasterKeyDataMultiSignature_27 = MasterKeyDataMultiSignature

# MasterKeyDataTypes_27 = Union[MasterKeyDataBIP32_27, MasterKeyDataElectrumOld1,
#     MasterKeyDataHardware_27, MasterKeyDataMultiSignature_27]
MasterKeyDataTypes_27 = MasterKeyDataTypes


class KeyInstanceDataBIP32SubPath1(TypedDict):
    subpath: DerivationPath


class KeyInstanceDataHash1(TypedDict):
    hash: str


class KeyInstanceDataPrivateKey1(TypedDict):
    pub: str
    prv: str


KeyInstanceDataTypes1 = Union[KeyInstanceDataBIP32SubPath1, KeyInstanceDataHash1,
    KeyInstanceDataPrivateKey1]


DerivationDataTypes1 = Union[KeyInstanceDataTypes1, MasterKeyDataTypes1]


ADDRESS_TYPES1 = { DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH }


def create_accounts1(db_context: DatabaseContext, entries: Iterable[AccountRow1]) \
        -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO Accounts (account_id, default_masterkey_id, default_script_type, "
        "account_name, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        nonlocal query, datas
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(query, datas)
    z = db_context.post_to_thread(_write)
    return z


def create_keys1(db_context: DatabaseContext, entries: Iterable[KeyInstanceRow_22]) \
        -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries]
    query = ("INSERT INTO KeyInstances (keyinstance_id, account_id, masterkey_id, "
        "derivation_type, derivation_data, script_type, flags, description, date_created, "
        "date_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        nonlocal query, datas
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(query, datas)
    return db_context.post_to_thread(_write)


def create_master_keys1(db_context: DatabaseContext, entries: Iterable[MasterKeyRow_22]) \
        -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)")
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        nonlocal query, datas
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(query, datas)
    return db_context.post_to_thread(_write)


def create_payment_requests1(db_context: DatabaseContext, entries: Iterable[PaymentRequestRow_22]) \
        -> concurrent.futures.Future[None]:
    # Duplicate the last column for date_updated = date_created
    query = ("INSERT INTO PaymentRequests "
        "(paymentrequest_id, keyinstance_id, state, value, expiration, description, date_created, "
        "date_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    datas = [ (*t, t[-1]) for t in entries ]
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        nonlocal query, datas
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(query, datas)
    return db_context.post_to_thread(_write)


def create_transaction_deltas_22(db_context: DatabaseContext,
        entries: Iterable[TransactionDeltaRow_22]) -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO TransactionDeltas (tx_hash, keyinstance_id, value_delta, "
        "date_created, date_updated) VALUES (?, ?, ?, ?, ?)")

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        nonlocal query, datas
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(query, datas)
    return db_context.post_to_thread(_write)


def create_transaction_outputs1(db_context: DatabaseContext,
        entries: Iterable[TransactionOutputRow_22]) -> concurrent.futures.Future[None]:
    timestamp = get_posix_timestamp()
    datas = [ (*t, timestamp, timestamp) for t in entries ]
    query = ("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, keyinstance_id, "
        "flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)")
    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        nonlocal query, datas
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(query, datas)
    return db_context.post_to_thread(_write)


def create_transactions1(db_context: DatabaseContext, entries: Iterable[TransactionRow1]) \
        -> concurrent.futures.Future[None]:
    query = ("INSERT INTO Transactions (tx_hash, tx_data, flags, "
        "block_height, block_position, fee_value, description, "
        "date_created, date_updated) "
        "VALUES (?,?,?,?,?,?,?,?,?)")

    datas = []
    for tx_hash, metadata, bytedata, flags, description in entries:
        assert type(tx_hash) is bytes and bytedata is not None
        assert (flags & TxFlags_22.HasByteData) == 0, "this flag is not applicable"
        flags &= ~TxFlags_22.METADATA_FIELD_MASK
        if metadata.height is not None:
            flags |= TxFlags_22.HasHeight
        if metadata.fee is not None:
            flags |= TxFlags_22.HasFee
        if metadata.position is not None:
            flags |= TxFlags_22.HasPosition
        assert metadata.date_added is not None and metadata.date_updated is not None
        datas.append((tx_hash, bytedata, flags, metadata.height, metadata.position,
            metadata.fee, description, metadata.date_added,
            metadata.date_updated))

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(query, datas)
    return db_context.post_to_thread(_write)


def create_wallet_datas1(db_context: DatabaseContext, entries: Iterable[WalletDataRow1]) \
        -> concurrent.futures.Future[None]:
    sql = ("INSERT INTO WalletData (key, value, date_created, date_updated) "
        "VALUES (?, ?, ?, ?)")
    timestamp = get_posix_timestamp()
    rows = []
    for entry in entries:
        assert type(entry.key) is str, f"bad key '{entry.key}'"
        data = json.dumps(entry.value)
        rows.append([ entry.key, data, timestamp, timestamp])

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        nonlocal sql, rows
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


@replace_db_context_with_connection
def read_wallet_data1(db: sqlite3.Connection, key: str) -> Any:
    sql = "SELECT value FROM WalletData WHERE key=?"
    cursor = db.execute(sql, (key,))
    row = cursor.fetchone()
    return json.loads(row[0]) if row is not None else None


def update_wallet_datas1(db_context: DatabaseContext, entries: Iterable[WalletDataRow1]) \
        -> concurrent.futures.Future[None]:
    sql = "UPDATE WalletData SET value=?, date_updated=? WHERE key=?"
    timestamp = get_posix_timestamp()
    rows = []
    for entry in entries:
        rows.append((json.dumps(entry.value), timestamp, entry.key))

    def _write(db: Optional[sqlite3.Connection]=None) -> None:
        nonlocal sql, rows
        assert db is not None and isinstance(db, sqlite3.Connection)
        db.executemany(sql, rows)
    return db_context.post_to_thread(_write)


# def convert_derivation_keyinstance_data1(derivation_type: DerivationType,
#         old_derivation_data: KeyInstanceDataTypes1) -> KeyInstanceDataTypes:
#     if derivation_type == DerivationType.BIP32_SUBPATH:
#         data_in = cast(KeyInstanceDataBIP32SubPath1, old_derivation_data)
#         pass
#     elif derivation_type in ADDRESS_TYPES1:
#         data_in = cast(KeyInstanceDataHash1, old_derivation_data)
#         pass
#     elif derivation_type == DerivationType.PRIVATE_KEY:
#         data_in = cast(KeyInstanceDataPrivateKey1, old_derivation_data)
#         pass
#     raise NotImplementedError(f"Unhandled type {derivation_type}")


def convert_masterkey_derivation_data1(derivation_type: DerivationType,
        old_derivation_data: MasterKeyDataTypes1, is_multisig: bool=False) -> MasterKeyDataTypes_27:
    data_dict = cast(Dict[str, Any], old_derivation_data)
    if derivation_type == DerivationType.BIP32:
        data_bip32_in = cast(MasterKeyDataBIP32_26, old_derivation_data)
        data_bip32_in.setdefault("label", None)
        data_bip32_in.setdefault("passphrase", None)
        data_bip32_in.setdefault("seed", None)
        data_bip32_in.setdefault("xprv", None)
        if is_multisig:
            assert "subpaths" not in data_dict
        else:
            del data_dict["subpaths"]
        assert len(data_dict) == 5
        return cast(MasterKeyDataBIP32_27, data_bip32_in)
    elif derivation_type == DerivationType.ELECTRUM_OLD:
        data_old_in = cast(MasterKeyDataElectrumOld1, old_derivation_data)
        data_old_in.setdefault("seed", None)
        del data_dict["subpaths"]
        assert len(data_dict) == 2, data_dict
        return data_old_in
    elif derivation_type == DerivationType.ELECTRUM_MULTISIG:
        assert "m" in data_dict
        assert "n" in data_dict
        assert "subpaths" in data_dict
        assert len(data_dict) == 4, data_dict
        del data_dict["subpaths"]
        data_multisig_in = cast(MasterKeyDataMultiSignature1, old_derivation_data)
        assert len(data_multisig_in["cosigner-keys"]) == data_multisig_in["n"]
        data_out = cast(MasterKeyDataMultiSignature_27, data_multisig_in)
        for i, (cosigner_derivation_type, cosigner_data_in) in \
                enumerate(data_multisig_in["cosigner-keys"]):
            data_out["cosigner-keys"][i] = (cosigner_derivation_type,
                cast(MultiSignatureMasterKeyDataTypes_27,
                    convert_masterkey_derivation_data1(cosigner_derivation_type, cosigner_data_in,
                        is_multisig=True)))
        return data_out
    elif derivation_type == DerivationType.HARDWARE:
        data_hardware_in = cast(MasterKeyDataHardware1, old_derivation_data)
        if isinstance(data_hardware_in["derivation"], list):
            data_hardware_in["derivation"] = bip32_build_chain_string(
                data_hardware_in["derivation"])
        data_hardware_in.setdefault("label", None)
        data_hardware_in.setdefault("cfg", None)
        del data_dict["subpaths"]
        assert len(data_dict) == 5
        return cast(MasterKeyDataHardware_27, data_hardware_in)
    raise NotImplementedError(f"Unhandled type {derivation_type}")

MasterKeyRow_27 = MasterKeyRow

def upgrade_masterkey_22(row: MasterKeyRow_22) -> MasterKeyRow_27:
    return MasterKeyRow_27(masterkey_id=row.masterkey_id,
        parent_masterkey_id=row.parent_masterkey_id, derivation_type=row.derivation_type,
        derivation_data=row.derivation_data, flags=MasterKeyFlags.NONE)

