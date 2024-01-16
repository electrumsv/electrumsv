import os, random, threading, time

try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3

from typing import cast, Type, TypeVar

from bitcoinx import base58_decode_check, PublicKey

from ..constants import DerivationType, pack_derivation_path
from ..types import KeyInstanceDataBIP32SubPath, KeyInstanceDataHash, KeyInstanceDataTypes, \
    KeyInstanceDataPrivateKey

T = TypeVar('T')
T2 = TypeVar('T2')


def create_derivation_data2(derivation_type: DerivationType,
        derivation_data: KeyInstanceDataTypes) -> bytes:
    if derivation_type == DerivationType.BIP32_SUBPATH:
        derivation_path = cast(KeyInstanceDataBIP32SubPath, derivation_data)["subpath"]
        return pack_derivation_path(derivation_path)
    elif derivation_type == DerivationType.PRIVATE_KEY:
        public_key_bytes = bytes.fromhex(cast(KeyInstanceDataPrivateKey, derivation_data)['pub'])
        # Ensure all public keys are canonically encoded in the compressed form.
        if len(public_key_bytes) != 33:
            public_key_bytes = PublicKey.from_bytes(public_key_bytes).to_bytes(compressed=True)
        return public_key_bytes
    elif derivation_type in (DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH):
        # We manually extract this rather than using the `bitcoinx.Address` class as we do
        # not care about the coin as that is implicit in the wallet.
        derivation_data_hash = cast(KeyInstanceDataHash, derivation_data)
        raw = cast(bytes, base58_decode_check(derivation_data_hash['hash']))
        if len(raw) != 21:
            raise ValueError(f'invalid address: {derivation_data_hash["hash"]}')
        return raw[1:]
    raise NotImplementedError()


def collect_results(result_type: Type[T], cursor: sqlite3.Cursor, results: list[T]) -> None:
    """
    Collect the results of a query and extend a result list with correct typing.
    """
    rows = cursor.fetchall()
    cursor.close()
    results.extend(result_type(*row) for row in rows)


def flag_clause(column: str, flags: T|None, mask: T|None) -> tuple[str, list[T]]:
    if flags is None:
        if mask is None:
            return "", []
        return f"({column} & ?) != 0", [mask]

    if mask is None:
        return f"({column} & ?) != 0", [flags]

    return f"({column} & ?) == ?", [mask, flags]


BASE_TIME           = 1199145601000     # Tue Jan 01 2008 00:00:01 GMT+0000
BITS_TIME           = 42
BITS_THREAD_ID      = 5
BITS_PROCESS_ID     = 5
BITS_INCREMENT      = 12

increment_lock = threading.Lock()
increment_value = 0

def database_id_from_timestamp(t: int) -> int:
    global increment_value
    ts_raw = int(t*1000) - BASE_TIME
    assert ts_raw >= 0
    ts = ts_raw & ((1<<42)-1)
    return (ts<<22) + random.randint(0, (1<<22)-1)

def database_id_from_parts(*, ts: int=0, tid: int=0, pid: int=0, n: int=0) -> int:
    ts &= (1<<42)-1
    tid &= (1<<5)-1
    pid &= (1<<5)-1
    n &= (1<<12)-1
    return (ts<<22) + (tid<<17) + (pid<<12) + n

def database_id() -> int:
    global increment_value
    increment_lock.acquire()
    n = increment_value & ((1<<12)-1)
    increment_value += 1
    increment_lock.release()
    ts = (int(time.time()*1000) - BASE_TIME) & ((1<<42)-1)
    tid = threading.get_ident() & ((1<<5)-1)
    pid = os.getpid() & ((1<<5)-1)
    return (ts<<22) + (tid<<17) + (pid<<12) + n

def timestamp_from_id(id: int) -> int:
    return (BASE_TIME + (id>>22))//1000
