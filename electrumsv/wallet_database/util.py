from datetime import datetime

try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore[no-redef]

from typing import cast, Optional, Type, TypeVar

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


def flag_clause(column: str, flags: Optional[T], mask: Optional[T]) -> tuple[str, list[T]]:
    if flags is None:
        if mask is None:
            return "", []
        return f"({column} & ?) != 0", [mask]

    if mask is None:
        return f"({column} & ?) != 0", [flags]

    return f"({column} & ?) == ?", [mask, flags]


UTC_TIMEZONE_INFO = '+00:00'
ZULU_TIMEZONE_SUFFIX = 'Z'


class NoTimezoneInfoException(Exception):
    pass


def from_isoformat(iso_timestamp: str) -> datetime:
    """Timestamps such as: '2022-06-23T04:31:07.5387707Z' will fail conversion because
    datetime.fromisoformat can only handle millisecond precision.
    Datetime objects also must have tzinfo in order for their internal unix timestamp to be
    correct."""
    if "." in iso_timestamp:  # precision cannot exceed milliseconds
        parts = iso_timestamp.split(".")
        if iso_timestamp.endswith(ZULU_TIMEZONE_SUFFIX):
            milliseconds = parts[1].replace(ZULU_TIMEZONE_SUFFIX, "")
        elif iso_timestamp.endswith(UTC_TIMEZONE_INFO):
            milliseconds = parts[1].replace(UTC_TIMEZONE_INFO, "")
        else:
            raise NoTimezoneInfoException()
        return datetime.fromisoformat(parts[0] + milliseconds + UTC_TIMEZONE_INFO)
    else:
        if iso_timestamp.endswith(UTC_TIMEZONE_INFO):
            return datetime.fromisoformat(iso_timestamp)
        elif iso_timestamp.endswith(ZULU_TIMEZONE_SUFFIX):
            return datetime.fromisoformat(iso_timestamp.replace('Z', UTC_TIMEZONE_INFO))
        else:
            raise NoTimezoneInfoException()
