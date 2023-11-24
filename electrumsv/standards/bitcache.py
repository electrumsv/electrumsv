from __future__ import annotations
import dataclasses, io, os, struct
from typing import cast

from bitcoinx import pack_le_uint16, pack_le_uint32, read_le_uint16, read_le_uint32, read_le_uint64

from ..constants import DerivationType, ScriptType
from ..logs import logs
from ..wallet_support.dump import encode_derivation_data, encode_script_type, \
    decode_derivation_data, decode_script_type

logger = logs.get_logger("bitcache-data")

class ChunkIds:
    # Message focus.
    TX              = "TXBYTES."
    TX_HASH         = "TXHASH.."        # FUTURE POST-MVP.

    # Focus metadata.
    KEY_USAGE       = "TXOKEYS."

@dataclasses.dataclass
class BitcacheTxoKeyUsage:
    txo_index: int
    script_type: ScriptType
    parent_key_fingerprint: bytes
    derivation_type: DerivationType
    derivation_data2: bytes

@dataclasses.dataclass
class BitcacheMessage:
    tx_data: bytes
    key_data: list[BitcacheTxoKeyUsage]


def read_bitcache_message(stream: io.BytesIO) -> BitcacheMessage:
    """
    Raises `struct.error` if there is a problem parsing a field.
    Raises `ValueError` if there is a problem parsing the message.
    """
    tx_bytes = b""
    key_data: list[BitcacheTxoKeyUsage] = []
    while True:
        chunk_id = stream.read(8)
        if len(chunk_id) == 0:
            return BitcacheMessage(tx_bytes, key_data)
        elif len(chunk_id) != 8:
            raise ValueError(f"Incorrect chunk id size '{chunk_id!r}'")
        chunk_length = read_le_uint64(stream.read)
        if chunk_id == ChunkIds.TX.encode():
            tx_bytes = stream.read(chunk_length)
            if len(tx_bytes) != chunk_length:
                raise ValueError(f"Bad {ChunkIds.TX} chunk data")
        elif chunk_id == ChunkIds.KEY_USAGE.encode():
            key_data = read_bitcache_txokeys_chunk(stream, chunk_length)
        else:
            logger.debug("Skipping unknown bitcache chunk '%s'", chunk_id)

def read_bitcache_txokeys_chunk(stream: io.BytesIO, chunk_length: int) \
        -> list[BitcacheTxoKeyUsage]:
    start_offset = stream.tell()
    key_data: list[BitcacheTxoKeyUsage] = []
    while True:
        consumed_length = stream.tell() - start_offset
        if consumed_length == chunk_length:
            return key_data
        if consumed_length > chunk_length:
            raise ValueError("Bad txo key chunk size")
        key_data.append(read_bitcache_txokey(stream))

def read_bitcache_txokey(stream: io.BytesIO) -> BitcacheTxoKeyUsage:
    """
    Raises `struct.error` if there are problems parsing a field.
    Raises `ValueError` if there are problems with the parsed field value.
    Raises `ValueError` if the parent key fingerprint cannot be resolved.
    From `_decode_script_type`:
        Raises `ValueError` if the script type is unknown.
    From `_decode_derivation_data`:
        Raises `UnicodeDecodeError` if the derivation path is not valid ASCII.
        Raises `ValueError` if the derivation type is unrecognised.
    """
    return BitcacheTxoKeyUsage(read_bitcache_txo_index(stream), read_bitcache_script_type(stream),
        read_bitcache_key_fingerprint(stream), *read_bitcache_key_derivation(stream))

def read_bitcache_txo_index(stream: io.BytesIO) -> int:
    return cast(int, read_le_uint32(stream.read))

def read_bitcache_script_type(stream: io.BytesIO) -> ScriptType:
    field_length = read_le_uint16(stream.read)
    if field_length < 4 or field_length > 32:
        raise ValueError(f"Bad key scripttype length {field_length}")
    return decode_script_type(stream.read(field_length).decode())

def read_bitcache_key_fingerprint(stream: io.BytesIO) -> bytes:
    field_length = read_le_uint16(stream.read)
    if field_length > 20*4 or field_length < 4 or field_length % 4:
        raise ValueError(f"Bad key fingerprint length {field_length}")
    return stream.read(field_length)

def read_bitcache_key_derivation(stream: io.BytesIO) -> tuple[DerivationType, bytes]:
    """
    Raises `UnicodeDecodeError` if the derivation text is not valid ASCII.
    """
    field_length = read_le_uint16(stream.read)
    if field_length < 4 or field_length > 32:
        raise ValueError(f"Bad key derivation length {field_length}")
    return decode_derivation_data(stream.read(field_length).decode("ascii"))

def write_bitcache_transaction_message(stream: io.BytesIO, data: BitcacheMessage) -> None:
    write_bitcache_transaction_chunk(stream, data.tx_data)
    write_bitcache_txokeys_chunk(stream, data.key_data)

def write_bitcache_transaction_chunk(stream: io.BytesIO, tx_value: bytes) -> None:
    stream.write(ChunkIds.TX.encode())
    stream.write(struct.pack("<Q", len(tx_value)))
    stream.write(tx_value)

def write_bitcache_txokeys_chunk(stream: io.BytesIO, entries: list[BitcacheTxoKeyUsage]) \
        -> None:
    stream.write(ChunkIds.KEY_USAGE.encode())
    length_offset = stream.tell()
    stream.write(b"\0" * 8)
    start_offset = stream.tell()
    for entry in entries:
        write_bitcache_txokey(stream, entry)
    chunk_length = stream.tell() - start_offset
    stream.seek(length_offset, os.SEEK_SET)
    stream.write(struct.pack("<Q", chunk_length))
    assert stream.tell() == start_offset

def write_bitcache_txokey(stream: io.BytesIO, data: BitcacheTxoKeyUsage) -> None:
    write_bitcache_txo_index(stream, data.txo_index)
    write_bitcache_script_type(stream, data.script_type)
    write_bitcache_key_fingerprint(stream, data.parent_key_fingerprint)
    write_bitcache_key_derivation(stream, data.derivation_type, data.derivation_data2)

def write_bitcache_txo_index(stream: io.BytesIO, txo_index: int) -> None:
    stream.write(pack_le_uint32(txo_index))

def write_bitcache_script_type(stream: io.BytesIO, script_type: ScriptType) -> None:
    value = encode_script_type(script_type).encode()
    stream.write(pack_le_uint16(len(value)))
    stream.write(value)

def write_bitcache_key_fingerprint(stream: io.BytesIO, key_fingerprint: bytes) -> None:
    stream.write(pack_le_uint16(len(key_fingerprint)))
    stream.write(key_fingerprint)

def write_bitcache_key_derivation(stream: io.BytesIO, derivation_type: DerivationType,
        derivation_data2: bytes) -> None:
    value = encode_derivation_data(derivation_type, derivation_data2).encode()
    stream.write(pack_le_uint16(len(value)))
    stream.write(value)
