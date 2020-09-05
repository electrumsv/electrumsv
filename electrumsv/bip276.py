import enum
from hashlib import sha256
from typing import Optional, Tuple

from .i18n import _


PREFIX_BIP276_SCRIPT = "bitcoin-script"
PREFIX_TEMPLATE = "bitcoin-template"
CURRENT_VERSION = 1

class BIP276Network(enum.IntEnum):
    NETWORK_MAINNET = 1
    NETWORK_TESTNET = 2
    NETWORK_SCALINGTESTNET = 3
    NETWORK_REGTEST = 4


class ChecksumMismatchError(Exception):
    pass

class NetworkMismatchError(Exception):
    pass


def _checksum(data: bytes) -> bytes:
    return sha256(sha256(data).digest()).digest()[0:4]

def bip276_encode(prefix: str, data: bytes, network: int=BIP276Network.NETWORK_MAINNET,
        version: int=CURRENT_VERSION) -> str:
    assert version == CURRENT_VERSION
    payload_bytes = bytearray()
    payload_bytes.append(version)
    payload_bytes.append(network)
    payload_bytes.extend(data)
    payload_hex = payload_bytes.hex()
    result = prefix +":"+ payload_hex
    return result + _checksum(result.encode()).hex()

def bip276_decode(text: str, network: Optional[int]=None) -> Tuple[str, int, int, bytes]:
    text = text.strip()
    prefix, payload_hex = text.split(":", 1)
    payload_bytes = bytes.fromhex(payload_hex)
    checksum = payload_bytes[-4:]
    version = payload_bytes[0]
    assert version == CURRENT_VERSION
    data = payload_bytes[2:-4]
    checksummed_bytes = text[:-8].encode()
    local_checksum = _checksum(checksummed_bytes)
    if checksum != local_checksum:
        raise ChecksumMismatchError(_("Checksum failure: expected {}, got {}").format(
            checksum.hex(), local_checksum.hex()))
    try:
        data_network = payload_bytes[1]
    except ValueError:
        raise NetworkMismatchError(_("Unrecognized network: got {}").format(payload_bytes.hex()))
    if network is not None and network != data_network:
        raise NetworkMismatchError(_("Incompatible network: expected {}, got {}").format(
            network, data_network))
    return prefix, version, data_network, data
