from typing import NamedTuple

class TxoKeyType(NamedTuple):
    tx_hash: bytes
    tx_index: int
