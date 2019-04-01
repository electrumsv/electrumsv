import os
from typing import Any

from .bitcoin import sha256d
from .app_state import app_state
from .transaction import Transaction

class TransactionStore:
    def __init__(self, keys) -> None:
        self._keys = frozenset(keys)
        self._cache = {}
        self._cache_path = os.path.join(app_state.config.electrum_path(), "txcache")
        if not os.path.exists(self._cache_path):
            os.makedirs(self._cache_path)

    def _is_persisted(self, tx_id: str) -> bool:
        txcache_path = os.path.join(self._cache_path, tx_id)
        return os.path.exists(txcache_path)

    def keys(self):
        return self._keys

    def items(self):
        raise NotImplementedError

    def get(self, tx_id: str, default: Any=None) -> Transaction:
        if tx_id in self._keys:
            return self[tx_id]
        return default

    def __iter__(self):
        return iter(self._keys)

    def __contains__(self, tx_id: str) -> bool:
        assert len(tx_id) == 32*2
        if tx_id in self._cache:
            return True
        return tx_id in self._keys

    def __len__(self):
        return len(self._keys)

    def __getitem__(self, tx_id: str) -> Transaction:
        assert len(tx_id) == 32*2
        if tx_id not in self._cache:
            txcache_path = os.path.join(self._cache_path, tx_id)
            if not os.path.exists(txcache_path):
                raise KeyError(tx_id)

            with open(txcache_path, "rb") as f:
                data = f.read()
                hash_bytes = sha256d(data)
                if hash_bytes[::-1].hex() != tx_id:
                    raise Exception("Bad transaction", tx_id)
                self._cache[tx_id] = Transaction(data.hex())
        return self._cache[tx_id]

    def __setitem__(self, tx_id: str, tx: Transaction) -> None:
        assert len(tx_id) == 32*2
        self._cache[tx_id] = tx
        self.persist(tx_id, tx)

    def __delitem__(self, tx_id: str) -> None:
        del self._cache[tx_id]
        self.unpersist(tx_id)

    def persist(self, tx_id: str, tx: Transaction) -> None:
        assert len(tx_id) == 32*2
        if not self._is_persisted(tx_id):
            txcache_path = os.path.join(self._cache_path, tx_id)
            with open(txcache_path, "wb") as f:
                tx_hex = str(tx)
                f.write(bytes.fromhex(tx_hex))

    def unpersist(self, tx_id: str) -> None:
        assert len(tx_id) == 32*2
        txcache_path = os.path.join(self._cache_path, tx_id)
        os.remove(txcache_path)
