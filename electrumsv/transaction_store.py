import sqlite3
import threading
from typing import Optional, Union, Dict, Set, Iterable

import bitcoinx

from .logs import logs
from .transaction import Transaction

# TODO: Deletion should be via a flag. Occasional purges might do row deletion of flagged rows.
# NOTE: We could hash the db and store the hash in the wallet storage to detect changes.

class TransactionStore:
    def __init__(self, wallet_path) -> None:
        self._logger = logs.get_logger("tx-store")
        self._state = threading.local()

        self._db_path = wallet_path +".sqlite"

        db = self._get_db()
        self._create(db)
        self._migrate(db)
        db.commit()

    def _get_db(self):
        if not hasattr(self._state, "db"):
            self._state.db = sqlite3.connect(self._db_path)
        return self._state.db

    def _create(self, db):
        db.execute("CREATE TABLE IF NOT EXISTS Transactions ("+
                        "Key TEXT, "+
                        "Value BLOB, "+
                        "IsPending INTEGER)")

    def _migrate(self, db):
        pass

    def close(self):
        # TODO: This only closes the database instance held on the current thread. In theory
        # only the async code behind the daemon should be touching this, not the GUI thread
        # via the wallet.
        self._state.db.close()
        self._state = None

    def has(self, tx_id: str) -> bool:
        db = self._get_db()
        cursor = db.execute("SELECT EXISTS(SELECT 1 FROM Transactions WHERE Key=?)", [tx_id])
        row = cursor.fetchone()
        return row[0] == 1

    def add(self, tx_id: str, value: Union[str, Transaction, bytes],
            is_pending: Optional[bool]=False) -> None:
        if type(value) is Transaction:
            value = str(value)
        if type(value) is str:
            value = bytes.fromhex(value)
        assert type(value) is bytes
        db = self._get_db()
        db.execute("INSERT INTO Transactions (Key, Value, IsPending) VALUES (?, ?, ?)",
            [tx_id, value, is_pending])
        db.commit()
        self._logger.debug("added %d transaction '%s'", 1, tx_id)

    def add_many(self, map: Dict[str, str], is_pending: Optional[bool]=False) -> None:
        db = self._get_db()
        for tx_id, tx_hex in map.items():
            tx_bytes = bytes.fromhex(tx_hex)
            db.execute("INSERT INTO Transactions (Key, Value, IsPending) VALUES (?, ?, ?)",
                [tx_id, tx_bytes, is_pending])
        db.commit()
        self._logger.debug("added %d transactions", len(map))

    def delete(self, tx_id: str) -> None:
        db = self._get_db()
        db.execute("DELETE FROM Transactions WHERE Key=?", [tx_id])
        db.commit()
        self._logger.debug("deleted %d transaction '%s'", 1, tx_id)

    def delete_many(self, tx_ids: Iterable[str]) -> None:
        db = self._get_db()
        for tx_id in tx_ids:
            db.execute("DELETE FROM Transactions WHERE Key=?", [tx_id])
        db.commit()
        self._logger.debug("deleted %d transactions", len(tx_ids))

    def was_received(self, tx_id: str) -> bool:
        db = self._get_db()
        cursor = db.execute("SELECT EXISTS("+
            "SELECT 1 FROM Transactions WHERE IsPending=0 AND Key=?)", [tx_id])
        row = cursor.fetchone()
        return row[0] == 1

    def get(self, tx_id: str, is_pending: Optional[bool]=None) -> Optional[Transaction]:
        db = self._get_db()
        if is_pending is None:
            cursor = db.execute("SELECT Value FROM Transactions WHERE Key=?", [tx_id])
        else:
            cursor = db.execute("SELECT Value FROM Transactions WHERE Key=? AND IsPending=?",
                [tx_id, is_pending])
        row = cursor.fetchone()
        if row is not None:
            hash_bytes = bitcoinx.double_sha256(row[0])
            if bitcoinx.hash_to_hex_str(hash_bytes) == tx_id:
                return Transaction(row[0].hex())
            self._logger.debug("found transaction with hash mismatch '%s'", tx_id)
            self.delete(tx_id)
        return None

    def get_ids(self, is_pending: Optional[bool]=None) -> Set[str]:
        db = self._get_db()
        if is_pending is None:
            cursor = db.execute("SELECT Key FROM Transactions")
        else:
            cursor = db.execute("SELECT Key FROM Transactions WHERE IsPending=?",
                [is_pending])
        return set(t[0] for t in cursor.fetchall())

    def get_received_ids(self) -> Set[str]:
        return self.get_ids(is_pending=False)

    def get_pending_ids(self) -> Set[str]:
        return self.get_ids(is_pending=True)
