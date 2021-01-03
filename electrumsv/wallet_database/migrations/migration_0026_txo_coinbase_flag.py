import json
try:
    # Linux expects the latest package version of 3.34.0 (as of pysqlite-binary 0.4.5)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.34.0 (as of 2021-01-13).
    # Windows builds use the official Python 3.9.1 builds and bundled version of 3.33.0.
    import sqlite3 # type: ignore
import time

from electrumsv.constants import TransactionOutputFlag

MIGRATION = 26

def execute(conn: sqlite3.Connection) -> None:
    # Ensure that for all transactions in block position 0, all outputs for those transactions
    # have the IS_COINBASE flag.
    conn.execute("UPDATE TransactionOutputs "
        f"SET flags=flags|{TransactionOutputFlag.IS_COINBASE} "
        "WHERE tx_hash in (SELECT tx_hash FROM Transactions WHERE block_position = 0)")

    date_updated = int(time.time())
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [json.dumps(MIGRATION),date_updated,"migration"])
