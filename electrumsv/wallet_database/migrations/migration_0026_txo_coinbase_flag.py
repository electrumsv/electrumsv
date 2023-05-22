import json
try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.9.13 builds and version of 3.37.2.
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
