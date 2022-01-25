import json
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore[no-redef]

from ...constants import TransactionOutputFlag
from ...util import get_posix_timestamp

MIGRATION = 26

def execute(conn: sqlite3.Connection) -> None:
    # Ensure that for all transactions in block position 0, all outputs for those transactions
    # have the IS_COINBASE flag.
    conn.execute("UPDATE TransactionOutputs "
        f"SET flags=flags|{TransactionOutputFlag.COINBASE} "
        "WHERE tx_hash in (SELECT tx_hash FROM Transactions WHERE block_position = 0)")

    date_updated = get_posix_timestamp()
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [json.dumps(MIGRATION),date_updated,"migration"])
