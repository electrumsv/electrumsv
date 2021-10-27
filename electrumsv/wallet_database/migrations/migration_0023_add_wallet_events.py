import json
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3
else:
    sqlite3 = pysqlite3

from ...constants import WalletEventFlag, WalletEventType
from ...util import get_posix_timestamp

MIGRATION = 23

def execute(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS WalletEvents ("
        "event_id INTEGER PRIMARY KEY,"
        "event_type INTEGER NOT NULL,"
        "event_flags INTEGER NOT NULL,"
        "account_id INTEGER,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY(account_id) REFERENCES Accounts (account_id)"
    ")")

    date_updated = get_posix_timestamp()
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [json.dumps(MIGRATION),date_updated,"migration"])

    # Inject seed backup reminders for every existing account (can actually only be one for now).
    account_rows = list(conn.execute("SELECT * FROM Accounts"))
    wallet_event_id = 1
    for account_row in account_rows:
        conn.execute("INSERT INTO WalletEvents (event_id, event_type, event_flags, "
            "account_id, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?)",
            (wallet_event_id, WalletEventType.SEED_BACKUP_REMINDER,
            WalletEventFlag.UNREAD | WalletEventFlag.FEATURED, account_row[0],
            date_updated, date_updated))
        wallet_event_id += 1

    if wallet_event_id > 1:
        conn.execute("INSERT INTO WalletData (key, value, date_created, date_updated) VALUES "
            "(?, ?, ?, ?)", ("next_wallet_event_id", json.dumps(wallet_event_id), date_updated,
            date_updated))
