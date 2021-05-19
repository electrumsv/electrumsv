import json
try:
    # Linux expects the latest package version of 3.34.0 (as of pysqlite-binary 0.4.5)
    # NOTE(typing) pylance complains about a missing import.
    import pysqlite3 as sqlite3 # type: ignore
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.34.0 (as of 2021-01-13).
    # Windows builds use the official Python 3.9.1 builds and bundled version of 3.33.0.
    import sqlite3 # type: ignore
import time

from ...i18n import _
from ...util.misc import ProgressCallbacks


MIGRATION = 28

def execute(conn: sqlite3.Connection, callbacks: ProgressCallbacks) -> None:
    date_updated = int(time.time())

    callbacks.progress(0, _("Reading existing data"))

    conn.execute("CREATE TABLE IF NOT EXISTS Servers ("
        "server_id INTEGER PRIMARY KEY,"
        "server_type INTEGER NOT NULL,"
        "uri TEXT NOT NULL,"
        "encrypted_api_key TEXT DEFAULT NULL,"
        "flags INTEGER NOT NULL DEFAULT 0,"
        # TODO Not sure about these dates.
        "date_last_connected INTEGER DEFAULT NULL,"
        "date_last_tried INTEGER DEFAULT NULL,"
        "date_application INTEGER DEFAULT NULL,"
        "date_static_data INTEGER DEFAULT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL"
    ")")

    conn.execute("CREATE TABLE IF NOT EXISTS ServerAccounts ("
        "server_id INTEGER NOT NULL,"
        "account_id INTEGER NOT NULL,"
        "encrypted_api_key TEXT DEFAULT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (server_id) REFERENCES Accounts (server_id),"
        "FOREIGN KEY (account_id) REFERENCES Accounts (account_id)"
    ")")

    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_ServerAccounts_unique ON ServerAccounts(server_id, account_id)")

    callbacks.progress(100, _("Rechecking work done"))

    date_updated = int(time.time())
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [json.dumps(MIGRATION),date_updated,"migration"])
