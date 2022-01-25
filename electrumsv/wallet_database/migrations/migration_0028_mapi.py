import json
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore[no-redef]

from ...i18n import _
from ...util import get_posix_timestamp
from ...util.misc import ProgressCallbacks


MIGRATION = 28

def execute(conn: sqlite3.Connection, callbacks: ProgressCallbacks) -> None:
    date_updated = get_posix_timestamp()

    callbacks.progress(0, _("Creating new database tables"))

    conn.execute("CREATE TABLE IF NOT EXISTS Servers ("
        "server_type INTEGER NOT NULL,"
        "url TEXT NOT NULL,"
        "encrypted_api_key TEXT DEFAULT NULL,"
        "flags INTEGER NOT NULL DEFAULT 0,"
        "fee_quote_json TEXT DEFAULT NULL,"
        "date_last_connected INTEGER DEFAULT 0,"
        "date_last_tried INTEGER DEFAULT 0,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL"
    ")")

    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_Servers_unique ON Servers(server_type, url)")

    conn.execute("CREATE TABLE IF NOT EXISTS ServerAccounts ("
        "server_type INTEGER NOT NULL,"
        "url TEXT NOT NULL,"
        "account_id INTEGER NOT NULL,"
        "encrypted_api_key TEXT DEFAULT NULL,"
        "fee_quote_json TEXT DEFAULT NULL,"
        "date_last_connected INTEGER DEFAULT 0,"
        "date_last_tried INTEGER DEFAULT 0,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (server_type, url) REFERENCES Servers (server_type, url),"
        "FOREIGN KEY (account_id) REFERENCES Accounts (account_id)"
    ")")

    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_ServerAccounts_unique ON ServerAccounts(server_type, url, account_id)")

    callbacks.progress(100, _("New database tables created"))

    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [json.dumps(MIGRATION),date_updated,"migration"])
