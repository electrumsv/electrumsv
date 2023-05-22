import json
try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.9.13 builds and version of 3.37.2.
    import sqlite3 # type: ignore
import time

MIGRATION = 22

def execute(conn: sqlite3.Connection) -> None:
    date_created = int(time.time())
    conn.execute("CREATE TABLE IF NOT EXISTS MasterKeys ("
        "masterkey_id INTEGER PRIMARY KEY,"
        "parent_masterkey_id INTEGER DEFAULT NULL,"
        "derivation_type INTEGER NOT NULL,"
        "derivation_data BLOB NOT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY(parent_masterkey_id) REFERENCES MasterKeys (masterkey_id)"
    ")")

    conn.execute("CREATE TABLE IF NOT EXISTS Accounts ("
        "account_id INTEGER PRIMARY KEY,"
        "default_masterkey_id INTEGER DEFAULT NULL,"
        "default_script_type INTEGER NOT NULL,"
        "account_name TEXT NOT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY(default_masterkey_id) REFERENCES MasterKeys (masterkey_id)"
    ")")

    conn.execute("CREATE TABLE IF NOT EXISTS KeyInstances ("
        "keyinstance_id INTEGER PRIMARY KEY,"
        "account_id INTEGER NOT NULL,"
        "masterkey_id INTEGER DEFAULT NULL,"
        "derivation_type INTEGER NOT NULL,"
        "derivation_data BLOB NOT NULL,"
        "script_type INTEGER NOT NULL,"
        "flags INTEGER NOT NULL,"
        "description TEXT DEFAULT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY(account_id) REFERENCES Accounts (account_id)"+
        "FOREIGN KEY(masterkey_id) REFERENCES MasterKeys (masterkey_id)"+
    ")")

    conn.execute("CREATE TABLE IF NOT EXISTS Transactions ("
        "tx_hash BLOB PRIMARY KEY,"
        "tx_data BLOB DEFAULT NULL,"
        "proof_data BLOB DEFAULT NULL,"
        "block_height INTEGER DEFAULT NULL,"
        "block_position INTEGER DEFAULT NULL,"
        "fee_value INTEGER DEFAULT NULL,"
        "flags INTEGER NOT NULL DEFAULT 0,"
        "description TEXT DEFAULT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL"
    ")")

    conn.execute("CREATE TABLE IF NOT EXISTS TransactionOutputs ("
        "tx_hash BLOB NOT NULL,"
        "tx_index INTEGER NOT NULL,"
        "value INTEGER NOT NULL,"
        "keyinstance_id INTEGER NOT NULL,"
        "flags INTEGER NOT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (tx_hash) REFERENCES Transactions (tx_hash),"
        "FOREIGN KEY (keyinstance_id) REFERENCES KeyInstances (keyinstance_id)"
    ")")

    # The unique constraint is also required for any upsert operation to work.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_TransactionOutputs_unique ON TransactionOutputs(tx_hash, tx_index)")

    conn.execute("CREATE TABLE IF NOT EXISTS TransactionDeltas ("
        "keyinstance_id INTEGER NOT NULL,"
        "tx_hash BLOB NOT NULL,"
        "value_delta INTEGER NOT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY(tx_hash) REFERENCES Transactions (tx_hash),"
        "FOREIGN KEY(keyinstance_id) REFERENCES KeyInstances (keyinstance_id) "
    ")")

    # The unique constraint is also required for any upsert operation to work.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_TransactionDeltas_unique "
        "ON TransactionDeltas(keyinstance_id, tx_hash)")

    conn.execute("CREATE TABLE IF NOT EXISTS WalletData ("
        "key TEXT NOT NULL,"
        "value TEXT NOT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL"
    ")")

    conn.execute("CREATE TABLE IF NOT EXISTS PaymentRequests ("
        "paymentrequest_id INTEGER PRIMARY KEY,"
        "keyinstance_id INTEGER NOT NULL,"
        "state INTEGER NOT NULL,"
        "description TEXT DEFAULT NULL,"
        "expiration INTEGER DEFAULT NULL,"
        "value INTEGER DEFAULT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY(keyinstance_id) REFERENCES KeyInstances (keyinstance_id) "
    ")")

    # The unique constraint is also required for any upsert operation to work.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_WalletData_unique ON WalletData(key)")

    conn.executemany("INSERT INTO WalletData (key, value, date_created, date_updated) VALUES "
            "(?, ?, ?, ?)", [
        ["migration", json.dumps(MIGRATION), date_created, date_created],
        ["next_masterkey_id", json.dumps(1), date_created, date_created],
        ["next_account_id", json.dumps(1), date_created, date_created],
        ["next_keyinstance_id", json.dumps(1), date_created, date_created],
        ["next_paymentrequest_id", json.dumps(1), date_created, date_created],
    ])
