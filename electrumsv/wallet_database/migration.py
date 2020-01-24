import json
import os
import sqlite3
import time

from electrumsv.constants import DATABASE_EXT, MIGRATION_CURRENT, MIGRATION_FIRST
from electrumsv.exceptions import DatabaseMigrationError


def migration_0000_create_database(conn: sqlite3.Connection) -> None:
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
        ["migration", json.dumps(22), date_created, date_created],
        ["next_masterkey_id", json.dumps(1), date_created, date_created],
        ["next_account_id", json.dumps(1), date_created, date_created],
        ["next_keyinstance_id", json.dumps(1), date_created, date_created],
        ["next_paymentrequest_id", json.dumps(1), date_created, date_created],
    ])


def _get_migration(db: sqlite3.Connection) -> int:
    cursor = db.execute("SELECT value FROM WalletData WHERE key='migration'")
    row = cursor.fetchone()
    if row is None:
        raise DatabaseMigrationError("wallet database migration metadata not present")
    return json.loads(row[0])

def _ensure_matching_migration(db: sqlite3.Connection, expected_migration: int):
    migration = _get_migration(db)
    if migration != expected_migration:
        raise DatabaseMigrationError("wallet database migration mismatch, expected "
            f"{expected_migration}, got {migration}")


def create_database(db: sqlite3.Connection) -> None:
    with db:
        migration_0000_create_database(db)
    _ensure_matching_migration(db, MIGRATION_FIRST)


def create_database_file(wallet_path: str) -> None:
    if wallet_path.endswith(DATABASE_EXT):
        raise DatabaseMigrationError("wallet path is not base path")
    if 22 != MIGRATION_FIRST:
        raise DatabaseMigrationError("constant MIGRATION_FIRST differs from local version")
    db_path = wallet_path + DATABASE_EXT
    if os.path.exists(db_path):
        raise DatabaseMigrationError("wallet database already exists")

    db = sqlite3.connect(db_path)
    create_database(db)
    db.close()

    update_database_file(wallet_path)

def update_database(db: sqlite3.Connection) -> None:
    # This will error if the database has not been created correctly with the metadata.
    version = _get_migration(db)

    # NOTE(rt12) There are no updates yet. This should apply migrations depending on their
    # associated version.
    pass
    _ensure_matching_migration(db, MIGRATION_CURRENT)

def update_database_file(wallet_path: str) -> None:
    if wallet_path.endswith(DATABASE_EXT):
        raise DatabaseMigrationError("wallet path is not base path")

    db_path = wallet_path + DATABASE_EXT
    if not os.path.exists(db_path):
        raise DatabaseMigrationError("wallet database does not exist")

    db = sqlite3.connect(db_path)
    update_database(db)
    db.close()
