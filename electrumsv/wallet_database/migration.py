import json
import os
import sqlite3

from electrumsv.constants import DATABASE_EXT, MIGRATION_CURRENT, MIGRATION_FIRST
from electrumsv.exceptions import DatabaseMigrationError


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
    from . import migrations
    with db:
        migrations.migration_0022_create_database.execute(db)
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

    from . import migrations
    with db:
        if version == 22:
            migrations.migration_0023_add_wallet_events.execute(db)
            version += 1
        if version == 23:
            migrations.migration_0024_account_transactions.execute(db)

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
