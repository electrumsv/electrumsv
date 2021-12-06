import json
import os
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore
from typing import cast, Optional

from ..constants import DATABASE_EXT, MIGRATION_CURRENT, MIGRATION_FIRST
from ..credentials import PasswordTokenProtocol
from ..exceptions import DatabaseMigrationError
from ..util.misc import ProgressCallbacks


def _get_migration(db: sqlite3.Connection) -> int:
    cursor = db.execute("SELECT value FROM WalletData WHERE key='migration'")
    row = cursor.fetchone()
    if row is None:
        raise DatabaseMigrationError("wallet database migration metadata not present")
    return cast(int, json.loads(row[0]))

def _ensure_matching_migration(db: sqlite3.Connection, expected_migration: int) -> None:
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
    """
    Create a non-updated wallet database. If a
    """
    if wallet_path.endswith(DATABASE_EXT):
        raise DatabaseMigrationError("wallet path is not base path")
    if 22 != MIGRATION_FIRST:
        raise DatabaseMigrationError("constant MIGRATION_FIRST differs from local version")
    db_path = wallet_path + DATABASE_EXT
    if os.path.exists(db_path):
        raise DatabaseMigrationError("wallet database already exists")

    # Python sqlite bindings automatically enter a transaction which prevents the PRAGMA from
    # exiting, which is why we use no isolation level.
    db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
    db.execute(f"PRAGMA journal_mode=WAL;")
    create_database(db)
    db.close()


def update_database(conn: sqlite3.Connection, password_token: PasswordTokenProtocol,
        callbacks: Optional[ProgressCallbacks]=None) -> None:
    # This will error if the database has not been created correctly with the metadata.
    version = _get_migration(conn)

    # Use a dummy set of callbacks if none are provided.
    if callbacks is None:
        callbacks = ProgressCallbacks()
    # 22, 23, 24, 25, 26, 27
    callbacks.set_stage_count(MIGRATION_CURRENT-22)

    from . import migrations
    with conn:
        if version == 22:
            callbacks.begin_stage(22)
            migrations.migration_0023_add_wallet_events.execute(conn)
            version = 23
        if version == 23:
            callbacks.begin_stage(23)
            migrations.migration_0024_account_transactions.execute(conn)
            version = 24
        if version == 24:
            callbacks.begin_stage(24)
            migrations.migration_0025_invoices.execute(conn)
            version = 25
        if version == 25:
            callbacks.begin_stage(25)
            migrations.migration_0026_txo_coinbase_flag.execute(conn)
            version = 26
        if version == 26:
            callbacks.begin_stage(26)
            migrations.migration_0027_tx_refactor2.execute(conn, callbacks)
            version = 27
        if version == 27:
            callbacks.begin_stage(27)
            migrations.migration_0028_mapi.execute(conn, callbacks)
            version = 28
        # if version == 28:
        #     callbacks.begin_stage(28)
        #     migrations.migration_0029_reference_server.execute(conn, password_token, callbacks)
        #     version = 29

        if version != MIGRATION_CURRENT:
            # This will cause the context manager to rollback its transaction.
            raise DatabaseMigrationError(f"Expected migration {MIGRATION_CURRENT}, got {version}")

    _ensure_matching_migration(conn, MIGRATION_CURRENT)

def update_database_file(wallet_path: str, password_token: PasswordTokenProtocol) -> None:
    if wallet_path.endswith(DATABASE_EXT):
        raise DatabaseMigrationError("wallet path is not base path")

    db_path = wallet_path + DATABASE_EXT
    if not os.path.exists(db_path):
        raise DatabaseMigrationError("wallet database does not exist")

    # We open a separate read connection so that the write connection can use existing
    # data in the database to work from, when using that data requires it be read into
    # memory for Python to operate on.
    conn = sqlite3.connect(db_path)
    update_database(conn, password_token)
    conn.close()
