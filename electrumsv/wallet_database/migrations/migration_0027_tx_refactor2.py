from collections import defaultdict
import json
try:
    # Linux expects the latest package version of 3.31.1 (as of p)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
    # Windows builds use the official Python 3.7.8 builds and version of 3.31.1.
    import sqlite3 # type: ignore
import time
from typing import Any, cast, Dict, List, NamedTuple, Optional, Sequence, Tuple

from bitcoinx import Address, hash_to_hex_str

from electrumsv.bitcoin import scripthash_bytes
from electrumsv.constants import (ACCOUNT_SCRIPT_TYPES, AccountTxFlags, AccountType,
    CHANGE_SUBPATH, DerivationType, KeyInstanceFlag, KeystoreType, RECEIVING_SUBPATH, ScriptType,
    TransactionInputFlag, TransactionOutputFlag, TxFlags)
from electrumsv.exceptions import DatabaseMigrationError
from electrumsv.i18n import _
from electrumsv.keys import (extract_public_key_hash, get_multi_signer_script_template,
    get_single_signer_script_template)
from electrumsv.keystore import (Imported_KeyStore, instantiate_keystore, KeyStore,
    Multisig_KeyStore, SinglesigKeyStoreTypes)
from electrumsv.logs import logs
from electrumsv.networks import Net
from electrumsv.transaction import Transaction
from electrumsv.types import TxoKeyType
from electrumsv.util.misc import ProgressCallbacks


logger = logs.get_logger("migration-0027")

# The purpose of this migration is to expose more of the contents of transaction data to the
# application without requiring the transaction data to be loaded from the database and parsed
# to get the desired information. This includes output script hashes, transaction inputs/spends
# and also formalising and recording other data.

# This migration code is intended to be as self-contained as possible in order to minimize the need
# to update it as other wallet code changes. It should ideally be able to work into the future and
# both not risk it breaking on edge cases as the modern wallet code is updated, and to not impose
# maintenance costs.
#
# NOTE(rt12) one exception to this is the reliance on `instantiate_keystore`
#

class MasterKeyRow(NamedTuple):
    masterkey_id: int
    parent_masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes

class KeyInstanceRow(NamedTuple):
    keyinstance_id: int
    account_id: int
    masterkey_id: Optional[int]
    derivation_type: DerivationType
    derivation_data: bytes
    script_type: ScriptType
    flags: KeyInstanceFlag

class AccountRow(NamedTuple):
    account_id: int
    default_masterkey_id: Optional[int]
    default_script_type: ScriptType

class PossibleScript(NamedTuple):
    account_id: int
    masterkey_id: Optional[int]
    keyinstance: KeyInstanceRow
    derivation_path: Sequence[int]
    script_type: ScriptType
    script_hash: bytes

class TXOData(NamedTuple):
    key: TxoKeyType
    value: int
    flags: TransactionOutputFlag
    exists: bool

class TXIInsertRow(NamedTuple):
    tx_hash: bytes
    txi_index: int
    spent_tx_hash: bytes
    spent_txo_index: int
    sequence: int
    flags: int
    script_offset: int
    script_length: int
    date_created: int
    date_updated: int

class TXOInsertRow(NamedTuple):
    # These are ordered and aligned with the SQL statement.
    tx_hash: bytes
    txo_index: int
    value: int
    keyinstance_id: Optional[int]
    flags: TransactionOutputFlag
    script_offset: int
    script_length: int
    script_hash: bytes
    date_created: int
    date_updated: int

class TXOUpdateRow(NamedTuple):
    # These are ordered and aligned with the SQL statement.
    script_hash: bytes
    flags: TransactionOutputFlag
    script_offset: int
    script_length: int
    date_updated: int
    tx_hash: bytes
    txo_index: int

class TXOExistingEntry(NamedTuple):
    flags: TransactionOutputFlag


MULTISIG_SCRIPT_TYPES = (ScriptType.MULTISIG_BARE, ScriptType.MULTISIG_P2SH)
SINGLESIG_SCRIPT_TYPES = (ScriptType.P2PK, ScriptType.P2PKH)


MIGRATION = 27

def execute(conn: sqlite3.Connection, callbacks: ProgressCallbacks) -> None:
    date_updated = int(time.time())

    callbacks.progress(0, _("Reading existing data"))
    ## Cache all the data we need in order to create key instances and tx deltas.
    # For now we rely on the keystore implementations, but as they change in future
    # this may have to be rewritten.

    # Cache wallet settings.
    wallet_settings: Dict[str, Any] = {}
    cursor = conn.execute("SELECT key, value FROM WalletData")
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        wallet_settings[row[0]] = json.loads(row[1])

    # Cache account data.
    accounts: Dict[int, AccountRow] = {}
    cursor = conn.execute("SELECT account_id, default_masterkey_id, default_script_type "
        "FROM Accounts")
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        accounts[row[0]] = AccountRow(row[0], row[1], ScriptType(row[2]))

    # Cache masterkey data.
    masterkeys: Dict[int, MasterKeyRow] = {}
    cursor = conn.execute("SELECT masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data FROM MasterKeys")
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        masterkeys[row[0]] = MasterKeyRow(*row)

    # Cache keyinstance data. These are only going to cover all existing detected key usage and the
    # gap limit beyond that. Because the creation and detection of the use of these is driven by
    # the indexer/electrumx telling us they have been used, it is not guaranteed that we will have
    # them all.
    keyinstances: Dict[int, KeyInstanceRow] = {}
    # For accounts with masterkeys. {(account_id, masterkey_id): { derivation_path: keyinstance }}
    mk_keyinstance_data: Dict[Tuple[int, int], Dict[Sequence[int], KeyInstanceRow]] = \
        defaultdict(dict)
    # For other account types. {account_id: [keyinstance,..]}
    other_keyinstance_data: Dict[int, List[KeyInstanceRow]] = defaultdict(list)
    cursor = conn.execute("SELECT keyinstance_id, account_id, masterkey_id, derivation_type, "
        "derivation_data, script_type, flags FROM KeyInstances")
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        krow = keyinstances[row[0]] = KeyInstanceRow(row[0], row[1], row[2],
            DerivationType(row[3]), row[4], ScriptType(row[5]), KeyInstanceFlag(row[6]))
        if krow.masterkey_id is not None:
            derivation_data = json.loads(krow.derivation_data)
            derivation_path = tuple(derivation_data["subpath"])
            mk_keyinstance_data[(krow.account_id, krow.masterkey_id)][derivation_path] = krow
        else:
            other_keyinstance_data[krow.account_id].append(krow)

    # Cache the existing transaction output entries. They will only be present for transactions the
    # network/electrumx has told us are related to the keys that exist at this point in time, and
    # even then only if we have online and have received up to date network state at the point the
    # account was last unloaded.
    cursor = conn.execute("SELECT tx_hash, tx_index, flags from TransactionOutputs")
    txo_existing_entries: Dict[Tuple[bytes, int], TXOExistingEntry] = {
        (row[0], row[1]): TXOExistingEntry(row[2]) for row in cursor.fetchall() }

    cursor = conn.execute("SELECT COUNT(*) FROM Transactions")
    tx_count: int = cursor.fetchone()[0]
    tx_index = 1
    tx_progress_text = _("Reading transaction data %d/%d")
    if tx_count > 0:
        progress = 5 + int(40 * (tx_index / tx_count))
        callbacks.progress(progress, tx_progress_text.format(tx_index, tx_count))

    # Process all transactions in the database.
    # 1. We want to populate the Transaction.locktime/Transaction.version fields.
    # 2. We want to index all the transaction inputs so we can link spends for all transactions.
    # 3. We want to add all the outputs that we do not know link to key usage but should.
    # 4. We want to make sure all outputs have their scripthash field populated.
    tx_updates: List[Tuple[int, int, int, bytes]] = []
    txi_inserts: Dict[TxoKeyType, TXIInsertRow] = {}
    txo_updates: Dict[TxoKeyType, TXOUpdateRow] = {}
    txo_inserts: Dict[TxoKeyType, TXOInsertRow] = {}
    txo_script_hashes: Dict[bytes, List[TXOData]] = {}
    for tx_hash, tx_data, date_created in conn.execute("SELECT tx_hash, tx_data, date_created "
            "FROM Transactions"):
        tx_index += 1
        progress = 5 + int(40 * (tx_index / tx_count))
        callbacks.progress(progress, tx_progress_text.format(tx_index, tx_count))

        if tx_data is None:
            continue

        tx = Transaction.from_bytes(tx_data)
        if tx.hash() != tx_hash:
            raise DatabaseMigrationError("Transaction data mismatch "+ hash_to_hex_str(tx_hash) +
                " vs "+ hash_to_hex_str(tx.hash()))

        base_txo_flags = TransactionOutputFlag.IS_COINBASE if tx.is_coinbase() \
            else TransactionOutputFlag.NONE

        # Collect the change to the transaction.
        tx_updates.append((tx.version, tx.locktime, date_updated, tx_hash))

        # Create the inputs for the transaction.
        for txi_index, txi in enumerate(tx.inputs):
            txi_inserts[TxoKeyType(txi.prev_hash, txi.prev_idx)] = TXIInsertRow(tx_hash, txi_index,
                txi.prev_hash, txi.prev_idx, txi.sequence, TransactionInputFlag.NONE,
                txi.script_offset, txi.script_length, date_created, date_created)

        # Create/update the outputs for the transaction.
        for txo_index, txo in enumerate(tx.outputs):
            script_hash = scripthash_bytes(txo.script_pubkey)
            txo_entry = txo_existing_entries.get((tx_hash, txo_index))
            txo_flags: TransactionOutputFlag
            if txo_entry is not None:
                txo_flags = txo_entry.flags
                txo_updates[TxoKeyType(tx_hash, txo_index)] = TXOUpdateRow(script_hash,
                    txo_flags, txo.script_offset, txo.script_length, date_updated,
                    tx_hash, txo_index)
            else:
                txo_flags = base_txo_flags
                txo_inserts[TxoKeyType(tx_hash, txo_index)] = TXOInsertRow(tx_hash, txo_index,
                    txo.value, None, txo_flags, txo.script_offset, txo.script_length, script_hash,
                    date_updated, date_updated)

            # Remember the same locking script can be used in multiple transactions.
            shl = txo_script_hashes.setdefault(script_hash, [])
            shl.append(TXOData(TxoKeyType(tx_hash, txo_index), txo.value, txo_flags,
                txo_entry is not None))

    callbacks.progress(46, _("Processing script hashes"))

    # Cache all script hashes. This needs to be done for all keys based on the account type and the
    # masterkey used by it. All script types for the given account type should be looked for.
    mk_keystores: Dict[int, KeyStore] = {}
    account_keystores: Dict[int, KeyStore] = {}
    for mkrow in sorted(masterkeys.values(), key=lambda t: 0 if t.masterkey_id is None
            else t.masterkey_id):
        assert mkrow is not None
        data: Dict[str, Any] = json.loads(mkrow.derivation_data)
        parent_keystore: Optional[KeyStore] = None
        if mkrow.parent_masterkey_id is not None:
            parent_keystore = mk_keystores[mkrow.parent_masterkey_id]
        mk_keystores[mkrow.masterkey_id] = instantiate_keystore(mkrow.derivation_type, data,
            parent_keystore, mkrow) # type: ignore

    private_key_types = set([ DerivationType.PRIVATE_KEY ])
    address_types = set([ DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH ])
    key_script_hashes: Dict[bytes, PossibleScript] = {}
    for account in accounts.values():
        account_id = account.account_id
        masterkey_id = account.default_masterkey_id
        if masterkey_id is None:
            account_keys = other_keyinstance_data.get(account_id, [])
            found_types = set(key.derivation_type for key in account_keys)
            if found_types & private_key_types:
                ikeystore = account_keystores[account_id] = Imported_KeyStore()
                ikeystore.load_state(account_keys) # type: ignore

                for keyinstance in account_keys:
                    public_key = ikeystore.get_public_key_for_id(keyinstance.keyinstance_id)
                    for script_type in SINGLESIG_SCRIPT_TYPES:
                        script_template = get_single_signer_script_template(public_key,
                            script_type)
                        script_hash = scripthash_bytes(script_template.to_script_bytes())
                        key_script_hashes[script_hash] = PossibleScript(account_id,
                            None, keyinstance, (), script_type,
                            script_hash)
            elif found_types & address_types:
                script_types = ACCOUNT_SCRIPT_TYPES[AccountType.IMPORTED_ADDRESS]
                for keyinstance in account_keys:
                    hash = extract_public_key_hash(keyinstance) # type: ignore
                    script_template = Address.from_string(hash, Net.COIN)
                    script_hash = scripthash_bytes(script_template.to_script_bytes())
                    key_script_hashes[script_hash] = PossibleScript(account_id,
                        None, keyinstance, (), script_type,
                        script_hash)
            else:
                raise DatabaseMigrationError(_("Account corrupt, types: {}").format(found_types))
        else:
            keystore = account_keystores[account_id] = mk_keystores[masterkey_id]
            mk_keyinstances = mk_keyinstance_data.get((account_id, masterkey_id), {})
            if keystore.type() == KeystoreType.MULTISIG:
                ms_keystore = cast(Multisig_KeyStore, keystore)
                child_ms_keystores = ms_keystore.get_cosigner_keystores()
                for subpath in (CHANGE_SUBPATH, RECEIVING_SUBPATH):
                    # We only look at the keys the account already has enumerated from the
                    # derivation path. The assumption is that if further keys are enumerated by the
                    # account later, they will get mapped and matched then.
                    for i in range(ms_keystore.get_next_index(subpath)):
                        derivation_path = subpath + (i,)
                        public_keys_hex = [ k.derive_pubkey(derivation_path).to_hex()
                            for k in child_ms_keystores ]
                        for script_type in MULTISIG_SCRIPT_TYPES:
                            script_template = get_multi_signer_script_template(public_keys_hex,
                                ms_keystore.m, script_type)
                            script_hash = scripthash_bytes(script_template.to_script_bytes())
                            key_script_hashes[script_hash] = PossibleScript(account_id,
                                masterkey_id, mk_keyinstances[derivation_path], derivation_path,
                                script_type, script_hash)
            else:
                ss_keystore = cast(SinglesigKeyStoreTypes, keystore)
                for subpath in (CHANGE_SUBPATH, RECEIVING_SUBPATH):
                    for i in range(ss_keystore.get_next_index(subpath)):
                        derivation_path = subpath + (i,)
                        public_key = ss_keystore.derive_pubkey(derivation_path)
                        for script_type in SINGLESIG_SCRIPT_TYPES:
                            script_template = get_single_signer_script_template(public_key,
                                script_type)
                            script_hash = scripthash_bytes(script_template.to_script_bytes())
                            key_script_hashes[script_hash] = PossibleScript(account_id,
                                masterkey_id, mk_keyinstances[derivation_path], derivation_path,
                                script_type, script_hash)

    # ------------------------------------------------------------------------
    # Fill in missing spend data.

    callbacks.progress(50, _("Populating additional data"))

    tx_deltas: Dict[Tuple[bytes, int], int] = defaultdict(int)
    for script_hash, txo_datas in txo_script_hashes.items():
        for txo_data in txo_datas:
            # We are mapping in TXO usage of keys, so if the script is unknown skip it.
            kscript = key_script_hashes.get(script_hash)
            if kscript is None:
                logger.warning("Failed to find key usage for script hash "
                    f"{script_hash.hex()} in txo {txo_data.key}")
                continue

            # All the inputs are inserts, so a single lookup here should prove existence of a spend.
            txi_spend = txi_inserts.get(txo_data.key)
            txo_update = txo_updates.get(txo_data.key)
            if txo_update:
                # The output already exists. So there should already be a positive tx delta also.
                if txi_spend:
                    if txo_data.flags & TransactionOutputFlag.IS_SPENT:
                        # TODO: Is there anything we can validate here?
                        pass
                    else:
                        # EFFECT: Account for a previously unrecognised spend.
                        tx_deltas[(txi_spend.tx_hash, kscript.keyinstance.keyinstance_id)]\
                            -= txo_data.value
                        txo_updates[txo_data.key] = txo_update._replace(
                            flags=txo_data.flags|TransactionOutputFlag.IS_SPENT)
                else:
                    if txo_data.flags & TransactionOutputFlag.IS_SPENT:
                        raise DatabaseMigrationError(_("txo update spent with no txi"))
                    # EFFECT: Account for a previously unrecognised receipt.
                    tx_deltas[(txo_update.tx_hash, kscript.keyinstance.keyinstance_id)]\
                        += txo_data.value
            else:
                txo_insert = txo_inserts[txo_data.key]
                # EFFECT: Account for a newly recognised receipt.
                tx_deltas[(txo_insert.tx_hash, kscript.keyinstance.keyinstance_id)]\
                    -= txo_data.value
                if txi_spend:
                    # EFFECT: Account for a newly recognised spend.
                    tx_deltas[(txi_spend.tx_hash, kscript.keyinstance.keyinstance_id)]\
                        -= txo_data.value
                    txo_inserts[txo_data.key] = txo_insert._replace(
                        flags=txo_data.flags|TransactionOutputFlag.IS_SPENT)

    # ------------------------------------------------------------------------
    # Update the database.

    progress_text = _("Writing data: {}")

    # Account transaction updates.
    callbacks.progress(60, progress_text.format(_("account transactions")))
    # Delete the `AccountTransactions` view and replace it with an `AccountTransactions` table
    # which allows per-account transaction state.
    conn.execute("CREATE TABLE AccountTransactions2 ("
        "tx_hash BLOB NOT NULL,"
        "account_id INTEGER NOT NULL,"
        "flags INTEGER NOT NULL DEFAULT 0,"
        "description TEXT DEFAULT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (account_id) REFERENCES Accounts (account_id),"
        "FOREIGN KEY (tx_hash) REFERENCES Transactions (tx_hash)"
    ")")
    # We transfer the "pays invoice" flag for a transaction to be per-account not per-tx.
    conn.execute("INSERT INTO AccountTransactions2 (tx_hash, account_id, description, "
        "flags, date_created, date_updated) SELECT AT.tx_hash, AT.account_id, T.description, "
        f"T.flags & {AccountTxFlags.PAYS_INVOICE}, T.date_created, T.date_updated "
        "FROM AccountTransactions AS AT INNER JOIN Transactions AS T ON AT.tx_hash = T.tx_hash")

    # Sanity check: There should be the same number of entries in both objects.
    rows = conn.execute("SELECT COUNT(*) FROM AccountTransactions2 UNION ALL "
        "SELECT COUNT(*) FROM AccountTransactions").fetchall()
    if len(rows) != 2 or rows[0][0] != rows[1][0]:
        # This will cause the context manager to rollback its transaction.
        raise DatabaseMigrationError("Failed to copy account transaction data")

    conn.execute("DROP VIEW AccountTransactions")
    conn.execute("ALTER TABLE AccountTransactions2 RENAME TO AccountTransactions")

    # Transaction output updates.
    callbacks.progress(62, progress_text.format(_("transaction outputs")))
    # Adjust the constraint on the `TransactionOutputs.keyinstance_id` field only way possible.
    conn.execute("CREATE TABLE IF NOT EXISTS TransactionOutputs2 ("
        "tx_hash BLOB NOT NULL,"
        "tx_index INTEGER NOT NULL,"
        "value INTEGER NOT NULL,"
        "keyinstance_id INTEGER DEFAULT NULL,"
        "flags INTEGER NOT NULL,"
        "script_offset INTEGER DEFAULT 0,"
        "script_length INTEGER DEFAULT 0,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (tx_hash) REFERENCES Transactions (tx_hash),"
        "FOREIGN KEY (keyinstance_id) REFERENCES KeyInstances (keyinstance_id)"
    ")")
    conn.execute("INSERT INTO TransactionOutputs2 (tx_hash, tx_index, value, keyinstance_id, "
        "flags, date_created, date_updated) SELECT tx_hash, tx_index, value, keyinstance_id, "
        "flags, date_created, date_updated FROM TransactionOutputs")
    conn.execute("DROP TABLE TransactionOutputs")
    conn.execute("ALTER TABLE TransactionOutputs2 RENAME TO TransactionOutputs")

    # This will add the `script_hash` column to the `TransactionOutputs` table, but set all
    # existing rows to the empty blob (we will correct this to give them their correct hash below).
    conn.execute("ALTER TABLE TransactionOutputs ADD COLUMN script_hash BLOB NOT NULL DEFAULT x''")

    # If we do not recreate this it gets lost (presumably with the old table).
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_TransactionOutputs_unique ON TransactionOutputs(tx_hash, tx_index)")

    conn.executemany("INSERT INTO TransactionOutputs (tx_hash, tx_index, value, "
        "keyinstance_id, flags, script_offset, script_length, script_hash, date_created, "
        "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?)", txo_inserts.values())
    cursor = conn.executemany("UPDATE TransactionOutputs SET script_hash=?, flags=?, "
        "script_offset=?, script_length=?, date_updated=? WHERE tx_hash=? AND tx_index=?",
        txo_updates.values())
    if cursor.rowcount != len(txo_updates):
        raise DatabaseMigrationError(f"Made {cursor.rowcount} txo changes, "
            f"not the expected {len(txo_updates)}")

    # Transaction input updates.
    callbacks.progress(64, progress_text.format(_("transaction inputs")))
    # Create the new `TransactionInputs` table.
    conn.execute("CREATE TABLE IF NOT EXISTS TransactionInputs ("
        "tx_hash BLOB NOT NULL,"
        "txi_index INTEGER NOT NULL,"
        "spent_tx_hash BLOB NOT NULL,"
        # No foreign key as this may not be present.
        "spent_txo_index INTEGER NOT NULL,"
        "sequence INTEGER NOT NULL,"
        "flags INTEGER NOT NULL,"
        "script_offset INTEGER,"
        "script_length INTEGER,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (tx_hash) REFERENCES Transactions (tx_hash)"
    ")")
    conn.executemany("INSERT INTO TransactionInputs (tx_hash, txi_index, spent_tx_hash, "
        "spent_txo_index, sequence, flags, script_offset, script_length, date_created, "
        "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?)", txi_inserts.values())

    # Transaction updates.
    callbacks.progress(66, progress_text.format(_("transactions")))
    # This will add the `lock_time` column to the `Transactions` table.
    conn.execute("ALTER TABLE Transactions ADD COLUMN locktime int DEFAULT NULL")
    conn.execute("ALTER TABLE Transactions ADD COLUMN version int DEFAULT NULL")
    cursor = conn.executemany("UPDATE Transactions SET version=?, locktime=?, date_updated=? "
        "WHERE tx_hash=?", tx_updates)
    if cursor.rowcount != len(tx_updates):
        raise DatabaseMigrationError(f"Made {cursor.rowcount} tx changes, "
            f"not the expected {len(tx_updates)}")
    # These should be pulled back in by the syncing process.
    cursor = conn.execute("UPDATE Transactions SET flags=(flags&?)", (~TxFlags.HasByteData,))
    logger.debug("Cleared bytedata flag from %d transactions", cursor.rowcount)

    cursor = conn.execute("SELECT COUNT(*) FROM Transactions WHERE flags=(flags&?)!=0",
        (TxFlags.HasByteData,))
    remaining_hasbytedata_count = cursor.fetchone()[0]
    if remaining_hasbytedata_count != 0:
        raise DatabaseMigrationError("Failed to clear HasByteData for "
            f"{remaining_hasbytedata_count} transactions")

    cursor = conn.execute("DELETE FROM Transactions WHERE tx_data IS NULL")
    logger.debug("Deleted %d transactions that had no data", cursor.rowcount)

    # Transaction delta updates.
    tx_delta_update_rows: List[Tuple[int, int, bytes, int]] = [ (date_updated, value, tx_hash,
        keyinstance_id) for ((tx_hash, keyinstance_id), value) in tx_deltas.items() ]
    tx_delta_insert_rows: List[Tuple[bytes, int, int, int, int]] = [ (tx_hash, keyinstance_id,
        value, date_updated, date_updated)
        for ((tx_hash, keyinstance_id), value) in tx_deltas.items() ]
    cursor = conn.executemany("UPDATE TransactionDeltas "
        "SET date_updated=?, value_delta=value_delta+? WHERE tx_hash=? AND keyinstance_id=?",
        tx_delta_update_rows)
    tx_delta_change_count = cursor.rowcount
    cursor = conn.executemany("INSERT OR IGNORE INTO TransactionDeltas "
        "(tx_hash, keyinstance_id, value_delta, date_created, date_updated) "
        "VALUES (?, ?, ?, ?, ?)", tx_delta_insert_rows)
    tx_delta_change_count += cursor.rowcount
    if tx_delta_change_count != len(tx_deltas):
        raise DatabaseMigrationError(f"Made {tx_delta_change_count} tx delta changes, "
            f"not the expected {len(tx_deltas)}")

    conn.execute("CREATE TABLE IF NOT EXISTS KeyInstanceScripts ("
        "keyinstance_id INTEGER NOT NULL,"
        "script_type INTEGER NOT NULL,"
        "script_hash BLOB NOT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (keyinstance_id) REFERENCES KeyInstances (keyinstance_id)"
    ")")

    # Add all the possible keyinstance script hashes.
    key_scripts_rows: List[Tuple[int, int, bytes, int, int]] = []
    for possible_script in key_script_hashes.values():
        rows.append((possible_script.keyinstance.keyinstance_id, possible_script.script_type,
        possible_script.script_hash, date_created, date_created))
    conn.executemany("INSERT INTO KeyInstanceScripts (keyinstance_id, script_type, script_hash, "
        "date_created, date_updated) VALUES (?,?,?,?,?)", key_scripts_rows)

    # ------------------------------------------------------------------------
    # Validation on completion of this migration step.
    callbacks.progress(90, _("Verifying migration step"))

    # Check that we set all the TransactionOutput script_hashes.
    row = conn.execute("SELECT COUNT(*) FROM TransactionOutputs WHERE script_hash=x''").fetchone()
    if row[0] > 0:
        raise DatabaseMigrationError(f"Found {row[0]} outputs with bad script hashes")
    # Check that we set all the Transaction locktimes and versions.
    row = conn.execute("SELECT COUNT(*) FROM Transactions WHERE version=-1 OR locktime=-1"
        ).fetchone()
    if row[0] > 0:
        raise DatabaseMigrationError(f"Found {row[0]} transactions with bad versions or locktimes")

    callbacks.progress(100, _("Rechecking work done"))

    date_updated = int(time.time())
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [json.dumps(MIGRATION),date_updated,"migration"])
