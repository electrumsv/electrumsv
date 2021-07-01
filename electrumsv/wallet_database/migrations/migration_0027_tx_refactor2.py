from collections import defaultdict
import json
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    # NOTE(typing) pylance complains about a missing import.
    import pysqlite3 as sqlite3 # type: ignore
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.9.5 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore
from typing import Any, cast, Dict, List, NamedTuple, Optional, Tuple

from bitcoinx import hash_to_hex_str, P2PKH_Address, P2SH_Address, PublicKey

from ...bitcoin import scripthash_bytes, sha256
from ...constants import AccountTxFlags, BlockHeight, CHANGE_SUBPATH, DerivationType, \
    DerivationPath, KeyInstanceFlag, KeystoreType, RECEIVING_SUBPATH, ScriptType, \
    TransactionInputFlag, TransactionOutputFlag
from ...exceptions import DatabaseMigrationError
from ...i18n import _
from ...keys import get_multi_signer_script_template, get_single_signer_script_template
from ...keystore import (Imported_KeyStore, instantiate_keystore, KeyStore,
    Multisig_KeyStore, SinglesigKeyStoreTypes)
from ...logs import logs
from ...networks import Net
from ...transaction import Transaction
from ...types import TxoKeyType
from ...util import get_posix_timestamp
from ...util.misc import ProgressCallbacks

from ..storage_migration import (AccountRow1, convert_masterkey_derivation_data1,
    KeyInstanceDataBIP32SubPath1, KeyInstanceDataTypes1, KeyInstanceFlag1, KeyInstanceRow1,
    MasterKeyDataBIP321, MasterKeyDataTypes1, MasterKeyRow1, TransactionOutputFlag1, TxFlags1,
    upgrade_masterkey1)
from ..util import create_derivation_data2

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

class PossibleScript(NamedTuple):
    account_id: int
    masterkey_id: Optional[int]
    keyinstance: KeyInstanceRow1
    derivation_path: DerivationPath
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
    script_hash: bytes
    script_type: ScriptType
    script_offset: int
    script_length: int
    spending_tx_hash: Optional[bytes]
    spending_txi_index: Optional[int]
    date_created: int
    date_updated: int

class TXOUpdateRow(NamedTuple):
    # These are ordered and aligned with the SQL statement.
    keyinstance_id: Optional[int]
    flags: TransactionOutputFlag
    script_hash: bytes
    script_type: ScriptType
    script_offset: int
    script_length: int
    spending_tx_hash: Optional[bytes]
    spending_txi_index: Optional[int]
    date_updated: int
    tx_hash: bytes
    txo_index: int

class TXOExistingEntry(NamedTuple):
    flags: TransactionOutputFlag1
    keyinstance_id: int


MULTISIG_SCRIPT_TYPES = (ScriptType.MULTISIG_BARE, ScriptType.MULTISIG_P2SH)
SINGLESIG_SCRIPT_TYPES = (ScriptType.P2PK, ScriptType.P2PKH)


MIGRATION = 27

def execute(conn: sqlite3.Connection, callbacks: ProgressCallbacks) -> None:
    date_updated = get_posix_timestamp()

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
    accounts: Dict[int, AccountRow1] = {}
    cursor = conn.execute("SELECT account_id, default_masterkey_id, default_script_type, "
        "account_name FROM Accounts")
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        accounts[row[0]] = AccountRow1(row[0], row[1], ScriptType(row[2]), row[3])

    # Cache masterkey data.
    masterkeys: Dict[int, MasterKeyRow1] = {}
    cursor = conn.execute("SELECT masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data FROM MasterKeys")
    rows = cursor.fetchall()
    cursor.close()
    for row in rows:
        masterkeys[row[0]] = MasterKeyRow1(*row)

    # Cache keyinstance data. These are only going to cover all existing detected key usage and the
    # gap limit beyond that. Because the creation and detection of the use of these is driven by
    # the indexer/electrumx telling us they have been used, it is not guaranteed that we will have
    # them all.
    keyinstances: Dict[int, KeyInstanceRow1] = {}
    # For accounts with masterkeys. {(account_id, masterkey_id): { derivation_path: keyinstance }}
    mk_keyinstance_data: Dict[Tuple[int, int], Dict[DerivationPath, KeyInstanceRow1]] = \
        defaultdict(dict)
    # For other account types. {account_id: [keyinstance,..]}
    other_keyinstance_data: Dict[int, List[Tuple[KeyInstanceRow1, bytes]]] = defaultdict(list)
    cursor = conn.execute("SELECT keyinstance_id, account_id, masterkey_id, derivation_type, "
        "derivation_data, script_type, flags, description FROM KeyInstances")
    rows = cursor.fetchall()
    cursor.close()
    keyinstance_updates: List[Tuple[bytes, int, int]] = []
    for row in rows:
        krow = keyinstances[row[0]] = KeyInstanceRow1(row[0], row[1], row[2],
            DerivationType(row[3]), row[4], ScriptType(row[5]), KeyInstanceFlag(row[6]),
            row[7])
        derivation_data_dict = cast(KeyInstanceDataTypes1, json.loads(krow.derivation_data))
        derivation_data2 = create_derivation_data2(krow.derivation_type, derivation_data_dict)
        if krow.masterkey_id is not None:
            assert krow.derivation_type == DerivationType.BIP32_SUBPATH
            derivation_path = tuple(
                cast(KeyInstanceDataBIP32SubPath1, derivation_data_dict)["subpath"])
            mk_keyinstance_data[(krow.account_id, krow.masterkey_id)][derivation_path] = krow
        else:
            # Used to calculate script hashes.
            other_keyinstance_data[krow.account_id].append((krow, derivation_data2))

        keyinstance_updates.append((derivation_data2, date_updated, row[0]))

    # Cache the existing transaction output entries. They will only be present for transactions the
    # network/electrumx has told us are related to the keys that exist at this point in time, and
    # even then only if we have online and have received up to date network state at the point the
    # account was last unloaded.
    cursor = conn.execute("SELECT tx_hash, tx_index, flags, keyinstance_id from TransactionOutputs")
    txo_existing_entries: Dict[Tuple[bytes, int], TXOExistingEntry] = {
        (row[0], row[1]): TXOExistingEntry(row[2], row[3]) for row in cursor.fetchall() }

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

        base_txo_flags = TransactionOutputFlag.COINBASE if tx.is_coinbase() \
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
                # This flag has been removed.
                txo_flags = TransactionOutputFlag(
                    txo_entry.flags & ~TransactionOutputFlag1.USER_SET_FROZEN)
                txo_updates[TxoKeyType(tx_hash, txo_index)] = TXOUpdateRow(txo_entry.keyinstance_id,
                    txo_flags, script_hash, ScriptType.NONE, txo.script_offset, txo.script_length,
                    None, None, date_updated, tx_hash, txo_index)
            else:
                txo_flags = base_txo_flags
                txo_inserts[TxoKeyType(tx_hash, txo_index)] = TXOInsertRow(tx_hash, txo_index,
                    txo.value, None, txo_flags, script_hash, ScriptType.NONE, txo.script_offset,
                    txo.script_length, None, None, date_updated, date_updated)

            # Remember the same locking script can be used in multiple transactions.
            shl = txo_script_hashes.setdefault(script_hash, [])
            shl.append(TXOData(TxoKeyType(tx_hash, txo_index), txo.value, txo_flags,
                txo_entry is not None))

    callbacks.progress(46, _("Processing script hashes"))

    # Cache all script hashes. This needs to be done for all keys based on the account type and the
    # masterkey used by it. All script types for the given account type should be looked for.
    mk_keystores: Dict[int, KeyStore] = {}
    mk_rows: Dict[int, MasterKeyRow1] = {}
    updated_masterkey_derivation_data: List[Tuple[bytes, int]] = []
    account_keystores: Dict[int, KeyStore] = {}
    for mkrow in sorted(masterkeys.values(), key=lambda t: 0 if t.masterkey_id is None
            else t.masterkey_id):
        assert mkrow is not None
        derivation_data_dict_old = cast(MasterKeyDataTypes1, json.loads(mkrow.derivation_data))
        parent_keystore: Optional[KeyStore] = None
        if mkrow.parent_masterkey_id is not None:
            parent_keystore = mk_keystores[mkrow.parent_masterkey_id]
        derivation_data_dict_new = convert_masterkey_derivation_data1(mkrow.derivation_type,
            derivation_data_dict_old)
        updated_masterkey_derivation_data.append((
            json.dumps(derivation_data_dict_new).encode(), mkrow.masterkey_id))
        mk_keystores[mkrow.masterkey_id] = instantiate_keystore(mkrow.derivation_type,
            derivation_data_dict_new,
            parent_keystore,
            upgrade_masterkey1(mkrow))
        mk_rows[mkrow.masterkey_id] = mkrow

    private_key_types = { DerivationType.PRIVATE_KEY }
    address_types = { DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH }
    key_script_hashes: Dict[bytes, PossibleScript] = {}
    for account in accounts.values():
        account_id = account.account_id
        masterkey_id = account.default_masterkey_id
        if masterkey_id is None:
            account_keyinstance_data = other_keyinstance_data.get(account_id, [])
            found_types = set(key.derivation_type
                for (key, _derivation_data2) in account_keyinstance_data)
            if found_types & private_key_types:
                ikeystore = account_keystores[account_id] = Imported_KeyStore()
                # NOTE(typing) Allow KeyInstanceRow1 to be passed as KeyInstanceRow
                ikeystore.set_state([ t[0] for t in account_keyinstance_data ]) # type: ignore

                for keyinstance, derivation_data2 in account_keyinstance_data:
                    public_key = PublicKey.from_bytes(derivation_data2)
                    for script_type in SINGLESIG_SCRIPT_TYPES:
                        script_template = get_single_signer_script_template(public_key,
                            script_type)
                        script_hash = sha256(script_template.to_script_bytes())
                        key_script_hashes[script_hash] = PossibleScript(account_id,
                            None, keyinstance, (), script_type,
                            script_hash)
            elif found_types & address_types:
                # NOTE In theory we have the hash in derivation_data2 here.
                for keyinstance, derivation_data2 in account_keyinstance_data:
                    if keyinstance.derivation_type == DerivationType.PUBLIC_KEY_HASH:
                        script_type = ScriptType.P2PKH
                        script_template = P2PKH_Address(derivation_data2, Net.COIN)
                    elif keyinstance.derivation_type == DerivationType.SCRIPT_HASH:
                        script_type = ScriptType.MULTISIG_P2SH
                        script_template = P2SH_Address(derivation_data2, Net.COIN)
                    else:
                        raise NotImplementedError("...")

                    script_hash = sha256(script_template.to_script_bytes())
                    key_script_hashes[script_hash] = PossibleScript(account_id,
                        None, keyinstance, (), script_type,
                        script_hash)
            else:
                raise DatabaseMigrationError(_("Account corrupt, types: {}").format(found_types))
        else:
            keystore = account_keystores[account_id] = mk_keystores[masterkey_id]
            # Extract the derivation subpath watermarks. We use these to generate the script
            # hashes up to the point we have already generated keys. We do this instead of just
            # generating them for used keys, as we do not know which the user has given out.
            mk_row = mk_rows[masterkey_id]
            mk_derivation_data = cast(MasterKeyDataBIP321, json.loads(mk_row.derivation_data))
            mk_watermarks: Dict[DerivationPath, int] = defaultdict(int)
            for derivation_path, next_index in mk_derivation_data["subpaths"]:
                mk_watermarks[tuple(derivation_path)] = next_index

            mk_keyinstances = mk_keyinstance_data.get((account_id, masterkey_id), {})
            if keystore.type() == KeystoreType.MULTISIG:
                ms_keystore = cast(Multisig_KeyStore, keystore)
                child_ms_keystores = ms_keystore.get_cosigner_keystores()
                for subpath in (CHANGE_SUBPATH, RECEIVING_SUBPATH):
                    # We only look at the keys the account already has enumerated from the
                    # derivation path. The assumption is that if further keys are enumerated by the
                    # account later, they will get mapped and matched then.
                    for i in range(mk_watermarks[subpath]):
                        derivation_path = tuple(subpath) + (i,)
                        public_keys_hex = [ k.derive_pubkey(derivation_path).to_hex()
                            for k in child_ms_keystores ]
                        for script_type in MULTISIG_SCRIPT_TYPES:
                            script_template = get_multi_signer_script_template(public_keys_hex,
                                ms_keystore.m, script_type)
                            script_hash = sha256(script_template.to_script_bytes())
                            key_script_hashes[script_hash] = PossibleScript(account_id,
                                masterkey_id, mk_keyinstances[derivation_path], derivation_path,
                                script_type, script_hash)
            else:
                ss_keystore = cast(SinglesigKeyStoreTypes, keystore)
                for subpath in (CHANGE_SUBPATH, RECEIVING_SUBPATH):
                    for i in range(mk_watermarks[subpath]):
                        derivation_path = tuple(subpath) + (i,)
                        public_key = ss_keystore.derive_pubkey(derivation_path)
                        for script_type in SINGLESIG_SCRIPT_TYPES:
                            script_template = get_single_signer_script_template(public_key,
                                script_type)
                            script_hash = sha256(script_template.to_script_bytes())
                            key_script_hashes[script_hash] = PossibleScript(account_id,
                                masterkey_id, mk_keyinstances[derivation_path], derivation_path,
                                script_type, script_hash)

    # ------------------------------------------------------------------------
    # Fill in missing spend data.

    callbacks.progress(50, _("Populating additional data"))

    # tx_deltas: Dict[Tuple[bytes, int], int] = defaultdict(int)
    for script_hash, txo_datas in txo_script_hashes.items():
        for txo_data in txo_datas:
            # We are mapping in TXO usage of keys, so if the script is unknown (likely because the
            # output does not belong to this wallet) skip it.
            kscript = key_script_hashes.get(script_hash)
            if kscript is None:
                logger.warning("Failed to find key usage for script hash %s in txo %s",
                    script_hash.hex(), txo_data.key)
                continue

            keyinstance_id = kscript.keyinstance.keyinstance_id
            # All the inputs are inserts, so a single lookup here should prove existence of a spend.
            txi_spend = txi_inserts.get(txo_data.key)
            txo_update = txo_updates.get(txo_data.key)
            spending_tx_hash: Optional[bytes] = None
            spending_txi_index: Optional[int] = None
            txo_flags = txo_data.flags
            if txo_update:
                # The output already exists. So there should already be a positive tx delta also.
                if txi_spend:
                    if txo_data.flags & TransactionOutputFlag.SPENT:
                        assert txo_update.keyinstance_id == keyinstance_id, \
                            "Transaction output spending key does not match"
                    else:
                        # EFFECT: Account for a previously unrecognised spend.
                        # tx_deltas[(txi_spend.tx_hash, keyinstance_id)] -= txo_data.value
                        txo_flags |= TransactionOutputFlag.SPENT
                    spending_tx_hash = txi_spend.tx_hash
                    spending_txi_index = txi_spend.txi_index
                else:
                    if txo_data.flags & TransactionOutputFlag.SPENT:
                        raise DatabaseMigrationError(_("txo update spent with no txi"))
                txo_updates[txo_data.key] = txo_update._replace(
                    flags=txo_flags,
                    keyinstance_id=txo_update.keyinstance_id,
                    script_type=kscript.script_type,
                    spending_tx_hash=spending_tx_hash,
                    spending_txi_index=spending_txi_index)
            else:
                txo_insert = txo_inserts[txo_data.key]
                txo_flags = txo_data.flags
                if txi_spend:
                    txo_flags |= TransactionOutputFlag.SPENT
                    spending_tx_hash = txi_spend.tx_hash
                    spending_txi_index = txi_spend.txi_index
                txo_inserts[txo_data.key] = txo_insert._replace(
                    flags=txo_flags,
                    keyinstance_id=keyinstance_id,
                    script_type=kscript.script_type,
                    spending_tx_hash=spending_tx_hash,
                    spending_txi_index=spending_txi_index)

    # ------------------------------------------------------------------------
    # Update the database.

    progress_text = _("Writing data: {}")

    conn.execute("PRAGMA foreign_keys=OFF;")

    # VIEW->TABLE: AccountTransactions
    callbacks.progress(60, progress_text.format(_("account transactions")))

    # Delete the `AccountTransactions` view and replace it with an `AccountTransactions` table
    # which allows per-account transaction state.
    logger.debug("start the replacement of view AccountTransactions by creating secondary table")
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
    logger.debug("copying the AccountTransactions view contents to secondary table")
    conn.execute(
        "INSERT INTO AccountTransactions2 (tx_hash, account_id, description, flags, "
            "date_created, date_updated) "
        "SELECT AT.tx_hash, AT.account_id, T.description, "
            f"T.flags & {AccountTxFlags.PAYS_INVOICE}, T.date_created, T.date_updated "
        "FROM AccountTransactions AS AT "
        "INNER JOIN Transactions AS T ON AT.tx_hash = T.tx_hash")

    # Sanity check: There should be the same number of entries in both objects.
    rows = conn.execute("SELECT COUNT(*) FROM AccountTransactions2 UNION ALL "
        "SELECT COUNT(*) FROM AccountTransactions").fetchall()
    if len(rows) != 2 or rows[0][0] != rows[1][0]:
        # This will cause the context manager to rollback its transaction.
        raise DatabaseMigrationError("Failed to copy account transaction data")

    logger.debug("dropping view AccountTransactions")
    conn.execute("DROP VIEW AccountTransactions")

    logger.debug("replacing view AccountTransactions with secondary table")
    conn.execute("ALTER TABLE AccountTransactions2 RENAME TO AccountTransactions")

    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_AccountTransactions_unique ON AccountTransactions(tx_hash, account_id)")

    # TABLE: TransactionOutputs
    #
    # SQLite does not have `ALTER TABLE DROP COLUMN` and other similar operations. This means that
    # if you want to replace a column or change it's constraints, you need to replace the table.
    # In fact this is their recommended approach.
    callbacks.progress(62, progress_text.format(_("transaction outputs")))

    logger.debug("fix table TransactionOutputs by creating secondary table")
    conn.execute("CREATE TABLE IF NOT EXISTS TransactionOutputs2 ("
        "tx_hash BLOB NOT NULL,"
        "txo_index INTEGER NOT NULL,"
        "value INTEGER NOT NULL,"
        "keyinstance_id INTEGER DEFAULT NULL,"
        "flags INTEGER NOT NULL,"
        f"script_type INTEGER DEFAULT {ScriptType.NONE},"
        "script_hash BLOB NOT NULL DEFAULT x'',"
        "script_offset INTEGER DEFAULT 0,"
        "script_length INTEGER DEFAULT 0,"
        "spending_tx_hash BLOB NULL,"
        "spending_txi_index INTEGER NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (tx_hash) REFERENCES Transactions (tx_hash),"
        "FOREIGN KEY (keyinstance_id) REFERENCES KeyInstances (keyinstance_id)"
    ")")

    logger.debug("copying the TransactionOutputs table to secondary table")
    conn.execute("INSERT INTO TransactionOutputs2 (tx_hash, txo_index, value, keyinstance_id, "
        "flags, date_created, date_updated) "
        "SELECT tx_hash, tx_index, value, keyinstance_id, flags, date_created, date_updated "
        "FROM TransactionOutputs")

    logger.debug("dropping table TransactionOutputs")
    conn.execute("DROP TABLE TransactionOutputs")

    logger.debug("replacing table TransactionOutputs with secondary table")
    conn.execute("ALTER TABLE TransactionOutputs2 RENAME TO TransactionOutputs")

    # If we do not recreate this it gets lost (presumably with the old table).
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_TransactionOutputs_unique ON TransactionOutputs(tx_hash, txo_index)")

    for output in txo_inserts.values():
        assert output.script_offset != 0
        assert output.script_length != 0

    logger.debug("inserting %d TransactionOutputs rows", len(txo_inserts))
    conn.executemany("INSERT INTO TransactionOutputs (tx_hash, txo_index, value, "
        "keyinstance_id, flags, script_hash, script_type, script_offset, script_length, "
        "spending_tx_hash, spending_txi_index, date_created, date_updated) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", txo_inserts.values())

    logger.debug("updating %d TransactionOutputs rows", len(txo_updates))
    cursor = conn.executemany("UPDATE TransactionOutputs SET keyinstance_id=?, flags=?, "
        "script_hash=?, script_type=?, script_offset=?, script_length=?, spending_tx_hash=?, "
        "spending_txi_index=?, date_updated=? WHERE tx_hash=? AND txo_index=?",
            txo_updates.values())
    logger.debug("updated %d TransactionOutputs rows", cursor.rowcount)
    if cursor.rowcount != len(txo_updates):
        raise DatabaseMigrationError(f"Made {cursor.rowcount} txo changes, "
            f"not the expected {len(txo_updates)}")

    # TABLE: Transaction inputs.
    callbacks.progress(64, progress_text.format(_("transaction inputs")))

    logger.debug("creating table TransactionInputs")
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
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_TransactionInputs_unique ON TransactionInputs(tx_hash, txi_index)")

    for input in txi_inserts.values():
        assert input.script_offset != 0
        assert input.script_length != 0

    logger.debug("inserting %d initial TransactionInputs rows", len(txi_inserts))
    conn.executemany("INSERT INTO TransactionInputs (tx_hash, txi_index, spent_tx_hash, "
        "spent_txo_index, sequence, flags, script_offset, script_length, date_created, "
        "date_updated) VALUES (?,?,?,?,?,?,?,?,?,?)", txi_inserts.values())

    # TABLE: Transactions.
    callbacks.progress(66, progress_text.format(_("transactions")))

    logger.debug("adding column Transactions.locktime")
    conn.execute("ALTER TABLE Transactions ADD COLUMN locktime INTEGER DEFAULT NULL")

    logger.debug("adding column Transactions.version")
    conn.execute("ALTER TABLE Transactions ADD COLUMN version INTEGER DEFAULT NULL")

    logger.debug("adding column Transactions.version")
    conn.execute("ALTER TABLE Transactions ADD COLUMN block_hash BLOB DEFAULT NULL")

    conn.execute(f"UPDATE Transactions SET block_height={BlockHeight.LOCAL} "
        "WHERE block_height IS NULL")

    logger.debug("setting Transactions.version/locktime values for %d affected rows",
        len(tx_updates))
    cursor = conn.executemany("UPDATE Transactions SET version=?, locktime=?, date_updated=? "
        "WHERE tx_hash=?", tx_updates)
    logger.debug("set Transactions.version/locktime values for %d updated rows",
        cursor.rowcount)
    if cursor.rowcount != len(tx_updates):
        raise DatabaseMigrationError(f"Made {cursor.rowcount} tx changes, "
            f"not the expected {len(tx_updates)}")

    # These flags are no longer used. For context, when we received notification from the indexer
    # that a transaction was in the mempool using one of our keys, we used to store a bytedata-less
    # record until we fetched the bytedata (hence HasByteData). And when we were experimenting
    # with encrypted databases, we used to store packed encrypted data and indicate the presence
    # of fields with values (hence HasFee, HasHeight and HasPosition).
    tx_clear_bits = ~(TxFlags1.HasByteData|TxFlags1.HasFee|TxFlags1.HasHeight|TxFlags1.HasPosition)
    cursor = conn.execute("UPDATE Transactions SET flags=(flags&?)", (tx_clear_bits,))
    logger.debug("cleared bytedata flag from %d transactions", cursor.rowcount)

    cursor = conn.execute("SELECT COUNT(*) FROM Transactions WHERE flags=(flags&?)!=0",
        (TxFlags1.HasByteData,))
    remaining_hasbytedata_count = cursor.fetchone()[0]
    if remaining_hasbytedata_count != 0:
        raise DatabaseMigrationError("Failed to clear HasByteData for "
            f"{remaining_hasbytedata_count} transactions")

    # These should be pulled back in by the syncing process.
    logger.debug("deleting Transactions records without bytedata")
    cursor = conn.execute("DELETE FROM Transactions WHERE tx_data IS NULL")
    logger.debug("deleted %d Transactions records without bytedata", cursor.rowcount)

    # TABLE: TransactionDeltas
    logger.debug("dropping table TransactionDeltas")
    conn.execute("DROP TABLE TransactionDeltas")

    # TABLE: MasterKeys
    if len(updated_masterkey_derivation_data):
        conn.executemany("UPDATE MasterKeys SET derivation_data=? WHERE masterkey_id=?",
            updated_masterkey_derivation_data)

    # TABLE: KeyInstances
    assert KeyInstanceFlag1.IS_ACTIVE == KeyInstanceFlag.ACTIVE
    # Mark any keyinstance as reserved that has a script type (is in use in an output).
    # This is introducing an post-migration flag `KeyInstanceFlag.USED` into pre-migration flags.
    conn.execute(f"UPDATE KeyInstances SET flags=flags|{KeyInstanceFlag.USED} "
        f"WHERE script_type!={ScriptType.NONE}")
    # Only keys flagged for a known reason should be left active. We do not want to leak active
    # keys and have user's wallets monitoring arbitrary number of keys we do not know why we are
    # monitoring.
    conn.execute(f"UPDATE KeyInstances SET flags=flags&? WHERE flags&?=?",
        (~KeyInstanceFlag1.IS_ACTIVE,
        KeyInstanceFlag1.IS_ACTIVE|KeyInstanceFlag1.IS_PAYMENT_REQUEST|
            KeyInstanceFlag1.USER_SET_ACTIVE,
        KeyInstanceFlag1.IS_ACTIVE))


    logger.debug("fix table KeyInstances by creating secondary table")
    conn.execute("CREATE TABLE IF NOT EXISTS KeyInstances2 ("
        "keyinstance_id INTEGER PRIMARY KEY,"
        "account_id INTEGER NOT NULL,"
        "masterkey_id INTEGER DEFAULT NULL,"
        "derivation_type INTEGER NOT NULL,"
        "derivation_data BLOB NOT NULL,"
        "derivation_data2 BLOB DEFAULT NULL,"
        "flags INTEGER NOT NULL,"
        "description TEXT DEFAULT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY(account_id) REFERENCES Accounts (account_id)"+
        "FOREIGN KEY(masterkey_id) REFERENCES MasterKeys (masterkey_id)"+
    ")")

    logger.debug("copying the KeyInstances table to secondary table")
    cursor = conn.execute("INSERT INTO KeyInstances2 (keyinstance_id, account_id, masterkey_id, "
        "derivation_type, derivation_data, flags, description, date_created, date_updated) "
        "SELECT keyinstance_id, account_id, masterkey_id, derivation_type, derivation_data, "
        "flags, description, date_created, date_updated FROM KeyInstances")
    logger.debug("copied %d KeyInstances rows", cursor.rowcount)

    logger.debug("dropping table KeyInstances")
    conn.execute("DROP TABLE KeyInstances")

    logger.debug("replacing table KeyInstances with secondary table")
    conn.execute("ALTER TABLE KeyInstances2 RENAME TO KeyInstances")

    logger.debug("setting KeyInstances[derivation_data2] values for %d affected rows",
        len(keyinstance_updates))
    cursor = conn.executemany("UPDATE KeyInstances SET derivation_data2=?, date_updated=? "
        "WHERE keyinstance_id=?",
        keyinstance_updates)
    assert cursor.rowcount == len(keyinstance_updates), "we read the database, writes should match"

    # TABLE: KeyInstanceScripts
    logger.debug("creating table KeyInstanceScripts")
    conn.execute("CREATE TABLE IF NOT EXISTS KeyInstanceScripts ("
        "keyinstance_id INTEGER NOT NULL,"
        "script_type INTEGER NOT NULL,"
        "script_hash BLOB NOT NULL,"
        "date_created INTEGER NOT NULL,"
        "date_updated INTEGER NOT NULL,"
        "FOREIGN KEY (keyinstance_id) REFERENCES KeyInstances (keyinstance_id)"
    ")")

    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS "
        "idx_KeyInstanceScripts_unique ON KeyInstanceScripts(keyinstance_id, script_type)")

    # Add all the possible keyinstance script hashes.
    key_scripts_rows: List[Tuple[int, int, bytes, int, int]] = []
    for possible_script in key_script_hashes.values():
        key_scripts_rows.append((possible_script.keyinstance.keyinstance_id,
        possible_script.script_type, possible_script.script_hash, date_updated, date_updated))
    logger.debug("inserting %d initial KeyInstanceScripts rows", len(key_scripts_rows))
    conn.executemany("INSERT INTO KeyInstanceScripts (keyinstance_id, script_type, script_hash, "
        "date_created, date_updated) VALUES (?,?,?,?,?)", key_scripts_rows)

    # VIEWS
    #
    # TransactionReceivedValues, TransactionSpentValues and TransactionValues replace the old
    # TransactionDeltas table. The idea is that TransactionValues can be used as a drop in
    # replacement for it, and if at a later stage we need to optimise things we can.
    #
    # TransactionReceivedValues: The outputs of a given account transaction, where those
    # outputs are associated with the account.

    logger.debug("creating view TransactionReceivedValues")
    conn.execute(
        "CREATE VIEW TransactionReceivedValues (account_id, tx_hash, keyinstance_id, value) "
        "AS "
            "SELECT ATX.account_id, ATX.tx_hash, TXO.keyinstance_id, TXO.value "
            "FROM AccountTransactions ATX "
            "INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=ATX.tx_hash "
            "INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id "
            "WHERE TXO.keyinstance_id IS NOT NULL AND KI.account_id=ATX.account_id"
    )

    logger.debug("creating view TransactionSpentValues")
    conn.execute(
        "CREATE VIEW TransactionSpentValues (account_id, tx_hash, keyinstance_id, value) AS "
            "SELECT ATX.account_id, ATX.tx_hash, PTXO.keyinstance_id, PTXO.value "
            "FROM AccountTransactions ATX "
            "INNER JOIN TransactionInputs TXI ON TXI.tx_hash=ATX.tx_hash "
            "INNER JOIN TransactionOutputs PTXO ON PTXO.tx_hash=TXI.spent_tx_hash "
                "AND PTXO.txo_index=TXI.spent_txo_index "
            "INNER JOIN KeyInstances KI ON KI.keyinstance_id=PTXO.keyinstance_id "
            "WHERE PTXO.keyinstance_id IS NOT NULL AND KI.account_id=ATX.account_id"
    )

    logger.debug("creating view TransactionValues")
    conn.execute(
        "CREATE VIEW TransactionValues (account_id, tx_hash, keyinstance_id, value) AS "
            "SELECT account_id, tx_hash, keyinstance_id, value FROM TransactionReceivedValues "
            "UNION ALL "
            "SELECT account_id, tx_hash, keyinstance_id, -value FROM TransactionSpentValues"
    )

    conn.execute("PRAGMA foreign_keys=ON;")

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

    # Check that we set all the Transaction locktimes and versions.
    row = conn.execute("SELECT COUNT(*) FROM KeyInstances WHERE masterkey_id IS NOT NULL AND "
        "derivation_data2 IS NULL").fetchone()
    if row[0] > 0:
        raise DatabaseMigrationError(f"Found {row[0]} keys with bad derivation paths")

    callbacks.progress(100, _("Rechecking work done"))

    date_updated = get_posix_timestamp()
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [json.dumps(MIGRATION),date_updated,"migration"])
