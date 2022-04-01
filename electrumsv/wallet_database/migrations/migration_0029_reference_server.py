# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from __future__ import annotations
import json
from typing import cast, List, Optional, Tuple, Any
from bitcoinx import ElectrumMnemonic, PublicKey, Wordlists
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3  # type: ignore[no-redef]

from ...constants import AccountFlags, ADDRESS_DERIVATION_TYPES, DerivationType, MasterKeyFlags, \
    ScriptType, WALLET_ACCOUNT_PATH_TEXT
from ...credentials import PasswordTokenProtocol
from ...i18n import _
from ...logs import logs
from ...keystore import bip32_master_key_data_from_seed, instantiate_keystore, KeyStore
from ...util import get_posix_timestamp
from ...util.misc import ProgressCallbacks
from ...wallet_support.keys import get_pushdata_hash_for_derivation, \
    get_pushdata_hash_for_keystore_key_data, get_pushdata_hash_for_public_keys

from ..storage_migration import KeyInstanceFlag_27, KeyInstanceRow_27, MasterKeyDataBIP32_27, \
    MasterKeyDataTypes_27, MasterKeyRow_27, TxFlags_22

MIGRATION = 29

logger = logs.get_logger(f"migration-{MIGRATION:04d}")


def execute(conn: sqlite3.Connection, password_token: PasswordTokenProtocol,
        callbacks: ProgressCallbacks) -> None:
    date_updated = get_posix_timestamp()
    callbacks.progress(0, _("Update started"))

    # We have persisted the next identifier for the `Accounts` table in the database.
    cursor = conn.execute("SELECT key, value FROM WalletData "
        "WHERE key='next_account_id' OR key='next_masterkey_id'")
    wallet_data: dict[str, Any] = { k: int(v) for (k, v) in cast(List[Tuple[str, str]],
        cursor.fetchall()) }
    account_id = wallet_data["next_account_id"]
    wallet_data["next_account_id"] += 1
    masterkey_id = wallet_data["next_masterkey_id"]
    wallet_data["next_masterkey_id"] += 1
    wallet_data["main_server"] = ""

    conn.execute("ALTER TABLE MasterKeys ADD COLUMN flags INTEGER NOT NULL DEFAULT 0")

    # Create the new wallet definitive seed words and the masterkey that stores them.
    derivation_text = "m"
    seed_phrase = ElectrumMnemonic.generate_new(Wordlists.bip39_wordlist("english.txt"))
    bip32_seed = ElectrumMnemonic.new_to_seed(seed_phrase, "", compatible=True)
    derivation_data_latest = bip32_master_key_data_from_seed(seed_phrase, "", bip32_seed,
        derivation_text, password_token.password)
    # Convert from the latest version of this structure to the version in place at time of writing.
    derivation_data1: MasterKeyDataBIP32_27 = {
        "xpub": derivation_data_latest["xpub"],
        "seed": derivation_data_latest["seed"],
        "derivation": derivation_data_latest["derivation"],
        "passphrase": derivation_data_latest["passphrase"],
        "label": derivation_data_latest["xpub"],
        "xprv": derivation_data_latest["xprv"],
    }
    derivation_data_bytes = json.dumps(derivation_data1).encode()
    sql = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)")
    conn.execute(sql, (masterkey_id, None, DerivationType.BIP32, derivation_data_bytes,
        MasterKeyFlags.WALLET_SEED | MasterKeyFlags.ELECTRUM_SEED, date_updated, date_updated))

    account_masterkey_id = wallet_data["next_masterkey_id"]
    wallet_data["next_masterkey_id"] += 1

    # Create the petty cash account masterkey. We derive the index matching the current account
    # id for accounts derived from the wallet, so that we do not have to track two different
    # account indexes.
    derivation_text = f"{WALLET_ACCOUNT_PATH_TEXT}/{account_id}'"
    derivation_data_latest = bip32_master_key_data_from_seed(None, "", bip32_seed,
        derivation_text, password_token.password)
    # Convert from the latest version of this structure to the version in place at time of writing.
    derivation_data2: MasterKeyDataBIP32_27 = {
        "xpub": derivation_data_latest["xpub"],
        "seed": derivation_data_latest["seed"],
        "derivation": derivation_data_latest["derivation"],
        "passphrase": derivation_data_latest["passphrase"],
        "label": derivation_data_latest["label"],
        "xprv": derivation_data_latest["xprv"],
    }
    derivation_data_bytes = json.dumps(derivation_data2).encode()
    sql = ("INSERT INTO MasterKeys (masterkey_id, parent_masterkey_id, derivation_type, "
        "derivation_data, flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)")
    conn.execute(sql, (account_masterkey_id, masterkey_id, DerivationType.BIP32,
        derivation_data_bytes, MasterKeyFlags.NONE, date_updated, date_updated))

    conn.execute("ALTER TABLE Accounts ADD COLUMN flags INTEGER NOT NULL DEFAULT 0")
    conn.execute("INSERT INTO Accounts (account_id, default_masterkey_id, default_script_type, "
        "account_name, flags, date_created, date_updated) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (account_id, account_masterkey_id, ScriptType.P2PKH, "Petty cash",
        AccountFlags.IS_PETTY_CASH, date_updated, date_updated))

    # NOTE(AustEcon) - Track tx_hashes for which we are awaiting a merkle proof callback from mAPI.
    # This is to safeguard against a missed notification from mAPI as well as to drive the lifetime
    # management of a given channel.
    #
    # There should be waiting time threshold at which we give up and request the merkle
    # proof directly from an indexer if it still has not arrived e.g. 24 hours since broadcast_date.
    conn.execute("""
        CREATE TABLE MAPIBroadcastCallbacks (
            tx_hash                     BLOB          PRIMARY KEY,
            peer_channel_id             VARCHAR(1024) NOT NULL,
            broadcast_date              INTEGER       NOT NULL,
            encrypted_private_key       BLOB          NOT NULL,
            server_id                   INTEGER       NOT NULL,
            status_flags                INTEGER       NOT NULL
        )
    """)

    # Using a composite key to refer to servers and different tables is awkward, especially
    # as we add dependent tables on servers. For this reason both the base server table and
    # server account table are now merged and there is a primary key `server_id` column.
    conn.execute("""
        CREATE TABLE Servers2 (
            server_id                   INTEGER     PRIMARY KEY,
            server_type                 INTEGER     NOT NULL,
            url                         TEXT        NOT NULL,
            account_id                  INTEGER     DEFAULT NULL,
            server_flags                INTEGER     NOT NULL DEFAULT 0,
            api_key_template            TEXT        DEFAULT NULL,
            encrypted_api_key           TEXT        DEFAULT NULL,
            fee_quote_json              TEXT        DEFAULT NULL,
            date_last_connected         INTEGER     DEFAULT 0,
            date_last_tried             INTEGER     DEFAULT 0,
            date_created                INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (account_id) REFERENCES Accounts (account_id)
        )
    """)
    # We ignore the `ServerAccounts` table because if people have account-specific server entries
    # they can recreate them. This is a new table and there will not be any real world usage.
    conn.execute("DROP TABLE ServerAccounts")
    conn.execute("DROP INDEX idx_Servers_unique")
    conn.execute("DROP TABLE Servers")
    conn.execute("ALTER TABLE Servers2 RENAME TO Servers")
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_Servers_unique
            ON Servers(server_type, url, account_id)
    """)

    # We add two more columns to `PaymentRequests`, `script_type` and `pushdata_hash`. These are
    # static values that relate to the copied text that is given out by the wallet owner. And we
    # can map them to their primary usage tip filtering registrations.
    conn.execute("""
        CREATE TABLE PaymentRequests2 (
            paymentrequest_id           INTEGER     PRIMARY KEY,
            keyinstance_id              INTEGER     NOT NULL,
            state                       INTEGER     NOT NULL,
            description                 TEXT        NULL,
            expiration                  INTEGER     NULL,
            value                       INTEGER     NULL,
            script_type                 INTEGER     NOT NULL,
            pushdata_hash               BLOB        NOT NULL,
            date_created                INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY(keyinstance_id) REFERENCES KeyInstances (keyinstance_id)
        )
    """)
    # TODO(1.4.0) Key usage. Copy across the existing records and populate the two new columns
    #     with the correct value.

    masterkey_rows: list[MasterKeyRow_27] = [ MasterKeyRow_27(t[0], t[1], DerivationType(t[2]),
        t[3], MasterKeyFlags(t[4])) for t in conn.execute("""
            SELECT masterkey_id, parent_masterkey_id, derivation_type, derivation_data, flags
            FROM MasterKeys
            ORDER BY masterkey_id ASC
        """).fetchall() ]

    keystores_by_masterkey_id = dict[int, KeyStore]()
    for masterkey_row in masterkey_rows:
        derivation_data = cast(MasterKeyDataTypes_27, json.loads(masterkey_row[3]))
        parent_keystore: Optional[KeyStore] = None
        if masterkey_row.parent_masterkey_id is not None:
            parent_keystore = keystores_by_masterkey_id[masterkey_row.parent_masterkey_id]
        keystores_by_masterkey_id[masterkey_row[0]] = instantiate_keystore(
            masterkey_row.derivation_type, derivation_data, parent_keystore, masterkey_row)

    paymentrequest_keyinstance_rows: list[tuple[KeyInstanceRow_27, int, ScriptType]] = [
        (KeyInstanceRow_27(t[0], t[1], t[2], DerivationType(t[3]), t[4], t[5],
        KeyInstanceFlag_27(t[6]), t[7]), t[8], ScriptType(t[9])) for t in conn.execute("""
            SELECT KI.keyinstance_id, KI.account_id, KI.masterkey_id, KI.derivation_type,
                KI.derivation_data, KI.derivation_data2, KI.flags, KI.description,
                PR.paymentrequest_id, A.default_script_type
            FROM PaymentRequests PR
            INNER JOIN KeyInstances KI ON KI.keyinstance_id=PR.keyinstance_id
            INNER JOIN Accounts A ON A.account_id=KI.account_id
        """).fetchall() ]

    logger.debug("Copying the original PaymentRequests table contents to updated table")
    for keyinstance_row, paymentrequest_id, script_type in paymentrequest_keyinstance_rows:
        assert keyinstance_row.derivation_data2 is not None
        if keyinstance_row.masterkey_id is not None:
            keystore = keystores_by_masterkey_id[keyinstance_row.masterkey_id]
            pushdata_hash = get_pushdata_hash_for_keystore_key_data(keystore, keyinstance_row,
                script_type)
        elif keyinstance_row.derivation_type in ADDRESS_DERIVATION_TYPES:
            # The account default script type is irrelevant. We use the script type inferred
            # by the address type.
            script_type, pushdata_hash = get_pushdata_hash_for_derivation(
                keyinstance_row.derivation_type, keyinstance_row.derivation_data2)
        elif keyinstance_row.derivation_type == DerivationType.PRIVATE_KEY:
            public_keys = [ PublicKey.from_bytes(keyinstance_row.derivation_data2) ]
            pushdata_hash = get_pushdata_hash_for_public_keys(script_type, public_keys)
        else:
            raise NotImplementedError(f"Unexpected key type {keyinstance_row}")

        conn.execute("""
            INSERT INTO PaymentRequests2 (paymentrequest_id, keyinstance_id, state, description,
                expiration, value, script_type, pushdata_hash, date_created, date_updated) "
            SELECT PR.paymentrequest_id, PR.keyinstance_id, PR.state, PR.description,
                PR.expiration, PR.value, ?, ?, PR.date_created, PR.date_updated
            FROM PaymentRequests AS PR
            WHERE paymentrequest_id=?
        """, (script_type, pushdata_hash, paymentrequest_id))

    conn.execute("DROP TABLE PaymentRequests")
    conn.execute("ALTER TABLE PaymentRequests2 RENAME TO PaymentRequests")

    # We need to persist the updated next primary key value for the `Accounts` table.
    # We need to persist the updated next identifier for the `Accounts` table.
    conn.executemany("UPDATE WalletData SET value=? WHERE key=?",
        [ (v, k) for (k, v) in wallet_data.items() ])

    ## Database cleanup.
    # Remove vestigal traces of `HasProofData` transaction flag (we cleared others in migration 22).
    clear_bits_args = (~TxFlags_22.HasProofData, TxFlags_22.HasProofData)
    cursor = conn.execute("UPDATE Transactions SET flags=(flags&?) WHERE flags&?", clear_bits_args)
    logger.debug("cleared HasProofData flag from %d transactions", cursor.rowcount)

    # We are deleting the existing non-TSC proofs for all transaction rows and we will reacquire
    # TSC versions of them. This is fine as there is no guarantee we have proofs for all legacy
    # transactions anyway and they would need to be acquired, so acquiring more is just more of
    # the same. The reason we do not clear the SETTLED flag is that this would be a bad user
    # experience and they would see all their transactions strangely revert back to CLEARED and
    # they may not be re-verified until they jump through server hoops.
    conn.execute("UPDATE Transactions SET proof_data=NULL")

    # Transfer all merkle proof data from the Transactions table to the
    # The pathways for insertion to this table are as follows:
    #  1) Wallet._obtain_merkle_proofs_worker_async -> Wallet.import_transaction_async
    #  2) Wallet._obtain_transactions_worker_async -> Wallet.import_transaction_async
    #  3) wait_for_merkle_proofs_and_double_spends (not yet in use) - mAPI callbacks
    # All proofs from all chains should be inserted here (i.e. including orphaned proofs). They
    # can be pruned when the proof on the main server chain is buried by sufficient proof of work .
    conn.execute("""CREATE TABLE IF NOT EXISTS TransactionProofs (
        block_hash BLOB,
        tx_hash BLOB,
        proof_data BLOB DEFAULT NULL,
        block_height INTEGER DEFAULT NULL,
        block_position INTEGER DEFAULT NULL
    )""")
    conn.execute("CREATE UNIQUE INDEX idx_tx_proofs ON TransactionProofs (tx_hash, block_hash)")

    ## Migration finalisation.
    callbacks.progress(100, _("Update done"))
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [str(MIGRATION),date_updated,"migration"])
