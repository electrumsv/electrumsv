from __future__ import annotations
from io import BytesIO
import json
import time
from typing import Any, cast, NamedTuple

import bitcoinx
from bitcoinx import Chain, double_sha256, ElectrumMnemonic, MissingHeader, P2PK_Output, \
    P2PKH_Address, P2SH_Address, PublicKey, Wordlists
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3

from ...app_state import app_state
from ...constants import AccountFlag, ADDRESS_DERIVATION_TYPES, DerivationType, KeystoreType, \
    MasterKeyFlag, MULTI_SIGNER_SCRIPT_TYPES, ScriptType, SEED_PREFIX_WALLET, TxFlag, \
    unpack_derivation_path, WALLET_ACCOUNT_PATH_TEXT
from ...credentials import PasswordTokenProtocol
from ...i18n import _
from ...logs import logs
from ...keystore import bip32_master_key_data_from_seed, instantiate_keystore, KeyStore, \
    Multisig_KeyStore, Xpub
from ...networks import Net
from ...standards.tsc_merkle_proof import ProofTargetFlag, TSCMerkleNode, TSCMerkleNodeKind, \
    TSCMerkleProof, verify_proof
from ...util.misc import ProgressCallbacks
from ...wallet_support.keys import get_output_script_template_for_public_keys, \
    get_pushdata_hash_for_derivation, get_pushdata_hash_for_keystore_key_data, \
    get_pushdata_hash_for_public_keys

from ..storage_migration import KeyInstanceFlag_27, KeyInstanceRow_27, MasterKeyDataBIP32_27, \
    MasterKeyDataTypes_27, MasterKeyRow_27, TxFlags_22
from ..util import database_id_from_timestamp, timestamp_from_id

MIGRATION = 29
logger = logs.get_logger(f"migration-{MIGRATION:04d}")


def execute(conn: sqlite3.Connection, password_token: PasswordTokenProtocol,
        callbacks: ProgressCallbacks) -> None:
    date_updated = int(time.time())
    callbacks.progress(0, _("Update started"))

    _introduce_wallet_masterkey(conn, password_token, date_updated)
    _introduce_mapi_broadcasts(conn)
    _migrate_server_tables(conn)
    _introduce_dpp_invoices(conn)
    _introduce_peer_channels(conn)
    _introduce_tip_filter(conn)
    _introduce_contacts(conn)
    _introduce_backups(conn)
    _introduce_bitcache(conn)

    _migrate_payment_requests(conn)
    _introduce_payments(conn)

    _migrate_merkle_proofs(conn)

    _create_new_views(conn)

    ## Migration finalisation.
    callbacks.progress(100, _("Update done"))
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [str(MIGRATION),date_updated,"migration"])


def _introduce_wallet_masterkey(conn: sqlite3.Connection, password_token: PasswordTokenProtocol,
        date_updated: int) -> None:
    """
    We are generating a master seed words and from this a master private key for each wallet now.
    Any new accounts will be derived from this, as will things like identity keys.
    """

    # We have persisted the next identifier for the `Accounts` table in the database.
    cursor = conn.execute("SELECT key, value FROM WalletData "
        "WHERE key='next_account_id' OR key='next_masterkey_id'")
    wallet_data: dict[str, Any] = { k: int(v) for (k, v) in cast(list[tuple[str, str]],
        cursor.fetchall()) }
    account_id = wallet_data["next_account_id"]
    wallet_data["next_account_id"] += 1
    masterkey_id = wallet_data["next_masterkey_id"]
    wallet_data["next_masterkey_id"] += 1

    conn.execute("ALTER TABLE MasterKeys ADD COLUMN flags INTEGER NOT NULL DEFAULT 0")

    # Create the new wallet definitive seed words and the masterkey that stores them.
    derivation_text = "m"
    seed_phrase = ElectrumMnemonic.generate_new(Wordlists.bip39_wordlist("english.txt"),
        prefix=SEED_PREFIX_WALLET)
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
        MasterKeyFlag.WALLET_SEED | MasterKeyFlag.ELECTRUM_SEED, date_updated, date_updated))

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
        derivation_data_bytes, MasterKeyFlag.NONE, date_updated, date_updated))

    conn.execute("ALTER TABLE Accounts ADD COLUMN flags INTEGER NOT NULL DEFAULT 0")
    conn.execute("ALTER TABLE Accounts ADD COLUMN blockchain_server_id INTEGER DEFAULT NULL")
    conn.execute("ALTER TABLE Accounts ADD COLUMN peer_channel_server_id INTEGER DEFAULT NULL")
    conn.execute("ALTER TABLE Accounts ADD COLUMN bitcache_peer_channel_id INTEGER DEFAULT NULL")
    conn.execute("ALTER TABLE Accounts ADD COLUMN external_bitcache_peer_channel_id "
        "INTEGER DEFAULT NULL")
    conn.execute("INSERT INTO Accounts (account_id, default_masterkey_id, default_script_type, "
        "account_name, flags, date_created, date_updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        (account_id, account_masterkey_id, ScriptType.P2PKH, "Petty cash",
        AccountFlag.IS_PETTY_CASH, date_updated, date_updated))

    # We need to persist the updated next primary key value for the `Accounts` table.
    # We need to persist the updated next identifier for the `Accounts` table.
    conn.executemany("UPDATE WalletData SET value=? WHERE key=?",
        [ (v, k) for (k, v) in wallet_data.items() ])

def _introduce_dpp_invoices(conn: sqlite3.Connection) -> None:
    # flags column can take all possible values of constants.MASK_DPP_STATE_MACHINE or PAID
    # In theory any DPPMessages with the PAID flag set could be deleted from the database at
    # that point
    conn.execute("""
        CREATE TABLE DPPMessages (
            message_id                  TEXT        PRIMARY KEY,
            paymentrequest_id           INTEGER     NOT NULL,
            dpp_invoice_id              TEXT        NOT NULL,
            correlation_id              TEXT        NOT NULL,
            app_id                      TEXT        NOT NULL,
            client_id                   TEXT        NOT NULL,
            user_id                     TEXT        NOT NULL,
            expiration                  TEXT        NULL,
            body                        BLOB        NULL,
            timestamp                   TEXT        NOT NULL,
            type                        TEXT        NOT NULL,
            FOREIGN KEY (paymentrequest_id) REFERENCES PaymentRequests (paymentrequest_id)
        )
    """)

def _introduce_peer_channels(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE ServerPeerChannels (
            peer_channel_id             INTEGER     PRIMARY KEY,
            server_id                   INTEGER     NOT NULL,
            remote_channel_id           TEXT        DEFAULT NULL,
            remote_url                  TEXT        DEFAULT NULL,
            peer_channel_flags          INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (server_id) REFERENCES Servers (server_id)
        )
    """)

    conn.execute("""
        CREATE TABLE ExternalPeerChannels (
            peer_channel_id             INTEGER     PRIMARY KEY,
            remote_url                  TEXT        DEFAULT NULL,
            peer_channel_flags          INTEGER     NOT NULL,
            access_token                TEXT        NOT NULL,
            token_permissions           INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE ServerPeerChannelAccessTokens (
            remote_id                   INTEGER     NOT NULL,
            peer_channel_id             INTEGER     NOT NULL,
            token_flags                 INTEGER     NOT NULL,
            permission_flags            INTEGER     NOT NULL,
            access_token                TEXT        NOT NULL,
            description                 TEXT        NOT NULL,
            FOREIGN KEY (peer_channel_id) REFERENCES ServerPeerChannels (peer_channel_id)
        )
    """)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_ServerPeerChannelAccessTokens_unique "
        "ON ServerPeerChannelAccessTokens(remote_id,peer_channel_id)")

    conn.execute("""
        CREATE TABLE ServerPeerChannelMessages (
            message_id                  INTEGER     PRIMARY KEY,
            peer_channel_id             INTEGER     NOT NULL,
            message_data                BLOB        NOT NULL,
            message_flags               INTEGER     NOT NULL,
            sequence                    INTEGER     NOT NULL,
            date_received               INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (peer_channel_id) REFERENCES ServerPeerChannels (peer_channel_id)
        )
    """)

    conn.execute("""
        CREATE TABLE ExternalPeerChannelMessages (
            message_id                  INTEGER     PRIMARY KEY,
            peer_channel_id             INTEGER     NOT NULL,
            message_data                BLOB        NOT NULL,
            message_flags               INTEGER     NOT NULL,
            sequence                    INTEGER     NOT NULL,
            date_received               INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (peer_channel_id) REFERENCES ExternalPeerChannels (peer_channel_id)
        )
    """)

def _introduce_tip_filter(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE ServerPushDataRegistrations (
            server_id                   INTEGER     NOT NULL,
            keyinstance_id              INTEGER     NOT NULL,
            script_type                 INTEGER     NOT NULL,
            pushdata_hash               BLOB        NOT NULL,
            pushdata_flags              INTEGER     NOT NULL,
            duration_seconds            INTEGER     NOT NULL,
            date_registered             INTEGER     DEFAULT NULL,
            date_created                INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (server_id) REFERENCES Servers (server_id),
            FOREIGN KEY (keyinstance_id) REFERENCES KeyInstances (keyinstance_id)
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ServerPushDataRegistrations_unique
            ON ServerPushDataRegistrations(server_id, pushdata_hash)
    """)

    # TODO(sqlite) The `block_hash` column was `BLOCK` as of 2022-12-07 where it should have been
    #     `BLOB`. This means that the affinity of the column would have been `NUMERIC`. As `BLOB`
    #     values do not get converted, not even with strict typing, this should not present a
    #     problem if we turn on strict typing. However if we do plan on turning on features like
    #     that, this sort of problem indicates we should check column types and correct them.
    conn.execute("""
        CREATE TABLE ServerPushDataMatches (
            server_id                   INTEGER     NOT NULL,
            pushdata_hash               BLOB        NOT NULL,
            transaction_hash            BLOB        NOT NULL,
            transaction_index           INTEGER     NOT NULL,
            block_hash                  BLOB        NULL,
            match_flags                 INTEGER     NOT NULL,
            date_created                INTEGER     NOT NULL,
            FOREIGN KEY (server_id) REFERENCES Servers (server_id)
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ServerPushDataMatches_unique
            ON ServerPushDataMatches(pushdata_hash, transaction_hash, transaction_index)
    """)

def _introduce_contacts(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE Contacts (
        contact_id                              INTEGER     PRIMARY KEY,
        contact_name                            TEXT        NOT NULL,
        direct_declared_name                    TEXT        DEFAULT NULL,
        local_peer_channel_id                   INTEGER     DEFAULT NULL,
        remote_peer_channel_url                 TEXT        DEFAULT NULL,
        remote_peer_channel_token               TEXT        DEFAULT NULL,
        direct_identity_key_bytes               BLOB        DEFAULT NULL,
        date_updated                            INTEGER     NOT NULL,
        FOREIGN KEY (local_peer_channel_id)     REFERENCES ServerPeerChannels (peer_channel_id)
    )""")
    conn.execute("CREATE UNIQUE INDEX idx_contacts ON Contacts (direct_identity_key_bytes) "
        "WHERE direct_identity_key_bytes IS NOT NULL")

def _introduce_backups(conn: sqlite3.Connection) -> None:
    # We do not pre-populate anything. It is up to the user to set up the process which should
    # do an initial snapshot and continual deltas.
    conn.execute("""CREATE TABLE BackupOutgoing (
        local_sequence                          INTEGER     PRIMARY KEY,
        local_flags                             INTEGER     NOT NULL,
        message_data                            BLOB        NOT NULL,
        date_created                            INTEGER     NOT NULL
    )""")

def _introduce_bitcache(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE BitcacheTransactions (
        account_id                              INTEGER     NOT NULL,
        tx_hash                                 BLOB        NOT NULL,
        flags                                   INTEGER     NOT NULL,
        channel_sequence                        INTEGER     NOT NULL,
        date_created                            INTEGER     NOT NULL,
        PRIMARY KEY (account_id, tx_hash),
        FOREIGN KEY (account_id)                REFERENCES Accounts (account_id),
        FOREIGN KEY (tx_hash)                   REFERENCES Transactions (tx_hash)
    )""")

def _migrate_payment_requests(conn: sqlite3.Connection) -> None:
    """
    Originally payment requests were for legacy payments to an address. Now we use them to
    represent a general expected incoming payment. This means they now cover:

    - An expected legacy payment.
    - An expected DPP invoice payment.
    - A local payment that will be satisfied through manual transaction import.

    As part of this migration we drop the old script hash oriented support.
    """
    # We add three more columns to `PaymentRequests`, `script_type` and `pushdata_hash` and
    # `server_id`. The first two are static values that relate to the copied text that is given out
    # by the wallet owner and we can map them to their primary usage tip filtering registrations.
    # The `server_id` is only applicable for new invoices using the direct payment protocol and
    # represents the dpp proxy server that was used.
    conn.execute("""
        CREATE TABLE PaymentRequests2 (
            paymentrequest_id           INTEGER     PRIMARY KEY,
            state                       INTEGER     NOT NULL,
            description                 TEXT        NULL,
            date_expires                INTEGER     NULL,
            value                       INTEGER     NULL,
            server_id                   INTEGER     NULL,
            dpp_invoice_id              TEXT        NULL,
            dpp_ack_json           TEXT        NULL,
            merchant_reference          TEXT        NULL,
            encrypted_key_text          TEXT        NULL,
            date_updated                INTEGER     NOT NULL
        )
    """)

    masterkey_rows: list[MasterKeyRow_27] = [ MasterKeyRow_27(t[0], t[1], DerivationType(t[2]),
        t[3], MasterKeyFlag(t[4]), t[5], t[6]) for t in conn.execute("""
            SELECT masterkey_id, parent_masterkey_id, derivation_type, derivation_data, flags,
                date_created, date_updated
            FROM MasterKeys
            ORDER BY masterkey_id ASC
        """).fetchall() ]

    keystores_by_masterkey_id: dict[int, KeyStore] = {}
    for masterkey_row in masterkey_rows:
        derivation_data = cast(MasterKeyDataTypes_27, json.loads(masterkey_row[3]))
        parent_keystore: KeyStore|None = None
        if masterkey_row.parent_masterkey_id is not None:
            parent_keystore = keystores_by_masterkey_id[masterkey_row.parent_masterkey_id]
        keystores_by_masterkey_id[masterkey_row[0]] = instantiate_keystore(
            masterkey_row.derivation_type, derivation_data, parent_keystore, masterkey_row)

    paymentrequest_keyinstance_rows: list[tuple[KeyInstanceRow_27, int, ScriptType, int, int, int]]\
        = [ (KeyInstanceRow_27(t[0], t[1], t[2], DerivationType(t[3]), t[4], t[5],
        KeyInstanceFlag_27(t[6]), t[7]), t[8], ScriptType(t[9]), t[10], t[11], t[12])
        for t in conn.execute("""
            SELECT KI.keyinstance_id, KI.account_id, KI.masterkey_id, KI.derivation_type,
                KI.derivation_data, KI.derivation_data2, KI.flags, KI.description,
                PR.paymentrequest_id, A.default_script_type, PR.value, PR.date_created,
                PR.date_updated
            FROM PaymentRequests PR
            INNER JOIN KeyInstances KI ON KI.keyinstance_id=PR.keyinstance_id
            INNER JOIN Accounts A ON A.account_id=KI.account_id
        """).fetchall() ]

    logger.debug("Copying the original PaymentRequests table contents to updated table")
    paymentrequest_output_rows: list[tuple[int, int, int, int, bytes, bytes, int, int, int]] \
        = []
    for keyinstance_row, paymentrequest_id, script_type, request_value, date_created, date_updated \
            in paymentrequest_keyinstance_rows:
        assert keyinstance_row.derivation_data2 is not None
        if keyinstance_row.masterkey_id is not None:
            keystore = keystores_by_masterkey_id[keyinstance_row.masterkey_id]
            pushdata_hash = get_pushdata_hash_for_keystore_key_data(keystore, keyinstance_row,
                script_type)
            if keystore.type() == KeystoreType.MULTISIG:
                assert script_type in MULTI_SIGNER_SCRIPT_TYPES
                assert keyinstance_row.derivation_type == DerivationType.BIP32_SUBPATH
                assert keyinstance_row.derivation_data2 is not None
                derivation_path = unpack_derivation_path(keyinstance_row.derivation_data2)

                ms_keystore = cast(Multisig_KeyStore, keystore)
                child_ms_keystores = ms_keystore.get_cosigner_keystores()
                public_keys = [ singlesig_keystore.derive_pubkey(derivation_path)
                    for singlesig_keystore in child_ms_keystores ]
                threshold = ms_keystore.m
            elif keyinstance_row.derivation_type == DerivationType.BIP32_SUBPATH:
                assert keyinstance_row.derivation_data2 is not None
                derivation_path = unpack_derivation_path(keyinstance_row.derivation_data2)
                xpub_keystore = cast(Xpub, keystore)
                public_keys = [ xpub_keystore.derive_pubkey(derivation_path) ]
                threshold = 1
            else:
                raise NotImplementedError(f"Unexpected deterministic key type {keyinstance_row}")
            script_bytes = get_output_script_template_for_public_keys(script_type,
                public_keys, threshold).to_script_bytes()
        elif keyinstance_row.derivation_type in ADDRESS_DERIVATION_TYPES:
            # We use the script type inferred by the address type instead of the account script
            # type as it is the one known to be used at the time.
            script_type, pushdata_hash = get_pushdata_hash_for_derivation(
                keyinstance_row.derivation_type, keyinstance_row.derivation_data2)
            if script_type == ScriptType.P2PKH:
                script_template = P2PKH_Address(keyinstance_row.derivation_data2, Net.COIN)
                script_bytes = script_template.to_script_bytes()
            elif script_type == ScriptType.MULTISIG_P2SH:
                script_template = P2SH_Address(keyinstance_row.derivation_data2, Net.COIN)
                script_bytes = script_template.to_script_bytes()
            else:
                raise NotImplementedError(f"Unexpected script type {script_type}")
        elif keyinstance_row.derivation_type == DerivationType.PRIVATE_KEY:
            public_key = PublicKey.from_bytes(keyinstance_row.derivation_data2)
            pushdata_hash = get_pushdata_hash_for_public_keys(script_type, [ public_key ])
            if script_type == ScriptType.P2PKH:
                script_bytes = public_key.to_address(network=Net.COIN).to_script_bytes()
            elif script_type == ScriptType.P2PK:
                script_bytes = P2PK_Output(public_key, Net.COIN).to_script_bytes()
            else:
                raise NotImplementedError("Unable to generate migration output script for "
                    f"script type {script_type}")
        else:
            raise NotImplementedError(f"Unexpected key type {keyinstance_row}")

        # - Expiration dates went from a relative number of seconds from `date_created` to the
        #   absolute expiry date.
        # - `keyinstance_id`, `script_type`, `pushdata_hash` went to the `PaymentRequestOutputs`
        #   table.
        conn.execute("""
            INSERT INTO PaymentRequests2 (paymentrequest_id, state, description, date_expires,
                value, server_id, dpp_invoice_id, dpp_ack_json, merchant_reference,
                encrypted_key_text, date_updated)
            SELECT PR.paymentrequest_id, PR.state, PR.description,
                CASE WHEN PR.expiration IS NULL THEN NULL ELSE PR.date_created + PR.expiration END,
                PR.value, NULL, NULL, NULL, NULL, NULL, PR.date_updated
            FROM PaymentRequests AS PR
            WHERE paymentrequest_id=?
        """, (paymentrequest_id,))
        paymentrequest_output_rows.append((paymentrequest_id, 0, 0, script_type, script_bytes,
            pushdata_hash, request_value, keyinstance_row.keyinstance_id,
            date_updated))

    conn.execute("DROP TABLE PaymentRequests")
    conn.execute("ALTER TABLE PaymentRequests2 RENAME TO PaymentRequests")

    # `output_value` can be NULL but only for blank payment requests that are monitored
    # (`PaymentFlag.MONITORED`).
    conn.execute("""
        CREATE TABLE PaymentRequestOutputs (
            paymentrequest_id           INTEGER     NOT NULL,
            transaction_index           INTEGER     NOT NULL,
            output_index                INTEGER     NOT NULL,
            output_script_type          INTEGER     NOT NULL,
            output_script               BLOB        NOT NULL,
            pushdata_hash               BLOB        NOT NULL,
            output_value                INTEGER     NULL,
            keyinstance_id              INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            PRIMARY KEY (paymentrequest_id, transaction_index, output_index),
            FOREIGN KEY (keyinstance_id)        REFERENCES KeyInstances (keyinstance_id),
            FOREIGN KEY (paymentrequest_id)     REFERENCES PaymentRequests (paymentrequest_id)
        )
    """)

    conn.executemany("INSERT INTO PaymentRequestOutputs (paymentrequest_id, transaction_index, "
        "output_index, output_script_type, output_script, pushdata_hash, output_value, "
        "keyinstance_id, date_updated) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        paymentrequest_output_rows)

    # Not the greatest idea, goodbye legacy script hash matching!
    conn.execute("DROP TABLE KeyInstanceScripts")

def _introduce_payments(conn: sqlite3.Connection) -> None:
    """
    A payment is an abstract concept and may be satisfied by more than one transaction.

    Migration agenda:
    1. Map all the existing transactions to Payments. Multi-transaction payment requests should
       map to a single Payment.
    2. Map all payment requests to a Payment.
    """

    pr_txhashes_read_rows = cast(list[tuple[int, bytes]], conn.execute("""
        SELECT DISTINCT PR.paymentrequest_id, TXO.tx_hash
        FROM PaymentRequests PR
        INNER JOIN PaymentRequestOutputs PRO ON PR.paymentrequest_id=PRO.paymentrequest_id
        LEFT JOIN TransactionOutputs TXO ON PRO.keyinstance_id=TXO.keyinstance_id
    """))
    transaction_hashes_by_paymentrequest_id: dict[int, list[bytes]] = {}
    date_created_by_paymentrequest_id: dict[int, int] = {}
    paymentrequest_id_by_transaction_hash: dict[bytes, int] = {}
    for request_id, tx_hash in pr_txhashes_read_rows:
        date_created_by_paymentrequest_id[request_id] = timestamp_from_id(request_id)
        if request_id not in transaction_hashes_by_paymentrequest_id:
            transaction_hashes_by_paymentrequest_id[request_id] = []
        # We will also get the payment requests with no transactions (represented by an empty list).
        if tx_hash is not None:
            transaction_hashes_by_paymentrequest_id[request_id].append(tx_hash)
            paymentrequest_id_by_transaction_hash[tx_hash] = request_id

    payment_id_by_paymentrequest_id: dict[int, int] = {}
    payment_rows: list[tuple[int, int]] = []
    tx_payment_rows: list[tuple[int, bytes]] = []
    for t in conn.execute("SELECT tx_hash, date_created FROM Transactions WHERE flags&?1=0",
            (TxFlag.REMOVED,)):
        tx_hash = cast(bytes, t[0])
        tx_date_created = cast(int, t[1])
        paymentrequest_id = paymentrequest_id_by_transaction_hash.get(tx_hash)
        if paymentrequest_id is None:
            new_payment_id = database_id_from_timestamp(tx_date_created)
            payment_rows.append((new_payment_id, tx_date_created))
            # Re: 1. Map all the existing transactions to Payments.
            # .. Here we add unique Payments for each standalone transaction.
            tx_payment_rows.append((new_payment_id, tx_hash))
            continue

        # Re: 2. Map all payment requests to a Payment.
        # .. Here we add common Payments for all payment requests linked to transactions.
        existing_payment_id = payment_id_by_paymentrequest_id.get(paymentrequest_id)
        if existing_payment_id is None:
            pr_date_created = date_created_by_paymentrequest_id[paymentrequest_id]
            existing_payment_id = database_id_from_timestamp(pr_date_created)
            payment_rows.append((existing_payment_id, pr_date_created))
            payment_id_by_paymentrequest_id[paymentrequest_id] = existing_payment_id

        # Re: 1. Map all the existing transactions to Payments.
        # .. Here we add common Payments for each payment request-related transaction.
        tx_payment_rows.append((existing_payment_id, tx_hash))

    # Re: 2. Map all payment requests to a Payment.
    # .. Here we add unique Payments for all payment requests that have no transactions.
    for paymentrequest_id, transaction_hashes in transaction_hashes_by_paymentrequest_id.items():
        if transaction_hashes:
            continue
        assert paymentrequest_id not in payment_id_by_paymentrequest_id
        pr_date_created = date_created_by_paymentrequest_id[paymentrequest_id]
        new_payment_id = database_id_from_timestamp(pr_date_created)
        payment_rows.append((new_payment_id, pr_date_created))
        payment_id_by_paymentrequest_id[paymentrequest_id] = new_payment_id

    conn.execute("""CREATE TABLE Payments (
        payment_id                              INTEGER     PRIMARY KEY,
        contact_id                              INTEGER     DEFAULT NULL,
        flags                                   INTEGER     NOT NULL DEFAULT 0,
        description                             TEXT        DEFAULT NULL,

        date_updated                            INTEGER     NOT NULL,
        FOREIGN KEY (contact_id)                REFERENCES Contacts (contact_id)
    )""")
    conn.executemany("INSERT INTO Payments (payment_id, date_updated) VALUES (?1, ?2)",
        payment_rows)

    conn.execute("ALTER TABLE Transactions ADD COLUMN payment_id INTEGER DEFAULT NULL")
    conn.executemany("UPDATE Transactions SET payment_id=?1 WHERE tx_hash=?2", tx_payment_rows)

    logger.debug("Updated %d transactions for %d created payments", len(tx_payment_rows),
        len(payment_rows))

    # Has to allow NULLs due to column creation and existing rows chicken and egg problem.
    conn.execute("ALTER TABLE PaymentRequests ADD COLUMN payment_id INTEGER DEFAULT NULL "
        "REFERENCES Payments (payment_id)")
    pr_payment_rows = list(payment_id_by_paymentrequest_id.items())
    conn.executemany("UPDATE PaymentRequests SET payment_id=?2 WHERE paymentrequest_id=?1",
        pr_payment_rows)

    # Migrate `AccountTransactions` -> `AccountPayments`. `AccountTransactions.flags` was not
    # used. `AccountTransactions.description` over grouped payment transactions not really used.
    conn.execute("""CREATE TABLE AccountPayments (
        account_id                              INTEGER     NOT NULL,
        payment_id                              INTEGER     NOT NULL,
        flags                                   INTEGER     NOT NULL DEFAULT 0,

        delta_value                             INTEGER     NOT NULL DEFAULT 0,
        tx_signed_count                         INTEGER     NOT NULL DEFAULT 0,
        tx_dispatched_count                     INTEGER     NOT NULL DEFAULT 0,
        tx_received_count                       INTEGER     NOT NULL DEFAULT 0,
        tx_cleared_count                        INTEGER     NOT NULL DEFAULT 0,
        tx_settled_count                        INTEGER     NOT NULL DEFAULT 0,
        tx_count                                INTEGER     NOT NULL DEFAULT 0,
        tx_min_height                           INTEGER     NOT NULL DEFAULT 0,
        tx_max_height                           INTEGER     NOT NULL DEFAULT 0,

        date_created                            INTEGER     NOT NULL,
        date_updated                            INTEGER     NOT NULL,
        FOREIGN KEY (account_id)                REFERENCES Accounts (account_id),
        FOREIGN KEY (payment_id)                REFERENCES Payments (payment_id)
    )""")
    conn.execute("CREATE UNIQUE INDEX idx_accpay ON AccountPayments (account_id, payment_id)")
    account_transaction_rows = cast(list[tuple[int, bytes, str|None, int, int]],
        conn.execute("SELECT account_id, tx_hash, description, date_created, "
            "date_updated FROM AccountTransactions"))
    account_payments_by_key: dict[tuple[int, int], tuple[int, int, int, int, int]] = {}
    payment_id_by_tx_hash: dict[bytes, int] = { t[1]: t[0] for t in tx_payment_rows }
    description_by_payment_id: dict[int, str] = {}
    for account_transaction_row in account_transaction_rows:
        payment_id = payment_id_by_tx_hash[account_transaction_row[1]]
        account_payment_key = account_transaction_row[0], payment_id
        if account_payment_key in account_payments_by_key:
            continue
        account_payment_row = (account_transaction_row[0], payment_id, 0,
            account_transaction_row[3], account_transaction_row[4])
        account_payments_by_key[account_payment_key] = account_payment_row
        if account_transaction_row[2]:
            if payment_id in description_by_payment_id:
                description_by_payment_id[payment_id] += "; "+ account_transaction_row[2]
            else:
                description_by_payment_id[payment_id] = account_transaction_row[2]

    account_payment_insert_rows = list(account_payments_by_key.values())
    conn.executemany("INSERT INTO AccountPayments (account_id, payment_id, flags, "
        "date_created, date_updated) VALUES (?1, ?2, ?3, ?4, ?5)", account_payment_insert_rows)

    # NOTE(rt12) Initially the plan was to have per-account descriptions for payments but it just
    #     complicates the UI too much, so for now we force shared payment descriptions.
    payment_update_rows = list(description_by_payment_id.items())
    conn.executemany("UPDATE Payments SET description=?2 WHERE payment_id=?1", payment_update_rows)

    conn.execute("""
    CREATE TABLE Invoices2 (
        invoice_id                  INTEGER PRIMARY KEY,
        payment_id                  INTEGER NOT NULL,
        payment_uri                 TEXT NOT NULL,
        description                 TEXT NULL,
        invoice_flags               INTEGER NOT NULL,
        value                       INTEGER NOT NULL,
        invoice_data                BLOB NOT NULL,
        date_expires                INTEGER DEFAULT NULL,
        date_created                INTEGER NOT NULL,
        date_updated                INTEGER NOT NULL,
        FOREIGN KEY (payment_id)    REFERENCES Payments (payment_id)
    )
    """)

    class OldInvoiceRow(NamedTuple):
        invoice_id:     int
        account_id:     int
        tx_hash:        bytes|None
        payment_uri:    str
        description:    str|None
        invoice_flags:  int
        value:          int
        invoice_data:   bytes
        date_expires:   int|None
        date_created:   int
        date_updated:   int

    class NewInvoiceRow(NamedTuple):
        invoice_id:     int
        payment_id:     int
        payment_uri:    str
        description:    str|None
        invoice_flags:  int
        value:          int
        invoice_data:   bytes
        date_expires:   int|None
        date_created:   int
        date_updated:   int

    payment_rows = []
    invoice_rows: list[NewInvoiceRow] = []
    old_invoice_rows = [ OldInvoiceRow(*row) for row in \
        conn.execute("SELECT invoice_id, account_id, tx_hash, payment_uri, description, " \
            "invoice_flags, value, invoice_data, date_expires, date_created, date_updated " \
            "FROM Invoices") ]
    for it_old in old_invoice_rows:
        if tx_hash not in payment_id_by_tx_hash:
            # Make a payment with no transactions (so old invoices that never got paid but were
            # never deleted appear in the list of payments).
            payment_id = database_id_from_timestamp(it_old.date_created)
            payment_rows.append((payment_id, it_old.date_created))
        else:
            payment_id = payment_id_by_tx_hash[tx_hash]
        invoice_rows.append(NewInvoiceRow(it_old.invoice_id, payment_id, it_old.payment_uri,
            it_old.description, it_old.invoice_flags, it_old.value, it_old.invoice_data,
            it_old.date_expires, it_old.date_created, it_old.date_updated))

    conn.executemany("INSERT INTO Payments (payment_id,date_updated) VALUES (?1,?2)", payment_rows)
    conn.executemany("INSERT INTO Invoices2 (invoice_id, payment_id, payment_uri, description, "
        "invoice_flags, value, invoice_data, date_expires, date_created, date_updated) VALUES "
        "(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)", invoice_rows)

    conn.execute("DROP TABLE Invoices")
    conn.execute("ALTER TABLE Invoices2 RENAME TO Invoices")

    # The views for balance calculation (may still be revisited!).
    conn.execute("DROP VIEW TransactionValues")
    conn.execute("DROP VIEW TransactionSpentValues")
    conn.execute("DROP VIEW TransactionReceivedValues")

    conn.execute("""
        CREATE VIEW TransactionReceivedValues (account_id, tx_hash, keyinstance_id, value)
        AS
            SELECT AP.account_id, T.tx_hash, TXO.keyinstance_id, TXO.value
            FROM AccountPayments AP
            INNER JOIN Transactions T ON T.payment_id=AP.payment_id
            INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=T.tx_hash
            INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id
            WHERE TXO.keyinstance_id IS NOT NULL AND KI.account_id=AP.account_id
    """)

    conn.execute("""
        CREATE VIEW TransactionSpentValues (account_id, tx_hash, keyinstance_id, value) AS
            SELECT AP.account_id, T.tx_hash, TXO.keyinstance_id, TXO.value
            FROM AccountPayments AP
            INNER JOIN Transactions T ON T.payment_id=AP.payment_id
            INNER JOIN TransactionInputs TI ON TI.tx_hash=T.tx_hash
            INNER JOIN TransactionOutputs TXO ON TXO.tx_hash=TI.spent_tx_hash
                AND TXO.txo_index=TI.spent_txo_index
            INNER JOIN KeyInstances KI ON KI.keyinstance_id=TXO.keyinstance_id
            WHERE TXO.keyinstance_id IS NOT NULL AND KI.account_id=AP.account_id
    """)

    conn.execute("""
        CREATE VIEW TransactionValues (account_id, tx_hash, keyinstance_id, value) AS
            SELECT account_id, tx_hash, keyinstance_id, value FROM TransactionReceivedValues
            UNION ALL
            SELECT account_id, tx_hash, keyinstance_id, -value FROM TransactionSpentValues
    """)

    conn.execute("DROP TABLE AccountTransactions")


def _migrate_merkle_proofs(conn: sqlite3.Connection) -> None:
    # We are going to try and convert the ElectrumX proofs to TSC proofs.
    def unpack_proof(raw: bytes) -> tuple[int, list[bytes]]:
        io = BytesIO(raw)
        pack_version = bitcoinx.read_varint(io.read)
        if pack_version != 1:
            return -1, []
        position = bitcoinx.read_varint(io.read)
        branch_count = bitcoinx.read_varint(io.read)
        merkle_branch = [ bitcoinx.read_varbytes(io.read) for i in range(branch_count) ]
        return position, merkle_branch

    def merkle_root_hash_from_proof(hash: bytes, branch: list[bytes], index:int) -> bytes|None:
        '''From ElectrumX.'''
        for elt in branch:
            if index & 1:
                hash = double_sha256(elt + hash)
            else:
                hash = double_sha256(hash + elt)
            index >>= 1
        if index:
            return None
        return hash

    assert app_state.headers is not None
    longest_chain = cast(Chain, app_state.headers.longest_chain())
    cursor = conn.execute("SELECT tx_hash, block_height, proof_data FROM Transactions "
        "WHERE proof_data IS NOT NULL")
    updated_tx_rows: list[tuple[bytes, int, bytes]] = []
    new_proof_rows: list[tuple[bytes, bytes, bytes, int, int]] = []
    for tx_hash, block_height, proof_data in \
            cast(list[tuple[bytes, int, bytes]], cursor.fetchall()):
        proof_index, merkle_branch = unpack_proof(proof_data)
        if proof_index == -1 or block_height < 1:
            logger.error("Invalid ElectrumX packed proof for transaction %s",
                bitcoinx.hash_to_hex_str(tx_hash))
            continue

        # There is no guarantee we have this header. The user may have deleted the headers or
        # have an older application version they used to a height longer than the headers this
        # application version has.
        try:
            header = app_state.header_at_height(longest_chain, block_height)
        except MissingHeader:
            logger.warning("Missing ElectrumX proof header for transaction %s",
                bitcoinx.hash_to_hex_str(tx_hash))
            continue

        # It is possible that the proof is for an old longest chain and is incorrect.
        merkle_root_bytes = cast(bytes, header.merkle_root)
        proof_merkle_root_bytes = merkle_root_hash_from_proof(tx_hash, merkle_branch, proof_index)
        if merkle_root_bytes == proof_merkle_root_bytes:
            tsc_proof_nodes: list[TSCMerkleNode] = []
            for branch_hash in merkle_branch:
                tsc_proof_nodes.append(TSCMerkleNode(TSCMerkleNodeKind.HASH, branch_hash))

            # Needs transaction hash by default.
            # Needs block hash by default.
            tsc_proof = TSCMerkleProof(ProofTargetFlag.BLOCK_HASH, proof_index,
                transaction_hash=tx_hash, block_hash=header.hash, nodes=tsc_proof_nodes)
            if verify_proof(tsc_proof, merkle_root_bytes):
                new_proof_rows.append((header.hash, tx_hash, tsc_proof.to_bytes(), proof_index,
                    block_height))
                updated_tx_rows.append((header.hash, proof_index, tx_hash))
            else:
                logger.error("Invalid proof for transaction %s", bitcoinx.hash_to_hex_str(tx_hash))
        else:
            logger.error("Invalid proof merkle root for transaction %s",
                bitcoinx.hash_to_hex_str(tx_hash))

    # Transfer all merkle proof data from the Transactions table to a new proofs table.
    # The pathways for insertion to this table are as follows:
    #  1) Wallet._obtain_merkle_proofs_worker_async -> Wallet.import_transaction_async
    #  2) Wallet._obtain_transactions_worker_async -> Wallet.import_transaction_async
    #  3) wait_for_merkle_proofs_and_double_spends (not yet in use) - mAPI callbacks
    # All proofs from all chains should be inserted here (i.e. including orphaned proofs). They
    # can be pruned when the proof on the main server chain is buried by sufficient proof of work .
    conn.execute("""CREATE TABLE IF NOT EXISTS TransactionProofs (
        block_hash                      BLOB        NOT NULL,
        tx_hash                         BLOB        NOT NULL,
        proof_data                      BLOB        NOT NULL,
        block_position                  INTEGER     NOT NULL,
        block_height                    INTEGER     NOT NULL,
        FOREIGN KEY (tx_hash) REFERENCES Transactions (tx_hash)
    )""")
    conn.execute("CREATE UNIQUE INDEX idx_tx_proofs ON TransactionProofs (tx_hash, block_hash)")

    if len(new_proof_rows) > 0:
        logger.debug("Converted and inserted %d transaction proofs", len(new_proof_rows))
        conn.executemany("UPDATE Transactions SET block_hash=?, block_position=? WHERE tx_hash=?",
            updated_tx_rows)
        conn.executemany("INSERT INTO TransactionProofs (block_hash, tx_hash, proof_data, "
            "block_position, block_height) VALUES (?,?,?,?,?)", new_proof_rows)

    # We cannot guarantee that SETTLED transactions now have a TSC proof.
    # - Older wallets never kept the proof data.
    # - Some of our transactions are missing their proof data!
    # - The convertion process may have failed.
    # The reason we do not clear the SETTLED flag for transactions that do not have one of these
    # proofs is that this would be a bad user experience and they would see all their transactions
    # strangely revert back to CLEARED and they may not be re-verified until they jump through
    # server hoops.
    conn.execute("ALTER TABLE Transactions DROP COLUMN proof_data")

    # Add the NOT NULL constraint to block_height column. SQLite doesn't allow ADD CONSTRAINT
    # see: https://www.sqlite.org/omitted.html, so it has to be done this way as a workaround.
    conn.execute("ALTER TABLE Transactions ADD COLUMN block_height2 INTEGER NOT NULL DEFAULT 0")
    conn.execute("UPDATE Transactions SET block_height2=block_height WHERE tx_hash=tx_hash")
    conn.execute("ALTER TABLE Transactions DROP COLUMN block_height")
    conn.execute("ALTER TABLE Transactions RENAME COLUMN block_height2 TO block_height")

    # Remove vestigial traces of `HasProofData` transaction flag (we cleared others in migration
    # 22).
    clear_bits_args = (~TxFlags_22.HasProofData, TxFlags_22.HasProofData)
    cursor = conn.execute("UPDATE Transactions SET flags=(flags&?) WHERE flags&?", clear_bits_args)
    logger.debug("cleared HasProofData flag from %d transactions", cursor.rowcount)

def _introduce_mapi_broadcasts(conn: sqlite3.Connection) -> None:
    # NOTE(AustEcon) - Track tx_hashes for which we are awaiting a merkle proof callback from mAPI.
    # This is to safeguard against a missed notification from mAPI as well as to drive the lifetime
    # management of a given channel.
    #
    # There should be waiting time threshold at which we give up and request the merkle
    # proof directly from an indexer if it still has not arrived e.g. 24 hours since broadcast_date.
    conn.execute("""
        CREATE TABLE MAPIBroadcasts (
            broadcast_id                INTEGER       PRIMARY KEY,
            tx_hash                     BLOB          NOT NULL,
            broadcast_server_id         INTEGER       NOT NULL,
            mapi_broadcast_flags        INTEGER       NOT NULL,
            peer_channel_id             INTEGER       DEFAULT NULL,
            response_data               BLOB          DEFAULT NULL,
            date_updated                INTEGER       NOT NULL,
            FOREIGN KEY (tx_hash)               REFERENCES Transactions (tx_hash),
            FOREIGN KEY (broadcast_server_id)   REFERENCES Servers (server_id),
            FOREIGN KEY (peer_channel_id)       REFERENCES ServerPeerChannels (peer_channel_id)
        )
    """)

def _migrate_server_tables(conn: sqlite3.Connection) -> None:
    # Using a composite key to refer to servers and different tables is awkward, especially
    # as we add dependent tables on servers. For this reason both the base server table and
    # server account table are now merged and there is a primary key `server_id` column.
    # TODO(1.4.0) Tip filters, issue#904. `tip_filter_peer_channel_id` may be unnecessary.
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
            tip_filter_peer_channel_id  INTEGER     DEFAULT NULL,
            date_last_connected         INTEGER     DEFAULT 0,
            date_last_tried             INTEGER     DEFAULT 0,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (account_id) REFERENCES Accounts (account_id),
            FOREIGN KEY (tip_filter_peer_channel_id) REFERENCES ServerPeerChannels (peer_channel_id)
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

def _create_new_views(conn: sqlite3.Connection) -> None:
    conn.execute(f"""
    CREATE VIEW AccountPaymentCachableMetadata (payment_id, account_id, tx_count, tx_coinbase,
        tx_min_height, tx_max_height, tx_signed_count, tx_dispatched_count, tx_received_count,
        tx_settled_count, tx_cleared_count, delta_value)
    AS
        SELECT P.payment_id, TV.account_id, COUNT(T.tx_hash),
            MAX(CASE WHEN T.block_position=0 THEN 1 ELSE 0 END),
            MIN(T.block_height), MAX(T.block_height),
            SUM(CASE WHEN T.flags&{TxFlag.STATE_SIGNED} THEN 1 ELSE 0 END),
            SUM(CASE WHEN T.flags&{TxFlag.STATE_DISPATCHED} THEN 1 ELSE 0 END),
            SUM(CASE WHEN T.flags&{TxFlag.STATE_RECEIVED} THEN 1 ELSE 0 END),
            SUM(CASE WHEN T.flags&{TxFlag.STATE_SETTLED} THEN 1 ELSE 0 END),
            SUM(CASE WHEN T.flags&{TxFlag.STATE_CLEARED} THEN 1 ELSE 0 END),
            SUM(TV.value)
        FROM Payments P
        LEFT JOIN Transactions T ON T.payment_id=P.payment_id
        INNER JOIN TransactionValues TV ON TV.tx_hash=T.tx_hash
        WHERE T.flags IS NULL OR T.flags&{TxFlag.REMOVED}=0
        GROUP BY P.payment_id, TV.account_id
    """)
