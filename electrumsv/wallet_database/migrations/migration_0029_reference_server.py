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
from io import BytesIO
import json
from typing import Any, cast, List, Optional, Tuple

import bitcoinx
from bitcoinx import Chain, double_sha256, ElectrumMnemonic, MissingHeader, P2PK_Output, \
    P2PKH_Address, P2SH_Address, PublicKey, Wordlists
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3  # type: ignore[no-redef]

from ...app_state import app_state
from ...constants import AccountFlags, ADDRESS_DERIVATION_TYPES, DerivationType, KeystoreType, \
    MasterKeyFlags, MULTI_SIGNER_SCRIPT_TYPES, ScriptType, unpack_derivation_path, \
    WALLET_ACCOUNT_PATH_TEXT
from ...credentials import PasswordTokenProtocol
from ...i18n import _
from ...logs import logs
from ...keystore import bip32_master_key_data_from_seed, instantiate_keystore, KeyStore, \
    Multisig_KeyStore, Xpub
from ...networks import Net
from ...standards.tsc_merkle_proof import ProofTargetFlags, TSCMerkleNode, TSCMerkleNodeKind, \
    TSCMerkleProof, verify_proof
from ...util import get_posix_timestamp
from ...util.misc import ProgressCallbacks
from ...wallet_support.keys import get_output_script_template_for_public_keys, \
    get_pushdata_hash_for_derivation, get_pushdata_hash_for_keystore_key_data, \
    get_pushdata_hash_for_public_keys

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
    conn.execute("ALTER TABLE Accounts ADD COLUMN blockchain_server_id INTEGER DEFAULT NULL")
    conn.execute("ALTER TABLE Accounts ADD COLUMN peer_channel_server_id INTEGER DEFAULT NULL")
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
        CREATE TABLE MAPIBroadcasts (
            broadcast_id                INTEGER       PRIMARY KEY,
            tx_hash                     BLOB          NOT NULL,
            broadcast_server_id         INTEGER       NOT NULL,
            mapi_broadcast_flags        INTEGER       NOT NULL,
            peer_channel_id             INTEGER       DEFAULT NULL,
            response_data               BLOB          DEFAULT NULL,
            date_created                INTEGER       NOT NULL,
            date_updated                INTEGER       NOT NULL,
            FOREIGN KEY (tx_hash)               REFERENCES Transactions (tx_hash),
            FOREIGN KEY (broadcast_server_id)   REFERENCES Servers (server_id),
            FOREIGN KEY (peer_channel_id)       REFERENCES ServerPeerChannels (peer_channel_id)
        )
    """)

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
            payment_key_bytes           BLOB        DEFAULT NULL,
            fee_quote_json              TEXT        DEFAULT NULL,
            tip_filter_peer_channel_id  INTEGER     DEFAULT NULL,
            date_last_connected         INTEGER     DEFAULT 0,
            date_last_tried             INTEGER     DEFAULT 0,
            date_created                INTEGER     NOT NULL,
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
            merchant_reference          TEXT        NULL,
            encrypted_key_text          TEXT        NULL,
            date_created                INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL
        )
    """)

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
    paymentrequest_output_rows: list[tuple[int, int, int, int, bytes, bytes, int, int, int, int]] \
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
                value, server_id, dpp_invoice_id, merchant_reference, encrypted_key_text,
                date_created, date_updated)
            SELECT PR.paymentrequest_id, PR.state, PR.description,
                CASE WHEN PR.expiration IS NULL THEN NULL ELSE PR.date_created + PR.expiration END,
                PR.value, NULL, NULL, NULL, NULL, PR.date_created,
                PR.date_updated
            FROM PaymentRequests AS PR
            WHERE paymentrequest_id=?
        """, (paymentrequest_id,))
        paymentrequest_output_rows.append((paymentrequest_id, 0, 0, script_type, script_bytes,
            pushdata_hash, request_value, keyinstance_row.keyinstance_id, date_created,
            date_updated))

    conn.execute("DROP TABLE PaymentRequests")
    conn.execute("ALTER TABLE PaymentRequests2 RENAME TO PaymentRequests")

    conn.execute("""
        CREATE TABLE PaymentRequestOutputs (
            paymentrequest_id           INTEGER     NOT NULL,
            transaction_index           INTEGER     NOT NULL,
            output_index                INTEGER     NOT NULL,
            output_script_type          INTEGER     NOT NULL,
            output_script               BLOB        NOT NULL,
            pushdata_hash               BLOB        NOT NULL,
            output_value                INTEGER     NOT NULL,
            keyinstance_id              INTEGER     NOT NULL,
            date_created                INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            PRIMARY KEY (paymentrequest_id, transaction_index, output_index),
            FOREIGN KEY (keyinstance_id) REFERENCES KeyInstances (keyinstance_id),
            FOREIGN KEY (paymentrequest_id) REFERENCES PaymentRequests (paymentrequest_id)
        )
    """)

    conn.executemany("INSERT INTO PaymentRequestOutputs (paymentrequest_id, transaction_index, "
        "output_index, output_script_type, output_script, pushdata_hash, output_value, "
        "keyinstance_id, date_created, date_updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, "
        "?10)", paymentrequest_output_rows)

    # Not the greatest idea, goodbye legacy script hash matching!
    conn.execute("DROP TABLE KeyInstanceScripts")

    conn.execute("""
        CREATE TABLE ServerPeerChannels (
            peer_channel_id             INTEGER     PRIMARY KEY,
            server_id                   INTEGER     NOT NULL,
            remote_channel_id           TEXT        DEFAULT NULL,
            remote_url                  TEXT        DEFAULT NULL,
            peer_channel_flags          INTEGER     NOT NULL,
            date_created                INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (server_id) REFERENCES Servers (server_id)
        )
    """)

    conn.execute("""
        CREATE TABLE ExternalPeerChannels (
            peer_channel_id             INTEGER     PRIMARY KEY,
            invoice_id                  INTEGER     NOT NULL,
            remote_channel_id           TEXT        DEFAULT NULL,
            remote_url                  TEXT        DEFAULT NULL,
            peer_channel_flags          INTEGER     NOT NULL,
            date_created                INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (invoice_id) REFERENCES Invoices (invoice_id)
        )
    """)

    conn.execute("""
        CREATE TABLE ServerPeerChannelAccessTokens (
            peer_channel_id             INTEGER     NOT NULL,
            token_flags                 INTEGER     NOT NULL,
            permission_flags            INTEGER     NOT NULL,
            access_token                TEXT        NOT NULL,
            FOREIGN KEY (peer_channel_id) REFERENCES ServerPeerChannels (peer_channel_id)
        )
    """)

    conn.execute("""
        CREATE TABLE ExternalPeerChannelAccessTokens (
            peer_channel_id             INTEGER     NOT NULL,
            token_flags                 INTEGER     NOT NULL,
            permission_flags            INTEGER     NOT NULL,
            access_token                TEXT        NOT NULL,
            FOREIGN KEY (peer_channel_id) REFERENCES ExternalPeerChannels (peer_channel_id)
        )
    """)

    conn.execute("""
        CREATE TABLE ServerPeerChannelMessages (
            message_id                  INTEGER     PRIMARY KEY,
            peer_channel_id             INTEGER     NOT NULL,
            message_data                BLOB        NOT NULL,
            message_flags               INTEGER     NOT NULL,
            sequence                    INTEGER     NOT NULL,
            date_received               INTEGER     NOT NULL,
            date_created                INTEGER     NOT NULL,
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
            date_created                INTEGER     NOT NULL,
            date_updated                INTEGER     NOT NULL,
            FOREIGN KEY (peer_channel_id) REFERENCES ExternalPeerChannels (peer_channel_id)
        )
    """)

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

    conn.execute("""
        CREATE TABLE ServerPushDataMatches (
            server_id                   INTEGER     NOT NULL,
            pushdata_hash               BLOB        NOT NULL,
            transaction_hash            BLOB        NOT NULL,
            transaction_index           INTEGER     NOT NULL,
            block_hash                  BLOCK       NULL,
            match_flags                 INTEGER     NOT NULL,
            date_created                INTEGER     NOT NULL,
            FOREIGN KEY (server_id) REFERENCES Servers (server_id)
        )
    """)
    conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_ServerPushDataMatches_unique
            ON ServerPushDataMatches(pushdata_hash, transaction_hash, transaction_index)
    """)

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

    # We need to persist the updated next primary key value for the `Accounts` table.
    # We need to persist the updated next identifier for the `Accounts` table.
    conn.executemany("UPDATE WalletData SET value=? WHERE key=?",
        [ (v, k) for (k, v) in wallet_data.items() ])

    ## Database cleanup.

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

    def merkle_root_hash_from_proof(hash: bytes, branch: list[bytes], index:int) -> Optional[bytes]:
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
    updated_tx_rows = list[tuple[bytes, int, bytes]]()
    new_proof_rows = list[tuple[bytes, bytes, bytes, int, int]]()
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
            tsc_proof_nodes = list[TSCMerkleNode]()
            for branch_hash in merkle_branch:
                tsc_proof_nodes.append(TSCMerkleNode(TSCMerkleNodeKind.HASH, branch_hash))

            # Needs transaction hash by default.
            # Needs block hash by default.
            tsc_proof = TSCMerkleProof(ProofTargetFlags.BLOCK_HASH, proof_index,
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

    # Remove vestigial traces of `HasProofData` transaction flag (we cleared others in migration
    # 22).
    clear_bits_args = (~TxFlags_22.HasProofData, TxFlags_22.HasProofData)
    cursor = conn.execute("UPDATE Transactions SET flags=(flags&?) WHERE flags&?", clear_bits_args)
    logger.debug("cleared HasProofData flag from %d transactions", cursor.rowcount)

    ## Migration finalisation.
    callbacks.progress(100, _("Update done"))
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [str(MIGRATION),date_updated,"migration"])
