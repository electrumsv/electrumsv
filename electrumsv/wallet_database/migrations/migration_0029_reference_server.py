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
from typing import cast, List, Tuple

from bitcoinx import ElectrumMnemonic, Wordlists
try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.10.0 builds and bundled version of 3.35.5.
    import sqlite3
else:
    sqlite3 = pysqlite3

from ...constants import AccountFlags, DerivationType, MasterKeyFlags, ScriptType, \
    WALLET_ACCOUNT_PATH_TEXT
from ...credentials import PasswordTokenProtocol
from ...i18n import _
from ...logs import logs
from ...keystore import bip32_master_key_data_from_seed
from ...util import get_posix_timestamp
from ...util.misc import ProgressCallbacks

from ..storage_migration import MasterKeyDataBIP32_29, TxFlags_22

MIGRATION = 29

logger = logs.get_logger(f"migration-{MIGRATION:04d}")


def execute(conn: sqlite3.Connection, password_token: PasswordTokenProtocol,
        callbacks: ProgressCallbacks) -> None:
    date_updated = get_posix_timestamp()
    callbacks.progress(0, _("Update started"))

    # We have persisted the next identifier for the `Accounts` table in the database.
    cursor = conn.execute("SELECT key, value FROM WalletData "
        "WHERE key='next_account_id' OR key='next_masterkey_id'")
    wallet_data = { k: int(v) for (k, v) in cast(List[Tuple[str, str]], cursor.fetchall()) }
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
    derivation_data1: MasterKeyDataBIP32_29 = {
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
    derivation_data2: MasterKeyDataBIP32_29 = {
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

    ## Migration finalisation.
    callbacks.progress(100, _("Update done"))
    conn.execute("UPDATE WalletData SET value=?, date_updated=? WHERE key=?",
        [str(MIGRATION),date_updated,"migration"])
