BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS "MasterKeys" (
    "masterkey_id" INTEGER,
    "parent_masterkey_id" INTEGER DEFAULT NULL,
    "derivation_type" INTEGER NOT NULL,
    "derivation_data" BLOB NOT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    "flags" INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY("parent_masterkey_id") REFERENCES "MasterKeys"("masterkey_id"),
    PRIMARY KEY("masterkey_id")
);

CREATE TABLE IF NOT EXISTS "Accounts" (
    "account_id" INTEGER,
    "default_masterkey_id" INTEGER DEFAULT NULL,
    "default_script_type" INTEGER NOT NULL,
    "account_name" TEXT NOT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    "flags" INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY("default_masterkey_id") REFERENCES "MasterKeys"("masterkey_id"),
    PRIMARY KEY("account_id")
);

CREATE TABLE IF NOT EXISTS "Transactions" (
    "tx_hash" BLOB,
    "tx_data" BLOB DEFAULT NULL,
    "proof_data" BLOB DEFAULT NULL,
    "block_height" INTEGER DEFAULT NULL,
    "block_position" INTEGER DEFAULT NULL,
    "fee_value" INTEGER DEFAULT NULL,
    "flags" INTEGER NOT NULL DEFAULT 0,
    "description" TEXT DEFAULT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    "locktime" INTEGER DEFAULT NULL,
    "version" INTEGER DEFAULT NULL,
    "block_hash" BLOB DEFAULT NULL,
    PRIMARY KEY("tx_hash")
);

CREATE TABLE IF NOT EXISTS "WalletData" (
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS "WalletEvents" (
    "event_id" INTEGER,
    "event_type" INTEGER NOT NULL,
    "event_flags" INTEGER NOT NULL,
    "account_id" INTEGER,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("account_id") REFERENCES "Accounts"("account_id"),
    PRIMARY KEY("event_id")
);

CREATE TABLE IF NOT EXISTS "Invoices" (
    "invoice_id" INTEGER,
    "account_id" INTEGER NOT NULL,
    "tx_hash" BLOB DEFAULT NULL,
    "payment_uri" TEXT NOT NULL,
    "description" TEXT,
    "invoice_flags" INTEGER NOT NULL,
    "value" INTEGER NOT NULL,
    "invoice_data" BLOB NOT NULL,
    "date_expires" INTEGER DEFAULT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("tx_hash") REFERENCES "Transactions"("tx_hash"),
    FOREIGN KEY("account_id") REFERENCES "Accounts"("account_id"),
    PRIMARY KEY("invoice_id")
);

CREATE TABLE IF NOT EXISTS "AccountTransactions" (
    "tx_hash" BLOB NOT NULL,
    "account_id" INTEGER NOT NULL,
    "flags" INTEGER NOT NULL DEFAULT 0,
    "description" TEXT DEFAULT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("account_id") REFERENCES "Accounts"("account_id"),
    FOREIGN KEY("tx_hash") REFERENCES "Transactions"("tx_hash")
);

CREATE TABLE IF NOT EXISTS "TransactionOutputs" (
    "tx_hash" BLOB NOT NULL,
    "txo_index" INTEGER NOT NULL,
    "value" INTEGER NOT NULL,
    "keyinstance_id" INTEGER DEFAULT NULL,
    "flags" INTEGER NOT NULL,
    "script_type" INTEGER DEFAULT 0,
    "script_hash" BLOB NOT NULL DEFAULT x '',
    "script_offset" INTEGER DEFAULT 0,
    "script_length" INTEGER DEFAULT 0,
    "spending_tx_hash" BLOB,
    "spending_txi_index" INTEGER,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("keyinstance_id") REFERENCES "KeyInstances"("keyinstance_id"),
    FOREIGN KEY("tx_hash") REFERENCES "Transactions"("tx_hash")
);

CREATE TABLE IF NOT EXISTS "TransactionInputs" (
    "tx_hash" BLOB NOT NULL,
    "txi_index" INTEGER NOT NULL,
    "spent_tx_hash" BLOB NOT NULL,
    "spent_txo_index" INTEGER NOT NULL,
    "sequence" INTEGER NOT NULL,
    "flags" INTEGER NOT NULL,
    "script_offset" INTEGER,
    "script_length" INTEGER,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("tx_hash") REFERENCES "Transactions"("tx_hash")
);

CREATE TABLE IF NOT EXISTS "KeyInstances" (
    "keyinstance_id" INTEGER,
    "account_id" INTEGER NOT NULL,
    "masterkey_id" INTEGER DEFAULT NULL,
    "derivation_type" INTEGER NOT NULL,
    "derivation_data" BLOB NOT NULL,
    "derivation_data2" BLOB DEFAULT NULL,
    "flags" INTEGER NOT NULL,
    "description" TEXT DEFAULT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("masterkey_id") REFERENCES "MasterKeys"("masterkey_id"),
    FOREIGN KEY("account_id") REFERENCES "Accounts"("account_id"),
    PRIMARY KEY("keyinstance_id")
);

CREATE TABLE IF NOT EXISTS "KeyInstanceScripts" (
    "keyinstance_id" INTEGER NOT NULL,
    "script_type" INTEGER NOT NULL,
    "script_hash" BLOB NOT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("keyinstance_id") REFERENCES "KeyInstances"("keyinstance_id")
);

CREATE TABLE IF NOT EXISTS "MAPIBroadcastCallbacks" (
    "tx_hash" BLOB,
    "peer_channel_id" VARCHAR(1024) NOT NULL,
    "broadcast_date" INTEGER NOT NULL,
    "encrypted_private_key" BLOB NOT NULL,
    "server_id" INTEGER NOT NULL,
    "status_flags" INTEGER NOT NULL,
    PRIMARY KEY("tx_hash")
);

CREATE TABLE IF NOT EXISTS "Servers" (
    "server_id" INTEGER,
    "server_type" INTEGER NOT NULL,
    "url" TEXT NOT NULL,
    "account_id" INTEGER DEFAULT NULL,
    "server_flags" INTEGER NOT NULL DEFAULT 0,
    "api_key_template" TEXT DEFAULT NULL,
    "encrypted_api_key" TEXT DEFAULT NULL,
    "fee_quote_json" TEXT DEFAULT NULL,
    "date_last_connected" INTEGER DEFAULT 0,
    "date_last_tried" INTEGER DEFAULT 0,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("account_id") REFERENCES "Accounts"("account_id"),
    PRIMARY KEY("server_id")
);

CREATE TABLE IF NOT EXISTS "PaymentRequests" (
    "paymentrequest_id" INTEGER,
    "keyinstance_id" INTEGER NOT NULL,
    "state" INTEGER NOT NULL,
    "description" TEXT,
    "expiration" INTEGER,
    "value" INTEGER,
    "script_type" INTEGER NOT NULL,
    "pushdata_hash" BLOB NOT NULL,
    "date_created" INTEGER NOT NULL,
    "date_updated" INTEGER NOT NULL,
    FOREIGN KEY("keyinstance_id") REFERENCES "KeyInstances"("keyinstance_id"),
    PRIMARY KEY("paymentrequest_id")
);

CREATE UNIQUE INDEX IF NOT EXISTS "idx_WalletData_unique" ON "WalletData" ("key");

CREATE UNIQUE INDEX IF NOT EXISTS "idx_Invoices_unique" ON "Invoices" ("payment_uri");

CREATE UNIQUE INDEX IF NOT EXISTS "idx_AccountTransactions_unique" ON "AccountTransactions" ("tx_hash", "account_id");

CREATE UNIQUE INDEX IF NOT EXISTS "idx_TransactionOutputs_unique" ON "TransactionOutputs" ("tx_hash", "txo_index");

CREATE UNIQUE INDEX IF NOT EXISTS "idx_TransactionInputs_unique" ON "TransactionInputs" ("tx_hash", "txi_index");

CREATE UNIQUE INDEX IF NOT EXISTS "idx_KeyInstanceScripts_unique" ON "KeyInstanceScripts" ("keyinstance_id", "script_type");

CREATE UNIQUE INDEX IF NOT EXISTS "idx_Servers_unique" ON "Servers" ("server_type", "url", "account_id");

CREATE VIEW TransactionReceivedValues (account_id, tx_hash, keyinstance_id, value) AS
SELECT
    ATX.account_id,
    ATX.tx_hash,
    TXO.keyinstance_id,
    TXO.value
FROM
    AccountTransactions ATX
    INNER JOIN TransactionOutputs TXO ON TXO.tx_hash = ATX.tx_hash
    INNER JOIN KeyInstances KI ON KI.keyinstance_id = TXO.keyinstance_id
WHERE
    TXO.keyinstance_id IS NOT NULL
    AND KI.account_id = ATX.account_id;

CREATE VIEW TransactionSpentValues (account_id, tx_hash, keyinstance_id, value) AS
SELECT
    ATX.account_id,
    ATX.tx_hash,
    PTXO.keyinstance_id,
    PTXO.value
FROM
    AccountTransactions ATX
    INNER JOIN TransactionInputs TXI ON TXI.tx_hash = ATX.tx_hash
    INNER JOIN TransactionOutputs PTXO ON PTXO.tx_hash = TXI.spent_tx_hash
    AND PTXO.txo_index = TXI.spent_txo_index
    INNER JOIN KeyInstances KI ON KI.keyinstance_id = PTXO.keyinstance_id
WHERE
    PTXO.keyinstance_id IS NOT NULL
    AND KI.account_id = ATX.account_id;

CREATE VIEW TransactionValues (account_id, tx_hash, keyinstance_id, value) AS
SELECT
    account_id,
    tx_hash,
    keyinstance_id,
    value
FROM
    TransactionReceivedValues
UNION
ALL
SELECT
    account_id,
    tx_hash,
    keyinstance_id,
    - value
FROM
    TransactionSpentValues;

COMMIT;
