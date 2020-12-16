GAP_LIMIT_RECEIVING = 20
GAP_LIMIT_CHANGE = 20


class WalletEventNames:
    # (tx_hash, height, conf, timestamp)
    VERIFIED = "verified"
    # (account_id, tx_hash, existing_flags, updated_flags)
    TRANSACTION_STATE_CHANGE = "transaction_state_change"
    # (tx_hash, tx, involved_account_ids, external)
    TRANSACTION_ADDED = "transaction_added"
