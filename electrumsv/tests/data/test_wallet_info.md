## Regtest Test Wallets
This document is to give some context around the built-in regtest wallets we use for testing,
how they were created, what they are used for and which association header files belong to 
which wallet database files.

### 26_regtest_standard_mining_with_mature_and_immature_coins.sqlite
Purpose: To provide test data for testing the `read_history_for_outputs` function.
Namely to test the ordering of locally signed, unconfirmed and confirmed transaction
outputs as well as coinbase handling.

This wallet is the result of submitting the blocks in `blockchain_115_3677f4` to the node.
The regtest mining account (full of coinbases) has the seed phrase:
`entire coral usage young front fury okay fade hen process follow light`

And two spending transactions:
- `88c92bb09626c7d505ed861ae8fa7e7aaab5b816fc517eac7a8a6c7f28b1b210`
- `d53a9ebfac748561132e49254c42dbe518080c2a5956822d5d3914d47324e842`

The associated `bitcoinx.Headers` file is found at 
`tests/headers/headers3_blockchain_115_3677f4` (i.e. the first 115 blocks of 
our main, precompiled regtest blockchain)

NOTE: This wallet should ideally not be modified or have any new blocks
mined for it because it would result in the unconfirmed transaction being
included into a block and the associated test function(s) would need to be
updated.

### 29_regtest_spending_wallet_paytomany.sqlite
Purpose: To provide test data for testing the `read_history_for_outputs` function.
Namely to test that there are indeed multiple rows returned for a single transaction
and that the details are correct.

This wallet is the result of generating 112 random regtest blocks
and using the node's mining account to create three funding txs
with the `sendtoaddress` RPC command. The resulting utxos are 
1.0,2.0 & 3.0 BSV respectively. A block is subsequently mined to
confirm the utxos.

These three coins are then used to create a single transaction 
(`e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063`) that pays
to three external outputs (belonging to the next described wallet)

One more block is generated to include this transaction in a block (height 114)

The results of `read_history_for_outputs` is:

    tx_hash: e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063, value: -50000000
    tx_hash: e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063, value: -200000000
    tx_hash: e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063, value: -300000000
    tx_hash: d248199cad3bde644abaedd31844a07aa843d5ef777936fda80351a2b1eee80d, value: 300000000
    tx_hash: cfbbf6d67eb286a12068b395d5a894c148e4f184ceb41d51b971ae5b8c432729, value: 200000000
    tx_hash: 7b422f2719248686cb905456b00afa92b571023fe49d724d485aabbf2e0d542a, value: 100000000

The associated `bitcoinx.Headers` file is found at 
- `tests/headers/headers3_paytomany`

### 29_regtest_receiving_wallet_paytomany.sqlite
Purpose: To provide test data for testing the `read_history_for_outputs` function.
Namely to test that there are indeed multiple rows returned for a single transaction
and that the details are correct.

This wallet is the result of generating 111 random regtest blocks 
(the same blocks as for the previously described wallet).

The funding transaction: `e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063`
pays to receive addresses owned by this wallet.

The results of `read_history_for_outputs` is:

    tx_hash: e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063, value: 50000000
    tx_hash: e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063, value: 200000000
    tx_hash: e0e1e9abbf418f1b1dfc68b65221df411abfbcca2f95b281a911a2aff8a74063, value: 300000000

The associated `bitcoinx.Headers` file is found at
- `tests/headers/headers3_paytomany`

