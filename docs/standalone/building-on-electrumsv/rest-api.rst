The REST API
===================

Technically, the restapi is an example 'dapp' (daemon application). But is nevertheless
provided in a format that aims to eventually cover the majority of basic use cases.

This RESTAPI may be subject to slight changes but the example dapp source code is there for users to modify
to suit your own specific needs. See ``examples/applications/README.rst`` for instructions.


Wallet Creation (without using the GUI)
#######################################
At this time, wallet creation via the REST API is only supported on the RegTest network.
To create a wallet and account programmatically, shutdown the ElectrumSV daemon and
run these commands on the command-line:

.. code-block::

    python3 electrum-sv create_wallet -w ~/.electrum-sv/wallets/mywallet.sqlite -wp test --no-password-check
    python3 electrum-sv create_account -w ~/.electrum-sv/wallets/mywallet.sqlite -wp test --no-password-check

This will create a wallet called ``mywallet.sqlite`` with a wallet password of ``test`` and will add a standard BIP32
account which uses P2PKH output scripts for receiving payments.

Endpoints
##########

get_all_wallets
**********************
Get a list of all available wallets

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets``

**Sample Response**

.. code-block::

    {
        "wallets": [
            "worker1.sqlite"
        ]
    }


get_parent_wallet
**********************
Get a high-level information about the parent wallet and accounts (within the parent wallet).

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite``

**Sample Response**

.. code-block::

    {
        "parent_wallet": "worker1.sqlite",
        "accounts": {
            "1": {
                "wallet_type": "Standard account",
                "default_script_type": "P2PKH",
                "is_wallet_ready": true
            }
        }
    }

load_wallet
**********************
Load the wallet on the daemon (i.e. subscribe to ElectrumX for active keys)
and initiate synchronization. Returns a high-level information about the
parent wallet and accounts.

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/load_wallet``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/load_wallet``

**Sample Response**

.. code-block::

    {
        "parent_wallet": "worker1.sqlite",
        "accounts": {
            "1": {
                "wallet_type": "Standard account",
                "default_script_type": "P2PKH",
                "is_wallet_ready": true
            }
        }
    }

get_account
**********************
Get high-level information about a given account

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1``

**Sample Response**

.. code-block::

    {
        "1": {
            "wallet_type": "Standard account",
            "default_script_type": "P2PKH",
            "is_wallet_ready": true
        }
    }

get_coin_state
**********************
Get the count of cleared, settled and matured coins.

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/utxos/coin_state``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/utxos/coin_state``

**Sample Response**

.. code-block::

    {
        "cleared_coins": 11,
        "settled_coins": 700,
        "unmatured_coins": 0
    }

get_utxos
**********************
Get a list of all utxos.

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/utxos``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/utxos``

**Sample Response**

.. code-block::

    {
        "utxos": [
            {
                "value": 20000,
                "script_pubkey": "76a91485324d225c81d414fe8a92bf101dba1a59211e8488ac",
                "script_type": 2,
                "tx_hash": "ce7c2fbc25d25d945b4ad539d2b41ead29e1b786a8aa42b2677af28da3f231a0",
                "out_index": 49,
                "keyinstance_id": 13,
                "address": "msfERZdhGaabQmeQ1ks8sHYdCDtxnTfL2z",
                "is_coinbase": false,
                "flags": 0
            },
            {
                "value": 20000,
                "script_pubkey": "76a91488471d45666dadece7f06aca22f1a1cf9a3a534988ac",
                "script_type": 2,
                "tx_hash": "ce7c2fbc25d25d945b4ad539d2b41ead29e1b786a8aa42b2677af28da3f231a0",
                "out_index": 50,
                "keyinstance_id": 12,
                "address": "mswXPFgWJbgvyxkWBFfYjbbaD1DZmFS3ig",
                "is_coinbase": false,
                "flags": 0
            },
        ]
    }


get_balance
**********************
Get account balance (confirmed, unconfirmed, unmatured) in satoshis.

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/balance``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/utxos/balance``

**Sample Response**

.. code-block::

    {
        "confirmed_balance": 14999694400,
        "unconfirmed_balance": 98000,
        "unmatured_balance": 0
    }

remove
**********
Removes transactions (currently restricted to 'StateSigned' transactions.)

Deleting transactions in the 'Dispatched', 'Cleared', 'Settled' states
could cause issues with the utxo set and so is not supported at this
time (a DisabledFeatureError will be returned). If you require this feature,
please make contact via the Atlantis Slack or the MetanetICU slack.

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs``

**Sample Body Payload**

.. code-block::

    {
        "txids": [
            "96eee07f8e2c96e33d457138496958d912042ff4ed7b3b9c74a2b810fa5c3750",
            "469ddc27b8ef3b386bf7451aebce64edfe22d836ad51076c7a82d78f8b4f4cf9",
            "e81472f9bbf2dc2c7dcc64c1f84b91b6214599d9c79e63be96dcda74dcb8103d"
        ]
    }

**Sample Response**

.. code-block::

    {
        "items": [
            {
                "id": "96eee07f8e2c96e33d457138496958d912042ff4ed7b3b9c74a2b810fa5c3750",
                "result": 200
            },
            {
                "id": "469ddc27b8ef3b386bf7451aebce64edfe22d836ad51076c7a82d78f8b4f4cf9",
                "result": 400,
                "description": "DisabledFeatureError: You used this endpoint in a way that is not supported for safety reasons. See documentation for details (https://electrumsv.readthedocs.io/ )"
            },
            {
                "id": "e81472f9bbf2dc2c7dcc64c1f84b91b6214599d9c79e63be96dcda74dcb8103d",
                "result": 400,
                "description": "Transaction not found"
            }
        ]
    }

get_transaction_history
*************************
Get transaction history. ``tx_flags`` can be specified in the request body. This is an enum representing
a bitmask for filtering transactions.

**The main `TxFlags` are:**

:StateCleared: 1 << 20  (received over p2p network and is unconfirmed and in the mempool)
:StateSettled: 1 << 21 (received over the p2p network and is confirmed in a block)
:StateReceived: 1 << 22 (received from another party and is unknown to the p2p network)
:StateSigned: 1 << 23 (not sent or given to anyone else, but are with-holding and consider the inputs it uses allocated)
:StateDispatched: 1 << 24 (a transaction you have given to someone else, and are considering the inputs it uses allocated)

However, there are other flags that can be set. See ``electrumsv/constants.py:TxFlags`` for details.

In the example below, (1 << 23 | 1 << 21) yields 9437184
(to filter for only StateSigned and StateCleared transactions)

An empty request body will return all transaction history for this account.
Pagination is not yet implemented.

**Request**

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/history``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/history``


**Sample Body Payload**

.. code-block::

    {
        "tx_flags": 9437184
    }

**Sample Response**

.. code-block::

    {
        "history": [
            {
                "txid": "64a9564588f9ebcce4ac52f4e0c8fe758b16dfd6fdb5bd8db5920da317aa15c8",
                "height": 0,
                "tx_flags": 1052720,
                "value": -10200
            },
            {
                "txid": "a6ec24243a79de1b51646d1a46ece854a8f682ff23b4d4afabaebc2bc10ef110",
                "height": 0,
                "tx_flags": 1052720,
                "value": -10200
            }
        ]
    }

fetch_transaction
***************************
Get the raw transaction for a given hex txid (as a hex string) - must be a transaction in the wallet's history.

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/fetch``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/fetch``

**Sample Request Payload**

.. code-block::

    {
        "txid": "d45145f0c2ff87f6cfe5524d46d5ba14932363e927bd5a4af899a9b8fc0ab76f"
    }

**Sample Response**

.. code-block::

    {
        "tx_hex": "0100000001e59dd2992ed46911bea87af1b4f7ab1edce8e038520f142d2aa219492664d993160000006b483045022100ec97e4887b5dd9bb3c1e0ebd0d5b2b3520aeda4d957de4bf0e06a920c7dd3fe802200be4c58192a7c67930518bf29b30ab49883fcc342ca4ee5815288c6f17d7b486412103ab06ed1f70de1524e34a4e36575993a70ff2c8800958045137d0cc2caf67ec91ffffffff0248260000000000001976a9143ef1b7677ea1ed53400da9719380b4d0373a1b5f88ac10270000000000001976a91403d0de941da4f897a7cd3828b4905fa64190a72f88acce000000"
    }

create_tx
***************************
Create a locally signed transaction ready for broadcast. A side effect of this is that the utxos associated with the
transaction are allocated for use and so cannot be used in any other transaction.

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/create``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/create``

**Sample Request Payload**
This example is of a single "OP_FALSE OP_RETURN" output with "Hello World" encoded in Hex.
The preceeding 0x0b byte represents a pushdata op code to push the next 11 bytes
onto the stack ("68656c6c6f20776f726c64").

Additional outputs for leftover change will be created automatically.

.. code-block::

    {
        "utxos": [
            {
                "value": 100,
                "script_pubkey": "76a914884f1ca934bc8cca71aff46d04755422198376da88ac",
                "script_type": 2,
                "tx_hash": "098fab209ec4a31aa69a4e486fb9660d2aeba708bef0385c24ff9e4c8b19bd82",
                "out_index": 0,
                "keyinstance_id": 5,
                "address": "1DRjftGzwgNQpujPAjX3LUcqDbgGbmDSw2",
                "is_coinbase": false,
                "flags": 0
            }
        ],
        "outputs": [
            {"script_pubkey":"006a0b68656c6c6f20776f726c64", "value": 0}
        ],
        "password": "test"
    }

**Sample Response**

.. code-block::

    {
        "txid": "96eee07f8e2c96e33d457138496958d912042ff4ed7b3b9c74a2b810fa5c3750",
        "rawtx": "0100000001cfdec4ce0f10c4148b44163bf6205f53e5ab31f04a57fcaaeb33ef6487e08511000000006b483045022100873bb0dabc0b053be5602ebd1bb1ce143999221317eda8835fdf96a3197b168e022037ac7ad4c5f27beee3805e581b483b418a5298a3c467872d548accdc056321cb412103bf03fd106e69b55fc2041cc862a2c1932367899de4a734ef37b8a8f056792869ffffffff0200000000000000000e006a0b68656c6c6f20776f726c64dd250000000000001976a914c6d2e09ff211db5671ea1a9a08df13703b5a06f988acd5000000"
    }


broadcast
***************************
Broadcast a rawtx (created with the previous endpoint).

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/broadcast``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/broadcast``

**Sample Request Payload**
This example is of a single "OP_FALSE OP_RETURN" output with "Hello World" encoded in Hex.
The preceeding 0x0b byte represents a pushdata op code to push the next 11 bytes
onto the stack ("68656c6c6f20776f726c64").

Additional outputs for leftover change will be created automatically.

.. code-block::

    {
        "rawtx": "0100000001ab9aff89a92c011b5436a0c02eb53cf6328286e5cf5767f309cde5414f657661000000006a473044022050750ec47afa183d3c99e22bc4324c3af83115fb409f966e345f72e0bcfa780302201e5d5920e0164c26f2fee2a71b079a4c4918ec9b269df624f3fb2fd483d6dedc4121038cac099086f38c1298d745f3b67e14bc4ab29a21fab5514111c65e196d430b29ffffffff0200000000000000000e006a0b68656c6c6f20776f726c64dd250000000000001976a914ee8f1e9312200924a406e4c39a2d0685df60924988acce000000"
    }

**Sample Response**

.. code-block::

    {
        "txid": "7ff0fcf6de91ffa71ef145e31d0bffe31467ecaa125a8db307cf9066fea55db5"
    }

create_and_broadcast
***************************
Atomically creates and broadcasts a transaction. If any errors occur, the intermediate step of creating a signed
transaction will be reversed (i.e. the transaction will be deleted and the utxos freed for use).

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/create_and_broadcast``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/create_and_broadcast``

**Sample Request Payload**
This example is of a single "OP_FALSE OP_RETURN" output with "Hello World" encoded in Hex.
The preceeding 0x0b byte represents a pushdata op code to push the next 11 bytes
onto the stack ("68656c6c6f20776f726c64").

Additional outputs for leftover change will be created automatically.

.. code-block::

    {
        "outputs": [
            {"script_pubkey":"006a0b68656c6c6f20776f726c64", "value": 0}
        ],
        "password": "test"
    }

**Sample Response**

.. code-block::

    {
        "txid": "469ddc27b8ef3b386bf7451aebce64edfe22d836ad51076c7a82d78f8b4f4cf9"
    }

split_utxos
***************************
Creates and broadcasts a coin-splitting transaction i.e. it breaks up existing utxos into a specified number of
new utxos with the desired "split_value" (satoshis). "split_count" represents the maximum number of splitting outputs
for the transaction. "desired_utxo_count" determines when the desired utxo count has been reached (i.e. if you have
200 utxos but "desired_utxo_count" is 220 then the next coin splitting transaction will create 20 more utxos.

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/split_utxos``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/split_utxos``

**Sample Request Payload**

.. code-block::

    {
        "split_value": 10000,
        "split_count": 100,
        "password": "test",
        "desired_utxo_count": 1000
    }

**Sample Response**

.. code-block::

    {
        "txid": "42329848db94cb16379b0c8898eb2b98542fb25d9257a47663c3fac7b0f49938"
    }

Regtest only endpoints
########################
If you try to access these endpoints when not in RegTest mode you will get back a 404 error because the endpoint will
not be available.

topup_account
***************************
Tops up the RegTest wallet from the RegTest node wallet (new blocks may be generated to facilitate this process).

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/topup_account``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/topup_account``

**Sample Request Payload**

.. code-block::

    {
        "amount": 10
    }

**Sample Response**

.. code-block::

    {
        "txid": "8f3dfe9b9e84c1d0b6d6ead8700be4114bb2d3ca1f97e1e84c64ea944415c723"
    }

generate_blocks
***************************
Tops up the RegTest wallet from the RegTest node wallet (new blocks may be generated to facilitate this process).

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/generate_blocks``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/generate_blocks``

**Sample Request Payload**

.. code-block::

    {
        "nblocks": 3
    }

**Sample Response**

.. code-block::

    {
        "txid": [
            "72d1270d0b3ad4c71d8257db8d6f880186108152534658ae6a127b616795530d"
        ]
    }


create_new_wallet
***************************
This will create a new wallet - in this example "worker1.sqlite". This example was produced via the electrumsv-sdk_ which
allows a convienient method for running a RegTest node, electrumX instance (pre-configured to connect) and an
ElectrumSV instance with data-dir=G:\\electrumsv_official\\electrumsv1.


.. _electrumsv-sdk: https://github.com/electrumsv/electrumsv-sdk

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/create_new_wallet``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/create_new_wallet``

**Sample Request Payload**

.. code-block::

    {
        "password": "test"
    }

**Sample Response**

.. code-block::

    {
        "new_wallet": "G:\\electrumsv_official\\electrumsv1\\regtest\\wallets\\worker1.sqlite"
    }
