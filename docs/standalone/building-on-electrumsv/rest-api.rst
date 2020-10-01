The REST API
===================

Technically, the restapi is an example 'dapp' (daemon application). But is nevertheless
provided in a format that aims to eventually cover the majority of basic use cases.

This RESTAPI may be subject to slight changes but the example dapp source code is there for users to modify
to suit your own specific needs.

Endpoints
##########

get_all_wallets
**********************
Get a list of all available wallets

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets``

get_parent_wallet
**********************
Get a high-level information about the parent wallet and accounts (within the parent wallet).

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite``

load_wallet
**********************
Load the wallet on the daemon (i.e. subscribe to ElectrumX for active keys)
and initiate synchronization. Returns a high-level information about the
parent wallet and accounts.

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite``

get_account
**********************
Get high-level information about a given account

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1``

get_coin_state
**********************
Get the count of cleared, settled and matured coins.

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/utxos/coin_state``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/utxos/coin_state``

get_utxos
**********************
Get a list of all utxos.

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/utxos``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/utxos``

get_balance
**********************
Get account balance (confirmed, unconfirmed, unmatured) in satoshis.

:Method: GET
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/balance``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/utxos/balance``

remove
**********************
Removes transactions in the 'Signed' state.

Deleting transactions in the
'Dispatched', 'Cleared', 'Settled' states could cause issues and so is
not supported at this time (a DisabledFeatureError will be returned). If you
require this feature, please make contact via the Atlantis Slack or the
MetanetICU slack.

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/remove``

**Request Body Payload**

.. code-block::

    {
        "txids": [<txid1>, <txid2>, ...]    (optional field)
    }


:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/remove``

**Sample Body Payload**

.. code-block::

    {
        "txids": ["d45145f0c2ff87f6cfe5524d46d5ba14932363e927bd5a4af899a9b8fc0ab76f"]
    }

**Sample Response**

.. code-block::

    {
        "value": {
            "message": "All StateSigned transactions in set: ['299405452db66866b9fed2ebe83bee5d41c4a29a0d88e2f8590f1ced7f5531b1'] deleted fromTxCache, TxInputs and TxOutputs cache and SqliteDatabase."
        }
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
        "value": [
{
    "value": [
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
        "value": {
            "tx_hex": "0200000001adc7943687d0f89c1e20bb1c196e16cd5f08449e5aa7e744c83cc5f67ffe1e6d000000006a47304402204a23d0a3b4f3806c741966748ab0433409e9a75eeb8203d9ddb5a4209b224a0c022034b4e134aabf77f54a37175f4e391f9ab2c08540d7dfef2cb7189e0526fb6235412102f1120ab677437a561b9c2c05584d974aedf01d6038c3edfe3a3af9742113a91cfeffffff0200f90295000000001976a914b3de43912c075239c5bba3e1061baa021d238e4d88ac1ef80295000000001976a91444afd14a53a354048320c19ccfb1833263b3bd0188acc8000000"
        }
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
This example is of a single "OP_FALSE OP_RETURN" output with "Hello" encoded in Hex ("48656c6c6f") the preceeding
0x05 byte represents a pushdata op code to push the next 5 bytes onto the stack (in this case "48656c6c6f").

Additional outputs for leftover change will be created automatically.

.. code-block::

    {
        "outputs": [
            {"script_pubkey":"006a0548656c6c6f", "value": 0}
        ],
        "password": "test"
    }

**Sample Response**

.. code-block::

    {
        "value": {
            "tx_hex": "0200000001adc7943687d0f89c1e20bb1c196e16cd5f08449e5aa7e744c83cc5f67ffe1e6d000000006a47304402204a23d0a3b4f3806c741966748ab0433409e9a75eeb8203d9ddb5a4209b224a0c022034b4e134aabf77f54a37175f4e391f9ab2c08540d7dfef2cb7189e0526fb6235412102f1120ab677437a561b9c2c05584d974aedf01d6038c3edfe3a3af9742113a91cfeffffff0200f90295000000001976a914b3de43912c075239c5bba3e1061baa021d238e4d88ac1ef80295000000001976a91444afd14a53a354048320c19ccfb1833263b3bd0188acc8000000"
        }
    }


broadcast
***************************
Broadcast a rawtx (created with the previous endpoint).

:Method: POST
:Content-Type: application/json
:Endpoint: ``http://127.0.0.1:9999/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/broadcast``
:Regtest example: ``http://127.0.0.1:9999/v1/regtest/dapp/wallets/worker1.sqlite/1/txs/broadcast``

**Sample Request Payload**
This example is of a single "OP_FALSE OP_RETURN" output with "Hello" encoded in Hex ("48656c6c6f") the preceeding
0x05 byte represents a pushdata op code to push the next 5 bytes onto the stack (in this case "48656c6c6f").

Additional outputs for leftover change will be created automatically.

.. code-block::

    {
        "rawtx": "0100000001b131557fed1c0f59f8e2880d9aa2c4415dee3be8ebd2feb96668b62d45059429010000006b48304502210087d8ef3f390e563499598501759695a519a5b405f36704f8c9506089b1d5de32022072477b3f96d1df1e4b32519f5606415928d67786b0193a87d372fb9bcf5ddc04412103e9ca43c3b2e885c8a420d5784bc3bbf26c0c3def9751a8fe7b4a4a9918c22d10ffffffff02000000000000000008006a0548656c6c6f60f70295000000001976a914b3de43912c075239c5bba3e1061baa021d238e4d88acc9000000"
    }

**Sample Response**

.. code-block::

    {
        "value": {
            "txid": "53b1b2886f038183199f3dc6979c9c54934ebe74166e20addb0f318165d1b7ce"
        }
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
This example is of a single "OP_FALSE OP_RETURN" output with "Hello" encoded in Hex ("48656c6c6f") the preceeding
0x05 byte represents a pushdata op code to push the next 5 bytes onto the stack (in this case "48656c6c6f").

Additional outputs for leftover change will be created automatically.

.. code-block::

    {
        "outputs": [
            {"script_pubkey":"006a0548656c6c6f", "value": 0}
        ],
        "password": "test"
    }

**Sample Response**

.. code-block::

    {
        "value": {
            "txid": "7a77e888bb9a60f277cf3ae570c1fb61f99c13c9335170895efa07c6a923c91c"
        }
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
        "value": {
            "txid": "7a77e888bb9a60f277cf3ae570c1fb61f99c13c9335170895efa07c6a923c91c"
        }
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
        "value": {
            "txid": "cea035abf5b8c6814db2b3ab4240a7c8f65ea08d8b3a32a0bdb1d6c0605bb7e0"
        }
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
        "value": {
            "txid": [
                "410a6fd9024613d8e98953706b31f13ed875a7dfd9f2cee39b33ed2de0a15c92",
                "262b113c711eb11e8a44b58aea8be36ba788b599a2089b425d0eb7f94d7d3913",
                "12a972760942e24b53d74c18608a16aeef6df3d193a80e5f503d1457b1fb815a"
            ]
        }
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
        "value": {
            "new_wallet": "G:\\electrumsv_official\\electrumsv1\\regtest\\wallets\\worker1.sqlite"
        }
    }
