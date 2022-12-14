The Node wallet API
===================

The Bitcoin SV node bitcoind has provided a JSON-RPC based wallet API. However running a node just
to operate a wallet is becoming prohibitive as blocks and the blockchain get larger and larger
on Bitcoin SV.

ElectrumSV aims to provide a replacement option to running the node. This is a special mode where
ElectrumSV is run as a wallet server without a GUI, that has to be explicitly activated with the
required command-line options. Where possible we aim to try and present the same API, errors and
experience that the node API does. This replacement option is the only JSON-RPC API that
ElectrumSV provides.

Command-line options
--------------------

Outside of ``--enable-node-wallet-api``, these command-line options are provided to match
those provided by `bitcoind`. They are not used for any other purpose outside of configuring
the node wallet API server.

``--enable-node-wallet-api``
############################

This command-line argument must be specified to direct ElectrumSV to run a server providing the
JSON-RPC wallet API.

In the following example, the operator provides this command-line argument and the
JSON-RPC wallet API can be seen to be available by the logged entry.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon --enable-node-wallet-api -rpcuser=bob -rpcpassword=weakpassword
    2022-11-07 12:28:54,983:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 12:28:54,983:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:8332

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon --enable-node-wallet-api -rpcuser=bob -rpcpassword=weakpassword
    2022-11-07 12:28:54,983:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 12:28:54,983:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:8332

In the following example, the operator does not provide this command-line argument and the
JSON-RPC wallet API can be seen as not available by the absence of the logged entry.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv
    2022-11-07 10:03:24,380:INFO:rest-server:REST API started on http://127.0.0.1:9999

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv
    2022-11-07 10:03:24,380:INFO:rest-server:REST API started on http://127.0.0.1:9999

``-rpcuser``
############

This is the basic authorization user name. It is required for the server to run, except when
credentials are disabled by an empty `rpcpassword` value.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon --enable-node-wallet-api -rpcuser=bob -rpcpassword=weakpassword
    2022-11-07 12:28:54,983:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 12:28:54,983:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:8332

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon --enable-node-wallet-api -rpcuser=bob -rpcpassword=weakpassword
    2022-11-07 12:28:54,983:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 12:28:54,983:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:8332

A value for this argument must be provided for the server to run, given that credentials have not
been disabled with a blank password. An error will be logged indicating why the server is not
running, if the operator does not provide this argument.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon --enable-node-wallet-api -rpcpassword=weakpassword
    2022-11-07 12:43:29,313:ERROR:daemon:JSON-RPC wallet API server not running: invalid user name or password
    2022-11-07 12:43:29,313:INFO:rest-server:REST API started on http://127.0.0.1:9999

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon --enable-node-wallet-api -rpcpassword=weakpassword
    2022-11-07 12:43:29,313:ERROR:daemon:JSON-RPC wallet API server not running: invalid user name or password
    2022-11-07 12:43:29,313:INFO:rest-server:REST API started on http://127.0.0.1:9999

``-rpcpassword``
################

This is the basic authorization password. Passing an empty password whether as `-rpcpassword=` or
`-rpcpassword ""` will disable authorization and allow anyone who can access the host it is
running on to freely make any API calls.

Providing a blank password disables credential checking and will log a warning.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon --enable-node-wallet-api -rpcpassword=
    2022-11-07 10:03:24,375:WARNING:daemon:No password set for JSON-RPC wallet API. No credentials required for access.
    2022-11-07 10:03:24,380:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 10:03:24,381:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:8332

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon  --enable-node-wallet-api -rpcpassword=
    2022-11-07 10:03:24,375:WARNING:daemon:No password set for JSON-RPC wallet API. No credentials required for access.
    2022-11-07 10:03:24,380:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 10:03:24,381:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:8332

A value for this argument must be provided for the server to run. An error will be logged indicating
why the server is not running, if the operator does not provide this argument.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon --enable-node-wallet-api -rpcuser=bob
    2022-11-07 12:43:29,313:ERROR:daemon:JSON-RPC wallet API server not running: invalid user name or password
    2022-11-07 12:43:29,313:INFO:rest-server:REST API started on http://127.0.0.1:9999

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon --enable-node-wallet-api -rpcuser=bob
    2022-11-07 12:43:29,313:ERROR:daemon:JSON-RPC wallet API server not running: invalid user name or password
    2022-11-07 12:43:29,313:INFO:rest-server:REST API started on http://127.0.0.1:9999

``-rpcport``
############

The server will default to using port `8332` to serve the API. Using this command-line argument
the operator can direct the JSON-RPC API to be served on a different port.

Specifying a custom port of `18332` will result in the server using that port instead.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon --enable-node-wallet-api -rpcpassword= -rpcport=18332
    2022-11-07 12:49:22,204:WARNING:daemon:No password set for JSON-RPC wallet API. No credentials required for access.
    2022-11-07 12:49:22,204:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 12:49:22,204:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:18332

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon --enable-node-wallet-api -rpcpassword= -rpcport=18332
    2022-11-07 12:49:22,204:WARNING:daemon:No password set for JSON-RPC wallet API. No credentials required for access.
    2022-11-07 12:49:22,204:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 12:49:22,204:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:18332

``-walletnotify``
#################

The way that external notifications are provided about changes in wallet state by `bitcoind` is
by providing a value to the `walletnotify` command-line argument. ElectrumSV also accepts this
command-line argument in order to aid in a clean switch. The provided value should be the full
command to execute and the `%s` placeholder will be replaced with the id of the transaction for
which there has been a state change.

Supported events:

* A transaction is added to the wallet.
* An external transaction is added to the wallet.
* The wallet broadcasts a transaction.
* The wallet is notified that a transaction has been broadcast.
* A transaction is associated with a block on the favoured tip (mined).
* A transaction is disassociated with a block on the favoured tip (reorged).

Here we specify the ``contrib/scripts/jsonrpc_wallet_event.py`` sample script provided with
ElectrumSV for debugging. It logs all events to a `tx.log` file in the same directory as the script
as a testing aid.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon --enable-node-wallet-api -rpcpassword= -walletnotify="python3 contrib/scripts/jsonrpc_wallet_event.py %s"
    2022-11-07 12:49:22,204:WARNING:daemon:No password set for JSON-RPC wallet API. No credentials required for access.
    2022-11-07 12:49:22,204:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 12:49:22,204:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:18332

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon --enable-node-wallet-api -rpcpassword= -walletnotify="py contrib\scripts\jsonrpc_wallet_event.py %s"
    2022-11-07 12:49:22,204:WARNING:daemon:No password set for JSON-RPC wallet API. No credentials required for access.
    2022-11-07 12:49:22,204:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 12:49:22,204:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:18332

Setup
-----

Once you are satisfied the ElectrumSV daemon is running correctly, there are several tasks that
need to be performed to get a working wallet and to be able to make use of the JSON-RPC API to
do things like solicit payments for it.

#. Create a compatible wallet.
#. Start the ElectrumSV daemon.
#. Load the wallet you created.
#. Link that wallet to a blockchain server.

Wallet creation
###############

In order to create a wallet that is compatible with the node wallet API, a special command
``create_jsonrpc_wallet`` has to be used. The file name to be used should be provided with the
``-w`` option and the wallet will be created in the "wallets" folder in the
:ref:`ElectrumSV data directory <data-directories>`.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv create_jsonrpc_wallet -w my_new_wallet
    Password:
    Confirm:
    Wallet saved in '/home/bob/.electrum-sv/wallets/my_new_wallet.sqlite'
    NOTE: This wallet is ready for use with the node wallet API.

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv create_jsonrpc_wallet -w my_new_wallet
    Password:
    Confirm:
    Wallet saved in 'C:\Users\bob\AppData\Roaming\ElectrumSV\regtest\wallets\my_new_wallet.sqlite'
    NOTE: This wallet is ready for use with the node wallet API.

.. warning::

    Wallets can only be used with the node wallet API if there is one and only one account in
    the wallet. Existing ElectrumSV wallets that have no accounts or more than one account will
    not be usable with the node wallet API.

Blockchain server access
########################

The advantage the wallet integrated into the Bitcoin node has is that it listens to and processes
all blocks, and knows what in them relates to the wallet. This is however why it is now problematic
to run, because the resource requirements to receive and process all those blocks is prohibitive.

In order to detect incoming payments the ElectrumSV JSON-RPC wallet needs to replace that
prohibitive block processing with something much much lighter weight. This is done by registering
the addresses those payments will come in on with a remote blockchain server. That blockchain
server also notifies us when transactions are broadcast and other events of interest that were
discerned directly from block data by the node wallet.

The wallet you created with the ``create_jsonrpc_wallet`` command needs to set up an account
on the blockchain server Bitcoin Association provides. This is what is described below.

The first step is to start the wallet server.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon --enable-node-wallet-api -rpcpassword=
    2022-11-07 10:03:24,375:WARNING:daemon:No password set for JSON-RPC wallet API. No credentials required for access.
    2022-11-07 10:03:24,380:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 10:03:24,381:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:8332

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon  --enable-node-wallet-api -rpcpassword=
    2022-11-07 10:03:24,375:WARNING:daemon:No password set for JSON-RPC wallet API. No credentials required for access.
    2022-11-07 10:03:24,380:INFO:rest-server:REST API started on http://127.0.0.1:9999
    2022-11-07 10:03:24,381:INFO:nodeapi-server:JSON-RPC wallet API started on http://127.0.0.1:8332

Next open another console/terminal and load your wallet with the daemon subcommand ``load_wallet``.
This asks the wallet server to load that wallet. If there is an error, it will display in
place of the ``true`` that is otherwise returned.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon load_wallet -w my_new_wallet
    Password:
    true

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon  load_wallet -w my_new_wallet
    Password:
    true

The final step is to setup the wallet's account with the blockchain server. This requires network
access by the wallet server and the ``service_signup`` daemon subcommand is used for this. You
need to specify the wallet you are signing up.

A successful signup will result in the following output:

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon service_signup -w my_new_wallet
    Password:
    Registering..
    For services:
        Blockchain.
        Message box.
    With server:
        http://127.0.0.1:47124/
    Done.

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon service_signup -w my_new_wallet
    Password:
    Registering..
    For services:
        Blockchain.
        Message box.
    With server:
        http://127.0.0.1:47124/
    Done.

If the wallet is already signed up for the services, the output will indicate this:

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon service_signup -w my_new_wallet
    Password:
    All services appear to be signed up for.

.. code-block:: doscon
    :caption: Windows

    electrumsv>py electrum-sv daemon service_signup -w my_new_wallet
    Password:
    All services appear to be signed up for.

It is also possible to use the ``status`` daemon subcommand to verify what servers you are connected
to and which services they are handling. This can be seen in the ``wallets`` section under the
``servers`` key:

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv daemon status
    {
        "blockchain_height": 116,
        "fee_per_kb": 500,
        "network": "online",
        "path": "/home/bob/.electrum-sv",
        "version": "1.4.0",
        "wallets": {
            "/home/bob/.electrum-sv/wallets/my_new_wallet.sqlite": {
                "servers": {
                    "http://127.0.0.1:47124/": [
                        "USE_BLOCKCHAIN",
                        "USE_MESSAGE_BOX"
                    ]
                }
            }
        }
    }

.. code-block:: doscon
    :caption: Windows

    electrumsv>py -3.10 electrum-sv daemon status
    {
        "blockchain_height": 116,
        "fee_per_kb": 500,
        "network": "online",
        "path": "c:\\Users\\bob\\AppData\\Roaming\\ElectrumSV",
        "version": "1.4.0",
        "wallets": {
            "c:\\Users\\bob\\AppData\\Roaming\\ElectrumSV\\wallets\\my_new_wallet.sqlite": {
                "servers": {
                    "http://127.0.0.1:47124/": [
                        "USE_BLOCKCHAIN",
                        "USE_MESSAGE_BOX"
                    ]
                }
            }
        }
    }

API usage
---------

Authorization
#############

Requests made on the JSON-RPC API are required to provide basic authorization credentials.

- If `rpcuser` is provided and `rpcpassword` is not, the server will not run.
- If `rpcpassword` is provided with an empty value, the server will run and will not check
  credentials.
- If both `rpcuser` and `rpcpassword` are provided, the server will run and expect those values
  to authorize access.

Curl can be used to make manual or scripted API calls, and will take care of encoding the
basic authorization user name and password for the request.

In the following example the arguments were ``-rpcuser bob`` and ``-rpcpassword weakpassword``.
This enforced basic authorization credential checking for that user name and password combination.

.. code-block:: console

    curl --user bob:weakpassword --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnewaddress", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/

In the following example the arguments were just ``-rpcpassword ""``. This disabled the checking of
credentials for API access.

.. code-block:: console

    curl --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getnewaddress", "params": [] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/

Base errors
###########

These errors are high level ones that happen outside of the handling of any call. They are modelled
on and should be identical to those returned by the node JSON-RPC implementation. Developers should
be able to come here when they encounter an error that is obviously not specific to the call they
are making and match the status code to a possible reason they are getting it.

- 400 (Bad request).

    - If a call entry from a single or batch request is not an object. The response body is:

        .. code-block:: js

            {
                id: null,
                result: null,
                error: {
                    code: -32600, // RPC_INVALID_REQUEST
                    message: "Invalid Request object"
                }
            }

    - If the `id` field is not a string, numeric or `null`. The response body is:

        .. code-block:: js

            {
                id: null,
                result: null,
                error: {
                    code: -32600, // RPC_INVALID_REQUEST
                    message: "Id must be int, string or null"
                }
            }

        .. warning::

            The node itself places no constraints on what the `id` value can be. This is a custom
            ElectrumSV constraint. We can relax it if we need to.

    - If the `method` field is not present. The response body is:

        .. code-block:: js

            {
                id: incoming_call.id,
                result: null,
                error: {
                    code: -32600, // RPC_INVALID_REQUEST
                    message: "Missing method"
                }
            }

    - If the `method` field value is not a string. The response body is:

        .. code-block:: js

            {
                id: incoming_call.id,
                result: null,
                error: {
                    code: -32600, // RPC_INVALID_REQUEST
                    message: "Method must be a string"
                }
            }

    - If the `params` field value is not an object or an array. The response body is:

        .. code-block:: js

            {
                id: incoming_call.id,
                result: null,
                error: {
                    code: -32600, // RPC_INVALID_REQUEST
                    message: "Params must be an array or object"
                }
            }

- 401 (Unauthorized).

    - If the `Authorization` header is required but not present.
    - If the authorization type is not `Basic`.
    - If the authorization value cannot be converted into a valid username and password.

- 404 (Not found).

    - If the `method` field value is not a recognized method name. The response body is:

        .. code-block:: js

            {
                id: incoming_call.id,
                result: null,
                error: {
                    code: -32601, // RPC_METHOD_NOT_FOUND
                    message: "Method not found"
                }
            }
- 500 (Internal server error).

    - If the JSON in the body cannot be deserialized correctly. The response body is:

        .. code-block:: js

            {
                id: null,
                result: null,
                error: {
                    code: -32700, // RPC_PARSE_ERROR
                    message: "Parse error"
                }
            }

    - If the deserialized body is not an object (a single call) or an array (a batch call).
      The response body is:

        .. code-block:: js

            {
                id: null,
                result: null,
                error: {
                    code: -32700, // RPC_PARSE_ERROR
                    message: "Top-level object parse error"
                }
            }

    - If the `/wallet/<wallet-name>` path form is used and no wallet with the name `<wallet-name>`
      exists. The response body is:

        .. code-block:: js

            {
                id: incoming_call.id,
                result: null,
                error: {
                    code: -18, // RPC_WALLET_NOT_FOUND
                    message: "Requested wallet does not exist or is not loaded"
                }
            }

Supported endpoints
###################


getnewaddress
~~~~~~~~~~~~~

Reserve the next unused receiving address (otherwise known as external key) and return it as a
P2PKH address.

Unlike the node wallet, this application does not receive and process all blocks. As such for an
address to be reserved and returned, a remote blockchain service needs to be successfully
provisioned to monitor this address for a set period of time.

**Parameters:**

None.

**Returns:**

The base58 encoded address for the reserved key (string).

**Error responses:**

These errors are the custom errors returned from within this call. Base errors that occur during
call processing are described above.

- 404 (Not found)

    - :Code: -32601 ``RPC_METHOD_NOT_FOUND``
      :Message: | ``Method not found (wallet method is disabled because no wallet is loaded)``
                | The implicit wallet access failed because no wallets are loaded.

- 500 (Internal server error)

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``No connected blockchain server``
                | No address can be provided until the wallet has signed up with a server and
                  it is currently connected to that server.

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``Blockchain server address monitoring request not successful``
                | It was not possible to get a successful acknowledgement from the blockchain
                  server that it would monitor the address. It might be that the server has lost
                  connection or it might be that some unexpected error occurred provisioning the
                  monitoring of the address from the server. See the logs.

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``Ambiguous account (found <count>, expected 1)``
                | A wallet used by the JSON-RPC API must only have one account so that the
                  API code knows which to make use of. The given wallet has either no accounts
                  or more than one account (the current number indicated by the `count`).

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``<other error messages>``
                | An error occurred attempting to register the address with the blockchain server
                  to be monitored for incoming payments. The error message provides some indication
                  of what happened, but the wallet logs will be needed to diagnose further.

listunspent
~~~~~~~~~~~

List the unspent outputs within the wallet. This can optionally be filtered by number of
confirmations or specific addresses.

**Parameters:**

#. ``minconf`` (integer, optional, default=1). Limit the results to the UTXOs with this number or
   more confirmations.
#. ``maxconf`` (integer, optional, default=9999999). Limit the results to the UTXOs with this number
   or less confirmations.
#. ``addresses`` (list of strings, optional, default=null). Limit the results to the UTXOs locked
   to the provided addresses.
#. ``include_unsafe`` (bool, optional, default=false). Safe coins are confirmed or unconfirmed and
   fully funded by ourselves. By default they are not included in the set of returned coins.

**Returns:**

An array of objects, where each object details a matched UTXO. Each object has the following
fields:

- ``txid``: The canonically encoded hexadeximal transaction id.
- ``vout``: The output index in that transaction.
- ``scriptPubKey``: The hexadecimal encoded output locking script.
- ``amount``: The number of bitcoin locked in the output.
- ``confirmations``: Number of mined blocks including the transaction and on top of it.
- ``spendable``: Whether we have the keys to spend this coin.
- ``solvable``: Whether we know how to spend this coin regardless of whether we have the keys to do
  so.
- ``safe``: Indicate if this coin is considered safe or not, if unsafe coins were included.
- ``address``: Only present if this address was included in the ``addresses`` array and filtered on.

For example, passing ``"params": { "addresses": ["mmne6bSrjwRZk16Y7TkwrrWysiUXZfd9ZY"] }`` returns:

.. code-block:: js

    [
        {
            "txid": "023d74ad33de138ef8b98cfd9950dc1b69c5855146e6a64f502a5be92fd626af",
            "vout": 0,
            "scriptPubKey":"76a91444c838328b3b9ab6e0ee1f021e281c46fb2804ca88ac",
            "amount": 50.00000553,
            "confirmations": 2,
            "spendable": false,
            "solvable": true,
            "safe": true,
            "address": "mmne6bSrjwRZk16Y7TkwrrWysiUXZfd9ZY"
        }
    ]

Note that in this case the UTXO is an unspent immature coinbase output, and is not spendable.

**Incompatibilities:**

#. The node wallet does redundant type checking on the ``minconf`` and ``maxconf`` parameters
   which would otherwise override the ``RPC_PARSE_ERROR`` with a ``RPC_TYPE_ERROR``. As existing
   API usage should not be erroring with incorrectly typed parameters, this should not be
   an important point of compatibility.

**Error responses:**

These errors are the custom errors returned from within this call. Base errors that occur during
call processing are described above.

- 404 (Not found)

    - :Code: -32601 ``RPC_METHOD_NOT_FOUND``
      :Message: | ``Method not found (wallet method is disabled because no wallet is loaded)``
                | The implicit wallet access failed because no wallets are loaded.

- 500 (Internal server error)

    - :Code: -3 ``RPC_TYPE_ERROR``
      :Message: | ``Expected type list, got <other type>``
                | The type of the ``addresses`` parameter was not a javascript array, and was
                  instead some other type here substituted as "<other type>".

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``Ambiguous account (found <count>, expected 1)``
                | A wallet used by the JSON-RPC API must only have one account so that the
                  API code knows which to make use of. The given wallet has either no accounts
                  or more than one account (the current number indicated by "<count>").

    - :Code: -5 ``RPC_INVALID_ADDRESS_OR_KEY``
      :Message: | ``Invalid Bitcoin address: <details>``
                | An entry in the ``addresses`` parameter was a string but not a valid address.
                  "<details>" will be substituted for contextual text on the reason the address
                  is not valid.

    - :Code: -8 ``RPC_INVALID_PARAMETER``
      :Message: | ``Invalid parameter, duplicated address: <address>``
                | An entry in the ``addresses`` parameter was specified twice. The node wallet
                  errors on this, so do we.
      :Message: | ``Invalid parameter, unexpected utxo type: <number>``
                | A unspent output was encountered that does not have a supported key type for
                  the JSON-RPC API. This would be if the user is accessing an externally created
                  account with this API.

    - :Code: -32602 ``RPC_INVALID_PARAMS``
      :Message: | ``Invalid parameters, see documentation for this call``
                | Either too few or too many parameters were provided.

    - :Code: -32700 ``RPC_PARSE_ERROR``
      :Message: | ``JSON value is not a string as expected``
                | The type of the entries in the ``addresses`` parameter are expected to be strings
                  and one or more were interpreted as another type.
      :Message: | ``JSON value is not an integer as expected``
                | The type of the ``minconf`` or ``maxconf`` parameters are expected to be integers
                  and one or more were interpreted as another type.
      :Message: | ``JSON value is not a boolean as expected``
                | The type of the ``include_unsafe`` parameter is expected to be a boolean
                  and was interpreted as another type.

sendtoaddress
~~~~~~~~~~~~~

Construct and broadcast a payment transaction to the given address for the given amount.

Broadcast of the transaction happens through a MAPI endpoint, and the fee is based on the
quote returned by that selected endpoint.

``TODO:`` Retry broadcast for failed broadcasts?

**Parameters:**

#. ``address`` (string, required). The P2PKH address of the recipient.
#. ``amount`` (numeric or string, required). The amount in BSV to send (e.g. 0.1).
#. ``comment`` (string, optional). A note to be attached to the transaction in the wallet, for
   reference purposes.
#. ``commentto`` (string, optional). The node wallet used this to allow the user to specify the name
   of a person or organisation who is the recipient. If provided this will be appended to the
   preceding comment parameter.
#. ``subtractfeefromamount`` (bool, optional). This is not supported and if passed with a ``true``
   value will give a ``RPC_INVALID_PARAMETER`` error.

**Returns:**

The transaction id of the broadcast transaction (string).

**Incompatibilities:**

#. We do not currently support the fifth parameter, which the node accepts as an indication the
   caller wishes the fee to be subtracted from the payment amount.

**Error responses:**

These errors are the custom errors returned from within this call. Base errors that occur during
call processing are described above.

- 404 (Not found)

    - :Code: -32601 ``RPC_METHOD_NOT_FOUND``
      :Message: | ``Method not found (wallet method is disabled because no wallet is loaded)``
                | The implicit wallet access failed because no wallets are loaded.

- 500 (Internal server error)

    - :Code: -3 ``RPC_TYPE_ERROR``
      :Message: | ``Invalid amount for send``
                | The specified amount is zero or less.

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``Ambiguous account (found <count>, expected 1)``
                | A wallet used by the JSON-RPC API must only have one account so that the
                  API code knows which to make use of. The given wallet has either no accounts
                  or more than one account (the current number indicated by the `count`).

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``No suitable MAPI server for broadcast``
                | The wallet tried to obtain fee quotes from MAPI servers and failed.
                  As it chooses the fee for the payment you are askign it to make based on
                  available MAPI server quotes, this means it cannot proceed.

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``<A succinct reason for why broadcast failed>``
                | There may be a range of reasons for why the broadcast of the signed transaction
                  failed. The 'succinct reason' detailed in the response should make it clear why,
                  and if not give a pointer to a path to follow up.

    - :Code: -5 ``RPC_INVALID_ADDRESS_OR_KEY``
      :Message: | ``Invalid address``
                | The provided address parameter is not a valid P2PKH address.

    - :Code: -6 ``RPC_WALLET_INSUFFICIENT_FUNDS``
      :Message: | ``Insufficient funds``
                | There is not enough money in the wallet available to meet the specified payment
                  amount.

    - :Code: -8 ``RPC_INVALID_PARAMETER``
      :Message: | ``Subtract fee from amount not currently supported``
                | This is an intentional incompatibility. The wallet application does not currently
                  support deducting the fee from the payment amount.

    - :Code: -13 ``RPC_WALLET_UNLOCK_NEEDED``
      :Message: | ``Error: Please enter the wallet passphrase with walletpassphrase first.``
                | In order to send funds from this wallet to the provided address, access to the
                  signing keys is required. This is given by unlocking the wallet, if it is not
                  already unlocked.

    - :Code: -32602 ``RPC_INVALID_PARAMS``
      :Message: | ``Invalid parameters, see documentation for this call``
                | Either too few or too many parameters were provided.

    - :Code: -32700 ``RPC_PARSE_ERROR``
      :Message: | ``JSON value is not a string as expected``
                | The type of the `comment` or `comment to` parameters are expected to be strings
                  and one or more were interpreted as another type.


walletpassphrase
~~~~~~~~~~~~~~~~

This call provides the ElectrumSV daemon with the password for the given wallet which allows the
daemon to perform secure operations without requiring user intervention. All private keys are
encrypted with the wallet password and without it available they cannot be accessed and operations
like signing cannot be performed.

**Parameters:**

#. Passphrase (string, required). The wallet passphrase.
#. Timeout (numeric, required). The time to keep the wallet passphrase cached in seconds.

**Returns:**

``null``.

**Error responses:**

These errors are the custom errors returned from within this call. Base errors that occur during
call processing are described above.

- 404 (Not found)

    - :Code: -32601 ``RPC_METHOD_NOT_FOUND``
      :Message: | ``Method not found (wallet method is disabled because no wallet is loaded)``
                | The implicit wallet access failed because no wallets are loaded.

- 500 (Internal server error)

    - :Code: -32602 ``RPC_INVALID_PARAMS``
      :Message: | ``Invalid parameters, see documentation for this call``
                | For this error the node would return documentation for this call as the response.
                  We do not. This error is seen when the two required parameters are not passed.

    - :Code: -32700 ``RPC_PARSE_ERROR``
      :Message: | ``JSON value is not a string as expected``
                | The type of the `passphrase` parameter is expected to be a string and was
                  interpreted as another type.

    - :Code: -32700 ``RPC_PARSE_ERROR``
      :Message: | ``JSON value is not an integer as expected``
                | The type of the `timeout` parameter is expected to be a integer and was
                  interpreted as another type.

    - :Code: -32700 ``RPC_PARSE_ERROR``
      :Message: | ``Invalid parameters, see documentation for this call``
                | This error is seen when the passphrase is an empty string.

    - :Code: -14 ``RPC_WALLET_PASSPHRASE_INCORRECT``
      :Message: | ``Error: The wallet passphrase entered was incorrect``
                | This error is seen when the passphrase is not the correct passphrase for the
                  wallet being accessed.
