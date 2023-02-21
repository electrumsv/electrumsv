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

createrawtransaction
~~~~~~~~~~~~~~~~~~~~

Act as a library of functionality and piece together an incomplete (not fully signed and final)
transaction using the provided list of inputs, an object containing outputs and optionally lock
time. The transaction created here is not persisted by the wallet in any way.

**Parameters:**

#. ``inputs`` (array of input objects, required). Each item in the array is an object containing
   fields relating to the given input. The structure of an input object is described below.
#. ``outputs`` (object of outputs, required). The amount in BSV to send (e.g. 0.1).
#. ``locktime`` (numeric, optional). The transaction locktime value to use.

Each object in the ``inputs`` array has the following structure:

- ``txid`` (string, required). The canonically hexadecimal encoded transaction hash of the
  transaction being spent.
- ``vout`` (numeric, required). The index of the output in the given transaction being spent.
- ``sequence`` (numeric, optional, default varies). The sequence value to be specified in the
  input. This can of course be used to differentiate between final and non-final inputs. If the
  transaction ``locktime`` value is non-zero, it will default to ``0xFFFFFFFE`` (last possible
  non-final value) otherwise it default to ``0xFFFFFFFF`` (final).

.. code-block:: json
    :caption: Example input object.

    {
        "txid": "0df80206d8c30046d1fbf0f19959b81cef72a9d01fe4fe831520cfee361d2a8a",
        "vout": 0
    }

The ``outputs`` object has the following structure:

- ``"<address>"`` (string, required). The address to send an amount to.
  - ``<amount>`` (numeric). The amount to send to the address.
- ``"data"`` (literal string, optional). One optional "op return" data output.

  - ``<hexadecimally encoded data>`` (string). The bytes of data to put in the
    ``OP_FALSE OP_RETURN`` 0-value data output.

.. code-block:: json
    :caption: Example outputs object.

    {
        "mneqqWSAQCg6tTP4BUdnPDBRanFqaaryMM": 200,
        "mineSVDRCrSg2gzBRsY4Swb5QHFgdnGkis": 500,
        "data": "6e6f77206973207468652074696d65"
    }

**Returns:**

The hexadecimally encoded serialised transaction bytes. ``scriptSig`` values in serialised inputs
will be empty, represented by ``0`` which is a zero-length push.

For example, we can force outputs that are considered to be unsafe to be returned:

.. code-block:: console

    curl --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "createrawtransaction", "params": [[{ "txid": "f6a5a25e297a40aafec9ad948efda26597945adf93a4b726ad32a656d73743df", "vout": 1 }], { "mneqqWSAQCg6tTP4BUdnPDBRanFqaaryMM": 0.5 }] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/

Returns a result similar to the following:

.. code-block:: js

    "0100000001df4337d756a632ad26b7a493df5a949765a2fd8e94adc9feaa407a295ea2a5f60100000000ffffffff0180f0fa02000000001976a9144e46d14cb7b049222f47ce498e61d7156c6f088f88ac00000000"

**Error responses:**

These errors are the custom errors returned from within this call. Base errors that occur during
call processing are described above.

- 500 (Internal server error)

    - :Code: -3 ``RPC_TYPE_ERROR``
      :Message: | ``Expected array, got <other type>``
                | The ``inputs`` argument is not the array type.
      :Message: | ``Expected object, got <other type>``
                | The ``outputs`` argument is not the object type.
      :Message: | ``Expected number, got <other type>``
                | The ``outputs`` argument is not the numeric type.
      :Message: | ``Amount is not a number or string``
                | An output object value is not a number or string.
      :Message: | ``Invalid amount``
                | An output object value is a string that cannot be parsed as a value.
      :Message: | ``Amount out of range``
                | An output object amount is an invalid amount of satoshis.

    - :Code: -5 ``RPC_INVALID_ADDRESS_OR_KEY``
      :Message: | ``Invalid Bitcoin address: <address>``
                | The provided address parameter is not a valid P2PKH address.

    - :Code: -8 ``RPC_INVALID_PARAMETER``
      :Message: | ``Invalid parameter, arguments 1 and 2 must be non-null``
                | One or both of ``inputs`` or ``outputs`` parameter were ``null``.
      :Message: | ``Invalid parameter, locktime out of range``
                | The value of ``locktime`` was not equal to or between 0 and 0xFFFFFFFF.
      :Message: | ``txid must be hexadecimal string (not '<whatever it is>') and length of it must be divisible by 2``
                | A ``txid`` field in an entry in the ``inputs`` parameter, was either missing,
                  ``null`` or not an string that was a valid hexadecimal data.
      :Message: | ``Invalid parameter, missing vout key``
                | A ``vout`` field in an entry in the ``inputs`` parameter, was either missing,
                  ``null`` or not an integer.
      :Message: | ``Invalid parameter, vout must be positive``
                | A ``vout`` field in an entry in the ``inputs`` parameter, was an integer but
                  was negative which is invalid.
      :Message: | ``Invalid parameter, sequence number is out of range``
                | A ``sequence`` field in an entry in the ``inputs`` parameter, was an integer but
                  was outside of the valid range of values. It cannot be less than 0 or greater
                  than ``0xFFFFFFFF``.
      :Message: | ``Invalid parameter, duplicated address: <address>``
                | An entry in the ``addresses`` parameter was specified twice. The node wallet
                  errors on this, so do we.

    - :Code: -32700 ``RPC_PARSE_ERROR``
      :Message: | ``JSON value is not an object as expected``
                | The type of an entry in the ``inputs`` parameter was not an object.

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
#. ``addresses`` (array of strings, optional, default=null). Limit the results to the UTXOs locked
   to the provided addresses.
#. ``include_unsafe`` (bool, optional, default=false). Safe coins are either confirmed, or
   unconfirmed and fully funded by ourselves. By default they are not included in the set of
   returned coins.

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

For example, we can filter for a specific address:

.. code-block:: console

    curl --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "listunspent", "params": { "addresses": ["mmne6bSrjwRZk16Y7TkwrrWysiUXZfd9ZY"] } }' -H 'content-type: text/plain;' http://127.0.0.1:8332/

Returns a result similar to the following:

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

For example, we can force outputs that are considered to be unsafe to be returned:

.. code-block:: console

    curl --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "listunspent", "params": [0,null,null,true] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/

Returns a result similar to the following:

.. code-block:: js

    [
      {
          "txid":"f6a5a25e297a40aafec9ad948efda26597945adf93a4b726ad32a656d73743df",
          "vout":1,
          "address":"mrUu747bPcGuEgGqnRy7LwtWz9phNpTzgF",
          "scriptPubKey":"76a9147845e39d07817a8415d5741893018e4204c2394388ac",
          "amount":1.0,
          "confirmations":0,
          "spendable":true,
          "solvable":true,
          "safe":false
      }
    ]

**Common problems:**

* If you are not seeing an incoming payment from another wallet or another party, this will likely
  be because you are not passing the ``"include_unsafe"=true`` parameter. For a unspent output to
  be included without this flag, the transaction it is in has to be confirmed or both unconfirmed
  and for all funding to come from this wallet.

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

signrawtransaction
~~~~~~~~~~~~~~~~~~

Take a transaction serialised in hexadecimal encoding and sign it using the keys available to the
account.

**Parameters:**

#. ``hexstring`` (string, required). The serialised incomplete transaction in hexadecimal encoding.
   It is expected that this will have one or more absent signatures, that the account will be able
   to sign as the purpose of this call. Multiple versions of this transaction can be concatenated
   into the value passed as this parameter and the pre-existing signatures will be extracted from
   each.
#. ``prevtxs`` (array of objects, optional). An array of objects containing the relevant parts
   of each parent transaction.
#. ``privkeys`` (array of strings, optional). An array of private keys that are not currently used.
   If we supported this, they would be used to sign instead of any of the keys available to the
   account.
#. ``sighashtype`` (string, optional, default="ALL|FORKID"). A specified sighash name out of
   twelve possible options accepted by bitcoind. Only the default value is currently accepted,
   see the Incompatibilities section.

The ``hexstring`` parameter is expected to encode unsigned or partially signed inputs in the
standard way accepted by bitcoind. ``scriptSig`` values in single signature serialised inputs will
be empty, represented by ``OP_0`` which is in effect a zero-length push. Multi-signature serialised
inputs are expected to have the correct ``scriptSig`` structure with absent signatures
substituted with ``OP_0`` (multi-signature support is currently disabled).

Each object in the ``prevtxs`` array has the following structure:

- ``txid`` (string, required). The canonically hexadecimal encoded transaction hash of the
  transaction being spent.
- ``vout`` (numeric, required). The index of the given transaction output being spent.
- ``scriptPubKey`` (string, required). The script from the given transaction output being spent.
- ``redeemScript`` (string, optional). If the script from the output in the given transaction
  being spent is an older P2SH script, then this is the redeem script of that P2SH script. See the
  Incompatibilities section.
- ``amount`` (numeric, required). The value stored in the given transaction output, denominated
  in units of bitcoin as per bitcoind convention.

.. code-block:: json
    :caption: Example prevtx object.

    {
        "txid": "0df80206d8c30046d1fbf0f19959b81cef72a9d01fe4fe831520cfee361d2a8a",
        "vout": 0,
        "scriptPubKey": "",
        "redeemScript": "",
        "amount": 1.2
    }

The ``privkeys`` array can contain base 58 encoded private keys. If these are provided these will
be the only keys used to sign the transaction and the keys in the wallet will not be used. These
parameter is not currently supported, see the Incompatibilities section.

The ``sighashtype`` value can in theory be one of twelve possible options accepted by bitcoind.
Note that currently we only accept ``ALL|FORKID`` which is also the default, see the
Incompatibilities section.

- ``ALL``
- ``ALL|ANYONECANPAY``
- ``ALL|FORKID``
- ``ALL|FORKID|ANYONECANPAY``
- ``NONE``
- ``NONE|ANYONECANPAY``
- ``NONE|FORKID``
- ``NONE|FORKID|ANYONECANPAY``
- ``SINGLE``
- ``SINGLE|ANYONECANPAY``
- ``SINGLE|FORKID``
- ``SINGLE|FORKID|ANYONECANPAY``

**Returns:**

The returned object has the following structure:

- ``"hex"`` (string, required). The serialised processed transaction in hexadecimal encoding.
- ``"complete"`` (boolean, required). Indicates whether the processed transaction is fully signed.
  It is not a requirement of successful signing for the processed transaction to have all inputs
  fully signed.
- ``"errors"`` (list of objects, optional). This is only present if there are entries to include.

  - ``"txid"`` (string, required). The canonically hexadecimal encoded hash of the transaction
    being spent.
  - ``"vout"`` (string, required). The index of the transaction output being spent.
  - ``"scriptSig"`` (string, required). The hexadecimally encoded signature script.
  - ``"sequence"`` (string, required). The sequence of the spending input.
  - ``"error"`` (string, required). Any text describing why the verification or spend failed.

.. code-block:: json
    :caption: Example returned object with no errors.

    {
        "hex": "<serialised hexadecimally encoded transaction>",
        "complete": true
    }

In theory this endpoint can return a variety of errors encountered. The returned transaction
should be unchanged from the base transaction originally provided for signing.

.. code-block:: json
    :caption: Example returned object with inline errors.

    {
        "hex": "<serialised hexadecimally encoded transaction>",
        "complete": false,
        "errors": [
            {
                "error": "<some message>",
                "scriptSig": "",
                "sequence": 4294967295,
                "txid": "2222222222222222222222222222222222222222222222222222222222222222",
                "vout": 0
            }
        ]
    }

In reality the ``errors`` property only ever returns errors for one specific situation. This is
where the wallet does not have the spent coin metadata for an input. Every input in the transaction
must have matching spent coin metadata. This is normally automatically retrieved from the account
database, but for inputs the wallet is not signing must be provided using the ``prevtxs`` parameter
intended for this purpose. If any coin metadata obtained from the account database is known to
be spent, this error entry will also be added for the given input for that reason.

.. code-block:: json
    :caption: Example returned object with inline errors.

    {
        "hex": "<serialised hexadecimally encoded transaction>",
        "complete": false,
        "errors": [
            {
                "error": "Input not found or already spent",
                "scriptSig": "",
                "sequence": 4294967295,
                "txid": "2222222222222222222222222222222222222222222222222222222222222222",
                "vout": 0
            }
        ]
    }

For example, here we are taking the result of ``createrawtransaction`` and using that as input:

.. code-block:: console

    curl --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "signrawtransaction", "params": [ "0100000001df4337d756a632ad26b7a493df5a949765a2fd8e94adc9feaa407a295ea2a5f60100000000ffffffff0180f0fa02000000001976a9144e46d14cb7b049222f47ce498e61d7156c6f088f88ac00000000"] }' -H 'content-type: text/plain;' http://127.0.0.1:8332/

Returned the following result:

.. code-block:: js

  {
    "hex":"0100000001df4337d756a632ad26b7a493df5a949765a2fd8e94adc9feaa407a295ea2a5f6010000006a47304402206d2e8a533d5a60cd2dc2f2c231b1d32b0bb7c9001130ffe1f165da8a7eb095f4022068e945a1adf75fb5d92be4d05fcfce417e853f123eeced54ab7e12c01301980d412103acb0f93ce0c3fa028226e6236f463150ba00eafb349bb221f5a9cf5cbe239cfaffffffff0180f0fa02000000001976a9144e46d14cb7b049222f47ce498e61d7156c6f088f88ac00000000",
    "complete":true
  }

**Incompatibilities:**

If a user requires any of these disabled functionalities, they should get in touch with their
contact at the Bitcoin Association and request the ones they need.

#. Only one transaction is currently accepted. If more than one transaction is provided then
   a compatibility related error will be raised.
#. Only spending of P2PKH coins is supported. While it is in theory to support P2PK, P2SH and
   bare multi-signature, spending of these coins are not currently enabled. Any attempt to do so
   will result in a compatibility related error.

   #. Related to this: If any ``prevouts`` entry contains a ``redeemScript`` property, it will
      be ignored as we do not currently handle P2SH spends.

#. External private keys are not currently accepted. If any are provided a compatibility related
   error will be raised.
#. Only the ``ALL|FORKID`` sighash name is accepted. As with the bitcoind implementation sighash
   names that do not include ``FORKID`` will result in a standard error. However, valid sighash
   names other than ``ALL|FORKID`` will raise a compatibility related error.

**Error responses:**

These errors are the custom errors returned from within this call. Base errors that occur during
call processing are described above.

- 404 (Not found)

    - :Code: -32601 ``RPC_METHOD_NOT_FOUND``
      :Message: | ``Method not found (wallet method is disabled because no wallet is loaded)``
                | The implicit wallet access failed because no wallets are loaded.

- 500 (Internal server error)

    - :Code: -3 ``RPC_TYPE_ERROR``
      :Message: | ``Expected string, got <other type>``
                | The ``hexstring`` argument is not the string type.
      :Message: | ``Expected array, got <other type>``
                | The ``prevtxs`` argument is not the array type.
      :Message: | ``Expected array, got <other type>``
                | The ``privkeys`` argument is not the array type.
      :Message: | ``Expected string, got <other type>``
                | The ``sighashtype`` argument is not the string type.
      :Message: | ``Missing txid``
                | The ``prevtxs`` array was found to contain at least one entry with a missing or
                  ``null`` value in the ``txid`` field.
      :Message: | ``Expected type string for txid, got <other type>``
                | The ``prevtxs`` array was found to contain at least one entry with a non-string
                  value for the ``txid`` field.
      :Message: | ``Missing vout``
                | The ``prevtxs`` array was found to contain at least one entry with a missing or
                  ``null`` value in the ``vout`` field.
      :Message: | ``Expected type integer for vout, got <other type>``
                | The ``prevtxs`` array was found to contain at least one entry with a non-integer
                  value for the ``vout`` field.
      :Message: | ``Missing scriptPubKey``
                | The ``prevtxs`` array was found to contain at least one entry with a missing or
                  ``null`` value in the ``scriptPubKey`` field.
      :Message: | ``Expected type string for scriptPubKey, got <other type>``
                | The ``prevtxs`` array was found to contain at least one entry with a non-string
                  value for the ``scriptPubKey`` field.
      :Message: | ``Amount is not a number or string``
                | The ``prevtxs`` array was found to contain at least one entry with a value for
                  the ``amount`` property that was not a string or number.
      :Message: | ``Invalid amount``
                | The ``prevtxs`` array was found to contain at least one entry with a string value
                  for the ``amount`` property that cannot be parsed as a value.
      :Message: | ``Amount out of range``
                | The ``prevtxs`` array was found to contain at least one entry with a string value
                  for the ``amount`` property that was an invalid amount of satoshis.

    - :Code: -4 ``RPC_WALLET_ERROR``
      :Message: | ``Ambiguous account (found <count>, expected 1)``
                | A wallet used by the JSON-RPC API must only have one account so that the
                  API code knows which to make use of. The given wallet has either no accounts
                  or more than one account (the current number indicated by the `count`).

    - :Code: -8 ``RPC_INVALID_PARAMETER``
      :Message: | ``hexstring must be hexadecimal string (not '<whatever it is>') and length of it must be divisible by 2``
                | The ``hexstring`` parameter, was either ``null`` or not an string that was
                  valid hexadecimal data.
      :Message: | ``scriptPubKey must be hexadecimal string (not '<whatever it is>') and length of it must be divisible by 2``
                | The ``prevtxs`` list was provided and had at least one object within it that had
                  a ``scriptPubKey`` value of either ``null`` or not an string that was valid hexadecimal data.
      :Message: | ``txid must be hexadecimal string (not '<whatever it is>') and length of it must be divisible by 2``
                | The ``prevtxs`` list was provided and had at least one object within it that had
                  a ``txid`` value of either ``null`` or not an string that was valid hexadecimal data.
      :Message: | ``txid must be of length 64 (not <actual hexadecimal string length>)``
                | The ``prevtxs`` list was provided and had at least one object within it that had
                  a ``txid`` value that was a valid hexadecimal string but was not the required
                  32 bytes in size.
      :Message: | ``Missing amount``
                | The ``prevtxs`` list was provided and had at least one object within it that had
                  a missing ``amount`` property.
      :Message: | ``Invalid sighash param``
                | The provided ``sighashtype`` parameter value is not one of the twelve accepted by
                  bitcoind.
      :Message: | ``Signature must use SIGHASH_FORKID``
                | The provided ``sighashtype`` parameter value is not one of the few that include
                  ``FORKID``, and ``FORKID`` is currently required for valid Bitcoin SV signatures.
      :Message: | ``Compatibility difference (only ALL|FORKID sighash accepted)``
                | See the Incompatibilities section.

    - :Code: -13 ``RPC_WALLET_UNLOCK_NEEDED``
      :Message: | ``Error: Please enter the wallet passphrase with walletpassphrase first.``
                | In order to send funds from this wallet to the provided address, access to the
                  signing keys is required. This is given by unlocking the wallet, if it is not
                  already unlocked.

    - :Code: -22 ``DESERIALIZATION_ERROR``
      :Message: | ``Tx decode failed``
                | The ``hexstring`` argument value was successfully decoded to bytes, but the
                  processing of it as a validly formed transaction failed.
      :Message: | ``Missing transaction``
                | The ``hexstring`` argument value is empty and contains no transaction to sign.
      :Message: | ``Compatibility difference (multiple transactions not accepted)``
                | See the Incompatibilities section.
      :Message: | ``Compatibility difference (non-P2PKH spends not accepted)``
                | See the Incompatibilities section.
      :Message: | ``expected object with {"txid","vout","scriptPubKey"}``
                | The ``prevtxs`` array was found to contain at least one non-object.
      :Message: | ``vout must be positive``
                | The ``prevtxs`` array was found to contain at least one object with a ``vout``
                  property that was correctly an integer, but less than zero.
      :Message: | ``Previous output scriptPubKey mismatch:\n<wallet asm>\nvs\n<prevtxs asm>``
                | If a ``prevtxs`` entry is provided for a coin managed by the wallet, the provided
                | ``scriptPubKey`` bytes must exactly match those the wallet has for that coin.
                  The disassembled script text will be substituted for the ``<wallet asm>`` and
                  ``<prevtxs asm>`` placeholders in the message text.

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
