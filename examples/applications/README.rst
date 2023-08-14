ElectrumSV - Example Applications
=================================

These are a formalised way to run an extended version of ElectrumSV. They are intended to be
useful in the case where you need access to (for instance) an extended set of REST API
functionality that ElectrumSV has either not incorporated yet, or will not incorporate because
it does not serve the general needs.

Be warned that we do not guarantee that ElectrumSV code and internal state will not be kept
backwards compatible. If you plan to write your own application code, you will need to be
prepared to maintain it and migrate it as ElectrumSV evolves.

However, we may provide useful skeletons. These will be updated as ElectrumSV evolves, and if
you derive from these, it is with the expectation you will be willing to migrate your code
following the changes made to them.

REST API
-----------

This extends the built-in REST API and is intended as both a general template for application
developers but also has the aim of growing to serve most general-purpose needs or to influence
future additions to the ESV built-in REST API.

Add the 'examples/applications' directory to your 'PYTHONPATH'.
Starting in the top-level directory of the electrumsv repository...

In windows cmd.exe::

    > set PYTHONPATH=examples/applications

In windows terminal / powershell::

    > $env:PYTHONPATH='examples/applications'


In linux bash::

    > export PYTHONPATH=examples/applications

Then start the ElectrumSV daemon application with::

    > py -3.9 electrum-sv --restapi daemon -dapp restapi

To disable basic authentication::

    > py -3.9 electrum-sv --restapi daemon -dapp restapi --restapi-password=

Otherwise, the basic auth credentials can be found in the json config file and will include a randomly generated,
base64 encoded password for example::

    "restapi_password": "GRmGKV_YWfx1mWaPEaXBGA=="
    "restapi_username": "user"

Note: **--restapi** and **--testnet** are global configuration flags to 'activate' the restapi and run on testnet
(whether running a daemon app or in GUI wallet mode). These arguments can be placed in any order (i.e. they could come last).

Whereas, **-dapp restapi** loads up a daemon app (in this case called 'restapi') and will cause its additional
endpoints to be registered onto the activated restapi. These commands are **specific to running ESV in daemon mode**, so
must follow the **"daemon"** command.

This runs ElectrumSV as a daemon providing an extended REST API. Early stage documentation can be
found here_:

.. _here: https://documenter.getpostman.com/view/9976147/SWLib6gk?version=latest


Creating a Wallet
-----------------
At this time, wallet creation via the REST API is only supported on the RegTest network.
To create a wallet and account programmatically, shutdown the ElectrumSV daemon and
run these commands on the command-line:

    python3 electrum-sv create_wallet -w ~/.electrum-sv/wallets/mywallet.sqlite -wp test --no-password-check
    python3 electrum-sv create_account -w ~/.electrum-sv/wallets/mywallet.sqlite -wp test --no-password-check

This will create a wallet called "mywallet.sqlite" with a wallet password of "test" and will add a standard BIP32
account which uses P2PKH output scripts for receiving payments.


Future possibilities include:
- Dedicated B and BCAT handlers for ease of file uploads.
- Websockets to ElectrumX subscriptions
- p2p broadcasting
- coin splitting
