ElectrumSV - Example Applications
=================================

These are a formalised way to run an extended version of ElectrumSV. They are intended to be
useful in the case where you need access to (for instance) an extended set of RPC
functionality that ElectrumSV has either not incorporated yet, or will not incorporate because
it does not serve the general needs.

Be warned that we do not guarantee that ElectrumSV code and internal state will not be kept
backwards compatible. If you plan to write your own application code, you will need to be
prepared to maintain it and migrate it as ElectrumSV evolves.

However, we may provide useful skeletons. These will be updated as ElectrumSV evolves, and if
you derive from these, it is with the expectation you will be willing to migrate your code
following the changes made to them.

File Upload
-----------

Two ways to upload files are 'b://' and 'Bcat'. This application extends ElectrumSV to provide
a way for users to upload files to the blockchain using either of these two different protocols
based on file size.

Add the 'examples/applications' directory to your 'PYTHONPATH'.

Then start it by::

    electrum-sv daemon -dapp esv_fileupload

This runs ElectrumSV as a daemon providing an extended JSON-RPC API. Then you can make use of
the 'fileupload.py' script, to upload files.

    examples/applications/fileupload.py -f my-cool-picture.jpg -eh 127.0.0.1 -ep 8888
    -u my_rpc_username -p my_rpc_password -wn spending_wallet -wp my_password

Merchant Server
---------------

ElectrumSV provides support for payment requests, both from the side of the consumer and
the merchant. This application extends ElectrumSV to provide suitable functionality for a
local web site to communicate with it via RPC, and detect payments and react to them.

This will be accompanied at a later stage by an example web site, but for now serves as an
initial example of an application.

Add the 'examples/applications' directory to your 'PYTHONPATH'.

Then start it by::

    electrum-sv daemon -dapp esv_merchant_server

