Replace the JSON-RPC API with REST
##################################

:Date: 2020-12-05
:Status: Completed.

Context
-------

There are numerous problems with the JSON-RPC API that ElectrumSV started with.

* REST is more common for APIs, and we wanted to support something that external developers
  who wanted to use ElectrumSV as a wallet server would be more likely to use.
* The `jsonrpclib` module did not support Python 3, so we were using some arbitrary fork called
  `jsonrpclib-pelix`.
* It was text-based, requiring all sent or retrieved binary data to be encoded as text.

Decision
--------

We rewrote the API as REST using the `aiohttp` library as a dependency.

Consequences
------------

* We still use JSON-RPC in the daemon. We need to replace this with something else to finally
  remove this dependency completely.
