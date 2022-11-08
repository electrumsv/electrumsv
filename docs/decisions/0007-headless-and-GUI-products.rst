Headless and GUI products
#########################

:Date: 2022-11-09
:Status: Pending.

Context
-------

Until now ElectrumSV has been an application that most use through it's user interface, and few
if any use the headless daemon feature. ElectrumSV is now part of the LiteClient project and is
going to be the reference implementation of the features Bitcoin Association is providing to help
move Bitcoin SV forward.

Decision
--------

Two products are going to be provided:

- The headless wallet server accessed by API.

  - REST API.
  - Node wallet API (JSON-RPC).

- The graphical user interface.

These will be the same code base but likely packaged to run as either headless or GUI, with
a different name for each.

Consequences
------------

- The GUI may get rewritten to be a customer of the in-built wallet server.
- We will need to test the wallet server better and more extensively.
