Replace the JSON storage with SQLite
####################################

:Date: 2020-12-05
:Status: Completed.

Context
-------

The way the wallet storage worked when ElectrumSV forked from Electron Cash, was a JSON file which
was optionally encrypted. Anytime the wallet data changed, if it had to be saved, the content of
that JSON file had to be pieced together serialised as JSON, compressed and encrypted.

A potential problem was that if the wallet application crashed, it was likely that all changes to
the wallet were lost. The actual loss was limited to the few pieces of local metadata like
transaction descriptions, the rest of the data was reliant on blockchain as the source of truth.
An example of this was that when a wallet signed a transaction, it wouldn't keep a copy, it would
instead send it to the network and add it when it received notification it was in the mempool.

With ElectrumSV moving to P2P and wanting to store a lot more local data, and the blockchain not
being a blindly observed source of truth, needed a way to store data as it was obtained in order
to ensure it was persisted.

Decision
--------

Each wallet should have its own SQLite database for its data storage.

Consequences
------------

* There is no easy way to encrypt all data stored in the database. Only private key data and other
  critical data can feasibly be encrypted in a database. At some time in the future we may revisit
  this but do not have the bandwidth for it at this time.
