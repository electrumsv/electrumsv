Remote service usage
====================

As part of providing it's user with the information they need, ElectrumSV has to make use of
remote servers. The following types of server provide different functionality that use is made
of.

Server types
!!!!!!!!!!!!

ElectrumSV reference server
---------------------------

These are standard APIs that ElectrumSV expects to be able to use if it is to provide the user
with updated wallet state and to react to external events. A
`reference implementation <https://github.com/electrumsv/electrumsv-reference-server/>`_ is provided
by the ElectrumSV developers, although it does not provide the more advanced APIs that are related
to processing new and old blocks.

Headers API
~~~~~~~~~~~

As an SPV client, ElectrumSV needs up-to-date headers from the blockchain. This API is used to
both sychronise existing headers and get notified of new headers as the server makes them
available.

The ideal way of obtaining headers is by having an application access the P2P network. However,
ElectrumSV cannot guarantee that it has unrestricted access to the network. For this reason we
do not use the P2P network, but instead rely on this external REST API. It is possible that in
the longer term we will also support direct P2P network access for this, and fallback to the
service API if it not usable.

Peer channel API
~~~~~~~~~~~~~~~~

In the same way that ElectrumSV cannot rely on accessing the P2P network to get headers due to
restrictive networking environments, it also cannot and should not rely on being able to connect
directly to another person's ElectrumSV application. This is due to restrictive networking
environments, privacy and security related concerns and the impracticality of expecting ElectrumSV
to be online 24/7. The peer channel API acts as a relaying service, a message box and a privacy aid.

Spent output API (forwarded)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
   The ElectrumSV project has neither the manpower or the interest in providing a non-regtest open source
   implementation of this API. It is expected that commercial services will provide it, as an
   optional enabled API provided by their servers.

It is useful to be able to ask whether a UTXO is spent. If it is spent then we need a way to find
out what transaction it was spent in and what block it was mined in, if not in the mempool. We need
to both query the state of outputs, and to register for notifications if there are any changes.

ElectrumSV uses this API to accomplish the following:

- Identify if a transaction is in the mempool.
- Identify if a transaction is mined in a block.
- Identify if a transaction has been malleated.
- Get notified if a transaction gets broadcast.
- Get notified if a transaction gets mined.
- Get notified if a transaction gets malleated.

There is some overlap with the merchant API here where we can use the act of successful
broadcasting as a trustworthy indication that the given transaction is in the mempool. It's
broadcast and double-spend callback will also serve as trustworthy way to get notified if the
transaction is either mined or double spent. We do not use the spent output API for transactions
that have been broadcast through the merchant API, unless something has gone wrong and we
cannot expect the merchant API callbacks to provide us with the data we need.

Restoration API (forwarded)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
   The ElectrumSV project has neither the manpower or the interest in providing a non-regtest open
   source implementation of this API. It is expected that commercial services will provide it, as an
   optional enabled API provided by their servers.

In the past there was an expectation that seed words could be used to locate all transactions
ever associated with a wallet, and that this could be used as both a form of backup and a way
to keep a wallet synchronised. As the blockchain becomes larger and larger, there is no-one
planning to support this, and if they did it would likely become more and more expensive as the
blockchain continue to grow.

The highest priority of the ElectrumSV project is to allow users to retain access to coins
where they have been able to access them in the past. One aspect of this is seed-based wallet
restoration and we continue to support this by allowing access to blockchain state and indexes
that only go up to a fixed height. Past this height, it is expected that users will have to take
responsibility for their own wallet data.

The restoration API is effectively a search engine over this limited earlier part of the blockchain,
that our users can use to do a limited restore of their seed words.

Transaction API (forwarded)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
   The ElectrumSV project has neither the manpower or the interest in providing a non-regtest open
   source implementation of this API. It is expected that commercial services will provide it, as an
   optional enabled API provided by their servers.

As the blockchain grows larger and larger, storage and access to arbitrary transaction data
becomes a specialised service that will likely require charging for access to data. The
transaction API is provided for requesting arbitrary transactions.

Merkle proof API (forwarded)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
   The ElectrumSV project has neither the manpower or the interest in providing a non-regtest open
   source implementation of this API. It is expected that commercial services will provide it, as an
   optional enabled API provided by their servers.

In an ideal world all transactions will be broadcast through a merchant API server, and a callback
from that server will notify if the transaction is mined and provide the merkle proof. In the real
world, not all transactions related to an ElectrumSV user's wallet are broadcast by that user
through MAPI. Other parties may broadcast the transaction, and this may not be desirable, expected
or have any channel through which the ElectrumSV user can hear about either the merkle proof.

It is necessary to have the ability to request arbitrary merkle proofs, and the merkle proof
API is used for this purpose.

Merchant API
------------

The purpose of the merchant API is so that miners can offer a way to both broadcast a transaction
and know the fee that must be used in any transaction in order for it to be accepted for broadcast.

Simple indexer API (regtest only)
---------------------------------

In order to both develop and test ElectrumSV on the regtest network, we need a simple
implementation of the following APIs:

- Merkle proof API.
- Restoration API.
- Transaction API.
- Spent output API.

The `simple indexer <https://github.com/electrumsv/simple-indexer>`_ is a very limited
implementation of these APIs that can run against the regtest network. It will never run on any
network other than regtest. The amount of work required to make it performant is something a
commercial business would have to do, and a commercial business would be required to run and keep
that production service going into the future.

Relevant wallet events
!!!!!!!!!!!!!!!!!!!!!!

There are a small number of wallet events that make use of these remote services.

Loading a wallet
----------------

Spent outputs:

- We monitor local transactions that we may not expect to be broadcast. These have the
  :ref:`transaction state <transaction-state>` values of ``STATE_SIGNED``,
  ``STATE_RECEIVED`` or ``STATE_DISPATCHED``.
- We monitor transactions that we know have been broadcast but we do not know if they are mined,
  with the exception of those that were broadcast using MAPI where the managing MAPI logic has
  not flagged a problem. These have the :ref:`transaction state <transaction-state>`
  value of ``STATE_CLEARED`` with no associated block.

Merkle proofs:

- If we have transactions that have been broadcast and mined, but which we have not obtained the
  merkle proof for, we pass them in a worker task that will take care of this. These will likely
  be transactions we received spent output state for, which we have not had the chance to process
  yet. These have the :ref:`transaction state <transaction-state>`
  value of ``STATE_CLEARED`` with an associated block.
- If we have transactions from before ElectrumSV 1.4.0 they will not have a TSC standardised
  merkle proof. We pass these to a worker task to take care of obtaining them. These have the
  :ref:`transaction state <transaction-state>` value of ``STATE_SETTLED`` with no
  associated block or proof.

Account restoration
-------------------

Restoration:

- The restoration process attempts to enumerate known key usage within different script types
  and locate them in the remote restoration index. It gets metadata about the transactions
  that use these keys back.

Merkle proof:

- Transactions are fetched through the merkle proof API, taking advantage of the TSC standard
  providing the ability for transaction data to be wrapped in the merkle proof.

New payment
-----------

This is a little complicated due to the fact that there are two steps, signing a transaction
and broadcasting a transaction. The user can construct a transaction and sign it, then it
gets added to their account history. In this case, we would want to treat it as a local transaction
and monitor it using the spent output API.  If however it gets signed, then broadcast, we would
want to leave management up to the MAPI broadcast management.

Spent outputs:

- We monitor the transaction for a nominal period of time after it is signed. If it is not
  broadcast we hand it off to the spent output notifications worker task to monitor.

Header sourcing
---------------

In order to obtain the latest headers, ElectrumSV connects to several servers offering header APIs.
The goal should be to have reliable access to header sources, and to be able to identify servers
that do not run reliably.

Headers:

- A web socket is opened to a minimum number of header servers on behalf of the whole application,
  not any given wallet. The server notifies ElectrumSV of their chain state, and then publishes
  notifications of new headers. ElectrumSV is expected to reconcile and obtain a copy of the
  server's main chain and factor it into whether it should be our main chain.

Arbitrary logic should never fetch headers, the tasks that track headers on different servers
should be the sole method through which headers are fetched. As new chain tips are obtained, other
logic that may be waiting on them, should be notified.

MAPI broadcast
--------------

These are the various ways that wallet transactions might be broadcast:

- Existing transactions in the account history list. The user will likely either use the context
  menu option, or view their transaction dialog and click on the `Broadcast` button. These will
  have one of the :ref:`transaction state <transaction-state>` values of
  ``STATE_RECEIVED``, ``STATE_DISPATCHED`` or ``STATE_SIGNED``.
- The payment the user has just entered and opted to send. This can be done in two slight
  variations. The first is that the user just sends or broadcasts the transaction and they
  have to perform the signing approval as part of this.  The second is that they explicitly
  sign the transaction and then broadcast it. This adds a period of uncertainty between when
  the transaction is added to the database in :ref:`transaction state <transaction-state>`  of
  ``STATE_SIGNED`` and when it is successfully broadcast via MAPI and is changed to the state
  ``STATE_CLEARED``.
- Background petty cash payments by the wallet that the user might not even know are happening
  and will not be involved in approving. These may not even be broadcast via MAPI, and the
  service being paid might take care of the broadcast and merkle proof delivery.

A transaction that has successfully been broadcast using MAPI is excluded from spent output
monitoring and the arbitrary merkle proof fetching. It is expected that there is some processing
that happens that checks these transactions, perhaps periodically, and gives up on the MAPI
callbacks and reclassifies the transaction and introduces it to the spent output
monitoring and the arbitrary merkle proof fetching.

Peer channels:

- Before a transaction is broadcast using MAPI, a peer channel is created on a designated server.
  A custom peer channel URL is provided to the MAPI server and this is used for the merkle proof
  and double spend notifications.

