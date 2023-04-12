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

Output spends API (forwarded)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
   The ElectrumSV project has neither the manpower or the interest in providing a non-regtest
   open source implementation of this API. Commercial services can if they choose, offer it,
   as an optional enabled API provided by their servers.

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

As we rely on output spends for events related to transactions we did not broadcast ourselves, we
just use output spends consistently for the transactions we do as well. We do not use the merchant
API for MAPI callbacks.

Restoration API (forwarded)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
   The ElectrumSV project has neither the manpower or the interest in providing a non-regtest
   open source implementation of this API. Commercial services can if they choose, offer it,
   as an optional enabled API provided by their servers.

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
   The ElectrumSV project has neither the manpower or the interest in providing a non-regtest
   open source implementation of this API. Commercial services can if they choose, offer it,
   as an optional enabled API provided by their servers.

As the blockchain grows larger and larger, storage and access to arbitrary transaction data
becomes a specialised service that will likely require charging for access to data. The
transaction API is provided for requesting arbitrary transactions.

Merkle proof API (forwarded)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::
   The ElectrumSV project has neither the manpower or the interest in providing a non-regtest
   open source implementation of this API. Commercial services can if they choose, offer it,
   as an optional enabled API provided by their servers.

While we currently broadcast all transactions through a merchant API server, and a callback
from that server can notify if the transaction is mined and provide the merkle proof. Not all
transactions related to an ElectrumSV user's wallet are broadcast by that user through MAPI.
Other parties may broadcast the transaction, and this may not be desirable, expected or have any
channel through which the ElectrumSV user can hear about the merkle proofs availability.

It is necessary to have the ability to request arbitrary merkle proofs, and the merkle proof
API is used for this purpose. We use it for both the broadcaster who uses MAPI and for the party
who has received an event notifying a transaction of interest was included in a block.

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
- We monitor transactions that we know have been broadcast but we do not know if they are mined.
  These have the :ref:`transaction state <transaction-state>` value of ``STATE_CLEARED`` with no
  associated block.

Merkle proofs:

- If we have transactions that have been broadcast and mined, but which we have not obtained the
  merkle proof for, we pass them in a worker task that will take care of this. These will likely
  be transactions we received spent output state for, which we have not had the chance to process
  yet. These have the :ref:`transaction state <transaction-state>`
  value of ``STATE_CLEARED`` with an associated block.
- If we have transactions from before ElectrumSV 1.4.0 they may not have a TSC standardised
  merkle proof. We pass these to a worker task to take care of obtaining them. These have the
  :ref:`transaction state <transaction-state>` value of ``STATE_SETTLED`` with no
  associated block. Wallets that were created in ElectrumSV and not earlier versions of the
  Electrum wallet will most likely have non-TSC proofs which will get converted to the TSC form
  as part of the wallet file upgrade.

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

There are two steps, signing a transaction and broadcasting it. The user can construct a
transaction and sign it, then it gets added to their account history. In this case, we want to
treat it as a local transaction and monitor it using the spent output API.  If it gets signed and
then broadcast, we would also monitor it using the spent output API.

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

Reliable server usage
!!!!!!!!!!!!!!!!!!!!!

The core requirement of ElectrumSV relying on servers for remote state is that we do our best to
handle all the reasonable problems in a way where the user is either unaware or presented with
minimal complication because of them. Unreasonable problems however, we do not need to be so
concerned about. We can try and take measures to prevent the user shooting themselves in the foot
but if they do things that are unsafe they may have to pay a third party service to recover
their wallet data.

The general approach
--------------------

There are four possible stages in using a service:

1. Poll for the state of any existing service usage and verify that the state on the service
   matches the state the wallet has.
2. Establish a web socket connection.
3. Register any per-connection service usage related to that web socket connection.
4. Make on-going requests.

Whether there is a successfully connected web socket or no web socket we will make ongoing requests:

* Requesting data or current state.
* Request short-term notifications for events for the life of the current connection.
* Requesting long-term notifications for events delivered via peer channels.

Handling problems establishing a connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are three potential problems that could be encountered when polling for state on the service
or establishing a web socket connection:

1. Inability to establish a connection.
2. Unexpected result when accessing an API endpoint.
3. The received state does not match the state the wallet has.

The first failure case when establishing a connection should cancel the whole process and any
other concurrently made API calls, and display a "server connection problems" UI to the user.
It is not required that the user already has a modal dialog showing connection progress but if
they do the problems should be incorporated into that existing UI. If they do not, then a UI
should be shown for that purpose.

The second failure case should render the server unusable. The server should be flagged
as broken, and the user should be informed of the problem and given options to deal with it.

The third failure case should attempt to reconcile the state. It might be that this is expected
because the user has not used the service for a long time, and any prepayment they made to
engage long term services like tip filter registrations and peer channels has lapsed. The user
would need to go to the payer and obtain the transaction they were watching for, pay extra for
any merkle proofs and so on. However it might also be because the user has been operating the
server with multiple copies of the wallet which will inevitably confuse one or more of those
copies. This will be covered elsewhere.

Handling problems making API requests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An API endpoint should be expected to just work. There are two potential problems:

1. Inability to establish a connection.
2. Unexpected result when accessing an API endpoint.

These can be handled the same as suggested in the establishing a connection section. It may be that
the API usage is not done with a specific server, and that it is possible for ElectrumSV to
just handle it without bothering the user by switching to another server behind the scenes.
If the API usage is with a specific server, then this is problematic and will involve notifying
the user and having them explicitly make a choice.

Special case HTTP response status codes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a request to an API endpoint receives one of these status codes, it is not an unexpected
result. It is also not ideal and we should have some standard way of handling them.

401 - UNAUTHORIZED
^^^^^^^^^^^^^^^^^^

Use of the given API endpoint requires authentication and the client has not provided that
authentication. This response should only be encountered if for some reason the current
authentication token is no longer valid and it needs to be renewed.

402 - PAYMENT_REQUIRED
^^^^^^^^^^^^^^^^^^^^^^

Use of the given API endpoint requires payment and there is insufficient funding remaining to
cover the requested server activity. ElectrumSV should automatically fund the channel from the
relevant petty cash account, limiting server usage until this is done. It may require user
notification or intervention. The implementation should be expected to try and predict this
ahead of time and prevent the user doing actions that may be problematic if there is insufficient
funding to complete them.

429 - TOO_MANY_REQUESTS
^^^^^^^^^^^^^^^^^^^^^^^

If a server implements a free quota it should return this response when the quota is used up.
Ideally ElectrumSV will have some idea of how large the quota is, what it permits and how close
it is to being used up. It can then inform the user if desired actions are not possible because
the quota is spent.

Indexer services
----------------

Most of the indexer services are stateless, and there are not many things that need to be
checked for consistency as part of the connection process.

Consistency actions:

* List the tip filter registrations.

Tip filter registrations
~~~~~~~~~~~~~~~~~~~~~~~~

Possible problems:

* A tip filter no longer exists due to lack of funding.
* A tip filter no longer exists with no identifiable reason.

Lack of funding
^^^^^^^^^^^^^^^

This should not happen as the initial use of this service will be for a specific purpose
with a known time limit. The user will be creating a receving address or script to give out to
the payer, and wanting to know when a transaction featuring that payment destination is
broadcast. ElectrumSV can prepay for that period guaranteeing that any reliable service will
monitor for the transaction for the expected amount of time. It can also default to a time
period that reflects the longest any reliable payer should have broadcast by and warn the user
if they choose a shorter time of the risks.

In the event that the payer does not send in a timely fashion and the payment is not detected
this is problematic in theory, but not in practice. In theory ElectrumSV then needs to pay for
a costly scan of the blocks that have been mined since they gave out the payment destination. In
practice existing businesses that pay this way already show the transaction id in the user's
account and the user can use that to cheaply manually instruct ElectrumSV to obtain the
transaction.

ElectrumSV should likely do the following:

* Ensure a tip filter is put in place (unless the user has opted not to).
* If a tip filter is put in place ensure the user accepts the expiry time as the latest time
  the payment transaction will be detected.
* If a payment can be made with no tip filter or after that expiry time that they know whether
  they can obtain the transaction id directly from the payer.

No identifiable reason
^^^^^^^^^^^^^^^^^^^^^^

A tip filter no longer being present when it should be would likely only be possible because of
a server error or the ElectrumSV user doing things they shouldn't.   The
user who causes this problem will likely have done something like open two copies of the wallet
or an outdated copy of the wallet.

A peer channel no longer being present could be because of a server error. Any service where this
happens likely has more widespread problems and will gain a reputation of being unreliable. If it
is a reliable service it has a vested interest in scanning recent blocks and detecting missed
filter matches, in order to make it right. And it should likely do this proactively as soon as
it detects the problem.

An ElectrumSV user may be able to do things that the wallet does not support, which could
result in this happening. A possible example is where they open a backup of the wallet file and
it has no way of recovering what was missing or even knowing what was missing, and corrupts
service usage of the up-to-date version of the wallet. ElectrumSV should do everything it can
to detect and disallow this from happening, but it might be that the user chooses to proceed
anyway or they find a new way to cause this problem.

Peer channel hosting
--------------------

Peer channels are a stateful service. The user needs the channels they have created to be alive
long enough for the channel to receive any incoming message and for ElectrumSV to identify the
presence of that message and fetch it.

Consistency actions:

* List the peer channels on the server.

Peer channel existence
~~~~~~~~~~~~~~~~~~~~~~

Possible problems:

* A channel no longer exists due to lack of funding.
* A channel no longer exists with no identifiable reason.

Lack of funding
^^^^^^^^^^^^^^^

This should not happen unless the user does not open their wallet for a prolonged period of time.
If the channel hosting service is professional, then the user should also be able to register
for out of band notifications perhaps to their email address in event of low funding.

ElectrumSV should clearly illustrate to the user that there are time limits to when they need
to revisit their service usage and top up payments.

No identifiable reason
^^^^^^^^^^^^^^^^^^^^^^

A peer channel no longer being present when it should be is a server error. The server cannot
recover messages it never received nor should it receive messages it thinks it does not expect.

An ElectrumSV user may be able to do things that the wallet does not support, which could
result in this happening. A possible example is where they open a backup of the wallet file and
it has no way of recovering what was missing or even knowing what was missing, and corrupts
service usage of the up-to-date version of the wallet. ElectrumSV should do everything it can
to detect and disallow this from happening, but it might be that the user chooses to proceed
anyway or they find a new way to cause this problem.
