Blockchain headers
==================

ElectrumSV is intended to be a P2P application. It should not be required to use external servers
provided by an ElectrumSV business. The device the user runs ElectrumSV on is where their wallet
state is kept and managed. This has repercussions that other wallets that are not P2P are not
subject to.

Possible limitations:

- The network the device is connected to may not allow access to the Bitcoin P2P network.
- The network the device is connected to may not allow non-HTTP internet access.
- The network the device is connected to may not allow incoming connections.
- The user may take their device with them to different networks with different limitations.

These influence ElectrumSV's approach to sourcing blockchain headers.

Header sources
--------------

The current policy is:

- If a blockchain service provider is used, use it as the authoritative source of a longest chain
  to ensure that acquired blockchain state is relevant to the any fork the wallet may be following.
- Connect to all known header servers.

Longer term option we think will be employed:

- Limit connections to perhaps ten concurrent header servers.
- If the Bitcoin P2P network is connectable, use it as a possible source of a longest chain, as
  long as there is no blockchain server. The user should be able to override it in order to rule
  out invalid malicious chains, and to ensure they are following a valid chain. If the blockchain
  server is being used as the authoritative header source, the P2P network can be used for
  comparison purposes.

The Bitcoin P2P network
~~~~~~~~~~~~~~~~~~~~~~~

At this time ElectrumSV does not connect to the P2P network to listen to headers, or to broadcast
transactions. In the longer term this will be the default approach, but there are other priorities
for now.

HTTP-based Header APIs
~~~~~~~~~~~~~~~~~~~~~~

Due to the some of the limitations mentioned above, ElectrumSV cannot rely on users reliably
having the ability to access the Bitcoin P2P network. It needs to have the ability for users
to get headers from remote HTTP-accessed services, either run by trusted parties or the user
themselves.

Wallet behaviour
----------------

Following a header source
~~~~~~~~~~~~~~~~~~~~~~~~~

A wallet follows a header source. When it changes header sources, or the header source switches
forks to another chain tip, the wallet performs a reorganisation.

If the wallet is relying on the services provided by a blockchain service provider, it must follow
the header API provided by that service. That service will be providing data tied to their chosen
chain tip, and when it switches chain tips (reorgs) providing data tied to the new chain tip.

Observing other header sources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If a wallet is following the longest known chain from the P2P network this is straightforward. If
a wallet is following a blockchain service provider then it has to follow that provider no matter
what to ensure the data it obtains from the service is relevant.

The header state of any other service provider can be observed and used to prompt the user to
switch service providers, if it looks like their current one is ill-managed or broken and not
fixed in a prompt manner.

The header state of the P2P network can also be observed and used to evaluate the reliability of
service providers.
