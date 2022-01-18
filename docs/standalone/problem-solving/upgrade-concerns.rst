Using older versions
====================

The ElectrumSV developers only support the latest officially released version and do not provide
support for older versions. You can continue to use older versions without our support, but they
may stop working unless you are willing to invest a lot of time and effort. Do not contact us
about this. We are more than willing to offer support if you upgrade to the latest officially
released version and observe the same problems there.

You need a server
-----------------

Versions of ElectrumSV before 1.4.0 use an open source server project called
`ElectrumX <https://github.com/kyuupichan/electrumx>`_. Most
users do not even pay much attention to the fact that generous community members and businesses
run these servers for them to use for free. While a blockchain is small and rarely used, this
was feasible. But as blocks get larger and larger, it will become impractical and expensive for
people to casually run these servers.

No-one will be running these ElectrumX servers and your wallet will not be able to:

- Detect any incoming or outgoing payments.
- Broadcast any transactions.
- Do pretty much anything other than work as if it were offline.

If you want the wallet to work you will need to run your own ElectrumX server, or pay someone
else to run the server for you. This will require additional programming work to deal with all
the indexing needs and the indexed blockchain data, as the blocks get bigger and bigger and
the blockchain data accrues.

Your responsibility
-------------------

If you do not upgrade to the latest version of ElectrumSV, then you are responsible for any
problems you have. You are responsible for the time, effort and costs in running the required
servers when the existing ones finally go down.