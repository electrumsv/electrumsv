Codebase reference
==================

.. toctree::
   :maxdepth: 1
   :hidden:
   :caption: Codebase reference

   /building-on-electrumsv/codebase-reference/blockchain-headers
   /building-on-electrumsv/codebase-reference/remote-services
   /building-on-electrumsv/codebase-reference/wallet-database

This section aims to provide an overview of how ElectrumSV works. This is useful for us, the
ElectrumSV developers to keep track how things are supposed to work and for programmers who wish to
get involved in the project.

Blockchain headers
    ElectrumSV is a P2P wallet and is limited by the network access the user running it has.
    While in the longer term we will obtain headers from the Bitcoin P2P network if possible,
    in the shorter term we need to focus on consistently reliable ways of obtaining headers.
    At this time headers are obtained via a standard REST API from remote servers. Read more about
    :doc:`how ElectrumSV obtains and uses headers <codebase-reference/blockchain-headers>`.

Remote service usage
    In order to obtain information about the blockchain and the transactions in a wallet,
    ElectrumSV has to make use of remote services. These provide things like the ability to
    broadcast transactions, obtain merkle proofs, obtain transactions and hear about
    relevant changes and data in the blockchain. Read more about what services ElectrumSV
    uses and :doc:`how it uses them <codebase-reference/remote-services>`.

The wallet database
    Each wallet loaded by ElectrumSV is separate and the data is accordingly stored in a
    separate wallet file. Read more about the structure and usage of the data in
    :doc:`the wallet database <codebase-reference/wallet-database>`.
