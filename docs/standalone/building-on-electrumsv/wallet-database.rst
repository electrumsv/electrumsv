The wallet database
===================

Each wallet is stored in it's own SQLite database. The current version of ElectrumSV at the time of
writing, 1.4.0b1, uses the database schema version 28. This schema is include for reference
purposes and cannot be used to a working wallet.

Each version of ElectrumSV includes migration code that applies any needed changes to older
versions of the wallet. This database format is pretty solid at this point, but it is a work in
progress. There are many other things ElectrumSV will need to support in the future.

Database schema
---------------

.. literalinclude:: database/28.sql
    :linenos:
    :language: sql

Details
-------

For now various details about the database schema are kept below, but as we flesh it out it
should end up being restructured.

Transaction table
~~~~~~~~~~~~~~~~~

`flags`
!!!!!!!

*STATE_SIGNED*

A fully signed transaction that is expected to not have been shared with external parties.

*STATE_DISPATCHED*

A transaction that has been shared with external parties, but is not expected to have been
broadcast to the P2P network.

If this is determined to have been broadcast, then additional as yet implemented handling should
be done to reconcile how to react to this event.

*STATE_RECEIVED*

A transaction that an external party has shared, but is not expected to have been broadcast to
the P2P network.

If this is determined to have been broadcast, then additional as yet implemented handling should
be done to reconcile how to react to this event.

*STATE_CLEARED*

A cleared transaction is one that is known to have been broadcast to the P2P network.

Nuances:

- `block_hash` will be `NULL` for transactions that have been broadcast. `block_position` and
  `proof_data` will also be `NULL`.
- `block_hash` will be non-`NULL` to represent knowledge that it has been mined (via non-MAPI
  channels) and that we should fetch a merkle proof to verify it is in a given block.
  `block_position` and `proof_data` will be `NULL`.
- `block_hash`, `block_position` and `proof_data` will all have valid unprocessed values if
  the application headers do not include the given block height yet.

*STATE_SETTLED*

A settled transaction is one that is known to have been mined in a block, and has been verified
as being in that block through checking the merkle proof.

Nuances:

- `proof_data` will be non-NULL for up-to-date verified transactions.
- `proof_data` will be `NULL` for transactions after migration 29, as the previous non-TSC merkle
  proofs are just deleted with the intention that the user will update them to TSC merkle proofs
  via some service that offers arbitrary merkle proofs.
