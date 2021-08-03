Initial key allocation policy
#############################

:Date: 2020-12-17

Context
-------

If the database is to be the arbiter of which existing keys are available for allocation, and which
existing keys are already allocated, we need to pre-emptively allocate keys before we use them.
This may leave open the chance that we allocate keys that we do not end up using, and that in turn
may create gaps in the allocation sequence where there was no key usage. When these gaps are larger
than the BIP32 gap limit, then this may make discovery of key usage by enumerating them and asking
an indexer if usage exists more involved than it was when gaps were expected to be limited.

If keys are allocated but usage does not happen, then we need to decide if we are going to reclaim
the keys and use them for some other purpose. Or are we okay with arbitrary gaps wherever they have
to occur due to circumstance?

Decision
--------

We should only ever attempt to reclaim keys if we are sure they were never used. And we should
never reclaim keys if they have been shared outside of the wallet. Minimising gaps in the
derivation sequences is no longer important, and no effort should be made to do so to aid
later indexer-based wallet recovery.

Consequences
------------

* If we remove linked records from the database that are the usage of an allocated key, then we
  need to make sure that this does not make a key available for recycling. In most cases this
  will be prevented as any allocation should be followed up by usage in a transaction, but this
  is not guaranteed. Examples might be where we allocate a key for usage in payment by an external
  party, but the external party never makes payment. This reveals the key to that external party
  and any subsequent reclaimation for other uses identifies usage of the user's wallet to that
  external party. Deleting the invoice, would leave no original transaction output in place because
  the external party never paying, never resulted in one.
* Gap limits can no longer be used for techniques like seed-based restoration. This is not a real
  problem as there are other solutions for restoration, like tagged transactions with encrypted
  payloads that can have gap-less sequences with the furthest found containing the latest
  update.
