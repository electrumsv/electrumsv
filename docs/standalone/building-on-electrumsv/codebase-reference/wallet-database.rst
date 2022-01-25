The wallet database
===================

Each wallet is stored in it's own SQLite database. The current version of ElectrumSV at the time of
writing, 1.4.0b1, uses the database schema version 28. This schema is include for reference
purposes and cannot be used to a working wallet.

Each version of ElectrumSV includes migration code that applies any needed changes to older
versions of the wallet. This database format is pretty solid at this point, but it is a work in
progress. There are many other things ElectrumSV will need to support in the future.

Transactions and atomicity
--------------------------

Between how `SQLite <https://www.sqlite.org/lockingv3.html>`_ works, how the
`Python sqlite3 module <https://docs.python.org/3/library/sqlite3.html#controlling-transactions>`_
works and how ElectrumSV builds upon both of these some elaboration is needed.

We pass the ``isolation_level=None`` parameter to the Python sqlite3 function that opens a
database connection. This overrides the custom way the Python sqlite3 module overrides how
SQLite works and returns it to the autocommit mode. This mode means that statements that
modify the database take effect immediately. Use of a ``BEGIN`` and ``SAVEPOINT`` statement
takes Sqlite out of autocommit mode, and the outermost ``COMMIT``, ``ROLLBACK`` or ``RELEASE``
statement returns Sqlite to autocommit mode.

ElectrumSV does all of it's database writes in custom transactions starting with the ``BEGIN``
statement, disabling the autocommit mode, and bundling the writes into groups with the
ability to commit them all or roll them all back. Additionally as SQLite does not allow
multiple connections to do
`concurrent writes <https://sqlite.org/src/doc/begin-concurrent/doc/begin_concurrent.md>`_,
ElectrumSV takes a well known approach of having a sequential writer thread. All writes happen
in a dedicated writer thread one after the other as managed transactions.

The following logic is used to wrap each ElectrumSV transaction:

.. code-block:: python

    def __call__(self, db: sqlite3.Connection) -> None:
        if not self._future.set_running_or_notify_cancel():
            return

        db.execute("BEGIN")
        try:
            result = self._fn(db, *self._args, **self._kwargs)
        except BaseException as exc:
            db.execute("ROLLBACK")
            self._future.set_exception(exc)
            # Break a reference cycle with the exception 'exc'
            self = None # type: ignore
        else:
            db.execute("COMMIT")
            self._future.set_result(result)

Synchronous writes
~~~~~~~~~~~~~~~~~~

The Python ``concurrent.futures`` module is used in synchronous logic to do database writes
in a non-blocking manner. The calling thread can block until the write is complete by calling
the `Future.result <https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.Future.result>`_
method. Or the calling thread can request a callback through the use of the
`Future.add_done_callback <https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.Future.add_done_callback>`_.

.. caution::
   Futures catch and log exceptions in their callbacks, preventing ElectrumSV from catching and
   reporting them. This means that the Future callbacks need to be certain they know about all
   possible exceptions and to catch and handle them all. Developers should be very sure they
   understand the code they are calling.

Synchronous database calls are performed in this manner:

.. code-block:: python

    def on_db_call_done(future: concurrent.futures.Future[bool]) -> None:
        # Skip if the operation was cancelled.
        if future.cancelled():
            return
        # Raise any exception if it errored or get the result if completed successfully.
        future.result()
        self.events.trigger_callback(WalletEvent.TRANSACTION_DELETED, self._id, tx_hash)

    future = db_functions.remove_transaction(self.get_db_context(), tx_hash)
    future.add_done_callback(on_db_call_done)

Asynchronous writes
~~~~~~~~~~~~~~~~~~~

How ElectrumSV wraps asynchronous calls is done in the ``DatabaseContext.run_in_thread_async``
method. If you wish to see how it works, you can look in the ``sqlite_support.py`` file.

Asynchronous database calls are performed in this manner:

.. code-block:: python

    if await update_transaction_flags_async(db_context, tx_hash,
            TxFlags.STATE_SETTLED, ~TxFlags.MASK_STATE):
        ...

Database schema
---------------

This is version 28 of our database schema. It should be correct for the ElectrumSV version
this documentation is intended for, but if it is not, please let us know.

.. literalinclude:: database/28.sql
    :linenos:
    :language: sql

Details
-------

For now various details about the database schema are kept below, but as we flesh it out it
should end up being restructured.

Transaction table
~~~~~~~~~~~~~~~~~

.. _transaction-state:

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
