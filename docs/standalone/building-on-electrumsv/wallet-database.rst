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
