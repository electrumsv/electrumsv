Database writes with SQLite
###########################

:Date: 2020-12-04

Context
-------

SQLite does not allow two connections to write to the database at the same time. This results in
the second connection erroring::

    OperationalError: database is locked

Decision
--------

A writer thread was created and all database writes during the user-driven operation of the
application are queued for this writer thread to execute against it's database connection.

Consequences
------------

* We no longer see these errors and everything just works, where before this solution was deployed
  it was possible for database writes to error sporadically.
* This is a custom solution. As more and more systems are built on top of it, it makes it
  harder to move away from it.
