Data directories
================

.. _data-directories:

Wallet data is stored in what is called the ElectrumSV data directory. When the application
starts up, it looks for the data directory in an expected location, and creates it if it does not
already exist.

Standard locations
------------------

Unless the user overrides the default behaviour, the data directory will be on a standard location.

On Linux and MacOS, this will be what is called a hidden folder (it starts with the dot
character ".") in the user's home directory always named ``.electrum-sv``. This should be easy
to find.

.. code-block:: console
    :caption: Linux / MacOS

    $ ls -a ~/ | grep elec
    .electrum-sv

On Windows, this will be within the user's application data directories. We currently store
most of the application data in the ``Roaming`` directory and the logs in the ``Local`` directory.
As log files may become quite large in the more verbose debugging levels, these are placed
where they won't be synchronised between computers. This is a little harder to find, but by
substituting your user name for "Bob" below you should be able to find it.

.. code-block:: doscon
    :caption: Windows

    C:\Users\Bob>dir AppData\Roaming\Elec*
    ...
     Directory of C:\Users\Bob\AppData\Roaming

    28/10/2022  08:54 AM    <DIR>          ElectrumSV


    C:\Users\Bob>dir AppData\Local\Elec*
    ...
     Directory of C:\Users\Bob\AppData\Local

    25/10/2022  06:47 AM    <DIR>          ElectrumSV

Custom locations
----------------

The simplest way to control where your ElectrumSV data directory is located is to use the
portable download we provide, this creates and uses an ``electrum_sv_data`` data directory in the
same directory as the portable build executable is located in.

It is also possible to run ElectrumSV from either the source code or our non-portable build, and
to tell it where to look for and place it's data directory. This can be done with the ``-D``
command-line parameter.

.. code-block:: console
    :caption: Linux / MacOS

    $ ./electrum-sv -D INSTANCE1
    2022-11-25 12:59:34,966:INFO:rest-server:REST API started on http://127.0.0.1:9999
    ...
    $ ls | grep INSTANCE
    INSTANCE1

.. code-block:: doscon
    :caption: Windows

    C:\Data\Git\electrumsv>py electrum-sv -D INSTANCE1
    2022-11-25 12:59:34,966:INFO:rest-server:REST API started on http://127.0.0.1:9999
    ...
    C:\Data\Git\electrumsv>dir INSTANCE
    ...
     Directory of C:\Data\Git\electrumsv

    25/11/2022  12:59 PM    <DIR>          INSTANCE1

.. note::

    Only one instance of ElectrumSV can be run at a time. The way this is enforced is through
    the data directory, and as by default an application instance will use the standard location
    only the first instance will run and any subsequent instance will exit. However, if each
    subsequent instance is directed to use a custom data directory, they will run at the same time.
