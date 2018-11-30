Electrum SV - Lightweight Bitcoin SV client
=====================================

::

  Licence: MIT Licence
  Author: Roger Taylor
  Language: Python
  Homepage: https://electrumsv.org/


.. image:: https://d322cqt584bo4o.cloudfront.net/electrum-sv/localized.svg
    :target: https://crowdin.com/project/electrum-sv
    :alt: Help translate Electrum SV online

Getting started
===============

Electrum SV is a pure python application forked from Electrum. If you want to use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

If you downloaded the official package (tar.gz), you can run
Electrum SV from its root directory (called Electrum), without installing it on your
system; all the python dependencies are included in the 'packages'
directory. To run Electrum SV from its root directory, just do::

    ./electrum-sv

You can also install Electrum SV on your system, by running this command::

    sudo apt-get install python3-setuptools
    python3 setup.py install

This will download and install the Python dependencies used by
Electrum SV, instead of using the 'packages' directory.

If you cloned the git repository, you need to compile extra files
before you can run Electrum SV. Read the next section, "Development
Version".



Development version
===================

Check out the code from Github::

    git clone https://github.com/Electrum-SV/Electrum-SV
    cd Electrum-SV

Run install (this should install dependencies)::

    python3 setup.py install

Compile the icons file for Qt::

    sudo apt-get install pyqt5-dev-tools
    pyrcc5 icons.qrc -o gui/qt/icons_rc.py

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/make_locale

For plugin development, see the `plugin documentation <plugins/README.rst>`_.

Running unit tests::

    pip install tox
    tox

Tox will take care of building a faux installation environment, and ensure that
the mapped import paths work correctly.

Creating Binaries
=================


To create binaries, create the 'packages/' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by Electrum SV.

The `make_packages` command may fail with some Ubuntu-packaged versions of
pip ("can't combine user with prefix."). To solve this, it is necessary to
upgrade your pip to the official version::

    pip install pip --user

Linux (source with packages)
----------------------------

Run the following to create the release tarball under `dist/`::

    ./setup.py sdist

Mac OS X / macOS
--------

See `contrib/build-osx/`.

Windows
-------

See `contrib/build-wine/`.

iOS
-------

See `ios/`.
