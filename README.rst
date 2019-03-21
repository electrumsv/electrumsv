ElectrumSV - Lightweight Bitcoin SV client
==========================================

::

  Licence: MIT Licence
  Maintainers: Neil Booth, Roger Taylor
  Project Lead: Roger Taylor
  Language: Python (>=3.6)
  Homepage: https://electrumsv.io/

|crowdin_badge| |azurepipeline_badge|

.. |crowdin_badge| image:: https://d322cqt584bo4o.cloudfront.net/electrumsv/localized.svg
    :target: https://crowdin.com/project/electrumsv
    :alt: Help translate ElectrumSV online \
.. |azurepipeline_badge| image:: https://dev.azure.com/electrumsv/ElectrumSV/_apis/build/status/electrumsv.electrumsv?branchName=master
    :target: https://dev.azure.com/electrumsv/ElectrumSV/_build/latest?definitionId=4&branchName=master
    :alt: Build status on Azure Pipelines

Getting started
===============

ElectrumSV is a pure python application forked from Electrum. If you want to use the
Qt interface, install the Qt dependencies::

    sudo apt-get install python3-pyqt5

If you downloaded the official package (tar.gz), you can run
ElectrumSV from its root directory (called Electrum), without installing it on your
system; all the python-only dependencies are included in the 'packages'
directory.

To run ElectrumSV from its root directory, first install the dependencies
which are not python-only::

    pip3 install electrumsv-secp256k1

If your platform is not supported with binary builds, you may be required to install the
`further dependencies <https://github.com/electrumsv/electrumsv-secp256k1>`_ of this dependency.

Then invoke it as so::

    ./electrum-sv

You can also install ElectrumSV on your system, by running these commands::

    pip3 install .
    pip3 install electrumsv-secp256k1

This will download and install all Python-based dependencies used by
ElectrumSV, instead of using the 'packages' directory.

If you are on Windows, and plan to use hardware wallets, you will need to obtain the `libusb`
dlls and put them in the same directory as the `electrum-sv` script. Refer to the Azure Pipelines
files in order to see where ElectrumSV gets it from, and what SHA256 checksum is expected forked
the downloaded archive that includes the DLLs.

If you cloned the git repository, you need to compile extra files
before you can run ElectrumSV. Read the next section, "Development
Version".


Development version
===================

Check out the code from Github::

    git clone https://github.com/ElectrumSV/ElectrumSV
    cd ElectrumSV

Run the pip installs (this should install dependencies)::

    pip3 install .
    pip3 install electrumsv-secp256k1

Compile the protobuf description file::

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/make_locale

Running unit tests::

    py -3 -m unittest discover electrumsv/tests

Running pylint::

    pylint --rcfile=.pylintrc electrumsv


Creating Binaries
=================


To create binaries, create the 'packages/' directory::

    ./contrib/make_packages

This directory contains the python dependencies used by ElectrumSV.

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

See `contrib/osx/`.


Windows
-------

See `contrib/build-wine/`.
