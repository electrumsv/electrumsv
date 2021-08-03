|azureboards_badge| |crowdin_badge| |azurepipeline_badge| |rtd_badge|

.. |azureboards_badge| image:: https://dev.azure.com/electrumsv/dc4594d0-46c9-4b75-ad35-f7fb21ce6933/46962181-6adc-4d37-bf1a-4f3f98c9c649/_apis/work/boardbadge/74437d75-4be7-4c91-8049-518350865962
    :target: https://dev.azure.com/electrumsv/dc4594d0-46c9-4b75-ad35-f7fb21ce6933/_boards/board/t/46962181-6adc-4d37-bf1a-4f3f98c9c649/Microsoft.RequirementCategory
    :alt: Board Status \
.. |azurepipeline_badge| image:: https://dev.azure.com/electrumsv/ElectrumSV/_apis/build/status/electrumsv.electrumsv?branchName=master
    :target: https://dev.azure.com/electrumsv/ElectrumSV/_build/latest?definitionId=4&branchName=master
    :alt: Build status on Azure Pipelines \
.. |crowdin_badge| image:: https://d322cqt584bo4o.cloudfront.net/electrumsv/localized.svg
    :target: https://crowdin.com/project/electrumsv
    :alt: Help translate ElectrumSV online \
.. |rtd_badge| image:: https://readthedocs.org/projects/electrumsv/badge/?version=sv-1.4.0
    :target: https://electrumsv.readthedocs.io/en/sv-1.4.0/?badge=sv-1.4.0
    :alt: Documentation Status

ElectrumSV - Lightweight Bitcoin SV client
==========================================

::

  Licence: Open BSV
  Maintainers: Neil Booth, Roger Taylor, AustEcon
  Project Lead: Roger Taylor
  Language: Python (>=3.9.5)
  Homepage: https://electrumsv.io/

Getting started on Linux/MacOS
==============================

ElectrumSV is a Python-based application forked from Electrum. If you want to use the
graphical user interface, install the Qt dependencies::

    (LINUX) sudo apt-get install python3-pyqt5
    (MacOS) brew install pyqt5

If you are running from the Github repository, you are advised to use the latest release branch,
which at this time is `releases/1.3`. The `master` branch is used for the latest development
changes and is not guaranteed to be as stable, or to have guaranteed long term support for some of
the more advanced features we may have added and later remove.

Ensuring you have at least Python 3.9.5
---------------------------------------

You need to ensure you can use Python 3.9.5, ensure the following command looks like this::

    $ python3 --version
    Python 3.9.5

If you see a lower version, you can use pyenv to install Python 3.9.5. First install pyenv::

    curl -L https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash

Edit your .bashrc file as described, and then ensure the changes are put into effect::

    $ source ~/.profile

Now you can install Python 3.9.5 using pyenv::

    $ pyenv install 3.9.5

If you encounter errors during that process, you can refer to the
`pyenv common problems <https://github.com/pyenv/pyenv/wiki/common-build-problems>`_.

At this point, you should be able to make Python 3.9.5 the default Python on your computer::

    $ pyenv global 3.9.5

And you can check that your `python3` version is indeed 3.9.5, by confirming the following command
now looks like this::

    $ python3 --version
    Python 3.9.5

Ensuring you have at least Sqlite 3.35.4
----------------------------------------

ElectrumSV MacOS and Windows builds come with at least Sqlite version 3.35.4, but there are no
Linux builds, and both Linux and MacOS users may wish to upgrade or make available the Sqlite
version on their computer.

Linux::

    $ python3 -m pip install -U pysqlite3-binary
    $ python3 -c "import pysqlite3; print(pysqlite3.sqlite_version)"
    3.35.4

MacOS::

    $ brew upgrade sqlite3
    $ python3 -c "import sqlite3; print(sqlite3.sqlite_version)"
    3.35.4

You may see a different version displayed than 3.35.4, but as long as it is higher, this is fine.

Installing other dependencies
-----------------------------

Ensure that your ``pip3`` command is associated with the version of Python that you are wanting to
use to run ElectrumSV. Check the following command prints a message that ends with something like
``(Python 3.8)`` that matches your desired Python version::

    pip3 --version

To run ElectrumSV from its top-level directory, first install the core dependencies::

    pip3 install --user -r contrib/deterministic-build/requirements.txt
    pip3 install --user -r contrib/deterministic-build/requirements-binaries.txt

If you have a hardware wallet, or want to ensure that the hardware wallet support can work,
install their specific dependencies::

    pip3 install --user -r contrib/deterministic-build/requirements-hw.txt

Then invoke it as so::

    ./electrum-sv

You can also proceed onward from this point and install ElectrumSV on your system. This will
download and install most dependencies used by ElectrumSV. This is useful if you with to use
the `electrumsv` Python library, perhaps for Bitcoin application development using ElectrumSV
as a wallet server. And of course it should make the `electrum-sv` command accessible for use.

In order to do so, run these commands::

    pip3 install --user -r contrib/deterministic-build/requirements-binaries.txt
    pip3 install .

Problem Solving
---------------

If you choose to use Linux, you introduce complexity and uncertainty into the process. It is not
possible to know all the unique choices you have made regarding it. The following tips may help
work around problems you encounter.

Errors relating to "wheels"
~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you encounter problems referring to wheels, make sure you have installed the wheel package::

    pip3 install --user wheel

Errors relating to "libusb" installing the pip3 requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Install the following::

    sudo apt install libusb-1.0.0-dev libudev-dev

Errors relating to "Python.h"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you encounter problems referring to "Python.h", first check your Python version::

    python3 --version

If it says "3.6", then install the following::

    sudo apt install python3.6-dev

If it says "3.7", then install the following::

    sudo apt install python3.7-dev

If it says a later version of Python, you should be able to figure out what to do.

Scanning QR codes
~~~~~~~~~~~~~~~~~

If you need to enable QR code scanning functionality, install the following::

    sudo apt-get install zbar-tools

Getting started on Windows
==========================

The easiest way to run ElectrumSV on Windows, is to obtain an executable for the latest version
from our website. This Git repository has a `build-hashes.txt` which should contain SHA-256
hashes for all our downloads. You can confirm that you have downloaded a valid file, by comparing
it's SHA-256 hash to the hash we provide for the same file name.

You can also run from the Git repository directly, which is useful if you wish to customise
ElectrumSV or help us develop it.

You need to be sure that you are using a version of Python either 3.9.5 or higher. And that the
version you are using has a version of Sqlite either 3.35.4 or higher. If you are for instance
using a version of Python 3.8 that has a lower version of Sqlite, then update your Python 3.8
installation.

First check that you have the scripts that were installed with Python installation available on
the command-line. You should be able to run the ``pip3`` command. If the ``pip3`` command is
not available:

1. Re-run the installer you used to install the version of Python you are using.
2. Choose the *Modify* option to proceed to the *Optional Features* page.
3. Select the *Next* button to proceed to the *Advanced Options* page.
4. Ensure *Create shortcuts for installed applications* option is checked.
5. Ensure *Add Python to environment variables* is checked.
6. Select *Install*.

To run ElectrumSV from its top-level directory, first install the core dependencies::

    pip3 install --user -r contrib\deterministic-build\requirements.txt
    pip3 install --user -r contrib\deterministic-build\requirements-binaries.txt

If you have a hardware wallet, or want to ensure that the hardware wallet support can work,
install their specific dependencies::

    pip3 install --user -r contrib\deterministic-build\requirements-hw.txt

Then invoke it as so::

    py -3 electrum-sv

You can also install ElectrumSV on your system. This will download and install most dependencies
used by ElectrumSV. This is useful if you with to use the `electrumsv` Python library, perhaps
for Bitcoin application development using ElectrumSV as a wallet server.

In order to do so, run these commands::

    pip3 install --user -r contrib\deterministic-build\requirements-binaries.txt
    pip3 install .

Using ElectrumSV SDK
====================

ElectrumSV is a client application and there is a big advantage to developing against
a local node. This is what the SDK is intended to allow. Both for developers working on ElectrumSV,
developers working on ElectrumSV-based applications and even developers who aren't and just want
a local node and application stack.

To install the ElectrumSV SDK::

    pip3 install electrumsv-sdk

Test that it is installed::

    electrumsv-sdk --version

You should see that the command is found, and a message detailing instructions on the command-line
arguments that can be used with it.

Extra development notes
=======================

Check out the code from Github::

    git clone https://github.com/ElectrumSV/ElectrumSV
    cd ElectrumSV

Run the pip installs (this should install dependencies)::

    pip3 install .

Create translations (optional)::

    sudo apt-get install python-requests gettext
    ./contrib/make_locale

Running unit tests (with the `pytest` package)::

    pytest electrumsv/tests

Running pylint::

    pylint --rcfile=.pylintrc electrum-sv electrumsv

Running mypy::

    mypy --config-file mypy.ini --python-version 3.7


Builds
======

Builds are created automatically for Git commits through the `Azure Pipelines CI`__ services which
Microsoft and Github kindly make available to us.

.. https://dev.azure.com/electrumsv/ElectrumSV/

The easiest way for you to create builds is to fork the project, and to link it to Azure Pipelines
and they should also happen automatically.  If you wish to look at the specific code that
handles a given part of the build process, these will be referenced below for the various
operating systems.  To see how these are engaged, refer to the Azure Pipelines YAML files.

Source Archives
---------------

Run the following to create the release archives under `dist/`::

    ./contrib/make_source_archives.py


Mac OS X / macOS
----------------

See `contrib/osx/`.


Windows
-------

See `contrib/build-wine/`.
