|azureboards_badge| |crowdin_badge| |azurepipeline_badge|

.. |azureboards_badge| image:: https://dev.azure.com/electrumsv/dc4594d0-46c9-4b75-ad35-f7fb21ce6933/46962181-6adc-4d37-bf1a-4f3f98c9c649/_apis/work/boardbadge/74437d75-4be7-4c91-8049-518350865962
    :target: https://dev.azure.com/electrumsv/dc4594d0-46c9-4b75-ad35-f7fb21ce6933/_boards/board/t/46962181-6adc-4d37-bf1a-4f3f98c9c649/Microsoft.RequirementCategory
    :alt: Board Status \
.. |azurepipeline_badge| image:: https://dev.azure.com/electrumsv/ElectrumSV/_apis/build/status/electrumsv.electrumsv?branchName=master
    :target: https://dev.azure.com/electrumsv/ElectrumSV/_build/latest?definitionId=4&branchName=master
    :alt: Build status on Azure Pipelines \
.. |crowdin_badge| image:: https://d322cqt584bo4o.cloudfront.net/electrumsv/localized.svg
    :target: https://crowdin.com/project/electrumsv
    :alt: Help translate ElectrumSV online

ElectrumSV - Lightweight Bitcoin SV client
==========================================

::

  Licence: Open BSV
  Maintainers: Neil Booth, Roger Taylor, AustEcon
  Project Lead: Roger Taylor
  Language: Python (requires Python 3.9 later than 3.9.13. 3.10 and 3.11 not officially supported)
  Homepage: https://electrumsv.io/

Getting started on Linux/MacOS
==============================

ElectrumSV is a Python-based application forked from Electrum Core.

If you are running from the Github repository, you are advised to use the latest release branch,
which at this time is `releases/1.3`. The `develop` branch is used for the latest development
changes and is not guaranteed to be as stable, or to have guaranteed long term support for some of
the more advanced features we may have added and later remove. The `master` branch is frozen, out
of date and will be overwritten by `develop` evenutally.

Ensuring you have at least Python 3.9.13
----------------------------------------

The ElectrumSV builds are created using Python 3.9.13 because these are the last release for
Python 3.9 that the Python development team do binary releases for. This is the minimum allowed
version of Python to use, we explicitly rule out running against earlier versions and we cannot
guarantee later versions like 3.10 and 3.11 will work reliably due to breaking changes by the
Python language developers.

You need to ensure you have Python 3.9.13 or later, the following command should look like this::

    $ python3 --version
    Python 3.9.16

You can use pyenv to install Python 3.9.16. First install pyenv::

    curl -L https://raw.githubusercontent.com/pyenv/pyenv-installer/master/bin/pyenv-installer | bash

Edit your .bashrc file as described, and then ensure the changes are put into effect::

    $ source ~/.profile

Now you can install Python 3.9.16 using pyenv::

    $ pyenv install 3.9.16

If you encounter errors during that process, you can refer to the
`pyenv common problems <https://github.com/pyenv/pyenv/wiki/common-build-problems>`_.

At this point, you can make Python 3.9.16 the default Python on your computer::

    $ pyenv global 3.9.16

And you can check that your `python3` version is indeed 3.9.16, by confirming the following command
now looks like this::

    $ python3 --version
    Python 3.9.16

Ensuring you have at least Sqlite 3.31.1
----------------------------------------

ElectrumSV MacOS and Windows builds come with at least Sqlite version 3.31.1, but there are no
Linux builds, and both Linux and MacOS users may wish to upgrade or make available the Sqlite
version on their computer.

MacOS::

    $ brew upgrade sqlite3
    $ python3 -c "import sqlite3; print(sqlite3.sqlite_version)"
    3.31.1

Linux::

    $ python3 -m pip install -U pysqlite3-binary
    $ python3 -c "import pysqlite3; print(pysqlite3.sqlite_version)"
    3.31.1

You may see a different version displayed than 3.31.1, but as long as it is higher, this is fine.

Installing other dependencies
-----------------------------

If you are running ElectrumSV from source, first install the dependencies::

MacOS::

    brew install pyqt5
    pip3 install --user -r contrib/deterministic-build/macos-py3.9-requirements-electrumsv.txt

Linux::

    sudo apt-get install python3-pyqt5
    pip3 install wheel
    pip3 install cython==0.29.36
    pip3 install --user -r contrib/deterministic-build/linux-py3.9-requirements-electrumsv.txt

Your should now be able to run ElectrumSV::

MacOS::

    python3 electrum-sv

Linux::

    python3 electrum-sv

You can also install ElectrumSV on your system. In order to do so, run the following command::

    pip3 install . --no-dependencies

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

    sudo apt-get install libusb-1.0.0-dev libudev-dev

Errors relating to "Python.h"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you encounter problems referring to "Python.h", first check your Python version::

    python3 --version

If it says "3.9", then install the following::

    sudo apt install python3.9-dev

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
or help us develop ElectrumSV.

You need to be sure that you are using a version of Python either 3.9.13 or higher. And that the
version you are using has a version of Sqlite either 3.31.1 or higher. If you are for instance
using a version of Python 3.8 that has a lower version of Sqlite, then update your Python 3.8
installation.

To run ElectrumSV from its top-level directory, first install the core dependencies::

    py -3.9 -m pip install --user -r contrib/deterministic-build/win64-py3.9-requirements-electrumsv.txt

Then invoke it as so::

    py -3.9 electrum-sv

You can also install ElectrumSV on your system. This will download and install most dependencies
used by ElectrumSV. This is useful if you with to use the `electrumsv` Python library, perhaps
for Bitcoin application development using ElectrumSV as a wallet server.

In order to do so, run these commands::

    pip3 install . --no-dependencies

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

    mypy --config-file mypy.ini --python-version 3.9


Builds
======

Builds are created automatically for Git commits through the Azure Pipelines CI services which
Microsoft and Github kindly make available to us.

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
