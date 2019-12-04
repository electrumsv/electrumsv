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

Getting started on Linux/MacOS
==============================

ElectrumSV is a pure python application forked from Electrum. If you want to use the
Qt interface, install the Qt dependencies::

    (LINUX) sudo apt-get install python3-pyqt5
    (MacOS) brew install pyqt5

If you downloaded the source archive (zip or tar.gz), you can run ElectrumSV from its top-level
directory, without installing it on your system.

To run ElectrumSV from its top-level directory, first install the core dependencies::

    pip3 install --user -r contrib/requirements/requirements.txt
    pip3 install --user -r contrib/requirements/requirements-binaries.txt

If you have a hardware wallet, or want to ensure that the hardware wallet support can work,
install their specific dependencies::

    pip3 install --user -r contrib/requirements/requirements-hw.txt

Then invoke it as so::

    ./electrum-sv

You can also install ElectrumSV on your system. This will download and install most dependencies
used by ElectrumSV. This is useful if you with to use the `electrumsv` Python library, perhaps
for Bitcoin application development using ElectrumSV as a wallet server. And of course it should
make the `electrum-sv` command accessible for use.

In order to do so, run these commands::

    pip3 install --user -r contrib/requirements/requirements-binaries.txt
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

Getting started on Windows
==========================

The easiest way to run ElectrumSV on Windows, is to obtain an executable for the latest version
from our website. This Git repository has a `build-hashes.txt` which should contain SHA-256
hashes for all our downloads. You can confirm that you have downloaded a valid file, by comparing
it's SHA-256 hash to the hash we provide for the same file name.

You can also run from the Git repository directly, which is useful if you wish to customise
or help us develop ElectrumSV.

To run ElectrumSV from its top-level directory, first install the core dependencies::

    pip3 install --user -r contrib\requirements\requirements.txt
    pip3 install --user -r contrib\requirements\requirements-binaries.txt

If you have a hardware wallet, or want to ensure that the hardware wallet support can work,
install their specific dependencies::

    pip3 install --user -r contrib\requirements\requirements-hw.txt

Then invoke it as so::

    py -3 electrum-sv

You can also install ElectrumSV on your system. This will download and install most dependencies
used by ElectrumSV. This is useful if you with to use the `electrumsv` Python library, perhaps
for Bitcoin application development using ElectrumSV as a wallet server.

In order to do so, run these commands::

    pip3 install --user -r contrib\requirements\requirements-binaries.txt
    pip3 install .

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

    pylint --rcfile=.pylintrc electrumsv


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
