Release process
===============

There are a lot of steps to releasing a new version of ElectrumSV. This document is intended to
lay out the entire proces and some of the reasoning behind it, so that any developer can jump in
and do a release if necessary. In addition, formalising the release process ensures that nothing
is accidentally left out due to any informal and casually documented process leading to an
oversight of various steps.

Initial preparation
-------------------

When it is time to release a new version, the first step is to freeze the release branch in
Github and prevent introduction of any changes that introduce new functionality or change
existing functionality. This is an exercise in self restraint, rather than anything that is
done to programmatically disallow these changes to be made.

Writing an article
~~~~~~~~~~~~~~~~~~

An initial outline of a release article is written, including the featured changes that will be
highlighted. Mostly this involves taking the last article, removing all the changes that were
included in the previous version, and putting the new version's changes in their place using the
same format. The key goal of these articles is to illustrate these changes and help users visualise
them even if they skim through the article, and it should include screenshots at every possible
opportunity.

For each change featured in a release article:

- A link should be provided to any issue that exists in relation to that change.
- A link should be provided to every code change made to the source code in the making of the
  given change.

Updating the version
~~~~~~~~~~~~~~~~~~~~

The version number is increased to the new version number, and the approximate release date is
updated to be approximately what it will be when the release is made. If the release process is
protracted over many days due to the testing, and any subsequent changes they require, then the
date may be modified later.

If the last version was ``1.3.6``:

- Find all ``1.3.6`` references and replace them with the new version ``1.3.7``.
- Find all ``1-3-6`` references. These will be in links to the release article for the previous
  version. The link should be replaced with the link to the new article.

Writing release notes
~~~~~~~~~~~~~~~~~~~~~

There are two places that changes are documented in the source code. The first is a HTML-based
summary that is accessible from the splash screen that ElectrumSV shows when it starts up. The
second is the text-based formal ``RELEASE-NOTES`` file in the top level of the source code.

The HTML-based summary is intended to be a list of user focused descriptions of the main changes
in the release. It lists the same changes as those chosen for the release article.

The ``RELEASE-NOTES`` file is intended to be developer oriented, and should attempt to list all
the changes made and included in the release.

Pre-build testing
-----------------

There are two different kinds of pre-build testing, both manual and automatic. The manual tests
are primarily those which involve a user checking the user interface works as it should. The
automatic tests ensure the code is correct as it is possible for such a tool to detect, and
that when asked to perform processes the outcomes of those processes are as they should be.

User interface testing
~~~~~~~~~~~~~~~~~~~~~~

There is a checklist of common use cases for ElectrumSV that the user interface is manually stepped
through. New accounts are created, keys and seeds are imported, invoices are paid, hardware wallets
are plugged in and out and most if not all of the menu options are used in order to ensure they
still work.

.. note::

   TODO: Reference manual user interface testing documents.

As bugs, problems or small aspects that can be improved are identified, they are fixed and the
relevant user interfaces are retested. Along these lines, if intuitively something does not quite
seem like it is working, time is spent to work out why.

Code analysis
~~~~~~~~~~~~~

As a part of normal development, before code changes are committed to the Github source code
repository, developers are expected to run code quality tools. If they push the changes to
Github and they have made changes that do not meet code quality standards, then the CI process
will do those same checks and error. The changes made to both prepare the release and fix any
problems observed in the user interface should be tested by the developer.

mypy
^^^^

Python is a programming language with optional typing. For users who choose to use
typing, this tool can then try and work out if the code that uses those types is buggy or
incorrect.

Running mypy on Windows, Linux or MacOS:

.. code:: doscon

   mypy --config-file mypy.ini --python-version 3.7

pylint
^^^^^^

This tool checks for general code correctness and common errors, and warns the
developer if it finds any.

Running pylint on Windows, Linux or MacOS:

.. code:: doscon

   pylint --rcfile=.pylintrc electrum-sv electrumsv

Unit testing
~~~~~~~~~~~~

The existing collection of unit tests ensure that a range of processes work correctly. This
includes how the code handles different kinds of accounts, migration of wallets from older
versions to newer versions, old Electrum seed words, new Electrum seed words, BIP39 seed
words, different key types and so on. Running these against lower level changes can often help
detect regressions or oversights made in implementing those changes.

Running the unit tests on Windows:

.. code:: doscon

   pytest electrumsv\tests

Running the unit tests on Linux or MacOS:

.. code:: console

  pytest electrumsv/tests


Building the release
--------------------

The continuous integration (CI) service is hooked up to Github. Every time a set of changes are
pushed to Github it automatically triggers the CI to test and build those changes. Every build
results in what are called a set of artifacts, which are the executables and archives produced
as a result of that build. If the developer adds a Git tag structured in a way to designate a
release version to the changes they push, then this modifies the build process and produces an
official versioned set of build artifacts.

Tagging the latest code as a potential stable release of a ``1.3.7`` version:

.. code:: console

   git tag sv-1.3.7

The developer then pushes both the latest code and the tag to Github, both separately, and in that
order:

.. code:: console

   git push
   git push --tags

A build is only triggered if unpushed code changes are pushed. And the build only looks for
the release tag at the start. So the developer needs to push unpushed code changes, and then the
new release tag in quick succession.

Build errors
~~~~~~~~~~~~

The build runs all the tests that the developer should run before they push the final changes.
If they fail, or their development tools are out of date, this might mean that either the developer
did not run the tests correctly or that the developer needs to update their tools.

Recapping the automated tests employed:

- The unit tests.
- The functional tests.
- Pylint for style and correctness checking.
- Mypy for type checking.

If there are build errors or the build needs to be rerun, the developer needs to delete the tag
and recreate it, and push a new tag with additional code changes to trigger a new build.

Deleting the local tag for a ``1.3.7`` release:

.. code:: console

   git tag --delete sv-1.3.7

Deleting the remote tag for a ``1.3.7`` release:

.. code:: console

   git push origin --delete sv-1.3.7

Testing the build
~~~~~~~~~~~~~~~~~

Once a successful candidate build has been made, the build artifacts are downloaded. One
artifact is deleted, the Windows installer which is named with the ``-setup.exe`` suffix.
At this time we do not support this or test it, and in the longer term we will provide this
in the form of a Windows Store application.

The build testing is not extensive. If a build executable runs and the wallet user interface
appears, then all testing of both functionality and user interface within the pre-build
testing will represent how the build behaves.

Linux
^^^^^

There are no Linux builds at this time, so there is no need for testing at this stage.

.. note::

   If a member of the community creates an AppImage build process that is of sufficient
   quality, we would be willing to help them maintain it and use it in producing official Linux
   builds.

MacOS
^^^^^

The build is downloaded to a MacOS device, and run.

The following trivial steps are tested:

1. Funds are sent to the wallet on the MacOS device.
2. The funds are then sent back out to an external wallet.

Windows
^^^^^^^

There are two builds on Windows, a portable build and a non-portable build. A quick recap on
the difference is that the portable build stores it's data in a directory local to the portable
build executable. The non-portable build stores it's data in the user's application data
directory.

The following trivial steps are tested for the non-portable build:

1. Funds are sent to the wallet on the MacOS device.
2. The funds are then sent back out to an external wallet.

The non-portable build is merely started, and if the user interface appears and the wallet
selection screen can be reached, it is deemed sufficient.

Deployment
----------

There are a range of steps to doing the deployment.

Build files
~~~~~~~~~~~

The build files are currently hosted for download on Amazon S3 storage rather than on the web
site. This was initially done in order to try and reduce the false positive flagging for Malware
that ElectrumSV gets on Windows, because of it's use of Pyinstaller. The process of uploading these
is intended to be paranoid to ensure that the files uploaded are the actually the ones the CI
process produced.

After the build artifacts are uploaded to Amazon S3 storage, they are re-downloaded and the SHA256
hash of each is compared to those that CI produced by redownloading the build hashes from CI.

Web site
~~~~~~~~

Besides reflecting the latest release, another function of the web site is that it
hosts a JSON file with signatures from at least one developer for the given release version and
date. This is used by the update checker to alert users that there is a new release. The web site
also hosts the GPG signatures from at least one developer, which need to be added before it is
generated.

Update signatures
^^^^^^^^^^^^^^^^^

The keys used to verify that a release has been signed by a known developer are hard-coded into
each build. This makes it difficult to add new signing developers, as users with older builds will
lack the keys for those new developers, those builds will appear illegitimate. It is probably a
good idea for the process to change sooner rather than later to prepare for working around this.

One or more of the developers can sign to announce the release of the build, and each should do
the following:

1. Take the release version which might be ``1.3.7``.
2. Take the release date which might be ``2020-10-08T20:00:00.000000+13:00``.
3. Combine them which in this case will result in ``1.3.72020-10-08T20:00:00.000000+13:00``.
4. Go into the signing wallet and select the signing key.
5. Select the `Sign/verify message` menu.
6. Enter the combined text.
7. Click the `Sign` button and enter the wallet password.
8. Copy the signature and place in the `release.json` file.

The existing `release.json` file is included in the web site generation content, and should be
updated and it will automatically be included in the generated web site.

GPG signatures
^^^^^^^^^^^^^^

In addition to hashes proving the integrity of downloaded build files, there are also GPG
signatures that indicate who they came from. The public keys of the developers who might sign
the build files are `in Github <https://github.com/electrumsv/electrumsv/tree/master/pubkeys>`_
much like the SHA256 hashes for each build file.

A sub-directory should be made within the `download` web site
`content directory <https://github.com/electrumsv/electrumsv/tree/master/docs/website/content/download>`_
for the release version, and the GPG signatures for each new build file placed in there.

Generation
^^^^^^^^^^

With GPG signatures and release version signatures in place, and also updated for the new version
and build files, the final web site can be generated and put in place on the ElectrumSV web host.
The generation instructions documented in the
`web site directory <https://github.com/electrumsv/electrumsv/tree/master/docs>`_.
Assuming that the developer has already been generating the web site in the past, the following
commands are all they need to do one final generation.

.. code:: console

   cd docs
   cd website
   pelican -s pelicanconf.py

Standard deployment steps need to be followed and the new uploaded `html` directory needs to
match the existing one in the following ways:

1. The same owner using ``chown -R``.
2. The same permissions using ``chmod -R``.

Documentation
~~~~~~~~~~~~~

The documentation is hosted on the `Read the Docs <https://readthedocs.org/>`_ service.
As changes are pushed to the Github repository, Read the Docs is notified and they fetch the
changes and trigger an update of the documentation. This mostly benefits users being able to
view development documentation. The deployed documentation for a given release cannot change
any time post-release development changes are made.

After the tag for the release changes is pushed to Github, a developer needs to add it to the
list of tags that Read the Docs is hosting documentation for. And then they need to make it the
default tag so that the documentation URL ``electrumsv.readthedocs.io`` goes there by default.

Github
~~~~~~

At this point the documentation, the web site, and almost all other changes should be present in
Github. The one thing that may be missing is the SHA256 hashes for the build files, which
need to be added to the file ``build-hashes.txt`` in the source code, and pushed as well.
Beyond that they need to be merged into
`the master branch <https://github.com/electrumsv/electrumsv/blob/master/build-hashes.txt>`_,
which is the place we recommend users go to find them.

Github releases
^^^^^^^^^^^^^^^

Github has it's own system for projects to make releases, and we do use that, but we do not
use it to release build files. It's primary used to formally designate the release tag as
a new release, and associate it with a list of the changes in the release. The changes listed
there are taken directly from the ``build-hashes.txt`` file.

Release article publication
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This should just be a matter of applying any final polish to the already prepared release article
and pressing whatever resembles the `Publish` button.

Announcements
~~~~~~~~~~~~~

The link to the release article should be posted to the following places with some additional
decorative text.

- Twitter.
- The Metanet.ICU slack.
- The Atlantistic Unwriter slack.
- Anywhere else.

.. note::

   TODO: Guidelines to how we write the standard decorative text should be added here.


The release checklist
---------------------

It is not realistic for developers to read this document when they want to make a release and
step through the description of the process. Instead, they should refer to the following checklist
and where necessary refer to the description of the process for context and further details.

.. note::

   TODO: Formalise the above as a list of concrete steps.
