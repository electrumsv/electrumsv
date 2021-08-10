Releases
========

Currently ElectrumSV only builds releases for Windows and MacOS. It is expected that Windows users
are using at least Windows 10, and MacOS users are using 10.15 or later. We intentionally do not
provide either Linux builds or support any form of packaging, and Linux users are expected to
get it running from source.

Some of the reasons we do this are intentional, and others are technical limitations that are
either imposed by our build environment or the dependencies we use. This document is intended to
detail those reasons, both for reference by our users and developers.

Platforms
---------

Developer resources are limited, and we need to focus it where it matters. This is the main reason
relating to our platform-related release choices. Even if a community member contributes changes to
add support for dated platform versions, accepting those changes can impose heavy ongoing costs on
developer time and even unacceptable limitations on development for recent platform versions.

Windows
~~~~~~~

ElectrumSV Windows builds are for Windows 10 or above. It is possible they work on earlier versions
of Windows, but we will neither test that it works or make unreasonable changes to keep it working.

MacOS
~~~~~

ElectrumSV MacOS builds are currently limited to 10.15 and above.

Build environment
^^^^^^^^^^^^^^^^^

Our releases are made in our CI environment provided by Microsoft. The release build the CI
environment creates currently requires `MacOS 10.15`_.

.. _MacOS 10.15: https://github.com/actions/virtual-environments#available-environments

Dependency: Qt
^^^^^^^^^^^^^^

ElectrumSV uses the Qt user interface package. Each updated version of Qt requires more
and more recent versions of MacOS. At the time of writing, we use 5.15 but we plan to update
to 6.1 when we get the time.

* `Qt 5.15`_ needs MacOS 10.13 or later.
* `Qt 6.0`_ needs MacOS 10.14 or later.
* `Qt 6.1`_ needs MacOS 10.14 or later.

.. _Qt 5.15: https://doc.qt.io/qt-5.15/supported-platforms.html
.. _Qt 6.0: https://doc.qt.io/archives/qt-6.0/supported-platforms.html
.. _Qt 6.1: https://doc.qt.io/qt-6.0/supported-platforms.html

Linux
~~~~~

ElectrumSV does not provide any builds or packages for Linux.

People have offered to contribute code to support various Linux packaging systems, but we have
had to refuse that. It is very little work to take in that code and produce those packages, but
it too much work to test them and verify they work on all the different Linux distributions. We
will never accept Linux packaging support for this reason.

What we would be willing to accept, is AppImage support, where the AppImage build runs on at least
all mainstream Linux distributions without any extra work. Unfortunately, there has been no
interest from Linux users on working on this and contributing that code. The ElectrumSV developers
will need to produce the builds, test them and polish them - so there are quality requirements.

.. important::
   Do you want ElectrumSV to have AppImage support for Linux? Get in touch with the ElectrumSV
   developers and work out what we require in any acceptable solution.
