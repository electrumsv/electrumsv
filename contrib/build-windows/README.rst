Building for Windows
====================

.. important::
   This is currently a work in progress. Further work to polish this is still required.

At the time of writing, Windows builds of ElectrumSV are created on Linux under Wine. This is
not ideal, it adds layers of abstraction and complication over the build process, making it harder
for developers to work with. Worse the docker images the builds are done in, become a form of
technical debt where system administration must be performed to keep them updated. Insanity!
All Windows builds are currently created in CI using this difficult to update docker image on
Azure Pipelines, both for distribution and testing.

Goals
-----

This directory is intended to replace the existing Wine on Linux build environment, with native
Windows building.

- Windows-based developers will be able to create their own builds.
- CI will use this to generate our builds.

A build will produce one or more artifacts:

- The standard PyInstaller "one file" executable we have always produced.
- The portable PyInstaller "one file" executable we have always produced.
- A PyInstaller "one directory" build suitable for use in the Windows store.
- A directory containing a custom embedded Python application suitable for use in the Windows store.

Build artifacts
---------------

There are reasons we need the different types of build artifacts.

PyInstaller "one file" executables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A PyInstaller executable does not necessarily need to be installed, and in fact we do not
distribute the installer form of this we do build. Instead it can run in place, which is
especially handy for the portable version which people might run from their USB drive. The
standard "one file" executable stores and accesses wallet data in the user's `AppData` directory.
The portable "one file" executable stores and accesses wallet data in the current directory, and
the user presumably executes it from the USB drive (or wherever) and the data is stored in the
same location as the executable.

An advantage of the "one file" executable is that we can sign it, and it retains full integrity,
making any tampering obvious as the signature will no longer be valid.

Windows store build
~~~~~~~~~~~~~~~~~~~

There are certain requirements for a Windows store application which need to be met. Some of these
are not clear yet, and may require further decisions based on problems encountered.

PyInstaller suitability
!!!!!!!!!!!!!!!!!!!!!!!

PyInstaller has been used by malware and any application that uses it to create a build gets
recognised as a malware false positive using the same detection patterns. It is unclear if this
will be a problem in any Windows store application, but it may mean we have to do what the
Linux-based build process does - which is rebuild the executable stub.

Build size
!!!!!!!!!!

PyInstaller does a lot of work to only include used parts of dependencies in the final build. This
means that the custom embedded build creates a compressed raw build that is around 140MiB in size,
whereas PyInstaller will take it and make it 80MiB.

Other issues
--------------

Startup time
~~~~~~~~~~~~

We need ElectrumSV to startup promptly. It is possible that the network startup delays the
ElectrumSV startup, and it would be good to have the splash screen displayed without it waiting
for the network startup (if that is the cause of the slow startup).
