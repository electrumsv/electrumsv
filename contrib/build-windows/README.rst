Building for Windows
====================

.. important::
   This is currently a work in progress. It has issues, and needs a lot more work.

At the time of writing, we use PyInstaller for Windows builds and that has issues
with it also being used by malware authors. So if your application is distributed
using the PyInstaller approach, it resembles malware and gets false positives.

Goal
----

If we can provide a directory that is a minimal in-place ElectrumSV build, then we
have two possible ways forward:

- We could distribute that directory zipped as a replacement for the portable build.
- We should be able to make an installer, sign it, and publish it on the Windows store.


Current issues
--------------

There are several issues that need to be overcome before this is a viable way forward.

Build size
~~~~~~~~~~

PyInstaller does a lot of work to only include used parts of dependencies in
the final build. This means that our process creates a raw build that is around
200MiB in size, whereas PyInstaller will take it and make it 30MiB.

Dependency errors
~~~~~~~~~~~~~~~~~

The hardware wallet dependencies error when being installed into the embedded Python
environment. The error in question is in the Construct dependency, which appears to
choke when being installed.

- The current code does not show stderr, only stdout, so this appears to happen
  silently.
