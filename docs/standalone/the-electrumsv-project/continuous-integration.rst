Continuous integration
======================

As Microsoft provide generous levels of free usage to open source projects hosted on Github
through their Azure DevOps service, ElectrumSV makes use of it for a range of purposes. Every time
changes are pushed to Github, the following tasks are run:

- Unit tests on Windows, MacOS and Linux.
- Linting.
- Type checking.
- Code coverage analysis.
- Producing releases.

While Azure DevOps will do these things against each individual commit, we have configured the
project to only do it against the latest commit.

Releases
--------

There are two goals in having CI produce build files:

- We can use it to produce the build files we release publically.
- Members of the public can access and download build files for any build.

Using CI to produce official release files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By having CI produce the build files, this allows a developer to offload the processing work
from their own computer and carry on working on other tasks. In addition there is some security
in having the build files made within CI, where the CI obtains the source code directly from
the latest commit on Github. And on generating the build files, also produces SHA256 hashes
that can be used to validate the content at any later time.

Benefits of public build access
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If a user is experiencing a bug, a developer can fix it and push the fix to Github. This will
result in an automatic build on Azure DevOps, and if it succeeds will produce build files. The
developer can point the user to the build, and although the user may not have an account with
Azure DevOps they still have enough access that they can download build artifacts like the
build files.
