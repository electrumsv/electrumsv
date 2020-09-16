Release process
===============

The process of making a release is as follows:

1. Write an article detailing the changes that are included in the release.
2. Put the article link in the correct places in the source code.
3. Update the version number in the correct places in the source code, including the ``version.py``
   file.
4. Update the release date and time in the ``version.py`` file.
5. Tag the release.
6. Push the updated source code to the Github release branch.
7. Push the release tag to Github quickly before the CI starts the build. This will mark the
   release as stable, and cause the release files to be named by release version rather than
   git commit revision.
8. Verify that the CI is doing a stable build and wait for it to finish.
9. Ensure that all unit tests pass.
10. Ensure that linting and typing checks all pass.
11. Download all build files that are produced on Azure Devops as artefacts of the stable build.
12. Delete the installer ``-setup.exe`` executable for Windows.
13. Test that the built executables work on each of Windows and MacOS.
14. Generate GPG signatures for all build files.
15. Upload all the build files to the Amazon S3 storage.
16. Update the web site source code for the new build files and their download links.
17. Update the web site in general for the new version.
18. Update the web site ``release.json`` file for the new version, release date and time, and the
    signature using the release credentials signing key.
19. Publish the web site.
20. Publish the article detailing the changes included in the release.
21. Announce the release on Twitter, Metanet.ICU slack, Atlantistic Unwriter slack and anywhere
    else.

