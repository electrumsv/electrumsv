What changed in ElectrumSV 1.3.16?
##################################

:date: 2023-05-22 20:00
:slug: electrumsv-1_3_16
:authors: The ElectrumSV Developers
:summary: This update includes essential changes and it is expected that you update to it.
:category: releases
:status: published
:unfurlimage: articles/electrumsv-1.3.16/20230522-example-history-list.png

.. |br| raw:: html

  <br/>

This article covers the release of ElectrumSV 1.3.16, and some of the more important changes that
have been made since ElectrumSV 1.3.15.

.. figure:: {static}electrumsv-1.3.16/20230522-example-history-list.png
   :align: center
   :width: 90 %
   :alt: An example wallet opened in ElectrumSV 1.3.16.

   An example wallet opened in ElectrumSV 1.3.16.

Warning
-------

**This release, ElectrumSV 1.3.16, is the only version we support. If you use older versions and
encounter bugs and security problems, you do so at your own risk. You are advised to upgrade
ElectrumSV to 1.3.16.**

`Click here <#what-has-changed-in-this-release>`__ to skip to the things that have changed.

Useful information
------------------

Do you need an introduction to how ElectrumSV works?
====================================================

We have a selected range of guides to common tasks that our users may want to do in our
documentation, please `check it out <https://electrumsv.readthedocs.io/>`__.

Where can you download ElectrumSV?
==================================

The only safe downloads are available from: `electrumsv.io <https://electrumsv.io/>`__

Where can you get help?
=======================

Find our `issue tracker here <https://github.com/electrumsv/electrumsv/issues>`__ where you can
create a ticket. Fill out the issue template, please! Otherwise we have no idea what steps you
took or any of the other details and then we have to spend time asking you them anyway and you
get help much later. **Fill out the template for your own sake, if not ours!**

We do not provide support over Twitter or any other forms of social media. Not only is it not
guaranteed we will see your comments, it is a very painful way to do support that we avoid. If
you need support, submit an issue on our issue tracker. Or you can raise subjects of interest on
the `official BSV Discord <https://discord.gg/bsv>`__ or the
`Metanet.ICU Slack <http://metanet.icu/>`__.

What has changed in this release?
---------------------------------

The main changes in this release have been listed below. If you don’t want to know the details,
just read the titles. If you want to find out about smaller fixes, you can check the
`release notes <https://github.com/electrumsv/electrumsv/blob/releases/1.3/RELEASE-NOTES>`__ in the
Github repository.

Browser root certificate revoked
================================

Due to the packages we depend on, we bundle the root certificates that are used
to verify that when we connect to a web site it is the legitimate web site. One of these
certificates was revoked, and we need to do a release to provide a version of the wallet
that does not contain that revoked certificate. The version of the `certifi` package we
include has been updated.

This is the primary reason for this release.

User interface bug
==================

User interface: There seems to be a bug where restoring a wallet would leave the history
tab list of transactions not correctly updated. Specifically, the dates would still show
"Unknown" despite the transaction having been verified as in a block with the merkle proof.
It should have been updated with the date of the block. A workaround was added to force
an update, but the whole model seems to need a rewrite however the current focus is on the
1.4 release.

Updated header checkpoints
==========================

We do not include all the past blockchain headers with the wallet, and
before the wallet can work properly it used to download all the headers. Nowadays we have
built-in checkpointing so that we can fetch the headers we need on demand, and not require
that long startup time. In order to make this release more user-friendly, we have updated
the mainnet and testnet header checkpoints.

Header bug fix
==============

There is an occasional bug where the file headers are stored in does not get written correctly.
This mainly happens on Windows, but has been observed on Linux. We have included a fix that flushes
and closes the file storage on exit, and should hopefully fix this rare but continuing problem.

Documentation correctness
=========================

The documentation covering how to verify your download with our PGP signatures
referred to a different file suffix ".sig" for the file signatures rather than ".asc" which
the tooling appears to have switched to, causing user confusion. This has now been aligned
with the tooling, and uses ".asc".

Technical debt (Python language)
================================

The Python standard library has provided a range of useful hashing functionality out of the box.
One of these, RIPEMD-160, is used in Bitcoin primarily for things like public key hashes (as used
in P2PKH addresses) and script hashes (as used in the past in P2SH addresses). The Python support
for RIPEMD-160 comes from the support for it in the OpenSSL library. With the removal of it from
OpenSSL 3, it is also no longer available in Python and ElectrumSV errored when it tried to access
it. We now bundle a giant hack that intercepts Python language RIPEMD-160 usage in both ElectrumSV
and in our `bitcoinx` dependency and reroutes it through Cryptodomex (which we included anyway
and primarily used to speed up AES encryption/decryption).

Technical debt (Hardware wallets)
=================================

Our hardware wallet support has always been something we have to maintain ourselves. This leaves
us and our users in a non-ideal position. Anyone using a hardware wallet has to avoid updating it
or they risk putting their device in a state where ElectrumSV cannot communicate with it.

* Ledger hardware wallets have declared the way we use them the legacy approach and the latest
  updates from them no longer support the legacy approach. It is unclear if this is a firmware
  or an on-device application issue. If it is an issue caused by firmware upgrades, then given that
  Ledger do not allow downgrades the upgraded hardware wallet is likely now unusable with
  ElectrumSV. If it is in the Bitcoin or Bitcoin Cash application, then it is possible a user who
  is updating the application might be able to work out how to revert to earlier versions. In
  either case it is best to avoid updating them.
* The Ledger Python packages we rely on are older versions compatible with the legacy approach
  which means we cannot use the newer versions. The Python packaging ecosystem maintainers have
  broken backwards compatibility for some aspect of packaging and the Ledger packages do that
  thing. So now we have forked those versions of the Ledger packages and maintain custom versions.
* Keepkey do not have official Python packages. We have had to fork an earlier version of their
  repository we know works (later versions gave us protobuf related errors) and publish our
  own packages for this device brand.
* Broken hidapi dependency. Ledger and Trezor rely on hidapi. But on MacOS the newer versions of this
  library cause segmentation faults on exit. So after a lot of experimenting we've pinned to older
  versions that are known to work. This is related to how ElectrumSV communicates with Ledger and
  Trezor devices.
* Broken protobuf dependency. We spent a lot of time trying to update our version of protobuf but
  encountered numerous problems. In the end we pinned to the old version we know worked for 1.3.15.
  This is related to how ElectrumSV communicates with Keepkey devices.

Known issues
============

We spent a lot of time trying to work out the most stable combination of packages we depend on
and get everything working as well as it used to for this release. We managed to do that, but there
are known issues.

* Some users on Windows will get an error when they click on something that opens a camera window
  for scanning QR codes. Whether we use the old qrcode support from 2012 we inherited from
  Electrum Core or a new version we compile from a modern maintained Github repository, this
  problem exists. After some examination it was found that this was already present in 1.3.15
  and preceding versions. Without a rewrite of the QR code support will not get fixed, and we
  cannot justify that work for the 1.3 line. It has already been fixed in 1.4 but the backporting
  work for an uncommon problem cannot be justified.

What changed before this release?
---------------------------------

Each of our release articles links to the article for the release before it. You can follow our
releases back and see what changed in each, by the article that accompanied that release.

Read about what changed in `ElectrumSV 1.3.15 <https://electrumsv.io/articles/2022/electrumsv-1_3_15.html>`__
