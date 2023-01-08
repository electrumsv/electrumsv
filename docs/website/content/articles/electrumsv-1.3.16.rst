What changed in ElectrumSV 1.3.16?
##################################

:date: 2023-01-03 16:00
:slug: electrumsv-1_3_16
:authors: The ElectrumSV Developers
:summary: This update includes essential changes and it is expected that you update to it.
:category: releases
:status: published
:unfurlimage: articles/electrumsv-1.3.15/20220617-example-history-list.png

.. |br| raw:: html

  <br/>

This article covers the release of ElectrumSV 1.3.16, and some of the more important changes that
have been made since ElectrumSV 1.3.15.

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
`release notes <https://github.com/electrumsv/electrumsv/blob/master/RELEASE-NOTES>`__ in the
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

Documentation correctness
=========================

The documentation covering how to verify your download with our PGP signatures
referred to a different file suffix ".sig" for the file signatures rather than ".asc" which
the tooling appears to have switched to, causing user confusion. This has now been aligned
with the tooling, and uses ".asc".

Technical debt (Python language)
================================

The Python standard library has provided a range of useful
hashing functionality out of the box. One of these, RIPEMD-160, is used in Bitcoin primarily
for things like public key hashes (as used in P2PKH addresses) and script hashes (as used
in the past in P2SH addresses). The Python support for RIPEMD-160 comes from the support for
it in the OpenSSL library. With the removal of it from OpenSSL 3, it is also no longer
available in Python and ElectrumSV errors when it tries to access it. We now bundle a giant
hack that intercepts Python language RIPEMD-160 usage in both ElectrumSV and in our `bitcoinx`
dependency and reroutes it through Cryptodomex (which we include anyway and is primarily used
to speed up AES encryption/decryption).

Technical debt (Github)
=======================

Github helpfully notifies us when any of the packages we depend on
have security issues. A lot of these issues do not affect us in meaningful ways, but Github
cannot tell this and continually "not-spams" us about them every time it sees any activity.
In order to reduce the pain of using Github it requires that we update those packages
regardless.

* Protobuf was updated. This is package is a nuisance with numerous problems. There's a
  security issue that does not effect us in 3.18.0, the version we previously used. But the
  recommendation was to update to 3.18.3, and this crashed on MacOS. 3.20 and above breaks
  backwards compatibility and we cannot use it because it is not our dependency, but that of
  a third party (keepkey). So we settled on 3.19.6, which is the latest release before the
  break in backwards compatibility and does not crash on MacOS.
* Setuptools was updated.

What changed before this release?
---------------------------------

Each of our release articles links to the article for the release before it. You can follow our
releases back and see what changed in each, by the article that accompanied that release.

Read about what changed in `ElectrumSV 1.3.15 <https://electrumsv.io/articles/2022/electrumsv-1_3_15.html>`__
