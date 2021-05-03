What changed in ElectrumSV 1.3.13?
##################################

:date: 2021-05-03 16:00
:slug: electrumsv-1_3_13
:authors: The ElectrumSV Developers
:summary: This update includes a variety of bug fixes and improvements. Read this illustrated overview to find out more.
:category: releases
:status: published
:unfurlimage: articles/electrumsv-1.3.13/20210503-scaling-testnet-wallet.png

.. |br| raw:: html

  <br/>

This article covers the release of ElectrumSV 1.3.13, and some of the more important changes that
have been made since ElectrumSV 1.3.12. **Skip to the “What has changed in this release?” section
to see what has changed**, if that is what you are here for.

We have not been making smaller releases like this. Most of the work is devoted to a larger update
that prepares ElectrumSV for many of the exciting things you might see coming in the
`Bitcoin Association roadmap <https://bitcoinassociation.net/bitcoin-sv-technical-standards-roadmap-2021-2023/>`__!
However, a couple of the changes in this release are important enough to warrant setting aside
the larger updates for now and getting a smaller one out.

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
`Unwriter’s Slack <https://atlantis.planaria.network/>`__, or the
`Metanet.ICU Slack <http://metanet.icu/>`__.

If you are a MacOS user and cannot install/run our latest release, please
`read this article <https://lapcatsoftware.com/articles/unsigned.html>`__.

What has changed in this release?
---------------------------------

The main changes in this release have been listed below. If you don’t want to know the details,
just read the titles. If you want to find out about smaller fixes, you can check the
`release notes <https://github.com/electrumsv/electrumsv/blob/master/RELEASE-NOTES>`__ in the
Github repository.

Restored scaling testnet access
===============================
*This means that this release and later ones will be compatible with the STN into the future.*

.. figure:: {static}electrumsv-1.3.13/20210503-scaling-testnet-feature.png
   :align: center
   :width: 90 %
   :alt: Featured content from the scaling test network web site.

   Featured content from the scaling test network web site.

In order to reduce the startup time before it can be used ElectrumSV uses checkpoints for the
different blockchains. Unlike other blockchains, the `scaling testnet <https://bitcoinscaling.io/>`__
(STN) blockchain gets periodically reset and this means any checkpoint we have for it becomes
invalid. Any ElectrumSV release (and this would include any from 1.3.12 and earlier) with an
invalid checkpoint will never be able to connect to the STN ever again.

At this point having a checkpoint for the STN seems like a bad idea, and so the checkpoint has been
removed. This will mean that any releases downloaded from 1.3.13 onward should always be
compatible with the STN.

.. figure:: {static}electrumsv-1.3.13/20210503-scaling-testnet-wallet.png
   :align: center
   :width: 90 %
   :alt: Using ElectrumSV on the scaling testnet.

   Using ElectrumSV on the scaling testnet.

In order to access the STN you also need a working server. The ElectrumSV run server has some hard
to debug technical issues, which have led to it falling offline for a while now. However Kayvan from
`satoshi.io <https://satoshi.io/>`_  has been running his own server which he has kindly agreed to
let ElectrumSV users use, and it is now built into ElectrumSV as the default.

You can read an article on how to `access the scaling testnet with ElectrumSV <https://electrumsv.io/articles/2021/the-scaling-test-network.html>`__ on our web site.

*Commits:* `#1 <https://github.com/electrumsv/electrumsv/commit/ac2fc1b0d4e70b6a9367776773874a074862ad0b>`__
`#2 <https://github.com/electrumsv/electrumsv/commit/9eb793e8f246c26763e8e2ebada85f199033b5b1>`__

Fixed transaction caching
=========================
*Users who accessed tonnes of transactions or large ones would get errors using the wallet.*

A while ago now, we identified a bottleneck with the wallet database in that different systems
would ask for a transaction for perhaps some small part of data, and we would end up seeing them
significantly slowed down reading that transaction from the database. In order to remove this
bottleneck we added a transaction cache, and the problem went away.

.. figure:: {static}electrumsv-1.3.13/20210503-preferences-wallet.png
   :align: center
   :alt: The transaction cache is configured in the wallet tab of the preferences window.

   The transaction cache is configured in the wallet tab of the preferences window.

.. figure:: {static}electrumsv-1.3.13/20210503-wallet-information-dialog.png
   :align: center
   :alt: The transaction cache status can be seen via the wallet information menu.

   The transaction cache status can be seen via the wallet information menu.

We have one gracious user who encountered the problem just under a year ago, and who used our
error reporting functionality to let us know. Without a reproduction case, it was not clear what
the cause was and since only one user reported it (we would get significantly higher numbers of
reports if it were a common problem) it was kind of ignored. However Aaron67 on the Atlantistic
slack recently reported that he was creating very large transactions and was getting it as well.
It turns out there was a typo in the original transaction cache code that has been there since it
was first written, and with it being fixed in this release this year old bug should now be
resolved.

While it is unlikely that any problem remains, given the nature of the typo and the observed
errors, if anyone does experience problems with the cache they can disable it by setting the
maximum size to 0. The screenshot above of the Wallet section of the Preferences dialog, contains
the setting that needs to be changed.

*Issues:* `#413 <https://github.com/electrumsv/electrumsv/issues/413>`__ |br|
*Commits:* `#1 <https://github.com/electrumsv/electrumsv/commit/50023e3fe18b0e3ab04fe12b9c7f620536391ca1>`__

Loading transactions from files and accepted file extensions
============================================================
*Affects user who saved transactions as JSON and had to use the .txn extension.*

One of the things you can do with ElectrumSV is load a transaction. You might do this because you
have some random transaction you want to look at, or you might do it because you are a cosigner
in a multi-signature account and need to sign your part. Perhaps you might have some other reason
not mentioned here. Unfortunately, we had a filter so that the only files the file open dialog
that we presented to allow you to select the transaction you wanted to load were those with the
extension ``.txn``. You could work around it and rename your transaction to have that extension
if it did not already, but now we give the file open dialog a selection of filters including
``*.txn``, ``*.json``, ``*.txt`` and the open ``*.*``.

*Issues:* `#708 <https://github.com/electrumsv/electrumsv/issues/708>`__ |br|
*Commits:* `#1 <https://github.com/electrumsv/electrumsv/commit/a7a309ce72d75db46a6e719b84035c67f940f88c>`__

Goodbye to MacOS automatic dark mode for now
============================================
*Affects MacOS users who occasionally had a graphically broken Electrum under auto dark mode.*

Having recently gained access to a MacOS laptop for testing, for some reason MacOS decided that it
needed automatically turn on dark mode in the middle of the day. This conflicted with the
custom stylesheets we have, and looked unacceptable. We do not have time to spend working out how
to detect if dark or light mode is used, and to add support for each. In fact I am not even sure
it is clearly documented how one would do this with custom CSS stylesheet in the Qt5 UI framework
we use.

.. figure:: {static}electrumsv-1.3.13/20210503-macos-preferences-general.jpg
   :align: center
   :width: 90%
   :alt: The MacOS general preferences option for auto light/dark modes.

   The MacOS general preferences option for auto light/dark modes.

Rather than forcing ElectrumSV users to disable auto dark mode entirely to avoid this aethetic
crime, the only viable solution for now is to force light mode for the MacOS releases. If someone
knows what is required and wants to put in the time to fix ElectrumSV to work with this auto dark
mode thing, so people can have dark mode again in middle of the day and light
whenever Apple decides that suits.. we're happy to accept pull requests.

*Commits:* `#1 <https://github.com/electrumsv/electrumsv/commit/87373049aaadbc800658bcf73c4f58c275d128eb>`__

Other changes
=============

* The documentation 'verify your download' guide has been extended with information on how to
  verify the GPG signatures on MacOS. Thanks to Amberto for the assistance with this.
* The web site has a new article detailing how to use the scaling testnet with ElectrumSV.

What changed before this release?
---------------------------------

Each of our release articles links to the article for the release before it. You can follow our
releases back and see what changed in each, by the article that accompanied that release.

Read about what changed in `ElectrumSV 1.3.12 <https://roger-taylor.medium.com/electrumsv-1-3-12-a4002e6dbdf6>`__
