What changed in ElectrumSV 1.3.15?
##################################

:date: 2022-06-17 16:00
:slug: electrumsv-1_3_15
:authors: The ElectrumSV Developers
:summary: This update includes essential changes and it is expected that you update to it.
:category: releases
:status: published
:unfurlimage: articles/electrumsv-1.3.15/20220617-example-history-list.png

.. |br| raw:: html

  <br/>

This article covers the release of ElectrumSV 1.3.15, and some of the more important changes that
have been made since ElectrumSV 1.3.14.

Warning
-------

**This release, ElectrumSV 1.3.15, is the only version we support. If you use older versions and
encounter bugs and security problems, you do so at your own risk. You are advised to upgrade
ElectrumSV to 1.3.15.**

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

Exploit fix
===========

The invoice payment support in ElectrumSV was inherited from
`Electrum Core <https://electrum.org/>`__ and provided the ability to read invoice files from disk.
Unfortunately there are security issues with this, where someone on the same local network could
access your computer if it was abused. On other operating systems it could be used to lock up a
user's wallet. You can read more about this in the Electrum Core
`security announcement <https://github.com/spesmilo/electrum/security/advisories/GHSA-4fh4-hx35-r355>`__.

The initial fix was made in 1.3.14, but this release is being made to add further polish and provide
a final release in the 1.3 line in preparation for the upcoming 1.4 lite client release in the
upcoming months. Due to the interest in doing a release before the exploit was announced, the
previous release did not explain this exploit as the reason why it was being made.

.. figure:: {static}electrumsv-1.3.15/20220617-send-tab.png
   :align: center
   :width: 90%
   :alt: The send tab where invoice payments are made.

   The send tab where invoice payments are made.

Wallet update prompt
====================

Previously we highlighted the update button in the toolbar in the wallet user interface as either
yellow (new update) or red (recent update) if you were using an older version of ElectrumSV. Now
we add a notification to the notifications list, in order to prompt users to update.

The ElectrumSV developers have limited resources and it is drain on our development time to hear
problems with older versions of ElectrumSV, especially as we will not fix them. Additionally we
want to be sure that if there are further exploits, we have a much more visible way of prompting
the user to update. This change should be that more visible way without hassling the user.

.. figure:: {static}electrumsv-1.3.15/20220617-update-electrumsv.png
   :align: center
   :width: 90%
   :alt: The new "update your wallet" prompt.

   The new "update your wallet" prompt.

Add account prompt
==================

New wallet users are sometimes not clear on how to create an account. We now add a notification
that is displayed when a new wallet is created, to prompt the user to look at the toolbar and
press the "Add account" button. Once the user has created an account this notification goes
away.

.. figure:: {static}electrumsv-1.3.15/20220617-create-an-account.png
   :align: center
   :width: 90%
   :alt: The new "add an wallet" prompt.

   The new "add an wallet" prompt.

What changed before this release?
---------------------------------

Each of our release articles links to the article for the release before it. You can follow our
releases back and see what changed in each, by the article that accompanied that release.

Read about what changed in `ElectrumSV 1.3.14 <https://electrumsv.io/articles/2022/electrumsv-1_3_14.html>`__
