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

We were notified that one of the root certificates browsers use was revoked. Due to how the third
party Python libraries we use work, the certificates have to be bundled in each ElectrumSV release.
This means that to update the included certificates to exclude the revoked one, we need to do
a new ElectrumSV release.

What changed before this release?
---------------------------------

Each of our release articles links to the article for the release before it. You can follow our
releases back and see what changed in each, by the article that accompanied that release.

Read about what changed in `ElectrumSV 1.3.15 <https://electrumsv.io/articles/2022/electrumsv-1_3_15.html>`__
