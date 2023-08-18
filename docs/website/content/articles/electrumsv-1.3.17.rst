What changed in ElectrumSV 1.3.17?
##################################

:date: 2023-08-19 20:00
:slug: electrumsv-1_3_17
:authors: The ElectrumSV Developers
:summary: This update includes essential changes and it is expected that you update to it.
:category: releases
:status: published
:unfurlimage: articles/electrumsv-1.3.16/20230522-example-history-list.png

.. |br| raw:: html

  <br/>

This article covers the release of ElectrumSV 1.3.17, and some of the more important changes that
have been made since ElectrumSV 1.3.16.

.. figure:: {static}electrumsv-1.3.16/20230522-example-history-list.png
   :align: center
   :width: 90 %
   :alt: An example wallet opened in ElectrumSV 1.3.16.

   An example wallet opened in ElectrumSV 1.3.16.

Warning
-------

**This release, ElectrumSV 1.3.17, is the only version we support. If you use older versions and
encounter bugs and security problems, you do so at your own risk. You are advised to upgrade
ElectrumSV to 1.3.17.**

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

Important: Browser root certificate revoked
===========================================

Due to the packages we depend on, we bundle the root certificates that are used
to verify that when we connect to a web site it is the legitimate web site. These have been
updated again with another root certificate has been revoked

Critical: Fix bug connecting to servers
=======================================

If you are experiencing this, the ElectrumSV networking status will continue to show
"Not connected" and will never change. If you start seeing it, you have to change a configuration
file to block a bad server - something so complicated no-one should ever have to do it ideally!
Which is why we are making this release.

ElectrumSV, like Electrum Core and Electron Cash before it, attempts to maintain connections to up
to 10 servers. The idea is that by doing so it can have a better overview of the correct state of
the blockchain and can follow a server that is working correctly. This has worked for all these
wallets for upwards of ten years.

The servers that ElectrumSV builds in for users to start with, are the ones we have vetted. But
this is not the only way that Electrum wallets find out about more servers to use, new servers
that start up gossip with existing servers and the existing servers tell connected ElectrumSV
wallets about the new servers.

A defective server appeared and went away. It returns a buggy result that breaks server connection
and causes the networking code to exit and prevent any server connections until ElectrumSV is
restarted. Unfortunately, anyone running ElectrumSV when it was around had this server added
to their server list as a possible server to check. When their copy of ElectrumSV starts up
it will attempt to connect to this defective server and it will return a result that causes this
problem.

This fix makes our server connection code more resilient and will remove the problem where a
server that is defective like this can break the network connection code.

What changed before this release?
---------------------------------

Each of our release articles links to the article for the release before it. You can follow our
releases back and see what changed in each, by the article that accompanied that release.

Read about what changed in `ElectrumSV 1.3.16 <https://electrumsv.io/articles/2023/electrumsv-1_3_16.html>`__
