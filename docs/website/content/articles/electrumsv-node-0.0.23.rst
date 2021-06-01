ElectrumSV node 0.0.23
######################

:date: 2021-06-01 16:00
:slug: electrumsv-node-0_0_23
:authors: The ElectrumSV Developers
:summary: A new release of the ElectrumSV node project including Bitcoin SV node v1.0.8.
:category: releases
:status: published
:unfurlimage: articles/electrumsv-node-0.0.23/20210601-bitcoinsv-node-software.png

.. |br| raw:: html

  <br/>

This article covers the release of electrumsv-node 0.0.23. The ElectrumSV node project is one
that we use daily in our development work on ElectrumSV. It provides pre-compiled builds of the
latest Bitcoin SV node software, that we use both for experimentation and to test changes that
are made to the wallet. But why aren't you running your own local node to do your own
experimentation and testing? Now you can.

You can download the executable node files from our `node project web site`__. But make sure you
verify your downloads. Alternately, you can install our Python packages and operate nodes using
`Python function calls`__.

__ https://electrumsv.io/node-project/
__ https://electrumsv-node.readthedocs.io/en/latest/release-artifacts/python-packages.html

What has changed in this release?
---------------------------------

The main changes in this release have been listed below. If you don’t want to know the details,
just read the titles.

Bitcoin SV v1.0.8
=================

Version 1.0.8 of the Bitcoin SV node project was recently released. Ideally we release an update
of this project as soon as we can with the new version of the node software, but keep in mind that
our primary priority is focusing on the ElectrumSV wallet software.

Both our Python packages and our archives of executable files should be available with this new
release of the Bitcoin SV node software.

.. figure:: {static}electrumsv-node-0.0.23/20210601-executables-windows.png
   :align: center
   :width: 90 %
   :alt: Our pre-built Windows node executables.

   Our pre-built Windows node executables.

.. figure:: {static}electrumsv-node-0.0.23/20210601-executables-macos.png
   :align: center
   :width: 90 %
   :alt: Our pre-built MacOS node executables.

   Our pre-built MacOS node executables.

Note that only 64 bit executables are provided because it is 2021, and additionally Linux
executables are not provided because the Bitcoin SV developers already provide them.

Documentation
=============

We have `written documentation`__ telling you how to obtain, install and use the our node builds.
Like the documentation for the ElectrumSV wallet, this is hosted on the wonderful Read the Docs
web site.

__ https://electrumsv-node.readthedocs.io/en/latest/

Using our Python packages
~~~~~~~~~~~~~~~~~~~~~~~~~

The documentation goes into detail about how to `install our Python packages`__.

__ https://electrumsv-node.readthedocs.io/en/latest/release-artifacts/python-packages.html#installing-the-package

.. figure:: {static}electrumsv-node-0.0.23/20210601-documentation-python-install.png
   :align: center
   :width: 90 %
   :alt: A guide to installing the Python packages.

   A guide to installing the Python packages.

Once you have installed the Python packages, the documentation then covers how to `start a node`__
and make RPC calls to it. Then it proceeds to extend that to `starting two nodes`__, making them
aware of each other and sharing blocks between them.

__ https://electrumsv-node.readthedocs.io/en/latest/release-artifacts/python-packages.html#running-the-node
__ https://electrumsv-node.readthedocs.io/en/latest/release-artifacts/python-packages.html#running-multiple-node-instances

.. figure:: {static}electrumsv-node-0.0.23/20210601-documentation-python-use.png
   :align: center
   :width: 90 %
   :alt: Running a node and making RPC calls.

   Running a node and making RPC calls.

Using our prebuilt executables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The documentation goes into detail about how to `verify your downloads are authentic`__. For that
matter it might be quite difficult to even download them, Windows Defender, Google Chrome and
other applications all warn about files recognised as bitcoin node applications. The problem is
that these are placed onto users computers covertly, and used to mine cryptocurrencies.
This is something that you, our user, and us the provider of these builds will have to work around
together.

__ https://electrumsv-node.readthedocs.io/en/latest/release-artifacts/archived-binaries.html#archived-binaries

.. figure:: {static}electrumsv-node-0.0.23/20210601-documentation-verify-your-downloads.png
   :align: center
   :width: 90 %
   :alt: Verify your downloads.

   Verify your downloads.

Once you have obtained the executables for your platform, the documentation then covers how
to `start a node`__ and make RPC calls to it. Then it proceeds to extend that to
`starting two nodes`__, making them aware of each other and sharing blocks between them.

__ https://electrumsv-node.readthedocs.io/en/latest/release-artifacts/archived-binaries.html#running-the-node
__ https://electrumsv-node.readthedocs.io/en/latest/release-artifacts/archived-binaries.html#running-multiple-node-instances

.. figure:: {static}electrumsv-node-0.0.23/20210601-documentation-binaries-use.png
   :align: center
   :width: 90 %
   :alt: Running a node and making RPC calls.

   Running a node and making RPC calls.

These are just the simplest things you can do with the node software at your finger tips. Think
about experimenting with the non-final mempool, or custom script variations. No need to wait for
blocks to be mined, you can mine your own as often as you need.
