What changed in ElectrumSV 1.4.0b1?
###################################

:date: 2021-08-19 16:00
:slug: electrumsv-1_4_0b1
:authors: The ElectrumSV Developers
:summary: This pre-release beta test update includes a variety of bug fixes and improvements. Read this illustrated overview to find out more.
:category: releases
:status: published
:unfurlimage: articles/electrumsv-1.4.0b1/receiving-a-payment-02-expected-payment-dialog.png

.. |br| raw:: html

   <br/>

.. contents:: Table of contents:
   :depth: 3

Remember that this is a beta release. It is already well tested, and very likely to be
what we release in the 1.4.0 release. Any wallet you update or create with this will be fully
supported in future releases. And yes, we do back up your wallet when you update it. Please
report any bugs you experience so we can fix them.

The highlights
--------------

These are the most important changes in this new version of ElectrumSV. It is by no means all
the changes that are included in this release, just the most important for you to learn about.

Declaring what payments you expect to receive
=============================================

The largest part of this release, is that ElectrumSV no longer monitors the blockchain anywhere
near as much as it used to. If you expect to receive an incoming payment, you need to use
the user interface to declare that you expect it first. If you don't, ElectrumSV will not know
about it.

.. figure:: {static}electrumsv-1.4.0b1/receiving-a-payment-02-expected-payment-dialog.png
   :align: center
   :width: 90 %
   :alt: The "Receive" tab where incoming payments are created and viewed.

   The "Receive" tab where incoming payments are created and viewed.

You can read our guide on `how to receive payments <https://electrumsv.readthedocs.io/en/releases-1.4/getting-started/receiving-a-payment.html>`__
in our documentation.

Looking on the blockchain for payments you do not have
======================================================

There are still at least two cases where ElectrumSV needs to look on the blockchain for payments
to an account in one of it's wallets. The most important case is wallet restoration. If someone
creates an account using their existing seed words, one of the first thing they will want to do is
find all the transactions relating to that account. Another case that it is important ElectrumSV
handles, is to look for missing transactions in the case of error whether on the part of
the wallet or the user. For this reason, we have added the blockchain scanner.

.. figure:: {static}electrumsv-1.4.0b1/20210803-blockchain-scanner-02-dialog-start-page.png
   :align: center
   :width: 90 %
   :alt: The "Blockchain scanner" dialog used to find payments on the blockchain.

   The "Blockchain scanner" dialog used to find payments on the blockchain.

You can read our guide on `how to scan the blockchain <https://electrumsv.readthedocs.io/en/releases-1.4/getting-started/scanning-the-blockchain.html>`__
in our documentation.

The details
-----------

Codebase upgrade
================

When the ElectrumSV project began, the software it inherited had a range of technical limitations.
These ranged from loading all wallet data into memory when a wallet was opened, and writing it all
out when it was saved. To potentially adding and deleting transactions to the user's wallet every
time they changed server.

With the 1.3.0 release we switched over to the use of a database for wallet storage, and solved
the "load all data" issue. But we didn't have time to rewrite things like the blockchain
synchonisation code that could delete a transaction the user just signed, because the server they
switched to had incompatible settings. This meant that the 1.3.0 release, whose purpose was
really primarily multi-signature transaction support, treated it's usage of database storage
as an interim step towards a later ideal.

Making the database authoritative
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A core goal with the 1.4.0 work was making the database layer enforce consistency for wallet
data. This required us to go through all the existing wallet data and reprocess it and extend
the databases. You can see our new schema in `our documentation <https://electrumsv.readthedocs.io/en/releases-1.4/building-on-electrumsv/wallet-database.html>`__,
but be aware you can't use it to get a working ElectrumSV wallet. We do not, and will never support this.

Removing complication
~~~~~~~~~~~~~~~~~~~~~

Previously we stored a whole lot of wallet data in memory, and every time we would process a
transaction we would reconcile that transaction against the in memory data and then change the
database. This was complicated, slow and hard to maintain. With the database enforcing
consistency, we can completely get rid of these. This and more, have left the code with a lot
less technical debt and made it much easier to develop.

Type annotations
^^^^^^^^^^^^^^^^

We have added type annotations to a lot of the code, with the exception of the user interface and
the unit tests. This provides us with a higher level of certainty that our code is correct, but
the inherent flaws of bolt-on type annotations cannot give us as good a certainty as we would have
if we were using a statically typed language. We will extend this support as far as we can, beyond
this release.

Database writes
^^^^^^^^^^^^^^^

Our original database implementation had a workable custom approach to doing database writes, and
waiting until they were complete. We now use the standard Python `Future mechanism <https://docs.python.org/3/library/concurrent.futures.html>`__
for this, which both makes the code more approachable to new developers and also allows us to write
faster code. You can check out `our implementation <https://github.com/electrumsv/electrumsv/blob/releases/1.4/electrumsv/wallet_database/sqlite_support.py#L295>`__, if
that's what you are into.

Transaction imports
^^^^^^^^^^^^^^^^^^^

When we receive a new transaction, we break it down and import it into the database. We store all
the inputs and all the outputs, and we even store the offsets of the scripts in each of those.
The goal is not to have to reprocess the transaction to get data from it, but to rather have that
data easily accessible from the database. You can check out `our implementation <https://github.com/electrumsv/electrumsv/blob/releases/1.4/electrumsv/wallet.py#L3387>`__, if that's
what you are into.

Useful information
------------------

Where can you learn more about how to use ElectrumSV?
=====================================================

We have a selected range of guides to common tasks that our users may want to do in our
documentation, please `check it out <https://electrumsv.readthedocs.io/>`__.

Where can you download ElectrumSV?
==================================

The only safe downloads are available from: `electrumsv.io <https://electrumsv.io/>`__

Where can you get support or assistance?
========================================

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

What changed in the earlier versions?
=====================================

Each of our release articles links to the article for the release before it. You can follow our
releases back and see what changed in each, by the article that accompanied that release.

Read about what changed in `ElectrumSV 1.3.13 <{filename}electrumsv-1.3.13.rst>`__

