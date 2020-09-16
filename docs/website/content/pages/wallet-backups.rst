Backing up a wallet
###################

:date: 2020-05-28 16:00
:modified: 2020-09-08 16:00
:authors: The ElectrumSV Developers
:tags: guide
:summary: How to back up a wallet

Bitcoin is overly technical. Using it is complicated and it is not uncommon to see people
who send funds without understanding what they are doing. There are currently no easy
solutions for backing up a wallet, and anyone who wishes to do so needs to make sure they
understand what is necessary. Only one person is responsible for ensuring their wallet, or all
of their accounts in their wallet are backed up, and that is the wallet owner.

Understanding backup approaches
-------------------------------

Backups, wallets and accounts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A wallet can have multiple accounts, and there is not necessary a link between them. If the wallet
is manually backed up, it will have all the wallet information as of the time of backup including
that of any accounts in it. Seed words may only relate to one account in the wallet.

The myth and the reality of seed words
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Historically, the way to back up an account, was declared to be the seed words that were used
to create that account. From those private and unique words, it was claimed that a wallet could
be recovered. But this is a fantasy, and believing in it is akin to believing in any other kind
of magical-thinking flim-flam. In reality, it is a shallow technique that can possibly restore
basic payment data.

Manually backing up a wallet file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A manual backup of a wallet will preserve the entire contents of the wallet, at the time
the backup was made. ElectrumSV should always be closed before the wallet file is copied. If
a user is not aware where their wallet file is located, they can find out through the "Wallet"
menu in their wallet window, using the "Information" sub-menu. This shows both the directory
the wallet file is located in, and the full path of the wallet file itself.

However, the obvious flaw with this is that is usage of the wallet is ongoing, any manual
backup will be inconvenient to do, if not quickly out of date as usage resumes.

Future backup approaches
------------------------

It is obvious that the current approaches to wallet backups are not good enough. Seed
word-based restoration is already too limited to preserve valuable wallet information
beyond naive payment information. Manual wallet file backups can be inconvenient and
insufficient. ElectrumSV will be looking at alternate approaches.

Related topics
--------------

* `Accounts and their secured data <{filename}secured-data.rst>`_
