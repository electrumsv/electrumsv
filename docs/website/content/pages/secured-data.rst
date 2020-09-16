Accounts and their secured data
===============================

:date: 2020-05-28 16:00
:modified: 2020-09-08 16:00
:authors: The ElectrumSV Developers
:tags: guide
:summary: An introduction to the topic of an accounts secured data.

The sole purpose of an account's secured data is that is currently used for restoration of the
payments made to, and from, that account. In the worst case, you can restore the account using
the secured data, which might include:

* Seed words (stored encrypted).
* A passphrase to accompany those seed words (stored encrypted).
* In some cases also the derivation path, which is required to be used with the
  seed words, in order to find the payments.

Not every type of account has secured data. Types which don't include:

* Hardware wallet accounts. The sole purpose of hardware wallets, which are unfortunately all
  flawed, is to store the secured data on the hardware wallet device outside of the wallet
  account they are linked to.
* Watch-only accounts. These are created with the purpose of monitoring the blockchain to
  see usage of the account's keys. They do not have secured data.

Viewing secured data
--------------------

Any accounts that have secured data, have an enabled "View Secured Data" menu accessible
through their entry in the accounts list.

One type of account that may have no secured data, one set of secured data or any number of
different secured data, is the multi-signature account. The secured data for these is accessed
through looking at the account information, and viewing the multi-signature only cosigner
overview provided there.

Related topics
--------------

* `Backing up your wallet <{filename}wallet-backups.rst>`_