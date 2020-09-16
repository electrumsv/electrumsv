The Coin-splitting tab
======================

:date: 2020-05-28 16:00
:modified: 2020-09-08 16:00
:authors: The ElectrumSV Developers
:tags: guide
:summary: The starting point for reading the ElectrumSV documentation.

If the account is thought to contain coins that are linked on both the Bitcoin SV and Bitcoin
Cash blockchains, then there is a danger that if they are used on the Bitcoin SV blockchain they
may accidentally also be used on the Bitcoin Cash blockchain.

This tab is intended to help our wallet owners try and safely unlink the coins in their account,
especially since some of these users may not understand what they are doing. You can read an
article on the subject of |xlink1| (external link), and it is recommended that you do so.

.. |xlink1| raw:: html

   <a target="_new" href="https://medium.com/@roger.taylor/understanding-coin-splitting-94080819414">understanding coin-splitting</a>

Splitting directly (recommended)
--------------------------------

This approach works differently depending on whether the account is multi-signature or
just the wallet owner signing a transaction. Check the relevant section for details.

Single signer
~~~~~~~~~~~~~

If the current account supports splitting directly, then the user can just click the split
button, enter their password and the coins should split right away.

This cannot work with hardware wallet accounts. Hardware wallets only sign outgoing payments
to simple one-party recipients. The approach used here is not one of the limited types of
simple outgoing payments they support.

Multi-signature signed
~~~~~~~~~~~~~~~~~~~~~~

While a single signer account owner can just be prompted to enter their password and the
process is almost completely taken care of for them, a multi-signature account requires that
enough cosigners be involved through the normal signing coordination process.

Clicking the split button will create an unsigned transaction and preview it, in much the
same way that many mulit-signature account cosigners might already do to start the signing
process. After previewing the transaction, it is their responsibility to go through their
normal signing coordination process.

Splitting using the faucet

The advantage of using the faucet is that it provides a small amount of Bitcoin SV in the form
of a simple incoming payment to be used to aid in the splitting process. This can be included
with coins from the account, and through it's presence, makes other coins it is involved with
only linked to the Bitcoin SV blockchain (split).

Because a hardware wallet can use this small amount of Bitcoin SV and does not have to sign
anything that isn't very simple, it can split coins using this method.

Splitting manually
------------------

If a wallet owner does not want to combine all the coins in their wallet, then they might
want to enable the ability to create Bitcoin SV only transactions, and split their coins
manually. This is manually doing what the direct approach does, but with the user taking
control and is covered further in the help section for the `Send tab <{filename}/send-tab.rst>`.
