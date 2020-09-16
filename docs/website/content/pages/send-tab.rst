The Send tab
------------

:date: 2020-05-28 16:00
:modified: 2020-09-08 16:00
:authors: The ElectrumSV Developers
:tags: guide
:summary: Information about the various features available in the send tab.

The Send tab is used to construct outgoing payments. The wallet owner can opt to leave choosing
what coins to spend to the wallet to select, or can manually select the ones to use from the
Coins tab using the ``Spend`` menu option.

From (optionally present)
=========================

The ``From`` field is only visible if the wallet owner has selected coins from the
``Coins`` tab, and used the ``Spend`` menu option to manually designate that
the payment should only use those coins. If the user has not manually designated the spending of
specific coins, then the wallet will choose from all the coins as needed to cover the
amount being spent.

Pay to (required)
=================

The wallet owner is required to provide a destination for the payment. There are several different
types of destination that can be provided:

- **An address**. This is implicitly used in what is known as a "pay to public key hash"
  (P2PKH) output, as an address is a public key hash. In the past "pay to script hash" (P2SH)
  outputs were also supported, using a different form of address, but these are now disabled
  on the Bitcoin SV blockchain. It must have the standard base58 encoding.
- **A |BIP276Link| script** (external link). This provides a way for payments to be
  made to destinations that do not have addresses. ElectrumSV uses these for multi-signature
  accounts, as both bare multi-signature and accumulator multi-signature accounts are not
  addressable. It must have the prefix "bitcoin-script:".
  **Script assembly.** There is no exact standard specification for consistent
  representation of bitcoin script in assembly language form. While for the most part
  assembly is used at a user's own risk, it can be used with some care. In order for the
  wallet to recognize script assembly, it must have the prefix "asm:".
- **Multiple destinations**. The ``Tools`` menu option ``Pay to many``
  can be used to toggle the ``Pay to`` field so that it accepts more than one
  destination.
  
.. |BIP276Link| raw:: html

   <a href="https://github.com/moneybutton/bips/blob/master/bip-0276.mediawiki" target="_new">BIP276-encoded</a>

Description (optional)
======================

If provided by the wallet owner, the description is recorded against the transaction and is
shown on the ``History`` tab (public transaction) or ``Transactions`` tab
(non-public transaction), depending on whether the transaction is public yet.

Optional setting: Bitcoin SV blockchain compatibility only
==========================================================

One way to ensure that all the coins in the current account are not also linked to the
Bitcoin Cash blockchain, is to spend them in a way that is only compatible with the Bitcoin SV
blockchain.

The simplest way to do this is to:

- Check this setting.
- Copy an address from the ``Receiving`` tab.
- Paste the address into the ``Pay to`` field.
- Click the ``Max`` button to spend all the coins in the account.
- Send the transaction.

All the coins in the account should now be Bitcoin SV only, and can be spent without worrying about
any previously linked Bitcoin Cash coins. This will not necessarily apply to new coins that arrive
in the account, which depending on the source may still be linked. One downside to this approach
is that it has no privacy, and links all the coins in your wallet to some degree. A wallet owner
who is paranoid about their privacy, can individually split their coins.

This setting is not available for hardware wallets. The existing hardware wallets that are
supported by ElectrumSV are made in such a way that they can only sign a very limited range of
transaction types. They are unable to sign correctly formed transaction data, like those used by
ElectrumSV to make transactions only compatible with the Bitcoin SV blockchain.

If this setting is visible and enabled, any payments made will be made with a transaction that
includes an extra data carrier output. This data carrier output is constructed with ``OP_FALSE
OP_RETURN`` and by including it, the transaction will be considered "non-standard" and
will be rejected by any Bitcoin Cash nodes it is sent to. It is possible that a malicious Bitcoin
Cash miner could choose to bypass the rules that would otherwise cause this transaction to be
rejected, but it is very unlikely that they will choose to and it would have negative repercussions
for the Bitcoin Cash blockchain.

This setting can be made visible or hidden from the ``Wallet`` tab of the
``Preferences`` window, where a setting for that purpose is present.
