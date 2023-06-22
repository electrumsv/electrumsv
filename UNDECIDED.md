# UNDECIDED

There are numerous things RT knows will be worked on and possible ways that they might change.
This document is intended to provide enough detail about these things that others might think
about and contribute to discussion that influences decisions about how we might either do these
things or prepare for them in the long term.

## Decisions to ponder.

### The wallet UI experience

The historical 1.3 wallet UI was basically one account where that account had the range of tabs
for sending, receiving and through to keys and utxos. The primary tabs were send, receive and the
history list. We can ignore the developer-oriented tabs and keep them in a complex form, but it
should be possible to replace all the primary tabs.

This frames one loose possibility as a directional guideline:

* When a wallet is opened the user could see their wallet history. This should include all payments
  for all accounts, as we have multiple accounts in 1.4.0.
* We should be able to remove the send tab. The form can be put into a popup dialog and a button
  could be added to the toolbar, perhaps "send payment". The user might be able to have multiple
  parallel send dialogs open doing different draft payments at the same time. The invoice list
  is no longer necessary as invoice payments are in the wallet history.
* We should be able to remove the receive tab. The form can be put in a popup dialog and a button
  could be added to the toolbar, perhaps "receive payment". The expected payment list is no longer
  necessary as payment request payments are in the wallet history.

There is also a line between what we need to do that is acceptable for an initial 1.4.0 release
and what we can defer but prepare for.

### The history list

The historical wallet UI for the history list is a list of transactions. These are ordered by block
timestamp in terms of block height and block position, which ensures that they appear as
unconfirmed, then confirmed transactions. And in this ordering spends of coins always came after
receipts of those coins, even if they were in the same block.

The 1.4.0 history list does not list transactions. It lists payments. These cannot be ordered in
the same way. Payments have three types:

* Associated with a payment request created internally (we are the payee).
* Associated with an invoice created externally (we are the payer).
* Not associated with anything. At this time these are transactions we have no information about
  that we recovered through the restoration process. There is also the case of coinbase
  transactions although this would need a registered tip filter to detect them and the user would
  have to manage that for now.

The goal is that the ordering makes as much sense as anything Bitcoin can to regular people. There
are some initial aspects that we might assume are true:

* We definitely want open payments (unpaid invoices and payment requests) to be listed at the top
  like unconfirmed transactions were. These would act like outstanding and draft payments.
* When a previously open payment is closed (paid, expires or manually closed) it should perhaps be
  marked with that timestamp for sorting.
* Payments that come from restoration cannot be sorted by date to give correct ordering. Each will
  have one transaction associated with them, but there is also the block index of that transaction
  that might influence ordering of spends of coins received in the same block. On one hand how much
  is it worth to address this, it would only affect legacy users not users who use the new backup
  moving forward.

Then there is the transaction dialog. Previously the user would double click on an entry in the
history list and it would open. Now we need a new payment dialog. But we want to keep it focused
on the core details of the payment, and put the developer centric things like the possibly
multiple transactions in areas developers can still get to but not front and center.

### Payment contacts

We have contacts in 1.4.0. A user can add one. The next step is integrating them more and more
into the wallet, and there will be natural ways to do this. One way that is being prepared for
is allowing a contact to be associated with a payment.

* A user could open the payment dialog and select the contact to be associated with it.
* A user when making a payment request could select a contact and derive keys based on their
  identity in some way, this would lock the payment request to that contact.
* A user importing an invoice from a "pay:" url might be prompted to select a contact to
  associate it with.
* An invoice or payment request made using the contact messaging has an implicit contact and that
  can automatically be locked to the payment.

We might show a column in the history list with the lifehash avatar of each involved contact.

### P2P network connectivity

Our first preference should be to broadcast transactions using the P2P network. But we should have
a fallback for when it is not available (MAPI or ARC). We should not trust either and should use
output spend notifications for all approaches.

What does the P2P experience look like in the wallet?
