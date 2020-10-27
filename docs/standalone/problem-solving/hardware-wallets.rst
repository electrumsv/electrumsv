Hardware wallet issues
======================

Ledger
------

Message: "The sign path is unusual"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

`Ledger have implemented <https://support.ledger.com/hc/en-us/articles/360015739499-Sign-or-derivation-path-is-unusual>`_
enforced derivation paths for each cryptocurrency. If you set up your hardware wallet with a
different derivation path than it expects for the app you are using on your Ledger device, then
it will in theory show you the above message warning you. You can read the reasons why on the
article linked above. However, some of our users have reported that this is not a warning and
in fact it prevents them from signing leaving them unable to access their funds.

It is recommended that users who experience this upgrade their Ledger firmware to the latest
version and if it still does not allow them to sign, then work out some way to get the funds
from their Ledger back into it with the derivation path Ledger expects. It is very likely that
if users were unable to sign, given that Ledger say it should only be a warning, that this
was a temporary bug in their firmware and an upgrade should fix it when they do.

The process of moving funds to the correct derivation path might be done as follows:

1. Make a new wallet and account in ElectrumSV using the text account option. This will involve
   entering your seed words from your Ledger, so that you can manage the coins directly in
   ElectrumSV.
2. Verify that you can see your coins in your new account, and send a small amount back to yourself
   to ensure you have access.
3. Make a second wallet and account in ElectrumSV using the hardware wallet option. Ensure you
   use the derivation path that Ledger expects you to use, whatever that is.
4. Send a small amount from the first (imported text words) account to the second (new hardware
   wallet) account. Verify that it arrives. This is intended to put an existing small amount of
   coins in your new hardware wallet account so you can verify it works correctly.
5. Send a small amount from the new hardware wallet account back to itself. Verify that the
   hardware wallet signs the transaction correctly as it has in the past, and the problem is
   solved.
6. Send all the coins remaining in the imported text words account over to the new hardware wallet
   account. You should now have your funds safely stored in your Ledger again.

This process of moving your coins of course completely bypasses the protection that your hardware
wallet was supposed to provide, but there's not much else you can do if you want to continue using
it and it won't otherwise let you.

Trezor
------

Message: "Signing transaction" never goes away
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to address flaws in the Bitcoin Core protocol,
`Trezor made changes <https://blog.trezor.io/latest-firmware-updates-correct-possible-segwit-transaction-vulnerability-266df0d2860>`_
to transaction signing which causes errors when users try to sign transactions in ElectrumSV. This
means that anyone who updates their Trezor firmware will not be able to sign transactions.

Let us be clear. It appears that Trezor decided to break all transaction signing for everyone in
order to fix a Bitcoin Core problem. They could have chosen to have Bitcoin Core users opt-in to
the fixes, and not casually broken all other transaction signing for all their users who use
other cryptocurrencies.

The changes to fix this are comprehensive. This is part of a recent pattern of hardware wallet
makers making changes that break their customers ability to use their devices. It is very likely
we will fix this, but we have a lot of other more pressing work to do and the cost of getting
side-tracked for this is too high at this time.

Trezor Model T
______________

:Supported firmware version: `trezor-2.3.0.bin <https://wallet.trezor.io/data/firmware/2/trezor-2.3.0.bin>`_
:Firmware release data: `Trezor Model T feed <https://wallet.trezor.io/data/firmware/2/releases.json>`_

If you are using a later firmware than the recommended version, you will need to downgrade. Make
sure that you have backed up your seed words, as this may cause the device to be wiped.

Trezor One
__________

:Supported firmware version: `trezor-1.9.0.bin <https://wallet.trezor.io/data/firmware/1/trezor-1.9.0.bin>`_
:Firmware release data: `Trezor One feed <https://wallet.trezor.io/data/firmware/1/releases.json>`_

If you are using a later firmware than the recommended version, you will need to downgrade. Make
sure that you have backed up your seed words, as this may cause the device to be wiped.
