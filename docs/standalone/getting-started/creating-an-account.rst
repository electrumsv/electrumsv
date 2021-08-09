Creating an account
===================

If you are reading this, you likely have a new wallet that has no accounts, and you want to add
one to it. We support addition of a wide variety of account types:

- A new "Standard" account. This is the equivalent of creating a new ElectrumSV seed-word
  based wallet in 1.2.5 and earlier.
- A multi-signature account. Use this if you are creating a new multi-signature account, or
  restoring an existing one from master public keys, seed words and so on.
- Importing from text. Use this to import your seed words, whether Electrum seed words, BIP39
  seed words from another wallet, private keys, public keys, master public keys, master private
  keys, and so on.
- Importing a hardware wallet. If you have an existing hardware wallet that has a seed set up on
  it, then you can use this to add an account that links to it and uses it to sign. If you have
  a hardware wallet that does not have a seed set up on it, you should also be able to use this
  to set it up unless the device is a Ledger. Do not buy a Ledger.

This guide solely covers creating a "Standard" account.

Adding a new account
--------------------

On creating a new wallet, the first thing you will be presented with is the window for adding
a new account.

.. figure:: images/creating-a-wallet-04-new-wallet-window.png
   :alt: The account creation window.
   :align: center
   :scale: 80%

   The account creation window.

If you dismiss this window, accidentally or otherwise, you can re-open it by clicking on the
"Add Account" button on the left hand side of the wallet window toolbar. Click it and it will open
the account wizard which allows all supported types of accounts to be created.

.. figure:: images/creating-a-wallet-05-wallet-window-no-account-yet.png
   :alt: The "Add Account" button highlighted.
   :align: center
   :scale: 80%

   The "Add Account" button highlighted.

Creating a new "Standard" Account
---------------------------------

Double-click on the "Standard" entry to proceed. Or if you prefer to work for it, click the
“Next” button or press the enter key. You will be asked for your password so that the generated
seed words and private key data can be encrypted into your wallet. This also verifies you have
the ability to really use this wallet, and should able to add an account.

.. figure:: images/password-dialog.png
   :alt: The password dialog.
   :align: center
   :scale: 80%

   The password dialog.

You will immediately see that the account has been added to your wallet. You will note that at
no point did you have to copy down your new seed words, or confirm them. You will be reminded to
back them up by the wallet, and can do so at your leisure and own risk.

.. figure:: images/creating-an-account-03-wallet-window-post-creation.png
   :alt: The first thing you see on creating your new account.
   :align: center
   :scale: 80%

   The first thing you see on creating your new account.

The "Notifications" tab will be shown every time you own your wallet as long as you have not
dismissed the "Backup your wallet" notification. It is advised you go and back up your secured
data immediately, as it instructs you to.

Follow the link to your secured data
------------------------------------

If you click on the “account’s secured data” link, it will take you directly to that secured
data. But first it will need your password so it can decrypt that data for display.

.. figure:: images/password-dialog.png
   :alt: The password dialog.
   :align: center
   :scale: 80%

   The password dialog.

Having entered the correct password you will see the secured data.

.. figure:: images/creating-an-account-07-secured-data-dialog.png
   :alt: The secured data dialog.
   :align: center
   :scale: 80%

   The secured data dialog.

Congratulations, now write down the seed words somewhere safe. I recommend you look into
`SAFEWORDS <https://coinstorage.guru/>`_ to help you with this. You can dismiss the notification
by clicking on the “X” in it’s top right corner.
