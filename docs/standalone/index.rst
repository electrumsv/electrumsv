Welcome to ElectrumSV's documentation!
======================================

ElectrumSV is a wallet application for `Bitcoin SV <https://wiki.bitcoinsv.io/index.php/Main_Page>`_, a
peer to peer form of electronic cash. As a wallet application it allows you to track, receive and
spend bitcoin whenever you need to. But that's just the basics, as it manages and secures
your keys it also helps you to do many other things.

.. important::
   ElectrumSV can only be downloaded from `electrumsv.io <https://electrumsv.io>`_.

Getting started
---------------

Before you can send and receive payments, you need to first create a wallet, and then create at
least one account within it.

How do you know you have the official software and not malware?
    Every person who had their coins stolen and was interested in investigating, identified that
    they had not downloaded from our official web site, and had instead obtained malware from some
    other fake site. Many swore they downloaded from the official site until their verified their
    download and found it to be malware. Read more about
    :doc:`verifying your download <getting-started/verifying-downloads>`.

How do you create a wallet?
    Your wallet is a standalone container for all your bitcoin-related data. You should be able
    to create as many accounts as you need within it, each account containing separated funds
    much like a bank account. Read more about
    :doc:`creating a wallet <getting-started/creating-a-wallet>`.

How do you create an account?
    Each account in your wallet is much like a bank account, with the funds in each separated from
    the others. Read more about :doc:`creating a new account <getting-started/creating-an-account>`.

How do you receive a payment from someone else?
    Each account has the ability to provide countless unique and private receiving addresses and
    by giving a different one of these out to each person who will send you coins, allows you to
    receive funds from them. Read more about
    :doc:`receiving a payment <getting-started/receiving-a-payment>`.

How do you make a payment to someone else?
    By obtaining an address from another person, if you have coins in one of your accounts, you
    should be able to send some or all of those coins to that address. Read more about
    :doc:`making a payment <getting-started/making-a-payment>`.

How do you scan the blockchain?
    Whether you have restored the wallet, or you are an advanced user and you have given out a
    payment destination ElectrumSV does not know about, it is necessary to be able to find
    payments related to your wallet that exist on the blockchain. Read more about
    :doc:`making a payment <getting-started/scanning-the-blockchain>`.

.. toctree::
   :maxdepth: 1
   :hidden:
   :caption: Getting started

   /getting-started/verifying-downloads
   /getting-started/creating-a-wallet
   /getting-started/creating-an-account
   /getting-started/receiving-a-payment
   /getting-started/making-a-payment
   /getting-started/scanning-the-blockchain

Problem solving
---------------

Why doesn't my hardware wallet work?
    Hardware wallet makers do not provide anywhere near enough support for their devices, and
    some have a history of making breaking changes that stop them working in ElectrumSV. If your
    hardware wallet does not work then this is where you should look for some pointers, whether
    the device is a Trezor, a Ledger, a Keepkey or a Bitbox. Read more about
    :doc:`hardware wallet issues <problem-solving/hardware-wallets>`.

How do I split my coins?
    If you have coins you have not touched since before Bitcoin SV and Bitcoin Cash split from each
    other, you might want to make sure that you can send one of these without accidentally sending
    the other. Read more about
    :doc:`coin splitting <problem-solving/coin-splitting>`.

How do I deal with problems on MacOS?
    Apple have a special operating system which many love. But it comes with some problems. If
    you use MacOS and something isn't working right, maybe we have documented it here. Read more
    about :doc:`solutions to MacOS problems <problem-solving/macos>`.

What if I do not want to upgrade to the latest version?
    Users may continue wanting to use the older ElectrumSV as it is, and not use the new releases.
    Read more about :doc:`upgrading concerns <problem-solving/upgrade-concerns>`.

.. toctree::
   :maxdepth: 1
   :hidden:
   :caption: Problem solving

   /problem-solving/hardware-wallets
   /problem-solving/coin-splitting
   /problem-solving/macos
   /problem-solving/upgrade-concerns

Using ElectrumSV
----------------

Where are the wallet files stored?
    When the wallet application is run it will store and look for related files like blockchain
    headers, wallet settings and wallets in either a standard folder location on the user's
    computer, or in a custom location they have explicitly specified.
    Read more about
    :doc:`data directories <using-electrumsv/data-directories>`.

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Using ElectrumSV

   /using-electrumsv/data-directories

Building on ElectrumSV
----------------------

How is ElectrumSV implemented?
    This section is intended to be a reference for developers, both the existing ElectrumSV
    developers and any other developers who might wish to work with the source code or get
    involved in the project. Refer to the
    :doc:`codebase reference <building-on-electrumsv/codebase-reference>`.

How can I access my wallet using the REST API?
    For most users, accessing their wallet with the user interface will be fine. But if you have
    a minimal amount of development skill the availability of the REST API gives you a lot more
    flexibility. The REST API allows a variety of actions among them loading multiple wallets,
    accessing different accounts, obtaining payment destinations or scripts from any of the
    accounts. Perhaps you want to add your own interface for your wallet or maybe automate how
    you use it. Read more about the
    :doc:`REST API <building-on-electrumsv/rest-api>`.

How can I access my wallet using the node wallet API?
    Read more about the
    :doc:`node wallet API <building-on-electrumsv/node-wallet-api>`.

How would I extend ElectrumSV as a customised wallet server?
    The REST API is limited in what it can do by nature. Getting the ElectrumSV development team
    to add what you want to it, is not guaranteed to happen, may not even be possible and if it was
    who knows how long it would take. An alternative is to build your own "daemon application"
    which is a way of extending ElectrumSV from the inside. Read more about
    :doc:`customised wallet servers <building-on-electrumsv/customised-wallet-servers>`.

Do I have to develop against the existing public blockchains?
    ElectrumSV provides a way for developers to do offline or local development.
    :doc:`customised wallet servers <building-on-electrumsv/local-or-offline-development>`.

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Building on ElectrumSV

   /building-on-electrumsv/codebase-reference
   /building-on-electrumsv/local-or-offline-development
   /building-on-electrumsv/rest-api
   /building-on-electrumsv/node-wallet-api
   /building-on-electrumsv/customised-wallet-servers
   /building-on-electrumsv/functional-tests
   /building-on-electrumsv/benchmarks

The ElectrumSV project
----------------------

Perhaps you are a developer who already helps out on the ElectrumSV project, or you who would like
to get involved in some way, or you are just curious about the processes and information related
to project management and development. If so, this is the information you want.

How can you contribute?
    There are many ways that you can help the ElectrumSV project improve. If you want something
    to work in a different way, you can work on making it different and offer us the changes.
    If you feel the documentation could be better, you can improve it and offer us the changes.
    If you want ElectrumSV or anything related to it in your native language, you can offer to
    do the work to translate it. And that's just a few of the possibilities. Read more about
    :doc:`contributing <the-electrumsv-project/how-you-can-contribute>`.

What platforms and platform versions do we make releases for?
    Our builds are created using both third-party dependencies and the Azure Devops services.
    There are certain limitations that each of these two things imposes on the releases we can
    make. Read more about the relevant choices and limitations involved in
    :doc:`our releases <the-electrumsv-project/releases>`.

Where is the continuous integration and how is it used?
    We use Microsoft's Azure DevOps services for continuous integration. Microsoft provide
    generous levels of free usage to open source projects hosted on Github. This is used to do
    a range of activities for every change we make to the source code, from running the unit
    tests against each change on each supported operating system, to creating a packaged
    release for each system that can be manually tested. Read more about our use of
    :doc:`continuous integration <the-electrumsv-project/continuous-integration>`.

What is the process of releasing a new version?
    Because we generate packaged releases for every change we make, with a bit of extra work we
    can generate properly prepared public releases. This involves changing the source code so
    that the release has the content changes required for new version, and also publishing the
    release and updating the web site to have the content changes required to offer it for
    download. Read more about the :doc:`release process <the-electrumsv-project/release-process>`.

.. toctree::
   :maxdepth: 1
   :hidden:
   :caption: The ElectrumSV project

   /the-electrumsv-project/how-you-can-contribute
   /the-electrumsv-project/continuous-integration
   /the-electrumsv-project/releases
   /the-electrumsv-project/release-process

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
