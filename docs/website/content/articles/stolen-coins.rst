How do coins get stolen?
========================

:date: 2020-10-05 16:00
:summary: This is an analysis of how people have had their coins stolen on BSV, BCH or BTC. And a formalisation of how ElectrumSV will deal with reports.
:category: research
:authors: Roger Taylor

Occasionally ElectrumSV users have reported that their coins were stolen out of their wallet.
This is something we never want to happen, but it does, and that it has to even just one person
is more often than it should have happened. In order to help people understand what they might
have done to put themselves in a situation where their coins could be stolen, we're going to read
and summarise all the past cases.

We'll start with our own wallet for Bitcoin SV, then we'll look at the equivalent wallet for
Bitcoin Cash and lastly we'll look at the original wallet from Bitcoin Core. After that, we'll
sum up the conclusions we came to after researching the existing identifiable cases. Hopefully
this will result in a path forward of some sort.

Summarising reports
-------------------

The approach used to find reports for each wallet is to look at the issue tracker for the given
Bitcoin. There are likely many more cases reported through social media, or other forms of
communication, but finding those is prohibitive in terms of the required effort.

Hacking is most likely installation of malware on the user's computer, but might also possibly
be that someone obtained access to their wallet or seed words.

ElectrumSV
~~~~~~~~~~

There are only two instances of people having their coins stolen on our issue tracker that I can
find, I've supplemented this with additional remembered instances.

- Coins moved on their own. User established that it was hacking not fake ElectrumSV. 1
- Coins moved on their own. Cause unknown. `1`__ `2`__
- Coins moved on their own. User downloaded fake ElectrumSV software from a fake site using a bad
  link. 1 2

__ https://github.com/electrumsv/electrumsv/issues/200
__ https://github.com/electrumsv/electrumsv/issues/528

Electron Cash
~~~~~~~~~~~~~

Like Electrum Core, Electron Cash suffered from a problem where bad actors could start malicious
servers and send authentic looking upgrade messages to any connected user with a fake update
link to fake software that had been altered to steal coins. The first release of ElectrumSV was
made after this problem was discovered, so we lucklily avoided this problem. It is very likely that
there were many more cases of fake software stealing coins than are listed here.

- Coins moved on their own. User established it was hacking not fake ElectrumSV. `1`__
- Coins moved on their own. Cause unknown. `1`__ `2`__ `3`__
- Coins moved on their own. User downloaded fake Electron Cash software from a fake site using a
  bad link. `1`__ `2`__ `3`__ `4`__

__ https://github.com/Electron-Cash/Electron-Cash/issues/1433

__ https://github.com/Electron-Cash/Electron-Cash/issues/1141
__ https://github.com/Electron-Cash/Electron-Cash/issues/1687
__ https://github.com/Electron-Cash/Electron-Cash/issues/73

__ https://github.com/Electron-Cash/Electron-Cash/issues/280
__ https://github.com/Electron-Cash/Electron-Cash/issues/966
__ https://github.com/Electron-Cash/Electron-Cash/issues/1288
__ https://github.com/Electron-Cash/Electron-Cash/issues/997

I went through the titles of all Electron Cash issues, and checked any that looked like they were
related to coin theft. In addition I searched for "malware", "theft", "stole" and a few other
keywords.

Electrum Core
~~~~~~~~~~~~~

Like Electron Cash, Electrum Core suffered from a problem where bad actors could start malicious
servers and send authentic looking upgrade messages to any connected user with a fake update
link to fake software that had been altered to steal coins. The first release of ElectrumSV was
made after this problem was discovered, so we lucklily avoided this problem. It is very likely that
there were many more cases of fake software stealing coins than are listed here.

- Coins moved on their own. User established it was hacking not fake ElectrumSV. `1`__ `2`__
  `3`__
- Coins moved on their own. Cause unknown. `1`__ `2`__ `3`__ `4`__ `5`__
- Coins moved on their own. User downloaded fake Electrum Core software from a fake site using a
  bad link. At the time of writing there are `69 known occurrences`__.
- Coins were stolen because of some weird Electrum bug. `1`__
- Additional coins were stolen because of fake recovery services. `1`__
- Coins were stolen by clipboard malware that changes addresses. `1`__

__ https://github.com/spesmilo/electrum/issues/5225
__ https://github.com/spesmilo/electrum/issues/2740
__ https://github.com/spesmilo/electrum/issues/834

__ https://github.com/spesmilo/electrum/issues/3976
__ https://github.com/spesmilo/electrum/issues/2699
__ https://github.com/spesmilo/electrum/issues/2131
__ https://github.com/spesmilo/electrum/issues/2705
__ https://github.com/spesmilo/electrum/issues/3034

__ https://github.com/spesmilo/electrum/issues?q=label%3Aphishing+is%3Aclosed

__ https://github.com/spesmilo/electrum/issues/613

__ https://github.com/spesmilo/electrum/issues/3238

__ https://github.com/spesmilo/electrum/issues/6091

Electrum Core has a thousand or so issues, so the issues located above were those that were
results in a search for "malware", "theft", "stole" and a few other keywords.

Analysis
--------

It is hard to say how common these problems are solely from the Github issues, as it is not
possible to link how often they appear there to how often they were reported through other
avenues. But if I had to guess, I would say they were not that common. If someone has their
coins stolen, they are going to complain loudly and they are more than likely going to be told
to report an issue. I would also expect that it has happened a lot more for Electrum Core and
Electron Cash due to their phishing problems with the fake upgrade alerts.

Public record
~~~~~~~~~~~~~

It is in ElectrumSV's interest to solely respond to users about these sorts of problems in our
Github issues. And it is also in our interest to push the user to investigate as comprehensively
as possible. Knowing how they were hacked, allows us to better act to protect our other users,
and having a record of both the reports and the results of any investigations is invaluable
to learning from this. While it is also possible that community members may chime in and help
with any investigation, it is considered unlikely they will.

Pre-existing altcoin usage
~~~~~~~~~~~~~~~~~~~~~~~~~~

One thing it has not occurred to me to ask, is if the user is also using Electrum Core
or Electron Cash. All a thief has to do is extract any seed words, and then look for usage of those
seed words on other blockchains. They can and would likely automate the process. We should add
asking this to a checklist to be asked of any users in this situation. I couldn't find any
instances where this was verified to occur, but I am pretty sure I have read about it happening
in the past.

Lying or laziness
~~~~~~~~~~~~~~~~~

In a few of the cases, users claimed to be using software that they couldn't have been using
given the developers analysis of the other information. It was likely that the user just went to
the project's web site and copied the latest link, and said "Here, this is what I am using."
rather than intentionally being deceitful.

Why aid us if coins are not recoverable
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We cannot provide the user who has had their coins stolen with a way to easily get them back.
So the question might be asked, why would they spend any time helping us investigate how they
were stolen?

If the user intends on reporting the theft to some authority, then any information we can help
them find, may be of assistance. However, I have yet to see any instances where someone has
reported theft of coins to the authorities, and had any resolution to their satisfaction. This
does not mean that no-one has. I expect most users will give up and shake their fist in
frustration that Bitcoin transactions are not reversible. Others will be aware that their
hard drive contains personal data they do not want to give out, or that they have material
obtained from P2P networks that might make them liable for crimes of various natures, whether
copyright or other.

The user might also be mistaken. Several Electrum Core reports were from people that did not
understand their wallet or much about how it worked, and often were just misreading things.
However, this is likely to be hinted at in any initial screenshots that the user provides in
their initial report. It might be worth improving the checklist to filter this out for sure.

It's even prohibitively hard to safely aid us in investigating the cause, if the assumption
is that it is best for them to stop using the computer because it might be hacked.

Shared frustration
~~~~~~~~~~~~~~~~~~

It is not enjoyable to hear that users have had their coins stolen and the worst possible scenario
would be that somehow an official build was compromised, and all users are now exposed to the
possibility of having their coins stolen. This does not just relate to coin theft, no maintainer
wants to release software with severe bugs in it either. Maintaining a wallet is enough work
without dealing with this sort of havoc. I can see the same pained resignation in responses to
reports like these by developers of other wallets that I feel when I have to deal with a similar
report for ElectrumSV.

So it is reassuring to see developers on other wallets using the same reasoning I have found myself
using. That if this were a buggy release or a compromised build, there would be a lot more reports
of the problem and a lot more angry users. That there is one user reporting this, and that
they lost a small amount of coins, is more indicative that the problem is not with ElectrumSV but
either that they were hacked or downloaded a fake version of the wallet instead.

Summing up
----------

The biggest discovery was that there were a much fewer reports of this than I expected. Electron
Cash had eight reports. ElectrumSV had five reports. And the older and more widely used Electrum
Core had eleven that were discoverable, ignoring those that were because of the malicious server
fake update alert debacle and other rarer problems.

Investigation checklist
~~~~~~~~~~~~~~~~~~~~~~~

It should be possible to continually refine a checklist of information needed from users, based
on past reports. There is no point in presenting users with a list of multiple questions at the
start of the process, they will not answer the questions reliably. Some users may not believe they
need to provide any details, and will assert their beliefs and dismiss any questions. Other users
may not have the technical skill to know how to answer them. It would be much more productive to
step them through the questions one by one.

1. Inform the user that they may have been hacked and that they should shut down the computer the
   wallet was on, and use another computer to continue the discussion.
2. Ask the user what operating system they are using because they won't have filled out the
   new issue template.
3. Ask the user to find the wallet file in their operating systems file explorer and take a
   screenshot of it.
4. If the file details do not match any known release, inform the user they downloaded a fake
   wallet and it is no surprise their coins were stolen. The investigation is complete.
5. Ask the user to provide the SHA256 checksum of the file. At this point their operating
   system should be known, and it should be able to provide them with instructions suited to
   that operating system.
6. If the SHA256 checksum does not match the checksum of the official release, then inform the user
   they downloaded a fake wallet and it is no surprise their coins were stolen. The investigation
   is complete.
7. Ask the user if they are using Electrum Core or Electron Cash, and if so, whether they used the
   same seed words in ElectrumSV.
8. If they used the same seed words in Electrum Core or Electron Cash, then inform them this may
   be the cause of their coins being stolen. They are however at this point in a quandary, if
   they open and check their coins in that other wallet and they have not been stolen then this
   might expose those wallets to theft as well. If they are using another computer, they can
   download known correct versions of the other wallet software and restore their coins, and see
   the state of their wallets.
9. At this point, they have proven by the SHA256 checksum that they have a legitimate version of
   ElectrumSV. They have claimed that they do not use the other wallets on the same computer,
   which indicates that that is not a potential cause. And that they do not use the same seed
   words in those other wallets if they use them elsewhere.
10. Are there widespread reports that match this for many many users of ElectrumSV? Given that
    there are tens of thousands of downloads of each release, if the official builds are
    compromised there will be widespread complaints and a mob of angry users. If so, then the
    investigation is complete. This would have been obvious before beginning working through
    the list, of course.

For investigation of stolen coins where the user makes it past the end of the list, the most
likely option is that they were hacked. They should do something like preserving their hard
drive for evidence, and reporting it to the police.

For users who refuse to aid in the investigation, there is not much we can do to help them. We
should state something along the lines that we are happy to help them investigate further when
they are willing to assist us, and close the issue until then. Similarly if they reveal they
have since reformatted their hard drive, then there is not much we can do.
