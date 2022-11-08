Python 3.11 upgrade
###################

:Date: 2022-11-09
:Status: Pending.

Context
-------

By upgrading to new Python versions as soon as possible we can avoid accruing upgrades as
technical debt which get harder as time passes.

Decision
--------

We will schedule an upgrade to Python 3.11 as soon as possible and require it as the minimum
version ElectrumSV runs against.

Consequences
------------

Minimising maintenance costs
============================

Not supporting older versions of Python means that we do not have to test against multiple
versions of Python, and only have to support the one. This reduces our maintenance costs. It also
reduces the work required to deal with breaking changes introduced by Python distribution
developers as we can just break our code to match their breaking changes and be done with it.

Affected users
==============

Our users primarily run our wallet software by downloading the built executables for their given
platform. These users will not notice any difference, as Python will be compiled into the
executable they download and builds will have been tested before release for regressions.

Linux users impose a cost we cannot pay. It is already problematic for some of the less technical
users to get ElectrumSV running, given the differences between Linux distributions and their
installation choices. A requirement of a minimum version of Python is just extra work they need
to do, out of lots of other work -- and `pyenv` can help them with that.

Moving forward we will likely offer Docker images that ElectrumSV can be run in headlessly. It is
expected these will make the problem for their users much the same as it is for the executable
build users, a technical detail they never see.

Risks
=====

Python developers are like Bitcoin Core developers and make breaking changes on a whim leaving
users to notice the bugs.

Known breaking changes and possible developer actions:

- `IntFlag` inverse operates relative to the set of allocated flags, and is no longer an integer
  inverse of the numerical value. This means that an enum with values A=1, B=2, C=4 will give
  `~(A|B|C) == 0` and `~A == B|C`. In 3.10 `~(A|B|C) == 0xFFFFFFF8` and `~A == 0xFFFFFFFE`.

  - Verify that no inverse operations should happen in `IntFlag` member assignments.

  - Verify that all inverse operations of `IntFlag` members cast to integer first.

  - Developers apply the preceding two entries moving forward.

  - Consider just dropping `IntFlag` and replacing it with something less fragile and less prone
    to undocumented changing behaviour.
