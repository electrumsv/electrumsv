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

We will schedule an upgrade to Python 3.11 as soon as possible.

Consequences
------------

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
