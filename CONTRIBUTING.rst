Branching Model
===============

This model is based on `A successful Git branching model
<https://nvie.com/posts/a-successful-git-branching-model/>`_ but has differences.

Each ElectrumSV major.minor release, e.g. 1.0, has its own *release branch* named, for
example, ``release-1.0``.

Revisions of such a release, for hot fixes, are tagged ``sv-1.0.0``, ``sv-1.0.1``, etc.
In this way someone running a specific release from source, or a developer preparing a new
revision of an existing ElectrumSV release can check out the branch to retrieve and update
the latest source for that release.

``dev`` branch represents current development, into which *feature branches* are merged.
It is not expected to be stable in general.

``master`` branch is intended to be the latest stable but unreleased code.
Production-ready features are merged from ``dev``, or ``dev`` as a whole if near-stable, for
beta-tester feedback.  Any changes here must be merged back into ``dev``.  Hot fixes from
the most recent release branch must be merged back into ``master``.

At some point ``master`` is branched to create a new release branch in preparation for the
next release.
