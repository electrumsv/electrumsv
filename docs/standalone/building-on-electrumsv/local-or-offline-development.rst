Local or offline development
============================

A command-line based environment is provided for local Bitcoin SV development.
There is no requirement to be online while using it (after the components are
installed).

More details about the SDK can be found here: https://electrumsv-sdk.readthedocs.io/

Essentially the SDK allows a developer to run:

- A RegTest Bitcoin node
- A RegTest ElectrumX instance (which is the currently used chain indexing service).
- A RegTest ElectrumSV wallet server with REST API or alternatively in GUI mode.
- The Merchant API which runs alongside the Bitcoin node and will be used for transaction broadcasting and merkle proofs.
- A mock service that acts as an intermediate agent for payment requests, invoices and other SPV / p2p functionalities.

With these processes running it allows for a faster development iteration cycle and
the ability to test the correctness of any new changes. This is particularly so for
things like processing of confirmed transactions and reorgs - which is not feasible
on public testnets (e.g. waiting for a new block to be mined or for a reorg to happen).

A useful workflow for debugging can be to set a "pdb" break point and run
the functional tests which then enters the debugger interactive terminal.

For details about formal, automated functional testing, please see the sections:

- functional tests
- stresstesting

The SDK also makes it trivial to reset all services back to a "clean slate" and to
perform deterministic (i.e. repeatable) testing - especially for simulated reorgs.

