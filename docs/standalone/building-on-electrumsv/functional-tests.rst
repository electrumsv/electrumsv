Functional tests
===================
The functional tests are a set of tests that use the REST API to manipulate the state of a
'live' RegTest wallet and check that the state changes are matching what is expected.
Eventually, the REST API should mature to cover all functionality available through the GUI,
allowing automation of any wallet tasks as well as full end-to-end integration testing
coverage.

The functional tests are run as part of the Azure pipeline for any commits to any new
feature branch or pull requests but can also be run locally (and offline) provided a few
dependencies are installed.

A few examples of functional tests are:

- A simulated reorg test (via the RegTest SDK) in which wallet transactions are affected and move to a new block height with a new merkle branch. The database and general wallet state is checked for consistency before and after the reorg.
- Loading the wallet on the daemon.
- Getting the account details.
- Getting utxos before and after topping up the wallet with new coins.
- Getting utxos before and after splitting a coin into smaller outputs.
- Concurrent transaction broadcasting to check the broadcast pathway and as a basic check for data races.

These tests give a broad-brush coverage of many different code paths and as the
REST API grows to cover all GUI interactions will give assurances about:

- Correctness of wallet state.
- Regressions at the wallet server level that could in turn affect the user experience.

Installation of dependencies
-------------------------------

1. Install pytest pre-requisites::

    python3 -m pip install pytest pytest-cov pytest-asyncio pytest-timeout electrumsv_node openpyxl


2. Install the ElectrumSV-SDK (follow instructions here: https://electrumsv-sdk.readthedocs.io/ ) and then do::

    electrumsv-sdk install node
    electrumsv-sdk install simple_indexer
    electrumsv-sdk install reference_server
    electrumsv-sdk install --repo=$PWD electrumsv

This will install the repositories and dependencies for these components.

Run the functional tests
--------------------------
**The SDK components should be stopped before running the tests as the tests automate
resetting and starting these services - it will fail if they are already running**.

Run the functional tests with pytest like this::

    python3 -m pytest -v -v -v contrib/functional_tests/functional

Which should output something like (but with verbose logging output)::

    contrib\functional_tests\functional\test_reorg.py::TestReorg::test_reorg PASSED
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_get_all_wallets PASSED                                                              [ 25%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_load_wallet PASSED                                                                  [ 33%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_websocket_wait_for_mempool PASSED                                                   [ 41%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_websocket_wait_for_confirmation PASSED                                              [ 50%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_get_parent_wallet PASSED                                                            [ 58%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_get_account PASSED                                                                  [ 66%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_get_utxos_and_top_up PASSED                                                         [ 75%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_get_balance PASSED                                                                  [ 83%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_concurrent_tx_creation_and_broadcast PASSED                                         [ 91%]
    contrib\functional_tests\functional\test_restapi.py::TestRestAPI::test_create_and_broadcast_exception_handling PASSED

    ============================================================= 11 passed, 1 skipped, 0 failed in 49.53s ==========================================================

Logging
---------------
There is a ``pytest.ini`` file in ``contrib/functional_tests/pytest.ini`` with these settings::

    [pytest]
    log_cli=true
    log_level=INFO

If you are finding the logging details distracting or you want more verbose logging you can refer
to the pytest documentation and change the ``pytest.ini`` settings as needed.
