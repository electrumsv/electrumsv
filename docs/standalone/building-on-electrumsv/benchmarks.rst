Benchmarks
===================
The benchmarks use the REST API running on a 'live' RegTest wallet server to
produce global metrics about performance.

Currently this includes the rate of transaction broadcast and processing and
its interaction with the size and composition of the utxo set. It is likely
that the benchmarks will be added to and changed from what they are today
(perhaps with an ergonimic way of gathering profiling data at runtime).

The benchmarks are not run in the Azure pipeline in order to avoid slowing it
down. Furthermore, the results would not be consistent across time because the underlying
hardware and strain on the Azure agent will vary over time. Therefore, the benchmarks
should be run on your local development machine where these factors can be controlled for.

Installation of dependencies
-------------------------------

1. Install pytest pre-requisites::

    python3 -m pip install pytest pytest-cov pytest-asyncio pytest-timeout electrumsv_node openpyxl


2. Install the ElectrumSV-SDK (follow instructions here: https://electrumsv-sdk.readthedocs.io/ ) and then do::

    electrumsv-sdk install node
    electrumsv-sdk install electrumx
    electrumsv-sdk install --repo=$PWD electrumsv

This will install the repositories and dependencies for these components.

Settings
-----------------
**The SDK components should be stopped before running the tests as the tests automate resetting and
starting these services - it will fail if they are already running.**

The current stresstest automates the preparatory measure of splitting utxos
up to a predefined count: ``DESIRED_UTXO_COUNT`` which defaults to 5000 utxos.

There is also a parameter for how many coin splitting outputs there are per
coin splitting transaction: ``SPLIT_TX_MAX_OUTPUTS`` which defaults to 2000.
This is included because prior experience found that this affected throughput.

The number of worker tasks: ``N_TX_CREATION_TASKS`` (which run as coroutines
on the asyncio event loop) defaults to 100. I recommend leaving this unchanged.

The total number of transactions that are created and broadcast is defined by
the environment variable: ``STRESSTEST_N_TXS`` and defaults to 2000. If you
want to perform a prolonged stresstest you could raise this significantly.

The timer starts when the initial coin splitting has completed and stops when
all transactions have been:

- Created and signed
- Broadcast to the network
- Fully confirmed and processed (there is an automated background task that mines blocks and a websocket for waiting on transaction state changes)

In summary; The default settings (as environment variables) are::

    N_TX_CREATION_TASKS = 100
    DESIRED_UTXO_COUNT = 5000
    SPLIT_TX_MAX_OUTPUTS = 2000
    STRESSTEST_N_TXS = 2000

Run with pytest
-------------------
Run the benchmark::

    python3 -m pytest -v contrib/functional_tests/stresstesting

The result is exported to::

    contrib/functional_tests/stresstesting/.benchmarks/bench_result.xlsx

With this format:

.. image:: example_bench_results.png


Run with a matrix of settings
-------------------------------
There is also a python script for running the benchmark multiple consecutive
times with a matrix of different settings and appending the results to the excel
spreadsheet::

    python3 contrib/functional_tests/stresstesting/run_stresstest_matrix.py

The initial output will look like this::

    ============================== Test Params Matrix ==============================
    TestParams(number_txs=2000, total_utxo_count=2000, max_split_tx_outputs=500)
    TestParams(number_txs=2000, total_utxo_count=2000, max_split_tx_outputs=2000)
    TestParams(number_txs=2000, total_utxo_count=5000, max_split_tx_outputs=500)
    TestParams(number_txs=2000, total_utxo_count=5000, max_split_tx_outputs=2000)
    TestParams(number_txs=2000, total_utxo_count=10000, max_split_tx_outputs=500)
    TestParams(number_txs=2000, total_utxo_count=10000, max_split_tx_outputs=2000)
    TestParams(number_txs=5000, total_utxo_count=2000, max_split_tx_outputs=500)
    TestParams(number_txs=5000, total_utxo_count=2000, max_split_tx_outputs=2000)
    TestParams(number_txs=5000, total_utxo_count=5000, max_split_tx_outputs=500)
    TestParams(number_txs=5000, total_utxo_count=5000, max_split_tx_outputs=2000)
    TestParams(number_txs=5000, total_utxo_count=10000, max_split_tx_outputs=500)
    TestParams(number_txs=5000, total_utxo_count=10000, max_split_tx_outputs=2000)
    ================================================================================


This can be thought of as an example script that can be tweaked to your own needs.


Logging
---------------
There is a ``pytest.ini`` file in ``contrib/functional_tests/pytest.ini`` with these settings::

    [pytest]
    log_cli=true
    log_level=INFO

If you are finding the logging details distracting or you want more verbose logging you can refer
to the pytest documentation and change the ``pytest.ini`` settings as needed.