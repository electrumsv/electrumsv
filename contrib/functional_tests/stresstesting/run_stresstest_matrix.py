"""this is to run the stresstest without pytest (as an option)"""
import logging
import os
import shlex
import subprocess
import sys
from collections import namedtuple
from pathlib import Path

MODULE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
TLD_ESV = MODULE_DIR.parent.parent.parent

logging.basicConfig()
logging.root.setLevel(logging.DEBUG)
logging.basicConfig(level=logging.DEBUG)

TestParams = namedtuple("TestParams", ["number_txs", "total_utxo_count", "max_split_tx_outputs"])

test_parameters = []
for number_txs in (2000, 5000):
    for total_utxo_count in (2000, 5000, 10000):
        for max_split_tx_outputs in (500, 2000):
            test_parameters.append(TestParams(number_txs, total_utxo_count, max_split_tx_outputs))

# test_parameters = [TestParams(2000, 10000, 5000)]
print("============================== Test Params Matrix ============================== ")
for test_params in test_parameters:
    print(test_params)
print("================================================================================ ")

def reset_electrumsv():
    command = f"electrumsv-sdk reset electrumsv"
    process = subprocess.Popen(command)
    process.wait()


def run_electrumsv_background():
    command = f"electrumsv-sdk start --repo={TLD_ESV} --background electrumsv"
    process = subprocess.Popen(command)
    process.wait()


def run_stresstest_pytest(test_params):
    env_vars = {
        'STRESSTEST_N_TXS': str(test_params.number_txs),
        'STRESSTEST_DESIRED_UTXO_COUNT': str(test_params.total_utxo_count),
        'STRESSTEST_SPLIT_TX_MAX_OUTPUTS': str(test_params.max_split_tx_outputs)
    }
    command = shlex.split(f"{sys.executable} -m pytest . -v -v -v", posix=0)
    process = subprocess.Popen(command, env=os.environ.update(env_vars))
    process.wait()
    return process


def stop_electrumsv():
    command = f"electrumsv-sdk stop electrumsv"
    process = subprocess.Popen(command)
    process.wait()


for test_params in test_parameters:
    reset_electrumsv()
    run_electrumsv_background()
    process = run_stresstest_pytest(test_params)
    if process.returncode != 0:
        stop_electrumsv()
        sys.exit(1)
    stop_electrumsv()

