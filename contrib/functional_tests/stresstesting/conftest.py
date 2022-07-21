from typing import Union

import os
import time

import pytest as pytest
from pathlib import Path

from electrumsv_sdk import commands

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


def pytest_sessionstart(session: pytest.Session) -> None:
    """
    Called after the Session object has been created and
    before performing collection and entering the run test loop.
    """
    # prepare something ahead of all tests
    ELECTRUMSV_TOP_LEVEL_DIRECTORY = Path(MODULE_DIR).parent.parent.parent

    commands.stop('node')
    commands.stop('simple_indexer')
    commands.stop('reference_server')
    commands.stop('electrumsv')
    commands.stop('merchant_api')
    commands.stop('header_sv')
    commands.reset('node')
    commands.reset('simple_indexer')
    commands.reset('reference_server')
    commands.reset('electrumsv', repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY,
        deterministic_seed=True)
    commands.reset('merchant_api')
    commands.reset('header_sv')

    # Start components
    if os.getenv("LOCAL_DEV"):
        commands.start("node", mode='new-terminal')
        commands.start("simple_indexer", mode='new-terminal')
        commands.start("reference_server", mode='new-terminal')
        commands.start('merchant_api', mode='new-terminal')
        commands.start('header_sv', mode='new-terminal')
        commands.start("electrumsv", repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY, mode='new-terminal')
    else:
        commands.start("node", mode='background')
        commands.start("simple_indexer", mode='background')
        commands.start("reference_server", mode='background')
        commands.start('merchant_api', mode='background')
        commands.start('header_sv', mode='background')
        commands.start("electrumsv", repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY, mode='background')
    time.sleep(8)


def pytest_sessionfinish(session: pytest.Session, exitstatus: Union[int, pytest.ExitCode]) -> None:
    """
    Called after whole test run finished, right before
    returning the exit status to the system.
    """
    # prepare something ahead of all tests
    commands.stop()
