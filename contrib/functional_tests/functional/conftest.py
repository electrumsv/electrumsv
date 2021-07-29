import os
import time
from pathlib import Path
from typing import Union

import pytest

from electrumsv_sdk import commands


MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


def pytest_sessionstart(session: pytest.Session) -> None:
    """
    Called after the Session object has been created and
    before performing collection and entering the run test loop.
    """
    # prepare something ahead of all tests
    ELECTRUMSV_TOP_LEVEL_DIRECTORY = Path(MODULE_DIR).parent.parent.parent

    if os.getenv("LOCAL_DEV"):
        electrumx_repo = os.getenv("LOCAL_REPO_ELECTRUMX", "")
        command_mode = "new-terminal"
    else:
        electrumx_repo = ""
        command_mode = "background"

    commands.stop('node', component_id='node1')
    commands.stop('electrumx', component_id='electrumx1')
    commands.stop('electrumsv', component_id='electrumsv1')
    commands.reset('node', component_id='node1')
    commands.reset('electrumx', component_id='electrumx1', repo=electrumx_repo)
    commands.reset('electrumsv', component_id='electrumsv1', repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY,
        deterministic_seed=True)

    # Start components
    commands.start("node", component_id='node1', mode=command_mode)
    commands.start("electrumx", component_id='electrumx1', mode=command_mode,
        repo=electrumx_repo)
    commands.start("electrumsv", component_id='electrumsv1',
        repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY, mode=command_mode)

    time.sleep(8)

def pytest_sessionfinish(session: pytest.Session, exitstatus: Union[int, pytest.ExitCode]) -> None:
    """
    Called after whole test run finished, right before
    returning the exit status to the system.
    """
    # prepare something ahead of all tests
    commands.stop()
