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
    # Always use the embedded postgres and run in portable mode for consistency between
    # Developer platforms. There is less chance of issues related to different development
    # environments this way.
    os.environ['SDK_POSTGRES_PORT'] = '55432'
    os.environ['SDK_PORTABLE_MODE'] = '1'
    ELECTRUMSV_TOP_LEVEL_DIRECTORY = str(Path(MODULE_DIR).parent.parent.parent)

    indexer_repo = os.getenv("LOCAL_REPO_INDEXER", "")
    reference_repo = os.getenv("LOCAL_REPO_REFERENCE_SERVER", "")

    if os.getenv("LOCAL_DEV"):
        SDK_HOME_DIR = str(Path(MODULE_DIR).parent / "portable_sdk_datadir")
        os.environ['SDK_HOME_DIR'] = SDK_HOME_DIR
        command_mode = "new-terminal"
    else:
        command_mode = "background"

    commands.install('node')
    commands.install('simple_indexer')
    commands.install('reference_server')
    commands.install('electrumsv', repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY)
    commands.install('merchant_api')
    commands.install('header_sv')

    commands.stop('node')
    commands.stop('simple_indexer')
    commands.stop('reference_server')
    commands.stop('electrumsv')
    commands.stop('merchant_api')
    commands.stop('header_sv')

    commands.reset('node')
    commands.reset('simple_indexer')
    commands.reset('reference_server')
    commands.reset('electrumsv', repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY, deterministic_seed=True)
    commands.reset('merchant_api')
    commands.reset('header_sv')

    # Start components
    commands.start("node", mode=command_mode)
    commands.start("simple_indexer", mode=command_mode, repo=indexer_repo)
    commands.start("reference_server", mode=command_mode, repo=reference_repo)
    commands.start('merchant_api', mode=command_mode)
    commands.start('header_sv', mode=command_mode)
    commands.start("electrumsv", repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY, mode=command_mode)

    time.sleep(8)

def pytest_sessionfinish(session: pytest.Session, exitstatus: Union[int, pytest.ExitCode]) -> None:
    """
    Called after whole test run finished, right before
    returning the exit status to the system.
    """
    commands.stop()
