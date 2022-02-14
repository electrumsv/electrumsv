import os
import time
from pathlib import Path

from electrumsv_sdk import commands

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


def pytest_sessionstart(session):
    """
    Called after the Session object has been created and
    before performing collection and entering the run test loop.
    """
    # prepare something ahead of all tests
    ELECTRUMSV_TOP_LEVEL_DIRECTORY = Path(MODULE_DIR).parent.parent.parent

    commands.stop('node', component_id='node1')
    commands.stop('simple_indexer', component_id='indexer1')
    commands.stop('reference_server', component_id='reference1')
    commands.stop('electrumsv', component_id='electrumsv1')
    commands.reset('node', component_id='node1')
    commands.reset('simple_indexer', component_id='indexer1')
    commands.reset('reference_server', component_id='reference1')
    commands.reset('electrumsv', component_id='electrumsv1', repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY,
        deterministic_seed=True)

    # Start components
    if os.getenv("LOCAL_DEV"):
        commands.start("node", component_id='node1', mode='new-terminal')
        commands.start("simple_indexer", component_id='indexer1', mode='new-terminal')
        commands.start("reference_server", component_id='reference1', mode='new-terminal')
        commands.start("electrumsv", component_id='electrumsv1',
            repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY, mode='new-terminal')
    else:
        commands.start("node", component_id='node1', mode='background')
        commands.start("simple_indexer", component_id='indexer1', mode='background')
        commands.start("reference_server", component_id='reference1', mode='background')
        commands.start("electrumsv", component_id='electrumsv1',
            repo=ELECTRUMSV_TOP_LEVEL_DIRECTORY, mode='background')
    time.sleep(8)


def pytest_sessionfinish(session, exitstatus):
    """
    Called after whole test run finished, right before
    returning the exit status to the system.
    """
    # prepare something ahead of all tests
    commands.stop()
