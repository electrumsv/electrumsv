import logging
import os
import sys
import threading
import unittest

# NOTE(rt12) We are monkeypatching in our replacement before anything else is imported ideally.
from electrumsv import ripemd # pylint: disable=unused-import

from electrumsv.networks import Net, SVTestnet, SVMainnet
from electrumsv.wallet_database.sqlite_support import DatabaseContext, JournalModes


logging.disable(logging.CRITICAL)


def setup_module(module):
    # In Python 3.8 on Windows, the DLL search paths have been constrained for security.
    if sys.version_info[:3] >= (3, 8, 0) and sys.platform == "win32":
        cwd = os.getcwd()
        libusbdll_path = os.path.join(cwd, "libusb-1.0.dll")
        if os.path.exists(libusbdll_path):
            os.add_dll_directory(cwd)

    # CI runs very slowly with sqlite WAL journaling, probably due to networked drives.
    DatabaseContext.JOURNAL_MODE = JournalModes.TRUNCATE



# Set this locally to make the test suite run faster.
# If set, unit tests that would normally test functions with multiple implementations,
# will only be run once, using the fastest implementation.
# e.g. libsecp256k1 vs python-ecdsa. pycryptodomex vs pyaes.
FAST_TESTS = False


# some unit tests are modifying globals; sorry.
class SequentialTestCase(unittest.TestCase):

    test_lock = threading.Lock()

    def setUp(self):
        super().setUp()
        self.test_lock.acquire()

    def tearDown(self):
        super().tearDown()
        self.test_lock.release()


class TestCaseForTestnet(SequentialTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        Net.set_to(SVTestnet)

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        Net.set_to(SVMainnet)
