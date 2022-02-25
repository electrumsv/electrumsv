import os
import sys
import threading
import unittest

from electrumsv_database.sqlite import DatabaseContext, JournalModes

from electrumsv.networks import Net, SVTestnet, SVMainnet


def setup_module(module):
    # In Python 3.8 on Windows, the DLL search paths have been constrained for security.
    if sys.version_info[:3] >= (3, 8, 0) and sys.platform == "win32":
        cwd = os.getcwd()
        libusbdll_path = os.path.join(cwd, "libusb-1.0.dll")
        if os.path.exists(libusbdll_path):
            os.add_dll_directory(cwd)

    # CI runs very slowly with sqlite WAL journaling, probably due to networked drives.
    DatabaseContext.JOURNAL_MODE = JournalModes.TRUNCATE


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
