import os
from typing import cast
import unittest

from electrumsv.i18n import _
from electrumsv.bitcoin import COINBASE_MATURITY
from electrumsv.constants import TxFlag
from electrumsv.util import format_timestamp
from electrumsv.wallet import AbstractAccount


class MockWhatever:
    pass


def get_confs_from_height(local_height: int, height: int) -> int:
    return max(local_height - height + 1, 0)


class HistoryListTests(unittest.TestCase):
    def test_get_tx_status(self) -> None:
        from electrumsv.gui.qt.history_list import TxStatus, get_tx_status

        local_height = 1000

        height = -1 # Legacy unconfirmed parent.
        status = get_tx_status(local_height, TxFlag.STATE_CLEARED, height, False)
        self.assertEqual(TxStatus.UNCONFIRMED, status)

        height = 0
        status = get_tx_status(local_height, TxFlag.STATE_CLEARED, height, False)
        self.assertEqual(TxStatus.UNCONFIRMED, status)

        height = local_height + 1
        status = get_tx_status(local_height, TxFlag.STATE_CLEARED, height, False)
        self.assertEqual(TxStatus.UNVERIFIED, status)

        height = local_height
        status = get_tx_status(local_height, TxFlag.STATE_SETTLED, height, False)
        self.assertEqual(TxStatus.FINAL, status)

        height = local_height - 1
        status = get_tx_status(local_height, TxFlag.STATE_SETTLED, height, False)
        self.assertEqual(TxStatus.FINAL, status)

    def test_get_tx_status_maturity(self) -> None:
        from electrumsv.gui.qt.history_list import TxStatus, get_tx_status

        local_height = 1000
        height = (local_height - COINBASE_MATURITY) + 1
        status = get_tx_status(local_height, TxFlag.STATE_CLEARED, height, True)
        self.assertEqual(TxStatus.UNMATURED, status)

        status = get_tx_status(local_height, TxFlag.STATE_SETTLED, height, True)
        self.assertEqual(TxStatus.UNMATURED, status)

        height = (local_height - COINBASE_MATURITY)
        status = get_tx_status(local_height, TxFlag.STATE_SETTLED, height, True)
        self.assertEqual(TxStatus.FINAL, status)


def test_qt_CheckState_typing() -> None:
    from PyQt6.QtCore import Qt
    # NOTE(typing) PyQt nonsense: `CheckState` is an `Enum` not and `IntEnum`.
    # We test this here to detect if it gets fixed in a PyQt6 update.
    assert Qt.CheckState.Unchecked != 0
    assert Qt.CheckState.Checked != 2

