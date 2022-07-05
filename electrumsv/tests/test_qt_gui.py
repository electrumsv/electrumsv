import os
from typing import cast
import unittest

from electrumsv.i18n import _
from electrumsv.bitcoin import COINBASE_MATURITY
from electrumsv.constants import TxFlags
from electrumsv.util import format_posix_timestamp
from electrumsv.wallet import AbstractAccount


class MockWhatever:
    pass


def get_confs_from_height(local_height: int, height: int) -> int:
    return max(local_height - height + 1, 0)


class HistoryListTests(unittest.TestCase):
    def test_get_tx_status(self) -> None:
        from electrumsv.gui.qt.history_list import TxStatus, get_tx_status

        mock_account = MockWhatever()
        local_height = 1000
        def _get_local_height() -> int:
            return local_height
        mock_account._wallet = MockWhatever()
        mock_account._wallet.get_local_height = _get_local_height
        timestamp = 1 # Ignored

        account = cast(AbstractAccount, mock_account)
        tx_hash = os.urandom(32)

        height = -1 # Legacy unconfirmed parent.
        position = None
        confs = 0
        status = get_tx_status(account, TxFlags.STATE_CLEARED, height, position, confs)
        self.assertEqual(TxStatus.UNCONFIRMED, status)

        height = 0
        position = None
        confs = 0
        status = get_tx_status(account, TxFlags.STATE_CLEARED, height, position, confs)
        self.assertEqual(TxStatus.UNCONFIRMED, status)

        height = local_height + 1
        confs = get_confs_from_height(local_height, height)
        status = get_tx_status(account, TxFlags.STATE_CLEARED, height, position, confs)
        self.assertEqual(TxStatus.UNVERIFIED, status)

        height = local_height
        confs = get_confs_from_height(local_height, height)
        status = get_tx_status(account, TxFlags.STATE_SETTLED, height, position, confs)
        self.assertEqual(TxStatus.FINAL, status)

        height = local_height - 1
        confs = get_confs_from_height(local_height, height)
        status = get_tx_status(account, TxFlags.STATE_SETTLED, height, position, confs)
        self.assertEqual(TxStatus.FINAL, status)

    def test_get_tx_status_maturity(self) -> None:
        from electrumsv.gui.qt.history_list import TxStatus, get_tx_status

        mock_account = MockWhatever()
        local_height = 1000
        def _get_local_height() -> int:
            return local_height
        mock_account._wallet = MockWhatever()
        mock_account._wallet.get_local_height = _get_local_height
        timestamp = confs = 1 # Ignored

        account = cast(AbstractAccount, mock_account)

        height = (local_height - COINBASE_MATURITY) + 1
        position = 0
        status = get_tx_status(account, TxFlags.STATE_CLEARED, height, position, confs)
        self.assertEqual(TxStatus.UNMATURED, status)

        status = get_tx_status(account, TxFlags.STATE_SETTLED, height, position, confs)
        self.assertEqual(TxStatus.UNMATURED, status)

        height = (local_height - COINBASE_MATURITY)
        position = 0
        status = get_tx_status(account, TxFlags.STATE_SETTLED, height, position, confs)
        self.assertEqual(TxStatus.FINAL, status)

    def test_get_tx_desc(self) -> None:
        from electrumsv.gui.qt.history_list import TxStatus, TX_STATUS, get_tx_desc
        # Values with a text description should return that text description.
        for status_kind in [ TxStatus.UNCONFIRMED, TxStatus.MISSING ]:
            self.assertEqual(TX_STATUS[status_kind], get_tx_desc(status_kind, 1))
        # Otherwise the timestamp should be used.
        time_string = format_posix_timestamp(1, "...")
        self.assertNotEqual("...", time_string)
        self.assertEqual(time_string, get_tx_desc(TxStatus.FINAL, 1))
        self.assertEqual(_("unknown"), get_tx_desc(TxStatus.FINAL, False))


def test_qt_CheckState_typing() -> None:
    from PyQt6.QtCore import Qt
    # NOTE(typing) PyQt nonsense: `CheckState` is an `Enum` not and `IntEnum`.
    # We test this here to detect if it gets fixed in a PyQt6 update.
    assert Qt.CheckState.Unchecked != 0
    assert Qt.CheckState.Checked != 2

