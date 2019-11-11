import os
from typing import Optional
import unittest

from electrumsv.i18n import _
from electrumsv.bitcoin import COINBASE_MATURITY
from electrumsv.util import format_time
from electrumsv.wallet import UTXO
from electrumsv.wallet_database.tables import TxData


class MockWhatever:
    pass


def get_confs_from_height(local_height: int, height: int) -> int:
    return max(local_height - height + 1, 0)


class HistoryListTests(unittest.TestCase):
    def test_get_tx_status(self) -> None:
        from electrumsv.gui.qt.history_list import TxStatus, get_tx_status

        account = MockWhatever()
        def _get_utxo(tx_hash: bytes, output_index: int) -> Optional[UTXO]:
            return None
        def _have_transaction_data(tx_hash: bytes) -> bool:
            return True
        def _get_transaction_metadata(tx_hash: bytes):
            return TxData(position=1)
        account.get_transaction_metadata = _get_transaction_metadata
        account.have_transaction_data = _have_transaction_data
        account.get_utxo = _get_utxo
        local_height = 1000
        def _get_local_height() -> int:
            return local_height
        account._wallet = MockWhatever()
        account._wallet.get_local_height = _get_local_height
        timestamp = 1 # Ignored

        tx_hash = os.urandom(32)

        height = -1 # Legacy unconfirmed parent.
        confs = 0
        status = get_tx_status(account, tx_hash, height, confs, timestamp)
        self.assertEqual(TxStatus.UNCONFIRMED, status)

        height = 0
        confs = 0
        status = get_tx_status(account, tx_hash, height, confs, timestamp)
        self.assertEqual(TxStatus.UNCONFIRMED, status)

        height = local_height + 1
        confs = get_confs_from_height(local_height, height)
        status = get_tx_status(account, tx_hash, height, confs, timestamp)
        self.assertEqual(TxStatus.UNVERIFIED, status)

        height = local_height
        confs = get_confs_from_height(local_height, height)
        status = get_tx_status(account, tx_hash, height, confs, timestamp)
        self.assertEqual(TxStatus.FINAL, status)

        height = local_height - 1
        confs = get_confs_from_height(local_height, height)
        status = get_tx_status(account, tx_hash, height, confs, timestamp)
        self.assertEqual(TxStatus.FINAL, status)

    def test_get_tx_status_maturity(self) -> None:
        from electrumsv.gui.qt.history_list import TxStatus, get_tx_status

        account = MockWhatever()
        def _get_utxo(tx_hash: bytes, output_index: int) -> Optional[UTXO]:
            return UTXO(100, b'', 0, tx_hash, output_index, 1000, 1, None, False, 0)
        def _have_transaction_data(tx_hash: bytes) -> bool:
            return True
        def _get_transaction_metadata(tx_hash: bytes):
            return TxData(position=0)
        account.get_transaction_metadata = _get_transaction_metadata
        account.have_transaction_data = _have_transaction_data
        account.get_utxo = _get_utxo
        local_height = 1000
        def _get_local_height() -> int:
            return local_height
        account._wallet = MockWhatever()
        account._wallet.get_local_height = _get_local_height
        timestamp = confs = 1 # Ignored

        tx_hash = os.urandom(32)

        height = (local_height - COINBASE_MATURITY) + 1
        status = get_tx_status(account, tx_hash, height, confs, timestamp)
        self.assertEqual(TxStatus.UNMATURED, status)

        height = (local_height - COINBASE_MATURITY)
        status = get_tx_status(account, tx_hash, height, confs, timestamp)
        self.assertEqual(TxStatus.FINAL, status)

    def test_get_tx_desc(self) -> None:
        from electrumsv.gui.qt.history_list import TxStatus, TX_STATUS, get_tx_desc
        # Values with a text description should return that text description.
        for status_kind in [ TxStatus.UNCONFIRMED, TxStatus.MISSING ]:
            self.assertEqual(TX_STATUS[status_kind], get_tx_desc(status_kind, 1))
        # Otherwise the timestamp should be used.
        time_string = format_time(1, "...")
        self.assertNotEqual("...", time_string)
        self.assertEqual(time_string, get_tx_desc(TxStatus.FINAL, 1))
        self.assertEqual(_("unknown"), get_tx_desc(TxStatus.FINAL, False))
