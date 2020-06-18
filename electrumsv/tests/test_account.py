from typing import List, NamedTuple, Optional, Tuple
import unittest

from bitcoinx import Script

from electrumsv.app_state import app_state
from electrumsv.bitcoin import ScriptTemplate
from electrumsv.constants import DerivationType, KeyInstanceFlag, ScriptType, TransactionOutputFlag
from electrumsv.wallet import AbstractAccount
from electrumsv.wallet_database.tables import AccountRow, KeyInstanceRow, TransactionOutputRow


class CustomAccount(AbstractAccount):
    def _load_sync_state(self) -> None:
        pass

    def get_script_template_for_id(self, keyinstance_id: int,
            script_type: Optional[ScriptType]=None) -> ScriptTemplate:
        return MockScriptTemplate()


class FakeTxin(NamedTuple):
    prev_hash: bytes
    prev_idx: int


class MockScriptTemplate:
    def __init__(self) -> None:
        pass

    def to_script(self) -> Script:
        return NotImplemented


class MockWallet:
    def __init__(self) -> None:
        self._transaction_cache = unittest.mock.Mock()
        self._db_context = unittest.mock.Mock()
        self._storage = unittest.mock.Mock()

    def name(self) -> str:
        return "MockWallet.name"


class MockAppState(object):
    async_ = None

    def __init__(self) -> None:
        app_state.set_proxy(self)


ACCOUNT_ID = 100
KEYINSTANCE_ID = 150
MASTERKEY_ID = 200
TX_HASH_1 = b'111111111'
TX_HASH_2 = b'222222222'


def test_key_archive_unarchive(mocker) -> None:
    state = MockAppState()
    mocker.patch.object(state, "async_", return_value=NotImplemented)

    mock_prt = mocker.patch("electrumsv.wallet_database.tables.PaymentRequestTable.read")
    mock_prt.return_value = []

    mock_tdt = mocker.patch(
        "electrumsv.wallet_database.tables.TransactionDeltaTable.update_used_keys")
    mock_tdt.return_value = [ KEYINSTANCE_ID+1 ]

    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, "ACCOUNT 1")
    keyinstance_rows = [
        KeyInstanceRow(KEYINSTANCE_ID+1, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            b'111', ScriptType.P2PKH, KeyInstanceFlag.IS_ACTIVE, None),
        KeyInstanceRow(KEYINSTANCE_ID+2, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            b'111', ScriptType.P2PKH, KeyInstanceFlag.IS_ACTIVE, None),
        KeyInstanceRow(KEYINSTANCE_ID+3, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            b'111', ScriptType.P2PKH, KeyInstanceFlag.IS_ACTIVE, None),
    ]
    transactionoutput_rows = [
        TransactionOutputRow(TX_HASH_1, 1, 100, KEYINSTANCE_ID+1, TransactionOutputFlag.IS_SPENT),
        TransactionOutputRow(TX_HASH_1, 2, 100, KEYINSTANCE_ID+2, TransactionOutputFlag.IS_SPENT),
        TransactionOutputRow(TX_HASH_1, 3, 200, KEYINSTANCE_ID+3, TransactionOutputFlag.NONE),
    ]

    wallet = MockWallet()
    account = CustomAccount(wallet, account_row, keyinstance_rows, transactionoutput_rows)

    assert (TX_HASH_1, 1) in account._stxos
    assert KEYINSTANCE_ID + 1 in account._keyinstances
    assert (TX_HASH_1, 2) in account._stxos
    assert KEYINSTANCE_ID + 2 in account._keyinstances
    assert (TX_HASH_1, 3) in account._utxos
    assert KEYINSTANCE_ID + 3 in account._keyinstances

    ## TEST ARCHIVE

    # Verify that the database updates are correct.
    def check_update_keyinstance_flags1(entries: List[Tuple[KeyInstanceFlag, int]]) -> None:
        for entry in entries:
            assert entry[1] == KEYINSTANCE_ID + 1
            assert entry[0] & KeyInstanceFlag.IS_ACTIVE == 0
    wallet.update_keyinstance_flags = check_update_keyinstance_flags1

    result = account.archive_keys({ KEYINSTANCE_ID+1 })

    # Verify the return value is correct.
    assert 1 == len(result)
    assert { KEYINSTANCE_ID + 1 } == result

    # Verify that the wallet state is removed.
    assert (TX_HASH_1, 1) not in account._stxos
    assert KEYINSTANCE_ID + 1 not in account._keyinstances

    ## TEST UNARCHIVE

    def fake_read_transactionoutputs(mask: Optional[TransactionOutputFlag]=None,
            key_ids: Optional[List[int]]=None) -> List[TransactionOutputRow]:
        return [ transactionoutput_rows[0] ]
    wallet.read_transactionoutputs = fake_read_transactionoutputs

    def fake_read_keyinstances(mask: Optional[KeyInstanceFlag]=None,
            key_ids: Optional[List[int]]=None) -> List[KeyInstanceRow]:
        return [
            KeyInstanceRow(KEYINSTANCE_ID+1, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
                b'111', ScriptType.P2PKH, KeyInstanceFlag.NONE, None)
        ]
    wallet.read_keyinstances = fake_read_keyinstances

    # Verify that the database updates are correct.
    def check_update_keyinstance_flags2(entries: List[Tuple[KeyInstanceFlag, int]]) -> None:
        for entry in entries:
            assert entry[1] == KEYINSTANCE_ID + 1
            assert entry[0] & KeyInstanceFlag.IS_ACTIVE == KeyInstanceFlag.IS_ACTIVE
    wallet.update_keyinstance_flags = check_update_keyinstance_flags2

    account.unarchive_transaction_keys([ (TX_HASH_1, { KEYINSTANCE_ID + 1 }) ])

    # Verify that the wallet state is restored.
    assert (TX_HASH_1, 1) in account._stxos
    assert KEYINSTANCE_ID + 1 in account._keyinstances


def test_remove_transaction(mocker) -> None:
    state = MockAppState()
    # Mocked out startup junk for AbstractAccount initialization.
    mocker.patch.object(state, "async_", return_value=NotImplemented)
    mocker.patch("electrumsv.wallet_database.tables.PaymentRequestTable.read").return_value = []

    account_row = AccountRow(ACCOUNT_ID, MASTERKEY_ID, ScriptType.P2PKH, "ACCOUNT 1")
    keyinstance_rows = [
        KeyInstanceRow(KEYINSTANCE_ID+1, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            b'111', ScriptType.P2PKH, KeyInstanceFlag.IS_ACTIVE, None),
        KeyInstanceRow(KEYINSTANCE_ID+2, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            b'111', ScriptType.P2PKH, KeyInstanceFlag.IS_ACTIVE, None),
        KeyInstanceRow(KEYINSTANCE_ID+3, ACCOUNT_ID, MASTERKEY_ID, DerivationType.BIP32,
            b'111', ScriptType.P2PKH, KeyInstanceFlag.IS_ACTIVE, None),
    ]
    transactionoutput_rows = [
        TransactionOutputRow(TX_HASH_1, 1, 100, KEYINSTANCE_ID+1, TransactionOutputFlag.IS_SPENT),
        TransactionOutputRow(TX_HASH_1, 2, 100, KEYINSTANCE_ID+2, TransactionOutputFlag.IS_SPENT),
        TransactionOutputRow(TX_HASH_2, 1, 200, KEYINSTANCE_ID+3, TransactionOutputFlag.NONE),
    ]

    wallet = MockWallet()
    account = CustomAccount(wallet, account_row, keyinstance_rows, transactionoutput_rows)

    def fake_get_transaction(tx_hash: bytes):
        tx = unittest.mock.Mock()
        tx.inputs = [ FakeTxin(TX_HASH_1, 1), FakeTxin(TX_HASH_1, 2) ]
        # We don't actually use what's in here, it's just used to mark the available outputs.
        tx.outputs = [ NotImplemented ]
        return tx
    wallet._transaction_cache.get_transaction = fake_get_transaction
    def fake_update_transactionoutput_flags(rows: List[Tuple[TransactionOutputFlag, bytes, int]]):
        assert 2 == len(rows)
        assert rows[0][0] == TransactionOutputFlag.NONE
        assert rows[0][1] == transactionoutput_rows[0].tx_hash
        assert rows[0][2] == transactionoutput_rows[0].tx_index
        assert rows[1][0] == TransactionOutputFlag.NONE
        assert rows[1][1] == transactionoutput_rows[1].tx_hash
        assert rows[1][2] == transactionoutput_rows[1].tx_index
    wallet.update_transactionoutput_flags = fake_update_transactionoutput_flags
    mocker.patch("electrumsv.wallet_database.tables.TransactionOutputTable.read").return_value = [
        transactionoutput_rows[0], transactionoutput_rows[1],
    ]
    account._remove_transaction(TX_HASH_2)

