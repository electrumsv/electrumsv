import asyncio
import json
import logging
import tempfile

import pytest
import bitcoinx
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
from bitcoinx import Address, Script, BitcoinTestnet, hex_str_to_hash
from typing import List, Union, Dict, Any, Optional, Tuple
from concurrent.futures.thread import ThreadPoolExecutor

from electrumsv.constants import TransactionOutputFlag, ScriptType
from electrumsv.restapi import good_response, Fault
from electrumsv.wallet import UTXO, Wallet, AbstractAccount
from electrumsv.transaction import Transaction
from ..errors import Errors

from ..handlers import ExtensionEndpoints



class SVTestnet(object):

    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    NAME = 'testnet'
    WIF_PREFIX = 0xef
    COIN = BitcoinTestnet
    BIP44_COIN_TYPE = 1


class _CurrentNetMeta(type):

    def __getattr__(cls, attr):
        return getattr(cls._net, attr)


class Net(metaclass=_CurrentNetMeta):

    _net = SVTestnet


SPENDABLE_UTXOS = [
    UTXO(address=Address.from_string('miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou',
                                              Net.COIN),
         is_coinbase=False,
         out_index=0,
         script_pubkey=Script(b'v\xa9\x14&\x0c\x95\x8e\x81\xc8o\xe3.\xc3\xd4\x1d7\x1cy'
                             b'\x0e\xed\x9a\xb4\xf3\x88\xac'),
         tx_hash=hex_str_to_hash(
             '76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf'),
         value=100000,
         script_type=ScriptType.P2PKH,
         keyinstance_id=0,
         flags=TransactionOutputFlag.NONE),
    UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr',
                                              Net.COIN),
         is_coinbase=False,
         out_index=0,
         script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff'
                              b'\x12\x88\xac'),
         tx_hash=hex_str_to_hash(
             '76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf'),
         value=100000,
         script_type=ScriptType.P2PKH,
         keyinstance_id=0,
         flags=TransactionOutputFlag.NONE)
    ]

p2pkh_object = bitcoinx.P2PKH_Address.from_string("muV4JqcF3V3Vi7J2hGucQJzSLcsUAaJwLA", Net.COIN)
P2PKH_OUTPUT = {"value": 100,
                "script_pubkey": p2pkh_object.to_script().to_hex()}

rawtx = "0100000001c2f9bbe87ab222fa84954a9f8140696eafdeb578e8a7555c1db60c7cb4b391b601" \
        "0000006a47304402207f4e64f379412ed251e4e454c52fb10b716b40a4f44986a1b410940663" \
        "d7fcce02200fbf6483de08e66e05ec91240fc69a7623d3295ec872e9676d95cac438e3207541" \
        "2102e49bb187d96b6a1556f08b46732a54b71a73e947e4d31cf84a4d14e20b071f6effffffff" \
        "02000000000000000009006a0648656c6c6f0afc050000000000001976a914c95b08d2e984a0" \
        "92c1bcaad98b387aa5d8db3f7d88ac7c761400"


def _fake_history_dto_succeeded(account: AbstractAccount, tx_states: int=None) -> List[Dict[
    Any, Any]]:
    result = [
        {
            "txid": "d4e226dde5c652782679a44bfad7021fb85df6ba8d32b1b17b8dc043e85d7103",
            "height": 1,
            "tx_flags": 2097152,
            "value": 5000000000
        },
        {
            "txid": "6a25882b47b3f2e97c09ee9f3131831df4b2ec1b54cc45fe3899bb4a3b5e2b29",
            "height": 0,
            "tx_flags": 1048576,
            "value": -104
        },
        {
            "txid": "611baae09b4db5894bbb4f13f35ae3ef492f34b388905a31a0ef82898cd3e6f6",
            "height": None,
            "tx_flags": 8388608,
            "value": -5999999718
        }
    ]
    return result


async def _fake_reset_wallet_transaction_state_succeeded(wallet_name, index) -> Optional[Fault]:
    return None


def _fake_balance_dto_succeeded(wallet) -> Dict[Any, Any]:
    return {"confirmed_balance": 10,
            "unconfirmed_balance": 20,
            "unmatured_balance": 0}


def _fake_remove_transaction(tx_hash: bytes, wallet: AbstractAccount):
    return


def _fake_remove_transaction_raise_fault(tx_hash: bytes, wallet: AbstractAccount):
    raise Fault(Errors.DISABLED_FEATURE_CODE, Errors.DISABLED_FEATURE_MESSAGE)


async def _fake_load_wallet_succeeds(wallet_name) -> Wallet:
    return MockWallet()


def _fake_coin_state_dto(wallet) -> Union[Fault, Dict[str, Any]]:
    results = {"cleared_coins": 50,
               "settled_coins": 2000,
               "unmatured": 100}
    return results


def _fake_create_transaction_succeeded(file_id, message_bytes, child_wallet, password,
                                       require_confirmed) -> Tuple[Any, set]:
    # Todo - test _create_transaction separately
    tx = Transaction.from_hex(rawtx)
    frozen_utxos = set([])
    return tx, frozen_utxos

async def _fake_broadcast_tx(rawtx: str, tx_hash: bytes, account: AbstractAccount) -> str:
    return "6797415e3b4a9fbb61b209302374853bdefeb4567ad0ed76ade055e94b9b66a2"

def _fake_get_frozen_utxos_for_tx(tx: Transaction, child_wallet: AbstractAccount) \
        -> List[UTXO]:
    """can get away with this for the 'happy path' but not if errors an unfreezing occurs"""
    pass


def _fake_spawn(fn, *args):
    return '<throwaway _future>'

class MockAccount(AbstractAccount):

    def __init__(self, wallet=None):
        self._id = 1
        self._frozen_coins = set([])
        self._subpath_gap_limits = {(0,): 20,
                                    (1,): 20}
        self._wallet = wallet

    def maybe_set_transaction_dispatched(self, tx_hash):
        return True

    def dumps(self):
        return None

    def get_spendable_coins(self, domain=None, config={}) -> List[UTXO]:
        return SPENDABLE_UTXOS

    def get_utxos(self, domain=None, exclude_frozen=False, mature=False, confirmed_only=False) \
            -> List[UTXO]:
        return SPENDABLE_UTXOS

    def make_unsigned_transaction(self, utxos=None, outputs=None, config=None):
        return Transaction.from_hex(rawtx)

    def sign_transaction(self, tx=None, password=None):
        return Transaction.from_hex(rawtx)


class MockWallet(Wallet):

    def __init__(self):
        self._accounts: Dict[int, AbstractAccount] = {1: MockAccount(self)}
        self._frozen_coins = set([])

    def set_boolean_setting(self, setting_name: str, enabled: bool) -> None:
        return

    def _fake_get_account(self, account_id):
        return self._accounts[account_id]


class MockApp:
    def __init__(self):
        self.txb_executor = ThreadPoolExecutor()

    def _create_transaction(self):
        pass

    def _broadcast_transaction(self):
        pass

    def broadcast_file(*args):
        pass

    def get_and_set_frozen_utxos_for_tx(self):
        pass

    def _create_tx_helper(self):
        pass


class MockConfig:
    def __init__(self):
        pass

    def estimate_fee(self, size):
        return size * 1  # 1 sat/byte

    def fee_per_kb(self):
        return 1000  # 1 sat/bytes


class MockAsync(object):

    def spawn(self, fn, *args):
        return '<throwaway _future>'


class MockSession:
    def __init__(self):
        pass

    def set_throttled(self, flag: bool):
        return True

    async def send_request(self, method, args):
        return '6797415e3b4a9fbb61b209302374853bdefeb4567ad0ed76ade055e94b9b66a2'


async def mock_main_session():
    return MockSession()

class MockNetwork:
    def __init__(self):
        self._main_session = mock_main_session

class MockDaemon:
    def __init__(self):
        self.network = MockNetwork()
        self.wallets = {"wallet_file1.sqlite": "path/to/wallet"}

class MockAppState:
    def __init__(self):
        self.app = MockApp()
        self.config = MockConfig()
        self.async_ = MockAsync()
        self.daemon = MockDaemon()


class MockDefaultEndpoints(ExtensionEndpoints):
    # fake init for LocalRESTExtensions
    def __init__(self):
        self.all_wallets = ["wallet_file1.sqlite", "wallet_file2.sqlite"]
        self.wallets_path = tempfile.TemporaryDirectory()
        self.app_state = MockAppState()
        self.logger = logging.getLogger("mock-restapi")
        self.prev_transaction = ''
        self.txb_executor = ThreadPoolExecutor(max_workers=1)

    def select_inputs_and_outputs(self, config=None, child_wallet=None, base_fee=None,
            split_count=None, desired_utxo_count=None, max_utxo_margin=200, split_value=3000,
            require_confirmed=None):
        return SPENDABLE_UTXOS, None, True

    # monkeypatching methods of LocalRESTExtensions
    def _fake_get_all_wallets(self, wallets_path):
        return self.all_wallets

    def _fake_get_parent_wallet(self, wallet_name):
        return MockWallet()

    def _fake_account_dto(self, wallet):
        return {wallet._id: {"wallet_type": "StandardWallet",
                             "is_wallet_ready": True}}

    def _fake_get_and_set_frozen_utxos_for_tx(self, tx, child_wallet):
        return

    def _fake_create_tx_helper_raise_exception(self, request) -> Tuple[Any, set]:
        raise Fault(Errors.INSUFFICIENT_COINS_CODE, Errors.INSUFFICIENT_COINS_MESSAGE)

    async def _fake_send_request(self, method, args):
        '''fake for 'blockchain.transaction.broadcast' '''
        return Transaction.from_hex(rawtx).txid()


def _fake_get_account_succeeded(wallet_name, index) -> Union[Fault, AbstractAccount]:
    return MockAccount()  # which in-turn patches get_spendable_coins()


class TestDefaultEndpoints:

    # PATHS
    VERSION = "/v1"
    NETWORK = "/{network}"
    BASE = VERSION + NETWORK + "/dapp"  # avoid conflicts with built-ins
    WALLETS_TLD = BASE + "/wallets"
    WALLETS_PARENT = WALLETS_TLD + "/{wallet_name}"
    WALLETS_ACCOUNT = WALLETS_PARENT + "/{account_id}"
    ACCOUNT_TXS = WALLETS_ACCOUNT + "/txs"
    ACCOUNT_UTXOS = WALLETS_ACCOUNT + "/utxos"

    @pytest.fixture
    def cli(self, loop, aiohttp_client, monkeypatch):
        """mock client - see: https://docs.aiohttp.org/en/stable/client_quickstart.html"""
        app = web.Application()
        app.router.add_get(self.WALLETS_TLD, self.rest_server.get_all_wallets)
        app.router.add_get(self.WALLETS_PARENT, self.rest_server.get_parent_wallet)
        app.router.add_post(self.WALLETS_PARENT + "/load_wallet", self.rest_server.load_wallet)
        app.router.add_get(self.WALLETS_ACCOUNT, self.rest_server.get_account)
        app.router.add_get(self.ACCOUNT_UTXOS + "/coin_state", self.rest_server.get_coin_state)
        app.router.add_get(self.ACCOUNT_UTXOS, self.rest_server.get_utxos)
        app.router.add_get(self.ACCOUNT_UTXOS + "/balance", self.rest_server.get_balance)
        app.router.add_delete(self.ACCOUNT_TXS, self.rest_server.remove_txs)
        app.router.add_get(self.ACCOUNT_TXS + "/history", self.rest_server.get_transaction_history)
        app.router.add_get(self.ACCOUNT_TXS + "/fetch", self.rest_server.fetch_transaction)
        app.router.add_post(self.ACCOUNT_TXS + "/create", self.rest_server.create_tx)
        app.router.add_post(self.ACCOUNT_TXS + "/create_and_broadcast",
                            self.rest_server.create_and_broadcast)
        app.router.add_post(self.ACCOUNT_TXS + "/broadcast", self.rest_server.broadcast)
        app.router.add_post(self.ACCOUNT_TXS + "/split_utxos", self.rest_server.split_utxos)
        return loop.run_until_complete(aiohttp_client(app))

    @pytest.fixture(autouse=True)
    def init_restapi(self, monkeypatch):
        """This is injected into all test functions"""
        self.rest_server = MockDefaultEndpoints()
        monkeypatch.setattr(self.rest_server, '_get_parent_wallet',
                            self.rest_server._fake_get_parent_wallet)
        monkeypatch.setattr(Wallet, 'get_account',
                            MockWallet._fake_get_account)
        monkeypatch.setattr(self.rest_server, '_account_dto',
                            self.rest_server._fake_account_dto)
        monkeypatch.setattr(self.rest_server, '_get_all_wallets',
                            self.rest_server._fake_get_all_wallets)

    # Todo
    #  - test_ping_txb_good_response
    #  - test_ping_node_via_txb_good_response

    async def test_get_all_wallets_good_request(self):
        """
        GET http://127.0.0.1:9999/v1/{network}/wallets
        Gets all wallet file paths in AppData / .electrumsv directory
        """
        network = "test"
        all_wallets = self.rest_server.all_wallets
        mock_request = make_mocked_request("GET", f"/v1/{network}/dapp/wallets/")
        expected_json = {"wallets": all_wallets}
        resp = await self.rest_server.get_all_wallets(mock_request)
        assert resp.text == good_response(expected_json).text

    async def test_get_parent_wallet_good_response(self, cli):
        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        resp = await cli.get(f"/v1/{network}/dapp/wallets/{wallet_name}")
        expected_json = {'parent_wallet': "wallet_file1.sqlite",
                         'accounts': {'1': {'wallet_type': 'StandardWallet',
                                            'is_wallet_ready': True}}}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_account_good_response(self, cli):
        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        account_id = "1"
        resp = await cli.get(f"/v1/{network}/dapp/wallets/{wallet_name}/"
                             f"{account_id}")
        # check
        expected_json = {'1': {'wallet_type': 'StandardWallet',
                               'is_wallet_ready': True}}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_load_wallet_good_request(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_load_wallet',
                            _fake_load_wallet_succeeds)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        resp = await cli.post(f"/v1/{network}/dapp/wallets/{wallet_name}/load_wallet")

        # check
        expected_json = {"parent_wallet": wallet_name,
                         "accounts": {'1': {"wallet_type": "StandardWallet",
                                            "is_wallet_ready": True}}}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_balance_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_balance_dto',
                            _fake_balance_dto_succeeded)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        account_id = "1"
        resp = await cli.get(f"/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/utxos/balance")

        # check
        expected_json = {"confirmed_balance": 10,
                         "unconfirmed_balance": 20,
                         "unmatured_balance": 0}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_remove_txs_specific_txid(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, 'remove_transaction',
                            _fake_remove_transaction)

        expected_response = {
                "items": [
                    {
                        'id': '0000000000000000000000000000000000000000000000000000000000000000',
                        'result': 200
                     }
            ]
        }

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        account_id = "1"
        txids = ["00" * 32]
        resp = await cli.delete(f"/v1/{network}/dapp/wallets/{wallet_name}/"
                              f"{account_id}/txs",
                              data=json.dumps({"txids": txids}))

        assert resp.status == 207, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_response

    async def test_remove_txs_specific_txid_failed_to_delete(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, 'remove_transaction',
                            _fake_remove_transaction_raise_fault)

        expected_response = {
                "items": [
                    {
                        'id': '0000000000000000000000000000000000000000000000000000000000000000',
                        'result': 400,
                        'description': 'DisabledFeatureError: You used this endpoint in a way that '
                                       'is not supported for safety reasons. See documentation for '
                                       'details (https://electrumsv.readthedocs.io/ )',
                    }
            ]
        }

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        account_id = "1"
        txids = ["00" * 32]
        resp = await cli.delete(f"/v1/{network}/dapp/wallets/{wallet_name}/"
                              f"{account_id}/txs",
                              data=json.dumps({"txids": txids}))

        assert resp.status == 207, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_response

    async def test_remove_txs_bad_request(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, 'remove_transaction',
                            _fake_remove_transaction_raise_fault)

        expected_response = \
            {'code': 40000, 'message': "Required body variable: 'txids' was not provided."}

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        account_id = "1"
        # txids = ["00" * 32]
        resp = await cli.delete(f"/v1/{network}/dapp/wallets/{wallet_name}/"
                              f"{account_id}/txs")

        assert resp.status == 400, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_response

    async def test_get_transaction_history_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_history_dto',
                            _fake_history_dto_succeeded)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        account_id = "1"
        resp = await cli.get(f"/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/txs/history")

        # check
        expected_json = {
            "history": [
                {
                    "txid": "d4e226dde5c652782679a44bfad7021fb85df6ba8d32b1b17b8dc043e85d7103",
                    "height": 1,
                    "tx_flags": 2097152,
                    "value": 5000000000
                },
                {
                    "txid": "6a25882b47b3f2e97c09ee9f3131831df4b2ec1b54cc45fe3899bb4a3b5e2b29",
                    "height": 0,
                    "tx_flags": 1048576,
                    "value": -104
                },
                {
                    "txid": "611baae09b4db5894bbb4f13f35ae3ef492f34b388905a31a0ef82898cd3e6f6",
                    "height": None,
                    "tx_flags": 8388608,
                    "value": -5999999718
                }
            ]
        }
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_coin_state_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_coin_state_dto',
                            _fake_coin_state_dto)
        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        account_id = "1"
        resp = await cli.get(f"/v1/{network}/dapp/wallets/{wallet_name}/{account_id}/"
                             f"utxos/coin_state")

        # check
        expected_json = {"cleared_coins": 50,
                         "settled_coins": 2000,
                         "unmatured": 100}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_utxos_good_response(self, monkeypatch, cli):

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "1"
        resp = await cli.get(f"/v1/{network}/dapp/wallets/{wallet_name}/{index}/utxos")

        # check
        expected_json = {"utxos": self.rest_server._utxo_dto(SPENDABLE_UTXOS)}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_create_tx_good_response(self, monkeypatch, cli):
        class MockEventLoop:

            async def run_in_executor(self, *args):
                tx = Transaction.from_hex(rawtx)
                frozen_utxos = None
                return tx, frozen_utxos

            def get_debug(self):
                return

            def is_running(self) -> bool:
                return True

        def _fake_get_event_loop():
            return MockEventLoop()

        monkeypatch.setattr(self.rest_server, '_get_account',
                            _fake_get_account_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, '_create_transaction',
                            _fake_create_transaction_succeeded)
        monkeypatch.setattr(asyncio, 'get_event_loop', _fake_get_event_loop)
        monkeypatch.setattr(self.rest_server.app_state.app, 'get_and_set_frozen_utxos_for_tx',
                            self.rest_server._fake_get_and_set_frozen_utxos_for_tx)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "1"
        password = "mypass"
        resp = await cli.request(path=f"/v1/{network}/dapp/wallets/{wallet_name}/"
                                      f"{index}/txs/create",
                                 method='post',
                                 json={"outputs": [P2PKH_OUTPUT],
                                       "password": password})
        # check
        expected_json = {"txid": Transaction.from_hex(rawtx).txid(),
                         "rawtx": rawtx}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_create_tx_insufficient_coins(self, monkeypatch, cli):
        """ensure that exception handling works even if no tx was successfully created"""
        class MockEventLoop:

            def get_debug(self):
                return

            def is_running(self) -> bool:
                return True


        def _fake_get_event_loop():
            return MockEventLoop()

        monkeypatch.setattr(self.rest_server, '_get_account',
                            _fake_get_account_succeeded)
        monkeypatch.setattr(self.rest_server, '_create_tx_helper',
                            self.rest_server._fake_create_tx_helper_raise_exception)
        monkeypatch.setattr(asyncio, 'get_event_loop', _fake_get_event_loop)
        monkeypatch.setattr(self.rest_server.app_state.app, 'get_and_set_frozen_utxos_for_tx',
                            self.rest_server._fake_get_and_set_frozen_utxos_for_tx)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "1"
        password = "mypass"
        resp = await cli.request(path=f"/v1/{network}/dapp/wallets/{wallet_name}/"
                                      f"{index}/txs/create",
                                 method='post',
                                 json={"outputs": [P2PKH_OUTPUT],
                                       "password": password})
        # check
        expected_json = {'code': 40006, 'message': 'You have insufficient coins for this transaction'}
        assert resp.status == 400, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_create_and_broadcast_good_response(self, monkeypatch, cli):

        monkeypatch.setattr(self.rest_server, '_get_account',
                            _fake_get_account_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, '_create_transaction',
                            _fake_create_transaction_succeeded)
        monkeypatch.setattr(self.rest_server, '_broadcast_transaction',
                            _fake_broadcast_tx)
        monkeypatch.setattr(self.rest_server.app_state.async_, 'spawn',
                            _fake_spawn)
        monkeypatch.setattr(self.rest_server.app_state.async_, 'spawn',
                            _fake_spawn)
        monkeypatch.setattr(self.rest_server.app_state.app, 'get_and_set_frozen_utxos_for_tx',
                            self.rest_server._fake_get_and_set_frozen_utxos_for_tx)
        monkeypatch.setattr(self.rest_server, 'send_request',
                            self.rest_server._fake_send_request)


        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "1"
        password = "mypass"
        resp = await cli.request(path=f"/v1/{network}/dapp/wallets/{wallet_name}/"
                                      f"{index}/txs/create_and_broadcast",
                                 method='post',
                                 json={"outputs": [P2PKH_OUTPUT],
                                       "password": password})
        # check
        expected_json = {'txid': Transaction.from_hex(rawtx).txid()}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_broadcast_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_get_account',
                            _fake_get_account_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, '_create_transaction',
                            _fake_create_transaction_succeeded)
        monkeypatch.setattr(self.rest_server, '_broadcast_transaction',
                            _fake_broadcast_tx)
        monkeypatch.setattr(self.rest_server.app_state.app, 'get_and_set_frozen_utxos_for_tx',
                            self.rest_server._fake_get_and_set_frozen_utxos_for_tx)
        monkeypatch.setattr(self.rest_server, 'send_request',
                            self.rest_server._fake_send_request)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "1"
        resp = await cli.request(path=f"/v1/{network}/dapp/wallets/{wallet_name}/"
                                      f"{index}/txs/broadcast",
                                 method='post',
                                 json={"rawtx": rawtx})
        # check
        tx = Transaction.from_hex(rawtx)
        expected_json = {"txid": tx.txid()}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    @pytest.mark.parametrize("spendable_utxos", [SPENDABLE_UTXOS[0]])
    async def test_split_utxos_good_response(self, monkeypatch, cli, spendable_utxos):
        monkeypatch.setattr(self.rest_server, '_get_account',
                            _fake_get_account_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, 'get_and_set_frozen_utxos_for_tx',
                            _fake_get_frozen_utxos_for_tx)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        account_id = "1"
        password = "mypass"
        resp = await cli.request(path=f"/v1/{network}/dapp/wallets/{wallet_name}/"
                                      f"{account_id}/txs/split_utxos",
                                 method='post',
                                 json={"split_count": 10,
                                       "desired_utxo_count": 100,
                                       "split_value": 3000,
                                       "password": password})
        # check
        tx = Transaction.from_hex(rawtx)
        expected_json = {"txid": tx.txid()}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json
