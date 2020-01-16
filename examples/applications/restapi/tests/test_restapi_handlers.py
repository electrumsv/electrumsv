import asyncio
import json

import bitcoinx
from aiohttp import web
from electrumsv.restapi import good_response, Fault
from aiohttp.test_utils import make_mocked_request
from concurrent.futures.thread import ThreadPoolExecutor
import pytest
from bitcoinx import Address, Script, BitcoinTestnet
import logging
from typing import List, Union, Dict, Any, Optional, Tuple
import tempfile
from electrumsv.wallet import ParentWallet, Abstract_Wallet, UTXO
from electrumsv.transaction import Transaction
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
    UTXO(address=Address.from_string('miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou', Net.COIN),
        height=1,
        is_coinbase=False,
        out_index=0,
        script_pubkey=Script(b'v\xa9\x14&\x0c\x95\x8e\x81\xc8o\xe3.\xc3\xd4\x1d7\x1cy'
                             b'\x0e\xed\x9a\xb4\xf3\x88\xac'),
        tx_hash='76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf',
        value=100000),
    UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr', Net.COIN),
         height=1,
         is_coinbase=False,
         out_index=0,
         script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff'
                              b'\x12\x88\xac'),
         tx_hash='8aed908726dc878fb7316fc4f11054dbc69b6ac8b206d3fca5a7412d7e9e458d',
         value=100000)
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


def _fake_history_dto_succeeded(wallet) -> List[Dict[Any, Any]]:
    result = [
        {"tx_hash": '...',
         "height": 0,
         "conf": 0,
         "timestamp": 1573709467,
         "delta": 10000},
        {"tx_hash": '...',
         "height": 1,
         "conf": 1,
         "timestamp": 1573709467,
         "delta": 10000}
    ]
    return result


async def _fake_reset_wallet_transaction_state_succeeded(wallet_name, index) -> Optional[Fault]:
    return None


def _fake_balance_dto_succeeded(wallet) -> Dict[Any, Any]:
    confirmed_bal, unconfirmed_bal, mature_coinbase_bal = 10, 20, 0
    return {"confirmed_balance": confirmed_bal + mature_coinbase_bal,
            "unconfirmed_balance": unconfirmed_bal}


def _fake_transaction_state_dto_succeeded(wallet, txids) -> Dict[Any, Any]:
    results = {
        "txid1...": {"block_id": 1,
                     "height": 1,
                     "conf": 1,
                     "timestamp": 1000000000},
        "txid2...": {"block_id": 1,
                     "height": 1,
                     "conf": 1,
                     "timestamp": 1000000000}}
    return results


async def _fake_load_wallet_succeeds(wallet_name, password) -> ParentWallet:
    return MockParentWallet()


def _fake_coin_state_dto(wallet) -> Union[Fault, Dict[str, Any]]:
    results = {"cleared_coins": 50,
               "settled_coins": 2000}
    return results


def _fake_create_transaction_succeeded(file_id, message_bytes, child_wallet, password,
                                       require_confirmed) -> Tuple[Any, set]:
    # Todo - test _create_transaction separately
    tx = Transaction.from_hex(rawtx)
    frozen_utxos = set([])
    return tx, frozen_utxos


async def _fake_broadcast_tx(tx, child_wallet=None, frozen_utxos=None, wallet_memo=None,
                             file_id=None) -> \
        Union[Dict, Fault]:
    pass
    # TODO - fix


def _fake_get_frozen_utxos_for_tx(tx: Transaction, child_wallet: Abstract_Wallet) \
        -> List[UTXO]:
    """can get away with this for the 'happy path' but not if errors an unfreezing occurs"""
    pass


def _fake_spawn(fn, *args):
    return '<throwaway _future>'


class MockChildWallet(Abstract_Wallet):

    def __init__(self):
        self._id = 0


    def dumps(self):
        return None

    def get_spendable_coins(self, domain=None, config={}, isInvoice=False) \
            -> List[UTXO]:
        return SPENDABLE_UTXOS

    def get_utxos(self, domain=None, exclude_frozen=False, mature=False, confirmed_only=False) \
            -> List[UTXO]:
        return SPENDABLE_UTXOS

    def make_unsigned_transaction(self, utxos=None, outputs=None, config=None):
        return Transaction.from_hex(rawtx)

    def sign_transaction(self, tx=None, password=None):
        return Transaction.from_hex(rawtx)


class MockParentWallet(ParentWallet):

    def __init__(self):
        self._child_wallets = [MockChildWallet()]

    def _fake_get_child_wallets(self):
        return [MockChildWallet()]


class MockApp:
    def __init__(self):
        self.txb_executor = ThreadPoolExecutor()

    def _create_transaction(self):
        pass

    def broadcast_tx(self):
        pass

    def broadcast_file(*args):
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


class MockAppState:
    def __init__(self):
        self.app = MockApp()
        self.config = MockConfig()
        self.async_ = MockAsync()


class MockDefaultEndpoints(ExtensionEndpoints):
    # fake init for LocalRESTExtensions
    def __init__(self):
        self.all_wallets = ["wallet_file1.sqlite", "wallet_file2.sqlite"]
        self.wallets_path = tempfile.TemporaryDirectory()
        self.app_state = MockAppState()
        self.logger = logging.getLogger("mock-restapi")
        self.prev_transaction = ''

    # monkeypatching methods of LocalRESTExtensions
    def _fake_get_all_wallets(self, wallets_path):
        return self.all_wallets

    def _fake_get_parent_wallet(self, wallet_name):
        return MockParentWallet()

    def _fake_child_wallet_dto(self, wallet):
        return {wallet._id: {"wallet_type": "StandardWallet",
                             "is_wallet_ready": True}}

    def _fake_get_and_set_frozen_utxos_for_tx(self, tx, child_wallet):
        return

    async def _fake_send_request(self, method, args):
        '''fake for 'blockchain.transaction.broadcast' '''
        return Transaction.from_hex(rawtx).txid()


def _fake_get_child_wallet_succeeded(wallet_name, index) -> Union[Fault, Abstract_Wallet]:
    return MockChildWallet()  # which in-turn patches get_spendable_coins()


class TestDefaultEndpoints:

    @pytest.fixture
    def cli(self, loop, aiohttp_client, monkeypatch):
        """mock client - see: https://docs.aiohttp.org/en/stable/client_quickstart.html"""
        app = web.Application()
        app.router.add_get('/v1/{network}/wallets/{wallet_name}/',
                           self.rest_server.get_parent_wallet)
        app.router.add_get('/v1/{network}/wallets/{wallet_name}/{index}/',
                           self.rest_server.get_child_wallet)
        app.router.add_post('/v1/{network}/wallets/{wallet_name}/load_wallet',
                           self.rest_server.load_wallet)
        app.router.add_post('/v1/{network}/wallets/{wallet_name}/{index}/txs/'
                            'delete_signed_txs',
                            self.rest_server.delete_signed_txs)
        app.router.add_get('/v1/{network}/wallets/{wallet_name}/{index}/balance',
                           self.rest_server.get_balance)
        app.router.add_get('/v1/{network}/wallets/{wallet_name}/{index}/txs/history',
                           self.rest_server.get_transaction_history)
        app.router.add_post('/v1/{network}/wallets/{wallet_name}/{index}/txs/metadata',
                            self.rest_server.get_transactions_metadata)
        app.router.add_get('/v1/{network}/wallets/{wallet_name}/{index}/utxos/coin_state',
                            self.rest_server.get_coin_state)
        app.router.add_get('/v1/{network}/wallets/{wallet_name}/{index}/utxos',
                            self.rest_server.get_utxos)
        app.router.add_post('/v1/{network}/wallets/{wallet_name}/{index}/txs/'
                            'create', self.rest_server.create_tx)
        app.router.add_post('/v1/{network}/wallets/{wallet_name}/{index}/txs/'
                            'create_and_broadcast', self.rest_server.create_and_broadcast)
        app.router.add_post('/v1/{network}/wallets/{wallet_name}/{index}/txs/'
                            'broadcast', self.rest_server.broadcast)
        return loop.run_until_complete(aiohttp_client(app))

    @pytest.fixture(autouse=True)
    def init_restapi(self, monkeypatch):
        """This is injected into all test functions"""
        self.rest_server = MockDefaultEndpoints()
        monkeypatch.setattr(self.rest_server, '_get_parent_wallet',
                            self.rest_server._fake_get_parent_wallet)
        monkeypatch.setattr(ParentWallet, 'get_child_wallets',
                            MockParentWallet._fake_get_child_wallets)
        monkeypatch.setattr(self.rest_server, '_child_wallet_dto',
                            self.rest_server._fake_child_wallet_dto)
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
        mock_request = make_mocked_request("GET", f"/v1/{network}/wallets/")
        expected_json = {'value': all_wallets}
        resp = await self.rest_server.get_all_wallets(mock_request)
        assert resp.text == good_response(expected_json).text

    async def test_get_parent_wallet_good_response(self, cli):
        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        resp = await cli.get(f"/v1/{network}/wallets/{wallet_name}/")
        expected_json = {'parent_wallet': "wallet_file1.sqlite",
                         'value': {'0': {'wallet_type': 'StandardWallet',
                                       'is_wallet_ready': True}}}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_child_wallet_good_response(self, cli):
        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.get(f"/v1/{network}/wallets/{wallet_name}/"
                             f"{index}/")
        # check
        expected_json = {'value': {'0': {'wallet_type': 'StandardWallet',
                                         'is_wallet_ready': True}}}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_load_wallet_good_request(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_load_wallet',
                            _fake_load_wallet_succeeds)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        resp = await cli.post(f"/v1/{network}/wallets/{wallet_name}/load_wallet")

        # check
        expected_json = {"parent_wallet": wallet_name,
                         "value": {'0': {"wallet_type": "StandardWallet",
                                       "is_wallet_ready": True}}}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_reset_child_wallet_coin_state_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_delete_signed_txs',
                            _fake_reset_wallet_transaction_state_succeeded)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.post(f"/v1/{network}/wallets/{wallet_name}/"
                              f"{index}/txs/delete_signed_txs")

        # check
        expected_json = {"value": {"message": "All StateSigned transactions deleted from TxCache, "
                                        "TxInputs and TxOutputs cache and SqliteDatabase. "
                                        "Corresponding utxos also removed from frozen list."}}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_balance_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_balance_dto',
                            _fake_balance_dto_succeeded)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.get(f"/v1/{network}/wallets/{wallet_name}/{index}/balance")

        # check
        expected_json = {"value": {"confirmed_balance": 10,
                                   "unconfirmed_balance": 20}}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_transaction_history_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_history_dto',
                            _fake_history_dto_succeeded)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.get(f"/v1/{network}/wallets/{wallet_name}/{index}/txs/history")

        # check
        expected_json = {"value": _fake_history_dto_succeeded(wallet=None)}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_transactions_metadata_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_transaction_state_dto',
                            _fake_transaction_state_dto_succeeded)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.request(path=f"/v1/{network}/wallets/{wallet_name}/"
                                      f"{index}/txs/metadata",
                                 method='post',
                                 json={"txids": ["txid1...", "txid2..."]})
        # check
        expected_json = {"value": _fake_transaction_state_dto_succeeded(None, None)}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_coin_state_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_coin_state_dto',
                            _fake_coin_state_dto)
        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.get(f"/v1/{network}/wallets/{wallet_name}/{index}/utxos/coin_state")

        # check
        expected_json = {"value": _fake_coin_state_dto(None)}
        assert resp.status == 200
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_get_utxos_good_response(self, monkeypatch, cli):

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.get(f"/v1/{network}/wallets/{wallet_name}/{index}/utxos")

        # check
        expected_json = {"value": {"utxos": self.rest_server._utxo_dto(SPENDABLE_UTXOS)}}
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

        def _fake_get_event_loop():
            return MockEventLoop()

        monkeypatch.setattr(self.rest_server, '_get_child_wallet',
                            _fake_get_child_wallet_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, '_create_transaction',
                            _fake_create_transaction_succeeded)
        monkeypatch.setattr(asyncio, 'get_event_loop', _fake_get_event_loop)
        monkeypatch.setattr(self.rest_server, '_get_and_set_frozen_utxos_for_tx',
                            self.rest_server._fake_get_and_set_frozen_utxos_for_tx)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.request(path=f"/v1/{network}/wallets/{wallet_name}/"
                                      f"{index}/txs/create",
                                 method='post',
                                 json={"outputs": [P2PKH_OUTPUT]})
        # check
        expected_json = {"value": {"txid": Transaction.from_hex(rawtx).txid(),
                                   "rawtx": rawtx}}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_create_and_broadcast_response(self, monkeypatch, cli):

        monkeypatch.setattr(self.rest_server, '_get_child_wallet',
                            _fake_get_child_wallet_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, '_create_transaction',
                            _fake_create_transaction_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, 'broadcast_tx',
                            _fake_broadcast_tx)
        monkeypatch.setattr(self.rest_server.app_state.async_, 'spawn',
                            _fake_spawn)
        monkeypatch.setattr(self.rest_server.app_state.async_, 'spawn',
                            _fake_spawn)
        monkeypatch.setattr(self.rest_server, '_get_and_set_frozen_utxos_for_tx',
                            self.rest_server._fake_get_and_set_frozen_utxos_for_tx)
        monkeypatch.setattr(self.rest_server, 'send_request',
                            self.rest_server._fake_send_request)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.request(path=f"/v1/{network}/wallets/{wallet_name}/"
                                      f"{index}/txs/create_and_broadcast",
                                 method='post',
                                 json={"outputs": [P2PKH_OUTPUT]})
        # check
        expected_json ={'value': {'txid': Transaction.from_hex(rawtx).txid()}}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json

    async def test_broadcast_good_response(self, monkeypatch, cli):
        monkeypatch.setattr(self.rest_server, '_get_child_wallet',
                            _fake_get_child_wallet_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, '_create_transaction',
                            _fake_create_transaction_succeeded)
        monkeypatch.setattr(self.rest_server.app_state.app, 'broadcast_tx',
                            _fake_broadcast_tx)
        monkeypatch.setattr(self.rest_server, '_get_and_set_frozen_utxos_for_tx',
                            self.rest_server._fake_get_and_set_frozen_utxos_for_tx)
        monkeypatch.setattr(self.rest_server, 'send_request',
                            self.rest_server._fake_send_request)

        # mock request
        network = "test"
        wallet_name = "wallet_file1.sqlite"
        index = "0"
        resp = await cli.request(path=f"/v1/{network}/wallets/{wallet_name}/"
                                      f"{index}/txs/broadcast",
                                 method='post',
                                 json={"rawtx": rawtx})
        # check
        tx = Transaction.from_hex(rawtx)
        expected_json = {"value": {"txid": tx.txid()}}
        assert resp.status == 200, await resp.read()
        response = await resp.read()
        assert json.loads(response) == expected_json
