import unittest

import pytest
from bitcoinx import Address
from electrumsv.wallet import Standard_Wallet
from electrumsv.wallet_database import UTXO, UTXOCache, TxXputCache, DBTxOutput

from bitcoinx import Address, Script
from electrumsv.wallet_database import UTXO

ADDRESSES = [
    Address.from_string('miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou'),
    Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr'),
]

FROZEN_COINS = {('dde980dd85e34e7ab2ba09f4e3408323c84132fe7ec1ac1fdfb9bd0a953601f2', 1),
                ('7fb5e74c98957fdcd645b5e42ef959d4a20e8dd7b23a9d911159a0ed4f059bb8', 0)}

FROZEN_ADDRESSES = {'dde980dd85e34e7ab2ba09f4e3408323c84132fe7ec1ac1fdfb9bd0a953601f2',
                    '7fb5e74c98957fdcd645b5e42ef959d4a20e8dd7b23a9d911159a0ed4f059bb8'}

SPENDABLE_UTXOS = [
    UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr'),
         height=1329528,
         is_coinbase=False,
         out_index=0,
         script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff\x12\x88'
                              b'\xac'),
         tx_hash='8aed908726dc878fb7316fc4f11054dbc69b6ac8b206d3fca5a7412d7e9e458d',
         value=7782292),
    UTXO(address=Address.from_string('miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou'),
         height=1329527,
         is_coinbase=False,
         out_index=0,
         script_pubkey=Script(b'v\xa9\x14&\x0c\x95\x8e\x81\xc8o\xe3.\xc3\xd4\x1d7\x1cy\x0e\xed'
                                b'\x9a\xb4\xf3\x88\xac'),
         tx_hash='76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf',
         value=3000000)
]

ALL_UTXOS = [UTXO(address=Address.from_string('miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou'),
                  height=1329527,
                  is_coinbase=False,
                  out_index=0,
                  script_pubkey=Script(b'v\xa9\x14&\x0c\x95\x8e\x81\xc8o\xe3.\xc3\xd4\x1d7\x1cy'
                                         b'\x0e\xed\x9a\xb4\xf3\x88\xac'),
                  tx_hash='76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf',
                  value=3000000),
             UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr'),
                  height=1329528,
                  is_coinbase=False,
                  out_index=0,
                  script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff'
                                         b'\x12\x88\xac'),
                  tx_hash='8aed908726dc878fb7316fc4f11054dbc69b6ac8b206d3fca5a7412d7e9e458d',
                  value=7782292),
             UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr'),
                  height=1329528,
                  is_coinbase=False,
                  out_index=0,
                  script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff'
                                         b'\x12\x88\xac'),
                  tx_hash='7fb5e74c98957fdcd645b5e42ef959d4a20e8dd7b23a9d911159a0ed4f059bb8',
                  value=98768),
             UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr'),
                  height=1329529,
                  is_coinbase=False,
                  out_index=1,
                  script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff'
                                         b'\x12\x88\xac'),
                  tx_hash='dde980dd85e34e7ab2ba09f4e3408323c84132fe7ec1ac1fdfb9bd0a953601f2',
                  value=2000000)]

ALL_TXOUT = {'76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf':
     [DBTxOutput(address_string='miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou', out_tx_n=0, amount=3000000, is_coinbase=False)],
 '7fb5e74c98957fdcd645b5e42ef959d4a20e8dd7b23a9d911159a0ed4f059bb8':
     [DBTxOutput(address_string='msccMGHunfHANQWXMZragRggHMkJaBWSFr', out_tx_n=0, amount=98768, is_coinbase=False)],
 '8aed908726dc878fb7316fc4f11054dbc69b6ac8b206d3fca5a7412d7e9e458d':
     [DBTxOutput(address_string='msccMGHunfHANQWXMZragRggHMkJaBWSFr', out_tx_n=0, amount=7782292, is_coinbase=False)],
 'dde980dd85e34e7ab2ba09f4e3408323c84132fe7ec1ac1fdfb9bd0a953601f2':
     [DBTxOutput(address_string='msccMGHunfHANQWXMZragRggHMkJaBWSFr', out_tx_n=1, amount=2000000, is_coinbase=False)]}

ALL_TXIN = {}

HISTORY = {
    ADDRESSES[0]: [
        ['76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf', 1329527]
    ],
    ADDRESSES[1]: [
        ['8aed908726dc878fb7316fc4f11054dbc69b6ac8b206d3fca5a7412d7e9e458d', 1329528],
        ['7fb5e74c98957fdcd645b5e42ef959d4a20e8dd7b23a9d911159a0ed4f059bb8', 1329528],
        ['dde980dd85e34e7ab2ba09f4e3408323c84132fe7ec1ac1fdfb9bd0a953601f2', 1329529]
    ]
}

class MockTxOutputCache:

    def get_entries(self, txid):
        return ALL_TXOUT.get(txid)


class MockTxInputCache:

    def get_entries(self, txid):
        return ALL_TXIN.get(txid, [])


class MockWalletData:
    def __init__(self):
        self.utxos = UTXOCache()
        self.txout = MockTxOutputCache()
        self.txin = MockTxInputCache()


class MockNetwork:

    def get_local_height(self):
        return 1329529

    def get_txouts(self):
        return


class MockWallet(Standard_Wallet):
    def __init__(self) -> None:
        self._datastore = MockWalletData()
        self._frozen_coins = FROZEN_COINS
        self._frozen_addresses = FROZEN_ADDRESSES
        self.config = {'confirmed_only': False}
        self.network = MockNetwork()
        self._history = HISTORY

    def get_receiving_addresses(self):
        return ADDRESSES

    def get_change_addresses(self):
        return []


class TestUTXOCache(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mockwallet_instance = MockWallet()

    def test_get_utxos(self):
        coins = self.mockwallet_instance.get_utxos(domain=None, exclude_frozen=False,
                                                   mature=False, confirmed_only=False)
        self.assertEqual(ALL_UTXOS, coins)

    def test_get_utxos_cached(self):
        coins = self.mockwallet_instance.get_utxos_cached(exclude_frozen=False,
                                                          mature=False, confirmed_only=False)
        self.assertEqual(ALL_UTXOS, coins)

    def test_get_spendable_coins(self):
        coins = self.mockwallet_instance.get_spendable_coins(None, {}, isInvoice=False)
        coins_repeated = self.mockwallet_instance.get_spendable_coins(None, {}, isInvoice=False)
        self.assertCountEqual(SPENDABLE_UTXOS, coins)
        self.assertEqual(coins, coins_repeated)

    def test_get_spendable_coins_cached(self):
        coins_cached = self.mockwallet_instance.get_spendable_coins_cached({}, isInvoice=False)
        coins = self.mockwallet_instance.get_spendable_coins(None, {}, isInvoice=False)
        self.assertEqual(coins, list(coins_cached))
        self.assertEqual(SPENDABLE_UTXOS, coins_cached)

