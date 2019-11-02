import threading
import unittest
from electrumsv.wallet import Standard_Wallet
from electrumsv.wallet_database import UTXO, UTXOCache, DBTxOutput
from bitcoinx import CheckPoint, Address, Script, BitcoinTestnet


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


ADDRESSES = [
    Address.from_string('miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou', Net.COIN),
    Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr', Net.COIN),
]

FROZEN_COINS = {('dde980dd85e34e7ab2ba09f4e3408323c84132fe7ec1ac1fdfb9bd0a953601f2', 1),
                ('7fb5e74c98957fdcd645b5e42ef959d4a20e8dd7b23a9d911159a0ed4f059bb8', 0)}

FROZEN_ADDRESSES = set({})

SPENDABLE_UTXOS = [
    UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr',
                                     Net.COIN),
         height=1329528,
         is_coinbase=False,
         out_index=0,
         script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff\x12\x88'
                              b'\xac'),
         tx_hash='8aed908726dc878fb7316fc4f11054dbc69b6ac8b206d3fca5a7412d7e9e458d',
         value=7782292),
    UTXO(address=Address.from_string('miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou',
                                     Net.COIN),
         height=1329527,
         is_coinbase=False,
         out_index=0,
         script_pubkey=Script(b'v\xa9\x14&\x0c\x95\x8e\x81\xc8o\xe3.\xc3\xd4\x1d7\x1cy\x0e\xed'
                                b'\x9a\xb4\xf3\x88\xac'),
         tx_hash='76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf',
         value=3000000)
]

ALL_UTXOS = [UTXO(address=Address.from_string('miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou',
                                              Net.COIN),
                  height=1329527,
                  is_coinbase=False,
                  out_index=0,
                  script_pubkey=Script(b'v\xa9\x14&\x0c\x95\x8e\x81\xc8o\xe3.\xc3\xd4\x1d7\x1cy'
                                         b'\x0e\xed\x9a\xb4\xf3\x88\xac'),
                  tx_hash='76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf',
                  value=3000000),
             UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr',
                                              Net.COIN),
                  height=1329528,
                  is_coinbase=False,
                  out_index=0,
                  script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff'
                                         b'\x12\x88\xac'),
                  tx_hash='8aed908726dc878fb7316fc4f11054dbc69b6ac8b206d3fca5a7412d7e9e458d',
                  value=7782292),
             UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr',
                                              Net.COIN),
                  height=1329528,
                  is_coinbase=False,
                  out_index=0,
                  script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff'
                                         b'\x12\x88\xac'),
                  tx_hash='7fb5e74c98957fdcd645b5e42ef959d4a20e8dd7b23a9d911159a0ed4f059bb8',
                  value=98768),
             UTXO(address=Address.from_string('msccMGHunfHANQWXMZragRggHMkJaBWSFr',
                                              Net.COIN),
                  height=1329529,
                  is_coinbase=False,
                  out_index=1,
                  script_pubkey=Script(b'v\xa9\x14\x84\xb3[1i\xe4+"}+\x9d\x85s!\t\xa1y\xab\xff'
                                         b'\x12\x88\xac'),
                  tx_hash='dde980dd85e34e7ab2ba09f4e3408323c84132fe7ec1ac1fdfb9bd0a953601f2',
                  value=2000000)]

ALL_TXOUT = {'76d5bfabe40ca6cbd315b04aa24b68fdd8179869fd1c3501d5a88a980c61c1bf':
     [DBTxOutput(address_string='miz93i75XiTdnvzkU6sDddvGcCr4ZrCmou', out_tx_n=0,
                 amount=3000000, is_coinbase=False)],
 '7fb5e74c98957fdcd645b5e42ef959d4a20e8dd7b23a9d911159a0ed4f059bb8':
     [DBTxOutput(address_string='msccMGHunfHANQWXMZragRggHMkJaBWSFr', out_tx_n=0,
                 amount=98768, is_coinbase=False)],
 '8aed908726dc878fb7316fc4f11054dbc69b6ac8b206d3fca5a7412d7e9e458d':
     [DBTxOutput(address_string='msccMGHunfHANQWXMZragRggHMkJaBWSFr', out_tx_n=0,
                 amount=7782292, is_coinbase=False)],
 'dde980dd85e34e7ab2ba09f4e3408323c84132fe7ec1ac1fdfb9bd0a953601f2':
     [DBTxOutput(address_string='msccMGHunfHANQWXMZragRggHMkJaBWSFr', out_tx_n=1,
                 amount=2000000, is_coinbase=False)]}

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
        self.lock = threading.RLock()
        self.transaction_lock = threading.RLock()

    def get_receiving_addresses(self):
        return ADDRESSES

    def get_change_addresses(self):
        return []


class TestUTXOCache(unittest.TestCase):

    def setUp(self) -> None:
        self.mockwallet_instance = MockWallet()

    def test_get_utxos(self):
        coins = self.mockwallet_instance.get_utxos(domain=None, exclude_frozen=False,
                                                   mature=False, confirmed_only=False)
        self.assertEqual(ALL_UTXOS, coins)

    def test_get_utxos_exclude_frozen(self):
        coins = self.mockwallet_instance.get_utxos(domain=None, exclude_frozen=True,
                                                   mature=False, confirmed_only=False)
        self.assertCountEqual(SPENDABLE_UTXOS, coins)

    def test_get_utxos_cached(self):
        default = self.mockwallet_instance.get_utxos_cached()
        coins = self.mockwallet_instance.get_utxos_cached(exclude_frozen=False,
                                                          mature=False, confirmed_only=False)
        self.assertEqual(ALL_UTXOS, default)
        self.assertEqual(ALL_UTXOS, coins)

    def test_get_utxos_cached_exclude_frozen(self):
        coins = self.mockwallet_instance.get_utxos_cached(exclude_frozen=True,
                                                          mature=False, confirmed_only=False)
        self.assertCountEqual(SPENDABLE_UTXOS, coins)

    def test_get_spendable_coins(self):
        coins = self.mockwallet_instance.get_spendable_coins(None, {}, isInvoice=False)
        repeat = self.mockwallet_instance.get_spendable_coins(None, {}, isInvoice=False)
        self.assertCountEqual(SPENDABLE_UTXOS, coins)
        self.assertEqual(coins, repeat)

    def test_get_spendable_coins_cached(self):
        coins_cached = self.mockwallet_instance.get_spendable_coins_cached({}, isInvoice=False)
        coins = self.mockwallet_instance.get_spendable_coins(None, {}, isInvoice=False)

        coins_cached_repeat = self.mockwallet_instance.get_spendable_coins_cached({},
                                                                                  isInvoice=False)
        self.assertCountEqual(coins, list(coins_cached))
        self.assertCountEqual(SPENDABLE_UTXOS, list(coins_cached))
        self.assertEqual(coins_cached, coins_cached_repeat)

    def test_filter_frozen_utxos(self):
        utxo_cache = UTXOCache(ALL_UTXOS)
        frozen_utxos = self.mockwallet_instance._datastore.utxos.get_frozen_utxos(
            FROZEN_COINS, utxo_cache)
        filtered = self.mockwallet_instance._datastore.utxos.filter_frozen_utxos(frozen_utxos,
                                                                                 utxo_cache)
        self.assertCountEqual(SPENDABLE_UTXOS, list(filtered))

    def test_remove_utxos(self):
        utxo_cache = self.mockwallet_instance.get_utxos_cached(exclude_frozen=False)  # load cache
        utxos_for_removal = self.mockwallet_instance._datastore.utxos.get_frozen_utxos(
            FROZEN_COINS, utxo_cache)

        # remove spent or frozen coins from utxo set
        self.mockwallet_instance._datastore.utxos.remove_utxos(utxos_for_removal)

        self.assertCountEqual(SPENDABLE_UTXOS, self.mockwallet_instance._datastore.utxos)

    def test_undo_remove_utxos(self):
        """Adds back utxos that have been unfrozen"""
        self.mockwallet_instance.get_utxos_cached(exclude_frozen=True)  # load cache
        utxos_to_add_back = self.mockwallet_instance._datastore.utxos.get_frozen_utxos(FROZEN_COINS,
                                                                                       ALL_UTXOS)

        # add back coins that were not spent or unfrozen due to failed broadcast
        self.mockwallet_instance._datastore.utxos.undo_remove_utxos(utxos_to_add_back)

        self.assertCountEqual(ALL_UTXOS, self.mockwallet_instance._datastore.utxos)
