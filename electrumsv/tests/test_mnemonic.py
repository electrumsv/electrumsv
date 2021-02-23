import unittest

from bitcoinx import BIP39Mnemonic, ElectrumMnemonic, Wordlists

from electrumsv.mnemonic import mnemonic_to_seed
from electrumsv.util import bh2u



class Test_NewMnemonic(unittest.TestCase):

    def test_to_seed(self):
        seed = mnemonic_to_seed(mnemonic='foobar', passphrase='none')
        self.assertEqual(bh2u(seed),
                          '741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5b'
                          'b22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce')


class Test_OldMnemonic(unittest.TestCase):
    def test(self):
        seed = '8edad31a95e7d59f8837667510d75a4d'
        result = ElectrumMnemonic.hex_seed_to_old(seed)
        words = 'hardly point goal hallway patience key stone difference ready caught listen fact'
        self.assertEqual(result, words)
        self.assertEqual(ElectrumMnemonic.old_to_hex_seed(result), seed)


class Test_BIP39Checksum(unittest.TestCase):
    def test(self):
        text = (u'gravity machine north sort system female filter attitude volume fold club stay '
            'feature office ecology stable narrow fog')
        assert BIP39Mnemonic.is_valid(text, Wordlists.bip39_wordlist("english.txt"))
