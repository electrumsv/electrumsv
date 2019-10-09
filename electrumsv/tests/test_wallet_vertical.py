import os
import tempfile
import unittest
from unittest import mock

from bitcoinx import Address

from electrumsv.bitcoin import seed_type, address_from_string
from electrumsv import keystore
from electrumsv import storage
from electrumsv import wallet
from electrumsv import wallet_database

from .util import setup_async, tear_down_async


def setUpModule():
    setup_async()


def tearDownModule():
    tear_down_async()


class _ParentWallet(wallet.ParentWallet):
    def name(self):
        return self.__class__.__name__

class MockStorage:
    def __init__(self) -> None:
        self.path = tempfile.mktemp()
        self.tx_store_aeskey_hex = os.urandom(32).hex()

    def get(self, attr_name, default=None):
        if attr_name == "tx_store_aeskey":
            return self.tx_store_aeskey_hex
        return default

    def get_path(self):
        return self.path

    def get_db_context(self):
        return wallet_database.DatabaseContext(self.path)


class TestWalletKeystoreAddressIntegrity(unittest.TestCase):
    gap_limit = 1  # make tests run faster

    def setUp(self) -> None:
        self.storage = MockStorage()
        self.parent_wallet = _ParentWallet.as_legacy_wallet_container(self.storage)

    def _check_seeded_keystore_sanity(self, ks):
        self.assertTrue (ks.is_deterministic())
        self.assertFalse(ks.is_watching_only())
        self.assertFalse(ks.can_import())
        self.assertTrue (ks.has_seed())

    def _check_xpub_keystore_sanity(self, ks):
        self.assertTrue (ks.is_deterministic())
        self.assertTrue (ks.is_watching_only())
        self.assertFalse(ks.can_import())
        self.assertFalse(ks.has_seed())

    def _create_standard_wallet(self, ks):
        keystore_usage = self.parent_wallet.add_keystore(ks.dump())
        w = wallet.Standard_Wallet.create_within_parent(self.parent_wallet,
            keystore_usage=[ keystore_usage ], gap_limit=self.gap_limit)
        w.synchronize()
        return w

    def _create_multisig_wallet(self, ks1, ks2):
        keystore_usages = []
        keystore_usage = self.parent_wallet.add_keystore(ks1.dump())
        keystore_usage['name'] = f'x{1:d}/'
        keystore_usages.append(keystore_usage)
        keystore_usage = self.parent_wallet.add_keystore(ks2.dump())
        keystore_usage['name'] = f'x{2:d}/'
        keystore_usages.append(keystore_usage)

        multisig_type = "%dof%d" % (2, 2)
        w = wallet.Multisig_Wallet.create_within_parent(self.parent_wallet,
            keystore_usage=keystore_usages, wallet_type=multisig_type, gap_limit=self.gap_limit)
        w.synchronize()
        return w

    def test_electrum_seed_standard(self):
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        self.assertEqual(seed_type(seed_words), 'standard')

        ks = keystore.from_seed(seed_words, '', False)

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0],
                         address_from_string('1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf'))
        self.assertEqual(w.get_change_addresses()[0],
                         address_from_string('1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D'))

    def test_electrum_seed_old(self):
        seed_words = 'powerful random nobody notice nothing important anyway look away hidden message over'
        self.assertEqual(seed_type(seed_words), 'old')

        ks = keystore.from_seed(seed_words, '', False)

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.Old_KeyStore))

        self.assertEqual(ks.mpk, 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0],
                         address_from_string('1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo'))
        self.assertEqual(w.get_change_addresses()[0],
                         address_from_string('1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe'))

    def test_bip39_seed_bip44_standard(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJWFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLdvdbjv')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.get_receiving_addresses()[0],
                         address_from_string('16j7Dqk3Z9DdTdBtHcCVLaNQy9MTgywUUo'))
        self.assertEqual(w.get_change_addresses()[0],
                         address_from_string('1GG5bVeWgAp5XW7JLCphse14QaC4qiHyWn'))

    def test_electrum_multisig_seed_standard(self):
        seed_words = 'blast uniform dragon fiscal ensure vast young utility dinosaur abandon rookie sure'
        self.assertEqual(seed_type(seed_words), 'standard')

        ks1 = keystore.from_seed(seed_words, '', True)
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcGNEPu3aJQqXTydqR9t49Tkwb4Esrj112kw8xLthv8uybxvaki4Ygt9xiwZUQGeFTG7T2TUzR3eA4Zp3aq5RXsABHFBUrq4c')

        ks2 = keystore.from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDbenT33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0], address_from_string('32ji3QkAgXNz6oFoRfakyD3ys1XXiERQYN'))
        self.assertEqual(w.get_change_addresses()[0], address_from_string('36XWwEHrrVCLnhjK5MrVVGmUHghr9oWTN1'))

    def test_bip39_multisig_seed_bip45_standard(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks1 = keystore.from_bip39_seed(seed_words, '', "m/45'/0")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xpub69xafV4YxC6o8Yiga5EiGLAtqR7rgNgNUGiYgw3S9g9pp6XYUne1KxdcfYtxwmA3eBrzMFuYcNQKfqsXCygCo4GxQFHfywxpUbKNfYvGJka')

        ks2 = keystore.from_xpub('xpub6Bco9vrgo8rNUSi8Bjomn8xLA41DwPXeuPcgJamNRhTTyGVHsp8fZXaGzp9ypHoei16J6X3pumMAP1u3Dy4jTSWjm4GZowL7Dcn9u4uZC9W')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.get_receiving_addresses()[0],
                         address_from_string('3H3iyACDTLJGD2RMjwKZcCwpdYZLwEZzKb'))
        self.assertEqual(w.get_change_addresses()[0],
                         address_from_string('31hyfHrkhNjiPZp1t7oky5CGNYqSqDAVM9'))
