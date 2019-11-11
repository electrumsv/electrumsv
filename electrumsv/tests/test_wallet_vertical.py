import pytest
import tempfile
import unittest


from electrumsv.bitcoin import seed_type, address_from_string
from electrumsv.constants import ScriptType
from electrumsv import keystore
from electrumsv.keystore import Multisig_KeyStore
from electrumsv.networks import Net, SVMainnet
from electrumsv import wallet_database
from electrumsv.wallet import MultisigAccount, StandardAccount, Wallet
from electrumsv.wallet_database.tables import AccountRow

from .util import setup_async, tear_down_async


def setUpModule():
    setup_async()


def tearDownModule():
    tear_down_async()


class _Wallet(Wallet):
    def name(self):
        return self.__class__.__name__

class MockStorage:
    def __init__(self) -> None:
        self.path = tempfile.mktemp()

        from electrumsv.wallet_database.migration import create_database_file, update_database_file
        create_database_file(self.path)
        update_database_file(self.path)

        self._data = {}

    def get(self, attr_name, default=None):
        return self._data.get(attr_name, default)

    def put(self, attr_name, value) -> None:
        self._data[attr_name] = value

    def get_path(self):
        return self.path

    def get_db_context(self):
        return wallet_database.DatabaseContext(self.path)


class TestWalletKeystoreAddressIntegrity(unittest.TestCase):
    gap_limit = 1  # make tests run faster

    def setUp(self) -> None:
        Net.set_to(SVMainnet)

        self.storage = MockStorage()
        self.wallet = _Wallet(self.storage)

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

    def _create_standard_wallet(self, ks: keystore.KeyStore) -> StandardAccount:
        masterkey_row = self.wallet.create_masterkey_from_keystore(ks)
        account_row = AccountRow(1, masterkey_row.masterkey_id, ScriptType.P2PKH, '...')
        account = StandardAccount(self.wallet, account_row, [], [])
        account.synchronize()
        return account

    def _create_multisig_wallet(self, ks1, ks2):
        keystore = Multisig_KeyStore({ 'm': 2, 'n': 2, "cosigner-keys": [] })
        keystore.add_cosigner_keystore(ks1)
        keystore.add_cosigner_keystore(ks2)
        masterkey_row = self.wallet.create_masterkey_from_keystore(keystore)
        account_row = AccountRow(1, masterkey_row.masterkey_id, ScriptType.MULTISIG_P2SH, 'text')
        account = MultisigAccount(self.wallet, account_row, [], [])
        self.wallet.register_account(account.get_id(), account)
        account.synchronize()
        return account

    @pytest.mark.timeout(8)
    def test_electrum_seed_standard(self):
        seed_words = 'cycle rocket west magnet parrot shuffle foot correct salt library feed song'
        self.assertEqual(seed_type(seed_words), 'standard')

        ks = keystore.from_seed(seed_words, '')

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xpub661MyMwAqRbcFWohJWt7PHsFEJfZAvw9ZxwQoDa4SoMgsDDM1T7WK3u'
            '9E4edkC4ugRnZ8E4xDZRpk8Rnts3Nbt97dPwT52CwBdDWroaZf8U')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.derive_script_template((0, 0)),
                         address_from_string('1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf'))
        self.assertEqual(w.derive_script_template((1, 0)),
                         address_from_string('1KSezYMhAJMWqFbVFB2JshYg69UpmEXR4D'))

    def test_electrum_seed_old(self):
        seed_words = 'powerful random nobody notice nothing important anyway look away hidden message over'
        self.assertEqual(seed_type(seed_words), 'old')

        ks = keystore.from_seed(seed_words, '')

        self._check_seeded_keystore_sanity(ks)
        self.assertTrue(isinstance(ks, keystore.Old_KeyStore))

        self.assertEqual(ks.mpk, 'e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c77'
            '37968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.derive_pubkeys((0, 0)).to_address(),
                         address_from_string('1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo'))
        self.assertEqual(w.derive_pubkeys((1, 0)).to_address(),
                         address_from_string('1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe'))

    def test_bip39_seed_bip44_standard(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks = keystore.from_bip39_seed(seed_words, '', "m/44'/0'/0'")

        self.assertTrue(isinstance(ks, keystore.BIP32_KeyStore))

        self.assertEqual(ks.xpub, 'xpub6DFh1smUsyqmYD4obDX6ngaxhd53Zx7aeFjoobebm7vbkT6f9awJ'
            'WFuGzBT9FQJEWFBL7UyhMXtYzRcwDuVbcxtv9Ce2W9eMm4KXLdvdbjv')

        w = self._create_standard_wallet(ks)

        self.assertEqual(w.derive_script_template((0, 0)),
                         address_from_string('16j7Dqk3Z9DdTdBtHcCVLaNQy9MTgywUUo'))
        self.assertEqual(w.derive_script_template((1, 0)),
                         address_from_string('1GG5bVeWgAp5XW7JLCphse14QaC4qiHyWn'))

    def test_electrum_multisig_seed_standard(self):
        seed_words = ('blast uniform dragon fiscal ensure vast young utility dinosaur '
            'abandon rookie sure')
        self.assertEqual(seed_type(seed_words), 'standard')

        ks1 = keystore.from_seed(seed_words, '')
        self._check_seeded_keystore_sanity(ks1)
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xpub661MyMwAqRbcGNEPu3aJQqXTydqR9t49Tkwb4Esrj112kw8xLthv'
            '8uybxvaki4Ygt9xiwZUQGeFTG7T2TUzR3eA4Zp3aq5RXsABHFBUrq4c')

        ks2 = keystore.from_xpub('xpub661MyMwAqRbcGfCPEkkyo5WmcrhTq8mi3xuBS7VEZ3LYvsgY1cCFDb'
            'enT33bdD12axvrmXhuX3xkAbKci3yZY9ZEk8vhLic7KNhLjqdh5ec')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.derive_script_template((0, 0)),
            address_from_string('32ji3QkAgXNz6oFoRfakyD3ys1XXiERQYN'))
        self.assertEqual(w.derive_script_template((1, 0)),
            address_from_string('36XWwEHrrVCLnhjK5MrVVGmUHghr9oWTN1'))

    def test_bip39_multisig_seed_bip45_standard(self):
        seed_words = 'treat dwarf wealth gasp brass outside high rent blood crowd make initial'
        self.assertEqual(keystore.bip39_is_checksum_valid(seed_words), (True, True))

        ks1 = keystore.from_bip39_seed(seed_words, '', "m/45'/0")
        self.assertTrue(isinstance(ks1, keystore.BIP32_KeyStore))
        self.assertEqual(ks1.xpub, 'xpub69xafV4YxC6o8Yiga5EiGLAtqR7rgNgNUGiYgw3S9g9pp6XYUne1'
            'KxdcfYtxwmA3eBrzMFuYcNQKfqsXCygCo4GxQFHfywxpUbKNfYvGJka')

        ks2 = keystore.from_xpub('xpub6Bco9vrgo8rNUSi8Bjomn8xLA41DwPXeuPcgJamNRhTTyGVHsp8fZX'
            'aGzp9ypHoei16J6X3pumMAP1u3Dy4jTSWjm4GZowL7Dcn9u4uZC9W')
        self._check_xpub_keystore_sanity(ks2)
        self.assertTrue(isinstance(ks2, keystore.BIP32_KeyStore))

        w = self._create_multisig_wallet(ks1, ks2)

        self.assertEqual(w.derive_script_template((0, 0)),
            address_from_string('3H3iyACDTLJGD2RMjwKZcCwpdYZLwEZzKb'))
        self.assertEqual(w.derive_script_template((1, 0)),
            address_from_string('31hyfHrkhNjiPZp1t7oky5CGNYqSqDAVM9'))
