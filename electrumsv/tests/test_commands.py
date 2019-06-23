import json
import unittest
from decimal import Decimal

from electrumsv.commands import Commands
from bitcoinx import PrivateKey


privkey = PrivateKey.from_WIF('L2o1ztYYR9t7DcXGzsV2zKWJUXEmfh3C6vmKM3CCAAfeJ44AkLcr')
pubkey_hex = privkey.public_key.to_hex()


class TestCommands(unittest.TestCase):

    def test_setconfig_non_auth_number(self):
        self.assertEqual(7777, Commands._setconfig_normalize_value('rpcport', "7777"))
        self.assertEqual(7777, Commands._setconfig_normalize_value('rpcport', '7777'))
        self.assertAlmostEqual(Decimal(2.3), Commands._setconfig_normalize_value('somekey', '2.3'))

    def test_setconfig_non_auth_number_as_string(self):
        self.assertEqual("7777", Commands._setconfig_normalize_value('somekey', "'7777'"))

    def test_setconfig_non_auth_boolean(self):
        self.assertEqual(True, Commands._setconfig_normalize_value('show_console_tab', "true"))
        self.assertEqual(True, Commands._setconfig_normalize_value('show_console_tab', "True"))

    def test_setconfig_non_auth_list(self):
        self.assertEqual(['file:///var/www/', 'https://electrumsv.io'],
            Commands._setconfig_normalize_value('url_rewrite',
                "['file:///var/www/','https://electrumsv.io']"))
        self.assertEqual(['file:///var/www/', 'https://electrumsv.io'],
            Commands._setconfig_normalize_value('url_rewrite',
                '["file:///var/www/","https://electrumsv.io"]'))

    def test_setconfig_auth(self):
        self.assertEqual("7777", Commands._setconfig_normalize_value('rpcuser', "7777"))
        self.assertEqual("7777", Commands._setconfig_normalize_value('rpcuser', '7777'))
        self.assertEqual("7777", Commands._setconfig_normalize_value('rpcpassword', '7777'))
        self.assertEqual("2asd", Commands._setconfig_normalize_value('rpcpassword', '2asd'))
        self.assertEqual("['file:///var/www/','https://electrumsv.io']",
            Commands._setconfig_normalize_value('rpcpassword',
                "['file:///var/www/','https://electrumsv.io']"))

    def test_encrypt(self):
        c = Commands(None, None, None)
        msg = 'BitcoinSV'
        enc_msg = c.encrypt(pubkey_hex, msg)
        assert privkey.decrypt_message(enc_msg).decode() == msg

    def test_verifymessage(self):
        c = Commands(None, None, None)
        message = 'Hello'
        signature = privkey.sign_message_to_base64(message)
        address = privkey.public_key.to_address()
        assert c.verifymessage(address, signature, message)

    def test_createmultisig(self):
        c = Commands(None, None, None)
        pubkeys = ["03b25918969e43702abeb6a60942e72e3a3c603dfd272de59e7679a52f35527ccf",
                    "0383cf538b41dbba7b7ee57a53bc673fef8a6896734ae587032f755ac0cba86cc2"]

        result = c.createmultisig(2, pubkeys)
        result_rev = c.createmultisig(2, list(reversed(pubkeys)))
        assert result == result_rev
        assert result == {
            "address": "3AiUfSRMbvXzyAHhFoFAtVFibWPdkNV9DW",
            "redeemScript": (
                "52210383cf538b41dbba7b7ee57a53bc673fef8a6896734ae587032f755ac0cba86c"
                "c22103b25918969e43702abeb6a60942e72e3a3c603dfd272de59e7679a52f35527ccf52ae"
            )
        }