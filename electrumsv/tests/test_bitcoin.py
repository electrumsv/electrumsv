import base64

from bitcoinx import (
    PublicKey, PrivateKey, Bitcoin, BitcoinTestnet, base58_encode_check, is_minikey,
    ElectrumMnemonic
)

from electrumsv.bitcoin import address_from_string, is_address_valid, scripthash_hex
from electrumsv.constants import SEED_PREFIX
from electrumsv.crypto import sha256d
from electrumsv import crypto
from electrumsv.exceptions import InvalidPassword
from electrumsv.storage import WalletStorage


from . import SequentialTestCase
from . import TestCaseForTestnet


def address_to_script(addr):
    return address_from_string(addr).to_script_bytes().hex()


class Test_bitcoin(SequentialTestCase):

    def test_msg_signing(self):
        msg1 = b'Chancellor on brink of second bailout for banks'
        msg2 = b'Electrum'

        def sign_message_with_wif_privkey(wif_privkey, msg):
            key = PrivateKey.from_WIF(wif_privkey)
            return key.sign_message(msg)

        sig1 = sign_message_with_wif_privkey(
            'L1TnU2zbNaAqMoVh65Cyvmcjzbrj41Gs9iTLcWbpJCMynXuap6UN', msg1)
        addr1 = '15hETetDmcXm1mM4sEf7U2KXC9hDHFMSzz'
        sig2 = sign_message_with_wif_privkey(
            '5Hxn5C4SQuiV6e62A1MtZmbSeQyrLFhu5uYks62pU5VBUygK2KD', msg2)
        addr2 = '1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6'

        sig1_b64 = base64.b64encode(sig1)
        sig2_b64 = base64.b64encode(sig2)

        self.assertEqual(sig1_b64, b'H/9jMOnj4MFbH3d7t4yCQ9i7DgZU/VZ278w3+ySv2F4yIsdqjsc5ng3kmN8OZAThgyfCZOQxZCWza9V5XzlVY0Y=')
        self.assertEqual(sig2_b64, b'G84dmJ8TKIDKMT9qBRhpX2sNmR0y5t+POcYnFFJCs66lJmAs3T8A6Sbpx7KA6yTQ9djQMabwQXRrDomOkIKGn18=')

        self.assertTrue(PublicKey.verify_message_and_address(sig1, msg1, addr1))
        self.assertTrue(PublicKey.verify_message_and_address(sig2, msg2, addr2))

        self.assertFalse(PublicKey.verify_message_and_address(b'wrong', msg1, addr1))
        self.assertFalse(PublicKey.verify_message_and_address(sig2, msg1, addr1))

    def test_decrypt_message(self):
        key = WalletStorage.get_eckey_from_password('pw123')
        self.assertEqual(b'me<(s_s)>age', key.decrypt_message('QklFMQMDFtgT3zWSQsa+Uie8H/WvfUjlu9UN9OJtTt3KlgKeSTi6SQfuhcg1uIz9hp3WIUOFGTLr4RNQBdjPNqzXwhkcPi2Xsbiw6UCNJncVPJ6QBg=='))
        self.assertEqual(b'me<(s_s)>age', key.decrypt_message('QklFMQKXOXbylOQTSMGfo4MFRwivAxeEEkewWQrpdYTzjPhqjHcGBJwdIhB7DyRfRQihuXx1y0ZLLv7XxLzrILzkl/H4YUtZB4uWjuOAcmxQH4i/Og=='))
        self.assertEqual(b'hey_there' * 100, key.decrypt_message('QklFMQLOOsabsXtGQH8edAa6VOUa5wX8/DXmxX9NyHoAx1a5bWgllayGRVPeI2bf0ZdWK0tfal0ap0ZIVKbd2eOJybqQkILqT6E1/Syzq0Zicyb/AA1eZNkcX5y4gzloxinw00ubCA8M7gcUjJpOqbnksATcJ5y2YYXcHMGGfGurWu6uJ/UyrNobRidWppRMW5yR9/6utyNvT6OHIolCMEf7qLcmtneoXEiz51hkRdZS7weNf9mGqSbz9a2NL3sdh1A0feHIjAZgcCKcAvksNUSauf0/FnIjzTyPRpjRDMeDC8Ci3sGiuO3cvpWJwhZfbjcS26KmBv2CHWXfRRNFYOInHZNIXWNAoBB47Il5bGSMd+uXiGr+SQ9tNvcu+BiJNmFbxYqg+oQ8dGAl1DtvY2wJVY8k7vO9BIWSpyIxfGw7EDifhc5vnOmGe016p6a01C3eVGxgl23UYMrP7+fpjOcPmTSF4rk5U5ljEN3MSYqlf1QEv0OqlI9q1TwTK02VBCjMTYxDHsnt04OjNBkNO8v5uJ4NR+UUDBEp433z53I59uawZ+dbk4v4ZExcl8EGmKm3Gzbal/iJ/F7KQuX2b/ySEhLOFVYFWxK73X1nBvCSK2mC2/8fCw8oI5pmvzJwQhcCKTdEIrz3MMvAHqtPScDUOjzhXxInQOCb3+UBj1PPIdqkYLvZss1TEaBwYZjLkVnK2MBj7BaqT6Rp6+5A/fippUKHsnB6eYMEPR2YgDmCHL+4twxHJG6UWdP3ybaKiiAPy2OHNP6PTZ0HrqHOSJzBSDD+Z8YpaRg29QX3UEWlqnSKaan0VYAsV1VeaN0XFX46/TWO0L5tjhYVXJJYGqo6tIQJymxATLFRF6AZaD1Mwd27IAL04WkmoQoXfO6OFfwdp/shudY/1gBkDBvGPICBPtnqkvhGF+ZF3IRkuPwiFWeXmwBxKHsRx/3+aJu32Ml9+za41zVk2viaxcGqwTc5KMexQFLAUwqhv+aIik7U+5qk/gEVSuRoVkihoweFzKolNF+BknH2oB4rZdPixag5Zje3DvgjsSFlOl69W/67t/Gs8htfSAaHlsB8vWRQr9+v/lxTbrAw+O0E+sYGoObQ4qQMyQshNZEHbpPg63eWiHtJJnrVBvOeIbIHzoLDnMDsWVWZSMzAQ1vhX1H5QLgSEbRlKSliVY03kDkh/Nk/KOn+B2q37Ialq4JcRoIYFGJ8AoYEAD0tRuTqFddIclE75HzwaNG7NyKW1plsa72ciOPwsPJsdd5F0qdSQ3OSKtooTn7uf6dXOc4lDkfrVYRlZ0PX'))

    def test_encrypt_message(self):
        key = WalletStorage.get_eckey_from_password('secret_password77')
        public_key = key.public_key
        msgs = [
            bytes([0] * 555),
            b'cannot think of anything funny'
        ]
        for plaintext in msgs:
            ciphertext1 = public_key.encrypt_message(plaintext)
            ciphertext2 = public_key.encrypt_message(plaintext)
            self.assertEqual(plaintext, key.decrypt_message(ciphertext1))
            self.assertEqual(plaintext, key.decrypt_message(ciphertext2))
            self.assertNotEqual(ciphertext1, ciphertext2)

    def test_sign_transaction(self):
        eckey1 = PrivateKey(bytes.fromhex('7e1255fddb52db1729fc3ceb21a46f95b8d9fe94cc83425e936a6c5223bb679d'))
        sig1 = eckey1.sign(bytes.fromhex('5a548b12369a53faaa7e51b5081829474ebdd9c924b3a8230b69aa0be254cd94'), None)
        self.assertEqual(bytes.fromhex('3045022100902a288b98392254cd23c0e9a49ac6d7920f171b8249a48e484b998f1874a2010220723d844826828f092cf400cb210c4fa0b8cd1b9d1a7f21590e78e022ff6476b9'), sig1)

        eckey2 = PrivateKey(bytes.fromhex('c7ce8c1462c311eec24dff9e2532ac6241e50ae57e7d1833af21942136972f23'))
        sig2 = eckey2.sign(bytes.fromhex('642a2e66332f507c92bda910158dfe46fc10afbf72218764899d3af99a043fac'), None)
        self.assertEqual(bytes.fromhex('30440220618513f4cfc87dde798ce5febae7634c23e7b9254a1eabf486be820f6a7c2c4702204fef459393a2b931f949e63ced06888f35e286e446dc46feb24b5b5f81c6ed52'), sig2)

    def test_aes_homomorphic(self):
        """Make sure AES is homomorphic."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        password = u'secret'
        enc = crypto.pw_encode(payload, password)
        dec = crypto.pw_decode(enc, password)
        self.assertEqual(dec, payload)

    def test_aes_encode_without_password(self):
        """When not passed a password, pw_encode is noop on the payload."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        enc = crypto.pw_encode(payload, None)
        self.assertEqual(payload, enc)

    def test_aes_deencode_without_password(self):
        """When not passed a password, pw_decode is noop on the payload."""
        payload = u'\u66f4\u7a33\u5b9a\u7684\u4ea4\u6613\u5e73\u53f0'
        enc = crypto.pw_decode(payload, None)
        self.assertEqual(payload, enc)

    def test_aes_decode_with_invalid_password(self):
        """pw_decode raises an Exception when supplied an invalid password."""
        payload = u"blah"
        password = u"uber secret"
        wrong_password = u"not the password"
        enc = crypto.pw_encode(payload, password)
        with self.assertRaises(InvalidPassword):
            crypto.pw_decode(enc, wrong_password)

    def test_sha256d(self):
        self.assertEqual(b'\x95MZI\xfdp\xd9\xb8\xbc\xdb5\xd2R&x)\x95\x7f~\xf7\xfalt\xf8\x84\x19\xbd\xc5\xe8"\t\xf4',
                         sha256d(u"test"))

    def test_address_to_script(self):
        # base58 P2PKH
        self.assertEqual(address_to_script('14gcRovpkCoGkCNBivQBvw7eso7eiNAbxG'), '76a91428662c67561b95c79d2257d2a93d9d151c977e9188ac')
        self.assertEqual(address_to_script('1BEqfzh4Y3zzLosfGhw1AsqbEKVW6e1qHv'), '76a914704f4b81cadb7bf7e68c08cd3657220f680f863c88ac')

        # base58 P2SH
        self.assertEqual(address_to_script('35ZqQJcBQMZ1rsv8aSuJ2wkC7ohUCQMJbT'), 'a9142a84cf00d47f699ee7bbc1dea5ec1bdecb4ac15487')
        self.assertEqual(address_to_script('3PyjzJ3im7f7bcV724GR57edKDqoZvH7Ji'), 'a914f47c8954e421031ad04ecd8e7752c9479206b9d387')


class Test_bitcoin_testnet(TestCaseForTestnet):

    def test_address_to_script(self):
        # base58 P2PKH
        self.assertEqual(address_to_script('mutXcGt1CJdkRvXuN2xoz2quAAQYQ59bRX'), '76a9149da64e300c5e4eb4aaffc9c2fd465348d5618ad488ac')
        self.assertEqual(address_to_script('miqtaRTkU3U8rzwKbEHx3g8FSz8GJtPS3K'), '76a914247d2d5b6334bdfa2038e85b20fc15264f8e5d2788ac')

        # base58 P2SH
        self.assertEqual(address_to_script('2N3LSvr3hv5EVdfcrxg2Yzecf3SRvqyBE4p'), 'a9146eae23d8c4a941316017946fc761a7a6c85561fb87')
        self.assertEqual(address_to_script('2NE4ZdmxFmUgwu5wtfoN2gVniyMgRDYq1kk'), 'a914e4567743d378957cd2ee7072da74b1203c1a7a0b87')


class Test_xprv_xpub(SequentialTestCase):

    xprv_xpub = (
        # Taken from test vectors in https://en.bitcoin.it/wiki/BIP_0032_TestVectors
        {'xprv': 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
         'xpub': 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'},
    )

    def test_version_bytes(self):
        xprv_headers_b58 = 'xprv'
        xpub_headers_b58 = 'xpub'

        xkey_bytes = Bitcoin.xprv_verbytes + bytes([0] * 74)
        xkey_b58 = base58_encode_check(xkey_bytes)
        self.assertTrue(xkey_b58.startswith(xprv_headers_b58))

        xkey_bytes = Bitcoin.xprv_verbytes + bytes([255] * 74)
        xkey_b58 = base58_encode_check(xkey_bytes)
        self.assertTrue(xkey_b58.startswith(xprv_headers_b58))

        xkey_bytes = Bitcoin.xpub_verbytes + bytes([0] * 74)
        xkey_b58 = base58_encode_check(xkey_bytes)
        self.assertTrue(xkey_b58.startswith(xpub_headers_b58))

        xkey_bytes = Bitcoin.xpub_verbytes + bytes([255] * 74)
        xkey_b58 = base58_encode_check(xkey_bytes)
        self.assertTrue(xkey_b58.startswith(xpub_headers_b58))


class Test_xprv_xpub_testnet(TestCaseForTestnet):

    def test_version_bytes(self):
        xprv_headers_b58 = 'tprv'
        xpub_headers_b58 = 'tpub'

        xkey_bytes = BitcoinTestnet.xprv_verbytes + bytes([0] * 74)
        xkey_b58 = base58_encode_check(xkey_bytes)
        self.assertTrue(xkey_b58.startswith(xprv_headers_b58))

        xkey_bytes = BitcoinTestnet.xprv_verbytes + bytes([255] * 74)
        xkey_b58 = base58_encode_check(xkey_bytes)
        self.assertTrue(xkey_b58.startswith(xprv_headers_b58))

        xkey_bytes = BitcoinTestnet.xpub_verbytes + bytes([0] * 74)
        xkey_b58 = base58_encode_check(xkey_bytes)
        self.assertTrue(xkey_b58.startswith(xpub_headers_b58))

        xkey_bytes = BitcoinTestnet.xpub_verbytes + bytes([255] * 74)
        xkey_b58 = base58_encode_check(xkey_bytes)
        self.assertTrue(xkey_b58.startswith(xpub_headers_b58))


class Test_keyImport(SequentialTestCase):

    priv_pub_addr = (
           {'priv': 'KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6',
            'exported_privkey': 'KzMFjMC2MPadjvX5Cd7b8AKKjjpBSoRKUTpoAtN6B3J9ezWYyXS6',
            'pub': '02c6467b7e621144105ed3e4835b0b4ab7e35266a2ae1c4f8baa19e9ca93452997',
            'address': '17azqT8T16coRmWKYFj3UjzJuxiYrYFRBR',
            'minikey' : False,
            'txin_type': 'p2pkh',
            'compressed': True,
            'addr_encoding': 'base58',
            'scripthash': 'c9aecd1fef8d661a42c560bf75c8163e337099800b8face5ca3d1393a30508a7'},
           {'priv': 'Kzj8VjwpZ99bQqVeUiRXrKuX9mLr1o6sWxFMCBJn1umC38BMiQTD',
            'exported_privkey': 'Kzj8VjwpZ99bQqVeUiRXrKuX9mLr1o6sWxFMCBJn1umC38BMiQTD',
            'pub': '0352d78b4b37e0f6d4e164423436f2925fa57817467178eca550a88f2821973c41',
            'address': '1GXgZ5Qi6gmXTHVSpUPZLy4Ci2nbfb3ZNb',
            'minikey': False,
            'txin_type': 'p2pkh',
            'compressed': True,
            'addr_encoding': 'base58',
            'scripthash': 'a9b2a76fc196c553b352186dfcca81fcf323a721cd8431328f8e9d54216818c1'},
           {'priv': '5Hxn5C4SQuiV6e62A1MtZmbSeQyrLFhu5uYks62pU5VBUygK2KD',
            'exported_privkey': '5Hxn5C4SQuiV6e62A1MtZmbSeQyrLFhu5uYks62pU5VBUygK2KD',
            'pub': '04e5fe91a20fac945845a5518450d23405ff3e3e1ce39827b47ee6d5db020a9075422d56a59195ada0035e4a52a238849f68e7a325ba5b2247013e0481c5c7cb3f',
            'address': '1GPHVTY8UD9my6jyP4tb2TYJwUbDetyNC6',
            'minikey': False,
            'txin_type': 'p2pkh',
            'compressed': False,
            'addr_encoding': 'base58',
            'scripthash': 'f5914651408417e1166f725a5829ff9576d0dbf05237055bf13abd2af7f79473'},
           {'priv': '5KhYQCe1xd5g2tqpmmGpUWDpDuTbA8vnpbiCNDwMPAx29WNQYfN',
            'exported_privkey': '5KhYQCe1xd5g2tqpmmGpUWDpDuTbA8vnpbiCNDwMPAx29WNQYfN',
            'pub': '048f0431b0776e8210376c81280011c2b68be43194cb00bd47b7e9aa66284b713ce09556cde3fee606051a07613f3c159ef3953b8927c96ae3dae94a6ba4182e0e',
            'address': '147kiRHHm9fqeMQSgqf4k35XzuWLP9fmmS',
            'minikey': False,
            'txin_type': 'p2pkh',
            'compressed': False,
            'addr_encoding': 'base58',
            'scripthash': '6dd2e07ad2de9ba8eec4bbe8467eb53f8845acff0d9e6f5627391acc22ff62df'},
           # from http://bitscan.com/articles/security/spotlight-on-mini-private-keys
           {'priv': 'SzavMBLoXU6kDrqtUVmffv',
            'exported_privkey': '5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF',
            'pub': '04588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9f88ff2a00d7e752d44cbe16e1ebcf0890b76ec7c78886109dee76ccfc8445424',
            'address': '1CC3X2gu58d6wXUWMffpuzN9JAfTUWu4Kj',
            'minikey': True,
            'txin_type': 'p2pkh',
            'compressed': False,  # this is actually ambiguous... issue #2748
            'addr_encoding': 'base58',
            'scripthash': '5b07ddfde826f5125ee823900749103cea37808038ecead5505a766a07c34445'},
    )

    def test_public_key_from_private_key(self):
        for priv_details in self.priv_pub_addr:
            privkey = PrivateKey.from_text(priv_details['priv'])
            result = privkey.public_key.to_hex()
            self.assertEqual(priv_details['pub'], result)
            self.assertEqual(priv_details['txin_type'], 'p2pkh')
            self.assertEqual(priv_details['compressed'], privkey.is_compressed())

    def test_is_valid_address(self):
        for priv_details in self.priv_pub_addr:
            addr = priv_details['address']
            print(addr)
            self.assertFalse(is_address_valid(priv_details['priv']))
            self.assertFalse(is_address_valid(priv_details['pub']))
            self.assertTrue(is_address_valid(addr))

        self.assertFalse(is_address_valid("not an address"))

    def test_address_to_scripthash(self):
        for priv_details in self.priv_pub_addr:
            sh = scripthash_hex(address_from_string(priv_details['address']).to_script())
            self.assertEqual(priv_details['scripthash'], sh)

    def test_is_minikey(self):
        for priv_details in self.priv_pub_addr:
            minikey = priv_details['minikey']
            priv = priv_details['priv']
            self.assertEqual(minikey, is_minikey(priv))



class Test_seeds(SequentialTestCase):
    """ Test old and new seeds. """

    mnemonics = {
        ('cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze', 'old'),
        ('cell dumb heartbeat north boom tease ' * 4, 'old'),
        ('cell dumb heartbeat north boom tease ship baby bright kingdom rare badword', ''),
        ('cElL DuMb hEaRtBeAt nOrTh bOoM TeAsE ShIp bAbY BrIgHt kInGdOm rArE SqUeEzE', 'old'),
        ('   cElL  DuMb hEaRtBeAt nOrTh bOoM  TeAsE ShIp    bAbY BrIgHt kInGdOm rArE SqUeEzE   ', 'old'),
        # below seed is actually 'invalid old' as it maps to 33 hex chars
        ('hurry idiot prefer sunset mention mist jaw inhale impossible kingdom rare squeeze', ''), # Was old
        ('cram swing cover prefer miss modify ritual silly deliver chunk behind inform able', 'standard'),
        ('cram swing cover prefer miss modify ritual silly deliver chunk behind inform', ''),
        ('ostrich security deer aunt climb inner alpha arm mutual marble solid task', 'standard'),
        ('OSTRICH SECURITY DEER AUNT CLIMB INNER ALPHA ARM MUTUAL MARBLE SOLID TASK', 'standard'),
        ('   oStRiCh sEcUrItY DeEr aUnT ClImB       InNeR AlPhA ArM MuTuAl mArBlE   SoLiD TaSk  ', 'standard'),
        ('x8', 'standard'),
        ('science dawn member doll dutch real ca brick knife deny drive list', ''),
    }

    def test_new_seed(self):
        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform able"
        self.assertTrue(ElectrumMnemonic.is_valid_new(seed, SEED_PREFIX))

        seed = "cram swing cover prefer miss modify ritual silly deliver chunk behind inform"
        self.assertFalse(ElectrumMnemonic.is_valid_new(seed, SEED_PREFIX))

    def test_old_seed(self):
        self.assertTrue(ElectrumMnemonic.is_valid_old(" ".join(["like"] * 12)))
        self.assertFalse(ElectrumMnemonic.is_valid_old(" ".join(["like"] * 18)))
        self.assertTrue(ElectrumMnemonic.is_valid_old(" ".join(["like"] * 24)))
        self.assertFalse(ElectrumMnemonic.is_valid_old("not a seed"))

        self.assertTrue(ElectrumMnemonic.is_valid_old("0123456789ABCDEF" * 2))
        self.assertTrue(ElectrumMnemonic.is_valid_old("0123456789ABCDEF" * 4))
