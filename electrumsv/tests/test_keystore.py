import pytest

from electrumsv.exceptions import InvalidPassword
from electrumsv.keystore import (
    Imported_KeyStore, Old_KeyStore, BIP32_KeyStore, from_bip39_seed, bip32_root
)
from electrumsv.crypto import pw_encode


class TestOld_KeyStore:

    @pytest.mark.parametrize("seed,mpk", (
        (b'BitcoinSV', '85c9c0adba51e6f9eaf3d8314a036a0e6292ef2ff23c55854aa9354b4b2b113f'
         'faf92a7ba053e5b6a6c2a8c60e8579264ee8fc2b69624721a5736e01f9f64b55'),
        (b'seed', '05c9d09c9d0cbfef6b0e5e986228d600b42999b9eecc7e91204b45815bcc911b0a9be'
         '06eaed983fbceb3a640464c3ad8f6b80a5e0dffceab4ec3328c1801e0bb'),
    ))
    def test_mpk_from_seed(self, seed, mpk):
        assert Old_KeyStore.mpk_from_seed(seed) == mpk

    @pytest.mark.parametrize("args,pubkey", (
        (('105a142ad6090e5a1cc29895f0a30289556cfe68731972bd70138f4f01865351c9a17269147fe'
          '551b5ad899f46f7f245d495bc1394409c49b364bbc31d01e849', False, 2),
         '04fdc2cfde886681e7f450b94b0e662761037dfed495909ab7b5a5c0de5a15428b4b7ec0142b'
         '180f7e24a699138a547cfa9156237d57825f04de56afcf1eb5ea7a'),
        (('a489d6967f19a32c4769c92a3e8a874f68fb1c8a9e03b638dc7eee54a4ce768b3f1a7d6338f6a'
          '307685c779e6afe929a7d6f9cec8b4d3acc29e1483bd0f05972', True, 5),
         '04d061d4f250c6722975e5084412cc88eb71dd5ddb96154ab3b652efe3f7f49249d3144ba'
         '816044d5b844f97c7660c49f1e7db1055b7f8b16d52df0fd2ef2ad0ba'),
    ))
    def test_get_pubkey_from_mpk(self, args, pubkey):
        assert Old_KeyStore.get_pubkey_from_mpk(*args) == pubkey

    def test_check_seed(self):
        seed = b'Satoshi'
        mpk = Old_KeyStore.mpk_from_seed(seed)
        keystore = Old_KeyStore({'mpk': mpk})
        keystore.check_seed(seed)
        with pytest.raises(InvalidPassword):
            keystore.check_seed(b'foo')

    def test_get_private_key_from_stretched_exponent(self):
        seed = b'Satoshi'
        mpk = Old_KeyStore.mpk_from_seed(seed)
        keystore = Old_KeyStore({'mpk': mpk})
        privkey = keystore.get_private_key_from_stretched_exponent(False, 10, 1234567)
        assert privkey.hex() == 'ad4109aa9abba7402c3077692bc877a297c0a30fd6bba822796e945f04631f44'


class TestImported_KeyStore:

    @pytest.mark.parametrize("WIF,pk_string", (
        ("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
         "04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd"
         "85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a"),
        ("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617",
         "02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c"),
        ("SZEfg4eYxCJoqzumUqP34g",
         "04e7dd15b4271f8308ff52ad3d3e472b652e78a2c5bc6ed10250a543d28c0128894ae86"
         "3d086488e6773c4589be93a1793f685dd3f1e8a1f1b390b23470f7d1095"
        ),
        ("S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy",
         "04fb4fd5872ff2f8a46c2d496383fccc503c0260ef126ffbac61407f6bd384e5d"
         "bae242ba554c607a273b4a2e0b7a298fb2505affa7cdf00222cab8a1cfd7ebbd7"
        ),
    ))
    def test_import_privkey(self, WIF, pk_string):
        d = Imported_KeyStore({})
        pubkey = d.import_privkey(WIF, b'')
        assert pubkey.to_string() == pk_string

    @pytest.mark.parametrize("WIF", (
        "5HueCGU8rMjxEXxiPuD5BDku4MkqeZyd4dZ1jvhTVqvbTLvyTJ",
        "cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx",
        "NUTBssxAs7z",
    ))
    def test_import_privkey_bad(self, WIF):
        d = Imported_KeyStore({})
        with pytest.raises(Exception):
            d.import_privkey(WIF, b'')

    def test_sign_message(self):
        password = b'password'
        message = 'BitcoinSV'
        d = Imported_KeyStore({})
        pubkey = d.import_privkey("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", password)
        msg_sig = d.sign_message(pubkey, message, password)
        assert msg_sig.hex() == (
            '1c26a18cb236e54bbe7e3db56639ef5cbefcf5a2e28850cdd304970832f84031'
            'fc073bed1a151f0510e5558a22d23f16ed8032a1b74ffcac05227c053e1a1d8af5'
        )

    def test_decrypt_message(self):
        password = b'password'
        enc_msg = ('QklFMQNkonLnVmRMF3dl+P0rHSbM4lvDPmnE2CFcD+98gGsOe6qtKtmVbCg4'
                   '9bxmT6vfmzl7udrvT81wH1Ri7wZItndtLiNHii6FBNVzoSV/1ZqN3w==')
        d = Imported_KeyStore({})
        pubkey = d.import_privkey("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", password)
        dec_msg = d.decrypt_message(pubkey, enc_msg, password)
        assert dec_msg == b'BitcoinSV'


class TestBIP32_KeyStore:

    def test_get_private_key(self):
        xprv = ('xprv9s21ZrQH143K4XLpSd2berkCzJTXDv68rusDQFiQGSqa1ZmVXnYzYpTQ9'
                'qYiSB7mHvg6kEsrd2ZtnHRJ61sZhSN4jZ2T8wxA4T75BE4QQZ1')
        password = b'password'
        xprv = pw_encode(xprv, password)
        keystore = BIP32_KeyStore({'xprv': xprv})
        privkey = keystore.get_private_key((1, 2, 3), password)
        assert privkey == (bytes.fromhex('985e4b09a0b05702c073b5086fcbb4b7dde4625bb98'
                                         '9ec51ce4c3337a7de2a13'), True)


    @pytest.mark.parametrize("password", (b'Password', None))
    def test_check_password(self, password):
        xprv = ('xprv9s21ZrQH143K4XLpSd2berkCzJTXDv68rusDQFiQGSqa1ZmVXnYzYpTQ9'
                'qYiSB7mHvg6kEsrd2ZtnHRJ61sZhSN4jZ2T8wxA4T75BE4QQZ1')
        xpub = ('xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8w'
                'GvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA')
        xprv = pw_encode(xprv, password)
        keystore = BIP32_KeyStore({'xprv': xprv, 'xpub': xpub})

        keystore.check_password(password)
        with pytest.raises(InvalidPassword):
            keystore.check_password(b'guess')
        if password is not None:
            with pytest.raises(InvalidPassword):
                keystore.check_password(None)


class TestXPub:

    @pytest.mark.parametrize("for_change,n,pubkey", (
        (False, 3, '03b90f6af678c35926a72e27908f1ddcf33e370f1444fbf1e4a85a028ac352a477'),
        (True, 5, '033177256871768b5ee8e031647f3727e63d1b62c8d776d9b422a367fd8e721bd3'),
    ))
    def test_derive_pubkey(self, for_change, n, pubkey):
        xpub = ('xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8w'
                'GvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA')
        keystore = BIP32_KeyStore({'xpub': xpub})
        assert keystore.derive_pubkey(for_change, n) == pubkey


def test_from_bip39_seed():
    keystore = from_bip39_seed('foo bar baz', '', "m/44'/0'/0'")
    assert keystore.xprv == ('xprv9xpBW4EdWnv4PEASBsu3VuPNAcxRiSMXTjAfZ9dkP5FCrKWCacKZBhS3cJVGCe'
                             'gAUNEp1uXXEncSAyro5CaJFwv7wYFcBQrF6MfWYoAXsTw')
    assert keystore.xpub == ('xpub6BoXuZmXMAUMbiEuHuS3s3L6ienv7u5Npx6GMY3MwQnBj7qM89dojV'
                             'kXTZtbpEvAzxSKAxnnsVDuwSAAvvXHWVncpX46V3LGj5SaKHtNNnc')


def test_bip32_root():
    assert bip32_root(b'BitcoinSV') == ('xprv9s21ZrQH143K48ebsYkLU9UPzgdDVfhT6SMdWFJ8ZXak1bjKVRLu'
                                        'xdmMCh7HZkwciZd7fga4gK4XW2QZhvWz5os6hJwqLfpZmW9r7pLgn9s')
