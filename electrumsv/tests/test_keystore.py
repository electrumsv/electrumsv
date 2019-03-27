import pytest

from electrumsv.exceptions import InvalidPassword
from electrumsv.keystore import (
    Imported_KeyStore, Old_KeyStore, BIP32_KeyStore, from_bip39_seed, bip32_root,
    from_master_key, from_seed
)
from electrumsv.crypto import pw_encode
from electrumsv.networks import Net, SVMainnet, SVTestnet


class TestOld_KeyStore:

    # Seed can be given in hex and as an old-style mnemonic
    @pytest.mark.parametrize("seed_text", (
        'powerful random nobody notice nothing important anyway look away hidden message over',
        'acb740e454c3134901d7c8f16497cc1c',
    ))
    def test_from_seed(self, seed_text):
        hex_seed = 'acb740e454c3134901d7c8f16497cc1c'
        keystore = from_seed(seed_text, None, False)
        assert isinstance(keystore, Old_KeyStore)
        assert keystore.seed == hex_seed
        assert keystore.mpk == ('e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9'
                                'c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3')

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

    def test_get_seed(self):
        seed = 'ee6ea9eceaf649640051a4c305ac5c59'
        keystore = Old_KeyStore.from_seed(seed)
        password = 'password'
        keystore.update_password(None, password)
        assert keystore.get_seed(password) == ('duck pattern possibly awaken utter roam sail '
                                               'couple curve travel treat lord')
        keystore.update_password(password, '')
        assert keystore.get_seed(None) == ('duck pattern possibly awaken utter roam sail '
                                           'couple curve travel treat lord')

    def test_get_private_key(self):
        seed = 'ee6ea9eceaf649640051a4c305ac5c59'
        keystore = Old_KeyStore.from_seed(seed)
        result = keystore.get_private_key((False, 10), None)
        assert result == (bytes.fromhex(
            '81279e4fe405363eb56e686726d450fe4a76a1d83b64311d7618b845683aab4a'), False)

    def test_check_seed(self):
        seed = 'ee6ea9eceaf649640051a4c305ac5c59'
        keystore = Old_KeyStore.from_seed(seed)
        keystore.check_seed(seed.encode())
        with pytest.raises(InvalidPassword):
            keystore.check_seed(b'foo')

    def test_hex_master_public_key(self):
        # An uncompressed public key in hex form without the 04 prefix
        mpk_hex = ("08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a688"
                   "63b37df75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d0")
        keystore = from_master_key(mpk_hex)
        assert isinstance(keystore, Old_KeyStore)
        assert keystore.get_master_public_key() == mpk_hex
        assert keystore.dump() == {'mpk': mpk_hex, 'type': 'old'}
        assert keystore.is_watching_only()
        assert keystore.get_xpubkey(False, 4) == (
            'fe08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a68'
            '863b37df75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d000000400'
        )
        assert keystore.get_xpubkey(True, 259) == (
            'fe08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a68863b37d'
            'f75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d001000301'
        )

    def test_get_pubkey_derivation(self):
        mpk_hex = ("08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a688"
                   "63b37df75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d0")
        keystore = from_master_key(mpk_hex)
        assert keystore.get_pubkey_derivation(
            'fe08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a68'
            '863b37df75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d000000400'
        ) == [0, 4]
        assert keystore.get_pubkey_derivation(
            'fe08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a68863b37d'
            'f75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d001000301'
        ) == [1, 259]
        assert keystore.get_pubkey_derivation(
            'fe18863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a68863b37d'
            'f75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d001000301'
        ) is None
        assert keystore.get_pubkey_derivation("ff") is None


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
        password = 'password'
        message = 'BitcoinSV'
        d = Imported_KeyStore({})
        pubkey = d.import_privkey("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", password)
        msg_sig = d.sign_message(pubkey, message, password)
        assert msg_sig.hex() == (
            '1c26a18cb236e54bbe7e3db56639ef5cbefcf5a2e28850cdd304970832f84031'
            'fc073bed1a151f0510e5558a22d23f16ed8032a1b74ffcac05227c053e1a1d8af5'
        )

    def test_decrypt_message(self):
        password = 'password'
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
        password = 'password'
        xprv = pw_encode(xprv, password)
        keystore = BIP32_KeyStore({'xprv': xprv})
        privkey = keystore.get_private_key((1, 2, 3), password)
        assert privkey == (bytes.fromhex('985e4b09a0b05702c073b5086fcbb4b7dde4625bb98'
                                         '9ec51ce4c3337a7de2a13'), True)


    @pytest.mark.parametrize("password", ('Password', None))
    def test_check_password(self, password):
        xprv = ('xprv9s21ZrQH143K4XLpSd2berkCzJTXDv68rusDQFiQGSqa1ZmVXnYzYpTQ9'
                'qYiSB7mHvg6kEsrd2ZtnHRJ61sZhSN4jZ2T8wxA4T75BE4QQZ1')
        xpub = ('xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8w'
                'GvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA')
        xprv = pw_encode(xprv, password)
        keystore = BIP32_KeyStore({'xprv': xprv, 'xpub': xpub})

        keystore.check_password(password)
        with pytest.raises(InvalidPassword):
            keystore.check_password('guess')
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
    Net.set_to(SVMainnet)
    assert bip32_root(b'BitcoinSV') == ('xprv9s21ZrQH143K48ebsYkLU9UPzgdDVfhT6SMdWFJ8ZXak1bjKVRLu'
                                        'xdmMCh7HZkwciZd7fga4gK4XW2QZhvWz5os6hJwqLfpZmW9r7pLgn9s')
    Net.set_to(SVTestnet)
    assert bip32_root(b'BitcoinSV') == ('tprv8ZgxMBicQKsPewt8Y7bqdo6PJp3RjBjTRzGkNfib3W5DoCUQUng'
                                        'fUP8o7sGwa8Kw619tfnBpqfeKxsxJq8rvts8hDxA912YcgbuGZX3AZDd')
    Net.set_to(SVMainnet)


def test_from_master_key():
    keystore = from_master_key('xprv9xpBW4EdWnv4PEASBsu3VuPNAcxRiSMXTjAfZ9dkP5FCrKWCacKZBhS3cJVGCe'
                               'gAUNEp1uXXEncSAyro5CaJFwv7wYFcBQrF6MfWYoAXsTw')
    assert keystore.xprv == ('xprv9xpBW4EdWnv4PEASBsu3VuPNAcxRiSMXTjAfZ9dkP5FCrKWCacKZBhS3cJVGCe'
                             'gAUNEp1uXXEncSAyro5CaJFwv7wYFcBQrF6MfWYoAXsTw')
    assert keystore.xpub == ('xpub6BoXuZmXMAUMbiEuHuS3s3L6ienv7u5Npx6GMY3MwQnBj7qM89dojV'
                             'kXTZtbpEvAzxSKAxnnsVDuwSAAvvXHWVncpX46V3LGj5SaKHtNNnc')
