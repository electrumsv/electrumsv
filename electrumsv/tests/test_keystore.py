import pytest

from electrumsv.keystore import Imported_KeyStore


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
