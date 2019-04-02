from io import StringIO
import json
import os
import shutil
import sys
import tempfile
import unittest

import pytest

from electrumsv.address import Address, PublicKey
from electrumsv.storage import WalletStorage, FINAL_SEED_VERSION
from electrumsv.wallet import sweep_preparations


class FakeSynchronizer(object):

    def __init__(self):
        self.store = []

    def add(self, address):
        self.store.append(address)


class WalletTestCase(unittest.TestCase):

    def setUp(self):
        super(WalletTestCase, self).setUp()
        self.user_dir = tempfile.mkdtemp()

        self.wallet_path = os.path.join(self.user_dir, "somewallet")

        self._saved_stdout = sys.stdout
        self._stdout_buffer = StringIO()
        sys.stdout = self._stdout_buffer

    def tearDown(self):
        super(WalletTestCase, self).tearDown()
        shutil.rmtree(self.user_dir)
        # Restore the "real" stdout
        sys.stdout = self._saved_stdout


class TestWalletStorage(WalletTestCase):

    def test_read_dictionary_from_file(self):

        some_dict = {"a":"b", "c":"d"}
        contents = json.dumps(some_dict)
        with open(self.wallet_path, "w") as f:
            contents = f.write(contents)

        storage = WalletStorage(self.wallet_path, manual_upgrades=True)
        self.assertEqual("b", storage.get("a"))
        self.assertEqual("d", storage.get("c"))

    def test_write_dictionary_to_file(self):

        storage = WalletStorage(self.wallet_path)

        some_dict = {
            u"a": u"b",
            u"c": u"d",
            u"seed_version": FINAL_SEED_VERSION}

        for key, value in some_dict.items():
            storage.put(key, value)
        storage.write()

        contents = ""
        with open(self.wallet_path, "r") as f:
            contents = f.read()
        self.assertEqual(some_dict, json.loads(contents))


sweep_utxos = {
    # SZEfg4eYxCJoqzumUqP34g uncompressed, address 1KXf5PUHNaV42jE9NbJFPKhGGN1fSSGJNK
    "6dd52f21a1376a67370452d1edfc811bc9d3f344bc7d973616ee27cebfd1940b": [
        {
            "height": 437146,
            "value": 45318048,
            "tx_hash": "9f2c45a12db0144909b5db269415f7319179105982ac70ed80d76ea79d923ebf",
            "tx_pos": 0,
        },
    ],
    # SZEfg4eYxCJoqzumUqP34g compressed, address 14vEZP9zQZGxaKqhRSMVgdPwyjPeDbcRS6
    "c369b25fc68c0697fb20b5790382a7f5946e85b1881b999949c41266bc736647": [
    ],
    # KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 (compressed)
    "e4f6742ca0c2dceef3d055333c7d318aa6d56b4016e5bfaf12a683bc0eee07a3": [
        {
            "height": 500000,
            "value": 18043706,
            "tx_hash": "bcf7ae875b585e00a61055372c1e99046b20f5fbfcd8659959afb6f428326bfa",
            "tx_pos": 1,
        },
    ],
    # KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 (P2PK)
    "b7c7a07e2d02c5686729179b0ec426d813326b54b42efe35214f0e320c81bc0d": [
    ],
    # 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ (uncompressed)
    "2df53273de1b740e6f566eba00d90366e53afd2c6af896a9488515f8ef5abbd8": [
    ],
    # 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ (P2PK)
    "7149d82068249701104cd662bfe8ebc0af131ce6e781b124cc6297f45f7f6de5": [
        {
            "height": 50000,
            "value": 1804376,
            "tx_hash": "3f5a1badfe1beb42b650f325b20935f09f3ab43a3c473c5be18f58308fc7eff1",
            "tx_pos": 3,
        },
    ],
}

result_S = ([{'height': 437146, 'value': 45318048, 'tx_hash': '9f2c45a12db0144909b5db269415f7319179105982ac70ed80d76ea79d923ebf', 'tx_pos': 0, 'address': Address.from_string("1KXf5PUHNaV42jE9NbJFPKhGGN1fSSGJNK"), 'type': 'p2pkh', 'prevout_hash': '9f2c45a12db0144909b5db269415f7319179105982ac70ed80d76ea79d923ebf', 'prevout_n': 0, 'pubkeys': ['04e7dd15b4271f8308ff52ad3d3e472b652e78a2c5bc6ed10250a543d28c0128894ae863d086488e6773c4589be93a1793f685dd3f1e8a1f1b390b23470f7d1095'], 'x_pubkeys': ['04e7dd15b4271f8308ff52ad3d3e472b652e78a2c5bc6ed10250a543d28c0128894ae863d086488e6773c4589be93a1793f685dd3f1e8a1f1b390b23470f7d1095'], 'signatures': [None], 'num_sig': 1}], {'04e7dd15b4271f8308ff52ad3d3e472b652e78a2c5bc6ed10250a543d28c0128894ae863d086488e6773c4589be93a1793f685dd3f1e8a1f1b390b23470f7d1095': (b'\x98\xe3\x15\xc3%j\x97\x17\xd4\xdd\xea0\xeb*\n-V\xa1d\x93yN\xb0SSf\xea"\xd8i\xa3 ', False), '03e7dd15b4271f8308ff52ad3d3e472b652e78a2c5bc6ed10250a543d28c012889': (b'\x98\xe3\x15\xc3%j\x97\x17\xd4\xdd\xea0\xeb*\n-V\xa1d\x93yN\xb0SSf\xea"\xd8i\xa3 ', True)})
result_K = ([{'height': 500000, 'value': 18043706, 'tx_hash': 'bcf7ae875b585e00a61055372c1e99046b20f5fbfcd8659959afb6f428326bfa', 'tx_pos': 1, 'address': Address.from_string("1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK"), 'type': 'p2pkh', 'prevout_hash': 'bcf7ae875b585e00a61055372c1e99046b20f5fbfcd8659959afb6f428326bfa', 'prevout_n': 1, 'pubkeys': ['02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c'], 'x_pubkeys': ['02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c'], 'signatures': [None], 'num_sig': 1}], {'02d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645c': (b"\x0c(\xfc\xa3\x86\xc7\xa2'`\x0b/\xe5\x0b|\xae\x11\xec\x86\xd3\xbf\x1f\xbeG\x1b\xe8\x98'\xe1\x9dr\xaa\x1d", True)})
result_5 = ([{'height': 50000, 'value': 1804376, 'tx_hash': '3f5a1badfe1beb42b650f325b20935f09f3ab43a3c473c5be18f58308fc7eff1', 'tx_pos': 3, 'address': PublicKey.from_pubkey("04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a"), 'type': 'p2pk', 'prevout_hash': '3f5a1badfe1beb42b650f325b20935f09f3ab43a3c473c5be18f58308fc7eff1', 'prevout_n': 3, 'pubkeys': ['04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a'], 'x_pubkeys': ['04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a'], 'signatures': [None], 'num_sig': 1}], {'04d0de0aaeaefad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e858e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a': (b"\x0c(\xfc\xa3\x86\xc7\xa2'`\x0b/\xe5\x0b|\xae\x11\xec\x86\xd3\xbf\x1f\xbeG\x1b\xe8\x98'\xe1\x9dr\xaa\x1d", False)})

@pytest.mark.parametrize("privkey,answer", (
    ("SZEfg4eYxCJoqzumUqP34g", result_S),
    ("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", result_K),
    ("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", result_5),
))
def test_sweep_preparations(privkey,answer):
    def get_utxos(script_hash):
        return sweep_utxos[script_hash]

    result = sweep_preparations([privkey], get_utxos)
    assert result == answer
