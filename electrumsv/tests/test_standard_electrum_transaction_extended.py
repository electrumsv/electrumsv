import json
from typing import cast

from bitcoinx import bip32_key_from_string, BIP32PublicKey, P2PKH_Address, PrivateKey, PublicKey, \
    Tx
import pytest

from electrumsv.bitcoin import address_from_string
from electrumsv.constants import DerivationPath, KeystoreTextType
from electrumsv.keystore import BIP32_KeyStore, instantiate_keystore_from_text, \
    Old_KeyStore, SinglesigKeyStoreTypes
from electrumsv.standards.electrum_transaction_extended import transaction_from_electrum_bytes, \
    transaction_from_electrumsv_dict, transaction_to_electrumsv_dict, \
    x_public_key_from_electrum_bytes
from electrumsv.transaction import XPublicKey, Transaction, TransactionContext

# pylint: disable=line-too-long


unsigned_blob = '010000000149f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed010000005701ff4c53ff0488b21e0000000000000000004f130d773e678a58366711837ec2e33ea601858262f8eaef246a7ebd19909c9a03c3b30e38ca7d797fee1223df1c9827b2a9f3379768f520910260220e0560014600002300feffffffd8e43201000000000118e43201000000001976a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac5fbd0700'
signed_blob = '010000000149f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed010000006a473044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f46885412103b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166feffffff0118e43201000000001976a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac5fbd0700'
# Both priv keys signed
signed_tx_3 = "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000006b4830450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d412102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000006b483045022100fa8ebdc7cefc407fd1b560fb2e2e5e96e900e94634d96df4fd284126048746a2022028d91ca132a1a386a67df69a2c5ba216218870c256c163d729f1575f7a8824f54121030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff01de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800"
# 2 inputs, one for each priv_key below
unsigned_tx = "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000002401ff2102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff146000000000000f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000002401ff21030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff415901000000000001de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800"

def _sign_electrum_extended_transaction(unsigned_tx_hex: str, priv_keys: list[PrivateKey]) \
        -> Transaction:
    keypairs = {XPublicKey.from_hex(priv_key.public_key.to_hex()):
                priv_key for priv_key in priv_keys}
    tx = transaction_from_electrum_bytes(bytes.fromhex(unsigned_tx_hex))
    tx.sign(keypairs)
    return tx

def _multisig_keystores() -> list[SinglesigKeyStoreTypes]:
    seed = 'ee6ea9eceaf649640051a4c305ac5c59'
    keystore1 = cast(Old_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_OLD_SEED_WORDS, seed, password="OLD"))

    xprv = ('xprv9s21ZrQH143K4XLpSd2berkCzJTXDv68rusDQFiQGSqa1ZmVXnYzYpTQ9'
            'qYiSB7mHvg6kEsrd2ZtnHRJ61sZhSN4jZ2T8wxA4T75BE4QQZ1')
    xpub = ('xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8w'
            'GvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA')
    keystore2 = cast(BIP32_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.EXTENDED_PRIVATE_KEY, xprv, password="BIP32"))
    assert keystore2.xpub == xpub

    return [keystore1, keystore2]



def test_electrum_extended_transaction_unsigned() -> None:
    tx = transaction_from_electrum_bytes(bytes.fromhex(unsigned_blob))
    assert tx.version == 1
    assert len(tx.inputs) == 1
    txin = tx.inputs[0]
    assert txin.prev_hash.hex() == '49f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed'
    assert txin.prev_idx == 1
    assert txin.script_sig.to_hex() == ''
    assert txin.script_length == 87
    assert txin.script_offset == 42
    assert txin.sequence == 4294967294
    assert txin.value == 20112600
    assert txin.signatures == {}
    assert txin.x_pubkeys == {
        # This has been implicitly converted to the compressed public key.
        bytes.fromhex("03b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166"):
        x_public_key_from_electrum_bytes(bytes.fromhex('ff0488b21e0000000000000000004f130d773e678a58366711837ec2e33ea601858262f8eaef246a7ebd19909c9a03c3b30e38ca7d797fee1223df1c9827b2a9f3379768f520910260220e0560014600002300'))
    }
    assert txin.threshold == 1
    txout = tx.outputs[0]
    assert txout.value == 20112408 and txout.script_pubkey == cast(P2PKH_Address, address_from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK')).to_script()
    assert txout.script_length == 25
    assert txout.script_offset == 151
    assert tx.locktime == 507231

    assert json.dumps(transaction_to_electrumsv_dict(tx, TransactionContext(), [])) == '{"version": 2, "hex": "010000000149f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed010000002401ff2103b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166feffffff0118e43201000000001976a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac5fbd0700", "complete": false, "inputs": [{"script_type": 2, "threshold": 1, "value": 20112600, "signatures": ["ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcFL6WFqND2XM2w1EfpBwFfhsSUcw9xDR3nH8eYLv4z4HAhxv5zkqjHojWsPYK1ZSK7yCr8fZ9iWU6D361G2ryv5UgsKjbeDq", "derivation_path": [0, 35]}]}]}'

def test_electrum_extended_transaction_signed() -> None:
    # This is testing the extended parsing for a signed transaction.
    tx_bytes = bytes.fromhex(signed_blob)
    tx = transaction_from_electrum_bytes(tx_bytes)
    assert tx.version == 1
    assert len(tx.inputs) == 1
    txin = tx.inputs[0]
    assert txin.prev_hash.hex() == '49f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed'
    assert txin.prev_idx == 1
    assert txin.script_sig.to_hex() == '473044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f46885412103b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166'
    assert txin.script_length == 106
    assert txin.script_offset == 42
    assert txin.sequence == 4294967294
    public_key_bytes = bytes.fromhex('03b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166')
    assert txin.x_pubkeys == { public_key_bytes: XPublicKey.from_hex('03b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166') }
    assert txin.signatures == { public_key_bytes: bytes.fromhex('3044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f4688541') }
    assert txin.threshold == 1
    txout = tx.outputs[0]
    assert txout.value == 20112408 and txout.script_pubkey == cast(P2PKH_Address, address_from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK')).to_script()
    assert txout.script_length == 25
    assert txout.script_offset == 162
    assert tx.locktime == 507231
    assert transaction_to_electrumsv_dict(tx, TransactionContext(), []) == {'hex': signed_blob, 'complete': True, 'version': 2}
    assert tx.to_hex() == signed_blob
    assert sum(tx.estimated_size()) == len(tx_bytes)

def test_electrum_extended_transaction_update_signatures() -> None:
    signed_tx = Tx.from_hex(signed_tx_3)
    sigs = [next(input.script_sig.ops())[:-1] for input in signed_tx.inputs]

    tx = transaction_from_electrum_bytes(bytes.fromhex(unsigned_tx))
    tx.update_signatures(sigs)
    assert tx.is_complete()
    assert tx.txid() == "b83acf939a92c420d0cb8d45d5d4dfad4e90369ebce0f49a45808dc1b41259b0"


priv_keys = [PrivateKey.from_WIF(WIF) for WIF in (
    "KzjWgFAozj8EfMFpeCBshWA69QXG7Kj7nMYHjSkkcTM8DM8GF1Hd",
    "KyY5VaoqPwjSgGpKHT3JJKDcxXMeqYo6umK7u1h3iBt9n9aihiPs",
)]

def test_sign_electrum_extended_transaction_first_input_only() -> None:
    tx = _sign_electrum_extended_transaction(unsigned_tx, [priv_keys[0]])
    assert json.dumps(transaction_to_electrumsv_dict(tx, TransactionContext(), [])) == '{"version": 2, "hex": "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000002401ff2102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000006b483045022100fa8ebdc7cefc407fd1b560fb2e2e5e96e900e94634d96df4fd284126048746a2022028d91ca132a1a386a67df69a2c5ba216218870c256c163d729f1575f7a8824f54121030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff01de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800", "complete": false, "inputs": [{"script_type": 2, "threshold": 1, "value": 18161, "signatures": ["ff"], "x_pubkeys": [{"pubkey_bytes": "02faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85"}]}, {"script_type": 2, "threshold": 1, "value": 88385, "signatures": ["3045022100fa8ebdc7cefc407fd1b560fb2e2e5e96e900e94634d96df4fd284126048746a2022028d91ca132a1a386a67df69a2c5ba216218870c256c163d729f1575f7a8824f541"], "x_pubkeys": [{"pubkey_bytes": "030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477ea"}]}]}'
    assert not tx.is_complete()

def test_sign_electrum_extended_transaction_second_input_only() -> None:
    tx = _sign_electrum_extended_transaction(unsigned_tx, [priv_keys[1]])
    assert json.dumps(transaction_to_electrumsv_dict(tx, TransactionContext(), [])) == '{"version": 2, "hex": "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000006b4830450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d412102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000002401ff21030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff01de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800", "complete": false, "inputs": [{"script_type": 2, "threshold": 1, "value": 18161, "signatures": ["30450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d41"], "x_pubkeys": [{"pubkey_bytes": "02faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85"}]}, {"script_type": 2, "threshold": 1, "value": 88385, "signatures": ["ff"], "x_pubkeys": [{"pubkey_bytes": "030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477ea"}]}]}'
    assert not tx.is_complete()

def test_sign_electrum_extended_transaction_both_inputs() -> None:
    tx = _sign_electrum_extended_transaction(unsigned_tx, priv_keys)
    assert tx.to_hex() == signed_tx_3
    assert tx.is_complete()
    assert tx.txid() == "b83acf939a92c420d0cb8d45d5d4dfad4e90369ebce0f49a45808dc1b41259b0"


# The difference between the ins and outs is conversion of an uncompressed public key to a
# compressed one. These are all a multi-signature with one compressed and one uncompressed.
unsigned_json_1_in = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000006e0001ff01ff4c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
unsigned_json_1_out = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000004d0001ff01ff475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
signed1_json_1_in = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000b400473044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c3914101ff4c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "3044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c39141"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
signed1_json_1_out = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000930001ff473044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c39141475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "3044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c39141"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
signed2_json_1_in = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000b500483045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c4101ff4c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["3045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c41", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
signed2_json_1_out = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000009400483045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c4101ff475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["3045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c41", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
fully_signed_json_1 = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000fb00483045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c41473044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c391414c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": true}' # pylint: disable=line-too-long

unsigned_json_2_in = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000006e0001ff01ff4c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "ff"], "x_pubkeys": [{"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}, {"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
unsigned_json_2_out = unsigned_json_1_out
signed1_json_2_in = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000b40047304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e4101ff4c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e41", "ff"], "x_pubkeys": [{"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}, {"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
signed1_json_2_out = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000930001ff47304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e41475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e41"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
signed2_json_2_in = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000b500483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a4101ff4c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "3045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a41"], "x_pubkeys": [{"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}, {"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
signed2_json_2_out = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000009400483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a4101ff475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["3045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a41", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
signed2_json_2_out_2 = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000009400483045022100fd8621418a6b1a45434858821e0f8c719ecacf6292bba52c8f1b5d796b93282202207087ba0f48d5317130ea0254c3ed651d959f83e560afd8883fef90e315fcadbf4101ff475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["3045022100fd8621418a6b1a45434858821e0f8c719ecacf6292bba52c8f1b5d796b93282202207087ba0f48d5317130ea0254c3ed651d959f83e560afd8883fef90e315fcadbf41", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
fully_signed_json_2 = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000fb0047304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e41483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a414c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": true}' # pylint: disable=line-too-long

@pytest.mark.parametrize("json_text_in,json_text_out", ((unsigned_json_1_in, unsigned_json_1_out),
    (signed1_json_1_in, signed1_json_1_out), (signed2_json_1_in, signed2_json_1_out),
    (fully_signed_json_1, fully_signed_json_1), (unsigned_json_2_in, unsigned_json_2_out),
    (signed1_json_2_in, signed1_json_2_out), (signed2_json_2_in, signed2_json_2_out),
    (fully_signed_json_2, fully_signed_json_2)))
def test_electrumsv_dict_multisig(json_text_in: str, json_text_out: str) -> None:
    tx, context = transaction_from_electrumsv_dict(json.loads(json_text_in), [])
    assert json.dumps(transaction_to_electrumsv_dict(tx, context, [])) == json_text_out


signed1_json_1_out_2 = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000940001ff483045022100b760b9d16d8159df851eda5bd4ce9d9b10287e6490186555d8f98b5b351cc60e02207ebf0d1ccc8c0023cc321cc85ffd3f0eee0751861651a3ae3642088602a7321341475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "3045022100b760b9d16d8159df851eda5bd4ce9d9b10287e6490186555d8f98b5b351cc60e02207ebf0d1ccc8c0023cc321cc85ffd3f0eee0751861651a3ae3642088602a7321341"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long
fully_signed_json_2_out_2 = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000db00483045022100fd8621418a6b1a45434858821e0f8c719ecacf6292bba52c8f1b5d796b93282202207087ba0f48d5317130ea0254c3ed651d959f83e560afd8883fef90e315fcadbf41483045022100b760b9d16d8159df851eda5bd4ce9d9b10287e6490186555d8f98b5b351cc60e02207ebf0d1ccc8c0023cc321cc85ffd3f0eee0751861651a3ae3642088602a7321341475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": true}' # pylint: disable=line-too-long
partially_signed2_json_out_2 = '{"version": 2, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000009400483045022100fd8621418a6b1a45434858821e0f8c719ecacf6292bba52c8f1b5d796b93282202207087ba0f48d5317130ea0254c3ed651d959f83e560afd8883fef90e315fcadbf4101ff475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["3045022100fd8621418a6b1a45434858821e0f8c719ecacf6292bba52c8f1b5d796b93282202207087ba0f48d5317130ea0254c3ed651d959f83e560afd8883fef90e315fcadbf41", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}' # pylint: disable=line-too-long

@pytest.mark.parametrize("unsigned_pair, signed1_pair, fully_signed_pair, signed2_pair", (
    (
        # Here the x_pubkeys are naturally sorted
        ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000a50001ff01ff4c9e524c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000045fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a90000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000', # pylint: disable=line-too-long
        unsigned_json_1_out),
        ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000eb0001ff473044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c391414c9e524c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000045fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a90000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000', # pylint: disable=line-too-long
        signed1_json_1_out_2),
        ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000db00483045022100fd8621418a6b1a45434858821e0f8c719ecacf6292bba52c8f1b5d796b93282202207087ba0f48d5317130ea0254c3ed651d959f83e560afd8883fef90e315fcadbf41483045022100b760b9d16d8159df851eda5bd4ce9d9b10287e6490186555d8f98b5b351cc60e02207ebf0d1ccc8c0023cc321cc85ffd3f0eee0751861651a3ae3642088602a7321341475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000', # pylint: disable=line-too-long
        fully_signed_json_2_out_2),
        ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000ec00483045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c4101ff4c9e524c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000045fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a90000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000', # pylint: disable=line-too-long
        partially_signed2_json_out_2),
    ),
    (
        # Here the x_pubkeys are reverse-sorted.  They should not be switched when signing.
        ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000a50001ff01ff4c9e5245fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9000000004c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000', # pylint: disable=line-too-long
        unsigned_json_1_out),
        ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000eb0047304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e4101ff4c9e5245fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9000000004c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000', # pylint: disable=line-too-long
        signed1_json_1_out_2),
        ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000db00483045022100fd8621418a6b1a45434858821e0f8c719ecacf6292bba52c8f1b5d796b93282202207087ba0f48d5317130ea0254c3ed651d959f83e560afd8883fef90e315fcadbf41483045022100b760b9d16d8159df851eda5bd4ce9d9b10287e6490186555d8f98b5b351cc60e02207ebf0d1ccc8c0023cc321cc85ffd3f0eee0751861651a3ae3642088602a7321341475221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8210272cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af73451005452aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000', # pylint: disable=line-too-long
        fully_signed_json_2_out_2),
        ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000ec0001ff483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a414c9e5245fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9000000004c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000', # pylint: disable=line-too-long
        signed2_json_2_out_2),
    )
))
def test_electrumsv_dict_multisig_2(unsigned_pair, signed1_pair, fully_signed_pair, signed2_pair):
    unsigned_hex, unsigned_json = unsigned_pair
    signed1_hex, signed1_json = signed1_pair
    fully_signed_hex, fully_signed_json = fully_signed_pair
    signed2_hex, signed2_json = signed2_pair

    tx = transaction_from_electrum_bytes(bytes.fromhex(unsigned_hex))
    assert json.dumps(transaction_to_electrumsv_dict(tx, TransactionContext(), [])) == unsigned_json

    keystore1, keystore2 = _multisig_keystores()
    # Sign with keystore 1, then 2
    keystore1.sign_transaction(tx, "OLD", TransactionContext())
    assert json.dumps(transaction_to_electrumsv_dict(tx, TransactionContext(), [])) == signed1_json

    keystore2.sign_transaction(tx, "BIP32", TransactionContext())
    assert tx.to_hex() == fully_signed_hex

    # Sign with keystore 2, then 1
    tx = transaction_from_electrum_bytes(bytes.fromhex(unsigned_hex))

    keystore2.sign_transaction(tx, "BIP32", TransactionContext())
    assert not tx.is_complete()
    assert json.dumps(transaction_to_electrumsv_dict(tx, TransactionContext(), [])) == signed2_json

    keystore1.sign_transaction(tx, "OLD", TransactionContext())
    assert tx.is_complete()
    assert tx.to_hex() == fully_signed_hex
    assert json.dumps(transaction_to_electrumsv_dict(tx, TransactionContext(), [])) == fully_signed_json


def test_electrum_extended_transaction_obsolete() -> None:
    """Confirm that we no longer re-serialise incomplete transactions as this format."""
    tx_hex = ('010000000111111111111111111111111111111111111111111111111111111111111111111b'
        '000000ec0001ff483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345b'
        'e781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a414c9e'
        '5245fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29'
        'ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9000000004c53ff0488b21e00000000'
        '0000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22'
        'cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000052aeffffffffb414'
        '0000000000000188130000000000001976a914000000000000000000000000000000000000000088ac'
        '00000000')
    tx = transaction_from_electrum_bytes(bytes.fromhex(tx_hex))
    # We do not serialize the old extended byte format anymore.
    assert tx.to_hex() != tx_hex


@pytest.mark.parametrize("raw_hex, path", (
    (
        'ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdb'
        'b213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa1201000a00',
        (1, 10),
    ),
    (
        'ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb2'
        '13d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa1200001900',
        (0, 25),
    ),
))
def test_bip32_extended_keys(raw_hex: str, path: DerivationPath, coin):
    # see test_keystore.py
    xpub = ('xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8w'
            'GvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA')
    root_key = bip32_key_from_string(xpub)
    True_10_public_key = cast(BIP32PublicKey, root_key.child(path[0]).child(path[1]))

    x_pubkey = x_public_key_from_electrum_bytes(bytes.fromhex(raw_hex))
    # assert x_pubkey.to_bytes() == bytes.fromhex(raw_hex)
    # assert x_pubkey.to_hex() == raw_hex
    assert x_pubkey.is_bip32_key()
    assert x_pubkey.bip32_extended_key_and_path() == (xpub, path)
    assert x_pubkey.to_public_key() == True_10_public_key
    assert x_pubkey.to_address() == True_10_public_key.to_address(network=coin)
    assert x_pubkey.to_address().network() is coin

@pytest.mark.parametrize("raw_hex, public_key_hex", (
    ('fee9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d'
        '5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b301000a00',
        '044794e135aa6d397222b4395091e53557f0e1ab9ffc0358303de6b9800642a9f544c3'
        'f8d2ece93e25864f19f44279661c16aaa8e85eea9ea1c8c1fcf1c61fcae0'
    ),
    ('fee9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09'
        'd5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b300000500',
        '04935970bd7c9e51bfe8e1135bb89a8ce09f8876d60d81ba4432f5e6fa394e6d09c9b'
        'a78f8d87aa7c519892a6adb5e7b39702379411dd7ba49f324f8c7e4e51f17'
    ),
))
def test_old_keystore(raw_hex: str, public_key_hex: str, coin) -> None:
    public_key = PublicKey.from_hex(public_key_hex)
    assert public_key.is_compressed() is False
    x_pubkey = x_public_key_from_electrum_bytes(bytes.fromhex(raw_hex))
    # assert x_pubkey.to_bytes() == bytes.fromhex(raw_hex)
    # assert x_pubkey.to_hex() == raw_hex
    assert not x_pubkey.is_bip32_key()
    assert x_pubkey.to_public_key() == public_key
    assert x_pubkey.to_public_key().is_compressed() is False
    assert x_pubkey.to_address() == public_key.to_address(network=coin)
    assert x_pubkey.to_address().network() is coin


def test_xpubkey() -> None:
    xpub = ('xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8w'
            'GvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA')
    xpubkey_hex =(
        'ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdb'
        'b213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa12')
    # The 1-depth case falls back to the old 2 byte 2 byte parsing.
    assert x_public_key_from_electrum_bytes(bytes.fromhex(
        xpubkey_hex + '01000a00')).bip32_extended_key_and_path() == (xpub, (1, 10))
    # Derivation path size must be multiples of 16 bit.
    with pytest.raises(AssertionError):
        x_public_key_from_electrum_bytes(bytes.fromhex(xpubkey_hex + '0a'))\
            .bip32_extended_key_and_path()

def test_electrum_extended_keys_old() -> None:
    mpk_hex = ("08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a688"
                "63b37df75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d0")
    keystore = cast(Old_KeyStore, instantiate_keystore_from_text(
        KeystoreTextType.ELECTRUM_OLD_SEED_WORDS, mpk_hex, password="OLD"))
    assert keystore.is_signature_candidate(x_public_key_from_electrum_bytes(bytes.fromhex(
        'fe08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a68'
        '863b37df75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d000000400')))
    assert keystore.is_signature_candidate(x_public_key_from_electrum_bytes(bytes.fromhex(
        'fe08863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a68863b37d'
        'f75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d001000301')))
    with pytest.raises(ValueError):
        x_public_key_from_electrum_bytes(bytes.fromhex(
            'fe18863ac1de668decc6406880c4c8d9a74e9986a5e8d9f2be262ac4af8a68863b37d'
            'f75ac48afcbb68bdd6a00f58a648bda9e5eb5e73bd51ef130a6e72dc698d001000301'
        )).to_public_key()

def test_electrum_extended_key_old_address() -> None:
    address = x_public_key_from_electrum_bytes(bytes.fromhex('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200')).to_address()
    assert address == address_from_string('19h943e4diLc68GXW7G75QNe2KWuMu7BaJ')

