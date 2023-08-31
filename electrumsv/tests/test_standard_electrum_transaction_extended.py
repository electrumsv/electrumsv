import json
from typing import cast

from bitcoinx import bip32_key_from_string, BIP32PublicKey, PrivateKey, PublicKey, Tx
import pytest

from electrumsv.bitcoin import address_from_string
from electrumsv.constants import DerivationPath, KeystoreTextType
from electrumsv.keystore import BIP32_KeyStore, instantiate_keystore_from_text, \
    Old_KeyStore, SinglesigKeyStoreTypes
from electrumsv.standards.electrum_transaction_extended import transaction_from_electrum_bytes, \
    x_public_key_from_electrum_bytes
from electrumsv.transaction import XPublicKey, Transaction, TxContext

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

def test_sign_electrum_extended_transaction_both_inputs() -> None:
    tx = _sign_electrum_extended_transaction(unsigned_tx, priv_keys)
    assert tx.to_hex() == signed_tx_3
    assert tx.is_complete()
    assert tx.txid() == "b83acf939a92c420d0cb8d45d5d4dfad4e90369ebce0f49a45808dc1b41259b0"


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

