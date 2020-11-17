import json
import pytest

from bitcoinx import (
    Address, PrivateKey, PublicKey, Tx, Script, TxOutput, bip32_key_from_string, hash160, Bitcoin
)

from electrumsv.bitcoin import address_from_string
from electrumsv.keystore import Old_KeyStore, BIP32_KeyStore
from electrumsv.transaction import XPublicKey, Transaction, TransactionContext, NO_SIGNATURE


unsigned_blob = '010000000149f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed010000005701ff4c53ff0488b21e0000000000000000004f130d773e678a58366711837ec2e33ea601858262f8eaef246a7ebd19909c9a03c3b30e38ca7d797fee1223df1c9827b2a9f3379768f520910260220e0560014600002300feffffffd8e43201000000000118e43201000000001976a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac5fbd0700'
signed_blob = '010000000149f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed010000006a473044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f46885412103b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166feffffff0118e43201000000001976a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac5fbd0700'
v2_blob = "0200000001191601a44a81e061502b7bfbc6eaa1cef6d1e6af5308ef96c9342f71dbf4b9b5000000006b483045022100a6d44d0a651790a477e75334adfb8aae94d6612d01187b2c02526e340a7fd6c8022028bdf7a64a54906b13b145cd5dab21a26bd4b85d6044e9b97bceab5be44c2a9201210253e8e0254b0c95776786e40984c1aa32a7d03efa6bdacdea5f421b774917d346feffffff026b20fa04000000001976a914024db2e87dd7cfd0e5f266c5f212e21a31d805a588aca0860100000000001976a91421919b94ae5cefcdf0271191459157cdb41c4cbf88aca6240700"


class TestTransaction:

    def test_tx_unsigned(self):
        tx = Transaction.from_extended_bytes(bytes.fromhex(unsigned_blob))
        assert tx.version == 1
        assert len(tx.inputs) == 1
        txin = tx.inputs[0]
        assert txin.prev_hash.hex() == '49f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed'
        assert txin.prev_idx == 1
        assert txin.script_sig.to_hex() == '01ff4c53ff0488b21e0000000000000000004f130d773e678a58366711837ec2e33ea601858262f8eaef246a7ebd19909c9a03c3b30e38ca7d797fee1223df1c9827b2a9f3379768f520910260220e0560014600002300'
        assert txin.sequence == 4294967294
        assert txin.value == 20112600
        assert txin.signatures == [NO_SIGNATURE]
        assert txin.x_pubkeys == [XPublicKey.from_hex('ff0488b21e0000000000000000004f130d773e678a58366711837ec2e33ea601858262f8eaef246a7ebd19909c9a03c3b30e38ca7d797fee1223df1c9827b2a9f3379768f520910260220e0560014600002300')]
        assert txin.threshold == 1
        assert (tx.outputs[0].value == 20112408 and tx.outputs[0].script_pubkey == \
            address_from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK').to_script())
        assert tx.locktime == 507231

        assert json.dumps(tx.to_dict()) == '{"version": 1, "hex": "010000000149f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed010000002401ff2103b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166feffffff0118e43201000000001976a914e158fb15c888037fdc40fb9133b4c1c3c688706488ac5fbd0700", "complete": false, "inputs": [{"script_type": 2, "threshold": 1, "value": 20112600, "signatures": ["ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcFL6WFqND2XM2w1EfpBwFfhsSUcw9xDR3nH8eYLv4z4HAhxv5zkqjHojWsPYK1ZSK7yCr8fZ9iWU6D361G2ryv5UgsKjbeDq", "derivation_path": [0, 35]}]}]}'

    def test_tx_signed(self):
        # This is testing the extended parsing for a signed transaction.
        tx = Transaction.from_extended_bytes(bytes.fromhex(signed_blob))
        assert tx.version == 1
        assert len(tx.inputs) == 1
        txin = tx.inputs[0]
        assert txin.prev_hash.hex() == '49f35e43fefd22d8bb9e4b3ff294c6286154c25712baf6ab77b646e5074d6aed'
        assert txin.prev_idx == 1
        assert txin.script_sig.to_hex() == '473044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f46885412103b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166'
        assert txin.sequence == 4294967294
        assert txin.signatures == [bytes.fromhex('3044022025bdc804c6fe30966f6822dc25086bc6bb0366016e68e880cf6efd2468921f3202200e665db0404f6d6d9f86f73838306ac55bb0d0f6040ac6047d4e820f24f4688541')]
        assert txin.x_pubkeys == [XPublicKey.from_hex('03b5bbebceeb33c1b61f649596b9c3611c6b2853a1f6b48bce05dd54f667fa2166')]
        assert txin.threshold == 1
        assert (tx.outputs[0].value == 20112408 and tx.outputs[0].script_pubkey == \
            address_from_string('1MYXdf4moacvaEKZ57ozerpJ3t9xSeN6LK').to_script())
        assert tx.locktime == 507231
        assert tx.to_dict() == {'hex': signed_blob, 'complete': True, 'version': 1}
        assert tx.serialize() == signed_blob

        tx.update_signatures(signed_blob)

        assert tx.estimated_size() == 192

    def test_parse_xpub(self):
        res = XPublicKey.from_hex('fe4e13b0f311a55b8a5db9a32e959da9f011b131019d4cebe6141b9e2c93edcbfc0954c358b062a9f94111548e50bde5847a3096b8b7872dcffadb0e9579b9017b01000200').to_address()
        assert res == address_from_string('19h943e4diLc68GXW7G75QNe2KWuMu7BaJ')

    def test_version_field(self):
        tx = Transaction.from_hex(v2_blob)
        assert tx.txid() == "b97f9180173ab141b61b9f944d841e60feec691d6daab4d4d932b24dd36606fe"

    def test_txid_coinbase_to_p2pk(self):
        tx = Transaction.from_hex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4103400d0302ef02062f503253482f522cfabe6d6dd90d39663d10f8fd25ec88338295d4c6ce1c90d4aeb368d8bdbadcc1da3b635801000000000000000474073e03ffffffff013c25cf2d01000000434104b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7bac00000000')
        assert 'dbaf14e1c476e76ea05a8b71921a46d6b06f0a950f17c5f9f1a03b8fae467f10' == tx.txid()

    def test_txid_coinbase_to_p2pkh(self):
        tx = Transaction.from_hex('01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff25033ca0030400001256124d696e656420627920425443204775696c640800000d41000007daffffffff01c00d1298000000001976a91427a1f12771de5cc3b73941664b2537c15316be4388ac00000000')
        assert '4328f9311c6defd9ae1bd7f4516b62acf64b361eb39dfcf09d9925c5fd5c61e8' == tx.txid()

    def test_txid_p2pk_to_p2pkh(self):
        tx = Transaction.from_hex('010000000118231a31d2df84f884ced6af11dc24306319577d4d7c340124a7e2dd9c314077000000004847304402200b6c45891aed48937241907bc3e3868ee4c792819821fcde33311e5a3da4789a02205021b59692b652a01f5f009bd481acac2f647a7d9c076d71d85869763337882e01fdffffff016c95052a010000001976a9149c4891e7791da9e622532c97f43863768264faaf88ac00000000')
        assert '90ba90a5b115106d26663fce6c6215b8699c5d4b2672dd30756115f3337dddf9' == tx.txid()

    def test_txid_p2pk_to_p2sh(self):
        tx = Transaction.from_hex('0100000001e4643183d6497823576d17ac2439fb97eba24be8137f312e10fcc16483bb2d070000000048473044022032bbf0394dfe3b004075e3cbb3ea7071b9184547e27f8f73f967c4b3f6a21fa4022073edd5ae8b7b638f25872a7a308bb53a848baa9b9cc70af45fcf3c683d36a55301fdffffff011821814a0000000017a9143c640bc28a346749c09615b50211cb051faff00f8700000000')
        assert '172bdf5a690b874385b98d7ab6f6af807356f03a26033c6a65ab79b4ac2085b5' == tx.txid()

    def test_txid_p2pkh_to_p2pkh(self):
        tx = Transaction.from_hex('0100000001f9dd7d33f315617530dd72264b5d9c69b815626cce3f66266d1015b1a590ba90000000006a4730440220699bfee3d280a499daf4af5593e8750b54fef0557f3c9f717bfa909493a84f60022057718eec7985b7796bb8630bf6ea2e9bf2892ac21bd6ab8f741a008537139ffe012103b4289890b40590447b57f773b5843bf0400e9cead08be225fac587b3c2a8e973fdffffff01ec24052a010000001976a914ce9ff3d15ed5f3a3d94b583b12796d063879b11588ac00000000')
        assert '24737c68f53d4b519939119ed83b2a8d44d716d7f3ca98bcecc0fbb92c2085ce' == tx.txid()

    def test_txid_p2pkh_to_p2sh(self):
        tx = Transaction.from_hex('010000000195232c30f6611b9f2f82ec63f5b443b132219c425e1824584411f3d16a7a54bc000000006b4830450221009f39ac457dc8ff316e5cc03161c9eff6212d8694ccb88d801dbb32e85d8ed100022074230bb05e99b85a6a50d2b71e7bf04d80be3f1d014ea038f93943abd79421d101210317be0f7e5478e087453b9b5111bdad586038720f16ac9658fd16217ffd7e5785fdffffff0200e40b540200000017a914d81df3751b9e7dca920678cc19cac8d7ec9010b08718dfd63c2c0000001976a914303c42b63569ff5b390a2016ff44651cd84c7c8988acc7010000')
        assert '155e4740fa59f374abb4e133b87247dccc3afc233cb97c2bf2b46bba3094aedc' == tx.txid()

    def test_txid_p2sh_to_p2pkh(self):
        tx = Transaction.from_hex('0100000001b98d550fa331da21038952d6931ffd3607c440ab2985b75477181b577de118b10b000000fdfd0000483045022100a26ea637a6d39aa27ea7a0065e9691d477e23ad5970b5937a9b06754140cf27102201b00ed050b5c468ee66f9ef1ff41dfb3bd64451469efaab1d4b56fbf92f9df48014730440220080421482a37cc9a98a8dc3bf9d6b828092ad1a1357e3be34d9c5bbdca59bb5f02206fa88a389c4bf31fa062977606801f3ea87e86636da2625776c8c228bcd59f8a014c69522102420e820f71d17989ed73c0ff2ec1c1926cf989ad6909610614ee90cf7db3ef8721036eae8acbae031fdcaf74a824f3894bf54881b42911bd3ad056ea59a33ffb3d312103752669b75eb4dc0cca209af77a59d2c761cbb47acc4cf4b316ded35080d92e8253aeffffffff0101ac3a00000000001976a914a6b6bcc85975bf6a01a0eabb2ac97d5a418223ad88ac00000000')
        assert '0ea982e8e601863e604ef6d9acf9317ae59d3eac9cafee6dd946abadafd35af8' == tx.txid()

    def test_txid_p2sh_to_p2sh(self):
        # Note the public keys in this transaction are not sorted.  This also tests we do
        # not sort them.
        tx = Transaction.from_hex('01000000018695eef2250b3a3b6ef45fe065e601610e69dd7a56de742092d40e6276e6c9ec00000000fdfd000047304402203199bf8e49f7203e8bcbfd754aa356c6ba61643a3490f8aef3888e0aaa7c048c02201e7180bfd670f4404e513359b4020fbc85d6625e3e265e0c357e8611f11b83e401483045022100e60f897db114679f9a310a032a22e9a7c2b8080affe2036c480ff87bf6f45ada02202dbd27af38dd97d418e24d89c3bb7a97e359dd927c1094d8c9e5cac57df704fb014c69522103adc563b9f5e506f485978f4e913c10da208eac6d96d49df4beae469e81a4dd982102c52bc9643a021464a31a3bfa99cfa46afaa4b3acda31e025da204b4ee44cc07a2103a1c8edcc3310b3d7937e9e4179e7bd9cdf31c276f985f4eb356f21b874225eb153aeffffffff02b8ce05000000000017a9145c9c158430b7b79c3ad7ef9bdf981601eda2412d87b82400000000000017a9146bf3ff89019ecc5971a39cdd4f1cabd3b647ad5d8700000000')
        assert '2caab5a11fa1ec0f5bb014b8858d00fecf2c001e15d22ad04379ad7b36fef305' == tx.txid()


# 2 inputs, one for each priv_key below
unsigned_tx = "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000002401ff2102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff146000000000000f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000002401ff21030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff415901000000000001de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800"

priv_keys = [PrivateKey.from_WIF(WIF) for WIF in (
    "KzjWgFAozj8EfMFpeCBshWA69QXG7Kj7nMYHjSkkcTM8DM8GF1Hd",
    "KyY5VaoqPwjSgGpKHT3JJKDcxXMeqYo6umK7u1h3iBt9n9aihiPs",
)]


# First priv key only signed
signed_tx_1 = "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000002401ff2102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff146000000000000f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000006b483045022100fa8ebdc7cefc407fd1b560fb2e2e5e96e900e94634d96df4fd284126048746a2022028d91ca132a1a386a67df69a2c5ba216218870c256c163d729f1575f7a8824f54121030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff01de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800"


# Second priv key only signed
signed_tx_2 = "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000006b4830450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d412102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000002401ff21030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff415901000000000001de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800"


# Both priv keys signed
signed_tx_3 = "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000006b4830450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d412102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000006b483045022100fa8ebdc7cefc407fd1b560fb2e2e5e96e900e94634d96df4fd284126048746a2022028d91ca132a1a386a67df69a2c5ba216218870c256c163d729f1575f7a8824f54121030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff01de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800"


class TestTransaction2:

    def sign_tx(self, unsigned_tx_hex, priv_keys):
        keypairs = {XPublicKey.from_hex(priv_key.public_key.to_hex()):
                    (priv_key.to_bytes(), priv_key.is_compressed())
                    for priv_key in priv_keys}
        tx = Transaction.from_extended_bytes(bytes.fromhex(unsigned_tx_hex))
        tx.sign(keypairs)
        return tx

    def test_sign_tx_1(self):
        # Test signing the first input only
        tx = self.sign_tx(unsigned_tx, [priv_keys[0]])
        assert json.dumps(tx.to_dict()) == '{"version": 1, "hex": "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000002401ff2102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000006b483045022100fa8ebdc7cefc407fd1b560fb2e2e5e96e900e94634d96df4fd284126048746a2022028d91ca132a1a386a67df69a2c5ba216218870c256c163d729f1575f7a8824f54121030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff01de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800", "complete": false, "inputs": [{"script_type": 2, "threshold": 1, "value": 18161, "signatures": ["ff"], "x_pubkeys": [{"pubkey_bytes": "02faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85"}]}, {"script_type": 2, "threshold": 1, "value": 88385, "signatures": ["3045022100fa8ebdc7cefc407fd1b560fb2e2e5e96e900e94634d96df4fd284126048746a2022028d91ca132a1a386a67df69a2c5ba216218870c256c163d729f1575f7a8824f541"], "x_pubkeys": [{"pubkey_bytes": "030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477ea"}]}]}'
        assert not tx.is_complete()

    def test_sign_tx_2(self):
        # Test signing the second input only
        tx = self.sign_tx(unsigned_tx, [priv_keys[1]])
        assert json.dumps(tx.to_dict()) == '{"version": 1, "hex": "0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084000000006b4830450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d412102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85fefffffff25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c912084010000002401ff21030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff01de9e0100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800", "complete": false, "inputs": [{"script_type": 2, "threshold": 1, "value": 18161, "signatures": ["30450221008dc02fa531a9a704f5c01abdeb58930514651565b42abf94f6ad1565d0ad6785022027b1396f772c696629a4a09b01aed2416861aeaee05d0ff4a2e6fdfde73ec84d41"], "x_pubkeys": [{"pubkey_bytes": "02faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e4730fe85"}]}, {"script_type": 2, "threshold": 1, "value": 88385, "signatures": ["ff"], "x_pubkeys": [{"pubkey_bytes": "030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477ea"}]}]}'
        assert not tx.is_complete()

    def test_sign_tx_3(self):
        # Test signing both
        tx = self.sign_tx(unsigned_tx, priv_keys)
        assert tx.to_hex() == signed_tx_3
        assert tx.is_complete()
        assert tx.txid() == "b83acf939a92c420d0cb8d45d5d4dfad4e90369ebce0f49a45808dc1b41259b0"

    def test_update_signatures(self):
        signed_tx = Tx.from_hex(signed_tx_3)
        sigs = [next(input.script_sig.ops())[:-1] for input in signed_tx.inputs]
        tx = Transaction.from_extended_bytes(bytes.fromhex(unsigned_tx))
        tx.update_signatures(sigs)
        assert tx.is_complete()
        assert tx.txid() == "b83acf939a92c420d0cb8d45d5d4dfad4e90369ebce0f49a45808dc1b41259b0"

    def multisig_keystores(self):
        seed = 'ee6ea9eceaf649640051a4c305ac5c59'
        keystore1 = Old_KeyStore.from_seed(seed)
        keystore1.update_password("OLD")

        xprv = ('xprv9s21ZrQH143K4XLpSd2berkCzJTXDv68rusDQFiQGSqa1ZmVXnYzYpTQ9'
                'qYiSB7mHvg6kEsrd2ZtnHRJ61sZhSN4jZ2T8wxA4T75BE4QQZ1')
        xpub = ('xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8w'
                'GvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA')
        keystore2 = BIP32_KeyStore({'xprv': xprv, 'xpub': xpub})
        keystore2.update_password("BIP32")

        return [keystore1, keystore2]

    unsigned_json_1 = '{"version": 1, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000006e0001ff01ff4c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}'
    signed1_json_1 = '{"version": 1, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000b400473044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c3914101ff4c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "3044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c39141"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}'
    signed2_json_1 = '{"version": 1, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000b500483045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c4101ff4c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["3045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c41", "ff"], "x_pubkeys": [{"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}, {"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}]}]}'
    fully_signed_json_1 = '{"version": 1, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000fb00483045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c41473044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c391414c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": true}'

    unsigned_json_2 = '{"version": 1, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b0000006e0001ff01ff4c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "ff"], "x_pubkeys": [{"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}, {"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}]}]}'
    signed1_json_2 = '{"version": 1, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000b40047304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e4101ff4c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e41", "ff"], "x_pubkeys": [{"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}, {"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}]}]}'
    signed2_json_2 = '{"version": 1, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000b500483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a4101ff4c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": false, "inputs": [{"script_type": 4, "threshold": 2, "value": 5300, "signatures": ["ff", "3045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a41"], "x_pubkeys": [{"old_mpk": "84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9", "derivation_path": [0, 0]}, {"bip32_xpub": "xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8wGvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA", "derivation_path": [0, 0]}]}]}'
    fully_signed_json_2 = '{"version": 1, "hex": "010000000111111111111111111111111111111111111111111111111111111111111111111b000000fb0047304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e41483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a414c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000", "complete": true}'

    @pytest.mark.parametrize("json_text", (unsigned_json_1, signed1_json_1, signed2_json_1,
        fully_signed_json_1, unsigned_json_2, signed1_json_2, signed2_json_2,
        fully_signed_json_2))
    def test_dict_io(self, json_text: str) -> None:
        tx = Transaction.from_dict(json.loads(json_text))
        assert json.dumps(tx.to_dict()) == json_text

    @pytest.mark.parametrize("unsigned_pair, signed1_pair, fully_signed_pair, signed2_pair", (
        (
            # Here the x_pubkeys are naturally sorted
            ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000a50001ff01ff4c9e524c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000045fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a90000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000',
            unsigned_json_1),
            ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000eb0001ff473044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c391414c9e524c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000045fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a90000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000',
            signed1_json_1),
            ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000fb00483045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c41473044022100a9b906ec7fd40b8063326675d5f229d36227241dc84f262b203b3eaadfd91789021f267473437145d77c69273ffef2426055c6c89457832c3d38fcb3c07eb8c391414c675221020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e8410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e52aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000',
            fully_signed_json_1),
            ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000ec00483045022100bc32a5f10b755dcd8dc9a498d76286f059993d1d72fbc5340d0da9dc99dcad0a022064e37760d9ad3e3b9f0b48263becca8dee5aac43bdcecfdfdc63553057083a8c4101ff4c9e524c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000045fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a90000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000',
            signed2_json_1),
        ),
        (
            # Here the x_pubkeys are reverse-sorted.  They should not be switched when signing.
            ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000a50001ff01ff4c9e5245fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9000000004c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000',
            unsigned_json_2),
            ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000eb0047304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e4101ff4c9e5245fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9000000004c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000',
            signed1_json_2),
            ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000fb0047304402207a923d1b0ca9930cfb2162f1e85dc5feb6e9322efcceeaba7a91ad37f72b815702207ed90ebab7c8bbf728d29c2d93931bb44ff1a7147b37982c1d27c822c139079e41483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a414c6752410472cd64a288e4a518059b388a9164522e05c3f3aef3f6791f31074af734510054bfde0bee54dbefa0eebe71a53d18298c628842b1865e2e0bc053bb4197af726e21020c8bd7a0cfa64714b8f01316cd46197b902565f2c812ed0d450fcd1425edc9e852aeffffffff0188130000000000001976a914000000000000000000000000000000000000000088ac00000000',
            fully_signed_json_2),
            ('010000000111111111111111111111111111111111111111111111111111111111111111111b000000ec0001ff483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345be781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a414c9e5245fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9000000004c53ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000052aeffffffffb4140000000000000188130000000000001976a914000000000000000000000000000000000000000088ac00000000',
            signed2_json_2),
        )
    ))
    def test_multisig(self, unsigned_pair, signed1_pair, fully_signed_pair, signed2_pair):
        unsigned_hex, unsigned_json = unsigned_pair
        signed1_hex, signed1_json = signed1_pair
        fully_signed_hex, fully_signed_json = fully_signed_pair
        signed2_hex, signed2_json = signed2_pair

        tx = Transaction.from_extended_bytes(bytes.fromhex(unsigned_hex))

        keystore1, keystore2 = self.multisig_keystores()

        assert json.dumps(tx.to_dict()) == unsigned_json

        # Sign with keystore 1, then 2
        keystore1.sign_transaction(tx, "OLD", TransactionContext())
        assert json.dumps(tx.to_dict()) == signed1_json

        keystore2.sign_transaction(tx, "BIP32", TransactionContext())
        assert tx.serialize() == fully_signed_hex

        # Sign with keystore 2, then 1
        tx = Transaction.from_extended_bytes(bytes.fromhex(unsigned_hex))

        keystore2.sign_transaction(tx, "BIP32", TransactionContext())
        assert json.dumps(tx.to_dict()) == signed2_json

        keystore1.sign_transaction(tx, "OLD", TransactionContext())
        assert tx.serialize() == fully_signed_hex
        assert json.dumps(tx.to_dict()) == fully_signed_json


class TestXPublicKey:

    def test_bad_type(self):
        public_key = PublicKey.from_hex(
            '034339a901d8526c4d733c8ea7c861f1a6324f37f6b86f838725820e0c5fc19570')
        with pytest.raises(AssertionError):
            XPublicKey(pubkey_bytes=public_key)

    def test_bad_key(self):
        with pytest.raises(ValueError):
            XPublicKey.from_hex(
                '034339a901d8526c4d733c8ea7c861f1a6324f37f6b86f838725820e0c5fc1957000')
        with pytest.raises(AssertionError):
            XPublicKey.from_hex(
            'ff0488b21e000000000000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdb'
            'b213d0025602e9aa22cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa1201000a'
            )

    @pytest.mark.parametrize("raw_hex", (
        # An uncompressed 04 key
        '046d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e'
        '2487e6222a6664e079c8edf7518defd562dbeda1e7593dfd7f0be285880a24dab',
        # A compressed 03 key
        '034339a901d8526c4d733c8ea7c861f1a6324f37f6b86f838725820e0c5fc19570',
        # A compressed 02 key
        '026370246118a7c218fd557496ebb2b0862d59c6486e88f83e07fd12ce8a88fb00',
    ))
    def test_raw_public_keys(self, raw_hex, coin):
        public_key = PublicKey.from_hex(raw_hex)
        x_pubkey = XPublicKey.from_hex(raw_hex)
        # assert x_pubkey.to_bytes() == bytes.fromhex(raw_hex)
        # assert x_pubkey.to_hex() == raw_hex
        assert not x_pubkey.is_bip32_key()
        assert x_pubkey.to_public_key() == public_key
        assert x_pubkey.to_address() == public_key.to_address(coin=coin)
        assert x_pubkey.to_address().coin() is coin

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
    def test_bip32_extended_keys(self, raw_hex, path, coin):
        # see test_keystore.py
        xpub = ('xpub661MyMwAqRbcH1RHYeZc1zgwYLJ1dNozE8npCe81pnNYtN6e5KsF6cmt17Fv8w'
                'GvJrRiv6Kewm8ggBG6N3XajhoioH3stUmLRi53tk46CiA')
        root_key = bip32_key_from_string(xpub)
        True_10_public_key = root_key.child(path[0]).child(path[1])

        x_pubkey = XPublicKey.from_bytes(bytes.fromhex(raw_hex))
        # assert x_pubkey.to_bytes() == bytes.fromhex(raw_hex)
        # assert x_pubkey.to_hex() == raw_hex
        assert x_pubkey.is_bip32_key()
        assert x_pubkey.bip32_extended_key_and_path() == (xpub, path)
        assert x_pubkey.to_public_key() == True_10_public_key
        assert x_pubkey.to_address() == True_10_public_key.to_address(coin=coin)
        assert x_pubkey.to_address().coin() is coin

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
    def test_old_keystore(self, raw_hex, public_key_hex, coin):
        public_key = PublicKey.from_hex(public_key_hex)
        assert public_key.is_compressed() is False
        x_pubkey = XPublicKey.from_hex(raw_hex)
        # assert x_pubkey.to_bytes() == bytes.fromhex(raw_hex)
        # assert x_pubkey.to_hex() == raw_hex
        assert not x_pubkey.is_bip32_key()
        assert x_pubkey.to_public_key() == public_key
        assert x_pubkey.to_public_key().is_compressed() is False
        assert x_pubkey.to_address() == public_key.to_address(coin=coin)
        assert x_pubkey.to_address().coin() is coin

    def test_fd_read_write(self):
        tx_hex = ('010000000111111111111111111111111111111111111111111111111111111111111111111b'
            '000000ec0001ff483045022100ae42f172f722ac2392ef3e5958d78bbca1ebedbce47eff27ba66345b'
            'e781c46f02207c9ab6ff496791bf2e56300ff4621beaec6ccdd3639e460612569c6e0407e09a414c9e'
            '5245fe84717a26df3332b129e59faaab25c11752277bc55c07d8724e1660e63b862d00b41d3db01e29'
            'ed54ca83300eb73d82b5381536298f40fdad8c1e307b66cf39a9000000004c53ff0488b21e00000000'
            '0000000000f79d7a4d3ea07099f09fbf35c3103908cbb4b1f30e8602a06ffbdbb213d0025602e9aa22'
            'cc7106abab85e4c41f18f030c370213769c18d6754f3d0584e69a7fa120000000052aeffffffffb414'
            '0000000000000188130000000000001976a914000000000000000000000000000000000000000088ac'
            '00000000')
        tx = Transaction.from_extended_bytes(bytes.fromhex(tx_hex))
        # We do not serialize the old extended byte format anymore.
        assert tx.serialize() != tx_hex
