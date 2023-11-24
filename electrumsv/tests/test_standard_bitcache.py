import io, json, os
from typing import cast

from electrumsv.standards.bitcache import BitcacheMessage, BitcacheTxoKeyUsage, \
    read_bitcache_message, write_bitcache_transaction_message
from electrumsv.tests.util import TEST_TRANSACTION_PATH
from electrumsv.wallet_support.dump import decode_derivation_data, decode_script_type, \
    JSONTxoKeyUsage

# This is the data from the exported regtest mining wallet we have in the simple indexer.
MINING_TEST_PATH = os.path.join(TEST_TRANSACTION_PATH, "regtest_mining")
MINING_BITCACHE_PATH = os.path.join(MINING_TEST_PATH, "bitcache")


def test_read_bitcache_messages() -> None:
    assert os.path.exists(MINING_BITCACHE_PATH)
    for filename in sorted(os.listdir(MINING_BITCACHE_PATH)):
        message_path = os.path.join(MINING_BITCACHE_PATH, filename)
        with open(message_path, "rb") as f:
            message_data = f.read()
            f.seek(0, os.SEEK_SET)
            message = read_bitcache_message(f)
        # Verify that the message has correct transaction data.
        filename_prefix, _filename_suffix = os.path.splitext(filename)
        transaction_path = os.path.join(MINING_TEST_PATH, filename_prefix+".txn")
        assert os.path.exists(transaction_path)
        assert message.tx_data == open(transaction_path, "rb").read()
        # Verify that the message has correct metadata.
        metadata_path = os.path.join(MINING_TEST_PATH, filename_prefix+".json")
        assert os.path.exists(metadata_path)
        with open(metadata_path, "r") as f:
            for i, o in enumerate(cast(list[JSONTxoKeyUsage], json.load(f))):
                k = message.key_data[i]
                assert o["vout"] == k.txo_index
                assert decode_script_type(o["script_type"]) == k.script_type
                assert bytes.fromhex(o["key_fingerprint"]) == k.parent_key_fingerprint
                derivation_type, derivation_data2 = decode_derivation_data(o["key_derivation"])
                assert derivation_type == k.derivation_type
                assert derivation_data2 == k.derivation_data2
        # Verify that reconstructing the message gives matching bytes.
        output_stream = io.BytesIO()
        write_bitcache_transaction_message(output_stream, message)
        assert message_data == output_stream.getbuffer()

# ---
# def test_bitcache_generate() -> None:
#     _generate_test_data()

def _generate_test_data() -> None:
    assert os.path.exists(MINING_TEST_PATH)
    os.makedirs(MINING_BITCACHE_PATH, exist_ok=True)
    for filename in os.listdir(MINING_TEST_PATH):
        prefix, suffix = os.path.splitext(filename)
        if suffix != ".txn":
            continue
        transaction_path = os.path.join(MINING_TEST_PATH, prefix+".txn")
        with open(transaction_path, "rb") as f:
            msg = BitcacheMessage(f.read(), [])

        key_usage_path = os.path.join(MINING_TEST_PATH, prefix+".json")
        assert os.path.exists(key_usage_path)
        with open(key_usage_path, "r") as f:
            for o in cast(list[JSONTxoKeyUsage], json.load(f)):
                msg.key_data.append(BitcacheTxoKeyUsage(o["vout"],
                    decode_script_type(o["script_type"]), bytes.fromhex(o["key_fingerprint"]),
                    *decode_derivation_data(o["key_derivation"])))

        output_path = os.path.join(MINING_BITCACHE_PATH, prefix+".bin")
        with open(output_path, "wb") as f:
            write_bitcache_transaction_message(f, msg)
