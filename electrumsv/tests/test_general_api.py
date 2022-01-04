
from electrumsv.network_support.general_api import unpack_binary_restoration_entry

BINARY_RESTORATION_RESPONSE = bytes.fromhex(
    "0186c73b803ee5229044621b2fb6fb61b7001a92cbfdab1c7314da27a2fee72948fd57f50c35251a260a0317a4"
    "975579047e89f5544d9a8841f10b3c9d4b73024600000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000")

MATCH_FLAGS = 1
PUSHDATA_HASH = bytes.fromhex('86c73b803ee5229044621b2fb6fb61b7001a92cbfdab1c7314da27a2fee72948')
TRANSACTION_HASH = bytes.fromhex('fd57f50c35251a260a0317a4975579047e89f5544d9a8841f10b3c9d4b730246')
SPEND_TRANSACTION_HASH = b"\0" * 32
TRANSACTION_OUTPUT_INDEX = 0
SPEND_INPUT_INDEX = 0

def test_unpack_binary_restoration_entry() -> None:
    result = unpack_binary_restoration_entry(BINARY_RESTORATION_RESPONSE)
    assert result.flags == MATCH_FLAGS
    assert result.push_data_hash == PUSHDATA_HASH
    assert result.locking_transaction_hash == TRANSACTION_HASH
    assert result.locking_output_index == TRANSACTION_OUTPUT_INDEX
    assert result.unlocking_transaction_hash == SPEND_TRANSACTION_HASH
    assert result.unlocking_input_index == SPEND_INPUT_INDEX
