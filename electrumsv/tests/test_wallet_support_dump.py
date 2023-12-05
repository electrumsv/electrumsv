from bitcoinx import hash_to_hex_str
import pytest

from electrumsv.constants import BitcacheTxFlag, DerivationType, ScriptType
from electrumsv.wallet_support.dump import convert_txrow_to_jsondata, encode_derivation_data, \
    encode_script_type, decode_derivation_data, decode_script_type, ScriptTypeNames, JSONTx
from electrumsv.wallet_database.types import BitcacheTransactionRow, TransactionOutputKeyDataRow

DPB_m_0_0 = bytes.fromhex("0000000000000000")

def test_encode_derivation_data() -> None:
    assert encode_derivation_data(DerivationType.BIP32_SUBPATH, DPB_m_0_0) == \
        "bip32:m/0/0"

def test_decode_derivation_data() -> None:
    assert decode_derivation_data("bip32:m/0/0") == (DerivationType.BIP32_SUBPATH, DPB_m_0_0)
    # Do not retest the `bip32_decompose_chain_string` function, just this function.
    with pytest.raises(ValueError):
        decode_derivation_data("bip32x:m/0/0")

def test_encode_script_type() -> None:
    assert encode_script_type(ScriptType.P2PKH) == ScriptTypeNames.P2PKH
    with pytest.raises(ValueError):
        assert encode_script_type(ScriptType.P2PK)

def test_decode_script_type() -> None:
    assert decode_script_type(ScriptTypeNames.P2PKH) == ScriptType.P2PKH

@pytest.mark.parametrize("key_fingerprint,row,result", [
        (bytes.fromhex("9341cb4c"), BitcacheTransactionRow(b"tx_hash", b"tx_bytes",
            BitcacheTxFlag.NONE, b"proof_bytes", b"block_hash", 112, 111,
            [ TransactionOutputKeyDataRow(b"", 0, ScriptType.P2PKH, None,
                DerivationType.BIP32_SUBPATH, DPB_m_0_0) ]),
        {
            "tsc_proof": b"proof_bytes".hex(),
            "block_hash": hash_to_hex_str(b"block_hash"),
            "block_height": 112,
            "block_position": 111,
            "key_usage": [{"vout": 0, "script_type": "p2pkh", "key_fingerprint": "9341cb4c",
                "key_derivation": "bip32:m/0/0"}]
        })
    ])
def test_convert_txrow_to_jsondata(key_fingerprint: bytes, row: BitcacheTransactionRow,
        result: JSONTx) -> None:
    assert convert_txrow_to_jsondata(row, key_fingerprint) == result
