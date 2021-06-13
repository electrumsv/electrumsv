import json
import pytest
from typing import cast

from electrumsv.network_support import mapi
from electrumsv.transaction import Transaction
from electrumsv.types import TransactionSize


taal_json_response_20210607 = r'{"payload":"{\"apiVersion\":\"1.1.0\",\"timestamp\":\"2021-06-07T00:51:14.666Z\",\"expiryTime\":\"2021-06-07T01:01:14.666Z\",\"minerId\":\"03e92d3e5c3f7bd945dfbf48e7a99393b1bfb3f11f380ae30d286e7ff2aec5a270\",\"currentHighestBlockHash\":\"000000000000000000200846e0db2397fd2a35289af3e42fed3eb764a6733829\",\"currentHighestBlockHeight\":690542,\"minerReputation\":null,\"fees\":[{\"id\":1,\"feeType\":\"standard\",\"miningFee\":{\"satoshis\":500,\"bytes\":1000},\"relayFee\":{\"satoshis\":250,\"bytes\":1000}},{\"id\":2,\"feeType\":\"data\",\"miningFee\":{\"satoshis\":500,\"bytes\":1000},\"relayFee\":{\"satoshis\":250,\"bytes\":1000}}]}","signature":"304502210083dcbde7fc1f73f2e2998b426821d6a8d3507b4ccc097f6ab4c648d76ce06671022016f6efdfa28be8d2fefb3b57b425882a4a82cf7e565269fe3d7d890d028921b5","publicKey":"03e92d3e5c3f7bd945dfbf48e7a99393b1bfb3f11f380ae30d286e7ff2aec5a270","encoding":"UTF-8","mimetype":"application/json"}' # pylint: disable=line-too-long

# 90b4b6e36ebb45b06aa2e78b7138c994fdb4735b7f1ff3769736fe8478b2015c
# data size = len(tx.outputs[1].script_pubkey) = 206
signed_testnet_tx = "0100000001fb9137c23f3df14eb80a00430fb77c632d5e6527921a07f6055b70e2ec3cb28e000000006a473044022027b429ec9af0809bd7937cc6dc4ac4d1f97f156be7d3a8237a8d44749fd36e4602200a212ba860be39fca2cc187ee1df08fc18d1c07c301de7ddd9c7f76c8452373441210237b580891849bef2c3e33246e72f0bffefef31cf6fcdd6601f51f8a5fcacd02fffffffff0322020000000000001976a914c34db40c501703bfc6199027629a4ba7f4d4659588ac0000000000000000ce006a046d6574614230323963623333663262616135666565626462376234613530366235333631636265326438383339353238356432616238663032386339613530646531313434316640656265623061633937663733653862316365386138306466373862636333663066306562323035353532336465346165653338353430633863333834383562310a7465737473686f776964114d657461416363657373436f6e74656e740c636330383561383734326537013005312e302e310a746578742f706c61696e055554462d383f040000000000001976a914d0839a2ed4357e0452ec9089587b6452d82db15c88ac00000000" # pylint: disable=line-too-long

def test_fee_quote_response_invalid_signature() -> None:
    invalid_response = taal_json_response_20210607.replace("83dcbde", "decb3d8")
    # Ensure that the signature we are invalidating was present.
    assert invalid_response != taal_json_response_20210607
    real_response = cast(mapi.JSONEnvelope, json.loads(invalid_response))
    with pytest.raises(ValueError):
        mapi.validate_json_envelope(real_response)


def test_fee_quote_response_valid_signature() -> None:
    real_response = cast(mapi.JSONEnvelope, json.loads(taal_json_response_20210607))
    mapi.validate_json_envelope(real_response)


def test_fee_quote_response_no_signature() -> None:
    # Test that if there is no signature and no public key we consider it good, whatever that
    # means. Ideally we would have a response from a MAPI server to test for this, but currently
    # we do not.
    fake_response_dict = {
        "payload": "",
        "signature": None,
        "publicKey": None,
    }
    fake_response = cast(mapi.JSONEnvelope, fake_response_dict)
    mapi.validate_json_envelope(fake_response)


def test_calculate_mapi_fee_standard_only() -> None:
    fake_fee_quote = {
        "fees": [
            {
                "feeType": "standard",
                "miningFee": {
                    "satoshis": 500,
                    "bytes": 1000,
                },
            },
        ]
    }
    fee_quote = cast(mapi.FeeQuote, fake_fee_quote)
    estimator = mapi.MAPIFeeEstimator(fee_quote)
    mapi_tx_size = TransactionSize(100, 1000)
    assert 550 == estimator.estimate_fee(mapi_tx_size)


def test_calculate_mapi_fee_data_only_errors() -> None:
    fake_fee_quote = {
        "fees": [
            {
                "feeType": "data",
                "miningFee": {
                    "satoshis": 500,
                    "bytes": 1000,
                },
            },
        ]
    }
    fee_quote = cast(mapi.FeeQuote, fake_fee_quote)
    with pytest.raises(AssertionError):
        mapi.MAPIFeeEstimator(fee_quote)


def test_calculate_mapi_fee_standard_and_data() -> None:
    fake_fee_quote = {
        "fees": [
            {
                "feeType": "standard",
                "miningFee": {
                    "satoshis": 500,
                    "bytes": 1000,
                },
            },
            {
                "feeType": "data",
                "miningFee": {
                    "satoshis": 2000,
                    "bytes": 1000,
                },
            },
        ]
    }
    fee_quote = cast(mapi.FeeQuote, fake_fee_quote)
    estimator = mapi.MAPIFeeEstimator(fee_quote)
    mapi_tx_size = TransactionSize(100, 1000)
    assert (50 + 2000) == estimator.estimate_fee(mapi_tx_size)


def test_calculate_mapi_transaction_size() -> None:
    tx = Transaction.from_hex(signed_testnet_tx)
    sizes = tx.estimated_size()
    assert sizes.data_size == 206
    assert sizes.standard_size == 234
