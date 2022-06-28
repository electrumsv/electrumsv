import json
import pytest
from typing import cast, get_type_hints

from electrumsv.network_support import mapi
from electrumsv.network_support.types import MAPICallbackResponse
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

# Taken from:
#   https://github.com/bitcoin-sv-specs/brfc-merchantapi#callback-notifications
DOUBLE_SPEND_RESPONSE: MAPICallbackResponse = {
    "callbackPayload": {'doubleSpendTxId': 'f1f8d3de162f3558b97b052064ce1d0c45805490c210bdbc4d4f8b44cd0f143e', 'payload': '01000000014979e6d8237d7579a19aa657a568a3db46a973f737c120dffd6a8ba9432fa3f6010000006a47304402205fc740f902ccdadc2c3323f0258895f597fb75f92b13d14dd034119bee96e5f302207fd0feb68812dfa4a8e281f9af3a5b341a6fe0d14ff27648ae58c9a8aacee7d94121027ae06a5b3fe1de495fa9d4e738e48810b8b06fa6c959a5305426f78f42b48f8cffffffff018c949800000000001976a91482932cf55b847ffa52832d2bbec2838f658f226788ac00000000'}, # pylint: disable=line-too-long
    "apiVersion": "1.4.0",
    "timestamp": "2021-11-03T13:24:31.233647Z",
    "minerId": "030d1fe5c1b560efe196ba40540ce9017c20daa9504c4c4cec6184fc702d9f274e",
    "blockHash": "34bbc00697512058cb040e1c7bbba5d03a2e94270093eb28114747430137f9b7",
    "blockHeight": 153,
    "callbackTxId": "8750e986a296d39262736ed8b8f8061c6dce1c262844e1ad674a3bc134772167",
    "callbackReason": "doubleSpend"
}

DOUBLE_SPEND_ATTEMPT_RESPONSE: MAPICallbackResponse = {
    "callbackPayload": {'doubleSpendTxId': '7ea230b1610768374285150537323add313c1b9271b1b8110f5ddc629bf77f46', 'payload': '0100000001e75284dc47cb0beae5ebc7041d04dd2c6d29644a000af67810aad48567e879a0000000006a47304402203d13c692142b4b50737141145795ccb5bb9f5f8505b2d9b5a35f2f838b11feb102201cee2f2fe33c3d592f5e990700861baf9605b3b0199142bbc69ae88d1a28fa964121027ae06a5b3fe1de495fa9d4e738e48810b8b06fa6c959a5305426f78f42b48f8cffffffff018c949800000000001976a91482932cf55b847ffa52832d2bbec2838f658f226788ac00000000'}, # pylint: disable=line-too-long
    "apiVersion": "1.4.0",
    "timestamp": "2021-11-03T13:24:31.233647Z",
    "minerId": "030d1fe5c1b560efe196ba40540ce9017c20daa9504c4c4cec6184fc702d9f274e",
    "blockHash": "34bbc00697512058cb040e1c7bbba5d03a2e94270093eb28114747430137f9b7",
    "blockHeight": 153,
    "callbackTxId": "8750e986a296d39262736ed8b8f8061c6dce1c262844e1ad674a3bc134772167",
    "callbackReason": "doubleSpendAttempt"
}

MERKLE_PROOF_CALLBACK_RESPONSE: MAPICallbackResponse = {
    "callbackPayload": {'index': 1, 'txOrId': 'e7b3eefab33072e62283255f193ef5d22f26bbcfc0a80688fe2cc5178a32dda6', 'targetType': 'header', 'target': '00000020a552fb757cf80b7341063e108884504212da2f1e1ce2ad9ffc3c6163955a27274b53d185c6b216d9f4f8831af1249d7b4b8c8ab16096cb49dda5e5fbd59517c775ba8b60ffff7f2000000000', 'nodes': ['30361d1b60b8ca43d5cec3efc0a0c166d777ada0543ace64c4034fa25d253909', 'e7aa15058daf38236965670467ade59f96cfc6ec6b7b8bb05c9a7ed6926b884d', 'dad635ff856c81bdba518f82d224c048efd9aae2a045ad9abc74f2b18cde4322', '6f806a80720b0603d2ad3b6dfecc3801f42a2ea402789d8e2a77a6826b50303a']}, # pylint: disable=line-too-long
    "apiVersion": "1.4.0",
    "timestamp": "2021-04-30T08:06:13.4129624Z",
    "minerId": "030d1fe5c1b560efe196ba40540ce9017c20daa9504c4c4cec6184fc702d9f274e",
    "blockHash": "2ad8af91739e9dc41ea155a9ab4b14ab88fe2a0934f14420139867babf5953c4",
    "blockHeight": 105,
    "callbackTxId": "e7b3eefab33072e62283255f193ef5d22f26bbcfc0a80688fe2cc5178a32dda6",
    "callbackReason": "merkleProof"
}


def test_validate_mapi_callback_response_double_spend() -> None:
    # Check that a valid response passes.
    mapi.validate_mapi_callback_response(DOUBLE_SPEND_RESPONSE)


def test_validate_mapi_callback_response_double_spend_attempt() -> None:
    # Check that a valid response passes.
    mapi.validate_mapi_callback_response(DOUBLE_SPEND_ATTEMPT_RESPONSE)


def test_validate_mapi_callback_response_double_merkle_proof() -> None:
    # Check that a valid response passes.
    mapi.validate_mapi_callback_response(MERKLE_PROOF_CALLBACK_RESPONSE)


def test_validate_mapi_callback_response_invalid_reason() -> None:
    modified_response = DOUBLE_SPEND_RESPONSE.copy()
    modified_response["callbackReason"] = "unexpected value"
    with pytest.raises(ValueError):
        mapi.validate_mapi_callback_response(modified_response)


def test_validate_mapi_callback_response_check_sha256_hashes() -> None:
    modified_response = DOUBLE_SPEND_RESPONSE.copy()
    for field_name in ("blockHash", "callbackTxId"):
        for new_value in ("", "too_short", "c"*63, "c"*65):
            modified_response[field_name] = new_value
            with pytest.raises(ValueError) as exception_info:
                mapi.validate_mapi_callback_response(modified_response)
            assert "not 64 characters" in exception_info.value.args[0]


def test_validate_mapi_callback_response_check_miner_id() -> None:
    # This should be a 33 byte public key encoding.
    modified_response = DOUBLE_SPEND_RESPONSE.copy()
    for new_value in ("", "too_short", "c"*32, "c"*34):
        modified_response["minerId"] = new_value
        with pytest.raises(ValueError) as exception_info:
            mapi.validate_mapi_callback_response(modified_response)
        assert "not 66 characters" in exception_info.value.args[0]

    # The field is optional, cover that case.
    modified_response["minerId"] = None
    mapi.validate_mapi_callback_response(modified_response)


def test_validate_mapi_callback_response_all_fields_required() -> None:
    # Remove each field in turn from a fresh copy and check it's absence is missed.
    for field_name, _field_type in get_type_hints(MAPICallbackResponse).items():
        modified_response = DOUBLE_SPEND_RESPONSE.copy()
        del modified_response[field_name]

        with pytest.raises(ValueError) as exception_info:
            mapi.validate_mapi_callback_response(modified_response)
        assert field_name in exception_info.value.args[0]

