import json
import pytest
from typing import cast

from electrumsv.network_support import mapi

taal_json_response_20210607 = r'{"payload":"{\"apiVersion\":\"1.1.0\",\"timestamp\":\"2021-06-07T00:51:14.666Z\",\"expiryTime\":\"2021-06-07T01:01:14.666Z\",\"minerId\":\"03e92d3e5c3f7bd945dfbf48e7a99393b1bfb3f11f380ae30d286e7ff2aec5a270\",\"currentHighestBlockHash\":\"000000000000000000200846e0db2397fd2a35289af3e42fed3eb764a6733829\",\"currentHighestBlockHeight\":690542,\"minerReputation\":null,\"fees\":[{\"id\":1,\"feeType\":\"standard\",\"miningFee\":{\"satoshis\":500,\"bytes\":1000},\"relayFee\":{\"satoshis\":250,\"bytes\":1000}},{\"id\":2,\"feeType\":\"data\",\"miningFee\":{\"satoshis\":500,\"bytes\":1000},\"relayFee\":{\"satoshis\":250,\"bytes\":1000}}]}","signature":"304502210083dcbde7fc1f73f2e2998b426821d6a8d3507b4ccc097f6ab4c648d76ce06671022016f6efdfa28be8d2fefb3b57b425882a4a82cf7e565269fe3d7d890d028921b5","publicKey":"03e92d3e5c3f7bd945dfbf48e7a99393b1bfb3f11f380ae30d286e7ff2aec5a270","encoding":"UTF-8","mimetype":"application/json"}' # pylint: disable=line-too-long


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
