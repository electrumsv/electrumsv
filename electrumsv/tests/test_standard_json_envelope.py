import json
from typing import cast

import pytest

from electrumsv.standards.json_envelope import JSONEnvelope, validate_json_envelope


# Examples taken from: https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope

example_utf8_json = r"""
{
  "payload": "{\"name\":\"simon\",\"colour\":\"blue\"}",
  "signature": "30450221008209b19ffe2182d859ce36fdeff5ded4b3f70ad77e0e8715238a539db97c1282022043b1a5b260271b7c833ca7c37d1490f21b7bd029dbb8970570c7fdc3df5c93ab",
  "publicKey": "02b01c0c23ff7ff35f774e6d3b3491a123afb6c98965054e024d2320f7dbd25d8a",
  "encoding": "UTF-8",
  "mimetype": "application/json"
}
"""

# NOTE(rt12) This "extra example" from the specification seems to have an invalid signature.
example_base64_image = r"""
{
  "payload": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wgARCAAKAAoDASIAAhEBAxEB/8QAFwAAAwEAAAAAAAAAAAAAAAAAAQMEB//EABUBAQEAAAAAAAAAAAAAAAAAAAAC/9oADAMBAAIQAxAAAAGjQS5H/8QAGBABAQEBAQAAAAAAAAAAAAAAAgMEAAX/2gAIAQEAAQUC9HbYaJJKTmE+/8QAFhEBAQEAAAAAAAAAAAAAAAAAAgAR/9oACAEDAQE/AScv/8QAFBEBAAAAAAAAAAAAAAAAAAAAAP/aAAgBAgEBPwF//8QAHxAAAgECBwAAAAAAAAAAAAAAAQIDABEEEBMUITFR/9oACAEBAAY/AsUdwY2jI04/aQslmI5oMyKWHRtl/8QAGhABAAMAAwAAAAAAAAAAAAAAAQARMRBBUf/aAAgBAQABPyFOB4HPtd3KY4ovGpvYACnH/9oADAMBAAIAAwAAABDb/8QAFhEBAQEAAAAAAAAAAAAAAAAAAREA/9oACAEDAQE/EESrbv/EABYRAQEBAAAAAAAAAAAAAAAAAAEAEf/aAAgBAgEBPxBdv//EABsQAQACAgMAAAAAAAAAAAAAAAEAIRARgaHB/9oACAEBAAE/EDyaVPB5UlLVgU4Z1DdcVNmP/9k=",
  "signature": "3045022100ebfde614a67d6f69c321664683b557a2eb605d7aa9357230684f49c1da4ccbef02203ab72beb9ffe1af76cb60b852b950baa2355c32ceb99715158e7e2d31a194f1d",
  "publicKey": "02aaee936deeb6d8296aa11d3134c624a2d8e72581ce49c73237f0359e4cf11949",
  "encoding": "base64",
  "mimetype": "image/jpeg"
}
"""

def test_json_envelope_samples() -> None:
    envelope_object = json.loads(example_utf8_json)
    validate_json_envelope(envelope_object, { "application/json" })

    envelope_object = json.loads(example_base64_image)
    with pytest.raises(ValueError) as exception_info:
        validate_json_envelope(envelope_object, { "image/jpeg" })
    assert "signature invalid" in exception_info.value.args[0]


def test_json_envelope_mimetype_acceptance() -> None:
    envelope_object = json.loads(example_utf8_json)
    envelope_object["mimetype"] = "morse"
    with pytest.raises(ValueError) as exception_info:
        validate_json_envelope(envelope_object, { "image/jpeg" })
    assert "mimetype not accepted" in exception_info.value.args[0]


def test_json_envelope_unsupported_encoding() -> None:
    envelope_object = json.loads(example_utf8_json)
    envelope_object["encoding"] = "morse"
    with pytest.raises(ValueError) as exception_info:
        validate_json_envelope(envelope_object)
    assert "encoding unknown" in exception_info.value.args[0]


def test_json_envelope_undecodable_payload() -> None:
    envelope_object = json.loads(example_utf8_json)
    envelope_object["encoding"] = "base64"
    envelope_object["payload"] = "dfgfggrwgrgrwgergw"
    # Changing details voids the signature so we clear it.
    envelope_object["signature"] = None
    with pytest.raises(ValueError) as exception_info:
        validate_json_envelope(envelope_object)
    assert "decoding errored" in exception_info.value.args[0]



taal_json_response_20210607 = r'{"payload":"{\"apiVersion\":\"1.1.0\",\"timestamp\":\"2021-06-07T00:51:14.666Z\",\"expiryTime\":\"2021-06-07T01:01:14.666Z\",\"minerId\":\"03e92d3e5c3f7bd945dfbf48e7a99393b1bfb3f11f380ae30d286e7ff2aec5a270\",\"currentHighestBlockHash\":\"000000000000000000200846e0db2397fd2a35289af3e42fed3eb764a6733829\",\"currentHighestBlockHeight\":690542,\"minerReputation\":null,\"fees\":[{\"id\":1,\"feeType\":\"standard\",\"miningFee\":{\"satoshis\":500,\"bytes\":1000},\"relayFee\":{\"satoshis\":250,\"bytes\":1000}},{\"id\":2,\"feeType\":\"data\",\"miningFee\":{\"satoshis\":500,\"bytes\":1000},\"relayFee\":{\"satoshis\":250,\"bytes\":1000}}]}","signature":"304502210083dcbde7fc1f73f2e2998b426821d6a8d3507b4ccc097f6ab4c648d76ce06671022016f6efdfa28be8d2fefb3b57b425882a4a82cf7e565269fe3d7d890d028921b5","publicKey":"03e92d3e5c3f7bd945dfbf48e7a99393b1bfb3f11f380ae30d286e7ff2aec5a270","encoding":"UTF-8","mimetype":"application/json"}' # pylint: disable=line-too-long


def test_fee_quote_response_invalid_signature() -> None:
    invalid_response = taal_json_response_20210607.replace("83dcbde", "decb3d8")
    # Ensure that the signature we are invalidating was present.
    assert invalid_response != taal_json_response_20210607
    real_response = cast(JSONEnvelope, json.loads(invalid_response))
    with pytest.raises(ValueError) as exception_info:
        validate_json_envelope(real_response)
    assert "signature invalid" in exception_info.value.args[0]


def test_fee_quote_response_valid_signature() -> None:
    real_response = cast(JSONEnvelope, json.loads(taal_json_response_20210607))
    validate_json_envelope(real_response)


def test_fee_quote_response_no_signature() -> None:
    # Test that if there is no signature and no public key we consider it good, whatever that
    # means. Ideally we would have a response from a MAPI server to test for this, but currently
    # we do not.
    fake_response_dict = {
        "payload": "",
        "signature": None,
        "publicKey": None,
        "encoding": "utf-8",
        "mimetype": None,
    }
    fake_response = cast(JSONEnvelope, fake_response_dict)
    validate_json_envelope(fake_response)

