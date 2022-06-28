import binascii
import codecs
from typing import TypedDict

from bitcoinx import PublicKey


class JSONEnvelope(TypedDict):
    payload: str
    signature: str | None
    publicKey: str | None
    encoding: str
    mimetype: str


def validate_json_envelope(envelope_object: JSONEnvelope,
        accepted_mime_types: set[str] | None=None) -> None:
    """
    Check that the contents of the JSON envelope are signed against MinerID signatures.

    NOTE(MinerID) This is currently just a consistency check for several reasons:
    - Not all miners include MinerID documents in their coinbase transactions.
    - There is no current way to get coinbase transactions anyway.
    - There can be no requirement to check signature until the preceding issues are addressed.

    See also https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope

    Raises `ValueError` to indicate that the signature is not valid for the payload.
    Raises `ValueError` to indicate that encoding is not supported.
    """
    message_bytes = envelope_object["payload"].encode()
    if envelope_object["signature"] is not None and envelope_object["publicKey"] is not None:
        signature_bytes = bytes.fromhex(envelope_object["signature"])
        # TODO(MinerID) If a miner signs their JSON envelopes, the public key they include
        #     should match the one that comes from their miner id entry in their coinbases.
        #     Currently we have no way to get coinbase transactions, so we have no way to get
        #     the announced public key to compare.
        public_key = PublicKey.from_hex(envelope_object["publicKey"])
        if not public_key.verify_der_signature(signature_bytes, message_bytes):
            raise ValueError("JSON envelope signature invalid")

    encoding = envelope_object['encoding'].lower()
    if encoding not in ("utf-8", "base64"):
        raise ValueError(f"JSON envelope payload encoding unknown (encoding '{encoding}')")

    try:
        codecs.decode(message_bytes, encoding)
    except binascii.Error:
        raise ValueError(f"JSON envelope payload decoding errored (encoding '{encoding}')")

    # TODO(JSONEnvelope) We can check if the payload decodes as the given `mimetype`,
    #     e.g. most likely to be `application/json`.
    mimetype = envelope_object["mimetype"]
    if accepted_mime_types is not None and mimetype not in accepted_mime_types:
        raise ValueError(f"JSON envelope mimetype not accepted (mimetype '{mimetype}')")
