from __future__ import annotations
from typing import Any, Literal, TYPE_CHECKING, TypedDict


if TYPE_CHECKING:
    from ..types import FeeQuoteTypeEntry


# A MAPI fee quote is packaged according to the JSON envelope BRFC.
# https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope
class FeeQuote(TypedDict):
    # https://github.com/bitcoin-sv-specs/brfc-merchantapi#1-get-fee-quote
    apiVersion: str
    timestamp: str
    expiryTime: str
    minerId: str
    currentHighestBlockHash: str
    currentHighestBlockHeight: int
    fees: list[FeeQuoteTypeEntry]


class MAPIBroadcastConflict(TypedDict):
    txid: str # Canonical hex transaction id.
    size: int
    hex: str


# A MAPI broadcast response is packaged according to the JSON envelope BRFC.
# https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope
class MAPIBroadcastResponse(TypedDict):
    # https://github.com/bitcoin-sv-specs/brfc-merchantapi#2-submit-transaction
    apiVersion: str
    timestamp: str
    txid: str                       # Canonical hex transaction id.
    returnResult: Literal["success", "failure"]
    resultDescription: str          # "" or "<error message>"
    minerId: str
    currentHighestBlockHash: str
    currentHighestBlockHeight: int
    txSecondMempoolExpiry: int
    conflictedWith: list[MAPIBroadcastConflict]

    # if returnResult is "failure" this allows for deleting the peer channel database entry
    peer_channel_id: int
    remote_channel_id: str


def _validate_mapi_broadcast_conflicted_with(data: MAPIBroadcastConflict) -> None:
    if "txid" not in data:
        raise ValueError("Missing conflict 'txid' field")
    if not isinstance(data["txid"], str):
        raise ValueError("Invalid conflict 'txid' type, expected str, "
            f"got {type(data['txid'])}")

    if "size" not in data:
        raise ValueError("Missing conflict 'size' field")
    if not isinstance(data["size"], int):
        raise ValueError("Invalid conflict 'size' type, expected int, "
            f"got {type(data['size'])}")

    if "hex" not in data:
        raise ValueError("Missing conflict 'hex' field")
    if not isinstance(data["hex"], str):
        raise ValueError("Invalid conflict 'hex' type, expected str, "
            f"got {type(data['hex'])}")


def validate_mapi_broadcast_response(response_data: MAPIBroadcastResponse) -> None:
    """
    MAPI broadcast response validation.
    Examples: https://github.com/bitcoin-sv-specs/brfc-merchantapi#2-submit-transaction

    Raises `ValueError` if the response does not match the expected result.
    """
    if "apiVersion" not in response_data:
        raise ValueError("Missing 'apiVersion' field")
    if not isinstance(response_data["apiVersion"], str):
        raise ValueError("Invalid 'apiVersion' type, expected str, "
            f"got {type(response_data['apiVersion'])}")

    if "timestamp" not in response_data:
        raise ValueError("Missing 'timestamp' field")
    if not isinstance(response_data["timestamp"], str):
        raise ValueError("Invalid 'timestamp' type, expected str, "
            f"got {type(response_data['timestamp'])}")

    if "txid" not in response_data:
        raise ValueError("Missing 'txid' field")
    if not isinstance(response_data["txid"], str):
        raise ValueError("Invalid 'txid' type, expected str, "
            f"got {type(response_data['txid'])}")

    if "returnResult" not in response_data:
        raise ValueError("Missing 'returnResult' field")
    if not isinstance(response_data["returnResult"], str):
        raise ValueError("Invalid 'returnResult' type, expected str, "
            f"got {type(response_data['returnResult'])}")

    if "resultDescription" not in response_data:
        raise ValueError("Missing 'resultDescription' field")
    if not isinstance(response_data["resultDescription"], str):
        raise ValueError("Invalid 'resultDescription' type, expected str, "
            f"got {type(response_data['resultDescription'])}")

    if "minerId" not in response_data:
        raise ValueError("Missing 'minerId' field")
    if not isinstance(response_data["minerId"], str):
        raise ValueError("Invalid 'minerId' type, expected str, "
            f"got {type(response_data['minerId'])}")

    if "currentHighestBlockHash" not in response_data:
        raise ValueError("Missing 'currentHighestBlockHash' field")
    if not isinstance(response_data["currentHighestBlockHash"], str):
        raise ValueError("Invalid 'currentHighestBlockHash' type, expected str, "
            f"got {type(response_data['currentHighestBlockHash'])}")

    if "currentHighestBlockHeight" not in response_data:
        raise ValueError("Missing 'currentHighestBlockHeight' field")
    if not isinstance(response_data["currentHighestBlockHeight"], int):
        raise ValueError("Invalid 'currentHighestBlockHeight' type, expected int, "
            f"got {type(response_data['currentHighestBlockHeight'])}")

    if "txSecondMempoolExpiry" not in response_data:
        raise ValueError("Missing 'txSecondMempoolExpiry' field")
    if not isinstance(response_data["txSecondMempoolExpiry"], int):
        raise ValueError("Invalid 'txSecondMempoolExpiry' type, expected int, "
            f"got {type(response_data['txSecondMempoolExpiry'])}")

    return_result = response_data["returnResult"]
    if return_result == "success":
        pass

    elif return_result == "failure":
        if "conflictedWith" in response_data:
            if not isinstance(response_data["conflictedWith"], list):
                raise ValueError("Invalid 'conflictedWith' type, expected list, "
                    f"got {type(response_data['conflictedWith'])}")
            for conflict_entry in response_data["conflictedWith"]:
                _validate_mapi_broadcast_conflicted_with(conflict_entry)
    else:
        raise ValueError(f"Invalid 'returnResult' '{return_result}'")

MapiCallbackReasonNames = Literal["doubleSpend", "doubleSpendAttempt", "merkleProof"]
MAPI_CALLBACK_REASONS: set[MapiCallbackReasonNames] = {"doubleSpend", "doubleSpendAttempt",
    "merkleProof"}


class MAPICallbackResponse(TypedDict):
    callbackPayload: dict[str, Any]
    apiVersion: str
    timestamp: str
    minerId: str | None
    blockHash: str
    blockHeight: int
    callbackTxId: str
    callbackReason: MapiCallbackReasonNames


class MAPICallbackDoubleSpendPayload(TypedDict):
    doubleSpendTxId: str
    payload: str


def validate_mapi_callback_response(response_data: MAPICallbackResponse) -> None:
    """
    MAPI callback response validation.
    Examples: https://github.com/bitcoin-sv-specs/brfc-merchantapi#callback-notifications

    Raises `ValueError` if the response does not match the expected result.
    """
    if "callbackPayload" not in response_data:
        raise ValueError("Missing 'callbackPayload' field")
    if not isinstance(response_data["callbackPayload"], dict):
        raise ValueError(f"Invalid 'callbackPayload' type, expected dict, "
            f"got {type(response_data['callbackPayload'])}")

    if "apiVersion" not in response_data:
        raise ValueError("Missing 'apiVersion' field")
    if not isinstance(response_data["apiVersion"], str):
        raise ValueError(f"Invalid 'apiVersion' type, expected str, "
            f"got {type(response_data['apiVersion'])}")

    if "timestamp" not in response_data:
        raise ValueError("Missing 'timestamp' field")
    if not isinstance(response_data["timestamp"], str):
        raise ValueError(f"Invalid 'timestamp' type, expected str, "
            f"got {type(response_data['timestamp'])}")

    if "minerId" not in response_data:
        raise ValueError("Missing 'minerId' field")
    if response_data["minerId"] is not None and not isinstance(response_data["minerId"], str):
        raise ValueError(f"Invalid 'minerId' type, expected str or None, "
            f"got {type(response_data['minerId'])}")

    if "blockHash" not in response_data:
        raise ValueError("Missing 'blockHash' field")
    if not isinstance(response_data["blockHash"], str):
        raise ValueError(f"Invalid 'blockHash' type, expected str, "
            f"got {type(response_data['blockHash'])}")

    if "blockHeight" not in response_data:
        raise ValueError("Missing 'blockHeight' field")
    if not isinstance(response_data["blockHeight"], int):
        raise ValueError(f"Invalid 'blockHeight' type, expected int, "
            f"got {type(response_data['blockHeight'])}")

    if "callbackTxId" not in response_data:
        raise ValueError("Missing 'callbackTxId' field")
    if not isinstance(response_data["callbackTxId"], str):
        raise ValueError(f"Invalid 'callbackTxId' type, expected str, "
            f"got {type(response_data['callbackTxId'])}")

    if "callbackReason" not in response_data:
        raise ValueError("Missing 'callbackReason' field")
    if not isinstance(response_data["callbackReason"], str):
        raise ValueError(f"Invalid 'callbackReason' type, expected str, "
            f"got {type(response_data['callbackReason'])}")

    if response_data["callbackReason"] == "doubleSpend":
        # TODO(technical-debt) Need to validate the mapi callback response payload (double spend).
        pass
    elif response_data["callbackReason"] == "doubleSpendAttempt":
        # TODO(technical-debt) Need to validate the mapi callback response payload (double spend a).
        pass
    elif response_data["callbackReason"] == "merkleProof":
        # TODO(technical-debt) Need to validate the mapi callback response payload (merkle proof).
        pass
    else:
        raise ValueError(f"Invalid 'callbackReason' '{response_data['callbackReason']}'")

    block_id = response_data["blockHash"]
    if len(block_id) != 32*2:
        raise ValueError(f"'blockHash' not 64 characters '{response_data['blockHash']}'")

    transaction_id = response_data["callbackTxId"]
    if len(transaction_id) != 32*2:
        raise ValueError(f"'callbackTxId' not 64 characters '{response_data['callbackTxId']}'")

    # This is optional and should be a 33 byte public key encoding.
    # https://github.com/bitcoin-sv-specs/brfc-minerid#321-static-coinbasedocument-template
    miner_id = response_data["minerId"]
    if miner_id is not None and len(miner_id) != 33*2:
        raise ValueError(f"'minerId' not 66 characters '{response_data['minerId']}'")
