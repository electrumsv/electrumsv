from __future__ import annotations
from typing import Literal, TYPE_CHECKING, TypedDict


if TYPE_CHECKING:
    from ..types import FeeQuoteTypeEntry1, FeeQuoteTypeEntry2, FeeQuoteTypeFee


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
    fees: list[FeeQuoteTypeEntry1]


def convert_mapi_fees(fees: list[FeeQuoteTypeEntry1]) -> FeeQuoteTypeEntry2:
    """
    MAPI historically contained a list of fees for two different types, mining and relay.

    Raises `ValueError` if the MAPI fee quote is not correctly structured.
    """
    data_fees: FeeQuoteTypeFee|None = None
    standard_fees: FeeQuoteTypeFee|None = None
    for fee_dict in fees:
        if fee_dict["feeType"] == "data":
            data_fees = fee_dict["miningFee"]
        elif fee_dict["feeType"] == "standard":
            standard_fees = fee_dict["miningFee"]

    if standard_fees is None:
        raise ValueError("MAPI fee quote is corrupt")
    if data_fees is None:
        data_fees = standard_fees
    return { "data": data_fees, "standard": standard_fees }

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

