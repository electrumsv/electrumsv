"""
Generate test transaction metadata for the JSON-RPC node API
============================================================

This is currently used just for the ``signrawtransaction`` endpoint.

Goal
----

This script should generate readable test transaction metadata variations to be used as input to
the node API:

1. The parameters to the call.
2. The metadata required for mocking out wallet functionality as providing the correct backend
   data and functionality.
3. The expected return value from the call.

Usage
-----

This script outputs the JSON data to standard output, where it should be redirected to the
file the unit tests read from.

> py -3.10 contrib\scripts\generate_transactions_nodeapi.py >
    electrumsv\tests\data\node_api\signrawtransaction_ok.json
"""

import itertools
import json
from typing import Any, cast, NamedTuple
from typing_extensions import NotRequired, TypedDict

import bitcoinx

COIN = 100000000
DEFAULT_SIGHASH = bitcoinx.SigHash(bitcoinx.SigHash.ALL | bitcoinx.SigHash.FORKID)
FINAL_SEQUENCE = 0xFFFFFFFF

# Funding input key/script 1 (required).
funding_private_key1 = bitcoinx.PrivateKey.from_hex(
    "184d204bb152f4dbfc1726f4509634916f4aa09792566be98a4dbd8814cc4c80")
funding_public_key1 = funding_private_key1.public_key
funding_script_pubkey1 = funding_public_key1.P2PKH_script()
funding_transaction1_hash = b"\x11" * 32
funding_transaction1_index = 0
funding_transaction1_amount = 1000
funding_transaction1_output = bitcoinx.TxOutput(funding_transaction1_amount, funding_script_pubkey1)
funding_transaction1_after_genesis = True

# Funding input key/script 2 (optional).
funding_private_key2 = bitcoinx.PrivateKey.from_hex(
    "4572a9a7c76a1ac2fa6ad0086a256e7121c3073537b694a81b48325a1edfde20")
funding_public_key2 = funding_private_key2.public_key
funding_script_pubkey2 = funding_public_key2.P2PKH_script()
funding_transaction2_hash = b"\x22" * 32
funding_transaction2_index = 0
funding_transaction2_amount = 2000
funding_transaction2_output = bitcoinx.TxOutput(funding_transaction2_amount, funding_script_pubkey2)
funding_transaction2_after_genesis = False

payment_private_key = bitcoinx.PrivateKey.from_hex(
    "dff12c97af221e33e043f8de6f828e5ea1f778438a87a7388f3c1d989026ade5")
payment_public_key = payment_private_key.public_key
payment_script_pubkey = payment_public_key.P2PKH_script()


def sign_for_spend(transaction_with_input: bitcoinx.Tx, input_index: int, spent_value: int,
        spent_script_pubkey: bitcoinx.Script, sighash: bitcoinx.SigHash,
        signing_private_key: bitcoinx.PrivateKey) -> bytes:
    """
    Helper function to generate a pre-prepared signature for use in the static mocked test data.
    """
    message_hash = transaction_with_input.signature_hash(input_index, spent_value,
        spent_script_pubkey, sighash)
    # NOTE(typing) bitcoinx lacks type annotations so we explicitly cast to the known return type.
    return cast(bytes, signing_private_key.sign(message_hash, hasher=None) +
        bitcoinx.pack_byte(sighash))

def check_spending_signature(transaction_with_input: bitcoinx.Tx, input_index: int,
        spent_output: bitcoinx.TxOutput, is_spent_output_after_genesis: bool,
        signature_bytes: bytes, public_key_bytes: bytes) -> bool:
    """
    Helper function to (hopefully) check that we are generating valid signatures.
    """
    input_context = bitcoinx.TxInputContext(transaction_with_input, input_index, spent_output,
        is_spent_output_after_genesis)
    # NOTE(typing) bitcoinx lacks type annotations so we explicitly cast to the known return type.
    return cast(bool,
        input_context.check_sig(signature_bytes, public_key_bytes, spent_output.script_pubkey))

# signature_bytes1 = sign_for_spend(payment_transaction1, 0, funding_transaction1_amount,
#     funding_script_pubkey1, SIGHASH, funding_private_key1)
# assert check_spending_signature(payment_transaction1, 0, funding_transaction1.outputs[0],
#     funding_transaction1_after_genesis, signature_bytes1,
#     funding_public_key1.to_bytes())


class SignRawTransactionErrorDict(TypedDict):
    txid: str
    vout: int
    scriptSig: str
    sequence: int
    error: str

class SignRawTransactionResultDict(TypedDict):
    hex: str
    complete: bool
    errors: NotRequired[list[SignRawTransactionErrorDict]]

class TransactionInputMetadata(NamedTuple):
    prev_hash: bytes
    prev_idx: int
    private_key: bitcoinx.PrivateKey
    parent_transaction_output: bitcoinx.TxOutput
    sequence: int = FINAL_SEQUENCE

TRANSACTION_INPUT_DATA = [
    TransactionInputMetadata(funding_transaction1_hash, funding_transaction1_index,
        funding_private_key1, funding_transaction1_output),
    TransactionInputMetadata(funding_transaction2_hash, funding_transaction2_index,
        funding_private_key2, funding_transaction2_output),
]

def generate_transaction(*, input_count: int, version: int=1, locktime: int=100000) -> bitcoinx.Tx:
    """
    Create an unsigned transaction with the specified number of inputs (empty `scriptSig`).
    """
    assert input_count > 0

    transaction_inputs: list[bitcoinx.TxInput] = []
    for transaction_input_index in range(input_count):
        input_metadata = TRANSACTION_INPUT_DATA[transaction_input_index]
        transaction_inputs.append(bitcoinx.TxInput(input_metadata.prev_hash,
            input_metadata.prev_idx, bitcoinx.Script(), input_metadata.sequence))

    transaction_outputs = [
        bitcoinx.TxOutput(funding_transaction1_amount + funding_transaction2_amount,
            payment_script_pubkey)
    ]
    return bitcoinx.Tx(version, transaction_inputs, transaction_outputs, locktime)

def generate_transaction_input_signature(transaction: bitcoinx.Tx, transaction_input_index: int,
        sighash: bitcoinx.SigHash=DEFAULT_SIGHASH) -> bytes:
    """
    Helper function to generate a pre-prepared signature for use in the static mocked test data.
    """
    assert transaction_input_index < len(transaction.inputs)
    input_metadata = TRANSACTION_INPUT_DATA[transaction_input_index]
    message_hash = transaction.signature_hash(transaction_input_index,
        input_metadata.parent_transaction_output.value,
        input_metadata.parent_transaction_output.script_pubkey, sighash)
    # NOTE(typing) bitcoinx lacks type annotations so we explicitly cast to the known return type.
    return cast(bytes, input_metadata.private_key.sign(message_hash, hasher=None) + \
        bitcoinx.pack_byte(sighash))

def insert_script_sig(transaction: bitcoinx.Tx, transaction_input_index: int,
        signature_bytes: bytes) -> None:
    assert transaction_input_index < len(transaction.inputs)
    input_metadata = TRANSACTION_INPUT_DATA[transaction_input_index]
    transaction.inputs[transaction_input_index].script_sig = \
        bitcoinx.Script(bitcoinx.push_item(signature_bytes) +
            bitcoinx.push_item(input_metadata.private_key.public_key.to_bytes()))

# This follows the convention of the JSON RPC parameter.
class MockPrevOutDict(TypedDict):
    txid: str
    vout: int
    scriptPubKey: str
    public_keys_hex: list[str]
    amount: NotRequired[int | str | float]
    is_spent: NotRequired[bool]

class MockDataDict(TypedDict):
    # Mapping of compressed public key hex to signature hex.
    signatures: dict[str, str]
    prevouts: list[MockPrevOutDict]

class TestCaseParameters(NamedTuple):
    test_case_label: str
    parameter_list: list[Any]
    mock_data: MockDataDict
    response: SignRawTransactionResultDict|None


def generate_test_data_signrawtransaction() -> list[TestCaseParameters]:
    test_cases: list[TestCaseParameters] = []

    # GROUPING: Transaction related to wallet.
    unique_test_case_ids: set[tuple[int, tuple[bool, ...]]] = set()
    for input_count, sign_input0, sign_input1 in itertools.product((1, 2), (True, False),
            (True, False)):
        # Only view the sign flags related to the current input count.
        input_sign_flags = [ sign_input0, sign_input1 ][:input_count]

        # Some combinations of ignored flags will be duplicates for lower input counts. Skip them.
        test_case_id = input_count, tuple(input_sign_flags)
        if test_case_id in unique_test_case_ids:
            continue
        unique_test_case_ids.add(test_case_id)

        transaction = generate_transaction(input_count=input_count)
        unsigned_transaction_hex = transaction.to_hex()

        signature_bytes_list: list[bytes] = []
        for input_index in range(input_count):
            if input_sign_flags[input_index]:
                signature_bytes = generate_transaction_input_signature(transaction, input_index,
                    DEFAULT_SIGHASH)
                signature_bytes_list.append(signature_bytes)
                insert_script_sig(transaction, input_index, signature_bytes)
            else:
                # Insert placeholder.
                signature_bytes_list.append(b"")

        signed_transaction_hex = transaction.to_hex()

        # FOCUS: Variations of different unsigned inputs that the wallet can or cannot sign.
        #     Correct signature and prevout entries will be present for signable inputs.
        parameters = TestCaseParameters(
            f"Transaction count: 1; input count: {input_count}; "
            f"inputs signable ({input_sign_flags}); criteria: prevout data and signature "
            "mocked as available for all signable inputs from wallet.",
            parameter_list=[ unsigned_transaction_hex, None, None, None ],
            mock_data={
                "signatures": {
                    TRANSACTION_INPUT_DATA[input_index].private_key.public_key.to_hex(
                        compressed=True): signature_bytes_list[input_index].hex()
                        for input_index in range(input_count) if input_sign_flags[input_index]
                },
                "prevouts": [
                    {
                        "txid": bitcoinx.hash_to_hex_str(
                            TRANSACTION_INPUT_DATA[input_index].prev_hash),
                        "vout": TRANSACTION_INPUT_DATA[input_index].prev_idx,
                        "scriptPubKey":
                            TRANSACTION_INPUT_DATA[input_index].parent_transaction_output. \
                                script_pubkey.to_hex(),
                        "amount":
                            COIN / TRANSACTION_INPUT_DATA[input_index]. \
                                parent_transaction_output.value,
                        "is_spent": False,
                        "public_keys_hex": [
                            TRANSACTION_INPUT_DATA[input_index].private_key.public_key.to_hex(
                                compressed=True)
                        ]
                    } for input_index in range(input_count) if input_sign_flags[input_index]
                ],
            },
            response={
                "hex": signed_transaction_hex,
                "complete": all(input_sign_flags),
            })
        if not all(input_sign_flags):
            assert parameters.response is not None
            parameters.response["errors"] = [
                {
                    "error": "Input not found or already spent",
                    "scriptSig": "",
                    "sequence": FINAL_SEQUENCE,
                    "txid": bitcoinx.hash_to_hex_str(TRANSACTION_INPUT_DATA[input_index].prev_hash),
                    "vout": TRANSACTION_INPUT_DATA[input_index].prev_idx
                } for input_index in range(input_count) if not input_sign_flags[input_index]
            ]
        test_cases.append(parameters)

        # FOCUS: Signatures present but failure anyway due to missing prevout wallet metadata.
        test_cases.append(
            TestCaseParameters(
                f"When one transaction with {input_count} unsigned input is expected to be signed "
                "by the wallet. Failure result because the prevout data is not present and it "
                "cannot be signed.",
                parameter_list=[ unsigned_transaction_hex, None, None, None ],
                mock_data={
                    "signatures": {
                        TRANSACTION_INPUT_DATA[input_index].private_key.public_key.to_hex(
                            compressed=True): signature_bytes_list[input_index].hex()
                            for input_index in range(input_count) if input_sign_flags[input_index]
                    },
                    "prevouts": [
                    ],
                },
                response={
                    "hex": unsigned_transaction_hex,
                    "errors": [
                        {
                            "error": "Input not found or already spent",
                            "scriptSig": "",
                            "sequence": FINAL_SEQUENCE,
                            "txid": bitcoinx.hash_to_hex_str(
                                TRANSACTION_INPUT_DATA[input_index].prev_hash),
                            "vout": TRANSACTION_INPUT_DATA[input_index].prev_idx
                        } for input_index in range(input_count)
                    ],
                    "complete": False,
                }))

        # FOCUS: Error on attempt to spend inputs the wallet already considered to be spent.
        test_cases.append(
            TestCaseParameters(
                f"When one transaction with {input_count} unsigned input is expected to be signed "
                "by the wallet. Failure result because the prevout data is present but already "
                "spent and so we refuse to sign it.",
                parameter_list=[ unsigned_transaction_hex, None, None, None ],
                mock_data={
                    "signatures": {
                        TRANSACTION_INPUT_DATA[input_index].private_key.public_key.to_hex(
                            compressed=True): signature_bytes_list[input_index].hex()
                            for input_index in range(input_count)
                    },
                    "prevouts": [
                        {
                            "txid": bitcoinx.hash_to_hex_str(TRANSACTION_INPUT_DATA[i].prev_hash),
                            "vout": TRANSACTION_INPUT_DATA[i].prev_idx,
                            "scriptPubKey": TRANSACTION_INPUT_DATA[i].parent_transaction_output. \
                                script_pubkey.to_hex(),
                            "amount":
                                COIN / TRANSACTION_INPUT_DATA[i].parent_transaction_output.value,
                            "is_spent": True,
                            "public_keys_hex": [
                                TRANSACTION_INPUT_DATA[i].private_key.public_key.to_hex(
                                    compressed=True)
                            ]
                        } for i in range(input_count)
                    ],
                },
                response={
                    "hex": unsigned_transaction_hex,
                    "errors": [
                        {
                            "error": "Input not found or already spent",
                            "scriptSig": "",
                            "sequence": FINAL_SEQUENCE,
                            "txid": bitcoinx.hash_to_hex_str(
                                TRANSACTION_INPUT_DATA[input_index].prev_hash),
                            "vout": TRANSACTION_INPUT_DATA[input_index].prev_idx
                        } for input_index in range(input_count)
                    ],
                    "complete": False,
                }))

    return test_cases

if __name__ == "__main__":
    test_cases = generate_test_data_signrawtransaction()
    print(json.dumps(test_cases, indent=4))
