from __future__ import annotations

from electrumsv.standards.node_transaction import transaction_from_node_bytes, \
    transactions_from_node_bytes


# Generated with `createrawtransaction`. The input script is empty.
P2PKH_TRANSACTION_HEX = \
    "02000000012240c035d2eb02308aa988fc953a46b07cf80fc109121c192a01e667f7d5b" \
    "41b0000000000ffffffff0140420f00000000001976a91443423852c99cb9825c2637f7" \
    "5ec386619132899088ac00000000"
P2PKH_TRANSACTION_BYTES = bytes.fromhex(P2PKH_TRANSACTION_HEX)


def test_transaction_from_node_bytes_p2pkh() -> None:
    transaction = transaction_from_node_bytes(P2PKH_TRANSACTION_BYTES, {})
    assert len(transaction.inputs) == 1
    # Check the enhanced parsing of inputs.
    assert len(transaction.inputs[0].signatures) == 0
    assert len(transaction.inputs[0].script_sig) == 0

def test_transactions_from_node_bytes_p2pkh() -> None:
    transactions_hex = P2PKH_TRANSACTION_BYTES * 4
    transactions = transactions_from_node_bytes(transactions_hex, {})
    assert len(transactions) == 4
    for transaction in transactions:
        # Check the enhanced parsing of inputs.
        assert len(transaction.inputs) == 1
        assert len(transaction.inputs[0].signatures) == 0
        assert len(transaction.inputs[0].script_sig) == 0
        # The nuances of output processing are less important as this is the default parsing.
        assert len(transaction.outputs) == 1
        assert transaction.outputs[0].value == 1000000
