from __future__ import annotations
from io import BytesIO
import os

from bitcoinx import Script

from ..transaction import Transaction, XPublicKey, XTxInput
from ..types import Outpoint

from .script_templates import CoinData, parse_script_sig


def process_transaction_input(transaction_input: XTxInput, coin_data: CoinData|None=None) -> None:
    """
    A incomplete node transaction has a script with placeholder empty signatures. This maps those
    scripts to what ElectrumSV expects for an incomplete transaction.
    """
    script_sig_bytes = bytes(transaction_input.script_sig)

    assert transaction_input.script_offset != 0

    # Ignore unsigned single signature inputs (which will be empty).
    # Ignore coinbase inputs (which will not be spending a UTXO).
    if script_sig_bytes != b"" and transaction_input.prev_hash != bytes(32):
        script_data = parse_script_sig(script_sig_bytes, XPublicKey.from_bytes,
            signature_placeholder=b"", coin_data=coin_data)
        transaction_input.x_pubkeys = script_data.x_pubkeys
        transaction_input.threshold = script_data.threshold
        transaction_input.signatures = script_data.signatures
        transaction_input.script_type = script_data.script_type

        # ElectrumSV use an empty `script_sig` on incomplete `XTxInput` objects.
        if len(script_data.signatures) < script_data.threshold:
            transaction_input.script_sig = Script(b"")

def transaction_from_node_stream(stream: BytesIO, coin_datas: dict[Outpoint, CoinData]) \
        -> Transaction:
    transaction = Transaction.read(stream.read, stream.tell)
    for transaction_input in transaction.inputs:
        outpoint = Outpoint(transaction_input.prev_hash, transaction_input.prev_idx)
        coin_data = coin_datas.get(outpoint)
        process_transaction_input(transaction_input, coin_data)
    return transaction

def transactions_from_node_stream(stream: BytesIO, coin_datas: dict[Outpoint, CoinData]) \
        -> list[Transaction]:
    stream.seek(0, os.SEEK_END)
    stream_length = stream.tell()
    stream.seek(0, os.SEEK_SET)
    transactions: list[Transaction] = []
    while stream.tell() < stream_length:
        transactions.append(transaction_from_node_stream(stream, coin_datas))
    return transactions

def transaction_from_node_bytes(raw: bytes, coin_datas: dict[Outpoint, CoinData]) -> Transaction:
    stream = BytesIO(raw)
    return transaction_from_node_stream(stream, coin_datas)

def transactions_from_node_bytes(raw: bytes, coin_datas: dict[Outpoint, CoinData]) \
        -> list[Transaction]:
    stream = BytesIO(raw)
    return transactions_from_node_stream(stream, coin_datas)

