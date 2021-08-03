import json
import os
from typing import cast, List, Sequence

from bitcoinx import bip32_key_from_string, BIP32PublicKey, BitcoinRegtest, PrivateKey
import requests


BITCOIN_NODE_HOST = os.environ.get("BITCOIN_NODE_HOST") or "127.0.0.1"
BITCOIN_NODE_PORT = os.environ.get("BITCOIN_NODE_PORT") or 18332
BITCOIN_NODE_RPCUSER = os.environ.get("BITCOIN_NODE_RPCUSER") or "rpcuser"
BITCOIN_NODE_RPCPASSWORD = os.environ.get("BITCOIN_NODE_RPCPASSWORD") or "rpcpassword"
BITCOIN_NODE_URI = f"http://{BITCOIN_NODE_RPCUSER}:{BITCOIN_NODE_RPCPASSWORD}" \
                   f"@{BITCOIN_NODE_HOST}:{BITCOIN_NODE_PORT}"


# Node mining wallet.
REGTEST_FUNDS_PRIVATE_KEY: PrivateKey = PrivateKey(
    bytes.fromhex('a2d9803c912ab380c1491d3bd1aaab34ca06742d7885a224ec8d386182d26ed2'),
    coin=BitcoinRegtest)
REGTEST_FUNDS_PRIVATE_KEY_WIF = REGTEST_FUNDS_PRIVATE_KEY.to_WIF()


# ESV mining wallet.
MINING_XPUB = "tpubD6NzVbkrYhZ4XTahhmjJgckNiZiTNJBLtY5fxsxbHj2wARR8TWu7WQLtw1bZfftBqUXKEiGe5" \
    "XqVp8feMr3c41Rn4pXPP9yZ3KrD9cvuHL3"

def mining_address_generator(parent_path: Sequence[int]) -> str:
    xpubkey = cast(BIP32PublicKey, bip32_key_from_string(MINING_XPUB))
    for n in parent_path:
        xpubkey = xpubkey.child_safe(n)
    idx = 0
    while True:
        yield xpubkey.child_safe(idx).to_address(coin=BitcoinRegtest).to_string()
        idx += 1


def regtest_generate_nblocks(nblocks: int, address: str) -> List:
    payload1 = json.dumps(
        {"jsonrpc": "2.0", "method": "generatetoaddress", "params": [nblocks, address],
         "id": 0})
    result = requests.post(BITCOIN_NODE_URI, data=payload1)
    result.raise_for_status()
    block_hashes = []
    for block_hash in result.json()['result']:
        block_hashes.append(block_hash)
    return block_hashes
