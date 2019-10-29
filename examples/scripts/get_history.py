#!/usr/bin/env python3

import sys

from electrumsv.network import Network
from electrumsv.util import json_encode
from electrumsv.bitcoin import address_from_string

try:
    addr = sys.argv[1]
except Exception:
    print("usage: get_history <bitcoin_address>")
    sys.exit(1)

n = Network()
n.start()
sh = address_from_string(addr).to_scripthash_hex()
h = n.synchronous_get(('blockchain.scripthash.get_history',[sh]))
print(json_encode(h))
