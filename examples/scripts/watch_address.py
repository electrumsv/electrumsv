#!/usr/bin/env python3

import sys
import time
from electrumsv.simple_config import SimpleConfig
from electrumsv.network import Network
from electrumsv.util import json_encode
from electrumsv.address import Address

try:
    addr = Address.from_string(sys.argv[1])
except Exception:
    print("usage: watch_address <bitcoin_address>")
    sys.exit(1)

# start network
c = SimpleConfig()
network = Network(c)
network.start()

# wait until connected
while network.is_connecting():
    time.sleep(0.1)

if not network.is_connected():
    print("daemon is not connected")
    sys.exit(1)

# 2. send the subscription
sh = addr.to_scripthash_hex()
callback = lambda response: print(json_encode(response.get('result')))
network.send([('blockchain.scripthash.subscribe',[sh])], callback)

# 3. wait for results
while network.is_connected():
    time.sleep(1)
