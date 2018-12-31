#!/usr/bin/env python

# A simple script that connects to a server and displays block headers

import sys
import time

from electrumsv.simple_config import SimpleConfig
from electrumsv.network import Network
from electrumsv.util import json_encode

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
callback = lambda response: print(json_encode(response.get('result')))
network.send([('server.version',["block_headers script", "1.2"])], callback)
network.send([('blockchain.headers.subscribe',[])], callback)

# 3. wait for results
while network.is_connected():
    time.sleep(1)
