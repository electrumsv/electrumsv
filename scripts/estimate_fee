#!/usr/bin/env python
import json
import util

peers = util.get_peers()
results = util.send_request(peers, 'blockchain.estimatefee', [2])
print(json.dumps(results, indent=4))
