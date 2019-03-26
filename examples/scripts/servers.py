#!/usr/bin/env python3

import json
import util

from electrumsv.logs import logs
from electrumsv.network import filter_version

logs.set_level('ERROR')

servers = filter_version(util.get_peers())
print(json.dumps(servers, sort_keys = True, indent = 4))
