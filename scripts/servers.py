#!/usr/bin/env python3

import json
import util

from electrumsv.util import disable_verbose_logging
from electrumsv.network import filter_version

disable_verbose_logging()

servers = filter_version(util.get_peers())
print(json.dumps(servers, sort_keys = True, indent = 4))
