# Electrum SV - lightweight Bitcoin SV client
# Copyright (C) 2019 The Electrum SV Developers
# Copyright (C) 2012 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

'''Global application state.   Use as follows:

from electrumsv.app_sate import app_state

app_state.config
app_state.daemon
app_state.func()

etc.
'''

import os
import threading

from bitcoinx import HeaderStorage, Headers, hash_to_hex_str

from .dnssec import resolve_openalias
from .logs import logs
from .networks import Net


logger = logs.get_logger("app_state")


class AppStateProxy(object):

    base_units = ['BSV', 'mBSV', 'bits', 'sats']    # large to small
    decimal_points = [8, 5, 2, 0]

    def __init__(self, config, gui_kind):
        from electrumsv.device import DeviceMgr

        self.config = config
        self.device_manager = DeviceMgr()
        self.gui_kind = gui_kind
        self.fx = None
        self.headers = None
        # Not entirely sure these are worth caching, but preserving existing method for now
        self.decimal_point = config.get('decimal_point', 8)
        self.num_zeros = config.get('num_zeros', 0)
        # Ugh
        self.fetch_alias()

    def headers_filename(self):
        return os.path.join(self.config.path, 'headers')

    def read_headers(self):
        storage = HeaderStorage(self.headers_filename(), Net.CHECKPOINT)
        storage.open_or_create()
        self.headers = Headers(Net.COIN, storage)
        for n, chain in enumerate(self.headers.chains(), start=1):
            logger.info(f'chain #{n}: height {chain.height:,d} work {chain.log2_work()} '
                        f'tip {hash_to_hex_str(chain.tip.hash)}')

    def base_unit(self):
        index = self.decimal_points.index(self.decimal_point)
        return self.base_units[index]

    def set_base_unit(self, base_unit):
        prior = self.decimal_point
        index = self.base_units.index(base_unit)
        self.decimal_point = self.decimal_points[index]
        if self.decimal_point != prior:
            self.config.set_key('decimal_point', self.decimal_point, True)
        return self.decimal_point != prior

    def set_alias(self, alias):
        self.config.set_key('alias', alias, True)
        if alias:
            self.fetch_alias()

    def fetch_alias(self):
        self.alias_info = None
        alias = self.config.get('alias')
        if alias:
            alias = str(alias)
            def f():
                self.alias_info = resolve_openalias(alias)
                self.alias_resolved()
            t = threading.Thread(target=f)
            t.setDaemon(True)
            t.start()

    def alias_resolved(self):
        '''Derived classes can hook into this.'''
        pass


class _AppStateMeta(type):

    def __getattr__(cls, attr):
        return getattr(cls._proxy, attr)

    def __setattr__(cls, attr, value):
        if attr == '_proxy':
            super().__setattr__(attr, value)
        return setattr(cls._proxy, attr, value)


class AppState(metaclass=_AppStateMeta):

    _proxy = None

    @classmethod
    def set_proxy(cls, proxy):
        cls._proxy = proxy


app_state = AppState
