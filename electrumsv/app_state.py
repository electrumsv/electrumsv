# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019 The ElectrumSV Developers
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

from bitcoinx import Headers

from .logs import logs
from .networks import Net


logger = logs.get_logger("app_state")


class AppStateProxy(object):
    app = None
    base_units = ['BSV', 'mBSV', 'bits', 'sats']    # large to small
    decimal_points = [8, 5, 2, 0]

    # Avoid wider dependencies by not using a reference to the config type.
    def __init__(self, config: 'SimpleConfig', gui_kind: str) -> None:
        from electrumsv.device import DeviceMgr
        self.config = config
        self.gui_kind = gui_kind
        # Call this now so any code, such as DeviceMgr's constructor, can use us
        AppState.set_proxy(self)
        self.device_manager = DeviceMgr()
        self.fx = None
        self.headers = None
        # Not entirely sure these are worth caching, but preserving existing method for now
        self.decimal_point = config.get('decimal_point', 8)
        self.num_zeros = config.get('num_zeros', 0)

    def has_app(self):
        return self.app is not None

    def headers_filename(self) -> str:
        return os.path.join(self.config.path, 'headers')

    def read_headers(self) -> None:
        self.headers = Headers.from_file(Net.COIN, self.headers_filename(), Net.CHECKPOINT)
        for n, chain in enumerate(self.headers.chains(), start=1):
            logger.info(f'chain #{n}: {chain.desc()}')

    def base_unit(self) -> str:
        index = self.decimal_points.index(self.decimal_point)
        return self.base_units[index]

    def set_base_unit(self, base_unit: str) -> bool:
        prior = self.decimal_point
        index = self.base_units.index(base_unit)
        self.decimal_point = self.decimal_points[index]
        if self.decimal_point != prior:
            self.config.set_key('decimal_point', self.decimal_point, True)
        return self.decimal_point != prior


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
