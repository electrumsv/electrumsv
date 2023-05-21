# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019-2020 The ElectrumSV Developers
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
import time
from typing import Optional, Tuple, Union

from bitcoinx import Headers

from .async_ import ASync
from .constants import MAX_INCOMING_ELECTRUMX_MESSAGE_MB
from .logs import logs
from .networks import Net
from .simple_config import SimpleConfig
from .regtest_support import HeadersRegTestMod, setup_regtest
from .util import format_satoshis

logger = logs.get_logger("app_state")


class DefaultApp(object):
    def __init__(self):
        pass

    def run_app(self):
        global app_state
        while app_state.daemon.is_running():
            time.sleep(0.5)

    def setup_app(self):
        # app_state.daemon's __init__ is called after app_state.app's.
        # Initialise things dependent upon app_state.daemon here."""
        return

    def on_new_wallet_event(self, wallet_path, row) -> None:
        # hack - an expected api when resetting / creating a new wallet...
        pass


class AppStateProxy(object):
    app = None
    base_units = ['BSV', 'mBSV', 'bits', 'sats']    # large to small
    decimal_points = [8, 5, 2, 0]

    # Avoid wider dependencies by not using a reference to the config type.
    def __init__(self, config: SimpleConfig, gui_kind: str) -> None:
        from electrumsv.device import DeviceMgr
        self.config = config
        self.gui_kind = gui_kind
        # Call this now so any code, such as DeviceMgr's constructor, can use us
        AppState.set_proxy(self)
        self.device_manager = DeviceMgr()
        self.fx = None
        self.headers: Optional[Union[Headers, HeadersRegTestMod]] = None
        # Not entirely sure these are worth caching, but preserving existing method for now
        self.decimal_point = config.get('decimal_point', 8)
        self.num_zeros = config.get('num_zeros', 0)
        self.async_ = ASync()

    def has_app(self):
        return self.app is not None

    def set_app(self, app) -> None:
        self.app = app

    def headers_filename(self) -> str:
        return os.path.join(self.config.path, 'headers')

    def read_headers(self) -> None:
        if self.config.get('regtest'):
            self.headers = setup_regtest(self)
        else:
            self.headers = Headers.from_file(Net.COIN, self.headers_filename(), Net.CHECKPOINT)
        for n, chain in enumerate(self.headers.chains(), start=1):  # type: ignore
            logger.info(f'chain #{n}: {chain.desc()}')

    def on_stop(self) -> None:
        # The headers object may not be created for command-line invocations that do not require it.
        if self.headers is not None:
            logger.debug("Closing headers store")
            self.headers.flush()
            self.headers._storage.close()

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

    def format_amount(self, x: Optional[int], is_diff: bool=False, whitespaces: bool=False) -> str:
        return format_satoshis(x, self.num_zeros, self.decimal_point, is_diff=is_diff,
            whitespaces=whitespaces)

    def format_amount_and_units(self, amount: Optional[int]) -> str:
        text = self.format_amount(amount) + ' ' + self.base_unit()
        if self.fx and self.fx.is_enabled():
            x = self.fx.format_amount_and_units(amount)
            if text and x:
                text += ' (%s)'%x
        return text

    def get_amount_and_units(self, amount: int) -> Tuple[str, str]:
        bitcoin_text = self.format_amount(amount) + ' ' + self.base_unit()
        if self.fx and self.fx.is_enabled():
            fiat_text = self.fx.format_amount_and_units(amount)
        else:
            fiat_text = ''
        return bitcoin_text, fiat_text

    def electrumx_message_size_limit(self) -> int:
        return max(0,
            self.config.get('electrumx_message_size_limit', MAX_INCOMING_ELECTRUMX_MESSAGE_MB))

    def set_electrumx_message_size_limit(self, maximum_size: int) -> None:
        assert maximum_size >= 0, f"invalid cache size {maximum_size}"
        self.config.set_key('electrumx_message_size_limit', max(0, maximum_size))



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
