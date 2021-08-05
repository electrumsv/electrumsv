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
from abc import ABC
import concurrent.futures
import os
import shutil
import time
from types import TracebackType
from typing import Any, Callable, cast, Coroutine, Optional, Tuple, Type, TYPE_CHECKING, TypeVar

from bitcoinx import Headers

from .async_ import ASync
from .constants import MAX_INCOMING_ELECTRUMX_MESSAGE_MB
from .credentials import CredentialCache
from .logs import logs
from .networks import Net
from .simple_config import SimpleConfig
from .startup import package_dir
from .util import format_satoshis

if TYPE_CHECKING:
    from .daemon import Daemon
    from .exchange_rate import FxTask
    from .gui.qt.app import SVApplication
    from .gui.qt.app_state import QtAppStateProxy


T1 = TypeVar("T1")

logger = logs.get_logger("app_state")


class ExceptionHandlerABC(ABC):
    def handler(self, exc_type: Type[BaseException], exc_value: BaseException,
            traceback: TracebackType) -> None:
        raise NotImplementedError


class DefaultApp(object):
    def __init__(self) -> None:
        pass

    def run_app(self) -> None:
        global app_state
        while app_state.daemon.is_running():
            time.sleep(0.5)

    def setup_app(self) -> None:
        # app_state.daemon's __init__ is called after app_state.app's.
        # Initialise things dependent upon app_state.daemon here."""
        return

    def new_window(self, path: Optional[str], uri: Optional[str]=None) -> None:
        raise NotImplementedError

    def run_coro(self, coro: Callable[..., Coroutine[Any, Any, T1]], *args: Any,
            on_done: Optional[Callable[[concurrent.futures.Future[T1]], None]]=None) \
                -> concurrent.futures.Future[T1]:
        global app_state
        return app_state.async_.spawn(coro, *args, on_done=on_done)


class AppStateProxy(object):
    app: DefaultApp
    base_units = ['BSV', 'mBSV', 'bits', 'sats']    # large to small
    decimal_points = [8, 5, 2, 0]

    daemon: "Daemon"
    fx: Optional["FxTask"] = None

    # Avoid wider dependencies by not using a reference to the config type.
    def __init__(self, config: SimpleConfig, gui_kind: str) -> None:
        from .device import DeviceMgr
        self.config = config
        self.gui_kind = gui_kind
        # Call this now so any code, such as DeviceMgr's constructor, can use us
        AppState.set_proxy(self)
        self.device_manager = DeviceMgr()
        self.credentials = CredentialCache()
        self.headers: Optional[Headers] = None
        # Not entirely sure these are worth caching, but preserving existing method for now
        self.decimal_point = config.get_explicit_type(int, 'decimal_point', 8)
        self.num_zeros = config.get_explicit_type(int, 'num_zeros', 0)
        self.async_ = ASync()

        self._migrate()

    def _migrate(self) -> None:
        # Remove the old headers file that used checkpointing in 1.3.13 and earlier, and had gaps
        # that needed to be filled before the checkpoint. It is easier to just delete it and
        # replace it.
        checkpointed_headers_filepath = os.path.join(self.config.path, "headers")
        if os.path.exists(checkpointed_headers_filepath):
            os.remove(checkpointed_headers_filepath)

        # NOTE(rt12) It takes me 50 minutes and gets me continually disconnected from every
        #   server for excessive resource usage, to download the 697505 headers in the initial
        #   version of this file. From 1.4.0 and beyond, we provide and facilitate keeping
        #   a copy of all headers in the wallet.
        headers2_filepath = os.path.join(self.config.path, "headers2")
        if Net.is_mainnet() and not os.path.exists(headers2_filepath):
            base_headers2_filepath = os.path.join(package_dir, "data", "headers_mainnet")
            shutil.copyfile(base_headers2_filepath, headers2_filepath)

    def shutdown(self) -> None:
        self.credentials.close()

    def has_app(self) -> bool:
        return self.app is not None

    # NOTE(app-metaclass-typing) This should be more an abstract base class that both `DefaultApp`
    #   or `SVApplication` derive from. However, that likely forces down the unholy path of
    #   multiple inheritance so maybe just pretending that `DefaultApp` is the base class is
    #   good enough for now.
    def set_app(self, app: DefaultApp) -> None:
        self.app = app

    @property
    def app_qt(self) -> "SVApplication":
        # NOTE(app-metaclass-typing)
        # We do not have anything more than the nebulous type checking reference to the QT
        # application type. We shouldn't either, so we just for now resolve this whole metaclassed
        # app problem by ensuring it's not the default headless app.
        assert type(self.app) is not DefaultApp
        return cast("SVApplication", self.app)

    def headers_filename(self) -> str:
        # 1.3.13 and earlier was "headers", renamed due to stopping checkpointing.
        return os.path.join(self.config.path, 'headers2')

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
            self.config.get_explicit_type(int, 'electrumx_message_size_limit',
                MAX_INCOMING_ELECTRUMX_MESSAGE_MB))

    def set_electrumx_message_size_limit(self, maximum_size: int) -> None:
        assert maximum_size >= 0, f"invalid cache size {maximum_size}"
        self.config.set_key('electrumx_message_size_limit', max(0, maximum_size))



class _AppStateMeta(type):

    def __getattr__(cls, attr: str) -> Any:
        return getattr(cls._proxy, attr)

    def __setattr__(cls, attr: str, value: Any) -> None:
        if attr == '_proxy':
            super().__setattr__(attr, value)
        return setattr(cls._proxy, attr, value)


class AppState(metaclass=_AppStateMeta):
    _proxy: Optional[AppStateProxy] = None

    @classmethod
    def set_proxy(cls, proxy: AppStateProxy) -> None:
        cls._proxy = proxy


# NOTE(app-metaclass-typing) The `app` and `app_state` objects can either be the default headless
#   versions present here or at least the current other option of the extended version from the GUI.
#   The typing support does not work for both metaclasses and inheritance, so the best I (rt12) can
#   come up with at this time is to have two different copies of each metaclass proxied variable
#   using the type that we want it as.
#
#   It is not possible to have module-level properties, so fetching the

app_state = cast(AppStateProxy, AppState)
def get_app_state_qt() -> "QtAppStateProxy":
    assert type(app_state) is not AppStateProxy
    return cast("QtAppStateProxy", app_state)


def attempt_exception_reporting(exc_type: Type[BaseException], exc_value: BaseException,
        traceback: TracebackType) -> bool:
    # Assume that any non-default app is GUI for now.
    if isinstance(app_state.app, DefaultApp):
        return False
    if app_state.app_qt.exception_hook is None:
        return False
    app_state.app_qt.exception_hook.handler(exc_type, exc_value, traceback)
    return True


