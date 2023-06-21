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
from __future__ import annotations

from abc import ABC
import concurrent.futures
import os
import shutil
import threading
import time
from types import TracebackType
from typing import Any, Callable, cast, Coroutine, Type, TYPE_CHECKING, TypeVar

from bitcoinx import Chain, hash_to_hex_str, Header, MissingHeader

from .async_ import ASync
from .cached_headers import (
    HeaderPersistenceCursor, read_cached_headers, write_cached_headers
)
from .credentials import CredentialCache
from .logs import logs
from .networks import Net
from .simple_config import SimpleConfig
from .startup import package_dir
from .util import format_satoshis

if TYPE_CHECKING:
    from bitcoinx import Headers

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
        app_state.daemon.wait_for_shutdown()

    def setup_app(self) -> None:
        # app_state.daemon's __init__ is called after app_state.app's.
        # Initialise things dependent upon app_state.daemon here."""
        return

    def new_window(self, path: str | None, uri: str | None=None) -> None:
        raise NotImplementedError

    def run_coro(self, coro: Coroutine[Any, Any, T1],
            on_done: Callable[[concurrent.futures.Future[T1]], None] | None=None) \
                -> concurrent.futures.Future[T1]:
        global app_state
        return app_state.async_.spawn(coro, on_done=on_done)


class AppStateProxy(object):
    app: DefaultApp
    base_units = ['BSV', 'mBSV', 'bits', 'sats']    # large to small
    decimal_points = [8, 5, 2, 0]

    daemon: Daemon
    fx: FxTask | None = None
    _longest_chain_future: concurrent.futures.Future[None] | None = None

    # Avoid wider dependencies by not using a reference to the config type.
    def __init__(self, config: SimpleConfig, gui_kind: str) -> None:
        from .device import DeviceMgr
        self.config = config
        self.gui_kind = gui_kind
        # Call this now so any code, such as DeviceMgr's constructor, can use us
        AppState.set_proxy(self)
        self.device_manager = DeviceMgr()
        self.credentials = CredentialCache()
        self.headers: Headers | None = None
        self.headers_cursor: HeaderPersistenceCursor = {}
        self._headers_lock = threading.RLock()
        self._last_headers_save: float|None = time.time()
        # Not entirely sure these are worth caching, but preserving existing method for now
        self.decimal_point = config.get_explicit_type(int, 'decimal_point', 8)
        self.num_zeros = config.get_explicit_type(int, 'num_zeros', 0)
        self.async_ = ASync()

        self._migrate()

        # The network listens for new connected headers and tracks the longest valid chain.
        # This event should be triggered when someone calls `connect` on our `Headers` store.
        self.headers_update_event = self.async_.event()

    def _migrate(self) -> None:
        # Remove the old headers file that used checkpointing in 1.3.13 and earlier, and had gaps
        # that needed to be filled before the checkpoint. It is easier to just delete it and
        # replace it.
        checkpointed_headers_filepath = os.path.join(self.config.path, "headers")
        if os.path.exists(checkpointed_headers_filepath):
            os.remove(checkpointed_headers_filepath)

        # Remove headers2 file that has metadata at the beginning of the file (bitcoinx <=0.7.1)
        headers2_filepath = os.path.join(self.config.path, "headers2")
        if os.path.exists(headers2_filepath):
            os.remove(headers2_filepath)

        # 3.x versions are a plain raw headers dump (bitcoinx >= 0.8)
        headers3_filepath = os.path.join(self.config.path, "headers3")
        if Net.is_mainnet() and not os.path.exists(headers3_filepath):
            base_headers3_filepath = os.path.join(package_dir, "data", "headers3_mainnet")
            shutil.copyfile(base_headers3_filepath, headers3_filepath)

    def read_header3_base_file(self) -> bytes:
        """This is for a performance optimisation in read_cached_headers. These headers must
        perfectly align with the headers3_mainnet_blockhashes file"""
        headers3_filepath = os.path.join(package_dir, "data", "headers3_mainnet")
        with open(headers3_filepath, 'rb') as hf:
            return hf.read()

    def read_header3_base_file_hashes(self) -> list[bytes]:
        """This is for a performance optimisation in read_cached_headers. These block hashes must
        perfectly align with the headers3_mainnet file."""
        headers3_blockhashes_filepath = os.path.join(package_dir, "data",
            "headers3_mainnet_blockhashes")
        with open(headers3_blockhashes_filepath, 'rb') as hf:
            data = hf.read()
            hash_size = 32
            hashes = []
            for i in range(0, len(data), hash_size):
                block_hash = data[i:i + hash_size]
                hashes.append(block_hash)
            return hashes

    def shutdown(self) -> None:
        self.credentials.close()
        if self._longest_chain_future is not None:
            self._longest_chain_future.cancel()

    def has_app(self) -> bool:
        return self.app is not None

    # NOTE(app-metaclass-typing) This should be more an abstract base class that both `DefaultApp`
    #   or `SVApplication` derive from. However, that likely forces down the unholy path of
    #   multiple inheritance so maybe just pretending that `DefaultApp` is the base class is
    #   good enough for now.
    def set_app(self, app: DefaultApp) -> None:
        self.app = app

    @property
    def app_qt(self) -> SVApplication:
        # NOTE(app-metaclass-typing)
        # We do not have anything more than the nebulous type checking reference to the QT
        # application type. We shouldn't either, so we just for now resolve this whole metaclassed
        # app problem by ensuring it's not the default headless app.
        assert type(self.app) is not DefaultApp
        return cast("SVApplication", self.app)

    def headers_filename(self) -> str:
        # 1.3.13 and earlier was "headers", renamed due to stopping checkpointing.
        return os.path.join(self.config.path, 'headers3')

    def read_headers(self) -> None:
        base_headers = self.read_header3_base_file()
        base_header_hashes = self.read_header3_base_file_hashes()
        self.headers, self.headers_cursor = read_cached_headers(Net.COIN, self.headers_filename(),
            base_headers, base_header_hashes)
        for n, chain in enumerate(self.headers.chains(), start=1):
            logger.debug("chain #%d: %s", n, chain.desc())

        # The daemon is only running if the application has been started up in either online or
        # offline mode. In these cases we want to support header import, whether from the network
        # when online or even a user importing them perhaps when offline but not necessarily so.
        daemon = getattr(self, "daemon", None)
        if daemon is None:
            return

        self._longest_chain_future = self.async_.spawn(self._follow_longest_valid_chain())

    def lookup_header(self, block_hash: bytes) -> tuple[Header, Chain]:
        """
        Thread-safe version of bitcoinx's `Headers` object `lookup` method.

        Raises `MissingHeader` if there is no header with the given height in the header store.

        Caveats:
        1. You should not be calling this if the calling context needs to respect what headers
           the wallet has already processed. Call `Wallet.lookup_header_for_height` or
           `Wallet.lookup_header_for_hash` instead.
        2. You should not call `headers.lookup` directly unless it is before any chance of
           race conditions.
        3. This may need some optimisation at some point if acquiring the lock is heavyweight.
        """
        assert self.headers is not None
        with self._headers_lock:

            # The bitcoinx Headers.lookup method API has changed in v0.8
            # it used to return a tuple[Header, Chain] and raise MissingHeader if no header
            # was found. This allows us to expose the same API from app_state.lookup as before.
            chain: Chain
            chain, height = self.headers.lookup(block_hash)
            if chain is None:
                raise MissingHeader(f"No header found for hash: "
                    f"{hash_to_hex_str(block_hash)}")
            header = chain.header_at_height(height)
            return header, chain

    def header_at_height(self, chain: Chain, block_height: int) -> Header:
        """
        Thread-safe version of bitcoinx's `Headers` object `header_at_height` method.

        Raises `MissingHeader` if there is no header for the given chain at the given height.
        """
        assert self.headers is not None
        with self._headers_lock:
            return cast(Header, self.headers.header_at_height(chain, block_height))

    def raw_header_at_height(self, chain: Chain, block_height: int) -> bytes:
        """
        Thread-safe version of bitcoinx's `Headers` object `raw_header_at_height` method.

        Raises `MissingHeader` if there is no header for the given chain at the given height.
        """
        assert self.headers is not None
        with self._headers_lock:
            return cast(bytes, self.headers.raw_header_at_height(chain, block_height))

    def connect_header(self, header_bytes: bytes) -> tuple[Header, Chain]:
        """
        Thread-safe version of bitcoinx's `Headers` object `connect` method.

        Raises `MissingHeader` if the previous header cannot be found, `IncorrectBits` if the
        header's bits don't meet the chain's rules, and `InsufficientPow` if the header's
        hash doesn't meet the target. These are all subclasses of `ChainException`.

        Caveats:
        1. Calling this does not make a wallet aware of a header.
        2. You should not call `headers.connect` directly unless it is before any chance of
           race conditions.
        3. This may need some optimisation at some point if acquiring the lock is heavyweight.
        """
        assert self.headers is not None
        with self._headers_lock:
            return cast(tuple[Header, Chain], self.headers.connect(header_bytes))

    def write_cached_headers_state(self) -> None:
        """
        Raises no exception (that we care to catch, see `flush_headers_object`).
        """
        with self._headers_lock:
            logger.debug("Writing cached headers state")
            self.headers_cursor = write_cached_headers(self.headers, self.headers_cursor, self)
            self._last_headers_save = time.time()

    async def _follow_longest_valid_chain(self) -> None:
        """
        Responsible for tracking the longest chain according to the headers store.

        Raises no exceptions.
        """
        # We import this inline to avoid a circular import as this file is imported in the
        # file we are importing.
        from .network_support.headers import get_longest_valid_chain

        current_chain = get_longest_valid_chain()
        current_tip_header = cast(Header, current_chain.tip())
        while True:
            await self.headers_update_event.wait()

            previous_chain = current_chain
            previous_tip_header = current_tip_header

            current_chain = get_longest_valid_chain()
            current_tip_header = cast(Header, current_chain.tip())
            # It is possible for this to be sent when there is no change.
            if current_tip_header == previous_tip_header:
                continue

            for wallet in list(self.daemon.wallets.values()):
                wallet.process_header_source_update(None, previous_chain,
                    previous_tip_header, current_chain, current_tip_header)

    def connect_out_of_band_header(self, header_bytes: bytes) -> tuple[Header | None, Chain | None]:
        """
        There is nothing wrong with connecting out of band headers. Wallets do not
        follow the updates to the header store, they follow specific notifications
        of synchronisation work for a header source (P2P or blockchain server).

        Raises no exceptions.

        WARNING: This must be called from the application main async thread/loop. The
            `headers_update_event` is bound to this loop, and this event must be set from within
            that context. That might mean that the caller has to spawn a task when calling this
            function in that main async thread/loop.
        """
        try:
            header, chain = self.connect_header(header_bytes)
        except MissingHeader:
            # TODO(low priority) Headers. We may be able to connect this later although whether
            #      there is any benefit to this I do not know (rt12).
            return None, None
        else:
            self.headers_update_event.set()
            self.headers_update_event.clear()
            return header, chain

    def on_stop(self) -> None:
        # The headers object may not be created for command-line invocations that do not require it.
        if self.headers is not None:
            with self._headers_lock:
                self.write_cached_headers_state()

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

    def format_amount(self, x: int | None, is_diff: bool=False, whitespaces: bool=False) -> str:
        return format_satoshis(x, self.num_zeros, self.decimal_point, is_diff=is_diff,
            whitespaces=whitespaces)

    def format_amount_and_units(self, amount: int | None) -> str:
        text = self.format_amount(amount) + ' ' + self.base_unit()
        if self.fx and self.fx.is_enabled():
            x = self.fx.format_amount_and_units(amount)
            if text and x:
                text += ' (%s)'%x
        return text

    def get_amount_and_units(self, amount: int) -> tuple[str, str]:
        bitcoin_text = self.format_amount(amount) + ' ' + self.base_unit()
        if self.fx and self.fx.is_enabled():
            fiat_text = self.fx.format_amount_and_units(amount)
        else:
            fiat_text = ''
        return bitcoin_text, fiat_text



class _AppStateMeta(type):

    def __getattr__(cls, attr: str) -> Any:
        return getattr(cls._proxy, attr)

    def __setattr__(cls, attr: str, value: Any) -> None:
        if attr == '_proxy':
            super().__setattr__(attr, value)
        return setattr(cls._proxy, attr, value)


class AppState(metaclass=_AppStateMeta):
    _proxy: AppStateProxy | None = None

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
def get_app_state_qt() -> QtAppStateProxy:
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


