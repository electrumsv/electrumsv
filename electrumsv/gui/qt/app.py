# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2019-2020 The ElectrumSV Developers
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

'''ElectrumSV application.'''

import asyncio
import concurrent.futures
import datetime
import os
from functools import partial
import signal
import sys
import threading
import time
from typing import Any, Callable, cast, Coroutine, Iterable, List, Optional, TypeVar

import PyQt6.QtCore as QtCore
from PyQt6.QtCore import pyqtSignal, QEvent, QObject, QTimer
from PyQt6.QtGui import QFileOpenEvent, QGuiApplication, QIcon
from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QWidget, QDialog

from ...app_state import app_state, ExceptionHandlerABC
from ...contacts import ContactEntry, ContactIdentity
from ...i18n import _
from ...logs import logs
from ...types import ExceptionInfoType
from ...util import UpdateCheckResultType
from ...wallet import AbstractAccount, Wallet

from . import dialogs
from .cosigner_pool import CosignerPool
from .main_window import ElectrumWindow
from .exception_window import Exception_Hook
from .label_sync import LabelSync
from .log_window import SVLogWindow, SVLogHandler
from .util import ColorScheme, get_default_language, MessageBox, read_QIcon
from .wallet_wizard import WalletWizard



T1 = TypeVar("T1")

logger = logs.get_logger('app')


class OpenFileEventFilter(QObject):
    def __init__(self, windows: List[ElectrumWindow]) -> None:
        super().__init__()
        self.windows = windows

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if event.type() == QtCore.QEvent.Type.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].pay_to_URI(cast(QFileOpenEvent, event).url().toString())
                return True
        return False


class SVApplication(QApplication):

    # Signals need to be on a QObject
    create_new_window_signal = pyqtSignal(object, object, bool)
    cosigner_received_signal = pyqtSignal(object, object)
    labels_changed_signal = pyqtSignal(object, object, object)
    window_opened_signal = pyqtSignal(object)
    window_closed_signal = pyqtSignal(object)
    # Async tasks
    async_tasks_done = pyqtSignal()
    # Logging
    new_category = pyqtSignal(str)
    new_log = pyqtSignal(object)
    # Preferences updates
    fiat_ccy_changed = pyqtSignal()
    custom_fee_changed = pyqtSignal()
    op_return_enabled_changed = pyqtSignal()
    num_zeros_changed = pyqtSignal()
    base_unit_changed = pyqtSignal()
    fiat_history_changed = pyqtSignal()
    fiat_balance_changed = pyqtSignal()
    update_check_signal = pyqtSignal(bool, object)
    # Contact events
    contact_added_signal = pyqtSignal(object, object)
    contact_removed_signal = pyqtSignal(object)
    identity_added_signal = pyqtSignal(object, object)
    identity_removed_signal = pyqtSignal(object, object)

    def __init__(self, argv: List[str]) -> None:
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(
                QtCore.Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum-sv.desktop')
        super().__init__(argv)

        self.startup_time = time.time()

        self.windows: List[ElectrumWindow] = []
        self.log_handler = SVLogHandler()
        self.log_window: Optional[SVLogWindow] = None
        self.timer = QTimer(self)
        self.exception_hook: Optional[ExceptionHandlerABC] = None
        # A floating point number, e.g. 129.1
        self.dpi = self.primaryScreen().physicalDotsPerInch()

        # init tray
        self.dark_icon = app_state.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self._tray_icon(), None)
        self.tray.setToolTip('ElectrumSV')
        self.tray.activated.connect(self._tray_activated)
        self._build_tray_menu()
        self.tray.show()

        # FIXME Fix what.. what needs to be fixed here?
        app_state.config.get('language', get_default_language())

        logs.add_handler(self.log_handler)
        self._start()

    def _start(self) -> None:
        self.setWindowIcon(read_QIcon("electrum-sv.png"))
        self.installEventFilter(OpenFileEventFilter(self.windows))
        self.create_new_window_signal.connect(self._start_new_window_signal)
        self.async_tasks_done.connect(app_state.async_.run_pending_callbacks)
        self.num_zeros_changed.connect(partial(self._signal_all, 'on_num_zeros_changed'))
        self.fiat_ccy_changed.connect(partial(self._signal_all, 'on_fiat_ccy_changed'))
        self.base_unit_changed.connect(partial(self._signal_all, 'on_base_unit_changed'))
        self.fiat_history_changed.connect(partial(self._signal_all, 'on_fiat_history_changed'))
        # Toggling of showing addresses in the fiat preferences.
        self.fiat_balance_changed.connect(partial(self._signal_all, 'on_fiat_balance_changed'))
        self.update_check_signal.connect(partial(self._signal_all, 'on_update_check'))
        ColorScheme.update_from_widget(QWidget())

    def _signal_all(self, method: str, *args: str) -> None:
        for window in self.windows:
            getattr(window, method)(*args)

    def _close(self) -> None:
        for window in self.windows:
            window.close()

    def close_window(self, window: ElectrumWindow) -> None:
        # NOTE: `ElectrumWindow` removes references to itself while it is closing. This creates
        # a problem where it gets garbage collected before it's Qt5 `closeEvent` handling is
        # completed and on Linux/MacOS it segmentation faults. On Windows, it is fine.
        QTimer.singleShot(0, partial(self._close_window, window))
        logger.debug("app.close_window.queued")

    def _close_window(self, window: ElectrumWindow) -> None:
        logger.debug(f"app.close_window.executing {window!r}")
        app_state.daemon.stop_wallet_at_path(window._wallet.get_storage_path())
        self.windows.remove(window)
        self.window_closed_signal.emit(window)
        self._build_tray_menu()
        if not self.windows:
            self._last_window_closed()

    def setup_app(self) -> None:
        # app_state.daemon is initialised after app. Setup things dependent on daemon here.
        pass

    def _build_tray_menu(self) -> None:
        # Avoid immediate GC of old menu when window closed via its action
        if self.tray.contextMenu() is None:
            m = QMenu()
            self.tray.setContextMenu(m)
        else:
            m = self.tray.contextMenu()
            m.clear()
        for window in self.windows:
            submenu = m.addMenu(window._wallet.name())
            submenu.addAction(_("Show/Hide"), window.show_or_hide)
            # NOTE(typing) Need to pretend things that Qt uses return nothing.
            submenu.addAction(_("Close"), cast(Callable[..., None], window.close))
        m.addAction(_("Dark/Light"), self._toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit ElectrumSV"), self._close)
        self.tray.setContextMenu(m)

    def _tray_icon(self) -> QIcon:
        if self.dark_icon:
            return read_QIcon('electrumsv_dark_icon.png')
        else:
            return read_QIcon('electrumsv_light_icon.png')

    def _toggle_tray_icon(self) -> None:
        self.dark_icon = not self.dark_icon
        app_state.config.set_key("dark_icon", self.dark_icon, True)
        self.tray.setIcon(self._tray_icon())

    def _tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            if all([w.is_hidden() for w in self.windows]):
                for w in self.windows:
                    w.bring_to_top()
            else:
                for w in self.windows:
                    w.hide()

    def new_window(self, path: Optional[str], uri: Optional[str]=None) -> None:
        # Use a signal as can be called from daemon thread
        self.create_new_window_signal.emit(path, uri, False)

    def show_log_viewer(self) -> None:
        if self.log_window is None:
            self.log_window = SVLogWindow(None, self.log_handler)
        self.log_window.show()

    def _last_window_closed(self) -> None:
        if self.log_window:
            self.log_window.accept()

    def on_transaction_label_change(self, account: AbstractAccount, tx_hash: bytes, text: str) \
            -> None:
        self.label_sync.set_transaction_label(account, tx_hash, text)

    def on_keyinstance_label_change(self, account: AbstractAccount, key_id: int, text: str) -> None:
        self.label_sync.set_keyinstance_label(account, key_id, text)

    def _create_window_for_wallet(self, wallet: Wallet) -> ElectrumWindow:
        w = ElectrumWindow(wallet)
        self.windows.append(w)
        self._build_tray_menu()
        self._register_wallet_events(wallet)
        self.window_opened_signal.emit(w)
        return w

    def _register_wallet_events(self, wallet: Wallet) -> None:
        # NOTE(typing) Some typing nonsense about not being able to assign to a method.
        wallet.contacts._on_contact_added = self._on_contact_added # type: ignore[assignment]
        wallet.contacts._on_contact_removed = self._on_contact_removed # type: ignore[assignment]
        wallet.contacts._on_identity_added = self._on_identity_added # type: ignore[assignment]
        wallet.contacts._on_identity_removed = self._on_identity_removed # type: ignore[assignment]

    def _on_identity_added(self, contact: ContactEntry, identity: ContactIdentity) -> None:
        self.identity_added_signal.emit(contact, identity)

    def _on_identity_removed(self, contact: ContactEntry, identity: ContactIdentity) -> None:
        self.identity_removed_signal.emit(contact, identity)

    def _on_contact_added(self, contact: ContactEntry, identity: ContactIdentity) -> None:
        self.contact_added_signal.emit(contact, identity)

    def _on_contact_removed(self, contact: ContactEntry) -> None:
        self.contact_removed_signal.emit(contact)

    def get_wallets(self) -> Iterable[Wallet]:
        return [ window._wallet for window in self.windows ]

    def get_wallet_window(self, path: str) -> Optional[ElectrumWindow]:
        for w in self.windows:
            if w._wallet.get_storage_path() == path:
                return w
        return None

    def get_wallet_window_by_id(self, wallet_id: int) -> Optional[ElectrumWindow]:
        for w in self.windows:
            if w._wallet.get_id() == wallet_id:
                return w
        return None

    def _start_new_window_signal(self, wallet_path: Optional[str], uri: Optional[str]=None,
            is_startup: bool=False) -> None:
        self.start_new_window(wallet_path, uri, is_startup)

    def start_new_window(self, wallet_path: Optional[str], uri: Optional[str]=None,
            is_startup: bool=False) -> Optional[ElectrumWindow]:
        '''Raises the window for the wallet if it is open.  Otherwise
        opens the wallet and creates a new window for it.'''
        for w in self.windows:
            if w._wallet.get_storage_path() == wallet_path:
                w.bring_to_top()
                break
        else:
            wizard_window: Optional[WalletWizard] = None
            if wallet_path is not None:
                open_result  = WalletWizard.attempt_open(wallet_path)
                if open_result.was_aborted:
                    return None
                if not open_result.is_valid:
                    wallet_filename = os.path.basename(wallet_path)
                    MessageBox.show_error(
                        _("Unable to load file '{}'.").format(wallet_filename))
                    return None
                wizard_window = open_result.wizard
            else:
                wizard_window = WalletWizard(is_startup=is_startup)
            if wizard_window is not None:
                result = wizard_window.run()
                # This will return Accepted in some failure cases, like migration failure, due
                # to wallet wizard standard buttons not being easily dynamically changeable.
                if result != QDialog.DialogCode.Accepted:
                    return None
                wallet_path = wizard_window.get_wallet_path()
                if wallet_path is None:
                    return None
            # All paths leading to this obtain a password and put it in the credential cache.
            assert wallet_path is not None
            wallet = app_state.daemon.load_wallet(wallet_path)
            assert wallet is not None
            w = self._create_window_for_wallet(wallet)
        if uri:
            w.pay_to_URI(uri)

        w.bring_to_top()
        w.setWindowState(QtCore.Qt.WindowState(
            w.windowState() & ~QtCore.Qt.WindowState.WindowMinimized |
                QtCore.Qt.WindowState.WindowActive))
        # this will activate the window
        w.activateWindow()

        return w

    def update_check(self) -> None:
        if (not app_state.config.get('check_updates', True) or
                app_state.config.get("offline", False)):
            return

        def f() -> None:
            import requests
            try:
                response = requests.request(
                    'GET', "https://electrumsv.io/release.json",
                    headers={'User-Agent' : 'ElectrumSV'}, timeout=10)
                result = response.json()
                self._on_update_check(True, result)
            except Exception:
                self._on_update_check(False, cast(ExceptionInfoType, sys.exc_info()))

        t = threading.Thread(target=f)
        t.setDaemon(True)
        t.start()

    def _on_update_check(self, success: bool, result: UpdateCheckResultType) -> None:
        if success:
            when_checked = datetime.datetime.now().astimezone().isoformat()
            app_state.config.set_key('last_update_check', result)
            app_state.config.set_key('last_update_check_time', when_checked, True)
        self.update_check_signal.emit(success, result)

    def initial_dialogs(self) -> None:
        '''Suppressible dialogs that are shown when first opening the app.'''
        dialogs.show_named('welcome-ESV-1.4.0b1')

    def event_loop_started(self) -> None:
        self.cosigner_pool = CosignerPool()
        self.label_sync = LabelSync()
        if app_state.config.get("show_crash_reporter", default=True):
            self.exception_hook = cast(ExceptionHandlerABC, Exception_Hook(self))
        self.timer.start()
        signal.signal(signal.SIGINT, lambda *args: self.quit())
        self.initial_dialogs()
        path = app_state.config.get_commandline_wallet_path()
        if not self.start_new_window(path, app_state.config.get('url'), is_startup=True):
            self.quit()

    def run_app(self) -> None:
        when_started = datetime.datetime.now().astimezone().isoformat()
        app_state.config.set_key('previous_start_time', app_state.config.get("start_time"))
        app_state.config.set_key('start_time', when_started, True)
        self.update_check()

        threading.current_thread().setName('GUI')
        self.timer.setSingleShot(False)
        self.timer.setInterval(500)  # msec
        self.timer.timeout.connect(app_state.device_manager.timeout_clients)

        QTimer.singleShot(0, self.event_loop_started)
        self.exec()

        logs.remove_handler(self.log_handler)
        # Shut down the timer cleanly
        self.timer.stop()
        # clipboard persistence
        # see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
        event = QtCore.QEvent(QtCore.QEvent.Type.Clipboard)
        self.sendEvent(self.clipboard(), event)
        self.tray.hide()

    def run_coro(self, coro: Coroutine[Any, Any, T1],
            on_done: Optional[Callable[[concurrent.futures.Future[T1]], None]]=None) \
                -> concurrent.futures.Future[T1]:
        '''Run a coroutine.  on_done, if given, is passed the future containing the reuslt or
        exception, and is guaranteed to be called in the context of the GUI thread.
        '''
        def task_done(future: concurrent.futures.Future[T1]) -> None:
            self.async_tasks_done.emit()

        future = app_state.async_.spawn(coro, on_done=on_done)
        future.add_done_callback(task_done)
        return future

    # NOTE(typing) This cannot be guaranteed to type-check correctly. In order to do that we
    #     would need to use `typing.ParamSpec` and be able to `Concatenate` the `on_done`
    #     keyword argument into the mix. However, that is not supported as per PEP 612.
    def run_in_thread(self, func: Callable[..., T1], /, *args: Any,
            on_done: Optional[Callable[[concurrent.futures.Future[T1]], None]]=None) \
                -> concurrent.futures.Future[T1]:
        '''Run func(*args) in a thread.  on_done, if given, is passed the future containing the
        reuslt or exception, and is guaranteed to be called in the context of the GUI
        thread.
        '''
        return self.run_coro(asyncio.to_thread(func, *args), on_done=on_done)
