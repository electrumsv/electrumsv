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

'''QT application state.'''

from functools import partial
import signal
import sys
import threading

from PyQt5.QtCore import QObject, pyqtSignal, QTimer
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMessageBox, QMenu, QWidget
import PyQt5.QtCore as QtCore

from electrumsv.app_state import AppStateProxy
from electrumsv.exceptions import UserCancelled, UserQuit
from electrumsv.i18n import _, set_language
from electrumsv.logs import logs
from electrumsv.plugin import run_hook
from electrumsv.storage import WalletStorage

from .exception_window import Exception_Hook
from .installwizard import InstallWizard, GoBack
from .main_window import ElectrumWindow
from .network_dialog import NetworkDialog
from .util import ColorScheme, read_QIcon


logger = logs.get_logger('app_state')


class OpenFileEventFilter(QObject):
    def __init__(self, windows):
        super().__init__()
        self.windows = windows

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].pay_to_URI(event.url().toString())
                return True
        return False


class QElectrumSVApplication(QApplication):

    # Signals need to be on a QObject
    new_window_signal = pyqtSignal(str, object)
    alias_resolved = pyqtSignal()
    # Preferences updates
    fiat_ccy_changed = pyqtSignal()
    custom_fee_changed = pyqtSignal()
    fees_editable_changed = pyqtSignal()
    op_return_enabled_changed = pyqtSignal()
    num_zeros_changed = pyqtSignal()
    base_unit_changed = pyqtSignal()


class QtAppStateProxy(AppStateProxy):

    def __init__(self, config):
        self.windows = []
        self.app = self._create_app()
        self.timer = QTimer()

        # This can trigger callbacks; so do it after the above attributes are set
        super().__init__(config)

        # FIXME: move language to app_state
        set_language(config.get('language'))

        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])

        self.nd = None
        self.exception_hook = None
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('ElectrumSV')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        run_hook('init_qt', self)
        ColorScheme.update_from_widget(QWidget())

    def _create_app(self):
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_X11InitThreads)
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum-sv.desktop')
        app = QElectrumSVApplication(sys.argv)
        app.installEventFilter(OpenFileEventFilter(self.windows))
        app.new_window_signal.connect(self.start_new_window)
        app.custom_fee_changed.connect(partial(self._signal_all, 'on_custom_fee_changed'))
        app.fees_editable_changed.connect(partial(self._signal_all, 'on_fees_editable_changed'))
        app.op_return_enabled_changed.connect(
            partial(self._signal_all, 'on_op_return_enabled_changed'))
        app.num_zeros_changed.connect(partial(self._signal_all, 'on_num_zeros_changed'))
        app.fiat_ccy_changed.connect(partial(self._signal_all, 'on_fiat_ccy_changed'))
        app.base_unit_changed.connect(partial(self._signal_all, 'on_base_unit_changed'))
        return app

    def _signal_all(self, method, *args):
        for window in self.windows:
            getattr(window, method)(*args)

    def alias_resolved(self):
        self.app.alias_resolved.emit()

    def set_base_unit(self, base_unit):
        if super().set_base_unit(base_unit):
            self.app.base_unit_changed.emit()

    def build_tray_menu(self):
        # Avoid immediate GC of old menu when window closed via its action
        if self.tray.contextMenu() is None:
            m = QMenu()
            self.tray.setContextMenu(m)
        else:
            m = self.tray.contextMenu()
            m.clear()
        for window in self.windows:
            submenu = m.addMenu(window.wallet.basename())
            submenu.addAction(_("Show/Hide"), window.show_or_hide)
            submenu.addAction(_("Close"), window.close)
        m.addAction(_("Dark/Light"), self.toggle_tray_icon)
        m.addSeparator()
        m.addAction(_("Exit ElectrumSV"), self.close)
        self.tray.setContextMenu(m)

    def tray_icon(self):
        if self.dark_icon:
            return read_QIcon('electrumsv_dark_icon.png')
        else:
            return read_QIcon('electrumsv_light_icon.png')

    def toggle_tray_icon(self):
        self.dark_icon = not self.dark_icon
        self.config.set_key("dark_icon", self.dark_icon, True)
        self.tray.setIcon(self.tray_icon())

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if all([w.is_hidden() for w in self.windows]):
                for w in self.windows:
                    w.bring_to_top()
            else:
                for w in self.windows:
                    w.hide()

    def close(self):
        for window in self.windows:
            window.close()

    def new_window(self, path, uri=None):
        # Use a signal as can be called from daemon thread
        self.app.new_window_signal.emit(path, uri)

    def show_network_dialog(self, parent):
        if not self.daemon.network:
            parent.show_warning(_('You are using ElectrumSV in offline mode; restart '
                                  'ElectrumSV if you want to get connected'), title=_('Offline'))
            return
        if self.nd:
            self.nd.on_update()
            self.nd.show()
            self.nd.raise_()
            return
        self.nd = NetworkDialog(self.daemon.network, self.config)
        self.nd.show()

    def create_window_for_wallet(self, wallet):
        w = ElectrumWindow(self, wallet)
        self.windows.append(w)
        self.build_tray_menu()
        # FIXME: Remove in favour of the load_wallet hook
        run_hook('on_new_window', w)
        return w

    def start_new_window(self, path, uri, is_startup=False):
        '''Raises the window for the wallet if it is open.  Otherwise
        opens the wallet and creates a new window for it.'''
        for w in self.windows:
            if w.wallet.storage.path == path:
                w.bring_to_top()
                break
        else:
            try:
                wallet = self.daemon.load_wallet(path, None)
                if not wallet:
                    storage = WalletStorage(path, manual_upgrades=True)
                    wizard = InstallWizard(self.config, self.app, self.plugins, storage)
                    try:
                        wallet = wizard.start_gui(is_startup=is_startup)
                    except UserQuit:
                        pass
                    except UserCancelled:
                        pass
                    except GoBack as e:
                        logger.error('[start_new_window] Exception caught (GoBack) %s', e)
                    finally:
                        wizard.terminate()
                    if not wallet:
                        return
                    wallet.start_threads(self.daemon.network)
                    self.daemon.add_wallet(wallet)
            except BaseException as e:
                logger.exception("")
                if '2fa' in str(e):
                    d = QMessageBox(QMessageBox.Warning, _('Error'),
                                    '2FA wallets are not unsupported.')
                    d.exec_()
                else:
                    d = QMessageBox(QMessageBox.Warning, _('Error'),
                                    'Cannot load wallet:\n' + str(e))
                    d.exec_()
                return
            w = self.create_window_for_wallet(wallet)
        if uri:
            w.pay_to_URI(uri)
        w.bring_to_top()
        w.setWindowState(w.windowState() & ~QtCore.Qt.WindowMinimized | QtCore.Qt.WindowActive)

        # this will activate the window
        w.activateWindow()
        return w

    def close_window(self, window):
        self.windows.remove(window)
        self.build_tray_menu()
        # save wallet path of last open window
        if not self.windows:
            self.config.save_last_wallet(window.wallet)
        run_hook('on_close_window', window)

    def maybe_choose_server(self):
        # Show network dialog if config does not exist
        if self.daemon.network and self.config.get('auto_connect') is None:
            try:
                wizard = InstallWizard(self.config, self.app,
                                       self.plugins, None)
                wizard.init_network(self.daemon.network)
                wizard.terminate()
            except Exception as e:
                if not isinstance(e, (UserCancelled, GoBack)):
                    logger.exception("")
                self.app.quit()

    def event_loop_started(self):
        if self.config.get("show_crash_reporter", default=True):
            self.exception_hook = Exception_Hook(self.app)
        self.timer.start()
        signal.signal(signal.SIGINT, lambda *args: self.app.quit())
        self.maybe_choose_server()
        self.config.open_last_wallet()
        path = self.config.get_wallet_path()
        if not self.start_new_window(path, self.config.get('url'), is_startup=True):
            self.app.quit()

    def run_gui(self):
        threading.current_thread().setName('GUI')
        self.timer.setSingleShot(False)
        self.timer.setInterval(500)  # msec

        QTimer.singleShot(0, self.event_loop_started)
        self.app.exec_()

        # Shut down the timer cleanly
        self.timer.stop()
        # clipboard persistence
        # see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
        event = QtCore.QEvent(QtCore.QEvent.Clipboard)
        self.app.sendEvent(self.app.clipboard(), event)
        self.tray.hide()
