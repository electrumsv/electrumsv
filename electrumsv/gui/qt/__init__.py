#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
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

import logging
import signal
import sys

try:
    import PyQt5
except Exception:
    sys.exit("Error: Could not import PyQt5 on Linux systems, you may try 'sudo apt-get install python3-pyqt5'")

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
import PyQt5.QtCore as QtCore

from electrumsv.i18n import _, set_language
from electrumsv.plugin import run_hook
from electrumsv import WalletStorage
from electrumsv.util import UserCancelled, print_error
from electrumsv.networks import NetworkConstants

from .exception_window import Exception_Hook
from .installwizard import InstallWizard, GoBack


try:
    from . import icons_rc
except Exception as e:
    print(e)
    print("Error: Could not find icons file.")
    print("Run 'pyrcc5 icons.qrc -o electrumsv/gui/qt/icons_rc.py', and re-run ElectrumSV")
    sys.exit(1)

from .util import *   # * needed for plugins
from .main_window import ElectrumWindow
from .network_dialog import NetworkDialog


class OpenFileEventFilter(QObject):
    def __init__(self, windows):
        self.windows = windows
        super(OpenFileEventFilter, self).__init__()

    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.FileOpen:
            if len(self.windows) >= 1:
                self.windows[0].pay_to_URI(event.url().toString())
                return True
        return False


class QElectrumApplication(QApplication):
    new_window_signal = pyqtSignal(str, object)


class ElectrumGui:

    def __init__(self, config, daemon, plugins):
        set_language(config.get('language'))
        # Uncomment this call to verify objects are being properly
        # GC-ed when windows are closed
        #network.add_jobs([DebugMem([Abstract_Wallet, SPV, Synchronizer,
        #                            ElectrumWindow], interval=5)])
        QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_X11InitThreads)
        if hasattr(QtCore.Qt, "AA_ShareOpenGLContexts"):
            QtCore.QCoreApplication.setAttribute(QtCore.Qt.AA_ShareOpenGLContexts)
        if hasattr(QGuiApplication, 'setDesktopFileName'):
            QGuiApplication.setDesktopFileName('electrum-sv.desktop')
        self.config = config
        self.daemon = daemon
        self.plugins = plugins
        self.windows = []
        self.efilter = OpenFileEventFilter(self.windows)
        self.app = QElectrumApplication(sys.argv)
        self.app.installEventFilter(self.efilter)
        # timer
        self.timer = QTimer(self.app)
        self.timer.setSingleShot(False)
        self.timer.setInterval(500)  # msec

        self.nd = None
        self.exception_hook = None
        # init tray
        self.dark_icon = self.config.get("dark_icon", False)
        self.tray = QSystemTrayIcon(self.tray_icon(), None)
        self.tray.setToolTip('ElectrumSV')
        self.tray.activated.connect(self.tray_activated)
        self.build_tray_menu()
        self.tray.show()
        self.app.new_window_signal.connect(self.start_new_window)
        run_hook('init_qt', self)
        ColorScheme.update_from_widget(QWidget())

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
            return QIcon(':icons/electrumsv_dark_icon.png')
        else:
            return QIcon(':icons/electrumsv_light_icon.png')

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
            parent.show_warning(_('You are using ElectrumSV in offline mode; restart ElectrumSV if you want to get connected'), title=_('Offline'))
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

    def start_new_window(self, path, uri):
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
                        wallet = wizard.run_and_get_wallet()
                    except UserCancelled:
                        pass
                    except GoBack as e:
                        print_error('[start_new_window] Exception caught (GoBack)', e)
                    finally:
                        wizard.terminate()
                    if not wallet:
                        return
                    wallet.start_threads(self.daemon.network)
                    self.daemon.add_wallet(wallet)
            except BaseException as e:
                logging.exception("")
                if '2fa' in str(e):
                    d = QMessageBox(QMessageBox.Warning, _('Error'), '2FA wallets for Bitcoin SV are currently unsupported by <a href="https://api.trustedcoin.com/#/">TrustedCoin</a>. Follow <a href="https://github.com/Electrum-SV/Electrum-SV/issues/41#issuecomment-357468208">this guide</a> in order to recover your funds.')
                    d.exec_()
                else:
                    d = QMessageBox(QMessageBox.Warning, _('Error'), 'Cannot load wallet:\n' + str(e))
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
                    logging.exception("")
                self.app.quit()

    def event_loop_started(self):
        if self.config.get("show_crash_reporter", default=True):
            self.exception_hook = Exception_Hook(self.app)
        self.timer.start()
        signal.signal(signal.SIGINT, lambda *args: self.app.quit())
        self.maybe_choose_server()
        self.config.open_last_wallet()
        path = self.config.get_wallet_path()
        if not self.start_new_window(path, self.config.get('url')):
            self.app.quit()

    def main(self):
        QTimer.singleShot(0, self.event_loop_started)
        self.app.exec_()
        # Shut down the timer cleanly
        self.timer.stop()
        # clipboard persistence. see http://www.mail-archive.com/pyqt@riverbankcomputing.com/msg17328.html
        event = QtCore.QEvent(QtCore.QEvent.Clipboard)
        self.app.sendEvent(self.app.clipboard(), event)
        self.tray.hide()
