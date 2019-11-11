from typing import Dict, Any, Optional

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QInputDialog, QLineEdit, QVBoxLayout, QLabel

from electrumsv.i18n import _
from electrumsv.keystore import Hardware_KeyStore

from electrumsv.gui.qt.main_window import ElectrumWindow
from electrumsv.gui.qt.util import WindowModalDialog

from .ledger import LedgerPlugin, Ledger_KeyStore
from ..hw_wallet.qt import QtHandlerBase, QtPluginBase, HandlerWindow


class Plugin(LedgerPlugin, QtPluginBase):
    icon_paired = "icons8-usb-connected-80.png"
    icon_unpaired = "icons8-usb-disconnected-80.png"

    def create_handler(self, window: HandlerWindow) -> QtHandlerBase:
        return Ledger_Handler(window)

    def show_settings_dialog(self, window: ElectrumWindow, keystore: Hardware_KeyStore) -> None:
        assert keystore.handler is not None
        keystore.handler.setup_dialog()


class Ledger_Handler(QtHandlerBase):
    setup_signal = pyqtSignal()
    auth_signal = pyqtSignal(object, object)

    def __init__(self, win) -> None:
        super(Ledger_Handler, self).__init__(win, 'Ledger')
        self.setup_signal.connect(self.setup_dialog)
        self.auth_signal.connect(self.auth_dialog)

    def word_dialog(self, msg) -> None:
        response = QInputDialog.getText(self.top_level_window(),
            "Ledger Wallet Authentication", msg, QLineEdit.Password)
        if not response[1]:
            self.word = None
        else:
            self.word = str(response[0])
        self.done.set()

    def message_dialog(self, msg, _on_cancel=None) -> None:
        self.clear_dialog()
        self.dialog = dialog = WindowModalDialog(self.top_level_window(), _("Ledger Status"))
        l = QLabel(msg)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(l)
        dialog.show()

    def auth_dialog(self, keystore: Ledger_KeyStore, data: Dict[str, Any]) -> None:
        try:
            from .auth2fa import LedgerAuthDialog
        except ImportError as e:
            self.message_dialog(str(e))
            return
        dialog = LedgerAuthDialog(self, keystore, data)
        dialog.exec_()
        self.word = dialog.pin
        self.done.set()

    def get_auth(self, keystore: Ledger_KeyStore, data: Dict[str, Any]) -> Optional[str]:
        self.done.clear()
        self.auth_signal.emit(keystore, data)
        self.done.wait()
        return self.word

    def get_setup(self) -> None:
        self.done.clear()
        self.setup_signal.emit()
        self.done.wait()

    def setup_dialog(self) -> None:
        #from btchip.btchipPersoWizard import StartBTChipPersoDialog
        #dialog = StartBTChipPersoDialog()
        #dialog.exec_()
        # rt12 -- Ledger settings use PyQt4, which we do not have.
        self.show_error(_('This button does nothing.'))
