from __future__ import annotations
from typing import Callable, Optional, TYPE_CHECKING
import weakref

from PyQt5.QtGui import QContextMenuEvent
from PyQt5.QtWidgets import QFileDialog

from ...i18n import _

from .util import ButtonsMode, ButtonsTextEdit, MessageBoxMixin, ColorScheme

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class ShowQRTextEdit(ButtonsTextEdit):
    def __init__(self, text: Optional[str]=None,
            buttons_mode: ButtonsMode=ButtonsMode.TOOLBAR_BOTTOM) -> None:
        super().__init__(text)
        self.buttons_mode = buttons_mode
        self.setReadOnly(True)
        self.qr_button = self.addButton("qrcode.png", self.qr_show, _("Show as QR code"))

    def qr_show(self) -> None:
        from .qrcodewidget import QRDialog
        try:
            s = str(self.toPlainText())
        except Exception:
            s = self.toPlainText()
        QRDialog(s).exec_()

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        m = self.createStandardContextMenu()
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(event.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, window: ElectrumWindow, text: str="", allow_multi: bool=False) -> None:
        ButtonsTextEdit.__init__(self, text)
        self._main_window_proxy = weakref.proxy(window)
        self.allow_multi = allow_multi
        self.setReadOnly(False)
        self.addButton("file.png", self.file_input, _("Read file"))
        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.addButton(icon, self.qr_input, _("Read QR code"))

    def file_input(self) -> None:
        fileName, __ = QFileDialog.getOpenFileName(self, 'select file')
        if not fileName:
            return
        try:
            with open(fileName, "r", encoding='utf-8') as f:
                data = f.read()
        except UnicodeDecodeError as reason:
            self.show_critical(
                _("The selected file appears to be a binary file.") + "\n" +
                _("Please ensure you only import text files."),
                title=_("Not a text file")
            )
            return
        self.setText(data)

    def qr_input(self, result_callback: Optional[Callable[[str], None]]=None,
            ignore_uris: bool=False) -> None:
        def callback(text: Optional[str]) -> None:
            if text is None:
                text = ""
            if self.allow_multi:
                new_text = self.text() + text + '\n'
            else:
                new_text = text
            # This should only be set if the subclass is calling itself and knows that it has
            # replaced this method and it supports the extra parameter. See `PayToEdit.qr_input()`.
            if ignore_uris:
                # NOTE(typing) setText is overriden to setPlainText in the `paytoedit.py`.
                self.setText(new_text, ignore_uris) # type: ignore[call-arg]
            else:
                self.setText(new_text)

            if result_callback is not None:
                result_callback(text)
        self._main_window_proxy.read_qrcode_and_call_callback(callback)

    def contextMenuEvent(self, e: QContextMenuEvent) -> None:
        m = self.createStandardContextMenu()
        m.addAction(_("Read QR code"), self.qr_input)
        m.exec_(e.globalPos())
