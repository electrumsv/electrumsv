from typing import Optional

from PyQt5.QtWidgets import QFileDialog

from electrumsv import qrscanner
from electrumsv.app_state import app_state
from electrumsv.i18n import _

from .util import ButtonsMode, ButtonsTextEdit, MessageBoxMixin, ColorScheme


class ShowQRTextEdit(ButtonsTextEdit):
    def __init__(self, text: Optional[str]=None,
            buttons_mode: ButtonsMode=ButtonsMode.TOOLBAR_BOTTOM) -> None:
        super().__init__(text)
        self.buttons_mode = buttons_mode
        self.setReadOnly(True)
        self.qr_button = self.addButton("qrcode.png", self.qr_show, _("Show as QR code"))

    def qr_show(self):
        from .qrcodewidget import QRDialog
        try:
            s = str(self.toPlainText())
        except Exception:
            s = self.toPlainText()
        QRDialog(s).exec_()

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Show as QR code"), self.qr_show)
        m.exec_(e.globalPos())


class ScanQRTextEdit(ButtonsTextEdit, MessageBoxMixin):

    def __init__(self, text="", allow_multi=False):
        ButtonsTextEdit.__init__(self, text)
        self.allow_multi = allow_multi
        self.setReadOnly(0)
        self.addButton("file.png", self.file_input, _("Read file"))
        icon = "qrcode_white.png" if ColorScheme.dark_scheme else "qrcode.png"
        self.addButton(icon, self.qr_input, _("Read QR code"))

    def file_input(self):
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

    def qr_input(self, ignore_uris: bool=False):
        """
        ignore_uris - external logic may already be handling post-processing of scanned data.
        """
        try:
            data = qrscanner.scan_barcode(app_state.config.get_video_device())
        except Exception as e:
            self.show_error(str(e))
            data = ''
        if not data:
            data = ''
        if self.allow_multi:
            new_text = self.text() + data + '\n'
        else:
            new_text = data
        # This should only be set if the subclass is calling itself and knows that it has replaced
        # this method and it supports the extra parameter. See `PayToEdit.qr_input()`.
        if ignore_uris:
            self.setText(new_text, ignore_uris)
        else:
            self.setText(new_text)
        return data

    def contextMenuEvent(self, e):
        m = self.createStandardContextMenu()
        m.addAction(_("Read QR code"), self.qr_input)
        m.exec_(e.globalPos())
