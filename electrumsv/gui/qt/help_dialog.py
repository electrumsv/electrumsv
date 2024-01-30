from PyQt6.QtCore import QUrl
from PyQt6.QtWidgets import QTextBrowser, QVBoxLayout, QWidget

from electrumsv.i18n import _
from electrumsv.util import text_resource_path

from .util import Buttons, OkButton, WindowModalDialog


class HelpDialog(WindowModalDialog):
    def __init__(self, parent: QWidget, help_dirname: str, help_file_name: str) -> None:
        super().__init__(parent)

        self.setWindowTitle(_("ElectrumSV - In-Wallet Help"))
        self.setMinimumSize(450, 400)

        source_path = text_resource_path(help_dirname, f"{help_file_name}.html")

        widget = QTextBrowser()
        widget.document().setDocumentMargin(15)
        widget.setOpenLinks(True)
        widget.setOpenExternalLinks(True)
        widget.setAcceptRichText(True)
        widget.setSource(QUrl.fromLocalFile(source_path))

        vbox = QVBoxLayout(self)
        vbox.addWidget(widget)
        vbox.addLayout(Buttons(OkButton(self)))

    def run(self) -> int:
        return self.exec()
