import os
from typing import Callable, TYPE_CHECKING

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QCursor, QPainter
from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QTextEdit, QHBoxLayout, QPushButton, QWidget)
import qrcode

from electrumsv.i18n import _
from electrumsv.app_state import app_state

from .util import WindowModalDialog

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class QRCodeWidget(QWidget):

    def __init__(self, data = None, fixedSize=False):
        QWidget.__init__(self)
        self.data = None
        self.qr = None
        self.fixedSize=fixedSize
        if fixedSize:
            self.setFixedSize(fixedSize, fixedSize)
        self.setData(data)

    def clean_up(self) -> None:
        del self.mouseReleaseEvent

    def link_to_window(self, toggle_func: Callable[[], None]) -> None:
        self.mouseReleaseEvent = toggle_func
        self.enterEvent = lambda x: app_state.app.setOverrideCursor(QCursor(Qt.PointingHandCursor))
        self.leaveEvent = lambda x: app_state.app.setOverrideCursor(QCursor(Qt.ArrowCursor))

    def setData(self, data) -> None:
        if self.data != data:
            self.data = data
        if self.data:
            self.qr = qrcode.QRCode()
            self.qr.add_data(self.data)
            if not self.fixedSize:
                k = len(self.qr.get_matrix())
                self.setMinimumSize(k*5,k*5)
        else:
            self.qr = None

        self.update()

    def paintEvent(self, e):
        if not self.data:
            return

        black = QColor(0, 0, 0, 255)
        white = QColor(255, 255, 255, 255)

        if not self.qr:
            qp = QPainter()
            qp.begin(self)
            qp.setBrush(white)
            qp.setPen(white)
            r = qp.viewport()
            qp.drawRect(0, 0, r.width(), r.height())
            qp.end()
            return

        matrix = self.qr.get_matrix()
        k = len(matrix)
        qp = QPainter()
        qp.begin(self)
        r = qp.viewport()

        margin = 10
        framesize = min(r.width(), r.height())
        boxsize = int( (framesize - 2*margin)/k )
        size = k*boxsize
        left = (r.width() - size)/2
        top = (r.height() - size)/2

        # Make a white margin around the QR in case of dark theme use
        qp.setBrush(white)
        qp.setPen(white)
        qp.drawRect(left-margin, top-margin, size+(margin*2), size+(margin*2))
        qp.setBrush(black)
        qp.setPen(black)

        for r in range(k):
            for c in range(k):
                if matrix[r][c]:
                    qp.drawRect(left+c*boxsize, top+r*boxsize, boxsize - 1, boxsize - 1)
        qp.end()



class QRDialog(WindowModalDialog):

    def __init__(self, data, parent=None, title = "", show_text=False):
        WindowModalDialog.__init__(self, parent, title)

        vbox = QVBoxLayout()
        qrw = QRCodeWidget(data)
        qscreen = QApplication.primaryScreen()
        vbox.addWidget(qrw, 1)
        if show_text:
            text = QTextEdit()
            text.setText(data)
            text.setReadOnly(True)
            vbox.addWidget(text)
        hbox = QHBoxLayout()
        hbox.addStretch(1)

        filename = os.path.join(app_state.config.path, "qrcode.png")

        def print_qr():
            pixmap = qrw.grab()
            pixmap.save(filename, 'png')
            self.show_message(_("QR code saved to file") + " " + filename)

        def copy_to_clipboard():
            pixmap = qrw.grab()
            QApplication.clipboard().setPixmap(pixmap)
            self.show_message(_("QR code copied to clipboard"))

        b = QPushButton(_("Copy"))
        hbox.addWidget(b)
        b.clicked.connect(copy_to_clipboard)

        b = QPushButton(_("Save"))
        hbox.addWidget(b)
        b.clicked.connect(print_qr)

        b = QPushButton(_("Close"))
        hbox.addWidget(b)
        b.clicked.connect(self.accept)
        b.setDefault(True)

        vbox.addLayout(hbox)
        self.setLayout(vbox)
