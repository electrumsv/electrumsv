import os
from typing import Optional

from PyQt5.QtCore import pyqtSignal, QEvent, Qt
from PyQt5.QtGui import QColor, QCursor, QMouseEvent, QPainter, QPaintEvent
from PyQt5.QtWidgets import (
    QApplication, QVBoxLayout, QTextEdit, QHBoxLayout, QPushButton, QWidget)
import qrcode

from ...i18n import _
from ...app_state import app_state, get_app_state_qt

from .util import WindowModalDialog


class QRCodeWidget(QWidget):
    mouse_release_signal = pyqtSignal()

    def __init__(self, data: Optional[str]=None, fixedSize: int=0) -> None:
        QWidget.__init__(self)
        self.data: Optional[str] = None
        self.qr: Optional[qrcode.QRCode] = None
        self.fixedSize=fixedSize
        if fixedSize:
            self.setFixedSize(fixedSize, fixedSize)
        self.setData(data)
        self.setToolTip(_("QR code"))

    def enterEvent(self, event: QEvent) -> None:
        get_app_state_qt().app_qt.setOverrideCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        super().enterEvent(event)

    def leaveEvent(self, event: QEvent) -> None:
        get_app_state_qt().app_qt.setOverrideCursor(QCursor(Qt.CursorShape.ArrowCursor))
        super().leaveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self.mouse_release_signal.emit()
        super().mouseReleaseEvent(event)

    def setData(self, data: Optional[str]) -> None:
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

    def paintEvent(self, event: QPaintEvent) -> None:
        black = QColor(0, 0, 0, 255)
        white = QColor(255, 255, 255, 255)

        if not self.qr:
            qp = QPainter()
            qp.begin(self)
            qp.setBrush(white)
            qp.setPen(white)
            rect = qp.viewport()
            qp.drawRect(0, 0, rect.width(), rect.height())
            qp.end()
            return

        matrix = self.qr.get_matrix()
        k = len(matrix)
        qp = QPainter()
        qp.begin(self)
        rect = qp.viewport()

        margin = 10
        framesize = min(rect.width(), rect.height())
        boxsize = int( (framesize - 2*margin)/k )
        size = k*boxsize
        left = (rect.width() - size)//2
        top = (rect.height() - size)//2

        # Make a white margin around the QR in case of dark theme use
        qp.setBrush(white)
        qp.setPen(white)
        qp.drawRect(left-margin, top-margin, size+(margin*2), size+(margin*2))
        qp.setBrush(black)
        qp.setPen(black)

        for rv in range(k):
            for c in range(k):
                if matrix[rv][c]:
                    qp.drawRect(left+c*boxsize, top+rv*boxsize, boxsize - 1, boxsize - 1)
        qp.end()



class QRDialog(WindowModalDialog):

    def __init__(self, data: str, parent: Optional[QWidget]=None, title: str = "",
            show_text: bool=False) -> None:
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

        def print_qr() -> None:
            pixmap = qrw.grab()
            pixmap.save(filename, 'png')
            self.show_message(_("QR code saved to file") + " " + filename)

        def copy_to_clipboard() -> None:
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
