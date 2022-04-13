#!/usr/bin/env python3
#
# Electron Cash - lightweight Bitcoin client
# Copyright (C) 2019 Axel Gembe <derago@gmail.com>
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

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QImage
from PyQt5.QtMultimedia import QAbstractVideoBuffer, QAbstractVideoSurface, QVideoFrame, \
    QVideoSurfaceFormat

from .....i18n import _
from .....logs import logs


_logger = logs.get_logger(__name__)


class QrReaderVideoSurface(QAbstractVideoSurface):
    """
    Receives QVideoFrames from QCamera, converts them into a QImage, flips the X and Y axis if
    necessary and sends them to listeners via the frame_available event.
    """

    # def __init__(self, parent: Optional[QObject]=None) -> None:
    #     super().__init__(parent)

    def present(self, frame: QVideoFrame) -> bool:
        if not frame.isValid():
            return False

        image_format = QVideoFrame.imageFormatFromPixelFormat(frame.pixelFormat())
        if image_format == QImage.Format.Format_Invalid:
            _logger.info(_('QR code scanner for video frame with invalid pixel format'))
            return False

        if not frame.map(QAbstractVideoBuffer.ReadOnly):
            _logger.info(_('QR code scanner failed to map video frame'))
            return False

        try:
            # NOTE(typing) No overload variant of "QImage" matches argument types "int", "int",
            #     "int", "Format"
            img = QImage(int(frame.bits()), frame.width(),  # type: ignore[call-overload]
                frame.height(), image_format)

            # Check whether we need to flip the image on any axis
            surface_format = self.surfaceFormat()
            flip_x = surface_format.isMirrored()
            flip_y = surface_format.scanLineDirection() == QVideoSurfaceFormat.BottomToTop

            # Mirror the image if needed
            if flip_x or flip_y:
                img = img.mirrored(flip_x, flip_y)

            # Create a copy of the image so the original frame data can be freed
            img = img.copy()
        finally:
            frame.unmap()

        self.frame_available.emit(img)

        return True

    # NOTE(typing) The method matches, but it has a ... for the argument, beats me.
    # error: Signature of "supportedPixelFormats" incompatible with supertype
    #     "QAbstractVideoSurface"  [override]
    # note:      Superclass:
    # note:          def supportedPixelFormats(self, type: HandleType = ...) -> List[PixelFormat]
    # note:      Subclass:
    # note:          def supportedPixelFormats(self, type: HandleType) -> List[PixelFormat]
    def supportedPixelFormats(self, # type: ignore[override]
            handler_type: QAbstractVideoBuffer.HandleType) -> list[QVideoFrame.PixelFormat]:
        if handler_type == QAbstractVideoBuffer.NoHandle:
            # We support all pixel formats that can be understood by QImage directly
            return [QVideoFrame.Format_ARGB32, QVideoFrame.Format_ARGB32_Premultiplied,
                QVideoFrame.Format_RGB32, QVideoFrame.Format_RGB24, QVideoFrame.Format_RGB565,
                QVideoFrame.Format_RGB555, QVideoFrame.Format_ARGB8565_Premultiplied]
        return []

    frame_available = pyqtSignal(QImage)
