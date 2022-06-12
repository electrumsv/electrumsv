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

import time
import math
import sys
import os
from typing import Optional

from PyQt6.QtCore import PYQT_VERSION, QByteArray, pyqtSignal, QObject, QPoint, QRect, QSize, Qt
from PyQt6.QtGui import QColorConstants, QImage, QPainter, QPixmap
from PyQt6.QtMultimedia import QCamera, QMediaCaptureSession, QMediaDevices, QVideoFrame, \
    QVideoFrameFormat, QVideoSink
from PyQt6.QtWidgets import QCheckBox, QDialog, QGraphicsEffect, QGraphicsScene, \
    QGraphicsPixmapItem, QHBoxLayout, QLabel, QLayout, QLayoutItem, QPushButton, QVBoxLayout, \
    QWidget

from .....simple_config import SimpleConfig
from .....i18n import _
from .....qrreader import get_qr_reader
from .....qrreader.abstract_base import QrCodeResult
from .....logs import logs

from ...util import MessageBoxMixin

from .video_widget import QrReaderVideoWidget
from .video_overlay import QrReaderVideoOverlay
from .crop_blur_effect import QrReaderCropBlurEffect
from .validator import AbstractQrReaderValidator, QrReaderValidatorCounted, QrReaderValidatorResult


logger = logs.get_logger("qrreader-camera")

class CameraError(RuntimeError):
    ''' Base class of the camera-related error conditions. '''

class NoCamerasFound(CameraError):
    ''' Raised by start_scan if no usable cameras were found. Interested
    code can catch this specific exception.'''

class NoCameraResolutionsFound(CameraError):
    ''' Raised internally if no usable camera resolutions were found. '''

class MissingQrDetectionLib(RuntimeError):
    ''' Raised if we can't find zbar or whatever other platform lib
    we require to detect QR in image frames. '''


# Copied from Electrum Core. Their standard copyright and license apply. No license header in
# the source file `electrum\gui\qt\util.py`.
class ImageGraphicsEffect(QObject):
    """
    Applies a QGraphicsEffect to a QImage
    """

    def __init__(self, parent: QObject, effect: QGraphicsEffect) -> None:
        super().__init__(parent)
        assert effect, 'effect must be set'
        self.effect = effect
        self.graphics_scene = QGraphicsScene()
        self.graphics_item = QGraphicsPixmapItem()
        self.graphics_item.setGraphicsEffect(effect)
        self.graphics_scene.addItem(self.graphics_item)

    def apply(self, image: QImage) -> QImage:
        assert image, 'image must be set'
        result = QImage(image.size(), QImage.Format.Format_ARGB32)
        result.fill(QColorConstants.Transparent)
        painter = QPainter(result)
        self.graphics_item.setPixmap(QPixmap.fromImage(image))
        self.graphics_scene.render(painter)
        self.graphics_item.setPixmap(QPixmap())
        return result


# Copied from Electrum Core. Their standard copyright and license apply. No license header in
# the source file `electrum\gui\qt\util.py`.
class FixedAspectRatioLayout(QLayout):
    def __init__(self, parent: Optional[QWidget]=None, aspect_ratio: float=1.0) -> None:
        super().__init__(parent)
        self.aspect_ratio = aspect_ratio
        self.items: list[QLayoutItem] = []

    def set_aspect_ratio(self, aspect_ratio: float = 1.0) -> None:
        self.aspect_ratio = aspect_ratio
        self.update()

    def addItem(self, item: QLayoutItem) -> None:
        self.items.append(item)

    def count(self) -> int:
        return len(self.items)

    # NOTE(typing) Return type "Optional[QLayoutItem]" of "itemAt" incompatible with return type
    #     "QLayoutItem" in supertype "QLayout"
    def itemAt(self, index: int) -> Optional[QLayoutItem]: # type: ignore[override]
        if index >= len(self.items):
            return None
        return self.items[index]

    # NOTE(typing) Return type "Optional[QLayoutItem]" of "takeAt" incompatible with return type
    #     "QLayoutItem" in supertype "QLayout"
    def takeAt(self, index: int) -> Optional[QLayoutItem]: # type: ignore[override]
        if index >= len(self.items):
            return None
        return self.items.pop(index)

    def _get_contents_margins_size(self) -> QSize:
        margins = self.contentsMargins()
        return QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def setGeometry(self, rect: QRect) -> None:
        super().setGeometry(rect)
        if not self.items:
            return

        contents = self.contentsRect()
        if contents.height() > 0:
            c_aratio = contents.width() / contents.height()
        else:
            c_aratio = 1
        s_aratio = self.aspect_ratio
        item_rect = QRect(QPoint(0, 0), QSize(
            contents.width() if c_aratio < s_aratio else int(contents.height() * s_aratio),
            contents.height() if c_aratio > s_aratio else int(contents.width() / s_aratio)
        ))

        content_margins = self.contentsMargins()
        free_space = contents.size() - item_rect.size()

        for item in self.items:
            if free_space.width() > 0 and \
                    not item.alignment() & Qt.AlignmentFlag.AlignLeft:
                if item.alignment() & Qt.AlignmentFlag.AlignRight:
                    item_rect.moveRight(contents.width() + content_margins.right())
                else:
                    item_rect.moveLeft(content_margins.left() + (free_space.width() // 2))
            else:
                item_rect.moveLeft(content_margins.left())

            if free_space.height() > 0 and \
                    not item.alignment() & Qt.AlignmentFlag.AlignTop:
                if item.alignment() & Qt.AlignmentFlag.AlignBottom:
                    item_rect.moveBottom(contents.height() + content_margins.bottom())
                else:
                    item_rect.moveTop(content_margins.top() + (free_space.height() // 2))
            else:
                item_rect.moveTop(content_margins.top())

            item.widget().setGeometry(item_rect)

    def sizeHint(self) -> QSize:
        result = QSize()
        for item in self.items:
            result = result.expandedTo(item.sizeHint())
        return self._get_contents_margins_size() + result

    def minimumSize(self) -> QSize:
        result = QSize()
        for item in self.items:
            result = result.expandedTo(item.minimumSize())
        return self._get_contents_margins_size() + result

    def expandingDirections(self) -> Qt.Orientation:
        return Qt.Orientation.Horizontal | Qt.Orientation.Vertical




class QrReaderCameraDialog(MessageBoxMixin, QDialog):
    """
    Dialog for reading QR codes from a camera
    """

    # Try to crop so we have minimum 512 dimensions
    SCAN_SIZE: int = 512

    qr_finished = pyqtSignal(bool, str, object)

    def __init__(self, parent: Optional[QWidget], *, config: SimpleConfig) -> None:
        ''' Note: make sure parent is a "top_level_window()" as per
        MessageBoxMixin API else bad things can happen on macOS. '''
        QDialog.__init__(self, parent=parent)
        self._logger = logs.get_logger(f"camera-dialog-{id(self)}")

        self.validator: Optional[AbstractQrReaderValidator] = None
        self.frame_id: int = 0
        self.qr_crop: Optional[QRect] = None
        self.qrreader_res: list[QrCodeResult] = []
        self.validator_res: Optional[QrReaderValidatorResult] = None
        self.last_stats_time: float = 0.0
        self.frame_counter: int = 0
        self.qr_frame_counter: int = 0
        self.last_qr_scan_ts: float = 0.0
        self._capture_session: Optional[QMediaCaptureSession] = None
        self._video_sink: Optional[QVideoSink] = None
        self.camera: Optional[QCamera] = None
        self._error_message: Optional[str] = None
        self._ok_done: bool = False
        self.camera_sc_conn = None
        self.resolution: Optional[QSize] = None

        self.config = config

        # Try to get the QR reader for this system
        self.qrreader = get_qr_reader()
        if not self.qrreader:
            raise MissingQrDetectionLib(_("The platform QR detection library is not available."))

        # Set up the window, add the maximize button
        flags = self.windowFlags()
        # NOTE(typing) Unsupported operand types for | ("WindowFlags" and "WindowType")
        flags = flags | Qt.WindowType.WindowMaximizeButtonHint
        self.setWindowFlags(flags)
        self.setWindowTitle(_("Scan QR Code"))
        self.setWindowModality(Qt.WindowModality.WindowModal if parent \
            else Qt.WindowModality.ApplicationModal)

        # Create video widget and fixed aspect ratio layout to contain it
        self.video_widget = QrReaderVideoWidget()
        self.video_overlay = QrReaderVideoOverlay()
        self.video_layout = FixedAspectRatioLayout()
        self.video_layout.addWidget(self.video_widget)
        self.video_layout.addWidget(self.video_overlay)

        # Create root layout and add the video widget layout to it
        vbox = QVBoxLayout()
        self.setLayout(vbox)
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addLayout(self.video_layout)

        self.lowres_label = QLabel(_("Note: This camera generates frames of relatively low "
            "resolution; QR scanning accuracy may be affected"))
        self.lowres_label.setWordWrap(True)
        self.lowres_label.setAlignment(Qt.AlignmentFlag(Qt.AlignmentFlag.AlignVCenter |
            Qt.AlignmentFlag.AlignHCenter))
        vbox.addWidget(self.lowres_label)
        self.lowres_label.setHidden(True)

        # Create a layout for the controls
        controls_layout = QHBoxLayout()
        controls_layout.addStretch(2)
        controls_layout.setContentsMargins(10, 10, 10, 10)
        controls_layout.setSpacing(10)
        vbox.addLayout(controls_layout)

        # Flip horizontally checkbox with default coming from global config
        self.flip_x = QCheckBox()
        self.flip_x.setText(_("&Flip horizontally"))
        self.flip_x.setChecked(bool(self.config.get('qrreader_flip_x', True)))
        self.flip_x.stateChanged.connect(self._on_flip_x_changed)
        controls_layout.addWidget(self.flip_x)

        close_but = QPushButton(_("&Close"))
        close_but.clicked.connect(self.reject)
        controls_layout.addWidget(close_but)

        # Create the video sink to receive events when new frames arrive.
        self._video_sink = QVideoSink()
        # NOTE(PyQt6) The bindings we are using do not define this signal (the documentation is
        #     vague on it as well).
        self._video_sink.videoFrameChanged.connect( # type: ignore[attr-defined]
            self._on_frame_available)

        # Create the crop blur effect
        self.crop_blur_effect = QrReaderCropBlurEffect(self)
        self.image_effect = ImageGraphicsEffect(self, self.crop_blur_effect)


        # Note these should stay as queued connections becasue we use the idiom
        # self.reject() and self.accept() in this class to kill the scan --
        # and we do it from within callback functions. If you don't use
        # queued connections here, bad things can happen.
        # NOTE(typing) Too many arguments for "connect" of "pyqtBoundSignal"
        self.finished.connect(self._boilerplate_cleanup,
            Qt.ConnectionType.QueuedConnection) # type: ignore[call-arg]
        # NOTE(typing) Too many arguments for "connect" of "pyqtBoundSignal"
        self.finished.connect(self._on_finished,
            Qt.ConnectionType.QueuedConnection) # type: ignore[call-arg]

    def _on_flip_x_changed(self, _state: int) -> None:
        self.config.set_key('qrreader_flip_x', self.flip_x.isChecked())

    def _get_resolution(self, resolutions: list[QSize], min_size: int) -> tuple[QSize, bool]:
        """
        Given a list of resolutions that the camera supports this function picks the
        lowest resolution that is at least min_size in both width and height.
        If no resolution is found, NoCameraResolutionsFound is raised.
        """
        def res_list_to_str(res_list: list[QSize]) -> str:
            return ', '.join(['{}x{}'.format(r.width(), r.height()) for r in res_list])

        def check_res(res: QSize) -> bool:
            return res.width() >= min_size and res.height() >= min_size

        self._logger.info('searching for at least {0}x{0}'.format(min_size))

        # Query and display all resolutions the camera supports
        format_str = 'camera resolutions: {}'
        self._logger.info(format_str.format(res_list_to_str(resolutions)))

        # Filter to those that are at least min_size in both width and height
        ideal_resolutions = [r for r in resolutions if check_res(r)]
        less_than_ideal_resolutions = [r for r in resolutions if r not in ideal_resolutions]
        format_str = 'ideal resolutions: {}, less-than-ideal resolutions: {}'
        self._logger.info(format_str.format(res_list_to_str(ideal_resolutions),
            res_list_to_str(less_than_ideal_resolutions)))

        # Raise an error if we have no usable resolutions
        if not ideal_resolutions and not less_than_ideal_resolutions:
            raise NoCameraResolutionsFound(_("Cannot start QR scanner, no usable camera "
                "resolution found.") + self._linux_pyqt5bug_msg())

        if not ideal_resolutions:
            self._logger.warning("No ideal resolutions found, falling back to less-than-ideal "
                "resolutions -- QR recognition may fail!")
            candidate_resolutions = less_than_ideal_resolutions
            is_ideal = False
        else:
            candidate_resolutions = ideal_resolutions
            is_ideal = True


        # Sort the usable resolutions, least number of pixels first, get the first element
        resolution = sorted(candidate_resolutions, key=lambda r: r.width() * r.height(),
            reverse=not is_ideal)[0]
        format_str = 'chosen resolution is {}x{}'
        self._logger.info(format_str.format(resolution.width(), resolution.height()))

        return resolution, is_ideal

    @staticmethod
    def _get_crop(resolution: QSize, scan_size: int) -> QRect:
        """
        Returns a QRect that is scan_size x scan_size in the middle of the resolution
        """
        scan_pos_x = (resolution.width() - scan_size) // 2
        scan_pos_y = (resolution.height() - scan_size) // 2
        return QRect(scan_pos_x, scan_pos_y, scan_size, scan_size)

    @staticmethod
    def _linux_pyqt5bug_msg() -> str:
        ''' Returns a string that may be appended to an exception error message
        only if on Linux and PyQt5 < 5.12.2, otherwise returns an empty string. '''
        if (sys.platform == 'linux' and PYQT_VERSION < 0x050c02 # Check if PyQt5 < 5.12.2 on linux
                # Also: this warning is not relevant to APPIMAGE; so make sure
                # we are not running from APPIMAGE.
                and not os.environ.get('APPIMAGE')):
            # In this case it's possible we couldn't detect a camera because
            # of that missing libQt5MultimediaGstTools.so problem.
            return ("\n\n" + _('If you indeed do have a usable camera connected, then this error '
                'may be caused by bugs in previous PyQt5 versions on Linux. Try installing the '
                'latest PyQt5:') + "\n\n" + "python3 -m pip install --user -I pyqt5")
        return ''

    def start_scan(self, device_id: bytes = b'') -> None:
        """
        Scans a QR code from the given camera device.
        If no QR code is found the returned string will be empty.
        If the camera is not found or can't be opened NoCamerasFound will be raised.
        """

        self.validator = QrReaderValidatorCounted()
        self.validator.strong_count = 5  # FIXME: make this time based rather than framect based

        device_info = None
        video_input_id = QByteArray(len(device_id), device_id)
        for video_input in QMediaDevices.videoInputs():
            if video_input.id() == video_input_id:
                device_info = video_input
                break

        if not device_info:
            self._logger.info('Failed to open selected camera, trying to use default camera')
            device_info = QMediaDevices.defaultVideoInput()

        if not device_info or device_info.isNull():
            raise NoCamerasFound(_("Cannot start QR scanner, no usable camera found.") +
                self._linux_pyqt5bug_msg())

        self._init_stats()
        self.qrreader_res = []
        self.validator_res = None
        self._ok_done = False
        self._error_message = None

        if self.camera:
            self._logger.info("Warning: start_scan already called for this instance.")

        assert self._video_sink is not None

        self.camera = QCamera(device_info)
        self._capture_session = QMediaCaptureSession()
        self._capture_session.setCamera(self.camera)
        self._capture_session.setVideoSink(self._video_sink)

        # log the errors we get, if any, for debugging
        self.camera.errorOccurred.connect(self._on_camera_error_occurred)
        self.camera.start()

    def _set_resolution(self, resolution: QSize) -> None:
        self.resolution = resolution
        self.qr_crop = self._get_crop(resolution, self.SCAN_SIZE)

        # Initialize the video widget
        # .. on macOS this makes it fixed size for some reason.
        #self.video_widget.setMinimumSize(resolution)
        self.resize(720, 540)
        self.video_overlay.set_crop(self.qr_crop)
        self.video_overlay.set_resolution(resolution)
        self.video_layout.set_aspect_ratio(resolution.width() / resolution.height())

        # Set up the crop blur effect
        self.crop_blur_effect.setCrop(self.qr_crop)

    # def _on_camera_status_changed(self, status: QCamera.Status) -> None:
    #     if self._ok_done:
    #         # camera/scan is quitting, abort.
    #         return

    #     if status == QCamera.LoadedStatus:
    #         # Determine the optimal resolution and compute the crop rect
    #         assert self.camera is not None
    #         camera_resolutions = self.camera.supportedViewfinderResolutions()
    #         try:
    #             resolution, was_ideal = self._get_resolution(camera_resolutions, self.SCAN_SIZE)
    #         except RuntimeError as e:
    #             self._error_message = str(e)
    #             self.reject()
    #             return
    #         self._set_resolution(resolution)

    #         # Set the camera resolution
    #         viewfinder_settings = QCameraViewfinderSettings()
    #         viewfinder_settings.setResolution(resolution)
    #         self.camera.setViewfinderSettings(viewfinder_settings)

    #         # Counter for the QR scanner frame number
    #         self.frame_id = 0

    #         self.camera.start()
    #         # if they have a low res camera, show the warning label.
    #         self.lowres_label.setVisible(not was_ideal)
    #     elif status == QCamera.UnloadedStatus or status == QCamera.UnavailableStatus:
    #         self._error_message = _("Cannot start QR scanner, camera is unavailable.")
    #         self.reject()
    #     elif status == QCamera.ActiveStatus:
    #         self.open()

    def _on_camera_error_occurred(self, errorCode: QCamera.Error, errorString: str) -> None:
        self._logger.info("QCamera error: %s", errorString)

    def accept(self) -> None:
        self._ok_done = True  # immediately blocks further processing
        super().accept()

    def reject(self) -> None:
        self._ok_done = True  # immediately blocks further processing
        super().reject()

    def _boilerplate_cleanup(self) -> None:
        self._close_camera()
        if self.isVisible():
            self.close()

    def _close_camera(self) -> None:
        self._capture_session = None
        self._video_sink = None
        if self.camera:
            self.camera.stop()
            self.camera = None

    def _on_finished(self, code: QDialog.DialogCode) -> None:
        res: str = ( (code == QDialog.DialogCode.Accepted
                    and self.validator_res and self.validator_res.accepted
                    and self.validator_res.simple_result)
                or '' )

        self.validator = None

        self._logger.info('closed %s', res)

        self.qr_finished.emit(code == QDialog.DialogCode.Accepted, self._error_message, res)

    def _on_frame_available(self, frame: QVideoFrame) -> None:
        if not frame.isValid():
            return None

        image_format = QVideoFrameFormat.imageFormatFromPixelFormat(frame.pixelFormat())
        if image_format == QImage.Format.Format_Invalid:
            logger.info(_('QR code scanner for video frame with invalid pixel format'))
            return None

        self._on_frame_image_available(frame.toImage())

        # if not frame.map(QVideoFrame.MapMode.ReadOnly):
        #     logger.info(_('QR code scanner failed to map video frame'))
        #     return None

        # try:
        #     # NOTE(typing) No overload variant of "QImage" matches argument types "int", "int",
        #     #     "int", "Format"
        #     image = QImage(int(frame.bits()), frame.width(),  # type: ignore[call-overload]
        #         frame.height(), image_format)

        #     # Check whether we need to flip the image on any axis
        #     surface_format = frame.surfaceFormat()
        #     flip_x = surface_format.isMirrored()
        #     flip_y = surface_format.scanLineDirection() == QVideoFrameFormat.Direction.BottomToTop

        #     # Mirror the image if needed
        #     if flip_x or flip_y:
        #         image = image.mirrored(flip_x, flip_y)

        #     # Create a copy of the image so the original frame data can be freed
        #     image = image.copy()
        # finally:
        #     frame.unmap()

    def _on_frame_image_available(self, image: QImage) -> None:
        if self._ok_done:
            return

        assert self.resolution is not None
        self.frame_id += 1

        if image.size() != self.resolution:
            self._logger.info('Getting video data at %dx%d instead of the requested %dx%d, '
                'switching resolution.', image.size().width(), image.size().height(),
                self.resolution.width(), self.resolution.height())
            self._set_resolution(image.size())

        flip_x = self.flip_x.isChecked()

        # Only QR scan every QR_SCAN_PERIOD secs
        assert self.qrreader is not None
        qr_scanned = time.time() - self.last_qr_scan_ts >= self.qrreader.interval()
        if qr_scanned:
            assert self.qr_crop is not None
            assert self.validator is not None

            self.last_qr_scan_ts = time.time()
            # Crop the frame so we only scan a SCAN_SIZE rect
            frame_cropped = image.copy(self.qr_crop)

            # Convert to Y800 / GREY FourCC (single 8-bit channel)
            # This creates a copy, so we don't need to keep the frame around anymore
            frame_y800 = frame_cropped.convertToFormat(QImage.Format.Format_Grayscale8)

            # Read the QR codes from the frame
            self.qrreader_res = self.qrreader.read_qr_code(
                # NOTE(typing) Argument 1 to "read_qr_code" of "AbstractQrCodeReader" has
                #     incompatible type "int"; expected "c_void_p"
                frame_y800.constBits().__int__(), # type: ignore[arg-type]
                frame_y800.sizeInBytes(),
                frame_y800.bytesPerLine(),
                frame_y800.width(),
                frame_y800.height(), self.frame_id
                )

            # Call the validator to see if the scanned results are acceptable
            self.validator_res = self.validator.validate_results(self.qrreader_res)

            # Update the video overlay with the results
            self.video_overlay.set_results(self.qrreader_res, flip_x, self.validator_res)

            # Close the dialog if the validator accepted the result
            if self.validator_res.accepted:
                self.accept()
                return

        # Apply the crop blur effect
        if self.image_effect:
            image = self.image_effect.apply(image)

        # If horizontal flipping is enabled, only flip the display
        if flip_x:
            image = image.mirrored(True, False)

        # Display the frame in the widget
        self.video_widget.setPixmap(QPixmap.fromImage(image))

        self._update_stats(qr_scanned)

    def _init_stats(self) -> None:
        self.last_stats_time = time.perf_counter()
        self.frame_counter = 0
        self.qr_frame_counter = 0

    def _update_stats(self, qr_scanned: bool) -> None:
        self.frame_counter += 1
        if qr_scanned:
            self.qr_frame_counter += 1
        now = time.perf_counter()
        last_stats_delta = now - self.last_stats_time
        if last_stats_delta > 1.0:  # stats every 1.0 seconds
            assert self.validator is not None
            fps = self.frame_counter / last_stats_delta
            qr_fps = self.qr_frame_counter / last_stats_delta
            if self.validator is not None:
                # 1/3 of a second's worth of qr frames determines strong_count
                self.validator.strong_count = math.ceil(qr_fps / 3)
            self._logger.info("running at %f FPS, scanner at %f FPS", fps, qr_fps)
            self.frame_counter = 0
            self.qr_frame_counter = 0
            self.last_stats_time = now
