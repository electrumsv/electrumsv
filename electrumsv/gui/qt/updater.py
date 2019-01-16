from distutils.version import StrictVersion
import requests
import time

from PyQt5.QtCore import QCoreApplication, QTimer
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QProgressBar, QLabel, QDialogButtonBox

from electrumsv.gui.qt.util import TaskThread, read_QIcon, read_qt_ui
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.version import PACKAGE_VERSION


MSG_TITLE_CHECK = "Checking ElectrumSV.io for Updates"
MSG_BODY_CHECK = "Please wait.."

MSG_BODY_ERROR = ("The update check encountered an error.<br/><br/>"+
    "{error_message}.")
MSG_BODY_UPDATE_AVAILABLE = (
    "This version of ElectrumSV, <b>{this_version}</b>, is obsolete.<br/>"+
    "The latest version, <b>{next_version}</b>, was released on <b>{next_version_date}</b>."+
    "<br/><br/>"+
    "Please download it from "+
    "<a href='{download_uri}{next_version}/'>electrumsv.io downloads</a>.")
MSG_BODY_NO_UPDATE_AVAILABLE = ("The update check was successful.<br/><br/>"+
    "You are already using <b>{this_version}</b>, which is the latest version.")

logger = logs.get_logger("updater")


class UpdaterDialog(QWidget):
    def __init__(self, main_window, result_cb=None):
        super().__init__()

        self._main_window = main_window

        self.setWindowTitle('ElectrumSV - ' + _('Update Check'))
        self.setWindowIcon(read_QIcon("electrum-sv.png"))
        self.resize(600, 400)

        widget: QWidget = read_qt_ui("updater_widget.ui")

        layout: QVBoxLayout = widget.findChild(QVBoxLayout, "vertical_layout")
        self._title_label: QLabel = widget.findChild(QLabel, "title_label")
        self._title_label.setText(_(MSG_TITLE_CHECK))
        self._progressbar: QProgressBar = widget.findChild(QProgressBar)
        self._progressbar.setValue(1)
        self._message_label: QLabel = widget.findChild(QLabel, "message_label")
        self._message_label.setText(_(MSG_BODY_CHECK))
        self._buttonbar: QDialogButtonBox = widget.findChild(QDialogButtonBox)
        self._buttonbar.rejected.connect(self.close)

        self.setLayout(layout)

        self.show()

        self.updater = Updater(self, result_cb)
        self.updater.start_gui()

    def closeEvent(self, event):
        self.updater.stop_gui()
        self.updater = None

        event.accept()

    def set_progress(self, ratio):
        self._progressbar.setValue(int(ratio * 500))

    def set_title(self, text):
        self._title_label.setText("<h3>"+ text +"</h3>")

    def set_message(self, text):
        self._message_label.setText(text)


class Updater:
    _parent = None
    _thread = None
    _timer = None

    def __init__(self, _parent=None, result_cb=None):
        self._parent = _parent
        self._running = False
        self._result_cb = result_cb

    def start_gui(self):
        def _on_request_success(result):
            if not self._running:
                return

            # Indicate success by filling in the progress bar.
            self._parent.set_progress(1.0)

            # Handle the case where data was fetched and it is incorrect or lacking.
            if type(result) is not dict or 'version' not in result or 'date' not in result:
                self._parent.set_message(_("The information about the latest version is broken."))
            # Handle the case where the data indicates a later version.
            elif StrictVersion(result['version']) > StrictVersion(PACKAGE_VERSION):
                self._parent.set_message(_(MSG_BODY_UPDATE_AVAILABLE).format(
                    this_version = PACKAGE_VERSION,
                    next_version = result['version'],
                    next_version_date = result['date'],
                    download_uri='https://electrumsv.io/download/'))

                if self._result_cb is not None:
                    self._result_cb(result)
            # Handle the case where the data indicates the same or older version.
            # Older version may be in the case of running from github.
            else:
                self._parent.set_message(_(MSG_BODY_NO_UPDATE_AVAILABLE).format(
                    this_version=result['version']))

        def _on_request_error(exc_info):
            if not self._running:
                return

            # Ensure the exception appears in the logs.
            logger.exception("Please consider reporting this exception:", exc_info=exc_info)

            message_text = _("Try again later, or consider reporting the problem.")
            if exc_info[0] is requests.exceptions.Timeout:
                message_text = _("The request took too long.") +" "+ message_text
            elif exc_info[0] is requests.exceptions.ConnectionError:
                message_text = _("Unable to connect.") +" "+ message_text
            else:
                message_text = str(exc_info[1]) +" "+ message_text

            # Change the color of the progress bar to red to reflect error.
            style_sheet = ("QProgressBar::chunk {background: QLinearGradient( x1: 0, y1: 0, "+
                "x2: 1, y2: 0,stop: 0 #FF0350,stop: 0.4999 #FF0020,stop: 0.5 #FF0019,"+
                "stop: 1 #FF0000 );border-bottom-right-radius: 5px;"+
                "border-bottom-left-radius: 5px;border: .px solid black;}")
            self._parent._progressBar.setStyleSheet(style_sheet)
            self._parent.set_progress(1.0)

            self._parent.set_message(MSG_BODY_ERROR.format(error_message=message_text))

        self._running = True
        self.request_version_metadata(_on_request_success, on_error=_on_request_error)

    def stop_gui(self):
        self._running = False
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        if self._thread is not None:
            # We forcefully exit the thread, as other options block.
            self._thread.terminate()
            self._thread.wait()

    def request_version_metadata(self, on_success, on_done=None, on_error=None):
        if self._thread is None:
            self._thread = TaskThread(self._parent)
        elif not self._thread.isRunning():
            self._thread.start()

        if self._parent is not None:
            # The timer is to update the progress bar while the request is blocking the thread.
            counter = 0
            def _on_timer_event():
                nonlocal counter
                counter += 1
                progress_fraction = counter / (10 * 10)
                self._parent.set_progress(progress_fraction)

                if progress_fraction >= 1.0:
                    pass

            self._timer = QTimer()
            self._timer.timeout.connect(_on_timer_event)
            self._timer.start(1000/10)

        def wrapped_done():
            if self._parent is not None:
                self._timer.stop()
                self._timer = None
            if self._thread.tasks.empty():
                self._thread.stop()

            if on_done is not None:
                on_done()

        self._thread.add(self._get_version_metadata, on_success, wrapped_done, on_error)

    def _get_version_metadata(self):
        response = requests.request(
            'GET', "https://electrumsv.io/release.json",
            headers={'User-Agent' : 'ElectrumSV'},
            timeout=10)
        return response.json()

    def is_running(self):
        return self._thread.isRunning()


if __name__ == '__main__':
    app = QCoreApplication([])

    def on_success(result):
        print(f"Received result: {result}")

    def on_error(error):
        print(f"Encountered error: {error}")

    updater = Updater()
    updater.request_version_metadata(on_success, on_error=on_error)
    while updater.is_running():
        app.processEvents()
        time.sleep(0.1)

    app.quit()
