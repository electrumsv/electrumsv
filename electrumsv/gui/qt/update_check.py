
from distutils.version import StrictVersion
import requests

from PyQt5.QtCore import QTimer
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QProgressBar, QLabel, QDialogButtonBox

from electrumsv.app_state import app_state
from electrumsv.gui.qt.util import read_QIcon, read_qt_ui
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.version import PACKAGE_VERSION


MSG_TITLE_CHECK = "Checking ElectrumSV.io for Updates"
MSG_BODY_CHECK = "Please wait.."

MSG_BODY_ERROR = ("The update check encountered an error.<br/><br/>"+
    "{error_message}.")
MSG_BODY_UPDATE_AVAILABLE = (
    "This version of ElectrumSV, <b>{this_version}</b>, is obsolete.<br/>"+
    "The latest version, <b>{next_version}</b>, was released on "+
    "<b>{next_version_date:%Y/%m/%d %I:%M%p}</b>."+
    "<br/><br/>"+
    "Please download it from "+
    "<a href='{download_uri}{next_version}/'>electrumsv.io downloads</a>.")
MSG_BODY_NO_UPDATE_AVAILABLE = ("The update check was successful.<br/><br/>"+
    "You are already using <b>{this_version}</b>, which is the latest version.")
MSG_BODY_UNRELEASED_AVAILABLE = ("The update check was successful.<br/><br/>"+
    "You are already using <b>{this_version}</b>, which is the later than the "+
    "last official version <b>{latest_version}</b>.")

logger = logs.get_logger("update_check.ui")


class UpdateCheckDialog(QWidget):
    _timer = None

    def __init__(self):
        super().__init__()

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

        # The timer is to update the progress bar while the request is blocking the thread.
        counter = 0
        def _on_timer_event():
            nonlocal counter
            counter += 1
            progress_fraction = counter / (10 * 10)
            self._set_progress(progress_fraction)

        self._timer = QTimer()
        self._timer.timeout.connect(_on_timer_event)
        self._timer.start(1000/10)

        app_state.app.update_check_signal.connect(self._on_update_result)
        app_state.app.update_check()

    def closeEvent(self, event):
        self._stop_updates()
        self._timer = None

        event.accept()

    def _stop_updates(self):
        self._timer.stop()
        try:
            app_state.app.update_check_signal.disconnect(self._on_update_result)
        except TypeError:
            # TypeError: 'method' object is not connected
            # This can be called twice, easier to catch the exception than store additional state.
            pass

    def _set_progress(self, ratio):
        self._progressbar.setValue(int(ratio * 500))

    def _set_title(self, text):
        self._title_label.setText(text)

    def _set_message(self, text):
        self._message_label.setText(text)

    def _on_update_result(self, success, result):
        if success:
            self._on_update_success(result)
        else:
            self._on_update_error(result)

    def _on_update_success(self, result):
        self._stop_updates()

        # Indicate success by filling in the progress bar.
        self._set_progress(1.0)

        # Handle the case where data was fetched and it is incorrect or lacking.
        if type(result) is not dict or 'version' not in result or 'date' not in result:
            self._set_message(_("The information about the latest version is broken."))
        # Handle the case where the data indicates a later version.
        elif StrictVersion(result['version']) > StrictVersion(PACKAGE_VERSION):
            from electrumsv import py37datetime
            release_date = py37datetime.datetime.fromisoformat(result['date']).astimezone()
            self._set_message(_(MSG_BODY_UPDATE_AVAILABLE).format(
                this_version = PACKAGE_VERSION,
                next_version = result['version'],
                next_version_date = release_date,
                download_uri='https://electrumsv.io/download/'))
        # Handle the case where the data indicates the same or older version.
        # Older version may be in the case of running from github.
        elif StrictVersion(result['version']) < StrictVersion(PACKAGE_VERSION):
            self._set_message(_(MSG_BODY_UNRELEASED_AVAILABLE).format(
                this_version=PACKAGE_VERSION, latest_version=result['version']))
        else:
            self._set_message(_(MSG_BODY_NO_UPDATE_AVAILABLE).format(
                this_version=result['version']))

    def _on_update_error(self, exc_info):
        self._stop_updates()

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
        self._progressBar.setStyleSheet(style_sheet)
        self._set_progress(1.0)

        self._set_message(MSG_BODY_ERROR.format(error_message=message_text))
