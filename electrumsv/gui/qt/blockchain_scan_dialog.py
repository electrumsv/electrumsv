from collections import defaultdict
import concurrent.futures
from enum import IntEnum
import time
from typing import cast, Dict, Optional, Sequence, TYPE_CHECKING

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFontMetrics
from PyQt5.QtWidgets import (QFrame, QHBoxLayout, QLabel, QLayout, QProgressBar, QPushButton,
    QSizePolicy, QSpinBox, QTreeWidget, QVBoxLayout, QWidget)

from ...constants import CHANGE_SUBPATH, RECEIVING_SUBPATH
from ...blockchain_scanner import AdvancedSettings, DEFAULT_GAP_LIMITS, Scanner
from ...i18n import _
from ...logs import logs
from ...wallet import Wallet

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
from .util import FormSectionWidget, WindowModalDialog

logger = logs.get_logger("scanner-ui")

# TODO(no-checkin) add a details section for the post-scan UI.

TEXT_TITLE = _("Blockchain scanner")
TEXT_SCAN_ADVANCED_TITLE = _("Advanced options")

# All these "about" texts have the top title, then a standard line spacing, then more text.
# Any pages with multi-line centering are fudged to get the same result.
TEXT_INTRODUCTION = _("<center><b>Ready to scan</b></center>"
    "<br/>"
    "This process will contact servers in order to locate existing transactions that are "
    "associated with this account, so that any coins it has access to can be identified. "
    "When this might be desirable as well as both risks and limitations are covered in the "
    "help document accessible below."
    "<br/><br/>")
TEXT_DISCOVERY = _("<center><b>Scanning</b>"
    "<br/><br/>"
    "{:,d} transactions located (in {:,d} seconds).</center>")
TEXT_PRE_IMPORT = _("<center><b>Ready to import</b></center>"
    "<br/>"
    "The completed scan found {:,d} transactions associated with this account. The transactions "
    "can be examined more closely in the details section, or just imported and added to the "
    "account as is."
    "<br/><br/>")

# The location of the help document.
HELP_FOLDER_NAME = "misc"
HELP_SCAN_FILE_NAME = "blockchain-scan-dialog"
HELP_SCAN_ADVANCED_FILE_NAME = "blockchain-scan-dialog-advanced"


class ScanDialogStage(IntEnum):
    INITIAL    = 0
    DISCOVERY  = 1
    PRE_IMPORT = 2
    IMPORT     = 3


class ScanDialogRole(IntEnum):
    ACCOUNT_CREATION      = 1
    MANUAL_RESCAN         = 2


class BlockchainScanDialog(WindowModalDialog):
    _stage = ScanDialogStage.INITIAL
    _scan_start_time: int = -1
    _scan_end_time: int = -1
    _transaction_count: int = 0
    _import_start_time: int = -1
    _import_end_time: int = -1

    def __init__(self, main_window_proxy: 'ElectrumWindow', wallet: Wallet, account_id: int,
            role: ScanDialogRole) -> None:
        super().__init__(main_window_proxy.reference(), TEXT_TITLE)
        self.setMinimumWidth(400)
        self.setMaximumWidth(400)
        self.setMinimumHeight(150)

        self._main_window = main_window_proxy
        self._wallet = wallet
        self._account_id = account_id
        self._role = role
        self._last_range = 0
        self._advanced_settings = AdvancedSettings()

        account = self._wallet.get_account(account_id)
        assert account is not None
        self._scanner = Scanner.from_account(account,
            settings=self._advanced_settings,
            extend_range_cb=self._on_scanner_range_extended)

        # We do not have to forceably stop this timer if the dialog is closed. It's lifecycle
        # is directly tied to the life of this dialog.
        self._timer = QTimer(self)

        self._about_label = QLabel(TEXT_INTRODUCTION)
        self._about_label.setWordWrap(True)
        self._about_label.setAlignment(Qt.AlignmentFlag(Qt.AlignLeft | Qt.AlignTop))
        self._about_label.setMinimumHeight(60)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setAlignment(Qt.AlignCenter)
        self._progress_bar.setFormat("%p% scanned")
        self._progress_bar.setVisible(False)

        self._advanced_button = QPushButton(_("Advanced"))
        # At the time of writing, there are no advanced options to set for non-deterministic ones.
        self._advanced_button.setEnabled(account.is_deterministic())
        self._help_button = QPushButton(_("Help"))
        self._scan_button = QPushButton()
        self._cancel_button = QPushButton()

        self._cancel_button.clicked.connect(self._on_clicked_button_cancel)
        self._help_button.clicked.connect(self._on_clicked_button_help)
        self._advanced_button.clicked.connect(self._on_clicked_button_advanced)

        expand_details_button = self._expand_details_button = QPushButton("+")
        expand_details_button.setStyleSheet("padding: 2px;")
        expand_details_button.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
        expand_details_button.clicked.connect(self._on_clicked_button_expand_details)
        expand_details_button.setMinimumWidth(15)

        # NOTE(copy-paste) Generic separation line code used elsewhere as well.
        details_header_line = QFrame()
        details_header_line.setStyleSheet("QFrame { border: 1px solid #C3C2C2; }")
        details_header_line.setFrameShape(QFrame.HLine)
        details_header_line.setFixedHeight(1)

        details_header = QHBoxLayout()
        details_header.addWidget(expand_details_button)
        details_header.addWidget(QLabel(_("Details")))
        details_header.addWidget(details_header_line, 1)

        tree = self._scan_detail_tree = QTreeWidget()
        tree.setHeaderHidden(True)
        tree.setVisible(False)

        details_layout = self._details_layout = QVBoxLayout()
        details_layout.addLayout(details_header)
        details_layout.addWidget(tree)

        # NOTE(copy-paste) Generic separation line code used elsewhere as well.
        button_box_line = QFrame()
        button_box_line.setStyleSheet("QFrame { border: 1px solid #E3E2E2; }")
        button_box_line.setFrameShape(QFrame.HLine)
        button_box_line.setFixedHeight(1)

        # We intentionally do not use a QDialogButtonBox because it gives us no apparent control
        # over the button ordering.
        button_box = QHBoxLayout()
        button_box.addWidget(self._help_button)
        button_box.addWidget(self._advanced_button)
        button_box.addStretch(1)
        if role == ScanDialogRole.MANUAL_RESCAN:
            self._scan_button.setText(_("Scan"))
            button_box.addWidget(self._scan_button)
            self._scan_button.clicked.connect(self._on_clicked_button_scan)

            self._cancel_button.setText(_("Cancel"))
            button_box.addWidget(self._cancel_button)
        else:
            self._scan_button.setText(_("Scan now"))
            button_box.addWidget(self._scan_button)
            self._cancel_button.setText(_("Scan later"))
            button_box.addWidget(self._cancel_button)

        vbox = QVBoxLayout(self)
        vbox.addWidget(self._about_label)
        vbox.addWidget(self._progress_bar, Qt.AlignCenter)
        vbox.addWidget(button_box_line)
        vbox.addLayout(button_box)
        vbox.setSizeConstraint(QLayout.SetFixedSize)

        self._scan_button.setFocus()
        self.rejected.connect(self._on_dialog_rejected)

        self.setLayout(vbox)

    def update_gap_limit(self, subpath: Sequence[int], value: int) -> None:
        # This is a reference to the object the scanner was given. It should only be possible for
        # the scan advanced settings to update this before the scan.
        self._advanced_settings.gap_limits[subpath] = value

    def _on_clicked_button_scan(self) -> None:
        if self._stage == ScanDialogStage.INITIAL:
            self._stage = ScanDialogStage.DISCOVERY
            self._scan_start_time = int(time.time())

            self._advanced_button.setEnabled(False)
            self._scan_button.setEnabled(False)
            # This does the unbounded progress indicator which repeatedly scrolls left to right.
            self._progress_bar.setVisible(True)
            self._progress_bar.setRange(0, 0)
            self._update_display()

            self._timer.timeout.connect(self._on_timer_scan_event)
            self._timer.start(250)

            self._scanner.start_scanning_for_usage(on_done=self._on_scan_complete)
        elif self._stage == ScanDialogStage.PRE_IMPORT:
            self._stage = ScanDialogStage.DISCOVERY
            self._import_start_time = int(time.time())

            self._progress_bar.setVisible(True)
            self._advanced_button.setEnabled(False)
            self._scan_button.setEnabled(False)

    def _on_clicked_button_expand_details(self) -> None:
        is_expanded = self._expand_details_button.text() == "-"
        if is_expanded:
            self._expand_details_button.setText("+")
            self._scan_detail_tree.setVisible(False)
        else:
            self._expand_details_button.setText("-")
            self._scan_detail_tree.setVisible(True)

    def _on_clicked_button_help(self) -> None:
        from .help_dialog import HelpDialog
        h = HelpDialog(self._main_window.reference(), HELP_FOLDER_NAME, HELP_SCAN_FILE_NAME)
        h.run()

    def _on_clicked_button_advanced(self) -> None:
        dialog = AdvancedScanOptionsDialog(self)
        dialog.exec_()

    def _on_clicked_button_cancel(self) -> None:
        # The local rejection signal handler does any required clean up.
        self.reject()

    def _on_timer_scan_event(self) -> None:
        """
        Called periodically to update the display during the 'DISCOVERY' stage.
        """
        self._update_display()

    def _update_transaction_count(self) -> None:
        tx_hashes: Dict[str, int] = defaultdict(int)
        for _script_hash, history_item in self._scanner.get_scan_results().items():
            for result in history_item.history:
                tx_hashes[cast(str, result["tx_hash"])] += 1
        self._transaction_count = len(tx_hashes)

    def _update_display(self) -> None:
        """
        One stop shop for updating the display for whatever the current stage is.
        """
        if self._stage in (ScanDialogStage.DISCOVERY, ScanDialogStage.PRE_IMPORT):
            # Continual updates for `DISCOVERY` stage.
            # Initial update for `PRE_IMPORT` stage.
            self._update_transaction_count()

            if self._stage == ScanDialogStage.DISCOVERY:
                end_time = self._scan_end_time if self._scan_end_time > -1 else int(time.time())
                seconds_passed = end_time - self._scan_start_time
                self._about_label.setText(TEXT_DISCOVERY.format(self._transaction_count,
                    seconds_passed))
                if self._last_range > 0:
                    self._progress_bar.setValue(self._scanner.get_result_count())
            elif self._stage == ScanDialogStage.PRE_IMPORT:
                self._about_label.setText(TEXT_PRE_IMPORT.format(self._transaction_count))
        else:
            pass

    def _on_scan_complete(self, future: concurrent.futures.Future) -> None:
        if future.cancelled():
            logger.debug("_on_scan_complete.cancelled")
            return

        assert future.done()
        logger.debug("_on_scan_complete.done")

        self._stage = ScanDialogStage.PRE_IMPORT
        self._timer.timeout.disconnect(self._on_timer_scan_event)
        self._timer.stop()

        self._scan_end_time = int(time.time())
        self._update_display()

        self._progress_bar.setVisible(False)
        self._progress_bar.setRange(0, 100)
        # This seems to be what Qt sets for a fresh progress bar and it hides the formatted text.
        self._progress_bar.setValue(-1)
        self._progress_bar.setFormat("%p% imported")

        self._scan_button.setText(_("Import"))
        self._scan_button.setEnabled(True)
        self._scan_button.setFocus()

        # Insert the details layout before the button box.
        self.layout().insertLayout(2, self._details_layout)

    def _on_dialog_rejected(self) -> None:
        if self._stage == ScanDialogStage.DISCOVERY:
            logger.debug("Cleaning up 'DISCOVERY' state")
            self._scanner.shutdown()
        elif self._stage == ScanDialogStage.IMPORT:
            pass

    def _on_scanner_range_extended(self, new_range: int) -> None:
        self._last_range = new_range
        self._progress_bar.setRange(0, new_range)


class AdvancedScanOptionsDialog(WindowModalDialog):
    def __init__(self, parent: WindowModalDialog) -> None:
        super().__init__(parent, TEXT_SCAN_ADVANCED_TITLE)

        account = parent._wallet.get_account(parent._account_id)

        self.setMinimumWidth(400)
        self.setMaximumWidth(400)
        self.setMinimumHeight(200)

        deterministic_form: Optional[FormSectionWidget] = None
        if account.is_deterministic():
            def mw(s: str) -> int:
                return QFontMetrics(self.font()).boundingRect(s).width() + 10

            receiving_edit = QSpinBox()
            receiving_edit.setAlignment(Qt.AlignRight)
            receiving_edit.setMinimum(20)
            receiving_edit.setMaximum(100000)
            receiving_edit.setMaximumWidth(mw("8888888") + 10)
            receiving_edit.setValue(DEFAULT_GAP_LIMITS[RECEIVING_SUBPATH])
            receiving_label = QLabel(_("consecutive unused keys"))
            # We word wrap in case translations or weird users with Linux or custom font settings
            # cause the label text to hit the maximum space limit (to stop it being clipped).
            receiving_label.setWordWrap(True)
            # Force some space between the label and spin box.
            self._adjust_contents_margins(receiving_label, left_plus=5)

            change_edit = QSpinBox()
            change_edit.setAlignment(Qt.AlignRight)
            change_edit.setMinimum(10)
            change_edit.setMaximum(100000)
            change_edit.setMaximumWidth(mw("8888888") + 10)
            change_edit.setValue(DEFAULT_GAP_LIMITS[CHANGE_SUBPATH])
            change_label = QLabel(_("consecutive unused keys"))
            change_label.setWordWrap(True)
            self._adjust_contents_margins(change_label, left_plus=5)

            hbox1 = QHBoxLayout()
            hbox1.addWidget(receiving_edit)
            hbox1.addWidget(receiving_label, 1)

            hbox2 = QHBoxLayout()
            hbox2.addWidget(change_edit)
            hbox2.addWidget(change_label, 1)

            deterministic_form = FormSectionWidget()
            deterministic_form.add_title(_("Detecting when to stop searching"))
            deterministic_form.add_row(_("Change"), hbox2, stretch_field=True)
            deterministic_form.add_row(_("Received funds"), hbox1, stretch_field=True)

            change_edit.valueChanged.connect(self._on_value_changed_change)
            receiving_edit.valueChanged.connect(self._on_value_changed_receiving)

        # NOTE(copy-paste) Generic separation line code used elsewhere as well.
        line = QFrame()
        line.setStyleSheet("QFrame { border: 1px solid #E3E2E2; }")
        line.setFrameShape(QFrame.HLine)
        line.setFixedHeight(1)

        help_button = QPushButton(_("Help"))
        help_button.clicked.connect(self._on_clicked_button_help)
        close_button = QPushButton(_("Close"))
        close_button.clicked.connect(self.close)

        button_box = QHBoxLayout()
        button_box.addWidget(help_button)
        button_box.addStretch(1)
        button_box.addWidget(close_button)

        vbox = QVBoxLayout()
        if deterministic_form is not None:
            vbox.addWidget(deterministic_form)
        vbox.addStretch(1)
        vbox.addWidget(line)
        vbox.addLayout(button_box)
        self.setLayout(vbox)

    def _on_value_changed_receiving(self, new_value: int) -> None:
        self.parent().update_gap_limit(RECEIVING_SUBPATH, new_value)

    def _on_value_changed_change(self, new_value: int) -> None:
        self.parent().update_gap_limit(CHANGE_SUBPATH, new_value)

    def _on_clicked_button_help(self) -> None:
        from .help_dialog import HelpDialog
        h = HelpDialog(self.parent()._main_window.reference(), HELP_FOLDER_NAME,
            HELP_SCAN_ADVANCED_FILE_NAME)
        h.run()

    def _adjust_contents_margins(self, widget: QWidget, *, left_plus=0, top_plus=0, right_plus=0,
            bottom_plus=0) -> None:
        margins = widget.contentsMargins()
        widget.setContentsMargins(margins.left() + left_plus, margins.top() + top_plus,
            margins.right() + right_plus, margins.bottom() + bottom_plus)
