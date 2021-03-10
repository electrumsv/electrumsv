from collections import defaultdict
import concurrent.futures
from dataclasses import dataclass, field
from enum import IntEnum
from functools import partial
import json
import time
from typing import Any, cast, Dict, Iterable, List, Optional, Sequence, Set, Tuple, TYPE_CHECKING
import webbrowser

from bitcoinx import hash_to_hex_str, hex_str_to_hash
from PyQt5.QtCore import pyqtSignal, Qt, QPoint, QTimer
from PyQt5.QtGui import QFontMetrics
from PyQt5.QtWidgets import (QFrame, QHBoxLayout, QHeaderView, QLabel, QLayout, QMenu,
    QProgressBar, QPushButton, QSizePolicy, QSpinBox, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget)

from ...app_state import app_state
from ...constants import CHANGE_SUBPATH, RECEIVING_SUBPATH, TxFlags
from ...blockchain_scanner import AdvancedSettings, DEFAULT_GAP_LIMITS, Scanner
from ...i18n import _
from ...logs import logs
from ...wallet import Wallet
from ...wallet_database.types import TransactionLinkState
from ...web import BE_URL

if TYPE_CHECKING:
    from .main_window import ElectrumWindow
from .util import FormSectionWidget, read_QIcon, WindowModalDialog


# TODO Need to ensure the keys are generated for all matched scans. Otherwise the linking stage
#   will fail.


logger = logs.get_logger("scanner-ui")


TEXT_TITLE = _("Blockchain scanner")
TEXT_SCAN_ADVANCED_TITLE = _("Advanced options")

# All these "about" texts have the top title, then a standard line spacing, then more text.
# Any pages with multi-line centering are fudged to get the same result.
TEXT_PRE_SCAN = _("<center><b>Ready to scan</b></center>"
    "<br/>"
    "This process will contact servers in order to locate existing transactions that are "
    "associated with this account, so that any coins it has access to can be identified. "
    "When this might be desirable as well as both risks and limitations are covered in the "
    "help document accessible below."
    "<br/><br/>")
TEXT_SCAN = _("<center><b>Scanning</b>"
    "<br/><br/>"
    "{:,d} transactions located (in {:,d} seconds).</center>")
TEXT_NO_IMPORT = _("<center><b>Nothing to import</b></center>"
    "<br/>"
    "The completed scan located no importable transactions associated with this account. "
    "Any other located transactions were either already imported or conflicted when their import "
    "was attempted."
    "<br/><br/>")
TEXT_PRE_IMPORT = _("<center><b>Ready to import</b></center>"
    "<br/>"
    "The completed scan found {:,d} importable transactions associated with this account. "
    "All transactions that were located, can be examined more closely in the details section. "
    "There those that already exist or are known to be in conflict can be distinguished "
    "from the importable ones."
    "<br/><br/>")
TEXT_IMPORT = _("<center><b>Importing</b>"
    "<br/><br/>"
    "{:,d} transactions imported (in {:,d} seconds).</center>")
TEXT_FINAL_COMPLETE = _("<center><b>Import complete</b>"
    "<br/><br/>"
    "This account has been scanned and any located transactions that were not already present "
    "were imported.")
TEXT_FINAL_FAILURE = _("<center><b>Import failed</b>"
    "<br/><br/>"
    "This account has been scanned and any located transactions that were not already present "
    "were imported. {:,d} transactions were not able to be imported due to conflicts. Expand the "
    "details section below for more information.")


# The location of the help document.
HELP_FOLDER_NAME = "misc"
HELP_SCAN_FILE_NAME = "blockchain-scan-dialog"
HELP_SCAN_ADVANCED_FILE_NAME = "blockchain-scan-dialog-advanced"


class ScanDialogStage(IntEnum):
    # The stage where the user must manually start the scan.
    PRE_SCAN    = 0
    SCAN        = 1
    # Holding stage while we decide if we do no import or pre import next.
    POST_SCAN   = 2
    NO_IMPORT   = 3
    PRE_IMPORT  = 4
    IMPORT      = 5
    FINAL       = 6


class ScanDialogRole(IntEnum):
    """
    This is the context in which the dialog is invoked.
    """
    # Immediately following account creation.
    ACCOUNT_CREATION      = 1
    # Any time after the initial scan for an existing account of suitable type.
    MANUAL_RESCAN         = 2


@dataclass
class TransactionScanState:
    tx_id: str
    script_hashes: Set[bytes]
    block_height: int
    fee_hint: Optional[int]
    is_missing = True
    already_imported = False
    already_conflicting = False
    found_spend_conflicts = False
    linked_account_ids: Set[int] = field(default_factory=set)


MEMPOOL_SORT_HEIGHT        = 100000000
MEMPOOL_PARENT_SORT_HEIGHT = 100000000-1

class Columns(IntEnum):
    STATUS = 0
    TX_ID = 1
    HEIGHT = 2
    COLUMN_COUNT = 3

class ImportRoles(IntEnum):
    ENTRY = Qt.UserRole


class BlockchainScanDialog(WindowModalDialog):
    _stage = ScanDialogStage.PRE_SCAN
    _scan_start_time: int = -1
    _scan_end_time: int = -1
    _import_start_time: int = -1
    _import_end_time: int = -1

    update_progress_signal = pyqtSignal(int)
    import_step_signal = pyqtSignal(bytes, object)

    def __init__(self, main_window_proxy: 'ElectrumWindow', wallet: Wallet, account_id: int,
            role: ScanDialogRole) -> None:
        super().__init__(main_window_proxy.reference(), TEXT_TITLE)

        self.setMinimumWidth(500)
        self.setMinimumHeight(150)

        self._main_window = main_window_proxy
        self._wallet = wallet
        self._account_id = account_id
        self._role = role
        self._last_range = 0
        self._advanced_settings = AdvancedSettings()

        self._import_fetch_steps = 0
        self._import_fetch_hashes: Set[bytes] = set()
        self._import_link_steps = 0
        self._import_link_hashes: Set[bytes] = set()
        self._import_tx_count = 0
        self._import_state: Dict[bytes, TransactionScanState] = {}

        account = self._wallet.get_account(account_id)
        assert account is not None
        self._scanner = Scanner.from_account(account,
            settings=self._advanced_settings,
            extend_range_cb=self._on_scanner_range_extended)

        # We do not have to forceably stop this timer if the dialog is closed. It's lifecycle
        # is directly tied to the life of this dialog.
        self._timer = QTimer(self)

        # NOTE(typing) PyQt5 lacks typing information for the connect method on signals.
        self.import_step_signal.connect(self._update_for_import_step) # type: ignore

        self.attempt_import_icon = read_QIcon("icons8-add-green-48-ui.png")
        self._conflicted_tx_icon = read_QIcon("icons8-error-48-ui.png")
        self._imported_tx_icon = read_QIcon("icons8-add-grey-48-ui.png")

        self._about_label = QLabel(TEXT_PRE_SCAN)
        self._about_label.setWordWrap(True)
        self._about_label.setAlignment(Qt.AlignmentFlag(Qt.AlignLeft | Qt.AlignTop))
        self._about_label.setMinimumHeight(60)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setAlignment(Qt.AlignCenter)
        self._progress_bar.setFormat("%p% scanned")
        self._progress_bar.setVisible(False)

        # NOTE(typing) PyQt5 lacks typing information for the connect method on signals.
        self.update_progress_signal.connect(self._progress_bar.setValue) # type: ignore

        self._advanced_button = QPushButton(_("Advanced"))
        # At the time of writing, there are no advanced options to set for non-deterministic ones.
        self._advanced_button.setEnabled(account.is_deterministic())
        self._help_button = QPushButton(_("Help"))
        self._scan_button = QPushButton()
        self._exit_button = QPushButton()

        self._exit_button.clicked.connect(self._on_clicked_button_exit)
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
        tree.header().setStretchLastSection(False)
        tree.setHeaderLabels([ "", "Transaction ID", "Block Height" ])
        tree.setColumnCount(Columns.COLUMN_COUNT)
        tree.header().setSectionResizeMode(Columns.STATUS, QHeaderView.ResizeToContents)
        tree.header().setSectionResizeMode(Columns.TX_ID, QHeaderView.Stretch)
        tree.header().setSectionResizeMode(Columns.HEIGHT, QHeaderView.ResizeToContents)
        tree.setVisible(False)
        tree.setContextMenuPolicy(Qt.CustomContextMenu)
        tree.customContextMenuRequested.connect(self._on_tree_scan_context_menu)
        tree.setSelectionMode(tree.ExtendedSelection)
        self._scan_tree_indexes: Dict[bytes, int] = {}

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
            self._scan_button.clicked.connect(self._on_clicked_button_action)

            self._exit_button.setText(_("Cancel"))
            button_box.addWidget(self._exit_button)
        else:
            self._scan_button.setText(_("Scan now"))
            button_box.addWidget(self._scan_button)
            self._exit_button.setText(_("Scan later"))
            button_box.addWidget(self._exit_button)

        vbox = QVBoxLayout(self)
        vbox.addWidget(self._about_label)
        vbox.addWidget(self._progress_bar, Qt.AlignCenter)
        vbox.addWidget(button_box_line)
        vbox.addLayout(button_box)
        vbox.setSizeConstraint(QLayout.SetFixedSize)

        self._scan_button.setFocus()
        self.rejected.connect(self._on_dialog_rejected)
        self.finished.connect(self._on_dialog_finished)

        self.setLayout(vbox)

    def update_gap_limit(self, subpath: Sequence[int], value: int) -> None:
        # This is a reference to the object the scanner was given. It should only be possible for
        # the scan advanced settings to update this before the scan.
        self._advanced_settings.gap_limits[subpath] = value

    def _on_clicked_button_action(self) -> None:
        if self._stage == ScanDialogStage.PRE_SCAN:
            self._stage = ScanDialogStage.SCAN
            self._scan_start_time = int(time.time())

            self._advanced_button.setEnabled(False)
            self._scan_button.setEnabled(False)
            # This does the unbounded progress indicator which repeatedly scrolls left to right.
            self._progress_bar.setVisible(True)
            self._progress_bar.setRange(0, 0)
            self._update_display()

            self._timer.timeout.connect(self._update_display)
            self._timer.start(250)

            self._scanner.start_scanning_for_usage(on_done=self._on_scan_complete)
        elif self._stage == ScanDialogStage.PRE_IMPORT:
            self._stage = ScanDialogStage.IMPORT
            self._import_start_time = int(time.time())

            self._update_display()

            self._progress_bar.setVisible(True)
            self._advanced_button.setEnabled(False)
            self._scan_button.setEnabled(False)

            # Gather the related import state for the scanned transactions.
            missing_tx_hashes: List[bytes] = []
            missing_tx_heights: Dict[bytes, int] = {}
            missing_tx_fee_hints: Dict[bytes, Optional[int]] = {}
            link_tx_hashes: Set[bytes] = set()
            for tx_hash, import_entry in self._import_state.items():
                if import_entry.already_imported or import_entry.already_conflicting:
                    continue
                if import_entry.is_missing:
                    missing_tx_hashes.append(tx_hash)
                    missing_tx_heights[tx_hash] = import_entry.block_height
                    missing_tx_fee_hints[tx_hash] = import_entry.fee_hint
                else:
                    link_tx_hashes.add(tx_hash)

            if len(missing_tx_hashes) or len(link_tx_hashes):
                self._wallet.register_callback(self._on_wallet_event,
                    ['missing_transaction_obtained'])

            self._on_scanner_range_extended(len(missing_tx_hashes) + len(link_tx_hashes))

            if len(missing_tx_hashes):
                # This will start the process of obtaining the missing transactions. The future
                # is not tied to the lifetime of this process, so we cannot cancel it should the
                # user use the cancel UI. We could extend the wallet to attempt this, but it is not
                # within the scope of the intitial feature set.
                future = app_state.async_.spawn(self._wallet.maybe_obtain_transactions_async,
                    missing_tx_hashes, missing_tx_heights, missing_tx_fee_hints)
                future.add_done_callback(self._on_import_obtain_transactions_started)

            if len(link_tx_hashes):
                self._import_link_hashes = link_tx_hashes
                self._import_link_future = app_state.async_.spawn(
                    self._import_immediately_linkable_transactions, link_tx_hashes)

    async def _import_immediately_linkable_transactions(self, link_tx_hashes: Set[bytes]) -> None:
        # Cannot hurt to verify that our action is still viable.
        if link_tx_hashes != self._import_link_hashes:
            return

        for tx_hash in list(link_tx_hashes):
            link_state = TransactionLinkState()
            await self._wallet.link_transaction_async(tx_hash, link_state)
            # NOTE(typing) PyQt5 lacks typing information for the emit method on signals.
            self._import_link_hashes.remove(tx_hash)
            self.import_step_signal.emit(tx_hash, link_state) # type: ignore

    def _on_wallet_event(self, event: str, *args: Iterable[Any]) -> None:
        """
        The general wallet callback event handler.

        This event is triggered by the wallet and is only received for events this object
        registers for and we have explicit handling for each.
        """
        tx_hash: bytes
        link_state: TransactionLinkState
        if event == 'missing_transaction_obtained':
            # NOTE(typing) Either we cast each argument, do unions and tuples or this.
            tx_hash, _tx, link_state = args # type: ignore

            # Perhaps we received events from other systems or before the import started.
            if tx_hash not in self._import_fetch_hashes:
                return
            self._import_fetch_hashes.remove(tx_hash)
            # NOTE(typing) PyQt5 lacks typing information for the emit method on signals.
            self.import_step_signal.emit(tx_hash, link_state) # type: ignore

    def _update_for_import_step(self, tx_hash: bytes, link_state: TransactionLinkState) -> None:
        tree_item_index = self._scan_tree_indexes[tx_hash]
        tree_item = self._scan_detail_tree.topLevelItem(tree_item_index)
        import_entry = cast(TransactionScanState, tree_item.data(Columns.STATUS, ImportRoles.ENTRY))
        if link_state.has_spend_conflicts:
            import_entry.found_spend_conflicts = link_state.has_spend_conflicts
            tree_item.setIcon(Columns.STATUS, self._conflicted_tx_icon)
            tree_item.setToolTip(Columns.STATUS, _("An attempt to import this transaction "
                "encountered a conflict where another imported transaction had already spent "
                "the given coins."))
        else:
            assert link_state.account_ids is not None, "expected account ids for non conflicted tx"
            import_entry.linked_account_ids = link_state.account_ids
            tree_item.setIcon(Columns.STATUS, self._imported_tx_icon)
            tree_item.setToolTip(Columns.STATUS, _("This transaction was imported successfully."))

        total_work_units, remaining_work_units = self._get_import_work_units()
        # NOTE(typing) PyQt5 lacks typing information for the emit method on signals.
        self.update_progress_signal.emit(total_work_units - remaining_work_units) # type: ignore

        if remaining_work_units == 0:
            self._stage = ScanDialogStage.FINAL

            self._import_end_time = int(time.time())
            self._update_display()

            self._exit_button.setText(_("Exit"))
            self._exit_button.setFocus()
            self._progress_bar.setVisible(False)
            self._scan_button.setEnabled(False)

    def _get_import_work_units(self) -> Tuple[int, int]:
        total_work_units = self._import_fetch_steps + self._import_link_steps
        remaining_work_units = len(self._import_fetch_hashes) + len(self._import_link_hashes)
        return total_work_units, remaining_work_units

    def _on_import_obtain_transactions_started(self, future: concurrent.futures.Future) -> None:
        """
        The callback for the when the process of obtaining the missing transaction has started.

        This will return which out of the transactions we asked it to import were not already
        present, and will go through the missing transaction obtaining process and automatically
        import those transactions into the matching accounts (not just the selected account).
        """
        if future.cancelled():
            return

        # Overwrite the default fetch step count value with the working value.
        self._import_fetch_hashes = set(future.result())
        self._import_fetch_steps = len(self._import_fetch_hashes)

        # This is a UI function being called in a callback following completion of a future.
        # It must be called in a UI thread, and in this case we know that future callbacks
        # happen in UI threads.
        total_work_units, _remaining_work_units = self._get_import_work_units()
        self._on_scanner_range_extended(total_work_units)

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

    def _on_clicked_button_exit(self) -> None:
        if self._import_end_time == -1:
            # The local rejection signal handler does any required clean up.
            self.reject()
        else:
            self.accept()

    def _update_display(self) -> None:
        """
        One stop shop for updating the display for whatever the current stage is.
        """
        if self._stage in (ScanDialogStage.SCAN, ScanDialogStage.PRE_IMPORT):
            # Continual updates for `DISCOVERY` stage.
            # Initial update for `PRE_IMPORT` stage.
            tx_hashes: Dict[str, int] = defaultdict(int)
            for history_item in self._scanner.get_scan_results().values():
                for result in history_item.history:
                    tx_hashes[cast(str, result["tx_hash"])] += 1
            transaction_count = len(tx_hashes)

            if self._stage == ScanDialogStage.SCAN:
                end_time = self._scan_end_time if self._scan_end_time > -1 else int(time.time())
                seconds_passed = end_time - self._scan_start_time
                self._about_label.setText(TEXT_SCAN.format(transaction_count,
                    seconds_passed))
                if self._last_range > 0:
                    self._progress_bar.setValue(self._scanner.get_result_count())
            elif self._stage == ScanDialogStage.PRE_IMPORT:
                self._about_label.setText(TEXT_PRE_IMPORT.format(transaction_count))
        elif self._stage == ScanDialogStage.NO_IMPORT:
           self._about_label.setText(TEXT_NO_IMPORT)
        elif self._stage == ScanDialogStage.IMPORT:
            total_work_units, remaining_work_units = self._get_import_work_units()
            end_time = self._import_end_time if self._import_end_time > -1 else int(time.time())
            seconds_passed = end_time - self._import_start_time
            self._about_label.setText(TEXT_IMPORT.format(total_work_units - remaining_work_units,
                seconds_passed))
        elif self._stage == ScanDialogStage.FINAL:
            failed_import = sum(e.found_spend_conflicts for e in self._import_state.values())
            if failed_import == 0:
                self._about_label.setText(TEXT_FINAL_COMPLETE)
            else:
                self._about_label.setText(TEXT_FINAL_FAILURE.format(failed_import))

    def _on_scan_complete(self, future: concurrent.futures.Future) -> None:
        if future.cancelled():
            logger.debug("_on_scan_complete.cancelled")
            return

        assert future.done()
        logger.debug("_on_scan_complete")

        # Switch to the post-scan analysis holding stage until we determine what the results mean.
        self._stage = ScanDialogStage.POST_SCAN

        self._timer.timeout.disconnect(self._update_display)
        self._timer.stop()

        self._scan_end_time = int(time.time())

        all_tx_hashes: List[bytes] = []
        subpath_indexes: Dict[Sequence[int], int] = defaultdict(int)
        self._import_state: Dict[bytes, TransactionScanState] = {}
        for script_hash, script_history in self._scanner.get_scan_results().items():
            # TODO Look into why there are empty script history lists. This seems like a minor
            #     thing that could be fixed.
            if len(script_history.history) == 0:
                continue

            key_subpath = script_history.bip32_subpath
            assert key_subpath is not None
            subpath_indexes[key_subpath] = max(subpath_indexes[key_subpath],
                script_history.bip32_subpath_index)

            for result in script_history.history:
                tx_id = cast(str, result["tx_hash"])
                tx_hash = hex_str_to_hash(tx_id)
                block_sort_height = cast(int, result["height"])
                if block_sort_height == 0:
                    block_sort_height = MEMPOOL_SORT_HEIGHT
                elif block_sort_height == -1:
                    block_sort_height = MEMPOOL_PARENT_SORT_HEIGHT
                fee_hint = cast(Optional[int], result.get("fee"))

                state = self._import_state.get(tx_hash)
                if state is None:
                    state = self._import_state[tx_hash] = TransactionScanState(tx_id,
                        { script_hash }, block_sort_height, fee_hint)
                    all_tx_hashes.append(tx_hash)
                else:
                    state.script_hashes.add(script_hash)
                    # TODO Work out the repercussions of this. The import process is modal and
                    # it is expected a reorg being encountered during the process is unlikely.
                    # Beyond the differences encountered within the indexer state that is located
                    # in the scan, it is also possible for the state to change after the scan.
                    state.block_height = max(block_sort_height, state.block_height)

        # The linking of transaction to accounts cannot be done unless the keys exist with their
        # script hashes.
        account = self._wallet.get_account(self._account_id)
        for subpath, subpath_index in subpath_indexes.items():
            account.derive_new_keys_until(tuple(subpath) + (subpath_index,))

        all_are_imported = True
        conflicts_were_found = False
        missing_tx_hashes = set(all_tx_hashes)
        for tx_row in self._wallet.read_transactions_exist(all_tx_hashes, self._account_id):
            missing_tx_hashes.remove(tx_row.tx_hash)

            state = self._import_state[tx_row.tx_hash]
            state.already_imported = tx_row.account_id is not None
            state.already_conflicting = (tx_row.flags & TxFlags.CONFLICTING) != 0
            state.is_missing = False

            conflicts_were_found = conflicts_were_found or state.already_conflicting
            all_are_imported = all_are_imported and state.already_imported

        if len(missing_tx_hashes):
            # We do not need to alter the import state for these transactions as the defaults suit.
            all_are_imported = False

        self._scan_button.setText(_("Import"))

        if all_are_imported or conflicts_were_found:
            self._stage = ScanDialogStage.NO_IMPORT

            self._scan_button.setEnabled(False)
            self._exit_button.setText(_("Exit"))
            self._exit_button.setFocus()
        else:
            self._stage = ScanDialogStage.PRE_IMPORT

            self._scan_button.setEnabled(True)
            self._scan_button.setFocus()

        self._update_display()

        self._progress_bar.setVisible(False)
        self._progress_bar.setRange(0, 100)
        # This seems to be what Qt sets for a fresh progress bar and it hides the formatted text.
        self._progress_bar.setValue(-1)
        self._progress_bar.setFormat("%p% imported")

        tx_state_items = sorted(self._import_state.items(), key=lambda x: x[1].block_height)
        tree_items: List[QTreeWidgetItem] = []
        for entry_index, (tx_hash, entry) in enumerate(tx_state_items):
            if entry.block_height in (MEMPOOL_SORT_HEIGHT, MEMPOOL_PARENT_SORT_HEIGHT):
                height_text = "Pending"
            else:
                height_text = str(entry.block_height)
            column_values = [ None, entry.tx_id, height_text ]
            tree_item = QTreeWidgetItem(column_values)
            if entry.already_conflicting:
                tree_item.setIcon(Columns.STATUS, self._conflicted_tx_icon)
                tree_item.setToolTip(Columns.STATUS, _("A previous attempt to import this "
                    "transaction found it to be in conflict with other pre-imported transactions, "
                    "and was not able to import it."))
            elif entry.already_imported:
                tree_item.setIcon(Columns.STATUS, self._imported_tx_icon)
                tree_item.setToolTip(Columns.STATUS, _("This transaction is already imported."))
            else:
                # This is both missing and present and not associated with account transactions.
                tree_item.setIcon(Columns.STATUS, self.attempt_import_icon)
                tree_item.setToolTip(Columns.STATUS, _("An attempt can be made to import this "
                    "transaction."))
            tree_item.setData(Columns.STATUS, ImportRoles.ENTRY, entry)
            tree_items.append(tree_item)
            self._scan_tree_indexes[tx_hash] = entry_index
        self._scan_detail_tree.insertTopLevelItems(0, tree_items)

        # Insert the details layout before the button box.
        self.layout().insertLayout(2, self._details_layout)

    def _on_dialog_finished(self) -> None:
        if self._stage == ScanDialogStage.IMPORT:
            self._wallet.unregister_callback(self._on_wallet_event)
        self._main_window.update_history_view()

    def _on_dialog_rejected(self) -> None:
        if self._stage == ScanDialogStage.SCAN:
            logger.debug("Cleaning up 'DISCOVERY' state")
            self._scanner.shutdown()
        elif self._stage == ScanDialogStage.IMPORT:
            pass

    def _on_scanner_range_extended(self, new_range: int) -> None:
        self._last_range = new_range
        self._progress_bar.setRange(0, new_range)

    def _on_tree_scan_context_menu(self, position: QPoint) -> None:
        """
        This operations on the selected items, not the row clicked on by the mouse.
        """
        tree = self._scan_detail_tree

        tree_items = tree.selectedItems()
        entries = [ tree_item.data(0, Qt.UserRole) for tree_item in tree_items ]
        if not len(entries):
            return

        menu = QMenu()
        menu.addAction(_("Copy transaction IDs as JSON"),
            partial(self._on_menu_copy_tx_ids_json_to_clipboard, entries))
        menu.addAction(_("Copy entries as JSON"),
            partial(self._on_menu_copy_entry_json_to_clipboard, entries))
        menu.addAction(_("View on block explorer"),
            partial(self._on_menu_view_on_block_explorer, entries))
        menu.exec_(tree.viewport().mapToGlobal(position))

    def _on_menu_copy_entry_json_to_clipboard(self, entries: List[TransactionScanState]) -> None:
        entries_text = json.dumps(list(
            {
                "tx_id": entry.tx_id,
                "script_hashes": list(hash_to_hex_str(hash) for hash in entry.script_hashes),
                "block_height": self._convert_height(entry.block_height)
            } for entry in entries))
        self._main_window.app.clipboard().setText(entries_text)

    def _on_menu_copy_tx_ids_json_to_clipboard(self, entries: List[TransactionScanState]) -> None:
        tx_ids_text = json.dumps(list(entry.tx_id for entry in entries))
        self._main_window.app.clipboard().setText(tx_ids_text)

    def _on_menu_view_on_block_explorer(self, entries) -> None:
        for entry in entries:
            tx_URL = BE_URL(app_state.config, 'tx', entry.tx_id)
            assert tx_URL is not None
            webbrowser.open(tx_URL)

    def _convert_height(self, block_height: int) -> int:
        if block_height == MEMPOOL_SORT_HEIGHT:
            return 0
        elif block_height == MEMPOOL_PARENT_SORT_HEIGHT:
            return -1
        else:
            return block_height



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

