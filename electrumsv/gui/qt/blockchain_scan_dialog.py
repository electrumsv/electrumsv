# Open BSV License version 4
#
# Copyright (c) 2021 Bitcoin Association for BSV ("Bitcoin Association")
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# 1 - The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# 2 - The Software, and any software that is derived from the Software or parts thereof,
# can only be used on the Bitcoin SV blockchains. The Bitcoin SV blockchains are defined,
# for purposes of this license, as the Bitcoin blockchain containing block height #556767
# with the hash "000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b" and
# that contains the longest persistent chain of blocks accepted by this Software and which
# are valid under the rules set forth in the Bitcoin white paper (S. Nakamoto, Bitcoin: A
# Peer-to-Peer Electronic Cash System, posted online October 2008) and the latest version
# of this Software available in this repository or another repository designated by Bitcoin
# Association, as well as the test blockchains that contain the longest persistent chains
# of blocks accepted by this Software and which are valid under the rules set forth in the
# Bitcoin whitepaper (S. Nakamoto, Bitcoin: A Peer-to-Peer Electronic Cash System, posted
# online October 2008) and the latest version of this Software available in this repository,
# or another repository designated by Bitcoin Association
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# This user interface currently supports two different types of scan:
#
# 1. Legacy ElectrumX scans.
# 2. Restoration indexer scans.
#
# The user cannot choose which one to use. The idea is that we will replace the legacy scans
# when services supporting the restoration scans are available. Until the legacy scanning is
# no longer needed we will retain the code, but the user will have to use the type we decide
# is active. There will be no user interface for them to choose between the types.

from __future__ import annotations
from collections import defaultdict
import concurrent.futures
from dataclasses import dataclass, field
from enum import IntEnum
from functools import partial
import json
import time
from typing import Any, cast, Dict, Iterable, List, Optional, Set, Tuple, TYPE_CHECKING
from weakref import ProxyType
import webbrowser

from bitcoinx import hash_to_hex_str, hex_str_to_hash
from PyQt5.QtCore import pyqtSignal, Qt, QPoint, QTimer
from PyQt5.QtGui import QFontMetrics
from PyQt5.QtWidgets import (QFrame, QHBoxLayout, QHeaderView, QLabel, QLayout, QMenu,
    QProgressBar, QPushButton, QSizePolicy, QSpinBox, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget)

from ...app_state import app_state
from ...constants import CHANGE_SUBPATH, DerivationPath, EMPTY_HASH, RECEIVING_SUBPATH, \
    SubscriptionType, TransactionImportFlag, TxFlags
from ...blockchain_scanner import AdvancedSettings, DEFAULT_GAP_LIMITS, BlockchainScanner, \
    ItemHashProtocol, PushDataHasher, PushDataHashHandler, ScriptHasher, ScriptHashHandler, \
    SearchKeyEnumerator
from ...network_support.general_api import MatchFlags
from ...i18n import _
from ...logs import logs
from ...wallet import Wallet
from ...wallet_database.types import TransactionLinkState
from ...web import BE_URL

from .constants import ScanDialogRole
from .util import FormSectionWidget, read_QIcon, WindowModalDialog

if TYPE_CHECKING:
    from .app import SVApplication
    from .main_window import ElectrumWindow


logger = logs.get_logger("scanner-ui")


# As a developer you can change the currently active scanning type here.

HARDCODED_SUBSCRIPTION_TYPE = SubscriptionType.SCRIPT_HASH
# HARDCODED_SUBSCRIPTION_TYPE = SubscriptionType.PUSHDATA_HASH


TEXT_TITLE = _("Blockchain scanner")
TEXT_SCAN_ADVANCED_TITLE = _("Advanced options")

# All these "about" texts have the top title, then a standard line spacing, then more text.
# Any pages with multi-line centering are fudged to get the same result.
TEXT_NO_SERVERS = _("<center><b>Not ready to scan</b></center>"
    "<br/>"
    "There are no servers currently available and ready for scanning. It is possible that they "
    "are not currently reachable or that required blockchain headers are still being obtained."
    "<br/><br/>")
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


@dataclass
class TransactionScanState:
    tx_hash: bytes
    item_hashes: Set[bytes]
    block_height: Optional[int]
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
    ENTRY = Qt.ItemDataRole.UserRole


class BlockchainScanDialog(WindowModalDialog):
    _stage = ScanDialogStage.PRE_SCAN
    _scan_start_time: int = -1
    _scan_end_time: int = -1
    _import_start_time: int = -1
    _import_end_time: int = -1

    update_progress_signal = pyqtSignal(int)
    import_step_signal = pyqtSignal(bytes, object)

    _pushdata_handler: Optional[PushDataHashHandler] = None
    _scripthash_handler: Optional[ScriptHashHandler] = None

    def __init__(self, main_window_proxy: ProxyType[ElectrumWindow], wallet: Wallet,
            account_id: int, role: ScanDialogRole) -> None:
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

        self._advanced_button = QPushButton(_("Advanced"))
        self._help_button = QPushButton(_("Help"))
        self._scan_button = QPushButton()
        self._exit_button = QPushButton()
        self._exit_button.clicked.connect(self._on_clicked_button_exit)
        self._help_button.clicked.connect(self._on_clicked_button_help)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._progress_bar.setFormat("%p% scanned")
        self._progress_bar.setVisible(False)

        account = self._wallet.get_account(account_id)
        assert account is not None

        item_hasher: Optional[ItemHashProtocol] = None

        assert self._wallet._network is not None
        if HARDCODED_SUBSCRIPTION_TYPE == SubscriptionType.SCRIPT_HASH:
            # The subscription model for ElectrumX servers designates one of the servers as a main
            # server, and all subscriptions are made with this server.
            if main_window_proxy.has_connected_main_server():
                # ElectrumX API.
                item_hasher = ScriptHasher()
                wallet_id = account.get_wallet().get_id()
                account_id = account.get_id()
                self._scripthash_handler = ScriptHashHandler(self._wallet._network, wallet_id,
                    account_id)
            else:
                self._about_label = QLabel(TEXT_NO_SERVERS)
                self._about_label.setWordWrap(True)
                self._about_label.setAlignment(Qt.AlignmentFlag(
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop))
                self._about_label.setMinimumHeight(60)

                self._scan_button.setVisible(False)
                self._advanced_button.setVisible(False)
        elif HARDCODED_SUBSCRIPTION_TYPE == SubscriptionType.PUSHDATA_HASH:
            # Capped restoration API.
            item_hasher = PushDataHasher()
            self._pushdata_handler = PushDataHashHandler(self._wallet._network, account)
        else:
            raise NotImplementedError("Unexpected subscription type")

        if item_hasher is not None:
            search_enumerator = SearchKeyEnumerator(item_hasher, self._advanced_settings)
            search_enumerator.use_account(account)

            if HARDCODED_SUBSCRIPTION_TYPE == SubscriptionType.SCRIPT_HASH:
                assert self._scripthash_handler is not None
                self._scanner = BlockchainScanner(self._scripthash_handler, search_enumerator,
                    extend_range_cb=self._on_scanner_range_extended)
            elif HARDCODED_SUBSCRIPTION_TYPE == SubscriptionType.PUSHDATA_HASH:
                assert self._pushdata_handler is not None
                self._scanner = BlockchainScanner(self._pushdata_handler, search_enumerator,
                    extend_range_cb=self._on_scanner_range_extended)
            else:
                raise NotImplementedError("Unexpected subscription type")

            # We do not have to forceably stop this timer if the dialog is closed. It's lifecycle
            # is directly tied to the life of this dialog.
            self._timer = QTimer(self)

            self.import_step_signal.connect(self._update_for_import_step)

            self._attempt_import_icon = read_QIcon("icons8-add-green-48-ui.png")
            self._conflicted_tx_icon = read_QIcon("icons8-error-48-ui.png")
            self._imported_tx_icon = read_QIcon("icons8-add-grey-48-ui.png")

            self._about_label = QLabel(TEXT_PRE_SCAN)
            self._about_label.setWordWrap(True)
            self._about_label.setAlignment(Qt.AlignmentFlag(
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop))
            self._about_label.setMinimumHeight(60)

            self.update_progress_signal.connect(self._progress_bar.setValue)

            # At the time of writing, there are no advanced options to set for non-deterministic.
            self._advanced_button.setEnabled(account.is_deterministic())
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
            tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            tree.setSelectionMode(tree.ExtendedSelection)
            tree.customContextMenuRequested.connect(self._on_tree_scan_context_menu)
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
            self._scan_button.clicked.connect(self._on_clicked_button_action)

            self._exit_button.setText(_("Scan later"))
            button_box.addWidget(self._exit_button)

        vbox = QVBoxLayout(self)
        vbox.addWidget(self._about_label)
        vbox.addWidget(self._progress_bar, Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(button_box_line)
        vbox.addLayout(button_box)
        vbox.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)

        self._scan_button.setFocus()
        self.rejected.connect(self._on_dialog_rejected)
        self.finished.connect(self._on_dialog_finished)

        self.setLayout(vbox)

    def update_gap_limit(self, subpath: DerivationPath, value: int) -> None:
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
                    assert isinstance(import_entry.block_height, int)
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
                future = cast("SVApplication", app_state.app).run_coro(
                    self._wallet.maybe_obtain_transactions_async,
                    missing_tx_hashes, missing_tx_heights, missing_tx_fee_hints,
                    TransactionImportFlag.PROMPTED)
                future.add_done_callback(self._on_import_obtain_transactions_started)

            if len(link_tx_hashes):
                # We store these to track what we are waiting for.
                self._import_link_hashes = link_tx_hashes
                app_state.async_.spawn(self._import_immediately_linkable_transactions,
                    link_tx_hashes)

    async def _import_immediately_linkable_transactions(self, link_tx_hashes: Set[bytes]) -> None:
        """
        Worker task to link each transaction that is already present in the wallet.
        """
        # Cannot hurt to verify that our action is still viable.
        if link_tx_hashes != self._import_link_hashes:
            return

        for tx_hash in list(link_tx_hashes):
            link_state = TransactionLinkState()
            await self._wallet.link_transaction_async(tx_hash, link_state)
            self._import_link_hashes.remove(tx_hash)
            self.import_step_signal.emit(tx_hash, link_state)

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
            self.import_step_signal.emit(tx_hash, link_state)

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
        self.update_progress_signal.emit(total_work_units - remaining_work_units)

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

    def _on_import_obtain_transactions_started(self,
            future: concurrent.futures.Future[Set[bytes]]) -> None:
        """
        The callback for the when the process of obtaining the missing transaction has started.

        This will return which out of the transactions we asked it to import were not already
        present, and will go through the missing transaction obtaining process and automatically
        import those transactions into the matching accounts (not just the selected account).

        As the work that was completed was run through `SVApplication.run_coro` this is
        guaranteed to be called in the UI thread.
        """
        if future.cancelled():
            return

        # Overwrite the default fetch step count value with the working value.
        self._import_fetch_hashes = future.result()
        self._import_fetch_steps = len(self._import_fetch_hashes)

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
            result_count: int = 0
            transaction_count: int = 0
            if HARDCODED_SUBSCRIPTION_TYPE == SubscriptionType.PUSHDATA_HASH:
                tx_hashes: Dict[bytes, int] = defaultdict(int)
                assert self._pushdata_handler is not None
                for result1 in self._pushdata_handler.get_results():
                    result_count += 1
                    tx_hashes[result1.transaction_hash] += 1
                    if result1.spend_transaction_hash != EMPTY_HASH:
                        tx_hashes[result1.spend_transaction_hash] += 1
                # TODO(no-checkin) Is this count correct? Is it true that we want every matched
                #   receive transaction and every matched spend transaction?
                transaction_count = len(tx_hashes)
            elif HARDCODED_SUBSCRIPTION_TYPE == SubscriptionType.SCRIPT_HASH:
                assert self._scripthash_handler is not None
                tx_ids: Dict[str, int] = defaultdict(int)
                for history_item in self._scripthash_handler.get_results().values():
                    result_count += 1
                    for result2 in history_item.history:
                        tx_ids[cast(str, result2["tx_hash"])] += 1
                transaction_count = len(tx_ids)
            else:
                raise NotImplementedError("Unexpected subscription type")

            if self._stage == ScanDialogStage.SCAN:
                end_time = self._scan_end_time if self._scan_end_time > -1 else int(time.time())
                seconds_passed = end_time - self._scan_start_time
                self._about_label.setText(TEXT_SCAN.format(transaction_count,
                    seconds_passed))
                if self._last_range > 0:
                    self._progress_bar.setValue(result_count)
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

    def _on_scan_complete(self, future: concurrent.futures.Future[None]) -> None:
        """
        The callback the blockchain scanner calls when the scanning process is completed.
        """
        if future.cancelled():
            logger.debug("_on_scan_complete.cancelled")
            return

        try:
            future.result()
        except Exception:
            # TODO This should be the types of exceptions that represent failures in the scanning
            #   process.
            pass

        logger.debug("_on_scan_complete")

        # Switch to the post-scan analysis holding stage until we determine what the results mean.
        self._stage = ScanDialogStage.POST_SCAN

        self._timer.timeout.disconnect(self._update_display)
        self._timer.stop()

        self._scan_end_time = int(time.time())

        all_tx_hashes: List[bytes] = []
        subpath_indexes: Dict[DerivationPath, int] = defaultdict(int)
        self._import_state = {}

        if HARDCODED_SUBSCRIPTION_TYPE == SubscriptionType.SCRIPT_HASH:
            assert self._scripthash_handler is not None
            for script_hash, script_history in self._scripthash_handler.get_results().items():
                # TODO Look into why there are empty script history lists. This seems like a minor
                #     thing that could be fixed.
                if len(script_history.history) == 0:
                    continue

                key_subpath = script_history.bip32_subpath
                assert key_subpath is not None
                subpath_indexes[key_subpath] = max(subpath_indexes[key_subpath],
                    script_history.bip32_subpath_index)

                for result1 in script_history.history:
                    tx_id = cast(str, result1["tx_hash"])
                    tx_hash = hex_str_to_hash(tx_id)
                    tx_block_height1 = cast(int, result1["height"])
                    fee_hint = cast(Optional[int], result1.get("fee"))

                    state = self._import_state.get(tx_hash)
                    if state is None:
                        state = self._import_state[tx_hash] = TransactionScanState(tx_hash,
                            { script_hash }, tx_block_height1, fee_hint)
                        all_tx_hashes.append(tx_hash)
                    else:
                        state.item_hashes.add(script_hash)
                        # TODO Work out the repercussions of this. The import process is modal and
                        # it is expected a reorg being encountered during the process is unlikely.
                        # Beyond the differences encountered within the indexer state that is
                        # located in the scan, it is also possible for the state to change after
                        # the scan.
                        if state.block_height is None:
                            state.block_height = tx_block_height1
                        else:
                            state.block_height = max(tx_block_height1, state.block_height)
        elif HARDCODED_SUBSCRIPTION_TYPE == SubscriptionType.PUSHDATA_HASH:
            assert self._pushdata_handler is not None
            fee_hint = None
            tx_block_height2 = None
            for result2 in self._pushdata_handler.get_results():
                tx_hashes: List[bytes] = []
                if result2.flags & MatchFlags.IN_OUTPUT:
                    # This is the transaction with the output script.
                    tx_hashes.append(result2.transaction_hash)
                    # It is expected to have been mined so this should not be empty.
                    if result2.spend_transaction_hash != EMPTY_HASH:
                        tx_hashes.append(result2.spend_transaction_hash)
                elif result2.flags & MatchFlags.IN_INPUT:
                    # This is the transaction with the input script.
                    tx_hashes.append(result2.transaction_hash)
                    # We do not expect to encounter this as all our matching is done on pushdata
                    # that will be in the output. The only place where historically we should
                    # encounter it is P2SH.
                else:
                    raise NotImplementedError

                # TODO(no-checkin) Get the indexes on the matches into this.
                for tx_hash in tx_hashes:
                    state = self._import_state.get(tx_hash)
                    if state is None:
                        state = self._import_state[tx_hash] = TransactionScanState(tx_hash,
                            { result2.push_data_hash }, tx_block_height2, fee_hint)
                        all_tx_hashes.append(result2.push_data_hash)
                    else:
                        state.item_hashes.add(result2.push_data_hash)
        else:
            raise NotImplementedError("")

        # The linking of transaction to accounts cannot be done unless the keys exist with their
        # script hashes.
        account = self._wallet.get_account(self._account_id)
        assert account is not None
        derivation_completion_future: Optional[concurrent.futures.Future[None]] = None
        for subpath, subpath_index in subpath_indexes.items():
            # TODO This derives script hashes which are used to map key usage to the imported
            #   transactions. At some point in the future, this will not be sufficient to cover
            #   mapping key usage to transaction importation, when we no longer have known script
            #   hashes.
            derivation_completion_future, keyinstance_rows = account.derive_new_keys_until(
                tuple(subpath) + (subpath_index,))
            if derivation_completion_future is not None:
                derivation_completion_future = derivation_completion_future
        # All the key creation writes get queued in the database dispatcher. We can wait on the
        # last one if we want to be sure they are created and ready for use.
        if derivation_completion_future is not None:
            derivation_completion_future.result()

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

        tx_state_items = list(self._import_state.items())
        tree_items: List[QTreeWidgetItem] = []
        for entry_index, (tx_hash, entry) in enumerate(tx_state_items):
            # NOTE(typing) It accepts `None` in an iterable of strings. Need to test if it can
            #   be replaced by an empty string.
            tx_id = hash_to_hex_str(tx_hash)
            column_values = [ None, tx_id ]
            tree_item = QTreeWidgetItem(column_values) # type: ignore[arg-type]
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
                tree_item.setIcon(Columns.STATUS, self._attempt_import_icon)
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
        entries = [ cast(TransactionScanState, tree_item.data(Columns.STATUS, ImportRoles.ENTRY))
            for tree_item in tree_items ]
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
                "tx_id": hash_to_hex_str(entry.tx_hash),
                "item_hashes": list(hash_to_hex_str(hash) for hash in entry.item_hashes)
            } for entry in entries))
        self._main_window.app.clipboard().setText(entries_text)

    def _on_menu_copy_tx_ids_json_to_clipboard(self, entries: List[TransactionScanState]) -> None:
        tx_ids_text = json.dumps(list(hash_to_hex_str(entry.tx_hash) for entry in entries))
        self._main_window.app.clipboard().setText(tx_ids_text)

    def _on_menu_view_on_block_explorer(self, entries: List[TransactionScanState]) -> None:
        for entry in entries:
            tx_URL = BE_URL(app_state.config, 'tx', hash_to_hex_str(entry.tx_hash))
            assert tx_URL is not None
            webbrowser.open(tx_URL)



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
            receiving_edit.setAlignment(Qt.AlignmentFlag.AlignRight)
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
            change_edit.setAlignment(Qt.AlignmentFlag.AlignRight)
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
            deterministic_form.add_row(_("Change"), hbox2)
            deterministic_form.add_row(_("Received funds"), hbox1)

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

    def _adjust_contents_margins(self, widget: QWidget, *, left_plus: int=0, top_plus: int=0,
            right_plus: int=0, bottom_plus: int=0) -> None:
        margins = widget.contentsMargins()
        widget.setContentsMargins(margins.left() + left_plus, margins.top() + top_plus,
            margins.right() + right_plus, margins.bottom() + bottom_plus)

