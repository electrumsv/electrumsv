# Open BSV License version 4
#
# Copyright (c) 2021,2022 Bitcoin Association for BSV ("Bitcoin Association")
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

from __future__ import annotations
import concurrent.futures
from dataclasses import dataclass, field
from enum import IntEnum
from functools import partial
import json
import time
from typing import Any, cast, Dict, Iterable, List, Optional, Set, Tuple, TYPE_CHECKING
import webbrowser

from bitcoinx import hash_to_hex_str
from PyQt6.QtCore import pyqtSignal, Qt, QPoint, QTimer
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import (QFrame, QHBoxLayout, QHeaderView, QLabel, QLayout, QMenu,
    QProgressBar, QPushButton, QSizePolicy, QSpinBox, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget)

from ...app_state import app_state
from ...constants import CHANGE_SUBPATH, DerivationPath, EMPTY_HASH, \
    RECEIVING_SUBPATH, ServerCapability, ServerConnectionFlag, TransactionImportFlag, TxFlags, \
    WalletEvent
from ...blockchain_scanner import AdvancedSettings, DEFAULT_GAP_LIMITS, BlockchainScanner, \
    PushDataHashHandler, PushDataSearchError, SearchKeyEnumerator
from ...exceptions import ServerConnectionError
from ...i18n import _
from ...network_support.exceptions import FilterResponseIncompleteError, FilterResponseInvalidError
from ...logs import logs
from ...wallet import Wallet
from ...wallet_database.types import TransactionLinkState, TransactionRow
from ...web import BE_URL

from .constants import ScanDialogRole
from .util import FormSectionWidget, read_QIcon, WindowModalDialog

if TYPE_CHECKING:
    from .app import SVApplication
    from .main_window import ElectrumWindow


logger = logs.get_logger("scanner-ui")


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
TEXT_SERVER_CONNECTION_ERROR = _("<center><b>Server connection error</b></center>"
    "<br/>"
    "The server cannot currently be connected to, and this means that it is not possible to "
    "restore this account."
    "<br/><br/>")
TEXT_SEARCH_ERROR = _("<center><b>Search error</b></center>"
    "<br/>"
    "{}"
    "<br/><br/>")
TEXT_BROKEN_SERVER_ERROR = _("<center><b>Broken server error</b></center>"
    "<br/>"
    "The server selected for restoration is not behaving as expected, and may be broken or "
    "not of sufficient quality for use yet."
    "<br/><br/>")
TEXT_UNRELIABLE_SERVER_ERROR = _("<center><b>Unreliable server error</b></center>"
    "<br/>"
    "The server selected for restoration is not able to provide complete responses to our "
    "requests and it does not seem like either it or our connection to it are reliable."
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
    "This account has been scanned and any located transactions not already present "
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


class ScanErrorKind(IntEnum):
    NONE = 0
    CONNECTION = 1
    SEARCH_PROBLEM = 2
    BROKEN_SERVER = 3
    UNRELIABLE_SERVER = 4


@dataclass(repr=False)
class TransactionScanState:
    tx_hash: bytes
    item_hashes: Set[bytes]
    is_missing = True
    already_imported = False
    already_conflicting = False
    found_spend_conflicts = False
    linked_account_ids: Set[int] = field(default_factory=set)

    def __repr__(self) -> str:
        return f"TransactionScanState(tx_hash={hash_to_hex_str(self.tx_hash)}, item_hashes=["+ \
            ", ".join([ value.hex() for value in self.item_hashes ]) +"] "+ \
            f"is_missing={self.is_missing}, already_imported={self.already_imported}, "+ \
            f"already_conflicting={self.already_conflicting}, "+ \
            f"found_spend_conflicts={self.found_spend_conflicts}, "+ \
            "linked_account_ids=["+ \
                ", ".join(str(account_id) for account_id in self.linked_account_ids) +"])"


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

    import_step_signal = pyqtSignal(TransactionRow, TransactionLinkState)

    _pushdata_handler: Optional[PushDataHashHandler] = None

    def __init__(self, main_window_proxy: ElectrumWindow, wallet: Wallet,
            account_id: int, role: ScanDialogRole) -> None:
        super().__init__(main_window_proxy.reference(), TEXT_TITLE)

        self.setMinimumWidth(500)
        self.setMinimumHeight(150)

        # NOTE(proxytype-is-shitty) weakref.proxy does not return something that mirrors
        #     attributes. This means that everything accessed is an `Any` and we leak those
        #     and it introduces silent typing problems everywhere it touches.
        self._main_window_proxy = main_window_proxy
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

        self._scan_final_text = TEXT_NO_IMPORT

        account = self._wallet.get_account(account_id)
        assert account is not None

        assert self._wallet._network is not None
        # Capped restoration API.
        self._pushdata_handler = PushDataHashHandler(self._wallet._network, account)

        search_enumerator = SearchKeyEnumerator(self._advanced_settings)
        search_enumerator.use_account(account)

        assert self._pushdata_handler is not None
        self._scanner = BlockchainScanner(self._pushdata_handler, search_enumerator,
            extend_range_cb=self._on_scanner_range_extended)

        # We do not have to forceably stop this timer if the dialog is closed. It's lifecycle
        # is directly tied to the life of this dialog.
        self._timer = QTimer(self)

        self.import_step_signal.connect(self._update_for_import_step)

        self._attempt_import_icon = read_QIcon("icons8-add-grey-48-ui.png")
        self._conflicted_tx_icon = read_QIcon("icons8-error-48-ui.png")
        self._imported_tx_icon = read_QIcon("icons8-add-green-48-ui.png")

        self._about_label = QLabel(TEXT_PRE_SCAN)
        self._about_label.setWordWrap(True)
        self._about_label.setAlignment(Qt.AlignmentFlag(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop))
        self._about_label.setMinimumHeight(60)

        # At the time of writing, there are no advanced options to set for non-deterministic.
        self._advanced_button.setEnabled(account.is_deterministic())
        self._advanced_button.clicked.connect(self._on_clicked_button_advanced)

        expand_details_button = self._expand_details_button = QPushButton("+")
        expand_details_button.setStyleSheet("padding: 2px;")
        expand_details_button.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Minimum)
        expand_details_button.clicked.connect(self._on_clicked_button_expand_details)
        expand_details_button.setMinimumWidth(15)

        # NOTE(copy-paste) Generic separation line code used elsewhere as well.
        details_header_line = QFrame()
        details_header_line.setStyleSheet("QFrame { border: 1px solid #C3C2C2; }")
        details_header_line.setFrameShape(QFrame.Shape.HLine)
        details_header_line.setFixedHeight(1)

        details_header = QHBoxLayout()
        details_header.addWidget(expand_details_button)
        details_header.addWidget(QLabel(_("Details")))
        details_header.addWidget(details_header_line, 1)

        tree = self._scan_detail_tree = QTreeWidget()
        tree.header().setStretchLastSection(False)
        tree.setHeaderLabels([ "", "Transaction ID", "Block Height" ])
        tree.setColumnCount(Columns.COLUMN_COUNT)
        tree.header().setSectionResizeMode(Columns.STATUS, QHeaderView.ResizeMode.ResizeToContents)
        tree.header().setSectionResizeMode(Columns.TX_ID, QHeaderView.ResizeMode.Stretch)
        tree.header().setSectionResizeMode(Columns.HEIGHT, QHeaderView.ResizeMode.ResizeToContents)
        tree.setVisible(False)
        tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        tree.setSelectionMode(tree.SelectionMode.ExtendedSelection)
        tree.customContextMenuRequested.connect(self._on_tree_scan_context_menu)
        self._scan_tree_indexes: Dict[bytes, int] = {}

        details_layout = self._details_layout = QVBoxLayout()
        details_layout.addLayout(details_header)
        details_layout.addWidget(tree)

        # NOTE(copy-paste) Generic separation line code used elsewhere as well.
        button_box_line = QFrame()
        button_box_line.setStyleSheet("QFrame { border: 1px solid #E3E2E2; }")
        button_box_line.setFrameShape(QFrame.Shape.HLine)
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

        self._layout = vbox
        self.setLayout(vbox)

        self._update_network_status()
        self._main_window_proxy.network_status_signal.connect(self._update_network_status)

    def _on_dialog_finished(self) -> None:
        self._main_window_proxy.network_status_signal.disconnect(self._update_network_status)

        if self._stage == ScanDialogStage.IMPORT:
            self._wallet.events.unregister_callback(self._on_wallet_event)
        self._main_window_proxy.update_history_view()

    def _on_dialog_rejected(self) -> None:
        if self._stage == ScanDialogStage.SCAN:
            logger.debug("Cleaning up 'DISCOVERY' state")
            self._scanner.shutdown()
        elif self._stage == ScanDialogStage.IMPORT:
            pass

    def _update_network_status(self) -> None:
        if self._stage == ScanDialogStage.PRE_SCAN:
            # This has to be `TIP_FILTER` and not `RESTORATION` as we set the former as the
            # lookup and don't do more intelligent lookups.
            server_state = self._wallet.get_server_state_for_capability(
                ServerCapability.TIP_FILTER)
            if server_state is not None and \
                    server_state.connection_flags & ServerConnectionFlag.WEB_SOCKET_READY:
                self._scan_button.setEnabled(True)
                self._about_label.setText(TEXT_PRE_SCAN)
            else:
                self._scan_button.setEnabled(False)
                self._about_label.setText(TEXT_SERVER_CONNECTION_ERROR)

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
            obtain_tx_keys = list[tuple[bytes, bool]]()
            link_tx_hashes = set[bytes]()
            for tx_hash, import_entry in self._import_state.items():
                if import_entry.already_imported or import_entry.already_conflicting:
                    continue
                if import_entry.is_missing:
                    # We have no idea if this is in a block. We're going to try and get the proof
                    # because we have no idea if this is in a block. The wallet can sort it out.
                    obtain_tx_keys.append((tx_hash, True))
                else:
                    link_tx_hashes.add(tx_hash)

            if len(obtain_tx_keys) or len(link_tx_hashes):
                self._wallet.events.register_callback(self._on_wallet_event,
                    [ WalletEvent.TRANSACTION_OBTAINED ])

            self._on_scanner_range_extended(len(obtain_tx_keys) + len(link_tx_hashes))

            if len(obtain_tx_keys):
                # This will start the process of obtaining the missing transactions. The future
                # is not tied to the lifetime of this process, so we cannot cancel it should the
                # user use the cancel UI. We could extend the wallet to attempt this, but it is not
                # within the scope of the intitial feature set.
                future = cast("SVApplication", app_state.app).run_coro(
                    self._wallet.obtain_transactions_async, self._account_id,
                    obtain_tx_keys, TransactionImportFlag.PROMPTED)
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
            tx_row = await self._wallet.link_transaction_async(tx_hash, link_state)
            self._import_link_hashes.remove(tx_hash)
            self.import_step_signal.emit(tx_row, link_state)

    def _on_wallet_event(self, event: WalletEvent, *args: Iterable[Any]) -> None:
        """
        The general wallet callback event handler.

        This event is triggered by the wallet and is only received for events this object
        registers for and we have explicit handling for each.
        """
        tx_row: TransactionRow
        link_state: TransactionLinkState
        if event == WalletEvent.TRANSACTION_OBTAINED:
            # NOTE(typing) Either we cast each argument, do unions and tuples or this.
            tx_row, _tx, link_state = args # type: ignore

            # Perhaps we received events from other systems or before the import started.
            if tx_row.tx_hash not in self._import_fetch_hashes:
                return
            self._import_fetch_hashes.remove(tx_row.tx_hash)
            self.import_step_signal.emit(tx_row, link_state)

    def _update_for_import_step(self, tx_row: TransactionRow, link_state: TransactionLinkState) \
            -> None:
        tree_item_index = self._scan_tree_indexes[tx_row.tx_hash]
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

        if tx_row.flags & TxFlags.STATE_SETTLED:
            assert tx_row.block_hash is not None
            lookup_result = self._wallet.lookup_header_for_hash(tx_row.block_hash)
            if lookup_result is not None:
                header, _chain = lookup_result
                tree_item.setText(Columns.HEIGHT, str(header.height))

        total_work_units, remaining_work_units = self._get_import_work_units()
        self._progress_bar.setValue(total_work_units - remaining_work_units)

        if remaining_work_units == 0:
            self._stage = ScanDialogStage.FINAL

            self._import_end_time = int(time.time())

            self._exit_button.setText(_("Exit"))
            self._exit_button.setFocus()
            self._progress_bar.setVisible(False)
            self._scan_button.setEnabled(False)

        self._update_display()

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
        h = HelpDialog(self._main_window_proxy.reference(), HELP_FOLDER_NAME, HELP_SCAN_FILE_NAME)
        h.run()

    def _on_clicked_button_advanced(self) -> None:
        dialog = AdvancedScanOptionsDialog(self)
        dialog.exec()

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
            tx_hashes = dict[bytes, int]()
            assert self._pushdata_handler is not None
            for match in self._pushdata_handler.get_results():
                result_count += 1

                if match.filter_result.locking_transaction_hash not in tx_hashes:
                    tx_hashes[match.filter_result.locking_transaction_hash] = 0
                tx_hashes[match.filter_result.locking_transaction_hash] += 1

                if match.filter_result.unlocking_transaction_hash != EMPTY_HASH:
                    if match.filter_result.unlocking_transaction_hash not in tx_hashes:
                        tx_hashes[match.filter_result.unlocking_transaction_hash] = 0
                    tx_hashes[match.filter_result.unlocking_transaction_hash] += 1

            transaction_count = len(tx_hashes)

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
           self._about_label.setText(self._scan_final_text)
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

        scan_error = ScanErrorKind.NONE
        try:
            future.result()
        except ServerConnectionError:
            logger.exception("_on_scan_complete")
            scan_error = ScanErrorKind.CONNECTION
            self._scan_final_text = TEXT_SERVER_CONNECTION_ERROR
        except PushDataSearchError as exc:
            logger.exception("_on_scan_complete")
            scan_error = ScanErrorKind.SEARCH_PROBLEM
            self._scan_final_text = TEXT_SEARCH_ERROR.format(exc.args[0])
        except FilterResponseInvalidError:
            logger.exception("_on_scan_complete")
            # Server behaving in a broken way.
            scan_error = ScanErrorKind.BROKEN_SERVER
            self._scan_final_text = TEXT_BROKEN_SERVER_ERROR
        except FilterResponseIncompleteError:
            logger.exception("_on_scan_complete")
            # Server mid-connection problem.
            scan_error = ScanErrorKind.UNRELIABLE_SERVER
            self._scan_final_text = TEXT_UNRELIABLE_SERVER_ERROR
        else:
            logger.debug("_on_scan_complete")

        # Switch to the post-scan analysis holding stage until we determine what the results mean.
        self._stage = ScanDialogStage.POST_SCAN

        self._timer.timeout.disconnect(self._update_display)
        self._timer.stop()

        self._scan_end_time = int(time.time())

        all_tx_hashes: List[bytes] = []
        subpath_indexes = dict[DerivationPath, int]()
        self._import_state = {}

        assert self._pushdata_handler is not None
        for push_data_match in self._pushdata_handler.get_results():
            # It does not matter if we match the pushdata in the output `MatchFlags.IN_OUTPUT`
            # or in the input `MatchFlags.IN_INPUT`. We are involved in the receipt (locking)
            # and the spend (unlocking) in both cases, and need to see what we received and
            # how it was spent.
            tx_hashes: List[bytes] = []

            # We will always have a locking transaction match, whether the match was in the
            # input or output.
            tx_hashes.append(push_data_match.filter_result.locking_transaction_hash)
            # We will have an unlocking match if the match was in the input, or if the match
            # was in the output and it has been spent. In both cases this is a spend of a
            # receipt by us, and we need to know about it.
            if push_data_match.filter_result.unlocking_transaction_hash != EMPTY_HASH:
                tx_hashes.append(push_data_match.filter_result.unlocking_transaction_hash)

            # TODO We can get the input/output indexes on the matches recorded here for
            #   later use to streamline the import. Given we know what pushdata we were looking
            #   for an in what contexts there is some potential to propagate that right to the
            #   actual import stage which might enable us to remove the scripthash matching.

            for tx_hash in tx_hashes:
                state = self._import_state.get(tx_hash)
                if state is None:
                    state = self._import_state[tx_hash] = TransactionScanState(tx_hash,
                        { push_data_match.filter_result.push_data_hash })
                    all_tx_hashes.append(tx_hash)
                else:
                    state.item_hashes.add(push_data_match.filter_result.push_data_hash)

            assert push_data_match.search_entry.parent_path is not None
            key_subpath = push_data_match.search_entry.parent_path.subpath
            if key_subpath in subpath_indexes:
                subpath_indexes[key_subpath] = max(subpath_indexes[key_subpath],
                    push_data_match.search_entry.parent_index)
            else:
                assert push_data_match.search_entry.parent_index > -1
                subpath_indexes[key_subpath] = push_data_match.search_entry.parent_index


        # The linking of transaction to accounts cannot be done unless the keys exist with their
        # script hashes (remember we link transactions to accounts based on script hashes).
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
        for tx_row in self._wallet.data.read_transactions_exist(all_tx_hashes, self._account_id):
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

        if all_are_imported or conflicts_were_found or scan_error != ScanErrorKind.NONE:
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
            column_values = [ None, tx_id, "?" ]
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
        self._layout.insertLayout(2, self._details_layout)

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
        menu.exec(tree.viewport().mapToGlobal(position))

    def _on_menu_copy_entry_json_to_clipboard(self, entries: List[TransactionScanState]) -> None:
        entries_text = json.dumps(list(
            {
                "tx_id": hash_to_hex_str(entry.tx_hash),
                "item_hashes": list(hash_to_hex_str(hash) for hash in entry.item_hashes)
            } for entry in entries))
        self._main_window_proxy.app.clipboard().setText(entries_text)

    def _on_menu_copy_tx_ids_json_to_clipboard(self, entries: List[TransactionScanState]) -> None:
        tx_ids_text = json.dumps(list(hash_to_hex_str(entry.tx_hash) for entry in entries))
        self._main_window_proxy.app.clipboard().setText(tx_ids_text)

    def _on_menu_view_on_block_explorer(self, entries: List[TransactionScanState]) -> None:
        for entry in entries:
            tx_URL = BE_URL(app_state.config, 'tx', hash_to_hex_str(entry.tx_hash))
            assert tx_URL is not None
            webbrowser.open(tx_URL)



class AdvancedScanOptionsDialog(WindowModalDialog):
    def __init__(self, parent: BlockchainScanDialog) -> None:
        super().__init__(parent, TEXT_SCAN_ADVANCED_TITLE)

        account = parent._wallet.get_account(parent._account_id)
        assert account is not None

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
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFixedHeight(1)

        help_button = QPushButton(_("Help"))
        help_button.clicked.connect(self._on_clicked_button_help)
        close_button = QPushButton(_("Close"))
        close_button.clicked.connect(self._close)

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

    def _close(self) -> None:
        # We provide this so the type signature of the signal method is correct.
        self.close()

    def _on_value_changed_receiving(self, new_value: int) -> None:
        cast(BlockchainScanDialog, self.parent()).update_gap_limit(RECEIVING_SUBPATH, new_value)

    def _on_value_changed_change(self, new_value: int) -> None:
        cast(BlockchainScanDialog, self.parent()).update_gap_limit(CHANGE_SUBPATH, new_value)

    def _on_clicked_button_help(self) -> None:
        from .help_dialog import HelpDialog
        parent = cast(BlockchainScanDialog, self.parent())
        h = HelpDialog(parent._main_window_proxy.reference(), HELP_FOLDER_NAME,
            HELP_SCAN_ADVANCED_FILE_NAME)
        h.run()

    def _adjust_contents_margins(self, widget: QWidget, *, left_plus: int=0, top_plus: int=0,
            right_plus: int=0, bottom_plus: int=0) -> None:
        margins = widget.contentsMargins()
        widget.setContentsMargins(margins.left() + left_plus, margins.top() + top_plus,
            margins.right() + right_plus, margins.bottom() + bottom_plus)

