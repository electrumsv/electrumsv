# The Open BSV license.
#
# Copyright © 2020 Bitcoin Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
#   1. The above copyright notice and this permission notice shall be included
#      in all copies or substantial portions of the Software.
#   2. The Software, and any software that is derived from the Software or parts
#      thereof, can only be used on the Bitcoin SV blockchains. The Bitcoin SV
#      blockchains are defined, for purposes of this license, as the Bitcoin
#      blockchain containing block height #556767 with the hash
#      “000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b” and
#      the test blockchains that are supported by the unmodified Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import concurrent
from enum import IntEnum
import os
from typing import Dict, Optional, TYPE_CHECKING

from bitcoinx import hash_to_hex_str

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtWidgets import QDialog, QHBoxLayout, QLabel, QTableWidget, QVBoxLayout

from electrumsv.app_state import app_state
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.util.importers import (identify_label_import_format, LabelImport, LabelImportFormat,
    LabelImportResult)
from electrumsv.wallet import Wallet

from .util import Buttons, CancelButton, FormSectionWidget, MessageBox, OkButton

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


logger = logs.get_logger("import-export")


class LabelState(IntEnum):
    UNKNOWN = 0
    ADD = 1
    REPLACE = 2
    EXISTS = 3



class LabelImporter(QDialog):
    labels_updated = pyqtSignal(int, object, object)

    def __init__(self, main_window: 'ElectrumWindow', wallet: Wallet, account_id: int) -> None:
        super().__init__(main_window, Qt.WindowSystemMenuHint | Qt.WindowTitleHint |
            Qt.WindowCloseButtonHint)

        self.setWindowModality(Qt.WindowModal)
        self.setWindowTitle(_("Label Importer"))
        self.setMinimumWidth(600)
        self.setStyleSheet("""
        QTableWidget QLabel {
            padding-left: 10px;
            padding-right: 10px;
        }
        """)

        self._main_window = main_window
        self._wallet = wallet
        self._account_id = account_id

        self._path: Optional[str] = None
        self._tx_state: Dict[bytes, LabelState] = {}
        self._key_state: Dict[int, LabelState] = {}
        self._import_result: Optional[LabelImportResult] = None
        self._problem_count = 0
        self._change_count = 0

        self._file_name_label = QLabel()
        file_name_form = FormSectionWidget()
        file_name_form.add_row(_("Source file"), self._file_name_label)

        self._detected_problems_label = QLabel(_("Detected Problems:"))

        self._detected_problems_table = QTableWidget()
        self._detected_problems_table.setColumnCount(3)
        self._detected_problems_table.setHorizontalHeaderLabels(
            [ "Type", "Identifier", "Description" ])
        self._detected_problems_table.setColumnWidth(0, 180)
        self._detected_problems_table.setColumnWidth(1, 200)
        hh = self._detected_problems_table.horizontalHeader()
        hh.setStretchLastSection(True)

        forms_layout = QHBoxLayout()

        left_form = FormSectionWidget(minimum_label_width=190)
        self._updateable_tx_label = QLabel()
        left_form.add_row(_("New transaction descriptions"), self._updateable_tx_label)
        self._replacement_tx_label = QLabel()
        left_form.add_row(_("Replacement transaction descriptions"), self._replacement_tx_label)
        self._unchanged_tx_label = QLabel()
        left_form.add_row(_("Unchanged transaction descriptions"), self._unchanged_tx_label)
        self._unmatched_tx_label = QLabel()
        left_form.add_row(_("Unknown transactions"), self._unmatched_tx_label)

        right_form = FormSectionWidget(minimum_label_width=190)
        self._matched_key_label = QLabel()
        right_form.add_row(_("New key descriptions"), self._matched_key_label)
        self._replacement_key_label = QLabel()
        right_form.add_row(_("Replacement key descriptions"), self._replacement_key_label)
        self._unchanged_key_label = QLabel()
        right_form.add_row(_("Unchanged key descriptions"), self._unchanged_key_label)
        self._unrecognized_label = QLabel()
        right_form.add_row(_("Otherwise unknown"), self._unrecognized_label)

        forms_layout.addWidget(left_form)
        forms_layout.addWidget(right_form)

        self._import_button = OkButton(self, _("Import"))
        self._import_button.setEnabled(False)
        self._cancel_button = CancelButton(self)

        vbox = QVBoxLayout()
        vbox.addWidget(file_name_form)
        vbox.addLayout(forms_layout)
        vbox.addSpacing(10)
        vbox.addWidget(self._detected_problems_label)
        vbox.addWidget(self._detected_problems_table)
        vbox.addLayout(Buttons(self._cancel_button, self._import_button))

        self.setLayout(vbox)

    def run(self) -> int:
        import_path = self._main_window.getOpenFileName(_("Open labels file"), "*.json")
        if not import_path:
            return

        try:
            with open(import_path, 'r') as f:
                text = f.read()
        except (IOError, os.error) as reason:
            MessageBox.show_error(_("Unable to import the selected file.") +"\n"+ str(reason))
            return

        matched_format = identify_label_import_format(text)
        if matched_format == LabelImportFormat.UNKNOWN:
            MessageBox.show_error(_("Unable to import the selected file.") +"\n"+
                _("The selected file is not recognized as any of the supported label export "
                "formats."))
            return

        self._path = import_path

        app_state.app.run_in_thread(self._threaded_import_thread, matched_format, text,
            on_done=self._threaded_import_complete)

        result = self.exec()
        if result == QDialog.Accepted:
            self._apply_import()
        return result

    def _apply_import(self) -> None:
        account = self._wallet.get_account(self._account_id)

        # TODO This should be done in bulk rather than a per-description write.
        for tx_hash, description_text in self._import_result.transaction_labels.items():
            self._wallet.set_transaction_label(tx_hash, description_text)

        for keyinstance_id, description_text in self._import_result.key_labels.items():
            account.set_keyinstance_label(keyinstance_id, description_text)

        self.labels_updated.emit(self._account_id, set(self._import_result.key_labels),
            set(self._import_result.transaction_labels))

    def _threaded_import_thread(self, matched_format: LabelImportFormat, text: str) -> None:
        try:
            self._threaded_import(matched_format, text)
        except Exception:
            logger.exception("unexpected exception in processing thread")

    def _threaded_import(self, matched_format: LabelImportFormat, text: str) -> None:
        account = self._wallet.get_account(self._account_id)

        if matched_format == LabelImportFormat.ACCOUNT:
            result = LabelImport.parse_label_export_json(account, text)
        elif matched_format == LabelImportFormat.LABELSYNC:
            result = LabelImport.parse_label_sync_json(account, text)
        else:
            return

        # We do not actually know what transactions belong to an account, transactions are
        # currently cached on a larger entire wallet basis.
        for tx_hash, tx_description in result.transaction_labels.items():
            if not self._wallet._transaction_cache.is_cached(tx_hash):
                self._tx_state[tx_hash] = LabelState.UNKNOWN
            else:
                existing_description = self._wallet.get_transaction_label(tx_hash)
                if existing_description == "":
                    self._tx_state[tx_hash] = LabelState.ADD
                elif existing_description == tx_description:
                    self._tx_state[tx_hash] = LabelState.EXISTS
                else:
                    self._tx_state[tx_hash] = LabelState.REPLACE

        for keyinstance_id, key_description in result.key_labels.items():
            existing_description = account.get_keyinstance_label(keyinstance_id)
            if existing_description == "":
                self._key_state[keyinstance_id] = LabelState.ADD
            elif existing_description == key_description:
                self._key_state[keyinstance_id] = LabelState.EXISTS
            else:
                self._key_state[keyinstance_id] = LabelState.REPLACE

        self._import_result = result

    def _threaded_import_complete(self, future: concurrent.futures.Future) -> None:
        if self._import_result is None:
            MessageBox.show_error(_("The selected file is unrecognised."))
            self.reject()
            return

        account = self._wallet.get_account(self._account_id)

        if self._import_result.format == LabelImportFormat.ACCOUNT:
            account_fingerprint = account.get_fingerprint().hex()
            if self._import_result.account_fingerprint != account_fingerprint:
                MessageBox.show_error(_("The selected file is for another account."))
                self.reject()
                return

        assert self._path is not None
        file_name = os.path.basename(self._path)

        row_index = 0

        tx_add_count = 0
        tx_replace_count = 0
        tx_skip_count = 0
        tx_unknown_count = 0

        for tx_hash, label_state in self._tx_state.items():
            if label_state == LabelState.ADD:
                tx_add_count += 1
                continue

            problem_text: str
            if label_state == LabelState.EXISTS:
                tx_skip_count += 1
                continue
            elif label_state == LabelState.REPLACE:
                tx_replace_count += 1
                problem_text = _("Replacement (for transaction)")
            elif label_state == LabelState.UNKNOWN:
                tx_unknown_count += 1
                problem_text = _("Unknown transaction")
            else:
                raise NotImplementedError(f"Unrecognized tx label state {label_state}")

            description_text = self._import_result.transaction_labels[tx_hash]

            self._detected_problems_table.insertRow(row_index)
            self._detected_problems_table.setCellWidget(row_index, 0, QLabel(problem_text))
            self._detected_problems_table.setCellWidget(row_index, 1,
                QLabel(hash_to_hex_str(tx_hash)))
            self._detected_problems_table.setCellWidget(row_index, 2, QLabel(_(description_text)))
            row_index += 1

        key_add_count = 0
        key_replace_count = 0
        key_skip_count = 0

        for keyinstance_id, label_state in self._key_state.items():
            if label_state == LabelState.ADD:
                key_add_count += 1
                continue

            problem_text: str
            if label_state == LabelState.EXISTS:
                key_skip_count += 1
                continue
            elif label_state == LabelState.REPLACE:
                key_replace_count += 1
                problem_text = _("Replacement (for key)")
            else:
                raise NotImplementedError(f"Unrecognized tx label state {label_state}")

            description_text = self._import_result.key_labels[keyinstance_id]

            self._detected_problems_table.insertRow(row_index)
            self._detected_problems_table.setCellWidget(row_index, 0, QLabel(problem_text))
            key_name = account.get_derivation_path_text(keyinstance_id)
            self._detected_problems_table.setCellWidget(row_index, 1, QLabel(key_name))
            self._detected_problems_table.setCellWidget(row_index, 2, QLabel(_(description_text)))
            row_index += 1

        for key_text, description_text in self._import_result.unknown_labels.items():
            self._detected_problems_table.insertRow(row_index)
            self._detected_problems_table.setCellWidget(row_index, 0,
                QLabel(_("Unrecognized entry")))
            self._detected_problems_table.setCellWidget(row_index, 1,
                QLabel(_(key_text)))
            self._detected_problems_table.setCellWidget(row_index, 2,
                QLabel(_(description_text)))
            row_index += 1

        self._problem_count = row_index
        self._change_count = tx_add_count + tx_replace_count + key_add_count + key_replace_count
        self._file_name_label.setText(file_name)

        self._updateable_tx_label.setText(str(tx_add_count))
        self._replacement_tx_label.setText(str(tx_replace_count))
        self._unchanged_tx_label.setText(str(tx_skip_count))
        self._unmatched_tx_label.setText(str(tx_unknown_count))
        self._matched_key_label.setText(str(key_add_count))
        self._replacement_key_label.setText(str(key_replace_count))
        self._unchanged_key_label.setText(str(key_skip_count))
        self._unrecognized_label.setText(str(len(self._import_result.unknown_labels)))

        if self._change_count > 0:
            self._import_button.setEnabled(True)
            self._import_button.setToolTip(_("Import {} label changes").format(self._change_count))
        else:
            self._import_button.setEnabled(False)
            self._import_button.setToolTip(_("There are no changes to be made"))
