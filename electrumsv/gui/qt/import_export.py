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

import concurrent.futures
from enum import IntEnum
import os
from typing import cast, Dict, Optional, Tuple, TYPE_CHECKING

from bitcoinx import bip32_build_chain_string, hash_to_hex_str

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtWidgets import QDialog, QHBoxLayout, QLabel, QTableWidget, QVBoxLayout

from ...app_state import app_state
from ...constants import DerivationPath, DerivationType, pack_derivation_path
from ...i18n import _
from ...logs import logs
from ...util.importers import (identify_label_import_format, LabelImport, LabelImportFormat,
    LabelImportResult)
from ...wallet import AbstractAccount, Wallet

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
        super().__init__(main_window, Qt.WindowType(Qt.WindowType.WindowSystemMenuHint |
            Qt.WindowType.WindowTitleHint | Qt.WindowType.WindowCloseButtonHint))

        self.setWindowModality(Qt.WindowModality.WindowModal)
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
        self._key_state: Dict[DerivationPath, Tuple[LabelState, int]] = {}
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

        left_form = FormSectionWidget()
        self._updateable_tx_label = QLabel()
        left_form.add_row(_("New transaction descriptions"), self._updateable_tx_label)
        self._replacement_tx_label = QLabel()
        left_form.add_row(_("Replacement transaction descriptions"), self._replacement_tx_label)
        self._unchanged_tx_label = QLabel()
        left_form.add_row(_("Unchanged transaction descriptions"), self._unchanged_tx_label)
        self._unmatched_tx_label = QLabel()
        left_form.add_row(_("Unknown transactions"), self._unmatched_tx_label)

        right_form = FormSectionWidget()
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

    def run(self) -> Optional[int]:
        import_path = self._main_window.getOpenFileName(_("Open labels file"), "*.json")
        if not import_path:
            return None

        try:
            with open(import_path, 'r') as f:
                text = f.read()
        except (IOError, os.error) as reason:
            MessageBox.show_error(_("Unable to import the selected file.") +"\n"+ str(reason))
            return None

        matched_format = identify_label_import_format(text)
        if matched_format == LabelImportFormat.UNKNOWN:
            MessageBox.show_error(_("Unable to import the selected file.") +"\n"+
                _("The selected file is not recognized as any of the supported label export "
                "formats."))
            return None

        self._path = import_path

        # Start the importing logic in a worker thread. This does not block and the user can
        # in theory cancel it by dismissing this dialog.
        app_state.app_qt.run_in_thread(self._threaded_import_thread, matched_format, text,
            on_done=self._threaded_import_complete)

        result = self.exec()
        if result == QDialog.DialogCode.Accepted:
            self._on_import_button_clicked()
        return result

    def _on_import_button_clicked(self) -> None:
        """
        Handle the 'Import' button being clicked and apply the imports.
        """
        assert self._import_result is not None

        account = cast(AbstractAccount, self._wallet.get_account(self._account_id))
        account.set_transaction_labels(self._import_result.transaction_labels.items())

        # TODO This should be a bulk set operation, not per key.
        for derivation_path, description_text in self._import_result.key_labels.items():
            keyinstance_id = self._key_state[derivation_path][1]
            account.set_keyinstance_label(keyinstance_id, description_text)

        self.labels_updated.emit(self._account_id, set(self._import_result.key_labels),
            set(self._import_result.transaction_labels))

    def _threaded_import_thread(self, matched_format: LabelImportFormat, text: str) -> None:
        """
        The worker thread that does the import processing.
        """
        try:
            self._threaded_import(matched_format, text)
        except Exception:
            logger.exception("unexpected exception in processing thread")

    def _threaded_import(self, matched_format: LabelImportFormat, text: str) -> None:
        """
        The worker logic that does the import processing.
        """
        account = self._wallet.get_account(self._account_id)
        assert account is not None

        if matched_format == LabelImportFormat.ACCOUNT:
            result = LabelImport.parse_label_export_json(account, text)
        elif matched_format == LabelImportFormat.LABELSYNC:
            result = LabelImport.parse_label_sync_json(account, text)
        else:
            return

        account_tx_hashes = { r.tx_hash
            for r in self._wallet.read_transaction_descriptions(self._account_id) }

        for tx_hash, tx_description in result.transaction_labels.items():
            if tx_hash not in account_tx_hashes:
                self._tx_state[tx_hash] = LabelState.UNKNOWN
            else:
                existing_description = account.get_transaction_label(tx_hash)
                if existing_description == "":
                    self._tx_state[tx_hash] = LabelState.ADD
                elif existing_description == tx_description:
                    self._tx_state[tx_hash] = LabelState.EXISTS
                else:
                    self._tx_state[tx_hash] = LabelState.REPLACE

        derivation_path_by_data2 = { pack_derivation_path(label_path): label_path
            for label_path in result.key_labels }
        existing_keys = self._wallet.read_keyinstances_for_derivations(account.get_id(),
            DerivationType.BIP32_SUBPATH, list(derivation_path_by_data2),
            account.get_masterkey_id())
        keyinstances_by_derivation_path = {
            derivation_path_by_data2[cast(bytes, keyinstance_row.derivation_data2)]: keyinstance_row
            for keyinstance_row in existing_keys }
        for derivation_path, key_description in result.key_labels.items():
            keyinstance_row = keyinstances_by_derivation_path[derivation_path]
            keyinstance_id = keyinstance_row.keyinstance_id
            if not keyinstance_row.description:
                self._key_state[derivation_path] = LabelState.ADD, keyinstance_id
            elif keyinstance_row.description == key_description:
                self._key_state[derivation_path] = LabelState.EXISTS, keyinstance_id
            else:
                self._key_state[derivation_path] = LabelState.REPLACE, keyinstance_id

        self._import_result = result

    def _threaded_import_complete(self, future: concurrent.futures.Future[None]) -> None:
        """
        GUI thread callback indicating the import logic completed.
        """
        if self._import_result is None:
            MessageBox.show_error(_("The selected file is unrecognised."))
            self.reject()
            return

        account = cast(AbstractAccount, self._wallet.get_account(self._account_id))

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

        for derivation_path, (label_state, keyinstance_id) in self._key_state.items():
            if label_state == LabelState.ADD:
                key_add_count += 1
                continue

            problem_text2: str
            if label_state == LabelState.EXISTS:
                key_skip_count += 1
                continue
            elif label_state == LabelState.REPLACE:
                key_replace_count += 1
                problem_text2 = _("Replacement (for key)")
            else:
                raise NotImplementedError(f"Unrecognized key label state {label_state}")

            description_text = self._import_result.key_labels[derivation_path]

            self._detected_problems_table.insertRow(row_index)
            self._detected_problems_table.setCellWidget(row_index, 0, QLabel(problem_text2))
            derivation_text = bip32_build_chain_string(derivation_path)
            self._detected_problems_table.setCellWidget(row_index, 1, QLabel(derivation_text))
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
