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

from functools import partial
from typing import Optional

from bitcoinx import bip32_key_from_string, BIP32PublicKey

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QPainter
from PyQt5.QtWidgets import (QAbstractItemView, QAbstractScrollArea, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QSizePolicy, QStyle, QStyleOption, QWizard)

from electrumsv.constants import DerivationType, KeystoreTextType
from electrumsv.i18n import _
from electrumsv.keystore import instantiate_keystore_from_text, KeyStore

from .main_window import ElectrumWindow
from .qrtextedit import ShowQRTextEdit
from .util import FormSectionWidget, protected, read_QIcon
from .wizard_common import WizardFlags


class CosignerState:
    keystore: Optional[KeyStore] = None
    name: Optional[str] = None
    is_local = False

    def __init__(self, cosigner_index: int, keystore: Optional[KeyStore]=None) -> None:
        self.cosigner_index = cosigner_index
        self.keystore = keystore

    def reset(self) -> None:
        self.keystore = None
        self.is_local = False

    def is_complete(self) -> bool:
        return self.keystore is not None


class CosignerCard(FormSectionWidget):
    minimum_label_width = 100

    cosigner_updated = pyqtSignal(int)

    def __init__(self, main_window: ElectrumWindow, state: CosignerState, create: bool) -> None:
        super().__init__()

        self._main_window = main_window
        self._state = state
        self._create = create

        self.setObjectName("CosignerCard")

        title_text = _("Cosigner #{}").format(state.cosigner_index+1)
        self.add_title(title_text)

        cosigner_name_edit = QLineEdit()
        cosigner_name_edit.setPlaceholderText(_("A name or label for this cosigner (optional)."))
        cosigner_name_edit.setContentsMargins(0, 0, 0, 0)
        cosigner_name_edit.textEdited.connect(self._event_name_changed)
        self._cosigner_name_edit = cosigner_name_edit

        self._key_icon = read_QIcon('icons8-key.svg')
        self._delete_icon = read_QIcon('icons8-delete.svg')

        key_edit = ShowQRTextEdit(self)
        key_edit.setPlaceholderText(_("Paste any extended public key for this cosigner here, or "
            "use the key button for other options."))
        key_edit.setFixedHeight(65)
        key_edit.setTabChangesFocus(True)
        key_edit.textChanged.connect(self._event_text_changed)
        self._show_qr_button = key_edit.qr_button
        self._key_copy_button = key_edit.addCopyButton(self._main_window.app)
        self._cosigner_key_button = key_edit.addButton(
            'icons8-key.svg',
            self._event_click_set_cosigner_key, _("Specify key data"))
        self._show_secured_data_button = key_edit.addButton(
            "icons8-grand-master-key-32-windows.png",
            partial(self._event_click_show_secured_data, main_window=self._main_window),
            _("Show secured data"))
        self._key_edit = key_edit

        signed_by_label = QLabel()
        signed_by_label.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.MinimumExpanding)
        self._signed_by_label = signed_by_label

        self.add_row(_("Master public key"), key_edit, True)
        self.add_row(_("Name"), cosigner_name_edit, True)
        self.add_row(_("Signed by"), signed_by_label)

        self._update_keystore(state.keystore)

    @protected
    def _event_click_show_secured_data(self, clicked: bool, *, main_window: ElectrumWindow,
            password: str) -> None:
        assert self._state.keystore is not None
        assert not self._state.keystore.is_watching_only()

        from .secured_data_dialog import SecuredDataDialog
        d = SecuredDataDialog(self._main_window, self, self._state.keystore, password)
        d.exec_()

    def _event_click_set_cosigner_key(self) -> None:
        if self._state.keystore is not None:
            self._update_keystore(None)
            return

        from .account_wizard import AccountWizard
        child_wizard = AccountWizard(self._main_window, WizardFlags.MULTISIG_MODE, self)
        subtitle_text = _("Cosigner #{} Key Selection").format(self._state.cosigner_index+1)
        child_wizard.set_subtitle(subtitle_text)
        if child_wizard.run() == QWizard.Accepted:
            assert child_wizard.has_result(), "accepted result-less wizard"
            self._update_keystore(child_wizard.get_keystore())
        else:
            self._update_keystore(None)

    def _event_click_copy_key(self) -> None:
        pass

    def _event_name_changed(self) -> None:
        self._state.name = self._cosigner_name_edit.text().strip()
        if self._state.keystore is not None:
            self._state.keystore.label = self._state.name

    def _event_text_changed(self) -> None:
        if self._key_edit.isReadOnly():
            return

        text = self._key_edit.toPlainText()
        try:
            key = bip32_key_from_string(text)
        except ValueError:
            return
        else:
            if not isinstance(key, BIP32PublicKey):
                return

        password = None
        keystore = instantiate_keystore_from_text(KeystoreTextType.EXTENDED_PUBLIC_KEY,
            text, password)
        self._update_keystore(keystore)

    def _update_keystore(self, keystore: Optional[KeyStore]) -> None:
        if keystore is None:
            self._state.reset()
            self._key_edit.setReadOnly(False)
            self._key_edit.clear()
            self._cosigner_key_button.setIcon(self._key_icon)
            self._cosigner_key_button.setToolTip(_("Set the current key for this cosigner"))
            self._cosigner_name_edit.setText("")
        else:
            self._state.keystore = keystore
            # The stringification of the key will ensure it displays correctly.
            self._key_edit.setReadOnly(True)
            self._key_edit.clear()
            self._key_edit.appendPlainText(keystore.get_master_public_key())
            self._cosigner_key_button.setIcon(self._delete_icon)
            self._cosigner_key_button.setToolTip(_("Clear the current key for this cosigner"))
            if self._create:
                if keystore.label is not None:
                    # This is likely copying the label from hardware accounts which are the only
                    # kind of account that gets a label when created (based on vendor.. etc).
                    self._cosigner_name_edit.setText(keystore.label)
                else:
                    # If the user set the label before setting the keystore, we need to copy it
                    # to the keystore.
                    keystore.label = self._state.name if self._state.name else None
                self._cosigner_name_edit.setReadOnly(False)
            else:
                if keystore.label is not None and len(keystore.label):
                    self._cosigner_name_edit.setText(keystore.label)
                else:
                    self._cosigner_name_edit.setEnabled(False)
                    self._cosigner_name_edit.setPlaceholderText("")
                self._cosigner_name_edit.setReadOnly(True)

        self._show_qr_button.setEnabled(keystore is not None)
        self._key_copy_button.setEnabled(keystore is not None)
        self._show_secured_data_button.setEnabled(
            keystore is not None and not keystore.is_watching_only() and
            keystore.derivation_type != DerivationType.HARDWARE)
        self._cosigner_key_button.setEnabled(self._create)
        self._update_status_label()

        self.cosigner_updated.emit(self._state.cosigner_index)

    def _update_status_label(self) -> None:
        if self._state.is_complete():
            if self._state.keystore.is_watching_only():
                self._signed_by_label.setText(_("External party") +".")
            else:
                self._signed_by_label.setText(_("This account") +".")
            self._signed_by_label.setStyleSheet("")
        else:
            self._signed_by_label.setText(_("Not yet specified") +".")
            self._signed_by_label.setStyleSheet("QLabel { color: red; }")

    # QWidget styles do not render. Found this somewhere on the qt5 doc site.
    def paintEvent(self, event):
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PE_Widget, opt, p, self)


class CosignerList(QListWidget):
    def __init__(self, main_window: ElectrumWindow, create: bool=True) -> None:
        self._main_window = main_window
        self._create = create

        super().__init__()
        # NOTE(rt12): If we do not set this to white, then opposite world things happen:
        # - The part of the text edit with the buttons has white background.
        # - The list has a strange white area on the right hand side sometimes.
        self.setStyleSheet("""
            QListWidget, QPlainTextEdit {
                background-color: white;
            }
        """)

        self.setSortingEnabled(False)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

    def add_state(self, state: CosignerState) -> CosignerCard:
        card = CosignerCard(self._main_window, state, self._create)
        list_item = QListWidgetItem()
        # The item won't display unless it gets a size hint. It seems to resize horizontally
        # but unless the height is a minimal amount it won't do anything proactive..
        list_item.setSizeHint(card.sizeHint())
        self.addItem(list_item)
        self.setItemWidget(list_item, card)
        return card
