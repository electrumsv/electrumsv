#!/usr/bin/env python
#
# ElectrumSV - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
# Copyright (C) 2019-2020 The ElectrumSV Developers
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

from typing import Any, Optional

from PyQt5.QtCore import Qt, QSortFilterProxyModel, QObject, QSize
from PyQt5.QtGui import QPainter, QPixmap
from PyQt5.QtWidgets import (QVBoxLayout, QLabel,
    QLineEdit, QComboBox, QCompleter, QGridLayout, QWidget, QHBoxLayout, QSizePolicy,
    QStyle, QStyleOption, QPushButton, QToolBar, QAction, QListWidget, QListWidgetItem)

from electrumsv.contacts import (get_system_id, IDENTITY_SYSTEM_NAMES, IdentitySystem,
    ContactDataError, IdentityCheckResult, ContactEntry, ContactIdentity)
from electrumsv.i18n import _

from .util import (Buttons, CancelButton, OkButton, WindowModalDialog, icon_path,
    read_QIcon)
from .wallet_api import WalletAPI

contactcard_stylesheet = """
#ContactCard {
    background-color: white;
    border-bottom: 1px solid #E3E2E2;
}

#ContactAvatar {
    padding: 4px;
    border: 1px solid #E2E2E2;
}
"""

class ListContext(QObject):
    def __init__(self, wallet_api: WalletAPI, contact_list: "ContactList") -> None:
        super().__init__(contact_list)

        self.contact_list = contact_list
        self.wallet_api = wallet_api


class ContactList(QWidget):
    def __init__(self, wallet_api: WalletAPI, parent: Optional['ElectrumWindow']=None):
        super().__init__(parent)

        self._context = ListContext(wallet_api, self)

        cards = ContactCards(self._context, self)
        self.setStyleSheet(contactcard_stylesheet)

        add_contact_action = QAction(self)
        add_contact_action.setIcon(read_QIcon("icons8-plus-blueui.svg"))
        add_contact_action.setToolTip(_("Add new contact"))
        add_contact_action.triggered.connect(self._on_add_contact_action)

        sort_action = QAction(self)
        sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-2-80-blueui.png"))
        sort_action.setToolTip(_("Sort"))
        sort_action.triggered.connect(self._on_sort_action)

        toolbar = QToolBar(self)
        toolbar.setMovable(False)
        toolbar.setOrientation(Qt.Vertical)
        toolbar.setToolButtonStyle(Qt.ToolButtonIconOnly)
        toolbar.addAction(add_contact_action)
        toolbar.addAction(sort_action)

        self._layout = QHBoxLayout()
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)
        self._layout.addWidget(cards)
        self._layout.addWidget(toolbar)
        self.setLayout(self._layout)

        self._cards = cards
        self._sort_action = sort_action
        self._sort_type = 1

    def _on_add_contact_action(self) -> None:
        edit_contact_dialog(self._context.wallet_api)

    def _on_sort_action(self) -> None:
        if self._sort_type == 1:
            self._sort_type = -1
            self._sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-80-blueui.png"))
            self._cards._list.sortItems(Qt.DescendingOrder)
        else:
            self._sort_type = 1
            self._sort_action.setIcon(read_QIcon("icons8-alphabetical-sorting-2-80-blueui.png"))
            self._cards._list.sortItems(Qt.AscendingOrder)


class ContactCards(QWidget):
    def __init__(self, context: ListContext, parent: Any=None) -> None:
        super().__init__(parent)

        self._context = context

        self._layout = QVBoxLayout()
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(0)

        self._empty_label = None
        self._list = None

        contact_identities = self._context.wallet_api.get_identities()
        if len(contact_identities) > 0:
            for contact, identity in sorted(contact_identities, key=lambda t: t[0].label):
                self._add_identity(contact, identity)
        else:
            self._add_empty_label()

        self.setLayout(self._layout)

        self._context.wallet_api.contact_changed.connect(self._on_contact_changed)

    def _add_identity(self, contact: ContactEntry, identity: ContactIdentity) -> None:
        self._remove_empty_label()
        if self._list is None:
            self._list = QListWidget(self)
            self._list.setSortingEnabled(True)
            self._layout.addWidget(self._list)

        test_card = ContactCard(self._context, contact, identity)
        test_card.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Minimum)

        list_item = QListWidgetItem()
        list_item.setText(contact.label)
        # The item won't display unless it gets a size hint. It seems to resize horizontally
        # but unless the height is a minimal amount it won't do anything proactive..
        list_item.setSizeHint(QSize(256, 130))
        self._list.addItem(list_item)
        self._list.setItemWidget(list_item, test_card)

    def _remove_identity(self, contact: ContactEntry, identity: ContactIdentity) -> None:
        removal_entries = []
        for i in range(self._list.count()-1, -1, -1):
            item = self._list.item(i)
            widget = self._list.itemWidget(item)
            if identity is None and widget._contact.contact_id == contact.contact_id:
                self._list.takeItem(i)
            elif widget._identity.identity_id == identity.identity_id:
                self._list.takeItem(i)

        if self._list.count() == 0:
            # Remove the list.
            self._list.setParent(None)
            self._list = None

            # Replace it with the placeholder label.
            self._add_empty_label()

    def _on_contact_changed(self, added: bool, contact: ContactEntry,
            identity: ContactIdentity) -> None:
        if added:
            self._add_identity(contact, identity)
        else:
            self._remove_identity(contact, identity)

    def _add_empty_label(self) -> None:
        self._empty_label = QLabel(_("You do not currently have any contacts."))
        self._empty_label.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        self._layout.addWidget(self._empty_label)

    def _remove_empty_label(self) -> None:
        if self._empty_label is not None:
            self._empty_label.setParent(None)
            self._empty_label = None


class ContactCard(QWidget):
    def __init__(self, context: ListContext, contact: ContactEntry, identity: ContactIdentity,
            parent: Any=None):
        super().__init__(parent)

        self._context = context
        self._contact = contact
        self._identity = identity

        self.setObjectName("ContactCard")

        avatar_label = QLabel("")
        avatar_label.setPixmap(QPixmap(icon_path("icons8-decision-80.png")))
        avatar_label.setObjectName("ContactAvatar")
        avatar_label.setToolTip(_("What your contact avatar looks like."))

        label = QLabel("...")
        label.setSizePolicy(QSizePolicy.MinimumExpanding, QSizePolicy.Preferred)
        label.setAlignment(Qt.AlignHCenter)

        name_layout = QVBoxLayout()
        name_layout.setContentsMargins(0, 0, 0, 0)
        name_layout.addWidget(avatar_label)
        name_layout.addWidget(label)

        def _on_pay_button_clicked(checked: Optional[bool]=False) -> None:
            from . import payment
            # from importlib import reload
            # reload(payment)
            self.w = payment.PaymentWindow(self._context.wallet_api, self._identity.identity_id,
                parent=self)
            self.w.show()

        def _on_delete_button_clicked(checked: Optional[bool]=False) -> None:
            wallet_window = self._context.wallet_api.wallet_window
            if not wallet_window.question(_("Are you sure?")):
                return
            self._context.wallet_api.remove_contacts([ self._contact.contact_id ])

        def _on_edit_button_clicked(checked: Optional[bool]=False) -> None:
            contact_key = (self._contact.contact_id, self._identity.identity_id)
            edit_contact_dialog(self._context.wallet_api, contact_key)

            contact = self._context.wallet_api.get_contact(contact_key[0])
            identity = [ ci for ci in contact.identities if ci.identity_id == contact_key[1] ][0]

            self._contact = contact
            self._identity = identity
            self._update()

        pay_button = QPushButton(_("Pay"), self)
        pay_button.clicked.connect(_on_pay_button_clicked)

        message_button = QPushButton(_("Message"), self)
        message_button.setEnabled(False)

        edit_button = QPushButton(_("Edit"), self)
        edit_button.clicked.connect(_on_edit_button_clicked)

        delete_button = QPushButton(_("Delete"), self)
        delete_button.clicked.connect(_on_delete_button_clicked)

        action_layout = QVBoxLayout()
        action_layout.setSpacing(0)
        action_layout.addStretch(1)
        action_layout.addWidget(pay_button)
        action_layout.addWidget(message_button)
        action_layout.addWidget(edit_button)
        action_layout.addWidget(delete_button)

        self._layout = QHBoxLayout()
        self._layout.setSpacing(8)
        self._layout.setContentsMargins(20, 10, 20, 10)
        self._layout.addLayout(name_layout)
        self._layout.addStretch(1)
        self._layout.addLayout(action_layout)
        self.setLayout(self._layout)

        self._avatar_label = avatar_label
        self._name_label = label

        self._update()

    # QWidget styles do not render. Found this somewhere on the qt5 doc site.
    def paintEvent(self, event):
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PE_Widget, opt, p, self)

    def _update(self):
        self._name_label.setText(self._contact.label)


# TODO: Refactor this into a class.
def edit_contact_dialog(wallet_api, contact_key=None):
    editing = contact_key is not None
    if editing:
        title = _("Edit Contact")
    else:
        title = _("New Contact")

    d = WindowModalDialog(wallet_api.wallet_window.reference(), title)
    vbox = QVBoxLayout(d)
    vbox.addWidget(QLabel(title + ':'))

    def _contact_insert_completion(text):
        if text:
            index = combo1.findText(text)
            combo1.setCurrentIndex(index)

    identity_line = QLineEdit()
    name_line = QLineEdit()
    combo1 = QComboBox()
    combo1.setFixedWidth(280)
    combo1.setEditable(True)

    # add a filter model to filter matching items
    contact_filter_model = QSortFilterProxyModel(combo1)
    contact_filter_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
    contact_filter_model.setSourceModel(combo1.model())

    contact_completer = QCompleter(contact_filter_model, combo1)
    contact_completer.setCompletionMode(QCompleter.UnfilteredPopupCompletion)
    combo1.setCompleter(contact_completer)

    ok_button = OkButton(d)
    ok_button.setEnabled(False)

    def _validate_form() -> None:
        def _set_validation_state(element, is_valid) -> None:
            if not is_valid:
                element.setStyleSheet("border: 1px solid red")
            else:
                element.setStyleSheet("")

        can_submit = True

        system_name = combo1.currentText().lower().strip()
        is_valid = True
        try:
            system_id = get_system_id(system_name)
        except ContactDataError:
            system_id = None
            is_valid = False
        _set_validation_state(combo1, is_valid)
        can_submit = can_submit and is_valid

        identity_text = identity_line.text().strip()
        if system_id is None:
            identity_result = IdentityCheckResult.Invalid
        else:
            identity_result = wallet_api.check_identity_valid(system_id, identity_text,
                skip_exists=editing)
        is_valid = identity_result == IdentityCheckResult.Ok
        _set_validation_state(identity_line, is_valid)
        if is_valid:
            identity_line.setToolTip("")
        elif identity_result == IdentityCheckResult.Invalid:
            if system_id == IdentitySystem.OnChain:
                identity_line.setToolTip(_("Not a valid Bitcoin address"))
            else:
                identity_line.setToolTip(_("Incorrect format"))
        elif identity_result == IdentityCheckResult.InUse:
            identity_line.setToolTip(_("Already in use"))
        can_submit = can_submit and is_valid

        name_text = name_line.text().strip()
        name_result = wallet_api.check_label(name_text)
        is_valid = (name_result == IdentityCheckResult.Ok or
            editing and name_result == IdentityCheckResult.InUse)
        _set_validation_state(name_line, is_valid)
        if is_valid:
            name_line.setToolTip("")
        elif name_result == IdentityCheckResult.Invalid:
            name_line.setToolTip(_("Name too short"))
        elif name_result == IdentityCheckResult.InUse:
            name_line.setToolTip(_("Name already in use"))
        can_submit = can_submit and is_valid

        ok_button.setEnabled(can_submit)

    def _contact_text_changed(text: str) -> None:
        _validate_form()

    combo1.lineEdit().textEdited.connect(contact_filter_model.setFilterFixedString)
    combo1.editTextChanged.connect(_contact_text_changed)
    identity_line.textChanged.connect(_contact_text_changed)
    name_line.textChanged.connect(_contact_text_changed)
    contact_completer.activated.connect(_contact_insert_completion)

    combo1.addItems(list(IDENTITY_SYSTEM_NAMES.values()))

    grid = QGridLayout()
    identity_line.setFixedWidth(280)
    name_line.setFixedWidth(280)
    grid.addWidget(QLabel(_("Identity Type")), 1, 0)
    grid.addWidget(combo1, 1, 1)
    grid.addWidget(QLabel(_("Identity")), 2, 0)
    grid.addWidget(identity_line, 2, 1)
    grid.addWidget(QLabel(_("Name")), 3, 0)
    grid.addWidget(name_line, 3, 1)

    vbox.addLayout(grid)
    vbox.addLayout(Buttons(CancelButton(d), ok_button))

    if contact_key is None:
        combo1.lineEdit().setText(IDENTITY_SYSTEM_NAMES[IdentitySystem.OnChain])
        identity_line.setFocus()
    else:
        entry = wallet_api.get_contact(contact_key[0])
        identity = [ ci for ci in entry.identities if ci.identity_id == contact_key[1] ][0]
        combo1.lineEdit().setText(IDENTITY_SYSTEM_NAMES[identity.system_id])
        identity_line.setText(identity.system_data)
        name_line.setText(entry.label)
        name_line.setFocus()

    if d.exec_():
        name_text = name_line.text().strip()
        identity_text = identity_line.text().strip()
        system_id = get_system_id(combo1.currentText())
        if contact_key is not None:
            contact = wallet_api.get_contact(contact_key[0])
            identity = [ ci for ci in contact.identities if ci.identity_id == contact_key[1] ][0]
            if contact_key[1] != identity.identity_id:
                wallet_api.remove_identity(contact_key[0], contact_key[1])
                wallet_api.add_identity(contact_key[0], system_id, identity_text)
            if contact.label != name_text:
                wallet_api.set_label(contact_key[0], name_text)
        else:
            wallet_api.add_contact(system_id, name_text, identity_text)
