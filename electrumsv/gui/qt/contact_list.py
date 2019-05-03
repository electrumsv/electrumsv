#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
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

from functools import partial

from PyQt5.QtCore import (Qt, QSortFilterProxyModel)
from PyQt5.QtWidgets import (QAbstractItemView, QMenu, QTreeWidgetItem, QVBoxLayout, QLabel,
    QLineEdit, QComboBox, QCompleter, QGridLayout)

from electrumsv.contacts import (get_system_id, IDENTITY_SYSTEM_NAMES, IdentitySystem,
    ContactDataError, IdentityCheckResult)
from electrumsv.i18n import _

from .util import (Buttons, CancelButton, MyTreeWidget, OkButton, WindowModalDialog)


class ContactList(MyTreeWidget):
    filter_columns = [0, 1, 2]  # Name, System, Identifier

    def __init__(self, parent):
        MyTreeWidget.__init__(self, parent, self.create_menu,
            [_('Name'), _('Type'), _('Identity')], 0, [0])
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setStyleSheet("QTreeView::item {  padding-right: 15px; }")

    def on_doubleclick(self, item, column):
        contact_key = item.data(0, Qt.UserRole)
        edit_contact_dialog(self, self.parent, contact_key)

    def create_menu(self, position):
        menu = QMenu()
        selected = self.selectedItems()
        if not selected:
            menu.addAction(_("New contact"), partial(edit_contact_dialog, self, self.parent))
        else:
            column = self.currentColumn()
            column_title = self.headerItem().text(column)
            column_data = '\n'.join([item.text(column) for item in selected])
            menu.addAction(_("Copy {}").format(column_title),
                           lambda: self.parent.app.clipboard().setText(column_data))
            if column in self.editable_columns:
                item = self.currentItem()
                contact_key = item.data(0, Qt.UserRole)
                menu.addAction(_("Edit {}").format(column_title),
                               lambda: partial(edit_contact_dialog, self, self.parent, contact_key))

            keys = [item.data(0, Qt.UserRole)[0] for item in selected]
            menu.addAction(_("Pay to"), lambda: self.parent.payto_contacts(keys))
            menu.addAction(_("Delete"), lambda: self._delete_contacts(keys))
            # URLs = [
            #     web.BE_URL(self.config, 'addr', Address.from_string(key))
            #     for key in keys if Address.is_valid(key)
            # ]
            # if URLs:
            #     menu.addAction(_("View on block explorer"),
            #                    lambda: [webbrowser.open(URL) for URL in URLs])

        menu.exec_(self.viewport().mapToGlobal(position))

    def on_update(self):
        item = self.currentItem()
        current_contact_key = item.data(0, Qt.UserRole) if item else None
        self.clear()

        for entry in sorted(self.parent.contacts.get_contacts(), key=lambda e: e.label):
            for identity in entry.identities:
                contact_key = (entry.contact_id, identity.system_id)
                system_name = IDENTITY_SYSTEM_NAMES[identity.system_id]
                item = QTreeWidgetItem([
                    entry.label,
                    system_name,
                    str(identity.system_data),
                ])
                item.setData(0, Qt.UserRole, contact_key)
                self.addTopLevelItem(item)
                if contact_key == current_contact_key:
                    self.setCurrentItem(item)

    def _delete_contacts(self, contact_ids):
        if not self.parent.question(_("Are you sure?")):
            return

        self.parent.contacts.remove_contacts(contact_ids)
        self.parent._on_contacts_changed()


def edit_contact_dialog(parent, main_window, contact_key=None):
    editing = contact_key is not None
    if editing:
        title = _("Edit Contact")
    else:
        title = _("New Contact")

    d = WindowModalDialog(parent, title)
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
            identity_result = main_window.contacts.check_identity_valid(system_id, identity_text,
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
        name_result = main_window.contacts.check_label(name_text)
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
        entry = main_window.contacts.get_contact(contact_key[0])
        identity = [ ci for ci in entry.identities if ci.system_id == contact_key[1] ][0]
        combo1.lineEdit().setText(IDENTITY_SYSTEM_NAMES[contact_key[1]])
        identity_line.setText(identity.system_data)
        name_line.setText(entry.label)
        name_line.setFocus()

    if d.exec_():
        name_text = name_line.text().strip()
        identity_text = identity_line.text().strip()
        system_id = get_system_id(combo1.currentText())
        if contact_key is not None:
            contact = main_window.contacts.get_contact(contact_key[0])
            if contact_key[1] != system_id:
                main_window.contacts.remove_identity(contact_key[0], contact_key[1])
                main_window.contacts.add_identity(contact_key[0], system_id, identity_text)
            if contact.label != name_text:
                main_window.contacts.set_label(contact_key[0], name_text)
        else:
            main_window.contacts.add_contact(system_id, name_text, identity_text)
        main_window._on_contacts_changed()

