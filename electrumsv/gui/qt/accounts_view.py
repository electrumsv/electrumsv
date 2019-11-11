from functools import partial
from typing import Optional

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, QListWidget, QListWidgetItem, QMenu, QSplitter,
    QVBoxLayout, QGridLayout, QLabel, QTabWidget)

from electrumsv.bitcoin import address_from_string
from electrumsv.i18n import _
from electrumsv.wallet import MultisigAccount, Wallet

from .main_window import ElectrumWindow
from .qrtextedit import ShowQRTextEdit
from .util import (Buttons, ChoicesLayout, CloseButton, MessageBox, protected)


class AccountsView(QSplitter):
    def __init__(self, main_window: ElectrumWindow, wallet: Wallet) -> None:
        super().__init__(main_window)

        self._main_window = main_window
        self._wallet = wallet

        self._main_window.account_created_signal.connect(self._on_account_created)

        self._selection_list = QListWidget()
        self._tab_widget = QTabWidget()

        self.addWidget(self._selection_list)
        self.addWidget(self._tab_widget)

        self.setStretchFactor(1, 2)

        self._selection_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._selection_list.customContextMenuRequested.connect(self._create_account_menu)

        self._update_account_list()

    def _on_account_created(self, new_account_id: int) -> None:
        self._update_account_list()

    def get_tab_widget(self) -> QTabWidget:
        return self._tab_widget

    def _update_account_list(self) -> None:
        self._selection_list.clear()
        for account in self._wallet.get_accounts():
            item = QListWidgetItem()
            item.setData(Qt.UserRole, account.get_id())
            item.setText(account.display_name())
            self._selection_list.addItem(item)

    def _create_account_menu(self, position) -> None:
        item = self._selection_list.currentItem()
        if not item:
            return

        account_id = item.data(Qt.UserRole)
        account = self._wallet.get_account(account_id)

        menu = QMenu()
        menu.addAction(_("&Information"),
            partial(self._show_master_public_keys, account_id))
        seed_menu = menu.addAction(_("&Seed"),
            partial(self._show_seed_dialog, main_window=self._main_window, account_id=account_id))
        seed_menu.setEnabled(account.has_seed())
        menu.addSeparator()

        private_keys_menu = menu.addMenu(_("&Private keys"))
        if account.can_import_privkey():
            private_keys_menu.addAction(_("&Import"), partial(self._import_privkey,
                main_window=self._main_window, account_id=account_id))

        if account.can_import_address():
            menu.addAction(_("Import addresses"), partial(self._import_addresses, account_id))

        menu.addSeparator()

        labels_menu = menu.addMenu(_("&Labels"))
        action = labels_menu.addAction(_("&Import"),
            partial(self._main_window.do_import_labels, account_id))
        # TODO(rt12) BACKLOG The plan is to implement this in a way that lets the user specify
        # whether to skip importing entries that already have a label (skip / overwrite).
        action.setEnabled(False)
        labels_menu.addAction(_("&Export"), partial(self._main_window.do_export_labels, account_id))

        menu.exec_(self._selection_list.viewport().mapToGlobal(position))

    def _show_master_public_keys(self, account_id: int) -> None:
        account = self._wallet.get_account(account_id)

        dialog = QDialog(self)
        dialog.setWindowTitle(_("Account Information"))
        dialog.setMinimumSize(500, 100)
        mpk_list = account.get_master_public_keys()
        vbox = QVBoxLayout()
        grid = QGridLayout()
        grid.addWidget(QLabel(_("Account name")+ ':'), 0, 0)
        grid.addWidget(QLabel(account.display_name()), 0, 1)
        # TODO(rt12) BACKLOG this should be shown somewhere, not sure it's here.
        # grid.addWidget(QLabel(_("Account type")+ ':'), 1, 0)
        # grid.addWidget(QLabel("wallet_type"), 1, 1)
        # grid.addWidget(QLabel(_("Script type")+ ':'), 2, 0)
        # grid.addWidget(QLabel("txin_type"), 2, 1)
        vbox.addLayout(grid)
        if account.is_deterministic():
            mpk_text = ShowQRTextEdit()
            mpk_text.setMaximumHeight(150)
            mpk_text.addCopyButton(self._main_window.app)
            def show_mpk(index):
                mpk_text.setText(mpk_list[index])
                mpk_text.repaint()   # macOS hack for Electrum #4777
            # only show the combobox in case multiple accounts are available
            if len(mpk_list) > 1:
                def label(key):
                    if isinstance(account, MultisigAccount):
                        return _("cosigner") + ' ' + str(key+1)
                    return ''
                labels = [label(i) for i in range(len(mpk_list))]
                on_click = lambda clayout: show_mpk(clayout.selected_index())
                labels_clayout = ChoicesLayout(_("Master Public Keys"), labels, on_click)
                vbox.addLayout(labels_clayout.layout())
            else:
                vbox.addWidget(QLabel(_("Master Public Key")))
            show_mpk(0)
            vbox.addWidget(mpk_text)
        vbox.addStretch(1)
        vbox.addLayout(Buttons(CloseButton(dialog)))
        dialog.setLayout(vbox)
        dialog.exec_()

    @protected
    def _show_seed_dialog(self, main_window: 'ElectrumWindow', account_id: int=-1,
            password: Optional[str]=None) -> None:
        # account_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        account = self._wallet.get_account(account_id)
        if not account.has_seed():
            MessageBox.show_message(self._main_window, _('This account has no seed'))
            return

        keystore = account.get_keystore()
        try:
            seed = keystore.get_seed(password)
            passphrase = keystore.get_passphrase(password)
        except Exception as e:
            MessageBox.show_error(self._main_window, str(e))
            return

        from .seed_dialog import SeedDialog
        d = SeedDialog(self._main_window, seed, passphrase)
        d.exec_()

    @protected
    def _import_privkey(self, main_window: 'ElectrumWindow', account_id: int=-1,
            password: Optional[str]=None) -> None:
        # account_id is a keyword argument so that 'protected' can identity the correct wallet
        # window to do the password request in the context of.
        account = self._wallet.get_account(account_id)

        title, msg = _('Import private keys'), _("Enter private keys")
        self._main_window._do_import(title, msg,
            lambda x: account.import_private_key(x, password))

    def _import_addresses(self, account_id: int) -> None:
        account = self._wallet.get_account(account_id)

        title, msg = _('Import addresses'), _("Enter addresses")
        def import_addr(addr):
            address = address_from_string(addr)
            if account.import_address(address):
                return address
            return None
        self._main_window._do_import(title, msg, import_addr)
