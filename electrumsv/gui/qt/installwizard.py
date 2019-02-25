import os
import shutil
import threading

from PyQt5.QtCore import Qt, pyqtSignal, QEventLoop, QRect
from PyQt5.QtGui import QPalette, QPen, QPainter, QPixmap
from PyQt5.QtWidgets import (
    QWidget, QDialog, QLabel, QPushButton, QScrollArea, QHBoxLayout, QVBoxLayout, QListWidget,
    QAbstractItemView, QListWidgetItem, QLineEdit, QFileDialog, QMessageBox, QSlider,
    QGridLayout, QDialogButtonBox
)

from electrumsv.app_state import app_state
from electrumsv.base_wizard import BaseWizard
from electrumsv.exceptions import UserCancelled, InvalidPassword
from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.storage import WalletStorage
from electrumsv.util import get_electron_cash_user_dir
from electrumsv.wallet import Wallet

from .network_dialog import NetworkChoiceLayout
from .password_dialog import PasswordLayout, PW_NEW, PasswordLineEdit
from .seed_dialog import SeedLayout, KeysLayout
from .util import (
    MessageBoxMixin, Buttons, WWLabel, ChoicesLayout, icon_path, WindowModalDialog,
)


logger = logs.get_logger('wizard')


class GoBack(Exception):
    pass

MSG_GENERATING_WAIT = _("ElectrumSV is generating your addresses, please wait...")
MSG_ENTER_ANYTHING = _("Please enter a seed phrase, a master key, a list of "
                       "Bitcoin addresses, or a list of private keys")
MSG_ENTER_SEED_OR_MPK = _("Please enter a seed phrase or a master key (xpub or xprv):")
MSG_COSIGNER = _("Please enter the master public key of cosigner #{}:")
MSG_ENTER_PASSWORD = _("Choose a password to encrypt your wallet keys.") + '\n'\
                     + _("Leave this field empty if you want to disable encryption.")
MSG_RESTORE_PASSPHRASE = \
    _("Please enter your seed derivation passphrase. "
      "Note: this is NOT your encryption password. "
      "Leave this field empty if you did not use one or are unsure.")


class CosignWidget(QWidget):
    size = 120

    def __init__(self, m, n):
        QWidget.__init__(self)
        self.R = QRect(0, 0, self.size, self.size)
        self.setGeometry(self.R)
        self.setMinimumHeight(self.size)
        self.setMaximumHeight(self.size)
        self.m = m
        self.n = n

    def set_n(self, n):
        self.n = n
        self.update()

    def set_m(self, m):
        self.m = m
        self.update()

    def paintEvent(self, event):
        bgcolor = self.palette().color(QPalette.Background)
        pen = QPen(bgcolor, 7, Qt.SolidLine)
        qp = QPainter()
        qp.begin(self)
        qp.setPen(pen)
        qp.setRenderHint(QPainter.Antialiasing)
        qp.setBrush(Qt.gray)
        for i in range(self.n):
            alpha = int(16* 360 * i/self.n)
            alpha2 = int(16* 360 * 1/self.n)
            qp.setBrush(Qt.green if i<self.m else Qt.gray)
            qp.drawPie(self.R, alpha, alpha2)
        qp.end()



def wizard_dialog(func):
    def func_wrapper(*args, **kwargs):
        run_next = kwargs.get('run_next')
        wizard = args[0]
        wizard.back_button.setText(_(MSG_BUTTON_BACK) if wizard.can_go_back()
                                   else _(MSG_BUTTON_CANCEL))
        try:
            out = func(*args, **kwargs)
        except GoBack:
            if wizard.can_go_back():
                wizard.go_back()
            else:
                wizard.close()
            return
        except UserCancelled:
            return
        if run_next is not None:
            if type(out) is not tuple:
                out = (out,)
            run_next(*out)
    return func_wrapper

MSG_BUTTON_NEXT = "Next"
MSG_BUTTON_BACK = "Back"
MSG_BUTTON_CANCEL = "Cancel"

class InstallWizard(QDialog, MessageBoxMixin, BaseWizard):

    accept_signal = pyqtSignal()
    synchronized_signal = pyqtSignal(str)

    def __init__(self, storage):
        BaseWizard.__init__(self, storage)
        QDialog.__init__(self, None)
        self.setWindowTitle('ElectrumSV')
        self.language_for_seed = app_state.config.get('language')
        self.setMinimumSize(600, 420)
        self.accept_signal.connect(self.accept)
        self.back_button = QPushButton(_(MSG_BUTTON_BACK), self)
        self.back_button.setText(_(MSG_BUTTON_BACK) if self.can_go_back() else _(MSG_BUTTON_CANCEL))
        self.next_button = QPushButton(_(MSG_BUTTON_NEXT), self)
        self.next_button.setDefault(True)
        self.icon_filename = None
        self.loop = QEventLoop()
        self.rejected.connect(lambda: self.loop.exit(0))
        self.back_button.clicked.connect(lambda: self.loop.exit(1))
        self.next_button.clicked.connect(lambda: self.loop.exit(2))
        self.scroll_widget = QWidget()
        self.scroll_widget.setLayout(self.create_template_layout())
        scroll = QScrollArea()
        scroll.setWidget(self.scroll_widget)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidgetResizable(True)
        outer_vbox = QVBoxLayout(self)
        outer_vbox.addWidget(scroll)
        outer_vbox.addLayout(Buttons(self.back_button, self.next_button))
        self.show()
        self.raise_()
        self.refresh_gui()  # Need for QT on MacOSX.  Lame.

    def create_template_layout(self):
        """
        The standard layout divides creates a three part template.
        """
        self.title = QLabel()
        self.main_widget = QWidget()
        self.please_wait = QLabel(_("Please wait..."))
        self.please_wait.setAlignment(Qt.AlignCenter)

        vbox = QVBoxLayout()
        vbox.addWidget(self.title)
        vbox.addWidget(self.main_widget)
        vbox.addStretch(1)
        vbox.addWidget(self.please_wait)
        vbox.addStretch(1)
        self.template_hbox = QHBoxLayout()
        vbox.addLayout(self.template_hbox)
        return vbox

    def start_gui(self, is_startup=False):
        if is_startup:
            self._copy_electron_cash_wallets()
        return self.run_and_get_wallet(is_startup)

    def _copy_electron_cash_wallets(self):
        """
        Work out whether we should show UI to offer to copy the user's
        Electron Cash wallets to their ElectrumSV wallet directory, and
        if so, show it and give them the chance.
        """
        # If the user has ElectrumSV wallets already, we do not offer to copy the one's
        # Electron Cash has.
        esv_wallets_dir = os.path.join(app_state.config.electrum_path(), "wallets")
        if len(self._list_user_wallets(esv_wallets_dir)) > 0:
            return
        ec_wallets_dir = get_electron_cash_user_dir(esv_wallets_dir)
        ec_wallet_count = len(self._list_user_wallets(ec_wallets_dir))
        # If the user does not have Electron Cash wallets to copy, there's no point in offering.
        if ec_wallet_count == 0:
            return

        vbox, file_list = self._create_copy_electron_cash_wallets_layout(ec_wallets_dir)
        self._set_standard_layout(vbox, title=_('Import Electron Cash wallets'))

        v = self.loop.exec_()
        # Cancel, exit application.
        if v == -1:
            raise UserCancelled()
        if v != 2:
            raise GoBack()

        self._do_copy_electron_cash_wallets(file_list, esv_wallets_dir, ec_wallets_dir)

    def _do_copy_electron_cash_wallets(self, file_list, esv_wallets_dir, ec_wallets_dir):
        # If the user selected any files, then we copy them before exiting to the next page.
        for item in file_list.selectedItems():
            filename = item.text()
            source_path = os.path.join(ec_wallets_dir, filename)
            target_path = os.path.join(esv_wallets_dir, filename)
            # If they are copying an Electron Cash wallet over an ElectrumSV wallet, make sure
            # they confirm they are going to replace/overwrite it.
            if os.path.exists(target_path):
                if self.question(_("You already have a wallet named '{}' for ElectrumSV. "+
                                "Replace/overwrite it?").format(filename), self,
                                _("Delete Wallet?")):
                    os.remove(target_path)
                else:
                    continue
            try:
                shutil.copyfile(source_path, target_path)
            except shutil.Error:
                # For now we ignore copy errors.
                pass

    def _create_copy_electron_cash_wallets_layout(self, ec_wallets_dir):
        def update_summary_label():
            selection_count = len(file_list.selectedItems())
            if selection_count == 0:
                summary_label.setText(_("No wallets are selected / will be copied."))
            elif selection_count == 1:
                summary_label.setText(_("1 wallet is selected / will be copied."))
            else:
                summary_label.setText(_("%d wallets are selected / will be copied.")
                                    % selection_count)

        wallet_filenames = sorted(os.listdir(ec_wallets_dir), key=lambda s: s.lower())

        file_list = QListWidget()
        file_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        for filename in wallet_filenames:
            if not self._ignore_wallet_file(os.path.join(ec_wallets_dir, filename)):
                file_list.addItem(QListWidgetItem(filename))
        file_list.itemSelectionChanged.connect(update_summary_label)

        vbox = QVBoxLayout()
        introduction_label = QLabel(
            _("Your Electron Cash wallet directory was found. If you want ElectrumSV to import "
            "any of them on your behalf, select the ones you want copied from the list below "
            "before clicking the Next button."))
        introduction_label.setWordWrap(True)
        vbox.setSpacing(20)
        vbox.addWidget(introduction_label)
        vbox.addWidget(file_list)
        summary_label = QLabel()
        update_summary_label()
        vbox.addWidget(summary_label)
        return vbox, file_list

    def _list_user_wallets(self, wallets_path):
        if os.path.exists(wallets_path):
            from stat import ST_MTIME
            l = [
                (os.stat(os.path.join(wallets_path, filename))[ST_MTIME], filename)
                for filename in os.listdir(wallets_path)
                if not self._ignore_wallet_file(os.path.join(wallets_path, filename))
            ]
            l = sorted(l, reverse=True)
            return [ entry[1] for entry in l ]
        return []

    def _ignore_wallet_file(self, wallet_path):
        if os.path.isdir(wallet_path):
            return True
        if wallet_path.startswith("."):
            return True
        return False

    def run_and_get_wallet(self, is_startup):
        vbox = QVBoxLayout()
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(_('Wallet') + ':'))
        self.name_e = QLineEdit()
        hbox.addWidget(self.name_e)
        button = QPushButton(_('Choose...'))
        hbox.addWidget(button)
        vbox.addLayout(hbox)

        self.msg_label = QLabel('')
        vbox.addWidget(self.msg_label)

        hbox2 = QHBoxLayout()
        self.pw_e = PasswordLineEdit()
        self.pw_e.setMinimumWidth(200)
        self.pw_label = QLabel(_('Password') + ':')
        self.pw_label.setAlignment(Qt.AlignTop)
        hbox2.addWidget(self.pw_label)
        hbox2.addWidget(self.pw_e)
        hbox2.addStretch()
        vbox.addLayout(hbox2)
        self._set_standard_layout(vbox,
            title=_('ElectrumSV wallet'),
            back_text=_(MSG_BUTTON_CANCEL))

        if is_startup:
            def _show_copy_electron_cash_wallets_dialog(*args):
                nonlocal esv_wallets_dir, ec_wallets_dir

                d = WindowModalDialog(self, _("Copy Electron Cash Wallets"))

                vbox, file_list = self._create_copy_electron_cash_wallets_layout(ec_wallets_dir)

                bbox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
                bbox.rejected.connect(d.reject)
                bbox.accepted.connect(d.accept)
                vbox.addWidget(bbox)

                d.setLayout(vbox)

                result = d.exec()
                if result == QDialog.Accepted:
                    self._do_copy_electron_cash_wallets(file_list, esv_wallets_dir, ec_wallets_dir)

                _update_selected_wallet()

            ec_import_icon = QLabel("")
            ec_import_icon.setPixmap(
                QPixmap(icon_path("icons8-info.svg")).scaledToWidth(16, Qt.SmoothTransformation))
            ec_import_label = QLabel(_("Existing Electron Cash wallets detected"))
            ec_import_button = QPushButton(_("Import..."))
            ec_import_button.clicked.connect(_show_copy_electron_cash_wallets_dialog)
            self.template_hbox.addWidget(ec_import_icon)
            self.template_hbox.addWidget(ec_import_label)
            self.template_hbox.addWidget(ec_import_button)
            self.template_hbox.addStretch(1)

            esv_wallets_dir = os.path.join(app_state.config.electrum_path(), "wallets")
            ec_wallets_dir = get_electron_cash_user_dir(esv_wallets_dir)
            if len(self._list_user_wallets(ec_wallets_dir)) == 0:
                ec_import_button.setEnabled(False)
                ec_import_button.setToolTip(_("Nothing to import"))
                ec_import_label.setText(_("No Electron Cash wallets detected"))

        wallet_folder = os.path.dirname(self.storage.path)

        def on_choose():
            path, __ = QFileDialog.getOpenFileName(self, "Select your wallet file", wallet_folder)
            if path:
                self.name_e.setText(path)

        def on_filename(filename):
            path = os.path.join(wallet_folder, filename)
            try:
                self.storage = WalletStorage(path, manual_upgrades=True)
                self.next_button.setEnabled(True)
            except IOError:
                self.storage = None
                self.next_button.setEnabled(False)
            if self.storage:
                if not self.storage.file_exists():
                    msg =_("This file does not exist.") + '\n' \
                          + _("Press 'Next' to create this wallet, or choose another file.")
                    pw = False
                elif self.storage.file_exists() and self.storage.is_encrypted():
                    msg = '\n'.join([
                        _("This file is encrypted."),
                        _('Enter your password or choose another file.'),
                    ])
                    pw = True
                else:
                    msg = _("Press 'Next' to open this wallet.")
                    pw = False
            else:
                msg = _('Cannot read file')
                pw = False
            self.msg_label.setText(msg)
            if pw:
                self.pw_label.show()
                self.pw_e.show()
                self.pw_e.setFocus()
            else:
                self.pw_label.hide()
                self.pw_e.hide()

        def _update_selected_wallet():
            wallet_name = None
            if not self.storage.file_exists() and is_startup:
                esv_wallet_names = self._list_user_wallets(esv_wallets_dir)
                if len(esv_wallet_names):
                    wallet_name = esv_wallet_names[0]
            if wallet_name is None:
                wallet_name = os.path.basename(self.storage.path)
            self.name_e.setText(wallet_name)

        button.clicked.connect(on_choose)
        self.name_e.textChanged.connect(on_filename)
        _update_selected_wallet()

        while True:
            if self.storage.file_exists() and not self.storage.is_encrypted():
                break
            if self.loop.exec_() != 2:  # 2 = next
                return
            if not self.storage.file_exists():
                break
            if self.storage.file_exists() and self.storage.is_encrypted():
                password = self.pw_e.text()
                try:
                    self.storage.decrypt(password)
                    self.pw_e.setText('')
                    break
                except InvalidPassword as e:
                    QMessageBox.information(None, _('Error'), str(e))
                    continue
                except Exception as e:
                    logger.exception("decrypting storage")
                    QMessageBox.information(None, _('Error'), str(e))
                    return

        path = self.storage.path
        if self.storage.requires_split():
            self.hide()
            msg = _("The wallet '{}' contains multiple accounts, which are not supported.\n\n"
                    "Do you want to split your wallet into multiple files?").format(path)
            if not self.question(msg):
                return
            file_list = '\n'.join(self.storage.split_accounts())
            msg = (_('Your accounts have been moved to') + ':\n' + file_list + '\n\n' +
                   _('Do you want to delete the old file') + ':\n' + path)
            if self.question(msg):
                os.remove(path)
                self.show_warning(_('The file was removed'))
            return

        if self.storage.requires_upgrade():
            self.hide()
            msg = _("The format of your wallet '%s' must be upgraded for ElectrumSV. "
                    "This change will not be backward compatible" % path)
            if not self.question(msg):
                return
            self.storage.upgrade()
            self.wallet = Wallet(self.storage)
            return self.wallet

        action = self.storage.get_action()
        if action and action != 'new':
            self.hide()
            msg = _("The file '{}' contains an incompletely created wallet.\n"
                    "Do you want to complete its creation now?").format(path)
            if not self.question(msg):
                if self.question(_("Do you want to delete '{}'?").format(path)):
                    os.remove(path)
                    self.show_warning(_('The file was removed'))
                return
            self.show()
        if action:
            # self.wallet is set in run
            self.run(action)
            return self.wallet

        self.wallet = Wallet(self.storage)
        return self.wallet



    def finished(self):
        """Called in hardware client wrapper, in order to close popups."""
        return

    def on_error(self, exc_info):
        if not isinstance(exc_info[1], UserCancelled):
            logger.exception("")
            self.show_error(str(exc_info[1]))

    def _remove_layout_from_widget(self, widget):
        """
        The only way to remove a layout from a first widget, is to transfer it to a second one.
        This needs to be done, to be able to set a new layout on the first widget.
        """
        existing_layout = widget.layout()
        QWidget().setLayout(existing_layout)

    def _set_layout(self, layout, next_enabled=True, back_text=None):
        """
        Set a layout that is in control of the whole display area.
        """
        self._remove_layout_from_widget(self.scroll_widget)
        self.scroll_widget.setLayout(layout)

        self.back_button.setEnabled(True)
        if back_text is not None:
            self.back_button.setText(back_text)
        self.next_button.setEnabled(next_enabled)
        if next_enabled:
            self.next_button.setFocus()

    def _set_standard_layout(self, layout, title=None, next_enabled=True, back_text=None):
        """
        Ensure the standard template layout is in place.
        And put the current stage's sub-layout in the defined place.
        """
        self._remove_layout_from_widget(self.scroll_widget)
        self.scroll_widget.setLayout(self.create_template_layout())

        self.title.setText("<b>%s</b>"%title if title else "")
        self.title.setVisible(bool(title))
        self.main_widget.setLayout(layout)

        if back_text is None:
            self.back_button.setText(_(MSG_BUTTON_BACK))
        else:
            self.back_button.setText(back_text)
        self.back_button.setEnabled(True)
        self.next_button.setText(_(MSG_BUTTON_NEXT))
        self.next_button.setEnabled(next_enabled)
        if next_enabled:
            self.next_button.setFocus()
        self.main_widget.setVisible(True)
        self.please_wait.setVisible(False)

    def exec_layout(self, layout, title=None, raise_on_cancel=True,
                        next_enabled=True):
        self._set_standard_layout(layout, title, next_enabled)
        result = self.loop.exec_()
        if not result and raise_on_cancel:
            raise UserCancelled
        if result == 1:
            raise GoBack
        self.title.setVisible(False)
        self.back_button.setEnabled(False)
        self.next_button.setEnabled(False)
        self.main_widget.setVisible(False)
        self.please_wait.setVisible(True)
        self.refresh_gui()
        return result

    def refresh_gui(self):
        # For some reason, to refresh the GUI this needs to be called twice
        app_state.app.processEvents()
        app_state.app.processEvents()

    def remove_from_recently_open(self, filename):
        app_state.config.remove_from_recently_open(filename)

    def text_input(self, title, message, is_valid, allow_multi=False):
        slayout = KeysLayout(parent=self, title=message, is_valid=is_valid,
                             allow_multi=allow_multi)
        self.exec_layout(slayout, title, next_enabled=False)
        return slayout.get_text()

    def seed_input(self, title, message, is_seed, options):
        slayout = SeedLayout(title=message, is_seed=is_seed, options=options, parent=self)
        self.exec_layout(slayout, title, next_enabled=False)
        return slayout.get_seed(), slayout.is_bip39, slayout.is_ext

    @wizard_dialog
    def add_xpub_dialog(self, title, message, is_valid, run_next, allow_multi=False):
        return self.text_input(title, message, is_valid, allow_multi)

    @wizard_dialog
    def add_cosigner_dialog(self, run_next, index, is_valid):
        title = _("Add Cosigner") + " %d"%index
        message = ' '.join([
            _('Please enter the master public key (xpub) of your cosigner.'),
            _('Enter their master private key (xprv) if you want to be able to sign for them.')
        ])
        return self.text_input(title, message, is_valid)

    @wizard_dialog
    def restore_seed_dialog(self, run_next, test):
        options = []
        if self.opt_ext:
            options.append('ext')
        if self.opt_bip39:
            options.append('bip39')
        title = _('Enter Seed')
        message = _('Please enter your seed phrase in order to restore your wallet.')
        return self.seed_input(title, message, test, options)

    @wizard_dialog
    def confirm_seed_dialog(self, run_next, test):
        app_state.app.clipboard().clear()
        title = _('Confirm Seed')
        message = ' '.join([
            _('Your seed is important!'),
            _('If you lose your seed, your money will be permanently lost.'),
            _('To make sure that you have properly saved your seed, please retype it here.')
        ])
        seed, is_bip39, is_ext = self.seed_input(title, message, test, None)
        return seed

    @wizard_dialog
    def show_seed_dialog(self, run_next, seed_text):
        title =  _("Your wallet generation seed is:")
        slayout = SeedLayout(seed=seed_text, title=title, msg=True, options=['ext'])
        self.exec_layout(slayout)
        return slayout.is_ext

    def pw_layout(self, msg, kind):
        playout = PasswordLayout(None, msg, kind, self.next_button)
        playout.encrypt_cb.setChecked(True)
        self.exec_layout(playout.layout())
        return playout.new_password(), playout.encrypt_cb.isChecked()

    @wizard_dialog
    def request_password(self, run_next):
        """Request the user enter a new password and confirm it.  Return
        the password or None for no password."""
        return self.pw_layout(MSG_ENTER_PASSWORD, PW_NEW)

    def show_restore(self, wallet, network):
        # FIXME: these messages are shown after the install wizard is
        # finished and the window closed.  On MacOSX they appear parented
        # with a re-appeared ghost install wizard window...
        if network:
            def task():
                wallet.wait_until_synchronized()
                if wallet.is_found():
                    msg = _("Recovery successful")
                else:
                    msg = _("No transactions found for this seed")
                self.synchronized_signal.emit(msg)
            self.synchronized_signal.connect(self.show_message)
            t = threading.Thread(target = task)
            t.daemon = True
            t.start()
        else:
            msg = _("This wallet was restored offline. It may "
                    "contain more addresses than displayed.")
            self.show_message(msg)

    @wizard_dialog
    def confirm_dialog(self, title, message, run_next):
        self.confirm(message, title)

    def confirm(self, message, title):
        label = WWLabel(message)
        vbox = QVBoxLayout()
        vbox.addWidget(label)
        self.exec_layout(vbox, title)

    @wizard_dialog
    def action_dialog(self, action, run_next):
        self.run(action)

    def terminate(self):
        self.accept_signal.emit()

    def waiting_dialog(self, task, msg):
        self.please_wait.setText(MSG_GENERATING_WAIT)
        self.refresh_gui()
        t = threading.Thread(target = task)
        t.start()
        t.join()

    @wizard_dialog
    def choice_dialog(self, title, message, choices, run_next):
        c_values = [x[0] for x in choices]
        c_titles = [x[1] for x in choices]
        clayout = ChoicesLayout(message, c_titles)
        vbox = QVBoxLayout()
        vbox.addLayout(clayout.layout())
        self.exec_layout(vbox, title)
        action = c_values[clayout.selected_index()]
        return action

    def query_choice(self, msg, choices):
        """called by hardware wallets"""
        clayout = ChoicesLayout(msg, choices)
        vbox = QVBoxLayout()
        vbox.addLayout(clayout.layout())
        self.exec_layout(vbox, '')
        return clayout.selected_index()

    @wizard_dialog
    def line_dialog(self, run_next, title, message, default, test, warning=''):
        vbox = QVBoxLayout()
        vbox.addWidget(WWLabel(message))
        line = QLineEdit()
        line.setText(default)
        def f(text):
            self.next_button.setEnabled(test(text))
        line.textEdited.connect(f)
        vbox.addWidget(line)
        vbox.addWidget(WWLabel(warning))
        self.exec_layout(vbox, title, next_enabled=test(default))
        return ' '.join(line.text().split())

    @wizard_dialog
    def show_xpub_dialog(self, xpub, run_next):
        msg = ' '.join([
            _("Here is your master public key."),
            _("Please share it with your cosigners.")
        ])
        vbox = QVBoxLayout()
        layout = SeedLayout(xpub, title=msg, icon=False)
        vbox.addLayout(layout.layout())
        self.exec_layout(vbox, _('Master Public Key'))
        return None

    def init_network(self, network):
        message = _("ElectrumSV communicates with remote servers to get "
                  "information about your transactions and addresses. The "
                  "servers all fulfil the same purpose only differing in "
                  "hardware. In most cases you simply want to let ElectrumSV "
                  "pick one at random.  However if you prefer feel free to "
                  "select a server manually.")
        choices = [_("Auto connect"), _("Select server manually")]
        title = _("How do you want to connect to a server? ")
        clayout = ChoicesLayout(message, choices)
        self.back_button.setText(_(MSG_BUTTON_CANCEL))
        self.exec_layout(clayout.layout(), title)
        r = clayout.selected_index()
        network.auto_connect = (r == 0)
        app_state.config.set_key('auto_connect', network.auto_connect, True)
        if r == 1:
            nlayout = NetworkChoiceLayout(network, app_state.config, wizard=True)
            if self.exec_layout(nlayout.layout()):
                nlayout.accept()

    @wizard_dialog
    def multisig_dialog(self, run_next):
        cw = CosignWidget(2, 2)
        m_edit = QSlider(Qt.Horizontal, self)
        n_edit = QSlider(Qt.Horizontal, self)
        n_edit.setMinimum(2)
        n_edit.setMaximum(15)
        m_edit.setMinimum(1)
        m_edit.setMaximum(2)
        n_edit.setValue(2)
        m_edit.setValue(2)
        n_label = QLabel()
        m_label = QLabel()
        grid = QGridLayout()
        grid.addWidget(n_label, 0, 0)
        grid.addWidget(n_edit, 0, 1)
        grid.addWidget(m_label, 1, 0)
        grid.addWidget(m_edit, 1, 1)
        def on_m(m):
            m_label.setText(_('Require %d signatures')%m)
            cw.set_m(m)
        def on_n(n):
            n_label.setText(_('From %d cosigners')%n)
            cw.set_n(n)
            m_edit.setMaximum(n)
        n_edit.valueChanged.connect(on_n)
        m_edit.valueChanged.connect(on_m)
        on_n(2)
        on_m(2)
        vbox = QVBoxLayout()
        vbox.addWidget(cw)
        vbox.addWidget(WWLabel(_("Choose the number of signatures needed to unlock "
                                 "funds in your wallet:")))
        vbox.addLayout(grid)
        self.exec_layout(vbox, _("Multi-Signature Wallet"))
        m = int(m_edit.value())
        n = int(n_edit.value())
        return (m, n)
