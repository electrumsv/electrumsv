import logging
import requests
import threading

from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from electrumsv import bitcoin
from electrumsv.i18n import _
from electrumsv.address import Address
from . import util

logger = logging.getLogger("coinsplitting")

TX_DESC_PREFIX = "ElectrumSV coin splitting"

RESULT_DUST_TIMEOUT = -4
RESULT_JSON_ERROR = -3
RESULT_HTTP_FAILURE = -2
RESULT_DIALOG_CLOSED = -1
RESULT_READY_FOR_SPLIT = 0

STAGE_INACTIVE = -1
STAGE_PREPARING = 0
STAGE_OBTAINING_DUST = 1
STAGE_SPLITTING = 2

STAGE_NAMES = {
    STAGE_INACTIVE: "Inactive.",
    STAGE_PREPARING: "Preparing..",
    STAGE_OBTAINING_DUST: "Obtaining dust..",
    STAGE_SPLITTING: "Splitting coins..",
}

class CoinSplittingTab(QWidget):
    receiving_address = None
    unfrozen_balance = None
    frozen_balance = None
    split_stage = STAGE_INACTIVE
    faucet_status_code = None
    faucet_result_json = None

    intro_label = None
    splittable_balance_label = None
    unsplittable_balance_label = None
    splittable_unit_label = None
    unsplittable_unit_label = None
    waiting_dialog = None
    new_transaction_cv = None

    def _on_split_button_clicked(self):
        window = self.window()
        self.receiving_address = window.wallet.get_unused_address()
        self.split_stage = STAGE_PREPARING
        self.new_transaction_cv = threading.Condition()

        window.network.register_callback(self._on_network_event, ['new_transaction'])
        self.waiting_dialog = SplitWaitingDialog(window, self, self._split_prepare_task, self._on_split_prepare_task_success, self._on_split_prepare_task_error)

    def _split_prepare_task(self):
        # rt12 --- the close button is removed and the cancel button is removed, which means this should not be needed.
        # if not self.waiting_dialog.isVisible():
        #    return RESULT_DIALOG_CLOSED

        self.split_stage = STAGE_OBTAINING_DUST
        
        if bitcoin.NetworkConstants.TESTNET:
            faucet_url = "https://testnet.satoshisvision.network"
        else:
            faucet_url = "https://faucet.satoshisvision.network"

        address_text = self.receiving_address.to_full_string(Address.FMT_BITCOIN)
        result = requests.get("{}/submit/{}".format(faucet_url, address_text))
        self.faucet_result = result
        if result.status_code != 200:
            return RESULT_HTTP_FAILURE

        d = result.json()
        self.faucet_result_json = d
        if d["error"]:
            return RESULT_JSON_ERROR

        # Wait for the transaction to arrive.
        # How long it takes before the progress bar stalls (should easily cover normal expected time required).
        max_time_passed_for_progress = 40.0
        # How long to wait before failing the process.
        max_time_passed_for_failure = 120.0
        was_received = False
        with self.new_transaction_cv:
            time_passed = 0.0
            while not was_received:
                self.waiting_dialog.set_stage_progress(time_passed/max_time_passed_for_progress)
                was_received = self.new_transaction_cv.wait(0.1)
                time_passed += 0.1
                if time_passed >= max_time_passed_for_failure:
                    return RESULT_DUST_TIMEOUT

        self.split_stage = STAGE_SPLITTING

        # The user needs to sign the transaction.  It can't be done in this thread.

        return RESULT_READY_FOR_SPLIT

    def _on_split_prepare_task_success(self, result):
        window = self.window()
        try:
            if result == RESULT_READY_FOR_SPLIT:
                self._ask_send_split_transaction()
                return

            if result == RESULT_DIALOG_CLOSED:
                window.show_error(_("You aborted the process."))
            elif result == RESULT_HTTP_FAILURE:
                status_code = self.faucet_result.status_code
                window.show_error(_("Unexpected response from faucet:\nHTTP status code = {}").format(status_code))
            elif result == RESULT_JSON_ERROR:
                window.show_error(_("Unexpected response from faucet:\n{}").format(self.faucet_result_json["message"]))
            elif result == RESULT_DUST_TIMEOUT:
                window.show_error(_("It took too long to get the dust from the faucet."))
            else:
                window.show_error(_("Unexpected situation. You should not even be here."))
        finally:
            self._split_cleanup()

    def _on_split_prepare_task_error(self, exc_info):
        logger.exception("on_split_prepare_task_error", exc_info=exc_info)
        self._split_cleanup()

    def _ask_send_split_transaction(self):
        window = self.window()
        wallet = window.wallet

        unused_address = window.wallet.get_unused_address()
        outputs = [
            (bitcoin.TYPE_ADDRESS, unused_address, "!")
        ]
        coins = wallet.get_utxos(None, exclude_frozen=True, mature=True, confirmed_only=False)
        tx = wallet.make_unsigned_transaction(coins, outputs, window.config)
        amount = tx.output_value()
        fee = tx.get_fee()

        msg = [
            _("Amount to be sent") + ": " + window.format_amount_and_units(amount),
            _("Mining fee") + ": " + window.format_amount_and_units(fee),
        ]

        if wallet.has_password():
            msg.append("")
            msg.append(_("Enter your password to proceed"))
            password = window.password_dialog('\n'.join(msg))
        else:
            msg.append(_('Proceed?'))
            password = None
            if not window.question('\n'.join(msg)):
                return

        def sign_done(success):
            if success:
                if not tx.is_complete():
                    window.show_error(_("Signed transaction is unexpectedly incomplete."))
                    return
                window.broadcast_transaction(tx, "{}: Your split coins".format(TX_DESC_PREFIX), success_text=_("Your coins have now been split."))
        window.sign_tx_with_password(tx, sign_done, password)

    def _split_cleanup(self):
        window = self.window()
        window.network.unregister_callback(self._on_network_event)

        self.receiving_address = None
        self.waiting_dialog = None
        self.faucet_status_code = None
        self.faucet_result_json = None
        self.split_stage = STAGE_INACTIVE

    def _on_network_event(self, event, *args):
        window = self.window()
        if event == 'new_transaction':
            tx, wallet = args
            if wallet == window.wallet: # filter out tx's not for this wallet
                our_storage_string = self.receiving_address.to_storage_string()
                for tx_output in tx.outputs():
                    if tx_output[1].to_storage_string() == our_storage_string:
                        wallet.set_label(tx.txid(), "{}: Dust from BSV faucet".format(TX_DESC_PREFIX))
                        break

                # Notify the progress dialog task thread.
                with self.new_transaction_cv:
                    self.new_transaction_cv.notify()

    def update_balances(self):
        window = self.window()
        wallet = window.wallet

        self.unfrozen_balance = wallet.get_balance(exclude_frozen_coins=True, exclude_frozen_addresses=True)
        self.frozen_balance = wallet.get_frozen_balance()

        unfrozen_confirmed, unfrozen_unconfirmed, unfrozen_unmature = self.unfrozen_balance
        frozen_confirmed, frozen_unconfirmed, frozen_unmature = self.frozen_balance

        splittable_amount = unfrozen_confirmed + unfrozen_unconfirmed
        unsplittable_amount = unfrozen_unmature + frozen_confirmed + frozen_unconfirmed + frozen_unmature

        splittable_amount_text = window.format_amount(splittable_amount)
        unit_text = window.base_unit()

        text = (
            "<p>" +
            _("As of the November 2018 hard-fork, Bitcoin Cash split into Bitcoin ABC and Bitcoin SV.") + " " +
            _("This tab allows you to easily split the available coins in this wallet (approximately {} {}) on the Bitcoin SV chain.".format(splittable_amount_text, unit_text)) + " " +
            _("This will involve the following steps if you choose to proceed:") +
            "</p>" +
            _("<ol>") +
            "<li>"+ _("A small amount of SV coin will be obtained from a faucet.") + "</li>" +
            "<li>"+ _("A transaction will be constructed including your entire spendable balance combined with the new known SV coin from the faucet, to be sent back into this wallet.") + "</li>")
        if wallet.has_password():
            text += "<li>"+ _("As this wallet is password protected, you will be prompted to enter your password to sign the transaction.") + "</li>"
        text += (
            "<li>"+ _("The transaction will then be broadcast, and immediately added to your wallet history so you can see it confirmed. It will be labeled as splitting related, so you can easily identify it.") + "</li>" +
            "<li>"+ _("You can then open Electron Cash and move your ABC coins to a different address, in order to finalise the split.") + "</li>" +
            _("</ol>"))

        self.intro_label.setText(text)

    def update_layout(self):
        window = self.window()
        if hasattr(window, "wallet"):
            wallet = window.wallet

            grid = QGridLayout()
            grid.setColumnStretch(0, 1)
            grid.setColumnStretch(4, 1)

            self.intro_label = QLabel("")
            self.intro_label.setTextFormat(Qt.RichText)
            self.intro_label.setMinimumWidth(600)
            self.intro_label.setWordWrap(True)

            split_button = QPushButton(_("Split"))
            split_button.setMaximumWidth(120)
            split_button.clicked.connect(self._on_split_button_clicked)

            help_content = "".join([
                "<ol>",
                "<li>"+ _("Frozen coins will not be included in any split you make. You can use the Coins tab to freeze or unfreeze selected coins, and by doing so only split chosen amounts of your coins at a time.  The View menu can be used to toggle tabs.") +"</li>",
                "<li>"+ _("In order to prevent abuse, the faucet will limit how often you can obtain dust to split with. But that's okay, you can wait and split more coins. Or, if you are not concerned with your coins being linked, you can split dust from your already split coins, and use that to split further subsets.") +"</li>",
                "</ol>",
            ])

            button_row = QHBoxLayout()
            button_row.addWidget(split_button)
            button_row.addWidget(util.HelpButton(help_content, textFormat=Qt.RichText, title="Additional Information"))

            grid.addWidget(self.intro_label, 0, 1, 1, 3)
            # grid.addWidget(balance_widget, 2, 1, 1, 3, Qt.AlignHCenter)
            grid.addLayout(button_row, 2, 1, 1, 3, Qt.AlignHCenter)

            vbox = QVBoxLayout()
            vbox.addStretch(1)
            vbox.addLayout(grid)
            vbox.addStretch(1)

            self.update_balances()
        else:
            label = QLabel("Wallet not loaded, change tabs and come back.")

            hbox = QHBoxLayout()
            hbox.addWidget(label, 0, Qt.AlignHCenter | Qt.AlignVCenter)

            vbox = QVBoxLayout()
            vbox.addLayout(hbox )

        # If the tab is already laid out, it's current layout needs to be reparented/removed before we can replace it.
        existingLayout = self.layout()
        if existingLayout:
            QWidget().setLayout(existingLayout)
        self.setLayout(vbox)


class SplitWaitingDialog(QProgressDialog):
    update_signal = pyqtSignal()

    update_label = None

    def __init__(self, parent, splitter, task, on_success=None, on_error=None):
        self.splitter = splitter

        # These flags remove the close button, which removes a corner case that we'd otherwise have to handle.
        QProgressDialog.__init__(self, "", None, 0, 100, parent, Qt.Window | Qt.WindowTitleHint | Qt.CustomizeWindowHint)

        self.setWindowModality(Qt.WindowModal)
        self.setWindowTitle(_("Please wait"))
        # self.setCancelButton(None)

        self.stage_progress = 0
        self.update_signal.connect(self.update)
        self.update()

        self.accepted.connect(self._on_accepted)
        self.show()
        self.thread = util.TaskThread(self)
        self.thread.add(task, on_success, self.accept, on_error)

    def wait(self):
        self.thread.wait()

    def _on_accepted(self):
        self.thread.stop()

    def set_stage_progress(self, stage_progress):
        self.stage_progress = max(0, min(0.99, stage_progress))
        self.update_signal.emit()

    def update(self):
        self.setValue(max(1, int(self.stage_progress * 100)))
        update_text = STAGE_NAMES[self.splitter.split_stage]
        if self.update_label is None:
            self.update_label = QLabel(update_text)
            self.setLabel(self.update_label)
        else:
            self.update_label.setText(update_text)
