from typing import Optional, Tuple

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QLineEdit, QSizePolicy, QStatusBar,
    QToolButton, QWidget, QWidgetAction)

from electrumsv.i18n import _

from .util import icon_path


class BalancePopup(QWidget):
    def __init__(self, main_window: 'ElectrumWindow', status_bar: 'StatusBar',
            parent: QWidget) -> None:
        super().__init__(parent)

        grid_layout = QGridLayout()
        grid_layout.addWidget(QLabel(_('Confirmed')), 0, 0, 1, 1)
        grid_layout.addWidget(QLabel(_('Unconfirmed')), 1, 0, 1, 1)
        grid_layout.addWidget(QLabel(_('Unmatured')), 2, 0, 1, 1)

        cc = uu = xx = 0
        for wallet in main_window.parent_wallet.get_child_wallets():
            c, u, x = wallet.get_balance()
            cc += c
            uu += u
            xx += x

        balances = (cc, uu, xx)
        for i, balance in enumerate(balances):
            bsv_status, fiat_status = main_window.get_amount_and_units(balance)
            grid_layout.addWidget(QLabel(bsv_status), i, 1, 1, 1, Qt.AlignRight)
            if status_bar._fiat_widget.isVisible():
                grid_layout.addWidget(QLabel(fiat_status), i, 2, 1, 1, Qt.AlignRight)

        self.setLayout(grid_layout)


class BalancePopupAction(QWidgetAction):
    def __init__(self, main_window: 'ElectrumWindow', status_bar: 'StatusBar',
            parent: Optional[QWidget]=None) -> None:
        super().__init__(parent)

        self._status_bar = status_bar
        self._main_window = main_window

    def createWidget(self, parent: QWidget) -> QWidget:
        return BalancePopup(self._main_window, self._status_bar, parent)


class StatusBar(QStatusBar):
    _balance_bsv_label: QLabel = None
    _balance_equals_label: QLabel = None
    _balance_fiat_label: QLabel = None
    _balance_widget: QToolButton = None

    _fiat_bsv_label: QLabel = None
    _fiat_value_label: QLabel = None
    _fiat_widget: QWidget = None

    _network_label: QLabel = None

    def __init__(self, main_window: 'ElectrumWindow') -> None:
        super().__init__(None)

        balance_widget = QToolButton()
        balance_widget.setAutoRaise(True)
        balance_widget.setPopupMode(QToolButton.MenuButtonPopup)
        balance_icon_label = QLabel("")
        balance_icon_label.setPixmap(QPixmap(icon_path("sb_balance.png")))
        hbox = QHBoxLayout()
        hbox.setSpacing(2)
        hbox.setSizeConstraint(hbox.SetFixedSize)
        hbox.addWidget(balance_icon_label)
        self._balance_bsv_label = QLabel("")
        hbox.addWidget(self._balance_bsv_label)
        self._balance_equals_label = QLabel("")
        self._balance_equals_label.setPixmap(QPixmap(icon_path("sb_approximate")))
        hbox.addWidget(self._balance_equals_label)
        self._balance_fiat_label = QLabel("")
        hbox.addWidget(self._balance_fiat_label)
        # This is to pad out the text on the RHS so that the menu indicator does not overlay it.
        hbox.addWidget(QLabel(" "))
        balance_widget.setLayout(hbox)
        balance_widget.addAction(BalancePopupAction(main_window, self, balance_widget))
        self._balance_widget = balance_widget
        self.addPermanentWidget(balance_widget)

        self._fiat_widget = QWidget()
        self._fiat_widget.setVisible(False)
        estimate_icon_label = QLabel("")
        estimate_icon_label.setPixmap(QPixmap(icon_path("sb_fiat.png")))
        hbox = QHBoxLayout()
        hbox.setSpacing(2)
        hbox.setSizeConstraint(hbox.SetFixedSize)
        hbox.addWidget(estimate_icon_label)
        self._fiat_bsv_label = QLabel("")
        hbox.addWidget(self._fiat_bsv_label)
        approximate_icon_label = QLabel("")
        approximate_icon_label.setPixmap(QPixmap(icon_path("sb_approximate")))
        hbox.addWidget(approximate_icon_label)
        self._fiat_value_label = QLabel("")
        fm = self._fiat_bsv_label.fontMetrics()
        width = fm.width("1,000.00 CUR")
        self._fiat_value_label.setMinimumWidth(width)
        hbox.addWidget(self._fiat_value_label)
        self._fiat_widget.setLayout(hbox)
        self.addPermanentWidget(self._fiat_widget)

        network_widget = QWidget()
        network_icon_label = QLabel("")
        network_icon_label.setPixmap(QPixmap(icon_path("sb_network.png")))
        hbox = QHBoxLayout()
        hbox.setSpacing(2)
        hbox.addWidget(network_icon_label)
        self._network_label = QLabel("")
        sp = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        sp.setHorizontalStretch(1)
        self._network_label.setSizePolicy(sp)
        hbox.addWidget(self._network_label)
        network_widget.setLayout(hbox)
        network_widget.setMinimumWidth(150)
        self.addPermanentWidget(network_widget)

        self.search_box = QLineEdit()
        # self.search_box.textChanged.connect(self.do_search)
        self.search_box.hide()
        self.addPermanentWidget(self.search_box)

    def set_balance_status(self, bsv_text: str, fiat_text: Optional[str]) -> None:
        have_fiat_text = bool(fiat_text)

        self._balance_bsv_label.setText(bsv_text)

        self._balance_equals_label.setVisible(have_fiat_text)
        self._balance_fiat_label.setVisible(have_fiat_text)
        self._balance_fiat_label.setText(fiat_text if have_fiat_text else '')

    def set_fiat_status(self, status: Optional[Tuple[str, str]]) -> None:
        # None: Fiat is disabled.
        # (None, None): Fiat is enabled, but no rate information yet.
        if status is None or status[0] is None and status[1] is None:
            self._fiat_widget.setVisible(False)
        else:
            self._fiat_widget.setVisible(True)
            # The first call before we fetch our first rate, will show empty space for status text.
            self._fiat_bsv_label.setText(status[0])
            self._fiat_value_label.setText(status[1])

    def set_network_status(self, text: str) -> None:
        self._network_label.setText(text)
