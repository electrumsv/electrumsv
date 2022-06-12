from typing import cast, Optional, Tuple, TYPE_CHECKING
import weakref

from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QPainter, QPaintEvent, QPixmap
from PyQt6.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QSizePolicy, QStatusBar,
    QStyle, QStyleOptionToolButton, QToolButton, QWidget, QWidgetAction)

from ...app_state import app_state
from ...i18n import _
from ...wallet_database.types import WalletBalance

from .util import icon_path

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class XToolButton(QToolButton):
    # This class enables the tool button icon to fill the whole button space.
    def __init__(self, parent: Optional[QWidget]=None) -> None:
        super().__init__(parent)

        self.pad = 2     # padding between the icon and the button frame
        sizePolicy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)
        self.setSizePolicy(sizePolicy)

    def paintEvent(self, event: QPaintEvent) -> None:
        qp = QPainter()
        qp.begin(self)

        # Get default style.
        opt = QStyleOptionToolButton()
        self.initStyleOption(opt)
        # Scale icon to button size.
        Rect = opt.rect
        h = Rect.height()
        w = Rect.width()
        iconSize = max(h, w) # - 2 * self.pad
        opt.iconSize = QSize(iconSize, iconSize)
        # Draw
        self.style().drawComplexControl(QStyle.ComplexControl.CC_ToolButton, opt, qp, self)
        qp.end()


class BalancePopup(QWidget):
    def __init__(self, main_window: 'ElectrumWindow', status_bar: 'StatusBar',
            parent: QWidget) -> None:
        super().__init__(parent)

        grid_layout = QGridLayout()
        grid_layout.addWidget(QLabel(_('Confirmed')), 0, 0, 1, 1)
        grid_layout.addWidget(QLabel(_('Unconfirmed')), 1, 0, 1, 1)
        grid_layout.addWidget(QLabel(_('Unmatured')), 2, 0, 1, 1)
        grid_layout.addWidget(QLabel(_('Allocated')), 3, 0, 1, 1)

        wallet_balance = WalletBalance()
        for account in main_window._wallet.get_accounts():
            wallet_balance += account.get_balance()

        for i, balance in enumerate(wallet_balance):
            bsv_status, fiat_status = app_state.get_amount_and_units(balance)
            grid_layout.addWidget(QLabel(bsv_status), i, 1, 1, 1, Qt.AlignmentFlag.AlignRight)
            if status_bar._fiat_widget.isVisible():
                grid_layout.addWidget(QLabel(fiat_status), i, 2, 1, 1, Qt.AlignmentFlag.AlignRight)

        self.setLayout(grid_layout)


class BalancePopupAction(QWidgetAction):
    def __init__(self, main_window: 'ElectrumWindow', status_bar: 'StatusBar',
            parent: QWidget) -> None:
        super().__init__(parent)

        self._status_bar = status_bar
        self._main_window = weakref.proxy(main_window)

    def createWidget(self, parent: QWidget) -> QWidget:
        return BalancePopup(self._main_window, self._status_bar, parent)


class StatusBar(QStatusBar):
    _fiat_bsv_label: QLabel
    _fiat_value_label: QLabel
    _fiat_widget: QWidget

    _network_label: QLabel

    def __init__(self, main_window: 'ElectrumWindow') -> None:
        super().__init__(None)
        self._main_window = weakref.proxy(main_window)

        self._fiat_widget = QWidget()
        self._fiat_widget.setVisible(False)
        estimate_icon_label = QLabel("")
        estimate_icon_label.setPixmap(QPixmap(icon_path("sb_fiat.png")))
        hbox = QHBoxLayout()
        hbox.setSpacing(2)
        hbox.setSizeConstraint(hbox.SizeConstraint.SetFixedSize)
        hbox.addWidget(estimate_icon_label)
        self._fiat_bsv_label = QLabel("")
        hbox.addWidget(self._fiat_bsv_label)
        approximate_icon_label = QLabel("")
        approximate_icon_label.setPixmap(QPixmap(icon_path("sb_approximate")))
        hbox.addWidget(approximate_icon_label)
        self._fiat_value_label = QLabel("")
        fm = self._fiat_bsv_label.fontMetrics()
        width = fm.boundingRect("1,000.00 CUR").width()
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
        sp = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        sp.setHorizontalStretch(1)
        self._network_label.setSizePolicy(sp)
        hbox.addWidget(self._network_label)
        network_widget.setLayout(hbox)
        network_widget.setMinimumWidth(150)
        self.addPermanentWidget(network_widget)

    def set_fiat_status(self, status: Optional[Tuple[Optional[str], Optional[str]]]) -> None:
        # None: Fiat is disabled.
        # (None, None): Fiat is enabled, but no rate information yet.
        if status is None or status[0] is None and status[1] is None:
            self._fiat_widget.setVisible(False)
        else:
            self._fiat_widget.setVisible(True)
            # The first call before we fetch our first rate, will show empty space for status text.
            self._fiat_bsv_label.setText(cast(str, status[0]))
            self._fiat_value_label.setText(cast(str, status[1]))

    def set_network_status(self, text: str, tooltip_text: str="") -> None:
        self._network_label.setText(text)
        self._network_label.setToolTip(tooltip_text)
