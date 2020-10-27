from typing import Optional, Tuple
import weakref

from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QPainter, QPixmap
from PyQt5.QtWidgets import (QGridLayout, QHBoxLayout, QLabel, QSizePolicy, QStatusBar,
    QStyle, QStyleOptionToolButton, QToolButton, QWidget, QWidgetAction)

from electrumsv.app_state import app_state
from electrumsv.i18n import _

from .util import icon_path, read_QIcon


class XToolButton(QToolButton):
    # This class enables the tool button icon to fill the whole button space.
    def __init__(self, parent: QWidget=None) -> None:
        super().__init__(parent)

        self.pad = 2     # padding between the icon and the button frame
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.setSizePolicy(sizePolicy)

    def paintEvent(self, event) -> None:
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
        self.style().drawComplexControl(QStyle.CC_ToolButton, opt, qp, self)
        qp.end()


class NotificationIndicator(XToolButton):
    def __init__(self, main_window: 'ElectrumWindow', parent: QWidget=None) -> None:
        super().__init__(parent)
        self._main_window = weakref.proxy(main_window)

        # Special case icons
        self._notification_urgent_icon = read_QIcon("icons8-topic-32-windows-urgent.png")
        self._notification_many_icon = read_QIcon("icons8-topic-32-windows-plus.png")

        self._notification_default_icon = read_QIcon("icons8-topic-32.png")
        self._notification_indexable_icons = [
            self._notification_default_icon,
        ]
        for i in range(1, 5+1):
            self._notification_indexable_icons.append(
                read_QIcon(f"icons8-topic-32-windows-{i}.png"))

        self.set_notification_state(0)
        self.setMinimumWidth(32)

        self.clicked.connect(self._on_notifications_clicked)

    def set_notification_state(self, how_many: int=0, is_urgent: bool=False) -> None:
        if is_urgent and how_many > 0:
            icon = self._notification_urgent_icon
            text = _("There are urgent unread notifications")
        elif how_many >= len(self._notification_indexable_icons):
            icon = self._notification_many_icon
            text = _("There are many unread notifications")
        else:
            icon = self._notification_indexable_icons[how_many]
            text = _("There are {} unread notifications").format(how_many)

        self.setIcon(icon)
        self.setToolTip(text)

    def _on_notifications_clicked(self) -> None:
        self._main_window.toggle_tab(self._main_window.notifications_tab, True, to_front=True)


class BalancePopup(QWidget):
    def __init__(self, main_window: 'ElectrumWindow', status_bar: 'StatusBar',
            parent: QWidget) -> None:
        super().__init__(parent)

        grid_layout = QGridLayout()
        grid_layout.addWidget(QLabel(_('Confirmed')), 0, 0, 1, 1)
        grid_layout.addWidget(QLabel(_('Unconfirmed')), 1, 0, 1, 1)
        grid_layout.addWidget(QLabel(_('Unmatured')), 2, 0, 1, 1)

        cc = uu = xx = 0
        for account in main_window._wallet.get_accounts():
            c, u, x = account.get_balance()
            cc += c
            uu += u
            xx += x

        balances = (cc, uu, xx)
        for i, balance in enumerate(balances):
            bsv_status, fiat_status = app_state.get_amount_and_units(balance)
            grid_layout.addWidget(QLabel(bsv_status), i, 1, 1, 1, Qt.AlignRight)
            if status_bar._fiat_widget.isVisible():
                grid_layout.addWidget(QLabel(fiat_status), i, 2, 1, 1, Qt.AlignRight)

        self.setLayout(grid_layout)


class BalancePopupAction(QWidgetAction):
    def __init__(self, main_window: 'ElectrumWindow', status_bar: 'StatusBar',
            parent: Optional[QWidget]=None) -> None:
        super().__init__(parent)

        self._status_bar = status_bar
        self._main_window = weakref.proxy(main_window)

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
        self._main_window = weakref.proxy(main_window)

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

        self._notification_default_icon = read_QIcon("icons8-topic-32.png")
        self._notification_urgent_icon = read_QIcon("icons8-topic-32-windows-urgent.png")
        self._notification_many_icon = read_QIcon("icons8-topic-32-windows-plus.png")

        self.notification_widget = NotificationIndicator(main_window)
        self.addPermanentWidget(self.notification_widget)

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
