from typing import Optional

from PyQt5.QtCore import (QAbstractItemModel, Qt, QSize, QSortFilterProxyModel, QVariant,
    QModelIndex, QEvent)
from PyQt5.QtGui import QPainter, QPixmap, QPalette
from PyQt5.QtWidgets import (QAction, QComboBox, QCompleter, QDialog, QDialogButtonBox,
    QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton,
    QSizePolicy, QStyledItemDelegate, QTabWidget, QVBoxLayout, QWidget, QLayout,
    QStyleOptionViewItem, QStyle, QStyleOption)

from electrumsv.i18n import _

from .util import icon_path, read_QIcon


payee_badge_css = """
    #PayeeBadgeName, #PayeeBadgeSystem {
        color: white;
        font-weight: 400;
        border-width: 1px;
        border-style: solid;
        padding-left: 4px;
        padding-right: 4px;
    }

    #PayeeBadgeName {
        border: 1px solid #5A5A5A;
        background-color: #5A5A5A;
        border-top-left-radius: 2px;
        border-bottom-left-radius: 2px;
    }

    #PayeeBadgeName::menu-indicator {
        width: 0px;
        image: none;
    }

    #PayeeBadgeSystem {
        border: 1px solid #4AC41C;
        background-color: #4AC41C;
        border-top-right-radius: 2px;
        border-bottom-right-radius: 2px;
    }

    #PayeeBadgeName:focus, #PayeeBadgeSystem:focus {
        border: 1px solid black;
        background-color: white;
        color: black;
    }

    #PayeeBadgeName:hover, #PayeeBadgeSystem:hover {
        border: 1px solid black;
        background-color: grey;
        color: white;
    }
"""


class PaymentAmountWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("PaymentAmount")

        amount_widget = QLineEdit()
        currency_widget = QLineEdit()

        combo = QComboBox()
        combo.setEditable(True)

        filter_model = QSortFilterProxyModel(combo)
        filter_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        filter_model.setSourceModel(combo.model())

        contact_completer = QCompleter(filter_model, combo)
        contact_completer.setCompletionMode(QCompleter.UnfilteredPopupCompletion)
        combo.setCompleter(contact_completer)

        options = [
            "BSV",
            "USD",
        ]

        combo.addItems(options)
        combo.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(amount_widget)
        layout.addWidget(combo)
        self.setLayout(layout)


class FundsSelectionWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("FundsSelector")

        combo = QComboBox()
        combo.setEditable(True)

        filter_model = QSortFilterProxyModel(combo)
        filter_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        filter_model.setSourceModel(combo.model())

        contact_completer = QCompleter(filter_model, combo)
        contact_completer.setCompletionMode(QCompleter.UnfilteredPopupCompletion)
        combo.setCompleter(contact_completer)

        # TODO: Get total available funds and append to the list entry.

        options = [
            "All available funds",
        ]

        combo.addItems(options)

        self.combo = combo

        layout = QHBoxLayout()
        # layout.addWidget(combo)
        self.setLayout(layout)


class PayeeBadge(QWidget):
    def __init__(self, contact, parent=None, is_interactive: bool=True) -> None:
        super().__init__(parent)

        # A QWidget has no display itself, it cannot be styled, only it's children can.

        self.name_button = name_button = QPushButton(contact.label)
        name_button.setObjectName("PayeeBadgeName")
        name_button.setAutoDefault(False)

        if is_interactive:
            view_action = QAction("View", self)
            view_action.setIcon(read_QIcon("icons8-about.svg"))
            view_action.setShortcut("Return")
            view_action.setShortcutVisibleInContextMenu(True)
            self.view_action = view_action
            # view_action.triggered.connect(self._action_view)

            clear_action = QAction("Clear", self)
            clear_action.setIcon(read_QIcon("icons8-delete.svg"))
            clear_action.setShortcut(Qt.Key_Delete)
            clear_action.setShortcutVisibleInContextMenu(True)
            self.clear_action = clear_action
            # clear_action.triggered.connect(self._action_clear)

            name_menu = QMenu()
            name_menu.addAction(view_action)
            name_menu.addAction(clear_action)
            name_button.setMenu(name_menu)

        self.system_button = system_button = QPushButton("ChainPay")
        system_button.setObjectName("PayeeBadgeSystem")
        system_button.setAutoDefault(False)

        if is_interactive:
            system_button.clicked.connect(self._on_system_button_clicked)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(name_button)
        layout.addWidget(system_button)
        self.setLayout(layout)

    def _action_view(self, checked: Optional[bool]=False) -> None:
        print("view action triggered")

    def _action_clear(self, checked: Optional[bool]=False) -> None:
        print("clear action triggered")

    def _on_system_button_clicked(self, checked: Optional[bool]=False) -> None:
        pass

    def paintEvent(self, event):
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PE_Widget, opt, p, self)


class PayeeSearchModel(QAbstractItemModel):
    def __init__(self, contacts, parent=None) -> None:
        super().__init__(parent)

        self._contacts = contacts

    def parent(self, model_index: QModelIndex) -> QModelIndex:
        return QModelIndex()

    def rowCount(self, model_index: QModelIndex) -> int:
        return len(self._contacts)

    def columnCount(self, model_index: QModelIndex) -> int:
        return 1

    def index(self, row: int, column: int, parent: QModelIndex) -> QModelIndex:
        if self.hasIndex(row, column, parent):
            return self.createIndex(row, column)
        return QModelIndex()

    def data(self, index: QModelIndex, role: int) -> QVariant:
        if role == Qt.EditRole:
            if index.isValid():
                return self._contacts[index.row()].label
            return None
        elif role == Qt.DisplayRole:
            if index.isValid():
                return self._contacts[index.row()].label
            return None
        return None

    def _get_contact(self, row_index: int):
        return self._contacts[row_index]


def get_source_index(model_index: QModelIndex):
    while not isinstance(model_index.model(), PayeeSearchModel):
        model_index = model_index.model().mapToSource(model_index)
    return model_index


class PayeeBadgeDelegate(QStyledItemDelegate):
    margin_x = 0
    margin_y = 0

    def paint(self, painter: QPainter, option: QStyleOptionViewItem,
            model_index: QModelIndex) -> None:
        # calculate render anchor point
        point = option.rect.topLeft()

        source_index = get_source_index(model_index)
        contact = source_index.model()._get_contact(source_index.row())
        widget = self._create_payee_badge(self.parent(), contact)
        if option.state & QStyle.State_Selected:
            p = option.palette
            p.setColor(QPalette.Background, p.color(QPalette.Active, QPalette.Highlight))
            widget.setPalette(p)
        # TODO: This appears to render with an unexpected margin at the top.
        widget.render(painter, point)

        dummyWidget = QWidget()
        widget.setParent(dummyWidget)

    def sizeHint(self, option: QStyleOptionViewItem, model_index: QModelIndex):
        # TODO: This appears to calculate an incorrect size.
        # source_index = get_source_index(model_index)
        # contact = source_index.model()._get_contact(source_index.row())
        # widget = self._create_payee_badge(self.parent(), contact)
        # size = widget.sizeHint()
        # dummyWidget = QWidget()
        # widget.setParent(dummyWidget)
        return QSize(150, 25)

    def _create_payee_badge(self, parent, contact):
        badge = PayeeBadge(contact, parent)
        return badge


class PayeeSearchWidget(QWidget):
    def __init__(self, local_api, parent=None) -> None:
        super().__init__(parent)

        self._local_api = local_api

        self.setObjectName("PayeeSearchWidget")

        contacts = local_api.get_contacts()
        self.model = PayeeSearchModel(contacts)

        edit_field = QLineEdit()
        edit_field.setMinimumWidth(200)

        filter_model = QSortFilterProxyModel(edit_field)
        filter_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        filter_model.setSourceModel(self.model)

        contact_completer = QCompleter(filter_model, edit_field)
        contact_completer.setCompletionMode(QCompleter.PopupCompletion)
        contact_completer.setCaseSensitivity(False)
        # pylint: disable=unsubscriptable-object
        contact_completer.activated[QModelIndex].connect(self._on_entry_selected)
        edit_field.setCompleter(contact_completer)

        popup = contact_completer.popup()
        popup.setUniformItemSizes(True)
        popup.setItemDelegate(PayeeBadgeDelegate(edit_field))
        popup.setSpacing(0)
        popup.setStyleSheet("""
            .QListView {
                background-color: #F2F2F2;
                selection-background-color: #D8D8D8;
            }
        """)

        layout = QHBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(edit_field)
        self.setLayout(layout)

    def paintEvent(self, event) -> None:
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PE_Widget, opt, p, self)

    def _on_entry_selected(self, model_index: QModelIndex) -> None:
        source_index = get_source_index(model_index)
        contact = source_index.model()._get_contact(source_index.row())
        self.parent().set_selected_contact(contact)



class PayeeWidget(QWidget):
    MODE_SEARCH = 1
    MODE_SELECTED = 2

    def __init__(self, local_api, parent=None) -> None:
        super().__init__(parent)
        self._local_api = local_api

        self.search_widget = PayeeSearchWidget(local_api)
        self._mode = self.MODE_SEARCH

        layout = QHBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.search_widget)
        self.setLayout(layout)

    def set_selected_contact(self, contact):
        self.badge_widget = PayeeBadge(contact, self)
        self._mode = self.MODE_SELECTED

        layout = self.layout()
        layout.addWidget(self.badge_widget)
        layout.removeWidget(self.search_widget)

        # Just removing the old widget from the layout doesn't remove it.
        dummy_widget = QWidget()
        self.search_widget.setParent(dummy_widget)

        self.setTabOrder(self._local_api.payment_window.tabs.tabBar(),
            self.badge_widget.name_button)
        self.setTabOrder(self.badge_widget.name_button, self.badge_widget.system_button)


class PaymentSectionWidget(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        self.frame_layout = QVBoxLayout()

        frame = QFrame()
        frame.setObjectName("PaymentFrame")
        frame.setLayout(self.frame_layout)

        vlayout = QVBoxLayout()
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.addWidget(frame)
        self.setLayout(vlayout)

    def add_title(self, title_text: str) -> None:
        label = QLabel(title_text +":")
        label.setObjectName("PaymentSectionTitle")
        label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.frame_layout.addWidget(label)

    def add_row(self, label_text: QWidget, field_widget: QWidget,
            stretch_field: bool=False) -> None:
        line = QFrame()
        line.setObjectName("PaymentSeparatorLine")
        line.setFrameShape(QFrame.HLine)
        line.setFixedHeight(1)

        self.frame_layout.addWidget(line)

        label = QLabel(label_text)
        label.setObjectName("PaymentSectionLabel")
        label.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)

        help_label = QLabel()
        help_label.setPixmap(
            QPixmap(icon_path("icons8-help.svg")).scaledToWidth(16, Qt.SmoothTransformation))
        help_label.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Maximum)

        label_layout = QHBoxLayout()
        label_layout.addWidget(label)
        label_layout.addWidget(help_label)
        label_layout.setSizeConstraint(QLayout.SetFixedSize)

        grid_layout = QGridLayout()
        grid_layout.addLayout(label_layout, 0, 0, Qt.AlignLeft)
        if stretch_field:
            grid_layout.addWidget(field_widget, 0, 1)
        else:
            field_layout = QHBoxLayout()
            field_layout.setContentsMargins(0, 0, 0, 0)
            field_layout.addWidget(field_widget)
            field_layout.addStretch(1)
            grid_layout.addLayout(field_layout, 0, 1)
        grid_layout.setColumnMinimumWidth(0, 80)
        grid_layout.setColumnStretch(0, 0)
        grid_layout.setColumnStretch(1, 1)
        grid_layout.setHorizontalSpacing(0)
        grid_layout.setSizeConstraint(QLayout.SetMinimumSize)

        self.frame_layout.addLayout(grid_layout)


class PaymentPayeeWidget(PaymentSectionWidget):
    def __init__(self, local_api, parent=None) -> None:
        super().__init__(parent)

        self.setObjectName("PaymentPayeeWidget")

        widget = PayeeWidget(local_api)

        self.add_title(_("Payee details"))
        self.add_row(_("Pay to"), widget)


class PaymentFundingWidget(PaymentSectionWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        from_widget = FundsSelectionWidget().combo
        amount_widget = PaymentAmountWidget()

        self.add_title(_("Payment details"))
        self.add_row(_("Pay from"), from_widget)
        self.add_row(_("Amount"), amount_widget)


class PaymentNoteWidget(PaymentSectionWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)

        yours_widget = QLineEdit()
        theirs_widget = QLineEdit()

        self.add_title(_("Payment notes"))
        self.add_row(_("Yours"), yours_widget, stretch_field=True)
        self.add_row(_("Theirs"), theirs_widget, stretch_field=True)


class PaymentDetailsFormWidget(QWidget):
    def __init__(self, local_api, parent=None) -> None:
        super().__init__(parent)

        payee_widget = PaymentPayeeWidget(local_api)

        funding_widget = PaymentFundingWidget()

        note_widget = PaymentNoteWidget()
        self.notes = note_widget

        vlayout = QVBoxLayout()
        vlayout.addWidget(payee_widget)
        vlayout.addWidget(funding_widget)
        vlayout.addWidget(note_widget)
        self.setLayout(vlayout)


class PaymentWindow(QDialog):
    def __init__(self, parent=None):
        _local_api = _LocalApi(parent, self)

        super().__init__(parent)

        self.setWindowTitle("Payment")

        self.setStyleSheet("""
        QTabWidget::right-corner {
            position: absolute;
            top: -10px;
        }

        QLabel#cornerWidget {
            font-size: 12pt;
            color: grey;
        }

        #PaymentFrame {
            background-color: #F2F2F2;
            border: 1px solid #E3E2E2;
        }

        #PaymentSectionTitle {
        }

        #PaymentSeparatorLine {
            border: 1px solid #E3E2E2;
        }

        #PaymentSectionLabel {
            color: grey;
        }
        """ + payee_badge_css)

        # green for badge: 4AC41C
        # red for badge: D8634C

        enter_details_widget = PaymentDetailsFormWidget(_local_api)
        enter_details_widget.setContentsMargins(0, 0, 0, 0)

        corner_text = _("Make a payment")
        corner_widget = QLabel(corner_text)
        corner_widget.setObjectName("cornerWidget")

        self.form = enter_details_widget

        self.tabs = tabs = QTabWidget()
        tabs.addTab(enter_details_widget, "Details")
        tabs.setCornerWidget(corner_widget)

        bbox = QDialogButtonBox(QDialogButtonBox.Close)
        bbox.rejected.connect(self.reject)
        bbox.accepted.connect(self.accept)

        close_button = bbox.button(QDialogButtonBox.Close)
        close_button.setAutoDefault(False)

        vlayout = QVBoxLayout()
        vlayout.addWidget(tabs)
        vlayout.addWidget(bbox)
        self.setLayout(vlayout)

        self.installEventFilter(enter_details_widget)

    def eventFilter(self, ob, event):
        if event.type() == QEvent.FocusIn:
            print(f"Fout {ob}")


class _LocalApi(object):
    def __init__(self, wallet_window, payment_window) -> None:
        self.wallet_window = wallet_window
        self.payment_window = payment_window

    def get_contacts(self):
        return list(self.wallet_window.contacts.get_contacts())

