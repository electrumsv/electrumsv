from __future__ import annotations
from typing import Any, cast, NamedTuple, TYPE_CHECKING
import weakref

from PyQt6.QtCore import QAbstractItemModel, QAbstractProxyModel, QEvent, QModelIndex, QSize, Qt, \
    QSortFilterProxyModel, QObject, pyqtSignal
from PyQt6.QtGui import QAction, QKeyEvent, QPainter, QPaintEvent, QPixmap, QPalette, \
    QStandardItemModel, QStandardItem
from PyQt6.QtWidgets import QAbstractItemView, QComboBox, QCompleter, QDialog, \
    QDialogButtonBox, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton, QSizePolicy, \
    QStyledItemDelegate, QTabWidget, QVBoxLayout, QWidget, QStyleOptionViewItem, QStyle, \
    QStyleOption, QTableView

from ...app_state import get_app_state_qt
from ...contacts import IDENTITY_SYSTEM_NAMES, IdentitySystem
from ...i18n import _
from ...wallet import WalletDataAccess
from ...wallet_database.types import ContactRow

from .util import FormSectionWidget, icon_path, read_QIcon


if TYPE_CHECKING:
    from .main_window import ElectrumWindow


app_state_qt = get_app_state_qt()

class Identity(NamedTuple):
    contact_row: ContactRow
    identity_id: IdentitySystem

# TODO(PyQt6) Payee badges. Clicking on a filtered contact crashes.

# Payment UI:
#   Tab 1: Details
#     TODO: Handle case where there are no contacts.
#     TODO: Receive and handle events.
#       - Fiat currency change (include from nothing and to nothing).
#       - Fiat value change.
#   Tab 2: Confirm
#     TODO: Show recipient.
#     TODO: Show monetary breakdown with fee.
#     TODO: ...
#

# Contact list UI:
# TODO: Contact cards in contact list ui.
#   - Button that opens up a payment dialog to the given contact.
#

# Transaction/contact links:
# TODO: Work out how these need to be stored.
#       - Address used linked to contact identity?
#

payee_badge_css = """
    #PayeeBadgeName, #PayeeBadgeSystem {
        color: white;
        font-weight: 400;
        border-width: 1px;
        border-style: solid;
        padding-left: 4px;
        padding-right: 4px;
        padding-top: 2px;
        padding-bottom: 2px;
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

class PaymentLineEdit(QLineEdit):
    balance_currency: str | None
    balance_amount: str | None


def contact_row_to_identities(contact_row: ContactRow) -> list[Identity]:
    contact_identities: list[Identity] = []
    if contact_row.remote_peer_channel_url is not None:
        contact_identities.append(Identity(contact_row, IdentitySystem.DirectConnection))
    return contact_identities

def read_contacts(wallet_data: WalletDataAccess) -> list[Identity]:
    contact_identities: list[Identity] = []
    for contact_row in wallet_data.read_contacts():
        contact_identities.extend(contact_row_to_identities(contact_row))
    return contact_identities


class DetailFormContext(QObject):
    set_payment_amount = pyqtSignal(object)
    clear_selected_payee = pyqtSignal()

    initial_identity: Identity | None = None

    def __init__(self, wallet_window: ElectrumWindow, payment_window: PaymentWindow) -> None:
        super().__init__(payment_window)

        self.payment_window = payment_window
        self.wallet_window = cast("ElectrumWindow", weakref.proxy(wallet_window))
        self.wallet_data = wallet_window._wallet.data

    def set_initial_identity(self, identity: Identity | None) -> None:
        self.initial_identity = identity

    def get_initial_identity(self) -> Identity | None:
        return self.initial_identity


class PaymentAmountWidget(QWidget):
    def __init__(self, form_context: DetailFormContext, parent: QWidget | None=None) -> None:
        super().__init__(parent)
        self._form_context = form_context

        self.setObjectName("PaymentAmount")

        amount_widget = QLineEdit()

        currency_combo = QComboBox()
        currency_combo.setEditable(True)

        filter_model = QSortFilterProxyModel(currency_combo)
        filter_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        filter_model.setSourceModel(currency_combo.model())

        contact_completer = QCompleter(filter_model, currency_combo)
        contact_completer.setCompletionMode(QCompleter.CompletionMode.UnfilteredPopupCompletion)
        currency_combo.setCompleter(contact_completer)

        # base unit.
        # selected fiat currency.

        options = []
        base_unit = app_state_qt.base_unit()
        options.append(base_unit)
        if app_state_qt.fx is not None and app_state_qt.fx.is_enabled():
            fiat_unit = app_state_qt.fx.get_currency()
            if fiat_unit is not None:
                options.append(fiat_unit)

        currency_combo.addItems(options)
        currency_combo.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

        layout = QHBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(currency_combo)
        layout.addWidget(amount_widget)
        self.setLayout(layout)

        self._currency_combo_options = options
        self._currency_combo = currency_combo
        self._amount_widget = amount_widget
        self._form_context.set_payment_amount.connect(self._set_payment_amount)

    def _set_payment_amount(self, balance_widget: PaymentLineEdit) -> None:
        currency = balance_widget.balance_currency
        amount = balance_widget.balance_amount
        assert currency is not None
        assert amount is not None

        idx = self._currency_combo_options.index(currency)
        self._currency_combo.setCurrentIndex(idx)
        self._amount_widget.setText(amount)


class FundsSelectionWidget(QWidget):
    def __init__(self, form_context: DetailFormContext, parent: QWidget | None=None) -> None:
        super().__init__(parent)
        self._form_context = form_context

        self.setObjectName("FundsSelector")

        balance = 0
        for account in form_context.wallet_window._wallet.get_accounts():
            c, u, x, a = account.get_balance()
            balance += c + u
        sv_text, fiat_text = app_state_qt.get_amount_and_units(balance)

        if fiat_text:
            column_count = 3
        else:
            column_count = 2
        model = QStandardItemModel(1, 3, self)
        model.setItem(0, 0, QStandardItem(_("All available funds")))
        sv_item = QStandardItem(sv_text)
        sv_item.setTextAlignment(
            Qt.AlignmentFlag(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter))
        model.setItem(0, 1, sv_item)
        if fiat_text:
            fiat_item = QStandardItem(fiat_text)
            fiat_item.setTextAlignment(
                Qt.AlignmentFlag(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter))
            model.setItem(0, 2, fiat_item)

        tableView = QTableView(self)
        tableView.setObjectName("FundsSelectionPopup")
        tableView.setWordWrap(False)
        tableView.setModel(model)
        tableView.verticalHeader().setVisible(False)
        tableView.horizontalHeader().setVisible(False)
        tableView.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        tableView.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tableView.setAutoScroll(False)
        tableView.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        # Show more compact rows, this will actually be larger forced out by the contents to be
        # just the necessary size.
        tableView.setRowHeight(0, 20)

        combo = QComboBox()
        combo.setObjectName("FundsSelectorCombo")
        combo.setModel(model)
        combo.setView(tableView)
        combo.setMinimumWidth(300)

        old_showPopup = combo.showPopup

        # Detect when the combobox popup view is shown by rebinding and wrapping the method.
        def _new_showPopup() -> None:
            nonlocal old_showPopup, tableView
            old_showPopup()
            tableView.resizeColumnsToContents()

        setattr(combo, "showPopup", _new_showPopup)

        hlayout1 = QHBoxLayout()
        hlayout1.setSpacing(0)
        hlayout1.setContentsMargins(0, 0, 0, 2)
        hlayout1.addWidget(combo, 1)

        hlayout2 = QHBoxLayout()
        hlayout2.setSpacing(0)
        hlayout2.setContentsMargins(0, 2, 0, 0)
        balance_icon_label = QLabel("")
        balance_icon_label.setPixmap(QPixmap(icon_path("sb_balance.png")))
        balance_icon_label.setToolTip(_("The balance of the selected account."))
        hlayout2.addWidget(balance_icon_label)
        hlayout2.addSpacing(4)
        sv_balance = PaymentLineEdit(sv_text)
        # NOTE(typing) We store attributes on these objects because this is Python..
        base_unit = app_state_qt.base_unit()
        base_amount = app_state_qt.format_amount(balance)
        sv_balance.balance_currency = base_unit
        sv_balance.balance_amount = base_amount
        sv_balance.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        sv_balance.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        sv_balance.setReadOnly(True)
        hlayout2.addWidget(sv_balance)

        fiat_balance: PaymentLineEdit | None = None
        if fiat_text:
            hlayout2.addSpacing(2)
            balance_equals_label = QLabel("")
            balance_equals_label.setPixmap(QPixmap(icon_path("sb_approximate")))
            hlayout2.addWidget(balance_equals_label)
            hlayout2.addSpacing(2)
            if app_state_qt.fx is not None and app_state_qt.fx.is_enabled():
                fiat_unit = app_state_qt.fx.get_currency()
            else:
                fiat_unit = None
            if app_state_qt.fx is not None and app_state_qt.fx.is_enabled():
                fiat_amount = app_state_qt.fx.format_amount(balance)
            else:
                fiat_amount = None
            fiat_balance = PaymentLineEdit(fiat_text)
            # NOTE(typing) We store attributes on these objects because this is Python..
            fiat_balance.balance_currency = fiat_unit
            fiat_balance.balance_amount = fiat_amount

            fiat_balance.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            fiat_balance.setReadOnly(True)
            hlayout2.addWidget(fiat_balance)

        vlayout = QVBoxLayout()
        vlayout.setSpacing(0)
        vlayout.setContentsMargins(0, 0, 0, 0)
        vlayout.addLayout(hlayout1)
        vlayout.addLayout(hlayout2)
        self.setLayout(vlayout)

        self._sv_balance = sv_balance
        self._fiat_balance = fiat_balance

        sv_balance.installEventFilter(self)
        if fiat_balance is not None:
            fiat_balance.installEventFilter(self)

    # QWidget styles do not render. Found this somewhere on the qt5 doc site.
    def paintEvent(self, event: QPaintEvent) -> None:
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PrimitiveElement.PE_Widget, opt, p, self)

    def eventFilter(self, event_object: QObject, event: QEvent) -> bool:
        # Clicking a balance field sets the amount currency and the amount.
        if event_object is self._sv_balance or event_object is self._fiat_balance:
            if self._checkLineEditEvent(event):
                self._form_context.set_payment_amount.emit(event_object)
        return False

    def _checkLineEditEvent(self, event: QEvent) -> bool:
        if event.type() == QEvent.Type.MouseButtonPress:
            return True
        if event.type() == QEvent.Type.KeyPress:
            key_event = cast(QKeyEvent, event)
            return key_event.key() in { Qt.Key.Key_Return, Qt.Key.Key_Space, Qt.Key.Key_Enter }
        return False


class PayeeBadge(QWidget):
    def __init__(self, form_context: DetailFormContext, identity: Identity,
            parent: QWidget | None=None, is_interactive: bool=True) -> None:
        super().__init__(parent)

        self._form_context = form_context
        self.identity = identity

        # A QWidget has no display itself, it cannot be styled, only it's children can.

        self.name_button = name_button = QPushButton(identity[0].contact_name)
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
            clear_action.setShortcut(Qt.Key.Key_Delete)
            clear_action.setShortcutVisibleInContextMenu(True)
            self.clear_action = clear_action
            clear_action.triggered.connect(self._action_clear)

            name_menu = QMenu()
            name_menu.addAction(view_action)
            name_menu.addAction(clear_action)
            name_button.setMenu(name_menu)

        identity_label = IDENTITY_SYSTEM_NAMES[IdentitySystem.DirectConnection]
        self.system_button = system_button = QPushButton(identity_label)
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

    def _action_view(self, checked: bool=False) -> None:
        print("view action triggered")

    def _action_clear(self, checked: bool=False) -> None:
        self._form_context.clear_selected_payee.emit()

    def _on_system_button_clicked(self, checked: bool=False) -> None:
        pass

    def paintEvent(self, event: QPaintEvent) -> None:
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PrimitiveElement.PE_Widget, opt, p, self)


class PayeeSearchModel(QAbstractItemModel):
    def __init__(self, identities: list[Identity]) -> None:
        super().__init__()

        self._identities = identities

    # NOTE(typing) This gets an error based on not matching the base class. However it is the
    #   same signature as the base class.. so no idea.
    def parent(self, model_index: QModelIndex) -> QModelIndex: # type: ignore[override]
        return QModelIndex()

    def rowCount(self, model_index: QModelIndex=QModelIndex()) -> int:
        return len(self._identities)

    def columnCount(self, model_index: QModelIndex=QModelIndex()) -> int:
        return 1

    def index(self, row: int, column: int, parent: QModelIndex=QModelIndex()) -> QModelIndex:
        if self.hasIndex(row, column, parent):
            return self.createIndex(row, column)
        return QModelIndex()

    def data(self, index: QModelIndex, role: int=Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.EditRole:
            if index.isValid():
                return self._identities[index.row()][0].contact_name
            return None
        elif role == Qt.ItemDataRole.DisplayRole:
            if index.isValid():
                return self._identities[index.row()][0].contact_name
            return None
        return None

    def _get_identity(self, row_index: int) -> Identity:
        return self._identities[row_index]


def get_source_index(model_index: QModelIndex) -> QModelIndex:
    model = model_index.model()
    while isinstance(model, QAbstractProxyModel):
        model_index = model.mapToSource(model_index)
        model = model_index.model()
    return model_index


class PayeeBadgeDelegate(QStyledItemDelegate):
    margin_x = 0
    margin_y = 0

    def __init__(self, form_context: DetailFormContext, parent: Any=None) -> None:
        super().__init__(parent)

        self._form_context = form_context

    def paint(self, painter: QPainter, option: QStyleOptionViewItem,
            model_index: QModelIndex) -> None:
        parent = cast(QWidget, self.parent())
        # calculate render anchor point
        point = option.rect.topLeft()
        source_index = get_source_index(model_index)
        model = source_index.model()
        assert isinstance(model, PayeeSearchModel)
        identity = model._get_identity(source_index.row())
        widget = self._create_payee_badge(parent, self._form_context, identity)
        if option.state & QStyle.StateFlag.State_Selected == QStyle.StateFlag.State_Selected:
            p = option.palette # PyQt5: Was Background
            p.setColor(QPalette.ColorRole.Window, p.color(QPalette.ColorGroup.Active,
                QPalette.ColorRole.Highlight))
            widget.setPalette(p)
        # TODO: This appears to render with an unexpected margin at the top.
        widget.render(painter, point)

        dummyWidget = QWidget()
        widget.setParent(dummyWidget)

    def sizeHint(self, option: QStyleOptionViewItem, model_index: QModelIndex) -> QSize:
        # TODO: This appears to calculate an incorrect size.
        # source_index = get_source_index(model_index)
        # payee_search_model = cast(PayeeSearchModel, source_index.model())
        # contact, identity = payee_search_model._get_identity(source_index.row())
        # widget = self._create_payee_badge(self.parent(), self._form_context, contact, identity)
        # size = widget.sizeHint()
        # dummyWidget = QWidget()
        # widget.setParent(dummyWidget)
        return QSize(150, 25)

    def _create_payee_badge(self, parent: QWidget, form_context: DetailFormContext,
            identity: Identity) -> PayeeBadge:
        return PayeeBadge(form_context, identity, parent)


class PayeeSearchWidget(QWidget):
    def __init__(self, form_context: DetailFormContext, parent: QWidget | None=None) -> None:
        super().__init__(parent)

        self._form_context = form_context

        self.setObjectName("PayeeSearchWidget")

        model = PayeeSearchModel(read_contacts(form_context.wallet_data))

        edit_field = QLineEdit()
        edit_field.setMinimumWidth(200)
        edit_field.setPlaceholderText("Type a contact name here..")

        filter_model = QSortFilterProxyModel(edit_field)
        filter_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        filter_model.setSourceModel(model)

        contact_completer = QCompleter(filter_model, edit_field)
        contact_completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        contact_completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        # pylint: disable=unsubscriptable-object
        contact_completer.activated[QModelIndex].connect(self._on_entry_selected)
        edit_field.setCompleter(contact_completer)

        popup = contact_completer.popup()
        # TODO(PyQt6) Method no longer present.
        #popup.setUniformItemSizes(True)
        popup.setItemDelegate(PayeeBadgeDelegate(form_context, edit_field))
        # TODO(PyQt6) Method no longer present.
        #popup.setSpacing(0)
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

        self._form_context.wallet_window.contacts_created_signal.connect(self._on_contacts_event)
        self._form_context.wallet_window.contacts_deleted_signal.connect(self._on_contacts_event)

        self._filter_model = filter_model
        self.focus_widget = edit_field

    def paintEvent(self, event: QPaintEvent) -> None:
        opt = QStyleOption()
        opt.initFrom(self)
        p = QPainter(self)
        self.style().drawPrimitive(QStyle.PrimitiveElement.PE_Widget, opt, p, self)

    def _on_entry_selected(self, model_index: QModelIndex) -> None:
        source_index = get_source_index(model_index)
        payee_search_model = cast(PayeeSearchModel, source_index.model())
        identity = payee_search_model._get_identity(source_index.row())
        payee_widget = cast(PayeeWidget, self.parent())
        payee_widget.set_selected_contact(identity)

    def _on_contacts_event(self, contact_rows: list[ContactRow]) -> None:
        model = PayeeSearchModel(read_contacts(self._form_context.wallet_data))
        self._filter_model.setSourceModel(model)


class PayeeWidget(QWidget):
    MODE_SEARCH = 1
    MODE_SELECTED = 2

    def __init__(self, form_context: DetailFormContext, parent: Any=None) -> None:
        super().__init__(parent)
        self._form_context = form_context

        layout = QHBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(layout)

        self.badge_widget: PayeeBadge | None = None
        self.search_widget: PayeeSearchWidget | None = None

        initial_widget: QWidget
        identity = form_context.get_initial_identity()
        if identity is not None:
            form_context.set_initial_identity(None)

            self.badge_widget = PayeeBadge(self._form_context, identity, self)
            self._mode = self.MODE_SELECTED
            initial_widget = self.badge_widget
        else:
            self.search_widget = PayeeSearchWidget(form_context)
            self._mode = self.MODE_SEARCH
            initial_widget = self.search_widget

        layout.addWidget(initial_widget)

        self._form_context.wallet_window.contacts_deleted_signal.connect(self._on_contacts_deleted)
        self._form_context.clear_selected_payee.connect(self._clear_selected_contact)

    def _on_contacts_deleted(self, contact_rows: list[ContactRow]) -> None:
        # If the selected identity is removed, then clear the contact.
        for contact_row in contact_rows:
            if self.badge_widget is None:
                break

            if contact_row.contact_id == self.badge_widget.identity.contact_row.contact_id:
                for identity in contact_row_to_identities(contact_row):
                    if identity.identity_id == self.badge_widget.identity.identity_id:
                        self._clear_selected_contact()
                        break
                else:
                    self._clear_selected_contact()

    def _clear_selected_contact(self) -> None:
        assert self.badge_widget is not None

        self._mode = self.MODE_SEARCH
        self.search_widget = PayeeSearchWidget(self._form_context, self)

        layout = self.layout()
        layout.addWidget(self.search_widget)
        layout.removeWidget(self.badge_widget)

        # Just removing the old widget from the layout doesn't remove it.
        dummy_widget = QWidget()
        self.badge_widget.setParent(dummy_widget)
        self.badge_widget = None

        # In theory we should be able to set the focus widget (or line edit) as the setFocusProxy()
        # target of the search widget, but it doesn't work.
        self.setTabOrder(self._form_context.payment_window.tabs.tabBar(),
            self.search_widget.focus_widget)

    def set_selected_contact(self, identity: Identity) -> None:
        assert self.search_widget is not None

        self.badge_widget = PayeeBadge(self._form_context, identity, self)
        self._mode = self.MODE_SELECTED

        layout = self.layout()
        layout.addWidget(self.badge_widget)
        layout.removeWidget(self.search_widget)

        # Just removing the old widget from the layout doesn't remove it.
        dummy_widget = QWidget()
        self.search_widget.setParent(dummy_widget)

        self.setTabOrder(self._form_context.payment_window.tabs.tabBar(),
            self.badge_widget.name_button)
        self.setTabOrder(self.badge_widget.name_button, self.badge_widget.system_button)



class PaymentPayeeWidget(FormSectionWidget):
    def __init__(self, form_context: DetailFormContext, parent: QWidget | None=None) -> None:
        super().__init__(parent)

        self.setObjectName("PaymentPayeeWidget")

        widget = PayeeWidget(form_context)

        self.add_title(_("Payee details"))
        self.add_row(_("Pay to"), widget)


class PaymentFundingWidget(FormSectionWidget):
    def __init__(self, form_context: DetailFormContext, parent: QWidget | None=None) -> None:
        super().__init__(parent)
        self._form_context = form_context

        from_widget = FundsSelectionWidget(form_context)
        amount_widget = PaymentAmountWidget(form_context)

        self.add_title(_("Payment details"))
        self.add_row(_("Pay from"), from_widget)
        self.add_row(_("Amount"), amount_widget)


class PaymentNoteWidget(FormSectionWidget):
    def __init__(self, parent: QWidget | None=None) -> None:
        super().__init__(parent)

        yours_widget = QLineEdit()
        theirs_widget = QLineEdit()
        theirs_widget.setEnabled(False)

        self.add_title(_("Payment notes"))
        self.add_row(_("Yours"), yours_widget)
        self.add_row(_("Theirs"), theirs_widget)


class PaymentDetailsFormWidget(QWidget):
    def __init__(self, form_context: DetailFormContext, parent: QWidget | None=None) -> None:
        super().__init__(parent)

        payee_widget = PaymentPayeeWidget(form_context)

        funding_widget = PaymentFundingWidget(form_context)

        note_widget = PaymentNoteWidget()
        self.notes = note_widget

        def _on_next_tab(checked: bool=False) -> None:
            current_index = form_context.payment_window.tabs.currentIndex()
            form_context.payment_window.tabs.setCurrentIndex(current_index+1)

        confirm_button = QPushButton(_("Next >>"))
        confirm_button.setAutoDefault(False)
        confirm_button.clicked.connect(_on_next_tab)
        confirm_button.setEnabled(False)

        confirm_layout = QHBoxLayout()
        confirm_layout.setSpacing(0)
        confirm_layout.setContentsMargins(0, 0, 0, 0)
        confirm_layout.addStretch(1)
        confirm_layout.addWidget(confirm_button)

        vlayout = QVBoxLayout()
        vlayout.addWidget(payee_widget)
        vlayout.addWidget(funding_widget)
        vlayout.addWidget(note_widget)
        vlayout.addLayout(confirm_layout)
        self.setLayout(vlayout)


class ConfirmPaymentFormWidget(QWidget):
    def __init__(self, form_context: DetailFormContext, parent: QWidget | None=None) -> None:
        super().__init__(parent)

        vlayout = QVBoxLayout()
        self.setLayout(vlayout)


class PaymentWindow(QDialog):
    def __init__(self, wallet_window: ElectrumWindow, contact_row: ContactRow | None=None,
            parent: QWidget | None=None):
        super().__init__(parent)

        # RT: As we use this (if we ever do) it should be obvious how we initially populate this.
        identity: Identity | None = None
        if contact_row is not None:
            all_identities = contact_row_to_identities(contact_row)
            if len(all_identities) > 0:
                identity = all_identities[0]

        form_context = DetailFormContext(wallet_window, self)
        form_context.set_initial_identity(identity)

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

        #FormSectionTitle {
        }

        QLineEdit:read-only {
            background-color: #F2F2F2;
        }

        QTableView#FundsSelectionPopup::item {
            padding-left: 4px;
            padding-right: 4px;
        }
        """ + payee_badge_css)

        # green for badge: 4AC41C
        # red for badge: D8634C

        enter_details_widget = PaymentDetailsFormWidget(form_context)
        confirm_details_widget = ConfirmPaymentFormWidget(form_context)

        # Does not look good on MacOS, due to shifted alignment.
        # corner_text = _("Make a payment")
        # corner_widget = QLabel(corner_text)
        # corner_widget.setObjectName("cornerWidget")

        self.form = enter_details_widget

        self.tabs = tabs = QTabWidget()
        # tabs.setCornerWidget(corner_widget)
        details_idx = tabs.addTab(enter_details_widget, _("Details"))
        confirm_idx = tabs.addTab(confirm_details_widget, _("Confirm"))
        tabs.setTabEnabled(confirm_idx, False)

        bbox = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bbox.rejected.connect(self.reject)
        bbox.accepted.connect(self.accept)

        close_button = bbox.button(QDialogButtonBox.StandardButton.Close)
        close_button.setAutoDefault(False)

        vlayout = QVBoxLayout()
        vlayout.addWidget(tabs)
        vlayout.addWidget(bbox)
        self.setLayout(vlayout)

