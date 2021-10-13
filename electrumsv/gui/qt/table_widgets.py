from typing import Callable, Optional

from PyQt5.QtCore import pyqtSignal, Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QHBoxLayout, QToolButton, QWidget

from electrumsv.i18n import _

from .util import KeyEventLineEdit, read_QIcon


class ButtonLayout(QHBoxLayout):
    def __init__(self, parent: Optional[QWidget]=None) -> None:
        # NOTE(typing) The checker does not have signatures for the parent being an explicit None.
        super().__init__(parent) # type: ignore

        # The offset to insert the next button at.
        self._button_index = 0

        self.setSpacing(2)
        self.setContentsMargins(0, 2, 0, 2)

    def _create_button(self, icon_name: str, on_click: Callable[[], None], tooltip: str) \
            -> QToolButton:
        button = QToolButton()
        button.setIcon(read_QIcon(icon_name))
        button.setToolTip(tooltip)
        button.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        button.clicked.connect(on_click)
        return button

    def add_button(self, icon_name: str, on_click: Callable[[], None], tooltip: str,
            position: Optional[int]=None) -> QToolButton:
        button = self._create_button(icon_name, on_click, tooltip)
        if position is None:
            position = self._button_index
            self._button_index += 1
        self.insertWidget(position, button)
        return button


class TableTopButtonLayout(ButtonLayout):
    add_signal = pyqtSignal()
    refresh_signal = pyqtSignal()
    filter_signal = pyqtSignal(str)

    def __init__(self, parent: Optional[QWidget]=None, filter_placeholder_text: str="",
            enable_filter: bool=True) -> None:
        super().__init__(parent)

        # The offset to insert the next button at.
        self._button_index = 0

        self._filter_button: Optional[QToolButton] = None
        self._filter_box = KeyEventLineEdit(override_events={Qt.Key.Key_Escape})
        # When the focus is in the search box, if the user presses Escape the filtering exits.
        self._filter_box.key_event_signal.connect(self._on_search_override_key_press_event)
        # As text in the search box changes, the filter updates in real time.
        self._filter_box.textChanged.connect(self._on_search_text_changed)
        if not filter_placeholder_text:
            filter_placeholder_text = _("Your filter text..")
        self._filter_box.setPlaceholderText(filter_placeholder_text)
        self._filter_box.hide()

        self.setSpacing(2)
        self.setContentsMargins(0, 2, 0, 2)
        self.add_refresh_button()
        if enable_filter:
            self._filter_button = self.add_filter_button()
        self.addWidget(self._filter_box, 1)
        self.addStretch(1)

        # Find the stretch QSpacerItem and hold a reference so we can add and remove it.
        # The reason we do this is that otherwise the stretch item prevents the search box from
        # expanding.
        self._stretch_item = self.takeAt(self.count()-1)
        self.addItem(self._stretch_item)

    def add_create_button(self, tooltip: Optional[str]=None) -> QToolButton:
        if tooltip is None:
            tooltip = _("Add a new entry.")
        return self.add_button("icons8-add-new-96-windows.png", self.add_signal.emit, tooltip)

    def add_refresh_button(self, tooltip: Optional[str]=None) -> QToolButton:
        if tooltip is None:
            tooltip = _("Refresh the list.")
        return self.add_button("refresh_win10_16.png", self.refresh_signal.emit, tooltip)

    def add_filter_button(self, tooltip: Optional[str]=None) -> QToolButton:
        if tooltip is None:
            tooltip = _("Toggle list searching/filtering (Control+F).")
        return self.add_button("icons8-filter-edit-32-windows.png", self.on_toggle_filter,
            tooltip)

    def _on_search_text_changed(self, text: str) -> None:
        if self._filter_box.isHidden():
            return
        self.filter_signal.emit(text)

    def _on_search_override_key_press_event(self, event_key: int) -> None:
        if event_key == Qt.Key.Key_Escape:
            self.on_toggle_filter()

    # Call externally to toggle the filter.
    def on_toggle_filter(self) -> None:
        assert self._filter_button is not None
        if self._filter_box.isHidden():
            # Activate filtering and show the text field.
            self._filter_button.setIcon(read_QIcon("icons8-clear-filters-32-windows.png"))
            self._filter_box.show()
            self.removeItem(self._stretch_item)
            self._filter_box.setFocus()
        else:
            self.addItem(self._stretch_item)
            # Deactivate filtering and hide the text field.
            self._filter_button.setIcon(read_QIcon("icons8-filter-edit-32-windows.png"))
            self._filter_box.setText('')
            self._filter_box.hide()
            self.filter_signal.emit('')
