
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import QWidget

class TabWidget(QWidget):
    menu_action: QAction
    tab_icon: QIcon
    tab_description: str
    tab_pos: int
    tab_name: str
