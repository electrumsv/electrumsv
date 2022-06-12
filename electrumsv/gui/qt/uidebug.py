from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QWidget

def widget_background_color(widget: QWidget) -> None:
    widget.setAutoFillBackground(True)
    p = QPalette(widget.palette()) # PyQt5: Was Background
    p.setColor(QPalette.ColorRole.Window, QColor("#DD4444"))
    widget.setPalette(p)
