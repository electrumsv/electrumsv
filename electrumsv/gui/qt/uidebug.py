from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtWidgets import QWidget

def widget_background_color(widget: QWidget) -> None:
    widget.setAutoFillBackground(True)
    p = QPalette(widget.palette())
    p.setColor(QPalette.Background, QColor("#DD4444"))
    widget.setPalette(p)
