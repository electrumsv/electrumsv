from PyQt5.QtGui import QPalette, QColor

def widget_background_color(widget):
    widget.setAutoFillBackground(True)
    p = QPalette(widget.palette())
    p.setColor(QPalette.Background, QColor("#DD4444"))
    widget.setPalette(p)
