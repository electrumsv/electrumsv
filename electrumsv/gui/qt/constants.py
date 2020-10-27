from enum import IntEnum

from electrumsv.constants import PaymentFlag
from electrumsv.i18n import _


ICON_NAME_INVOICE_PAYMENT = "seal"


pr_icons = {
    PaymentFlag.UNPAID: "unpaid.png",
    PaymentFlag.PAID: "icons8-checkmark-green-52.png",
    PaymentFlag.EXPIRED: "expired.png"
}

pr_tooltips = {
    PaymentFlag.UNPAID:_('Unpaid'),
    PaymentFlag.PAID:_('Paid'),
    PaymentFlag.EXPIRED:_('Expired'),
    PaymentFlag.UNKNOWN:_('Unknown'),
    PaymentFlag.ARCHIVED:_('Archived'),
}

expiration_values = [
    (_('1 hour'), 60*60),
    (_('1 day'), 24*60*60),
    (_('1 week'), 7*24*60*60),
    (_('Never'), None)
]


class UIBroadcastSource(IntEnum):
    TRANSACTION_DIALOG = 1
    SEND_VIEW_BUTTON = 2
    TRANSACTION_LIST_MENU = 3


# NOTE(rt12): Without this style, there is no padding. With just the item padding and border the
# focus style does this weird thing with the dotted selection showing in the cell with focus, and
# all other cells in that row are blank. Forcing the item and item focus styles to be identical
# except for background color fixes this.

# 'padding-left' or 'padding-right' does not work! Only 'padding'.

CSS_TABLE_CELL_FOCUS_COLOR = "#D3EBFF"
CSS_ALTERNATING_BACKGROUND_COLOR = "#F5F8FA"

CSS_TABLE_VIEW_STYLE = ("""
QListView {
"""
f"  alternate-background-color: {CSS_ALTERNATING_BACKGROUND_COLOR};"
"""
}

QListView:item {
  color: black;
}

QListView:item:selected {
"""
f"  background-color: {CSS_TABLE_CELL_FOCUS_COLOR};"
"""
}

QTableView {
  outline: 0;
"""
f"  alternate-background-color: {CSS_ALTERNATING_BACKGROUND_COLOR};"
"""
}
QTableView:item {
  color: black;
  border: 0px;
}
QTableView::item:focus {
  color: black;
"""
f"  background-color: {CSS_TABLE_CELL_FOCUS_COLOR};"
"""
  border: 0px;
}

QTreeView {
"""
f"  alternate-background-color: {CSS_ALTERNATING_BACKGROUND_COLOR};"
"""
}
QTreeView::item {
  padding: 0px 0px 0px 4px;
}
""")

CSS_STYLES = """
#NotificationCard {
    background-color: white;
    border-bottom: 1px solid #E3E2E2;
}

#NotificationCardImage {
    padding: 4px;
    border: 1px solid #E2E2E2;
}

#NotificationCardTitle {
    font-weight: bold;
    font-size: 14pt;
}

#NotificationCardContext {
    color: grey;
}

#FormSeparatorLine {
    border: 1px solid #E3E2E2;
}
"""

# QTreeView::item {
#   border-top: 0.5px solid lightgray;
#   border-left: 0.5px solid lightgray;
# }
# QTreeView::focus {
#   color: inherit;
#   border-top: 0.5px solid lightgray;
#   border-left: 0.5px solid lightgray;
# }


CSS_WALLET_WINDOW_STYLE = CSS_TABLE_VIEW_STYLE + CSS_STYLES
