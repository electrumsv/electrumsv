from enum import IntEnum

from ...constants import PaymentFlag
from ...i18n import _


ICON_NAME_INVOICE_PAYMENT = "seal"


pr_icons = {
    PaymentFlag.STATE_UNPAID: "unpaid.png",
    PaymentFlag.STATE_PAID: "icons8-checkmark-green-52.png",
    PaymentFlag.STATE_EXPIRED: "expired.png"
}

pr_tooltips = {
    PaymentFlag.STATE_UNPAID:_('Unpaid'),
    PaymentFlag.STATE_PAID:_('Paid'),
    PaymentFlag.STATE_EXPIRED:_('Expired'),
}


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


class RestorationDialogRole(IntEnum):
    """
    This is the context in which the dialog is invoked.
    """
    # Immediately following account creation.
    ACCOUNT_CREATION      = 1
    # Any time after the initial scan for an existing account of suitable type.
    MANUAL_RESCAN         = 2
