
from electrumsv.constants import PaymentFlag
from electrumsv.i18n import _


pr_icons = {
    PaymentFlag.UNPAID: "unpaid.png",
    PaymentFlag.PAID: "icons8-checkmark-green-52.png",
    PaymentFlag.EXPIRED: "expired.png"
}

pr_tooltips = {
    PaymentFlag.UNPAID:_('Pending'),
    PaymentFlag.PAID:_('Paid'),
    PaymentFlag.EXPIRED:_('Expired')
}

expiration_values = [
    (_('1 hour'), 60*60),
    (_('1 day'), 24*60*60),
    (_('1 week'), 7*24*60*60),
    (_('Never'), None)
]
