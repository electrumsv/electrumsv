# NOTE(rt12) We are monkeypatching in our replacement before anything else is imported ideally.
from electrumsv import ripemd # pylint: disable=unused-import

from .app_state import LocalAppStateProxy

# The AppStateProxy subclass is identifed by ElectrumSV as the entrypoint.
