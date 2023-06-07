# Mypy requires explicitly exporting 'main'
__all__ = ['main']

# pylint: disable=unused-import
import electrumsv.startup
from electrumsv.platform import platform

try:
    from electrumsv.main import main
except ImportError as e:
    platform.missing_import(e)
