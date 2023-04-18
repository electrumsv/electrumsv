#!/usr/bin/env python2
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import threading
from typing import Any, Dict, TYPE_CHECKING

from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.util import versiontuple

from .cmdline import CmdLineHandler

if TYPE_CHECKING:
    from electrumsv.keystore import KeyStore
    from electrumsv.wallet_database.tables import MasterKeyRow

class HW_PluginBase(object):
    keystore_class: Any
    libraries_available_message: str

    hid_lock = threading.Lock()

    def __init__(self, device_kind) -> None:
        self.device: Any = self.keystore_class.device
        self.name = device_kind
        self.logger = logs.get_logger(device_kind)

    def create_keystore(self, data: Dict[str, Any], row: 'MasterKeyRow') -> 'KeyStore':
        keystore = self.keystore_class(data, row)
        keystore.plugin = self
        # This should be replaced when a window is opened in the gui
        keystore.gui_handler = CmdLineHandler()
        return keystore

    def create_handler(self, window: Any) -> Any:
        raise NotImplementedError

    def is_enabled(self):
        return True

    def get_library_version(self) -> str:
        """Returns the version of the 3rd party python library
        for the hw wallet. For example '0.9.0'

        Returns 'unknown' if library is found but cannot determine version.
        Raises 'ImportError' if library is not found.
        Raises 'LibraryFoundButUnusable' if found but there was a problem (includes version num).
        """
        raise NotImplementedError()

    def check_libraries_available(self) -> bool:
        def version_str(t):
            return ".".join(str(i) for i in t)

        try:
            # this might raise ImportError or LibraryFoundButUnusable
            library_version = self.get_library_version()
            # if no exception so far, we might still raise LibraryFoundButUnusable
            if (library_version == 'unknown' or
                    versiontuple(library_version) < self.minimum_library or  # type: ignore
                    hasattr(self, "maximum_library") and
                    versiontuple(library_version) > self.maximum_library):  # type: ignore
                raise LibraryFoundButUnusable(library_version=library_version)
        except ImportError:
            return False
        except LibraryFoundButUnusable as e:
            library_version = e.library_version
            max_version_str = (version_str(self.maximum_library)  # type: ignore
                               if hasattr(self, "maximum_library") else "inf")
            self.libraries_available_message = (
                    _("Library version for '{}' is incompatible.").format(self.name)
                    + '\nInstalled: {}, Needed: {} <= x < {}'
                    .format(library_version,
                            version_str(self.minimum_library),  # type: ignore
                            max_version_str))  # type: ignore
            self.logger.warning(self.libraries_available_message)
            return False

        return True

    def get_library_not_available_message(self) -> str:
        if hasattr(self, 'libraries_available_message'):
            message = self.libraries_available_message
        else:
            message = _("Missing libraries for {}.").format(self.name)
        message += '\n' + _("Make sure you install it with python3")
        return message

    def enumerate_devices(self):
        raise NotImplementedError


class LibraryFoundButUnusable(Exception):
    def __init__(self, library_version='unknown'):
        super().__init__()
        self.library_version = library_version
