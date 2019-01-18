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

from electrumsv.i18n import _
from electrumsv.logs import logs
from electrumsv.util import versiontuple

from .cmdline import CmdLineHandler


class HW_PluginBase(object):
    # Derived classes provide:
    #
    #  class-static variables: client_class, firmware_URL, handler_class,
    #     libraries_available, libraries_URL, minimum_firmware,
    #     wallet_class, ckd_public, types, HidTransport

    def __init__(self, device_kind):
        self.device = self.keystore_class.device
        self.name = device_kind
        self.logger = logs.get_logger(device_kind)

    def create_keystore(self, d):
        keystore = self.keystore_class(d)
        keystore.plugin = self
        # This should be replaced when a window is opened in the gui
        keystore.gui_handler = CmdLineHandler()
        return keystore

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
                    versiontuple(library_version) < self.minimum_library or
                    hasattr(self, "maximum_library") and
                    versiontuple(library_version) >= self.maximum_library):
                raise LibraryFoundButUnusable(library_version=library_version)
        except ImportError:
            return False
        except LibraryFoundButUnusable as e:
            library_version = e.library_version
            max_version_str = (version_str(self.maximum_library)
                               if hasattr(self, "maximum_library") else "inf")
            self.libraries_available_message = (
                    _("Library version for '{}' is incompatible.").format(self.name)
                    + '\nInstalled: {}, Needed: {} <= x < {}'
                    .format(library_version, version_str(self.minimum_library), max_version_str))
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


class LibraryFoundButUnusable(Exception):
    def __init__(self, library_version='unknown'):
        super().__init__()
        self.library_version = library_version



def is_any_tx_output_on_change_branch(tx):
    if not tx.output_info:
        return False
    for o in tx.outputs():
        info = tx.output_info.get(o.address)
        if info is not None:
            if info.address_index[0] == 1:
                return True
    return False
