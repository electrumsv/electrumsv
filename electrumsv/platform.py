# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019 The Electrum SV Developers
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

'''Platform-specific customization for ElectrumSV'''

import logging
import platform
import sys

from electrumsv.i18n import _


logger = logging.getLogger("platform")


class Platform(object):

    module_map = {
        'PyQt5': 'PyQt5',
        'SimpleWebSocketServer': 'SimpleWebSocketServer',
        'dns': 'dnspython',
        'ecdsa': 'ecdsa',
        'jsonrpclib': 'jsonrpclib-pelix',
        'protobuf': 'protobuf',
        'pyaes': 'pyaes',
        'qrcode': 'qrcode',
        'requests': 'requests',
        'socks': 'PySocks',
    }
    monospace_font = 'monospace'
    name = 'unset platform'

    def missing_import(self, exception):
        module = exception.name
        for m, package in self.module_map.items():
            # because submodule could be imported instead
            if module.startswith(m):
                sys.exit(_('cannot import module "{0}" - try running "pip3 install {1}"'
                           .format(module, package)))
        raise exception from None


class Darwin(Platform):
    monospace_font = 'Monaco'
    name = 'MacOSX'


class Linux(Platform):
    name = 'Linux'


class Unix(Platform):
    name = 'Unix'


class Windows(Platform):
    monospace_font = 'Lucida Console'
    name = 'Windows'


def _detect():
    system = platform.system()
    if system == 'Darwin':
        cls = Darwin
    elif system == 'Linux':
        cls = Linux
    elif system == 'Windows':
        cls = Windows
    elif system in ('FreeBSD', 'NetBSD', 'OpenBSD', 'DragonFly'):
        cls = Unix
    else:
        logger.warning(_('unknown system "{}"; falling back to Unix.  Please report this.')
                       .format(system))
        cls = Unix
    logging.debug(f'using platform class {cls.__name__} for system "{system}"')
    return cls()


platform = _detect()
