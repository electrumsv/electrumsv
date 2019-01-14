# Electrum SV - lightweight Bitcoin SV client
# Copyright (C) 2019 The Electrum SV Developers
# Copyright (C) 2012 thomasv@gitorious
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

'''Global application state.   Use as follows:

from electrumsv.app_sate import app_state

app_state.config
app_state.daemon
app_state.plugins
app_state.func()

etc.
'''


class AppStateProxy(object):

    def __init__(self, config):
        self.config = config


class _AppStateMeta(type):

    def __getattr__(cls, attr):
        return getattr(cls._proxy, attr)

    def __setattr__(cls, attr, value):
        if attr == '_proxy':
            super().__setattr__(attr, value)
        return setattr(cls._proxy, attr, value)


class AppState(metaclass=_AppStateMeta):

    _proxy = None

    @classmethod
    def set_proxy(cls, proxy):
        cls._proxy = proxy


app_state = AppState
