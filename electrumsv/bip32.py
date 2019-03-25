# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2018 The Electrum developers
# Copyright (C) 2019 The ElectrumSV Developers
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

from .bitcoin import EncodeBase58Check
from .networks import Net
from .util import bfh


def xpub_header(*, net=None):
    net = net or Net
    return bfh("%08x" % net.XPUB_HEADERS['standard'])


def serialize_xpub(c, cK, depth=0, fingerprint=b'\x00'*4,
                   child_number=b'\x00'*4, *, net=None):
    xpub = xpub_header(net=net) \
           + bytes([depth]) + fingerprint + child_number + c + cK
    return EncodeBase58Check(xpub)
