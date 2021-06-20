# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2019-2020 The ElectrumSV Developers
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


# NOTE: no imports in this file can be 3rd-party.  All MUST be in the base Python system
# libraries.  Also, this file MUST NOT use f-strings.
import os.path as path
import sys

MINIMUM_PYTHON_VERSION = (3, 9, 5)
MINIMUM_SQLITE_VERSION = (3, 35, 4)

vtuple = sys.version_info[:3]
if vtuple < MINIMUM_PYTHON_VERSION:
    fv = lambda parts: '.'.join(str(part) for part in parts)
    sys.exit('error: ElectrumSV requires Python version {} or higher; you are running Python {}'
             .format(fv(MINIMUM_PYTHON_VERSION), fv(vtuple)))

try:
    # Linux expects the latest package version of 3.35.4 (as of pysqlite-binary 0.4.6)
    import pysqlite3 as sqlite3
except ModuleNotFoundError:
    # MacOS has latest brew version of 3.35.5 (as of 2021-06-20).
    # Windows builds use the official Python 3.9.5 builds and bundled version of 3.35.5.
    import sqlite3 # type: ignore


vtuple = sqlite3.sqlite_version_info
if vtuple < MINIMUM_SQLITE_VERSION:
    fv = lambda parts: '.'.join(str(part) for part in parts)
    sys.exit('error: ElectrumSV requires Sqlite version {} or higher; you have Sqlite {}'
             .format(fv(MINIMUM_SQLITE_VERSION), fv(vtuple)))


# True if a pyinstaller binary
is_bundle = getattr(sys, 'frozen', False)
package_dir = path.dirname(path.realpath(__file__))
base_dir, _base_name = path.split(package_dir)
