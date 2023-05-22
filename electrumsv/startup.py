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
import platform
import sys

# NOTE(rt12) We are monkeypatching in our replacement before anything else is imported ideally.
from electrumsv import ripemd # pylint: disable=unused-import

# - On MacOS we had to upgrade to 3.9.16 for builds to ensure that we include the latest fixes that
#   allow builds made on later versions of MacOS (13.3+) to run on earlier versions (11.1+). Most
#   users should be running a build, so this should only affect those running from source.
# - As development is done on Windows and the last version of Python that the Python lanugage
#   developers provide binary installers for is 3.9.13, we allow this as the minimum version.
MINIMUM_PYTHON_VERSION = (3, 9, 13)
MINIMUM_SQLITE_VERSION = (3, 31, 1)

vtuple = sys.version_info[:3]
if vtuple < MINIMUM_PYTHON_VERSION:
    fv = lambda parts: '.'.join(str(part) for part in parts)
    sys.exit('error: ElectrumSV requires Python version {} or higher; you are running Python {}'
             .format(fv(MINIMUM_PYTHON_VERSION), fv(vtuple)))

if platform.system() == "Linux":
    try:
        # Linux expects the latest package version of 3.31.1 (as of p)
        import pysqlite3 as sqlite3
    except ModuleNotFoundError:
        # MacOS expects the latest brew version of 3.32.1 (as of 2020-07-10).
        # Windows builds use the official Python 3.9.13 builds and version of 3.37.2.
        import sqlite3 # type: ignore
else:
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
packages_dir = path.join(base_dir, 'packages')

# Add 'packages' directory to search path if running from source
if not is_bundle and path.exists(path.join(base_dir, 'electrum-sv.desktop')):
    sys.path.insert(0, packages_dir)
