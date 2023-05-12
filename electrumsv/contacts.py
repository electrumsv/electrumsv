# Electrum - Lightweight Bitcoin Client
# Copyright (c) 2015 Thomas Voegtlin
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

from enum import IntEnum

from .logs import logs


logger = logs.get_logger("contacts")


class IdentityCheckResult(IntEnum):
    Ok = 1
    Invalid = 2
    InUse = 3


class IdentitySystem(IntEnum):
    DirectConnection = 1
    Paymail = 2


IDENTITY_SYSTEM_NAMES = {
    IdentitySystem.DirectConnection: "Direct",
    IdentitySystem.Paymail: "Paymail",
}


class ContactDataError(Exception):
    pass


class ContactNotFoundError(Exception):
    pass


def get_system_id(system_name: str) -> IdentitySystem:
    system_name = system_name.strip().lower()
    for k, v in IDENTITY_SYSTEM_NAMES.items():
        if v.lower() == system_name:
            return k
    raise ContactDataError(f"Unknown system name {system_name}")
