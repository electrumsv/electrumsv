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

from typing import Set

from .i18n import _

class NotEnoughFunds(Exception):
    pass

class ExcessiveFee(Exception):
    pass

class InvalidPassword(Exception):
    def __str__(self):
        return _("Incorrect password")


class FileImportFailed(Exception):
    def __str__(self):
        return _("Failed to import file.")


class FileImportFailedEncrypted(FileImportFailed):
    def __str__(self):
        return (_('Failed to import file.') + ' ' +
                _('Perhaps it is encrypted...') + '\n' +
                _('Importing encrypted files is not supported.'))


# Throw this exception to unwind the stack like when an error occurs.
# However unlike other exceptions the user won't be informed.
class UserCancelled(Exception):
    '''An exception that is suppressed from the user'''
    pass


class UserQuit(Exception):
    pass


class Bip270Exception(Exception):
    pass

class OverloadedMultisigKeystore(Exception):
    pass

class UnknownTransactionException(Exception):
    pass

class IncompatibleWalletError(Exception):
    pass

class DatabaseMigrationError(Exception):
    pass

class WalletLoadError(Exception):
    pass

class InvalidPayToError(Exception):
    pass

class PreviousTransactionsMissingException(Exception):
    have_tx_hashes: Set[bytes]
    need_tx_hashes: Set[bytes]

    def __init__(self, have_tx_hashes: Set[bytes], need_tx_hashes: Set[bytes]) -> None:
        super().__init__()

        self.have_tx_hashes = have_tx_hashes
        self.need_tx_hashes = need_tx_hashes

    def __str__(self) -> str:
        required_count = len(self.need_tx_hashes)
        return _("Signing this transaction requires {} other transactions " \
            "the coins are being spent from.").format(required_count)

class WaitingTaskCancelled(Exception):
    pass
