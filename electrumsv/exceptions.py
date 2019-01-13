from .i18n import _

class NotEnoughFunds(Exception): pass

class ExcessiveFee(Exception): pass

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
