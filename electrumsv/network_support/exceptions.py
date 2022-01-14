# Exceptions are placed here to simplify the import dependency graph and resolve circular imports
class GeneralAPIError(Exception):
    pass

class FilterResponseInvalidError(GeneralAPIError):
    pass

class FilterResponseIncompleteError(GeneralAPIError):
    pass

class TransactionNotFoundError(GeneralAPIError):
    pass

class HeaderNotFoundError(GeneralAPIError):
    pass

class HeaderResponseError(GeneralAPIError):
    pass
