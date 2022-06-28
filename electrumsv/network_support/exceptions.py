from ..exceptions import ServerError

# Exceptions are placed here to simplify the import dependency graph and resolve circular imports

class GeneralAPIError(ServerError):
    """
    This is the base class for all servers that use the protocol that ElectrumSV uses against
    it's reference server.
    """
    pass

class IndexerResponseMissingError(GeneralAPIError):
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

class InvalidStateError(Exception):
    pass

class AuthenticationError(Exception):
    pass
