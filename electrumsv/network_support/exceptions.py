from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .api_server import NewServer


# Exceptions are placed here to simplify the import dependency graph and resolve circular imports

class ServerError(Exception):
    """
    This is a base class for all server-related errors, regardless of the protocol.
    """
    pass


class BadServerError(ServerError):
    """
    This server has sent a blatantly incorrect response. This is not to be confused with an
    unreliable server, that errors remotely or gives any associated status codes.
    """
    pass


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
