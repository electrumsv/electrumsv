from enum import IntEnum


class ServerProblemKind(IntEnum):
    BAD_SERVER                      = 1
    CONNECTION_ERROR                = 2
    UNEXPECTED_API_RESPONSE         = 3

