
class DatabaseUpdateError(Exception):
    pass


class KeyInstanceNotFoundError(Exception):
    pass


class TransactionAlreadyExistsError(Exception):
    pass


class TransactionProofAlreadyExistsError(Exception):
    pass


class TransactionRemovalError(Exception):
    pass
