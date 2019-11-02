# ...
from enum import IntEnum


## Wallet

class WalletTypes:
    STANDARD = "standard"
    MULTISIG = "multisig"
    IMPORTED = "imported"

class ParentWalletKinds:
    MULTI_ACCOUNT = "electrumsv/multi-account"
    LEGACY = "electrum/legacy"

## Wallet storage

class StorageKind(IntEnum):
    UNKNOWN = 0
    FILE = 1
    HYBRID = 2
    DATABASE = 3

## Wallet database

DATABASE_EXT = ".sqlite"

class TxFlags(IntEnum):
    Unset = 0

    # TxData() packed into Transactions.MetaData:
    HasFee = 1 << 4
    HasHeight = 1 << 5
    HasPosition = 1 << 6
    HasTimestamp = 1 << 7

    # TODO: Evaluate whether maintaining these is more effort than it's worth.
    # Reflects Transactions.ByteData contains a value:
    HasByteData = 1 << 12
    # Reflects Transactions.ProofData contains a value:
    HasProofData = 1 << 13

    # A transaction received over the p2p network which is unconfirmed and in the mempool.
    StateCleared = 1 << 20
    # A transaction received over the p2p network which is confirmed and known to be in a block.
    StateSettled = 1 << 21
    # A transaction received from another party which is unknown to the p2p network.
    StateReceived = 1 << 22
    # A transaction you have not sent or given to anyone else, but are with-holding and are
    # considering the inputs it uses frozen. """
    StateSigned = 1 << 23
    # A transaction you have given to someone else, and are considering the inputs it uses frozen.
    StateDispatched = 1 << 24

    METADATA_FIELD_MASK = (HasFee | HasHeight | HasPosition | HasTimestamp)
    STATE_MASK = (StateSettled | StateDispatched | StateReceived | StateCleared | StateSigned)
    MASK = 0xFFFFFFFF

    def __repr__(self):
        return f"TxFlags({self.name})"

    @staticmethod
    def to_repr(bitmask: int):
        if bitmask is None:
            return repr(bitmask)

        # Handle existing values.
        try:
            return f"TxFlags({TxFlags(bitmask).name})"
        except ValueError:
            pass

        # Handle bit flags.
        mask = int(TxFlags.StateDispatched)
        names = []
        while mask > 0:
            value = bitmask & mask
            if value == mask:
                try:
                    names.append(TxFlags(value).name)
                except ValueError:
                    pass
            mask >>= 1

        return f"TxFlags({'|'.join(names)})"


# All these states can only be set if there is transaction data present.
TRANSACTION_FLAGS = (TxFlags.StateSettled, TxFlags.StateDispatched, TxFlags.StateReceived,
    TxFlags.StateCleared, TxFlags.StateSigned)

