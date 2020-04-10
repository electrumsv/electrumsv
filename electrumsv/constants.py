# ...
from enum import Enum, IntEnum

## Wallet

# NOTE(rt12) remove when base wizard is removed.
class WalletTypes:
    STANDARD = "standard"
    MULTISIG = "multisig"
    IMPORTED = "imported"

## Wallet storage

class StorageKind(IntEnum):
    UNKNOWN = 0
    FILE = 1
    HYBRID = 2
    DATABASE = 3

## Wallet database

DATABASE_EXT = ".sqlite"
MIGRATION_FIRST = 22
MIGRATION_CURRENT = 22

class TxFlags(IntEnum):
    Unset = 0

    # TxData() packed into Transactions.MetaData:
    HasFee = 1 << 4
    HasHeight = 1 << 5
    HasPosition = 1 << 6
    HasByteData = 1 << 12
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

    METADATA_FIELD_MASK = (HasFee | HasHeight | HasPosition)
    STATE_MASK = (StateSettled | StateDispatched | StateReceived | StateCleared | StateSigned)
    STATE_UNCLEARED_MASK = (StateDispatched | StateReceived | StateSigned)
    STATE_BROADCAST_MASK = (StateSettled | StateCleared)
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


class ScriptType(IntEnum):
    NONE = 0
    COINBASE = 1
    P2PKH = 2
    P2PK = 3
    MULTISIG_P2SH = 4
    MULTISIG_BARE = 5
    MULTISIG_ACCUMULATOR = 6

ADDRESSABLE_SCRIPT_TYPES = (ScriptType.P2PKH, ScriptType.MULTISIG_P2SH)


class DerivationType(IntEnum):
    NONE = 0
    ELECTRUM_OLD = 1
    ELECTRUM_MULTISIG = 2
    BIP32 = 3
    BIP32_SUBPATH = 4
    IMPORTED = 5
    HARDWARE = 6
    PUBLIC_KEY_HASH = 7
    PUBLIC_KEY = 8
    PRIVATE_KEY = 9
    SCRIPT_HASH = 10


RECEIVING_SUBPATH = (0,)
CHANGE_SUBPATH = (1,)

DEFAULT_FEE = 500


class KeystoreTextType(IntEnum):
    UNRECOGNIZED = 0
    ADDRESSES = 2
    PRIVATE_KEYS = 3
    BIP39_SEED_WORDS = 4
    ELECTRUM_SEED_WORDS = 5
    ELECTRUM_OLD_SEED_WORDS = 6
    EXTENDED_PRIVATE_KEY = 7
    EXTENDED_PUBLIC_KEY = 8


class KeyInstanceFlag(IntEnum):
    NONE = 0

    # This key should be loaded and managed appropriately.
    IS_ACTIVE = 1 << 0

    # The user explicitly set this key to be active. It is not intended that the management
    # mark it inactive without good reason.
    USER_SET_ACTIVE = 1 << 8
    IS_PAYMENT_REQUEST = 1 << 9

    # The mask used to load the subset of keys that are actively cached by accounts.
    CACHE_MASK = IS_ACTIVE
    ACTIVE_MASK = IS_ACTIVE | USER_SET_ACTIVE
    ALLOCATED_MASK = IS_PAYMENT_REQUEST


class TransactionOutputFlag(IntEnum):
    NONE = 0

    # If the UTXO is in a local or otherwise unconfirmed transaction.
    IS_ALLOCATED = 1 << 1
    # If the UTXO is in a confirmed transaction.
    IS_SPENT = 1 << 2
    # If the UTXO is marked as not to be used. It should not be allocated if unallocated, and
    # if allocated then ideally we might extend this to prevent further dispatch in any form.
    IS_FROZEN = 1 << 3
    IS_COINBASE = 1 << 4

    USER_SET_FROZEN = 1 << 8

    FROZEN_MASK = IS_FROZEN | USER_SET_FROZEN


class PaymentState(IntEnum):
    UNPAID  = 0
    EXPIRED = 1
    UNKNOWN = 2     # sent but not propagated
    PAID    = 3     # send and propagated

# Transaction limits
MAX_MESSAGE_BYTES = 99000
MAX_INCOMING_ELECTRUMX_MESSAGE_SIZE = 10_000_000

MINIMUM_TXDATA_CACHE_SIZE_MB = 0
DEFAULT_TXDATA_CACHE_SIZE_MB = 32
MAXIMUM_TXDATA_CACHE_SIZE_MB = 2147483647 # Maximum the spinbox widget can handle :-()

DEFAULT_COSIGNER_COUNT = 2
MAXIMUM_COSIGNER_COUNT = 15


class KeystoreType(Enum):
    BIP32 = "bip32"
    HARDWARE = "hardware"
    IMPORTED_PRIVATE_KEY = "impprvkey"
    MULTISIG = "multisig"
    OLD = "old"
    SOFTWARE = "software"
    UNSPECIFIED = "unspecified"


class AccountType(Enum):
    UNSPECIFIED = "unspecified"
    STANDARD = "standard"
    MULTISIG = "multisig"
    IMPORTED_ADDRESS = "impaddress"
    IMPORTED_PRIVATE_KEY = "impprvkey"
