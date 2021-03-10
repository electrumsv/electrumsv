from enum import Enum, IntEnum
from enum import IntFlag as _IntFlag
from typing import Optional, Sequence

from bitcoinx import pack_be_uint32, unpack_be_uint32_from


## Hacks to deal with standard library bugs.
# https://bugs.python.org/issue41907
class IntFlag(_IntFlag):
    def __format__(self, spec):
        return format(self.value, spec)

## Local functions to avoid circular dependencies. This file should be independent

# Also available as `electrumsv.bitcoin.pack_derivation_path`.
def pack_derivation_path(derivation_path: Sequence[int]) -> bytes:
    return b''.join(pack_be_uint32(v) for v in derivation_path)

# Also available as `electrumsv.bitcoin.unpack_derivation_path`.
def unpack_derivation_path(data: bytes) -> Sequence[int]:
    return tuple(unpack_be_uint32_from(data, i)[0] for i in range(0, len(data), 4))

## Wallet

# NOTE(rt12) remove when base wizard is removed.
class WalletTypes:
    STANDARD = "standard"
    MULTISIG = "multisig"
    IMPORTED = "imported"

## Wallet storage

class StorageKind(IntEnum):
    UNKNOWN = 0
    # Pre-database ElectrumSV, Electron Cash and Electrum Core formats.
    FILE = 1
    # A temporary mid-transition to database format we do not really support.
    HYBRID = 2
    # The current database storage.
    DATABASE = 3

## Wallet database

DATABASE_EXT = ".sqlite"
MIGRATION_FIRST = 22
MIGRATION_CURRENT = 27


# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet


class TxFlags(IntFlag):
    UNSET = 0

    # The transaction has been "removed" and is no longer linked to any account.
    REMOVED = 1 << 0
    # The transaction spends conflict with other transactions and it is not linked to any account.
    CONFLICTING = 1 << 7

    # Complete transactions must always be added with bytedata. We no longer use this flag.
    # There will be incomplete transactions which may allow b'' perhaps, and which should be
    # updateable, but we're not there yet.
    HAS_BYTEDATA = 1 << 12
    # HasProofData = 1 << 13 # Deprecated.
    # Not currently used.
    INCOMPLETE = 1 << 14

    # A transaction received over the p2p network which is unconfirmed and in the mempool.
    STATE_CLEARED = 1 << 20
    # A transaction received over the p2p network which is confirmed and known to be in a block.
    STATE_SETTLED = 1 << 21
    # A transaction received from another party which is unknown to the p2p network.
    STATE_RECEIVED = 1 << 22
    # A transaction you have not sent or given to anyone else, but are with-holding and are
    # considering the inputs it uses allocated. """
    STATE_SIGNED = 1 << 23
    # A transaction you have given to someone else, and are considering the inputs it uses
    # allocated.
    STATE_DISPATCHED = 1 << 24

    PAYS_INVOICE = 1 << 30

    MASK_STATE = (STATE_SETTLED | STATE_DISPATCHED | STATE_RECEIVED | STATE_CLEARED | STATE_SIGNED)
    MASK_STATE_UNCLEARED = (STATE_DISPATCHED | STATE_RECEIVED | STATE_SIGNED)
    MASK_STATE_BROADCAST = (STATE_SETTLED | STATE_CLEARED)
    # The transaction is present but not linked to any accounts for these known reasons.
    MASK_UNLINKED = (REMOVED | CONFLICTING)
    MASK = 0xFFFFFFFF

    def __repr__(self):
        return self.to_repr(self.value)
        # return f"TxFlags({self.name})"

    @staticmethod
    def to_repr(bitmask: Optional[int]) -> str:
        if bitmask is None:
            return repr(bitmask)

        # Handle existing values.
        entry = TxFlags(bitmask)
        if entry.name is not None:
            return f"TxFlags({entry.name})"

        # Handle bit flags.
        mask = int(TxFlags.PAYS_INVOICE)
        names = []
        while mask > 0:
            value = bitmask & mask
            if value == mask:
                entry = TxFlags(value)
                if entry.name is not None:
                    names.append(entry.name)
                else:
                    names.append(f"{value:x}")
            mask >>= 1

        return f"TxFlags({'|'.join(names)})"


class AccountTxFlags(IntFlag):
    NONE = 0

    # This transaction has been replaced by another transaction and is no longer relevant.
    # An example of this is a transaction in a payment channel that is no longer the latest
    # transaction that has the same set of ordered inputs.
    REPLACED = 1 << 10
    # This transaction has been manually removed from the account by the user.
    # TODO(no-merge) Implement?
    DELETED = 1 << 11

    # This transaction is part of paying an invoice.
    PAYS_INVOICE = 1 << 30

    # TODO(no-merge) Ensure this is observed where it should be.
    # This transaction should be ignored from being included in the account balance.
    IRRELEVANT_MASK = REPLACED | DELETED


class ScriptType(IntEnum):
    NONE = 0
    COINBASE = 1
    P2PKH = 2
    P2PK = 3
    MULTISIG_P2SH = 4
    MULTISIG_BARE = 5
    MULTISIG_ACCUMULATOR = 6
    OP_RETURN = 7

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


RECEIVING_SUBPATH: Sequence[int] = (0,)
RECEIVING_SUBPATH_BYTES = pack_derivation_path(RECEIVING_SUBPATH)
CHANGE_SUBPATH: Sequence[int] = (1,)
CHANGE_SUBPATH_BYTES = pack_derivation_path(CHANGE_SUBPATH)

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


class KeyInstanceFlag(IntFlag):
    NONE = 0

    ## These are the two primary flags.
    # This key should be loaded and managed appropriately.
    IS_ACTIVE = 1 << 0
    # This key has been assigned for some use and should not be reassigned ever.
    IS_ASSIGNED = 1 << 1

    ## These are the secondary flags for `IS_ACTIVE`.
    # The user explicitly set this key to be active. It is not intended that the wallet go and
    # mark it inactive without good reason.
    USER_SET_ACTIVE = 1 << 8

    ## These are the secondary reason flags for `IS_ASSIGNED`.
    IS_PAYMENT_REQUEST = 1 << 9
    IS_INVOICE = 1 << 10


class SubscriptionType(IntEnum):
    NONE = 0
    SCRIPT_HASH = 1


class SubscriptionOwnerPurpose(IntEnum):
    NONE = 0
    SCANNER = 1
    GAP_LIMIT_OBSERVER = 2
    ACTIVE_KEYS = 3
    TRANSACTION_STATE = 4


class TransactionInputFlag(IntFlag):
    NONE = 0


class TransactionOutputFlag(IntFlag):
    NONE = 0

    # If the UTXO is in a local or otherwise unconfirmed transaction.
    IS_ALLOCATED = 1 << 1
    # If the UTXO is in a confirmed transaction.
    IS_SPENT = 1 << 2
    # If the UTXO is marked as not to be used. It should not be allocated if unallocated, and
    # if allocated then ideally we might extend this to prevent further dispatch in any form.
    IS_FROZEN = 1 << 3
    IS_COINBASE = 1 << 4

    RESERVED_MASK = IS_FROZEN | IS_ALLOCATED
    # When IS_SPENT is set, these flags are preserved and not cleared.
    SPEND_PRESERVE_MASK = IS_COINBASE


class PaymentFlag(IntFlag):
    NONE =     0
    UNPAID  =  1 << 0
    EXPIRED =  1 << 1     # deprecated
    UNKNOWN =  1 << 2     # sent but not propagated
    PAID    =  1 << 3     # send and propagated
    ARCHIVED = 1 << 4     # unused until we have ui support for filtering

    MASK_STATE = (UNPAID | EXPIRED | PAID | ARCHIVED)
    CLEARED_MASK_STATE = ~MASK_STATE


# Transaction limits
MAX_MESSAGE_BYTES = 99000
# This will be the JSON message, not the final data.
MAX_INCOMING_ELECTRUMX_MESSAGE_MB = 50

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


class WalletEventType(IntEnum):
    # Generate wallet-related events.
    # ... none ...

    # Account-related events
    SEED_BACKUP_REMINDER = 100001


class WalletEventFlag(IntFlag):
    NONE = 0

    # Toggle to indicate that the user has dismissed it.
    UNREAD = 1 << 0
    # Set to indicate that it is an event the user sees in their notifications.
    FEATURED = 1 << 1


class WalletSettings:
    USE_CHANGE = 'use_change'
    MULTIPLE_CHANGE = 'multiple_change'
    MULTIPLE_ACCOUNTS = 'multiple_accounts'
    ADD_SV_OUTPUT = 'sv_output'


class NetworkEventNames:
    HISTORICAL_EXCHANGE_RATES = "on_history"
    EXCHANGE_RATE_QUOTES = "on_quotes"

PREFIX_ASM_SCRIPT = "asm:"

# WARNING(script-types) We currently bake all the possible script hashes for a key into the
#   `KeyInstanceScripts` database table. If you add a script type here, you need to write a
#   database migration that includes that new script type OR resolve this in another way.
# NOTE(script-type-ordering) The script types are ordered in terms of preferred script type that
#   the user should be using for a given form of signer.
MULTI_SIGNER_SCRIPT_TYPES: Sequence[ScriptType] = tuple([
    ScriptType.MULTISIG_BARE,
    ScriptType.MULTISIG_P2SH,
    ScriptType.MULTISIG_ACCUMULATOR,
])
SINGLE_SIGNER_SCRIPT_TYPES: Sequence[ScriptType] = tuple([
    ScriptType.P2PKH,
    ScriptType.P2PK
])

# These script types are possible choices the user could make (or have chosen for them) for which
# script type the user can use for a given account type. Note that imported address accounts have
# an implicit script type depending on the derivation type of the given key, therefore the user
# has no choice. Addresses are a legacy concept.
ACCOUNT_SCRIPT_TYPES = {
    AccountType.IMPORTED_ADDRESS: (),
    AccountType.IMPORTED_PRIVATE_KEY: SINGLE_SIGNER_SCRIPT_TYPES,
    AccountType.MULTISIG: MULTI_SIGNER_SCRIPT_TYPES,
    AccountType.STANDARD: SINGLE_SIGNER_SCRIPT_TYPES,
}


class DatabaseWriteErrorCodes(IntEnum):
    TX_ADD_MISSING_KEYS = 1
