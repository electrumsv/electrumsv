from enum import Enum, IntEnum, IntFlag
from typing import Optional, Sequence, Tuple

from bitcoinx import pack_be_uint32, unpack_be_uint32_from


## Local functions to avoid circular dependencies. This file should be independent

DerivationPath = Tuple[int, ...]

def pack_derivation_path(derivation_path: DerivationPath) -> bytes:
    return b''.join(pack_be_uint32(v) for v in derivation_path)

def unpack_derivation_path(data: bytes) -> DerivationPath:
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
MIGRATION_CURRENT = 29


# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet

TOKEN_PASSWORD = "631a0b30bf8ee0f4e33e915954c8ee8ffac32d77af5e89302a4ee7dd3ecd99da"


# TODO Add an UNRELATED flag? used for external transactions that have been added
#    to the database. I do not believe that we add these transactions at this time, they are
#    instead ephemeral.
class TxFlags(IntFlag):
    UNSET = 0

    # The transaction has been "removed" and is no longer linked to any account.
    REMOVED = 1 << 0

    # The transaction spends conflict with other transactions and it is not linked to any account.
    CONFLICTING = 1 << 7
    EXPOSED = 1 << 8

    # Not currently used.
    INCOMPLETE = 1 << 14

    # TODO(technical-debt) Flatten down these flags to a set of packed values as they are all
    #     separate states of which a transaction can only be one. This should be able to be done
    #     in a database migration.
    # A transaction known to the p2p network which is unconfirmed and in the mempool.
    STATE_CLEARED = 1 << 20
    # A transaction known to the p2p network which is confirmed and known to be in a block.
    STATE_SETTLED = 1 << 21
    # A transaction received from another party which is unknown to the p2p network.
    STATE_RECEIVED = 1 << 22
    # A transaction you have not sent or given to anyone else, but are with-holding and are
    # considering the inputs it uses allocated.
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

    def __repr__(self) -> str:
        return self.to_repr(self.value)

    @staticmethod
    def to_repr(bitmask: Optional[int]) -> str:
        if bitmask is None:
            return repr(bitmask)

        # Handle existing values.
        entry = TxFlags(bitmask)
        if entry.name is not None:
            return f"TxFlags({entry.name})"

        # Handle bit flags. Start with the highest bit, work back.
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


class AccountFlags(IntFlag):
    NONE = 0

    IS_PETTY_CASH = 1 << 0


class MasterKeyFlags(IntFlag):
    NONE = 0

    # The generated seed phrase / master private key for backup.
    WALLET_SEED                         = 1 << 0
    # If we know it is an Electrum seed (which we didn't always track).
    ELECTRUM_SEED                       = 1 << 1
    # If we know it is an BIP39 seed (which we didn't always track).
    BIP39_SEED                          = 1 << 2


class AccountTxFlags(IntFlag):
    NONE = 0

    # This transaction has been replaced by another transaction and is no longer relevant.
    # An example of this is a transaction in a payment channel that is no longer the latest
    # transaction that has the same set of ordered inputs.
    REPLACED = 1 << 10
    # This transaction has been manually removed from the account by the user.
    DELETED = 1 << 11

    # This transaction is part of paying an invoice.
    PAYS_INVOICE = 1 << 30

    # This transaction should be ignored from being included in the account balance.
    IRRELEVANT_MASK = REPLACED | DELETED


class BlockHeight(IntEnum):
    """
    If there is one reason we avoid setting the block height to `NULL` or `None`, it is so we can
    always sort transactions by `block_height` in the database.
    """
    LOCAL = -2
    MEMPOOL_UNCONFIRMED_PARENT = -1
    MEMPOOL = 0
    BLOCK1 = 1


class ScriptType(IntEnum):
    # These names are used as text identifiers in REST results. Consider that if you plan on
    # renaming them.
    NONE = 0
    COINBASE = 1
    P2PKH = 2
    P2PK = 3
    MULTISIG_P2SH = 4
    MULTISIG_BARE = 5
    MULTISIG_ACCUMULATOR = 6
    OP_RETURN = 7

ADDRESSABLE_SCRIPT_TYPES = (ScriptType.P2PKH, ScriptType.MULTISIG_P2SH)


class DatabaseKeyDerivationType(IntEnum):
    # NOTE: We do checks like >= EXTENSION_LINKED in code, use this to determine if the entry
    #   has been sanity checked and is considered authoritative.
    UNKNOWN = 0
    # The user has just created an unpersisted unsigned transaction.
    SIGNING = 1
    # Used for imported incomplete transactions (complete transactions do not embed signing
    # metadata at this time).
    IMPORTED = 2
    # The transaction output using this key exists in the database.
    EXTENSION_LINKED = 3
    # The key usage was found in the database for the input outpoint.
    EXTENSION_UNLINKED = 4
    # Exploration of the derivation paths found this match.
    EXTENSION_EXPLORATION = 5


class DerivationType(IntEnum):
    NONE = 0
    # Old-style electrum seed words.
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


RECEIVING_SUBPATH: DerivationPath = (0,)
RECEIVING_SUBPATH_BYTES = pack_derivation_path(RECEIVING_SUBPATH)
CHANGE_SUBPATH: DerivationPath = (1,)
CHANGE_SUBPATH_BYTES = pack_derivation_path(CHANGE_SUBPATH)

DEFAULT_FEE = 500

WALLET_ACCOUNT_PATH_TEXT: str = "m/50'"


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
    # This key should be loaded and managed appropriately. This flag has supplementary flags
    # like `USER_SET_ACTIVE`.
    ACTIVE = 1 << 0
    # This key has been assigned for some use and should not be reassigned ever. This will mean
    # that if a user assigns it, then deletes whatever thing it was assigned for, it will stay
    # marked as assigned to prevent accidental reuse.
    USED = 1 << 1

    ## These are the secondary flags for `ACTIVE`.
    # The user explicitly set this key to be active. It is not intended that the wallet go and
    # mark it inactive without good reason. The wallet should detect all usage of this key and
    # obtain any transaction seen to be involved with it.
    USER_SET_ACTIVE = 1 << 8

    ## These are the secondary reason flags that may be set in addition to `USED`.
    IS_PAYMENT_REQUEST = 1 << 9
    IS_INVOICE = 1 << 10

    FROZEN = 1 << 15

    MASK_RESERVATION = IS_PAYMENT_REQUEST | IS_INVOICE
    MASK_ACTIVE_REASON = MASK_RESERVATION | USER_SET_ACTIVE


class SubscriptionType(IntEnum):
    NONE = 0
    SCRIPT_HASH = 1
    PUSHDATA_HASH = 2

BYTE_SUBSCRIPTION_TYPES = { SubscriptionType.SCRIPT_HASH, SubscriptionType.PUSHDATA_HASH }


class SubscriptionOwnerPurpose(IntEnum):
    NONE = 0
    SCANNER = 1
    GAP_LIMIT_OBSERVER = 2
    ACTIVE_KEYS = 3


class TransactionImportFlag(IntFlag):
    UNSET = 0
    # The transaction was obtained externally and is being imported into an account.
    EXTERNAL = 1 << 0
    # The user drove the process that caused this transaction to be imported.
    # This is used to decide if we should notify the user about the arrival of this transaction.
    PROMPTED = 1 << 1


class TransactionInputFlag(IntFlag):
    NONE = 0


class TransactionOutputFlag(IntFlag):
    NONE                = 0

    # If the UTXO is in a local or otherwise unconfirmed transaction.
    ALLOCATED           = 1 << 1
    # If the UTXO is in a confirmed transaction.
    SPENT               = 1 << 2
    # If the UTXO is marked as not to be used. It should not be allocated if unallocated, and
    # if allocated then ideally we might extend this to prevent further dispatch in any form.
    FROZEN              = 1 << 3
    COINBASE            = 1 << 4
    COINBASE_IMMATURE   = 1 << 5


class PaymentFlag(IntFlag):
    NONE                = 0
    UNPAID              = 1 << 0
    EXPIRED             = 1 << 1     # deprecated
    UNKNOWN             = 1 << 2     # sent but not propagated
    PAID                = 1 << 3     # send and propagated
    ARCHIVED            = 1 << 4     # unused until we have UI support for filtering

    MASK_STATE = (UNPAID | EXPIRED | PAID | ARCHIVED)
    CLEARED_MASK_STATE = ~MASK_STATE

    NOT_ARCHIVED = ~ARCHIVED


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


class AccountCreationType(IntFlag):
    UNKNOWN = 0

    NEW = 1
    MULTISIG = 2
    IMPORTED = 3
    HARDWARE = 4


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


EMPTY_HASH = b"\0" * 32


class NetworkEventNames:
    HISTORICAL_EXCHANGE_RATES = "on_history"
    EXCHANGE_RATE_QUOTES = "on_quotes"


class NetworkServerType(IntEnum):
    MERCHANT_API = 1
    GENERAL = 2


API_SERVER_TYPES = { NetworkServerType.MERCHANT_API, NetworkServerType.GENERAL }


class ServerCapability(IntEnum):
    TRANSACTION_BROADCAST = 1
    FEE_QUOTE = 2
    MERKLE_PROOF_NOTIFICATION = 3
    HEADERS = 4
    PEER_CHANNELS = 5

    # The following are for the NetworkServerType.GENERAL sub-API for restoration and
    # fetching of arbitrary transactions and merkle proofs
    RESTORATION = 6
    MERKLE_PROOF_REQUEST = 7
    TRANSACTION_REQUEST = 8


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
    AccountType.IMPORTED_ADDRESS: (ScriptType.P2PKH,),
    AccountType.IMPORTED_PRIVATE_KEY: SINGLE_SIGNER_SCRIPT_TYPES,
    AccountType.MULTISIG: MULTI_SIGNER_SCRIPT_TYPES,
    AccountType.STANDARD: SINGLE_SIGNER_SCRIPT_TYPES,
}


class DatabaseWriteErrorCodes(IntEnum):
    TX_ADD_MISSING_KEYS = 1


class NetworkServerFlag(IntFlag):
    NONE = 0
    ANY_ACCOUNT = 1 << 0
    API_KEY_REQUIRED = 1 << 12


class CredentialPolicyFlag(IntFlag):
    NONE = 0
    # Flushing is a backup mechanism and it is expected that the pending use happened and
    # discarded the credential.
    ERROR_IF_FLUSHED = 1 << 1

    # Some standard periods that expire in the short term.
    FLUSH_ALMOST_IMMEDIATELY1 = 1 << 10
    FLUSH_ALMOST_IMMEDIATELY2 = 1 << 11
    FLUSH_ALMOST_IMMEDIATELY3 = 1 << 12
    FLUSH_AFTER_WALLET_LOAD = FLUSH_ALMOST_IMMEDIATELY1

    # Do not cache.
    DISCARD_IMMEDIATELY = 1 << 20
    DISCARD_ON_USE = (1 << 21) | FLUSH_ALMOST_IMMEDIATELY1 | ERROR_IF_FLUSHED

    # Cache flags.
    IS_BEING_ADDED = 1 << 30


# Where the user is spending all the satoshis and not a specific amount.
MAX_VALUE = -1


class PendingHeaderWorkKind(IntEnum):
    # We have a merkle proof for a transaction but no synchronised chain including it.
    MERKLE_PROOF = 1
    # A new header arrived.
    NEW_HEADER = 2

