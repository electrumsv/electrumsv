from enum import Enum, IntEnum, IntFlag
from typing import Literal, Sequence

from bitcoinx import pack_be_uint32, unpack_be_uint32_from
from electrumsv_database.sqlite import DATABASE_EXT as SQLITE_DATABASE_EXT


## Local functions to avoid circular dependencies. This file should be independent

DerivationPath = tuple[int, ...]

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

DATABASE_EXT = SQLITE_DATABASE_EXT
MIGRATION_FIRST = 22
MIGRATION_CURRENT = 29

# Electrum Core has reconcepted the version prefix to have an embedded length. The first nibble is
# the number of extra nibbles over the two initial ones in the original seed prefix ("01"). So
# they use "100" for segwit, which is 4*(1+2) bits or three nibbles. The original seed prefix is
# 4*(0+2). If we have a case for additional seed versions we should consider following their
# lead.
#
# The hash of mnemonic seeds used for accounts must begin with this. This is the original Electrum
# Core prefix. As we have migrated from a single account wallet to a multi-account wallet, this is
# analogous to legacy single account wallets.
SEED_PREFIX_ACCOUNT      = "01"      # Pre-1.4.0 standard wallet
# The hash of mnemonic seeds used for 1.4.0 wallet master seeds must begin with this.
SEED_PREFIX_WALLET       = "02"


# TODO Add an UNRELATED flag? used for external transactions that have been added
#    to the database. I do not believe that we add these transactions at this time, they are
#    instead ephemeral.
class TxFlag(IntFlag):
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
    # A transaction known to the p2p network which is confirmed and verified as being in a block.
    STATE_SETTLED = 1 << 21
    # A transaction received from another party which is unknown to the p2p network.
    STATE_RECEIVED = 1 << 22
    # A transaction you have not sent or given to anyone else, but are with-holding and are
    # considering the inputs it uses allocated.
    STATE_SIGNED = 1 << 23
    # A transaction you have given to someone else, and are considering the inputs it uses
    # allocated.
    STATE_DISPATCHED = 1 << 24

    LAST_BIT_USED = 1 << 31

    MASK_STATE = STATE_SETTLED | STATE_DISPATCHED | STATE_RECEIVED | STATE_CLEARED | STATE_SIGNED
    MASK_STATELESS = ~MASK_STATE
    MASK_STATE_LOCAL = STATE_DISPATCHED | STATE_RECEIVED | STATE_SIGNED
    MASK_STATE_BROADCAST = STATE_SETTLED | STATE_CLEARED
    # The transaction is present but not linked to any accounts for these known reasons.
    MASK_UNLINKED = REMOVED | CONFLICTING
    MASK = 0xFFFFFFFF

    def __repr__(self) -> str:
        return self.to_repr(self.value)

    @staticmethod
    def to_repr(bitmask: int | None) -> str:
        if bitmask is None:
            return repr(bitmask)

        # Handle existing values.
        entry = TxFlag(bitmask)
        if entry.name is not None:
            return f"TxFlag({entry.name})"

        # Handle bit flags. Start with the highest bit, work back.
        mask = int(TxFlag.LAST_BIT_USED)
        names = []
        while mask > 0:
            value = bitmask & mask
            if value == mask:
                entry = TxFlag(value)
                if entry.name is not None:
                    names.append(entry.name)
                else:
                    names.append(f"{value:x}")
            mask >>= 1

        return f"TxFlag({'|'.join(names)})"


class AccountFlag(IntFlag):
    NONE = 0

    IS_PETTY_CASH = 1 << 0


class MasterKeyFlag(IntFlag):
    NONE = 0

    # The generated seed phrase / master private key for backup.
    WALLET_SEED                         = 1 << 0
    # If we know it is an Electrum seed (which we didn't always track).
    ELECTRUM_SEED                       = 1 << 1
    # If we know it is an BIP39 seed (which we didn't always track).
    BIP39_SEED                          = 1 << 2


class PaymentFlag(IntFlag):
    NONE                                = 0

    # This payment has been manually removed by the user.
    DELETED                             = 1 << 0

    # This payment and any linked transactions are not to be included for the user by default.
    REMOVED                             = DELETED


class AccountPaymentFlag(IntFlag):
    NONE = 0

    # This account payment needs to have it's cached columns regenerated.
    DIRTY_HISTORY                       = 1 << 0


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

# Should only be used for UI override of fee rate.
DEFAULT_FEE = 100
# NOTE(rt12) Fee rates. At the time of writing regtest MAPI is returning 500 sats/kb.
MAX_FEE = 1000

# The number of satoshis that is the current dust threshold.
# History:
# - The hard-coded Bitcoin SV dust threshold as of Sep 2018 was 546 satoshis.
# - The hard-coded Bitcoin SV dust threshold as of the v1.0.11 node release is 1 satoshi.
DUST_THRESHOLD = 1

WALLET_ACCOUNT_PATH_TEXT: str = "m/50'"
WALLET_IDENTITY_PATH_TEXT: str = "m/51'"


class KeystoreTextType(IntEnum):
    UNRECOGNIZED = 0
    ADDRESSES = 2
    PRIVATE_KEYS = 3
    BIP39_SEED_WORDS = 4
    ELECTRUM_SEED_WORDS = 5
    ELECTRUM_OLD_SEED_WORDS = 6
    EXTENDED_PRIVATE_KEY = 7
    EXTENDED_PUBLIC_KEY = 8

KEYSTORE_TEXT_ALLOW_WATCH_ONLY = (KeystoreTextType.BIP39_SEED_WORDS,
    KeystoreTextType.ELECTRUM_SEED_WORDS, KeystoreTextType.EXTENDED_PRIVATE_KEY)
KEYSTORE_TEXT_FORCE_WATCH_ONLY = KeystoreTextType.ADDRESSES, KeystoreTextType.EXTENDED_PUBLIC_KEY



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
    # Deprecated: The user explicitly set this key to be active. The idea was that the wallet
    # would monitor this key usage as long as the flag was set. However, now we require use
    # of the tip filter and restoration and do not support this.
    USER_SET_ACTIVE = 1 << 8

    ## These are the secondary reason flags that may be set in addition to `USED`.
    # This key was reserved to be given out to external parties to pay in our invoice to them.
    IS_PAYMENT_REQUEST = 1 << 9
    # This key was reserved to pay an invoice received from an external party.
    # TODO(1.4.0) Technical debt. We do not set this flag.
    IS_INVOICE = 1 << 10
    # This is for acquiring a change address via the `getrawchangeaddress` Node API endpoint
    # it will *not* be actively monitored by a blockchain monitoring service
    IS_RAW_CHANGE_ADDRESS = 1 << 11

    FROZEN = 1 << 15

    MASK_RESERVATION = IS_PAYMENT_REQUEST | IS_INVOICE | IS_RAW_CHANGE_ADDRESS
    MASK_ACTIVE_REASON = IS_PAYMENT_REQUEST | IS_INVOICE | USER_SET_ACTIVE


class TxImportFlag(IntFlag):
    UNSET = 0
    # The user drove the process that caused this transaction to be imported.
    # This is used to decide if we should notify the user about the arrival of this transaction.
    PROMPTED                    = 1 << 0
    # The user has explicitly signed this transaction instead of implicitly signing/broadcasting.
    MANUAL_IMPORT               = 1 << 3
    # These transactions are associated with a payment request so attempt closing it post import.
    TIP_FILTER_MATCH            = 1 << 4
    # These transactions were found at the request of the restoration systems.
    RESTORATION_MATCH           = 1 << 5


class TXIFlag(IntFlag):
    NONE = 0


class TXOFlag(IntFlag):
    NONE                = 0

    # If the UTXO is in a local or otherwise unconfirmed transaction.
    ALLOCATED           = 1 << 1
    # If the UTXO is in a confirmed transaction.
    SPENT               = 1 << 2
    # If the UTXO is marked as not to be used. It should not be allocated if unallocated, and
    # if allocated then ideally we might extend this to prevent further dispatch in any form.
    FROZEN              = 1 << 3
    COINBASE            = 1 << 4


class PaymentRequestFlag(IntFlag):
    NONE                        = 0

    # The state of the payment request. These states are atomic and are never combined.
    STATE_UNPAID                = 0b0001     # The payment request is either pending payment or
                                             # has expired (inferred from the expiry date).
    STATE_EXPIRED               = 0b0010     # Deprecated for database storage. This is now only
                                             # used at runtime as an in-memory substitution.
    STATE_PREPARING             = 0b0011     # The payment request is not ready and has not been
                                             # fully created.
    STATE_UNKNOWN               = 0b0100     # Deprecated ????.
    STATE_PAID                  = 0b1000     # We have received transactions that were adequate
                                             # to satisfy this payment request.
    MASK_STATE                  = 0b1111
    CLEARED_MASK_STATE          = 0xFFFFFFFF & ~MASK_STATE

    ARCHIVED                    = 1 << 4     # The user has selected and opted to hide this. Not
                                             # currently used or implemented.
    DELETED                     = 1 << 5     # The application has deleted this and is keeping it
                                             # around in case a user requests support.
    MASK_HIDDEN                 = ARCHIVED | DELETED

    # The type of the payment request. These types are atomic and are never combined.
    TYPE_LEGACY                 = 0b00 << 10
    TYPE_INVOICE                = 0b01 << 10
    TYPE_IMPORTED               = 0b10 << 10
    TYPE_MONITORED              = 0b11 << 10
    MASK_TYPE                   = 0b11 << 10

    # Sub-state of the `INVOICE` type payment requests.
    # There is an expected order of these, see `is_later_dpp_message_sequence`.
    DPP_TERMS_REQUESTED         = 0b00 << 12  # Payee: paymentterms.create -> paymentterms.response
    DPP_PAYMENT_RECEIVED        = 0b01 << 12  # Payee: payment message received
    DPP_TERMS_RECEIVED          = 0b10 << 12  # Payer: paymentrequest.response received
    MASK_DPP_STATE              = 0b11 << 12

    NOT_ARCHIVED                = 0xFFFFFFFF ^ ARCHIVED


# Transaction limits
MAX_MESSAGE_BYTES = 99000

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


class WalletEvent(Enum):
    ACCOUNT_CREATE = "account_created"
    ACCOUNT_RENAME = "on_account_renamed"
    CONTACTS_CREATED = "contacts_created"
    CONTACTS_DELETED = "contacts_deleted"
    CONTACTS_UPDATED = "contacts_updated"
    KEYS_CREATE = "keys_created"
    KEYS_UPDATE = "keys_updated"
    NOTIFICATIONS_CREATE = "notifications_created"
    NOTIFICATIONS_UPDATE = "notifications_updated"
    PAYMENT_REQUEST_PAID = "payment_requests_paid"
    TRANSACTION_ADD = "transaction_added"
    PAYMENT_DELETE = "transaction_deleted"
    TRANSACTION_HEIGHTS_UPDATED = "transaction_heights_updated"
    PAYMENT_LABELS_UPDATE = "payment_labels_updated"
    TRANSACTION_OBTAINED = "missing_transaction_obtained"
    TRANSACTION_STATE_CHANGE = "transaction_state_change"
    TRANSACTION_VERIFIED = "transaction_verified"
    WALLET_SETTING_CHANGE = "on_setting_changed"


class WalletSettings:
    MULTIPLE_CHANGE = 'multiple_change'
    MULTIPLE_ACCOUNTS = 'multiple_accounts'


EMPTY_HASH = b"\0" * 32


class NetworkEventNames(Enum):
    HISTORICAL_EXCHANGE_RATES = "on_history"
    EXCHANGE_RATE_QUOTES = "on_quotes"
    GENERIC_UPDATE = "updated"
    GENERIC_STATUS = "status"
    BANNER = "banner"
    SESSIONS = "sessions"
    MAIN_CHAIN = "main_chain"
    NEW_TIP = "new_tip"


class NetworkServerType(IntEnum):
    MERCHANT_API = 1
    GENERAL = 2                     # ElectrumSV
    DPP_PROXY = 3


API_SERVER_TYPES = { NetworkServerType.MERCHANT_API, NetworkServerType.GENERAL,
    NetworkServerType.DPP_PROXY }


class ServerCapability(IntEnum):
    TRANSACTION_BROADCAST = 1
    FEE_QUOTE = 2
    # The ElectrumX script hash notification API.
    SCRIPTHASH_HISTORY = 3
    MERKLE_PROOF_REQUEST = 4
    MERKLE_PROOF_NOTIFICATION = 5
    # The "General API" restoration sub-API.
    RESTORATION = 6
    TRANSACTION_REQUEST = 7
    HEADERS = 8
    PEER_CHANNELS = 9
    OUTPUT_SPENDS = 10
    TIP_FILTER = 11
    DIRECT_PAYMENT_PROTOCOL = 12


PEER_CHANNEL_EXPIRY_SECONDS = 60 * 60


PREFIX_ASM_SCRIPT = "asm:"
PREFIX_PSBT_BYTES = b"psbt\xff"

ADDRESS_DERIVATION_TYPES = [ DerivationType.PUBLIC_KEY_HASH, DerivationType.SCRIPT_HASH ]

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
    NONE                                            = 0
    # The user edited this and updated the API key manually. We use this as a decision point
    # whether to apply changes from any updated config entry (if the user edited, we do not).
    API_KEY_MANUALLY_UPDATED                        = 1 << 0
    # For a server base row, this means it applies to any account.
    # For an server account row, this means the account row overrides the base row.
    ENABLED                                         = 1 << 1

    # This server was added from the config, not from a user manual addition.
    FROM_CONFIG                                     = 1 << 4
    # Unless a server has been explicitly marked as not supporting API keys, it should.
    API_KEY_SUPPORTED                               = 1 << 5
    # `API_KEY_SUPPORTED` must also be set. To use this server requires an API key.
    API_KEY_REQUIRED                                = 1 << 6

    # The "General API" restoration sub-API.
    CAPABILITY_MERKLE_PROOF_REQUEST                 = 1 << 10
    CAPABILITY_RESTORATION                          = 1 << 11
    CAPABILITY_TRANSACTION_REQUEST                  = 1 << 12
    CAPABILITY_HEADERS                              = 1 << 13
    CAPABILITY_PEER_CHANNELS                        = 1 << 14
    CAPABILITY_OUTPUT_SPENDS                        = 1 << 15
    CAPABILITY_TIP_FILTER                           = 1 << 16
    CAPABILITY_DPP                                  = 1 << 17

    # Used as
    REGISTERED_WITH                                 = 1 << 20
    USE_BLOCKCHAIN                                  = 1 << 21
    USE_MESSAGE_BOX                                 = 1 << 22

    MASK_UTILISATION                                = USE_BLOCKCHAIN | USE_MESSAGE_BOX
    # When a wallet processes the "hard-coded" servers it replaces all flags other than these.
    MASK_RETAINED                                   = REGISTERED_WITH | MASK_UTILISATION


SERVER_USES = { NetworkServerFlag.USE_BLOCKCHAIN, NetworkServerFlag.USE_MESSAGE_BOX }


class CredentialPolicyFlag(IntFlag):
    NONE = 0
    # Flushing is a backup mechanism and it is expected that the pending use happened and
    # discarded the credential.
    ERROR_IF_FLUSHED = 1 << 1

    # Some standard periods that expire in the short term.
    FLUSH_ALMOST_IMMEDIATELY = 1 << 10
    FLUSH_AFTER_WALLET_LOAD = FLUSH_ALMOST_IMMEDIATELY
    FLUSH_AFTER_CUSTOM_DURATION = 1 << 11

    # Do not cache.
    DISCARD_IMMEDIATELY = 1 << 20
    DISCARD_ON_USE = (1 << 21) | FLUSH_ALMOST_IMMEDIATELY | ERROR_IF_FLUSHED

    # Cache flags.
    IS_BEING_ADDED = 1 << 30


# Where the user is spending all the satoshis and not a specific amount.
MAX_VALUE = -1


NO_BLOCK_HASH = bytes(32)


class ChannelFlag(IntFlag):
    NONE                                        = 0
    # This gets set immediately before we create the actual peer channel remotely.
    ALLOCATING                                  = 1 << 0
    DEACTIVATED                                 = 1 << 1

    PURPOSE_TIP_FILTER_DELIVERY                 = 1 << 16
    PURPOSE_CONTACT_CONNECTION                  = 1 << 17
    PURPOSE_BITCACHE                            = 1 << 18
    # NOTE(rt12) This is not persisted and can be dropped when there is
    #     an alternative purpose that can be used in the tests (at this time
    #     there is only the tip filter option).
    PURPOSE_TEST_ALTERNATIVE                    = 1 << 19
    MASK_PURPOSE                                = PURPOSE_TIP_FILTER_DELIVERY | \
        PURPOSE_CONTACT_CONNECTION | PURPOSE_BITCACHE | PURPOSE_TEST_ALTERNATIVE


class ChannelMessageFlag(IntFlag):
    NONE                                        = 0

    UNPROCESSED                                 = 1 << 31


class ChannelAccessTokenFlag(IntFlag):
    NONE                                        = 0

    # This token is for use by this wallet.
    FOR_LOCAL_USAGE                             = 1 << 0
    # This token was given out to a third party for them to use accessing the given channel.
    FOR_THIRD_PARTY_USAGE                       = 1 << 1


class PushDataHashRegistrationFlag(IntFlag):
    NONE                                        = 0
    # This gets set immediately before we register the filter remotely.
    REGISTERING                                 = 1 << 0
    REGISTRATION_FAILED                         = 1 << 1
    DELETED                                     = 1 << 2


class ServerConnectionFlag(IntFlag):
    NONE                                        = 0

    INITIALISED                                 = 1 << 0
    STARTING                                    = 1 << 1
    VERIFYING                                   = 1 << 2
    ESTABLISHING_WEB_SOCKET                     = 1 << 3
    PREPARING_WEB_SOCKET                        = 1 << 4
    OUTPUT_SPENDS_READY                         = 1 << 5
    TIP_FILTER_READY                            = 1 << 6
    WEB_SOCKET_READY                            = 1 << 7
    EXITING                                     = 1 << 8
    EXITED                                      = 1 << 9

    DISCONNECTED                                = 1 << 21

    MASK_EXIT                                   = EXITING | EXITED
    MASK_COMMON_INITIAL                         = INITIALISED | STARTING | DISCONNECTED


class PushDataMatchFlag(IntFlag):
    NONE                                        = 0

    # Remote flags we receive.
    OUTPUT                                      = 1 << 0
    INPUT                                       = 1 << 1


class ChainWorkerToken(IntEnum):
    CONNECT_PROOF_CONSUMER                      = 1
    OBTAIN_PROOF_WORKER                         = 2
    OBTAIN_TRANSACTION_WORKER                   = 3


class ChainManagementKind(IntEnum):
    BLOCKCHAIN_EXTENSION                        = 1
    BLOCKCHAIN_REORGANISATION                   = 2


class MAPIBroadcastFlag(IntFlag):
    NONE                                        = 0
    BROADCAST                                   = 1 << 0
    DELETED                                     = 1 << 1
    RECEIVED_PROOF_CALLBACK                     = 1 << 2



CSS_LABEL_WARNING = """
    QLabel {
        border: 1px solid #FDEEB7;
        color: #826400;
        background-color: #FEFECB;
    }
"""

DaemonSubcommands = ("load_wallet", "service_signup", "start", "status", "stop", \
    "unload_wallet")
DaemonSubcommandLiteral = Literal["load_wallet", "service_signup", "start", "status", "stop", \
    "unload_wallet"]


class DPPMessageType(str, Enum):
    # Note: Python enums order the values in order of definition. The order of these types are
    #     the order we expect them to occur, and we use this in `is_later_dpp_message_sequence`.
    JOIN_SUCCESS        = "join.success"
    REQUEST_CREATE      = "paymentterms.create"
    REQUEST_RESPONSE    = "paymentterms.response"
    REQUEST_ERROR       = "paymentterms.error"
    PAYMENT             = "payment"
    PAYMENT_ACK         = "payment.ack"
    PAYMENT_ERROR       = "payment.error"
    CHANNEL_EXPIRED     = "channel.expired"


class BackupMessageFlag(IntFlag):
    NONE                                        = 0


class BitcacheTxFlag(IntFlag):
    NONE            = 0

    SENT            = 0b001 << 1
    RECEIVED        = 0b010 << 1
    MASK_PROCESSED  = 0b111 << 1

class TokenPermissions(IntFlag):
    NONE            = 0
    READ_ACCESS     = 1 << 1
    WRITE_ACCESS    = 1 << 2
