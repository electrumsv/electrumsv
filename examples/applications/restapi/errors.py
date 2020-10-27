from electrumsv.constants import MAX_MESSAGE_BYTES


class Errors:
    # http 400 bad requests
    GENERIC_BAD_REQUEST_CODE = 40000
    URL_INVALID_NETWORK_CODE = 40001
    URL_NETWORK_MISMATCH_CODE = 40002
    JSON_DECODE_ERROR_CODE = 40003
    LOAD_BEFORE_GET_CODE = 40004
    EMPTY_REQUEST_BODY_CODE = 40005
    INSUFFICIENT_COINS_CODE = 40006
    DATA_TOO_BIG_CODE = 40007
    BAD_WALLET_NAME_CODE = 40008
    WALLET_NOT_LOADED_CODE = 40009
    ALREADY_SENT_TRANSACTION_CODE = 40010
    AIORPCX_ERROR_CODE = 40011
    BROADCAST_FAILURE_CODE = 40012
    CHAIN_TOO_LONG_CODE = 40013
    SPLIT_FAILED_CODE = 40014
    DISABLED_FEATURE_CODE = 40015

    # http 401 unauthorized
    AUTH_CREDENTIALS_MISSING_CODE = 40102
    AUTH_UNSUPPORTED_TYPE_CODE = 40103

    # http 402 - 402xx series
    # http 403 - 403xx series
    AUTH_CREDENTIALS_INVALID_CODE = 40301

    # http 404 not found
    WALLET_NOT_FOUND_CODE = 40401
    TRANSACTION_NOT_FOUND_CODE = 40404

    # http 500 internal server error
    GENERIC_INTERNAL_SERVER_ERROR = 50000

    AUTH_CREDENTIALS_INVALID_MESSAGE = "Authentication failed (bad credentials)."
    AUTH_CREDENTIALS_MISSING_MESSAGE = "Authentication failed (missing credentials)."
    AUTH_UNSUPPORTED_TYPE_MESSAGE = "Authentication failed (only basic auth is supported)."
    URL_INVALID_NETWORK_MESSAGE = "Only {} networks are supported. You entered: '{}' network."
    URL_NETWORK_MISMATCH_MESSAGE = "Wallet is on '{}' network. You requested: '{}' network."
    WALLET_NOT_FOUND_MESSAGE = "Wallet: '{}' does not exist."
    LOAD_BEFORE_GET_MESSAGE = "Must load wallet (POST request to " \
                              "http://127.0.0.1:9999/v1/{}/wallets/{}" \
                              "/load_wallet)"
    EMPTY_REQUEST_BODY_MESSAGE = "Request body was empty"
    HEADER_VAR_NOT_PROVIDED_MESSAGE = "Required header variable: '{}' was not provided."
    BODY_VAR_NOT_PROVIDED_MESSAGE = "Required body variable: '{}' was not provided."
    DATA_TOO_BIG_MESSAGE = "Message is too large (>%s bytes))." % MAX_MESSAGE_BYTES
    BAD_WALLET_NAME_MESSAGE = "Wallet name invalid."
    WALLET_NOT_LOADED_MESSAGE = "Wallet was unable to be loaded (bad password?)"
    INSUFFICIENT_COINS_MESSAGE = "You have insufficient coins for this transaction"
    TRANSACTION_NOT_FOUND_MESSAGE = "Transaction not found"
    SPLIT_FAILED_MESSAGE = "Split failed (not necessary? not possible?)"
    DISABLED_FEATURE_MESSAGE = "DisabledFeatureError: You used this endpoint in a way that is " \
                               "not supported for safety reasons. See documentation for details (" \
                               "https://electrumsv.readthedocs.io/ )"
