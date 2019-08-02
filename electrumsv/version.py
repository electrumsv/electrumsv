PACKAGE_VERSION = '1.2.3'                          # version of the client package
PACKAGE_DATE = '2019-08-02T20:00:00.000000+13:00'  # official timestamp for client package
PROTOCOL_VERSION = '1.4.2'                         # protocol version requested
PROTOCOL_VERSION_MINIMUM = '1.4'                   # do not connect to lower than this

# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet


def seed_prefix(seed_type):
    assert seed_type == 'standard'
    return SEED_PREFIX
