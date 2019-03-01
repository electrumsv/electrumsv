PACKAGE_VERSION = '1.1.2'                          # version of the client package
PACKAGE_DATE = '2019-03-01T16:00:00.000000+13:00'  # official timestamp for client package
PROTOCOL_VERSION = '1.4'                           # protocol version requested

# The hash of the mnemonic seed must begin with this
SEED_PREFIX      = '01'      # Standard wallet


def seed_prefix(seed_type):
    assert seed_type == 'standard'
    return SEED_PREFIX
