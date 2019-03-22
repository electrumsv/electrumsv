import enum

from . import bitcoin
from . import keystore


class SeedWordTypes(enum.IntEnum):
    ELECTRUM_OLD = 1
    ELECTRUM_NEW = 2
    BIP39 = 3


def find_matching_seed_word_types(seed_words):
    matches = []
    if bitcoin.is_old_seed(seed_words):
        matches.append(SeedWordTypes.ELECTRUM_OLD)
    if bitcoin.is_new_seed(seed_words):
        matches.append(SeedWordTypes.ELECTRUM_NEW)

    is_checksum_valid, is_wordlist_valid = keystore.bip39_is_checksum_valid(seed_words)
    if is_checksum_valid and is_wordlist_valid:
        matches.append(SeedWordTypes.BIP39)

    return matches

