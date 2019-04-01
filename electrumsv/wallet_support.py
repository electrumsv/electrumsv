import enum

from bitcoinx import is_minikey

from . import bitcoin
from . import keystore


class SeedWordTypes(enum.IntEnum):
    ELECTRUM_OLD = 1
    ELECTRUM_NEW = 2
    BIP39 = 3


class TextImportTypes(enum.IntEnum):
    PRIVATE_KEY_SEED = 10
    PRIVATE_KEY_MINIKEY = 11



def find_matching_seed_word_types(seed_words):
    matches = set([])
    if bitcoin.is_old_seed(seed_words):
        matches.add(SeedWordTypes.ELECTRUM_OLD)
    if bitcoin.is_new_seed(seed_words):
        matches.add(SeedWordTypes.ELECTRUM_NEW)

    is_checksum_valid, is_wordlist_valid = keystore.bip39_is_checksum_valid(seed_words)
    if is_checksum_valid and is_wordlist_valid:
        matches.add(SeedWordTypes.BIP39)

    return matches


def find_matching_text_import_types(text):
    matches = set([])
    seed_word_matches = find_matching_seed_word_types(text)
    if len(seed_word_matches):
        matches.add(TextImportTypes.PRIVATE_KEY_SEED)
    if is_minikey(text):
        matches.add(TextImportTypes.PRIVATE_KEY_MINIKEY)
    return matches
