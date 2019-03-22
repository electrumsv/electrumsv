import unittest

from electrumsv import wallet_support


TI_MINIKEY = 'SzavMBLoXU6kDrqtUVmffv'
SW_ESV_OLD = 'hardly point goal hallway patience key stone difference ready caught listen fact'
SW_ESV_NEW = 'anxiety earth place surprise thrive catch hungry apology calm vapor camera veteran'
SW_BIP39 = ('gravity machine north sort system female filter attitude volume fold club '+
            'stay feature office ecology stable narrow fog')
SW_NOTHING = 'now is the time for all good men to come to the'


class Test_SeedWordIdentification(unittest.TestCase):
    def test_match_old_electrum_seed_words(self):
        matches = wallet_support.find_matching_seed_word_types(SW_ESV_OLD)
        self.assertEqual(matches, {wallet_support.SeedWordTypes.ELECTRUM_OLD})

    def test_match_new_electrum_seed_words(self):
        matches = wallet_support.find_matching_seed_word_types(SW_ESV_NEW)
        self.assertEqual(matches, {wallet_support.SeedWordTypes.ELECTRUM_NEW})

    def test_match_bip39_seed_words(self):
        matches = wallet_support.find_matching_seed_word_types(SW_BIP39)
        self.assertEqual(matches, {wallet_support.SeedWordTypes.BIP39})

    def test_match_nothing_for_random_words(self):
        matches = wallet_support.find_matching_seed_word_types(SW_NOTHING)
        self.assertEqual(matches, set({}))


class Test_TextImportIdentification(unittest.TestCase):
    def test_match_minikey(self):
        matches = wallet_support.find_matching_text_import_types(TI_MINIKEY)
        self.assertEqual(matches, {wallet_support.TextImportTypes.PRIVATE_KEY_MINIKEY})

    def test_match_seed_word_types(self):
        for text in (SW_ESV_OLD, SW_ESV_NEW, SW_BIP39):
            matches = wallet_support.find_matching_text_import_types(text)
            self.assertEqual(matches, {wallet_support.TextImportTypes.PRIVATE_KEY_SEED})

    def test_match_nothing(self):
        matches = wallet_support.find_matching_text_import_types(SW_NOTHING)
        self.assertEqual(matches, set([]))

