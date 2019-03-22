import unittest

from electrumsv import wallet_support


class Test_SeedWordIdentification(unittest.TestCase):
    def test_match_old_electrum_seed_words(self):
        s = 'hardly point goal hallway patience key stone difference ready caught listen fact'
        matches = wallet_support.find_matching_seed_word_types(s)
        self.assertEqual(matches, [wallet_support.SeedWordTypes.ELECTRUM_OLD])

    def test_match_new_electrum_seed_words(self):
        s = 'anxiety earth place surprise thrive catch hungry apology calm vapor camera veteran'
        matches = wallet_support.find_matching_seed_word_types(s)
        self.assertEqual(matches, [wallet_support.SeedWordTypes.ELECTRUM_NEW])

    def test_match_bip39_seed_words(self):
        s = ('gravity machine north sort system female filter attitude volume fold club '+
            'stay feature office ecology stable narrow fog')
        matches = wallet_support.find_matching_seed_word_types(s)
        self.assertEqual(matches, [wallet_support.SeedWordTypes.BIP39])

    def test_match_nothing_for_random_words(self):
        s = 'now is the time for all good men to come to the'
        matches = wallet_support.find_matching_seed_word_types(s)
        self.assertEqual(matches, [])

