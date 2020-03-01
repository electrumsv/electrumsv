import unittest

from electrumsv.util import format_satoshis, get_identified_release_signers


class TestUtil(unittest.TestCase):
    def test_format_satoshis(self):
        result = format_satoshis(1234)
        expected = "0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_zero(self):
        result = format_satoshis(0)
        expected = "0."
        self.assertEqual(expected, result)

    def test_format_satoshis_negative(self):
        result = format_satoshis(-1234)
        expected = "-0.00001234"
        self.assertEqual(expected, result)

    def test_format_fee(self):
        result = format_satoshis(1700/1000, 0, 0)
        expected = "1.7"
        self.assertEqual(expected, result)

    def test_format_fee_precision(self):
        result = format_satoshis(1666/1000, 0, 0, precision=6)
        expected = "1.666"
        self.assertEqual(expected, result)

        result = format_satoshis(1666/1000, 0, 0, precision=1)
        expected = "1.7"
        self.assertEqual(expected, result)

    def test_format_satoshis_whitespaces(self):
        result = format_satoshis(12340, whitespaces=True)
        expected = "     0.0001234 "
        self.assertEqual(expected, result)

        result = format_satoshis(1234, whitespaces=True)
        expected = "     0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_whitespaces_negative(self):
        result = format_satoshis(-12340, whitespaces=True)
        expected = "    -0.0001234 "
        self.assertEqual(expected, result)

        result = format_satoshis(-1234, whitespaces=True)
        expected = "    -0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_positive(self):
        result = format_satoshis(1234, is_diff=True)
        expected = "+0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_negative(self):
        result = format_satoshis(-1234, is_diff=True)
        expected = "-0.00001234"
        self.assertEqual(expected, result)


def test_get_identified_release_signers():
    entry = {
	"version": "1.2.0",
	"date": "2019-03-20T18:00:00.000000+13:00",
	"signatures": [
    "IPHe+QklAmNmIdROtaMXt8YSomu9edExbQSg+Rm8Ckc8Mm1iAvb1yYIo1eqhJvndT9b6gaVtgtjzXaNAnfyKa20=",
    "IOpCqrDwQsOjOyMfr4FiHMeY6ekyHZz/qUJ/eas0KWN/XDl9HegERwL7Qcz+jKWg66X+2k9nT3KBvV0OopNpZd8="
    ]
    }

    assert get_identified_release_signers(entry) == {'kyuupichan', 'rt121212121'}

    entry['version'] = "1.2"
    assert not get_identified_release_signers(entry)
