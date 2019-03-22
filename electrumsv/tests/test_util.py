import unittest

from electrumsv.util import format_satoshis, get_identified_release_signers
from electrumsv.web import parse_URI, URIError


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

    def _do_test_parse_URI(self, uri, expected):
        result = parse_URI(uri)
        self.assertEqual(expected, result)

    def test_parse_URI_address(self):
        self._do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': ''})

    def test_parse_URI_only_address(self):
        self._do_test_parse_URI('15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
                                {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'})


    def test_parse_URI_address_label(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?label=electrum%20test&sv',
            {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '',
             'label': 'electrum test'})

    def test_parse_URI_address_message(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv&message=electrum%20test',
            {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '',
             'message': 'electrum test', 'memo': 'electrum test'})

    def test_parse_URI_address_amount(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv&amount=0.0003',
            {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '', 'amount': 30000})

    def test_parse_URI_address_request_url(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv&r=http://dom.tld/page?h%3D2a8628fc2fbe',
            {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '',
             'r': 'http://dom.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_ignore_args(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?test=test&sv',
            {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '', 'test': 'test'})

    def test_parse_URI_multiple_args(self):
        self._do_test_parse_URI(
            'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv&amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page',
            {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '', 'amount': 4000,
             'label': 'electrum-test', 'message': u'electrum test', 'memo': u'electrum test',
             'r': 'http://domain.tld/page', 'test': 'none'})

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI('bitcoin:?sv&r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'r': 'http://domain.tld/page?h=2a8628fc2fbe', 'sv': ''})

    def test_parse_URI_invalid_address(self):
        self.assertRaises(URIError, parse_URI,
                          'bitcoin:invalidaddress')

    def test_parse_URI_invalid(self):
        self.assertRaises(URIError, parse_URI,
                          'notbitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')

    def test_parse_URI_parameter_duplication(self):
        self.assertRaises(URIError, parse_URI,
                          'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.0003&'
                          'label=test&amount=30.0')

    def test_fail_bitcoincash(self):
        self.assertRaises(URIError, parse_URI,
            'bitcoincash:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?label=electrum%20test')


def test_get_identified_release_signers():
    entry = {
	"version": "1.2.0",
	"date": "2019-03-20T18:00:00.000000+13:00",
	"signatures": ["IPHe+QklAmNmIdROtaMXt8YSomu9edExbQSg+Rm8Ckc8Mm1iAvb1yYIo1eqhJvndT9b6gaVtgtjzXaNAnfyKa20=","IOpCqrDwQsOjOyMfr4FiHMeY6ekyHZz/qUJ/eas0KWN/XDl9HegERwL7Qcz+jKWg66X+2k9nT3KBvV0OopNpZd8="]
    }

    assert get_identified_release_signers(entry) == {'kyuupichan', 'rt121212121'}

    entry['version'] = "1.2"
    assert not get_identified_release_signers(entry)
