import pytest

from electrumsv.networks import Net, SVMainnet, SVTestnet
from electrumsv.web import create_URI, is_URI, parse_URI, URIError


BIP276_TEXT = ("bitcoin-script:0102006b6376a91435b0bdd2e9d50cbcd08ba55ae3e8c6fc0bc2ee0888ad6c8b6"
    "b686376a914e80cfb6db2de0542842228416f0a6873536468e388ad6c8b6b68526ca278e8a1b0")
BIP276_URI = ("bitcoin-script:0102006b6376a91435b0bdd2e9d50cbcd08ba55ae3e8c6fc0bc2ee0888"
    "ad6c8b6b686376a914e80cfb6db2de0542842228416f0a6873536468e388ad6c8b6b68526ca278e8a1b0?amo"
    "unt=0.12112121&message=the%20money%20i%20owe%20you")
BIP276_DATA = (b'\x00kcv\xa9\x145\xb0\xbd\xd2\xe9\xd5\x0c\xbc\xd0\x8b\xa5Z\xe3\xe8'
    b'\xc6\xfc\x0b\xc2\xee\x08\x88\xadl\x8bkhcv\xa9\x14\xe8\x0c\xfbm'
    b'\xb2\xde\x05B\x84"(Ao\nhsSdh\xe3\x88\xadl\x8bkhRl\xa2')

def test_create_uri_bip276() -> None:
    amount = 12112121
    message = "the money i owe you"
    assert BIP276_URI == create_URI(BIP276_TEXT, amount, message)

def test_is_uri_bip276() -> None:
    assert is_URI(BIP276_URI)

def test_parse_uri_bip276() -> None:
    Net.set_to(SVTestnet)
    try:
        d = parse_URI(BIP276_URI)
    finally:
        Net.set_to(SVMainnet)

    expected_message = "the money i owe you"
    assert d == {
        "bip276": BIP276_TEXT,
        "script": BIP276_DATA,
        "amount": 12112121,
        "message": expected_message,
        "memo": expected_message,
    }



def _do_test_parse_URI(uri, expected):
    result = parse_URI(uri)
    assert expected == result

def test_parse_URI_address():
    _do_test_parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv',
                            {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': ''})

def test_parse_URI_only_address():
    _do_test_parse_URI('15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma',
                            {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma'})

def test_parse_URI_address_label():
    _do_test_parse_URI(
        'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?label=electrum%20test&sv',
        {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '',
            'label': 'electrum test'})

def test_parse_URI_address_message():
    _do_test_parse_URI(
        'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv&message=electrum%20test',
        {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '',
            'message': 'electrum test', 'memo': 'electrum test'})

def test_parse_URI_address_amount():
    _do_test_parse_URI(
        'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv&amount=0.0003',
        {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '', 'amount': 30000})

def test_parse_URI_address_request_url():
    _do_test_parse_URI(
        'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv&r=http://dom.tld/page?h%3D2a8628fc2fbe',
        {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '',
            'r': 'http://dom.tld/page?h=2a8628fc2fbe'})

def test_parse_URI_ignore_args():
    _do_test_parse_URI(
        'bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?test=test&sv',
        {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '', 'test': 'test'})

def test_parse_URI_multiple_args():
    _do_test_parse_URI(
        ('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?sv&amount=0.00004&label=electrum-test&'
        'message=electrum%20test&test=none&r=http://domain.tld/page'),
        {'address': '15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma', 'sv': '', 'amount': 4000,
            'label': 'electrum-test', 'message': u'electrum test', 'memo': u'electrum test',
            'r': 'http://domain.tld/page', 'test': 'none'})

def test_parse_URI_no_address_request_url():
    _do_test_parse_URI('bitcoin:?sv&r=http://domain.tld/page?h%3D2a8628fc2fbe',
                            {'r': 'http://domain.tld/page?h=2a8628fc2fbe', 'sv': ''})

def test_parse_URI_invalid_address():
    with pytest.raises(URIError):
        parse_URI('bitcoin:invalidaddress')

def test_parse_URI_invalid():
    with pytest.raises(URIError):
        parse_URI('notbitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma')

def test_parse_URI_parameter_duplication():
    with pytest.raises(URIError):
        parse_URI('bitcoin:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?amount=0.0003&'
            'label=test&amount=30.0')

def test_fail_bitcoincash():
    with pytest.raises(URIError):
        parse_URI('bitcoincash:15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma?label=electrum%20test')

