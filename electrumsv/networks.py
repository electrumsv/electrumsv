# ElectrumSV - lightweight Bitcoin SV client
# Copyright (C) 2011 thomasv@gitorious
# Copyright (C) 2017 Neil Booth
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Block explorer requirements:
#
# In order to be included, a block explorer must use real Bitcoin addresses, not an alternate
# system like "cash addresses". In order to avoid user confusion, we wish to avoid showing
# our users confusing weird addressing systems for Bitcoin SV addresses, that belong solely
# being used by dark coins like Bitcoin Cash.

import json

from bitcoinx import CheckPoint, Bitcoin, BitcoinTestnet, BitcoinScalingTestnet

from .util import resource_path

def read_json_dict(filename):
    path = resource_path(filename)
    with open(path, 'r') as f:
        return json.loads(f.read())


class SVMainnet(object):
    ADDRTYPE_P2PKH = 0
    ADDRTYPE_P2SH = 5
    CASHADDR_PREFIX = "bitcoincash"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = read_json_dict('servers.json')
    GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    NAME = 'mainnet'
    URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0x80

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 478559
    BITCOIN_CASH_FORK_BLOCK_HASH = (
        "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"
    )

    COIN = Bitcoin

    # A post-split SV checkpoint.
    CHECKPOINT = CheckPoint(bytes.fromhex(
        '000000201ff55a51c860352808114e52a9b09ae65dd9156a24e75e01000000000000000033320991'
        '190dcb5a86159e56b9ba2da6bca4e515d9dcbab6878471f8fcdf4039cd98425d7dee0518c5322529'
    ), height=593660, prev_work=0xe5eef982b80af19dbeb052)

    VERIFICATION_BLOCK_MERKLE_ROOT = (
        '6acb9cf11127bd497bbebc61fca7d522d985b43be813f8710dca95351e89953e'
    )

    BIP44_COIN_TYPE = 0

    BLOCK_EXPLORERS = {
        'hugeblock.info': (
            'https://hugeblock.info',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'whatsonchain.com': (
            'https://whatsonchain.com',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'blockchair.com' : (
            'https://blockchair.com/bitcoin-sv',
            {'tx': 'transaction', 'addr': 'address'},
        ),
        'satoshi.io': (
            'https://satoshi.io',
            {'tx': 'tx', 'addr': 'address'},
        ),
    }

    FAUCET_URL = "https://faucet.satoshisvision.network"
    KEEPKEY_DISPLAY_COIN_NAME = 'Bitcoin'
    TREZOR_COIN_NAME = 'Bcash'
    # Really we want to put the difficulty logic in this file
    TWENTY_MINUTE_RULE = False


class SVTestnet(object):

    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "bchtest"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = read_json_dict('servers_testnet.json')
    GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    NAME = 'testnet'
    URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0xef

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
    BITCOIN_CASH_FORK_BLOCK_HASH = (
        "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5e"
    )

    COIN = BitcoinTestnet

    # A post-split SV checkpoint.
    CHECKPOINT = CheckPoint(bytes.fromhex(
        '0000002029f1e3df7fda466242b9b56076792ffdb9e5d7ea51610307bc010000000000007ac1fa84'
        'ef5f0998232fb01cd6fea2c0199e34218df2fb33e4e80e79d22b6a746994435d41c4021a208bae0a'
    ), height=1314717, prev_work=0x62ba4d708756160950)

    VERIFICATION_BLOCK_MERKLE_ROOT = (
        '93414acafdef2dad790c456a424a6a261b66771a3426117125d8c13a1c93f10e'
    )

    BIP44_COIN_TYPE = 1

    BLOCK_EXPLORERS = {
        'bitcoincloud.net': (
            'https://testnet.bitcoincloud.net',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'whatsonchain.com': (
            'http://test.whatsonchain.com',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'satoshi.io': (
            'https://test.satoshi.io',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'system default': (
            'blockchain:',
            {'tx': 'tx', 'addr': 'address'},
        ),
    }

    FAUCET_URL = "https://testnet.satoshisvision.network"
    KEEPKEY_DISPLAY_COIN_NAME = 'Testnet'
    # Note: testnet allegedly supported only by unofficial firmware
    TREZOR_COIN_NAME = 'Bcash Testnet'
    # Really we want to put the difficulty logic in this file
    TWENTY_MINUTE_RULE = True


class SVScalingTestnet(object):

    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "bchtest"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = read_json_dict('servers_scalingtestnet.json')
    GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    NAME = 'scalingtestnet'
    URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0xef

    # Bitcoin Cash fork block specification
    # BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
    # BITCOIN_CASH_FORK_BLOCK_HASH = (
    #     "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5e"
    # )

    COIN = BitcoinScalingTestnet

    CHECKPOINT = CheckPoint(bytes.fromhex(
        '00000020e00cb24913995b9db004e06a016e99128c862b6ad075ec259164219e00000000432acae3'
        '6979a88471935a3fb891bf462a017204e834e7eef034c10540e70db47abab45dffff001d117e9185'
    ), height=2500, prev_work=0x6f4cd3b9b05b4)

    VERIFICATION_BLOCK_MERKLE_ROOT = (
        '2a9310d4af21e92d20e6f2aaeabc54d8c0b5d5e74a1278ffcd4c9ba47cffe422'
    )

    # Use the following for a chain reset.
    # CHECKPOINT = CheckPoint(bytes.fromhex(
    #     '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
    #     '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18'
    # ), height=0, prev_work=0)
    # VERIFICATION_BLOCK_MERKLE_ROOT = None

    BIP44_COIN_TYPE = 1

    BLOCK_EXPLORERS = {
        'bitcoinscaling.io': (
            'https://bigblocks.bitcoinscaling.io',
            {'tx': 'transaction', 'addr': 'address'},
        ),
        'whatsonchain.com': (
            'http://stn.whatsonchain.com',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'satoshi.io': (
            'https://stn.satoshi.io',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'system default': (
            'blockchain:',
            {'tx': 'tx', 'addr': 'address'},
        ),
    }

    FAUCET_URL = "https://faucet.bitcoinscaling.io"
    KEEPKEY_DISPLAY_COIN_NAME = 'Testnet'
    # Note: testnet allegedly supported only by unofficial firmware
    TREZOR_COIN_NAME = 'Bcash Testnet'
    # Really we want to put the difficulty logic in this file
    TWENTY_MINUTE_RULE = True


class _CurrentNetMeta(type):

    def __getattr__(cls, attr):
        return getattr(cls._net, attr)


class Net(metaclass=_CurrentNetMeta):
    '''The current selected network.

    Use like so:

        from electrumsv.networks import Net, SVTestnet
        Net.set_to(SVTestnet)
    '''

    _net = SVMainnet

    @classmethod
    def set_to(cls, net_class):
        cls._net = net_class
