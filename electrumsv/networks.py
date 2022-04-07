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
from typing import Any, Dict, Optional, Tuple, Type, Union

from bitcoinx import CheckPoint, Bitcoin, BitcoinTestnet, BitcoinScalingTestnet, \
    BitcoinRegtest

from .util import resource_path

BLOCK_HEIGHT_OUT_OF_RANGE_ERROR = -8


class NetworkName:
    MAINNET = 'mainnet'
    REGTEST = 'regtest'
    TESTNET = 'testnet'
    SCALING_TESTNET = 'scalingtestnet'

TEST_NETWORK_NAMES = { NetworkName.REGTEST, NetworkName.TESTNET, NetworkName.SCALING_TESTNET }


def read_json_dict(filename: str) -> Any:
    path = resource_path(filename)
    with open(path, 'r') as f:
        return json.loads(f.read())


class SVMainnet(object):
    ADDRTYPE_P2PKH = 0
    ADDRTYPE_P2SH = 5
    CASHADDR_PREFIX = "bitcoincash"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS_API = read_json_dict('api_servers.json')
    GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    NAME = NetworkName.MAINNET
    BITCOIN_URI_PREFIX = "bitcoin"
    PAY_URI_PREFIX = "pay"
    WIF_PREFIX = 0x80
    BIP276_VERSION = 1

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 478559
    BITCOIN_CASH_FORK_BLOCK_HASH = (
        "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"
    )

    COIN = Bitcoin

    # A post-split SV checkpoint.
    CHECKPOINT = CheckPoint(bytes.fromhex(
        '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
        '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c'
    ), height=0, prev_work=0)
    VERIFICATION_BLOCK_MERKLE_ROOT: Optional[str] = None

    BIP44_COIN_TYPE = 0

    BLOCK_EXPLORERS = {
        'whatsonchain.com': (
            'https://whatsonchain.com',
            {'tx': 'tx', 'addr': 'address', 'script': 'script'},
        ),
        'blockchair.com' : (
            'https://blockchair.com/bitcoin-sv',
            {'tx': 'transaction', 'addr': 'address'},
        ),
        'satoshi.io': (
            'https://satoshi.io',
            {'tx': 'tx', 'addr': 'address', 'script': 'script'},
        ),
    }

    FAUCET_URL = "https://faucet.satoshisvision.network"
    KEEPKEY_DISPLAY_COIN_NAME: str = 'Bitcoin'
    TREZOR_COIN_NAME: str = 'Bcash'
    # Really we want to put the difficulty logic in this file
    TWENTY_MINUTE_RULE = False


class SVTestnet(object):

    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "bchtest"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS_API = read_json_dict('api_servers_testnet.json')
    GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    NAME = NetworkName.TESTNET
    BITCOIN_URI_PREFIX = "bitcoin"
    PAY_URI_PREFIX = "pay"
    WIF_PREFIX = 0xef
    BIP276_VERSION = 2

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
    BITCOIN_CASH_FORK_BLOCK_HASH = (
        "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5e"
    )

    COIN = BitcoinTestnet

    # A post-split SV checkpoint.
    CHECKPOINT = CheckPoint(bytes.fromhex(
        '00000020b9ea0b497adc73aff2e3d2c3663db12bdf4f8d612d3317e76700000000000000b1e1eda1'
        '767dc2e6fdb63e82d570461da2daa2f4fd9fe375ebce93f5b180a6f5ae7e285faef5021a7f406d4d'
    ), height=1377549, prev_work=0xade538ee77b27b019d)

    VERIFICATION_BLOCK_MERKLE_ROOT: Optional[str] = (
        'c2ca8aef7a20779fc9b7cc00af6b9b65f7ff99ae68fe22132c448d15de0d5943'
    )

    BIP44_COIN_TYPE = 1

    BLOCK_EXPLORERS = {
        'bitcoincloud.net': (
            'https://testnet.bitcoincloud.net',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'whatsonchain.com': (
            'http://test.whatsonchain.com',
            {'tx': 'tx', 'addr': 'address', 'script': 'script'},
        ),
        'satoshi.io': (
            'https://testnet.satoshi.io',
            {'tx': 'tx', 'addr': 'address', 'script': 'script'},
        ),
        'system default': (
            'blockchain:',
            {'tx': 'tx', 'addr': 'address'},
        ),
    }

    FAUCET_URL = "https://testnet.satoshisvision.network"
    KEEPKEY_DISPLAY_COIN_NAME = 'Testnet'
    # Note: testnet allegedly supported only by unofficial firmware
    TREZOR_COIN_NAME: str = 'Bcash Testnet'
    # Really we want to put the difficulty logic in this file
    TWENTY_MINUTE_RULE = True


class SVScalingTestnet(object):

    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "bchtest"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS_API = read_json_dict('api_servers_scalingtestnet.json')
    GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    NAME = NetworkName.SCALING_TESTNET
    BITCOIN_URI_PREFIX = "bitcoin"
    PAY_URI_PREFIX = "pay"
    WIF_PREFIX = 0xef
    BIP276_VERSION = 3

    # Bitcoin Cash fork block specification
    # BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
    # BITCOIN_CASH_FORK_BLOCK_HASH = (
    #     "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5e"
    # )

    COIN = BitcoinScalingTestnet

    # Replace after sufficient time has passed after a chain reset.
    # CHECKPOINT = CheckPoint(bytes.fromhex(
    #     '0000002050c936fce8c10522b399a9feee9c48fba7c409561d0553369fd6dc0a00000000735d99a4'
    #     '0a4ff9d2499db4524ca1663b82736211390885bd5d813ef2d4612c798e7e285f99d91d1cb33ad085'
    # ), height=15789, prev_work=0x12c8202e00871)

    # VERIFICATION_BLOCK_MERKLE_ROOT: Optional[str] = (
    #     '3c6449749d6376dd341f4e1b2192ec658b68c241beaaf665e5615ae01c35b853'
    # )

    # Use the following for a chain reset.
    CHECKPOINT = CheckPoint(bytes.fromhex(
        '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
        '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18'
    ), height=0, prev_work=0)
    VERIFICATION_BLOCK_MERKLE_ROOT: Optional[str] = None

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
    TREZOR_COIN_NAME: str = 'Bcash Testnet'
    # Really we want to put the difficulty logic in this file
    TWENTY_MINUTE_RULE = True


class SVRegTestnet(object):
    MIN_CHECKPOINT_HEIGHT = 0
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "bchtest"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS_API = read_json_dict('api_servers_regtest.json')
    GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    NAME = NetworkName.REGTEST
    BITCOIN_URI_PREFIX = "bitcoin"
    PAY_URI_PREFIX = "pay"
    WIF_PREFIX = 0xef
    BIP276_VERSION = 2
    COIN = BitcoinRegtest

    # Use the following for a chain reset.
    CHECKPOINT = CheckPoint(bytes.fromhex(
        '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
        '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000'
    ), height=0, prev_work=0)
    VERIFICATION_BLOCK_MERKLE_ROOT: Optional[str] = None

    BIP44_COIN_TYPE = 1

    BLOCK_EXPLORERS: Dict[str, Tuple[str, Dict[str, str]]] = {}

    FAUCET_URL = ""
    KEEPKEY_DISPLAY_COIN_NAME = 'Testnet'
    # Note: testnet allegedly supported only by unofficial firmware
    TREZOR_COIN_NAME: str = 'Bcash Testnet'
    TWENTY_MINUTE_RULE = True


NetworkTypes = Union[SVMainnet, SVTestnet, SVScalingTestnet, SVRegTestnet]


class _CurrentNetMeta(type):

    def __getattr__(cls, attr: str) -> Any:
        return getattr(cls._net, attr)


class Net(metaclass=_CurrentNetMeta):
    '''The current selected network.

    Use like so:

        from electrumsv.networks import Net, SVTestnet
        Net.set_to(SVTestnet)
    '''

    _net: Type[NetworkTypes] = SVMainnet

    @classmethod
    def set_to(cls, net_class: Type[NetworkTypes]) -> None:
        cls._net = net_class

    @classmethod
    def is_mainnet(cls) -> bool:
        return cls._net is SVMainnet

    @classmethod
    def is_testnet(cls) -> bool:
        return cls._net is SVTestnet

    @classmethod
    def is_scaling_testnet(cls) -> bool:
        return cls._net is SVScalingTestnet

    @classmethod
    def is_regtest(cls) -> bool:
        return cls._net is SVRegTestnet
