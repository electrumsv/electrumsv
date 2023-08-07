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
from typing import Any, Literal, Type

from bitcoinx import (
    Bitcoin, BitcoinRegtest, BitcoinScalingTestnet, BitcoinTestnet
)

from .util import resource_path

NetworkNames = Literal["mainnet", "testnet", "scalingtestnet", "regtest"]
TEST_NETWORK_NAMES: set[NetworkNames] = { "regtest", "testnet", "scalingtestnet" }


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
    NAME: NetworkNames = "mainnet"
    BITCOIN_URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0x80
    BIP276_VERSION = 1

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 478559
    BITCOIN_CASH_FORK_BLOCK_HASH = (
        "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"
    )

    COIN = Bitcoin
    VERIFICATION_BLOCK_MERKLE_ROOT: str | None = None

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
    NAME: NetworkNames = "testnet"
    BITCOIN_URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0xef
    BIP276_VERSION = 2

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
    BITCOIN_CASH_FORK_BLOCK_HASH = (
        "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5e"
    )

    COIN = BitcoinTestnet
    VERIFICATION_BLOCK_MERKLE_ROOT: str | None = (
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
    NAME: NetworkNames = "scalingtestnet"
    BITCOIN_URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0xef
    BIP276_VERSION = 3

    # Bitcoin Cash fork block specification
    # BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
    # BITCOIN_CASH_FORK_BLOCK_HASH = (
    #     "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5e"
    # )

    COIN = BitcoinScalingTestnet
    VERIFICATION_BLOCK_MERKLE_ROOT: str | None = None

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
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "bchtest"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS_API = read_json_dict('api_servers_regtest.json')
    GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
    NAME: NetworkNames = "regtest"
    BITCOIN_URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0xef
    BIP276_VERSION = 2
    COIN = BitcoinRegtest
    VERIFICATION_BLOCK_MERKLE_ROOT: str | None = None

    BIP44_COIN_TYPE = 1

    BLOCK_EXPLORERS: dict[str, tuple[str, dict[str, str]]] = {}

    FAUCET_URL = ""
    KEEPKEY_DISPLAY_COIN_NAME = 'Testnet'
    # Note: testnet allegedly supported only by unofficial firmware
    TREZOR_COIN_NAME: str = 'Bcash Testnet'
    TWENTY_MINUTE_RULE = True


NetworkTypes = SVMainnet | SVTestnet | SVScalingTestnet | SVRegTestnet


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
