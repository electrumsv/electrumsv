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

import json
import os

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
    NAME = 'Mainnet'
    URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0x80

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 478559
    BITCOIN_CASH_FORK_BLOCK_HASH = (
        "000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"
    )

    # This is a pre-split (BABC/BSV) checkpoint
    # cls.VERIFICATION_BLOCK_MERKLE_ROOT = (
    #     "3848ff6c001ebf78ec1a798c2002f154ace4ba6c0f0a58ccb22f66934eda7143"
    # )
    # cls.VERIFICATION_BLOCK_HEIGHT = 540250

    # A post-split SV checkpoint.
    VERIFICATION_BLOCK_MERKLE_ROOT = (
        "2eb4a1d21caa056385dbedd7743878e481d26052092aba97b319a6459ff6fa1b"
    )
    VERIFICATION_BLOCK_HEIGHT = 557957

    XPRV_HEADERS = {
        'standard':    0x0488ade4,  # xprv
    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,  # xpub
    }
    BIP44_COIN_TYPE = 0

    BLOCK_EXPLORERS = {
        'bchsvexplorer.com': (
            'https://bchsvexplorer.com',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'svblox.com': (
            'https://svblox.com',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'whatsonchain.com': (
            'https://whatsonchain.com',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'bsvexplorer.io': (
            'https://bsvexplorer.io',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'bitcoinsvexplorer.com': (
            'https://www.bitcoinsvexplorer.com',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'blockchair.com' : (
            'https://blockchair.com/bitcoin-sv',
            {'tx': 'transaction', 'addr': 'address'},
        ),
        'btc.com': (
            'https://bsv.btc.com',
            {'tx': '', 'addr': ''},
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
    NAME = 'Testnet'
    URI_PREFIX = "bitcoin"
    WIF_PREFIX = 0xef

    # Bitcoin Cash fork block specification
    BITCOIN_CASH_FORK_BLOCK_HEIGHT = 1155876
    BITCOIN_CASH_FORK_BLOCK_HASH = (
        "00000000000e38fef93ed9582a7df43815d5c2ba9fd37ef70c9a0ea4a285b8f5e"
    )

    # Bitcoin Cash fork block specification
    # cls.VERIFICATION_BLOCK_MERKLE_ROOT = (
    #    "029d920720e864945b8a5f97cd83e78e13fa001349cd1998815bdf2a6996dfa7"
    # )
    # cls.VERIFICATION_BLOCK_HEIGHT = 1248199

    VERIFICATION_BLOCK_MERKLE_ROOT = (
        "2fde3bf6de5266bd7a2c65b6e6971f8aa5e7b839ee18523994309ab42a18a70c"
    )
    VERIFICATION_BLOCK_HEIGHT = 1273000

    XPRV_HEADERS = {
        'standard':    0x04358394,  # tprv
    }
    XPUB_HEADERS = {
        'standard':    0x043587cf,  # tpub
    }
    BIP44_COIN_TYPE = 1

    BLOCK_EXPLORERS = {
        'satoshisvision.network': (
            'http://explore.satoshisvision.network',
            {'tx': 'tx', 'addr': 'address'},
        ),
        'bitcoincloud.net': (
            'https://testnet.bitcoincloud.net',
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


class _CurrentNetMeta(type):

    def __getattr__(cls, attr):
        return getattr(cls._net, attr)


class Net(metaclass=_CurrentNetMeta):
    '''The current selected network.

    Use like so:

        from electrumsv.networks import Net, SVTestnet
        Net.VERIFICATION_BLOCK_HEIGHT
        Net.set_to(SVTestnet)
    '''

    _net = SVMainnet

    @classmethod
    def set_to(cls, net_class):
        cls._net = net_class
