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
from typing import Dict, Tuple

from bitcoinx import CheckPoint, Bitcoin, BitcoinTestnet, BitcoinScalingTestnet, \
    BitcoinRegtest, PrivateKey, PublicKey, P2PKH_Address

from .util import resource_path

BLOCK_HEIGHT_OUT_OF_RANGE_ERROR = -8


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
        '00e0ff37689867096945489d8f39ccb2859e31f6f0fb3894705e3b0b0000000000000000f282be97'
        'e1a80610fd44c3cd9bfa386f49e4b3bce4126600c0a98d22f18ae3314db8b3637cc30b1802cd6874'
    ), height=773040, prev_work=0x140cb8794e892f2e39f0609)

    VERIFICATION_BLOCK_MERKLE_ROOT = (
        '8e9c79a13f25f19bd2e126475cd6fcc359d8a66485cd6a7c1deebacf289dfd15'
    )

    BIP44_COIN_TYPE = 0

    BLOCK_EXPLORERS = {
        'hugeblock.info': (
            'https://hugeblock.info',
            {'tx': 'tx', 'addr': 'address'},
        ),
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
        '00000020f248a5cf335bb0964833cb81bae10b2f47cc640f477d44926d000000000000005e737849'
        'ae351b1d17e0fc3e9032ffd889ad218d561143a883a3664a4e20e0729bc1b3634485021a68ca47cc'
    ), height=1530084, prev_work=0x1346dab3d7c7e35b984)
    VERIFICATION_BLOCK_MERKLE_ROOT = (
        '2ee768ac67da75c6df3326bd5d680ff39faeec07174e1d500fa0b6ca35932112'
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

    # VERIFICATION_BLOCK_MERKLE_ROOT = (
    #     '3c6449749d6376dd341f4e1b2192ec658b68c241beaaf665e5615ae01c35b853'
    # )

    # Use the following for a chain reset.
    CHECKPOINT = CheckPoint(bytes.fromhex(
        '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
        '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18'
    ), height=0, prev_work=0)
    VERIFICATION_BLOCK_MERKLE_ROOT = None

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


class SVRegTestnet(object):
    """The checkpoint cannot be made until the bitcoin node has at least generated 146 blocks (to
    calculate the DAA). Blocks are therefore generated until there are at least 200. A new
    checkpoint at height = 200 is then calculated before allowing anything further to proceed.

    Note: RegTest overflows the max nBits field, presumably due to a very short time interval
    between generated blocks. To modify this field would be to change the hash of the header so
    as a workaround, bitcoinx is monkeypatched to skip the checking of the difficulty target
    (see HeadersRegtestMod)."""

    # hardcoded
    # - WIF private_key:    cT3G2vJGRNbpmoCVXYPYv2JbngzwtznLvioPPJXu39jfQeLpDuX5
    # - Pubkey hash:        mfs8Y8gAwC2vJHCeSXkHs6LF5nu5PA7nxc
    REGTEST_FUNDS_PRIVATE_KEY: PrivateKey = PrivateKey(
        bytes.fromhex('a2d9803c912ab380c1491d3bd1aaab34ca06742d7885a224ec8d386182d26ed2'),
        coin=BitcoinRegtest)
    REGTEST_FUNDS_PRIVATE_KEY_WIF = REGTEST_FUNDS_PRIVATE_KEY.to_WIF()
    REGTEST_FUNDS_PUBLIC_KEY: PublicKey = REGTEST_FUNDS_PRIVATE_KEY.public_key
    REGTEST_P2PKH_ADDRESS: P2PKH_Address = REGTEST_FUNDS_PUBLIC_KEY.to_address().to_string()

    # For CI/CD use (restapi will by default reset everything back to empty wallet with this seed)
    # First receive address: mwv1WZTsrtKf3S9mRQABEeMaNefLbQbKpg
    REGTEST_DEFAULT_ACCOUNT_SEED = 'tprv8ZgxMBicQKsPd4wsdaJ11eH84eq4hHLX1K6Mx8EQQhJzq8jr25WH1m8hg' \
        'GkCqnksJDCZPZbDoMbQ6QtroyCyn5ZckCmsLeiHDb1MAxhNUHN'

    MIN_CHECKPOINT_HEIGHT = 0
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    CASHADDR_PREFIX = "bchtest"
    DEFAULT_PORTS = {'t': '51001'}
    DEFAULT_SERVERS = read_json_dict('servers_regtest.json')
    GENESIS = "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"
    NAME = 'regtest'
    BITCOIN_URI_PREFIX = "bitcoin"
    PAY_URI_PREFIX = "pay"
    WIF_PREFIX = 0xef
    BIP276_VERSION = 2
    COIN = BitcoinRegtest

    # Use the following for a chain reset.
    CHECKPOINT = CheckPoint(bytes.fromhex(
        '0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd'
        '7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18'
    ), height=0, prev_work=0)
    VERIFICATION_BLOCK_MERKLE_ROOT = None

    BIP44_COIN_TYPE = 1

    BLOCK_EXPLORERS: Dict[str, Tuple[str, Dict[str, str]]] = {}

    FAUCET_URL = ""
    KEEPKEY_DISPLAY_COIN_NAME = 'Testnet'
    # Note: testnet allegedly supported only by unofficial firmware
    TREZOR_COIN_NAME = 'Bcash Testnet'
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
