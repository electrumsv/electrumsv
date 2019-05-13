#!/usr/bin/python3

# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


"""Reference tests for cashaddr adresses"""

import random
from bitcoinx import cashaddr
from bitcoinx.cashaddr import _encode_full as cashaddr_encode_full

import pytest


BSV_PREFIX = "bitcoincash"
BSV_TESTNET_PREFIX = "bchtest"

VALID_PUBKEY_ADDRESSES = [
    "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
    "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r"
]

VALID_SCRIPT_ADDRESSES = [
    "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
    "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
    "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37"
]

VALID_HASHES = [
    bytes([ 118, 160, 64,  83, 189, 160, 168, 139, 218, 81,
            119, 184, 106, 21, 195, 178, 159, 85,  152, 115 ]),
    bytes([ 203, 72, 18, 50, 41,  156, 213, 116, 49,  81,
            172, 75, 45, 99, 174, 25,  142, 123, 176, 169 ]),
    bytes([ 1,   31, 40,  228, 115, 201, 95, 64,  19,  215,
            213, 62, 197, 251, 195, 180, 45, 248, 237, 16 ]),
]


class TestCashAddrAddress:
    """Unit test class for cashaddr addressess."""

    # Valid address sizes from the cashaddr spec
    valid_sizes = [160, 192, 224, 256, 320, 384, 448, 512]

    def test_encode_bad_inputs(self):
        with pytest.raises(TypeError):
            cashaddr_encode_full(2, cashaddr.PUBKEY_TYPE, bytes(20))
        with pytest.raises(TypeError):
            cashaddr_encode_full(BSV_PREFIX, cashaddr.PUBKEY_TYPE, '0' * 40)
        with pytest.raises(ValueError):
            cashaddr_encode_full(BSV_PREFIX, 15, bytes(20))

    def test_encode_decode(self):
        """Test whether valid addresses encode and decode properly, for all
        valid hash sizes.
        """
        for prefix in (BSV_PREFIX, BSV_TESTNET_PREFIX):
            for bits_size in self.valid_sizes:
                size = bits_size // 8
                # Convert to a valid number of bytes for a hash
                hashbytes = bytes(random.randint(0, 255) for i in range(size))
                addr = cashaddr_encode_full(prefix, cashaddr.PUBKEY_TYPE,
                                            hashbytes)
                rprefix, kind, addr_hash = cashaddr.decode(addr)
                assert rprefix == prefix
                assert kind == cashaddr.PUBKEY_TYPE
                assert addr_hash == hashbytes

    def test_bad_encode_size(self):
        """Test that bad sized hashes fail to encode."""
        for bits_size in self.valid_sizes:
            size = bits_size // 8
            # Make size invalid
            size += 1
            # Convert to a valid number of bytes for a hash
            hashbytes = bytes(random.randint(0, 255) for i in range(size))
            with pytest.raises(ValueError):
                cashaddr_encode_full(BSV_PREFIX, cashaddr.PUBKEY_TYPE,
                                     hashbytes)

    def test_decode_bad_inputs(self):
        with pytest.raises(TypeError):
            cashaddr.decode(b'foobar')

    def test_bad_decode_size(self):
        """Test that addresses with invalid sizes fail to decode."""
        for bits_size in self.valid_sizes:
            size = bits_size // 8
            # Convert to a valid number of bytes for a hash
            hashbytes = bytes(random.randint(0, 255) for i in range(size))
            payload = cashaddr._pack_addr_data(cashaddr.PUBKEY_TYPE, hashbytes)
            # Add some more 5-bit data after size has been encoded
            payload += bytes(random.randint(0, 15) for i in range(3))
            # Add checksum
            payload += cashaddr._create_checksum(BSV_PREFIX, payload)
            addr = BSV_PREFIX + ':' + ''.join(cashaddr._CHARSET[d] for d in payload)
            # Check decode fails.  This can trigger the length mismatch,
            # excess padding, or non-zero padding errors
            with pytest.raises(ValueError):
                cashaddr.decode(addr)

    def test_address_case(self):
        prefix, _kind, _hash160 = cashaddr.decode("bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq")
        assert prefix == "bitcoincash"
        prefix, _kind, _hash160 = cashaddr.decode("BITCOINCASH:PPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVN0H829PQ")
        assert prefix == "BITCOINCASH"
        with pytest.raises(ValueError):
            cashaddr.decode("bitcoincash:PPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVN0H829PQ")
        with pytest.raises(ValueError):
            cashaddr.decode("bitcoincash:ppm2qsznhks23z7629mmS6s4cwef74vcwvn0h829pq")

    def test_prefix(self):
        with pytest.raises(ValueError):
            cashaddr.decode(":ppm2qsznhks23z7629mms6s4cwef74vcwvn0h82")
        with pytest.raises(ValueError):
            cashaddr.decode("ppm2qsznhks23z7629mms6s4cwef74vcwvn0h82")
        with pytest.raises(ValueError):
            cashaddr.decode("bitcoin cash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h82")
        with pytest.raises(ValueError):
            cashaddr.decode("bitcoin cash:ab")
        # b is invalid
        with pytest.raises(ValueError):
            cashaddr.decode("bitcoincash:ppm2qsznbks23z7629mms6s4cwef74vcwvn0h82")


    @pytest.mark.parametrize("mangled_addr", (
        'qz3jljn0cms4fxkgwr2p8jgkjyw0rnxyesmq0kh2pq',
        'q93d4uh7r2revpkch695vvssm4y6tm438lav0za49rjqwa3w',
        'qgrkaz88sm8s8vrdq87s3uzjss6wljteguzva9vka23t5dqwsuxxhvh',
        'qwr05vx8hu7la2tpu6fefw5ndxlc43q35mj3ny9sa4l9ylfdekwfv8r7805d6',
        'qj9z9z2h80zj2ddhea2ywmuyw32zgjclj7rvpmt0l3s7awpnmwd4jpzc5grj7ywy4uc3g07rs4',
        'q4zy536yrje4rdv0sus3epe2wrazvutajezma3vc9g54dkhv785kegeqklrz3emepmv3z2q39yr7pcsy660wdyy',
        'qecf9u5myey7m8ug9us08egt7dz3rc0k892p7ywjs7a6ravy'
        '6z874pzk7nvj7sd382ptc4q2k5e9fe39rrc6y9dp5lxqapwzajx5',
        'qatl0fxkdj65zj6m3tvs4lrn35zca70lld279u633qxu8ex82gzmmej0ul6'
        'xzkjtkj5ytrr2g02h576p8gv6nrlqvnky2hewm7hrqr2n2jddpgsw',
    ))
    def test_bad_decode_checksum(self, mangled_addr):
        """Test whether addresses with invalid checksums fail to decode."""
        with pytest.raises(ValueError) as e:
            cashaddr.decode('bitcoincash:' + mangled_addr)
        assert 'invalid checksum' in str(e.value)

    def test_valid_scripthash(self):
        """Test whether valid P2PK addresses decode to the correct output."""
        for (address, hashbytes) in zip(VALID_SCRIPT_ADDRESSES, VALID_HASHES):
            rprefix, kind, addr_hash = cashaddr.decode(address)
            assert rprefix == BSV_PREFIX
            assert kind == cashaddr.SCRIPT_TYPE
            assert addr_hash == hashbytes

    def test_valid_pubkeys(self):
        """Test whether valid P2SH addresses decode to the correct output."""
        for (address, hashbytes) in zip(VALID_PUBKEY_ADDRESSES, VALID_HASHES):
            rprefix, kind, addr_hash = cashaddr.decode(address)
            assert rprefix == BSV_PREFIX
            assert kind == cashaddr.PUBKEY_TYPE
            assert addr_hash == hashbytes
