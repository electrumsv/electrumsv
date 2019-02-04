# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
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

from bitcoinx import Chain, MissingHeader, hash_to_hex_str

from .app_state import app_state
from .crypto import sha256d


HEADER_SIZE = 80 # bytes


# Called by network.py:Network._validate_checkpoint_result()
def root_from_proof(hash_, branch, index):
    """ Copied from electrumx """
    for elt in branch:
        if index & 1:
            hash_ = sha256d(elt + hash_)
        else:
            hash_ = sha256d(hash_ + elt)
        index >>= 1
    if index:
        raise ValueError('index out of range for branch')
    return hash_


class Blockchain:
    """
    Manages blockchain headers and their verification
    """

    blockchains = []
    needs_checkpoint_headers = True

    def __init__(self, chain):
        self.chain = chain
        self.catch_up = None   # interface catching up
        # Add ourselves to the global
        self.blockchains.append(self)

    @classmethod
    def from_chain(cls, chain):
        '''Return a Blockchain object for the chain.

        Enforce a unique Blockchain object for each Chain object.
        '''
        assert isinstance(chain, Chain)
        for b in cls.blockchains:
            if b.chain is chain:
                return b
        return cls(chain)

    @classmethod
    def read_blockchains(cls):
        app_state.read_headers()
        for chain in app_state.headers.chains():
            cls.from_chain(chain)

    @classmethod
    def longest(cls):
        result = cls.blockchains[0]
        for blockchain in cls.blockchains:
            if blockchain.chain.work > result.chain.work:
                result = blockchain
        return result

    @classmethod
    def required_checkpoint_headers(cls):
        '''Returns (start_height, count).  The range of headers needed for the DAA so that all
        post-checkpoint headers can have their difficulty verified.
        '''
        if cls.needs_checkpoint_headers:
            longest = cls.longest()
            cp_height = app_state.headers.checkpoint.height
            try:
                for height in range(cp_height - 146, cp_height):
                    longest.header_at_height(height)
                cls.needs_checkpoint_headers = False
            except MissingHeader:
                return height, cp_height - height
        return 0, 0

    # Called by verifier.py:SPV.undo_verifications()
    # Called by gui.qt.network_dialog.py:NetworkChoiceLayout.update()
    # Called by gui.qt.network_dialog.py:NodesListWidget.update()
    def get_base_height(self):
        return self.chain.first_height

    # Called by gui.qt.network_dialog.py:NodesListWidget.update()
    def get_name(self, other_chain):
        if other_chain is self:
            return f'our_chain'
        else:
            fork_height = self.common_height(other_chain) + 1
            header = self.header_at_height(fork_height)
            prefix = hash_to_hex_str(header.hash).lstrip('00')[0:10]
            return f'{prefix}@{fork_height}'

    # Called by network.py:Network._on_block_headers()
    # Called by network.py:Network._on_header()
    # Called by network.py:Network._process_latest_tip()
    # Called by network.py:Network.get_local_height()
    # Called by gui.qt.network_dialog.py:NodesListWidget.update()
    def height(self):
        return self.chain.height

    def header_at_height(self, height):
        return app_state.headers.header_at_height(self.chain, height)

    def common_height(self, other_blockchain):
        chain, height = self.chain.common_chain_and_height(other_blockchain.chain)
        return height

    @classmethod
    def connect(cls, height, raw_header, proof_was_provided):
        headers_obj = app_state.headers
        checkpoint = headers_obj.checkpoint

        if height < checkpoint.height:
            assert proof_was_provided
            headers_obj.set_one(height, raw_header)
            return headers_obj.coin.deserialized_header(raw_header), cls.longest()
        else:
            header, chain = app_state.headers.connect(raw_header)
            return header, cls.from_chain(chain)

    @classmethod
    def connect_chunk(cls, start_height, raw_chunk, proof_was_provided):
        headers_obj = app_state.headers
        checkpoint = headers_obj.checkpoint
        coin = headers_obj.coin
        end_height = start_height + len(raw_chunk) // HEADER_SIZE

        # This should be enforced by network.py
        assert (end_height < checkpoint.height) is proof_was_provided

        def extract_header(height):
            start = (height - start_height) * 80
            return raw_chunk[start: start + 80]

        def verify_chunk_contiguous_and_set(next_raw_header, to_height):
            # Set headers backwards from a proven header, verifying the prev_hash links.
            for height in reversed(range(start_height, to_height)):
                raw_header = extract_header(height)
                if coin.header_prev_hash(next_raw_header) != coin.header_hash(raw_header):
                    raise MissingHeader('prev_hash does not connect')
                headers_obj.set_one(height, raw_header)
                next_raw_header = raw_header

        # For pre-checkpoint headers with a verified proof, just set the headers after
        # verifying the prev_hash links
        if end_height < checkpoint.height:
            assert proof_was_provided
            # Set the last proven header
            last_header = extract_header(end_height - 1)
            headers_obj.set_one(end_height - 1, last_header)
            verify_chunk_contiguous_and_set(last_header, end_height - 1)
            return cls.longest()

        # For chunks prior to but connecting to the checkpoint, no proof is required
        verify_chunk_contiguous_and_set(checkpoint.raw_header, checkpoint.height)

        # Process any remaining headers forwards from the checkpoint
        chain = None
        for height in range(max(checkpoint.height + 1, start_height), end_height):
            _header, chain = headers_obj.connect(extract_header(height))

        if chain:
            return cls.from_chain(chain)
        return cls.longest()
