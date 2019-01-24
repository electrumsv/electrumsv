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

from bitcoinx import Chain, MissingHeader

from .app_state import app_state
from .crypto import sha256d
from .networks import Net
from .bitcoin import int_to_hex, rev_hex, hash_encode, bfh


HEADER_SIZE = 80 # bytes

# Called by test_blockchain.py:test_retargetting()
def _serialize_header(res):
    s = int_to_hex(res.get('version'), 4) \
        + rev_hex(res.get('prev_block_hash')) \
        + rev_hex(res.get('merkle_root')) \
        + int_to_hex(int(res.get('timestamp')), 4) \
        + int_to_hex(int(res.get('bits')), 4) \
        + int_to_hex(int(res.get('nonce')), 4)
    return s

# Called by network.py:Network._on_header()
# Called by network.py:Network._on_notify_header()
def deserialize_header(s, height):
    h = {}
    h['version'] = int.from_bytes(s[0:4], 'little')
    h['prev_block_hash'] = hash_encode(s[4:36])
    h['merkle_root'] = hash_encode(s[36:68])
    h['timestamp'] = int.from_bytes(s[68:72], 'little')
    h['bits'] = int.from_bytes(s[72:76], 'little')
    h['nonce'] = int.from_bytes(s[76:80], 'little')
    h['block_height'] = height
    return h

# Called by scripts/peers.py
# Called by test_blockchain.py:get_block()
def hash_header(header):
    if header is None:
        return '0' * 64
    if header.get('prev_block_hash') is None:
        header['prev_block_hash'] = '00'*32
    return hash_encode(sha256d(bfh(_serialize_header(header))))



# Called by network.py:Network._on_header()
# Called by network.py:Network._process_latest_tip()
def check_header(header):
    if type(header) is not dict:
        return False
    for b in Blockchain.blockchains:
        if b.check_header(header):
            return b
    return False

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

    def __init__(self, chain):
        # FIXME: base height logic is ... bizarre
        def base_height(c):
            if c.parent is None:
                return 0
            else:
                return c._first_height

        self.chain = chain
        self.catch_up = None # interface catching up
        self.base_height = base_height(chain)
        if chain.parent is None:
            self.parent_base_height = None
        else:
            self.parent_base_height = base_height(chain.parent)
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
    def legacy_map(cls):
        '''Remove this - just a temporary shim for legacy code expecting it.'''
        return {b.base_height: b for b in cls.blockchains}

    @classmethod
    def longest(cls):
        result = cls.blockchains[0]
        for blockchain in cls.blockchains:
            if blockchain.chain.work > result.chain.work:
                result = blockchain
        return result

    # Called by network.py:Network._on_header()
    def parent(self):
        # The base chain returns itself
        if self.chain.parent is None:
            return self
        return self.from_chain(self.chain.parent)

    def _get_max_child(self):
        children = [y for y in self.blockchains
                    if y.parent_base_height == self.base_height]
        return max([x.base_height for x in children]) if children else None

    # Called by verifier.py:SPV.undo_verifications()
    # Called by gui.qt.network_dialog.py:NetworkChoiceLayout.update()
    # Called by gui.qt.network_dialog.py:NodesListWidget.update()
    def get_base_height(self):
        mc = self._get_max_child()
        return mc if mc is not None else self.base_height

    # Called by gui.qt.network_dialog.py:NodesListWidget.update()
    def get_name(self):
        return self._get_hash(self.get_base_height()).lstrip('00')[0:10]

    # Called by network.py:Network._on_header()
    # Called by network.py:Network._process_latest_tip()
    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self._get_hash(height)

    # Called by network.py:Network._on_block_headers()
    # Called by network.py:Network._on_header()
    # Called by network.py:Network._process_latest_tip()
    # Called by network.py:Network.get_local_height()
    # Called by gui.qt.network_dialog.py:NodesListWidget.update()
    def height(self):
        return self.chain.height

    # Called by network.py:Network._switch_lagging_interface()
    # Called by network.py:Network.run()
    # Called by verifier.py:SPV.verify_merkle()
    # Called by wallet.py:Abstract_Wallet.undo_verifications()
    def read_header(self, height, chunk=None):
        # If the read is done within an outer call with local unstored header data, we
        # first look in the chunk data currently being processed.
        if chunk is not None and chunk.contains_height(height):
            return chunk.get_header_at_height(height)

        try:
            raw_header = app_state.headers.raw_header_at_height(self.chain, height)
            return deserialize_header(raw_header, height)
        except MissingHeader:
            return None

    def _get_hash(self, height):
        if height == -1:
            return '0000000000000000000000000000000000000000000000000000000000000000'
        elif height == 0:
            return Net.GENESIS
        return hash_header(self.read_header(height))

    @classmethod
    def connect(cls, header):
        raw_header = bfh(_serialize_header(header))
        header, chain = app_state.headers.connect(raw_header)
        return header, cls.from_chain(chain)

    @classmethod
    def connect_chunk(cls, start_height, raw_chunk, proof_was_provided):
        headers_obj = app_state.headers
        checkpoint = headers_obj.storage.checkpoint
        coin = headers_obj.coin
        end_height = start_height + len(raw_chunk) // HEADER_SIZE

        # This should be enforced by network.py
        #assert (end_height < checkpoint.height) is proof_was_provided

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
            verify_chunk_contiguous_and_set(extract_header(end_height), end_height)
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
