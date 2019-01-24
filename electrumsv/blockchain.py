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
from .logs import logs
from .networks import Net
from .bitcoin import int_to_hex, rev_hex, hash_encode, bfh

logger = logs.get_logger("blockchain")


class VerifyError(Exception):
    '''Exception used for blockchain verification errors.'''

CHUNK_FORKS = -3
CHUNK_BAD = -2
CHUNK_LACKED_PROOF = -1
CHUNK_ACCEPTED = 0

def _bits_to_work(bits):
    return (1 << 256) // (_bits_to_target(bits) + 1)

# Called by test_blockchain.py:TestBlockchain.test_bits_to_target_conversion()
def _bits_to_target(bits):
    if bits == 0:
        return 0
    size = bits >> 24
    assert size <= 0x1d

    word = bits & 0x00ffffff
    assert 0x8000 <= word <= 0x7fffff

    if size <= 3:
        return word >> (8 * (3 - size))
    else:
        return word << (8 * (size - 3))

# Called by test_blockchain.py:TestBlockchain.test_bits_to_target_conversion()
def _target_to_bits(target):
    if target == 0:
        return 0
    target = min(target, MAX_TARGET)
    size = (target.bit_length() + 7) // 8
    mask64 = 0xffffffffffffffff
    if size <= 3:
        compact = (target & mask64) << (8 * (3 - size))
    else:
        compact = (target >> (8 * (size - 3))) & mask64

    if compact & 0x00800000:
        compact >>= 8
        size += 1
    assert compact == (compact & 0x007fffff)
    assert size < 256
    return compact | size << 24

HEADER_SIZE = 80 # bytes
MAX_BITS = 0x1d00ffff
MAX_TARGET = _bits_to_target(MAX_BITS)

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

# Called by network.py:Network._on_block_headers()
def verify_proven_chunk(chunk_base_height, chunk_data):
    chunk = _HeaderChunk(chunk_base_height, chunk_data)

    header_count = len(chunk_data) // HEADER_SIZE
    prev_header_hash = None
    for i in range(header_count):
        header = chunk.get_header_at_index(i)
        # Check the chain of hashes for all headers preceding the proven one.
        this_header_hash = hash_header(header)
        if i > 0:
            if prev_header_hash != header.get('prev_block_hash'):
                raise VerifyError("prev hash mismatch: %s vs %s" %
                                  (prev_header_hash, header.get('prev_block_hash')))
        prev_header_hash = this_header_hash

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

class _HeaderChunk:
    def __init__(self, base_height, data):
        self.base_height = base_height
        self.header_count = len(data) // HEADER_SIZE
        self.headers = [deserialize_header(data[i * HEADER_SIZE : (i + 1) * HEADER_SIZE],
                                           base_height + i)
                        for i in range(self.header_count)]

    def __repr__(self):
        return "_HeaderChunk(base_height={}, header_count={})".format(
            self.base_height, self.header_count)

    def get_count(self):
        return self.header_count

    def contains_height(self, height):
        return height >= self.base_height and height < self.base_height + self.header_count

    def get_header_at_height(self, height):
        assert self.contains_height(height)
        return self.get_header_at_index(height - self.base_height)

    def get_header_at_index(self, index):
        return self.headers[index]


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
        self.config = app_state.config
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

    # Called by gui.qt.network_dialog.py:NetworkChoiceLayout.update()
    def get_branch_size(self):
        return self.height() - self.get_base_height() + 1

    # Called by gui.qt.network_dialog.py:NodesListWidget.update()
    def get_name(self):
        return self._get_hash(self.get_base_height()).lstrip('00')[0:10]

    # Called by network.py:Network._on_header()
    # Called by network.py:Network._process_latest_tip()
    def check_header(self, header):
        header_hash = hash_header(header)
        height = header.get('block_height')
        return header_hash == self._get_hash(height)

    # Called by network.py:Network._on_header()
    def fork(self, header):
        raw_header = bfh(_serialize_header(header))
        chain = app_state.headers.add_raw_header(raw_header)
        return self.from_chain(chain)

    # Called by network.py:Network._on_block_headers()
    # Called by network.py:Network._on_header()
    # Called by network.py:Network._process_latest_tip()
    # Called by network.py:Network.get_local_height()
    # Called by gui.qt.network_dialog.py:NodesListWidget.update()
    def height(self):
        return self.chain.height

    def _verify_header(self, header, prev_header, bits=None):
        prev_header_hash = hash_header(prev_header)
        this_header_hash = hash_header(header)
        if prev_header_hash != header.get('prev_block_hash'):
            raise VerifyError("prev hash mismatch: %s vs %s" %
                              (prev_header_hash, header.get('prev_block_hash')))

        # We do not need to check the block difficulty if the chain of linked header
        # hashes was proven correct against our checkpoint.
        if bits is not None:
            # checkpoint BitcoinCash fork block
            if (header.get('block_height') == Net.BITCOIN_CASH_FORK_BLOCK_HEIGHT and
                    hash_header(header) != Net.BITCOIN_CASH_FORK_BLOCK_HASH):
                raise VerifyError("block at height %i is not cash chain fork block. hash %s" %
                                  (header.get('block_height'), hash_header(header)))
            if bits != header.get('bits'):
                raise VerifyError("bits mismatch: %s vs %s" % (bits, header.get('bits')))
            target = _bits_to_target(bits)
            if int('0x' + this_header_hash, 16) > target:
                raise VerifyError("insufficient proof of work: %s vs target %s" %
                                  (int('0x' + this_header_hash, 16), target))

    def _verify_chunk(self, chunk_base_height, chunk_data):
        chunk = _HeaderChunk(chunk_base_height, chunk_data)

        prev_header = None
        if chunk_base_height != 0:
            prev_header = self.read_header(chunk_base_height - 1)

        header_count = len(chunk_data) // HEADER_SIZE
        for i in range(header_count):
            header = chunk.get_header_at_index(i)
            # Check the chain of hashes and the difficulty.
            bits = self._get_bits(header, chunk)
            self._verify_header(header, prev_header, bits)
            prev_header = header

    def _save_chunk(self, base_height, chunk_data):
        logger.debug(f'save_chunk: base_height {base_height}')
        chunk_offset = (base_height - self.base_height) * HEADER_SIZE
        if chunk_offset < 0:
            chunk_data = chunk_data[-chunk_offset:]
            chunk_offset = 0
        # Headers at and before the verification checkpoint are sparsely filled.
        # Those should be overwritten and should not truncate the chain.
        top_height = base_height + (len(chunk_data) // HEADER_SIZE) - 1
        truncate = top_height > Net.VERIFICATION_BLOCK_HEIGHT
        self._write(chunk_data, chunk_offset, truncate)
        self._swap_with_parent()

    def _swap_with_parent(self):
        if self.parent_base_height is None:
            return
        parent_branch_size = self.parent().height() - self.base_height + 1
        if parent_branch_size >= self.get_branch_size():
            return
        logger.debug("swap %s %s", self.base_height, self.parent_base_height)
        # FIXME: surely a no-op?

    def _write(self, data, offset, truncate=True):
        height = self.base_height + offset // 80
        headers = app_state.headers
        for start in range(0, len(data), 80):
            raw_header = data[start: start + 80]
            if height < Net.CHECKPOINT.height:
                headers.set_one(height, raw_header)
            elif height > self.chain.height:
                new_chain = headers.add_raw_header(raw_header)
                assert self.chain is new_chain
            else:
                assert raw_header == headers.raw_header_at_height(self.chain, height)
            height += 1

    # Called by network.py:Network._on_header()
    # Called by network.py:Network._process_latest_tip()
    def save_header(self, header):
        delta = header.get('block_height') - self.base_height
        data = bfh(_serialize_header(header))
        assert delta == self.get_branch_size()
        assert len(data) == HEADER_SIZE
        self._write(data, delta*HEADER_SIZE)
        self._swap_with_parent()

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

    def _get_median_time_past(self, height, chunk=None):
        if height < 0:
            return 0
        times = [
            self.read_header(h, chunk)['timestamp']
            for h in range(max(0, height - 10), height + 1)
        ]
        return sorted(times)[len(times) // 2]

    def _get_suitable_block_height(self, suitableheight, chunk=None):
        # In order to avoid a block in a very skewed timestamp to have too much
        # influence, we select the median of the 3 top most block as a start point
        # Reference: github.com/Bitcoin-ABC/bitcoin-abc/master/src/pow.cpp#L201
        blocks2 = self.read_header(suitableheight, chunk)
        blocks1 = self.read_header(suitableheight-1, chunk)
        blocks = self.read_header(suitableheight-2, chunk)

        if blocks['timestamp'] > blocks2['timestamp']:
            blocks,blocks2 = blocks2,blocks
        if blocks['timestamp'] > blocks1['timestamp']:
            blocks,blocks1 = blocks1,blocks
        if blocks1['timestamp'] > blocks2['timestamp']:
            blocks1,blocks2 = blocks2,blocks1

        return blocks1['block_height']

    def _get_bits(self, header, chunk=None):
        '''Return bits for the given height.'''
        # Difficulty adjustment interval?
        height = header['block_height']
        # Genesis
        if height == 0:
            return MAX_BITS

        prior = self.read_header(height - 1, chunk)
        if prior is None:
            raise Exception("_get_bits missing header {} with chunk {!r}".format(height - 1, chunk))
        bits = prior['bits']

        #NOV 13 HF DAA

        prevheight = height -1
        daa_mtp = self._get_median_time_past(prevheight, chunk)

        #if daa_mtp >= 1509559291:  #leave this here for testing
        if daa_mtp >= 1510600000:
            if Net.TWENTY_MINUTE_RULE:
                # testnet 20 minute rule
                if header['timestamp'] - prior['timestamp'] > 20*60:
                    return MAX_BITS

            # determine block range
            daa_starting_height = self._get_suitable_block_height(prevheight-144, chunk)
            daa_ending_height = self._get_suitable_block_height(prevheight, chunk)

            # calculate cumulative work (EXcluding work from block daa_starting_height,
            # INcluding work from block daa_ending_height)
            daa_cumulative_work = 0
            for daa_i in range (daa_starting_height+1, daa_ending_height+1):
                daa_prior = self.read_header(daa_i, chunk)
                daa_bits_for_a_block = daa_prior['bits']
                daa_work_for_a_block = _bits_to_work(daa_bits_for_a_block)
                daa_cumulative_work += daa_work_for_a_block

            # calculate and sanitize elapsed time
            daa_starting_timestamp = self.read_header(daa_starting_height, chunk)['timestamp']
            daa_ending_timestamp = self.read_header(daa_ending_height, chunk)['timestamp']
            daa_elapsed_time = daa_ending_timestamp - daa_starting_timestamp
            if daa_elapsed_time > 172800:
                daa_elapsed_time = 172800
            if daa_elapsed_time < 43200:
                daa_elapsed_time = 43200

            # calculate and return new target
            daa_Wn = (daa_cumulative_work*600) // daa_elapsed_time
            daa_target = (1 << 256) // daa_Wn - 1
            daa_retval = _target_to_bits(daa_target)
            daa_retval = int(daa_retval)
            return daa_retval

        #END OF NOV-2017 DAA

        if height % 2016 == 0:
            return self._get_new_bits(height, chunk)

        if Net.TWENTY_MINUTE_RULE:
            # testnet 20 minute rule
            if header['timestamp'] - prior['timestamp'] > 20*60:
                return MAX_BITS
            return self.read_header(height // 2016 * 2016, chunk)['bits']

        # bitcoin cash EDA
        # Can't go below minimum, so early bail
        if bits == MAX_BITS:
            return bits
        mtp_6blocks = (self._get_median_time_past(height - 1, chunk) -
                       self._get_median_time_past(height - 7, chunk))
        if mtp_6blocks < 12 * 3600:
            return bits

        # If it took over 12hrs to produce the last 6 blocks, increase the
        # target by 25% (reducing difficulty by 20%).
        target = _bits_to_target(bits)
        target += target >> 2

        return _target_to_bits(target)

    def _get_new_bits(self, height, chunk=None):
        assert height % 2016 == 0
        # Genesis
        if height == 0:
            return MAX_BITS
        first = self.read_header(height - 2016, chunk)
        prior = self.read_header(height - 1, chunk)
        prior_target = _bits_to_target(prior['bits'])

        target_span = 14 * 24 * 60 * 60
        span = prior['timestamp'] - first['timestamp']
        span = min(max(span, target_span // 4), target_span * 4)
        new_target = (prior_target * span) // target_span
        return _target_to_bits(new_target)

    @classmethod
    def connect(cls, header):
        raw_header = bfh(_serialize_header(header))
        header, chain = app_state.headers.connect(raw_header)
        return header, cls.from_chain(chain)

    # Called by network.py:Network.on_block_headers()
    def connect_chunk(self, base_height, hexdata, proof_was_provided=False):
        chunk = _HeaderChunk(base_height, hexdata)

        header_count = len(hexdata) // HEADER_SIZE
        top_height = base_height + header_count - 1
        # We know that chunks before the checkpoint height, end at the checkpoint height, and
        # will be guaranteed to be covered by the checkpointing. If no proof is provided then
        # this is wrong.
        if top_height <= Net.VERIFICATION_BLOCK_HEIGHT:
            if not proof_was_provided:
                return CHUNK_LACKED_PROOF
            # We do not truncate when writing chunks before the checkpoint, and there's no
            # way at this time to know if we have this chunk, or even a consecutive subset.
            # So just overwrite it.
        elif base_height < Net.VERIFICATION_BLOCK_HEIGHT and proof_was_provided:
            # This was the initial verification request which gets us enough leading headers
            # that we can calculate difficulty and verify the headers that we add to this
            # chain above the verification block height.
            if top_height <= self.height():
                return CHUNK_ACCEPTED
        elif base_height != self.height() + 1:
            # This chunk covers a segment of this blockchain which we already have headers
            # for. We need to verify that there isn't a split within the chunk, and if
            # there is, indicate the need for the server to fork.
            intersection_height = min(top_height, self.height())
            chunk_header = chunk.get_header_at_height(intersection_height)
            our_header = self.read_header(intersection_height)
            if hash_header(chunk_header) != hash_header(our_header):
                return CHUNK_FORKS
            if intersection_height <= self.height():
                return CHUNK_ACCEPTED
        else:
            # This base of this chunk joins to the top of the blockchain in theory.
            # We need to rule out the case where the chunk is actually a fork at the
            # connecting height.
            our_header = self.read_header(self.height())
            chunk_header = chunk.get_header_at_height(base_height)
            if hash_header(our_header) != chunk_header['prev_block_hash']:
                return CHUNK_FORKS

        try:
            if not proof_was_provided:
                self._verify_chunk(base_height, hexdata)
            self._save_chunk(base_height, hexdata)
            return CHUNK_ACCEPTED
        except VerifyError as e:
            logger.error('_verify_chunk failed %s', e)
            return CHUNK_BAD
