from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from io import BufferedIOBase, BytesIO
import struct
from typing import TypedDict

from bitcoinx import double_sha256, hex_str_to_hash, pack_varint, read_varint, unpack_header


# See: https://tsc.bitcoinassociation.net/standards/merkle-proof-standardised-format/

class ProofTransactionFlag(IntFlag):
    TRANSACTION_HASH    = 0
    FULL_TRANSACTION    = 1 << 0
    MASK                = TRANSACTION_HASH | FULL_TRANSACTION

class ProofTargetFlag(IntFlag):
    BLOCK_HASH          = 0
    BLOCK_HEADER        = 1 << 1
    MERKLE_ROOT         = 1 << 2
    MASK                = BLOCK_HASH | BLOCK_HEADER | MERKLE_ROOT

class ProofTypeFlag(IntFlag):
    MERKLE_BRANCH       = 0
    MERKLE_TREE         = 1 << 3
    MASK                = MERKLE_BRANCH | MERKLE_TREE

class ProofCountFlag(IntFlag):
    SINGLE              = 0
    MULTIPLE            = 1 << 4
    MASK                = SINGLE | MULTIPLE

FLAG_MASK = ProofTransactionFlag.MASK | ProofTargetFlag.MASK | ProofTypeFlag.MASK | \
    ProofCountFlag.MASK


@dataclass
class TSCMerkleNode:
    type: int
    value_bytes: bytes = b''
    value_int: int = 0


class TSCMerkleNodeKind(IntEnum):
    HASH                = 0
    DUPLICATE           = 1
    INDEX               = 2


class TSCMerkleProofError(Exception):
    ...



def validate_proof_flags(flags: int) -> None:
    invalid_flags = flags & ~FLAG_MASK
    if invalid_flags:
        raise TSCMerkleProofError(f"Unexpected flags {invalid_flags:x}")

    if flags & ProofCountFlag.MASK != ProofCountFlag.SINGLE:
        raise TSCMerkleProofError("Proofs can currently only be singular")

    if flags & ProofTypeFlag.MASK != ProofTypeFlag.MERKLE_BRANCH:
        raise TSCMerkleProofError("Proofs can currently only be merkle branches")


def verify_proof(proof: TSCMerkleProof, expected_merkle_root_bytes: bytes | None=None) -> bool:
    transaction_hash = proof.transaction_hash
    if transaction_hash is None:
        transaction_hash = double_sha256(proof.transaction_bytes)

    if proof.flags & ProofTargetFlag.MASK == ProofTargetFlag.BLOCK_HEADER:
        assert expected_merkle_root_bytes is None
        assert proof.block_header_bytes is not None
        try:
            _version, _prev_hash, expected_merkle_root_bytes, _timestamp, _bits, _nonce = \
                unpack_header(proof.block_header_bytes)
        except ValueError:
            raise TSCMerkleProofError("Invalid block header")
    elif proof.flags & ProofTargetFlag.MASK == ProofTargetFlag.MERKLE_ROOT:
        assert expected_merkle_root_bytes is None
        expected_merkle_root_bytes = proof.merkle_root_bytes
    else:
        # If the proof has a block hash, the caller needs to look up that header and get the
        # expected merkle root and provide it to us.
        assert expected_merkle_root_bytes is not None

    if len(proof.nodes) == 0:
        return transaction_hash == expected_merkle_root_bytes

    transaction_index = proof.transaction_index
    c = transaction_hash
    p: bytes
    for node in proof.nodes:
        c_is_left = transaction_index % 2 == 0

        if node.type == TSCMerkleNodeKind.HASH:
            p = node.value_bytes
        elif node.type == TSCMerkleNodeKind.DUPLICATE:
            if not c_is_left:
                raise TSCMerkleProofError("Duplicate node cannot be on right")
            p = c
        else:
            raise TSCMerkleProofError(f"Unsupported node type {node.type}")

        if c_is_left:
            c = double_sha256(c + p)
        else:
            c = double_sha256(p + c)

        transaction_index //= 2

    return c == expected_merkle_root_bytes


def le_int_to_char(le_int: int) -> bytes:
    return struct.pack('<I', le_int)[0:1]

class TxOrId(IntEnum):
    TRANSACTION_ID = 0
    FULL_TRANSACTION = 1 << 0


class TargetType(IntEnum):
    HASH = 0
    HEADER = 1 << 1
    MERKLE_ROOT = 1 << 2


class ProofType(IntEnum):
    MERKLE_BRANCH = 0
    MERKLE_TREE = 1 << 3


class CompositeProof(IntEnum):
    SINGLE_PROOF = 0
    COMPOSITE_PROOF = 1 << 4


class TSCMerkleProofJson(TypedDict):
    index: int
    txOrId: str  # hex
    targetType: str | None
    target: str  # hex
    nodes: list[str]




@dataclass
class TSCMerkleProof:
    flags: int
    transaction_index: int
    transaction_hash: bytes | None = None
    transaction_bytes: bytes | None = None
    block_hash: bytes | None = None
    block_header_bytes: bytes | None = None
    merkle_root_bytes: bytes | None = None
    nodes: list[TSCMerkleNode] = field(default_factory=list[TSCMerkleNode])

    @classmethod
    def from_json(cls, tsc_json: TSCMerkleProofJson) -> TSCMerkleProof:
        target_type = tsc_json["targetType"]

        flags = 0
        transaction_index = tsc_json['index']
        transaction_hash: bytes | None = None
        transaction_bytes: bytes | None = None
        block_hash: bytes | None = None
        block_header_bytes: bytes | None = None
        merkle_root_bytes: bytes | None = None
        nodes = list[TSCMerkleNode]()

        include_full_tx = len(tsc_json['txOrId']) > 64
        if include_full_tx:
            flags = flags | TxOrId.FULL_TRANSACTION

        if target_type == 'hash':
            flags = flags | TargetType.HASH
        elif target_type == 'header':
            flags = flags | TargetType.HEADER
        elif target_type == 'merkleroot':
            flags = flags | TargetType.MERKLE_ROOT
        else:
            raise NotImplementedError("Caller should have ensured `target_type` is valid.")

        flags = flags | ProofType.MERKLE_BRANCH  # ProofType.MERKLE_TREE not supported
        flags = flags | CompositeProof.SINGLE_PROOF  # CompositeProof.COMPOSITE_PROOF not supported

        if include_full_tx:
            transaction_bytes = bytes.fromhex(tsc_json['txOrId'])
        else:
            transaction_hash = hex_str_to_hash(tsc_json['txOrId'])

        if target_type in ('hash', 'merkleroot'):
            block_hash = hex_str_to_hash(tsc_json['target'])
        elif target_type == 'header':
            block_header_bytes = bytes.fromhex(tsc_json['target'])
        else:
            raise NotImplementedError("Caller should have ensured `target_type` is valid.")

        for node in tsc_json['nodes']:
            value_bytes = b''
            value_int = 0
            if node == "*":
                node_type = TSCMerkleNodeKind.DUPLICATE
            else:
                node_type = TSCMerkleNodeKind.HASH
                value_bytes = hex_str_to_hash(node)
            nodes.append(TSCMerkleNode(node_type, value_bytes, value_int))

        return cls(flags, transaction_index, transaction_hash, transaction_bytes, block_hash,
            block_header_bytes, merkle_root_bytes, nodes)

    @classmethod
    def from_bytes(cls, proof_bytes: bytes) -> TSCMerkleProof:
        stream = BytesIO(proof_bytes)
        return cls.from_stream(stream)

    @classmethod
    def from_stream(cls, stream: BufferedIOBase) -> TSCMerkleProof:
        """
        Raises `TSCMerkleProofError` for all known error cases.
        """
        flag_byte = stream.read(1)
        if len(flag_byte) != 1:
            raise TSCMerkleProofError("Proof is clipped and missing data")
        flags = ord(flag_byte)
        validate_proof_flags(flags)

        transaction_index = read_varint(stream.read)
        transaction_hash: bytes | None = None
        transaction_bytes: bytes | None = None
        block_hash: bytes | None = None
        block_header_bytes: bytes | None = None
        merkle_root_bytes: bytes | None = None

        if flags & ProofTransactionFlag.MASK == ProofTransactionFlag.TRANSACTION_HASH:
            # The serialised form is the transaction id (which is the reversed hash).
            transaction_hash = stream.read(32)
            if len(transaction_hash) != 32:
                raise TSCMerkleProofError("Proof is clipped and missing data")
        else:
            transaction_length = read_varint(stream.read)
            if transaction_length == 0:
                raise TSCMerkleProofError("Embedded transaction length is zero")
            # TODO This will need a different model if we are ever dealing with really large
            #      transactions.
            transaction_bytes = stream.read(transaction_length)
            if len(transaction_bytes) != transaction_length:
                raise TSCMerkleProofError("Proof is clipped and missing data")

        if flags & ProofTargetFlag.MASK == ProofTargetFlag.BLOCK_HEADER:
            block_header_bytes = stream.read(80)
            if len(block_header_bytes) != 80:
                raise TSCMerkleProofError("Proof is clipped and missing data")
        elif flags & ProofTargetFlag.MASK == ProofTargetFlag.MERKLE_ROOT:
            merkle_root_bytes = stream.read(32)
            if len(merkle_root_bytes) != 32:
                raise TSCMerkleProofError("Proof is clipped and missing data")
        else:
            # This is the default.
            block_hash = stream.read(32)
            if len(block_hash) != 32:
                raise TSCMerkleProofError("Proof is clipped and missing data")

        try:
            node_count = read_varint(stream.read)
            nodes: list[TSCMerkleNode] = []
            for i in range(node_count):
                node_type = ord(stream.read(1))
                value_bytes = b''
                value_int = 0
                if node_type == TSCMerkleNodeKind.HASH:
                    value_bytes = stream.read(32)
                    if len(value_bytes) != 32:
                        raise TSCMerkleProofError("Proof is clipped and missing data")
                elif node_type == TSCMerkleNodeKind.DUPLICATE:
                    pass
                elif node_type == TSCMerkleNodeKind.INDEX:
                    value_int = read_varint(stream.read)
                nodes.append(TSCMerkleNode(node_type, value_bytes, value_int))
        except struct.error:
            # bitcoinx `read_varint` unexpectedly encountered clipped buffer.
            raise TSCMerkleProofError("Proof is clipped and missing data")

        return cls(flags, transaction_index, transaction_hash, transaction_bytes, block_hash,
            block_header_bytes, merkle_root_bytes, nodes)

    def to_bytes(self) -> bytes:
        validate_proof_flags(self.flags)

        stream = BytesIO()
        stream.write(self.flags.to_bytes(1, 'little'))
        stream.write(pack_varint(self.transaction_index))

        if self.flags & ProofTransactionFlag.MASK == ProofTransactionFlag.FULL_TRANSACTION:
            if self.transaction_bytes is None:
                raise TSCMerkleProofError("No transaction bytes for embedded transaction")
            stream.write(pack_varint(len(self.transaction_bytes)))
            stream.write(self.transaction_bytes)
        else:
            if self.transaction_hash is None:
                raise TSCMerkleProofError("Expected transaction hash, was not set")
            stream.write(self.transaction_hash)

        if self.flags & ProofTargetFlag.MASK == ProofTargetFlag.BLOCK_HEADER:
            if self.block_header_bytes is None:
                raise TSCMerkleProofError("Expected block header bytes, was not set")
            stream.write(self.block_header_bytes)
        elif self.flags & ProofTargetFlag.MASK == ProofTargetFlag.MERKLE_ROOT:
            if self.merkle_root_bytes is None:
                raise TSCMerkleProofError("Expected merkle root bytes, was not set")
            stream.write(self.merkle_root_bytes)
        else:
            if self.block_hash is None:
                raise TSCMerkleProofError("Expected block hash, was not set")
            stream.write(self.block_hash)

        stream.write(pack_varint(len(self.nodes)))
        for node in self.nodes:
            stream.write(node.type.to_bytes(1, 'little'))
            if node.type == TSCMerkleNodeKind.HASH:
                stream.write(node.value_bytes)
            elif node.type == TSCMerkleNodeKind.DUPLICATE:
                pass
            elif node.type == TSCMerkleNodeKind.INDEX:
                stream.write(pack_varint(node.value_int))

        return stream.getvalue()


# TODO unit test this.
def separate_proof_and_embedded_transaction(proof: TSCMerkleProof,
        expected_transaction_hash: bytes) -> tuple[bytes, TSCMerkleProof]:
    transaction_bytes = proof.transaction_bytes
    assert transaction_bytes is not None
    transaction_hash = double_sha256(transaction_bytes)
    assert expected_transaction_hash == transaction_hash
    proof.transaction_bytes = None
    proof.transaction_hash = transaction_hash
    proof.flags &= ~ProofTransactionFlag.MASK
    proof.flags |= ProofTransactionFlag.TRANSACTION_HASH
    return transaction_bytes, proof

def separate_proof_and_embedded_transaction_from_bytes(proof_bytes: bytes,
        expected_transaction_hash: bytes) -> tuple[bytes, TSCMerkleProof]:
    proof = TSCMerkleProof.from_bytes(proof_bytes)
    return separate_proof_and_embedded_transaction(proof, expected_transaction_hash)
