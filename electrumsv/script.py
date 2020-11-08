
from bitcoinx import Ops, P2MultiSig_Output, pack_byte, push_int, push_item


class AccumulatorMultiSigOutput(P2MultiSig_Output):
    # Do not use this or other forms of non-standard script construction unless unit tests are
    # written against a script simulator to prove correctness.
    def __eq__(self, other):
        return (isinstance(other, AccumulatorMultiSigOutput)
                and self.public_keys == other.public_keys
                and self.threshold == other.threshold)

    def __hash__(self):
        return hash(self.public_keys) + self.threshold + 256796

    def to_script_bytes(self):
        parts = [
            pack_byte(Ops.OP_0),
            pack_byte(Ops.OP_TOALTSTACK),
        ]
        for public_key in self.public_keys:
            parts.extend([
                pack_byte(Ops.OP_IF),
                pack_byte(Ops.OP_DUP), pack_byte(Ops.OP_HASH160),
                push_item(public_key.hash160()),
                pack_byte(Ops.OP_EQUALVERIFY), pack_byte(Ops.OP_CHECKSIGVERIFY),
                pack_byte(Ops.OP_FROMALTSTACK), pack_byte(Ops.OP_1ADD),
                pack_byte(Ops.OP_TOALTSTACK),
                pack_byte(Ops.OP_ENDIF),
            ])
        parts.extend([
            # Is this the right order?
            pack_byte(Ops.OP_FROMALTSTACK),
            push_int(self.threshold),
            pack_byte(Ops.OP_GREATERTHANOREQUAL),
        ])
        return b''.join(parts)
