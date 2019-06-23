# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 Thomas Voegtlin
# Copyright (C) 2019 Neil Booth
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

import struct

import attr
from bitcoinx import (
    PublicKey, PrivateKey, bip32_key_from_string, base58_encode_check,
    Ops, der_signature_to_compact, InvalidSignatureError,
    Script, push_int, push_item, hash_to_hex_str,
    Address, P2PKH_Address, P2SH_Address, P2PK_Output,
    Tx, TxInput, TxOutput, SigHash, classify_output_script,
    read_le_uint32, read_varbytes, read_le_int32, read_le_int64, read_list,
    pack_byte, pack_le_int32, pack_le_uint32, pack_le_int64, pack_list, unpack_le_uint16,
    double_sha256, hash160
)

from .networks import Net
from .logs import logs
from .util import bfh, bh2u


NO_SIGNATURE = b'\xff'
dummy_public_key = PublicKey.from_bytes(bytes(range(3, 36)))
dummy_signature = bytes(72)

logger = logs.get_logger("transaction")


def classify_tx_output(tx_output: TxOutput):
    # This returns a P2PKH_Address, P2SH_Address, P2PK_Output, OP_RETURN_Output,
    # P2MultiSig_Output or Unknown_Output
    return classify_output_script(tx_output.script_pubkey)


def tx_output_to_display_text(tx_output: TxOutput):
    kind = classify_tx_output(tx_output)
    if isinstance(kind, Address):
        text = kind.to_string(coin=Net.COIN)
    elif isinstance(kind, P2PK_Output):
        text = kind.public_key.hex()
    else:
        text = tx_output.script_pubkey.to_asm()
    return text, kind


class XPublicKey:

    def __init__(self, raw) -> None:
        if not isinstance(raw, (bytes, str)):
            raise TypeError(f'raw {raw} must be bytes or a string')
        try:
            self.raw = raw if isinstance(raw, bytes) else bytes.fromhex(raw)
            self.to_public_key()
        except (ValueError, AssertionError):
            raise ValueError(f'invalid XPublicKey: {raw}')

    def __eq__(self, other) -> bool:
        return isinstance(other, XPublicKey) and self.raw == other.raw

    def __hash__(self) -> int:
        return hash(self.raw) + 1

    def _bip32_public_key(self):
        extended_key, path = self.bip32_extended_key_and_path()
        result = bip32_key_from_string(extended_key)
        for n in path:
            result = result.child(n)
        return result

    def _old_keystore_public_key(self):
        mpk, path = self.old_keystore_mpk_and_path()
        mpk = PublicKey.from_bytes(pack_byte(4) + mpk)
        delta = double_sha256(f'{path[1]}:{path[0]}:'.encode() + self.raw[1:65])
        return mpk.add(delta)

    def to_bytes(self) -> bytes:
        return self.raw

    def to_hex(self) -> str:
        return self.raw.hex()

    def kind(self):
        return self.raw[0]

    def is_bip32_key(self) -> bool:
        return self.kind() == 0xff

    def bip32_extended_key(self):
        assert len(self.raw) == 83    # 1 + 78 + 2 + 2
        assert self.is_bip32_key()
        return base58_encode_check(self.raw[1:79])

    def bip32_extended_key_and_path(self):
        extended_key = self.bip32_extended_key()
        return extended_key, [unpack_le_uint16(self.raw[n: n+2])[0] for n in (79, 81)]

    def old_keystore_mpk_and_path(self):
        assert len(self.raw) == 69
        assert self.kind() == 0xfe
        mpk = self.raw[1:65]  # The public key bytes without the 0x04 prefix
        return mpk, [unpack_le_uint16(self.raw[n: n+2])[0] for n in (65, 67)]

    def to_public_key(self):
        '''Returns a PublicKey instance or an Address instance.'''
        kind = self.kind()
        if kind in {0x02, 0x03, 0x04}:
            return PublicKey.from_bytes(self.raw)
        if kind == 0xff:
            return self._bip32_public_key()
        if kind == 0xfe:
            return self._old_keystore_public_key()
        assert kind == 0xfd
        result = classify_output_script(Script(self.raw[1:]))
        assert isinstance(result, Address)
        result = (result.__class__)(result.hash160(), coin=Net.COIN)
        return result

    def to_public_key_hex(self):
        # Only used for the pubkeys array
        public_key = self.to_public_key()
        if isinstance(public_key, Address):
            return public_key.to_script_bytes().hex()
        return public_key.to_hex()

    def to_address(self):
        result = self.to_public_key()
        if not isinstance(result, Address):
            result = result.to_address(coin=Net.COIN)
        return result

    def is_compressed(self):
        return self.kind() not in (0x04, 0xfe)

    def __repr__(self):
        return f"XPublicKey('{self.raw.hex()}')"


@attr.s(slots=True, repr=False)
class XTxInput(TxInput):
    '''An extended bitcoin transaction input.'''
    value = attr.ib()
    x_pubkeys = attr.ib()
    address = attr.ib()
    threshold = attr.ib()
    signatures = attr.ib()

    @classmethod
    def read(cls, read):
        prev_hash = read(32)
        prev_idx = read_le_uint32(read)
        script_sig = Script(read_varbytes(read))
        sequence = read_le_uint32(read)
        kwargs = {'x_pubkeys': [], 'address': None, 'threshold': 0, 'signatures': []}
        if prev_hash != bytes(32):
            _parse_script_sig(script_sig.to_bytes(), kwargs)
        result = cls(prev_hash, prev_idx, script_sig, sequence, value=0, **kwargs)
        if not result.is_complete():
            result.value = read_le_int64(read)
        return result

    def _realize_script_sig(self, x_pubkeys, signatures):
        type_ = self.type()
        if type_ == 'p2pk':
            return Script(push_item(signatures[0]))
        if type_ == 'p2pkh':
            return Script(push_item(signatures[0]) + push_item(x_pubkeys[0].to_bytes()))
        if type_ == 'p2sh':
            parts = [pack_byte(Ops.OP_0)]
            parts.extend(push_item(signature) for signature in signatures)
            nested_script = multisig_script(x_pubkeys, self.threshold)
            parts.append(push_item(nested_script))
            return Script(b''.join(parts))
        return self.script_sig

    def to_bytes(self):
        if self.is_complete():
            x_pubkeys = [x_pubkey.to_public_key() for x_pubkey in self.x_pubkeys]
            signatures = self.signatures_present()
            self.script_sig = self._realize_script_sig(x_pubkeys, signatures)
            return super().to_bytes()
        else:
            self.script_sig = self._realize_script_sig(self.x_pubkeys, self.signatures)
            return super().to_bytes() + pack_le_int64(self.value)

    def signatures_present(self):
        '''Return a list of all signatures that are present.'''
        return [sig for sig in self.signatures if sig != NO_SIGNATURE]

    def is_complete(self):
        '''Return true if this input has all signatures present.'''
        return len(self.signatures_present()) >= self.threshold

    def stripped_signatures_with_blanks(self):
        '''Strips the sighash byte.'''
        return [b'' if sig == NO_SIGNATURE else sig[:-1] for sig in self.signatures]

    def unused_x_pubkeys(self):
        if self.is_complete():
            return []
        return [x_pubkey for x_pubkey, signature in zip(self.x_pubkeys, self.signatures)
                if signature == NO_SIGNATURE]

    def estimated_size(self):
        '''Return an estimated of serialized input size in bytes.'''
        saved_script_sig = self.script_sig
        x_pubkeys = [x_pubkey.to_public_key() for x_pubkey in self.x_pubkeys]
        signatures = [dummy_signature] * self.threshold
        self.script_sig = self._realize_script_sig(x_pubkeys, signatures)
        size = len(TxInput.to_bytes(self))   # base class implementation
        self.script_sig = saved_script_sig
        return size

    def type(self):
        if isinstance(self.address, P2PKH_Address):
            return 'p2pkh'
        if isinstance(self.address, P2SH_Address):
            return 'p2sh'
        if isinstance(self.address, PublicKey):
            return 'p2pk'
        if self.is_coinbase():
            return 'coinbase'
        return 'unknown'

    def __repr__(self):
        return (
            f'XTxInput(prev_hash="{hash_to_hex_str(self.prev_hash)}", prev_idx={self.prev_idx}, '
            f'script_sig="{self.script_sig}", sequence={self.sequence}), value={self.value} '
            f'x_pubkeys={self.x_pubkeys}, address={self.address}, '
            f'threshold={self.threshold}'
        )


def _script_GetOp(_bytes):
    i = 0
    blen = len(_bytes)
    while i < blen:
        vch = None
        opcode = _bytes[i]
        i += 1

        if opcode <= Ops.OP_PUSHDATA4:
            nSize = opcode
            if opcode == Ops.OP_PUSHDATA1:
                nSize = _bytes[i] if i < blen else 0
                i += 1
            elif opcode == Ops.OP_PUSHDATA2:
                # tolerate truncated script
                (nSize,) = struct.unpack_from('<H', _bytes, i) if i+2 <= blen else (0,)
                i += 2
            elif opcode == Ops.OP_PUSHDATA4:
                (nSize,) = struct.unpack_from('<I', _bytes, i) if i+4 <= blen else (0,)
                i += 4
            # array slicing here never throws exception even if truncated script
            vch = _bytes[i:i + nSize]
            i += nSize

        yield opcode, vch, i


def _match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False
    for i in range(len(decoded)):
        # Ops below OP_PUSHDATA4 all just push data
        if (to_match[i] == Ops.OP_PUSHDATA4 and
                decoded[i][0] <= Ops.OP_PUSHDATA4 and decoded[i][0] > 0):
            continue
        if to_match[i] != decoded[i][0]:
            return False
    return True


def _parse_script_sig(script, kwargs):
    try:
        decoded = list(_script_GetOp(script))
    except Exception:
        # coinbase transactions raise an exception
        logger.exception("cannot find address in input script %s", bh2u(script))
        return

    # P2PK
    match = [ Ops.OP_PUSHDATA4 ]
    if _match_decoded(decoded, match):
        item = decoded[0][1]
        kwargs['signatures'] = [item]
        kwargs['threshold'] = 1
        return

    # P2PKH inputs push a signature (around seventy bytes) and then their public key
    # (65 bytes) onto the stack
    match = [ Ops.OP_PUSHDATA4, Ops.OP_PUSHDATA4 ]
    if _match_decoded(decoded, match):
        sig = decoded[0][1]
        x_pubkey = XPublicKey(decoded[1][1])
        kwargs['signatures'] = [sig]
        kwargs['threshold'] = 1
        kwargs['x_pubkeys'] = [x_pubkey]
        kwargs['address'] = x_pubkey.to_address()
        return

    # p2sh transaction, m of n
    match = [ Ops.OP_0 ] + [ Ops.OP_PUSHDATA4 ] * (len(decoded) - 1)
    if not _match_decoded(decoded, match):
        logger.error("cannot find address in input script %s", bh2u(script))
        return
    nested_script = decoded[-1][1]
    dec2 = [ x for x in _script_GetOp(nested_script) ]
    x_pubkeys = [XPublicKey(x[1]) for x in dec2[1:-2]]
    m = dec2[0][0] - Ops.OP_1 + 1
    n = dec2[-2][0] - Ops.OP_1 + 1
    op_m = Ops.OP_1 + m - 1
    op_n = Ops.OP_1 + n - 1
    match_multisig = [ op_m ] + [Ops.OP_PUSHDATA4]*n + [ op_n, Ops.OP_CHECKMULTISIG ]
    if not _match_decoded(dec2, match_multisig):
        logger.error("cannot find address in input script %s", bh2u(script))
        return
    kwargs['x_pubkeys'] = x_pubkeys
    kwargs['threshold'] = m
    kwargs['address'] = P2SH_Address(hash160(multisig_script(x_pubkeys, m)))
    kwargs['signatures'] = [x[1] for x in decoded[1:-1]]
    return


def multisig_script(x_pubkeys, threshold):
    '''Returns bytes.

    x_pubkeys is an array of XPulicKey objects or an array of PublicKey objects.
    '''
    assert 1 <= threshold <= len(x_pubkeys)
    parts = [push_int(threshold)]
    parts.extend(push_item(x_pubkey.to_bytes()) for x_pubkey in x_pubkeys)
    parts.append(push_int(len(x_pubkeys)))
    parts.append(pack_byte(Ops.OP_CHECKMULTISIG))
    return b''.join(parts)


def tx_from_str(txt):
    "Takes json or hexadecimal, returns a hexadecimal string."
    import json
    txt = txt.strip()
    if not txt:
        raise ValueError("empty string")
    try:
        bfh(txt)
        is_hex = True
    except:
        is_hex = False
    if is_hex:
        return txt
    tx_dict = json.loads(str(txt))
    assert "hex" in tx_dict.keys()
    return tx_dict["hex"]



class Transaction(Tx):

    SIGHASH_FORKID = 0x40

    @classmethod
    def from_io(cls, inputs, outputs, locktime=0):
        return cls(version=1, inputs=inputs, outputs=outputs.copy(), locktime=locktime)

    @classmethod
    def read(cls, read):
        '''Overridden to specialize reading the inputs.'''
        return cls(
            read_le_int32(read),
            read_list(read, XTxInput.read),
            read_list(read, TxOutput.read),
            read_le_uint32(read),
        )

    def to_bytes(self):
        return b''.join((
            pack_le_int32(self.version),
            pack_list(self.inputs, XTxInput.to_bytes),
            pack_list(self.outputs, TxOutput.to_bytes),
            pack_le_uint32(self.locktime),
        ))

    def __str__(self):
        return self.serialize()

    def is_complete(self):
        '''Return true if this input has all signatures present.'''
        return all(txin.is_complete() for txin in self.inputs)

    def update_signatures(self, signatures):
        """Add new signatures to a transaction

        `signatures` is expected to be a list of binary sigs with signatures[i]
        intended for self.inputs[i], without the SIGHASH appended.
        This is used by hardware device code.
        """
        if self.is_complete():
            return
        if len(self.inputs) != len(signatures):
            raise RuntimeError('expected {} signatures; got {}'
                               .format(len(self.inputs), len(signatures)))
        for txin, signature in zip(self.inputs, signatures):
            full_sig = signature + bytes([self.nHashType()])
            logger.warning(f'Signature: {full_sig.hex()}')
            if full_sig in txin.signatures:
                continue
            pubkeys = [x_pubkey.to_public_key() for x_pubkey in txin.x_pubkeys]
            pre_hash = self.preimage_hash(txin)
            rec_sig_base = der_signature_to_compact(signature)
            for recid in range(4):
                rec_sig = rec_sig_base + bytes([recid])
                try:
                    public_key = PublicKey.from_recoverable_signature(rec_sig, pre_hash, None)
                except (InvalidSignatureError, ValueError):
                    # the point might not be on the curve for some recid values
                    continue
                if public_key in pubkeys:
                    try:
                        public_key.verify_recoverable_signature(rec_sig, pre_hash, None)
                    except Exception:
                        logger.exception('')
                        continue
                    j = pubkeys.index(public_key)
                    logger.debug(f'adding sig {j} {public_key} {full_sig}')
                    txin.signatures[j] = full_sig
                    break

    @classmethod
    def get_preimage_script(self, txin):
        _type = txin.type()
        if _type == 'p2pkh':
            return txin.address.to_script_bytes().hex()
        elif _type == 'p2sh':
            pubkeys = [x_pubkey.to_public_key() for x_pubkey in txin.x_pubkeys]
            return multisig_script(pubkeys, txin.threshold).hex()
        elif _type == 'p2pk':
            x_pubkey = txin.x_pubkeys[0]
            output = P2PK_Output(x_pubkey.to_public_key())
            return output.to_script_bytes().hex()
        else:
            raise RuntimeError('Unknown txin type', _type)

    def BIP_LI01_sort(self):
        # See https://github.com/kristovatlas/rfc/blob/master/bips/bip-li01.mediawiki
        self.inputs.sort(key = lambda txin: txin.prevout_bytes())
        self.outputs.sort(key = lambda output: (output.value, output.script_pubkey.to_bytes()))

    @classmethod
    def nHashType(cls):
        '''Hash type in hex.'''
        return 0x01 | cls.SIGHASH_FORKID

    def preimage_hash(self, txin):
        input_index = self.inputs.index(txin)
        script_code = bytes.fromhex(self.get_preimage_script(txin))
        sighash = SigHash(self.nHashType())
        return self.signature_hash(input_index, txin.value, script_code, sighash=sighash)

    def serialize(self):
        return self.to_bytes().hex()

    def txid(self):
        '''A hexadecimal string if complete, otherwise None.'''
        if self.is_complete():
            return hash_to_hex_str(self.hash())
        return None

    def input_value(self):
        return sum(txin.value for txin in self.inputs)

    def output_value(self):
        return sum(output.value for output in self.outputs)

    def get_fee(self):
        return self.input_value() - self.output_value()

    def estimated_size(self):
        '''Return an estimated tx size in bytes.'''
        saved_inputs = self.inputs
        self.inputs = []
        size_without_inputs = len(self.to_bytes())
        self.inputs = saved_inputs
        input_size = sum(txin.estimated_size() for txin in self.inputs)
        return size_without_inputs + input_size

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.inputs:
            signatures = txin.signatures_present()
            s += len(signatures)
            r += txin.threshold
        return s, r

    def sign(self, keypairs):
        assert all(isinstance(key, XPublicKey) for key in keypairs)
        for txin in self.inputs:
            if txin.is_complete():
                continue
            for j, x_pubkey in enumerate(txin.x_pubkeys):
                if x_pubkey in keypairs.keys():
                    logger.debug("adding signature for %s", x_pubkey)
                    sec, compressed = keypairs.get(x_pubkey)
                    txin.signatures[j] = self.sign_txin(txin, sec)
                    if x_pubkey.kind() == 0xfd:
                        pubkey_bytes = PrivateKey(sec).public_key.to_bytes(compressed=compressed)
                        txin.x_pubkeys[j] = XPublicKey(pubkey_bytes)
        logger.debug("is_complete %s", self.is_complete())

    def sign_txin(self, txin, privkey_bytes):
        pre_hash = self.preimage_hash(txin)
        privkey = PrivateKey(privkey_bytes)
        sig = privkey.sign(pre_hash, None)
        return sig + pack_byte(self.nHashType())

    def as_dict(self):
        out = {
            'hex': self.to_hex(),
            'complete': self.is_complete(),
        }
        return out
