import dataclasses
from enum import IntEnum
from io import BytesIO
import os
from typing import BinaryIO, cast, NamedTuple

from bitcoinx import pack_le_uint32, pack_varint, read_le_uint32, read_varint, Script, \
    unpack_le_uint32

from ..constants import DerivationPath, ScriptType
from ..logs import logs
from ..transaction import parse_script_sig, Transaction, XPublicKey
from ..types import DatabaseKeyDerivationData


logger = logs.get_logger("psbt")

DEBUG = False

class PSBTError(Exception):
    ...

class PSBTInvalidError(PSBTError):
    ...

class PSBTIncompatibleError(PSBTError):
    ...

class PSBTUnknownFingerprintError(PSBTError):
    ...

# BIP0174: Partially Signed Bitcoin Transaction Format
# https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
# BIP0380: PSBT Version 2
# https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki

class PSBTGlobalTypes(IntEnum):
    # Key data:   None.
    # Value data: <bytes transaction>
    #             The transaction in network serialization. The scriptSigs and witnesses for each
    #             input must be empty.
    PSBT_GLOBAL_UNSIGNED_TX             = 0x00
    # Key data:   <bytes xpub>
    #             The 78 byte serialized extended public key as defined by BIP 32. Extended public
    #             keys are those that can be used to derive public keys used in the inputs and
    #             outputs of this transaction. It should be the public key at the highest hardened
    #             derivation index so that the unhardened child keys used in the transaction can be
    #             derived.
    # Value data: <4 byte fingerprint> <32-bit little endian uint path element>*
    #             The master key fingerprint as defined by BIP 32 concatenated with the derivation
    #             path of the public key. The derivation path is represented as 32-bit little
    #             endian unsigned integer indexes concatenated with each other. The number of 32
    #             bit unsigned integer indexes must match the depth provided in the extended public
    #             key.
    PSBT_GLOBAL_XPUB                    = 0x01
    # The 32-bit little endian signed integer representing the version number of the transaction
    # being created.
    PSBT_GLOBAL_TX_VERSION              = 0x02
    # The 32-bit little endian unsigned integer representing the transaction locktime to use if
    # no inputs specify a required locktime.
    PSBT_GLOBAL_FALLBACK_LOCKTIME       = 0x03
    # Key data:   None.
    # Value data: <compact size uint input count>
    #             Compact size unsigned integer representing the number of inputs in this PSBT.
    PSBT_GLOBAL_INPUT_COUNT             = 0x04
    # Key data:   None.
    # Value data: <compact size uint output count>
    #             Compact size unsigned integer representing the number of outputs in this PSBT.
    PSBT_GLOBAL_OUTPUT_COUNT            = 0x05
    # An 8 bit little endian unsigned integer as a bitfield for various transaction modification
    # flags.
    # Bit 0 is the Inputs Modifiable Flag and indicates whether inputs can be modified.
    # Bit 1 is the Outputs Modifiable Flag and indicates whether outputs can be modified.
    # Bit 2 is the Has SIGHASH_SINGLE flag and indicates whether the transaction has a
    #   SIGHASH_SINGLE signature who's input and output pairing must be preserved. Bit 2
    #   essentially indicates that the Constructor must iterate the inputs to determine whether
    #   and how to add an input.
    PSBT_GLOBAL_TX_MODIFIABLE           = 0x06
    # Key data:   None.
    # Value data: <32-bit little endian uint version>
    #             The 32-bit little endian unsigned integer representing the version number of this
    #             PSBT. If omitted, the version number is 0.
    PSBT_GLOBAL_VERSION                 = 0xFB
    PSBT_GLOBAL_PROPRIETARY             = 0xFC

class PSBTInputTypes(IntEnum):
    # Key data:   None.
    # Value data: <bytes transaction>
    #             The transaction in network serialization format the current input spends from.
    #             This should be present for inputs that spend non-segwit outputs and can be
    #             present for inputs that spend segwit outputs. An input can have both
    #             NON_WITNESS_UTXO and WITNESS_UTXO.
    PARENT_TRANSACTION          = 0x00 # Renamed from `NON_WITNESS_UTXO`.
    WITNESS_UTXO                = 0x01 # Irrelevant.
    # Key data:   <bytes pubkey>
    #             The public key which corresponds to this signature.
    # Value data: <bytes signature>
    #             The signature as would be pushed to the stack from a scriptSig or witness. The
    #             signature should be a valid ECDSA signature corresponding to the pubkey that
    #             would return true when verified and not a value that would return false or be
    #             invalid otherwise (such as a NULLDUMMY).
    PARTIAL_SIG                 = 0x02
    # Key data:   None.
    # Value data: <32-bit little endian uint sighash type>
    #             The 32-bit unsigned integer specifying the sighash type to be used for this
    #             input. Signatures for this input must use the sighash type, finalizers must fail
    #             to finalize inputs which have signatures that do not match the specified sighash
    #             type. Signers who cannot produce signatures with the sighash type must not
    #             provide a signature.
    SIGHASH_TYPE                = 0x03
    # Key data:   None.
    # Value data: <bytes redeemScript>
    #             The redeemScript for this input if it has one.
    REDEEM_SCRIPT               = 0x04
    WITNESS_SCRIPT              = 0x05 # Irrelevant.
    # Key data:   <bytes pubkey>
    #             The public key
    # Value data: <4 byte fingerprint> <32-bit little endian uint path element>*
    #             The master key fingerprint as defined by BIP 32 concatenated with the derivation
    #             path of the public key. The derivation path is represented as 32 bit unsigned
    #             integer indexes concatenated with each other. Public keys are those that will
    #             be needed to sign this input
    BIP32_DERIVATION            = 0x06
    # Key data:   None.
    # Value data: <bytes scriptSig>
    #             The Finalized scriptSig contains a fully constructed scriptSig with signatures
    #             and any other scripts necessary for the input to pass validation.
    FINAL_SCRIPTSIG             = 0x07
    FINAL_SCRIPTWITNESS         = 0x08 # Irrelevant.
    POR_COMMITMENT              = 0x09 # Irrelevant.
    # Key data:   <20-byte hash>
    #             The resulting hash of the preimage
    # Value data: <bytes preimage>
    #             The hash preimage, encoded as a byte vector, which must equal the key when run
    #             through the RIPEMD160 algorithm
    RIPEMD160                   = 0x0a
    # Key data:   <32-byte hash>
    #              The resulting hash of the preimage
    # Value data: <bytes preimage>
    #             The hash preimage, encoded as a byte vector, which must equal the key when run
    #             through the SHA256 algorithm
    SHA256                      = 0x0b
    # Key data:   <20-byte hash>
    #             The resulting hash of the preimage
    # Value data: <bytes preimage>
    #             The hash preimage, encoded as a byte vector, which must equal the key when run
    #             through the SHA256 algorithm followed by the RIPEMD160 algorithm
    HASH160                     = 0x0c
    # Key data:   <32-byte hash>
    #             The resulting hash of the preimage
    # Value data: <bytes preimage>
    #             The hash preimage, encoded as a byte vector, which must equal the key when run
    #             through the SHA256 algorithm twice
    HASH256                     = 0x0d
    # Key data:   None.
    # Value data: <32 byte txid>
    #             32 byte txid of the previous transaction whose output at OUTPUT_INDEX is
    #             being spent.
    PREVIOUS_TXID               = 0x0e
    # Key data:   None.
    # Value data: <32-bit little endian uint index>
    #             32 bit little endian integer representing the index of the output being spent
    #             in the transaction with the txid of PREVIOUS_TXID.
    OUTPUT_INDEX                = 0x0f
    # Key data:   None.
    # Value data: <32-bit little endian uint sequence>
    #             The 32 bit unsigned little endian integer for the sequence number of this input.
    #             If omitted, the sequence number is assumed to be the final sequence number
    #             (0xffffffff).
    SEQUENCE                    = 0x10
    # Key data:   None.
    # Value data: <32-bit little endian uint locktime>
    #             32 bit unsigned little endian integer greater than or equal to 500000000
    #             representing the minimum Unix timestamp that this input requires to be set as
    #             the transaction's lock time.
    REQUIRED_TIME_LOCKTIME      = 0x11
    # Key data:   None.
    # Value data: <32-bit uiht locktime>
    #             32 bit unsigned little endian integer less than 500000000 representing the
    #             minimum block height that this input requires to be set as the transaction's
    #             lock time.
    REQUIRED_HEIGHT_LOCKTIME    = 0x12
    TAP_KEY_SIG                 = 0x13 # Irrelevant.
    TAP_SCRIPT_SIG              = 0x14 # Irrelevant.
    TAP_LEAF_SCRIPT             = 0x15 # Irrelevant.
    TAP_BIP32_DERIVATION        = 0x16 # Irrelevant.
    TAP_INTERNAL_KEY            = 0x17 # Irrelevant.
    TAP_MERKLE_ROOT             = 0x18 # Irrelevant.
    PROPRIETARY                 = 0xFC

IRRELEVANT_INPUT_TYPES = { PSBTInputTypes.WITNESS_UTXO, PSBTInputTypes.WITNESS_SCRIPT,
    PSBTInputTypes.FINAL_SCRIPTWITNESS, PSBTInputTypes.POR_COMMITMENT, PSBTInputTypes.TAP_KEY_SIG,
    PSBTInputTypes.TAP_SCRIPT_SIG, PSBTInputTypes.TAP_LEAF_SCRIPT,
    PSBTInputTypes.TAP_BIP32_DERIVATION, PSBTInputTypes.TAP_INTERNAL_KEY,
    PSBTInputTypes.TAP_MERKLE_ROOT }

class PSBTOutputTypes(IntEnum):
    # Key data:   None.
    # Value data: <bytes redeemScript>
    #             The redeemScript for this output if it has one.
    REDEEM_SCRIPT              = 0x00
    WITNESS_SCRIPT             = 0x01 # Irrelevant.
    # Key data:   <bytes public key>
    # Value data: <4 byte fingerprint> <32-bit little endian uint path element>*
    #             The master key fingerprint concatenated with the derivation path of the public
    #             key. The derivation path is represented as 32-bit little endian unsigned integer
    #             indexes concatenated with each other. Public keys are those needed to spend this
    #             output.
    BIP32_DERIVATION           = 0x02
    # Key data:   None.
    # Value data: <64-bit int amount>
    #             64 bit signed little endian integer representing the output's amount in satoshis.
    AMOUNT                     = 0x03
    # Key data:   None.
    # Value data: <bytes script>
    #             The script for this output, also known as the scriptPubKey. Must be omitted in
    #             PSBTv0. Must be provided in PSBTv2.
    SCRIPT                     = 0x04
    TAP_INTERNAL_KEY           = 0x05 # Irrelevant.
    TAP_TREE                   = 0x06 # Irrelevant.
    TAP_BIP32_DERIVATION       = 0x07 # Irrelevant.
    PROPRIETARY                = 0xFC

IRRELEVANT_OUTPUT_TYPES = { PSBTOutputTypes.WITNESS_SCRIPT, PSBTOutputTypes.TAP_INTERNAL_KEY,
    PSBTOutputTypes.TAP_TREE, PSBTOutputTypes.TAP_BIP32_DERIVATION }

@dataclasses.dataclass
class PSBTKeyPair:
    key_type: int
    key_data: bytes
    value_data: bytes

    # Error reporting information?
    stream_offset: int

def unpack_fingerprint_and_derivation_path(raw: bytes) -> tuple[bytes, DerivationPath]:
    stream_length = len(raw)
    stream = BytesIO(raw)
    fingerprint = stream.read(4)
    path_values: list[int] = []
    while stream.tell() + 4 < stream_length:
        path_values.append(read_le_uint32(stream.read))
    return fingerprint, tuple(path_values)

def pack_fingerprint_and_derivation_path(fingerprint: bytes, derivation_path: DerivationPath) \
        -> bytes:
    return fingerprint + b"".join(pack_le_uint32(value) for value in derivation_path)

# DESERIALISATION

def _read_psbt_section(stream: BinaryIO) -> dict[int, list[PSBTKeyPair]]:
    section_data: dict[int, list[PSBTKeyPair]] = {}
    while True:
        stream_offset = stream.tell()
        key_size = cast(int, read_varint(stream.read))
        if key_size == 0:
            return section_data

        key_offset = stream.tell()
        key_type = cast(int, read_varint(stream.read))
        key_data_size = key_size - (stream.tell() - key_offset)
        key_data = stream.read(key_data_size)
        if len(key_data) != key_data_size:
            logger.debug("PSBT parse section error, key data size mismatch, offset %d, "
                "key type %d, expected size %d, actual size %d", key_offset, key_type,
                key_data_size, len(key_data))
            raise PSBTInvalidError("PSBT invalid")

        value_size = cast(int, read_varint(stream.read))
        value_data = stream.read(value_size)
        if len(value_data) != value_size:
            logger.debug("PSBT parse section error, data size mismatch, offset %d, "
                "key type %d, expected size %d, actual size %d", key_offset, key_type,
                value_size, len(value_data))
            raise PSBTInvalidError("PSBT invalid")

        if key_type not in section_data:
            section_data[key_type] = []
        # "There can be multiple entries with the same <keytype> within a specific <map>, but
        #  the <key> must be unique."
        if any(key_pair.key_data == key_data for key_pair in section_data[key_type]):
            raise PSBTInvalidError("Duplicate key for type {}".format(key_type))
        section_data[key_type].append(PSBTKeyPair(key_type, key_data, value_data,
            stream_offset))

class PSBTMasterKeyDerivation(NamedTuple):
    masterkey_fingerprint: bytes
    derivation_path: DerivationPath

@dataclasses.dataclass
class PSBTInputMetadata:
    signatures: dict[bytes, bytes] = dataclasses.field(default_factory=dict)
    sighash: int | None = None
    redeem_script: Script | None = None
    script_sig: bytes | None = None

@dataclasses.dataclass
class PSBTOutputMetadata:
    pass

@dataclasses.dataclass
class PSBTTransactionData:
    psbt_version: int | None = None
    transaction: Transaction | None = None
    input_metadata: list[PSBTInputMetadata] = dataclasses.field(default_factory=list)
    output_metadata: list[PSBTOutputMetadata] = dataclasses.field(default_factory=list)
    parent_transactions: dict[bytes, Transaction] = dataclasses.field(default_factory=dict)

def read_psbt_stream(stream: BinaryIO, xpubs_by_fingerprint: dict[bytes, str]) \
        -> PSBTTransactionData:
    """
    Raises `PSBTError` if there are problems parsing the PSBT structure.
    """
    metadata = PSBTTransactionData()

    stream.seek(0, os.SEEK_END)
    stream_length = stream.tell()
    stream.seek(0, os.SEEK_SET)

    prefix_bytes = stream.read(5)
    if prefix_bytes != b"psbt\xff":
        raise PSBTInvalidError("PSBT invalid")

    global_key_pairs = _read_psbt_section(stream)
    if global_key_pairs is None:
        logger.debug("PSBT parse error in the global section")
        raise PSBTInvalidError("PSBT invalid")

    input_count: int | None = None
    output_count: int | None = None
    for global_key_type, global_entries in global_key_pairs.items():
        global_key = PSBTGlobalTypes(global_key_type)
        for key_pair in global_entries:
            if DEBUG:
                logger.debug("GLOBAL %s %s %s", global_key, key_pair.key_data,
                    key_pair.value_data)
            if global_key == PSBTGlobalTypes.PSBT_GLOBAL_UNSIGNED_TX:
                if metadata.transaction is not None:
                    raise PSBTInvalidError("Too many PSBT_GLOBAL_UNSIGNED_TX values")
                if len(key_pair.key_data) != 0:
                    raise PSBTInvalidError("Invalid PSBT_GLOBAL_UNSIGNED_TX key value")

                transaction_stream = BytesIO(key_pair.value_data)
                metadata.transaction = Transaction.read(transaction_stream.read,
                    transaction_stream.tell)
            elif global_key == PSBTGlobalTypes.PSBT_GLOBAL_INPUT_COUNT:
                input_count = read_varint(BytesIO(key_pair.value_data))
            elif global_key == PSBTGlobalTypes.PSBT_GLOBAL_OUTPUT_COUNT:
                output_count = read_varint(BytesIO(key_pair.value_data))
            elif global_key == PSBTGlobalTypes.PSBT_GLOBAL_VERSION:
                if metadata.psbt_version is not None:
                    raise PSBTInvalidError("Too many PSBT_GLOBAL_VERSION values")
                metadata.psbt_version = cast(int, unpack_le_uint32(key_pair.value_data)[0])
            else:
                raise PSBTInvalidError("Unexpected global key {}".format(global_key))

    if metadata.psbt_version is None:
        metadata.psbt_version = 0

    if metadata.psbt_version != 0:
        raise PSBTIncompatibleError("PSBT version {} not supported".format(metadata.psbt_version))

    if metadata.transaction is not None:
        if input_count is not None and input_count != len(metadata.transaction.inputs):
            raise PSBTInvalidError("Input count has {}, expected {}".format(
                input_count, len(metadata.transaction.inputs)))
        input_count = len(metadata.transaction.inputs)
        if output_count is not None and output_count != len(metadata.transaction.outputs):
            raise PSBTInvalidError("Output count has {}, expected {}".format(
                output_count, len(metadata.transaction.outputs)))
        output_count = len(metadata.transaction.outputs)
    else:
        raise PSBTInvalidError("No unsigned transaction included")

    for input_index in range(input_count):
        assert len(metadata.input_metadata) == input_index

        input_metadata = PSBTInputMetadata()
        metadata.input_metadata.append(input_metadata)

        input_key_pairs = _read_psbt_section(stream)
        if input_key_pairs is None:
            logger.debug("PSBT parse error in the inputs section")
            raise PSBTInvalidError("Missing input section {}".format(input_index))

        for input_key_type, input_entries in input_key_pairs.items():
            input_key = PSBTInputTypes(input_key_type)
            for key_pair in input_entries:
                if DEBUG:
                    logger.debug("INPUT %s %s %s", input_key, key_pair.key_data,
                        key_pair.value_data)

                if input_key == PSBTInputTypes.PARENT_TRANSACTION:
                    parent_transaction = Transaction.from_bytes(key_pair.value_data)
                    metadata.parent_transactions[parent_transaction.hash()] = \
                        parent_transaction
                elif input_key == PSBTInputTypes.PARTIAL_SIG:
                    key_length = len(key_pair.key_data)
                    if key_length not in (33, 65):
                        raise PSBTInvalidError("Invalid input signature key length={})".format(
                            key_length))
                    signature_length = len(key_pair.value_data)
                    if signature_length not in (71, 72, 73):
                        raise PSBTInvalidError("Invalid input signature length={}".format(
                            signature_length))
                    input_metadata.signatures[key_pair.key_data] = key_pair.value_data
                elif input_key == PSBTInputTypes.SIGHASH_TYPE:
                    input_metadata.sighash = cast(int, unpack_le_uint32(key_pair.value_data)[0])
                elif input_key == PSBTInputTypes.REDEEM_SCRIPT:
                    input_metadata.redeem_script = Script(key_pair.value_data)
                elif input_key == PSBTInputTypes.BIP32_DERIVATION:
                    if len(key_pair.key_data) not in (33, 65):
                        raise PSBTInvalidError("Invalid input derivation key length={})".format(
                            len(key_pair.key_data)))
                    masterkey_fingerprint, derivation_path = \
                        unpack_fingerprint_and_derivation_path(key_pair.value_data)
                    if masterkey_fingerprint not in xpubs_by_fingerprint:
                        raise PSBTUnknownFingerprintError(
                            "Unknown BIP32 input fingerprint {}".format(
                                masterkey_fingerprint.hex()))
                    metadata.transaction.inputs[input_index].x_pubkeys[key_pair.key_data] = \
                        XPublicKey(bip32_xpub=xpubs_by_fingerprint[masterkey_fingerprint],
                            derivation_data=DatabaseKeyDerivationData(derivation_path))
                elif input_key == PSBTInputTypes.FINAL_SCRIPTSIG:
                    if len(key_pair.key_data) > 0:
                        raise PSBTInvalidError("Unexpected FINAL_SCRIPTSIG key data")
                    input_metadata.script_sig = key_pair.key_data
                elif input_key in IRRELEVANT_INPUT_TYPES:
                    raise PSBTIncompatibleError("Incompatible input key {}".format(input_key.name))
                else:
                    raise PSBTInvalidError("Unexpected input key {}".format(input_key))

    for output_index in range(output_count):
        assert len(metadata.output_metadata) == output_index

        output_metadata = PSBTOutputMetadata()
        metadata.output_metadata.append(output_metadata)

        output_key_pairs = _read_psbt_section(stream)
        if output_key_pairs is None:
            logger.debug("PSBT parse error in the output section")
            raise PSBTInvalidError("Missing output section {}".format(output_index))

        for output_key_type, output_entries in output_key_pairs.items():
            output_key = PSBTOutputTypes(output_key_type)
            for key_pair in output_entries:
                if DEBUG:
                    logger.debug("OUTPUT %s %s %s", output_key, key_pair.key_data,
                        key_pair.value_data)

                if output_key == PSBTOutputTypes.BIP32_DERIVATION:
                    if len(key_pair.key_data) not in (33, 65):
                        raise PSBTInvalidError("Invalid output derivation key length={})".format(
                            len(key_pair.key_data)))
                    masterkey_fingerprint, derivation_path = \
                        unpack_fingerprint_and_derivation_path(key_pair.value_data)
                    if masterkey_fingerprint not in xpubs_by_fingerprint:
                        raise PSBTUnknownFingerprintError(
                            "Unknown BIP32 output fingerprint {}".format(
                                masterkey_fingerprint.hex()))
                    metadata.transaction.outputs[output_index].x_pubkeys[key_pair.key_data] = \
                        XPublicKey(bip32_xpub=xpubs_by_fingerprint[masterkey_fingerprint],
                            derivation_data=DatabaseKeyDerivationData(derivation_path))
                elif output_key in IRRELEVANT_OUTPUT_TYPES:
                    raise PSBTIncompatibleError("Incompatible output key {}".format(
                        output_key.name))
                else:
                    raise PSBTInvalidError("Unexpected output key {}".format(output_key))

    if stream.tell() != stream_length:
        logger.warning("PSBT has trailing data, current offset %d, data length %d",
            stream.tell(), stream_length)

    # We want the unsigned transaction to have all fields initialised correctly.
    for input_index, input_metadata in enumerate(metadata.input_metadata):
        # PSBTv2 preparation means not assuming we have the input the metadata is for.
        if len(metadata.transaction.inputs) > input_index:
            transaction_input = metadata.transaction.inputs[input_index]
            if input_metadata.script_sig is not None:
                script_data = parse_script_sig(input_metadata.script_sig,
                    XPublicKey.from_bytes)
                transaction_input.script_sig = Script(input_metadata.script_sig)
                # If we recognised the script type then copy across what we extracted from it.
                if script_data.script_type != ScriptType.NONE:
                    transaction_input.script_type = script_data.script_type
                    transaction_input.threshold = script_data.threshold

                    # Remember these are only full extended public keys for legacy extended
                    # transactions. Otherwise they will just be wrapped public keys. If we were
                    # given BIP32 derivation data, we try and map them in and replace the basic
                    # wrapped public key versions.
                    final_xpubkeys: dict[bytes, XPublicKey] = {}
                    for public_key_bytes, x_public_key in transaction_input.x_pubkeys.items():
                        final_xpubkeys[public_key_bytes] = x_public_key
                    for public_key_bytes, basic_xpubkey in script_data.x_pubkeys.items():
                        if public_key_bytes not in final_xpubkeys:
                            final_xpubkeys[public_key_bytes] = basic_xpubkey
                    transaction_input.x_pubkeys = final_xpubkeys

            assert len(transaction_input.signatures) == 0
            assert all(public_key_hash in transaction_input.x_pubkeys
                for public_key_hash in input_metadata.signatures)
            transaction_input.signatures = input_metadata.signatures

    return metadata

def parse_psbt_bytes(psbt_bytes: bytes, xpubs_by_fingerprint: dict[bytes, str]) \
        -> PSBTTransactionData:
    stream = BytesIO(psbt_bytes)
    return read_psbt_stream(stream, xpubs_by_fingerprint)

# SERIALISATION

def _write_psbt_section(stream: BinaryIO, type_data: list[tuple[int, list[PSBTKeyPair]]]) -> None:
    for key_type, key_pairs in type_data:
        key_type_bytes = pack_varint(key_type)
        for key_pair in key_pairs:
            key_size_bytes = pack_varint(len(key_type_bytes) + len(key_pair.key_data))
            stream.write(key_size_bytes)
            stream.write(key_pair.key_data)
            stream.write(pack_varint(len(key_pair.value_data)))
            stream.write(key_pair.value_data)
    # End the map.
    stream.write(pack_varint(0))

def serialise_transaction(transaction: Transaction) -> bytes:
    if not transaction.is_complete():
        raise PSBTInvalidError("Transaction is fully signed already")

    # TODO This should not have placeholder scriptsig.
    # TODO This should have a public key to signature mapping.
    # TODO This should have a public key to bip32 derivation mapping.
    transaction_bytes = transaction.to_bytes()
    # def to_bytes(self) -> bytes:
    # transaction_bytes = b''.join((
    #         pack_le_int32(self.version),
    #         pack_list(self.inputs, XTxInput.to_bytes),
    #         pack_list(self.outputs, XTxOutput.to_bytes),
    #         pack_le_uint32(self.locktime),
    #     ))


    global_map: list[tuple[int, list[PSBTKeyPair]]] = []
    input_map: list[tuple[int, list[PSBTKeyPair]]] = []
    output_map: list[tuple[int, list[PSBTKeyPair]]] = []

    stream = BytesIO()
    stream.write(b"psbt\xff")
    _write_psbt_section(stream, global_map)
    _write_psbt_section(stream, input_map)
    _write_psbt_section(stream, output_map)

    return b""
