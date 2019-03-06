# taken (with minor modifications) from pycoin
# https://github.com/richardkiss/pycoin/blob/01b1787ed902df23f99a55deb00d8cd076a906fe/
# pycoin/ecdsa/native/secp256k1.py

import ecdsa
import electrumsv_secp256k1

from .logs import logs


logger = logs.get_logger("ecc")

CDATA_SIG_LENGTH = 64


def _create_context():
    if not electrumsv_secp256k1.lib:
        logger.warning('libsecp256k1 library failed to load')
        return None

    _context = electrumsv_secp256k1.create_context()
    if _context is None:
        logger.warning('libsecp256k1 library could not create context')
        return None

    return _context


class _patched_functions:
    prepared_to_patch = False
    monkey_patching_active = False


def _prepare_monkey_patching_of_python_ecdsa_internals_with_libsecp256k1():
    if not _libsecp256k1:
        return

    # save original functions so that we can undo patching (needed for tests)
    _patched_functions.orig_sign   = staticmethod(ecdsa.ecdsa.Private_key.sign)
    _patched_functions.orig_verify = staticmethod(ecdsa.ecdsa.Public_key.verifies)
    _patched_functions.orig_mul    = staticmethod(ecdsa.ellipticcurve.Point.__mul__)

    curve_secp256k1 = ecdsa.ecdsa.curve_secp256k1
    curve_order = ecdsa.curves.SECP256k1.order
    point_at_infinity = ecdsa.ellipticcurve.INFINITY

    def mul(self: ecdsa.ellipticcurve.Point, other: int):
        if self.curve() != curve_secp256k1:
            # this operation is not on the secp256k1 curve; use original implementation
            return _patched_functions.orig_mul(self, other)
        other %= curve_order
        if self == point_at_infinity or other == 0:
            return point_at_infinity
        pubkey = electrumsv_secp256k1.ffi.new('secp256k1_pubkey *')
        public_pair_bytes = (b'\4' + self.x().to_bytes(32, byteorder="big") +
                             self.y().to_bytes(32, byteorder="big"))
        r = _libsecp256k1.secp256k1_ec_pubkey_parse(
            _context, pubkey, public_pair_bytes, len(public_pair_bytes))
        if not r:
            return False
        r = _libsecp256k1.secp256k1_ec_pubkey_tweak_mul(_context, pubkey,
                                                        other.to_bytes(32, byteorder="big"))
        if not r:
            return point_at_infinity

        pubkey_serialized = electrumsv_secp256k1.ffi.new('unsigned char [65]')
        pubkey_size = electrumsv_secp256k1.ffi.new('size_t *', 65)
        _libsecp256k1.secp256k1_ec_pubkey_serialize(
            _context, pubkey_serialized, pubkey_size, pubkey,
            _libsecp256k1.SECP256K1_EC_UNCOMPRESSED)
        pks_bytes = bytes(electrumsv_secp256k1.ffi.buffer(pubkey_serialized, 65))
        x = int.from_bytes(pks_bytes[1:33], byteorder="big")
        y = int.from_bytes(pks_bytes[33:], byteorder="big")
        return ecdsa.ellipticcurve.Point(curve_secp256k1, x, y, curve_order)

    def sign(self: ecdsa.ecdsa.Private_key, hash: int, random_k: int):
        # note: random_k is ignored
        if self.public_key.curve != curve_secp256k1:
            # this operation is not on the secp256k1 curve; use original implementation
            return _patched_functions.orig_sign(self, hash, random_k)
        secret_exponent = self.secret_multiplier
        nonce_function = electrumsv_secp256k1.ffi.NULL
        nonce_data = electrumsv_secp256k1.ffi.NULL
        sig = electrumsv_secp256k1.ffi.new('secp256k1_ecdsa_signature *')
        sig_hash_bytes = hash.to_bytes(32, byteorder="big")
        _libsecp256k1.secp256k1_ecdsa_sign(
            _context, sig, sig_hash_bytes,
            secret_exponent.to_bytes(32, byteorder="big"), nonce_function, nonce_data)
        compact_signature = electrumsv_secp256k1.ffi.new(f'unsigned char[{CDATA_SIG_LENGTH}]')
        _libsecp256k1.secp256k1_ecdsa_signature_serialize_compact(
            _context, compact_signature, sig)
        cs_bytes = bytes(electrumsv_secp256k1.ffi.buffer(compact_signature, CDATA_SIG_LENGTH))
        r = int.from_bytes(cs_bytes[:32], byteorder="big")
        s = int.from_bytes(cs_bytes[32:], byteorder="big")
        return ecdsa.ecdsa.Signature(r, s)

    def verify(self: ecdsa.ecdsa.Public_key, hash: int, signature: ecdsa.ecdsa.Signature):
        if self.curve != curve_secp256k1:
            # this operation is not on the secp256k1 curve; use original implementation
            return _patched_functions.orig_verify(self, hash, signature)
        sig = electrumsv_secp256k1.ffi.new('secp256k1_ecdsa_signature *')
        input64 = (signature.r.to_bytes(32, byteorder="big") +
                   signature.s.to_bytes(32, byteorder="big"))
        r = _libsecp256k1.secp256k1_ecdsa_signature_parse_compact(_context, sig, input64)
        if not r:
            return False
        r = _libsecp256k1.secp256k1_ecdsa_signature_normalize(_context, sig, sig)

        public_pair_bytes = (b'\4' + self.point.x().to_bytes(32, byteorder="big") +
                             self.point.y().to_bytes(32, byteorder="big"))
        pubkey = electrumsv_secp256k1.ffi.new('secp256k1_pubkey *')
        r = _libsecp256k1.secp256k1_ec_pubkey_parse(
            _context, pubkey, public_pair_bytes, len(public_pair_bytes))
        if not r:
            return False

        return 1 == _libsecp256k1.secp256k1_ecdsa_verify(
            _context, sig, hash.to_bytes(32, byteorder="big"), pubkey)

    # save new functions so that we can (re-)do patching
    _patched_functions.fast_sign   = sign
    _patched_functions.fast_verify = verify
    _patched_functions.fast_mul    = mul

    _patched_functions.prepared_to_patch = True


def do_monkey_patching_of_python_ecdsa_internals_with_libsecp256k1():
    if not _libsecp256k1:
        logger.info('libsecp256k1 library not available, falling back to python-ecdsa. '
                    'This means signing operations will be slower.')
        return
    if not _patched_functions.prepared_to_patch:
        raise Exception("can't patch python-ecdsa without preparations")
    ecdsa.ecdsa.Private_key.sign      = _patched_functions.fast_sign
    ecdsa.ecdsa.Public_key.verifies   = _patched_functions.fast_verify
    ecdsa.ellipticcurve.Point.__mul__ = _patched_functions.fast_mul
    # ecdsa.ellipticcurve.Point.__add__ = ...  # TODO??

    _patched_functions.monkey_patching_active = True
    logger.info('libsecp256k1 library found and will be used for ecdsa signing operations.')


def undo_monkey_patching_of_python_ecdsa_internals_with_libsecp256k1():
    if not _libsecp256k1:
        return
    if not _patched_functions.prepared_to_patch:
        raise Exception("can't patch python-ecdsa without preparations")
    ecdsa.ecdsa.Private_key.sign      = _patched_functions.orig_sign
    ecdsa.ecdsa.Public_key.verifies   = _patched_functions.orig_verify
    ecdsa.ellipticcurve.Point.__mul__ = _patched_functions.orig_mul

    _patched_functions.monkey_patching_active = False


def is_using_fast_ecc():
    return _patched_functions.monkey_patching_active


_libsecp256k1 = electrumsv_secp256k1.lib
_context = _create_context()

_prepare_monkey_patching_of_python_ecdsa_internals_with_libsecp256k1()
