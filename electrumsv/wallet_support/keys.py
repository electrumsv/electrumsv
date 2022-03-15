from __future__ import annotations
from typing import cast, TYPE_CHECKING

from bitcoinx import hash160, P2MultiSig_Output, PublicKey, sha256

from ..constants import DerivationType, KeystoreType, ScriptType, MULTI_SIGNER_SCRIPT_TYPES, \
    unpack_derivation_path
from ..wallet_database.types import KeyDataProtocol

if TYPE_CHECKING:
    from ..keystore import KeyStore, Multisig_KeyStore
    from ..wallet import AbstractAccount


def get_pushdata_hash_for_derivation(derivation_type: DerivationType, derivation_data2: bytes) \
        -> tuple[ScriptType, bytes]:
    if derivation_type == DerivationType.PUBLIC_KEY_HASH:
        # We are looking for this hash160 in a P2PKH script output.
        item_hash = cast(bytes, sha256(derivation_data2))
        return ScriptType.P2PKH, item_hash
    elif derivation_type == DerivationType.SCRIPT_HASH:
        # We are looking for this hash160 in a P2SH script output.
        item_hash = cast(bytes, sha256(derivation_data2))
        return ScriptType.MULTISIG_P2SH, item_hash
    raise NotImplementedError(f"Unexpected derivation type {derivation_type}")


def get_pushdata_hash_for_public_keys(script_type: ScriptType, public_keys: list[PublicKey],
        threshold: int=1) -> bytes:
    hashable_item: bytes = b''
    if script_type == ScriptType.P2PK:
        # We are looking for this public key.
        assert len(public_keys) == 1
        hashable_item = public_keys[0].to_bytes()
    elif script_type == ScriptType.P2PKH:
        # We are looking for the hash160 of this public key.
        assert len(public_keys) == 1
        hashable_item = public_keys[0].hash160()
    elif script_type == ScriptType.MULTISIG_BARE:
        # We are looking for any one of the featured cosigner public keys used in this.
        hashable_item = public_keys[0].to_bytes()
    elif script_type == ScriptType.MULTISIG_P2SH:
        # We are looking for the hash160 of the redeem script.
        public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
        redeem_script = P2MultiSig_Output(sorted(public_keys_hex), threshold).to_script_bytes()
        hashable_item = hash160(redeem_script)
    elif script_type == ScriptType.MULTISIG_ACCUMULATOR:
        # We are looking for any one of the featured cosigner public keys used in this.
        hashable_item = public_keys[0].hash160()
    else:
        raise NotImplementedError(f"unsupported script type {script_type}")
    return cast(bytes, sha256(hashable_item))


def get_pushdata_hash_for_account_key_data(account: AbstractAccount, key_data: KeyDataProtocol,
        script_type: ScriptType) -> bytes:
    assert key_data.derivation_data2 is not None
    if key_data.derivation_type in (DerivationType.BIP32_SUBPATH, DerivationType.PRIVATE_KEY):
        public_keys = account.get_public_keys_for_derivation(key_data.derivation_type,
            key_data.derivation_data2)
        item_hash = get_pushdata_hash_for_public_keys(script_type, public_keys)
    else:
        key_script_type, item_hash = get_pushdata_hash_for_derivation(key_data.derivation_type,
            key_data.derivation_data2)
        assert key_script_type == script_type
    return item_hash


def get_pushdata_hash_for_keystore_key_data(keystore: KeyStore, key_data: KeyDataProtocol,
        script_type: ScriptType) -> bytes:
    assert key_data.derivation_data2 is not None
    if key_data.derivation_type == DerivationType.PRIVATE_KEY:
        public_keys = [ PublicKey.from_bytes(key_data.derivation_data2) ]
        return get_pushdata_hash_for_public_keys(script_type, public_keys)
    elif keystore.type() == KeystoreType.MULTISIG:
        assert script_type in MULTI_SIGNER_SCRIPT_TYPES
        assert key_data.derivation_type == DerivationType.BIP32_SUBPATH
        assert key_data.derivation_data2 is not None
        derivation_path = unpack_derivation_path(key_data.derivation_data2)

        ms_keystore = cast(Multisig_KeyStore, keystore)
        child_ms_keystores = ms_keystore.get_cosigner_keystores()
        public_keys = [ singlesig_keystore.derive_pubkey(derivation_path)
            for singlesig_keystore in child_ms_keystores ]
        return get_pushdata_hash_for_public_keys(script_type, public_keys, ms_keystore.m)

    key_script_type, pushdata_hash = get_pushdata_hash_for_derivation(key_data.derivation_type,
        key_data.derivation_data2)
    assert key_script_type == script_type
    return pushdata_hash
