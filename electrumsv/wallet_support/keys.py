from __future__ import annotations
from collections.abc import Collection
from typing import cast, TYPE_CHECKING

from bitcoinx import classify_output_script, hash160, P2MultiSig_Output, P2PK_Output, \
    P2PKH_Address, P2SH_Address, PublicKey, sha256

from ..bitcoin import ScriptTemplate
from ..constants import DerivationType, KeystoreType, ScriptType, MULTI_SIGNER_SCRIPT_TYPES, \
    unpack_derivation_path
from ..exceptions import UnsupportedScriptTypeError
from ..networks import Net
from ..script import AccumulatorMultiSigOutput
from ..types import ImportTransactionKeyUsage
from ..wallet_database.types import KeyDataProtocol

if TYPE_CHECKING:
    from ..keystore import KeyStore, Multisig_KeyStore
    from ..transaction import Transaction


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


def get_single_signer_script_template(public_key: PublicKey, script_type: ScriptType) \
        -> ScriptTemplate:
    if script_type == ScriptType.P2PK:
        return P2PK_Output(public_key, network=Net.COIN)
    elif script_type == ScriptType.P2PKH:
        return public_key.to_address(network=Net.COIN)
    else:
        raise UnsupportedScriptTypeError("unsupported script type", script_type)


def get_multi_signer_script_template(public_keys_hex: list[str], threshold: int,
        script_type: ScriptType | None=None) -> ScriptTemplate:
    if script_type == ScriptType.MULTISIG_BARE:
        return P2MultiSig_Output(sorted(public_keys_hex), threshold)
    elif script_type == ScriptType.MULTISIG_P2SH:
        redeem_script = P2MultiSig_Output(sorted(public_keys_hex), threshold).to_script_bytes()
        return P2SH_Address(hash160(redeem_script), Net.COIN)
    elif script_type == ScriptType.MULTISIG_ACCUMULATOR:
        return AccumulatorMultiSigOutput(sorted(public_keys_hex), threshold)
    else:
        raise UnsupportedScriptTypeError("unsupported script type", script_type)


def get_output_script_template_for_public_keys(script_type: ScriptType,
        public_keys: list[PublicKey], threshold: int=1) -> ScriptTemplate:
    if script_type in (ScriptType.P2PK, ScriptType.P2PKH):
        return get_single_signer_script_template(public_keys[0], script_type)
    elif script_type in (ScriptType.MULTISIG_BARE, ScriptType.MULTISIG_P2SH,
            ScriptType.MULTISIG_ACCUMULATOR):
        public_keys_hex = [ public_key.to_hex() for public_key in public_keys ]
        return get_multi_signer_script_template(public_keys_hex, threshold, script_type)
    raise NotImplementedError(f"unsupported script type {script_type}")


def get_pushdata_hash_for_keystore_key_data(keystore: KeyStore, key_data: KeyDataProtocol,
        script_type: ScriptType) -> bytes:
    assert key_data.derivation_data2 is not None
    if key_data.derivation_type == DerivationType.PRIVATE_KEY:
        public_keys = [ PublicKey.from_bytes(key_data.derivation_data2) ]
        return get_pushdata_hash_for_public_keys(script_type, public_keys)
    elif key_data.derivation_type == DerivationType.BIP32_SUBPATH:
        assert key_data.derivation_data2 is not None
        derivation_path = unpack_derivation_path(key_data.derivation_data2)
        from ..keystore import Xpub
        xpub_keystore = cast(Xpub, keystore)
        public_keys = [ xpub_keystore.derive_pubkey(derivation_path) ]
        return get_pushdata_hash_for_public_keys(script_type, public_keys)
    elif keystore.type() == KeystoreType.MULTISIG:
        assert script_type in MULTI_SIGNER_SCRIPT_TYPES
        assert DerivationType(key_data.derivation_type) == DerivationType.BIP32_SUBPATH
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


def map_transaction_output_key_usage(transaction: Transaction,
        key_metadatas: Collection[ImportTransactionKeyUsage]) \
            -> dict[int, tuple[int, ScriptType]]:
    """
    This takes the matched pushdata hashes for a transaction and works out what outputs use
    which keys with which script types.
    """
    results: dict[int, tuple[int, ScriptType]] = {}
    for output_index, transaction_output in enumerate(transaction.outputs):
        script_template = classify_output_script(transaction_output.script_pubkey, Net.COIN)
        if isinstance(script_template, P2MultiSig_Output):
            script_type = ScriptType.MULTISIG_BARE
            pushdata_hashes = { sha256(public_key.to_bytes()) for public_key in
                script_template.public_keys }
        elif isinstance(script_template, P2PK_Output):
            script_type = ScriptType.P2PK
            pushdata_hashes = { sha256(script_template.public_key.to_bytes()) }
        elif isinstance(script_template, P2PKH_Address):
            script_type = ScriptType.P2PKH
            pushdata_hashes = { sha256(script_template.hash160()) }
        elif isinstance(script_template, P2SH_Address):
            script_type = ScriptType.MULTISIG_P2SH
            pushdata_hashes = { sha256(script_template.hash160()) }
        else:
            continue

        for key_metadata in key_metadatas:
            if key_metadata.script_type == script_type and \
                    key_metadata.pushdata_hash in pushdata_hashes:
                assert key_metadata.keyinstance_id is not None
                results[output_index] = key_metadata.keyinstance_id, key_metadata.script_type
    return results
