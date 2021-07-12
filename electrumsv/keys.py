import json
from typing import cast, List, Optional, TYPE_CHECKING

from bitcoinx import hash160, P2MultiSig_Output, P2PK_Output, P2SH_Address, PublicKey

from .bitcoin import ScriptTemplate
from .constants import DerivationType, ScriptType
from .exceptions import UnsupportedScriptTypeError
from .networks import Net
from .script import AccumulatorMultiSigOutput
from .wallet_database.types import KeyInstanceRow


if TYPE_CHECKING:
    from .types import KeyInstanceDataHash


def extract_public_key_hash(row: KeyInstanceRow) -> str:
    assert row.derivation_type == DerivationType.PUBLIC_KEY_HASH
    derivation_data = cast(KeyInstanceDataHash, json.loads(row.derivation_data))
    return derivation_data['hash']


def get_single_signer_script_template(public_key: PublicKey, script_type: ScriptType) \
        -> ScriptTemplate:
    if script_type == ScriptType.P2PK:
        return P2PK_Output(public_key, coin=Net.COIN)
    elif script_type == ScriptType.P2PKH:
        return public_key.to_address(coin=Net.COIN)
    else:
        raise UnsupportedScriptTypeError("unsupported script type", script_type)


def get_multi_signer_script_template(public_keys_hex: List[str], threshold: int,
        script_type: Optional[ScriptType]=None) -> ScriptTemplate:
    if script_type == ScriptType.MULTISIG_BARE:
        return P2MultiSig_Output(sorted(public_keys_hex), threshold)
    elif script_type == ScriptType.MULTISIG_P2SH:
        redeem_script = P2MultiSig_Output(sorted(public_keys_hex), threshold).to_script_bytes()
        return P2SH_Address(hash160(redeem_script), Net.COIN)
    elif script_type == ScriptType.MULTISIG_ACCUMULATOR:
        return AccumulatorMultiSigOutput(sorted(public_keys_hex), threshold)
    else:
        raise UnsupportedScriptTypeError("unsupported script type", script_type)
