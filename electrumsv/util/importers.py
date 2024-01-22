from enum import IntEnum
import json
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bitcoinx import Address, Base58Error, bip32_decompose_chain_string, hex_str_to_hash

from electrumsv.bitcoin import ScriptTemplate
from electrumsv.constants import ScriptType
from electrumsv.networks import Net
from electrumsv.wallet import AbstractAccount, MultisigAccount


class LabelImportFormat(IntEnum):
    UNKNOWN = 0
    LABELSYNC = 1
    ACCOUNT = 2


class LabelImportResult:
    def __init__(self, format: LabelImportFormat) -> None:
        self.format = format
        self.account_fingerprint: Optional[str] = None
        # These are known to be transaction labels, even if the wallet does not know of them all.
        self.transaction_labels: Dict[bytes, str] = {}
        # These are known to be key instance labels, the wallet knows them all.
        self.key_labels: Dict[int, str] = {}
        # These are things that were not for any possible transactions or existing key instances.
        self.unknown_labels: Dict[str, str] = {}


def identify_label_import_format(text: str) -> LabelImportFormat:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return LabelImportFormat.UNKNOWN

    if isinstance(data, dict) and len(data) > 0:
        if len(data) == 1 or len(data) == 2:
            if "transactions" in data:
                return LabelImportFormat.ACCOUNT
            if "keys" in data:
                if "account_fingerprint" in data["keys"] and "entries" in data["keys"]:
                    return LabelImportFormat.ACCOUNT

        if all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
            return LabelImportFormat.LABELSYNC

    return LabelImportFormat.UNKNOWN


class LabelImport:
    @classmethod
    def _get_derivations(klass, account: AbstractAccount) -> Dict[Sequence[int], int]:
        keypaths = account.get_key_paths()
        result: Dict[Sequence[int], int] = {}
        for keyinstance_id, derivation_path in keypaths.items():
            result[derivation_path] = keyinstance_id
        return result

    @classmethod
    def _get_addresses(klass, account: AbstractAccount) -> Dict[ScriptTemplate, int]:
        script_type = ScriptType.P2PKH
        if isinstance(account, MultisigAccount):
            script_type = ScriptType.MULTISIG_P2SH
        result: Dict[ScriptTemplate, int] = {}
        for keyinstance_id in account.get_keyinstance_ids():
            template = account.get_script_template_for_id(keyinstance_id, script_type)
            result[template] = keyinstance_id
        return result

    @classmethod
    def parse_label_sync_json(klass, account: AbstractAccount, text: str) -> LabelImportResult:
        addresses = klass._get_addresses(account)
        updates: List[Tuple[str, str]] = json.loads(text).items()
        results = LabelImportResult(LabelImportFormat.LABELSYNC)
        for label_reference, label_text in updates:
            if len(label_reference) == 64: # length of the transaction id (hex of hash)
                try:
                    tx_hash = hex_str_to_hash(label_reference)
                except (TypeError, ValueError):
                    pass
                else:
                    results.transaction_labels[tx_hash] = label_text
                    continue
            else:
                try:
                    address = Address.from_string(label_reference, Net.COIN)
                except (Base58Error, ValueError):
                    pass
                else:
                    keyinstance_id = addresses.get(address)
                    if keyinstance_id is not None:
                        results.key_labels[keyinstance_id] = label_text
                        continue
            results.unknown_labels[label_reference] = label_text

        return results

    @classmethod
    def parse_label_export_json(klass, account: AbstractAccount, text: str) -> LabelImportResult:
        updates: Dict[str, Any] = json.loads(text)
        results = LabelImportResult(LabelImportFormat.ACCOUNT)
        for tx_id, label_text in updates.get("transactions", []):
            if len(tx_id) == 64: # length of the transaction id (hex of hash)
                try:
                    tx_hash = hex_str_to_hash(tx_id)
                except (TypeError, ValueError):
                    pass
                else:
                    results.transaction_labels[tx_hash] = label_text
                    continue
            results.unknown_labels[tx_id] = label_text

        keydata: Optional[Dict[str, Any]] = updates.get("keys")
        if keydata is not None:
            account_fingerprint = account.get_fingerprint().hex()
            if isinstance(keydata.get("account_fingerprint"), str):
                results.account_fingerprint = keydata["account_fingerprint"]
            derivations = klass._get_derivations(account)
            for derivation_path_text, label_text in keydata["entries"]:
                try:
                    derivation_path = tuple(bip32_decompose_chain_string(derivation_path_text))
                except (TypeError, ValueError):
                    pass
                else:
                    # We never import key descriptions if the account does not match.
                    if account_fingerprint == results.account_fingerprint:
                        keyinstance_id = derivations.get(derivation_path)
                        if keyinstance_id is not None:
                            results.key_labels[keyinstance_id] = label_text
                            continue
                results.unknown_labels[derivation_path_text] = label_text

        return results
