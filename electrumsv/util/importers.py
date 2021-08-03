# The Open BSV license.
#
# Copyright © 2020 Bitcoin Association
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the “Software”), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
#   1. The above copyright notice and this permission notice shall be included
#      in all copies or substantial portions of the Software.
#   2. The Software, and any software that is derived from the Software or parts
#      thereof, can only be used on the Bitcoin SV blockchains. The Bitcoin SV
#      blockchains are defined, for purposes of this license, as the Bitcoin
#      blockchain containing block height #556767 with the hash
#      “000000000000000001d956714215d96ffc00e0afda4cd0a96c96f8d802b1662b” and
#      the test blockchains that are supported by the unmodified Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


from enum import IntEnum
import json
from typing import Any, Dict, List, Optional, Tuple

from bitcoinx import Address, Base58Error, bip32_decompose_chain_string, hex_str_to_hash

from ..bitcoin import ScriptTemplate
from ..constants import ScriptType, DerivationPath, unpack_derivation_path
from ..networks import Net
from ..wallet import AbstractAccount, MultisigAccount
from ..wallet_database.types import KeyInstanceRow


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
        self.key_labels: Dict[DerivationPath, str] = {}
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
    def _get_addresses(cls, account: AbstractAccount) -> Dict[ScriptTemplate, KeyInstanceRow]:
        script_type = ScriptType.P2PKH
        if isinstance(account, MultisigAccount):
            script_type = ScriptType.MULTISIG_P2SH
        result: Dict[ScriptTemplate, KeyInstanceRow] = {}
        for keyinstance in account.get_keyinstances():
            template = account.get_script_template_for_derivation(script_type,
                keyinstance.derivation_type, keyinstance.derivation_data2)
            result[template] = keyinstance
        return result

    @classmethod
    def parse_label_sync_json(cls, account: AbstractAccount, text: str) -> LabelImportResult:
        addresses = cls._get_addresses(account)
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
                    keyinstance = addresses.get(address)
                    if keyinstance is not None:
                        assert keyinstance.derivation_data2 is not None
                        derivation_path = unpack_derivation_path(keyinstance.derivation_data2)
                        results.key_labels[derivation_path] = label_text
                        continue
            results.unknown_labels[label_reference] = label_text

        return results

    @classmethod
    def parse_label_export_json(cls, account: AbstractAccount, text: str) -> LabelImportResult:
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

            for derivation_path_text, label_text in keydata["entries"]:
                try:
                    derivation_path = tuple(bip32_decompose_chain_string(derivation_path_text))
                except (TypeError, ValueError):
                    pass
                else:
                    # We never import key descriptions if the account does not match.
                    if account_fingerprint == results.account_fingerprint:
                        results.key_labels[derivation_path] = label_text
                        continue
                results.unknown_labels[derivation_path_text] = label_text

        return results
