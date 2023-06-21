from __future__ import annotations
import json
from typing import cast, TYPE_CHECKING
from typing_extensions import Any

from bitcoinx import bip32_key_from_string, hash_to_hex_str

from ..constants import ScriptType
from ..types import BackupAccountEntry, BackupAccountPaymentEntry, BackupKeyUsageEntry, \
    BackupMasterKeyEntry, BackupPaymentEntry, BackupWritingProtocol, BackupTransactionEntry, \
    MasterKeyDataBIP32

if TYPE_CHECKING:
    from ..wallet_database.types import AccountRow, AccountPaymentRow, \
        AccountTransactionOutputSpendableRow, KeyDataProtocol, MasterKeyRow, \
        TransactionInputSnapshotRow, TransactionRow


class BackupWriter(BackupWritingProtocol):
    def translate_masterkey(self, row: MasterKeyRow) -> BackupMasterKeyEntry:
        derivation_data = cast(MasterKeyDataBIP32, json.loads(row.derivation_data))
        key_fingerprint = bip32_key_from_string(derivation_data["xpub"]).fingerprint()
        return {
            "type": "masterkey",
            "masterkey_id": row.masterkey_id,
            "derivation": derivation_data["derivation"],
            "subtype": "fingerprint",
            "pubkey": key_fingerprint.hex(),
            "date_created": row.date_created,
        }

    def translate_account(self, row: AccountRow) -> BackupAccountEntry:
        return {
            "type": "account",
            "account_id": row.account_id,
            "account_name": row.account_name,
            "masterkey_id": row.default_masterkey_id,
            "date_created": row.date_created,
        }

    def translate_transaction(self, row: TransactionRow) -> BackupTransactionEntry:
        assert row.tx_bytes is not None
        return {
            "type": "transaction",
            "transaction_id": hash_to_hex_str(row.tx_hash),
            "transaction_data": row.tx_bytes.hex(),
        }

    def translate_account_payment(self, row: AccountPaymentRow) -> BackupAccountPaymentEntry:
        return {
            "type": "account-payment",
            "account_id": row.account_id,
            "payment_id": row.payment_id,
            "description": row.description,
            "date_created": row.date_created,
        }

    def translate_payment(self,
            # date_created: int,
            transaction_rows: list[TransactionRow],
            input_groups: dict[bytes, list[TransactionInputSnapshotRow]],
            output_groups: dict[bytes, list[AccountTransactionOutputSpendableRow]]) \
                -> BackupPaymentEntry:
        # TODO(1.4.0) Backup. This should pass in payment request data?? subtype should
        #     depend on invoice or payment request.
        return {
            "type": "payment",
            "subtype": "blockchain",
            "transactions": [
                {
                    "type": "payment-transaction",
                    "transaction_id": hash_to_hex_str(row.tx_hash),
                    "transaction_inputs": [
                        {
                            "input_index": input_row.spending_txi_index,
                            "spent_transaction_id": hash_to_hex_str(input_row.spent_tx_hash),
                            "spent_output_index": input_row.spent_txo_index,
                        } for input_row in input_groups[row.tx_hash]
                    ],
                    "transaction_outputs": [
                        {
                            "output_index": output_row.txo_index,
                            "script_template":
                                self.convert_script_type_to_template_name(output_row.script_type),
                            "key_usage": self.translate_key_usage(cast(KeyDataProtocol, output_row))
                        } for output_row in output_groups[row.tx_hash]
                    ],
                } for row in transaction_rows
            ],
            "date_created": 1, # date_created,
        }

    def translate_key_usage(self, key_data: KeyDataProtocol) -> BackupKeyUsageEntry:
        # The difference between `AccountTransactionOutputSpendableRow` (for instance) and
        # `KeyDataProtocol` is that the former allows an optional `keyinstance_id`. Callers may
        # have to cast to ensure the typing works, but we're asserting to make sure.
        assert key_data.keyinstance_id is not None
        # TODO(technical-debt) Backup. See `BackupKeyUsageEntry` for commentary on `masterkey_id`.
        assert key_data.masterkey_id is not None

        # TODO(1.4.0) Backup. Resolve `subtype` from the derivation data.
        return {
            "type": "key-usage",
            "subtype": "derivation??",
            "masterkey_id": key_data.masterkey_id,
        }

    def convert_script_type_to_template_name(self,  script_type: ScriptType) -> str:
        if script_type == ScriptType.P2PKH:
            return "p2pkh"
        elif script_type == ScriptType.P2PK:
            return "p2pk"
        elif script_type == ScriptType.MULTISIG_P2SH:
            return "multisig-p2sh"
        elif script_type == ScriptType.MULTISIG_BARE:
            return "multisig-bare"
        raise NotImplementedError(f"Unhandled script type {script_type}")

    def convert_entries_to_bytes(self, value: Any) -> bytes:
        return json.dumps(value).encode()
