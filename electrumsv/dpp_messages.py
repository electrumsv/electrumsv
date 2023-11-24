#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2014 Thomas Voegtlin
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

from __future__ import annotations

import json
import time
from typing import Any, cast, Literal
from typing_extensions import NotRequired, TypedDict
import urllib.parse

from bitcoinx import Address, hex_str_to_hash, PublicKey, Script
import requests

from .exceptions import DPPException, DPPLocalException, DPPRemoteException
from .i18n import _
from .logs import logs
from .networks import Net, SVScalingTestnet, SVTestnet, SVMainnet, SVRegTestnet
from .standards.json_envelope import JSONEnvelope, validate_json_envelope
from .transaction import Transaction, XTxInput, XTxOutput
from .types import FeeQuoteTypeEntry2

logger = logs.get_logger("dpp-messages")

# NOTE: This now follows the TSC spec for the Direct Payment Protocol:
# https://tsc.bitcoinassociation.net/standards/direct_payment_protocol/

# BIP 273 - Use "Accept" header for response type negotiation with Simplified Payment Request URLs
# https://github.com/electrumsv/bips/blob/master/bip-0273.mediawiki
REQUEST_HEADERS = {
    'Accept': 'application/json',
    'User-Agent': 'ElectrumSV'
}

# BIP 270 - Simplified Payment Protocol
# https://github.com/electrumsv/bips/blob/master/bip-0270.mediawiki

def is_inv_expired(expiration_timestamp: int | None) -> bool:
    return expiration_timestamp is not None and expiration_timestamp < time.time()


HYBRID_PAYMENT_MODE_BRFCID = "ef63d9775da5"

# NOTE(rt12) In theory, we could remove this and assume that because JSON is inherently extensible
#     other parties could throw in custom properties and we could ignore them and everyone could
#     be happy. But in practice, if you don't know what you are dealing with you do not know that
#     you are handling it correctly. So for now, this must be set.
STRICT_PROPERTY_CHECKS = True
OUTPUT_POLICY_KEYS = frozenset({ "fees", "lockTime", "SPVRequired" })
INPUT_KEYS = frozenset({ "nSequence", "scriptSig", "txid", "vout", "value" })


# DPP Message Types as per the TSC spec.
# NOTE(rt12) We keep this around in case we need to put a dummy entry with
#     fake values to keep the DPP proxy working.
class PeerChannelDict(TypedDict):
    host: str
    token: str
    channel_id: str


class Policies(TypedDict):
    fees: dict[str, int] | None
    SPVRequired: bool
    lockTime: int


class DPPNativeInput(TypedDict):
    scriptSig: str
    txid: str
    vout: int
    value: int
    nSequence: int | None


class DPPNativeOutput(TypedDict):
    script: str
    amount: int
    description: str | None


# HPM == "HybridPaymentMode"
class HybridModeTransactionTermsDict(TypedDict):
    outputs: dict[Literal["native"], list[DPPNativeOutput]]
    inputs: dict[Literal["native"], list[DPPNativeInput]] | None
    policies: Policies | None


class PaymentTermsModes(TypedDict):
    # i.e. {
    #           HYBRID_PAYMENT_MODE_BRFCID: {
    #               <choiceIDs> : {
    #                   "transactions": [
    #                       <hybrid payment mode struct>
    #                   ]
    #               }
    #           }
    #      }
    ef63d9775da5: dict[str, dict[str, list[HybridModeTransactionTermsDict]]]


class HybridModePaymentACKDict(TypedDict):
    transactionIds: list[str]


class HybridModePaymentDict(TypedDict):
    optionId: str
    transactions: list[str]  # hex raw transactions
    ancestors: NotRequired[dict[str, Any] | None]


class PaymentTermsDict(TypedDict):
    network: str
    version: str
    creationTimestamp: int
    expirationTimestamp: NotRequired[int]
    memo: NotRequired[str]
    paymentUrl: str
    beneficiary: NotRequired[dict[str, Any] | None]
    modes: PaymentTermsModes


class PaymentDict(TypedDict):
    modeId: str  # i.e. HYBRID_PAYMENT_MODE_BRFCID
    mode: HybridModePaymentDict
    originator: NotRequired[dict[str, Any]]
    transaction: NotRequired[str] # DEPRECATED as per TSC spec.
    memo: NotRequired[str | None]


class PaymentACKDict(TypedDict):
    modeId: str
    mode: HybridModePaymentACKDict
    peerChannel: NotRequired[PeerChannelDict | None]
    redirectUrl: str | None



# See: https://tsc.bitcoinassociation.net/standards/direct_payment_protocol/#Specification
# changed from "mainnet" to "bitcoin-sv" for backwards compatibility
DPP_NETWORK_MAINNET: Literal["bitcoin-sv"] = "bitcoin-sv"
DPP_NETWORK_REGTEST: Literal["regtest"] = "regtest"
DPP_NETWORK_TESTNET: Literal["testnet"] = "testnet"
DPP_NETWORK_STN: Literal["stn"] = "stn"
NETWORK_NAMES = Literal["bitcoin-sv", "regtest", "testnet", "stn"]


def get_dpp_network_string() -> NETWORK_NAMES:
    if Net._net is SVMainnet:
        return DPP_NETWORK_MAINNET
    elif Net._net is SVTestnet:
        return DPP_NETWORK_TESTNET
    elif Net._net is SVScalingTestnet:
        return DPP_NETWORK_STN
    elif Net._net is SVRegTestnet:
        return DPP_NETWORK_REGTEST
    raise ValueError("Unrecognized network")


class PolicyDict(TypedDict):
    # NOTE(rt12) The DPP spec at this time has stale text related to mining and relay fees, but
    #     the examples do not follow the text. This is likely because the text was not updated.
    fees: FeeQuoteTypeEntry2
    lockTime: NotRequired[int]
    SPVRequired: NotRequired[bool]


class PaymentTermsMessage:
    MAXIMUM_JSON_LENGTH = 10 * 1000 * 1000

    _id: int|None = None
    _raw_json: str|None = None
    creation_timestamp: int
    expiration_timestamp: int|None = None
    memo: str|None
    payment_url: str|None

    def __init__(self, transactions: list[Transaction], transaction_policies: list[PolicyDict|None],
            network: str, version: str, *, creation_timestamp: int | None,
            expiration_timestamp: int | None=None, memo: str | None=None,
            beneficiary: dict[str, Any] | None=None, payment_url: str | None=None,
            raw_json: str|None = None) -> None:
        # This is only set for incoming payment terms for which we are the payer. We use it for
        # writing the unpaid invoice to the database, and nothing else.
        self._raw_json = raw_json

        self.network = network
        self.version = version

        self.transactions = transactions
        self.transaction_policies = transaction_policies

        if creation_timestamp is not None:
            self.creation_timestamp = int(creation_timestamp)
        else:
            self.creation_timestamp = int(time.time())
        if expiration_timestamp is not None:
            self.expiration_timestamp = int(expiration_timestamp)
        self.memo = memo
        self.beneficiary = beneficiary
        # TODO(nocheckin) Payments. Work out when this is `None` and document it and why it is
        #     correct.
        self.payment_url = payment_url

    @classmethod
    def from_json(cls, s: str) -> PaymentTermsMessage:
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise DPPException("Payment request oversized")

        payment_terms = cast(PaymentTermsDict, json.loads(s))

        network = payment_terms.get('network')
        if network not in (DPP_NETWORK_REGTEST, DPP_NETWORK_TESTNET, DPP_NETWORK_STN,
                DPP_NETWORK_MAINNET):
            raise DPPRemoteException(f"Invalid network '{network}'")

        if "version" not in payment_terms or type(payment_terms["version"]) is not str:
            raise DPPRemoteException("Missing string key 'version'")
        if "1.0" != payment_terms["version"]:
            raise DPPRemoteException("'1.0' expected for 'version'")
        if "outputs" in payment_terms:
            raise DPPRemoteException("Key 'outputs' not accepted")
        if "modes" not in payment_terms:
            raise DPPRemoteException("Missing key 'mode'")
        if HYBRID_PAYMENT_MODE_BRFCID not in payment_terms["modes"]:
            raise DPPRemoteException("Missing key 'mode.ef63d9775da5'")

        hybrid_payment_mode = payment_terms["modes"]["ef63d9775da5"]
        if not isinstance(hybrid_payment_mode, dict):
            raise DPPRemoteException("Key not object typed 'mode.ef63d9775da5'")
        if "choiceID0" not in hybrid_payment_mode:
            raise DPPRemoteException(
                "Missing key 'mode.ef63d9775da5.choiceID0'")

        choice0_payment_mode = hybrid_payment_mode["choiceID0"]
        if "transactions" not in choice0_payment_mode or \
                type(choice0_payment_mode["transactions"]) is not list:
            raise DPPRemoteException(
                "Missing list typed key 'mode.ef63d9775da5.choiceID0.transactions'")

        transactions: list[Transaction] = []
        transaction_policies: list[PolicyDict|None] = []
        transactions_list = cast(list[HybridModeTransactionTermsDict],
            choice0_payment_mode["transactions"])
        if len(transactions_list) < 1:
            raise DPPRemoteException(
                "Key missing entries 'mode.ef63d9775da5.choiceID0.transactions'")
        for i, transaction_dict in enumerate(transactions_list):
            if "inputs" in transaction_dict and type(transaction_dict["inputs"]) is not dict:
                raise DPPRemoteException("Optional key not object typed "
                    f"'mode.ef63d9775da5.choiceID0.transactions[{i}].inputs'")
            if "outputs" not in transaction_dict or type(transaction_dict["outputs"]) is not dict:
                raise DPPRemoteException("Missing list typed key "
                    f"'mode.ef63d9775da5.choiceID0.transactions[{i}].outputs'")
            policies_dict: PolicyDict|None = None
            if "policies" in transaction_dict:
                if type(transaction_dict["policies"]) is not dict:
                    raise DPPRemoteException("Optional key not object typed "
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].policies'")

                policies_dict = cast(PolicyDict, transaction_dict["policies"])
                if STRICT_PROPERTY_CHECKS:
                    extra_key_names = set(policies_dict) - OUTPUT_POLICY_KEYS
                    if len(extra_key_names) > 0:
                        raise DPPRemoteException("Payment terms invalid: object "
                            f"'mode.ef63d9775da5.choiceID0.transactions[{i}].policies' "
                            f"has unrecognised properties {list(extra_key_names)}")

                fee_data = policies_dict["fees"]
                if type(fee_data) is not dict:
                    raise DPPRemoteException("Payment terms invalid: not an object "
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].policies.fees'")

                if "data" not in fee_data or type(fee_data["data"]) is not dict:
                    raise DPPRemoteException("Payment terms invalid: not an object "
                        "'mode.ef63d9775da5.choiceID0.transactions[{i}].policies.fees.data'")
                if "satoshis" not in fee_data["data"] or \
                        type(fee_data["data"]["satoshis"]) is not int:
                    raise DPPRemoteException("Payment terms invalid: not an object "
                        "'mode.ef63d9775da5.choiceID0."
                        f"transactions[{i}].policies.fees.data.satoshis'")
                if "bytes" not in fee_data["data"] or \
                        type(fee_data["data"]["bytes"]) is not int:
                    raise DPPRemoteException("Payment terms invalid: not an object "
                        "'mode.ef63d9775da5.choiceID0."
                        f"transactions[{i}].policies.fees.data.bytes'")

                if "standard" not in fee_data or type(fee_data["standard"]) is not dict:
                    raise DPPRemoteException("Payment terms invalid: not an object "
                        "'mode.ef63d9775da5.choiceID0."
                        f"transactions[{i}].policies.fees.standard'")
                if "satoshis" not in fee_data["standard"] or \
                        type(fee_data["standard"]["satoshis"]) is not int:
                    raise DPPRemoteException("Payment terms invalid: not an object "
                        "'mode.ef63d9775da5.choiceID0."
                        f"transactions[{i}].policies.fees.standard.satoshis'")
                if "bytes" not in fee_data["standard"] or \
                        type(fee_data["standard"]["bytes"]) is not int:
                    raise DPPRemoteException("Payment terms invalid: not an object "
                        "'mode.ef63d9775da5.choiceID0."
                        f"transactions[{i}].policies.fees.standard.bytes'")

                if "SPVRequired" in policies_dict and \
                        type(policies_dict["SPVRequired"]) is not bool:
                    raise DPPRemoteException(
                        "Payment terms invalid: optional key not boolean typed "
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].policies.SPVRequired]'")
                if "lockTime" in policies_dict and (type(policies_dict["lockTime"]) is not int or
                        policies_dict["lockTime"] >= 0 and policies_dict["lockTime"] <= 0xFFFFFFFF):
                    raise DPPRemoteException("Key is not integer typed and >=0 and <=0xFFFFFFFF"
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].policies.lockTime]'")
            transaction_policies.append(policies_dict)

            inputs: list[XTxInput] = []
            if "inputs" in transaction_dict and "native" in transaction_dict["inputs"]:
                if type(transaction_dict["inputs"]["native"]) is not list:
                    raise DPPRemoteException("Optional key not list typed "
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].inputs.native'")

                inputs_list = cast(list[DPPNativeInput], transaction_dict["inputs"]["native"])
                for j, input_dict in enumerate(inputs_list):
                    if STRICT_PROPERTY_CHECKS:
                        extra_key_names = set(input_dict) - INPUT_KEYS
                        if len(extra_key_names) > 0:
                            raise DPPRemoteException("Payment terms invalid: object "
                                f"'mode.ef63d9775da5.choiceID0.transactions[{i}].inputs' "
                                f"has unrecognised properties {list(extra_key_names)}")

                    if "scriptSig" not in input_dict or type(input_dict["scriptSig"]) is not str:
                        raise DPPRemoteException("Missing string typed key "
                            f"'mode.ef63d9775da5.choiceID0.transactions[{i}]"
                            f".inputs[{j}].scriptSig'")
                    if "txid" not in input_dict or type(input_dict["txid"]) is not str:
                        raise DPPRemoteException("Missing string typed key "
                            f"'mode.ef63d9775da5.choiceID0.transactions[{i}]"
                            f".inputs[{j}].txid'")
                    if "vout" not in input_dict or type(input_dict["vout"]) is not int:
                        raise DPPRemoteException("Missing integer typed key "
                            f"'mode.ef63d9775da5.choiceID0.transactions[{i}]"
                            f".inputs[{j}].vout'")
                    if "value" not in input_dict or type(input_dict["value"]) is not int:
                        raise DPPRemoteException("Missing integer typed key "
                            f"'mode.ef63d9775da5.choiceID0.transactions[{i}]"
                            f".inputs[{j}].value'")
                    if "nSequence" in input_dict and type(input_dict["nSequence"]) is not int:
                        raise DPPRemoteException("Key is not integer typed "
                            f"'mode.ef63d9775da5.choiceID0.transactions[{i}]"
                            f".inputs[{j}].nSequence]'")

                    try:
                        script = Script.from_hex(input_dict["scriptSig"])
                    except ValueError:
                        raise DPPRemoteException("Key "
                            f"'mode.ef63d9775da5.choiceID0.transactions[{i}]."
                            f"inputs[{j}].scriptSig' is not valid hex")

                    # TODO(nocheckin) Payments / payment terms / ancestors. See below.
                    #     This should be deferred and we should not accept payment terms that
                    #     specify ancestors until we have proper handling.
                    # TODO(1.4.0) Proper handling for payment terms with inputs.
                    #     1. Any inputs that have parents and merkle proofs should be checked and
                    #        if they are valid they are checked off and if not valid then we reject.
                    #     2. Any inputs that do not have parents we reject.
                    #     3. Any inputs that have parents without a merkle proof we check output
                    #        spends.
                    #     4. If output spends show in the mempool then that is good enough.
                    #     5. We should consider what to do if there is a reorg.

                    invalid = False
                    try:
                        prev_hash = hex_str_to_hash(input_dict["txid"])
                    except ValueError:
                        invalid = True
                    else:
                        invalid = len(prev_hash) != 32
                    if invalid:
                        raise DPPRemoteException("Key "
                            f"'mode.ef63d9775da5.choiceID0.transactions[{i}]."
                            f"inputs[{j}].txid' is not valid hex")

                    prev_idx = input_dict["vout"]
                    nSequence = 0xFFFFFFFF
                    if "nSequence" in input_dict:
                        nSequence = input_dict["nSequence"]
                        if nSequence < 0 or nSequence > 0xFFFFFFFF:
                            raise DPPRemoteException("Key out of range "
                                f"'mode.ef63d9775da5.choiceID0.transactions[{i}]"
                                f".inputs[{j}].nSequence]'")

                    inputs.append(XTxInput(prev_hash=prev_hash, # type: ignore[call-arg]
                        prev_idx=prev_idx, script_sig=script, sequence=nSequence))

            outputs_dict = cast(dict[str, list[dict[str, Any]]], transaction_dict["outputs"])
            if len(outputs_dict) != 1:
                raise DPPRemoteException("Only 'native' entries should be in "
                    f"'mode.ef63d9775da5.choiceID0.transactions[{i}].outputs'")

            if "native" not in outputs_dict or type(outputs_dict["native"]) is not list:
                raise DPPRemoteException("Missing list typed key "
                    f"'mode.ef63d9775da5.choiceID0.transactions[{i}].outputs[{j}].native'")

            outputs: list[XTxOutput] = []
            for j, output_dict in enumerate(outputs_dict["native"]):
                if type(output_dict) is not dict:
                    raise DPPRemoteException("Missing object typed key "
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].outputs.native[{j}]'")

                if "amount" not in output_dict or type(output_dict["amount"]) is not int:
                    raise DPPRemoteException("Missing int typed key "
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].outputs.native[{j}]"
                        ".amount'")
                value = output_dict["amount"]

                if "script" not in output_dict or type(output_dict["script"]) is not str:
                    raise DPPRemoteException("Missing string typed key "
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].outputs.native[{j}]"
                        ".script'")
                script_hex = output_dict["script"]
                try:
                    script = Script.from_hex(script_hex)
                except ValueError:
                    raise DPPRemoteException("Key "
                        f"'mode.ef63d9775da5.choiceID0.transactions[{i}].outputs.native[{j}]"
                        ".script' is not valid hex")

                # NOTE(rt12) This is someone else's payment script. We do not care what it is,
                #     they asked to be paid to it and we will do as requested. It should not be
                #     expected that we will recognise the template.

                # from .standards.script_templates import classify_transaction_output_script
                # script_type, threshold, output = classify_transaction_output_script(script)

                outputs.append(XTxOutput(value=value, # type: ignore[call-arg]
                    script_pubkey=script))
            locktime = policies_dict.get("lockTime", 0) if policies_dict is not None else 0
            transactions.append(Transaction.from_io(inputs, outputs, locktime=locktime))

        if 'creationTimestamp' not in payment_terms or \
                type(payment_terms['creationTimestamp']) is not int:
            raise DPPRemoteException("Missing int typed key 'creationTimestamp'")

        expiration_timestamp = payment_terms.get('expirationTimestamp')
        if expiration_timestamp is not None and type(expiration_timestamp) is not int:
            raise DPPRemoteException("Optional key not int typed 'expirationTimestamp'")

        memo = payment_terms.get("memo")
        if memo is not None and type(memo) is not str:
            raise DPPRemoteException("Optional key not string typed 'memo'")

        payment_url = payment_terms.get('paymentUrl')
        if payment_url is not None and type(payment_url) is not str:
            raise DPPRemoteException("Optional key not string typed 'paymentUrl'")

        creation_timestamp = payment_terms['creationTimestamp']
        return cls(transactions, transaction_policies, network, payment_terms['version'],
            creation_timestamp=creation_timestamp, expiration_timestamp=expiration_timestamp,
            memo=memo, payment_url=payment_url, raw_json=s)

    def to_json(self) -> str:
        # This code is called if we are the payer and the invoice is beign written to the database.
        if self._raw_json is not None:
            return self._raw_json

        assert self.payment_url is not None

        # TODO(nocheckin) Payments. This should be the thing containing transactions and so on.
        transaction_list: list[HybridModeTransactionTermsDict] = []
        modes: PaymentTermsModes = {
            "ef63d9775da5": {
                "choiceID0": {
                    "transactions": transaction_list,
                }
            },
        }

        # TODO: This should be a TypedDict.
        payment_terms_dict: PaymentTermsDict = {
            "network": self.network,
            "version": "1.0",
            "creationTimestamp": self.creation_timestamp,
            "paymentUrl": self.payment_url,
            "modes": modes,
        }
        if self.expiration_timestamp is not None:
            payment_terms_dict['expirationTimestamp'] = self.expiration_timestamp
        if self.memo is not None:
            payment_terms_dict["memo"] = self.memo
        if self.beneficiary:
            payment_terms_dict['beneficiary'] = self.beneficiary
        return json.dumps(payment_terms_dict)

    def has_expired(self) -> bool:
        return is_inv_expired(self.expiration_timestamp)

    def get_amount(self) -> int:
        payment_value = 0
        for transaction in self.transactions:
            # These are expected to be inputs provided by the payee.
            for input in transaction.inputs:
                assert input.value is not None
                payment_value -= input.value
            for output in transaction.outputs:
                payment_value += output.value
        return payment_value

    def get_id(self) -> int|None:
        return self._id

    def set_id(self, invoice_id: int) -> None:
        self._id = invoice_id


class PaymentMessage:
    MAXIMUM_JSON_LENGTH = 10 * 1000 * 1000

    def __init__(self, transactions: list[Transaction], memo: str|None=None) -> None:
        # TODO(nocheckin) Payments. We should check locktime and input finality.
        assert all(tx.is_complete() for tx in transactions)
        self.transactions = transactions
        self.memo = memo

    @classmethod
    def from_json(cls, s: str) -> PaymentMessage:
        """
        This function takes a serialised payment message and deserialises it.

        WARNING: This expects to be called only for payments paying us, not payments we constructed
            and sent or intended to send as the payer. As such it bakes in our expectations in terms
            of the payment structure.

        Raises `DPPRemoteException` when the deserialised text is incorrect in some way. The
            specific error message is not for direct display to the user but should be relayable
            in some way to the payer
        """
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise DPPRemoteException("Invalid payment, too large")
        data = json.loads(s)
        if "modeId" not in data or type(data["modeId"]) is not str:
            raise DPPRemoteException("Missing string typed key 'modeId'")
        if "mode" not in data or type(data["mode"]) is not dict:
            raise DPPRemoteException("Missing object typed 'mode' field")

        mode_id = data["modeId"]
        if mode_id != HYBRID_PAYMENT_MODE_BRFCID:
            raise DPPRemoteException(f"'{HYBRID_PAYMENT_MODE_BRFCID}' expected in 'modeId'")

        originator = data.get('originator')
        if originator is not None and type(originator) is not dict:
            raise DPPRemoteException("Invalid key 'originator'")

        # This should
        mode = data["mode"]

        if "optionId" not in mode or type(mode["optionId"]) is not str:
            raise DPPRemoteException("Missing list typed key 'mode.optionId'")
        if "choiceID0" != mode["optionId"]:
            raise DPPRemoteException("'choiceID0' expected in 'mode.optionId'")

        if "transactions" not in mode or type(mode["transactions"]) is not list:
            raise DPPRemoteException("Missing list typed key 'mode.transactions'")

        ancestors: dict[str, Any]|None = None
        # NOTE(rt12) DPP proxy de/reserialises the payment message injecting a `null` if missing.
        if "ancestors" in mode and mode["ancestors"] is not None:
            if type(mode["ancestors"]) is not dict:
                raise DPPRemoteException("Invalid object typed key 'mode.ancestors'")
            # TODO(nocheckin) Payments. Validate ancestors.
            ancestors = cast(dict[str, Any], mode["ancestors"])

        # TODO(nocheckin) Payments. We need to validate that these match our requirements! But in
        #     the caller, not here.

        memo = data.get("memo")
        if memo is not None and type(memo) is not str:
            raise DPPRemoteException("Invalid json 'memo' field")

        transaction_list = mode["transactions"]
        if len(transaction_list) < 1:
            raise DPPRemoteException("Missing entries for key 'mode.transactions'")

        transactions: list[Transaction] = []
        for i, transaction_hex in enumerate(transaction_list):
            if type(transaction_hex) is not str:
                raise DPPRemoteException(f"Missing string typed value 'mode.transactions[{i}]'")

            try:
                tx = Transaction.from_hex(transaction_hex)
            except ValueError:
                raise DPPRemoteException(f"Incorrect transaction hex in 'mode.transactions[{i}]'")
            transactions.append(tx)
        return cls(transactions, memo)

    def to_json(self) -> str:
        """
        This function serialised this payment message as JSON.

        WARNING: This expects to be called only for payments we are making to a payee, not payments
            we have received from a payer. As such it bakes in our expectations in terms of the
            payment structure.

        Raises nothing.
        """
        data: PaymentDict = {
            "modeId": HYBRID_PAYMENT_MODE_BRFCID,
            "mode": {
                "optionId": "choiceID0",
                "transactions": [ tx.to_hex() for tx in self.transactions ],
                # TODO(nocheckin) Payments. Ancestors if payee requests otherwise we don't give it.
                #'ancestors': <TSCAncestors>.to_json() - if SPVRequired
            },
            "memo": self.memo
            # 'originator': None  # optional
            # 'transaction': self.transaction_hex  # DEPRECATED as per TSC spec.
        }
        if self.memo:
            data["memo"] = self.memo
        return json.dumps(data)


class PaymentACKMessage:
    MAXIMUM_JSON_LENGTH = 11 * 1000 * 1000

    def __init__(self, mode_id: str, mode: HybridModePaymentACKDict,
            redirect_url: str | None = None) -> None:
        self.mode_id = mode_id
        self.mode = mode
        self.redirect_url = redirect_url

    def to_json(self) -> str:
        data = PaymentACKDict(
            modeId=self.mode_id,
            mode=self.mode,
            redirectUrl=self.redirect_url
        )
        return json.dumps(data)

    @classmethod
    def from_json(cls, s: bytes | str) -> PaymentACKMessage:
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise DPPException("Invalid payment ACK, too large")
        data = cast(PaymentACKDict, json.loads(s))
        mode_id = data.get("modeId")
        if mode_id is None:
            raise DPPException("'modeId' field is required")

        if mode_id is not None and mode_id != HYBRID_PAYMENT_MODE_BRFCID:
            raise DPPException(f"Invalid json 'modeId' field: {mode_id}")

        mode = data.get("mode")
        if mode is None:
            raise DPPException("'mode' field is required")

        if mode is not None and type(mode) is not dict:
            raise DPPException("Invalid json 'mode' field")

        redirect_url = data.get('redirectUrl')
        if redirect_url is not None and type(redirect_url) is not str:
            raise DPPException("Invalid json 'redirectUrl' field")

        assert mode_id is not None
        assert mode is not None
        return cls(mode_id, mode, redirect_url=redirect_url)


def get_payment_terms(url: str, declared_receiver_address: Address) -> PaymentTermsMessage:
    u = urllib.parse.urlparse(url)
    if u.scheme not in ['http', 'https']:
        raise DPPLocalException(_("Not a recognisable payment URL"))

    try:
        response = requests.request('GET', url, headers=REQUEST_HEADERS)
    except requests.exceptions.RequestException:
        # NOTE(technical-debt) This is terrible. We should know why this happens and present it in
        #     a way that does not look like technobabble to the user. -- rt12
        #     - Comment "`requests.request` raises `RequestException` when <some reason> or
        #       <some other reason>"" and custom exception with specific user presentable reason
        #       for each case.
        raise DPPLocalException(_("The payment URL does not point to a working payment server"))

    try:
        response.raise_for_status()
        # Guard against `bitcoin:`-URIs with invalid payment request URLs
        contentType = response.headers.get("Content-Type", "")
        if "application/json" not in contentType:
            logger.debug("Failed payment request, content type '%s'", contentType)
            raise DPPLocalException(_("The payment URL does not point to a working payment server"))

        data = cast(dict[str, Any], response.json())
        logger.debug("Fetched payment request '%s'", url)
    except requests.exceptions.RequestException:
        # NOTE(technical-debt) This is terrible. We should know why this happens and present it in
        #     a way that does not look like technobabble to the user. -- rt12
        #     - We do not know which method is raising, we should guard specific methods for the
        #       exceptions they raise not group them into exception stew.
        raise DPPRemoteException(response.content.decode())

    envelope_data = cast(JSONEnvelope, data)
    try:
        validate_json_envelope(envelope_data, { "application/json" })
    except ValueError as value_error:
        raise DPPRemoteException(value_error.args[0])

    received_public_key_hex = envelope_data["publicKey"]
    received_signature = envelope_data["signature"]
    if received_public_key_hex is None or received_signature is None:
        raise DPPLocalException(_("The payment terms are unsigned"))

    # While the above validation checks the included public key signed the payment terms, we
    # need to use the payee's address included in the invoice URL is the same as that public key.
    # This ensures the payment terms come from the same party we got the invoice URL.
    received_public_key = PublicKey.from_hex(received_public_key_hex)
    if declared_receiver_address != received_public_key.to_address(compressed=True):
        raise DPPLocalException(_("The payment terms were signed by an unknown party"))

    payload_text = cast(str, data["payload"])
    return PaymentTermsMessage.from_json(payload_text)
