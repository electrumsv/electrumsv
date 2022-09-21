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
from typing import Any, cast, List, Optional, Dict, TYPE_CHECKING, Union, TypedDict
import types
import urllib.parse

from bitcoinx import Address, PublicKey, Script
import requests

from .bip276 import bip276_encode, BIP276Network, PREFIX_BIP276_SCRIPT
from .exceptions import Bip270Exception
from .i18n import _
from .logs import logs
from .networks import Net, SVScalingTestnet, SVTestnet, SVMainnet, SVRegTestnet
from .standards.json_envelope import JSONEnvelope, validate_json_envelope
from .transaction import XTxOutput
from .util import get_posix_timestamp
from .wallet_database.types import PaymentRequestRow, PaymentRequestOutputRow

if TYPE_CHECKING:
    from electrumsv.wallet import AbstractAccount

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

def has_expired(expiration_timestamp: Optional[int]=None) -> bool:
    return expiration_timestamp is not None and expiration_timestamp < get_posix_timestamp()


HYBRID_PAYMENT_MODE_BRFCID = "ef63d9775da5"


# DPP Message Types as per the TSC spec.
class PeerChannelDict(TypedDict):
    host: str
    token: str
    channel_id: str


class PeerChannelsDict(TypedDict):
    peerChannel: dict[str, Any]


class TransactionDict(TypedDict):
    outputs: dict[Any, Any]
    inputs: dict[str, Any] | None
    policies: dict[str, Any] | None


class HybridPaymentModeStandardDict(TypedDict):
    optionId: str
    transactions: list[TransactionDict]
    ancestors: dict[str, Any] | None


class HybridPaymentModeDict(TypedDict):
    # i.e. { HYBRID_PAYMENT_MODE_BRFCID: HybridPaymentModeStandard }
    ef63d9775da5: dict[str, HybridPaymentModeStandardDict]


class PaymentDict(TypedDict):
    modeId: str  # i.e. HYBRID_PAYMENT_MODE_BRFCID
    # TODO(1.4.0) DPP. - this is actually wrong. "mode" here differs from the PR
    mode: HybridPaymentModeDict
    originator: dict[str, Any] | None
    transaction: Optional[str]  # DEPRECATED as per TSC spec.
    memo: Optional[str]  # Optional


class PaymentTermsDict(TypedDict):
    network: str
    version: str
    creationTimestamp: int
    expirationTimestamp: int
    memo: str
    paymentUrl: str
    beneficiary: dict[str, Any] | None
    modes: HybridPaymentModeDict
    merchantData: dict[str, Any] | None


class PaymentACKDict(TypedDict):
    modeId: str
    # TODO(1.4.0) DPP. - this is actually wrong. "mode" here differs from the PR
    mode: HybridPaymentModeDict
    peerChannel: PeerChannelDict
    redirectUrl: str | None
    memo: str | None
    error: int | None


class Output:
    def __init__(self, script_bytes: bytes, amount: int|None=None,
            description: str|None=None) -> None:
        self.script_bytes = script_bytes
        if description is not None:
            description_json = json.dumps(description)
            if len(description_json) > 100:
                raise Bip270Exception("Output description too long")
        self.description = description
        self.amount = amount

    def to_tx_output(self) -> XTxOutput:
        script = Script(self.script_bytes)
        # NOTE(rt12) This seems to be some attrs/mypy clash, the base class attrs should come before
        # the XTxOutput attrs, but typing expects these to be the XTxOutput attrs.
        return XTxOutput(self.amount, script) # type: ignore

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Output':
        if 'script' not in data:
            raise Bip270Exception("Missing required 'script' field")
        script_hex = data['script']

        amount = data.get('amount')
        if amount is not None and type(amount) is not int:
            raise Bip270Exception("Invalid 'amount' field")

        description = data.get('description')
        if description is not None and type(description) is not str:
            raise Bip270Exception("Invalid 'description' field")

        return cls(bytes.fromhex(script_hex), amount, description)

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            'script': self.script_bytes.hex(),
        }
        if self.amount and type(self.amount) is int:
            data['amount'] = self.amount
        if self.description:
            data['description'] = self.description
        return data

    @classmethod
    def from_json(cls, s: str) -> 'Output':
        data = json.loads(s)
        return cls.from_dict(data)

    def to_json(self) -> str:
        data = self.to_dict()
        return json.dumps(data)


class PaymentTerms:
    HANDCASH_NETWORK = "bitcoin"
    BIP270_NETWORK = "bitcoin-sv"

    # See: https://tsc.bitcoinassociation.net/standards/direct_payment_protocol/#Specification
    DPP_NETWORK_REGTEST = "regtest"
    DPP_NETWORK_TESTNET = "testnet"
    DPP_NETWORK_STN = "stn"
    DPP_NETWORK_MAINNET = "mainnet"

    MAXIMUM_JSON_LENGTH = 10 * 1000 * 1000

    error: Optional[str] = None

    def __init__(self, outputs: List[Output], version: str, creation_timestamp: Optional[int]=None,
            expiration_timestamp: int | None=None, memo: str | None=None,
            beneficiary: dict[str, Any] | None=None, payment_url: str | None=None,
            merchant_data: str | None=None,
            hybrid_payment_data: dict[str, HybridPaymentModeStandardDict] | None=None) -> None:
        # This is only used if there is a requestor identity (old openalias, needs rewrite).
        self._id: Optional[int] = None
        self.tx = None

        self.network = self.DPP_NETWORK_REGTEST
        self.version = version
        self.outputs = outputs
        self.hybrid_payment_data = hybrid_payment_data
        if creation_timestamp is not None:
            creation_timestamp = int(creation_timestamp)
        else:
            creation_timestamp = get_posix_timestamp()
        self.creation_timestamp = creation_timestamp
        if expiration_timestamp is not None:
            expiration_timestamp = int(expiration_timestamp)
        self.expiration_timestamp = expiration_timestamp
        self.memo = memo
        self.beneficiary = beneficiary
        self.payment_url = payment_url
        self.merchant_data = merchant_data

    def __str__(self) -> str:
        return self.to_json()

    @classmethod
    def from_wallet_entry(cls, request_row: PaymentRequestRow,
            request_output_rows: list[PaymentRequestOutputRow]) -> PaymentTerms:
        outputs = [ Output(request_output_row.output_script_bytes,
            request_output_row.output_value) for request_output_row in request_output_rows ]
        return cls(outputs, "1.0", creation_timestamp=request_row.date_created,
            expiration_timestamp=request_row.date_expires, memo=request_row.merchant_reference)

    @classmethod
    def from_json(cls, s: Union[bytes, str]) -> PaymentTerms:
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise Bip270Exception(_("Payment request oversized"))

        payment_terms = cast(PaymentTermsDict, json.loads(s))

        network = payment_terms.get('network')
        if network not in (cls.DPP_NETWORK_REGTEST, cls.DPP_NETWORK_TESTNET, cls.DPP_NETWORK_STN,
                cls.DPP_NETWORK_MAINNET):
            raise Bip270Exception(_("Invalid network '{}'").format(network))

        if 'version' not in payment_terms:
            raise Bip270Exception(_("version field missing"))

        if 'outputs' in payment_terms:
            raise Bip270Exception(_("The 'outputs' field is now deprecated in favour of "
                                    "HybridPaymentMode: see DPP TSC spec."))
        if 'modes' not in payment_terms:
            raise Bip270Exception(_("Payment details missing"))

        if 'ef63d9775da5' not in payment_terms['modes']:
            raise Bip270Exception(_("modes section must include standard mode: 'ef63d9775da5'"))

        payment_modes = payment_terms['modes']['ef63d9775da5']
        if not isinstance(payment_modes, dict):
            raise Bip270Exception(_("Corrupt payment details"))

        # For the time being we only accept 'native' outputs and only a single
        # choice - i.e. "choiceID0" to avoid too much up-front-complexity
        if 'choiceID0' not in payment_modes:
            raise Bip270Exception(_("choiceID0 field is required by ElectrumSV, outputs must "
                                    "be native type and policies field must contain a valid "
                                    "mAPI fee quote"))

        choice0_payment_mode = payment_modes['choiceID0']
        if 'transactions' not in choice0_payment_mode:
            raise Bip270Exception(_("choiceID0 field is required by ElectrumSV, outputs must "
                                    "be native type and policies field must contain a valid "
                                    "mAPI fee quote"))

        transactions = choice0_payment_mode['transactions']
        for tx in transactions:
            for output in tx['outputs']:
                if 'native' not in output:
                    raise Bip270Exception(_("Only native type outputs are accepted at this time"))

            tx_policies = tx['policies']
            assert tx_policies is not None
            if 'fees' not in tx_policies or 'SPVRequired' not in tx_policies:
                tx_policies['SPVRequired'] = False
                tx_policies['fees'] = None

        if len(transactions) > 1:
            raise Bip270Exception("ElectrumSV can currently only handle 1 transaction at a time. "
                                  "This Payment Request contains multiple transaction requests")
        outputs = []

        for ui_dict in transactions[0]['outputs']['native']:
            outputs.append(Output.from_dict(ui_dict))

        pr = cls(outputs=outputs, version=payment_terms['version'])
        # We preserve the network we were given as maybe it is HandCash's non-standard "bitcoin"
        pr.network = network
        pr.hybrid_payment_data = payment_modes

        if 'creationTimestamp' not in payment_terms:
            raise Bip270Exception(_("Creation time missing"))
        creation_timestamp = payment_terms['creationTimestamp']
        if type(creation_timestamp) is not int:
            raise Bip270Exception(_("Corrupt creation time"))
        pr.creation_timestamp = creation_timestamp
        expiration_timestamp = payment_terms.get('expirationTimestamp')
        if expiration_timestamp is not None and type(expiration_timestamp) is not int:
            raise Bip270Exception(_("Corrupt expiration time"))
        pr.expiration_timestamp = expiration_timestamp

        memo = payment_terms.get('memo')
        if memo is not None and type(memo) is not str:
            raise Bip270Exception(_("Corrupt memo"))
        pr.memo = memo

        payment_url = payment_terms.get('paymentUrl')
        if payment_url is not None and type(payment_url) is not str:
            raise Bip270Exception(_("Corrupt payment URL"))
        pr.payment_url = payment_url

        # NOTE: payd wallet returns a nested json dictionary but technically the BIP270 spec.
        # states this must be a string up to 10000 characters long.
        merchant_data = payment_terms.get('merchantData')
        if not isinstance(merchant_data, (str, types.NoneType)):
            raise Bip270Exception(_("Corrupt merchant data"))
        pr.merchant_data = merchant_data

        return pr

    def to_json(self) -> str:
        # TODO: This should be a TypedDict.
        d: dict[str, Any] = {}
        d['network'] = self.network
        d['version'] = self.version
        d['creationTimestamp'] = self.creation_timestamp
        if self.expiration_timestamp is not None:
            d['expirationTimestamp'] = self.expiration_timestamp
        if self.memo is not None:
            d['memo'] = self.memo
        if self.payment_url is not None:
            d['paymentUrl'] = self.payment_url
        if self.beneficiary:
            d['beneficiary'] = self.beneficiary
        d['modes'] = {HYBRID_PAYMENT_MODE_BRFCID: self.hybrid_payment_data}
        if self.merchant_data is not None:
            d['merchantData'] = self.merchant_data
        return json.dumps(d)

    def is_pr(self) -> bool:
        return self.get_amount() != 0

    def has_expired(self) -> bool:
        return has_expired(self.expiration_timestamp)

    def get_expiration_date(self) -> Optional[int]:
        return self.expiration_timestamp

    def get_amount(self) -> int:
        return sum(cast(int, x.amount) for x in self.outputs)

    def get_address(self) -> str:
        if Net._net is SVMainnet:
            network = BIP276Network.NETWORK_MAINNET
        elif Net._net is SVTestnet:
            network = BIP276Network.NETWORK_TESTNET
        elif Net._net is SVScalingTestnet:
            network = BIP276Network.NETWORK_SCALINGTESTNET
        elif Net._net is SVRegTestnet:
            network = BIP276Network.NETWORK_REGTEST
        else:
            raise Exception("unhandled network", Net._net)
        return bip276_encode(PREFIX_BIP276_SCRIPT, self.outputs[0].script_bytes, network)

    def get_payment_uri(self) -> str:
        assert self.payment_url is not None
        return self.payment_url

    def get_memo(self) -> Optional[str]:
        return self.memo

    def get_id(self) -> Optional[int]:
        return self._id

    def set_id(self, invoice_id: int) -> None:
        self._id = invoice_id

    def get_outputs(self) -> List[XTxOutput]:
        return [output.to_tx_output() for output in self.outputs]


class Payment:
    """See PaymentDPP type above for json format
    At present ElectrumSV can strictly only handle a single transaction and the standard
    HYBRID_PAYMENT_MODE_BRFCID = "ef63d9775da5". And only for * native * type outputs.
    """
    MAXIMUM_JSON_LENGTH = 10 * 1000 * 1000

    def __init__(self, transaction_hex: str, memo: str | None=None) -> None:
        self.transaction_hex = transaction_hex
        self.memo = memo

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Payment':
        if "modeId" in data:
            mode_id = data['modeId']
            if type(mode_id) is not str:
                raise Bip270Exception("Invalid json 'modeId' field")
        else:
            raise Bip270Exception("Missing required json 'modeId' field")

        if "mode" in data:
            mode = data['mode']
            # TODO(1.4.0) DPP. Mode should have a TypedDict and validation should be more extensive
            if type(mode) is not dict:
                raise Bip270Exception("Invalid json 'mode' field")

            transactions = mode['transactions']
            if len(transactions) > 1:
                raise Bip270Exception("Cannot handle multiple transactions at this time")

            transaction_hex = transactions[0]
        else:
            raise Bip270Exception("Missing required json 'mode' field")

        originator = data.get('originator')
        if originator is not None and type(originator) is not dict:
            raise Bip270Exception("Invalid json 'originator' field")

        memo = data.get('memo')
        if memo is not None and type(memo) is not str:
            raise Bip270Exception("Invalid json 'memo' field")

        transaction_deprecated = data.get('transaction')
        if transaction_deprecated is not None and type(transaction_deprecated) is not str:
            raise Bip270Exception("Invalid json the top-level 'transaction' field is deprecated. "
                                  "Use the 'mode' section")

        return cls(transaction_hex, memo)

    def to_dict(self) -> PaymentDict:
        data = cast(PaymentDict, {
            'modeId': HYBRID_PAYMENT_MODE_BRFCID,
            'mode': {
                'transactions': [self.transaction_hex],
                'optionId': 'choiceID01',
                #'ancestors': <TSCAncestors>.to_json() - if SPVRequired
            },
            'memo': self.memo
            # 'originator': None  # optional
            # 'transaction': self.transaction_hex  # DEPRECATED as per TSC spec.
        })
        if self.memo:
            data['memo'] = self.memo
        return data

    @classmethod
    def from_json(cls, s: str) -> 'Payment':
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise Bip270Exception("Invalid payment, too large")
        data = json.loads(s)
        return cls.from_dict(data)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class PaymentACK:
    MAXIMUM_JSON_LENGTH = 11 * 1000 * 1000

    def __init__(self, mode_id: str | None = None, mode: HybridPaymentModeDict | None = None,
            peer_channel_info: PeerChannelDict | None = None, redirect_url: str | None = None,
            memo: str | None = None, error: int | None = None) -> None:
        self.mode_id = mode_id
        self.mode = mode
        self.peer_channel_info = peer_channel_info
        self.redirect_url = redirect_url
        self.memo = memo
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        if self.mode_id:
            data["modeId"] = self.mode_id
        if self.mode:
            data["mode"] = self.mode
        if self.peer_channel_info:
            data["peerChannel"] = self.peer_channel_info
        if self.redirect_url:
            data["redirectUrl"] = self.redirect_url
        if self.memo:
            data["memo"] = self.memo
        if self.error:
            data["error"] = self.error
        return data

    @classmethod
    def from_dict(cls, data: PaymentACKDict) -> PaymentACK:
        mode_id = data.get('modeId')
        if mode_id is not None and mode_id != HYBRID_PAYMENT_MODE_BRFCID:
            raise Bip270Exception(f"Invalid json 'modeId' field: {mode_id}")

        mode = data.get('mode')
        if mode is not None and type(mode) is not dict:
            raise Bip270Exception("Invalid json 'mode' field")

        peer_channel_info = data.get('peerChannel')
        if mode_id is not None and type(peer_channel_info) is not dict:
            raise Bip270Exception("Invalid json 'peerChannel' field")

        redirect_url = data.get('redirectUrl')
        if redirect_url is not None and type(redirect_url) is not str:
            raise Bip270Exception("Invalid json 'redirectUrl' field")

        memo = data.get('memo')
        if memo is not None and type(memo) is not str:
            raise Bip270Exception("Invalid json 'memo' field")

        error = data.get('error')
        if error is not None and type(error) is not int:
            raise Bip270Exception("Invalid json 'error' field")

        assert mode_id is not None
        assert mode is not None
        assert peer_channel_info is not None
        return cls(mode_id, mode, peer_channel_info, redirect_url=redirect_url, memo=memo,
            error=error)

    def to_json(self) -> str:
        data = self.to_dict()
        return json.dumps(data)

    @classmethod
    def from_json(cls, s: Union[bytes, str]) -> PaymentACK:
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise Bip270Exception("Invalid payment ACK, too large")
        data = cast(PaymentACKDict, json.loads(s))
        return cls.from_dict(data)


def get_payment_terms(url: str, declared_receiver_address: Address) -> PaymentTerms:
    u = urllib.parse.urlparse(url)
    if u.scheme not in ['http', 'https']:
        raise Bip270Exception(f"unknown scheme {url}")

    try:
        response = requests.request('GET', url, headers=REQUEST_HEADERS)
    except requests.exceptions.RequestException:
        raise Bip270Exception("payment URL not pointing to a valid server")

    try:
        response.raise_for_status()
        # Guard against `bitcoin:`-URIs with invalid payment request URLs
        contentType = response.headers.get("Content-Type", "")
        if "application/json" not in contentType:
            logger.debug("Failed payment request, content type '%s'", contentType)
            raise Bip270Exception("payment URL not pointing to a bitcoinSV payment request "
                "handling server")

        data = cast(dict[str, Any], response.json())
        logger.debug('fetched payment request \'%s\'', url)
    except requests.exceptions.RequestException:
        raise Bip270Exception(response.content.decode())

    envelope_data = cast(JSONEnvelope, data)
    try:
        validate_json_envelope(envelope_data, { "application/json" })
    except ValueError as value_error:
        raise Bip270Exception(value_error.args[0])

    received_public_key_hex = envelope_data["publicKey"]
    received_signature = envelope_data["signature"]
    if received_public_key_hex is None or received_signature is None:
        raise Bip270Exception("The payment terms are unsigned")

    received_public_key = PublicKey.from_hex(received_public_key_hex)
    if declared_receiver_address != received_public_key.to_address(compressed=True):
        raise Bip270Exception("The payment terms were signed by an unknown party")

    # Because we have checked that the data has a signature and public key, we know that the
    # signature was checked in `validate_json_envelope` and must be valid for our public key.
    payload_text = cast(str, data["payload"])
    return PaymentTerms.from_json(payload_text)
