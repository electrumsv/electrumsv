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

import json
from typing import Any, cast, List, Optional, Dict, TYPE_CHECKING, Union, TypedDict
import urllib.parse

from bitcoinx import Script
import requests

from .bip276 import bip276_encode, BIP276Network, PREFIX_BIP276_SCRIPT, bip276_decode
from .exceptions import Bip270Exception
from .i18n import _
from .logs import logs
from .networks import Net, SVScalingTestnet, SVTestnet, SVMainnet, SVRegTestnet
from .transaction import XTxOutput
from .util import get_posix_timestamp
from .wallet_database.types import PaymentRequestReadRow
from .web import parse_URI

if TYPE_CHECKING:
    from electrumsv.wallet import AbstractAccount

logger = logs.get_logger("paymentrequest")

# NOTE: This now follows the TSC spec for the Direct Payment Protocol:
# https://tsc.bitcoinassociation.net/standards/direct_payment_protocol/

# BIP 273 - Use "Accept" header for response type negotiation with Simplified Payment Request URLs
# https://github.com/electrumsv/bips/blob/master/bip-0273.mediawiki
REQUEST_HEADERS = {
    'Accept': 'application/bitcoinsv-paymentrequest',
    'User-Agent': 'ElectrumSV'
}

ACK_HEADERS = {
    'Content-Type': 'application/bitcoinsv-payment',
    'Accept': 'application/bitcoinsv-paymentack',
    'User-Agent': 'ElectrumSV'
}

# BIP 270 - Simplified Payment Protocol
# https://github.com/electrumsv/bips/blob/master/bip-0270.mediawiki

def has_expired(expiration_timestamp: Optional[int]=None) -> bool:
    return expiration_timestamp is not None and expiration_timestamp < get_posix_timestamp()


HYBRID_PAYMENT_MODE_BRFCID = "ef63d9775da5"


# DPP Message Types as per the TSC spec.
class PeerChannel(TypedDict):
    host: str
    token: str
    channelid: str


class PeerChannelsDPP(TypedDict):
    peerChannel: dict


class TransactionDPP(TypedDict):
    outputs: dict
    policies: dict


class HybridPaymentModeStandardDPP(TypedDict):
    optionId: str
    transactions: list[TransactionDPP]
    ancestors: Optional[dict]


class HybridPaymentModeDPP(TypedDict):
    # i.e. { HYBRID_PAYMENT_MODE_BRFCID: HybridPaymentModeStandard }
    ef63d9775da5: HybridPaymentModeStandardDPP


class PaymentDPP(TypedDict):
    modeId: str  # i.e. HYBRID_PAYMENT_MODE_BRFCID
    mode: HybridPaymentModeDPP
    originator: Optional[dict]
    transaction: Optional[str]  # DEPRECATED as per TSC spec.
    memo: Optional[str]  # Optional


class PaymentTermsDPP(TypedDict):
    network: str
    version: str
    creationTimestamp: int
    expirationTimestamp: int
    memo: str
    paymentURL: str
    beneficiary: Optional[dict]
    modes: HybridPaymentModeDPP
    # for backwards compatibility:
    outputs: list
    merchantData: Optional[dict]


class PaymentACKDPP(TypedDict):
    modeId: str
    mode: HybridPaymentModeDPP
    peerChannel: PeerChannel
    redirectUrl: Optional[str]



class Output:
    def __init__(self, script: Script, amount: Optional[int]=None,
                 description: Optional[str]=None):
        self.script = script
        if description is not None:
            description_json = json.dumps(description)
            if len(description_json) > 100:
                raise Bip270Exception("Output description too long")
        self.description = description
        self.amount = amount

    def to_tx_output(self) -> XTxOutput:
        # NOTE(rt12) This seems to be some attrs/mypy clash, the base class attrs should come before
        # the XTxOutput attrs, but typing expects these to be the XTxOutput attrs.
        return XTxOutput(self.amount, self.script) # type: ignore

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Output':
        if 'script' not in data:
            raise Bip270Exception("Missing required 'script' field")
        script_hex = data['script']

        amount = data.get('amount')
        if amount is not None and type(amount) is not int:
            raise Bip270Exception("Invalid 'amount' field")

        description = data.get('description')
        if description is not None and type(description) is not str:
            raise Bip270Exception("Invalid 'description' field")

        return cls(Script.from_hex(script_hex), amount, description)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            'script': self.script.to_hex(),
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


class PaymentRequest:
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
            expiration_timestamp: Optional[int]=None, memo: Optional[str]=None,
            beneficiary: Optional[dict]=None, payment_url: Optional[str]=None,
            merchant_data: Optional[str]=None,
            hybrid_payment_data: Optional[HybridPaymentModeDPP]=None) -> None:
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
    def from_wallet_entry(cls, account: 'AbstractAccount',
            pr: PaymentRequestReadRow) -> 'PaymentRequest':
        wallet = account.get_wallet()
        keyinstance = wallet.data.read_keyinstance(keyinstance_id=pr.keyinstance_id)
        assert keyinstance is not None
        script_type = account.get_default_script_type()
        script = account.get_script_for_derivation(script_type, keyinstance.derivation_type,
            keyinstance.derivation_data2)
        date_expiry = None
        if pr.expiration is not None:
            date_expiry = pr.date_created + pr.expiration
        outputs = [ Output(script, pr.requested_value) ]
        return cls(outputs, pr.date_created, date_expiry, pr.description)

    @classmethod
    def from_json(cls, s: Union[bytes, str]) -> 'PaymentRequest':
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise Bip270Exception(_("Payment request oversized"))

        d = cast(PaymentTermsDPP, json.loads(s))

        network = d.get('network')
        if network not in (cls.DPP_NETWORK_REGTEST, cls.DPP_NETWORK_TESTNET, cls.DPP_NETWORK_STN,
                cls.DPP_NETWORK_MAINNET):
            raise Bip270Exception(_("Invalid network '{}'").format(network))

        if 'version' not in d:
            raise Bip270Exception(_("version field missing"))

        if 'outputs' in d:
            raise Bip270Exception(_("The 'outputs' field is now deprecated in favour of "
                                    "HybridPaymentMode: see DPP TSC spec."))
        if 'modes' not in d:
            raise Bip270Exception(_("Payment details missing"))

        if 'ef63d9775da5' not in d['modes']:
            raise Bip270Exception(_("modes section must include standard mode: 'ef63d9775da5'"))

        if type(d['modes']['ef63d9775da5']) is not dict:
            raise Bip270Exception(_("Corrupt payment details"))

        # For the time being we only accept 'native' outputs and only a single
        # choice - i.e. "choiceID0" to avoid too much up-front-complexity
        if 'choiceID0' not in d['modes']['ef63d9775da5'] or \
                'transactions' not in d['modes']['ef63d9775da5']['choiceID0']:
            raise Bip270Exception(_("choiceID0 field is required by ElectrumSV, outputs must "
                                    "be native type and policies field must contain a valid "
                                    "mAPI fee quote"))

        transactions = cast(list[TransactionDPP],
            d['modes']['ef63d9775da5']['choiceID0']['transactions'])
        for tx in transactions:
            for output in tx['outputs']:
                if 'native' not in output:
                    raise Bip270Exception(_("Only native type outputs are accepted at this time"))

            if 'fees' not in tx['policies'] or 'SPVRequired' not in tx['policies']:
                    raise Bip270Exception(_("policies field must contain 'fees' and 'SPVRequired' "
                                            "fields"))

        if len(transactions) > 1:
            raise Bip270Exception("ElectrumSV can currently only handle 1 transaction at a time. "
                                  "This Payment Request contains multiple transaction requests")
        outputs = []
        for ui_dict in transactions[0]['outputs']['native']:
            outputs.append(Output.from_dict(ui_dict))

        pr = cls(outputs=outputs, version=d['version'])
        # We preserve the network we were given as maybe it is HandCash's non-standard "bitcoin"
        pr.network = network

        pr.hybrid_payment_data = d['modes'][HYBRID_PAYMENT_MODE_BRFCID]

        if 'creationTimestamp' not in d:
            raise Bip270Exception(_("Creation time missing"))
        creation_timestamp = d['creationTimestamp']
        if type(creation_timestamp) is not int:
            raise Bip270Exception(_("Corrupt creation time"))
        pr.creation_timestamp = creation_timestamp

        expiration_timestamp = d.get('expirationTimestamp')
        if expiration_timestamp is not None and type(expiration_timestamp) is not int:
            raise Bip270Exception(_("Corrupt expiration time"))
        pr.expiration_timestamp = expiration_timestamp

        memo = d.get('memo')
        if memo is not None and type(memo) is not str:
            raise Bip270Exception(_("Corrupt memo"))
        pr.memo = memo

        payment_url = d.get('paymentURL')
        if payment_url is not None and type(payment_url) is not str:
            raise Bip270Exception(_("Corrupt payment URL"))
        pr.payment_url = payment_url

        # NOTE: payd wallet returns a nested json dictionary but technically the BIP270 spec.
        # states this must be a string up to 10000 characters long.
        merchant_data = d.get('merchantData')
        if merchant_data is not None and type(merchant_data) is not str:
            raise Bip270Exception(_("Corrupt merchant data"))
        pr.merchant_data = merchant_data

        return pr

    def to_json(self) -> str:
        # TODO: This should be a TypedDict.
        d: Dict[str, Any] = {}
        d['network'] = self.network
        d['version'] = self.version
        d['creationTimestamp'] = self.creation_timestamp
        if self.expiration_timestamp is not None:
            d['expirationTimestamp'] = self.expiration_timestamp
        if self.memo is not None:
            d['memo'] = self.memo
        if self.payment_url is not None:
            d['paymentURL'] = self.payment_url
        if self.beneficiary:
            d['beneficiary'] = self.beneficiary
        d['modes'] = self.hybrid_payment_data
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
        elif isinstance(Net._net, SVRegTestnet):
            network = BIP276Network.NETWORK_REGTEST
        else:
            raise Exception("unhandled network", Net._net)
        return bip276_encode(PREFIX_BIP276_SCRIPT, bytes(self.outputs[0].script), network)

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

    def send_payment(self, account: 'AbstractAccount', transaction_hex: str) -> bool:
        self.error = None

        if not self.payment_url:
            self.error = _("No URL")
            return False

        payment_memo = "Paid using ElectrumSV"
        payment = Payment(transaction_hex, payment_memo)

        parsed_url = parse_URI(self.payment_url)
        if not parsed_url:
            raise Bip270Exception("Failed to parse payment uri to send payment")

        logger.debug(f"Parsed url contents: {parsed_url}")
        response = self._make_request(parsed_url['r'], payment.to_json())
        if response.get_status_code() not in (200, 201, 202):
            # Propagate 'Bad request' (HTTP 400) messages to the user since they
            # contain valuable information.
            if response.get_status_code() == 400:
                self.error = f"{response.get_reason()}: {response.get_content().decode('UTF-8')}"
                return False
            # Some other errors might display an entire HTML document.
            # Hide those and just display the name of the error code.
            self.error = response.get_reason()
            return False

        ack_json = response.get_content()
        ack_data = json.loads(ack_json)

        # Handcash response.
        # https://handcash.github.io/handcash-merchant-integration/#/merchant-payments?id=examples
        if "success" in ack_data and ack_data["success"] is True:
            return True

        # BIP270 response.
        try:
            payment_ack = PaymentACK.from_json(ack_json)
        except Bip270Exception as e:
            self.error = e.args[0]
            return False

        logger.debug("PaymentACK message received: %s", payment_ack.to_json())
        return True

    # The following function and classes is abstracted to allow unit testing.
    def _make_request(self, url: str, message: str) -> "_RequestsResponseWrapper":
        r = requests.post(url, data=message, headers=ACK_HEADERS)
        return self._RequestsResponseWrapper(r)

    class _RequestsResponseWrapper:
        def __init__(self, response: requests.Response) -> None:
            self._response = response

        def get_status_code(self) -> int:
            return self._response.status_code

        def get_reason(self) -> str:
            return self._response.reason

        def get_content(self) -> bytes:
            return self._response.content


class Payment:
    """See PaymentDPP type above for json format
    At present ElectrumSV can strictly only handle a single transaction and the standard
    HYBRID_PAYMENT_MODE_BRFCID = "ef63d9775da5". And only for * native * type outputs.
    """
    MAXIMUM_JSON_LENGTH = 10 * 1000 * 1000

    def __init__(self, transaction_hex: str, memo: Optional[str]=None) -> None:
        self.transaction_hex = transaction_hex
        self.memo = memo

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Payment':
        if 'transaction' in data:
            transaction_hex = data['transaction']
            if type(transaction_hex) is not str:
                raise Bip270Exception("Invalid json 'transaction' field")
        else:
            raise Bip270Exception("Missing required json 'transaction' field")

        memo = data.get('memo')
        if memo is not None and type(memo) is not str:
            raise Bip270Exception("Invalid json 'memo' field")

        return cls(transaction_hex, memo)

    def to_dict(self) -> PaymentDPP:
        option_id = HYBRID_PAYMENT_MODE_BRFCID
        transactions = [self.transaction_hex]
        ancestors = None

        standard_payment_mode_data = HybridPaymentModeStandardDPP(optionId=option_id,
            transactions=transactions, ancestors=ancestors)

        data = cast(PaymentDPP, {
            'modeId': HYBRID_PAYMENT_MODE_BRFCID,
            'mode': {HYBRID_PAYMENT_MODE_BRFCID: standard_payment_mode_data},
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

    def __init__(self, mode_id: str, mode: HybridPaymentModeDPP, peer_channel_info: PeerChannel,
            redirect_url: Optional[str]) -> None:
        self.mode_id = mode_id
        self.mode = mode
        self.peer_channel_info = peer_channel_info
        self.redirect_url = redirect_url

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            'modeId': self.mode_id,
            'mode': self.mode,
            'peerChannel': self.peer_channel_info,
            'redirectUrl': self.redirect_url
        }
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PaymentACK':
        mode_id = data.get('modeId')
        if mode_id is None:
            raise Bip270Exception("'modeId' field is required")

        if mode_id is not None and mode_id != HYBRID_PAYMENT_MODE_BRFCID:
            raise Bip270Exception(f"Invalid json 'modeId' field: {mode_id}")

        mode = data.get('mode')
        if mode is None:
            raise Bip270Exception("'mode' field is required")

        if mode is not None and type(mode) is not dict:
            raise Bip270Exception("Invalid json 'mode' field")

        peer_channel_info = data.get('peerChannel')
        if peer_channel_info is None:
            raise Bip270Exception("'peerChannel' field is required")
        if mode_id is not None and type(peer_channel_info) is not dict:
            raise Bip270Exception("Invalid json 'peerChannel' field")

        redirect_url = data.get('redirectUrl')
        if redirect_url is not None and type(redirect_url) is not str:
            raise Bip270Exception("Invalid json 'redirectUrl' field")

        assert mode_id is not None
        assert mode is not None
        assert peer_channel_info is not None
        return cls(mode_id, mode, peer_channel_info, redirect_url=redirect_url)

    def to_json(self) -> str:
        data = self.to_dict()
        return json.dumps(data)

    @classmethod
    def from_json(cls, s: Union[bytes, str]) -> 'PaymentACK':
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise Bip270Exception("Invalid payment ACK, too large")
        data = cast(PaymentACKDPP, json.loads(s))
        return cls.from_dict(data)


def get_payment_request(url: str) -> PaymentRequest:
    error = None
    response = None
    data: Any = None
    u = urllib.parse.urlparse(url)
    if u.scheme in ['http', 'https']:
        try:
            response = requests.request('GET', url, headers=REQUEST_HEADERS)
            response.raise_for_status()
            # Guard against `bitcoin:`-URIs with invalid payment request URLs
            contentType = response.headers.get("Content-Type", "")
            if "application/json" not in contentType:
                logger.debug("Failed payment request, content type '%s'", contentType)
                data = None
                error = "payment URL not pointing to a bitcoinSV payment request handling server"
            else:
                data = response.content
            logger.debug('fetched payment request \'%s\' (%d)', url, len(response.content))
        except requests.exceptions.RequestException:
            data = None
            if response is not None:
                error = response.content.decode()
            else:
                error = "payment URL not pointing to a valid server"
    elif u.scheme == 'file':
        try:
            with open(u.path, 'r', encoding='utf-8') as f:
                data = f.read()
        except IOError:
            data = None
            error = "payment URL not pointing to a valid file"
    else:
        error = f"unknown scheme {url}"

    if error:
        raise Bip270Exception(error)

    return PaymentRequest.from_json(data)
