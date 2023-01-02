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
import time
from typing import Any, List, Optional, Dict, TYPE_CHECKING
import urllib.parse

from .bip276 import bip276_encode, BIP276Network, PREFIX_BIP276_SCRIPT
from bitcoinx import Script
import certifi
import requests

from .exceptions import Bip270Exception
from .i18n import _
from .logs import logs
from .networks import Net, SVScalingTestnet, SVTestnet, SVMainnet, SVRegTestnet
from .transaction import XTxOutput
from .wallet_database.tables import PaymentRequestRow


if TYPE_CHECKING:
    from electrumsv.wallet import DeterministicAccount

logger = logs.get_logger("paymentrequest")

# BIP 273 - Use "Accept" header for response type negotiation with Simplified Payment Request URLs
# https://github.com/moneybutton/bips/blob/master/bip-0273.mediawiki
REQUEST_HEADERS = {
    'Accept': 'application/bitcoinsv-paymentrequest',
    'User-Agent': 'ElectrumSV'
}

ACK_HEADERS = {
    'Content-Type': 'application/bitcoinsv-payment',
    'Accept': 'application/bitcoinsv-paymentack',
    'User-Agent': 'ElectrumSV'
}

# Used for requests.
ca_path = certifi.where()

# BIP 270 - Simplified Payment Protocol
# https://github.com/moneybutton/bips/blob/master/bip-0270.mediawiki

def has_expired(expiration_timestamp: Optional[int]=None) -> bool:
    return expiration_timestamp is not None and expiration_timestamp < int(time.time())


class Output:
    # FIXME: this should either be removed in favour of TxOutput, or be a lighter wrapper
    # around it.

    def __init__(self, script: Script, amount: Optional[int]=None,
                 description: Optional[str]=None):
        self.script = script
        # TODO: Must not have a JSON string length of 100 bytes.
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
    def from_dict(cls, data: dict) -> 'Output':
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
        data = {
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
    MAXIMUM_JSON_LENGTH = 10 * 1000 * 1000

    error: Optional[str] = None

    def __init__(self, outputs, creation_timestamp=None, expiration_timestamp=None, memo=None,
                 payment_url=None, merchant_data=None) -> None:
        # This is only used if there is a requestor identity (old openalias, needs rewrite).
        self._id: Optional[int] = None
        self.tx = None

        self.network = self.BIP270_NETWORK
        self.outputs = outputs
        if creation_timestamp is not None:
            creation_timestamp = int(creation_timestamp)
        else:
            creation_timestamp = int(time.time())
        self.creation_timestamp = creation_timestamp
        if expiration_timestamp is not None:
            expiration_timestamp = int(expiration_timestamp)
        self.expiration_timestamp = expiration_timestamp
        self.memo = memo
        self.payment_url = payment_url
        self.merchant_data = merchant_data

    def __str__(self) -> str:
        return self.to_json()

    @classmethod
    def from_wallet_entry(cls, account: 'DeterministicAccount',
            pr: PaymentRequestRow) -> 'PaymentRequest':
        script = account.get_script_for_id(pr.keyinstance_id)
        date_expiry = None
        if pr.expiration is not None:
            date_expiry = pr.date_created + pr.expiration
        outputs = [ Output(script, pr.value) ]
        return cls(outputs, pr.date_created, date_expiry, pr.description)

    @classmethod
    def from_json(cls, s: str) -> 'PaymentRequest':
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise Bip270Exception(_("Payment request oversized"))

        d = json.loads(s)

        network = d.get('network')
        if network not in (cls.BIP270_NETWORK, cls.HANDCASH_NETWORK):
            raise Bip270Exception(_("Invalid network '{}'").format(network))

        if 'outputs' not in d:
            raise Bip270Exception(_("Payment details missing"))
        if type(d['outputs']) is not list:
            raise Bip270Exception(_("Corrupt payment details"))

        outputs = []
        for ui_dict in d['outputs']:
            outputs.append(Output.from_dict(ui_dict))
        pr = cls(outputs)
        # We preserve the network we were given as maybe it is HandCash's non-standard "bitcoin"
        pr.network = network

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

        payment_url = d.get('paymentUrl')
        if payment_url is not None and type(payment_url) is not str:
            raise Bip270Exception(_("Corrupt payment URL"))
        pr.payment_url = payment_url

        merchant_data = d.get('merchantData')
        if merchant_data is not None and type(merchant_data) is not str:
            raise Bip270Exception(_("Corrupt merchant data"))
        pr.merchant_data = merchant_data

        return pr

    def to_json(self) -> str:
        d = {}
        d['network'] = self.network
        d['outputs'] = [output.to_dict() for output in self.outputs]  # type: ignore
        d['creationTimestamp'] = self.creation_timestamp
        if self.expiration_timestamp is not None:
            d['expirationTimestamp'] = self.expiration_timestamp
        if self.memo is not None:
            d['memo'] = self.memo
        if self.payment_url is not None:
            d['paymentUrl'] = self.payment_url
        if self.merchant_data is not None:
            d['merchantData'] = self.merchant_data
        return json.dumps(d)

    def is_pr(self) -> bool:
        return self.get_amount() != 0

    def has_expired(self) -> bool:
        return has_expired(self.expiration_timestamp)

    def get_expiration_date(self) -> int:
        return self.expiration_timestamp

    def get_amount(self) -> int:
        return sum(x.amount for x in self.outputs)

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

    def get_memo(self) -> str:
        return self.memo

    def get_id(self) -> Optional[int]:
        return self._id

    def set_id(self, invoice_id: int) -> None:
        self._id = invoice_id

    def get_outputs(self) -> List[XTxOutput]:
        return [output.to_tx_output() for output in self.outputs]

    def send_payment(self, account: 'DeterministicAccount', transaction_hex: str) -> bool:
        self.error = None

        if not self.payment_url:
            self.error = _("No URL")
            return False

        payment_memo = "Paid using ElectrumSV"
        payment = Payment(self.merchant_data, transaction_hex, payment_memo)

        parsed_url = urllib.parse.urlparse(self.payment_url)
        response = self._make_request(parsed_url.geturl(), payment.to_json())
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

        logger.debug("PaymentACK message received: memo=%r", payment_ack.memo)
        return True

    # The following function and classes is abstracted to allow unit testing.
    def _make_request(self, url, message):
        r = requests.post(url, data=message, headers=ACK_HEADERS, verify=ca_path)
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
    MAXIMUM_JSON_LENGTH = 10 * 1000 * 1000

    def __init__(self, merchant_data: Any, transaction_hex: str, memo: Optional[str]=None) -> None:
        self.merchant_data = merchant_data
        self.transaction_hex = transaction_hex
        self.memo = memo

    @classmethod
    def from_dict(cls, data: dict, ack: bool=False) -> 'Payment':
        merchant_data: Any
        if 'merchantData' in data:
            merchant_data = data['merchantData']
        elif ack:
            merchant_data = {}
        else:
            raise Bip270Exception("Missing required json 'merchantData' field")

        if 'transaction' in data:
            transaction_hex = data['transaction']
            if type(transaction_hex) is not str:
                raise Bip270Exception("Invalid json 'transaction' field")
        else:
            raise Bip270Exception("Missing required json 'transaction' field")

        memo = data.get('memo')
        if memo is not None and type(memo) is not str:
            raise Bip270Exception("Invalid json 'memo' field")

        return cls(merchant_data, transaction_hex, memo)

    def to_dict(self) -> dict:
        data = {
            'merchantData': self.merchant_data,
            'transaction': self.transaction_hex,
        }
        if self.memo:
            data['memo'] = self.memo
        return data

    @classmethod
    def from_json(cls, s: str) -> 'Payment':
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise Bip270Exception(f"Invalid payment, too large")
        data = json.loads(s)
        return cls.from_dict(data)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class PaymentACK:
    MAXIMUM_JSON_LENGTH = 11 * 1000 * 1000

    def __init__(self, payment: Payment, memo: Optional[str] = None) -> None:
        self.payment = payment
        self.memo = memo

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            'payment': self.payment.to_dict(),
        }
        if self.memo:
            data['memo'] = self.memo
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PaymentACK':
        if 'payment' not in data:
            raise Bip270Exception("Missing required json 'payment' field")

        memo = data.get('memo')
        if memo is not None and type(memo) is not str:
            raise Bip270Exception("Invalid json 'memo' field")

        payment = Payment.from_dict(data['payment'], ack=True)
        return cls(payment, memo)

    def to_json(self) -> str:
        data = self.to_dict()
        return json.dumps(data)

    @classmethod
    def from_json(cls, s: str) -> 'PaymentACK':
        if len(s) > cls.MAXIMUM_JSON_LENGTH:
            raise Bip270Exception(f"Invalid payment ACK, too large")
        data = json.loads(s)
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
    else:
        error = f"unknown scheme {url}"

    if error:
        raise Bip270Exception(error)

    return PaymentRequest.from_json(data)
