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
import requests
import time
import urllib.parse

from . import bitcoin
# Create with 'protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto'
from . import paymentrequest_pb2 as pb2
from . import transaction
from . import util
from .exceptions import FileImportFailed, FileImportFailedEncrypted
from .logs import logs
from .util import bh2u, bfh


logger = logs.get_logger("paymentrequest")

REQUEST_HEADERS = {
    'Accept': 'application/bitcoin-paymentrequest',
    'User-Agent': 'ElectrumSV'
}
ACK_HEADERS = {
    'Content-Type': 'application/bitcoin-payment',
    'Accept': 'application/bitcoin-paymentack',
    'User-Agent': 'ElectrumSV'
}

# Used for requests.
ca_path = requests.certs.where()


# status of payment requests
PR_UNPAID  = 0
PR_EXPIRED = 1
PR_UNKNOWN = 2     # sent but not propagated
PR_PAID    = 3     # send and propagated



def get_payment_request(url):
    u = urllib.parse.urlparse(url)
    error = None
    response = None
    if u.scheme in ['http', 'https']:
        try:
            response = requests.request('GET', url, headers=REQUEST_HEADERS)
            response.raise_for_status()
            # Guard against `bitcoin:`-URIs with invalid payment request URLs
            if "Content-Type" not in response.headers \
            or response.headers["Content-Type"] != "application/bitcoin-paymentrequest":
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
        raise Exception("unknown scheme", url)
    pr = PaymentRequest(data, error)
    return pr


class PaymentRequest:

    def __init__(self, data, error=None):
        self.raw = data
        self.error = error
        self.parse(data)
        self.requestor = None # known after verify
        self.tx = None

    def __str__(self):
        return str(self.raw)

    def parse(self, r):
        if self.error:
            return
        self.id = bh2u(bitcoin.sha256(r)[0:16])
        try:
            self.data = pb2.PaymentRequest()
            self.data.ParseFromString(r)
        except:
            self.error = "cannot parse payment request"
            return
        self.details = pb2.PaymentDetails()
        self.details.ParseFromString(self.data.serialized_payment_details)
        self.outputs = []
        for o in self.details.outputs:
            addr = transaction.get_address_from_output_script(o.script)[1]
            self.outputs.append((bitcoin.TYPE_ADDRESS, addr, o.amount))
        self.memo = self.details.memo
        self.payment_url = self.details.payment_url

    def is_pr(self):
        return self.get_amount() != 0

    def verify(self, contacts):
        if self.error:
            return False
        if not self.raw:
            self.error = "Empty request"
            return False
        pr = pb2.PaymentRequest()
        try:
            pr.ParseFromString(self.raw)
        except:
            self.error = "Error: Cannot parse payment request"
            return False
        # the address will be dispayed as requestor
        self.requestor = None
        return True

    def has_expired(self):
        return self.details.expires and self.details.expires < int(time.time())

    def get_expiration_date(self):
        return self.details.expires

    def get_amount(self):
        return sum(x[2] for x in self.outputs)

    def get_address(self):
        o = self.outputs[0]
        assert o[0] == bitcoin.TYPE_ADDRESS
        return o[1].to_string()

    def get_requestor(self):
        return self.requestor if self.requestor else self.get_address()

    def get_verify_status(self):
        return self.error if self.requestor else "No Signature"

    def get_memo(self):
        return self.memo

    def get_dict(self):
        return {
            'requestor': self.get_requestor(),
            'memo':self.get_memo(),
            'exp': self.get_expiration_date(),
            'amount': self.get_amount(),
            'signature': self.get_verify_status(),
            'txid': self.tx,
            'outputs': self.get_outputs()
        }

    def get_id(self):
        return self.id if self.requestor else self.get_address()

    def get_outputs(self):
        return self.outputs[:]

    def send_payment(self, raw_tx, refund_addr):
        pay_det = self.details
        if not self.details.payment_url:
            return False, "no url"
        paymnt = pb2.Payment()
        paymnt.merchant_data = pay_det.merchant_data
        paymnt.transactions.append(bfh(raw_tx))
        ref_out = paymnt.refund_to.add()
        ref_out.script = bfh(transaction.Transaction.pay_script(refund_addr))
        paymnt.memo = "Paid using ElectrumSV"
        pm = paymnt.SerializeToString()
        payurl = urllib.parse.urlparse(pay_det.payment_url)
        try:
            r = requests.post(payurl.geturl(), data=pm, headers=ACK_HEADERS, verify=ca_path)
        except requests.exceptions.SSLError:
            logger.debug("Payment Message/PaymentACK verify Failed")
            try:
                r = requests.post(payurl.geturl(), data=pm, headers=ACK_HEADERS, verify=False)
            except Exception as e:
                logger.exception("Payment Message/PaymentACK")
                return False, "Payment Message/PaymentACK Failed"
        if r.status_code != 200:
            # Propagate 'Bad request' (HTTP 400) messages to the user since they
            # contain valuable information.
            if r.status_code == 400:
                return False, (r.reason + ": " + r.content.decode('UTF-8'))
            # Some other errors might display an entire HTML document.
            # Hide those and just display the name of the error code.
            return False, r.reason
        try:
            paymntack = pb2.PaymentACK()
            paymntack.ParseFromString(r.content)
        except Exception:
            return False, ("PaymentACK could not be processed. Payment was sent; "
                           "please manually verify that payment was received.")
        logger.debug("PaymentACK message received: %s", paymntack.memo)
        return True, paymntack.memo


def make_unsigned_request(req):
    from .transaction import Transaction
    addr = req['address']
    time = req.get('time', 0)
    exp = req.get('exp', 0)
    if time and type(time) != int:
        time = 0
    if exp and type(exp) != int:
        exp = 0
    amount = req['amount']
    if amount is None:
        amount = 0
    memo = req['memo']
    script = bfh(Transaction.pay_script(addr))
    outputs = [(script, amount)]
    pd = pb2.PaymentDetails()
    for script, amount in outputs:
        pd.outputs.add(amount=amount, script=script)
    pd.time = time
    pd.expires = time + exp if exp else 0
    pd.memo = memo
    pr = pb2.PaymentRequest()
    pr.serialized_payment_details = pd.SerializeToString()
    pr.signature = util.to_bytes('')
    return pr


def serialize_request(req):
    return make_unsigned_request(req)


def make_request(config, req):
    return make_unsigned_request(req)



class InvoiceStore(object):

    def __init__(self, storage):
        self.storage = storage
        self.invoices = {}
        self.paid = {}
        d = self.storage.get('invoices', {})
        self.load(d)

    def set_paid(self, pr, txid):
        pr.tx = txid
        self.paid[txid] = pr.get_id()

    def load(self, d):
        for k, v in d.items():
            try:
                pr = PaymentRequest(bfh(v.get('hex')))
                pr.tx = v.get('txid')
                pr.requestor = v.get('requestor')
                self.invoices[k] = pr
                if pr.tx:
                    self.paid[pr.tx] = k
            except:
                continue

    def import_file(self, path):
        try:
            with open(path, 'r') as f:
                d = json.loads(f.read())
                self.load(d)
        except json.decoder.JSONDecodeError:
            logger.exception("")
            raise FileImportFailedEncrypted()
        except Exception:
            logger.exception("")
            raise FileImportFailed()
        self.save()

    def save(self):
        l = {}
        for k, pr in self.invoices.items():
            l[k] = {
                'hex': bh2u(pr.raw),
                'requestor': pr.requestor,
                'txid': pr.tx
            }
        self.storage.put('invoices', l)

    def get_status(self, key):
        pr = self.get(key)
        if pr is None:
            logger.debug("[InvoiceStore] get_status() can't find pr for %s", key)
            return
        if pr.tx is not None:
            return PR_PAID
        if pr.has_expired():
            return PR_EXPIRED
        return PR_UNPAID

    def add(self, pr):
        key = pr.get_id()
        self.invoices[key] = pr
        self.save()
        return key

    def remove(self, key):
        paid_list = self.paid.items()
        for p in paid_list:
            if p[1] == key:
                self.paid.pop(p[0])
                break
        self.invoices.pop(key)
        self.save()

    def get(self, k):
        return self.invoices.get(k)

    def sorted_list(self):
        # sort
        return self.invoices.values()

    def unpaid_invoices(self):
        return [invoice for key, invoice in self.invoices.items()
                if self.get_status(key) != PR_PAID]
