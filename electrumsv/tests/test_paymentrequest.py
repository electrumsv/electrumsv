import json
import os
import time
import unittest

import bitcoinx

from electrumsv import address
from electrumsv import paymentrequest


PKH_HEX = "8b2b1e60ccf6c206f1fde862897cd61be5f2a021"
PKH_BYTES = bytes.fromhex(PKH_HEX)
PKH_ADDRESS = address.Address.from_P2PKH_hash(PKH_BYTES).to_string()
P2PKH_SCRIPT_ASM = bitcoinx.Script.P2PKH_script(PKH_BYTES).to_asm()

TRANSACTION_HEX = ("0100000002f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b839d1c"+
    "912084000000002401ff2102faf7f10ccad1bc40e697e6b90b1d7c9daf92fdf47a4cf726f1c0422e473"+
    "0fe85fefffffff146000000000000f25568d10d46181bc65b01b735f8cccdb91e4e7d172c5efb984b83"+
    "9d1c912084010000006b483045022100fa8ebdc7cefc407fd1b560fb2e2e5e96e900e94634d96df4fd2"+
    "84126048746a2022028d91ca132a1a386a67df69a2c5ba216218870c256c163d729f1575f7a8824f541"+
    "21030c4ee92cd3c174e9aabcdec56ddc6b6d09a7767b563055a10e5406ec48f477eafeffffff01de9e0"+
    "100000000001976a914428f0dbcc74fc3a999bbaf8bf4600531e155e66b88ac75c50800")


def _generate_address():
    pkh_bytes = os.urandom(20)
    return address.Address.from_P2PKH_hash(pkh_bytes).to_string()



class TestOutput(unittest.TestCase):
    def test_get_address_string(self):
        output = paymentrequest.Output(P2PKH_SCRIPT_ASM)
        self.assertEqual(PKH_ADDRESS, output.get_address_string())

    def test_dict_optional_fields_unused(self):
        output = paymentrequest.Output(P2PKH_SCRIPT_ASM)
        data = output.to_dict()
        self.assertTrue('amount' not in data)
        self.assertTrue('description' not in data)

    def test_dict_optional_fields_used(self):
        output = paymentrequest.Output(P2PKH_SCRIPT_ASM, 1, "description")
        data = output.to_dict()
        self.assertTrue('script' in data)
        self.assertEqual(P2PKH_SCRIPT_ASM, data['script'])
        self.assertTrue('amount' in data)
        self.assertTrue('description' in data)

    def test_json_restoration_all(self):
        original_output = paymentrequest.Output(P2PKH_SCRIPT_ASM, 1, "description")
        output_json = original_output.to_json()
        restored_output = paymentrequest.Output.from_json(output_json)
        self.assertEqual(original_output.script_asm, restored_output.script_asm)
        self.assertEqual(original_output.amount, restored_output.amount)
        self.assertEqual(original_output.description, restored_output.description)

    def test_json_restoration_required(self):
        original_output = paymentrequest.Output(P2PKH_SCRIPT_ASM)
        output_json = original_output.to_json()
        restored_output = paymentrequest.Output.from_json(output_json)
        self.assertEqual(original_output.script_asm, restored_output.script_asm)
        self.assertEqual(original_output.amount, restored_output.amount)
        self.assertEqual(original_output.description, restored_output.description)


class TestPayment(unittest.TestCase):
    def test_dict_optional_fields_unused(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        payment = paymentrequest.Payment("merchant_data", "transaction_hex", outputs)
        data = payment.to_dict()
        self.assertTrue('merchantData' in data)
        self.assertTrue('refundTo' in data)
        self.assertFalse('memo' in data)

    def test_dict_optional_fields_used(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        payment = paymentrequest.Payment("merchant_data", "transaction_hex", outputs, "memo")
        data = payment.to_dict()
        self.assertTrue('merchantData' in data)
        self.assertTrue('refundTo' in data)
        self.assertTrue('memo' in data)

    def test_json_restoration_all(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        original = paymentrequest.Payment("merchant_data", "transaction_hex", outputs, "memo")
        json_value = original.to_json()
        restored = paymentrequest.Payment.from_json(json_value)
        self.assertEqual(original.merchant_data, restored.merchant_data)
        self.assertEqual(original.transaction_hex, restored.transaction_hex)
        self.assertEqual(len(original.refund_outputs), len(restored.refund_outputs))
        self.assertEqual(original.refund_outputs[0].script_asm,
                         restored.refund_outputs[0].script_asm)
        self.assertEqual(original.memo, restored.memo)

    def test_json_restoration_required(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        original = paymentrequest.Payment("merchant_data", "transaction_hex", outputs)
        json_value = original.to_json()
        restored = paymentrequest.Payment.from_json(json_value)
        self.assertEqual(original.merchant_data, restored.merchant_data)
        self.assertEqual(original.transaction_hex, restored.transaction_hex)
        self.assertEqual(len(original.refund_outputs), len(restored.refund_outputs))
        self.assertEqual(original.refund_outputs[0].script_asm,
                         restored.refund_outputs[0].script_asm)
        self.assertEqual(original.memo, restored.memo)


class TestPaymentACK(unittest.TestCase):
    def test_dict_optional_fields_unused(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        payment = paymentrequest.Payment("merchant_data", "transaction_hex", outputs)
        payment_ack = paymentrequest.PaymentACK(payment)
        data = payment_ack.to_dict()
        self.assertTrue('payment' in data)
        self.assertFalse('memo' in data)

    def test_dict_optional_fields_used(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        payment = paymentrequest.Payment("merchant_data", "transaction_hex", outputs, "memo")
        payment_ack = paymentrequest.PaymentACK(payment, 'memo')
        data = payment_ack.to_dict()
        self.assertTrue('payment' in data)
        self.assertTrue('memo' in data)

    def test_json_restoration_all(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        payment = paymentrequest.Payment("merchant_data", "transaction_hex", outputs, "memo")
        original = paymentrequest.PaymentACK(payment)
        json_value = original.to_json()
        restored = paymentrequest.PaymentACK.from_json(json_value)
        self.assertEqual(original.payment.merchant_data, restored.payment.merchant_data)
        self.assertEqual(original.payment.transaction_hex, restored.payment.transaction_hex)
        self.assertEqual(len(original.payment.refund_outputs),
                         len(restored.payment.refund_outputs))
        self.assertEqual(original.payment.refund_outputs[0].script_asm,
                         restored.payment.refund_outputs[0].script_asm)
        self.assertEqual(original.payment.memo, restored.payment.memo)
        self.assertEqual(original.memo, restored.memo)

    def test_json_restoration_required(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        payment = paymentrequest.Payment("merchant_data", "transaction_hex", outputs)
        original = paymentrequest.PaymentACK(payment)
        json_value = original.to_json()
        restored = paymentrequest.PaymentACK.from_json(json_value)
        self.assertEqual(original.memo, restored.memo)


class TestPaymentRequest(unittest.TestCase):
    def test_dict_optional_fields_unused(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        original = paymentrequest.PaymentRequest(outputs)
        json_value = original.to_json()
        restored = paymentrequest.PaymentRequest.from_json(json_value)
        self.assertEqual(len(original.outputs), len(restored.outputs))
        self.assertEqual(original.outputs[0].script_asm, restored.outputs[0].script_asm)
        self.assertEqual(original.creation_timestamp, restored.creation_timestamp)
        self.assertEqual(original.expiration_timestamp, restored.expiration_timestamp)
        self.assertEqual(original.memo, restored.memo)
        self.assertEqual(original.payment_url, restored.payment_url)
        self.assertEqual(original.merchant_data, restored.merchant_data)

    def test_dict_optional_fields_used(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        creation_timestamp = int(time.time() + 100)
        expiration_timestamp = creation_timestamp + 100
        request = paymentrequest.PaymentRequest(
            outputs, creation_timestamp, expiration_timestamp, "memo", "pay_url", "merchant_data")
        json_value = request.to_json()
        data = json.loads(json_value)
        self.assertTrue('creationTimestamp' in data)
        self.assertTrue('expirationTimestamp' in data)
        self.assertTrue('memo' in data)
        self.assertTrue('paymentUrl' in data)
        self.assertTrue('merchantData' in data)

    def test_json_restoration_all(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        creation_timestamp = int(time.time() + 100)
        expiration_timestamp = creation_timestamp + 100
        original = paymentrequest.PaymentRequest(
            outputs, creation_timestamp, expiration_timestamp, "memo", "pay_url", "merchant_data")
        json_value = original.to_json()
        restored = paymentrequest.PaymentRequest.from_json(json_value)
        self.assertEqual(len(original.outputs), len(restored.outputs))
        self.assertEqual(original.outputs[0].script_asm, restored.outputs[0].script_asm)
        self.assertEqual(original.creation_timestamp, restored.creation_timestamp)
        self.assertEqual(original.expiration_timestamp, restored.expiration_timestamp)
        self.assertEqual(original.memo, restored.memo)
        self.assertEqual(original.payment_url, restored.payment_url)
        self.assertEqual(original.merchant_data, restored.merchant_data)

    def test_json_restoration_required(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        original = paymentrequest.PaymentRequest(outputs)
        json_value = original.to_json()
        restored = paymentrequest.PaymentRequest.from_json(json_value)
        self.assertEqual(len(original.outputs), len(restored.outputs))
        self.assertEqual(original.outputs[0].script_asm, restored.outputs[0].script_asm)
        self.assertEqual(original.creation_timestamp, restored.creation_timestamp)
        self.assertEqual(original.expiration_timestamp, restored.expiration_timestamp)
        self.assertEqual(original.memo, restored.memo)
        self.assertEqual(original.payment_url, restored.payment_url)
        self.assertEqual(original.merchant_data, restored.merchant_data)

    class _FakeRequestResponse:
        def __init__(self, status_code, reason, content):
            self._status_code = status_code
            self._reason = reason
            self._content = content

        def get_status_code(self):
            return self._status_code

        def get_reason(self):
            return self._reason

        def get_content(self):
            return self._content

    def test_send_payment_success(self):
        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        payment = paymentrequest.Payment("merchant_data", "transaction_hex", outputs)
        ack_memo = "ack_memo"
        payment_ack = paymentrequest.PaymentACK(payment, ack_memo)
        ack_json = payment_ack.to_json()

        class PaymentRequestTestable(paymentrequest.PaymentRequest):
            def _make_request(self, url, message):
                return TestPaymentRequest._FakeRequestResponse(200, NotImplemented, ack_json)

        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        creation_timestamp = int(time.time() + 100)
        expiration_timestamp = creation_timestamp + 100
        payment_request = PaymentRequestTestable(
            outputs, creation_timestamp, expiration_timestamp, "memo", "pay_url", "merchant_data")

        refund_address = _generate_address()
        response_status, response_message = payment_request.send_payment(
            TRANSACTION_HEX, refund_address)
        # The response was successful.
        self.assertTrue(response_status)
        # The ack memo is the response message.
        self.assertEqual(ack_memo, response_message)

    def test_send_payment_ssl_exception(self):
        class PaymentRequestTestable(paymentrequest.PaymentRequest):
            def _make_request(self, url, message):
                return None

        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        creation_timestamp = int(time.time() + 100)
        expiration_timestamp = creation_timestamp + 100
        payment_request = PaymentRequestTestable(
            outputs, creation_timestamp, expiration_timestamp, "memo", "pay_url", "merchant_data")

        refund_address = _generate_address()
        response_status, response_message = payment_request.send_payment(
            TRANSACTION_HEX, refund_address)
        self.assertFalse(response_status)

    def test_send_payment_default_error(self):
        class PaymentRequestTestable(paymentrequest.PaymentRequest):
            def _make_request(self, url, message):
                return TestPaymentRequest._FakeRequestResponse(403, "reason", b"content")

        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        creation_timestamp = int(time.time() + 100)
        expiration_timestamp = creation_timestamp + 100
        payment_request = PaymentRequestTestable(
            outputs, creation_timestamp, expiration_timestamp, "memo", "pay_url", "merchant_data")

        refund_address = _generate_address()
        response_status, response_message = payment_request.send_payment(
            TRANSACTION_HEX, refund_address)
        self.assertFalse(response_status)
        self.assertEqual("reason", response_message)

    def test_send_payment_400_error(self):
        class PaymentRequestTestable(paymentrequest.PaymentRequest):
            def _make_request(self, url, message):
                return TestPaymentRequest._FakeRequestResponse(400, "reason", b"content")

        outputs = [ paymentrequest.Output(P2PKH_SCRIPT_ASM) ]
        creation_timestamp = int(time.time() + 100)
        expiration_timestamp = creation_timestamp + 100
        payment_request = PaymentRequestTestable(
            outputs, creation_timestamp, expiration_timestamp, "memo", "pay_url", "merchant_data")

        refund_address = _generate_address()
        response_status, response_message = payment_request.send_payment(
            TRANSACTION_HEX, refund_address)
        self.assertFalse(response_status)
        self.assertEqual("reason: content", response_message)

